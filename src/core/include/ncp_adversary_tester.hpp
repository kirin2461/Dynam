#pragma once

/**
 * @file ncp_adversary_tester.hpp
 * @brief Shadow Classifier / Adversary Tester — Phase 1 ML Pipeline
 *
 * Evaluates obfuscated traffic against heuristic detectors BEFORE
 * sending it to the network. Feeds DetectionFeedback back into
 * AdversarialPadding::report_feedback() to close the adaptive loop.
 *
 * Six statistical metrics (no external ML dependencies):
 *   1. Shannon entropy          — encrypted vs plaintext detection
 *   2. Chi-squared goodness     — deviation from uniform distribution
 *   3. Kolmogorov-Smirnov       — size distribution vs reference profile
 *   4. Packet size variance     — constant-size padding detection
 *   5. Inter-arrival timing CoV — flow shaping artifacts
 *   6. Burst ratio              — abnormal burst patterns
 *
 * Thread-safe: all public methods lock internal mutex.
 * Feedback callback is fired OUTSIDE the lock to prevent deadlocks.
 *
 * Future: Phase 3 adds ONNX Runtime shadow classifiers (ET-BERT-tiny,
 * FlowPic-lite) behind #ifdef NCP_HAS_ONNXRUNTIME.
 */

#include "ncp_adversarial.hpp"
#include "ncp_flow_shaper.hpp"
#include "ncp_csprng.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>
#include <cmath>
#include <chrono>
#include <mutex>
#include <deque>
#include <functional>
#include <memory>
#include <optional>

namespace ncp {
namespace DPI {

// ===== Heuristic Scores =====

struct HeuristicScores {
    double entropy_score;       ///< 0.0 (obvious plaintext) — 1.0 (indistinguishable from random)
    double chi_squared_pvalue;  ///< >0.05 = passes, <0.01 = definitely detected
    double ks_distance;         ///< <0.1 = good mimicry, >0.3 = poor
    double w1_distance = 0.0;   ///< Wasserstein-1 (bytes) vs reference; 0 = identical shape
    double size_variance_ratio; ///< observed_var / reference_var; ~1.0 = good
    double timing_cov;          ///< coefficient of variation σ/μ; close to reference = good
    double burst_anomaly;       ///< 0.0 = normal, 1.0 = extreme anomaly

    /// Weighted aggregate stealth score: 0.0 = detected, 1.0 = invisible.
    /// Initial weights are hardcoded; ncp_ml_orchestrator (Phase 2) can
    /// learn optimal weights from real-world data.
    ///
    /// Size shape is scored twice on purpose: KS bounds the CDF gap, W1 prices
    /// the actual displacement in bytes. KS alone is insensitive to a uniform
    /// shift of every packet, which is exactly the failure mode of naive
    /// padding; W1 sees it. KS keeps the larger share of the size budget
    /// because W1 is in bytes and its scale is workload-dependent.
    double aggregate_stealth() const {
        constexpr double W_ENTROPY  = 0.25;
        constexpr double W_CHI2     = 0.25;
        constexpr double W_KS       = 0.10;
        constexpr double W_W1       = 0.05;
        constexpr double W_SIZE_VAR = 0.10;
        constexpr double W_TIMING   = 0.15;
        constexpr double W_BURST    = 0.10;

        // Half-marks at 75 bytes: a flow whose sizes are displaced by one
        // average packet header's worth already loses half the W1 component.
        constexpr double W1_SCALE_BYTES = 75.0;

        double e = entropy_score;
        double c = chi_squared_pvalue > 1.0 ? 1.0 : chi_squared_pvalue;
        double k = 1.0 - (ks_distance > 1.0 ? 1.0 : ks_distance);
        double w = 1.0 / (1.0 + std::fabs(w1_distance) / W1_SCALE_BYTES);
        double s = 1.0 / (1.0 + std::fabs(size_variance_ratio - 1.0));
        double t = 1.0 / (1.0 + std::fabs(timing_cov));
        double b = 1.0 - (burst_anomaly > 1.0 ? 1.0 : burst_anomaly);

        return W_ENTROPY * e + W_CHI2 * c + W_KS * k + W_W1 * w +
               W_SIZE_VAR * s + W_TIMING * t + W_BURST * b;
    }

    /// Convert to DetectionFeedback for AdversarialPadding::report_feedback()
    DetectionFeedback to_feedback(AdversarialStrategy strategy_used) const {
        double stealth = aggregate_stealth();
        DetectionFeedback fb;
        fb.detected = (stealth < 0.5);
        fb.confidence = 1.0 - stealth;
        fb.classifier_name = "heuristic-v1";
        fb.strategy_used = strategy_used;
        fb.timestamp = std::chrono::steady_clock::now();
        return fb;
    }
};

// ===== Flow Snapshot (collected over a window) =====

struct FlowSnapshot {
    std::vector<size_t> packet_sizes;                                ///< Payload sizes
    std::vector<std::chrono::microseconds> inter_arrival_times;      ///< Δt between packets
    size_t total_bytes = 0;
    size_t packet_count = 0;

    // FIX: Running per-packet content metrics (accumulated in record_packet)
    double running_entropy_sum = 0.0;    ///< Σ per-packet shannon_entropy
    double running_chi2_sum = 0.0;       ///< Σ per-packet chi2 p-value
    size_t content_samples = 0;          ///< Number of packets with content metrics

    // Connection errors observed in the same window (feed via record_error()).
    size_t error_count = 0;
};

// ===== Online size/error learner (Task 1) =====
//
// Learns how windowed packet-size statistics and connection-error rates
// relate to detection. A tiny logistic model updated by SGD — deliberately
// dependency-free and inspectable. Until min_samples observations exist,
// predict() returns a transparent heuristic prior.
struct SizeErrorFeatures {
    double size_mean = 0.0;    ///< mean payload size, bytes
    double size_cv = 0.0;      ///< stddev / mean (0 if mean == 0)
    double frac_small = 0.0;   ///< fraction of packets <= 128 B
    double frac_large = 0.0;   ///< fraction of packets >= 1200 B
    double error_rate = 0.0;   ///< errors / (packets + errors), [0,1]
    double timing_cov = 0.0;   ///< coefficient of variation of IATs
    double burst_anomaly = 0.0;///< [0,1] from burst_anomaly_score()
    double ks_distance = 0.0;  ///< [0,1] from KS test
};

class SizeErrorLearner {
public:
    struct Params {
        double learning_rate = 0.05;
        double l2 = 0.001;
        size_t min_samples = 8;
    };

    SizeErrorLearner();
    explicit SizeErrorLearner(const Params& params);

    void set_params(const Params& params);
    Params get_params() const;

    /// Estimated probability that this window is detected, [0,1].
    double predict(const SizeErrorFeatures& f) const;

    /// Update the model from an observed outcome (detected = true/false).
    void observe(const SizeErrorFeatures& f, bool detected);

    size_t samples() const;
    /// Nine values: eight feature weights followed by the bias.
    std::array<double, 9> weights() const;
    void reset();

    /// Derive features from a collected window plus an explicit error rate.
    static SizeErrorFeatures from_snapshot(const FlowSnapshot& snapshot,
                                           double error_rate);

private:
    static double sigmoid(double z);
    static std::array<double, 8> normalize(const SizeErrorFeatures& f);

    mutable std::mutex mutex_;
    Params params_;
    std::array<double, 8> w_{};
    double bias_ = 0.0;
    size_t samples_ = 0;
};

// ===== Reference Profile for KS-test and variance =====

struct ReferenceProfile {
    std::string name;
    std::vector<double> size_cdf;        ///< CDF values at standard bucket boundaries
    std::vector<size_t> size_buckets;    ///< Bucket boundaries (e.g., 64, 128, 256...)
    double expected_size_variance = 0.0;
    double expected_timing_cov = 0.0;    ///< Expected coefficient of variation
    double expected_burst_ratio = 0.0;

    static ReferenceProfile web_browsing();
    static ReferenceProfile video_stream();
    static ReferenceProfile messenger();
    static ReferenceProfile gaming();  ///< Online game (UDP, 60fps tick, ±5ms jitter)
    static ReferenceProfile for_flow_profile(FlowProfile profile);
};

// ===== Tester Configuration =====

struct AdversaryTesterConfig {
    bool enabled = true;

    /// Window size: evaluate after every N packets
    size_t window_packets = 50;

    /// Auto-report feedback to AdversarialPadding when score < threshold
    bool auto_feedback = true;
    double detection_threshold = 0.5;

    /// Reference profile for KS-test (default: web browsing)
    FlowProfile reference_profile = FlowProfile::WEB_BROWSING;

    /// Keep last N evaluation results for trend analysis
    size_t history_size = 100;
};

// ===== Tester Statistics =====

struct AdversaryTesterStats {
    uint64_t evaluations_run = 0;
    uint64_t detections_triggered = 0;
    uint64_t feedbacks_sent = 0;
    double avg_stealth_score = 0.0;
    double min_stealth_score = 1.0;
    double max_stealth_score = 0.0;
};

// ===== Test Report (single evaluation) =====

struct TestReport {
    HeuristicScores scores;
    FlowSnapshot snapshot;
    AdversarialStrategy strategy_tested;
    std::chrono::steady_clock::time_point timestamp;
    bool detected;         ///< aggregate_stealth < threshold
    /// Learned P(detected) from the attached SizeErrorLearner, or -1 when no
    /// learner is attached / the report came from a benchmark.
    double learned_detection_probability = -1.0;
};

// ===== Main Class =====

class AdversaryTester {
public:
    AdversaryTester();
    explicit AdversaryTester(const AdversaryTesterConfig& config);
    ~AdversaryTester() = default;

    AdversaryTester(const AdversaryTester&) = delete;
    AdversaryTester& operator=(const AdversaryTester&) = delete;

    // ===== Packet Collection =====

    /// Record an outgoing packet (after obfuscation, before network send).
    /// Computes per-packet entropy and chi2 on content bytes.
    /// When window_packets are collected, triggers automatic evaluation.
    void record_packet(
        const std::vector<uint8_t>& payload,
        AdversarialStrategy strategy = AdversarialStrategy::ADAPTIVE);

    // ===== Manual Evaluation =====

    /// Evaluate a single packet against heuristics (no flow context).
    HeuristicScores evaluate_packet(const std::vector<uint8_t>& payload) const;

    /// Evaluate the current flow window (even if not full).
    TestReport evaluate_flow();

    /// Run benchmark: apply strategy N times to random data, return report.
    /// NOTE: Timing in benchmark is synthetic uniform [100μs, 50ms].
    /// Phase 2 should use recorded flow replays for realistic timing.
    TestReport run_strategy_benchmark(
        AdversarialStrategy strategy,
        AdversarialPadding& padder,
        size_t num_samples = 200);

    // ===== Static Metric Functions =====

    static double shannon_entropy(const uint8_t* data, size_t len);
    static double chi_squared_uniformity(const uint8_t* data, size_t len);

    static double ks_distance(
        const std::vector<size_t>& observed_sizes,
        const ReferenceProfile& reference);

    static double timing_coefficient_of_variation(
        const std::vector<std::chrono::microseconds>& times);

    static double burst_anomaly_score(
        const std::vector<std::chrono::microseconds>& times,
        double reference_burst_ratio);

    // ===== Feedback Target =====

    using FeedbackCallback = std::function<void(const DetectionFeedback&)>;
    void set_feedback_callback(FeedbackCallback cb);

    // ===== Config & Stats =====

    void set_config(const AdversaryTesterConfig& config);
    AdversaryTesterConfig get_config() const;
    AdversaryTesterStats get_stats() const;
    void reset_stats();

    std::vector<TestReport> get_history() const;
    void clear_history();

    // ===== Size/error learning (Task 1) =====

    /// Record a connection error (connect failure, RST, timeout) observed in
    /// the current window. Errors feed SizeErrorFeatures::error_rate.
    void record_error();

    /// Attach a learner. When set, every flow evaluation also updates the
    /// model and records its estimate in TestReport.
    void set_size_learner(std::shared_ptr<SizeErrorLearner> learner);
    std::shared_ptr<SizeErrorLearner> get_size_learner() const;

    /// Most recent learned P(detected), or -1 before the first evaluation.
    double last_detection_probability() const;

private:
    /// Evaluate current window. Returns optional pending feedback
    /// (to be fired outside the lock).
    std::optional<DetectionFeedback> evaluate_window_locked(bool force);

    ReferenceProfile current_reference() const;
    void update_running_stats(double stealth);

    mutable std::mutex mutex_;
    AdversaryTesterConfig config_;
    AdversaryTesterStats stats_;

    // Flow window
    FlowSnapshot current_window_;
    AdversarialStrategy current_strategy_ = AdversarialStrategy::ADAPTIVE;
    std::chrono::steady_clock::time_point last_packet_time_;

    // History
    std::deque<TestReport> history_;

    // Feedback output
    FeedbackCallback feedback_cb_;

    // Size/error learner (optional)
    std::shared_ptr<SizeErrorLearner> learner_;
    double last_prob_ = -1.0;
};

} // namespace DPI
} // namespace ncp
