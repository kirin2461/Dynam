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

namespace ncp {
namespace DPI {

// ===== Heuristic Scores =====

struct HeuristicScores {
    double entropy_score;       ///< 0.0 (obvious plaintext) — 1.0 (indistinguishable from random)
    double chi_squared_pvalue;  ///< >0.05 = passes, <0.01 = definitely detected
    double ks_distance;         ///< <0.1 = good mimicry, >0.3 = poor
    double size_variance_ratio; ///< observed_var / reference_var; ~1.0 = good
    double timing_cov;          ///< coefficient of variation σ/μ; close to reference = good
    double burst_anomaly;       ///< 0.0 = normal, 1.0 = extreme anomaly

    /// Weighted aggregate stealth score: 0.0 = detected, 1.0 = invisible.
    /// Initial weights are hardcoded; ncp_ml_orchestrator (Phase 2) can
    /// learn optimal weights from real-world data.
    double aggregate_stealth() const {
        // Weights: entropy and chi-squared dominate (TSPU starts with these)
        constexpr double W_ENTROPY  = 0.25;
        constexpr double W_CHI2     = 0.25;
        constexpr double W_KS       = 0.15;
        constexpr double W_SIZE_VAR = 0.10;
        constexpr double W_TIMING   = 0.15;
        constexpr double W_BURST    = 0.10;

        // Normalize each metric to [0, 1] where 1 = stealthy
        double e = entropy_score;                                    // already [0,1]
        double c = chi_squared_pvalue > 1.0 ? 1.0 : chi_squared_pvalue; // [0,1]
        double k = 1.0 - (ks_distance > 1.0 ? 1.0 : ks_distance);  // invert: low dist = good
        double s = 1.0 / (1.0 + std::fabs(size_variance_ratio - 1.0)); // peaks at ratio=1.0
        double t = 1.0 / (1.0 + std::fabs(timing_cov));             // lower anomaly = better
        double b = 1.0 - (burst_anomaly > 1.0 ? 1.0 : burst_anomaly); // invert

        return W_ENTROPY * e + W_CHI2 * c + W_KS * k +
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
};

// ===== Reference Profile for KS-test and variance =====

struct ReferenceProfile {
    std::string name;
    std::vector<double> size_cdf;        ///< CDF values at standard bucket boundaries
    std::vector<size_t> size_buckets;    ///< Bucket boundaries (e.g., 64, 128, 256...)
    double expected_size_variance = 0.0;
    double expected_timing_cov = 0.0;    ///< Expected coefficient of variation
    double expected_burst_ratio = 0.0;

    /// Built-in profiles matching FlowShaper's profiles
    static ReferenceProfile web_browsing();
    static ReferenceProfile video_stream();
    static ReferenceProfile messenger();
    static ReferenceProfile for_flow_profile(FlowProfile profile);
};

// ===== Tester Configuration =====

struct AdversaryTesterConfig {
    bool enabled = true;

    /// Window size: evaluate after every N packets
    size_t window_packets = 50;

    /// Auto-report feedback to AdversarialPadding when score < threshold
    bool auto_feedback = true;
    double detection_threshold = 0.5;   ///< aggregate_stealth < this → detected

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
    /// When window_packets are collected, triggers automatic evaluation.
    /// @param payload   Obfuscated packet payload
    /// @param strategy  Strategy that produced this packet
    void record_packet(
        const std::vector<uint8_t>& payload,
        AdversarialStrategy strategy = AdversarialStrategy::ADAPTIVE);

    // ===== Manual Evaluation =====

    /// Evaluate a single packet against heuristics (no flow context).
    HeuristicScores evaluate_packet(const std::vector<uint8_t>& payload) const;

    /// Evaluate the current flow window.
    TestReport evaluate_flow();

    /// Run benchmark: apply strategy N times to random data, return report.
    TestReport run_strategy_benchmark(
        AdversarialStrategy strategy,
        AdversarialPadding& padder,
        size_t num_samples = 200);

    // ===== Static Metric Functions =====

    /// Shannon entropy of byte distribution, normalized to [0, 1].
    /// 1.0 = perfectly uniform (looks encrypted/random).
    /// 0.0 = all identical bytes.
    static double shannon_entropy(const uint8_t* data, size_t len);

    /// Chi-squared p-value testing uniformity of byte distribution.
    /// >0.05 = plausibly random, <0.01 = definitely non-random.
    static double chi_squared_uniformity(const uint8_t* data, size_t len);

    /// Kolmogorov-Smirnov distance between observed size distribution
    /// and reference CDF. Lower = better mimicry.
    static double ks_distance(
        const std::vector<size_t>& observed_sizes,
        const ReferenceProfile& reference);

    /// Coefficient of variation (σ/μ) of inter-arrival times.
    static double timing_coefficient_of_variation(
        const std::vector<std::chrono::microseconds>& times);

    /// Burst ratio: max_burst_size / avg_packet_rate.
    /// Deviation from reference indicates flow shaping artifacts.
    static double burst_anomaly_score(
        const std::vector<std::chrono::microseconds>& times,
        double reference_burst_ratio);

    // ===== Feedback Target =====

    /// Set callback to receive DetectionFeedback (connects to AdversarialPadding).
    using FeedbackCallback = std::function<void(const DetectionFeedback&)>;
    void set_feedback_callback(FeedbackCallback cb);

    // ===== Config & Stats =====

    void set_config(const AdversaryTesterConfig& config);
    AdversaryTesterConfig get_config() const;
    AdversaryTesterStats get_stats() const;
    void reset_stats();

    /// Get last N test reports for trend analysis
    std::vector<TestReport> get_history() const;
    void clear_history();

private:
    void try_auto_evaluate();
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
};

} // namespace DPI
} // namespace ncp
