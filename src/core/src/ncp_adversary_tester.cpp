/**
 * @file ncp_adversary_tester.cpp
 * @brief Shadow Classifier / Adversary Tester — Phase 1 ML Pipeline
 *
 * Implements 6 heuristic detectors that approximate what TSPU statistical
 * engines check before escalating to ET-BERT / deep learning classifiers.
 *
 * No external dependencies beyond libsodium (via ncp_csprng.hpp).
 *
 * FIX review findings:
 *   - Entropy/Chi2 now computed from actual packet content bytes
 *     (running average in FlowSnapshot), not from size distribution
 *   - Feedback callback fired OUTSIDE mutex to prevent deadlocks
 *   - evaluate_flow() no longer mutates config_; uses force flag instead
 *   - ks_distance() has TODO note for pre-sort optimization at scale
 *   - run_strategy_benchmark() documents synthetic timing limitation
 */

#include "../include/ncp_adversary_tester.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cstring>

namespace ncp {
namespace DPI {

// ══════════════════════════════════════════════════════════
// Reference Profiles
// ══════════════════════════════════════════════════════════

ReferenceProfile ReferenceProfile::web_browsing() {
    ReferenceProfile p;
    p.name = "web_browsing";
    p.size_buckets = {64, 128, 256, 512, 1024, 1460};
    p.size_cdf     = {0.35, 0.52, 0.68, 0.82, 0.93, 1.0};
    p.expected_size_variance = 180000.0;
    p.expected_timing_cov = 1.8;
    p.expected_burst_ratio = 8.0;
    return p;
}

ReferenceProfile ReferenceProfile::video_stream() {
    ReferenceProfile p;
    p.name = "video_stream";
    p.size_buckets = {64, 128, 256, 512, 1024, 1460};
    p.size_cdf     = {0.05, 0.08, 0.12, 0.20, 0.45, 1.0};
    p.expected_size_variance = 120000.0;
    p.expected_timing_cov = 0.3;
    p.expected_burst_ratio = 2.0;
    return p;
}

ReferenceProfile ReferenceProfile::messenger() {
    ReferenceProfile p;
    p.name = "messenger";
    p.size_buckets = {64, 128, 256, 512, 1024, 1460};
    p.size_cdf     = {0.55, 0.78, 0.90, 0.96, 0.99, 1.0};
    p.expected_size_variance = 8000.0;
    p.expected_timing_cov = 2.5;
    p.expected_burst_ratio = 3.0;
    return p;
}

ReferenceProfile ReferenceProfile::for_flow_profile(FlowProfile profile) {
    switch (profile) {
    case FlowProfile::WEB_BROWSING:   return web_browsing();
    case FlowProfile::VIDEO_STREAM:   return video_stream();
    case FlowProfile::MESSENGER:      return messenger();
    case FlowProfile::GAMING:         return web_browsing();  // TODO: dedicated
    case FlowProfile::FILE_DOWNLOAD:  return video_stream();  // similar pattern
    default:                          return web_browsing();
    }
}

// ══════════════════════════════════════════════════════════
// Static Metric Functions
// ══════════════════════════════════════════════════════════

double AdversaryTester::shannon_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    double n = static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / n;
        entropy -= p * std::log2(p);
    }

    // Normalize to [0, 1]: max entropy for 256 symbols = 8.0 bits
    return entropy / 8.0;
}

double AdversaryTester::chi_squared_uniformity(const uint8_t* data, size_t len) {
    if (!data || len < 16) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    double expected = static_cast<double>(len) / 256.0;
    double chi2 = 0.0;
    for (int i = 0; i < 256; ++i) {
        double diff = static_cast<double>(freq[i]) - expected;
        chi2 += (diff * diff) / expected;
    }

    // Wilson-Hilferty normal approximation for chi-squared, k=255 df
    double k = 255.0;
    double term = 2.0 / (9.0 * k);
    double z = (std::cbrt(chi2 / k) - (1.0 - term)) / std::sqrt(term);

    // Standard normal CDF (Abramowitz & Stegun 7.1.26)
    double abs_z = std::fabs(z);
    double t = 1.0 / (1.0 + 0.2316419 * abs_z);
    double d = 0.3989422804014327;  // 1/sqrt(2π)
    double p_upper = d * std::exp(-0.5 * z * z) *
        (t * (0.319381530 +
         t * (-0.356563782 +
         t * (1.781477937 +
         t * (-1.821255978 +
         t * 1.330274429)))));

    if (z > 0) return p_upper;
    return 1.0 - p_upper;
}

double AdversaryTester::ks_distance(
    const std::vector<size_t>& observed_sizes,
    const ReferenceProfile& reference)
{
    if (observed_sizes.empty() || reference.size_buckets.empty()) return 1.0;

    // Build empirical CDF at the same bucket boundaries
    // TODO: For large windows (>1000 packets), pre-sort observed_sizes
    // and use binary search (std::upper_bound) per bucket boundary.
    size_t n = observed_sizes.size();
    std::vector<double> empirical_cdf;
    empirical_cdf.reserve(reference.size_buckets.size());

    for (size_t boundary : reference.size_buckets) {
        size_t count = 0;
        for (size_t s : observed_sizes) {
            if (s <= boundary) count++;
        }
        empirical_cdf.push_back(static_cast<double>(count) / static_cast<double>(n));
    }

    double max_d = 0.0;
    for (size_t i = 0; i < empirical_cdf.size() && i < reference.size_cdf.size(); ++i) {
        double d_val = std::fabs(empirical_cdf[i] - reference.size_cdf[i]);
        if (d_val > max_d) max_d = d_val;
    }

    return max_d;
}

double AdversaryTester::timing_coefficient_of_variation(
    const std::vector<std::chrono::microseconds>& times)
{
    if (times.size() < 2) return 0.0;

    double sum = 0.0;
    for (const auto& t : times) {
        sum += static_cast<double>(t.count());
    }
    double mean = sum / static_cast<double>(times.size());
    if (mean < 1.0) return 0.0;

    double var_sum = 0.0;
    for (const auto& t : times) {
        double diff = static_cast<double>(t.count()) - mean;
        var_sum += diff * diff;
    }
    double stddev = std::sqrt(var_sum / static_cast<double>(times.size()));

    return stddev / mean;
}

double AdversaryTester::burst_anomaly_score(
    const std::vector<std::chrono::microseconds>& times,
    double reference_burst_ratio)
{
    if (times.size() < 5 || reference_burst_ratio <= 0.0) return 0.0;

    constexpr int64_t BURST_THRESHOLD_US = 10000;  // 10ms

    size_t max_burst = 0;
    size_t current_burst = 1;
    for (size_t i = 0; i < times.size(); ++i) {
        if (times[i].count() < BURST_THRESHOLD_US) {
            current_burst++;
        } else {
            if (current_burst > max_burst) max_burst = current_burst;
            current_burst = 1;
        }
    }
    if (current_burst > max_burst) max_burst = current_burst;

    double total_us = 0.0;
    for (const auto& t : times) total_us += static_cast<double>(t.count());
    double avg_rate = (total_us > 0.0)
        ? static_cast<double>(times.size()) / (total_us / 1e6)
        : 1.0;

    double observed_ratio = (avg_rate > 0.0)
        ? static_cast<double>(max_burst) / avg_rate
        : 0.0;

    double deviation = std::fabs(observed_ratio - reference_burst_ratio) / reference_burst_ratio;
    return std::min(deviation, 1.0);
}

// ══════════════════════════════════════════════════════════
// Constructor / Config
// ══════════════════════════════════════════════════════════

AdversaryTester::AdversaryTester()
    : AdversaryTester(AdversaryTesterConfig{})
{}

AdversaryTester::AdversaryTester(const AdversaryTesterConfig& config)
    : config_(config)
    , last_packet_time_(std::chrono::steady_clock::now())
{}

void AdversaryTester::set_config(const AdversaryTesterConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

AdversaryTesterConfig AdversaryTester::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

AdversaryTesterStats AdversaryTester::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void AdversaryTester::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = {};
}

void AdversaryTester::set_feedback_callback(FeedbackCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    feedback_cb_ = std::move(cb);
}

std::vector<TestReport> AdversaryTester::get_history() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {history_.begin(), history_.end()};
}

void AdversaryTester::clear_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    history_.clear();
}

// ══════════════════════════════════════════════════════════
// Packet Collection
// ══════════════════════════════════════════════════════════

void AdversaryTester::record_packet(
    const std::vector<uint8_t>& payload,
    AdversarialStrategy strategy)
{
    // Compute per-packet content metrics BEFORE taking the lock
    // (these are pure functions, no shared state needed)
    double pkt_entropy = 0.0;
    double pkt_chi2 = 0.0;
    if (!payload.empty()) {
        pkt_entropy = shannon_entropy(payload.data(), payload.size());
        pkt_chi2 = chi_squared_uniformity(payload.data(), payload.size());
    }

    // FIX: Feedback callback must be fired outside mutex_.
    // evaluate_window_locked() returns optional pending feedback.
    std::optional<DetectionFeedback> pending_feedback;
    FeedbackCallback cb_copy;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!config_.enabled) return;

        auto now = std::chrono::steady_clock::now();

        // Record inter-arrival time
        if (current_window_.packet_count > 0) {
            auto delta = std::chrono::duration_cast<std::chrono::microseconds>(
                now - last_packet_time_);
            current_window_.inter_arrival_times.push_back(delta);
        }
        last_packet_time_ = now;

        // Record size
        current_window_.packet_sizes.push_back(payload.size());
        current_window_.total_bytes += payload.size();
        current_window_.packet_count++;
        current_strategy_ = strategy;

        // FIX: Accumulate per-packet content entropy and chi2
        current_window_.running_entropy_sum += pkt_entropy;
        current_window_.running_chi2_sum += pkt_chi2;
        current_window_.content_samples++;

        // Auto-evaluate when window is full
        if (current_window_.packet_count >= config_.window_packets) {
            pending_feedback = evaluate_window_locked(false);
            cb_copy = feedback_cb_;
        }
    }
    // mutex_ released — safe to call external code

    if (pending_feedback && cb_copy) {
        cb_copy(*pending_feedback);
    }
}

// ══════════════════════════════════════════════════════════
// Core Evaluation (called under mutex_)
// ══════════════════════════════════════════════════════════

std::optional<DetectionFeedback> AdversaryTester::evaluate_window_locked(bool force) {
    // Note: caller must hold mutex_

    if (!force && current_window_.packet_count < config_.window_packets) {
        return std::nullopt;
    }

    if (current_window_.packet_count == 0) {
        return std::nullopt;
    }

    ReferenceProfile ref = current_reference();
    HeuristicScores scores{};

    // 1. Shannon entropy — averaged from per-packet content entropy
    if (current_window_.content_samples > 0) {
        scores.entropy_score = current_window_.running_entropy_sum
                             / static_cast<double>(current_window_.content_samples);
    } else {
        scores.entropy_score = 0.0;
    }

    // 2. Chi-squared — averaged from per-packet content chi2 p-values
    if (current_window_.content_samples > 0) {
        scores.chi_squared_pvalue = current_window_.running_chi2_sum
                                  / static_cast<double>(current_window_.content_samples);
    } else {
        scores.chi_squared_pvalue = 0.0;
    }

    // 3. KS distance
    scores.ks_distance = ks_distance(current_window_.packet_sizes, ref);

    // 4. Size variance ratio
    if (current_window_.packet_sizes.size() >= 2 && ref.expected_size_variance > 0.0) {
        double sum = 0.0;
        for (size_t s : current_window_.packet_sizes) sum += static_cast<double>(s);
        double mean = sum / static_cast<double>(current_window_.packet_sizes.size());
        double var = 0.0;
        for (size_t s : current_window_.packet_sizes) {
            double d = static_cast<double>(s) - mean;
            var += d * d;
        }
        var /= static_cast<double>(current_window_.packet_sizes.size());
        scores.size_variance_ratio = var / ref.expected_size_variance;
    } else {
        scores.size_variance_ratio = 1.0;
    }

    // 5. Timing CoV
    if (!current_window_.inter_arrival_times.empty()) {
        double observed_cov = timing_coefficient_of_variation(
            current_window_.inter_arrival_times);
        if (ref.expected_timing_cov > 0.0) {
            scores.timing_cov = std::fabs(observed_cov - ref.expected_timing_cov)
                              / ref.expected_timing_cov;
        } else {
            scores.timing_cov = observed_cov;
        }
    } else {
        scores.timing_cov = 0.0;
    }

    // 6. Burst anomaly
    scores.burst_anomaly = burst_anomaly_score(
        current_window_.inter_arrival_times,
        ref.expected_burst_ratio);

    // Build report
    TestReport report;
    report.scores = scores;
    report.snapshot = current_window_;
    report.strategy_tested = current_strategy_;
    report.timestamp = std::chrono::steady_clock::now();
    report.detected = (scores.aggregate_stealth() < config_.detection_threshold);

    // Update stats
    stats_.evaluations_run++;
    if (report.detected) stats_.detections_triggered++;
    update_running_stats(scores.aggregate_stealth());

    // History
    history_.push_back(report);
    while (history_.size() > config_.history_size) {
        history_.pop_front();
    }

    // Reset window
    current_window_ = FlowSnapshot{};

    // Return pending feedback (caller fires it outside lock)
    if (config_.auto_feedback) {
        stats_.feedbacks_sent++;
        return scores.to_feedback(current_strategy_);
    }

    return std::nullopt;
}

// ══════════════════════════════════════════════════════════
// Manual Evaluation
// ══════════════════════════════════════════════════════════

HeuristicScores AdversaryTester::evaluate_packet(
    const std::vector<uint8_t>& payload) const
{
    HeuristicScores scores{};
    if (payload.empty()) return scores;

    scores.entropy_score = shannon_entropy(payload.data(), payload.size());
    scores.chi_squared_pvalue = chi_squared_uniformity(payload.data(), payload.size());
    scores.ks_distance = 0.0;
    scores.size_variance_ratio = 1.0;
    scores.timing_cov = 0.0;
    scores.burst_anomaly = 0.0;

    return scores;
}

TestReport AdversaryTester::evaluate_flow() {
    // FIX: No longer mutates config_. Uses force flag instead.
    std::optional<DetectionFeedback> pending_feedback;
    FeedbackCallback cb_copy;
    TestReport result;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (current_window_.packet_count == 0) {
            TestReport empty;
            empty.detected = false;
            empty.timestamp = std::chrono::steady_clock::now();
            empty.strategy_tested = current_strategy_;
            return empty;
        }

        pending_feedback = evaluate_window_locked(true);  // force=true
        cb_copy = feedback_cb_;

        if (!history_.empty()) {
            result = history_.back();
        } else {
            result.detected = false;
            result.timestamp = std::chrono::steady_clock::now();
        }
    }
    // mutex_ released

    if (pending_feedback && cb_copy) {
        cb_copy(*pending_feedback);
    }

    return result;
}

TestReport AdversaryTester::run_strategy_benchmark(
    AdversarialStrategy strategy,
    AdversarialPadding& padder,
    size_t num_samples)
{
    // Generate random payloads, pad them, collect metrics, evaluate.
    // NOTE: Timing is synthetic uniform [100μs, 50ms]. Phase 2 should
    // use recorded flow replays for realistic burst/timing analysis.
    FlowSnapshot bench_flow;

    double entropy_sum = 0.0;
    double chi2_sum = 0.0;

    for (size_t i = 0; i < num_samples; ++i) {
        size_t payload_size = static_cast<size_t>(ncp::csprng_range(50, 1400));
        std::vector<uint8_t> payload(payload_size);
        ncp::csprng_fill(payload);

        auto padded = padder.pad(payload);

        bench_flow.packet_sizes.push_back(padded.size());
        bench_flow.total_bytes += padded.size();
        bench_flow.packet_count++;

        // Per-packet content metrics
        if (!padded.empty()) {
            entropy_sum += shannon_entropy(padded.data(), padded.size());
            chi2_sum += chi_squared_uniformity(padded.data(), padded.size());
        }

        // Synthetic timing
        if (i > 0) {
            auto delta = std::chrono::microseconds(
                ncp::csprng_range(100, 50000));
            bench_flow.inter_arrival_times.push_back(delta);
        }
    }

    bench_flow.running_entropy_sum = entropy_sum;
    bench_flow.running_chi2_sum = chi2_sum;
    bench_flow.content_samples = num_samples;

    // Compute scores
    std::lock_guard<std::mutex> lock(mutex_);
    ReferenceProfile ref = current_reference();

    HeuristicScores scores{};

    // Content entropy & chi2 from actual padded bytes
    scores.entropy_score = (num_samples > 0)
        ? entropy_sum / static_cast<double>(num_samples) : 0.0;
    scores.chi_squared_pvalue = (num_samples > 0)
        ? chi2_sum / static_cast<double>(num_samples) : 0.0;

    scores.ks_distance = ks_distance(bench_flow.packet_sizes, ref);

    // Size variance
    if (bench_flow.packet_sizes.size() >= 2 && ref.expected_size_variance > 0.0) {
        double sum = 0.0;
        for (size_t s : bench_flow.packet_sizes) sum += static_cast<double>(s);
        double mean = sum / static_cast<double>(bench_flow.packet_sizes.size());
        double var = 0.0;
        for (size_t s : bench_flow.packet_sizes) {
            double d = static_cast<double>(s) - mean;
            var += d * d;
        }
        var /= static_cast<double>(bench_flow.packet_sizes.size());
        scores.size_variance_ratio = var / ref.expected_size_variance;
    } else {
        scores.size_variance_ratio = 1.0;
    }

    scores.timing_cov = timing_coefficient_of_variation(bench_flow.inter_arrival_times);
    scores.burst_anomaly = burst_anomaly_score(
        bench_flow.inter_arrival_times, ref.expected_burst_ratio);

    TestReport report;
    report.scores = scores;
    report.snapshot = bench_flow;
    report.strategy_tested = strategy;
    report.timestamp = std::chrono::steady_clock::now();
    report.detected = (scores.aggregate_stealth() < config_.detection_threshold);

    return report;
}

// ══════════════════════════════════════════════════════════
// Internal Helpers
// ══════════════════════════════════════════════════════════

ReferenceProfile AdversaryTester::current_reference() const {
    return ReferenceProfile::for_flow_profile(config_.reference_profile);
}

void AdversaryTester::update_running_stats(double stealth) {
    if (stats_.evaluations_run <= 1) {
        stats_.avg_stealth_score = stealth;
    } else {
        stats_.avg_stealth_score = 0.9 * stats_.avg_stealth_score + 0.1 * stealth;
    }
    if (stealth < stats_.min_stealth_score) stats_.min_stealth_score = stealth;
    if (stealth > stats_.max_stealth_score) stats_.max_stealth_score = stealth;
}

} // namespace DPI
} // namespace ncp
