/**
 * @file ncp_adversary_tester.cpp
 * @brief Shadow Classifier / Adversary Tester — Phase 1 ML Pipeline
 *
 * Implements 6 heuristic detectors that approximate what TSPU statistical
 * engines check before escalating to ET-BERT / deep learning classifiers.
 *
 * No external dependencies beyond libsodium (via ncp_csprng.hpp).
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
    // Typical HTTPS web browsing size distribution (CDF at bucket boundaries)
    p.size_buckets = {64, 128, 256, 512, 1024, 1460};
    p.size_cdf     = {0.35, 0.52, 0.68, 0.82, 0.93, 1.0};
    p.expected_size_variance = 180000.0;  // high variance in web traffic
    p.expected_timing_cov = 1.8;          // bursty, high CoV
    p.expected_burst_ratio = 8.0;
    return p;
}

ReferenceProfile ReferenceProfile::video_stream() {
    ReferenceProfile p;
    p.name = "video_stream";
    p.size_buckets = {64, 128, 256, 512, 1024, 1460};
    p.size_cdf     = {0.05, 0.08, 0.12, 0.20, 0.45, 1.0};
    p.expected_size_variance = 120000.0;
    p.expected_timing_cov = 0.3;          // very regular
    p.expected_burst_ratio = 2.0;
    return p;
}

ReferenceProfile ReferenceProfile::messenger() {
    ReferenceProfile p;
    p.name = "messenger";
    p.size_buckets = {64, 128, 256, 512, 1024, 1460};
    p.size_cdf     = {0.55, 0.78, 0.90, 0.96, 0.99, 1.0};
    p.expected_size_variance = 8000.0;
    p.expected_timing_cov = 2.5;          // very sporadic
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
    if (!data || len < 16) return 0.0;  // Too short for meaningful test

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

    // Approximate p-value using Wilson-Hilferty normal approximation
    // for chi-squared with k=255 degrees of freedom.
    // X ~ N(0,1) where X = ((chi2/k)^(1/3) - (1 - 2/(9k))) / sqrt(2/(9k))
    double k = 255.0;
    double term = 2.0 / (9.0 * k);
    double z = (std::cbrt(chi2 / k) - (1.0 - term)) / std::sqrt(term);

    // Standard normal CDF approximation (Abramowitz & Stegun 7.1.26)
    // P(Z > z) = 1 - Φ(z)
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

    // D = max |F_empirical(x) - F_reference(x)|
    double max_d = 0.0;
    for (size_t i = 0; i < empirical_cdf.size() && i < reference.size_cdf.size(); ++i) {
        double d = std::fabs(empirical_cdf[i] - reference.size_cdf[i]);
        if (d > max_d) max_d = d;
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
    if (mean < 1.0) return 0.0;  // Avoid division by near-zero

    double var_sum = 0.0;
    for (const auto& t : times) {
        double diff = static_cast<double>(t.count()) - mean;
        var_sum += diff * diff;
    }
    double stddev = std::sqrt(var_sum / static_cast<double>(times.size()));

    return stddev / mean;  // coefficient of variation
}

double AdversaryTester::burst_anomaly_score(
    const std::vector<std::chrono::microseconds>& times,
    double reference_burst_ratio)
{
    if (times.size() < 5 || reference_burst_ratio <= 0.0) return 0.0;

    // Define a burst: consecutive packets with inter-arrival < 10ms
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

    // Average packet rate (packets per second)
    double total_us = 0.0;
    for (const auto& t : times) total_us += static_cast<double>(t.count());
    double avg_rate = (total_us > 0.0)
        ? static_cast<double>(times.size()) / (total_us / 1e6)
        : 1.0;

    double observed_ratio = (avg_rate > 0.0)
        ? static_cast<double>(max_burst) / avg_rate
        : 0.0;

    // Anomaly = normalized deviation from reference
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

    // Auto-evaluate when window is full
    if (current_window_.packet_count >= config_.window_packets) {
        try_auto_evaluate();
    }
}

void AdversaryTester::try_auto_evaluate() {
    // Note: caller must hold mutex_
    ReferenceProfile ref = current_reference();

    // Compute heuristic scores from current window
    HeuristicScores scores{};

    // 1. Shannon entropy — aggregate all packet bytes from sizes
    //    (We don't have raw bytes in the window, so use size distribution entropy
    //     as proxy. For per-packet entropy, call evaluate_packet() directly.)
    //    Use size distribution as a proxy for content entropy:
    //    convert sizes to a byte array and measure.
    {
        std::vector<uint8_t> size_bytes;
        size_bytes.reserve(current_window_.packet_sizes.size() * 2);
        for (size_t s : current_window_.packet_sizes) {
            size_bytes.push_back(static_cast<uint8_t>(s & 0xFF));
            size_bytes.push_back(static_cast<uint8_t>((s >> 8) & 0xFF));
        }
        if (!size_bytes.empty()) {
            scores.entropy_score = shannon_entropy(size_bytes.data(), size_bytes.size());
        }
    }

    // 2. Chi-squared — same proxy
    {
        std::vector<uint8_t> size_bytes;
        size_bytes.reserve(current_window_.packet_sizes.size() * 2);
        for (size_t s : current_window_.packet_sizes) {
            size_bytes.push_back(static_cast<uint8_t>(s & 0xFF));
            size_bytes.push_back(static_cast<uint8_t>((s >> 8) & 0xFF));
        }
        if (size_bytes.size() >= 16) {
            scores.chi_squared_pvalue = chi_squared_uniformity(
                size_bytes.data(), size_bytes.size());
        }
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
        // Anomaly = deviation from expected CoV
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

    // Build test report
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

    // Store in history
    history_.push_back(report);
    while (history_.size() > config_.history_size) {
        history_.pop_front();
    }

    // Auto-feedback
    if (config_.auto_feedback && feedback_cb_) {
        DetectionFeedback fb = scores.to_feedback(current_strategy_);
        stats_.feedbacks_sent++;
        // Call feedback outside of our own logic to keep it simple
        // (callback may call back into AdversarialPadding which has its own mutex)
        FeedbackCallback cb = feedback_cb_;
        // Release lock before calling external code? No — we document that
        // callback must not call back into AdversaryTester.
        // For Phase 2, this will be decoupled via a queue.
        cb(fb);
    }

    // Reset window for next batch
    current_window_ = FlowSnapshot{};
}

// ══════════════════════════════════════════════════════════
// Manual Evaluation
// ══════════════════════════════════════════════════════════

HeuristicScores AdversaryTester::evaluate_packet(
    const std::vector<uint8_t>& payload) const
{
    HeuristicScores scores{};

    if (payload.empty()) return scores;

    // Per-packet: only entropy and chi-squared are meaningful
    scores.entropy_score = shannon_entropy(payload.data(), payload.size());
    scores.chi_squared_pvalue = chi_squared_uniformity(payload.data(), payload.size());

    // Flow metrics not applicable to single packet
    scores.ks_distance = 0.0;
    scores.size_variance_ratio = 1.0;
    scores.timing_cov = 0.0;
    scores.burst_anomaly = 0.0;

    return scores;
}

TestReport AdversaryTester::evaluate_flow() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Force evaluation of current window even if not full
    if (current_window_.packet_count == 0) {
        TestReport empty;
        empty.detected = false;
        empty.timestamp = std::chrono::steady_clock::now();
        empty.strategy_tested = current_strategy_;
        return empty;
    }

    // Save window (try_auto_evaluate resets it)
    size_t saved_window = config_.window_packets;
    config_.window_packets = 0;  // Force eval
    try_auto_evaluate();
    config_.window_packets = saved_window;

    if (!history_.empty()) {
        return history_.back();
    }

    TestReport empty;
    empty.detected = false;
    empty.timestamp = std::chrono::steady_clock::now();
    return empty;
}

TestReport AdversaryTester::run_strategy_benchmark(
    AdversarialStrategy strategy,
    AdversarialPadding& padder,
    size_t num_samples)
{
    // Generate random payloads, pad them, collect in a window, evaluate
    FlowSnapshot bench_flow;
    auto t_prev = std::chrono::steady_clock::now();

    std::vector<uint8_t> all_padded_bytes;
    all_padded_bytes.reserve(num_samples * 256);

    for (size_t i = 0; i < num_samples; ++i) {
        // Random payload 50-1400 bytes
        size_t payload_size = static_cast<size_t>(ncp::csprng_range(50, 1400));
        std::vector<uint8_t> payload(payload_size);
        ncp::csprng_fill(payload);

        // Apply adversarial padding
        auto padded = padder.pad(payload);

        bench_flow.packet_sizes.push_back(padded.size());
        bench_flow.total_bytes += padded.size();
        bench_flow.packet_count++;

        // Simulate timing (100us - 50ms jitter)
        auto now = std::chrono::steady_clock::now();
        if (i > 0) {
            auto delta = std::chrono::microseconds(
                ncp::csprng_range(100, 50000));
            bench_flow.inter_arrival_times.push_back(delta);
        }

        // Collect bytes for entropy/chi2
        all_padded_bytes.insert(all_padded_bytes.end(),
            padded.begin(), padded.end());
    }

    // Compute scores
    std::lock_guard<std::mutex> lock(mutex_);
    ReferenceProfile ref = current_reference();

    HeuristicScores scores{};
    if (!all_padded_bytes.empty()) {
        scores.entropy_score = shannon_entropy(
            all_padded_bytes.data(), all_padded_bytes.size());
        scores.chi_squared_pvalue = chi_squared_uniformity(
            all_padded_bytes.data(), all_padded_bytes.size());
    }
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
    // Note: caller must hold mutex_
    return ReferenceProfile::for_flow_profile(config_.reference_profile);
}

void AdversaryTester::update_running_stats(double stealth) {
    // Note: caller must hold mutex_
    if (stats_.evaluations_run <= 1) {
        stats_.avg_stealth_score = stealth;
    } else {
        // Exponential moving average (α = 0.1)
        stats_.avg_stealth_score = 0.9 * stats_.avg_stealth_score + 0.1 * stealth;
    }
    if (stealth < stats_.min_stealth_score) stats_.min_stealth_score = stealth;
    if (stealth > stats_.max_stealth_score) stats_.max_stealth_score = stealth;
}

} // namespace DPI
} // namespace ncp
