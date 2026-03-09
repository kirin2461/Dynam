/**
 * @file ncp_self_test_monitor.cpp
 * @brief SelfTestMonitor implementation
 *
 * Background thread runs 5 self-attack tests every test_interval seconds
 * (or 60 s at HIGH threat). Failed tests trigger countermeasure logging
 * and optional FailureCallback.
 */

#include "ncp_self_test_monitor.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <sstream>
#include <cmath>
#include <numeric>
#include <array>

namespace ncp {

// =====================================================================
// SelfTestMonitorStats
// =====================================================================

void SelfTestMonitorStats::reset() noexcept {
    tests_run.store(0);
    tests_passed.store(0);
    tests_failed.store(0);
    countermeasures_applied.store(0);
    consecutive_failures.store(0);
}

// =====================================================================
// Construction / Destruction
// =====================================================================

SelfTestMonitor::SelfTestMonitor() {
    config_.enabled = Config::instance().getBool("self_test.enabled", true);
    int interval_s  = Config::instance().getInt("self_test.interval_s", 300);
    config_.test_interval       = std::chrono::seconds(interval_s);
    config_.fail_threshold      = 0.6;
    config_.auto_countermeasure = Config::instance().getBool(
        "self_test.auto_countermeasure", true);
    config_.notify_on_fail      = true;

    NCP_LOG_DEBUG("SelfTestMonitor: initialized (default config)");
}

SelfTestMonitor::SelfTestMonitor(const SelfTestMonitorConfig& cfg)
    : config_(cfg)
{
    NCP_LOG_DEBUG("SelfTestMonitor: initialized (custom config)");
}

SelfTestMonitor::~SelfTestMonitor() {
    stop();
}

// =====================================================================
// Accessors
// =====================================================================

void SelfTestMonitor::set_config(const SelfTestMonitorConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
}

SelfTestMonitorConfig SelfTestMonitor::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

SelfTestMonitorStats SelfTestMonitor::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void SelfTestMonitor::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
}

void SelfTestMonitor::set_threat_level(ncp::DPI::ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    threat_level_ = level;
    NCP_LOG_DEBUG("SelfTestMonitor: threat level set to " +
        std::to_string(static_cast<int>(level)));
}

void SelfTestMonitor::set_failure_callback(FailureCallback cb) {
    std::lock_guard<std::mutex> lock(mutex_);
    failure_callback_ = std::move(cb);
}

std::vector<SelfTestResult> SelfTestMonitor::get_last_results() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_results_;
}

// =====================================================================
// effective_interval_
// =====================================================================

std::chrono::seconds SelfTestMonitor::effective_interval_() const {
    // Called under lock
    if (threat_level_ >= ncp::DPI::ThreatLevel::HIGH) {
        return std::chrono::seconds(60);
    }
    return config_.test_interval;
}

// =====================================================================
// Background thread management
// =====================================================================

void SelfTestMonitor::start() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!config_.enabled) {
            NCP_LOG_INFO("SelfTestMonitor: disabled in config, not starting");
            return;
        }
    }

    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        NCP_LOG_WARN("SelfTestMonitor: already running");
        return;
    }

    monitor_thread_ = std::thread(&SelfTestMonitor::monitor_loop_, this);
    NCP_LOG_INFO("SelfTestMonitor: background thread started");
}

void SelfTestMonitor::stop() {
    running_.store(false);
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
        NCP_LOG_INFO("SelfTestMonitor: background thread stopped");
    }
}

bool SelfTestMonitor::is_running() const {
    return running_.load();
}

// =====================================================================
// monitor_loop_
// =====================================================================

void SelfTestMonitor::monitor_loop_() {
    NCP_LOG_DEBUG("SelfTestMonitor: monitor_loop_ starting");

    auto next_run = std::chrono::steady_clock::now();

    while (running_.load()) {
        auto now = std::chrono::steady_clock::now();

        if (now >= next_run) {
            NCP_LOG_DEBUG("SelfTestMonitor: running periodic self-tests");
            auto results = run_all_tests();

            // Compute next run time using the (possibly reduced) interval
            {
                std::lock_guard<std::mutex> lock(mutex_);
                next_run = std::chrono::steady_clock::now() + effective_interval_();
            }
        }

        // Sleep in 250ms chunks for responsive shutdown
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    NCP_LOG_DEBUG("SelfTestMonitor: monitor_loop_ exiting");
}

// =====================================================================
// run_all_tests
// =====================================================================

std::vector<SelfTestResult> SelfTestMonitor::run_all_tests() {
    std::vector<SelfTestResult> results;
    results.reserve(5);

    const std::array<SelfTestType, 5> types = {
        SelfTestType::ENTROPY_CHECK,
        SelfTestType::TIMING_ANALYSIS,
        SelfTestType::SIZE_DISTRIBUTION,
        SelfTestType::FINGERPRINT_CHECK,
        SelfTestType::DNS_LEAK_CHECK
    };

    for (auto t : types) {
        results.push_back(run_test(t));
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        last_results_ = results;
    }
    return results;
}

// =====================================================================
// run_test
// =====================================================================

SelfTestResult SelfTestMonitor::run_test(SelfTestType type) {
    SelfTestResult result;

    // Dispatch
    switch (type) {
    case SelfTestType::ENTROPY_CHECK:
        result = test_entropy_();
        break;
    case SelfTestType::TIMING_ANALYSIS:
        result = test_timing_();
        break;
    case SelfTestType::SIZE_DISTRIBUTION:
        result = test_size_distribution_();
        break;
    case SelfTestType::FINGERPRINT_CHECK:
        result = test_fingerprint_();
        break;
    case SelfTestType::DNS_LEAK_CHECK:
        result = test_dns_leak_();
        break;
    }

    // Update stats
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.tests_run.fetch_add(1);

        double threshold = config_.fail_threshold;
        if (result.score < threshold) {
            result.passed = false;
            stats_.tests_failed.fetch_add(1);
            stats_.consecutive_failures.fetch_add(1);

            NCP_LOG_WARN("SelfTestMonitor: test FAILED — " +
                result.test_name + " score=" +
                std::to_string(result.score) + " detail=" + result.detail);

            if (config_.auto_countermeasure) {
                // apply_countermeasure acquires mutex_ itself — we must release first
            }
            if (config_.notify_on_fail && failure_callback_) {
                // Similarly release lock before calling
            }
        } else {
            result.passed = true;
            stats_.tests_passed.fetch_add(1);
            stats_.consecutive_failures.store(0);

            NCP_LOG_DEBUG("SelfTestMonitor: test PASSED — " +
                result.test_name + " score=" + std::to_string(result.score));
        }
    }

    // Now apply countermeasure and callback (outside mutex to avoid deadlock)
    if (!result.passed) {
        if (get_config().auto_countermeasure) {
            apply_countermeasure(result);
        }
        FailureCallback cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = failure_callback_;
        }
        if (cb) {
            cb(result);
        }
    }

    return result;
}

// =====================================================================
// feed_packet
// =====================================================================

void SelfTestMonitor::feed_packet(const std::vector<uint8_t>& data,
                                   double inter_arrival_ms)
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Compute and store Shannon entropy of this packet
    if (!data.empty()) {
        double e = compute_entropy_(data);
        if (recent_packet_entropies_.size() >= MAX_SAMPLES) {
            recent_packet_entropies_.erase(recent_packet_entropies_.begin());
        }
        recent_packet_entropies_.push_back(e);
    }

    // Store inter-arrival time
    if (inter_arrival_ms >= 0.0) {
        if (recent_inter_arrival_ms_.size() >= MAX_SAMPLES) {
            recent_inter_arrival_ms_.erase(recent_inter_arrival_ms_.begin());
        }
        recent_inter_arrival_ms_.push_back(inter_arrival_ms);
    }

    // Store packet size
    if (!data.empty()) {
        if (recent_packet_sizes_.size() >= MAX_SAMPLES) {
            recent_packet_sizes_.erase(recent_packet_sizes_.begin());
        }
        recent_packet_sizes_.push_back(data.size());
    }
}

// =====================================================================
// apply_countermeasure
// =====================================================================

void SelfTestMonitor::apply_countermeasure(const SelfTestResult& result) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stats_.countermeasures_applied.fetch_add(1);
    }

    NCP_LOG_INFO("SelfTestMonitor: applying countermeasure for " +
        result.test_name + " — " + result.countermeasure);

    switch (result.type) {
    case SelfTestType::ENTROPY_CHECK:
        NCP_LOG_INFO("SelfTestMonitor [COUNTERMEASURE]: "
            "Enable/increase adversarial padding to normalise entropy. "
            "Consider switching to constant-byte padding.");
        break;

    case SelfTestType::TIMING_ANALYSIS:
        NCP_LOG_INFO("SelfTestMonitor [COUNTERMEASURE]: "
            "Enable Tamaraw WF defense or increase jitter in FlowShaper. "
            "Target CV > 0.3 for inter-arrival times.");
        break;

    case SelfTestType::SIZE_DISTRIBUTION:
        NCP_LOG_INFO("SelfTestMonitor [COUNTERMEASURE]: "
            "Enable packet size normalization in WFDefense. "
            "Pad all packets to fixed MTU size.");
        break;

    case SelfTestType::FINGERPRINT_CHECK:
        NCP_LOG_INFO("SelfTestMonitor [COUNTERMEASURE]: "
            "Rotate TLS browser fingerprint profile. "
            "Verify TLSFingerprint module is active.");
        break;

    case SelfTestType::DNS_LEAK_CHECK:
        NCP_LOG_INFO("SelfTestMonitor [COUNTERMEASURE]: "
            "All DNS queries must use DoH. "
            "Verify ncp_doh and ncp_dns_leak_prevention are active.");
        break;
    }
}

// =====================================================================
// Static helper: compute_entropy_
// =====================================================================

double SelfTestMonitor::compute_entropy_(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;

    std::array<uint64_t, 256> freq{};
    freq.fill(0);
    for (uint8_t b : data) ++freq[b];

    double entropy = 0.0;
    double n = static_cast<double>(data.size());
    for (uint64_t f : freq) {
        if (f == 0) continue;
        double p = static_cast<double>(f) / n;
        entropy -= p * std::log2(p);
    }
    return entropy; // bits, range [0, 8]
}

// =====================================================================
// Static helper: mean_
// =====================================================================

double SelfTestMonitor::mean_(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double sum = std::accumulate(v.begin(), v.end(), 0.0);
    return sum / static_cast<double>(v.size());
}

// =====================================================================
// Static helper: stddev_
// =====================================================================

double SelfTestMonitor::stddev_(const std::vector<double>& v, double m) {
    if (v.size() < 2) return 0.0;
    double accum = 0.0;
    for (double x : v) {
        double d = x - m;
        accum += d * d;
    }
    return std::sqrt(accum / static_cast<double>(v.size() - 1));
}

// =====================================================================
// test_entropy_
// =====================================================================

SelfTestResult SelfTestMonitor::test_entropy_() {
    SelfTestResult r;
    r.type      = SelfTestType::ENTROPY_CHECK;
    r.test_name = "EntropyCheck";
    r.timestamp = std::chrono::steady_clock::now();
    r.countermeasure =
        "Increase adversarial padding to raise entropy toward 7.5–8.0 bits/byte";

    std::vector<double> samples;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        samples = recent_packet_entropies_;
    }

    if (samples.size() < 10) {
        // Not enough data — pass by default
        r.score  = 1.0;
        r.detail = "Insufficient samples (" + std::to_string(samples.size()) + ")";
        return r;
    }

    double avg_entropy = mean_(samples);

    // Expected encrypted range: 7.5 – 8.0 bits/byte
    const double LOW  = 7.5;
    const double HIGH = 8.0;

    if (avg_entropy >= LOW && avg_entropy <= HIGH) {
        r.score  = 1.0;
        r.detail = "avg_entropy=" + std::to_string(avg_entropy) + " (in range)";
    } else if (avg_entropy < LOW) {
        // Score drops linearly from 1.0 at LOW to 0.0 at LOW-1.0
        double deficit = LOW - avg_entropy;
        r.score  = std::max(0.0, 1.0 - deficit);
        r.detail = "avg_entropy=" + std::to_string(avg_entropy) +
                   " below expected minimum " + std::to_string(LOW);
    } else {
        // avg_entropy > 8.0 — theoretically impossible, but handle gracefully
        r.score  = 0.9;
        r.detail = "avg_entropy=" + std::to_string(avg_entropy) +
                   " above 8.0 (unusual)";
    }
    return r;
}

// =====================================================================
// test_timing_
// =====================================================================

SelfTestResult SelfTestMonitor::test_timing_() {
    SelfTestResult r;
    r.type      = SelfTestType::TIMING_ANALYSIS;
    r.test_name = "TimingAnalysis";
    r.timestamp = std::chrono::steady_clock::now();
    r.countermeasure =
        "Enable Tamaraw WF defense; increase jitter in FlowShaper to raise CV above 0.3";

    std::vector<double> samples;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        samples = recent_inter_arrival_ms_;
    }

    if (samples.size() < 10) {
        r.score  = 1.0;
        r.detail = "Insufficient samples (" + std::to_string(samples.size()) + ")";
        return r;
    }

    double m  = mean_(samples);
    double sd = stddev_(samples, m);
    double cv = (m > 0.0) ? (sd / m) : 0.0;

    // Traffic should NOT be too regular (CV < 0.2 is suspicious)
    // But also should not be wildly variable.
    // Score drops as CV falls below 0.2.
    const double MIN_CV = 0.2;
    const double IDEAL_CV = 0.5;

    if (cv >= MIN_CV) {
        // Good variability — score 1.0 at IDEAL_CV, slightly less outside
        double deviation = std::abs(cv - IDEAL_CV);
        r.score = std::max(0.7, 1.0 - deviation * 0.2);
        r.detail = "CV=" + std::to_string(cv) + " mean_ms=" + std::to_string(m);
    } else {
        // Too regular
        double deficit = MIN_CV - cv;
        r.score = std::max(0.0, 1.0 - deficit / MIN_CV);
        r.detail = "CV=" + std::to_string(cv) + " < threshold=" +
                   std::to_string(MIN_CV) + " (too regular)";
    }
    return r;
}

// =====================================================================
// test_size_distribution_
// =====================================================================

SelfTestResult SelfTestMonitor::test_size_distribution_() {
    SelfTestResult r;
    r.type      = SelfTestType::SIZE_DISTRIBUTION;
    r.test_name = "SizeDistribution";
    r.timestamp = std::chrono::steady_clock::now();
    r.countermeasure =
        "Enable WFDefense packet-size normalization; target bimodal "
        "distribution (~100B ACKs + ~1400B data segments)";

    std::vector<size_t> samples;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        samples = recent_packet_sizes_;
    }

    if (samples.size() < 10) {
        r.score  = 1.0;
        r.detail = "Insufficient samples (" + std::to_string(samples.size()) + ")";
        return r;
    }

    // Count packets in ACK range (~40–200 B) and data range (~900–1500 B)
    size_t ack_count  = 0;
    size_t data_count = 0;
    size_t other_count = 0;
    for (size_t sz : samples) {
        if (sz >= 40 && sz <= 200)   ++ack_count;
        else if (sz >= 900 && sz <= 1500) ++data_count;
        else ++other_count;
    }

    double n     = static_cast<double>(samples.size());
    double bimod = static_cast<double>(ack_count + data_count) / n;

    // Ideally 80%+ in bimodal ranges
    const double BIMOD_TARGET = 0.8;
    if (bimod >= BIMOD_TARGET) {
        r.score  = 1.0;
        r.detail = "bimodal_ratio=" + std::to_string(bimod) +
                   " ack=" + std::to_string(ack_count) +
                   " data=" + std::to_string(data_count);
    } else {
        r.score  = bimod / BIMOD_TARGET;
        r.detail = "bimodal_ratio=" + std::to_string(bimod) +
                   " < " + std::to_string(BIMOD_TARGET) +
                   " other_count=" + std::to_string(other_count);
    }
    return r;
}

// =====================================================================
// test_fingerprint_ (placeholder)
// =====================================================================

SelfTestResult SelfTestMonitor::test_fingerprint_() {
    SelfTestResult r;
    r.type      = SelfTestType::FINGERPRINT_CHECK;
    r.test_name = "FingerprintCheck";
    r.timestamp = std::chrono::steady_clock::now();
    r.score     = 1.0;
    r.detail    = "TLS fingerprint check requires live TLS state — placeholder always passes";
    r.countermeasure =
        "Rotate TLS browser fingerprint profile via TLSFingerprint module";
    return r;
}

// =====================================================================
// test_dns_leak_ (placeholder)
// =====================================================================

SelfTestResult SelfTestMonitor::test_dns_leak_() {
    SelfTestResult r;
    r.type      = SelfTestType::DNS_LEAK_CHECK;
    r.test_name = "DNSLeakCheck";
    r.timestamp = std::chrono::steady_clock::now();
    r.countermeasure =
        "Ensure all DNS queries route through DoH (ncp_doh). "
        "Verify ncp_dns_leak_prevention is active.";

    // Placeholder: assume DoH is active if doh_enabled config is set
    bool doh_enabled = Config::instance().getBool("dns.doh_enabled", true);
    if (doh_enabled) {
        r.score  = 0.9; // Non-perfect: we can't verify without intercepting live traffic
        r.detail = "dns.doh_enabled=true (assumed, not verified)";
    } else {
        r.score  = 0.0;
        r.detail = "dns.doh_enabled=false — DNS leaks likely!";
        NCP_LOG_WARN("SelfTestMonitor: DNS leak check failed — DoH disabled");
    }
    return r;
}

} // namespace ncp
