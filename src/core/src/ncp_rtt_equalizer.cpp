/**
 * @file ncp_rtt_equalizer.cpp
 * @brief RTT Equalizer implementation — Phase 5 dMAP Defense
 *
 * Delays ACKs so (App_RTT - TCP_RTT) matches normal HTTPS browsing (~2ms),
 * defeating dMAP-style fingerprinting that achieves ~96% VPN detection
 * accuracy by exploiting this discrepancy.
 */

#include "ncp_rtt_equalizer.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>
#include <vector>

namespace ncp {
namespace DPI {

// ===== Constructors =====

RTTEqualizer::RTTEqualizer() {
    NCP_LOG_DEBUG("[RTTEqualizer] Initialized with default config");
}

RTTEqualizer::RTTEqualizer(const RTTEqualizerConfig& cfg)
    : config_(cfg)
{
    NCP_LOG_DEBUG("[RTTEqualizer] Initialized with custom config"
                  " (target_overhead=" + std::to_string(cfg.target_rtt_overhead_ms) + "ms)");
}

// ===== Public API =====

void RTTEqualizer::record_tcp_rtt(double rtt_ms) {
    if (rtt_ms <= 0.0) return;

    std::lock_guard<std::mutex> lock(mutex_);

    RTTSample s;
    s.timestamp = std::chrono::steady_clock::now();
    s.rtt_ms = rtt_ms;
    tcp_rtt_samples_.push_back(s);
    trim_samples_(tcp_rtt_samples_);
    stats_.samples_collected.fetch_add(1, std::memory_order_relaxed);

    if (config_.adaptive_mode) {
        adaptive_adjust_();
    }
}

void RTTEqualizer::record_app_rtt(double rtt_ms) {
    if (rtt_ms <= 0.0) return;

    std::lock_guard<std::mutex> lock(mutex_);

    RTTSample s;
    s.timestamp = std::chrono::steady_clock::now();
    s.rtt_ms = rtt_ms;
    app_rtt_samples_.push_back(s);
    trim_samples_(app_rtt_samples_);
    stats_.samples_collected.fetch_add(1, std::memory_order_relaxed);

    if (config_.adaptive_mode) {
        adaptive_adjust_();
    }
}

std::chrono::microseconds RTTEqualizer::compute_ack_delay(const std::string& flow_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return std::chrono::microseconds(0);
    }

    double tcp_med  = compute_median_(tcp_rtt_samples_);
    double app_med  = compute_median_(app_rtt_samples_);

    // Effective target overhead, adjusted for threat level
    double effective_target = config_.target_rtt_overhead_ms;
    double effective_jitter = config_.rtt_jitter_ms;

    if (threat_level_ >= ThreatLevel::HIGH) {
        // At HIGH+ threat: increase jitter, reduce target overhead
        // to make timing look more "random and natural"
        effective_jitter = config_.rtt_jitter_ms * 2.5;
        effective_target = config_.target_rtt_overhead_ms * 0.75;
    } else if (threat_level_ == ThreatLevel::MEDIUM) {
        effective_jitter = config_.rtt_jitter_ms * 1.5;
    }

    double gap = (app_med > 0.0 && tcp_med > 0.0) ? (app_med - tcp_med) : 0.0;

    double delay_ms = 0.0;
    if (gap >= effective_target) {
        // Gap already looks natural — no delay needed, only tiny jitter
        delay_ms = csprng_double_range(0.0, effective_jitter * 0.3);
    } else {
        // Bridge the gap + add jitter
        double shortfall  = effective_target - gap;
        double jitter_val = csprng_double_range(-effective_jitter, effective_jitter);
        delay_ms = shortfall + jitter_val;
    }

    // Apply bounds
    delay_ms = std::max(config_.min_delay_ms, std::min(config_.max_delay_ms, delay_ms));

    auto delay_us = static_cast<int64_t>(delay_ms * 1000.0);
    if (delay_us <= 0) {
        return std::chrono::microseconds(0);
    }

    stats_.acks_delayed.fetch_add(1, std::memory_order_relaxed);
    stats_.total_delay_us.fetch_add(static_cast<uint64_t>(delay_us), std::memory_order_relaxed);

    std::ostringstream oss;
    oss << "[RTTEqualizer] flow=" << flow_key
        << " tcp_med=" << tcp_med << "ms"
        << " app_med=" << app_med << "ms"
        << " gap=" << gap << "ms"
        << " delay=" << delay_ms << "ms";
    NCP_LOG_DEBUG(oss.str());

    return std::chrono::microseconds(delay_us);
}

double RTTEqualizer::get_estimated_tcp_rtt_ms() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return compute_median_(tcp_rtt_samples_);
}

double RTTEqualizer::get_estimated_app_rtt_ms() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return compute_median_(app_rtt_samples_);
}

double RTTEqualizer::get_current_gap_ms() const {
    std::lock_guard<std::mutex> lock(mutex_);
    double tcp_med = compute_median_(tcp_rtt_samples_);
    double app_med = compute_median_(app_rtt_samples_);
    if (tcp_med <= 0.0 || app_med <= 0.0) return 0.0;
    return app_med - tcp_med;
}

// ===== Config / stats =====

void RTTEqualizer::set_config(const RTTEqualizerConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[RTTEqualizer] Config updated");
}

RTTEqualizerConfig RTTEqualizer::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

RTTEqualizerStats RTTEqualizer::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void RTTEqualizer::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    NCP_LOG_DEBUG("[RTTEqualizer] Stats reset");
}

void RTTEqualizer::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (threat_level_ != level) {
        threat_level_ = level;
        NCP_LOG_INFO(std::string("[RTTEqualizer] Threat level changed to ")
                     + std::to_string(static_cast<int>(level)));
    }
}

ThreatLevel RTTEqualizer::get_threat_level() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return threat_level_;
}

// ===== Private helpers =====

void RTTEqualizer::adaptive_adjust_() {
    // Must be called with mutex_ held.
    // Require at least half the window before adjusting.
    size_t min_samples = std::max<size_t>(5, config_.rtt_sample_window / 4);
    if (tcp_rtt_samples_.size() < min_samples || app_rtt_samples_.size() < min_samples) {
        return;
    }

    double tcp_med = compute_median_(tcp_rtt_samples_);
    double app_med = compute_median_(app_rtt_samples_);
    if (tcp_med <= 0.0 || app_med <= 0.0) return;

    double gap = app_med - tcp_med;

    // If the measured gap is already above target, we don't need to delay much.
    // The current_delay_ms_ tracks what we think the equalizer should inject.
    double new_delay = std::max(0.0, config_.target_rtt_overhead_ms - gap);
    if (std::fabs(new_delay - current_delay_ms_) > 0.1) {
        current_delay_ms_ = new_delay;
        stats_.adaptive_adjustments.fetch_add(1, std::memory_order_relaxed);

        std::ostringstream oss;
        oss << "[RTTEqualizer] Adaptive adjust: gap=" << gap
            << "ms, new base delay=" << new_delay << "ms";
        NCP_LOG_DEBUG(oss.str());
    }
}

double RTTEqualizer::compute_median_(const std::deque<RTTSample>& samples) const {
    // Must be called with mutex_ held.
    if (samples.empty()) return 0.0;

    std::vector<double> vals;
    vals.reserve(samples.size());
    for (const auto& s : samples) {
        vals.push_back(s.rtt_ms);
    }
    std::sort(vals.begin(), vals.end());

    size_t n = vals.size();
    if (n % 2 == 0) {
        return (vals[n / 2 - 1] + vals[n / 2]) * 0.5;
    }
    return vals[n / 2];
}

void RTTEqualizer::trim_samples_(std::deque<RTTSample>& samples) {
    // Must be called with mutex_ held.
    while (samples.size() > config_.rtt_sample_window) {
        samples.pop_front();
    }
}

} // namespace DPI
} // namespace ncp
