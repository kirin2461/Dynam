/**
 * @file ncp_time_correlation_breaker.cpp
 * @brief Time Correlation Breaker implementation — Phase 5
 *
 * Injects randomised inter-session jitter to keep the coefficient of
 * variation (CV) of observed inter-event gaps above the configured
 * minimum, making timing-correlation attacks computationally infeasible.
 */

#include "ncp_time_correlation_breaker.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

namespace ncp {
namespace DPI {

// ===== Constructors =====

TimeCorrelationBreaker::TimeCorrelationBreaker() {
    NCP_LOG_DEBUG("[TimeCorrelationBreaker] Initialized with default config");
}

TimeCorrelationBreaker::TimeCorrelationBreaker(const TimeCorrelationBreakerConfig& cfg)
    : config_(cfg)
{
    NCP_LOG_DEBUG("[TimeCorrelationBreaker] Initialized"
                  " (min_cv=" + std::to_string(cfg.min_cv)
                  + ", max_jitter=" + std::to_string(cfg.max_jitter_ms) + "ms)");
}

// ===== Public API =====

std::chrono::microseconds TimeCorrelationBreaker::compute_jitter() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return std::chrono::microseconds(0);
    }

    // Effective bounds — elevated at HIGH/CRITICAL threat
    double effective_min_cv      = config_.min_cv;
    double effective_min_jitter  = config_.min_jitter_ms;
    double effective_max_jitter  = config_.max_jitter_ms;

    if (threat_level_ >= ThreatLevel::CRITICAL) {
        effective_min_cv     = 0.50;
        effective_min_jitter = config_.min_jitter_ms * 2.0;
        effective_max_jitter = config_.max_jitter_ms * 2.5;
    } else if (threat_level_ == ThreatLevel::HIGH) {
        effective_min_cv     = 0.50;
        effective_min_jitter = config_.min_jitter_ms * 1.5;
        effective_max_jitter = config_.max_jitter_ms * 1.8;
    } else if (threat_level_ == ThreatLevel::MEDIUM) {
        effective_min_cv     = config_.min_cv * 1.2;
        effective_max_jitter = config_.max_jitter_ms * 1.3;
    }

    // Base jitter: uniform sample in [min, max]
    double jitter_ms = csprng_double_range(effective_min_jitter, effective_max_jitter);

    // Auto-adjust: if current CV is below threshold, scale jitter up to compensate
    if (config_.auto_adjust && gap_samples_.size() >= 2) {
        double cv = compute_cv_();
        if (cv > 1e-9 && cv < effective_min_cv) {
            double scale = effective_min_cv / cv;
            // Limit the scale to avoid runaway delays
            scale = std::min(scale, 5.0);
            jitter_ms *= scale;
            stats_.cv_adjustments.fetch_add(1, std::memory_order_relaxed);

            std::ostringstream oss;
            oss << "[TimeCorrelationBreaker] CV=" << cv
                << " < " << effective_min_cv
                << ", scaling jitter by " << scale
                << " → " << jitter_ms << "ms";
            NCP_LOG_DEBUG(oss.str());
        }
    }

    // Clamp to effective bounds
    jitter_ms = std::max(effective_min_jitter, std::min(effective_max_jitter, jitter_ms));
    accumulated_jitter_ms_ += jitter_ms;

    auto jitter_us = static_cast<int64_t>(jitter_ms * 1000.0);

    stats_.jitters_applied.fetch_add(1, std::memory_order_relaxed);
    stats_.total_jitter_us.fetch_add(static_cast<uint64_t>(jitter_us),
                                      std::memory_order_relaxed);

    NCP_LOG_DEBUG("[TimeCorrelationBreaker] Jitter: " + std::to_string(jitter_ms) + "ms");

    return std::chrono::microseconds(jitter_us);
}

void TimeCorrelationBreaker::record_gap(double gap_ms) {
    if (gap_ms < 0.0) return;

    std::lock_guard<std::mutex> lock(mutex_);

    gap_samples_.push_back(gap_ms);

    // Trim to sliding window
    while (gap_samples_.size() > config_.sample_window) {
        gap_samples_.pop_front();
    }

    // Recompute and cache CV
    double cv = compute_cv_();
    stats_.current_cv_x1000.store(
        static_cast<uint32_t>(cv * 1000.0), std::memory_order_relaxed);

    std::ostringstream oss;
    oss << "[TimeCorrelationBreaker] Gap recorded: " << gap_ms
        << "ms, CV=" << cv
        << " (n=" << gap_samples_.size() << ")";
    NCP_LOG_DEBUG(oss.str());
}

double TimeCorrelationBreaker::get_current_cv() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return compute_cv_();
}

bool TimeCorrelationBreaker::is_correlation_safe() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (gap_samples_.size() < 2) {
        // Not enough data — assume safe (no evidence either way)
        return true;
    }
    return compute_cv_() >= config_.min_cv;
}

// ===== Config / stats =====

void TimeCorrelationBreaker::set_config(const TimeCorrelationBreakerConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[TimeCorrelationBreaker] Config updated");
}

TimeCorrelationBreakerConfig TimeCorrelationBreaker::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

TimeCorrelationBreakerStats TimeCorrelationBreaker::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void TimeCorrelationBreaker::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    gap_samples_.clear();
    accumulated_jitter_ms_ = 0.0;
    NCP_LOG_DEBUG("[TimeCorrelationBreaker] Stats reset");
}

void TimeCorrelationBreaker::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (threat_level_ != level) {
        threat_level_ = level;
        NCP_LOG_INFO("[TimeCorrelationBreaker] Threat level → "
                     + std::to_string(static_cast<int>(level)));
    }
}

ThreatLevel TimeCorrelationBreaker::get_threat_level() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return threat_level_;
}

// ===== Private helpers =====

double TimeCorrelationBreaker::compute_cv_() const {
    // Caller must hold mutex_.
    if (gap_samples_.size() < 2) return 0.0;

    double mean = compute_mean_(gap_samples_);
    if (mean <= 1e-9) return 0.0;

    double stddev = compute_stddev_(gap_samples_, mean);
    return stddev / mean;
}

double TimeCorrelationBreaker::compute_mean_(const std::deque<double>& samples) const {
    // Caller must hold mutex_.
    if (samples.empty()) return 0.0;
    double sum = 0.0;
    for (double v : samples) sum += v;
    return sum / static_cast<double>(samples.size());
}

double TimeCorrelationBreaker::compute_stddev_(const std::deque<double>& samples,
                                                double mean) const {
    // Caller must hold mutex_.
    if (samples.size() < 2) return 0.0;
    double variance = 0.0;
    for (double v : samples) {
        double diff = v - mean;
        variance += diff * diff;
    }
    variance /= static_cast<double>(samples.size());   // population stddev
    return std::sqrt(variance);
}

} // namespace DPI
} // namespace ncp
