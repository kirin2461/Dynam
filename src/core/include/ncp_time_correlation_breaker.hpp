#pragma once

/**
 * @file ncp_time_correlation_breaker.hpp
 * @brief Time Correlation Breaker — Phase 5 Traffic-Correlation Defense
 *
 * Prevents timing-correlation attacks (e.g. GFW-side vs exit-side correlation)
 * by injecting random jitter between sessions/requests so that the coefficient
 * of variation (CV = stddev / mean) of inter-event gaps stays above a minimum
 * threshold (~0.3), making correlation computationally infeasible.
 *
 * Research basis:
 *   Low-latency anonymity attacks: if an adversary observes both ends of a
 *   tunnel, timing correlation with CV < 0.1 allows >90% accuracy in linking
 *   sessions.  Maintaining CV > 0.3 reduces accuracy below random chance
 *   because the injected entropy exceeds the observable signal.
 */

#ifndef NCP_TIME_CORRELATION_BREAKER_HPP
#define NCP_TIME_CORRELATION_BREAKER_HPP

#include <cstdint>
#include <cstddef>
#include <deque>
#include <mutex>
#include <atomic>
#include <chrono>

#include "ncp_orchestrator.hpp"

namespace ncp {
namespace DPI {

// ===== Configuration =====

struct TimeCorrelationBreakerConfig {
    bool enabled = true;

    double min_cv          = 0.30;   ///< Minimum required coefficient of variation
    double max_jitter_ms   = 500.0;  ///< Upper bound on jitter injected
    double min_jitter_ms   = 10.0;   ///< Lower bound on jitter injected
    size_t sample_window   = 50;     ///< Sliding window for CV calculation
    bool   auto_adjust     = true;   ///< Increase jitter when CV < min_cv
};

// ===== Statistics =====

struct TimeCorrelationBreakerStats {
    std::atomic<uint64_t> jitters_applied{0};
    std::atomic<uint64_t> total_jitter_us{0};
    std::atomic<uint64_t> cv_adjustments{0};
    /// Last computed CV × 1000, stored as integer to be atomic-safe.
    std::atomic<uint32_t> current_cv_x1000{0};

    void reset() {
        jitters_applied.store(0);
        total_jitter_us.store(0);
        cv_adjustments.store(0);
        current_cv_x1000.store(0);
    }

    TimeCorrelationBreakerStats() = default;
    TimeCorrelationBreakerStats(const TimeCorrelationBreakerStats& o)
        : jitters_applied(o.jitters_applied.load()),
          total_jitter_us(o.total_jitter_us.load()),
          cv_adjustments(o.cv_adjustments.load()),
          current_cv_x1000(o.current_cv_x1000.load()) {}

    TimeCorrelationBreakerStats& operator=(const TimeCorrelationBreakerStats& o) {
        if (this != &o) {
            jitters_applied.store(o.jitters_applied.load());
            total_jitter_us.store(o.total_jitter_us.load());
            cv_adjustments.store(o.cv_adjustments.load());
            current_cv_x1000.store(o.current_cv_x1000.load());
        }
        return *this;
    }
};

// ===== TimeCorrelationBreaker =====

class TimeCorrelationBreaker {
public:
    TimeCorrelationBreaker();
    explicit TimeCorrelationBreaker(const TimeCorrelationBreakerConfig& cfg);

    /**
     * @brief Compute jitter to insert before the next session or request.
     *
     * Algorithm:
     *   1. Sample a base jitter from [min_jitter_ms, max_jitter_ms].
     *   2. If auto_adjust and current CV < min_cv: scale jitter up by
     *      (min_cv / current_cv) to boost variance.
     *   3. Clamp to [min_jitter_ms, max_jitter_ms].
     *   4. Update stats.
     *
     * At HIGH/CRITICAL threat: min_cv is increased to 0.5 and max_jitter
     * is doubled for the duration of this call.
     *
     * @return Microseconds of delay to wait before the next action.
     */
    std::chrono::microseconds compute_jitter();

    /**
     * @brief Record an observed inter-session/inter-request gap.
     *
     * Maintains a sliding window of size sample_window.
     * After pushing, the CV is recomputed and stored in stats.
     *
     * @param gap_ms  Gap in milliseconds.
     */
    void record_gap(double gap_ms);

    /**
     * @brief Get the current coefficient of variation of recorded gaps.
     *
     * Returns 0.0 if fewer than 2 samples are available.
     */
    double get_current_cv() const;

    /**
     * @brief Return true if the current CV is at or above min_cv.
     */
    bool is_correlation_safe() const;

    // ===== Config / stats =====

    void set_config(const TimeCorrelationBreakerConfig& cfg);
    TimeCorrelationBreakerConfig get_config() const;

    TimeCorrelationBreakerStats get_stats() const;
    void reset_stats();

    void set_threat_level(ThreatLevel level);
    ThreatLevel get_threat_level() const;

private:
    TimeCorrelationBreakerConfig config_;
    TimeCorrelationBreakerStats  stats_;
    mutable std::mutex           mutex_;
    ThreatLevel                  threat_level_ = ThreatLevel::NONE;

    std::deque<double> gap_samples_;       ///< Sliding window of gap_ms values
    double accumulated_jitter_ms_ = 0.0;   ///< Running total (informational)

    /**
     * @brief Compute CV from gap_samples_.
     * Returns 0.0 if fewer than 2 samples.
     * Caller must hold mutex_.
     */
    double compute_cv_() const;

    /**
     * @brief Compute the mean of a deque.
     * Caller must hold mutex_.
     */
    double compute_mean_(const std::deque<double>& samples) const;

    /**
     * @brief Compute population standard deviation of a deque given its mean.
     * Caller must hold mutex_.
     */
    double compute_stddev_(const std::deque<double>& samples, double mean) const;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_TIME_CORRELATION_BREAKER_HPP
