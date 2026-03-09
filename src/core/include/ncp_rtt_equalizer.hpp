#pragma once

/**
 * @file ncp_rtt_equalizer.hpp
 * @brief RTT Equalizer — Phase 5 dMAP/Fingerprinting Defense
 *
 * Defeats dMAP-style analysis (~96% accuracy) that detects VPN/tunnel traffic
 * by measuring the discrepancy between TCP-level RTT and application-level RTT.
 *
 * Strategy: Delay ACKs so that (App_RTT - TCP_RTT) is indistinguishable from
 * direct HTTPS browsing overhead, where the gap is typically ~2ms due to
 * TLS/HTTP processing in a browser.
 *
 * Research basis:
 *   dMAP (2023): Detects VPNs with 96% accuracy by comparing TCP SYN-ACK
 *   RTT against HTTP request-response RTT. Tunneled traffic shows large gaps
 *   (10-50ms) vs. direct browsing gaps (~2ms).
 */

#ifndef NCP_RTT_EQUALIZER_HPP
#define NCP_RTT_EQUALIZER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <deque>
#include <mutex>
#include <atomic>
#include <chrono>
#include <algorithm>

#include "ncp_orchestrator.hpp"

namespace ncp {
namespace DPI {

// ===== Configuration =====

struct RTTEqualizerConfig {
    bool enabled = true;
    double target_rtt_overhead_ms = 2.0;   ///< Target app-TCP RTT gap to simulate (direct HTTPS ~2ms)
    double rtt_jitter_ms = 0.5;            ///< Random jitter range ±ms
    double min_delay_ms = 0.0;             ///< Minimum ACK delay allowed
    double max_delay_ms = 50.0;            ///< Safety cap on delay
    size_t rtt_sample_window = 100;        ///< Sliding window size for RTT estimation
    bool adaptive_mode = true;             ///< Auto-adjust target based on measured TCP RTT
};

// ===== RTT Sample =====

struct RTTSample {
    std::chrono::steady_clock::time_point timestamp;
    double rtt_ms;   ///< RTT measurement in milliseconds
};

// ===== Statistics =====

struct RTTEqualizerStats {
    std::atomic<uint64_t> acks_delayed{0};
    std::atomic<uint64_t> total_delay_us{0};
    std::atomic<uint64_t> samples_collected{0};
    std::atomic<uint64_t> adaptive_adjustments{0};

    void reset() {
        acks_delayed.store(0);
        total_delay_us.store(0);
        samples_collected.store(0);
        adaptive_adjustments.store(0);
    }

    RTTEqualizerStats() = default;
    RTTEqualizerStats(const RTTEqualizerStats& o)
        : acks_delayed(o.acks_delayed.load()),
          total_delay_us(o.total_delay_us.load()),
          samples_collected(o.samples_collected.load()),
          adaptive_adjustments(o.adaptive_adjustments.load()) {}

    RTTEqualizerStats& operator=(const RTTEqualizerStats& o) {
        if (this != &o) {
            acks_delayed.store(o.acks_delayed.load());
            total_delay_us.store(o.total_delay_us.load());
            samples_collected.store(o.samples_collected.load());
            adaptive_adjustments.store(o.adaptive_adjustments.load());
        }
        return *this;
    }
};

// ===== RTTEqualizer =====

class RTTEqualizer {
public:
    RTTEqualizer();
    explicit RTTEqualizer(const RTTEqualizerConfig& cfg);

    /**
     * @brief Record a TCP-level RTT measurement.
     * @param rtt_ms  RTT measured from SYN-ACK timing or DATA-ACK echo.
     */
    void record_tcp_rtt(double rtt_ms);

    /**
     * @brief Record an application-level RTT measurement.
     * @param rtt_ms  RTT from request sent to response received.
     */
    void record_app_rtt(double rtt_ms);

    /**
     * @brief Compute the delay to apply to an outgoing ACK for the given flow.
     *
     * Logic:
     *   gap = median(app_rtt) - median(tcp_rtt)
     *   if gap >= target_overhead  → delay = 0  (already looks natural)
     *   else                       → delay = (target_overhead - gap) + jitter
     *
     * @param flow_key  Identifier for the flow (e.g. "src:sport→dst:dport")
     * @return Microseconds of delay to apply before sending the ACK.
     */
    std::chrono::microseconds compute_ack_delay(const std::string& flow_key);

    /**
     * @brief Get current estimated TCP RTT (median of sample window).
     */
    double get_estimated_tcp_rtt_ms() const;

    /**
     * @brief Get current estimated app RTT (median of sample window).
     */
    double get_estimated_app_rtt_ms() const;

    /**
     * @brief Get the current RTT gap (app_rtt - tcp_rtt).
     *
     * A well-equalised connection should have gap ≈ target_rtt_overhead_ms.
     */
    double get_current_gap_ms() const;

    // ===== Config / stats =====

    void set_config(const RTTEqualizerConfig& cfg);
    RTTEqualizerConfig get_config() const;

    RTTEqualizerStats get_stats() const;
    void reset_stats();

    void set_threat_level(ThreatLevel level);
    ThreatLevel get_threat_level() const;

private:
    RTTEqualizerConfig config_;
    RTTEqualizerStats  stats_;
    mutable std::mutex mutex_;
    ThreatLevel        threat_level_ = ThreatLevel::NONE;

    std::deque<RTTSample> tcp_rtt_samples_;
    std::deque<RTTSample> app_rtt_samples_;
    double current_delay_ms_ = 0.0;  ///< Currently computed target delay

    /**
     * @brief Re-compute current_delay_ms_ from sample statistics.
     * Called whenever enough samples are available.
     * Caller must hold mutex_.
     */
    void adaptive_adjust_();

    /**
     * @brief Compute the median RTT value from a sample deque.
     * @param samples  Deque of RTTSample values.
     * @return Median rtt_ms, or 0.0 if empty.
     * Caller must hold mutex_.
     */
    double compute_median_(const std::deque<RTTSample>& samples) const;

    /**
     * @brief Trim a sample deque to the configured window size.
     * Caller must hold mutex_.
     */
    void trim_samples_(std::deque<RTTSample>& samples);
};

} // namespace DPI
} // namespace ncp

#endif // NCP_RTT_EQUALIZER_HPP
