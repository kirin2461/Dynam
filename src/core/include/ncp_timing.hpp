#pragma once

/**
 * @file ncp_timing.hpp
 * @brief TimingObfuscator - Phase 6
 *
 * Adds random delays between packet transmissions to defeat
 * timing-based traffic analysis. HIGH stealth priority.
 * Uses jitter distributions that mimic natural human browsing patterns.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace ncp {
namespace DPI {

/**
 * @brief Timing profile presets for different stealth levels
 */
struct TimingProfile {
    double min_delay_ms  = 10.0;    ///< Minimum inter-packet delay (ms)
    double max_delay_ms  = 100.0;   ///< Maximum inter-packet delay (ms)
    double jitter_factor = 0.3;     ///< Jitter as fraction of delay (0.0-1.0)
    bool   burst_mode    = false;   ///< Allow bursts of packets with minimal delay
    double burst_prob    = 0.1;     ///< Probability of a burst (0.0-1.0)
    size_t burst_size    = 3;       ///< Number of packets in a burst

    /// Low stealth: minimal delays, mostly transparent
    static TimingProfile low();

    /// Moderate stealth: noticeable delays, good balance
    static TimingProfile moderate();

    /// High stealth: significant delays, mimics human browsing
    static TimingProfile high();

    /// Maximum stealth: extreme jitter, very slow but nearly undetectable
    static TimingProfile paranoid();
};

/**
 * @brief Statistics tracked by TimingObfuscator
 */
struct TimingStats {
    uint64_t packets_delayed   = 0;     ///< Total packets that were delayed
    uint64_t total_delay_ms    = 0;     ///< Cumulative delay applied (ms)
    double   avg_delay_ms      = 0.0;   ///< Average delay per packet
    uint64_t bursts_triggered  = 0;     ///< Number of burst events
    uint64_t packets_in_bursts = 0;     ///< Total packets sent in bursts
};

/**
 * @brief Callback type for sending a packet after delay
 *
 * The TimingObfuscator calls this callback when it's time to send
 * each packet, after the appropriate delay has elapsed.
 */
using PacketSendCallback = std::function<void(const std::vector<uint8_t>&)>;

/**
 * @brief TimingObfuscator - adds random inter-packet delays
 *
 * Runs a background thread that dequeues packets and sends them
 * with randomized timing to defeat traffic analysis.
 *
 * Usage:
 *   TimingObfuscator obfuscator;
 *   obfuscator.start(TimingProfile::high(), [](const auto& pkt) {
 *       send_raw(pkt);
 *   });
 *   obfuscator.enqueue(packet_data);
 *   // ... later ...
 *   obfuscator.stop();
 */
class TimingObfuscator {
public:
    TimingObfuscator();
    ~TimingObfuscator();

    // Non-copyable, movable
    TimingObfuscator(const TimingObfuscator&) = delete;
    TimingObfuscator& operator=(const TimingObfuscator&) = delete;
    TimingObfuscator(TimingObfuscator&&) noexcept;
    TimingObfuscator& operator=(TimingObfuscator&&) noexcept;

    /**
     * @brief Start the timing obfuscation thread
     * @param profile  Timing profile to use
     * @param callback Function called to send each packet
     */
    void start(const TimingProfile& profile, PacketSendCallback callback);

    /**
     * @brief Stop the timing obfuscation thread
     *
     * Flushes remaining queued packets and joins the worker thread.
     */
    void stop();

    /**
     * @brief Check if the obfuscator is running
     */
    bool is_running() const;

    /**
     * @brief Enqueue a packet for delayed sending
     * @param packet Raw packet data
     */
    void enqueue(const std::vector<uint8_t>& packet);

    /**
     * @brief Enqueue multiple packets for delayed sending
     * @param packets Vector of raw packet data
     */
    void enqueue_batch(const std::vector<std::vector<uint8_t>>& packets);

    /**
     * @brief Update the timing profile while running
     * @param profile New timing profile
     */
    void set_profile(const TimingProfile& profile);

    /**
     * @brief Get current queue depth
     * @return Number of packets waiting to be sent
     */
    size_t queue_size() const;

    /**
     * @brief Get timing statistics
     */
    TimingStats get_stats() const;

    /**
     * @brief Reset timing statistics
     */
    void reset_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace DPI
} // namespace ncp
