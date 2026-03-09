#pragma once
#ifndef NCP_SESSION_FRAGMENTER_HPP
#define NCP_SESSION_FRAGMENTER_HPP

/**
 * @file ncp_session_fragmenter.hpp
 * @brief SessionFragmenter — anti-TSPU TCP session lifetime control
 *
 * Breaks long-lived TCP sessions before TSPU statistical VPN fingerprinters
 * can confirm them. Sessions are reset after a randomized lifetime in
 * [min_session_lifetime, max_session_lifetime] and immediately reopened
 * through a fresh ephemeral source port.
 *
 * Architecture: ncp namespace, C++17, MSVC-compatible, thread-safe.
 */

#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"
#include "ncp_orchestrator.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

namespace ncp {

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

struct SessionFragmenterConfig {
    bool enabled                                   = true;
    std::chrono::seconds max_session_lifetime{120}; ///< 2 min default
    std::chrono::seconds min_session_lifetime{60};  ///< randomize between min..max
    uint16_t port_range_start                      = 49152;
    uint16_t port_range_end                        = 65535;
    size_t   max_tracked_sessions                  = 10000;
    bool     randomize_lifetime                    = true;  ///< jitter around max
};

// ---------------------------------------------------------------------------
// Per-session record
// ---------------------------------------------------------------------------

struct TrackedSession {
    std::string flow_key;  ///< "srcIP:srcPort-dstIP:dstPort"
    uint16_t    src_port;
    uint16_t    dst_port;
    std::string dst_ip;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::seconds assigned_lifetime;
    uint64_t bytes_sent     = 0;
    uint64_t bytes_received = 0;
    bool     marked_for_reset = false;
};

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct SessionFragmenterStats {
    std::atomic<uint64_t> sessions_tracked{0};
    std::atomic<uint64_t> sessions_reset{0};
    std::atomic<uint64_t> sessions_reopened{0};
    std::atomic<uint64_t> total_resets{0};

    SessionFragmenterStats() = default;

    /// Custom copy constructor: atomics are not copyable, load each value.
    SessionFragmenterStats(const SessionFragmenterStats& o)
        : sessions_tracked (o.sessions_tracked.load())
        , sessions_reset   (o.sessions_reset.load())
        , sessions_reopened(o.sessions_reopened.load())
        , total_resets     (o.total_resets.load())
    {}

    SessionFragmenterStats& operator=(const SessionFragmenterStats& o) {
        if (this != &o) {
            sessions_tracked.store (o.sessions_tracked.load());
            sessions_reset.store   (o.sessions_reset.load());
            sessions_reopened.store(o.sessions_reopened.load());
            total_resets.store     (o.total_resets.load());
        }
        return *this;
    }

    void reset() {
        sessions_tracked.store(0);
        sessions_reset.store(0);
        sessions_reopened.store(0);
        total_resets.store(0);
    }
};

// ---------------------------------------------------------------------------
// SessionFragmenter
// ---------------------------------------------------------------------------

class SessionFragmenter {
public:
    SessionFragmenter();
    explicit SessionFragmenter(const SessionFragmenterConfig& cfg);
    ~SessionFragmenter();

    // Non-copyable, movable
    SessionFragmenter(const SessionFragmenter&)            = delete;
    SessionFragmenter& operator=(const SessionFragmenter&) = delete;
    SessionFragmenter(SessionFragmenter&&)                 = default;
    SessionFragmenter& operator=(SessionFragmenter&&)      = default;

    // -----------------------------------------------------------------------
    // Core packet API
    // -----------------------------------------------------------------------

    /**
     * @brief Called for every outbound packet.
     *
     * Creates a TrackedSession if one doesn't exist yet, updates byte
     * counters and last_activity, and checks whether the session's
     * assigned lifetime has been exceeded.
     *
     * @return true  packet may proceed
     * @return false session lifetime expired — caller must send RST
     */
    bool process_packet(const std::string& src_ip, uint16_t src_port,
                        const std::string& dst_ip, uint16_t dst_port,
                        size_t packet_size);

    /**
     * @brief Scan all tracked sessions and collect expired flow_keys.
     *
     * Does NOT remove sessions — caller must call remove_session() after
     * the RST has been sent.
     */
    std::vector<std::string> check_expired_sessions();

    /**
     * @brief Pick a fresh ephemeral port from [port_range_start..port_range_end].
     *
     * Avoids the last 256 ports returned to prevent accidental reuse while
     * the original session's TIME_WAIT is still active.
     */
    uint16_t generate_new_port();

    /**
     * @brief Remove a session from tracking after RST has been sent.
     */
    void remove_session(const std::string& flow_key);

    // -----------------------------------------------------------------------
    // Background monitor
    // -----------------------------------------------------------------------

    /**
     * @brief Start a background thread that calls check_expired_sessions()
     *        every 5 seconds and invokes on_expire for each expired key.
     */
    void start_monitor(std::function<void(const std::string& flow_key)> on_expire);

    /** @brief Stop the background monitor thread (blocks until joined). */
    void stop_monitor();

    // -----------------------------------------------------------------------
    // Configuration & stats
    // -----------------------------------------------------------------------

    void                       set_config(const SessionFragmenterConfig& cfg);
    SessionFragmenterConfig    get_config() const;
    SessionFragmenterStats     get_stats()  const;  ///< snapshot copy
    void                       reset_stats();
    void                       set_threat_level(DPI::ThreatLevel level);

private:
    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * @brief Compute a randomized session lifetime.
     *
     * If randomize_lifetime is true, picks uniformly from
     * [min_session_lifetime, max_session_lifetime]; otherwise returns
     * max_session_lifetime.
     *
     * At HIGH/CRITICAL threat level the effective maximum is capped at 60 s.
     */
    std::chrono::seconds compute_lifetime_();

    /**
     * @brief Evict sessions that have been idle longest when the map is full.
     *
     * Removes up to 10 % of max_tracked_sessions (or at least 1 entry).
     * Called under mutex_.
     */
    void cleanup_old_sessions_();

    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------

    SessionFragmenterConfig config_;
    SessionFragmenterStats  stats_;
    DPI::ThreatLevel        threat_level_ = DPI::ThreatLevel::NONE;

    mutable std::mutex mutex_;

    std::unordered_map<std::string, TrackedSession> sessions_;
    std::vector<uint16_t>                           recently_used_ports_;

    std::thread         monitor_thread_;
    std::atomic<bool>   running_{false};
};

} // namespace ncp

#endif // NCP_SESSION_FRAGMENTER_HPP
