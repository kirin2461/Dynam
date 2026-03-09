#pragma once
/**
 * @file ncp_wf_defense.hpp
 * @brief Website Fingerprinting (WF) Defense
 *
 * Injects dummy packets so that all website page loads appear
 * identical in size and timing patterns, defeating traffic-analysis
 * based fingerprinting attacks (e.g. WF classifiers).
 *
 * Implements the Tamaraw defense schedule:
 *   - Outgoing packets at a fixed rate (default 40 ms)
 *   - Incoming packets at a fixed rate (default 12 ms)
 *   - Total packet count padded to a multiple of tamaraw_pad_multiple
 *
 * Also supports a simpler constant-rate mode and a target-based
 * normalization mode.
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>

#include "ncp_orchestrator.hpp"   // ncp::DPI::ThreatLevel

namespace ncp {
namespace DPI {

// =====================================================================
// Configuration
// =====================================================================

struct WFDefenseConfig {
    bool enabled = true;

    // Normalization targets (non-Tamaraw mode)
    size_t target_total_packets = 500;   ///< Normalize all pages to ~500 packets
    size_t target_total_bytes   = 500000;///< Normalize to ~500 KB
    size_t packet_size          = 1000;  ///< Fixed packet size for padding

    double max_overhead_ratio = 2.0;     ///< Max allowed padding overhead

    // Constant-rate mode (most secure, highest overhead)
    bool   constant_rate_mode = false;
    double constant_rate_pps  = 50.0;   ///< Packets per second in constant mode

    // Tamaraw defense (practical WF defense — recommended)
    bool   tamaraw_mode = true;
    double tamaraw_outgoing_rate_ms = 40.0;  ///< One outgoing pkt every 40 ms
    double tamaraw_incoming_rate_ms = 12.0;  ///< One incoming pkt every 12 ms
    size_t tamaraw_pad_multiple     = 100;   ///< Pad total count to multiple of 100
};

// =====================================================================
// Statistics
// =====================================================================

struct WFDefenseStats {
    std::atomic<uint64_t> pages_defended{0};
    std::atomic<uint64_t> dummy_packets_sent{0};
    std::atomic<uint64_t> dummy_bytes_sent{0};
    std::atomic<uint64_t> real_packets_processed{0};
    std::atomic<uint64_t> overhead_bytes{0};

    void reset() noexcept;

    WFDefenseStats() = default;
    WFDefenseStats(const WFDefenseStats& o) noexcept
        : pages_defended(o.pages_defended.load())
        , dummy_packets_sent(o.dummy_packets_sent.load())
        , dummy_bytes_sent(o.dummy_bytes_sent.load())
        , real_packets_processed(o.real_packets_processed.load())
        , overhead_bytes(o.overhead_bytes.load())
    {}
    WFDefenseStats& operator=(const WFDefenseStats& o) noexcept {
        if (this != &o) {
            pages_defended.store(o.pages_defended.load());
            dummy_packets_sent.store(o.dummy_packets_sent.load());
            dummy_bytes_sent.store(o.dummy_bytes_sent.load());
            real_packets_processed.store(o.real_packets_processed.load());
            overhead_bytes.store(o.overhead_bytes.load());
        }
        return *this;
    }
};

// =====================================================================
// Padding plan (output of end_page_load)
// =====================================================================

struct PaddingPlan {
    size_t dummy_outgoing_packets;  ///< Extra outgoing packets to inject
    size_t dummy_incoming_packets;  ///< Extra incoming packets to inject
    size_t dummy_packet_size;       ///< Byte size of each dummy packet
    std::chrono::microseconds send_interval; ///< Target inter-packet interval
};

// =====================================================================
// Main class
// =====================================================================

class WFDefense {
public:
    WFDefense();
    explicit WFDefense(const WFDefenseConfig& cfg);

    // -----------------------------------------------------------------
    // Session lifecycle
    // -----------------------------------------------------------------

    /// Begin defending a new page-load session.
    void begin_page_load();

    /**
     * @brief Record one real packet observed during the current session.
     * @param size        Packet size in bytes.
     * @param is_outgoing True if the packet is outgoing (client → server).
     */
    void record_real_packet(size_t size, bool is_outgoing);

    /**
     * @brief End the current page-load session.
     *
     * Computes how many dummy packets are needed to reach the target
     * profile and returns a PaddingPlan the caller can execute.
     *
     * @return PaddingPlan with dummy packet counts and scheduling.
     */
    PaddingPlan end_page_load();

    // -----------------------------------------------------------------
    // Packet generation
    // -----------------------------------------------------------------

    /**
     * @brief Generate one CSPRNG-filled dummy packet.
     * @param is_outgoing Direction tag (currently unused in payload gen).
     * @return Byte vector of length config_.packet_size.
     */
    std::vector<uint8_t> generate_dummy_packet(bool is_outgoing);

    // -----------------------------------------------------------------
    // Tamaraw scheduling
    // -----------------------------------------------------------------

    /**
     * @brief Compute next scheduled send time for a packet under Tamaraw.
     * @param is_outgoing Selects outgoing (40 ms) or incoming (12 ms) schedule.
     * @return Microseconds since the session start when the packet should fire.
     */
    std::chrono::microseconds get_next_send_time(bool is_outgoing);

    // -----------------------------------------------------------------
    // State
    // -----------------------------------------------------------------

    /// Returns true when a page-load defense session is active.
    bool is_active() const;

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    void            set_config(const WFDefenseConfig& cfg);
    WFDefenseConfig get_config() const;
    WFDefenseStats  get_stats()  const;
    void            reset_stats();
    void            set_threat_level(ThreatLevel level);

private:
    WFDefenseConfig  config_;
    WFDefenseStats   stats_;
    mutable std::mutex mutex_;
    ThreatLevel      threat_level_ = ThreatLevel::NONE;

    // Session state (protected by mutex_)
    bool        active_session_      = false;
    size_t      real_outgoing_count_ = 0;
    size_t      real_incoming_count_ = 0;
    size_t      real_bytes_          = 0;

    std::chrono::steady_clock::time_point session_start_;
    std::chrono::steady_clock::time_point last_outgoing_time_;
    std::chrono::steady_clock::time_point last_incoming_time_;

    /// Compute the padded target count for real_count under Tamaraw rules.
    size_t compute_pad_target_(size_t real_count) const;
};

} // namespace DPI
} // namespace ncp
