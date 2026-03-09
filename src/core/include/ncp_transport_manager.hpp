#pragma once

/**
 * @file ncp_transport_manager.hpp
 * @brief Transport Management Modules — Phase 3b Anti-TSPU
 *
 * Three tightly coupled modules for transport-layer obfuscation:
 *
 *   ProtocolRotationSchedule — rotate transport protocols by time-of-day
 *                              to defeat temporal fingerprinting.
 *
 *   ASAwareRouter            — distribute connections across multiple
 *                              Autonomous Systems / CDN providers to
 *                              avoid traffic-concentration detection.
 *
 *   GeoObfuscator            — route connections through geographically
 *                              plausible exit nodes to mask origin.
 *
 * Dependencies:
 *   ncp_csprng.hpp       — cryptographically secure randomness
 *   ncp_logger.hpp       — NCP_LOG_* macros
 *   ncp_config.hpp       — Config::instance()
 *   ncp_orchestrator.hpp — ncp::DPI::ThreatLevel
 *
 * Standard: C++17, MSVC-compatible.
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"
#include "ncp_orchestrator.hpp"

namespace ncp {

// ============================================================
//  Shared alias
// ============================================================
using ThreatLevel = DPI::ThreatLevel;


// ============================================================
// ============================================================
//   CLASS 1: ProtocolRotationSchedule
// ============================================================
// ============================================================

/// Transport protocols understood by the rotation scheduler.
enum class TransportProtocol {
    OBFS4,              ///< obfs4 obfuscation bridge
    WEBSOCKET_TLS,      ///< TLS-wrapped WebSocket (blends with HTTPS)
    QUIC_LIKE,          ///< QUIC-inspired UDP transport
    RAW_TLS_1_3,        ///< Bare TLS 1.3 handshake
    MEEK_FRONTING,      ///< Domain-fronting through CDN
    SHADOWSOCKS_AEAD    ///< Shadowsocks AEAD cipher stream
};

/// One time-of-day window with its set of allowed protocols.
struct TimeSlot {
    uint8_t start_hour;                          ///< Start hour (UTC, 0-23)
    uint8_t end_hour;                            ///< End hour   (UTC, exclusive; wraps midnight)
    std::vector<TransportProtocol> allowed_protocols;
    TransportProtocol preferred;
};

/// Configuration for the rotation scheduler.
struct ProtocolRotationConfig {
    bool enabled                                = true;
    std::vector<TimeSlot> schedule;             ///< Time-based rotation schedule
    std::chrono::minutes min_protocol_duration{30};   ///< Minimum time on one protocol
    std::chrono::minutes max_protocol_duration{120};  ///< Maximum before forced rotation
    bool randomize_within_slot                  = true;
};

/// Runtime statistics for ProtocolRotationSchedule.
struct ProtocolRotationStats {
    std::atomic<uint64_t> rotations{0};
    std::atomic<uint64_t> forced_rotations{0};
    std::atomic<uint64_t> slot_transitions{0};

    void reset() {
        rotations.store(0);
        forced_rotations.store(0);
        slot_transitions.store(0);
    }

    ProtocolRotationStats() = default;
    ProtocolRotationStats(const ProtocolRotationStats& o)
        : rotations(o.rotations.load()),
          forced_rotations(o.forced_rotations.load()),
          slot_transitions(o.slot_transitions.load()) {}

    ProtocolRotationStats& operator=(const ProtocolRotationStats& o) {
        if (this != &o) {
            rotations.store(o.rotations.load());
            forced_rotations.store(o.forced_rotations.load());
            slot_transitions.store(o.slot_transitions.load());
        }
        return *this;
    }
};

/// Time-based transport-protocol rotation scheduler.
class ProtocolRotationSchedule {
public:
    ProtocolRotationSchedule();
    explicit ProtocolRotationSchedule(const ProtocolRotationConfig& cfg);

    /// Current recommended protocol (time-slot and threat aware).
    TransportProtocol get_current_protocol() const;

    /// True when a rotation is due (time or duration criterion).
    bool should_rotate() const;

    /// Advance to the next protocol and return it.
    TransportProtocol rotate();

    /// All protocols allowed in the current time slot.
    std::vector<TransportProtocol> get_allowed_protocols() const;

    /// Populate the schedule with sensible defaults.
    void load_default_schedule();

    // ---- config / stats / threat ----
    void              set_config(const ProtocolRotationConfig& cfg);
    ProtocolRotationConfig get_config() const;
    ProtocolRotationStats  get_stats()  const;
    void              reset_stats();
    void              set_threat_level(ThreatLevel level);

private:
    ProtocolRotationConfig                    config_;
    ProtocolRotationStats                     stats_;
    mutable std::mutex                        mutex_;
    ThreatLevel                               threat_level_ = ThreatLevel::NONE;

    TransportProtocol                         current_protocol_ = TransportProtocol::WEBSOCKET_TLS;
    std::chrono::steady_clock::time_point     last_rotation_time_;

    /// Find the TimeSlot that covers the current UTC hour (nullptr if none).
    const TimeSlot* find_current_slot_() const;

    /// Current hour in UTC (0-23).
    uint8_t current_hour_utc_() const;
};


// ============================================================
// ============================================================
//   CLASS 2: ASAwareRouter
// ============================================================
// ============================================================

/// Describes one Autonomous System (or CDN AS) used for routing.
struct ASEntry {
    uint32_t    asn               = 0;
    std::string name;               ///< e.g. "Cloudflare"
    std::string ip_range;           ///< CIDR notation
    double      weight            = 1.0;
    bool        is_cdn            = false;
    uint64_t    bytes_sent        = 0;     ///< cumulative bytes tracked
    size_t      active_connections = 0;
};

/// Configuration for the AS-aware router.
struct ASAwareRouterConfig {
    bool   enabled               = true;
    size_t max_connections_per_as = 3;
    double balance_ratio         = 0.3;   ///< Max fraction of traffic to one AS
    bool   prefer_cdn            = true;  ///< CDN traffic looks normal
    std::chrono::minutes rebalance_interval{10};
};

/// Runtime statistics for ASAwareRouter.
struct ASAwareRouterStats {
    std::atomic<uint64_t> connections_routed{0};
    std::atomic<uint64_t> rebalances{0};
    std::atomic<uint64_t> as_switches{0};
    std::atomic<uint64_t> cdn_connections{0};

    void reset() {
        connections_routed.store(0);
        rebalances.store(0);
        as_switches.store(0);
        cdn_connections.store(0);
    }

    ASAwareRouterStats() = default;
    ASAwareRouterStats(const ASAwareRouterStats& o)
        : connections_routed(o.connections_routed.load()),
          rebalances(o.rebalances.load()),
          as_switches(o.as_switches.load()),
          cdn_connections(o.cdn_connections.load()) {}

    ASAwareRouterStats& operator=(const ASAwareRouterStats& o) {
        if (this != &o) {
            connections_routed.store(o.connections_routed.load());
            rebalances.store(o.rebalances.load());
            as_switches.store(o.as_switches.load());
            cdn_connections.store(o.cdn_connections.load());
        }
        return *this;
    }
};

/// Routes new connections across AS entries to avoid traffic concentration.
class ASAwareRouter {
public:
    ASAwareRouter();
    explicit ASAwareRouter(const ASAwareRouterConfig& cfg);

    /// Add a known AS entry.
    void add_as_entry(const ASEntry& entry);

    /// Populate with well-known CDN autonomous systems.
    void load_default_entries();

    /// Select the next AS for a new connection (weighted, balanced).
    /// Returns nullptr when no AS is available.
    const ASEntry* select_next_as();

    /// Record bytes transferred to a given ASN.
    void record_traffic(uint32_t asn, size_t bytes);

    /// Release one active connection from a given ASN.
    void release_connection(uint32_t asn);

    /// True when traffic is well-distributed across AS entries.
    bool is_balanced() const;

    /// Force a rebalance pass (reset connection counts etc.).
    void rebalance();

    // ---- config / stats / threat ----
    void             set_config(const ASAwareRouterConfig& cfg);
    ASAwareRouterConfig get_config() const;
    ASAwareRouterStats  get_stats()  const;
    void             reset_stats();
    void             set_threat_level(ThreatLevel level);

private:
    ASAwareRouterConfig                       config_;
    ASAwareRouterStats                        stats_;
    mutable std::mutex                        mutex_;
    ThreatLevel                               threat_level_ = ThreatLevel::NONE;

    std::vector<ASEntry>                      as_entries_;
    std::chrono::steady_clock::time_point     last_rebalance_;

    /// Highest fraction of total bytes sent to any single AS.
    double compute_max_fraction_() const;
};


// ============================================================
// ============================================================
//   CLASS 3: GeoObfuscator
// ============================================================
// ============================================================

/// Geographic region descriptor.
struct GeoRegion {
    std::string code;             ///< ISO 3166-1 alpha-2 (e.g. "DE")
    std::string name;
    double      latitude         = 0.0;
    double      longitude        = 0.0;
    double      expected_rtt_ms  = 0.0; ///< Expected RTT from home region
    double      weight           = 1.0;
};

/// One exit node located in a geographic region.
struct GeoExitNode {
    std::string address;          ///< IP or hostname
    uint16_t    port              = 0;
    GeoRegion   region;
    double      measured_rtt_ms  = 0.0;
    bool        is_alive         = true;
    std::chrono::steady_clock::time_point last_check;
};

/// Configuration for GeoObfuscator.
struct GeoObfuscatorConfig {
    bool        enabled               = true;
    std::string home_region           = "RU";
    std::vector<std::string> preferred_exit_regions; ///< e.g. {"DE","NL","FI"}
    double      max_rtt_penalty_ms    = 100.0;
    bool        auto_select_region    = true;
    std::chrono::minutes health_check_interval{5};
};

/// Runtime statistics for GeoObfuscator.
struct GeoObfuscatorStats {
    std::atomic<uint64_t> connections_routed{0};
    std::atomic<uint64_t> region_switches{0};
    std::atomic<uint64_t> health_checks{0};
    std::atomic<uint64_t> dead_nodes_detected{0};

    void reset() {
        connections_routed.store(0);
        region_switches.store(0);
        health_checks.store(0);
        dead_nodes_detected.store(0);
    }

    GeoObfuscatorStats() = default;
    GeoObfuscatorStats(const GeoObfuscatorStats& o)
        : connections_routed(o.connections_routed.load()),
          region_switches(o.region_switches.load()),
          health_checks(o.health_checks.load()),
          dead_nodes_detected(o.dead_nodes_detected.load()) {}

    GeoObfuscatorStats& operator=(const GeoObfuscatorStats& o) {
        if (this != &o) {
            connections_routed.store(o.connections_routed.load());
            region_switches.store(o.region_switches.load());
            health_checks.store(o.health_checks.load());
            dead_nodes_detected.store(o.dead_nodes_detected.load());
        }
        return *this;
    }
};

/// Selects geographically appropriate exit nodes to mask traffic origin.
class GeoObfuscator {
public:
    GeoObfuscator();
    explicit GeoObfuscator(const GeoObfuscatorConfig& cfg);

    /// Add an exit node to the pool.
    void add_exit_node(const GeoExitNode& node);

    /// Populate pool with placeholder nodes for default regions.
    void load_default_nodes();

    /// Select the best exit node across all preferred regions.
    /// Returns nullptr when no alive node is available.
    const GeoExitNode* select_exit_node();

    /// Select best alive exit node in a specific region.
    /// Returns nullptr when none available.
    const GeoExitNode* select_exit_in_region(const std::string& region_code);

    /// Update the measured RTT for a specific node.
    void record_node_rtt(const std::string& address, double rtt_ms);

    /// Mark a node alive or dead.
    void set_node_status(const std::string& address, bool alive);

    /// ISO-3166 codes of all regions that have at least one exit node.
    std::vector<std::string> get_available_regions() const;

    /// Trigger a health-check pass (placeholder — logs intent).
    void run_health_checks();

    // ---- config / stats / threat ----
    void              set_config(const GeoObfuscatorConfig& cfg);
    GeoObfuscatorConfig get_config() const;
    GeoObfuscatorStats  get_stats()  const;
    void              reset_stats();
    void              set_threat_level(ThreatLevel level);

private:
    GeoObfuscatorConfig                       config_;
    GeoObfuscatorStats                        stats_;
    mutable std::mutex                        mutex_;
    ThreatLevel                               threat_level_ = ThreatLevel::NONE;

    std::vector<GeoExitNode>                  exit_nodes_;
    std::string                               current_region_;

    /// Score a node: lower RTT + alive + region-weight bonus => higher score.
    double compute_node_score_(const GeoExitNode& node) const;

    /// All alive nodes in a region (raw pointers into exit_nodes_).
    std::vector<GeoExitNode*> get_alive_nodes_in_region_(const std::string& region);
};


} // namespace ncp
