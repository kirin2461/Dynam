#pragma once

/**
 * @file ncp_orchestrator.hpp
 * @brief Protocol Orchestrator — Phase 4 (unified anti-TSPU pipeline)
 *
 * Wires together:
 *   Phase 1: AdversarialPadding  — packet-level adversarial bytes
 *   Phase 2: FlowShaper          — flow-level timing/size shaping
 *   Phase 3: ProbeResist          — server-side active probe defense
 *   +        TrafficMimicry       — protocol wrapping (HTTPS/DNS/QUIC)
 *   Phase 2+: TLSFingerprint     — realistic TLS fingerprinting (JA3/JA4)
 *   Phase 2+: AdvancedDPIBypass   — multi-technique DPI evasion
 *   Phase 3D: ECH                — Encrypted Client Hello
 *
 * into a single send()/receive() API with automatic strategy selection.
 */

#include "ncp_adversarial.hpp"
#include "ncp_flow_shaper.hpp"
#include "ncp_probe_resist.hpp"
#include "ncp_mimicry.hpp"
#include "ncp_tls_fingerprint.hpp"
#include "ncp_dpi_advanced.hpp"
#include "ncp_ech.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

namespace ncp {
namespace DPI {

// ===== Threat Level =====

enum class ThreatLevel {
    NONE     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4
};

const char* threat_level_to_string(ThreatLevel t) noexcept;
ThreatLevel threat_level_from_int(int level) noexcept;

// ===== Detection Feedback =====

struct DetectionEvent {
    enum class Type {
        CONNECTION_RESET,
        CONNECTION_TIMEOUT,
        THROTTLED,
        PROBE_RECEIVED,
        TLS_ALERT,
        DNS_POISONED,
        IP_BLOCKED,
        SUCCESS
    };
    Type type = Type::SUCCESS;
    std::string details;
    std::chrono::system_clock::time_point timestamp;
};

// ===== Strategy =====

struct OrchestratorStrategy {
    std::string name;
    ThreatLevel min_threat = ThreatLevel::NONE;

    // Phase 1: Adversarial Padding
    bool enable_adversarial = true;
    AdversarialConfig adversarial_config;

    // Phase 2: Flow Shaping
    bool enable_flow_shaping = true;
    FlowShaperConfig flow_config;

    // Phase 3: Probe Resistance (server-side)
    bool enable_probe_resist = true;
    ProbeResistConfig probe_config;

    // Mimicry
    bool enable_mimicry = true;
    TrafficMimicry::MimicProfile mimic_profile = TrafficMimicry::MimicProfile::HTTPS_APPLICATION;

    // Phase 2+: TLS Fingerprint configuration
    bool enable_tls_fingerprint = true;
    ncp::BrowserType tls_browser_profile = ncp::BrowserType::CHROME;
    bool tls_rotate_per_connection = false;

    // Phase 2+: Advanced DPI bypass
    bool enable_advanced_dpi = false;
    AdvancedDPIBypass::BypassPreset dpi_preset = AdvancedDPIBypass::BypassPreset::MODERATE;

    // Phase 3D: ECH (only used when advanced_dpi is disabled as fallback)
    bool enable_ech_fallback = false;

    // Presets
    static OrchestratorStrategy stealth();
    static OrchestratorStrategy balanced();
    static OrchestratorStrategy performance();
    static OrchestratorStrategy max_compat();
};

// ===== Orchestrator Config =====

struct OrchestratorConfig {
    bool enabled = true;

    bool adaptive = true;
    int escalation_threshold = 3;
    int deescalation_threshold = 20;
    int deescalation_cooldown_sec = 300;

    OrchestratorStrategy strategy;

    bool is_server = false;
    std::vector<uint8_t> shared_secret;
    int health_check_interval_sec = 30;

    // Phase 2+: ECH configuration (optional)
    std::vector<uint8_t> ech_config_data;
    bool ech_enabled = false;

    using StrategyChangeCallback = std::function<void(
        ThreatLevel old_level, ThreatLevel new_level,
        const std::string& reason)>;
    StrategyChangeCallback on_strategy_change;

    static OrchestratorConfig client_default();
    static OrchestratorConfig server_default();
};

// ===== Combined Statistics =====

struct OrchestratorStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_original{0};
    std::atomic<uint64_t> bytes_on_wire{0};

    std::atomic<uint64_t> escalations{0};
    std::atomic<uint64_t> deescalations{0};
    std::atomic<uint64_t> detection_events{0};
    std::atomic<uint64_t> successful_sends{0};

    // Phase 2+: TLS fingerprint stats
    std::atomic<uint64_t> tls_fingerprints_applied{0};
    std::atomic<uint64_t> ech_encryptions{0};

    // Phase 4A: Advanced DPI stats
    std::atomic<uint64_t> advanced_dpi_segments{0};

    ThreatLevel current_threat = ThreatLevel::NONE;
    std::string current_strategy_name;

    double adversarial_overhead_pct = 0.0;
    double flow_shaping_overhead_pct = 0.0;
    double mimicry_overhead_pct = 0.0;
    double total_overhead_pct = 0.0;

    void reset() {
        packets_sent.store(0); packets_received.store(0);
        bytes_original.store(0); bytes_on_wire.store(0);
        escalations.store(0); deescalations.store(0);
        detection_events.store(0); successful_sends.store(0);
        tls_fingerprints_applied.store(0); ech_encryptions.store(0);
        advanced_dpi_segments.store(0);
    }

    OrchestratorStats() = default;
    OrchestratorStats(const OrchestratorStats& o)
        : packets_sent(o.packets_sent.load()),
          packets_received(o.packets_received.load()),
          bytes_original(o.bytes_original.load()),
          bytes_on_wire(o.bytes_on_wire.load()),
          escalations(o.escalations.load()),
          deescalations(o.deescalations.load()),
          detection_events(o.detection_events.load()),
          successful_sends(o.successful_sends.load()),
          tls_fingerprints_applied(o.tls_fingerprints_applied.load()),
          ech_encryptions(o.ech_encryptions.load()),
          advanced_dpi_segments(o.advanced_dpi_segments.load()),
          current_threat(o.current_threat),
          current_strategy_name(o.current_strategy_name),
          adversarial_overhead_pct(o.adversarial_overhead_pct),
          flow_shaping_overhead_pct(o.flow_shaping_overhead_pct),
          mimicry_overhead_pct(o.mimicry_overhead_pct),
          total_overhead_pct(o.total_overhead_pct) {}
};

// ===== Processed Packet =====

struct OrchestratedPacket {
    std::vector<uint8_t> data;
    std::chrono::microseconds delay{0};
    bool is_dummy = false;
};

using OrchestratorSendCallback = std::function<void(const OrchestratedPacket&)>;

// ===== Main Class =====

class ProtocolOrchestrator {
public:
    ProtocolOrchestrator();
    explicit ProtocolOrchestrator(const OrchestratorConfig& config);
    ~ProtocolOrchestrator();

    ProtocolOrchestrator(const ProtocolOrchestrator&) = delete;
    ProtocolOrchestrator& operator=(const ProtocolOrchestrator&) = delete;

    void start(OrchestratorSendCallback send_cb);
    void stop();
    bool is_running() const;

    std::vector<OrchestratedPacket> send(const std::vector<uint8_t>& payload);
    void send_async(const std::vector<uint8_t>& payload);

    std::vector<uint8_t> receive(
        const std::vector<uint8_t>& wire_data,
        const std::string& source_ip,
        uint16_t source_port,
        const std::string& ja3 = "",
        AuthResult* auth_result = nullptr);

    std::vector<uint8_t> generate_cover_response();

    void report_detection(const DetectionEvent& event);
    void report_success();
    ThreatLevel get_threat_level() const;
    void set_threat_level(ThreatLevel level);

    void set_strategy(const OrchestratorStrategy& strategy);
    OrchestratorStrategy get_strategy() const;
    void apply_preset(const std::string& name);

    AdversarialPadding& adversarial();
    FlowShaper& flow_shaper();
    ProbeResist& probe_resist();
    TrafficMimicry& mimicry();

    const AdversarialPadding& adversarial() const;
    const FlowShaper& flow_shaper() const;
    const ProbeResist& probe_resist() const;
    const TrafficMimicry& mimicry() const;

    // Phase 2+: TLS Fingerprint access
    ncp::TLSFingerprint& tls_fingerprint();
    const ncp::TLSFingerprint& tls_fingerprint() const;

    // Phase 4A: Advanced DPI bypass access (may be nullptr if disabled)
    AdvancedDPIBypass* advanced_dpi();
    const AdvancedDPIBypass* advanced_dpi() const;

    // Phase 3D: ECH config access
    const ECH::ECHConfig& ech_config() const;
    bool is_ech_initialized() const;

    void set_config(const OrchestratorConfig& config);
    OrchestratorConfig get_config() const;
    OrchestratorStats get_stats() const;
    void reset_stats();

private:
    void apply_strategy(const OrchestratorStrategy& strategy);
    void escalate(const std::string& reason);
    void deescalate(const std::string& reason);
    OrchestratorStrategy strategy_for_threat(ThreatLevel level);
    void health_monitor_func();
    void update_overhead_stats();

    // Deadlock fix: lock-free version called when strategy_mutex_ is already held
    void report_success_locked_();

    // Phase 4A: Initialize/rebuild AdvancedDPIBypass from current strategy
    void init_advanced_dpi_();
    void rebuild_advanced_dpi_();

    // Phase 4A: Process a single data buffer through post-DPI pipeline
    //           (adversarial → mimicry → probe auth → flow shaping)
    std::vector<OrchestratedPacket> process_single_segment_(
        std::vector<uint8_t> data, bool is_first_segment);

    OrchestratorConfig config_;
    OrchestratorStats stats_;
    OrchestratorStrategy current_strategy_;
    ThreatLevel threat_level_ = ThreatLevel::NONE;

    // Components
    AdversarialPadding adversarial_;
    FlowShaper flow_shaper_;
    ProbeResist probe_resist_;
    TrafficMimicry mimicry_;

    // Phase 2+: TLS Fingerprint component
    ncp::TLSFingerprint tls_fingerprint_;

    // Phase 4A: Advanced DPI bypass component (owned)
    std::unique_ptr<AdvancedDPIBypass> advanced_dpi_;

    // Phase 3D: ECH state
    ECH::ECHConfig ech_config_;
    bool ech_initialized_ = false;
    std::vector<uint8_t> ech_private_key_;

    int consecutive_failures_ = 0;
    int consecutive_successes_ = 0;
    std::chrono::steady_clock::time_point last_escalation_;
    mutable std::mutex strategy_mutex_;

    std::atomic<bool> running_{false};
    OrchestratorSendCallback send_callback_;
    std::thread health_thread_;
};

} // namespace DPI
} // namespace ncp
