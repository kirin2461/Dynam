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
 *   +        AdvancedDPIBypass     — technique-driven DPI evasion pipeline
 *   +        TLSFingerprint        — JA3/JA4 fingerprint spoofing
 *
 * into a single send()/receive() API with automatic strategy selection.
 */

#include "ncp_adversarial.hpp"
#include "ncp_flow_shaper.hpp"
#include "ncp_probe_resist.hpp"
#include "ncp_mimicry.hpp"
#include "ncp_dpi_advanced.hpp"
#include "ncp_tls_fingerprint.hpp"

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
    NONE     = 0,  // No DPI detected
    LOW      = 1,  // Basic SNI filtering only
    MEDIUM   = 2,  // Signature-based DPI (zapret-level)
    HIGH     = 3,  // ML-based flow classification
    CRITICAL = 4   // Active probing + ML + fingerprinting
};

const char* threat_level_to_string(ThreatLevel t) noexcept;
ThreatLevel threat_level_from_int(int level) noexcept;

// ===== Detection Feedback (from network) =====

struct DetectionEvent {
    enum class Type {
        CONNECTION_RESET,    // RST received after handshake
        CONNECTION_TIMEOUT,  // No response / black-holed
        THROTTLED,           // Bandwidth suddenly dropped
        PROBE_RECEIVED,      // Server got an active probe
        TLS_ALERT,           // Unexpected TLS alert
        DNS_POISONED,        // DNS response doesn't match
        IP_BLOCKED,          // Can't reach server at all
        SUCCESS              // Connection worked fine
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

    // ── Advanced DPI bypass (Step 2A) ──────────────────────────────
    bool enable_advanced_dpi = true;
    AdvancedDPIBypass::BypassPreset advanced_dpi_preset =
        AdvancedDPIBypass::BypassPreset::MODERATE;

    /// Per-strategy technique overrides applied *on top* of the preset.
    /// Empty = use preset defaults only.
    std::vector<EvasionTechnique> extra_techniques;

    // ── TLS Fingerprint spoofing (Step 2A) ─────────────────────────
    bool enable_tls_fingerprint = true;
    ncp::BrowserType tls_browser_profile = ncp::BrowserType::CHROME;

    // Presets
    static OrchestratorStrategy stealth();       // max protection, higher overhead
    static OrchestratorStrategy balanced();      // good protection, moderate overhead
    static OrchestratorStrategy performance();   // min overhead, basic protection
    static OrchestratorStrategy max_compat();    // maximum compatibility
};

// ===== Orchestrator Config =====

struct OrchestratorConfig {
    bool enabled = true;

    // Adaptive mode: auto-escalate on detection, de-escalate on success
    bool adaptive = true;
    int escalation_threshold = 3;     // N failures before escalating
    int deescalation_threshold = 20;  // N successes before de-escalating
    int deescalation_cooldown_sec = 300; // wait 5min after escalation

    // Initial strategy
    OrchestratorStrategy strategy;

    // Role
    bool is_server = false;  // true = enable probe_resist; false = client mode

    // Shared secret for probe resistance auth
    std::vector<uint8_t> shared_secret;

    // Health check interval
    int health_check_interval_sec = 30;

    // ── Advanced DPI full config (Step 2A) ─────────────────────────
    /// When set, overrides the preset from strategy.advanced_dpi_preset.
    /// Leave default-constructed to let the preset fill it in.
    AdvancedDPIConfig advanced_dpi_config;

    // ── TLS Fingerprint default profile (Step 2A) ──────────────────
    ncp::BrowserType tls_browser_profile = ncp::BrowserType::CHROME;

    // Callback when strategy changes
    using StrategyChangeCallback = std::function<void(
        ThreatLevel old_level, ThreatLevel new_level,
        const std::string& reason)>;
    StrategyChangeCallback on_strategy_change;

    // Presets
    static OrchestratorConfig client_default();
    static OrchestratorConfig server_default();
};

// ===== Combined Statistics =====

struct OrchestratorStats {
    // Pipeline
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};
    std::atomic<uint64_t> bytes_original{0};
    std::atomic<uint64_t> bytes_on_wire{0};

    // Adaptive
    std::atomic<uint64_t> escalations{0};
    std::atomic<uint64_t> deescalations{0};
    std::atomic<uint64_t> detection_events{0};
    std::atomic<uint64_t> successful_sends{0};

    // Current state
    ThreatLevel current_threat = ThreatLevel::NONE;
    std::string current_strategy_name;

    // Per-phase overhead
    double adversarial_overhead_pct = 0.0;
    double flow_shaping_overhead_pct = 0.0;
    double mimicry_overhead_pct = 0.0;
    double total_overhead_pct = 0.0;

    void reset() {
        packets_sent.store(0); packets_received.store(0);
        bytes_original.store(0); bytes_on_wire.store(0);
        escalations.store(0); deescalations.store(0);
        detection_events.store(0); successful_sends.store(0);
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

// ===== Send Callback =====

using OrchestratorSendCallback = std::function<void(const OrchestratedPacket&)>;

// ===== Main Class =====

class ProtocolOrchestrator {
public:
    ProtocolOrchestrator();
    explicit ProtocolOrchestrator(const OrchestratorConfig& config);
    ~ProtocolOrchestrator();

    ProtocolOrchestrator(const ProtocolOrchestrator&) = delete;
    ProtocolOrchestrator& operator=(const ProtocolOrchestrator&) = delete;

    // ===== Lifecycle =====

    void start(OrchestratorSendCallback send_cb);
    void stop();
    bool is_running() const;

    // ===== Client Pipeline =====

    /// Full client send pipeline:
    /// payload → tls_fingerprint → advanced_dpi → adversarial_pad
    ///         → mimicry_wrap → auth_prepend → flow_shape
    /// Returns shaped packets ready for the wire.
    std::vector<OrchestratedPacket> send(const std::vector<uint8_t>& payload);

    /// Async send: enqueues for background processing via callback.
    void send_async(const std::vector<uint8_t>& payload);

    // ===== Server Pipeline =====

    /// Full server receive pipeline:
    /// wire_data → auth_verify → flow_unshape → mimicry_unwrap → adversarial_unpad
    /// Returns original payload or empty if auth failed.
    /// auth_result is set to the authentication outcome.
    std::vector<uint8_t> receive(
        const std::vector<uint8_t>& wire_data,
        const std::string& source_ip,
        uint16_t source_port,
        const std::string& ja3 = "",
        AuthResult* auth_result = nullptr);

    /// Generate cover response for failed auth (server-side).
    std::vector<uint8_t> generate_cover_response();

    // ===== Adaptive Control =====

    /// Report a detection event (connection reset, timeout, etc.).
    void report_detection(const DetectionEvent& event);

    /// Report successful communication.
    void report_success();

    /// Get current threat level.
    ThreatLevel get_threat_level() const;

    /// Manually set threat level (disables adaptive for this level).
    void set_threat_level(ThreatLevel level);

    // ===== Strategy Management =====

    void set_strategy(const OrchestratorStrategy& strategy);
    OrchestratorStrategy get_strategy() const;

    /// Apply a named preset.
    void apply_preset(const std::string& name);

    // ===== Component Access =====

    AdversarialPadding& adversarial();
    FlowShaper& flow_shaper();
    ProbeResist& probe_resist();
    TrafficMimicry& mimicry();

    const AdversarialPadding& adversarial() const;
    const FlowShaper& flow_shaper() const;
    const ProbeResist& probe_resist() const;
    const TrafficMimicry& mimicry() const;

    /// Access the advanced DPI bypass component (may be nullptr if disabled).
    AdvancedDPIBypass* advanced_dpi();
    const AdvancedDPIBypass* advanced_dpi() const;

    /// Access the TLS fingerprint component (may be nullptr if disabled).
    ncp::TLSFingerprint* tls_fingerprint();
    const ncp::TLSFingerprint* tls_fingerprint() const;

    // ===== Config & Stats =====

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

    /// Initialize / reconfigure the advanced DPI bypass from current strategy.
    void init_advanced_dpi();

    /// Apply TLS browser profile to the fingerprint component.
    void apply_tls_profile(ncp::BrowserType profile);

    OrchestratorConfig config_;
    OrchestratorStats stats_;
    OrchestratorStrategy current_strategy_;
    ThreatLevel threat_level_ = ThreatLevel::NONE;

    // Core components
    AdversarialPadding adversarial_;
    FlowShaper flow_shaper_;
    ProbeResist probe_resist_;
    TrafficMimicry mimicry_;

    // Advanced DPI components (Step 2A)
    std::unique_ptr<AdvancedDPIBypass> advanced_dpi_;
    std::unique_ptr<ncp::TLSFingerprint> tls_fingerprint_;

    // Adaptive state
    int consecutive_failures_ = 0;
    int consecutive_successes_ = 0;
    std::chrono::steady_clock::time_point last_escalation_;
    mutable std::mutex strategy_mutex_;

    // Background
    std::atomic<bool> running_{false};
    OrchestratorSendCallback send_callback_;
    std::thread health_thread_;
};

} // namespace DPI
} // namespace ncp
