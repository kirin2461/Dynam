#ifndef NCP_ORCHESTRATOR_CAPS_PATCH_HPP
#define NCP_ORCHESTRATOR_CAPS_PATCH_HPP

// ======================================================================
//  Patch for ncp_orchestrator.hpp — Capabilities Integration
// ======================================================================
//
//  This file documents the exact changes needed in ncp_orchestrator.hpp.
//  Apply these additions to the existing header.
//
//  ---- PATCH START ----
//
//  1. Add #include at top of ncp_orchestrator.hpp:
//     #include "ncp_capabilities.hpp"
//
//  2. Add 4 new stage flags to OrchestratorStrategy (after enable_ech_fallback):
//
//     // Phase 5+: Additional stages (default=false for backward compat)
//     bool enable_protocol_morph = false;
//     bool enable_burst_morpher = false;
//     bool enable_geneva_ga = false;
//     bool enable_entropy_masking = false;
//
//  3. Add to OrchestratorConfig (after ech_enabled):
//
//     // Capabilities negotiation (A+C hybrid)
//     bool allow_in_band_negotiation = false;  // Default: pre-shared only
//     std::optional<NCPCapabilities> local_capabilities;  // What we advertise
//     std::optional<NCPCapabilities> peer_capabilities;   // What peer sent us
//     std::optional<NegotiatedConfig> negotiated;          // Result of negotiation
//
//  4. Add method to ProtocolOrchestrator public interface:
//
//     /// Apply negotiated capabilities to the pipeline.
//     /// Thread-safe: uses set_strategy() internally.
//     /// Called after capabilities exchange completes.
//     void apply_negotiated_config(const NegotiatedConfig& config);
//
//     /// Build NCPCapabilities from current strategy.
//     /// Used to generate local capabilities for exchange.
//     NCPCapabilities build_local_capabilities() const;
//
//  ---- PATCH END ----

#include "ncp_capabilities.hpp"
#include "ncp_orchestrator.hpp"

namespace ncp {
namespace DPI {

// ======================================================================
//  Standalone helper: build NCPCapabilities from OrchestratorStrategy
// ======================================================================

inline NCPCapabilities build_capabilities_from_strategy(
    const OrchestratorStrategy& strategy) {

    NCPCapabilities caps;
    caps.version = NCP_CAPS_VERSION;
    caps.supported_stages = StageFlag::NONE;
    caps.preferred_stages = StageFlag::NONE;

    // Map bool flags → bitmap
    auto map_flag = [&](bool enabled, StageFlag flag) {
        if (enabled) {
            caps.supported_stages |= flag;
            caps.preferred_stages |= flag;
        }
    };

    map_flag(strategy.enable_adversarial,      StageFlag::ADVERSARIAL_PADDING);
    map_flag(strategy.enable_flow_shaping,     StageFlag::FLOW_SHAPING);
    map_flag(strategy.enable_probe_resist,     StageFlag::PROBE_RESIST);
    map_flag(strategy.enable_mimicry,          StageFlag::TRAFFIC_MIMICRY);
    map_flag(strategy.enable_tls_fingerprint,  StageFlag::TLS_FINGERPRINT);
    map_flag(strategy.enable_advanced_dpi,     StageFlag::ADVANCED_DPI);
    map_flag(strategy.enable_ech_fallback,     StageFlag::ECH);

    // These 4 require the patched OrchestratorStrategy with new fields.
    // Until patched, they are always disabled in capabilities.
    // After patch, uncomment:
    // map_flag(strategy.enable_protocol_morph,   StageFlag::PROTOCOL_MORPH);
    // map_flag(strategy.enable_burst_morpher,    StageFlag::BURST_MORPHER);
    // map_flag(strategy.enable_geneva_ga,        StageFlag::GENEVA_GA);
    // map_flag(strategy.enable_entropy_masking,  StageFlag::ENTROPY_MASKING);

    // TLS profile
    caps.tls_profile = static_cast<uint8_t>(strategy.tls_browser_profile);

    // Generate random morph seed (will be combined with peer's via HKDF)
    // Caller should fill this with randombytes_buf() before exchange.

    return caps;
}

// ======================================================================
//  Standalone helper: apply NegotiatedConfig to OrchestratorStrategy
// ======================================================================

inline void apply_negotiated_to_strategy(
    OrchestratorStrategy& strategy,
    const NegotiatedConfig& config) {

    // Map bitmap → bool flags
    strategy.enable_adversarial     = has_flag(config.active_stages, StageFlag::ADVERSARIAL_PADDING);
    strategy.enable_flow_shaping    = has_flag(config.active_stages, StageFlag::FLOW_SHAPING);
    strategy.enable_probe_resist    = has_flag(config.active_stages, StageFlag::PROBE_RESIST);
    strategy.enable_mimicry         = has_flag(config.active_stages, StageFlag::TRAFFIC_MIMICRY);
    strategy.enable_tls_fingerprint = has_flag(config.active_stages, StageFlag::TLS_FINGERPRINT);
    strategy.enable_advanced_dpi    = has_flag(config.active_stages, StageFlag::ADVANCED_DPI);
    strategy.enable_ech_fallback    = has_flag(config.active_stages, StageFlag::ECH);

    // These 4 require patched OrchestratorStrategy:
    // strategy.enable_protocol_morph  = has_flag(config.active_stages, StageFlag::PROTOCOL_MORPH);
    // strategy.enable_burst_morpher   = has_flag(config.active_stages, StageFlag::BURST_MORPHER);
    // strategy.enable_geneva_ga       = has_flag(config.active_stages, StageFlag::GENEVA_GA);
    // strategy.enable_entropy_masking = has_flag(config.active_stages, StageFlag::ENTROPY_MASKING);

    // Apply resolved TLS profile
    if (config.tls_profile != 0) {
        strategy.tls_browser_profile =
            static_cast<ncp::BrowserType>(config.tls_profile);
    }

    // Apply fragment size
    // (Feed into AdvancedDPIBypass or Geneva config as needed)
}

} // namespace DPI
} // namespace ncp

#endif // NCP_ORCHESTRATOR_CAPS_PATCH_HPP
