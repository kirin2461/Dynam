#pragma once

/**
 * @file ncp_transport_config.hpp
 * @brief Versioned wire-transport configuration (docs/MIMICRY_CONFIG_MIGRATION.md
 *        §2) — the first executable artifact of the migration contract.
 *
 * Scope (deliberately small):
 *
 *   - A strict textual loader for `schema_version: 1|2` transport
 *     configurations. Unsupported keys, duplicate keys, misplaced sections
 *     and unknown values are HARD errors (§1 principle 4) — nothing is
 *     silently ignored or defaulted beyond the documented schema-1 legacy
 *     defaults.
 *   - A validator implementing the §3 initial transport-specific rules.
 *   - A binder that turns a validated configuration into the real session
 *     creation inputs: a HopSchedule (legacy-porthop only) plus the initial
 *     PathState fields applied to NcpMimicrySession::Config — the template
 *     consumed by NcpConnectionDirector at real session creation.
 *
 * What this is NOT:
 *
 *   - Not a QUIC/TURN stack. `wire_transport: quic|turn` select a FIXED-PATH
 *     session (PathHopPolicy::Disabled, no HopSchedule, no PortHop framing
 *     reserved); the real QUIC (ncp_real_quic) and TURN (ncp_turn_client)
 *     stacks remain the transport owners. No PortHop->QUIC migration is
 *     implied or enabled (quic_migration_v1 is a separate ADR/capability).
 *   - Not a secret store. The PortHop hop secret is a runtime input to the
 *     binder, never part of the parsed configuration; TURN `credential_ref`
 *     is an opaque external reference and is never resolved, printed or
 *     persisted here.
 *
 * Legacy compatibility (§1 principle 1): a configuration with no transport
 * fields (schema 1, including a completely empty file) binds to the exact
 * legacy defaults below and produces a HopSchedule byte-identical to one
 * constructed directly from the same parameters.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ncp_datagram_path.hpp"
#include "ncp_mimicry_session.hpp"
#include "ncp_porthop.hpp"

namespace ncp {

/// Wire transport selected by a schema-2 configuration (§2).
enum class WireTransport : uint8_t { LegacyPortHop = 0, Quic = 1, Turn = 2 };

const char* to_string(WireTransport t) noexcept;

struct TransportConfig {
    static constexpr uint32_t kSchemaLegacy = 1;     ///< unversioned config
    static constexpr uint32_t kSchemaTransport = 2;  ///< transport extension

    /// Legacy PortHop parameters (§2). The defaults ARE the schema-1
    /// interpretation of an unversioned configuration.
    struct LegacyPortHopFields {
        uint16_t base_port = 45000;
        uint16_t range = 8;
        /// Whole seconds only: HopSchedule is second-granular, so a
        /// sub-second or non-multiple value is a hard validation error,
        /// never a silent truncation.
        uint32_t hop_interval_ms = 60000;
    };

    /// Fixed-path QUIC parameters (§3.2). `hop_policy` accepts exactly
    /// "disabled"; anything else is a hard error.
    struct QuicFields {
        std::string hop_policy = "disabled";
        std::string alpn = "ncp/1";
        /// Single explicit remote path ("host" or "host:port"); required —
        /// a fixed path cannot be inferred.
        std::string remote;
    };

    /// TURN parameters (§3.3). `transport` accepts exactly "udp" and
    /// `data_mode` exactly "channel-data" for the established flow.
    struct TurnFields {
        std::string transport = "udp";
        std::string data_mode = "channel-data";
        /// Names an external runtime secret-store entry. Never a password;
        /// never printed in reports; required (independent long-term
        /// credentials — NCP/E2E/mask/hop secrets are never reused).
        std::string credential_ref;
    };

    uint32_t schema_version = kSchemaLegacy;
    WireTransport wire_transport = WireTransport::LegacyPortHop;

    LegacyPortHopFields legacy_porthop{};
    QuicFields quic{};
    TurnFields turn{};

    /// Parse-time section presence. A section whose fields do not belong to
    /// the selected wire transport is a hard error (§3), which requires
    /// distinguishing "absent" from "present with default values".
    bool legacy_section_present = false;
    bool quic_section_present = false;
    bool turn_section_present = false;
};

/**
 * Parse a transport configuration from text.
 *
 * Grammar (the §2 YAML subset; nothing else is accepted):
 *   - blank lines and '#' comments (full-line or trailing) are ignored;
 *   - top-level `schema_version: <uint>` and `wire_transport: <name>`;
 *   - top-level sections `legacy_porthop:` / `quic:` / `turn:` whose fields
 *     are indented `key: value` lines with the exact keys of §2;
 *   - unknown keys, duplicate keys/sections, misplaced fields and malformed
 *     values are hard errors (the error string says which line and why).
 *
 * Absence of all transport fields yields the schema-1 legacy configuration.
 * Any transport field (wire_transport or a section) requires an explicit
 * `schema_version: 2`. Parsed results are always run through
 * validate_transport_config() before being returned.
 */
std::optional<TransportConfig> parse_transport_config(const std::string& text,
                                                      std::string& error);

/// File convenience wrapper over parse_transport_config().
std::optional<TransportConfig> load_transport_config_file(
    const std::string& path, std::string& error);

/**
 * §3 validation for a programmatically built or freshly parsed config.
 * Pure value/cross-section checks; performs no I/O and never touches
 * secrets. On failure `error` names every violated rule's first hit.
 */
bool validate_transport_config(const TransportConfig& cfg, std::string& error);

/**
 * The output of binding a validated configuration to real session creation.
 */
struct BoundTransportConfig {
    TransportConfig config;  ///< validated copy

    /// The exact hop schedule for PortHopClient/PortHopServer creation.
    /// Present IFF wire_transport == LegacyPortHop — a fixed-path QUIC/TURN
    /// configuration NEVER produces a hop schedule (no accidental hopping).
    std::optional<HopSchedule> hop_schedule;

    /// Initial path for NcpMimicrySession::Config: LegacyPortHop for the
    /// legacy transport, Disabled (fixed path) for QUIC/TURN.
    PathHopPolicy hop_policy = PathHopPolicy::LegacyPortHop;
    /// Direct for legacy/QUIC, TurnChannelData for TURN.
    OuterTransportKind outer_transport = OuterTransportKind::Direct;
};

/**
 * Bind a transport configuration to session creation inputs (§1 principles
 * 2–3: binding happens at creation; a live session is never rewritten).
 *
 * `porthop_secret` is the runtime PortHop hop secret. It is REQUIRED for
 * legacy-porthop (it seeds the HopSchedule) and MUST be empty for QUIC/TURN
 * (§3.2: the PH hop secret is never reused as a QUIC/TURN credential —
 * passing one is a hard error, not a silent ignore).
 *
 * Fails (nullopt + error) before any socket/schedule object would be
 * created when the configuration is invalid (§8 gate).
 */
std::optional<BoundTransportConfig> bind_transport_config(
    const TransportConfig& cfg,
    const std::vector<uint8_t>& porthop_secret,
    std::string& error);

/**
 * Apply a bound configuration to an adapter session template (the
 * NcpConnectionDirector session_template / NcpMimicrySession::Config used
 * at real session creation). Sets the initial hop policy, outer transport
 * and PH overhead reservation consistently:
 *
 *   - legacy-porthop: LegacyPortHop path accounting; porthop_overhead_bytes
 *     is raised (never lowered) to at least the 20-byte PH header plus the
 *     template's padding headroom;
 *   - quic: fixed path (hop Disabled, Direct); PH overhead reservation 0;
 *   - turn: fixed path (hop Disabled, TurnChannelData); PH overhead 0.
 *
 * The template's crypto/profile/shaper fields are left untouched.
 */
void apply_transport_config(const BoundTransportConfig& bound,
                            NcpMimicrySession::Config& session_cfg);

} // namespace ncp
