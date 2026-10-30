#pragma once

/**
 * @file ncp_mimicry_session_provider.hpp
 * @brief Read-only, cross-thread-safe telemetry view of per-session
 *        UDP/mimicry state (NcpConnectionDirector -> observers such as
 *        ProtocolOrchestrator).
 *
 * This interface is strictly READ-ONLY. All UDP/mimicry actuation (profile
 * transitions, key rotation, handshake, sends) stays exclusively with
 * NcpConnectionDirector / the profile-transition API. Implementations must
 * expose only snapshots of state; there is deliberately no method here that
 * can mutate mimicry/profile state, and no path from this interface to
 * TrafficMimicry::set_strategy() / global presets.
 *
 * Threading: implementations are required to be safe to call from any
 * thread. The canonical implementation (NcpConnectionDirector) publishes a
 * mutex-guarded snapshot from its single poll loop — providers never touch
 * per-session adapters from a foreign thread.
 *
 * Dependency note: this header is intentionally dependency-light (no
 * adapter/transition includes) so both NcpConnectionDirector and
 * ProtocolOrchestrator can consume it without include cycles.
 * ProfileTransitionState is forward-declared; consumers that need to compare
 * states include ncp_profile_transition.hpp.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ncp {

enum class ProfileTransitionState : uint8_t;  // ncp_profile_transition.hpp

/// Flattened read-only snapshot of one protected session's externally
/// interesting state (mirrors the telemetry subset of
/// NcpMimicrySession::Stats, flattened to plain value fields).
struct MimicrySessionView {
    uint64_t session_id = 0;          ///< transport-level (PortHop) session id

    bool established = false;         ///< E2E session up + profile context live
    bool transition_capable = false;  ///< profile_transition_v1 negotiated
    /// FSM state; value-initializes to 0 == ProfileTransitionState::IDLE.
    /// Compare against enumerator names by including
    /// ncp_profile_transition.hpp.
    ProfileTransitionState transition_state = ProfileTransitionState{};

    std::string active_profile_id;
    uint32_t active_profile_revision = 0;

    bool has_pending_profile = false;  ///< transition outstanding
    std::string pending_profile_id;    ///< valid only when has_pending_profile
    uint32_t pending_profile_revision = 0;

    uint32_t profile_epoch = 0;        ///< effective inner PD profile epoch
    uint64_t crypto_epoch = 0;         ///< monotonic E2E crypto epoch

    // From ProfileTransitionCounters (flattened):
    uint64_t transitions_effective = 0;
    uint64_t transitions_aborted = 0;
    uint64_t transitions_timed_out = 0;

    uint64_t e2e_messages_sent = 0;
    uint64_t e2e_messages_received = 0;

    uint64_t mtu_budget_rejections = 0;  ///< oversized sends refused
    uint64_t ingress_dropped = 0;
};

/// Read-only telemetry provider over the set of protected UDP/mimicry
/// sessions. All methods are cross-thread safe and never block the data
/// plane beyond a short mutex-guarded snapshot copy.
class IMimicrySessionProvider {
public:
    virtual ~IMimicrySessionProvider() = default;

    /// Snapshot of every live session (bounded by the director's
    /// max_sessions, <= 64). Order is unspecified.
    virtual std::vector<MimicrySessionView> list_sessions() const = 0;

    /// Snapshot of one session; nullopt when the id is unknown.
    virtual std::optional<MimicrySessionView> session(
        uint64_t session_id) const = 0;
};

} // namespace ncp
