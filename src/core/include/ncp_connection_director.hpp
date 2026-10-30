#pragma once

/**
 * @file ncp_connection_director.hpp
 * @brief Per-session production registry / poll-loop owner for
 *        NcpMimicrySession adapters (the "ConnectionDirector").
 *
 * One NcpConnectionDirector sits between a datagram transport (PortHop
 * client/server) and the application. It owns one NcpMimicrySession per
 * protected session (keyed by the PortHop session_id on the server side)
 * and enforces the adapter's threading contract:
 *
 *   - SINGLE poll-loop data plane: on_datagram(), send_application(),
 *     start_handshake(), poll() and all session state access run on ONE
 *     thread (the owner's I/O loop). The director never creates threads.
 *
 *   - Cross-thread control: RotationCoordinator callbacks fire on the
 *     coordinator's scheduler thread and MimicryAutoPilot::request_transition
 *     may fire from a control thread. Those entry points ONLY enqueue a
 *     bounded request (enqueue_profile_transition(), enqueue_key_rotation(),
 *     transition_request_handler(), rotation_callback()); the poll loop
 *     drains the queue and applies requests to the adapters. No adapter
 *     method is ever invoked from a foreign thread, and never under a
 *     transport (PortHop) lock — the transport only ever hands over
 *     complete datagram payloads and receives complete egress datagrams.
 *
 *   - Commit/rollback feedback: a transition requested through the director
 *     is tracked per session. When the adapter reports the transition
 *     effective / aborted / timed out, the director invokes the registered
 *     feedback callbacks (wire them to MimicryAutoPilot::commit_transition /
 *     abort_transition). A failed apply at drain time reports an abort so an
 *     outstanding autopilot request is never left dangling.
 *
 *   - Pacing: OutboundDatagram::pacing_delay is honored through a bounded
 *     poll-loop due queue (min-heap on due time). Control datagrams
 *     (is_control) are prioritized on a separate immediate FIFO and NEVER
 *     consume data shapes nor wait on pacing. Queue overflow drops are
 *     counted, never silent.
 *
 *   - No global state: the director never calls TrafficMimicry::set_strategy,
 *     never applies global presets and never shares mimicry/shaper instances
 *     across sessions — every session owns its adapter, which owns its own
 *     TrafficMimicry/MimicryShaper (see ncp_mimicry_session.hpp).
 *
 *   - PortHop L2 epoch stays separate: the director is transport-neutral and
 *     never sees PortHop frames, hop epochs or ports. RotationLayer::
 *     L2_IDENTITY rotations are acknowledged and ignored (PortHop owns L2);
 *     L7 rotations map to per-session E2E key rotation.
 *
 *   - Legacy peers: a session whose peer did not negotiate
 *     profile_transition_v1 reports transition_capable() == false; transition
 *     requests for it are refused with TransitionResult::NOT_SUPPORTED and
 *     nothing is emitted on the wire. There is no plaintext fallback — the
 *     session template's allow_insecure_plaintext_legacy is respected as-is
 *     (default OFF).
 *
 *   - Read-only telemetry: mimicry_provider() hands observers (e.g.
 *     ProtocolOrchestrator) a cross-thread-safe snapshot of per-session
 *     profile/transition/crypto state. It can never mutate session state —
 *     all UDP/mimicry actuation stays with this director and the
 *     profile-transition API.
 *
 * Bounded defaults: every queue (cross-thread requests, pacing due queue,
 * control FIFO, application inbox) and the session registry itself are
 * bounded; constructor misconfiguration is reported via config_error().
 */

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "ncp_mimicry_session.hpp"
#include "ncp_mimicry_session_provider.hpp"  // IMimicrySessionProvider
#include "ncp_mimicry_autopilot.hpp"     // MimicryAutoPilot::TransitionResult
#include "ncp_rotation_coordinator.hpp"  // DPI::RotationLayer / RotationCallback

namespace ncp {

class NcpConnectionDirector {
public:
    /// Registry key: the PortHop session_id (transport-level session key).
    using SessionId = uint64_t;

    enum class Error : uint8_t {
        NONE = 0,
        INVALID_STATE,      ///< director misconfigured, or wrong-role call
        SESSION_EXISTS,     ///< add_session() for a live session id
        NO_SUCH_SESSION,    ///< unknown session id
        TOO_MANY_SESSIONS,  ///< registry bound (Config::max_sessions) hit
        NOT_ESTABLISHED,    ///< E2E session not established yet
        REJECTED,           ///< adapter refused (budget/state); see stats
    };
    static const char* to_string(Error e) noexcept;

    struct Config {
        /// Template for every per-session adapter. The role is taken from
        /// session_template.role: Server sessions auto-accept inbound
        /// sessions (see auto_accept_sessions); Client sessions are created
        /// explicitly with add_session() + start_handshake().
        NcpMimicrySession::Config session_template;

        /// Hard bounds (all must be non-zero; safe defaults provided).
        size_t max_sessions = 64;           ///< registry bound (server)
        size_t max_pending_requests = 64;   ///< cross-thread request queue
        size_t max_due_datagrams = 256;     ///< pacing due queue (data)
        size_t max_control_queue = 256;     ///< immediate control FIFO
        size_t max_inbox = 256;             ///< application data inbox

        /// Backstop for commit/rollback feedback when the adapter FSM itself
        /// does not resolve a requested transition in time.
        uint64_t transition_feedback_timeout_ms = 10000;

        /// Server role: create a session adapter on the first datagram of an
        /// unknown (transport-accepted) session id. Ignored for Client role.
        bool auto_accept_sessions = true;
    };

    /// One outbound datagram to hand to the transport (PortHop payload).
    struct Egress {
        SessionId session_id = 0;
        std::vector<uint8_t> bytes;   ///< complete adapter datagram
        bool is_control = false;      ///< prioritized; never paced
        uint32_t profile_epoch = 0;   ///< inner PD epoch (data plane)
    };

    /// One decrypted application payload (post-E2E, never plaintext legacy).
    struct AppData {
        SessionId session_id = 0;
        std::vector<uint8_t> payload;
    };

    struct Stats {
        uint64_t sessions_created = 0;
        uint64_t sessions_removed = 0;
        uint64_t session_create_rejected = 0;   ///< max_sessions bound hit
        uint64_t requests_enqueued = 0;         ///< cross-thread, accepted
        uint64_t requests_dropped_full = 0;     ///< bounded queue overflow
        uint64_t requests_applied = 0;          ///< drained into an adapter
        uint64_t requests_failed = 0;           ///< adapter refused at drain
        uint64_t rotations_enqueued = 0;
        uint64_t rotations_applied = 0;         ///< sessions actually rotated
        uint64_t l2_rotations_ignored = 0;      ///< PortHop owns the L2 epoch
        uint64_t datagrams_in = 0;
        uint64_t datagrams_out = 0;
        uint64_t app_messages_in = 0;
        uint64_t app_messages_out = 0;
        uint64_t inbox_dropped = 0;             ///< bounded inbox overflow
        uint64_t due_dropped_overflow = 0;      ///< pacing queue overflow
        uint64_t control_dropped_overflow = 0;  ///< control FIFO overflow
        uint64_t ingress_unknown_session = 0;   ///< dropped: no such session
        uint64_t transition_commits_reported = 0;
        uint64_t transition_aborts_reported = 0;
        uint64_t transition_feedback_timeouts = 0;
    };

    explicit NcpConnectionDirector(Config cfg);
    ~NcpConnectionDirector();

    NcpConnectionDirector(const NcpConnectionDirector&) = delete;
    NcpConnectionDirector& operator=(const NcpConnectionDirector&) = delete;

    /// Constructor validation. When false, config_error() explains why and
    /// every operation is a no-op / error.
    bool is_valid() const;
    const std::string& config_error() const;
    NcpMimicrySession::Role role() const;

    // ==================== poll-loop thread API ====================
    // All methods below (unless marked [any-thread]) MUST be called from the
    // single owning poll loop. The director itself creates no threads.

    /// Create a session adapter from the template. Server loops normally let
    /// auto_accept_sessions do this on first ingress; clients create their
    /// session explicitly before start_handshake().
    Error add_session(SessionId id);
    Error remove_session(SessionId id);
    bool has_session(SessionId id) const;
    size_t session_count() const;
    std::vector<SessionId> session_ids() const;

    /// Client role: emit the E2E key-exchange datagram (scheduled as
    /// priority control; retrieve it via poll()). Idempotent-failing:
    /// INVALID_STATE when already initiated or for a server-role session.
    Error start_handshake(SessionId id, uint64_t now_ms);

    bool is_established(SessionId id) const;

    /// Feed one inbound transport payload (complete PortHop payload).
    /// Unknown session ids are auto-accepted (server role) or dropped and
    /// counted. Decrypted application data lands in the bounded inbox;
    /// adapter reactions are scheduled for poll().
    void on_datagram(SessionId id, const uint8_t* data, size_t len,
                     uint64_t now_ms);
    void on_datagram(SessionId id, const std::vector<uint8_t>& d,
                     uint64_t now_ms) {
        on_datagram(id, d.data(), d.size(), now_ms);
    }

    /// Encode one application payload; the datagram is scheduled honoring
    /// the adapter's pacing_delay and emitted by poll() when due.
    /// NOT_ESTABLISHED before the E2E session is up; REJECTED on budget
    /// violation (counted by the adapter, never truncated).
    Error send_application(SessionId id, const std::vector<uint8_t>& payload,
                           uint64_t now_ms);

    /// Poll-loop heartbeat: drains the cross-thread request queue, ticks
    /// every adapter (retransmissions/grace), resolves transition feedback
    /// and returns every datagram due for transmission — control first,
    /// then paced data in due order.
    std::vector<Egress> poll(uint64_t now_ms);

    /// Next decrypted application payload (bounded inbox), FIFO.
    std::optional<AppData> next_application_data();

    /// Per-session adapter stats snapshot (nullopt: unknown session).
    /// [poll-thread only] Reads the adapter directly, without locking —
    /// NOT safe from foreign threads. Use mimicry_provider() for
    /// cross-thread telemetry.
    std::optional<NcpMimicrySession::Stats> session_stats(SessionId id) const;

    /// [any-thread] Read-only telemetry provider over all live sessions.
    ///
    /// The returned provider is backed by a PUBLISHED SNAPSHOT: the poll
    /// loop refreshes flattened MimicrySessionView values (after each
    /// poll() and on session create/remove) into a mutex-guarded store
    /// owned by the provider object. Provider reads copy out under that
    /// mutex and NEVER touch the per-session adapters, so they are safe
    /// from any thread and independent of the poll loop.
    ///
    /// Lifetime: the director owns the provider via shared_ptr; observers
    /// (e.g. ProtocolOrchestrator::set_mimicry_session_provider) should hold
    /// it through a weak_ptr so director destruction is never blocked and
    /// an expired weak_ptr cleanly reports "no telemetry".
    ///
    /// READ-ONLY: this interface exposes telemetry only. All UDP/mimicry
    /// actuation stays exclusively with this director's request API and the
    /// profile-transition API.
    std::shared_ptr<const IMimicrySessionProvider> mimicry_provider() const;

    /// Stable E2E session identifier ("" when unknown/not established).
    /// Stable across mask-only transitions — a change implies a reconnect.
    std::string session_e2e_id(SessionId id) const;

    /// Director-level counters (never secrets, addresses or payload data).
    Stats stats() const;

    // ==================== cross-thread request API ====================
    // [any-thread] Safe to call from RotationCoordinator / MimicryAutoPilot
    // callback threads. These entry points ONLY enqueue into the bounded
    // request queue; the poll loop applies them. The reference catalog (if
    // any) is consulted READ-ONLY here — it must not be mutated while
    // requests may be enqueued.

    /// Enqueue a catalog-driven profile transition for one session.
    /// revision == 0 resolves to the latest registered revision.
    /// Mimics MimicryAutoPilot::TransitionResult semantics:
    ///   ACCEPTED       — queued; commit/abort feedback will follow
    ///   BUSY           — session missing/not established/transition already
    ///                    outstanding, or the bounded queue is full (retry)
    ///   NOT_SUPPORTED  — session established but the peer is legacy
    ///                    (profile_transition_v1 not negotiated)
    ///   INVALID_PROFILE— (id, revision) not in the attached catalog
    MimicryAutoPilot::TransitionResult enqueue_profile_transition(
        SessionId id, const std::string& profile_id, uint32_t revision);

    /// [any-thread] Enqueue an L7 rotation: the poll loop performs a
    /// per-session E2E key rotation (rotate_e2e_keys) on every established
    /// session. L2_IDENTITY is acknowledged-and-ignored (PortHop owns the
    /// L2 hop epoch) and counted as l2_rotations_ignored. Returns false only
    /// when the bounded queue is full.
    bool enqueue_key_rotation(DPI::RotationLayer layer);

    /// [any-thread] Callback factory for MimicryAutoPilot::Config::
    /// request_transition bound to one session.
    std::function<MimicryAutoPilot::TransitionResult(const std::string&,
                                                     uint32_t)>
        transition_request_handler(SessionId id);

    /// [any-thread] Callback factory for RotationCoordinator::
    /// set_rotation_callback. Enqueues only.
    DPI::RotationCallback rotation_callback();

    // ==================== transition feedback (poll thread) ====================

    /// Invoked (poll thread) when a director-requested transition became
    /// effective on the wire. Wire to MimicryAutoPilot::commit_transition.
    using TransitionCommittedCb =
        std::function<void(SessionId, const std::string& profile_id,
                           uint32_t revision)>;
    /// Invoked (poll thread) when a director-requested transition aborted,
    /// timed out, or failed at apply time. Wire to
    /// MimicryAutoPilot::abort_transition.
    using TransitionAbortedCb =
        std::function<void(SessionId, const std::string& profile_id,
                           uint32_t revision, AbortReason reason)>;

    void set_transition_feedback(TransitionCommittedCb committed,
                                 TransitionAbortedCb aborted);

private:
    struct Impl;
    Impl* impl_;  // raw owning pointer (deleted in dtor), mirrors adapter ABI
};

} // namespace ncp
