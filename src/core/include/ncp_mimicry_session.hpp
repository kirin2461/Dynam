#ifndef NCP_MIMICRY_SESSION_HPP
#define NCP_MIMICRY_SESSION_HPP

/**
 * @file ncp_mimicry_session.hpp
 * @brief Production-native per-session adapter: E2E + profile-transition +
 *        traffic mimicry + shaping over transport-neutral datagrams.
 *
 * One NcpMimicrySession instance per protected UDP/PortHop session. It is an
 * ADAPTER ONLY — it composes the existing blocks and implements neither
 * transport nor crypto itself:
 *
 *   - E2ESession                real X25519 (or configured) handshake, Double
 *                               Ratchet AEAD; the ONLY authentication layer.
 *   - SessionProfileContext     negotiated profile_transition_v1 gating, NCP
 *                               message tagging, PD data framing, epoch
 *                               fencing, old/new dual decode at the inner
 *                               (plaintext) level, grace window handling.
 *   - ReferenceProfileCatalog   read-only profile lookup; derive_session()
 *                               produces the per-session polymorphic
 *                               StatProfile + rng seed for the shaper.
 *   - TrafficMimicry            per-session OUTER mask (stable profile plus an
 *                               optional pending profile during a transition).
 *                               Never a global/shared instance; no strategy
 *                               mutation API. A mask-only switch never resets
 *                               TLS session state, keys or counters.
 *   - MimicryShaper             per-session, built from the catalog-derived
 *                               profile. Data packets consume prepared shapes;
 *                               control packets never touch the shaper.
 *   - MimicryFsmSession         per-session, epoch-bound FSM shape/timing
 *                               source, engaged INSTEAD of the shaper for
 *                               data packets when the active profile's
 *                               catalog descriptor carries fsm.enabled.
 *                               Rebuilt from the same per-session derivation
 *                               at every profile activation; control packets
 *                               never consume FSM data shapes. The borrowed
 *                               ProfileDescriptor lives in the caller-owned
 *                               catalog, which must outlive this session.
 *
 * Datagram wire layout (what a PortHopClient/Server payload carries):
 *
 *   [kind:1][ body ... ]
 *     'H'  — raw E2E key-exchange blob (request or response)
 *     'C'  — serialized E2E EncryptedMessage of a tagged capabilities message
 *     'E'  — outer-mimicked serialized E2E EncryptedMessage (NCP-tagged
 *            profile-transition control or PD-framed DATA inside the AEAD)
 *     'P'  — insecure plaintext compatibility datagram (see below)
 *
 * Strict authentication ordering: the outer mimicry layer is an
 * unauthenticated mask. Inbound datagrams are unwrapped with the active outer
 * profile first, then — only during the post-activation grace window — with
 * the previous outer profile; every candidate must then pass the E2E AEAD +
 * replay checks AND the inner PD profile-epoch check inside
 * SessionProfileContext before it can produce data or confirm a transition.
 * Corrupted or replayed bytes therefore cannot confirm a transition: the E2E
 * ratchet and the inner epoch fence stay authoritative.
 *
 * Legacy peers: "legacy" means profile_transition_v1 was NOT negotiated.
 * The data wire then stays the pre-existing PROTECTED form — E2E-serialized
 * raw application payload without the NCP tag / PD framing — and hot profile
 * switch is disabled: start_profile_transition() fails with
 * TransitionError::NOT_SUPPORTED without emitting anything. The adapter NEVER
 * silently downgrades an established E2E session to plaintext.
 *
 * Insecure plaintext compatibility: pre-handshake plaintext datagrams
 * (kind 'P') are a SEPARATE, explicit compatibility mode gated by
 * Config::allow_insecure_plaintext_legacy (default: OFF — such datagrams are
 * dropped). Even when enabled they are only surfaced until the E2E session
 * is established; afterwards they are always dropped.
 *
 * Crypto epoch: the adapter never invents an epoch counter. The transition
 * context is bound to E2ESession::get_crypto_epoch() (monotonic; bumped by
 * DH ratchet steps / key rotation) at context creation, at every API entry
 * point that can emit or process control, and after every successful
 * decrypt. A mask-only profile switch never changes it.
 *
 * MTU/datagram budget: send_application() refuses payloads above
 * Config::max_application_payload and additionally verifies the final
 * datagram (kind byte + outer mask + E2E serialization + NCP tag + PD header
 * + PD padding) fits path_mtu_bytes - porthop_overhead_bytes. Violations are
 * counted, never silently truncated.
 *
 * Threading/ownership: single-threaded poll-loop ownership. No threads are
 * created; all methods must be called from the owning poll loop, which also
 * owns the monotonic millisecond clock passed to tick()/on_datagram().
 * Outbound datagrams produced as reactions (handshake answers, capability
 * advertisements, control (re)transmissions) are queued internally and
 * drained via next_outbound().
 *
 * SCOPE: generic, stateless outer masks (e.g. GENERIC_UDP / GENERIC_TCP) are
 * always supported. The session-bound stateful v2 masks
 * (QUIC_SHORT_HEADER, STUN_MESSAGE) are valid transition targets iff
 * profile_transition_v2 was negotiated (Stats::transition_v2_capable);
 * v1-negotiated sessions keep the GENERIC-only target gate and the exact
 * v1 wire behavior.
 */

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ncp_capabilities.hpp"
#include "ncp_datagram_path.hpp"
#include "ncp_e2e.hpp"
#include "ncp_mimicry.hpp"
#include "ncp_mimicry_fsm.hpp"
#include "ncp_mimicry_stats.hpp"
#include "ncp_profile_transition.hpp"
#include "ncp_reference_profile_catalog.hpp"

namespace ncp {

class NcpMimicrySession {
public:
    enum class Role : uint8_t { Client, Server };

    /// What an inbound datagram turned out to be.
    enum class IngressKind : uint8_t {
        Dropped = 0,   ///< malformed / replayed / unauthenticated: no effect
        Handshake,     ///< E2E key-exchange message consumed
        Capabilities,  ///< peer capabilities consumed
        Control,       ///< profile-transition control consumed (or deduped)
        Data           ///< application data; app_payload is set
    };

    struct IngressResult {
        IngressKind kind = IngressKind::Dropped;
        std::optional<std::vector<uint8_t>> app_payload;
        /// True when the payload was surfaced via the explicit insecure
        /// plaintext compatibility mode (never for an established session).
        bool insecure_plaintext = false;
    };

    /// One outbound datagram handed to the transport (PortHop payload).
    struct OutboundDatagram {
        std::vector<uint8_t> bytes;        ///< complete datagram (incl. kind byte)
        uint32_t profile_epoch = 0;        ///< inner PD epoch stamped on data
        std::chrono::milliseconds pacing_delay{0};  ///< shaper delay (data only)
        bool is_control = false;           ///< transition control: hosts may
                                           ///< prioritize; never consumes a
                                           ///< data shape
    };

    struct Config {
        Role role = Role::Client;
        E2EConfig e2e_config{};

        /// Stable (initial) inner profile identity + layout. The ProfileRef
        /// should match a catalog descriptor when a catalog is attached.
        ProfileRef stable_profile{};
        ProfileLayoutParams stable_layout{};

        /// Outer mask for the stable profile. For v1-negotiated sessions only
        /// stateless wire-compatible profiles are supported by this adapter
        /// (GENERIC_UDP, GENERIC_TCP) and the constraint is ENFORCED for
        /// transition targets: the outer mask swaps synchronously at local
        /// activation, and under v1 the follow-up COMMIT/CONFIRM are wrapped
        /// with the NEW mask, so a target whose mask is not
        /// length-prefix-compatible would make them undecodable and silently
        /// diverge the profile state. Under v1, start_profile_transition()
        /// therefore refuses a resolved/requested non-generic target mask
        /// with TransitionError::INVALID_PROFILE (no state change, no control
        /// traffic), and a PREPARE whose target resolves to a non-generic
        /// mask is refused with ABORT(UNKNOWN_PROFILE) before READY.
        /// When profile_transition_v2 is negotiated the gate is lifted:
        /// control is pinned to the transition-stable mask (C1) and the
        /// pending mask is an RX candidate (C3), so arbitrary masks —
        /// including the session-bound QUIC_SHORT_HEADER / STUN_MESSAGE —
        /// are valid targets.
        TrafficMimicry::MimicProfile stable_mimic =
            TrafficMimicry::MimicProfile::GENERIC_UDP;

        /// Template config for the per-session TrafficMimicry instance.
        /// wire_version MUST be non-zero so both peers agree on the wire
        /// format (0 = random per instance would desynchronize peers).
        TrafficMimicry::MimicConfig mimic_config{};

        /// Read-only catalog used for profile lookup, the layout resolver and
        /// per-session shaper derivation. Not owned; may be nullptr (shaper
        /// and catalog-convenience APIs are then disengaged).
        const ReferenceProfileCatalog* catalog = nullptr;

        /// Resolve the outer mask for a transition target. Required for
        /// catalog-driven transitions; unresolved targets keep the stable
        /// outer mask (the inner PD layout switch still applies). Under a
        /// v1-negotiated session a resolved mask MUST be a
        /// length-prefix-compatible generic one (GENERIC_UDP / GENERIC_TCP):
        /// any other result makes the transition fail fast — INVALID_PROFILE
        /// locally, or a responder refusal with ABORT(UNKNOWN_PROFILE).
        /// Under v2 any resolved mask is accepted (v2 mask schedule).
        std::function<std::optional<TrafficMimicry::MimicProfile>(
            const ProfileRef&)> mimic_resolver;

        /// Advertise profile_transition_v1 to the peer. When false (or when
        /// the peer does not advertise it) the session keeps the legacy
        /// PROTECTED wire behavior (E2E-serialized raw payload, no NCP/PD
        /// tagging) and never emits transition control.
        bool advertise_profile_transition = true;

        /// Advertise profile_transition_v2 (transition protocol v2:
        /// arbitrary outer-mask transition targets). Negotiated only when
        /// BOTH peers advertise v2 AND v1 (strict AND via negotiate(); a
        /// v2 advertisement without v1 is malformed and treated as v1-only).
        /// While negotiated: transition control is pinned to the
        /// transition-stable mask, the pending mask becomes an RX candidate
        /// (active → pending → old-grace), and non-generic transition
        /// targets are permitted. When not negotiated the v1 mask schedule
        /// and the GENERIC-only target gate apply unchanged (byte-identical
        /// v1 wire behavior). No behavior change beyond the advertised bit
        /// until a transition actually runs.
        bool advertise_profile_transition_v2 = true;

        /// Operator escape hatch for the FSM-driven mask variants (step 6,
        /// design §3.4). Default false: when the session negotiated v2 AND
        /// the active profile's hash-bound descriptor engages the FSM shape
        /// source AND its family has a variant map, data datagrams are
        /// wrapped with the variant selected by the engaged FSM state and
        /// the RX candidate list gains the sibling family variant (4th
        /// candidate; the acceptance set stays a pure function of the
        /// descriptor family — I-V2-5). When true: data always goes out in
        /// the active mask and no sibling candidate is tried. Control
        /// datagrams are NEVER variant-wrapped, regardless of this flag
        /// (C1 pinning is unchanged). WARNING: this flag MUST be configured
        /// symmetrically on both peers — asymmetric use causes one-way loss
        /// of variant-wrapped datagrams (the disabled side never tries the
        /// sibling-variant RX candidate).
        bool disable_mask_variants = false;

        /// Explicit INSECURE compatibility mode for pre-handshake plaintext
        /// datagrams (kind 'P'). Default OFF: plaintext datagrams are always
        /// dropped. When enabled they are surfaced only until the E2E session
        /// is established — an established session is never downgraded.
        bool allow_insecure_plaintext_legacy = false;

        /// Transition FSM tuning (retransmit/grace). session_id is overridden
        /// internally with a value derived from the established E2E shared
        /// secret; callers leave it zeroed. When profile_transition_v2 is
        /// negotiated the adapter raises the effective grace period to at
        /// least retransmit_interval_ms * max_retransmit_attempts + 2 *
        /// retransmit_interval_ms (the retransmit budget plus margin), so
        /// post-activation control retransmits — decodable only via the
        /// old-grace RX candidate under the v2 C1 control-mask pin — cannot
        /// outlive the grace window; a larger configured grace is kept
        /// (floor, never a cap). v1-negotiated sessions use the configured
        /// grace_period_ms exactly.
        ProfileTransitionConfig transition_config{};

        /// Legacy sizing inputs mapped onto PathState at session creation.
        /// path_mtu_bytes is the IP MTU. porthop_overhead_bytes must reserve
        /// the actual 20-byte PH header plus porthop_padding_headroom_bytes.
        /// Existing encoded application datagrams are unchanged; the corrected
        /// default only removes the historical 4-byte under-reservation.
        uint32_t path_mtu_bytes = 1500;
        uint32_t porthop_overhead_bytes = 20;
        uint32_t porthop_padding_headroom_bytes = 0;

        /// Initial wire-path hop policy (docs/MIMICRY_CONFIG_MIGRATION.md,
        /// G2.2 transport-config binding). The default LegacyPortHop
        /// preserves the pre-existing behavior exactly: the 20-byte PH
        /// header (+ padding headroom) is reserved in the path budget.
        /// Fixed-path sessions created from a schema-2 quic/turn transport
        /// configuration use PathHopPolicy::Disabled and then
        /// porthop_padding_headroom_bytes MUST be 0 (enforced at
        /// construction). This adapter never emits PH headers itself (the
        /// PortHop transport owns the L2 frame); the policy selects the
        /// path accounting and the initial PathState reported via
        /// path_state(). A live session's policy is never rewritten by
        /// configuration — update_path_state() remains the only in-session
        /// path-state channel.
        PathHopPolicy hop_policy = PathHopPolicy::LegacyPortHop;

        /// Initial outer encapsulation: Direct (plain UDP, also used for
        /// fixed-path QUIC) or TurnChannelData (TURN relay). TurnSendData
        /// is bootstrap-only and is rejected at construction (fail before
        /// socket creation).
        OuterTransportKind outer_transport = OuterTransportKind::Direct;

        /// Conservative pre-check cap for application payloads. The exact
        /// post-encode budget check is always applied on top of this.
        size_t max_application_payload = 1024;

        /// Structural bounds for the internal outbound reaction queue
        /// (handshake responses, capability advertisements, transition
        /// control incl. retransmissions). Enforced on every enqueue
        /// (I-DRAIN-8): a datagram that would exceed either bound is
        /// REFUSED — the queue is never grown past a bound and never
        /// silently truncated; the refusal is counted in
        /// Stats::queue_dropped_packets / queue_dropped_bytes. Existing
        /// queued datagrams are never dropped to make room (an in-flight
        /// handshake/caps/control reaction is never sacrificed), so the
        /// policy is refuse-new. A single datagram larger than
        /// max_outbound_queue_bytes can never be queued (always refused
        /// and counted). 0 disables queueing entirely (every enqueue is
        /// refused and counted).
        size_t max_outbound_queue_packets = 64;
        size_t max_outbound_queue_bytes = 256 * 1024;
    };

    /// Snapshot of the adapter's externally interesting state.
    struct Stats {
        bool established = false;
        bool transition_capable = false;   ///< negotiated (both advertised)
        /// Negotiated profile_transition_v2 (both peers advertised v2 AND
        /// v1). False for v1-only/legacy peers; the v1 mask schedule and
        /// GENERIC-only target gate then remain in force.
        bool transition_v2_capable = false;
        ProfileTransitionState transition_state = ProfileTransitionState::IDLE;
        ProfileRef active_profile{};
        std::optional<ProfileRef> pending_profile{};
        uint32_t profile_epoch = 0;        ///< effective epoch stamped on new
                                           ///< outbound data (pending epoch
                                           ///< once a transition activates)
        uint32_t tx_epoch = 0;             ///< epoch stamped on outbound data
        TrafficMimicry::MimicProfile active_mimic =
            TrafficMimicry::MimicProfile::GENERIC_UDP;
        std::optional<TrafficMimicry::MimicProfile> pending_mimic{};
        ProfileTransitionCounters transition_counters{};
        TrafficMimicry::MimicStats outer_stats{};
        uint64_t e2e_messages_sent = 0;
        uint64_t e2e_messages_received = 0;
        uint32_t e2e_sending_chain_length = 0;
        uint32_t e2e_receiving_chain_length = 0;
        /// Monotonic E2E crypto epoch (DH-ratchet/key-rotation count),
        /// mirrored into the transition context. A mask-only profile switch
        /// never changes it.
        uint64_t crypto_epoch = 0;
        uint64_t shaper_epoch = 0;
        bool shaper_engaged = false;
        /// True when the active profile's catalog descriptor carries
        /// fsm.enabled and the per-session MimicryFsmSession is the
        /// data-shape/timing source for data packets (the shaper object is
        /// still maintained but bypassed while the FSM is engaged).
        bool fsm_engaged = false;
        uint64_t fsm_state_epoch = 0;      ///< FSM state epoch (0 when off)
        uint64_t fsm_profile_epoch = 0;    ///< FSM profile/override epoch
        MimicryFsmPhase fsm_phase = MimicryFsmPhase::BOOTSTRAP;
        std::string fsm_state;             ///< current FSM state ("" when off)
        uint64_t fsm_control_packets = 0;  ///< control packets accounted to
                                           ///< the engaged FSM (no RNG/shape
                                           ///< effect — accounting only)
        uint64_t mtu_budget_rejections = 0;  ///< oversized sends refused
        uint64_t ingress_dropped = 0;
        /// Current occupancy of the internal outbound reaction queue
        /// (I-DRAIN-8); bounded by Config::max_outbound_queue_packets /
        /// max_outbound_queue_bytes.
        uint64_t outbound_queue_packets = 0;
        uint64_t outbound_queue_bytes = 0;
        /// Datagrams refused by the queue bounds (never queued; existing
        /// queued datagrams are never evicted) and their total wire size.
        uint64_t queue_dropped_packets = 0;
        uint64_t queue_dropped_bytes = 0;
        /// I-TXD-2: exact per-datagram RX-candidate work accounting.
        /// *_total accumulate over the session lifetime; *_max are the
        /// per-datagram maxima and are structurally bounded by the RX
        /// candidate cap kMaxRxCandidates (= 4). An AEAD attempt is a
        /// candidate feed into the E2E decrypt path (only reachable after
        /// a non-empty mask unwrap), so aead <= unwrap always.
        uint64_t candidate_unwrap_attempts_total = 0;
        uint64_t candidate_aead_attempts_total = 0;
        uint32_t candidate_unwrap_attempts_max = 0;
        uint32_t candidate_aead_attempts_max = 0;
    };

    /// Hard structural cap on the RX candidate list (I-V2-3 / I-TXD-2):
    /// active, pending, old-grace, and at most one sibling variant beyond
    /// the dedup set. Enforced in code — no more than this many unwrap or
    /// AEAD attempts are performed for a single inbound datagram.
    static constexpr uint32_t kMaxRxCandidates = 4;

    explicit NcpMimicrySession(Config cfg);
    ~NcpMimicrySession();

    NcpMimicrySession(const NcpMimicrySession&) = delete;
    NcpMimicrySession& operator=(const NcpMimicrySession&) = delete;

    // ---- handshake / bring-up ----

    /// Client role: emit the E2E key-exchange request datagram. Returns
    /// nullopt for the server role or if already initiated.
    std::optional<OutboundDatagram> start_handshake();

    /// True once the E2E session is established (both ratchet directions live)
    /// and the per-session profile context has been created.
    bool is_established() const;

    /// Negotiated profile_transition_v1 (both peers advertised it). False for
    /// legacy peers; the wire format then stays protected raw/legacy.
    bool transition_capable() const;

    /// Host-driven E2E key rotation (sending-half DH ratchet step). Bumps the
    /// monotonic crypto epoch; the transition context is re-synchronized
    /// immediately. Returns true only when the rotation was actually applied
    /// (the E2E layer fences rotations on the non-initiator and while a
    /// previous rotation is still in flight).
    bool rotate_e2e_keys();

    // ---- data plane ----

    /// Encode one application payload into an outbound datagram. Returns
    /// nullopt (and counts the rejection) when the payload violates the
    /// configured budget or the session is not established. E2E exceptions at
    /// the crypto boundary are caught and surface as nullopt.
    std::optional<OutboundDatagram> send_application(
        const std::vector<uint8_t>& payload, uint64_t now_ms);

    /// Feed one inbound datagram (a complete PortHop payload). Reactions
    /// (handshake response, capabilities advertisement, transition control)
    /// are queued internally; drain them with next_outbound(). Never throws.
    IngressResult on_datagram(const uint8_t* data, size_t len, uint64_t now_ms);
    IngressResult on_datagram(const std::vector<uint8_t>& d, uint64_t now_ms) {
        return on_datagram(d.data(), d.size(), now_ms);
    }

    // ---- outbound reaction queue ----
    bool has_outbound() const;
    std::optional<OutboundDatagram> next_outbound();

    // ---- transitions ----

    /// Catalog-driven transition: resolves the ProfileRef (id + revision +
    /// content hash) and the PD layout from the attached catalog and the
    /// outer mask via Config::mimic_resolver. Fails with
    /// TransitionError::INVALID_PROFILE when the resolved outer mask is not
    /// a generic length-prefix-compatible one AND the session is not
    /// v2-negotiated (no state change, no traffic).
    TransitionError start_profile_transition(const std::string& profile_id,
                                             uint32_t revision,
                                             uint64_t now_ms);

    /// Explicit form (no catalog required). The caller supplies the exact
    /// wire identity, PD layout and outer mask of the target. For
    /// v1-negotiated sessions the mask MUST be GENERIC_UDP or GENERIC_TCP —
    /// any other mask is refused with TransitionError::INVALID_PROFILE (no
    /// state change, no traffic). v2-negotiated sessions accept arbitrary
    /// masks (v2 mask schedule).
    TransitionError start_profile_transition(ProfileRef target,
                                             ProfileLayoutParams layout,
                                             TrafficMimicry::MimicProfile mimic,
                                             uint64_t now_ms);

    /// Local pre-activation abort. False when nothing is outstanding or the
    /// transition already activated (no post-activation rollback).
    bool abort_transition(AbortReason reason, uint64_t now_ms);

    /// Retransmission/grace driver; call from the poll loop with a monotonic
    /// millisecond clock.
    void tick(uint64_t now_ms);

    /// Effective transition grace ceiling (ms): the configured
    /// Config::transition_config.grace_period_ms, raised to at least the
    /// retransmit budget + margin once v2 is negotiated (see the
    /// transition_config field comment). Reports the configured value before
    /// the E2E session is established.
    uint32_t effective_transition_grace_ms() const;

    // ---- authoritative path sizing (G3) ----

    /// Maximum application payload whose worst-case complete encoding fits
    /// the supplied path. Includes E2E/PD padding, kind/mask, PH, TURN, UDP
    /// and IP overhead. Unsupported masks or impossible mask floors return 0.
    size_t max_application_datagram(const PathState& path_state) const;

    /// Install freshly measured/negotiated path state. Invalid PH/TURN
    /// combinations are refused without changing the previous state.
    bool update_path_state(const PathState& path_state);

    /// Apply an OS-demuxed ICMP Packet Too Big hint for this socket/path.
    /// It may only LOWER effective MTU; increases and invalid IPv6 hints are
    /// ignored. Real QUIC owns its PMTUD and does not use this adapter hook.
    bool apply_icmp_packet_too_big(uint32_t advertised_mtu);

    /// Current path used by send_application()'s pre-encode budget check.
    PathState path_state() const;

    // ---- state / stats ----
    Stats stats() const;
    std::string e2e_session_id() const;  ///< stable per established session

    // ---- shaper introspection (host pacing/cancellation tests) ----
    /// True when a catalog-derived per-session shaper is attached.
    bool shaper_engaged() const;
    uint64_t shaper_epoch() const;
    const char* shaper_profile_name() const;
    /// Catalog-derived session distinguisher (public, non-secret).
    uint64_t shaper_session_tag() const;
    bool shaper_has_prepared_shape() const;
    /// Control-style peek: queues (idempotently) the next data shape WITHOUT
    /// consuming it. Returns false when no shaper is engaged.
    bool shaper_peek_prepared(PreparedShape& out);

    // ---- FSM introspection (data-shape/timing source when engaged) ----
    /// True when the active profile's descriptor carries fsm.enabled and a
    /// per-session MimicryFsmSession supplies data shapes/pacing.
    bool fsm_engaged() const;
    /// Current FSM lifecycle phase (BOOTSTRAP when no FSM is engaged).
    MimicryFsmPhase fsm_phase() const;
    /// Current FSM state name; "" when no FSM is engaged.
    const char* fsm_state_name() const;
    /// FSM state epoch (0 when no FSM is engaged).
    uint64_t fsm_state_epoch() const;
    /// Deterministic per-session FSM seed (0 when disengaged). Derived from
    /// the same HMAC-based per-session material as shaper_session_tag();
    /// public, non-secret (it cannot reveal the shared secret).
    uint64_t fsm_seed() const;
    /// Control-style peek: queues (idempotently) the next FSM data shape
    /// WITHOUT consuming it. Returns false when no FSM is engaged.
    bool fsm_peek_prepared(MimicryFsmShape& out);

    /// Maximum datagram size this adapter will emit (budget).
    size_t max_datagram_bytes() const;

private:
    struct Impl;
    Impl* impl_;
};

} // namespace ncp

#endif // NCP_MIMICRY_SESSION_HPP
