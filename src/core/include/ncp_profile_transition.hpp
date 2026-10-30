#ifndef NCP_PROFILE_TRANSITION_HPP
#define NCP_PROFILE_TRANSITION_HPP

/**
 * @file ncp_profile_transition.hpp
 * @brief Generic per-session seamless profile transition (mask/layout switch).
 *
 * One SessionProfileContext per protected session; it is the single owner of
 * the active / pending / draining profile state. The profile_epoch is
 * GENERIC and independent from any porthop epoch or crypto epoch: a profile
 * switch NEVER resets the crypto session, double-ratchet state, replay
 * windows, message counters, TLS state or mimicry session state.
 *
 * Protocol (all control messages ride INSIDE the existing AEAD channel as
 * plaintext; the context re-encrypts on every (re)transmission, so a logical
 * retransmit keeps the same transition_id but gets a fresh ratchet
 * counter/nonce/tag — ciphertext is never reused):
 *
 *   initiator                 responder
 *     | ---- PREPARE ----------> |   (target profile id/revision/hash, epoch)
 *     | <---- READY ------------ |
 *     | ---- COMMIT -----------> |   both ACTIVATE locally (TX -> new layout,
 *     | ---- CONFIRM ----------> |   old RX layout kept for grace period)
 *     | <---- CONFIRM ---------- |
 *     | ==== new-layout data ==> |   valid new data also confirms
 *     |      (drain old RX until grace deadline, then IDLE)
 *
 * A duplicate CONFIRM received in DRAIN with a FRESH effective crypto counter
 * is a retransmission from a peer still waiting in COMMIT (its copy of our
 * CONFIRM was lost); it is re-acked with an idempotent CONFIRM (no state
 * change, no new timers, bounded per transition). A duplicate that re-carries
 * the previously recorded counter is a logical replay and is only counted.
 *
 * FSM: IDLE -> PREPARE -> READY -> COMMIT -> DRAIN -> IDLE.
 * ABORT / TIMEOUT are safe only BEFORE activation; a post-activation ABORT is
 * ignored (no rollback — the way back is a NEW transition).
 *
 * Every control body binds: session_id, transition_id, target profile
 * id/revision/content_hash, direction, effective_counter, target
 * profile_epoch and the sender's current crypto_epoch. All fields are
 * strictly verified against the SessionProfileContext state. Crypto-epoch
 * verification is PEER-epoch-relative (a peer's advertised epoch is fenced
 * only against epochs previously observed FROM THAT PEER) because E2E
 * crypto epochs are permanently asymmetric between the endpoints.
 *
 * This module does NOT promise distributed atomic commit: after a timeout
 * the two endpoints may transiently disagree (one committed, one aborted);
 * the committed side keeps the new profile (no silent rollback) and the
 * mismatch is surfaced via counters / SwitchEvent.confirmed == false.
 *
 * Capability gating: profile_transition_v1 (NCPCapabilities reserved[0]
 * bit 0x01) must be negotiated; otherwise start_transition() returns
 * NotSupported and the outbound callback is never invoked.
 */

#include <array>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ncp {

// ==================== Constants ====================

inline constexpr uint8_t PROFILE_TRANSITION_WIRE_VERSION = 1;
inline constexpr size_t  PROFILE_SESSION_ID_SIZE = 16;
inline constexpr size_t  PROFILE_HASH_SIZE = 32;
inline constexpr size_t  MAX_PROFILE_ID_LEN = 64;
/// Absolute wire cap for a single control body (strict parser bound).
inline constexpr size_t  MAX_CONTROL_BODY_BYTES = 256;
/// Absolute cap for a single application payload inside a data message.
inline constexpr size_t  MAX_PROFILE_DATA_PAYLOAD_BYTES = 65535;

// ==================== Enums ====================

enum class ProfileTransitionState : uint8_t {
    IDLE = 0,  ///< no outstanding transition; stable profile active
    PREPARE,   ///< initiator: PREPARE sent, awaiting READY
    READY,     ///< responder: PREPARE accepted, READY sent, awaiting COMMIT
    COMMIT,    ///< committed + locally activated; awaiting peer confirmation
    DRAIN,     ///< peer confirmed (CONFIRM / valid new data) or post-activation
               ///< timeout; old RX layout accepted until the grace deadline
};

enum class TransitionMsgType : uint8_t {
    PREPARE = 1,
    READY   = 2,
    COMMIT  = 3,
    CONFIRM = 4,
    ABORT   = 5,
};

enum class TransitionDirection : uint8_t {
    BIDIRECTIONAL = 0,  ///< switch TX and RX layouts
    TX_ONLY       = 1,  ///< switch only the TX layout
    RX_ONLY       = 2,  ///< switch only the RX layout
};

enum class TransitionError : uint8_t {
    NONE = 0,
    NOT_SUPPORTED,    ///< profile_transition_v1 capability not negotiated
    BUSY,             ///< another transition is outstanding
    INVALID_PROFILE,  ///< malformed target identity
    STALE_EPOCH,      ///< target epoch is not current+1
    INVALID_STATE,
};

enum class AbortReason : uint8_t {
    NONE = 0,
    LOCAL_REQUEST  = 1,
    PEER_BUSY      = 2,
    TIMEOUT        = 3,
    UNKNOWN_PROFILE= 4,
    PROTOCOL_ERROR = 5,
    STALE_EPOCH    = 6,
};

const char* to_string(ProfileTransitionState s) noexcept;
const char* to_string(TransitionMsgType t) noexcept;
const char* to_string(TransitionError e) noexcept;
const char* to_string(AbortReason r) noexcept;

// ==================== Types ====================

/// Bounded profile identity carried on the wire. The full descriptor is
/// never serialised into control messages.
struct ProfileRef {
    std::string id;            ///< [a-z0-9_.-], 1..MAX_PROFILE_ID_LEN
    uint32_t    revision = 0;
    std::array<uint8_t, PROFILE_HASH_SIZE> content_hash{};

    bool operator==(const ProfileRef& o) const noexcept {
        return id == o.id && revision == o.revision &&
               content_hash == o.content_hash;
    }
    bool operator!=(const ProfileRef& o) const noexcept { return !(*this == o); }
    bool valid() const noexcept {
        return !id.empty() && id.size() <= MAX_PROFILE_ID_LEN;
    }
};

/// Minimal layout description used by the built-in framing adapter.
/// (mask-only switch: header overhead + block padding; payloads are carried
/// verbatim, authentication is provided by the surrounding AEAD channel).
struct ProfileLayoutParams {
    uint32_t header_overhead_bytes = 0;  ///< informational (accounting/stats)
    uint32_t padding_block_bytes = 0;    ///< 0 or 1 => no block padding

    bool operator==(const ProfileLayoutParams& o) const noexcept {
        return header_overhead_bytes == o.header_overhead_bytes &&
               padding_block_bytes == o.padding_block_bytes;
    }
};

struct ProfileTransitionConfig {
    /// Per-session binding for every control message (e.g. first 16 bytes of
    /// a hash of the established session id / shared secret fingerprint).
    std::array<uint8_t, PROFILE_SESSION_ID_SIZE> session_id{};

    uint64_t first_transition_id = 1;     ///< local transition_id sequence start
    uint32_t retransmit_interval_ms = 200;
    uint32_t max_retransmit_attempts = 5; ///< per control step (incl. first send)
    uint32_t grace_period_ms = 1000;      ///< old-layout RX window after activation
    size_t   max_control_bytes = MAX_CONTROL_BODY_BYTES;
    size_t   max_payload_bytes = 16384;
};

/// What actually happened when a transition became effective.
struct SwitchEvent {
    uint64_t  transition_id = 0;
    ProfileRef from;
    ProfileRef to;
    uint32_t  new_profile_epoch = 0;
    /// Local crypto packet counter (TX direction) at the activation point —
    /// the position in the crypto stream from which this endpoint's new
    /// layout is effective. NOT a transition sequence number.
    uint64_t  effective_counter = 0;
    /// true  => confirmed by peer CONFIRM or first valid new-layout data;
    /// false => completed after a post-activation timeout (UNCERTAIN —
    ///          the peer may have aborted; no silent rollback either way).
    bool confirmed = false;
    /// true if confirmation came from valid new-layout data (not CONFIRM).
    bool via_data = false;
};

struct RetransmitState {
    TransitionMsgType last_message = TransitionMsgType::PREPARE;
    uint32_t attempts = 0;          ///< sends so far (incl. initial)
    uint64_t next_deadline_ms = 0;  ///< next tick() deadline
    bool     active = false;
};

struct ProfileTransitionCounters {
    // ---- data plane ----
    uint64_t tx_data = 0;                 ///< all data messages encoded
    uint64_t tx_data_stable = 0;          ///< encoded on the stable (old) epoch
    uint64_t tx_data_new = 0;             ///< encoded on the activated new epoch
    uint64_t rx_data_stable = 0;          ///< decoded on stable epoch (no transition)
    uint64_t rx_data_new = 0;             ///< decoded on the new epoch post-commit
    uint64_t rx_data_old_grace = 0;       ///< old-epoch data accepted during grace
    uint64_t rx_rejected_early_new = 0;   ///< pending-epoch data before COMMIT
    uint64_t rx_rejected_old_expired = 0; ///< superseded-epoch data after the
                                          ///< grace deadline (old decoder
                                          ///< removed), before or after
                                          ///< finalize
    uint64_t rx_rejected_unknown_epoch = 0;
    uint64_t rx_rejected_malformed = 0;
    // ---- control plane ----
    uint64_t control_tx = 0;
    uint64_t control_rx = 0;
    uint64_t control_rx_rejected = 0;  ///< parse / binding / fencing failures
    uint64_t control_retransmits = 0;
    uint64_t control_duplicates = 0;   ///< deduped replays (no state change)
    // ---- transitions (committed vs effective vs uncertain) ----
    uint64_t transitions_started = 0;
    uint64_t transitions_committed = 0;   ///< local activation performed
    uint64_t transitions_effective = 0;   ///< confirmed (CONFIRM / new data)
    uint64_t transitions_uncertain = 0;   ///< completed after timeout, unconfirmed
    uint64_t transitions_aborted = 0;     ///< clean pre-activation abort/rollback
    uint64_t transitions_timed_out = 0;   ///< pre-activation timeouts
    uint64_t aborts_ignored_post_activation = 0;
};

// ==================== Control message (wire view) ====================

struct ControlMessage {
    TransitionMsgType type = TransitionMsgType::PREPARE;
    std::array<uint8_t, PROFILE_SESSION_ID_SIZE> session_id{};
    uint64_t transition_id = 0;
    uint32_t profile_epoch = 0;       ///< TARGET profile epoch
    /// Sender's EFFECTIVE crypto packet counter for the transition's
    /// direction at message build time (e.g. ratchet sending chain length
    /// for TX/BIDIRECTIONAL, receive counter for RX_ONLY). Monotonic per
    /// crypto_epoch; verified against the crypto stream, NOT a transition
    /// sequence number.
    uint64_t effective_counter = 0;
    uint64_t crypto_epoch = 0;        ///< sender's current crypto epoch
    TransitionDirection direction = TransitionDirection::BIDIRECTIONAL;
    uint8_t  reason = 0;              ///< AbortReason for ABORT, app-defined otherwise
    uint32_t grace_ms = 0;            ///< proposed/accepted grace (PREPARE/READY/COMMIT)
    ProfileRef target;                ///< empty id for ABORT
};

/// Strict bounded codec for control bodies (plaintext, pre-AEAD).
/// Unknown type/version, inconsistent or oversized input => nullopt;
/// no partial state is ever produced.
class ProfileTransitionCodec {
public:
    /// Serialise. Returns nullopt if the message itself is out of bounds.
    static std::optional<std::vector<uint8_t>> encode(
        const ControlMessage& msg, size_t max_bytes = MAX_CONTROL_BODY_BYTES);

    /// Strict parse: exact length, bounded id, full identity for
    /// PREPARE/READY/COMMIT/CONFIRM, identity-free fixed form for ABORT.
    static std::optional<ControlMessage> decode(
        const uint8_t* data, size_t len, size_t max_bytes = MAX_CONTROL_BODY_BYTES);
    static std::optional<ControlMessage> decode(
        const std::vector<uint8_t>& v, size_t max_bytes = MAX_CONTROL_BODY_BYTES) {
        return decode(v.data(), v.size(), max_bytes);
    }
};

// ==================== Manager (FSM, plaintext level) ====================

struct ProfileTransitionHooks {
    /// Every call MUST be freshly encrypted by the callee (the manager
    /// supplies plaintext; ciphertext is never cached or reused).
    std::function<void(const std::vector<uint8_t>& control_plaintext)> emit_control;
    /// Resolve layout params for an inbound PREPARE target (read-only
    /// catalog lookup etc.). nullopt => ABORT(UNKNOWN_PROFILE).
    std::function<std::optional<ProfileLayoutParams>(const ProfileRef&)> resolve_layout;
    /// Sender-side effective crypto packet counter for the given direction
    /// (e.g. E2ESession sending/receiving chain length). Bound into every
    /// outbound control message; called fresh on each (re)build, so a
    /// retransmission carries a FRESH counter under the same transition_id.
    /// When unset, 0 is sent and only crypto_epoch fencing applies.
    std::function<uint64_t(TransitionDirection)> local_crypto_counter;
    /// Inbound upper-bound validation of the peer's claimed effective
    /// counter against the crypto stream. `packet_counter` is the crypto
    /// counter of the carrying packet when known (nullopt when the message
    /// arrived below the crypto layer). Return false => message rejected.
    std::function<bool(uint64_t claimed, TransitionDirection,
                       std::optional<uint64_t> packet_counter)> validate_peer_claim;
    /// Local activation point (COMMIT applied). After this returns, TX uses
    /// the new layout (subject to direction) and RX accepts new + old-in-grace.
    std::function<void(const ProfileRef& target,
                       const ProfileLayoutParams& layout,
                       uint32_t new_profile_epoch,
                       TransitionDirection dir)> on_activate;
    /// Transition became effective (CONFIRM / valid new data), or completed
    /// unconfirmed after a post-activation timeout (event.confirmed=false).
    /// NEVER fired for a mere request.
    std::function<void(const SwitchEvent&)> on_switch;
    /// Clean pre-activation abort/rollback (local or peer initiated). Also
    /// fired when an inbound proposal is REFUSED with ABORT(UNKNOWN_PROFILE)
    /// while IDLE — the refusal is a clean pre-activation abort of the
    /// proposed transition_id and is recorded in transitions_aborted.
    std::function<void(uint64_t transition_id, AbortReason)> on_aborted;
};

/**
 * Generic per-session profile-transition FSM. One instance per protected
 * session; owns stable/pending profile identity, the single outstanding
 * transition, retransmission state and the grace deadline. Crypto-agnostic:
 * inbound messages are already AEAD-decrypted, outbound messages are
 * plaintext handed to hooks.emit_control.
 */
class ProfileTransitionManager {
public:
    ProfileTransitionManager(ProfileTransitionConfig cfg,
                             ProfileRef stable_profile,
                             uint32_t stable_profile_epoch = 0);
    ~ProfileTransitionManager();

    ProfileTransitionManager(const ProfileTransitionManager&) = delete;
    ProfileTransitionManager& operator=(const ProfileTransitionManager&) = delete;

    void set_hooks(ProfileTransitionHooks hooks);

    /// Negotiated profile_transition_v1 capability. When false,
    /// start_transition() returns NOT_SUPPORTED and emit_control is never
    /// invoked; inbound control messages are rejected without any outbound.
    void set_peer_capable(bool capable);
    bool peer_capable() const;

    /// Host-reported LOCAL crypto epoch (e.g. key-rotation count). Bound
    /// into OUTBOUND messages only. Inbound crypto-epoch fencing is
    /// PEER-epoch-relative: the peer's first message of a transition binds
    /// the peer's epoch (replays below that bound are rejected, forward
    /// motion ratchets it), and the cross-transition PREPARE fence tracks
    /// the highest peer-advertised epoch of completed transitions. The local
    /// epoch never fences peer messages — E2E epochs are permanently
    /// asymmetric between the endpoints (the rotation initiator gains +2
    /// per completed DH cycle, the responder +1).
    void set_crypto_epoch(uint64_t epoch);
    uint64_t crypto_epoch() const;

    bool has_outstanding() const;  ///< state != IDLE
    bool is_activated() const;     ///< state == COMMIT || state == DRAIN

    TransitionError start_transition(ProfileRef target,
                                     TransitionDirection direction,
                                     uint8_t reason,
                                     uint32_t grace_ms,
                                     uint64_t now_ms);

    /// Local pre-activation abort. Returns false if there is no outstanding
    /// transition or it is already activated (no rollback post-activation).
    bool abort_transition(AbortReason reason, uint64_t now_ms);

    /// Inbound AEAD-decrypted control body. `packet_crypto_counter` is the
    /// crypto counter of the carrying packet when known (enables the
    /// upper-bound check on the claimed effective counter). Returns true if
    /// accepted (duplicates included); false if rejected without state
    /// corruption.
    bool on_control_plaintext(const uint8_t* data, size_t len, uint64_t now_ms,
                              std::optional<uint64_t> packet_crypto_counter =
                                  std::nullopt);
    bool on_control_plaintext(const std::vector<uint8_t>& v, uint64_t now_ms,
                              std::optional<uint64_t> packet_crypto_counter =
                                  std::nullopt) {
        return on_control_plaintext(v.data(), v.size(), now_ms,
                                    packet_crypto_counter);
    }

    /// Valid new-layout data observed by the data plane. Confirms the peer
    /// only in COMMIT state; a no-op otherwise (early data never confirms).
    void note_new_layout_data(uint64_t now_ms);

    /// Deterministic retransmission / timeout driver.
    void tick(uint64_t now_ms);

    // ---- state ----
    ProfileTransitionState state() const;
    const ProfileRef& stable_profile() const;
    std::optional<ProfileRef> pending_profile() const;
    uint32_t stable_profile_epoch() const;    ///< effective epoch
    uint32_t current_profile_epoch() const;   ///< pending epoch while activated
    uint64_t transition_id() const;           ///< outstanding tid (0 if none)
    /// Last accepted effective crypto packet counter claimed by the peer
    /// (monotonic fence state, per current crypto epoch). 0 if none yet.
    uint64_t peer_effective_counter() const;
    TransitionDirection direction() const;
    RetransmitState retransmit_state() const;
    std::optional<uint64_t> activation_time_ms() const;
    std::optional<uint64_t> grace_deadline_ms() const;
    uint32_t grace_period_ms() const;

    /// Raise the configured grace period to at least floor_ms (never
    /// lowers it). For protocol-level grace floors learned after
    /// construction (e.g. a negotiated-capability-dependent clamp applied
    /// by an adapter). Affects the locally proposed grace AND the
    /// responder-side clamp on peer-proposed values; the grace already
    /// bound to an in-flight transition is NOT retroactively changed.
    void set_grace_floor_ms(uint32_t floor_ms);
    /// Configured grace ceiling (ProfileTransitionConfig::grace_period_ms,
    /// possibly raised by set_grace_floor_ms) — distinct from
    /// grace_period_ms(), which reports the CURRENT transition's value
    /// (0 before any transition).
    uint32_t configured_grace_period_ms() const;

    const ProfileTransitionCounters& counters() const;

private:
    struct Impl;
    Impl* impl_;
};

// ==================== SessionProfileContext ====================

/**
 * Per-session owner of profile state + data-plane framing. Composes a
 * ProfileTransitionManager with the session's existing crypto channel
 * (typically E2ESession) and a simple authenticated-layout framing adapter.
 *
 * Crypto is injected, never owned: encrypt() is called fresh for every
 * outbound message (initial send AND every retransmit), so the ratchet
 * counter/nonce/tag are always new while the logical transition_id stays.
 * decrypt() failures (AEAD/replay) are treated as transport drops — the
 * transition layer keeps its own dedup by (transition_id, state), never by
 * crypto counter.
 */
class SessionProfileContext {
public:
    struct Crypto {
        /// plaintext -> wire ciphertext (fresh encryption on every call)
        std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> encrypt;
        /// wire ciphertext -> plaintext (nullopt on auth/replay failure)
        std::function<std::optional<std::vector<uint8_t>>(
            const std::vector<uint8_t>&)> decrypt;
        /// Optional: decrypt + report the crypto packet counter of the
        /// carrying packet (e.g. EncryptedMessage::header.message_number).
        /// Enables upper-bound validation of effective_counter claims.
        std::function<std::optional<std::pair<std::vector<uint8_t>, uint64_t>>(
            const std::vector<uint8_t>&)> decrypt_ex;
        /// Effective crypto packet counters per direction (e.g.
        /// E2ESession::get_sending_chain_length / get_receiving_chain_length).
        /// Bound into outbound control messages; NOT reset by transitions.
        std::function<uint64_t()> tx_crypto_counter;
        std::function<uint64_t()> rx_crypto_counter;
    };

    SessionProfileContext(ProfileTransitionConfig cfg,
                          ProfileRef stable_profile,
                          ProfileLayoutParams stable_layout,
                          Crypto crypto);
    ~SessionProfileContext();

    SessionProfileContext(const SessionProfileContext&) = delete;
    SessionProfileContext& operator=(const SessionProfileContext&) = delete;

    // ---- wiring ----
    void set_peer_capable(bool capable);
    void set_crypto_epoch(uint64_t epoch);
    void set_layout_resolver(
        std::function<std::optional<ProfileLayoutParams>(const ProfileRef&)> r);
    /// Receives fully encrypted wire bytes for outbound control messages.
    void set_control_outbound_handler(
        std::function<void(const std::vector<uint8_t>& wire)> h);
    void set_switch_event_handler(std::function<void(const SwitchEvent&)> h);
    void set_abort_handler(
        std::function<void(uint64_t transition_id, AbortReason)> h);
    /// Epoch-fence observers: fired at local activation with
    /// (old_epoch, new_epoch) so hosts can cancel queued shape/timer work
    /// bound to superseded epochs. (Coordination point — this module never
    /// touches shaper/stats objects directly.)
    void add_epoch_observer(
        std::function<void(uint32_t old_epoch, uint32_t new_epoch)> obs);

    // ---- data plane ----
    /// Encode an application payload under the current TX profile/epoch.
    /// Returns the wire ciphertext (freshly encrypted), or nullopt if the
    /// payload exceeds limits or crypto is not wired.
    std::optional<std::vector<uint8_t>> encode_data(
        const std::vector<uint8_t>& payload);

    /// Inbound wire ciphertext: decrypt, then route control vs data.
    /// Returns the decoded application payload for data messages;
    /// nullopt for control messages and for any rejection.
    std::optional<std::vector<uint8_t>> on_ciphertext(
        const std::vector<uint8_t>& wire, uint64_t now_ms);

    /// Plaintext-level entry point for hosts that decrypt themselves.
    /// The plaintext must carry the NCP message tag (0x03 control / 0x00
    /// data); without the negotiated capability the wire format is legacy
    /// (untagged payload passed through unchanged). `packet_crypto_counter`
    /// (crypto counter of the carrying packet, when known) enables the
    /// effective_counter upper-bound check. Returns decoded payload for
    /// data, nullopt otherwise.
    std::optional<std::vector<uint8_t>> on_plaintext(
        const std::vector<uint8_t>& plaintext, uint64_t now_ms,
        std::optional<uint64_t> packet_crypto_counter = std::nullopt);

    // ---- transitions ----
    TransitionError start_transition(ProfileRef target,
                                     ProfileLayoutParams target_layout,
                                     TransitionDirection direction,
                                     uint8_t reason,
                                     uint64_t now_ms);
    bool abort_transition(AbortReason reason, uint64_t now_ms);
    void tick(uint64_t now_ms);

    // ---- state / stats ----
    ProfileTransitionState state() const;
    const ProfileRef& stable_profile() const;
    std::optional<ProfileRef> pending_profile() const;
    ProfileRef tx_profile() const;       ///< profile currently used for encoding
    ProfileRef rx_primary_profile() const; ///< preferred decode profile
    uint32_t profile_epoch() const;      ///< effective (stable) epoch
    uint32_t tx_epoch() const;           ///< epoch stamped on outbound data
    /// Epoch fence: data epochs below this are never accepted. Hosts may use
    /// it to cancel queued shape/timer operations for superseded epochs.
    uint32_t min_accepted_data_epoch() const;
    /// Last accepted effective crypto packet counter claimed by the peer.
    uint64_t peer_effective_counter() const;
    std::optional<uint64_t> grace_deadline_ms() const;
    bool in_grace_period(uint64_t now_ms) const;

    /// Raise the effective grace period (this context AND the composed
    /// manager) to at least floor_ms; never lowers it. See
    /// ProfileTransitionManager::set_grace_floor_ms.
    void set_grace_floor_ms(uint32_t floor_ms);
    /// Configured grace ceiling (post any set_grace_floor_ms raise).
    uint32_t configured_grace_period_ms() const;

    ProfileTransitionCounters counters() const;  ///< merged manager+data view
    ProfileTransitionManager& manager();
    const ProfileTransitionManager& manager() const;

private:
    struct Impl;
    Impl* impl_;
};

// ==================== Optional catalog integration (read-only) ====================

struct ProfileDescriptor;        // ncp_reference_profile_catalog.hpp
class ReferenceProfileCatalog;   // ncp_reference_profile_catalog.hpp

/// Map a catalog descriptor to wire identity + layout params. Read-only;
/// the descriptor is never copied into control messages.
ProfileRef profile_ref_from_descriptor(const ProfileDescriptor& d);
ProfileLayoutParams profile_layout_from_descriptor(const ProfileDescriptor& d);

/// Build a layout resolver backed by a read-only catalog lookup
/// (id + revision, content_hash verified). Returns nullopt on mismatch.
std::function<std::optional<ProfileLayoutParams>(const ProfileRef&)>
make_catalog_layout_resolver(const ReferenceProfileCatalog* catalog);

} // namespace ncp

#endif // NCP_PROFILE_TRANSITION_HPP
