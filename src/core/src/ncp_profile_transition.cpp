/**
 * @file ncp_profile_transition.cpp
 * @brief Generic per-session seamless profile transition — implementation.
 *
 * See ncp_profile_transition.hpp for the protocol description. This module
 * NEVER touches crypto ratchet state, replay windows, TLS/mimicry session
 * state, porthop epochs, or shaper/stats objects; epoch-fence observers are
 * the only coordination point with queued shape/timer work.
 */

#include "ncp_profile_transition.hpp"
#include "ncp_capabilities.hpp"               // NCP message tag conventions
#include "ncp_reference_profile_catalog.hpp"  // read-only catalog integration

#include <algorithm>
#include <cstring>

namespace ncp {

// ==================== to_string ====================

const char* to_string(ProfileTransitionState s) noexcept {
    switch (s) {
        case ProfileTransitionState::IDLE:    return "IDLE";
        case ProfileTransitionState::PREPARE: return "PREPARE";
        case ProfileTransitionState::READY:   return "READY";
        case ProfileTransitionState::COMMIT:  return "COMMIT";
        case ProfileTransitionState::DRAIN:   return "DRAIN";
    }
    return "unknown";
}
const char* to_string(TransitionMsgType t) noexcept {
    switch (t) {
        case TransitionMsgType::PREPARE: return "PREPARE";
        case TransitionMsgType::READY:   return "READY";
        case TransitionMsgType::COMMIT:  return "COMMIT";
        case TransitionMsgType::CONFIRM: return "CONFIRM";
        case TransitionMsgType::ABORT:   return "ABORT";
    }
    return "unknown";
}
const char* to_string(TransitionError e) noexcept {
    switch (e) {
        case TransitionError::NONE:            return "none";
        case TransitionError::NOT_SUPPORTED:   return "not_supported";
        case TransitionError::BUSY:            return "busy";
        case TransitionError::INVALID_PROFILE: return "invalid_profile";
        case TransitionError::STALE_EPOCH:     return "stale_epoch";
        case TransitionError::INVALID_STATE:   return "invalid_state";
    }
    return "unknown";
}
const char* to_string(AbortReason r) noexcept {
    switch (r) {
        case AbortReason::NONE:            return "none";
        case AbortReason::LOCAL_REQUEST:   return "local_request";
        case AbortReason::PEER_BUSY:       return "peer_busy";
        case AbortReason::TIMEOUT:         return "timeout";
        case AbortReason::UNKNOWN_PROFILE: return "unknown_profile";
        case AbortReason::PROTOCOL_ERROR:  return "protocol_error";
        case AbortReason::STALE_EPOCH:     return "stale_epoch";
    }
    return "unknown";
}

// ==================== BE helpers ====================
namespace {

void put_u16(std::vector<uint8_t>& o, uint16_t v) {
    o.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    o.push_back(static_cast<uint8_t>(v & 0xFF));
}
void put_u32(std::vector<uint8_t>& o, uint32_t v) {
    o.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    o.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    o.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    o.push_back(static_cast<uint8_t>(v & 0xFF));
}
void put_u64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 7; i >= 0; --i)
        o.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

struct Reader {
    const uint8_t* p;
    size_t n;
    size_t pos = 0;
    bool u8(uint8_t& v)  { if (pos + 1 > n) return false; v = p[pos++]; return true; }
    bool u16(uint16_t& v) {
        if (pos + 2 > n) return false;
        v = static_cast<uint16_t>((p[pos] << 8) | p[pos + 1]); pos += 2; return true;
    }
    bool u32(uint32_t& v) {
        if (pos + 4 > n) return false;
        v = (static_cast<uint32_t>(p[pos]) << 24) |
            (static_cast<uint32_t>(p[pos + 1]) << 16) |
            (static_cast<uint32_t>(p[pos + 2]) << 8) |
             static_cast<uint32_t>(p[pos + 3]);
        pos += 4; return true;
    }
    bool u64(uint64_t& v) {
        if (pos + 8 > n) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p[pos + i];
        pos += 8; return true;
    }
    bool bytes(uint8_t* dst, size_t k) {
        if (pos + k > n) return false;
        std::memcpy(dst, p + pos, k); pos += k; return true;
    }
};

// Control body layout (all big-endian):
//   'P','T' | version:1 | type:1 | session_id:16 | transition_id:8 |
//   profile_epoch:4 | effective_counter:8 | crypto_epoch:8 | direction:1 |
//   reason:1 | grace_ms:4 | profile_id_len:1 |
//   [profile_id:N | revision:4 | content_hash:32]   (absent for ABORT)
constexpr size_t kCtlFixedBeforeId = 55;   // up to and including profile_id_len
constexpr size_t kCtlIdTail = 4 + PROFILE_HASH_SIZE;  // revision + hash
constexpr uint8_t kCtlMagic0 = 'P';
constexpr uint8_t kCtlMagic1 = 'T';

} // namespace

// ==================== Codec ====================

std::optional<std::vector<uint8_t>> ProfileTransitionCodec::encode(
    const ControlMessage& m, size_t max_bytes) {

    if (max_bytes > MAX_CONTROL_BODY_BYTES) max_bytes = MAX_CONTROL_BODY_BYTES;

    const bool is_abort = (m.type == TransitionMsgType::ABORT);
    if (!is_abort && !m.target.valid()) return std::nullopt;
    if (is_abort && !m.target.id.empty()) return std::nullopt;

    std::vector<uint8_t> o;
    o.reserve(96);
    o.push_back(kCtlMagic0);
    o.push_back(kCtlMagic1);
    o.push_back(PROFILE_TRANSITION_WIRE_VERSION);
    o.push_back(static_cast<uint8_t>(m.type));
    o.insert(o.end(), m.session_id.begin(), m.session_id.end());
    put_u64(o, m.transition_id);
    put_u32(o, m.profile_epoch);
    put_u64(o, m.effective_counter);
    put_u64(o, m.crypto_epoch);
    o.push_back(static_cast<uint8_t>(m.direction));
    o.push_back(m.reason);
    put_u32(o, m.grace_ms);

    if (is_abort) {
        o.push_back(0);  // profile_id_len = 0, no identity tail
    } else {
        o.push_back(static_cast<uint8_t>(m.target.id.size()));
        o.insert(o.end(), m.target.id.begin(), m.target.id.end());
        put_u32(o, m.target.revision);
        o.insert(o.end(), m.target.content_hash.begin(),
                 m.target.content_hash.end());
    }
    if (o.size() > max_bytes) return std::nullopt;
    return o;
}

std::optional<ControlMessage> ProfileTransitionCodec::decode(
    const uint8_t* data, size_t len, size_t max_bytes) {

    if (max_bytes > MAX_CONTROL_BODY_BYTES) max_bytes = MAX_CONTROL_BODY_BYTES;
    if (!data) return std::nullopt;
    if (len < kCtlFixedBeforeId || len > max_bytes) return std::nullopt;

    Reader r{data, len, 0};
    uint8_t m0, m1, ver, type;
    if (!r.u8(m0) || !r.u8(m1) || !r.u8(ver) || !r.u8(type)) return std::nullopt;
    if (m0 != kCtlMagic0 || m1 != kCtlMagic1) return std::nullopt;
    if (ver != PROFILE_TRANSITION_WIRE_VERSION) return std::nullopt;
    if (type < static_cast<uint8_t>(TransitionMsgType::PREPARE) ||
        type > static_cast<uint8_t>(TransitionMsgType::ABORT)) return std::nullopt;

    ControlMessage m;
    m.type = static_cast<TransitionMsgType>(type);
    if (!r.bytes(m.session_id.data(), PROFILE_SESSION_ID_SIZE)) return std::nullopt;
    if (!r.u64(m.transition_id)) return std::nullopt;
    if (!r.u32(m.profile_epoch)) return std::nullopt;
    if (!r.u64(m.effective_counter)) return std::nullopt;
    if (!r.u64(m.crypto_epoch)) return std::nullopt;
    uint8_t dir, reason;
    if (!r.u8(dir) || !r.u8(reason)) return std::nullopt;
    if (dir > static_cast<uint8_t>(TransitionDirection::RX_ONLY)) return std::nullopt;
    m.direction = static_cast<TransitionDirection>(dir);
    m.reason = reason;
    if (!r.u32(m.grace_ms)) return std::nullopt;

    uint8_t id_len;
    if (!r.u8(id_len)) return std::nullopt;

    if (m.type == TransitionMsgType::ABORT) {
        // ABORT carries no identity: strict fixed-size form.
        if (id_len != 0) return std::nullopt;
        if (r.pos != len) return std::nullopt;  // no trailing bytes
        return m;
    }

    if (id_len == 0 || id_len > MAX_PROFILE_ID_LEN) return std::nullopt;
    if (r.pos + id_len + kCtlIdTail != len) return std::nullopt;  // exact length
    m.target.id.assign(reinterpret_cast<const char*>(r.p + r.pos), id_len);
    r.pos += id_len;
    if (!r.u32(m.target.revision)) return std::nullopt;
    if (!r.bytes(m.target.content_hash.data(), PROFILE_HASH_SIZE)) return std::nullopt;
    if (r.pos != len) return std::nullopt;
    return m;
}

// ==================== Manager ====================

struct ProfileTransitionManager::Impl {
    ProfileTransitionConfig cfg;
    ProfileTransitionHooks hooks;

    ProfileRef stable;
    uint32_t   stable_epoch = 0;

    bool peer_capable = false;
    /// LOCAL crypto epoch (host-reported, e.g. key-rotation count). Bound
    /// into OUTBOUND messages only. It must never fence inbound ones: E2E
    /// epochs are permanently asymmetric between the endpoints (the rotation
    /// initiator gains +2 per completed DH cycle, the responder +1).
    uint64_t crypto_epoch = 0;
    /// Cross-transition PREPARE fence, PEER-epoch-relative: the highest
    /// crypto epoch the PEER advertised in a completed transition. The local
    /// epoch is never mixed in.
    uint64_t last_completed_peer_crypto_epoch = 0;

    ProfileTransitionState state = ProfileTransitionState::IDLE;

    // outstanding transition (valid when state != IDLE)
    uint64_t tid = 0;
    uint64_t next_tid = 1;
    ProfileRef pending;
    uint32_t pending_epoch = 0;
    TransitionDirection direction = TransitionDirection::BIDIRECTIONAL;
    uint32_t grace_ms = 0;
    /// Per-transition PEER crypto-epoch fence. The peer's first message of
    /// the transition binds its epoch (PREPARE at the responder; the first
    /// valid non-PREPARE message at the initiator). Subsequent messages must
    /// not regress below the bound — older-generation replays are rejected —
    /// while forward motion (a mid-transition peer rekey) ratchets it. The
    /// LOCAL crypto epoch never participates (see crypto_epoch above).
    uint64_t peer_bound_crypto_epoch = 0;
    bool     peer_bound_set = false;
    bool     initiator = false;

    // Effective-counter fencing: the peer's claimed crypto packet counter is
    // monotonic within a crypto epoch and resets when the epoch advances.
    bool     has_peer_claim = false;
    uint64_t peer_claim = 0;
    uint64_t peer_claim_epoch = 0;
    uint64_t local_claim_at_activation = 0;  // recorded for SwitchEvent

    // Retransmission state (single outstanding logical message). The body is
    // REBUILT on every retransmit — same transition_id, freshly sampled
    // effective counter — and the context re-encrypts with a fresh ratchet
    // counter/nonce/tag. Ciphertext is never stored or reused.
    TransitionMsgType last_type = TransitionMsgType::PREPARE;
    uint8_t  last_reason = 0;
    std::vector<uint8_t> last_plaintext;  // most recent build (reference only)
    uint32_t attempts = 0;
    uint64_t deadline = 0;

    uint64_t activated_at = 0;
    uint64_t grace_deadline = 0;
    bool     peer_confirmed = false;
    /// Bounded courtesy re-CONFIRMs while in DRAIN (answers a peer whose
    /// CONFIRM retransmission proves it never saw ours). Capped by
    /// cfg.max_retransmit_attempts so a CONFIRM->CONFIRM echo between two
    /// DRAIN peers self-terminates instead of ping-ponging until grace end.
    uint32_t drain_confirm_replies = 0;

    ProfileTransitionCounters counters;

    explicit Impl(ProfileTransitionConfig c, ProfileRef s, uint32_t epoch)
        : cfg(std::move(c)), stable(std::move(s)), stable_epoch(epoch) {
        next_tid = cfg.first_transition_id ? cfg.first_transition_id : 1;
    }

    bool is_activated() const {
        return state == ProfileTransitionState::COMMIT ||
               state == ProfileTransitionState::DRAIN;
    }

    void emit(TransitionMsgType type, const std::vector<uint8_t>& plaintext) {
        last_type = type;
        last_plaintext = plaintext;
        counters.control_tx++;
        if (hooks.emit_control) hooks.emit_control(plaintext);
    }

    /// Send a message that is NOT part of the current retransmission step
    /// (e.g. a busy-refusal ABORT for a foreign proposal) — must NOT clobber
    /// the outstanding transition's retransmission state (regression M3).
    void emit_side(const std::vector<uint8_t>& plaintext) {
        counters.control_tx++;
        if (hooks.emit_control) hooks.emit_control(plaintext);
    }

    uint64_t local_claim(TransitionDirection dir) const {
        if (hooks.local_crypto_counter) return hooks.local_crypto_counter(dir);
        return 0;
    }

    ControlMessage base_msg(TransitionMsgType t) const {
        ControlMessage m;
        m.type = t;
        m.session_id = cfg.session_id;
        m.transition_id = tid;
        m.profile_epoch = pending_epoch;
        m.effective_counter = local_claim(direction);
        m.crypto_epoch = crypto_epoch;
        m.direction = direction;
        m.grace_ms = grace_ms;
        m.target = pending;
        return m;
    }

    bool send(TransitionMsgType t, uint8_t reason = 0) {
        auto m = base_msg(t);
        m.reason = reason;
        if (t == TransitionMsgType::ABORT) m.target = ProfileRef{};
        auto enc = ProfileTransitionCodec::encode(m, cfg.max_control_bytes);
        if (!enc) return false;
        last_type = t;
        last_reason = reason;
        emit(t, *enc);
        return true;
    }

    void arm(uint64_t now) {  // first send of a step
        attempts = 1;
        deadline = now + cfg.retransmit_interval_ms;
    }

    void retransmit(uint64_t now) {
        attempts++;
        deadline = now + cfg.retransmit_interval_ms;
        counters.control_retransmits++;
        send(last_type, last_reason);  // rebuild: fresh claim + fresh crypto
    }

    void activate(uint64_t now) {
        counters.transitions_committed++;
        activated_at = now;
        grace_deadline = now + grace_ms;
        peer_confirmed = false;
        local_claim_at_activation = local_claim(direction);
        if (hooks.on_activate)
            hooks.on_activate(pending, ProfileLayoutParams{}, pending_epoch,
                              direction);
        // NOTE: layout params are carried by the context, not the manager;
        // the context's hook supplies the concrete layout.
        state = ProfileTransitionState::COMMIT;
    }

    SwitchEvent make_switch_event(bool confirmed, bool via_data) const {
        SwitchEvent ev;
        ev.transition_id = tid;
        ev.from = stable;
        ev.to = pending;
        ev.new_profile_epoch = pending_epoch;
        ev.effective_counter = local_claim_at_activation;
        ev.confirmed = confirmed;
        ev.via_data = via_data;
        return ev;
    }

    void become_effective(bool via_data, uint64_t now) {
        (void)now;
        peer_confirmed = true;
        state = ProfileTransitionState::DRAIN;
        // no more retransmits; deadline becomes the grace deadline
        attempts = 0;
        deadline = grace_deadline;
        drain_confirm_replies = 0;
        counters.transitions_effective++;
        if (hooks.on_switch) hooks.on_switch(make_switch_event(true, via_data));
    }

    void become_uncertain(uint64_t now) {
        (void)now;
        peer_confirmed = false;
        state = ProfileTransitionState::DRAIN;
        attempts = 0;
        deadline = grace_deadline;
        drain_confirm_replies = 0;
        counters.transitions_uncertain++;
        if (hooks.on_switch) hooks.on_switch(make_switch_event(false, false));
    }

    void finalize() {  // DRAIN -> IDLE: new profile becomes stable
        stable = pending;
        stable_epoch = pending_epoch;
        // Record ONLY the peer-sourced epoch bound observed during this
        // transition; the local crypto epoch is never mixed in (it runs
        // ahead of the peer's on the rotation initiator and would poison
        // the cross-transition PREPARE fence against peer-led transitions).
        if (peer_bound_set) {
            last_completed_peer_crypto_epoch =
                std::max(last_completed_peer_crypto_epoch,
                         peer_bound_crypto_epoch);
        }
        clear_transition();
    }

    void clear_transition() {
        state = ProfileTransitionState::IDLE;
        tid = 0;
        pending = ProfileRef{};
        pending_epoch = 0;
        last_plaintext.clear();
        last_reason = 0;
        attempts = 0;
        deadline = 0;
        peer_confirmed = false;
        initiator = false;
        drain_confirm_replies = 0;
        peer_bound_crypto_epoch = 0;
        peer_bound_set = false;
    }

    void rollback(uint64_t now, AbortReason reason, bool count_timeout) {
        (void)now;
        uint64_t aborted_tid = tid;
        clear_transition();
        if (count_timeout) counters.transitions_timed_out++;
        else counters.transitions_aborted++;
        if (hooks.on_aborted) hooks.on_aborted(aborted_tid, reason);
    }
};

ProfileTransitionManager::ProfileTransitionManager(
    ProfileTransitionConfig cfg, ProfileRef stable_profile,
    uint32_t stable_profile_epoch)
    : impl_(new Impl(std::move(cfg), std::move(stable_profile),
                     stable_profile_epoch)) {}

ProfileTransitionManager::~ProfileTransitionManager() { delete impl_; }

void ProfileTransitionManager::set_hooks(ProfileTransitionHooks hooks) {
    impl_->hooks = std::move(hooks);
}
void ProfileTransitionManager::set_peer_capable(bool capable) {
    impl_->peer_capable = capable;
}
bool ProfileTransitionManager::peer_capable() const { return impl_->peer_capable; }
void ProfileTransitionManager::set_crypto_epoch(uint64_t epoch) {
    impl_->crypto_epoch = epoch;
}
uint64_t ProfileTransitionManager::crypto_epoch() const {
    return impl_->crypto_epoch;
}
bool ProfileTransitionManager::has_outstanding() const {
    return impl_->state != ProfileTransitionState::IDLE;
}
bool ProfileTransitionManager::is_activated() const {
    return impl_->is_activated();
}

TransitionError ProfileTransitionManager::start_transition(
    ProfileRef target, TransitionDirection direction, uint8_t reason,
    uint32_t grace_ms, uint64_t now_ms) {

    auto& im = *impl_;
    if (!im.peer_capable) return TransitionError::NOT_SUPPORTED;
    if (im.state != ProfileTransitionState::IDLE) return TransitionError::BUSY;
    if (!target.valid()) return TransitionError::INVALID_PROFILE;

    im.initiator = true;
    im.tid = im.next_tid++;
    im.pending = std::move(target);
    im.pending_epoch = im.stable_epoch + 1;
    im.direction = direction;
    im.grace_ms = grace_ms ? grace_ms : im.cfg.grace_period_ms;
    // No epoch binding here: the PEER's epoch is bound from its first
    // message of the transition (READY), never from the local epoch.
    im.state = ProfileTransitionState::PREPARE;
    im.counters.transitions_started++;
    im.arm(now_ms);
    im.send(TransitionMsgType::PREPARE, reason);
    return TransitionError::NONE;
}

bool ProfileTransitionManager::abort_transition(AbortReason reason,
                                                uint64_t now_ms) {
    auto& im = *impl_;
    if (im.state == ProfileTransitionState::IDLE) return false;
    if (im.is_activated()) {
        // Post-activation: no rollback. The only way back is a new transition.
        im.counters.aborts_ignored_post_activation++;
        return false;
    }
    im.send(TransitionMsgType::ABORT, static_cast<uint8_t>(reason));
    im.rollback(now_ms, reason, false);
    return true;
}

bool ProfileTransitionManager::on_control_plaintext(
    const uint8_t* data, size_t len, uint64_t now_ms,
    std::optional<uint64_t> packet_crypto_counter) {

    auto& im = *impl_;

    auto msg = ProfileTransitionCodec::decode(data, len, im.cfg.max_control_bytes);
    if (!msg) { im.counters.control_rx_rejected++; return false; }

    // Session binding first: never act on foreign sessions.
    if (msg->session_id != im.cfg.session_id) {
        im.counters.control_rx_rejected++; return false;
    }

    // Capability gate: without negotiation we never emit anything outbound.
    if (!im.peer_capable) {
        im.counters.control_rx_rejected++; return false;
    }

    // ---- effective-counter fence (peer's claimed crypto packet counter):
    // monotonic within a crypto epoch, resets when the peer's crypto epoch
    // advances, rejects regressions (cross-epoch/counter replays).
    if (im.has_peer_claim) {
        if (msg->crypto_epoch < im.peer_claim_epoch ||
            (msg->crypto_epoch == im.peer_claim_epoch &&
             msg->effective_counter < im.peer_claim)) {
            im.counters.control_rx_rejected++; return false;
        }
    }
    // Upper-bound validation against the actual crypto stream.
    if (im.hooks.validate_peer_claim &&
        !im.hooks.validate_peer_claim(msg->effective_counter, msg->direction,
                                      packet_crypto_counter)) {
        im.counters.control_rx_rejected++; return false;
    }

    im.counters.control_rx++;
    const TransitionMsgType t = msg->type;

    // ---- epoch fencing ----
    const uint32_t expected_epoch = (im.state == ProfileTransitionState::IDLE)
        ? im.stable_epoch + 1 : im.pending_epoch;
    if (msg->profile_epoch != expected_epoch) {
        im.counters.control_rx_rejected++; return false;
    }
    if (t == TransitionMsgType::PREPARE) {
        // crypto-epoch monotonic fence across transitions — PEER-relative:
        // the bound is the highest crypto epoch the PEER advertised in a
        // completed transition, never the local epoch (E2E epochs are
        // permanently asymmetric between the endpoints).
        if (msg->crypto_epoch < im.last_completed_peer_crypto_epoch) {
            im.counters.control_rx_rejected++; return false;
        }
    } else {
        if (im.state == ProfileTransitionState::IDLE ||
            msg->transition_id != im.tid) {
            // stale / unknown transition: reject without state corruption
            im.counters.control_rx_rejected++; return false;
        }
        // Peer-epoch fence for the current transition: the first valid peer
        // message binds the peer's epoch; afterwards a message from an older
        // crypto generation is a replay and is rejected, while forward
        // motion (a mid-transition peer rekey) ratchets the bound.
        if (im.peer_bound_set &&
            msg->crypto_epoch < im.peer_bound_crypto_epoch) {
            im.counters.control_rx_rejected++; return false;
        }
        im.peer_bound_crypto_epoch = std::max(im.peer_bound_crypto_epoch,
                                              msg->crypto_epoch);
        im.peer_bound_set = true;
    }

    // All fences passed: record the peer's effective-counter claim. Determine
    // first whether this message ADVANCES the claim: a retransmission is
    // rebuilt with a freshly sampled crypto counter (strictly greater), while
    // a logical replay re-carries the previously recorded one.
    const bool fresh_effective_counter =
        !im.has_peer_claim ||
        msg->crypto_epoch > im.peer_claim_epoch ||
        (msg->crypto_epoch == im.peer_claim_epoch &&
         msg->effective_counter > im.peer_claim);
    if (!im.has_peer_claim || msg->crypto_epoch > im.peer_claim_epoch) {
        im.peer_claim_epoch = msg->crypto_epoch;
        im.peer_claim = msg->effective_counter;
        im.has_peer_claim = true;
    } else if (msg->effective_counter > im.peer_claim) {
        im.peer_claim = msg->effective_counter;
    }

    // ---- dispatch ----
    switch (t) {
    case TransitionMsgType::PREPARE: {
        if (im.state == ProfileTransitionState::READY && !im.initiator &&
            msg->transition_id == im.tid) {
            // duplicate PREPARE: re-ack, NO new timers.
            im.counters.control_duplicates++;
            im.send(TransitionMsgType::READY);
            return true;
        }
        if (im.state != ProfileTransitionState::IDLE) {
            if (im.state == ProfileTransitionState::PREPARE && im.initiator &&
                msg->transition_id > im.tid) {
                // glare: deterministic tie-break — higher transition_id wins;
                // our pre-activation proposal is rolled back cleanly.
                im.rollback(now_ms, AbortReason::PEER_BUSY, false);
                // fall through to accept the peer's PREPARE
            } else {
                // busy: refuse the new proposal (pre-activation safe).
                // emit_side: must NOT clobber our outstanding transition's
                // retransmission state (regression: M3 review).
                ControlMessage busy;
                busy.type = TransitionMsgType::ABORT;
                busy.session_id = im.cfg.session_id;
                busy.transition_id = msg->transition_id;
                busy.profile_epoch = msg->profile_epoch;
                busy.effective_counter = im.local_claim(msg->direction);
                busy.crypto_epoch = im.crypto_epoch;
                busy.direction = msg->direction;
                busy.reason = static_cast<uint8_t>(AbortReason::PEER_BUSY);
                if (auto enc = ProfileTransitionCodec::encode(
                        busy, im.cfg.max_control_bytes)) {
                    im.emit_side(*enc);
                }
                return true;
            }
        }
        // identity must be resolvable to layout params
        if (im.hooks.resolve_layout && !im.hooks.resolve_layout(msg->target)) {
            ControlMessage ab;
            ab.type = TransitionMsgType::ABORT;
            ab.session_id = im.cfg.session_id;
            ab.transition_id = msg->transition_id;
            ab.profile_epoch = msg->profile_epoch;
            ab.effective_counter = im.local_claim(msg->direction);
            ab.crypto_epoch = im.crypto_epoch;
            ab.direction = msg->direction;
            ab.reason = static_cast<uint8_t>(AbortReason::UNKNOWN_PROFILE);
            if (auto enc = ProfileTransitionCodec::encode(
                    ab, im.cfg.max_control_bytes)) {
                im.emit_side(*enc);
            }
            // The refusal IS a clean pre-activation abort of the proposed
            // transition: record it (state untouched — we never left IDLE).
            im.counters.transitions_aborted++;
            if (im.hooks.on_aborted)
                im.hooks.on_aborted(msg->transition_id,
                                    AbortReason::UNKNOWN_PROFILE);
            return true;
        }
        im.initiator = false;
        im.tid = msg->transition_id;
        im.pending = msg->target;
        im.pending_epoch = msg->profile_epoch;
        im.direction = msg->direction;
        im.grace_ms = msg->grace_ms
            ? std::min(msg->grace_ms, im.cfg.grace_period_ms)
            : im.cfg.grace_period_ms;
        // PREPARE is the peer's first message of the transition: bind the
        // PEER's crypto epoch (never the local one).
        im.peer_bound_crypto_epoch = msg->crypto_epoch;
        im.peer_bound_set = true;
        im.state = ProfileTransitionState::READY;
        im.counters.transitions_started++;
        im.arm(now_ms);
        im.send(TransitionMsgType::READY);
        return true;
    }

    case TransitionMsgType::READY: {
        if (!im.initiator) { im.counters.control_rx_rejected++; return false; }
        if (msg->target != im.pending || msg->direction != im.direction) {
            im.counters.control_rx_rejected++; return false;
        }
        if (im.state == ProfileTransitionState::COMMIT ||
            im.state == ProfileTransitionState::DRAIN) {
            // duplicate READY (our COMMIT was lost): re-emit COMMIT+CONFIRM,
            // no new timers, no re-activation.
            im.counters.control_duplicates++;
            im.send(TransitionMsgType::COMMIT);
            im.send(TransitionMsgType::CONFIRM);
            return true;
        }
        if (im.state != ProfileTransitionState::PREPARE) {
            im.counters.control_rx_rejected++; return false;
        }
        im.grace_ms = msg->grace_ms
            ? std::min(msg->grace_ms, im.grace_ms) : im.grace_ms;
        im.state = ProfileTransitionState::READY;  // transient
        im.activate(now_ms);
        im.arm(now_ms);
        im.send(TransitionMsgType::COMMIT);
        im.send(TransitionMsgType::CONFIRM);
        return true;
    }

    case TransitionMsgType::COMMIT: {
        if (im.initiator) { im.counters.control_rx_rejected++; return false; }
        if (msg->target != im.pending || msg->direction != im.direction) {
            im.counters.control_rx_rejected++; return false;
        }
        if (im.state == ProfileTransitionState::COMMIT ||
            im.state == ProfileTransitionState::DRAIN) {
            // duplicate COMMIT: re-CONFIRM, no re-activation, no new timers.
            im.counters.control_duplicates++;
            im.send(TransitionMsgType::CONFIRM);
            return true;
        }
        if (im.state != ProfileTransitionState::READY) {
            im.counters.control_rx_rejected++; return false;
        }
        im.grace_ms = msg->grace_ms
            ? std::min(msg->grace_ms, im.grace_ms) : im.grace_ms;
        im.activate(now_ms);
        im.arm(now_ms);
        im.send(TransitionMsgType::CONFIRM);
        return true;
    }

    case TransitionMsgType::CONFIRM: {
        if (msg->target != im.pending) {
            im.counters.control_rx_rejected++; return false;
        }
        if (im.state == ProfileTransitionState::DRAIN) {
            im.counters.control_duplicates++;  // replay: never re-confirms
            // A duplicate CONFIRM carrying a FRESH effective counter observed
            // on the live crypto stream (packet counter present) is a
            // retransmission, not a replay: the peer is still in COMMIT and
            // never received our CONFIRM (e.g. we reached DRAIN via the
            // peer's piggybacked CONFIRM while our own CONFIRM was lost and
            // our retransmission timer had already stopped). Re-emit CONFIRM
            // — idempotent, no state change, no new timers — so the peer can
            // still confirm. Bounded per transition: two DRAIN peers cannot
            // echo CONFIRM back and forth past the retransmission budget.
            // Plaintext-level feeds without crypto provenance (logical
            // replays, self-feeds) never generate traffic.
            if (fresh_effective_counter && packet_crypto_counter.has_value() &&
                im.drain_confirm_replies < im.cfg.max_retransmit_attempts) {
                im.drain_confirm_replies++;
                im.send(TransitionMsgType::CONFIRM);
            }
            return true;
        }
        if (im.state != ProfileTransitionState::COMMIT) {
            im.counters.control_rx_rejected++; return false;
        }
        im.become_effective(/*via_data=*/false, now_ms);
        return true;
    }

    case TransitionMsgType::ABORT: {
        if (im.is_activated()) {
            // Post-activation ABORT never rolls back.
            im.counters.aborts_ignored_post_activation++;
            return true;
        }
        im.rollback(now_ms, static_cast<AbortReason>(msg->reason), false);
        return true;
    }
    }
    return false;
}

void ProfileTransitionManager::note_new_layout_data(uint64_t now_ms) {
    auto& im = *impl_;
    // Early new data (PREPARE/READY) never activates and never confirms —
    // the data plane rejects it before calling this. Only COMMIT counts.
    if (im.state == ProfileTransitionState::COMMIT) {
        im.become_effective(/*via_data=*/true, now_ms);
    }
}

void ProfileTransitionManager::tick(uint64_t now_ms) {
    auto& im = *impl_;
    switch (im.state) {
    case ProfileTransitionState::IDLE:
        return;

    case ProfileTransitionState::DRAIN:
        if (now_ms >= im.grace_deadline) im.finalize();
        return;

    case ProfileTransitionState::PREPARE:
    case ProfileTransitionState::READY:
        if (now_ms < im.deadline) return;
        if (im.attempts >= im.cfg.max_retransmit_attempts) {
            // pre-activation timeout: safe clean rollback (+ best-effort ABORT)
            im.send(TransitionMsgType::ABORT,
                    static_cast<uint8_t>(AbortReason::TIMEOUT));
            im.rollback(now_ms, AbortReason::TIMEOUT, true);
            return;
        }
        im.retransmit(now_ms);
        return;

    case ProfileTransitionState::COMMIT:
        if (now_ms < im.deadline) return;
        if (im.attempts >= im.cfg.max_retransmit_attempts) {
            // Post-activation timeout: NO silent rollback. Keep the new
            // profile, mark the outcome uncertain, drain until grace end.
            im.become_uncertain(now_ms);
            return;
        }
        im.retransmit(now_ms);
        return;
    }
}

ProfileTransitionState ProfileTransitionManager::state() const {
    return impl_->state;
}
const ProfileRef& ProfileTransitionManager::stable_profile() const {
    return impl_->stable;
}
std::optional<ProfileRef> ProfileTransitionManager::pending_profile() const {
    if (impl_->state == ProfileTransitionState::IDLE) return std::nullopt;
    return impl_->pending;
}
uint32_t ProfileTransitionManager::stable_profile_epoch() const {
    return impl_->stable_epoch;
}
uint32_t ProfileTransitionManager::current_profile_epoch() const {
    return impl_->state == ProfileTransitionState::IDLE
        ? impl_->stable_epoch : impl_->pending_epoch;
}
uint64_t ProfileTransitionManager::transition_id() const {
    return impl_->tid;
}
uint64_t ProfileTransitionManager::peer_effective_counter() const {
    return impl_->has_peer_claim ? impl_->peer_claim : 0;
}
TransitionDirection ProfileTransitionManager::direction() const {
    return impl_->direction;
}
RetransmitState ProfileTransitionManager::retransmit_state() const {
    RetransmitState rs;
    rs.last_message = impl_->last_type;
    rs.attempts = impl_->attempts;
    rs.next_deadline_ms = impl_->deadline;
    rs.active = impl_->state != ProfileTransitionState::IDLE &&
                impl_->state != ProfileTransitionState::DRAIN &&
                impl_->attempts > 0;
    return rs;
}
std::optional<uint64_t> ProfileTransitionManager::activation_time_ms() const {
    if (!impl_->is_activated()) return std::nullopt;
    return impl_->activated_at;
}
std::optional<uint64_t> ProfileTransitionManager::grace_deadline_ms() const {
    if (!impl_->is_activated()) return std::nullopt;
    return impl_->grace_deadline;
}
uint32_t ProfileTransitionManager::grace_period_ms() const {
    return impl_->grace_ms;
}
void ProfileTransitionManager::set_grace_floor_ms(uint32_t floor_ms) {
    if (floor_ms > impl_->cfg.grace_period_ms)
        impl_->cfg.grace_period_ms = floor_ms;
}
uint32_t ProfileTransitionManager::configured_grace_period_ms() const {
    return impl_->cfg.grace_period_ms;
}
const ProfileTransitionCounters& ProfileTransitionManager::counters() const {
    return impl_->counters;
}

// ==================== SessionProfileContext ====================

namespace {

// Data body framing (inside the NCP DATA-tagged plaintext):
//   'P','D' | version:1 | profile_epoch:4 | payload_len:2 | payload | pad*
constexpr uint8_t kDataMagic0 = 'P';
constexpr uint8_t kDataMagic1 = 'D';
constexpr size_t  kDataHeader = 2 + 1 + 4 + 2;

std::vector<uint8_t> frame_data_body(uint32_t epoch,
                                     const std::vector<uint8_t>& payload,
                                     uint32_t padding_block) {
    std::vector<uint8_t> o;
    o.push_back(kDataMagic0);
    o.push_back(kDataMagic1);
    o.push_back(PROFILE_TRANSITION_WIRE_VERSION);
    put_u32(o, epoch);
    put_u16(o, static_cast<uint16_t>(payload.size()));
    o.insert(o.end(), payload.begin(), payload.end());
    if (padding_block > 1) {
        const size_t rem = o.size() % padding_block;
        if (rem) o.resize(o.size() + (padding_block - rem), 0);
    }
    return o;
}

struct ParsedData {
    uint32_t epoch = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

/// Strict parse of a data body under a given layout. Padding (if any) must
/// be zero-filled and bring the total size to a multiple of the block.
bool parse_data_body(const uint8_t* p, size_t n, uint32_t padding_block,
                     size_t max_payload, ParsedData& out) {
    if (!p || n < kDataHeader) return false;
    if (p[0] != kDataMagic0 || p[1] != kDataMagic1) return false;
    if (p[2] != PROFILE_TRANSITION_WIRE_VERSION) return false;
    Reader r{p, n, 3};
    uint32_t epoch; uint16_t plen;
    if (!r.u32(epoch) || !r.u16(plen)) return false;
    if (plen > max_payload) return false;
    if (r.pos + plen > n) return false;
    const size_t pad = n - (r.pos + plen);
    if (padding_block > 1) {
        if (n % padding_block != 0) return false;
        if (pad >= padding_block) return false;
    } else {
        if (pad != 0) return false;
    }
    for (size_t i = n - pad; i < n; ++i) if (p[i] != 0) return false;
    out.epoch = epoch;
    out.payload = p + r.pos;
    out.payload_len = plen;
    return true;
}

} // namespace

struct SessionProfileContext::Impl {
    ProfileTransitionConfig cfg;
    Crypto crypto;
    ProfileTransitionManager mgr;

    ProfileLayoutParams stable_layout;
    ProfileLayoutParams active_layout;   // == stable_layout until activation
    ProfileLayoutParams old_layout;      // pre-activation layout (grace decode)
    bool activated = false;
    bool tx_uses_new = false;
    bool rx_accepts_new = false;

    std::function<void(const std::vector<uint8_t>&)> outbound;
    std::function<void(const SwitchEvent&)> switch_handler;
    std::function<void(uint64_t, AbortReason)> abort_handler;
    std::function<std::optional<ProfileLayoutParams>(const ProfileRef&)> resolver;
    std::vector<std::function<void(uint32_t, uint32_t)>> epoch_observers;

    // pending layout chosen locally (initiator) or resolved (responder)
    std::optional<ProfileLayoutParams> pending_layout;

    // data-plane counters (control/transition counters live in the manager)
    uint64_t tx_data = 0, tx_data_stable = 0, tx_data_new = 0;
    uint64_t rx_data_stable = 0, rx_data_new = 0, rx_data_old_grace = 0;
    uint64_t rx_rejected_early_new = 0, rx_rejected_old_expired = 0;
    uint64_t rx_rejected_unknown_epoch = 0, rx_rejected_malformed = 0;

    Impl(ProfileTransitionConfig c, ProfileRef stable,
         ProfileLayoutParams layout, Crypto cc)
        : cfg(c), crypto(std::move(cc)),
          mgr(c, stable, 0), stable_layout(layout), active_layout(layout),
          old_layout(layout) {
        ProfileTransitionHooks hooks;
        auto* self = this;
        hooks.emit_control = [self](const std::vector<uint8_t>& body) {
            if (!self->crypto.encrypt || !self->outbound) return;
            // NCP tag: PROFILE_TRANSITION control; fresh AEAD per call.
            std::vector<uint8_t> pt;
            pt.reserve(NCP_MSG_TAG_SIZE + body.size());
            pt.push_back(NCP_MSG_MAGIC[0]);
            pt.push_back(NCP_MSG_MAGIC[1]);
            pt.push_back(NCP_MSG_MAGIC[2]);
            pt.push_back(static_cast<uint8_t>(
                E2EMessageType::PROFILE_TRANSITION));
            pt.insert(pt.end(), body.begin(), body.end());
            self->outbound(self->crypto.encrypt(pt));
        };
        hooks.resolve_layout = [self](const ProfileRef& ref)
            -> std::optional<ProfileLayoutParams> {
            std::optional<ProfileLayoutParams> r;
            if (self->resolver) r = self->resolver(ref);
            else r = ProfileLayoutParams{};  // default: accept, no padding
            if (r) self->pending_layout = r;  // responder adopts resolved layout
            return r;
        };
        // effective_counter binding: actual crypto packet counter of the
        // transition's direction (never reset by profile transitions).
        hooks.local_crypto_counter = [self](TransitionDirection dir) -> uint64_t {
            if (dir == TransitionDirection::RX_ONLY)
                return self->crypto.rx_crypto_counter
                    ? self->crypto.rx_crypto_counter() : 0;
            return self->crypto.tx_crypto_counter
                ? self->crypto.tx_crypto_counter() : 0;
        };
        hooks.validate_peer_claim =
            [self](uint64_t claimed, TransitionDirection dir,
                   std::optional<uint64_t> packet_counter) -> bool {
            // A claim must never exceed what the crypto stream can prove.
            if (dir == TransitionDirection::RX_ONLY) {
                // the claim refers to the peer's RX stream == our TX stream
                if (self->crypto.tx_crypto_counter &&
                    claimed > self->crypto.tx_crypto_counter()) return false;
                return true;
            }
            // TX/BIDIRECTIONAL: claim refers to the peer's TX stream == the
            // stream carrying this packet. The claim is sampled before the
            // carrying packet is encrypted, so it can never exceed the
            // packet's own crypto counter.
            if (packet_counter && claimed > *packet_counter) return false;
            return true;
        };
        hooks.on_activate = [self](const ProfileRef&, const ProfileLayoutParams&,
                                   uint32_t new_epoch, TransitionDirection dir) {
            const uint32_t old_epoch = self->mgr.stable_profile_epoch();
            self->old_layout = self->active_layout;
            self->active_layout = self->pending_layout.value_or(
                ProfileLayoutParams{});
            self->activated = true;
            // NOTE on TX_ONLY: both endpoints activate with tx_uses_new=true
            // and rx_accepts_new=false, so during the grace window each side
            // TRANSMITS new-epoch data that the peer still rejects
            // (rx_rejected_unknown_epoch) until it finalizes. This transient
            // new-epoch data loss in BOTH directions is intended: a TX_ONLY
            // switch changes only the sender layout, and RX acceptance of
            // the new epoch begins once it becomes the stable epoch.
            self->tx_uses_new = (dir != TransitionDirection::RX_ONLY);
            self->rx_accepts_new = (dir != TransitionDirection::TX_ONLY);
            for (auto& obs : self->epoch_observers)
                if (obs) obs(old_epoch, new_epoch);
        };
        hooks.on_switch = [self](const SwitchEvent& ev) {
            if (self->switch_handler) self->switch_handler(ev);
        };
        hooks.on_aborted = [self](uint64_t tid, AbortReason r) {
            self->activated = false;
            self->tx_uses_new = false;
            self->rx_accepts_new = false;
            self->active_layout = self->stable_layout;
            self->pending_layout.reset();
            if (self->abort_handler) self->abort_handler(tid, r);
        };
        mgr.set_hooks(std::move(hooks));
    }

    bool in_grace_period(uint64_t now_ms) const {
        auto dl = mgr.grace_deadline_ms();
        return dl.has_value() && now_ms <= *dl;
    }

    void on_finalize_side_effects() {
        // called when the manager returns to IDLE after a completed switch
        if (mgr.state() == ProfileTransitionState::IDLE && activated &&
            !mgr.has_outstanding()) {
            stable_layout = active_layout;
            activated = false;
            pending_layout.reset();
        }
    }
};

SessionProfileContext::SessionProfileContext(
    ProfileTransitionConfig cfg, ProfileRef stable_profile,
    ProfileLayoutParams stable_layout, Crypto crypto)
    : impl_(new Impl(std::move(cfg), std::move(stable_profile),
                     stable_layout, std::move(crypto))) {}

SessionProfileContext::~SessionProfileContext() { delete impl_; }

void SessionProfileContext::set_peer_capable(bool capable) {
    impl_->mgr.set_peer_capable(capable);
}
void SessionProfileContext::set_crypto_epoch(uint64_t epoch) {
    impl_->mgr.set_crypto_epoch(epoch);
}
void SessionProfileContext::set_layout_resolver(
    std::function<std::optional<ProfileLayoutParams>(const ProfileRef&)> r) {
    impl_->resolver = std::move(r);
}
void SessionProfileContext::set_control_outbound_handler(
    std::function<void(const std::vector<uint8_t>& wire)> h) {
    impl_->outbound = std::move(h);
}
void SessionProfileContext::set_switch_event_handler(
    std::function<void(const SwitchEvent&)> h) {
    impl_->switch_handler = std::move(h);
}
void SessionProfileContext::set_abort_handler(
    std::function<void(uint64_t, AbortReason)> h) {
    impl_->abort_handler = std::move(h);
}
void SessionProfileContext::add_epoch_observer(
    std::function<void(uint32_t, uint32_t)> obs) {
    impl_->epoch_observers.push_back(std::move(obs));
}

TransitionError SessionProfileContext::start_transition(
    ProfileRef target, ProfileLayoutParams target_layout,
    TransitionDirection direction, uint8_t reason, uint64_t now_ms) {
    auto err = impl_->mgr.start_transition(target, direction, reason,
                                           impl_->cfg.grace_period_ms, now_ms);
    if (err == TransitionError::NONE) impl_->pending_layout = target_layout;
    return err;
}

bool SessionProfileContext::abort_transition(AbortReason reason,
                                             uint64_t now_ms) {
    return impl_->mgr.abort_transition(reason, now_ms);
}

void SessionProfileContext::tick(uint64_t now_ms) {
    impl_->mgr.tick(now_ms);
    impl_->on_finalize_side_effects();
}

// ---- data plane ----

std::optional<std::vector<uint8_t>> SessionProfileContext::encode_data(
    const std::vector<uint8_t>& payload) {
    auto& im = *impl_;
    if (!im.crypto.encrypt) return std::nullopt;
    if (payload.size() > im.cfg.max_payload_bytes ||
        payload.size() > MAX_PROFILE_DATA_PAYLOAD_BYTES) return std::nullopt;

    // Legacy peer (capability not negotiated): wire format UNCHANGED —
    // raw payload, no NCP tag, no profile framing.
    if (!im.mgr.peer_capable()) {
        im.tx_data++;
        im.tx_data_stable++;
        return im.crypto.encrypt(payload);
    }

    const bool use_new = im.activated && im.tx_uses_new;
    const uint32_t epoch = use_new ? im.mgr.current_profile_epoch()
                                   : im.mgr.stable_profile_epoch();
    const auto& layout = use_new ? im.active_layout : im.stable_layout;

    auto body = frame_data_body(epoch, payload, layout.padding_block_bytes);
    std::vector<uint8_t> pt;
    pt.reserve(NCP_MSG_TAG_SIZE + body.size());
    pt.push_back(NCP_MSG_MAGIC[0]);
    pt.push_back(NCP_MSG_MAGIC[1]);
    pt.push_back(NCP_MSG_MAGIC[2]);
    pt.push_back(static_cast<uint8_t>(E2EMessageType::DATA));
    pt.insert(pt.end(), body.begin(), body.end());

    im.tx_data++;
    if (use_new) im.tx_data_new++; else im.tx_data_stable++;
    return im.crypto.encrypt(pt);
}

std::optional<std::vector<uint8_t>> SessionProfileContext::on_ciphertext(
    const std::vector<uint8_t>& wire, uint64_t now_ms) {
    auto& im = *impl_;
    std::optional<uint64_t> packet_counter;
    std::optional<std::vector<uint8_t>> pt;
    if (im.crypto.decrypt_ex) {
        auto r = im.crypto.decrypt_ex(wire);
        if (r) { packet_counter = r->second; pt = std::move(r->first); }
    } else if (im.crypto.decrypt) {
        pt = im.crypto.decrypt(wire);
    } else {
        return std::nullopt;
    }
    if (!pt) {
        // AEAD / replay failure: transport-level drop, not a protocol event.
        return std::nullopt;
    }
    return on_plaintext(*pt, now_ms, packet_counter);
}

std::optional<std::vector<uint8_t>> SessionProfileContext::on_plaintext(
    const std::vector<uint8_t>& plaintext, uint64_t now_ms,
    std::optional<uint64_t> packet_crypto_counter) {
    auto& im = *impl_;

    // Legacy peer: no profile framing on the wire at all. A tagged control
    // message is still rejected (never answered); everything else is
    // application payload as-is.
    if (!im.mgr.peer_capable()) {
        if (CapabilitiesExchange::has_magic(plaintext) &&
            CapabilitiesExchange::peek_type(plaintext) ==
                E2EMessageType::PROFILE_TRANSITION) {
            auto body = CapabilitiesExchange::unwrap(plaintext);
            // manager rejects (capability gate), nothing goes outbound
            im.mgr.on_control_plaintext(body, now_ms, packet_crypto_counter);
            return std::nullopt;
        }
        im.rx_data_stable++;
        return plaintext;
    }

    if (!CapabilitiesExchange::has_magic(plaintext)) {
        im.rx_rejected_malformed++;
        return std::nullopt;
    }
    const auto type = CapabilitiesExchange::peek_type(plaintext);
    auto body = CapabilitiesExchange::unwrap(plaintext);

    if (type == E2EMessageType::PROFILE_TRANSITION) {
        im.mgr.on_control_plaintext(body, now_ms, packet_crypto_counter);
        im.on_finalize_side_effects();
        return std::nullopt;
    }
    if (type != E2EMessageType::DATA) {
        im.rx_rejected_malformed++;
        return std::nullopt;
    }

    // ---- data message: epoch routing with old/new dual decode ----
    ParsedData probe;
    // Peek epoch first (fixed offset) without committing to a layout.
    if (body.size() < kDataHeader ||
        body[0] != kDataMagic0 || body[1] != kDataMagic1) {
        im.rx_rejected_malformed++;
        return std::nullopt;
    }
    const uint32_t epoch =
        (static_cast<uint32_t>(body[3]) << 24) |
        (static_cast<uint32_t>(body[4]) << 16) |
        (static_cast<uint32_t>(body[5]) << 8) |
         static_cast<uint32_t>(body[6]);

    const uint32_t stable_epoch = im.mgr.stable_profile_epoch();
    const uint32_t new_epoch = im.mgr.current_profile_epoch();
    const bool outstanding = im.mgr.has_outstanding();

    const ProfileLayoutParams* layout = nullptr;
    enum { kStable, kNew, kOldGrace } which = kStable;

    if (!im.activated) {
        if (epoch == stable_epoch) {
            layout = &im.stable_layout; which = kStable;
        } else if (outstanding && epoch == new_epoch) {
            // Early new-layout data before COMMIT: never activates,
            // never confirms.
            im.rx_rejected_early_new++;
            return std::nullopt;
        } else if (epoch < stable_epoch) {
            // Superseded epoch: the old decoder was removed when the grace
            // deadline passed (DRAIN finalized). Same rejection class as the
            // activated post-grace path — the epoch is provably OLD, not
            // unknown.
            im.rx_rejected_old_expired++;
            return std::nullopt;
        } else {
            im.rx_rejected_unknown_epoch++;
            return std::nullopt;
        }
    } else {
        if (im.rx_accepts_new && epoch == new_epoch) {
            layout = &im.active_layout; which = kNew;
        } else if (epoch == stable_epoch) {
            if (im.in_grace_period(now_ms)) {
                layout = &im.old_layout; which = kOldGrace;
            } else {
                im.rx_rejected_old_expired++;
                return std::nullopt;
            }
        } else {
            im.rx_rejected_unknown_epoch++;
            return std::nullopt;
        }
    }

    if (!parse_data_body(body.data(), body.size(),
                         layout->padding_block_bytes,
                         im.cfg.max_payload_bytes, probe)) {
        im.rx_rejected_malformed++;
        return std::nullopt;
    }

    switch (which) {
        case kStable:   im.rx_data_stable++; break;
        case kNew:
            im.rx_data_new++;
            // Valid new-layout data post-COMMIT confirms the transition.
            im.mgr.note_new_layout_data(now_ms);
            break;
        case kOldGrace: im.rx_data_old_grace++; break;
    }
    im.on_finalize_side_effects();
    return std::vector<uint8_t>(probe.payload, probe.payload + probe.payload_len);
}

// ---- state / stats ----

ProfileTransitionState SessionProfileContext::state() const {
    return impl_->mgr.state();
}
const ProfileRef& SessionProfileContext::stable_profile() const {
    return impl_->mgr.stable_profile();
}
std::optional<ProfileRef> SessionProfileContext::pending_profile() const {
    return impl_->mgr.pending_profile();
}
ProfileRef SessionProfileContext::tx_profile() const {
    if (impl_->activated && impl_->tx_uses_new) {
        auto p = impl_->mgr.pending_profile();
        if (p) return *p;
    }
    return impl_->mgr.stable_profile();
}
ProfileRef SessionProfileContext::rx_primary_profile() const {
    if (impl_->activated && impl_->rx_accepts_new) {
        auto p = impl_->mgr.pending_profile();
        if (p) return *p;
    }
    return impl_->mgr.stable_profile();
}
uint32_t SessionProfileContext::profile_epoch() const {
    return impl_->mgr.stable_profile_epoch();
}
uint32_t SessionProfileContext::tx_epoch() const {
    return (impl_->activated && impl_->tx_uses_new)
        ? impl_->mgr.current_profile_epoch()
        : impl_->mgr.stable_profile_epoch();
}
uint32_t SessionProfileContext::min_accepted_data_epoch() const {
    // Epoch fence for cancelling queued shape/timer work: while activated,
    // the old epoch remains acceptable only inside the grace window.
    return impl_->mgr.stable_profile_epoch();
}
uint64_t SessionProfileContext::peer_effective_counter() const {
    return impl_->mgr.peer_effective_counter();
}
std::optional<uint64_t> SessionProfileContext::grace_deadline_ms() const {
    return impl_->mgr.grace_deadline_ms();
}
bool SessionProfileContext::in_grace_period(uint64_t now_ms) const {
    auto dl = impl_->mgr.grace_deadline_ms();
    return dl.has_value() && now_ms <= *dl;
}
void SessionProfileContext::set_grace_floor_ms(uint32_t floor_ms) {
    if (floor_ms > impl_->cfg.grace_period_ms)
        impl_->cfg.grace_period_ms = floor_ms;
    impl_->mgr.set_grace_floor_ms(floor_ms);
}
uint32_t SessionProfileContext::configured_grace_period_ms() const {
    return impl_->cfg.grace_period_ms;
}

ProfileTransitionCounters SessionProfileContext::counters() const {
    ProfileTransitionCounters c = impl_->mgr.counters();  // control+transition
    c.tx_data = impl_->tx_data;
    c.tx_data_stable = impl_->tx_data_stable;
    c.tx_data_new = impl_->tx_data_new;
    c.rx_data_stable = impl_->rx_data_stable;
    c.rx_data_new = impl_->rx_data_new;
    c.rx_data_old_grace = impl_->rx_data_old_grace;
    c.rx_rejected_early_new = impl_->rx_rejected_early_new;
    c.rx_rejected_old_expired = impl_->rx_rejected_old_expired;
    c.rx_rejected_unknown_epoch = impl_->rx_rejected_unknown_epoch;
    c.rx_rejected_malformed = impl_->rx_rejected_malformed;
    return c;
}
ProfileTransitionManager& SessionProfileContext::manager() {
    return impl_->mgr;
}
const ProfileTransitionManager& SessionProfileContext::manager() const {
    return impl_->mgr;
}

// ==================== Catalog integration (read-only) ====================

ProfileRef profile_ref_from_descriptor(const ProfileDescriptor& d) {
    ProfileRef r;
    r.id = d.profile_id;
    r.revision = d.revision;
    r.content_hash.fill(0);
    if (d.content_hash.size() == PROFILE_HASH_SIZE * 2) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        bool ok = true;
        for (size_t i = 0; i < PROFILE_HASH_SIZE && ok; ++i) {
            int hi = nibble(d.content_hash[i * 2]);
            int lo = nibble(d.content_hash[i * 2 + 1]);
            if (hi < 0 || lo < 0) { ok = false; break; }
            r.content_hash[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        if (!ok) r.content_hash.fill(0);
    }
    return r;
}

ProfileLayoutParams profile_layout_from_descriptor(const ProfileDescriptor& d) {
    ProfileLayoutParams p;
    p.header_overhead_bytes = d.padding_header.header_overhead_bytes;
    p.padding_block_bytes = d.padding_header.padding_block_bytes;
    return p;
}

std::function<std::optional<ProfileLayoutParams>(const ProfileRef&)>
make_catalog_layout_resolver(const ReferenceProfileCatalog* catalog) {
    return [catalog](const ProfileRef& ref)
        -> std::optional<ProfileLayoutParams> {
        if (!catalog) return std::nullopt;
        const auto* d = catalog->find(ref.id, ref.revision);
        if (!d) return std::nullopt;
        // Content-hash binding: the resolved descriptor must be exactly the
        // one referenced on the wire.
        if (profile_ref_from_descriptor(*d) != ref) return std::nullopt;
        return profile_layout_from_descriptor(*d);
    };
}

} // namespace ncp
