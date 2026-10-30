// ══════════════════════════════════════════════════════════════════════════════
// tests/test_profile_transition.cpp
// Этап: generic per-session ProfileTransitionManager + SessionProfileContext
//
// Hermetic two-endpoint tests over an in-memory transport. Crypto is the REAL
// E2ESession (X25519 handshake + double ratchet + AEAD + replay protection);
// only the wire transport is in-memory. This is NOT a live UDP test — real
// socket-level evidence is produced separately.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_profile_transition.hpp"
#include "ncp_capabilities.hpp"
#include "ncp_e2e.hpp"
#include "ncp_reference_profile_catalog.hpp"

#include <deque>
#include <cstring>

using namespace ncp;

namespace {

// ── Profiles / layouts ─────────────────────────────────────────────────────

ProfileRef make_ref(const char* id, uint32_t rev, uint8_t hash_fill) {
    ProfileRef r;
    r.id = id;
    r.revision = rev;
    r.content_hash.fill(hash_fill);
    return r;
}

const ProfileRef kP0 = make_ref("baseline.udp", 1, 0xA0);
const ProfileRef kP1 = make_ref("mimic.webrtc", 2, 0xB0);
const ProfileRef kP2 = make_ref("mimic.http2", 1, 0xC0);

const ProfileLayoutParams kL0{0, 0};      // no padding
const ProfileLayoutParams kL1{64, 16};    // block-padded mask
const ProfileLayoutParams kL2{48, 8};

constexpr uint64_t kT0 = 100000;          // deterministic start time (ms)
constexpr uint32_t kInterval = 100;       // retransmit interval
constexpr uint32_t kAttempts = 4;
constexpr uint32_t kGrace = 500;

// ── Endpoint over real E2ESession + in-memory transport ────────────────────

struct Endpoint {
    E2ESession e2e;
    KeyPair keys;
    std::unique_ptr<SessionProfileContext> ctx;
    std::deque<std::vector<uint8_t>> outbox;           // control ciphertexts
    std::vector<std::vector<uint8_t>> sent_plaintexts; // plaintext tap
    std::vector<SwitchEvent> events;
    std::vector<std::pair<uint64_t, AbortReason>> aborts;
    std::vector<std::pair<uint32_t, uint32_t>> epoch_changes;

    static E2EConfig make_e2e_config() {
        E2EConfig c;
        c.enable_padding = false;  // deterministic wire sizes
        return c;
    }

    Endpoint() : e2e(make_e2e_config()) { keys = e2e.generate_key_pair(); }

    void make_context(const std::array<uint8_t, PROFILE_SESSION_ID_SIZE>& sid,
                      const ProfileRef& stable, const ProfileLayoutParams& sl) {
        ProfileTransitionConfig cfg;
        cfg.session_id = sid;
        cfg.retransmit_interval_ms = kInterval;
        cfg.max_retransmit_attempts = kAttempts;
        cfg.grace_period_ms = kGrace;
        cfg.max_payload_bytes = 4096;

        SessionProfileContext::Crypto crypto;
        crypto.encrypt = [this](const std::vector<uint8_t>& pt) {
            sent_plaintexts.push_back(pt);
            return E2EUtils::serialize_message(e2e.encrypt(pt));
        };
        crypto.decrypt = [this](const std::vector<uint8_t>& wire)
            -> std::optional<std::vector<uint8_t>> {
            auto m = E2EUtils::deserialize_message(wire);
            if (!m) return std::nullopt;
            return e2e.decrypt(*m);
        };
        crypto.decrypt_ex = [this](const std::vector<uint8_t>& wire)
            -> std::optional<std::pair<std::vector<uint8_t>, uint64_t>> {
            auto m = E2EUtils::deserialize_message(wire);
            if (!m) return std::nullopt;
            const uint64_t pkt = m->header.message_number;
            auto pt = e2e.decrypt(*m);
            if (!pt) return std::nullopt;
            return std::make_pair(std::move(*pt), pkt);
        };
        // effective_counter binding: the REAL crypto packet counters of the
        // underlying E2ESession (double-ratchet chain lengths), per direction.
        crypto.tx_crypto_counter = [this]() -> uint64_t {
            return e2e.get_sending_chain_length();
        };
        crypto.rx_crypto_counter = [this]() -> uint64_t {
            return e2e.get_receiving_chain_length();
        };

        ctx = std::make_unique<SessionProfileContext>(cfg, stable, sl,
                                                      std::move(crypto));
        // Both endpoints resolve the same layout for the same profile
        // identity — the wire carries only the bounded ProfileRef.
        ctx->set_layout_resolver([](const ProfileRef& r)
            -> std::optional<ProfileLayoutParams> {
            if (r == kP0) return kL0;
            if (r == kP1) return kL1;
            if (r == kP2) return kL2;
            return std::nullopt;
        });
        ctx->set_control_outbound_handler(
            [this](const std::vector<uint8_t>& w) { outbox.push_back(w); });
        ctx->set_switch_event_handler(
            [this](const SwitchEvent& e) { events.push_back(e); });
        ctx->set_abort_handler(
            [this](uint64_t tid, AbortReason r) { aborts.emplace_back(tid, r); });
        ctx->add_epoch_observer([this](uint32_t o, uint32_t n) {
            epoch_changes.emplace_back(o, n);
        });
    }
};

struct Pair {
    Endpoint a, b;
    uint64_t now = kT0;
    /// Session binding id derived from the real X25519 shared secret.
    std::array<uint8_t, PROFILE_SESSION_ID_SIZE> sid{};

    /// Real X25519 handshake + session-id binding from the shared secret.
    bool establish(bool capable = true) {
        auto req = a.e2e.create_key_exchange_request(a.keys);
        auto resp = b.e2e.process_key_exchange_request(req, b.keys);
        if (!a.e2e.complete_key_exchange(resp, a.keys)) return false;
        if (!a.e2e.is_established() || !b.e2e.is_established()) return false;

        std::vector<uint8_t> bpub(b.keys.public_key.data(),
                                  b.keys.public_key.data() + b.keys.public_key.size());
        std::vector<uint8_t> apub(a.keys.public_key.data(),
                                  a.keys.public_key.data() + a.keys.public_key.size());
        auto sa = a.e2e.compute_shared_secret(a.keys, bpub);
        auto sb = b.e2e.compute_shared_secret(b.keys, apub);
        if (sa.size() != sb.size() ||
            std::memcmp(sa.data(), sb.data(), sa.size()) != 0) return false;
        auto sid_key = a.e2e.derive_keys(sa, "profile-transition-session-id",
                                         PROFILE_SESSION_ID_SIZE);
        std::memcpy(sid.data(), sid_key.data(), PROFILE_SESSION_ID_SIZE);

        a.make_context(sid, kP0, kL0);
        b.make_context(sid, kP0, kL0);
        a.ctx->set_peer_capable(capable);
        b.ctx->set_peer_capable(capable);
        a.ctx->set_crypto_epoch(1);
        b.ctx->set_crypto_epoch(1);
        return true;
    }

    /// Deliver up to n control messages src->dst. Returns delivered count.
    int pump(Endpoint& src, Endpoint& dst, int n = -1) {
        int delivered = 0;
        while (!src.outbox.empty() && (n < 0 || delivered < n)) {
            dst.ctx->on_ciphertext(src.outbox.front(), now);
            src.outbox.pop_front();
            ++delivered;
        }
        return delivered;
    }
    int drop(Endpoint& src, int n = 1) {
        int d = 0;
        while (!src.outbox.empty() && d < n) { src.outbox.pop_front(); ++d; }
        return d;
    }
    void advance(uint64_t ms) { now += ms; }

    /// Drive ticks/delivery until quiescent (both IDLE, empty outboxes).
    void settle(unsigned max_iters = 64) {
        for (unsigned i = 0; i < max_iters; ++i) {
            a.ctx->tick(now);
            b.ctx->tick(now);
            pump(a, b); pump(b, a);
            if (a.ctx->state() == ProfileTransitionState::IDLE &&
                b.ctx->state() == ProfileTransitionState::IDLE &&
                a.outbox.empty() && b.outbox.empty()) return;
            advance(kInterval);
        }
    }
};

std::vector<uint8_t> payload(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

/// Decode an outbound control ciphertext of `src` as seen by `dst`
/// (test inspection only — consumes a skipped key on dst like real delivery).
std::optional<ControlMessage> peek_control(Endpoint& dst,
                                           const std::vector<uint8_t>& wire) {
    auto m = E2EUtils::deserialize_message(wire);
    if (!m) return std::nullopt;
    auto pt = dst.e2e.decrypt(*m);
    if (!pt) return std::nullopt;
    if (!CapabilitiesExchange::has_magic(*pt)) return std::nullopt;
    if (CapabilitiesExchange::peek_type(*pt) !=
        E2EMessageType::PROFILE_TRANSITION) return std::nullopt;
    auto body = CapabilitiesExchange::unwrap(*pt);
    return ProfileTransitionCodec::decode(body);
}

/// Full happy-path transition A->P1 with CONFIRM-based confirmation.
void run_happy_path(Pair& p) {
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        /*reason=*/1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);  // PREPARE
    p.pump(p.b, p.a);  // READY
    p.pump(p.a, p.b);  // COMMIT + CONFIRM
    p.pump(p.b, p.a);  // CONFIRM
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Capability helpers (additive feature bit)
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransitionCaps, ReservedFeatureBitRoundtrip) {
    NCPCapabilities caps;
    EXPECT_FALSE(capabilities_support_profile_transition(caps));
    capabilities_set_profile_transition(caps);
    EXPECT_TRUE(capabilities_support_profile_transition(caps));

    // survives serialize/deserialize and leaves other bits untouched
    caps.reserved[0] |= 0x40;  // unknown future bit
    auto ser = caps.serialize();
    auto back = NCPCapabilities::deserialize(ser);
    ASSERT_TRUE(back.has_value());
    EXPECT_TRUE(capabilities_support_profile_transition(*back));
    EXPECT_EQ(back->reserved[0] & 0x40, 0x40);

    capabilities_set_profile_transition(*back, false);
    EXPECT_FALSE(capabilities_support_profile_transition(*back));
    EXPECT_EQ(back->reserved[0] & 0x40, 0x40);  // other bit preserved

    // enum value sanity
    EXPECT_EQ(static_cast<uint8_t>(E2EMessageType::PROFILE_TRANSITION), 0x03);
}

// ══════════════════════════════════════════════════════════════════════════════
// Codec: strict bounded parser
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransitionCodec, RoundtripAllTypes) {
    std::array<uint8_t, PROFILE_SESSION_ID_SIZE> sid{};
    sid[0] = 0x11;
    for (auto t : {TransitionMsgType::PREPARE, TransitionMsgType::READY,
                   TransitionMsgType::COMMIT, TransitionMsgType::CONFIRM,
                   TransitionMsgType::ABORT}) {
        ControlMessage m;
        m.type = t;
        m.session_id = sid;
        m.transition_id = 0x1122334455667788ULL;
        m.profile_epoch = 7;
        m.effective_counter = 3;
        m.crypto_epoch = 42;
        m.direction = TransitionDirection::BIDIRECTIONAL;
        m.reason = 9;
        m.grace_ms = 1234;
        if (t != TransitionMsgType::ABORT) m.target = kP1;
        auto enc = ProfileTransitionCodec::encode(m);
        ASSERT_TRUE(enc.has_value()) << "encode failed for type "
                                     << static_cast<int>(t);
        auto dec = ProfileTransitionCodec::decode(*enc);
        ASSERT_TRUE(dec.has_value());
        EXPECT_EQ(dec->type, t);
        EXPECT_EQ(dec->session_id, sid);
        EXPECT_EQ(dec->transition_id, m.transition_id);
        EXPECT_EQ(dec->profile_epoch, 7u);
        EXPECT_EQ(dec->effective_counter, 3u);
        EXPECT_EQ(dec->crypto_epoch, 42u);
        EXPECT_EQ(dec->grace_ms, 1234u);
        if (t != TransitionMsgType::ABORT) {
            EXPECT_EQ(dec->target, kP1);
        } else {
            EXPECT_TRUE(dec->target.id.empty());
        }
    }
}

TEST(ProfileTransitionCodec, RejectsMalformed) {
    ControlMessage m;
    m.type = TransitionMsgType::PREPARE;
    m.session_id.fill(0x22);
    m.transition_id = 1;
    m.profile_epoch = 1;
    m.effective_counter = 1;
    m.target = kP1;
    auto good = ProfileTransitionCodec::encode(m);
    ASSERT_TRUE(good.has_value());

    // truncated at every prefix length
    for (size_t n = 0; n < good->size(); ++n) {
        EXPECT_FALSE(ProfileTransitionCodec::decode(good->data(), n).has_value())
            << "truncated to " << n;
    }
    // trailing garbage
    auto extra = *good; extra.push_back(0x00);
    EXPECT_FALSE(ProfileTransitionCodec::decode(extra).has_value());
    // bad magic / version / type
    auto bad = *good;
    bad[0] = 'X';  EXPECT_FALSE(ProfileTransitionCodec::decode(bad).has_value());
    bad = *good; bad[2] = 0x7F;
    EXPECT_FALSE(ProfileTransitionCodec::decode(bad).has_value());
    bad = *good; bad[3] = 0x00;
    EXPECT_FALSE(ProfileTransitionCodec::decode(bad).has_value());
    bad = *good; bad[3] = 0x06;
    EXPECT_FALSE(ProfileTransitionCodec::decode(bad).has_value());
    // bad direction enum (offset: 2 magic + 1 ver + 1 type + 16 sid +
    // 8 tid + 4 epoch + 8 effective_counter + 8 crypto_epoch = 48)
    bad = *good; bad[48] = 0x09;
    EXPECT_FALSE(ProfileTransitionCodec::decode(bad).has_value());
    // inconsistent id_len (claims more than available); id_len at offset 54
    bad = *good; bad[54] = 64;
    EXPECT_FALSE(ProfileTransitionCodec::decode(bad).has_value());
    // nullptr / empty
    EXPECT_FALSE(ProfileTransitionCodec::decode(nullptr, 0).has_value());
    // oversized input rejected by bound
    std::vector<uint8_t> huge(MAX_CONTROL_BODY_BYTES + 1, 0);
    EXPECT_FALSE(ProfileTransitionCodec::decode(huge).has_value());

    // ABORT must not carry an identity; strict fixed form
    ControlMessage ab;
    ab.type = TransitionMsgType::ABORT;
    ab.transition_id = 1; ab.profile_epoch = 1; ab.effective_counter = 1;
    ab.target = kP1;  // illegal for ABORT
    EXPECT_FALSE(ProfileTransitionCodec::encode(ab).has_value());
    ab.target = ProfileRef{};
    auto abe = ProfileTransitionCodec::encode(ab);
    ASSERT_TRUE(abe.has_value());
    auto abx = *abe; abx.push_back(0x00);
    EXPECT_FALSE(ProfileTransitionCodec::decode(abx).has_value());

    // oversized profile id never encodes
    ControlMessage big = m;
    big.target.id.assign(MAX_PROFILE_ID_LEN + 1, 'x');
    EXPECT_FALSE(ProfileTransitionCodec::encode(big).has_value());
}

// ══════════════════════════════════════════════════════════════════════════════
// Happy path
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, HappyPathContinuousDataAndCounters) {
    Pair p;
    ASSERT_TRUE(p.establish());

    // continuous app data on the stable profile before the transition
    for (int i = 0; i < 3; ++i) {
        auto w = p.a.ctx->encode_data(payload("stable-a2b"));
        ASSERT_TRUE(w.has_value());
        auto got = p.b.ctx->on_ciphertext(*w, p.now);
        ASSERT_TRUE(got.has_value());
        EXPECT_EQ(*got, payload("stable-a2b"));
    }

    const uint64_t sent_before = p.a.e2e.get_messages_sent();
    const uint32_t chain_before = p.a.e2e.get_sending_chain_length();

    // SwitchEvent must NOT fire on request — only after confirmation.
    EXPECT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::PREPARE);
    EXPECT_TRUE(p.a.events.empty());
    ASSERT_EQ(p.a.outbox.size(), 1u);

    p.pump(p.a, p.b);  // PREPARE
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
    EXPECT_TRUE(p.b.events.empty());

    // SwitchEvent.effective_counter must be A's actual TX crypto packet
    // counter (sending chain length) sampled at activation — captured here,
    // before the READY pump that triggers activation (A sent only PREPARE).
    const uint64_t a_tx_at_activation = p.a.e2e.get_sending_chain_length();
    p.pump(p.b, p.a);  // READY -> A activates locally
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    EXPECT_TRUE(p.a.ctx->tx_profile() == kP1);
    EXPECT_EQ(p.a.ctx->tx_epoch(), 1u);
    EXPECT_TRUE(p.a.events.empty());   // still not confirmed
    ASSERT_EQ(p.a.epoch_changes.size(), 1u);
    EXPECT_EQ(p.a.epoch_changes[0], std::make_pair(0u, 1u));

    // data keeps flowing during the transition: A on NEW layout now
    auto w = p.a.ctx->encode_data(payload("new-before-b-commit"));
    ASSERT_TRUE(w.has_value());

    p.pump(p.a, p.b);  // COMMIT + CONFIRM (B activates + confirms)
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_EQ(p.b.events.size(), 1u);
    EXPECT_TRUE(p.b.events[0].confirmed);
    EXPECT_FALSE(p.b.events[0].via_data);
    EXPECT_TRUE(p.b.events[0].to == kP1);

    // the in-flight new-layout data from A is valid post-commit at B
    auto got = p.b.ctx->on_ciphertext(*w, p.now);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, payload("new-before-b-commit"));

    p.pump(p.b, p.a);  // B's CONFIRM confirms A
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_EQ(p.a.events.size(), 1u);
    EXPECT_TRUE(p.a.events[0].confirmed);
    // effective_counter = the actual TX crypto packet counter at activation
    EXPECT_EQ(p.a.events[0].effective_counter, a_tx_at_activation);
    // peer_effective_counter = B's last accepted claim: positive, and never
    // beyond what A's TX crypto stream has actually produced.
    EXPECT_GT(p.b.ctx->peer_effective_counter(), 0u);
    EXPECT_LE(p.b.ctx->peer_effective_counter(),
              static_cast<uint64_t>(p.a.e2e.get_sending_chain_length()));

    // new-layout data both ways
    for (int i = 0; i < 2; ++i) {
        auto wa = p.a.ctx->encode_data(payload("post-a2b"));
        ASSERT_TRUE(wa.has_value());
        EXPECT_TRUE(p.b.ctx->on_ciphertext(*wa, p.now).has_value());
        auto wb = p.b.ctx->encode_data(payload("post-b2a"));
        ASSERT_TRUE(wb.has_value());
        EXPECT_TRUE(p.a.ctx->on_ciphertext(*wb, p.now).has_value());
    }

    // finalize after grace
    p.advance(kGrace + 1);
    p.a.ctx->tick(p.now);
    p.b.ctx->tick(p.now);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP1);
    EXPECT_EQ(p.a.ctx->profile_epoch(), 1u);
    EXPECT_EQ(p.b.ctx->profile_epoch(), 1u);
    // Crypto counters only advanced throughout — the transition never reset
    // the ratchet (no transition-sequence semantics).
    EXPECT_GT(p.a.e2e.get_sending_chain_length(), chain_before);
    EXPECT_GT(p.a.ctx->peer_effective_counter(), 0u);
    EXPECT_GT(p.b.ctx->peer_effective_counter(), 0u);

    // counters: committed vs effective distinguished, crypto never reset
    auto ca = p.a.ctx->counters();
    auto cb = p.b.ctx->counters();
    EXPECT_EQ(ca.transitions_started, 1u);
    EXPECT_EQ(ca.transitions_committed, 1u);
    EXPECT_EQ(ca.transitions_effective, 1u);
    EXPECT_EQ(ca.transitions_uncertain, 0u);
    EXPECT_EQ(ca.tx_data_stable, 3u);
    EXPECT_EQ(ca.tx_data_new, 3u);
    EXPECT_EQ(cb.rx_data_new, 3u);
    EXPECT_GT(ca.control_tx, 0u);
    EXPECT_GT(cb.control_rx, 0u);
    EXPECT_GT(p.a.e2e.get_messages_sent(), sent_before);
    EXPECT_GT(p.a.e2e.get_sending_chain_length(), chain_before);
    EXPECT_TRUE(p.a.e2e.is_established());
    EXPECT_TRUE(p.b.e2e.is_established());
}

// ══════════════════════════════════════════════════════════════════════════════
// Loss + retransmission: same transition_id, FRESH crypto counter/ciphertext
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, PrepareLossRetransmitFreshCryptoCounter) {
    Pair p;
    ASSERT_TRUE(p.establish());

    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    ASSERT_EQ(p.a.outbox.size(), 1u);
    auto first_wire = p.a.outbox.front();
    auto first_hdr = E2EUtils::deserialize_message(first_wire);
    ASSERT_TRUE(first_hdr.has_value());

    // PREPARE lost on the wire
    p.drop(p.a);
    p.pump(p.a, p.b);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);

    // no retransmit before the deadline
    p.a.ctx->tick(p.now + kInterval - 1);
    EXPECT_TRUE(p.a.outbox.empty());

    // deterministic tick at the deadline -> retransmission
    p.a.ctx->tick(p.now + kInterval);
    ASSERT_EQ(p.a.outbox.size(), 1u);
    auto second_wire = p.a.outbox.front();
    auto second_hdr = E2EUtils::deserialize_message(second_wire);
    ASSERT_TRUE(second_hdr.has_value());

    // same logical message (transition_id), fresh ratchet counter + ciphertext
    EXPECT_GT(second_hdr->header.message_number, first_hdr->header.message_number);
    EXPECT_NE(second_wire, first_wire);
    // plaintext tap: first and retransmitted PREPARE bodies
    auto pt1 = ProfileTransitionCodec::decode(
        CapabilitiesExchange::unwrap(p.a.sent_plaintexts.front()));
    auto pt2 = ProfileTransitionCodec::decode(
        CapabilitiesExchange::unwrap(p.a.sent_plaintexts.back()));
    ASSERT_TRUE(pt1.has_value());
    ASSERT_TRUE(pt2.has_value());
    EXPECT_EQ(pt1->transition_id, pt2->transition_id);
    EXPECT_EQ(pt1->type, TransitionMsgType::PREPARE);
    EXPECT_EQ(pt2->type, TransitionMsgType::PREPARE);
    // fresh effective crypto counter sampled on the retransmission (the body
    // is rebuilt; the logical transition_id stays, the crypto counter moves)
    EXPECT_GT(pt2->effective_counter, pt1->effective_counter);
    EXPECT_EQ(p.a.ctx->counters().control_retransmits, 1u);

    // the retransmission is accepted and the transition completes
    p.pump(p.a, p.b);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
    p.pump(p.b, p.a);
    p.pump(p.a, p.b);
    p.pump(p.b, p.a);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
}

TEST(ProfileTransition, ReadyLossDuplicatePrepareNoNewTimers) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);                       // PREPARE delivered
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
    auto rs0 = p.b.ctx->manager().retransmit_state();
    ASSERT_TRUE(rs0.active);
    EXPECT_EQ(rs0.attempts, 1u);

    p.drop(p.b);                            // READY lost
    p.pump(p.b, p.a);

    // A times out and retransmits PREPARE; B must re-ack WITHOUT resetting
    // its retransmission state (repeated PREPARE creates no new timers).
    p.advance(kInterval);
    p.a.ctx->tick(p.now);
    ASSERT_EQ(p.a.outbox.size(), 1u);
    const auto& prepare_pt = p.a.sent_plaintexts.back();

    // deliver as a LOGICAL duplicate at plaintext level as well
    p.b.ctx->on_plaintext(prepare_pt, p.now);
    auto rs1 = p.b.ctx->manager().retransmit_state();
    EXPECT_EQ(rs1.attempts, rs0.attempts);                 // no new timer
    EXPECT_EQ(rs1.next_deadline_ms, rs0.next_deadline_ms); // deadline intact
    EXPECT_EQ(p.b.ctx->manager().counters().control_duplicates, 1u);
    ASSERT_EQ(p.b.outbox.size(), 1u);                      // re-acked READY

    p.pump(p.b, p.a);                       // READY arrives now
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    p.pump(p.a, p.b);
    p.pump(p.b, p.a);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
}

TEST(ProfileTransition, CommitLossRecoveredByReadyRetransmit) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);
    p.pump(p.b, p.a);                       // READY -> A activates
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    p.drop(p.a, 2);                         // COMMIT + CONFIRM lost
    ASSERT_TRUE(p.a.outbox.empty());

    // B times out waiting for COMMIT and retransmits READY;
    // A treats it as a duplicate and re-emits COMMIT + CONFIRM.
    p.advance(kInterval);
    p.b.ctx->tick(p.now);
    ASSERT_EQ(p.b.outbox.size(), 1u);
    EXPECT_EQ(p.b.ctx->counters().control_retransmits, 1u);
    p.pump(p.b, p.a);
    EXPECT_EQ(p.a.ctx->manager().counters().control_duplicates, 1u);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT); // no re-activation
    EXPECT_EQ(p.a.epoch_changes.size(), 1u);                     // activated once
    ASSERT_EQ(p.a.outbox.size(), 2u);

    p.pump(p.a, p.b);                       // COMMIT + CONFIRM now delivered
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    p.pump(p.b, p.a);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
}

// ══════════════════════════════════════════════════════════════════════════════
// Duplicates / replay never re-confirm
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, LogicalDuplicatesAndReplayDoNotConfirm) {
    Pair p;
    ASSERT_TRUE(p.establish());
    run_happy_path(p);
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    const auto events_a = p.a.events.size();

    // ciphertext-level replay of B's CONFIRM: rejected by the real AEAD
    // replay protection (transport drop, not a protocol event).
    // B's CONFIRM is B's last control ciphertext; it was consumed already,
    // so craft the logical duplicate at plaintext level instead:
    // replay the CONFIRM plaintext after it already confirmed.
    ASSERT_FALSE(p.b.sent_plaintexts.empty());
    p.b.ctx->on_plaintext(p.b.sent_plaintexts.back(), p.now);  // dup CONFIRM @ B? no—
    // ^ feeding B its own message is meaningless; feed A's CONFIRM to B again:
    p.a.ctx->on_plaintext(p.a.sent_plaintexts.back(), p.now);  // A's CONFIRM @ A? no—
    // Proper logical replay: deliver the peer's CONFIRM plaintext again.
    // a.sent_plaintexts.back() is A's CONFIRM (last control A sent).
    auto b_dup_before = p.b.ctx->manager().counters().control_duplicates;
    p.b.ctx->on_plaintext(p.a.sent_plaintexts.back(), p.now);
    EXPECT_EQ(p.b.ctx->manager().counters().control_duplicates,
              b_dup_before + 1);
    EXPECT_EQ(p.b.events.size(), 1u);       // no second SwitchEvent
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.a.events.size(), events_a);

    // replay of the whole transition after completion: stale epoch => reject
    p.advance(kGrace + 1);
    p.a.ctx->tick(p.now);
    p.b.ctx->tick(p.now);
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    const uint64_t claim_b = p.b.ctx->peer_effective_counter();

    // replay original PREPARE plaintext (tapped) at B
    auto rejected_before = p.b.ctx->manager().counters().control_rx_rejected;
    p.b.ctx->on_plaintext(p.a.sent_plaintexts.front(), p.now);
    EXPECT_GT(p.b.ctx->manager().counters().control_rx_rejected,
              rejected_before);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    // stale replay did not move the peer-claim fence backwards
    EXPECT_EQ(p.b.ctx->peer_effective_counter(), claim_b);
    EXPECT_TRUE(p.b.outbox.empty());        // no response to stale replay
}

// ══════════════════════════════════════════════════════════════════════════════
// Early new data / old data grace / expiry
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, EarlyNewDataDoesNotActivateOrConfirm) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);                       // B in READY (not activated)
    p.pump(p.b, p.a);                       // A activates
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    // hold B's COMMIT — A's new-layout data arrives EARLY at B
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);

    auto w = p.a.ctx->encode_data(payload("early-new"));
    ASSERT_TRUE(w.has_value());
    auto got = p.b.ctx->on_ciphertext(*w, p.now);
    EXPECT_FALSE(got.has_value());
    EXPECT_EQ(p.b.ctx->counters().rx_rejected_early_new, 1u);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY); // not activated
    EXPECT_TRUE(p.b.events.empty());                            // not confirmed
    EXPECT_TRUE(p.b.epoch_changes.empty());                     // no activation

    // once COMMIT is processed, subsequent new data is valid and confirms
    p.pump(p.a, p.b);                       // COMMIT + CONFIRM
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
}

TEST(ProfileTransition, OldDataInGraceAcceptedAfterGraceRejected) {
    Pair p;
    ASSERT_TRUE(p.establish());

    // pre-capture old-epoch data ciphertexts (valid, not yet delivered)
    auto old1 = p.a.ctx->encode_data(payload("old-in-grace"));
    auto old2 = p.a.ctx->encode_data(payload("old-after-grace"));
    ASSERT_TRUE(old1.has_value());
    ASSERT_TRUE(old2.has_value());

    run_happy_path(p);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_TRUE(p.b.ctx->grace_deadline_ms().has_value());

    // old-layout data inside the grace window: accepted via old decoder
    auto got = p.b.ctx->on_ciphertext(*old1, p.now);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, payload("old-in-grace"));
    EXPECT_EQ(p.b.ctx->counters().rx_data_old_grace, 1u);

    // past the grace deadline but BEFORE finalize tick: old data rejected
    p.advance(kGrace + 1);
    EXPECT_FALSE(p.b.ctx->on_ciphertext(*old2, p.now).has_value());
    EXPECT_EQ(p.b.ctx->counters().rx_rejected_old_expired, 1u);

    // finalize
    p.b.ctx->tick(p.now);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Corrupt control / aborts / busy / legacy
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, CorruptControlNoStateCorruption) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    ASSERT_EQ(p.a.outbox.size(), 1u);

    // bit-flipped ciphertext: real AEAD rejects, B sees nothing
    auto bad_wire = p.a.outbox.front();
    bad_wire[bad_wire.size() / 2] ^= 0x01;
    EXPECT_FALSE(p.b.ctx->on_ciphertext(bad_wire, p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_EQ(p.b.ctx->manager().counters().control_rx, 0u);

    // malformed control body at plaintext level: rejected, no state change
    std::vector<uint8_t> garbage = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                                    NCP_MSG_MAGIC[2], 0x03, 'P', 'T', 1, 99};
    EXPECT_FALSE(p.b.ctx->on_plaintext(garbage, p.now).has_value());
    EXPECT_EQ(p.b.ctx->manager().counters().control_rx_rejected, 1u);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.b.outbox.empty());

    // wrong session binding: rejected, no state change
    ControlMessage foreign;
    foreign.type = TransitionMsgType::PREPARE;
    foreign.session_id.fill(0xEE);
    foreign.transition_id = 1;
    foreign.profile_epoch = 1;
    foreign.effective_counter = 1;
    foreign.crypto_epoch = 1;
    foreign.target = kP1;
    auto fe = ProfileTransitionCodec::encode(foreign);
    ASSERT_TRUE(fe.has_value());
    std::vector<uint8_t> fpt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                                NCP_MSG_MAGIC[2], 0x03};
    fpt.insert(fpt.end(), fe->begin(), fe->end());
    EXPECT_FALSE(p.b.ctx->on_plaintext(fpt, p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.b.outbox.empty());

    // legit flow still works afterwards (no corruption)
    p.pump(p.a, p.b);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
}

TEST(ProfileTransition, PreActivationAbortCleanRollback) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    EXPECT_TRUE(p.a.ctx->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP0);   // unchanged
    EXPECT_EQ(p.a.ctx->profile_epoch(), 0u);
    ASSERT_EQ(p.a.aborts.size(), 1u);
    EXPECT_EQ(p.a.aborts[0].second, AbortReason::LOCAL_REQUEST);
    EXPECT_TRUE(p.a.events.empty());                 // never effective
    EXPECT_TRUE(p.a.epoch_changes.empty());          // never activated
    EXPECT_EQ(p.a.ctx->counters().transitions_aborted, 1u);

    // peer receives ABORT: clean rollback, no state corruption
    p.pump(p.a, p.b);   // [PREPARE, ABORT]
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP0);
    ASSERT_EQ(p.b.aborts.size(), 1u);
    EXPECT_EQ(p.b.ctx->counters().transitions_aborted, 1u);
    EXPECT_TRUE(p.b.events.empty());

    // data path never broke
    auto w = p.a.ctx->encode_data(payload("after-abort"));
    ASSERT_TRUE(w.has_value());
    EXPECT_TRUE(p.b.ctx->on_ciphertext(*w, p.now).has_value());
}

TEST(ProfileTransition, PostActivationAbortIgnoredNoRollback) {
    Pair p;
    ASSERT_TRUE(p.establish());
    run_happy_path(p);
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);

    // local API: post-activation abort refused
    EXPECT_FALSE(p.a.ctx->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
    EXPECT_EQ(p.a.ctx->counters().aborts_ignored_post_activation, 1u);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);

    // wire ABORT from the peer post-activation: ignored, no rollback.
    // Craft it directly (B's own abort_transition is refused post-activation,
    // which we assert first).
    EXPECT_FALSE(p.b.ctx->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
    EXPECT_EQ(p.b.ctx->counters().aborts_ignored_post_activation, 1u);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);

    ControlMessage ab;
    ab.type = TransitionMsgType::ABORT;
    ab.session_id = p.sid;
    ab.transition_id = p.b.ctx->manager().transition_id();
    ab.profile_epoch = 1;
    // claim must satisfy the effective-counter fence (monotonic, same epoch)
    ab.effective_counter = p.b.ctx->peer_effective_counter();
    ab.crypto_epoch = 1;
    ab.reason = static_cast<uint8_t>(AbortReason::LOCAL_REQUEST);
    auto abe = ProfileTransitionCodec::encode(ab);
    ASSERT_TRUE(abe.has_value());
    std::vector<uint8_t> pt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                               NCP_MSG_MAGIC[2], 0x03};
    pt.insert(pt.end(), abe->begin(), abe->end());
    const auto ignored_before =
        p.b.ctx->counters().aborts_ignored_post_activation;
    EXPECT_FALSE(p.b.ctx->on_plaintext(pt, p.now).has_value());
    EXPECT_EQ(p.b.ctx->counters().aborts_ignored_post_activation,
              ignored_before + 1);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);  // no rollback

    // the way back is a NEW transition (checked in RepeatedTransitions)
    p.settle();
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP1);
}

TEST(ProfileTransition, BusySingleOutstanding) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    // second local start while outstanding
    EXPECT_EQ(p.a.ctx->start_transition(kP2, kL2,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::BUSY);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::PREPARE);
    EXPECT_EQ(p.a.ctx->manager().transition_id(), 1u);

    // peer with an outstanding transition refuses a foreign proposal
    p.pump(p.a, p.b);                       // B in READY (tid=1)
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
    const auto rs0 = p.b.ctx->manager().retransmit_state();
    ASSERT_TRUE(rs0.active);
    EXPECT_EQ(rs0.last_message, TransitionMsgType::READY);

    // Foreign PREPARE (unknown transition_id) at plaintext level. B must
    // answer with a busy ABORT bound to the FOREIGN tid via emit_side —
    // without touching its outstanding READY retransmission state.
    ControlMessage foreign;
    foreign.type = TransitionMsgType::PREPARE;
    foreign.session_id = p.sid;
    foreign.transition_id = 77;
    foreign.profile_epoch = 1;              // == B's pending epoch (passes fence)
    foreign.effective_counter = 0;
    foreign.crypto_epoch = 1;
    foreign.direction = TransitionDirection::BIDIRECTIONAL;
    foreign.target = kP2;
    auto fe = ProfileTransitionCodec::encode(foreign);
    ASSERT_TRUE(fe.has_value());
    std::vector<uint8_t> fpt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                                NCP_MSG_MAGIC[2], 0x03};
    fpt.insert(fpt.end(), fe->begin(), fe->end());
    EXPECT_FALSE(p.b.ctx->on_plaintext(fpt, p.now).has_value());

    // outbox: [READY (outstanding), busy ABORT]; the ABORT is a side emission
    ASSERT_EQ(p.b.outbox.size(), 2u);
    auto ab = peek_control(p.a, p.b.outbox.back());
    ASSERT_TRUE(ab.has_value());
    EXPECT_EQ(ab->type, TransitionMsgType::ABORT);
    EXPECT_EQ(ab->transition_id, 77u);
    EXPECT_EQ(ab->reason, static_cast<uint8_t>(AbortReason::PEER_BUSY));
    p.b.outbox.pop_back();                  // consume the side ABORT

    // the outstanding transition's retransmission state is NOT clobbered
    auto rs1 = p.b.ctx->manager().retransmit_state();
    EXPECT_EQ(rs1.last_message, TransitionMsgType::READY);
    EXPECT_EQ(rs1.attempts, rs0.attempts);
    EXPECT_EQ(rs1.next_deadline_ms, rs0.next_deadline_ms);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
    EXPECT_EQ(p.b.ctx->manager().transition_id(), 1u);

    // tick at the deadline retransmits the ORIGINAL control (READY), not the
    // ABORT — same transition_id, fresh crypto counter/ciphertext.
    p.advance(kInterval);
    p.b.ctx->tick(p.now);
    ASSERT_EQ(p.b.outbox.size(), 2u);       // original READY + retransmit
    ASSERT_EQ(p.b.sent_plaintexts.size(), 3u);
    auto orig = ProfileTransitionCodec::decode(
        CapabilitiesExchange::unwrap(p.b.sent_plaintexts[0]));
    auto rt = ProfileTransitionCodec::decode(
        CapabilitiesExchange::unwrap(p.b.sent_plaintexts[2]));
    ASSERT_TRUE(orig.has_value());
    ASSERT_TRUE(rt.has_value());
    EXPECT_EQ(orig->type, TransitionMsgType::READY);
    EXPECT_EQ(rt->type, TransitionMsgType::READY);
    EXPECT_EQ(orig->transition_id, 1u);
    EXPECT_EQ(rt->transition_id, 1u);
    EXPECT_GT(rt->effective_counter, orig->effective_counter);
    EXPECT_NE(p.b.outbox.front(), p.b.outbox.back());  // fresh ciphertext
    EXPECT_EQ(p.b.ctx->counters().control_retransmits, 1u);

    // the foreign proposal never disturbed the real transition: it completes
    p.pump(p.b, p.a);                       // READY + duplicate READY
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    p.pump(p.a, p.b);                       // COMMIT + CONFIRM (x2)
    p.pump(p.b, p.a);                       // CONFIRM
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
}

// ══════════════════════════════════════════════════════════════════════════════
// Legacy peer (no capability): no wire traffic at all
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, LegacyPeerNoWire) {
    Pair p;
    ASSERT_TRUE(p.establish(/*capable=*/false));

    EXPECT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NOT_SUPPORTED);
    EXPECT_TRUE(p.a.outbox.empty());            // outbound never invoked
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_EQ(p.a.ctx->counters().control_tx, 0u);

    // inbound control from a non-negotiated peer: rejected, no response
    ControlMessage m;
    m.type = TransitionMsgType::PREPARE;
    m.session_id = p.sid;
    m.transition_id = 1;
    m.profile_epoch = 1;
    m.effective_counter = 1;
    m.crypto_epoch = 1;
    m.target = kP1;
    auto enc = ProfileTransitionCodec::encode(m);
    ASSERT_TRUE(enc.has_value());
    std::vector<uint8_t> pt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                               NCP_MSG_MAGIC[2], 0x03};
    pt.insert(pt.end(), enc->begin(), enc->end());
    EXPECT_FALSE(p.b.ctx->on_plaintext(pt, p.now).has_value());
    EXPECT_TRUE(p.b.outbox.empty());            // never answers without capability
    EXPECT_EQ(p.b.ctx->manager().counters().control_rx_rejected, 1u);

    // plain data path unaffected
    auto w = p.a.ctx->encode_data(payload("legacy-data"));
    ASSERT_TRUE(w.has_value());
    auto got = p.b.ctx->on_ciphertext(*w, p.now);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, payload("legacy-data"));
}

// ══════════════════════════════════════════════════════════════════════════════
// Timeouts
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, PreActivationTimeoutCleanAbort) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.drop(p.a);                                // PREPARE lost forever

    // attempts: initial + (max-1) retransmits, then timeout
    for (uint32_t i = 1; i < kAttempts; ++i) {
        p.advance(kInterval);
        p.a.ctx->tick(p.now);
        ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::PREPARE);
        ASSERT_EQ(p.a.outbox.size(), 1u);
        p.drop(p.a);
    }
    p.advance(kInterval);
    p.a.ctx->tick(p.now);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_EQ(p.a.ctx->counters().transitions_timed_out, 1u);
    EXPECT_EQ(p.a.ctx->counters().control_retransmits, kAttempts - 1);
    ASSERT_EQ(p.a.aborts.size(), 1u);
    EXPECT_EQ(p.a.aborts[0].second, AbortReason::TIMEOUT);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP0);
    ASSERT_EQ(p.a.outbox.size(), 1u);           // best-effort ABORT emitted
}

TEST(ProfileTransition, TimeoutAsymmetricNoSilentRollback) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);                           // PREPARE
    p.pump(p.b, p.a);                           // READY -> A activated
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    p.drop(p.a, 2);                             // COMMIT + CONFIRM lost

    // B (pre-activation) exhausts READY retransmits and aborts cleanly.
    for (uint32_t i = 1; i < kAttempts; ++i) {
        p.advance(kInterval);
        p.b.ctx->tick(p.now);
        ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
        p.drop(p.b);                            // retransmitted READYs lost
    }
    p.advance(kInterval);
    p.b.ctx->tick(p.now);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_EQ(p.b.ctx->counters().transitions_timed_out, 1u);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP0);

    // B's ABORT reaches A — but A is post-activation: ignored, no rollback.
    p.pump(p.b, p.a);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    EXPECT_EQ(p.a.ctx->counters().aborts_ignored_post_activation, 1u);

    // A (post-activation) exhausts CONFIRM retransmits: completes as
    // UNCERTAIN — keeps the new profile, no silent rollback.
    for (uint32_t i = 1; i < kAttempts; ++i) {
        p.advance(kInterval);
        p.a.ctx->tick(p.now);
        ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
        p.drop(p.a);
    }
    p.advance(kInterval);
    p.a.ctx->tick(p.now);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_EQ(p.a.events.size(), 1u);
    EXPECT_FALSE(p.a.events[0].confirmed);      // uncertain completion
    EXPECT_EQ(p.a.ctx->counters().transitions_uncertain, 1u);
    EXPECT_EQ(p.a.ctx->counters().transitions_effective, 0u);

    // asymmetric outcome: A keeps new profile, B stays on old — surfaced via
    // counters, no hidden state change on either side.
    p.advance(kGrace + 1);
    p.a.ctx->tick(p.now);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);   // committed side wins
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP0);   // aborted side unchanged
}

// ══════════════════════════════════════════════════════════════════════════════
// Epoch fencing / cross-epoch replay
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, EpochFencingRejectsStaleAndFuture) {
    Pair p;
    ASSERT_TRUE(p.establish());

    auto mk_prepare = [&](uint64_t tid, uint32_t epoch, uint32_t eff,
                          uint64_t crypto_epoch) {
        ControlMessage m;
        m.type = TransitionMsgType::PREPARE;
        m.session_id = p.sid;
        m.transition_id = tid;
        m.profile_epoch = epoch;
        m.effective_counter = eff;
        m.crypto_epoch = crypto_epoch;
        m.target = kP1;
        auto enc = ProfileTransitionCodec::encode(m);
        EXPECT_TRUE(enc.has_value());
        std::vector<uint8_t> pt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                                   NCP_MSG_MAGIC[2], 0x03};
        pt.insert(pt.end(), enc->begin(), enc->end());
        return pt;
    };

    // wrong target epoch (current is 0 => only 1 is acceptable)
    EXPECT_FALSE(p.b.ctx->on_plaintext(mk_prepare(1, 0, 1, 1), p.now).has_value());
    EXPECT_FALSE(p.b.ctx->on_plaintext(mk_prepare(1, 2, 1, 1), p.now).has_value());
    // effective_counter above what the crypto stream can prove (claimed 7
    // but the carrying packet's crypto counter is only 3): impossible claim
    EXPECT_FALSE(p.b.ctx->on_plaintext(mk_prepare(1, 1, 7, 1), p.now,
                                                  /*packet_crypto_counter=*/3)
                     .has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_EQ(p.b.ctx->manager().counters().control_rx_rejected, 3u);

    // valid one accepted (claim 0 == A's real chain start, so the fence stays
    // consistent with the genuine transition below). Control messages never
    // yield a payload from on_plaintext — acceptance shows as state change.
    EXPECT_FALSE(p.b.ctx->on_plaintext(mk_prepare(5, 1, 0, 1), p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
    // roll back to make room for the cross-epoch check
    p.b.ctx->abort_transition(AbortReason::LOCAL_REQUEST, p.now);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);

    // complete a real transition at crypto_epoch 1, then rotate crypto epoch
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b); p.pump(p.b, p.a); p.pump(p.a, p.b); p.pump(p.b, p.a);
    p.advance(kGrace + 1);
    p.a.ctx->tick(p.now); p.b.ctx->tick(p.now);
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);

    // simulate a key rotation on both ends (crypto epoch moves forward)
    p.a.ctx->set_crypto_epoch(2);
    p.b.ctx->set_crypto_epoch(2);

    // a PREPARE replayed/bound to an older crypto epoch is fenced out
    EXPECT_FALSE(p.b.ctx->on_plaintext(mk_prepare(9, 2, 2, 0), p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    // current crypto epoch accepted (control => nullopt payload, READY state)
    EXPECT_FALSE(p.b.ctx->on_plaintext(mk_prepare(9, 2, 2, 2), p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);
}

// ══════════════════════════════════════════════════════════════════════════════
// Crypto continuity across the transition (no ratchet/replay/counter reset)
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, RatchetReplayAndCountersSurviveTransition) {
    Pair p;
    ASSERT_TRUE(p.establish());

    // capture an out-of-order old-epoch message (skipped key material)
    auto early = p.a.ctx->encode_data(payload("ooo-old"));
    ASSERT_TRUE(early.has_value());
    auto early_hdr = E2EUtils::deserialize_message(*early);
    ASSERT_TRUE(early_hdr.has_value());

    const uint32_t send_chain_a = p.a.e2e.get_sending_chain_length();
    const uint32_t recv_chain_b = p.b.e2e.get_receiving_chain_length();

    run_happy_path(p);

    // chains only advanced — the transition never reset them
    EXPECT_GT(p.a.e2e.get_sending_chain_length(), send_chain_a);
    EXPECT_GT(p.b.e2e.get_receiving_chain_length(), recv_chain_b);

    // the pre-transition message still decrypts via skipped keys (grace)
    auto got = p.b.ctx->on_ciphertext(*early, p.now);
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, payload("ooo-old"));
    EXPECT_EQ(p.b.ctx->counters().rx_data_old_grace, 1u);

    // and its exact ciphertext replay is rejected by the real replay window
    EXPECT_FALSE(p.b.ctx->on_ciphertext(*early, p.now).has_value());

    // sessions still established, message counters monotonic
    EXPECT_TRUE(p.a.e2e.is_established());
    EXPECT_TRUE(p.b.e2e.is_established());
}

// ══════════════════════════════════════════════════════════════════════════════
// Confirmation via first valid new-layout data (no CONFIRM needed)
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, ConfirmViaNewLayoutData) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);                  // PREPARE
    p.pump(p.b, p.a);                  // READY (A activates)
    // deliver only COMMIT, drop A's CONFIRM
    ASSERT_EQ(p.a.outbox.size(), 2u);
    auto commit_wire = p.a.outbox.front();
    p.a.outbox.pop_front();
    p.drop(p.a);                       // CONFIRM dropped
    p.b.ctx->on_ciphertext(commit_wire, p.now);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::COMMIT);
    p.drop(p.b);                       // B's CONFIRM dropped too

    // first valid new-layout data confirms both directions
    auto w_ab = p.a.ctx->encode_data(payload("confirm-by-data"));
    ASSERT_TRUE(w_ab.has_value());
    ASSERT_TRUE(p.b.ctx->on_ciphertext(*w_ab, p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_EQ(p.b.events.size(), 1u);
    EXPECT_TRUE(p.b.events[0].confirmed);
    EXPECT_TRUE(p.b.events[0].via_data);

    auto w_ba = p.b.ctx->encode_data(payload("confirm-back"));
    ASSERT_TRUE(w_ba.has_value());
    ASSERT_TRUE(p.a.ctx->on_ciphertext(*w_ba, p.now).has_value());
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    ASSERT_EQ(p.a.events.size(), 1u);
    EXPECT_TRUE(p.a.events[0].via_data);

    EXPECT_EQ(p.a.ctx->counters().transitions_effective, 1u);
    EXPECT_EQ(p.b.ctx->counters().transitions_effective, 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Repeated transitions + epoch-fence API for queued shape/timer cancellation
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, RepeatedTransitionsEpochFence) {
    Pair p;
    ASSERT_TRUE(p.establish());

    // transition 1: P0 -> P1
    run_happy_path(p);
    p.advance(kGrace + 1);
    p.settle();
    ASSERT_EQ(p.a.ctx->profile_epoch(), 1u);
    ASSERT_TRUE(p.a.ctx->stable_profile() == kP1);
    // peer-claim fence state after transition 1 (crypto counters, not a
    // transition sequence): must keep advancing across transitions
    const uint64_t claim1_a = p.a.ctx->peer_effective_counter();
    const uint64_t claim1_b = p.b.ctx->peer_effective_counter();
    EXPECT_GT(claim1_a, 0u);
    EXPECT_GT(claim1_b, 0u);

    // transition 2: P1 -> P2 (reverse-capable: repeated transitions work)
    ASSERT_EQ(p.a.ctx->start_transition(kP2, kL2,
                                        TransitionDirection::BIDIRECTIONAL,
                                        2, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b); p.pump(p.b, p.a); p.pump(p.a, p.b); p.pump(p.b, p.a);
    p.advance(kGrace + 1);
    p.settle();

    EXPECT_EQ(p.a.ctx->profile_epoch(), 2u);
    EXPECT_EQ(p.b.ctx->profile_epoch(), 2u);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP2);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP2);
    // same crypto_epoch => effective counters are strictly monotonic across
    // transitions (the crypto stream never resets)
    EXPECT_GT(p.a.ctx->peer_effective_counter(), claim1_a);
    EXPECT_GT(p.b.ctx->peer_effective_counter(), claim1_b);

    // epoch observers fired for both activations (host cancels queued
    // shape/timer work for superseded epochs through this fence)
    ASSERT_EQ(p.a.epoch_changes.size(), 2u);
    EXPECT_EQ(p.a.epoch_changes[0], std::make_pair(0u, 1u));
    EXPECT_EQ(p.a.epoch_changes[1], std::make_pair(1u, 2u));
    EXPECT_EQ(p.a.ctx->min_accepted_data_epoch(), 2u);

    // data flows on the newest layout — after finalize the new epoch IS the
    // stable epoch, so it is counted on the stable bucket
    auto w = p.a.ctx->encode_data(payload("third-layout"));
    ASSERT_TRUE(w.has_value());
    EXPECT_TRUE(p.b.ctx->on_ciphertext(*w, p.now).has_value());
    EXPECT_EQ(p.b.ctx->counters().rx_data_stable, 1u);
    EXPECT_EQ(p.b.ctx->counters().rx_data_new, 0u);

    // stale epoch-1 data is now unknown/fenced out
    ControlMessage stale;  // control replay with old epoch rejected
    stale.type = TransitionMsgType::PREPARE;
    stale.session_id = p.sid;
    stale.transition_id = 99;
    stale.profile_epoch = 1;             // current+1 would be 3
    stale.effective_counter = 3;
    stale.crypto_epoch = 1;
    stale.target = kP1;
    auto se = ProfileTransitionCodec::encode(stale);
    ASSERT_TRUE(se.has_value());
    std::vector<uint8_t> pt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                               NCP_MSG_MAGIC[2], 0x03};
    pt.insert(pt.end(), se->begin(), se->end());
    EXPECT_FALSE(p.b.ctx->on_plaintext(pt, p.now).has_value());
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
}

// ══════════════════════════════════════════════════════════════════════════════
// Catalog integration (read-only resolver)
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, CatalogLayoutResolver) {
    ReferenceProfileCatalog catalog;
    catalog.register_legacy_builtins();
    ASSERT_GT(catalog.size(), 0u);

    const auto* d = catalog.find_latest("webrtc_video");
    ASSERT_NE(d, nullptr);

    auto resolver = make_catalog_layout_resolver(&catalog);
    auto ref = profile_ref_from_descriptor(*d);
    auto layout = resolver(ref);
    ASSERT_TRUE(layout.has_value());
    EXPECT_EQ(layout->header_overhead_bytes,
              d->padding_header.header_overhead_bytes);
    EXPECT_EQ(layout->padding_block_bytes,
              d->padding_header.padding_block_bytes);

    // wrong revision / tampered hash => nullopt
    EXPECT_FALSE(resolver(make_ref("webrtc_video", 999, 0x00)).has_value());
    auto bad = ref;
    bad.content_hash[0] ^= 0xFF;
    EXPECT_FALSE(resolver(bad).has_value());
    // null catalog => nullopt
    EXPECT_FALSE(make_catalog_layout_resolver(nullptr)(ref).has_value());
}

// ══════════════════════════════════════════════════════════════════════════════
// Direction: TX_ONLY switches TX only, RX keeps decoding old layout
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, TxOnlyDirectionKeepsRxOnStable) {
    Pair p;
    ASSERT_TRUE(p.establish());
    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::TX_ONLY,
                                        1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b); p.pump(p.b, p.a);
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);

    // A encodes on the new epoch...
    EXPECT_EQ(p.a.ctx->tx_epoch(), 1u);
    // ...but does not accept new-epoch RX itself (TX_ONLY). B has not
    // activated yet, so its data is on the OLD epoch; post-activation at A
    // that is the grace decode path.
    auto w_new = p.b.ctx->encode_data(payload("b-still-old"));
    ASSERT_TRUE(w_new.has_value());
    EXPECT_TRUE(p.a.ctx->on_ciphertext(*w_new, p.now).has_value());
    EXPECT_EQ(p.a.ctx->counters().rx_data_old_grace, 1u);
    EXPECT_EQ(p.a.ctx->counters().rx_data_stable, 0u);

    p.pump(p.a, p.b); p.pump(p.b, p.a);
    p.advance(kGrace + 1);
    p.settle();
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Crypto-epoch fences are PEER-epoch-relative (review: E2E epoch asymmetry).
// e2e.cpp bumps crypto_epoch at rotate_keys() AND at commit_dh_step(), so the
// rotation initiator gains +2 per completed cycle and the responder +1 — the
// gap never shrinks. Fencing the peer's advertised epoch against LOCAL epoch
// state made every READY unreachable once the gap exceeded the retransmit
// budget and poisoned the cross-transition PREPARE fence against peer-led
// transitions. The fences now bind and ratchet the PEER's epoch only.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ProfileTransition, EpochGapTransitionCompletes) {
    Pair p;
    ASSERT_TRUE(p.establish());

    // Simulate >=6 completed E2E rotation cycles of epoch asymmetry (gap 8,
    // well beyond the retransmit budget kAttempts = 4).
    p.a.ctx->set_crypto_epoch(17);   // rotation-initiator side (+2/cycle)
    p.b.ctx->set_crypto_epoch(9);    // responder side (+1/cycle)
    ASSERT_GE(17u - 9u, 6u);

    // Initiator-led transition MUST complete on a lossless link despite the
    // epoch gap: the READY carries the peer's LOWER epoch and must bind the
    // peer-epoch fence instead of being rejected against the local epoch.
    run_happy_path(p);
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);

    // No fence fired on the genuine message flow.
    EXPECT_EQ(p.a.ctx->counters().control_rx_rejected, 0u);
    EXPECT_EQ(p.b.ctx->counters().control_rx_rejected, 0u);

    p.advance(kGrace + 1);
    p.settle();
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP1);   // same stable profile
    EXPECT_EQ(p.a.ctx->profile_epoch(), 1u);
    EXPECT_EQ(p.b.ctx->profile_epoch(), 1u);
    EXPECT_EQ(p.a.ctx->counters().transitions_effective, 1u);
    EXPECT_EQ(p.b.ctx->counters().transitions_effective, 1u);
}

TEST(ProfileTransition, ResponderLedAfterInitiatorLedEpochGap) {
    Pair p;
    ASSERT_TRUE(p.establish());
    p.a.ctx->set_crypto_epoch(17);
    p.b.ctx->set_crypto_epoch(9);

    // Transition 1: led by the epoch-AHEAD endpoint, completes.
    run_happy_path(p);
    p.advance(kGrace + 1);
    p.settle();
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_TRUE(p.a.ctx->stable_profile() == kP1);

    // Transition 2: led immediately by the epoch-TRAILING endpoint. Its
    // PREPARE advertises crypto_epoch 9; the cross-transition fence at A must
    // compare it against the PEER's last completed epoch (9), not the local
    // epoch (17) — otherwise the peer-led transition is fenced out forever.
    ASSERT_EQ(p.b.ctx->start_transition(kP0, kL0,
                                        TransitionDirection::BIDIRECTIONAL,
                                        /*reason=*/2, p.now),
              TransitionError::NONE);
    p.pump(p.b, p.a);  // PREPARE
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::READY)
        << "responder-led PREPARE fenced out by a locally inflated epoch";
    p.pump(p.a, p.b);  // READY
    p.pump(p.b, p.a);  // COMMIT + CONFIRM
    p.pump(p.a, p.b);  // CONFIRM

    p.advance(kGrace + 1);
    p.settle();
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP0);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP0);
    EXPECT_EQ(p.a.ctx->profile_epoch(), 2u);
    EXPECT_EQ(p.b.ctx->profile_epoch(), 2u);
    EXPECT_EQ(p.a.ctx->counters().transitions_effective, 2u);
    EXPECT_EQ(p.b.ctx->counters().transitions_effective, 2u);
}

TEST(ProfileTransition, MidTransitionPeerRekeyAccepted) {
    Pair p;
    ASSERT_TRUE(p.establish());
    p.a.ctx->set_crypto_epoch(17);
    p.b.ctx->set_crypto_epoch(9);

    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        /*reason=*/1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);  // PREPARE (epoch 17 binds the peer fence at B)
    p.pump(p.b, p.a);  // READY (epoch 9 binds the peer fence at A)
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::READY);

    // The peer's crypto epoch ADVANCES between its messages (mid-transition
    // rekey): forward motion must be accepted and ratchet the bound.
    p.b.ctx->set_crypto_epoch(12);
    p.pump(p.a, p.b);  // COMMIT + CONFIRM (epoch 17 >= bound 17 at B)
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    p.pump(p.b, p.a);  // CONFIRM (epoch 12 >= bound 9 at A: ratchet)
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.a.ctx->counters().control_rx_rejected, 0u);
    EXPECT_EQ(p.b.ctx->counters().control_rx_rejected, 0u);

    p.advance(kGrace + 1);
    p.settle();
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::IDLE);
    ASSERT_EQ(p.b.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP1);
}

TEST(ProfileTransition, OlderGenerationReplayRejected) {
    Pair p;
    ASSERT_TRUE(p.establish());
    p.a.ctx->set_crypto_epoch(17);
    p.b.ctx->set_crypto_epoch(9);

    ASSERT_EQ(p.a.ctx->start_transition(kP1, kL1,
                                        TransitionDirection::BIDIRECTIONAL,
                                        /*reason=*/1, p.now),
              TransitionError::NONE);
    p.pump(p.a, p.b);  // PREPARE
    p.pump(p.b, p.a);  // READY: peer-epoch bound at A is now 9
    ASSERT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);

    // A control message replayed with a crypto_epoch LOWER than the observed
    // peer bound for this transition: rejected, counted, no state change.
    ControlMessage replay;
    replay.type = TransitionMsgType::READY;
    replay.session_id = p.sid;
    replay.transition_id = p.a.ctx->manager().transition_id();
    replay.profile_epoch = 1;
    replay.effective_counter = 0;
    replay.crypto_epoch = 5;  // older generation than the bound (9)
    replay.direction = TransitionDirection::BIDIRECTIONAL;
    replay.target = kP1;
    auto enc = ProfileTransitionCodec::encode(replay);
    ASSERT_TRUE(enc.has_value());
    std::vector<uint8_t> pt = {NCP_MSG_MAGIC[0], NCP_MSG_MAGIC[1],
                               NCP_MSG_MAGIC[2], 0x03};
    pt.insert(pt.end(), enc->begin(), enc->end());

    const uint64_t rejected_before =
        p.a.ctx->manager().counters().control_rx_rejected;
    const size_t outbox_before = p.a.outbox.size();
    p.a.ctx->on_plaintext(pt, p.now);
    EXPECT_EQ(p.a.ctx->manager().counters().control_rx_rejected,
              rejected_before + 1)
        << "older-generation replay was not rejected";
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::COMMIT);
    EXPECT_EQ(p.a.outbox.size(), outbox_before);  // no reaction traffic
    EXPECT_TRUE(p.a.events.empty());

    // The genuine transition still completes afterwards.
    p.pump(p.a, p.b);  // COMMIT + CONFIRM
    p.pump(p.b, p.a);  // CONFIRM
    EXPECT_EQ(p.a.ctx->state(), ProfileTransitionState::DRAIN);
    EXPECT_EQ(p.b.ctx->state(), ProfileTransitionState::DRAIN);
    p.advance(kGrace + 1);
    p.settle();
    EXPECT_TRUE(p.a.ctx->stable_profile() == kP1);
    EXPECT_TRUE(p.b.ctx->stable_profile() == kP1);
}
