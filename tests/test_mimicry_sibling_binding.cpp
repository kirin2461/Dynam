// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_sibling_binding.cpp
//
// I-SIB-1 regression: the hash-bound descriptor's `ProtocolFamily family`
// IS the closed built-in mask-variant group (catalog schema 1 normative
// resolution — no separate per-descriptor variant-group field exists).
//
// Rationale under test:
//   * `family` is covered by ProfileDescriptor::content_hash, so the
//     verified descriptor identity (id, revision, content_hash)
//     deterministically selects the reviewed built-in variant map
//     (family_variant_masks() in ncp_mimicry_session.cpp) on BOTH endpoints;
//   * a timing/statistics revision must not silently change the wire
//     parsers the receiver loads — same family => same sibling set, even
//     across a rev-N -> rev-N+1 transition with a different content_hash;
//   * a stale content_hash (family/content mutated without re-hash, or a
//     hash replayed across revisions) is detected and refused;
//   * moving to a DIFFERENT family deterministically swaps the sibling set
//     on both endpoints; new variant groups require reviewed code (a family
//     map change), never arbitrary catalog data.
//
// Evidence (real NcpMimicrySession pairs, real datagrams, exact candidate
// work counters — harness adapted from tests/test_mimicry_session_fsm.cpp):
//   (a) SameFamilyRevisionTransitionRetainsSiblingSet — two revisions of
//       the same QUIC descriptor id with different content_hash retain the
//       family-derived sibling set {QUIC_INITIAL, QUIC_SHORT_HEADER};
//       QUIC_INITIAL data still decodes via the sibling candidate after a
//       rev1 -> rev2 transition (and the per-datagram candidate work is
//       unchanged).
//   (b) FamilyMutationChangesHashAndStaleHashRejected — flipping ONLY
//       `family` changes compute_content_hash(); a descriptor registered
//       with a stale (pre-mutation) hash fails validation; and a live
//       session refuses a PREPARE whose ProfileRef carries a stale hash
//       (ABORT before READY) while accepting the same target with the fresh
//       hash.
//   (c) FamilyTransitionSwapsSiblingSetOnBothEndpoints — QUIC -> FSM-enabled
//       WEBRTC transition deterministically swaps the RX sibling set on
//       both endpoints: after grace expiry a foreign QUIC_INITIAL datagram
//       drops from {active QUIC_SHORT + sibling QUIC_INITIAL} work to
//       WEBRTC/STUN-only work.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_mimicry_fsm.hpp"
#include "ncp_mimicry_session.hpp"

#include <array>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace ncp;

namespace {

// ── Test catalog ────────────────────────────────────────────────────────────
//
//   sib.quic  rev1/rev2 — QUIC family, FSM parked at "bootstrap" (TX variant
//                         QUIC_INITIAL; sibling set {QUIC_INITIAL,
//                         QUIC_SHORT_HEADER}). rev2 differs from rev1 ONLY in
//                         the timing/statistics model (iat/sizes), so it has
//                         a different content_hash but the same family.
//   sib.webrtc rev1     — WEBRTC family, FSM parked at "data" (variant
//                         STUN_MESSAGE == active mask; sibling set
//                         {STUN_MESSAGE}).
constexpr const char* kQuicId   = "sib.quic";
constexpr const char* kWebrtcId = "sib.webrtc";

/// Zero derivation bounds: deterministic, exactly reconstructible session
/// derivation (mirrors tests/test_mimicry_session_fsm.cpp).
ProfileDescriptor make_base_descriptor(const char* id, uint32_t revision,
                                       ProtocolFamily fam) {
    ProfileDescriptor d;
    d.profile_id = id;
    d.revision = revision;
    d.family = fam;
    d.min_wire_version = 1;
    d.max_wire_version = 3;

    d.sizes.kind = SizeDistKind::NORMAL;
    d.sizes.mean = 500.0;
    d.sizes.stddev = 50.0;
    d.sizes.clamp_min = 64.0;
    d.sizes.clamp_max = 1200.0;

    d.iat.kind = IntervalKind::NORMAL;
    d.iat.mean_ms = 5.0;
    d.iat.stddev_ms = 1.0;

    d.padding_header.header_overhead_bytes = 0;
    d.padding_header.padding_block_bytes = 0;
    d.padding_header.padding_max_bytes = 64;
    d.padding_header.pad_to_block = false;

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1400;

    d.provenance.sample_count = 5000;
    d.provenance.window_count = 50;

    d.derivation = DerivationBounds{};  // zero jitter: exact reconstruction

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

void add_fsm_model(ProfileDescriptor& d, const char* initial_state) {
    d.fsm.enabled = true;
    d.fsm.initial_state = initial_state;
    d.fsm.states = {
        {"bootstrap",   5.0,    1.0},
        {"handshake",   50.0,   0.0},
        {"established", 200.0,  10.0},
        {"data",        1000.0, 100.0},
    };
    d.fsm.transitions = {
        {"bootstrap",   "handshake",   1.0},
        {"handshake",   "established", 1.0},
        {"established", "data",        1.0},
        {"data",        "data",        1.0},
    };
    ReferenceProfileCatalog::update_content_hash(d);
}

/// Outer-mask shape probe over a complete adapter datagram (kind byte +
/// body) — same probe as tests/test_mimicry_session_fsm.cpp.
enum class MaskShape { kOther, kGenericUdp, kQuicInitial, kQuicShort, kStun };

MaskShape probe_shape(const std::vector<uint8_t>& d) {
    if (d.size() < 21 || d[0] != 'E') return MaskShape::kOther;
    const uint8_t* b = d.data() + 1;
    const size_t n = d.size() - 1;
    if (b[0] & 0x80) return MaskShape::kQuicInitial;          // long header
    if ((b[0] & 0xC0) == 0x40) return MaskShape::kQuicShort;  // short header
    if (n >= 8 && b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xA4 &&
        b[7] == 0x42)
        return MaskShape::kStun;                              // RFC 5389 cookie
    return MaskShape::kGenericUdp;
}

// ── Hermetic session pair (adapted from VariantPair) ────────────────────────

struct SibPair {
    ReferenceProfileCatalog catalog;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;  // manual monotonic ms

    std::vector<std::vector<uint8_t>> cli_app;
    std::vector<std::vector<uint8_t>> srv_app;

    SibPair() {
        auto q1 = make_base_descriptor(kQuicId, 1, ProtocolFamily::QUIC);
        add_fsm_model(q1, "bootstrap");
        auto r1 = catalog.register_builtin(q1);
        EXPECT_TRUE(r1.ok()) << (r1.issues.empty() ? "" : r1.issues[0].message);

        // rev2: same id, same family, same wire parsers — only the
        // timing/statistics model changed (iat mean + size mean). This is
        // exactly the revision class that must NOT silently change the RX
        // sibling set.
        auto q2 = make_base_descriptor(kQuicId, 2, ProtocolFamily::QUIC);
        q2.iat.mean_ms = 7.5;
        q2.sizes.mean = 480.0;
        add_fsm_model(q2, "bootstrap");
        auto r2 = catalog.register_builtin(q2);
        EXPECT_TRUE(r2.ok()) << (r2.issues.empty() ? "" : r2.issues[0].message);
        EXPECT_NE(q2.content_hash, q1.content_hash)
            << "statistics revision must change the content_hash";

        auto w = make_base_descriptor(kWebrtcId, 1, ProtocolFamily::WEBRTC);
        add_fsm_model(w, "data");
        auto rw = catalog.register_builtin(w);
        EXPECT_TRUE(rw.ok()) << (rw.issues.empty() ? "" : rw.issues[0].message);
    }

    static std::optional<TrafficMimicry::MimicProfile> resolve_mimic(
        const ProfileRef& r) {
        using MP = TrafficMimicry::MimicProfile;
        if (r.id == kQuicId) return MP::QUIC_SHORT_HEADER;  // family base
        if (r.id == kWebrtcId) return MP::STUN_MESSAGE;
        return std::nullopt;
    }

    void init(const char* stable_id, uint32_t stable_rev) {
        const auto* desc = catalog.find(stable_id, stable_rev);
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;  // deterministic wire sizes
        base.catalog = &catalog;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_resolver = &SibPair::resolve_mimic;
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1000;
        base.path_mtu_bytes = 1500;
        base.porthop_overhead_bytes = 20;
        base.max_application_payload = 1024;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.stable_profile = profile_ref_from_descriptor(*desc);
        cc.stable_layout = profile_layout_from_descriptor(*desc);
        cc.stable_mimic = *resolve_mimic(cc.stable_profile);
        cc.mimic_config.profile = cc.stable_mimic;
        cli.reset(new NcpMimicrySession(cc));

        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        sc.stable_profile = profile_ref_from_descriptor(*desc);
        sc.stable_layout = profile_layout_from_descriptor(*desc);
        sc.stable_mimic = *resolve_mimic(sc.stable_profile);
        sc.mimic_config.profile = sc.stable_mimic;
        srv.reset(new NcpMimicrySession(sc));
    }

    void advance(uint64_t ms) {
        now += ms;
        cli->tick(now);
        srv->tick(now);
    }

    NcpMimicrySession::IngressResult deliver(NcpMimicrySession& to,
                                             const std::vector<uint8_t>& d) {
        auto r = to.on_datagram(d, now);
        if (r.kind == NcpMimicrySession::IngressKind::Data && r.app_payload)
            (&to == cli.get() ? cli_app : srv_app).push_back(*r.app_payload);
        return r;
    }

    void pump() {
        for (int i = 0; i < 1000; ++i) {
            bool progress = false;
            while (auto o = cli->next_outbound()) {
                deliver(*srv, o->bytes);
                progress = true;
            }
            while (auto o = srv->next_outbound()) {
                deliver(*cli, o->bytes);
                progress = true;
            }
            if (!progress) break;
        }
    }

    bool established() {
        if (!cli->is_established()) {
            auto hs = cli->start_handshake();
            if (hs) deliver(*srv, hs->bytes);
        }
        pump();
        return cli->is_established() && srv->is_established();
    }

    /// A foreign (different session-key material) TrafficMimicry instance
    /// crafting hostile-but-well-formed QUIC_INITIAL datagrams: the
    /// QUIC_INITIAL mask is self-authenticating, so its unwrap SUCCEEDS at
    /// the mask layer whenever the sibling candidate is installed, and the
    /// datagram is then rejected by the real E2E AEAD.
    std::vector<uint8_t> craft_foreign_quic_initial(size_t n) {
        TrafficMimicry foreign;
        TrafficMimicry::MimicConfig mc;
        mc.wire_version = 3;
        foreign.set_config(mc);
        std::vector<uint8_t> junk(n, 0xAB);
        auto w = foreign.wrap_payload(
            junk, TrafficMimicry::MimicProfile::QUIC_INITIAL);
        std::vector<uint8_t> d;
        d.push_back('E');
        d.insert(d.end(), w.begin(), w.end());
        return d;
    }

    static std::vector<uint8_t> app_payload(uint32_t seq, size_t len) {
        std::vector<uint8_t> p(len);
        p[0] = static_cast<uint8_t>((seq >> 24) & 0xFF);
        p[1] = static_cast<uint8_t>((seq >> 16) & 0xFF);
        p[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
        p[3] = static_cast<uint8_t>(seq & 0xFF);
        for (size_t i = 4; i < len; ++i)
            p[i] = static_cast<uint8_t>((seq * 31u + i * 7u) & 0xFF);
        return p;
    }
};

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return true;
    }();
    ASSERT_TRUE(once);
}

// ── Candidate-work accounting helpers (I-TXD-2 counters) ────────────────────

struct CandWork {
    uint64_t unwrap;
    uint64_t aead;
};

CandWork snap(NcpMimicrySession& s) {
    const auto st = s.stats();
    return {st.candidate_unwrap_attempts_total,
            st.candidate_aead_attempts_total};
}

/// Deliver `n` foreign QUIC_INITIAL datagrams to `rx` and require EXACTLY
/// `unwrap_per` mask-unwrap attempts and `aead_per` AEAD attempts per
/// datagram — the direct, non-fakeable evidence of which candidates (active
/// / old-grace / sibling) are currently installed.
void expect_foreign_initial_work(SibPair& p, NcpMimicrySession& rx,
                                 uint64_t unwrap_per, uint64_t aead_per,
                                 int n = 8) {
    const auto s0 = snap(rx);
    const auto i0 = rx.stats().ingress_dropped;
    for (int i = 0; i < n; ++i)
        EXPECT_EQ(p.deliver(rx, p.craft_foreign_quic_initial(40)).kind,
                  NcpMimicrySession::IngressKind::Dropped);
    const auto s1 = snap(rx);
    EXPECT_EQ(s1.unwrap - s0.unwrap, unwrap_per * static_cast<uint64_t>(n))
        << "unexpected per-datagram mask-candidate work";
    EXPECT_EQ(s1.aead - s0.aead, aead_per * static_cast<uint64_t>(n))
        << "unexpected per-datagram AEAD work";
    EXPECT_EQ(rx.stats().ingress_dropped, i0 + static_cast<uint64_t>(n));
}

/// Send one real data datagram `from` -> `to` and require it to decode with
/// payload integrity.
void expect_data_decodes(SibPair& p, NcpMimicrySession& from,
                         NcpMimicrySession& to, uint32_t seq,
                         MaskShape expect_shape) {
    auto d = from.send_application(SibPair::app_payload(seq, 64), p.now);
    ASSERT_TRUE(d.has_value());
    EXPECT_FALSE(d->is_control);
    EXPECT_EQ(probe_shape(d->bytes), expect_shape);
    auto r = p.deliver(to, d->bytes);
    ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r.app_payload.has_value());
    EXPECT_EQ(*r.app_payload, SibPair::app_payload(seq, 64));
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// (a) Two revisions of the same QUIC descriptor id with different
//     content_hash retain the family-derived sibling set: a rev1 -> rev2
//     transition changes the bound hash (statistics/timing revision) but the
//     sibling set stays {QUIC_INITIAL, QUIC_SHORT_HEADER}, and QUIC_INITIAL
//     data keeps decoding via the sibling candidate on both endpoints.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySiblingBinding, SameFamilyRevisionTransitionRetainsSiblingSet) {
    ensure_init();
    SibPair p;
    p.init(kQuicId, 1);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->stats().transition_v2_capable);
    ASSERT_TRUE(p.cli->fsm_engaged());
    EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");

    // The two registered revisions: same id, same family, different
    // content_hash (statistics/timing-only revision).
    const auto* rev1 = p.catalog.find(kQuicId, 1);
    const auto* rev2 = p.catalog.find(kQuicId, 2);
    ASSERT_NE(rev1, nullptr);
    ASSERT_NE(rev2, nullptr);
    ASSERT_EQ(rev1->family, rev2->family);
    ASSERT_NE(rev1->content_hash, rev2->content_hash);
    ASSERT_EQ(p.cli->stats().active_profile,
              profile_ref_from_descriptor(*rev1));

    // Pre-transition baseline: the sibling candidate is installed — a
    // foreign Initial costs exactly 2 unwrap attempts (active QUIC_SHORT
    // fails its session-DCID check, sibling QUIC_INITIAL unwrap succeeds)
    // and exactly 1 AEAD attempt, on BOTH endpoints.
    expect_foreign_initial_work(p, *p.srv, 2, 1);
    expect_foreign_initial_work(p, *p.cli, 2, 1);

    // Real variant data (FSM state "bootstrap" -> QUIC_INITIAL on the wire)
    // decodes at the peer whose active mask is QUIC_SHORT_HEADER — i.e. via
    // the sibling candidate — in both directions.
    expect_data_decodes(p, *p.cli, *p.srv, 1, MaskShape::kQuicInitial);
    expect_data_decodes(p, *p.srv, *p.cli, 2, MaskShape::kQuicInitial);

    // rev1 -> rev2 transition of the SAME descriptor id (different
    // content_hash, same family).
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 2, p.now),
              TransitionError::NONE);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    p.advance(2000);  // past the 1000 ms grace window
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.cli->stats().profile_epoch, 1u);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);

    // The hash-bound identity moved to rev2 on BOTH endpoints...
    EXPECT_EQ(p.cli->stats().active_profile,
              profile_ref_from_descriptor(*rev2));
    EXPECT_EQ(p.srv->stats().active_profile,
              profile_ref_from_descriptor(*rev2));
    // ...but the family-derived sibling set did not change: active mask is
    // still QUIC_SHORT_HEADER, the FSM re-engaged at "bootstrap", and the
    // RX candidate work for a foreign Initial is exactly as before
    // (active + sibling, 2 unwraps + 1 AEAD). A timing/statistics revision
    // did NOT silently change the wire parsers.
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    EXPECT_EQ(p.srv->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    ASSERT_TRUE(p.cli->fsm_engaged());
    EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");
    EXPECT_STREQ(p.srv->fsm_state_name(), "bootstrap");
    expect_foreign_initial_work(p, *p.srv, 2, 1);
    expect_foreign_initial_work(p, *p.cli, 2, 1);

    // QUIC_INITIAL data still decodes via the sibling candidate after the
    // rev1 -> rev2 transition, in both directions, with payload integrity.
    const auto drop0_cli = p.cli->stats().ingress_dropped;
    const auto drop0_srv = p.srv->stats().ingress_dropped;
    expect_data_decodes(p, *p.cli, *p.srv, 10, MaskShape::kQuicInitial);
    expect_data_decodes(p, *p.srv, *p.cli, 11, MaskShape::kQuicInitial);
    EXPECT_EQ(p.cli->stats().ingress_dropped, drop0_cli);
    EXPECT_EQ(p.srv->stats().ingress_dropped, drop0_srv);
}

// ══════════════════════════════════════════════════════════════════════════════
// (b) `family` is covered by content_hash: mutating ONLY the family changes
//     the computed hash; a descriptor whose stored hash is stale (mutation
//     without re-hash) fails catalog validation; and a live session refuses
//     a transition PREPARE whose ProfileRef carries a stale hash (the exact
//     production gate: make_catalog_layout_resolver verifies
//     (id, revision, content_hash) before the transition manager enters
//     READY — nullopt resolution becomes ABORT(UNKNOWN_PROFILE)).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySiblingBinding, FamilyMutationChangesHashAndStaleHashRejected) {
    ensure_init();

    // ── Catalog-level: family is hash-covered; staleness is detectable ──
    auto quic = make_base_descriptor(kQuicId, 1, ProtocolFamily::QUIC);
    add_fsm_model(quic, "bootstrap");
    const std::string hash_quic = quic.content_hash;

    ProfileDescriptor mutated = quic;  // flip ONLY the family; do NOT re-hash
    mutated.family = ProtocolFamily::WEBRTC;
    const std::string hash_webrtc =
        ReferenceProfileCatalog::compute_content_hash(mutated);
    EXPECT_NE(hash_webrtc, hash_quic)
        << "family mutation must change the computed content_hash";
    ASSERT_EQ(mutated.content_hash, hash_quic);  // stored hash now stale
    {
        // The catalog's own validation detects the staleness: recomputed
        // hash != stored hash => hash_mismatch, and the EXTERNAL
        // registration path (the one arbitrary catalog data flows through)
        // refuses it. DEV_UNSIGNED policy isolates the rejection to the
        // hash binding (signature enforcement is not the refusing party).
        // (The trusted register_builtin path re-hashes by design — its
        // stored-hash gate is review time, not runtime.)
        ReferenceProfileCatalog::Options opts;
        opts.external_policy = SignaturePolicy::DEV_UNSIGNED;
        ReferenceProfileCatalog probe_catalog(opts);
        const auto issues = probe_catalog.validate_descriptor(mutated);
        bool saw_hash_mismatch = false;
        for (const auto& i : issues)
            if (i.code == "hash_mismatch") saw_hash_mismatch = true;
        EXPECT_TRUE(saw_hash_mismatch)
            << "stale content_hash after family mutation not detected";
        const auto stale_outcome = probe_catalog.register_profile(mutated);
        EXPECT_EQ(stale_outcome.status,
                  ReferenceProfileCatalog::RegisterStatus::REJECTED)
            << "external path accepted a descriptor with a stale hash";
        saw_hash_mismatch = false;
        for (const auto& i : stale_outcome.issues)
            if (i.code == "hash_mismatch") saw_hash_mismatch = true;
        EXPECT_TRUE(saw_hash_mismatch)
            << "rejection not attributable to the hash binding";

        // Positive control: the same family-mutated descriptor WITH a
        // refreshed hash is accepted — a family change is legitimate only
        // as a re-hashed, reviewed descriptor, never as silent mutation.
        ReferenceProfileCatalog::update_content_hash(mutated);
        EXPECT_TRUE(probe_catalog.register_profile(mutated).ok())
            << "freshly re-hashed descriptor refused";
    }

    // ── Session-level: a PREPARE carrying a stale hash is refused ───────
    SibPair p;
    p.init(kQuicId, 1);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);

    const auto* rev1 = p.catalog.find(kQuicId, 1);
    const auto* rev2 = p.catalog.find(kQuicId, 2);
    ASSERT_NE(rev1, nullptr);
    ASSERT_NE(rev2, nullptr);

    // Hostile/stale initiator: target rev2, but with rev1's content_hash
    // replayed (a hash that does not match the rev2 descriptor the wire
    // identity points at). Built via the explicit ProfileRef overload —
    // the same control path a peer-driven PREPARE takes at the responder.
    ProfileRef stale_ref = profile_ref_from_descriptor(*rev2);
    stale_ref.content_hash = profile_ref_from_descriptor(*rev1).content_hash;
    ASSERT_NE(stale_ref, profile_ref_from_descriptor(*rev2));
    ASSERT_EQ(p.cli->start_profile_transition(
                  stale_ref, profile_layout_from_descriptor(*rev2),
                  TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER, p.now),
              TransitionError::NONE);
    p.pump();  // PREPARE -> responder hash check fails -> ABORT -> rollback

    // The responder never installed the stale target and never committed;
    // the initiator rolled back cleanly. No state diverged.
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed, 0u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_started, 0u);
    EXPECT_FALSE(p.srv->stats().pending_profile.has_value());
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_aborted, 1u);
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().profile_epoch, 0u);
    EXPECT_EQ(p.cli->stats().active_profile, profile_ref_from_descriptor(*rev1));

    // Same session, same target revision, FRESH hash: accepted — the
    // refusal above was the hash binding, not the target. This also
    // demonstrates the reviewed path to a new revision: re-hashed
    // descriptor registered in the catalog.
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 2, p.now),
              TransitionError::NONE);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().active_profile, profile_ref_from_descriptor(*rev2));
    EXPECT_EQ(p.srv->stats().active_profile, profile_ref_from_descriptor(*rev2));

    // The session is undamaged: real variant data still decodes both ways.
    expect_data_decodes(p, *p.cli, *p.srv, 20, MaskShape::kQuicInitial);
    expect_data_decodes(p, *p.srv, *p.cli, 21, MaskShape::kQuicInitial);
}

// ══════════════════════════════════════════════════════════════════════════════
// (c) QUIC -> FSM-enabled WEBRTC transition deterministically swaps the
//     sibling set on BOTH endpoints. Before the transition a foreign
//     QUIC_INITIAL datagram costs {active QUIC_SHORT + sibling QUIC_INITIAL}
//     work (2 unwraps + 1 AEAD). During the post-activation grace window the
//     old QUIC_SHORT decoder is still installed (2 unwraps, 0 AEAD — neither
//     STUN active nor QUIC_SHORT old unwraps a foreign Initial). After grace
//     expiry the QUIC candidate set is gone entirely: exactly 1 unwrap
//     attempt (WEBRTC/STUN active; the WEBRTC sibling set {STUN_MESSAGE}
//     dedups against it) and 0 AEAD attempts.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySiblingBinding, FamilyTransitionSwapsSiblingSetOnBothEndpoints) {
    ensure_init();
    SibPair p;
    p.init(kQuicId, 1);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->stats().transition_v2_capable);
    ASSERT_EQ(p.cli->effective_transition_grace_ms(), 1000u);
    ASSERT_EQ(p.srv->effective_transition_grace_ms(), 1000u);

    // Pre-transition: sibling set {QUIC_INITIAL, QUIC_SHORT_HEADER} on both
    // endpoints (2 unwraps + 1 AEAD per foreign Initial).
    expect_foreign_initial_work(p, *p.srv, 2, 1);
    expect_foreign_initial_work(p, *p.cli, 2, 1);
    expect_data_decodes(p, *p.cli, *p.srv, 1, MaskShape::kQuicInitial);

    // Transition QUIC -> FSM-enabled WEBRTC descriptor.
    ASSERT_EQ(p.cli->start_profile_transition(kWebrtcId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::STUN_MESSAGE);
    EXPECT_EQ(p.srv->stats().active_mimic,
              TrafficMimicry::MimicProfile::STUN_MESSAGE);
    EXPECT_EQ(p.cli->stats().active_profile.id, kWebrtcId);
    EXPECT_EQ(p.srv->stats().active_profile.id, kWebrtcId);
    ASSERT_TRUE(p.cli->fsm_engaged());  // FSM-enabled target: variant family
    ASSERT_TRUE(p.srv->fsm_engaged());  // rebound on both endpoints

    // During grace (same `now`, activation just happened): candidates are
    // active STUN + old-grace QUIC_SHORT; the foreign Initial work is
    // already down to 2 unwraps and 0 AEAD (the QUIC_INITIAL sibling is
    // gone — the self-authenticating Initial unwrap no longer runs).
    expect_foreign_initial_work(p, *p.srv, 2, 0);
    expect_foreign_initial_work(p, *p.cli, 2, 0);

    // Past the grace deadline the old QUIC decoder is removed: foreign
    // QUIC_INITIAL candidate work drops to WEBRTC/STUN-only — exactly 1
    // unwrap attempt, 0 AEAD — deterministically on BOTH endpoints.
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    expect_foreign_initial_work(p, *p.srv, 1, 0);
    expect_foreign_initial_work(p, *p.cli, 1, 0);

    // Positive control: real data on the new family (STUN-shaped) decodes
    // in both directions after the sibling-set swap.
    const auto drop0_cli = p.cli->stats().ingress_dropped;
    const auto drop0_srv = p.srv->stats().ingress_dropped;
    expect_data_decodes(p, *p.cli, *p.srv, 30, MaskShape::kStun);
    expect_data_decodes(p, *p.srv, *p.cli, 31, MaskShape::kStun);
    EXPECT_EQ(p.cli->stats().ingress_dropped, drop0_cli);
    EXPECT_EQ(p.srv->stats().ingress_dropped, drop0_srv);
}
