// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_session_fsm.cpp
//
// Hermetic tests for the FSM shape/timing source integration in
// NcpMimicrySession: when the active session profile's catalog descriptor
// carries fsm.enabled, the per-session MimicryFsmSession is the data-shape
// source for adapter data packets (pacing via OutboundDatagram.pacing_delay);
// otherwise the catalog-derived MimicryShaper path is used unchanged.
//
// Evidence covered:
//   * FSM-enabled stable profile engages the FSM on both endpoints at
//     bring-up; pacing matches a parallel standalone MimicryFsmSession built
//     from the same descriptor + derivation (zero-jitter test descriptors
//     make the adapter-side derive_session() reconstructible from the
//     exposed fsm_seed())
//   * wire format is unchanged by FSM engagement (byte-exact size formula)
//   * control packets never consume FSM data shapes (shape sequence
//     unaffected); abort cancels the queued shape exactly like the shaper
//   * FSM->FSM transition rebuilds the FSM at the activation epoch boundary
//     (fresh deterministic sequence, no stale-epoch leakage)
//   * FSM->non-FSM->FSM transitions switch the shape source correctly
//   * non-FSM profile sessions behave exactly as before (shaper path, no
//     FSM objects engaged)
//
// Same harness style as tests/test_mimicry_session.cpp: real components,
// hermetic datagram queues, manual monotonic clock, no threads.
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

constexpr const char* kFsmAlphaId = "fsm.alpha";  // FSM, GENERIC_UDP outer
constexpr const char* kFsmBetaId  = "fsm.beta";   // FSM, GENERIC_TCP outer
constexpr const char* kPlainId    = "plain.udp";  // no FSM, GENERIC_UDP outer

/// Base descriptor: ZERO derivation bounds so the adapter-side
/// derive_session() output is exactly reconstructible in the test (stat ==
/// to_stat_profile(d), dwell scale 1, shifts 0) except for rng_seed, which
/// the adapter exposes via fsm_seed().
ProfileDescriptor make_base_descriptor(const char* id, ProtocolFamily fam,
                                       uint32_t padding_block) {
    ProfileDescriptor d;
    d.profile_id = id;
    d.revision = 1;
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
    d.padding_header.padding_block_bytes = padding_block;
    d.padding_header.padding_max_bytes = 64;
    d.padding_header.pad_to_block = padding_block > 0;

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1400;

    d.provenance.sample_count = 5000;
    d.provenance.window_count = 50;

    d.derivation = DerivationBounds{};  // zero jitter: exact reconstruction

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

void add_fsm_model(ProfileDescriptor& d) {
    d.fsm.enabled = true;
    d.fsm.initial_state = "bootstrap";
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

struct FsmCatalog {
    ReferenceProfileCatalog catalog;
    FsmCatalog() {
        auto a = make_base_descriptor(kFsmAlphaId, ProtocolFamily::GENERIC_UDP, 0);
        add_fsm_model(a);
        auto ra = catalog.register_builtin(a);
        EXPECT_TRUE(ra.ok()) << (ra.issues.empty() ? "" : ra.issues[0].message);

        auto b = make_base_descriptor(kFsmBetaId, ProtocolFamily::GENERIC_TCP, 16);
        add_fsm_model(b);
        auto rb = catalog.register_builtin(b);
        EXPECT_TRUE(rb.ok()) << (rb.issues.empty() ? "" : rb.issues[0].message);

        auto p = make_base_descriptor(kPlainId, ProtocolFamily::GENERIC_UDP, 0);
        auto rp = catalog.register_builtin(p);
        EXPECT_TRUE(rp.ok()) << (rp.issues.empty() ? "" : rp.issues[0].message);
    }
    const ProfileDescriptor* alpha() const { return catalog.find(kFsmAlphaId, 1); }
    const ProfileDescriptor* beta()  const { return catalog.find(kFsmBetaId, 1); }
    const ProfileDescriptor* plain() const { return catalog.find(kPlainId, 1); }
};

// ── Hermetic session pair (mirrors tests/test_mimicry_session.cpp) ──────────

struct FsmPair {
    FsmCatalog cat;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;  // manual monotonic ms

    std::vector<std::vector<uint8_t>> cli_app;
    std::vector<std::vector<uint8_t>> srv_app;

    void init(const char* stable_id) {
        const auto* desc = cat.catalog.find(stable_id, 1);
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;  // deterministic wire sizes
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.catalog = &cat.catalog;
        base.mimic_config.profile = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_resolver = [](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            if (r.id == kFsmAlphaId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            if (r.id == kFsmBetaId)
                return TrafficMimicry::MimicProfile::GENERIC_TCP;
            if (r.id == kPlainId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            return std::nullopt;
        };
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1000;
        base.path_mtu_bytes = 1500;
        base.porthop_overhead_bytes = 20;
        base.max_application_payload = 1024;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cli.reset(new NcpMimicrySession(cc));

        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
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

// ── Parallel (standalone) FSM mirror ────────────────────────────────────────

/// Reconstruct the exact DerivedProfile the adapter built internally (the
/// test descriptors carry zero derivation bounds, so only rng_seed comes
/// from the session secret) and build a standalone FSM from it, parked at
/// ESTABLISHED exactly like the adapter's bring-up rebind.
std::unique_ptr<MimicryFsmSession> make_parallel_fsm(const ProfileDescriptor& d,
                                                     uint64_t seed) {
    DerivedProfile dp;
    dp.profile_id = d.profile_id;
    dp.revision = d.revision;
    dp.rng_seed = seed;
    dp.stat = ReferenceProfileCatalog::to_stat_profile(d);
    dp.burst_scale = 1.0;
    dp.fsm_dwell_scale = 1.0;
    dp.header_gap_shift_bytes = 0;
    dp.padding_extra_bytes = 0;
    std::unique_ptr<MimicryFsmSession> f(new MimicryFsmSession(d, dp));
    while (f->phase() < MimicryFsmPhase::ESTABLISHED)
        if (!f->advance_phase()) break;
    return f;
}

void expect_shapes_equal(const MimicryFsmShape& a, const MimicryFsmShape& b) {
    EXPECT_EQ(a.payload_bytes, b.payload_bytes);
    EXPECT_EQ(a.padding_bytes, b.padding_bytes);
    EXPECT_EQ(a.total_bytes, b.total_bytes);
    EXPECT_EQ(a.delay_ms, b.delay_ms);
    EXPECT_EQ(a.state_epoch, b.state_epoch);
    EXPECT_EQ(a.profile_epoch, b.profile_epoch);
    EXPECT_EQ(a.state, b.state);
}

/// Mirror one adapter data send against the parallel FSM: the queued shape
/// must equal the parallel peek, the datagram pacing must equal the parallel
/// consumed shape delay, and the datagram must decode at the peer.
void expect_fsm_send(NcpMimicrySession& from, NcpMimicrySession& to,
                     MimicryFsmSession& par, FsmPair& p, uint32_t seq) {
    while (par.phase() < MimicryFsmPhase::DATA)
        if (!par.advance_phase()) break;

    MimicryFsmShape adapter_peek;
    ASSERT_TRUE(from.fsm_peek_prepared(adapter_peek));
    const MimicryFsmShape expect = par.prepare_data_shape();  // idempotent
    expect_shapes_equal(adapter_peek, expect);

    MimicryFsmShape taken;
    ASSERT_TRUE(par.take_data_shape(taken));

    auto o = from.send_application(FsmPair::app_payload(seq, 64), p.now);
    ASSERT_TRUE(o.has_value());
    EXPECT_FALSE(o->is_control);
    EXPECT_EQ(o->pacing_delay.count(),
              static_cast<long long>(taken.delay_ms));
    EXPECT_LE(o->bytes.size(), from.max_datagram_bytes());
    auto r = p.deliver(to, o->bytes);
    ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r.app_payload.has_value());
    EXPECT_EQ(*r.app_payload, FsmPair::app_payload(seq, 64));
}

// Inner PD framing + outer mask overhead (see tests/test_mimicry_session.cpp).
constexpr size_t kDataHeader = 2 + 1 + 4 + 2;
constexpr size_t kNcpTag = 4;

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return true;
    }();
    ASSERT_TRUE(once);
}

// ── Step 6: FSM-driven mask variants (design §3.4) ──────────────────────────
//
// Variant-capable test profiles. All are QUIC-family FSM descriptors whose
// initial state selects the per-datagram variant (the adapter parks the FSM
// at the model's initial state — it drives phases, not states):
//   fsm.quic.boot — initial "bootstrap"  → variant QUIC_INITIAL
//   fsm.quic.data — initial "data"       → variant QUIC_SHORT_HEADER
//   plain.stun    — no FSM, STUN_MESSAGE mask (transition target for the
//                   candidate-cap test)
constexpr const char* kQuicBootId  = "fsm.quic.boot";
constexpr const char* kQuicDataId  = "fsm.quic.data";
constexpr const char* kStunPlainId = "plain.stun";

ProfileDescriptor make_variant_descriptor(const char* id,
                                          const char* initial_state) {
    auto d = make_base_descriptor(id, ProtocolFamily::QUIC, 0);
    add_fsm_model(d);
    d.fsm.initial_state = initial_state;  // selects the TX variant
    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

/// Outer-mask shape probe over a complete adapter datagram (kind byte + body).
enum class MaskShape { kOther, kGenericUdp, kQuicInitial, kQuicShort, kStun };

MaskShape probe_shape(const std::vector<uint8_t>& d) {
    if (d.size() < 21 || d[0] != 'E') return MaskShape::kOther;
    const uint8_t* b = d.data() + 1;
    const size_t n = d.size() - 1;
    if (b[0] & 0x80) return MaskShape::kQuicInitial;       // long header 0xC0|x
    if ((b[0] & 0xC0) == 0x40) return MaskShape::kQuicShort;  // short 0x40|x
    if (n >= 8 && b[4] == 0x21 && b[5] == 0x12 && b[6] == 0xA4 &&
        b[7] == 0x42)
        return MaskShape::kStun;                           // RFC 5389 cookie
    return MaskShape::kGenericUdp;
}

struct VariantPair {
    ReferenceProfileCatalog catalog;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;  // manual monotonic ms

    std::vector<std::vector<uint8_t>> cli_app;
    std::vector<std::vector<uint8_t>> srv_app;
    /// Every control datagram observed leaving either endpoint (C1 probe).
    std::vector<std::vector<uint8_t>> control_tap;

    VariantPair() {
        auto a = make_variant_descriptor(kQuicBootId, "bootstrap");
        auto ra = catalog.register_builtin(a);
        EXPECT_TRUE(ra.ok()) << (ra.issues.empty() ? "" : ra.issues[0].message);
        auto b = make_variant_descriptor(kQuicDataId, "data");
        auto rb = catalog.register_builtin(b);
        EXPECT_TRUE(rb.ok()) << (rb.issues.empty() ? "" : rb.issues[0].message);
        auto s = make_base_descriptor(kStunPlainId, ProtocolFamily::STUN, 0);
        auto rs = catalog.register_builtin(s);
        EXPECT_TRUE(rs.ok()) << (rs.issues.empty() ? "" : rs.issues[0].message);
    }

    static std::optional<TrafficMimicry::MimicProfile> resolve_mimic(
        const ProfileRef& r) {
        using MP = TrafficMimicry::MimicProfile;
        if (r.id == kQuicBootId || r.id == kQuicDataId)
            return MP::QUIC_SHORT_HEADER;  // family base variant
        if (r.id == kStunPlainId) return MP::STUN_MESSAGE;
        return std::nullopt;
    }

    void init(const char* cli_stable, const char* srv_stable,
              bool cli_disable_variants = false,
              bool srv_disable_variants = false) {
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;  // deterministic wire sizes
        base.catalog = &catalog;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_resolver = &VariantPair::resolve_mimic;
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1000;
        base.path_mtu_bytes = 1500;
        base.porthop_overhead_bytes = 20;
        base.max_application_payload = 1024;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.stable_profile =
            profile_ref_from_descriptor(*catalog.find(cli_stable, 1));
        cc.stable_layout =
            profile_layout_from_descriptor(*catalog.find(cli_stable, 1));
        cc.stable_mimic = *resolve_mimic(cc.stable_profile);
        cc.mimic_config.profile = cc.stable_mimic;
        cc.disable_mask_variants = cli_disable_variants;
        cli.reset(new NcpMimicrySession(cc));

        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        sc.stable_profile =
            profile_ref_from_descriptor(*catalog.find(srv_stable, 1));
        sc.stable_layout =
            profile_layout_from_descriptor(*catalog.find(srv_stable, 1));
        sc.stable_mimic = *resolve_mimic(sc.stable_profile);
        sc.mimic_config.profile = sc.stable_mimic;
        sc.disable_mask_variants = srv_disable_variants;
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
                if (o->is_control) control_tap.push_back(o->bytes);
                deliver(*srv, o->bytes);
                progress = true;
            }
            while (auto o = srv->next_outbound()) {
                if (o->is_control) control_tap.push_back(o->bytes);
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
    /// used to craft hostile-but-well-formed QUIC_INITIAL datagrams: the
    /// QUIC_INITIAL mask is self-authenticating (key derived from the
    /// per-packet random DCID), so its unwrap SUCCEEDS at the mask layer and
    /// the datagram is then rejected by the real E2E AEAD — i.e. exactly one
    /// counted mask-layer success per crafted datagram.
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
};

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// FSM-enabled stable profile: the FSM is engaged at bring-up on both
// endpoints, drives data pacing exactly like a same-seed standalone
// MimicryFsmSession, and leaves the wire format byte-identical.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsm, EngagedFromBringUpAndMatchesParallelFsm) {
    ensure_init();
    FsmPair p;
    p.init(kFsmAlphaId);
    ASSERT_TRUE(p.established());

    // Engaged on both endpoints; shaper object still maintained underneath.
    ASSERT_TRUE(p.cli->fsm_engaged());
    ASSERT_TRUE(p.srv->fsm_engaged());
    EXPECT_TRUE(p.cli->shaper_engaged());
    EXPECT_TRUE(p.srv->shaper_engaged());

    // Lifecycle phase mapping: bring-up parks the FSM at ESTABLISHED.
    EXPECT_EQ(p.cli->fsm_phase(), MimicryFsmPhase::ESTABLISHED);
    EXPECT_EQ(p.srv->fsm_phase(), MimicryFsmPhase::ESTABLISHED);
    EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");
    EXPECT_EQ(p.cli->fsm_state_epoch(), 0u);

    // Stats surface the engagement.
    const auto cs = p.cli->stats();
    EXPECT_TRUE(cs.fsm_engaged);
    EXPECT_EQ(cs.fsm_phase, MimicryFsmPhase::ESTABLISHED);
    EXPECT_EQ(cs.fsm_state, "bootstrap");
    EXPECT_EQ(cs.fsm_state_epoch, 0u);
    EXPECT_EQ(cs.fsm_profile_epoch, 0u);
    EXPECT_EQ(cs.fsm_control_packets, 0u);

    // Both endpoints derived the identical FSM from the shared secret.
    const uint64_t seed = p.cli->fsm_seed();
    ASSERT_NE(seed, 0u);
    EXPECT_EQ(p.srv->fsm_seed(), seed);

    auto par_cli = make_parallel_fsm(*p.cat.alpha(), seed);
    auto par_srv = make_parallel_fsm(*p.cat.alpha(), seed);

    // Calibrate the constant E2E serialization overhead from the first
    // datagram (padding disabled, GENERIC_UDP outer, PD block 0): FSM
    // engagement must not change the wire format.
    size_t e2e_overhead = 0;
    {
        auto o = p.cli->send_application(FsmPair::app_payload(900, 64), p.now);
        ASSERT_TRUE(o.has_value());
        ASSERT_TRUE(p.deliver(*p.srv, o->bytes)
                        .app_payload.has_value());
        e2e_overhead = o->bytes.size() - (1 + 4 + kNcpTag + kDataHeader + 64);
        // Account for the calibration packet on the parallel sequence.
        MimicryFsmShape taken;
        while (par_cli->phase() < MimicryFsmPhase::DATA)
            if (!par_cli->advance_phase()) break;
        par_cli->prepare_data_shape();
        ASSERT_TRUE(par_cli->take_data_shape(taken));
        EXPECT_EQ(o->pacing_delay.count(),
                  static_cast<long long>(taken.delay_ms));
        EXPECT_EQ(p.cli->fsm_phase(), MimicryFsmPhase::DATA);
    }

    for (uint32_t i = 0; i < 6; ++i) {
        expect_fsm_send(*p.cli, *p.srv, *par_cli, p, 100 + i);
        // Wire format unchanged: byte-exact size formula of the shaper path.
        // (checked inside expect_fsm_send via budget; exact size below)
    }
    for (uint32_t i = 0; i < 4; ++i)
        expect_fsm_send(*p.srv, *p.cli, *par_srv, p, 200 + i);

    // Byte-exact wire size for the last send direction.
    {
        while (par_cli->phase() < MimicryFsmPhase::DATA)
            if (!par_cli->advance_phase()) break;
        par_cli->prepare_data_shape();
        MimicryFsmShape taken;
        ASSERT_TRUE(par_cli->take_data_shape(taken));
        auto o = p.cli->send_application(FsmPair::app_payload(300, 100), p.now);
        ASSERT_TRUE(o.has_value());
        EXPECT_EQ(o->bytes.size(),
                  1 + 4 + e2e_overhead + kNcpTag + kDataHeader + 100)
            << "FSM engagement changed the wire format";
        EXPECT_EQ(o->pacing_delay.count(),
                  static_cast<long long>(taken.delay_ms));
        ASSERT_TRUE(p.deliver(*p.srv, o->bytes).app_payload.has_value());
    }

    EXPECT_EQ(p.srv_app.size(), 8u);
    EXPECT_EQ(p.cli_app.size(), 4u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Control packets never consume FSM data shapes. Abort cancels the queued
// shape exactly like the shaper path; the sequence then continues
// deterministically.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsm, ControlPacketsNeverConsumeFsmShapes) {
    ensure_init();
    FsmPair p;
    p.init(kFsmAlphaId);
    ASSERT_TRUE(p.established());

    auto par_cli = make_parallel_fsm(*p.cat.alpha(), p.cli->fsm_seed());
    auto par_srv = make_parallel_fsm(*p.cat.alpha(), p.srv->fsm_seed());

    // Queue (without consuming) the next data shape on both endpoints.
    MimicryFsmShape cli_before, srv_before;
    ASSERT_TRUE(p.cli->fsm_peek_prepared(cli_before));
    ASSERT_TRUE(p.srv->fsm_peek_prepared(srv_before));
    expect_shapes_equal(cli_before, par_cli->prepare_data_shape());
    expect_shapes_equal(srv_before, par_srv->prepare_data_shape());

    // Start a transition: the PREPARE is control traffic on the FSM-engaged
    // profile. Deliver ONLY the PREPARE (the READY stays queued).
    ASSERT_EQ(p.cli->start_profile_transition(kFsmBetaId, 1, p.now),
              TransitionError::NONE);
    ASSERT_TRUE(p.cli->has_outbound());
    auto prep = p.cli->next_outbound();
    ASSERT_TRUE(prep.has_value());
    ASSERT_TRUE(prep->is_control);
    p.deliver(*p.srv, prep->bytes);
    ASSERT_TRUE(p.srv->has_outbound());  // READY queued (control)

    // Control accounting moved; the queued data shapes are untouched.
    EXPECT_GE(p.cli->stats().fsm_control_packets, 1u);
    EXPECT_GE(p.srv->stats().fsm_control_packets, 1u);
    MimicryFsmShape cli_after, srv_after;
    ASSERT_TRUE(p.cli->fsm_peek_prepared(cli_after));
    ASSERT_TRUE(p.srv->fsm_peek_prepared(srv_after));
    EXPECT_EQ(cli_after.payload_bytes, cli_before.payload_bytes);
    EXPECT_EQ(cli_after.padding_bytes, cli_before.padding_bytes);
    EXPECT_EQ(cli_after.total_bytes, cli_before.total_bytes);
    EXPECT_EQ(cli_after.delay_ms, cli_before.delay_ms);
    EXPECT_EQ(cli_after.state_epoch, cli_before.state_epoch);
    EXPECT_EQ(cli_after.profile_epoch, cli_before.profile_epoch);
    EXPECT_EQ(cli_after.state, cli_before.state)
        << "control packet consumed/disturbed the queued FSM data shape";
    expect_shapes_equal(srv_after, srv_before);

    // Pre-activation abort: cancels the queued shapes (mirrors the shaper
    // path) but the FSM stays engaged (no activation happened).
    ASSERT_TRUE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
    par_cli->cancel_prepared_shape();
    p.pump();  // ABORT (and the stale READY) both ways
    par_srv->cancel_prepared_shape();    // responder abort handler fired
    p.advance(2000);
    p.pump();

    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().profile_epoch, 0u);
    ASSERT_TRUE(p.cli->fsm_engaged());
    ASSERT_TRUE(p.srv->fsm_engaged());
    EXPECT_EQ(p.cli->fsm_seed(), par_cli->seed());

    // The sequence continues deterministically after the cancel.
    expect_fsm_send(*p.cli, *p.srv, *par_cli, p, 1);
    expect_fsm_send(*p.srv, *p.cli, *par_srv, p, 2);
    expect_fsm_send(*p.cli, *p.srv, *par_cli, p, 3);
}

// ══════════════════════════════════════════════════════════════════════════════
// FSM -> FSM transition: the activation epoch boundary rebuilds the FSM from
// the new profile's descriptor. The old FSM object is destroyed, so no
// stale-epoch shape can leak; shapes afterwards follow the new profile's
// deterministic sequence.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsm, TransitionFsmToFsmRebindsAtEpochBoundary) {
    ensure_init();
    FsmPair p;
    p.init(kFsmAlphaId);
    ASSERT_TRUE(p.established());

    const uint64_t seed_alpha = p.cli->fsm_seed();
    auto par_alpha = make_parallel_fsm(*p.cat.alpha(), seed_alpha);
    expect_fsm_send(*p.cli, *p.srv, *par_alpha, p, 1);
    expect_fsm_send(*p.cli, *p.srv, *par_alpha, p, 2);

    ASSERT_EQ(p.cli->start_profile_transition(kFsmBetaId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.cli->stats().profile_epoch, 1u);

    // Fresh FSM for the new profile on both endpoints: same (new) seed,
    // fresh epochs, parked at ESTABLISHED. The shaper was re-derived too
    // (existing behavior preserved underneath the FSM).
    ASSERT_TRUE(p.cli->fsm_engaged());
    ASSERT_TRUE(p.srv->fsm_engaged());
    const uint64_t seed_beta = p.cli->fsm_seed();
    EXPECT_NE(seed_beta, seed_alpha);
    EXPECT_EQ(p.srv->fsm_seed(), seed_beta);
    EXPECT_EQ(p.cli->fsm_state_epoch(), 0u);
    EXPECT_EQ(p.cli->stats().fsm_profile_epoch, 0u);
    EXPECT_EQ(p.cli->fsm_phase(), MimicryFsmPhase::ESTABLISHED);
    EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");
    EXPECT_STREQ(p.cli->shaper_profile_name(), kFsmBetaId);
    EXPECT_EQ(p.cli->shaper_epoch(), 1u);
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_TCP);

    // Shapes follow the NEW profile's FSM — a shape bound to the superseded
    // alpha FSM could never satisfy this byte/exact-delay equality.
    auto par_beta_cli = make_parallel_fsm(*p.cat.beta(), seed_beta);
    auto par_beta_srv = make_parallel_fsm(*p.cat.beta(), seed_beta);
    for (uint32_t i = 0; i < 4; ++i)
        expect_fsm_send(*p.cli, *p.srv, *par_beta_cli, p, 10 + i);
    for (uint32_t i = 0; i < 2; ++i)
        expect_fsm_send(*p.srv, *p.cli, *par_beta_srv, p, 20 + i);

    EXPECT_EQ(p.srv_app.size(), 6u);
    EXPECT_EQ(p.cli_app.size(), 2u);
}

// ══════════════════════════════════════════════════════════════════════════════
// FSM -> non-FSM -> FSM: the shape source switches to the shaper on commit
// to a profile without an FSM model, and back to a freshly derived FSM on
// the way back.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsm, TransitionFsmToNonFsmAndBack) {
    ensure_init();
    FsmPair p;
    p.init(kFsmAlphaId);
    ASSERT_TRUE(p.established());
    const uint64_t seed_alpha = p.cli->fsm_seed();

    // --- FSM -> non-FSM ---
    ASSERT_EQ(p.cli->start_profile_transition(kPlainId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.cli->stats().profile_epoch, 1u);
    ASSERT_EQ(p.cli->stats().active_profile.id, kPlainId);

    // FSM disengaged on both endpoints; the shaper path takes over.
    EXPECT_FALSE(p.cli->fsm_engaged());
    EXPECT_FALSE(p.srv->fsm_engaged());
    EXPECT_TRUE(p.cli->shaper_engaged());
    EXPECT_STREQ(p.cli->shaper_profile_name(), kPlainId);
    EXPECT_EQ(p.cli->shaper_epoch(), 1u);
    EXPECT_EQ(p.cli->fsm_phase(), MimicryFsmPhase::BOOTSTRAP);
    EXPECT_STREQ(p.cli->fsm_state_name(), "");
    EXPECT_EQ(p.cli->fsm_state_epoch(), 0u);
    EXPECT_EQ(p.cli->fsm_seed(), 0u);
    MimicryFsmShape dummy;
    EXPECT_FALSE(p.cli->fsm_peek_prepared(dummy));
    const auto ds = p.cli->stats();
    EXPECT_FALSE(ds.fsm_engaged);
    EXPECT_EQ(ds.fsm_state_epoch, 0u);
    EXPECT_TRUE(ds.fsm_state.empty());

    // Data flows via the shaper path (pacing reported, payload intact).
    bool any_pacing = false;
    for (uint32_t i = 0; i < 6; ++i) {
        auto o = p.cli->send_application(FsmPair::app_payload(i, 64), p.now);
        ASSERT_TRUE(o.has_value());
        EXPECT_FALSE(o->is_control);
        if (o->pacing_delay.count() > 0) any_pacing = true;
        ASSERT_TRUE(p.deliver(*p.srv, o->bytes).app_payload.has_value());
    }
    EXPECT_TRUE(any_pacing);
    EXPECT_EQ(p.srv_app.size(), 6u);

    // --- non-FSM -> FSM (back to alpha) ---
    ASSERT_EQ(p.cli->start_profile_transition(kFsmAlphaId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().profile_epoch, 2u);
    ASSERT_EQ(p.cli->stats().active_profile.id, kFsmAlphaId);

    // Re-engaged with the SAME deterministic derivation as the initial
    // bring-up (same descriptor + same session secret).
    ASSERT_TRUE(p.cli->fsm_engaged());
    ASSERT_TRUE(p.srv->fsm_engaged());
    EXPECT_EQ(p.cli->fsm_seed(), seed_alpha);
    EXPECT_EQ(p.srv->fsm_seed(), seed_alpha);
    EXPECT_STREQ(p.cli->shaper_profile_name(), kFsmAlphaId);
    EXPECT_EQ(p.cli->shaper_epoch(), 2u);

    auto par = make_parallel_fsm(*p.cat.alpha(), seed_alpha);
    for (uint32_t i = 0; i < 3; ++i)
        expect_fsm_send(*p.cli, *p.srv, *par, p, 100 + i);
}

// ══════════════════════════════════════════════════════════════════════════════
// Non-FSM profile session: no FSM object is ever engaged; behavior is the
// pre-existing shaper path.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsm, NonFsmProfileSessionKeepsShaperPath) {
    ensure_init();
    FsmPair p;
    p.init(kPlainId);
    ASSERT_TRUE(p.established());

    EXPECT_FALSE(p.cli->fsm_engaged());
    EXPECT_FALSE(p.srv->fsm_engaged());
    EXPECT_TRUE(p.cli->shaper_engaged());
    EXPECT_TRUE(p.srv->shaper_engaged());
    EXPECT_EQ(p.cli->fsm_seed(), 0u);
    EXPECT_STREQ(p.cli->fsm_state_name(), "");
    MimicryFsmShape dummy;
    EXPECT_FALSE(p.cli->fsm_peek_prepared(dummy));
    const auto s = p.cli->stats();
    EXPECT_FALSE(s.fsm_engaged);
    EXPECT_EQ(s.fsm_state_epoch, 0u);
    EXPECT_EQ(s.fsm_profile_epoch, 0u);
    EXPECT_EQ(s.fsm_phase, MimicryFsmPhase::BOOTSTRAP);
    EXPECT_TRUE(s.fsm_state.empty());
    EXPECT_EQ(s.fsm_control_packets, 0u);
    EXPECT_STREQ(p.cli->shaper_profile_name(), kPlainId);

    // Shaper pacing path unchanged: non-negative delays, delivery intact.
    bool any_pacing = false;
    for (uint32_t i = 0; i < 8; ++i) {
        auto o = p.cli->send_application(FsmPair::app_payload(i, 64), p.now);
        ASSERT_TRUE(o.has_value());
        EXPECT_GE(o->pacing_delay.count(), 0);
        if (o->pacing_delay.count() > 0) any_pacing = true;
        ASSERT_TRUE(p.deliver(*p.srv, o->bytes).app_payload.has_value());
    }
    EXPECT_TRUE(any_pacing);
    EXPECT_EQ(p.srv_app.size(), 8u);
    EXPECT_EQ(p.cli->stats().transition_counters.tx_data_stable, 8u);
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_stable, 8u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Step 6 (design §3.4): FSM-driven mask variants.
//
//   * per-datagram TX variant selection follows the engaged FSM state of the
//     active profile (bootstrap/handshake → QUIC_INITIAL, established/data →
//     QUIC_SHORT_HEADER for family QUIC); active_mimic itself only flips at
//     profile activation
//   * control datagrams are NEVER variant-wrapped (C1 pin intact)
//   * RX accepts the sibling variant as the 4th candidate — a pure function
//     of the hash-bound descriptor family, so endpoints whose independent
//     FSM instances sit in different states still decode each other (I-V2-5)
//   * the candidate evaluation stays bounded (cap 4) under hostile input
//   * Config::disable_mask_variants disables both the TX variant selection
//     and the RX sibling candidate
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsmVariants, VariantSelectionPerFsmStateAndControlPinning) {
    ensure_init();
    VariantPair p;
    p.init(kQuicBootId, kQuicBootId);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->stats().transition_v2_capable);
    ASSERT_TRUE(p.cli->fsm_engaged());
    EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");

    // Engaged state "bootstrap" → data datagrams take the QUIC_INITIAL
    // variant; the session mask state (active_mimic) is untouched.
    for (uint32_t i = 0; i < 3; ++i) {
        auto d = p.cli->send_application(FsmPair::app_payload(i, 64), p.now);
        ASSERT_TRUE(d.has_value());
        EXPECT_FALSE(d->is_control);
        EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicInitial)
            << "bootstrap-state data not variant-wrapped";
        EXPECT_LE(d->bytes.size(), p.cli->max_datagram_bytes());
        EXPECT_EQ(p.cli->stats().active_mimic,
                  TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER)
            << "variant selection flipped active_mimic outside a transition";
        // The peer's active mask is QUIC_SHORT_HEADER: the QUIC_INITIAL
        // datagram decodes via the sibling (4th) candidate.
        auto r = p.deliver(*p.srv, d->bytes);
        ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
        ASSERT_TRUE(r.app_payload.has_value());
        EXPECT_EQ(*r.app_payload, FsmPair::app_payload(i, 64));
    }
    {
        auto d = p.srv->send_application(FsmPair::app_payload(50, 64), p.now);
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicInitial);
        ASSERT_TRUE(p.deliver(*p.cli, d->bytes).app_payload.has_value());
    }

    // Transition to a profile whose engaged FSM state is "data": control
    // traffic of the whole transition stays pinned to the transition-stable
    // mask (QUIC_SHORT_HEADER) — never variant-wrapped.
    ASSERT_EQ(p.cli->start_profile_transition(kQuicDataId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.cli->stats().profile_epoch, 1u);
    ASSERT_FALSE(p.control_tap.empty());
    for (const auto& c : p.control_tap)
        EXPECT_EQ(probe_shape(c), MaskShape::kQuicShort)
            << "control datagram variant-wrapped (C1 violated)";

    // Engaged state "data" → QUIC_SHORT_HEADER variant (== active mask).
    ASSERT_TRUE(p.cli->fsm_engaged());
    EXPECT_STREQ(p.cli->fsm_state_name(), "data");
    EXPECT_STREQ(p.srv->fsm_state_name(), "data");
    auto d = p.cli->send_application(FsmPair::app_payload(90, 64), p.now);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicShort);
    ASSERT_TRUE(p.deliver(*p.srv, d->bytes).app_payload.has_value());
}

TEST(MimicrySessionFsmVariants, SiblingCandidateDecodeAcrossFsmStateSkew) {
    ensure_init();
    // Forced FSM-state skew between endpoints: same QUIC family, but the
    // client engages a model parked at "bootstrap" (TX variant QUIC_INITIAL)
    // while the server engages one parked at "data" (TX variant
    // QUIC_SHORT_HEADER). RX acceptance is family-derived only (I-V2-5), so
    // neither endpoint's own FSM state affects decode.
    VariantPair p;
    p.init(kQuicBootId /*cli*/, kQuicDataId /*srv*/);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");
    EXPECT_STREQ(p.srv->fsm_state_name(), "data");
    const auto drop0_cli = p.cli->stats().ingress_dropped;
    const auto drop0_srv = p.srv->stats().ingress_dropped;

    // cli (state bootstrap) → QUIC_INITIAL on the wire; srv (state data,
    // active QUIC_SHORT_HEADER) decodes via the sibling candidate.
    for (uint32_t i = 0; i < 4; ++i) {
        auto d = p.cli->send_application(FsmPair::app_payload(i, 64), p.now);
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicInitial);
        auto r = p.deliver(*p.srv, d->bytes);
        ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data)
            << "sibling candidate failed across FSM-state skew";
        EXPECT_EQ(*r.app_payload, FsmPair::app_payload(i, 64));
    }
    // srv (state data) → QUIC_SHORT_HEADER; cli (state bootstrap) decodes
    // via candidate 1 (active).
    for (uint32_t i = 0; i < 4; ++i) {
        auto d = p.srv->send_application(FsmPair::app_payload(100 + i, 64),
                                         p.now);
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicShort);
        auto r = p.deliver(*p.cli, d->bytes);
        ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
        EXPECT_EQ(*r.app_payload, FsmPair::app_payload(100 + i, 64));
    }
    EXPECT_EQ(p.srv->stats().ingress_dropped, drop0_srv);
    EXPECT_EQ(p.cli->stats().ingress_dropped, drop0_cli);
    EXPECT_EQ(p.srv_app.size(), 4u);
    EXPECT_EQ(p.cli_app.size(), 4u);
}

TEST(MimicrySessionFsmVariants, CandidateCapRespectedUnderHostileFlood) {
    ensure_init();
    VariantPair p;
    p.init(kQuicDataId, kQuicDataId);  // active QUIC_SHORT, sibling QUIC_INITIAL
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->fsm_engaged());

    auto garbage = [](size_t n) {
        std::vector<uint8_t> d(1 + n);
        d[0] = 'E';
        for (size_t i = 0; i < n; ++i)
            d[1 + i] = static_cast<uint8_t>((i * 131u + n * 17u + 5u) & 0xFF);
        return d;
    };

    // ── No transition outstanding: candidates = active + sibling ─────────
    // NOTE: MimicStats::packets_unwrapped counts unwrap ATTEMPTS (every
    // candidate tried), so the delta directly evidences how many candidates
    // were evaluated per datagram — the candidate-cap evidence.
    // Raw garbage: exactly 2 attempts per datagram (active QUIC_SHORT fails
    // its session-DCID check, sibling QUIC_INITIAL fails AEAD) — never more
    // than the installed candidate count, never above the hard cap of 4.
    {
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto i0 = p.srv->stats().ingress_dropped;
        for (int i = 0; i < 100; ++i)
            EXPECT_EQ(p.deliver(*p.srv, garbage(8 + (i % 180))).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        EXPECT_EQ(p.srv->stats().outer_stats.packets_unwrapped.load() - u0,
                  200u)
            << "expected exactly 2 candidate attempts per garbage datagram";
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 100);
    }
    // Well-formed foreign QUIC_INITIAL datagrams: the sibling candidate's
    // unwrap SUCCEEDS at the mask layer (self-authenticating Initial), then
    // the real E2E AEAD rejects — still exactly 2 attempts per datagram.
    {
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto i0 = p.srv->stats().ingress_dropped;
        for (int i = 0; i < 50; ++i)
            EXPECT_EQ(p.deliver(*p.srv, p.craft_foreign_quic_initial(40)).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        EXPECT_EQ(p.srv->stats().outer_stats.packets_unwrapped.load() - u0,
                  100u)
            << "expected exactly 2 candidate attempts per crafted Initial";
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 50);
    }

    // ── Transition outstanding: candidates = active + pending + sibling ──
    ASSERT_EQ(p.cli->start_profile_transition(kStunPlainId, 1, p.now),
              TransitionError::NONE);
    {
        auto prep = p.cli->next_outbound();
        ASSERT_TRUE(prep.has_value());
        ASSERT_TRUE(prep->is_control);
        p.deliver(*p.srv, prep->bytes);  // responder READY, pending installed
    }
    ASSERT_TRUE(p.srv->stats().pending_mimic.has_value());
    {
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto i0 = p.srv->stats().ingress_dropped;
        for (int i = 0; i < 50; ++i) {
            EXPECT_EQ(p.deliver(*p.srv, p.craft_foreign_quic_initial(40)).kind,
                      NcpMimicrySession::IngressKind::Dropped);
            EXPECT_EQ(p.deliver(*p.srv, garbage(64)).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        }
        // Exactly 3 attempts per datagram (active QUIC_SHORT + pending STUN
        // + sibling QUIC_INITIAL): the sibling joins the ordered candidate
        // list without exceeding it; the pending STUN candidate
        // (session-HMAC-bound) and the active QUIC_SHORT candidate
        // (session-DCID-bound) fail closed. The hard cap of 4 (§1.6/I-V2-3)
        // is structural — the fourth slot is the old-grace candidate, empty
        // pre-activation — and the flood never amplifies per-datagram work.
        EXPECT_EQ(p.srv->stats().outer_stats.packets_unwrapped.load() - u0,
                  300u);
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 100);
        // Hostile input never disturbed the transition state.
        EXPECT_EQ(p.srv->stats().transition_state,
                  ProfileTransitionState::READY);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed,
                  0u);
    }

    // The in-flight transition completes cleanly afterwards (no poisoning).
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::STUN_MESSAGE);
}

// ══════════════════════════════════════════════════════════════════════════════
// I-TXD-2: exact per-datagram candidate-work counters on the full 4-slot
// candidate list (active + pending + sibling; old-grace slot empty
// pre-activation). Unwrap AND AEAD attempts are accounted separately with
// exact deltas (a dead counter cannot fake a PASS), and the per-datagram
// maxima must respect the structural kMaxRxCandidates cap (= 4).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionFsmVariants, CandidateAttemptCountersBoundedAtCap) {
    ensure_init();
    VariantPair p;
    p.init(kQuicDataId, kQuicDataId);  // active QUIC_SHORT, sibling QUIC_INITIAL
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->fsm_engaged());

    auto snap = [](NcpMimicrySession& s) {
        const auto st = s.stats();
        return std::array<uint64_t, 4>{
            st.candidate_unwrap_attempts_total, st.candidate_aead_attempts_total,
            st.candidate_unwrap_attempts_max, st.candidate_aead_attempts_max};
    };

    // Fresh session: only 'H'/'C' datagrams so far, which never touch the
    // 'E' candidate path — all four counters must be exactly zero.
    {
        const auto s0 = snap(*p.srv);
        EXPECT_EQ(s0[0], 0u);
        EXPECT_EQ(s0[1], 0u);
        EXPECT_EQ(s0[2], 0u);
        EXPECT_EQ(s0[3], 0u);
    }

    auto garbage = [](size_t n) {
        std::vector<uint8_t> d(1 + n);
        d[0] = 'E';
        for (size_t i = 0; i < n; ++i)
            d[1 + i] = static_cast<uint8_t>((i * 131u + n * 17u + 5u) & 0xFF);
        return d;
    };

    // ── Phase A: raw garbage, no transition ─────────────────────────────
    // active QUIC_SHORT fails its session-DCID check, sibling QUIC_INITIAL
    // fails to parse: exactly 2 unwrap attempts and 0 AEAD attempts each.
    {
        const auto s0 = snap(*p.srv);
        for (int i = 0; i < 50; ++i)
            EXPECT_EQ(p.deliver(*p.srv, garbage(8 + (i % 180))).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        const auto s1 = snap(*p.srv);
        EXPECT_EQ(s1[0] - s0[0], 100u) << "unwrap attempts != 2/datagram";
        EXPECT_EQ(s1[1] - s0[1], 0u)
            << "mask-rejected garbage must never reach the AEAD layer";
        EXPECT_EQ(s1[2], 2u);
        EXPECT_EQ(s1[3], 0u);
    }

    // ── Phase B: crafted foreign QUIC_INITIAL, no transition ────────────
    // The self-authenticating sibling unwrap SUCCEEDS, then the real E2E
    // AEAD rejects: 2 unwraps + exactly 1 AEAD attempt per datagram.
    {
        const auto s0 = snap(*p.srv);
        for (int i = 0; i < 25; ++i)
            EXPECT_EQ(p.deliver(*p.srv, p.craft_foreign_quic_initial(40)).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        const auto s1 = snap(*p.srv);
        EXPECT_EQ(s1[0] - s0[0], 50u);
        EXPECT_EQ(s1[1] - s0[1], 25u) << "expected 1 AEAD attempt/datagram";
        EXPECT_EQ(s1[2], 2u);
        EXPECT_EQ(s1[3], 1u);
    }

    // ── Phase C: transition outstanding (active + pending + sibling) ────
    ASSERT_EQ(p.cli->start_profile_transition(kStunPlainId, 1, p.now),
              TransitionError::NONE);
    {
        auto prep = p.cli->next_outbound();
        ASSERT_TRUE(prep.has_value());
        p.deliver(*p.srv, prep->bytes);  // responder READY, pending installed
    }
    ASSERT_TRUE(p.srv->stats().pending_mimic.has_value());
    {
        const auto s0 = snap(*p.srv);
        for (int i = 0; i < 25; ++i) {
            EXPECT_EQ(p.deliver(*p.srv, p.craft_foreign_quic_initial(40)).kind,
                      NcpMimicrySession::IngressKind::Dropped);
            EXPECT_EQ(p.deliver(*p.srv, garbage(64)).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        }
        const auto s1 = snap(*p.srv);
        // 3 candidates per datagram; only the crafted Initials reach AEAD
        // (via the sibling candidate) — the session-HMAC-bound STUN pending
        // candidate and the session-DCID-bound QUIC_SHORT active candidate
        // fail closed at the mask layer.
        EXPECT_EQ(s1[0] - s0[0], 150u) << "unwrap attempts != 3/datagram";
        EXPECT_EQ(s1[1] - s0[1], 25u) << "AEAD attempts != 1/crafted datagram";
        EXPECT_EQ(s1[2], 3u);
        EXPECT_EQ(s1[3], 1u);
        // Hostile input never disturbed the transition state.
        EXPECT_EQ(p.srv->stats().transition_state,
                  ProfileTransitionState::READY);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed,
                  0u);
    }

    // Structural invariants over the whole run: the per-datagram maxima
    // respect the hard cap, and AEAD work never exceeds unwrap work.
    {
        const auto st = p.srv->stats();
        EXPECT_EQ(NcpMimicrySession::kMaxRxCandidates, 4u);
        EXPECT_LE(st.candidate_unwrap_attempts_max,
                  NcpMimicrySession::kMaxRxCandidates);
        EXPECT_LE(st.candidate_aead_attempts_max,
                  NcpMimicrySession::kMaxRxCandidates);
        EXPECT_LE(st.candidate_aead_attempts_max,
                  st.candidate_unwrap_attempts_max);
        EXPECT_LE(st.candidate_aead_attempts_total,
                  st.candidate_unwrap_attempts_total);
    }

    // The in-flight transition completes cleanly afterwards (no poisoning).
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::STUN_MESSAGE);
}

TEST(MimicrySessionFsmVariants, DisableMaskVariantsEscapeHatch) {
    ensure_init();

    // ── Both endpoints disabled: data always takes the active mask and the
    // sibling candidate is gone, even with an FSM-engaged variant family.
    {
        VariantPair p;
        p.init(kQuicBootId, kQuicBootId,
               /*cli_disable_variants=*/true, /*srv_disable_variants=*/true);
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->stats().transition_v2_capable);
        ASSERT_TRUE(p.cli->fsm_engaged());
        EXPECT_STREQ(p.cli->fsm_state_name(), "bootstrap");

        auto d = p.cli->send_application(FsmPair::app_payload(1, 64), p.now);
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicShort)
            << "disable_mask_variants did not pin TX to the active mask";
        ASSERT_TRUE(p.deliver(*p.srv, d->bytes).app_payload.has_value());

        // The sibling candidate is off too: a well-formed foreign Initial is
        // evaluated against the ACTIVE candidate ONLY (exactly one attempt),
        // then dropped.
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto i0 = p.srv->stats().ingress_dropped;
        EXPECT_EQ(p.deliver(*p.srv, p.craft_foreign_quic_initial(40)).kind,
                  NcpMimicrySession::IngressKind::Dropped);
        EXPECT_EQ(p.srv->stats().outer_stats.packets_unwrapped.load() - u0,
                  1u)
            << "sibling candidate evaluated despite disable_mask_variants";
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 1);
    }

    // ── Mixed config (sender variants on, receiver off): variant datagrams
    // are dropped by the disabled receiver; its own TX stays on the active
    // mask and decodes fine at the enabled peer.
    {
        VariantPair p;
        p.init(kQuicBootId, kQuicBootId,
               /*cli_disable_variants=*/false, /*srv_disable_variants=*/true);
        ASSERT_TRUE(p.established());

        auto d = p.cli->send_application(FsmPair::app_payload(1, 64), p.now);
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_shape(d->bytes), MaskShape::kQuicInitial);
        const auto i0 = p.srv->stats().ingress_dropped;
        EXPECT_EQ(p.deliver(*p.srv, d->bytes).kind,
                  NcpMimicrySession::IngressKind::Dropped)
            << "disabled receiver accepted a sibling variant";
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 1);

        auto d2 = p.srv->send_application(FsmPair::app_payload(2, 64), p.now);
        ASSERT_TRUE(d2.has_value());
        EXPECT_EQ(probe_shape(d2->bytes), MaskShape::kQuicShort);
        ASSERT_TRUE(p.deliver(*p.cli, d2->bytes).app_payload.has_value());
    }
}
