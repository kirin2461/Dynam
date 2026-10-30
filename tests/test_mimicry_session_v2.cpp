// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_session_v2.cpp
//
// Hermetic tests for transition protocol v2 in NcpMimicrySession — arbitrary
// outer-mask transition targets via the v2 mask schedule:
//
//   C1  control mask pin: every control datagram of an outstanding transition
//       (PREPARE/READY/COMMIT/CONFIRM/ABORT, all retransmissions, side-band
//       busy/unknown-profile ABORTs) is wrapped with the transition-stable
//       mask, never with the pending/active post-activation mask.
//   C2  data TX switches to the new mask at local activation (v1 timing).
//   C3  ordered RX candidates active → pending → old-grace (hard cap 4);
//       the pending candidate is installed no later than the peer's first
//       possible new-mask transmission (zero-gap).
//   C4  finalize drops old/pending candidates.
//
//   plus the gated lift of the GENERIC-only target gate (v2 negotiated iff
//   both peers advertise V1∧V2) and v1-negotiated byte-behavior regression.
//
// Real components, hermetic datagram queues (the pattern of
// tests/test_mimicry_session.cpp); a manual monotonic clock drives tick();
// grace_period_ms = 1500 leaves margin over the retransmit budget
// (6 × 50 ms) per the design's config guidance.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_mimicry_session.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <optional>
#include <string>
#include <vector>

using namespace ncp;

namespace {

// ── Test catalog ────────────────────────────────────────────────────────────

constexpr const char* kBaselineId = "generic.udp";   // GENERIC_UDP mask
constexpr const char* kUdpAltId   = "generic.udp.alt";  // GENERIC_UDP mask,
                                                        // different PD layout
constexpr const char* kTcpId      = "generic.tcp";   // GENERIC_TCP mask
constexpr const char* kQuicId     = "quic.short";    // QUIC_SHORT_HEADER mask
constexpr const char* kStunId     = "stun.msg";      // STUN_MESSAGE mask
constexpr int kTcpPadding = 24;  // deterministic GENERIC_TCP outer padding

ProfileDescriptor make_v2_descriptor(const char* id, ProtocolFamily fam,
                                     uint32_t padding_block) {
    ProfileDescriptor d;
    d.profile_id = id;
    d.revision = 1;
    d.family = fam;
    d.min_wire_version = 1;
    d.max_wire_version = 3;

    d.sizes.kind = SizeDistKind::NORMAL;
    d.sizes.mean = 700.0;
    d.sizes.stddev = 60.0;
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

    d.derivation.size_mean_rel_jitter = 0.10;
    d.derivation.iat_mean_rel_jitter = 0.10;
    d.derivation.burst_rel_jitter = 0.10;
    d.derivation.fsm_dwell_rel_jitter = 0.10;
    d.derivation.padding_extra_max_bytes = 16;
    d.derivation.header_gap_shift_max_bytes = 4;

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

struct V2Catalog {
    ReferenceProfileCatalog catalog;
    V2Catalog() {
        const ProfileDescriptor descs[] = {
            make_v2_descriptor(kBaselineId, ProtocolFamily::GENERIC_UDP, 0),
            make_v2_descriptor(kUdpAltId, ProtocolFamily::GENERIC_UDP, 16),
            make_v2_descriptor(kTcpId, ProtocolFamily::GENERIC_TCP, 16),
            make_v2_descriptor(kQuicId, ProtocolFamily::QUIC, 0),
            make_v2_descriptor(kStunId, ProtocolFamily::STUN, 0)};
        for (const auto& d : descs) {
            auto r = catalog.register_builtin(d);
            EXPECT_TRUE(r.ok()) << (r.issues.empty() ? "" : r.issues[0].message);
        }
    }
    const ProfileDescriptor* baseline() const {
        return catalog.find(kBaselineId, 1);
    }
};

using MimicProfile = TrafficMimicry::MimicProfile;
using Resolver = std::function<std::optional<MimicProfile>(const ProfileRef&)>;

// ── Outer-mask wire attribution probe ───────────────────────────────────────
//
// The masks used here are structurally unambiguous for datagrams of this
// size class (< 1500 B):
//   * QUIC_SHORT_HEADER: first byte has 0x80 clear and 0x40 set. A GENERIC
//     length prefix can never have 0x40 set in its top byte (that would be
//     a ≥ 1 GiB length), and a STUN type word (0x0001/0x0101) never does.
//   * STUN_MESSAGE: type + magic cookie at fixed offsets, exact length.
//   * GENERIC_UDP: 4-byte BE length prefix, exact (no trailing padding).
//   * GENERIC_TCP: same prefix + exactly kTcpPadding trailing pad bytes.
enum class OuterShape { kGenericUdp, kGenericTcp, kQuicShort, kStun, kOther };

OuterShape probe_outer(const std::vector<uint8_t>& d) {
    if (d.size() < 2 || d[0] != 'E') return OuterShape::kOther;
    if ((d[1] & 0x80) == 0 && (d[1] & 0x40) != 0) return OuterShape::kQuicShort;
    if (d.size() >= 21) {
        const uint16_t t = static_cast<uint16_t>((d[1] << 8) | d[2]);
        if ((t == 0x0001 || t == 0x0101) && d[5] == 0x21 && d[6] == 0x12 &&
            d[7] == 0xA4 && d[8] == 0x42) {
            return OuterShape::kStun;
        }
    }
    if (d.size() >= 5) {
        const uint32_t l = (static_cast<uint32_t>(d[1]) << 24) |
                           (static_cast<uint32_t>(d[2]) << 16) |
                           (static_cast<uint32_t>(d[3]) << 8) | d[4];
        if (5u + l == d.size()) return OuterShape::kGenericUdp;
        if (5u + l + static_cast<size_t>(kTcpPadding) == d.size())
            return OuterShape::kGenericTcp;
    }
    return OuterShape::kOther;
}

// ── Hermetic session pair ───────────────────────────────────────────────────

struct WireRecord {
    std::vector<uint8_t> bytes;
    bool is_control = false;
};

struct V2Pair {
    V2Catalog cat;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;  // manual monotonic ms

    std::vector<std::vector<uint8_t>> cli_app;
    std::vector<std::vector<uint8_t>> srv_app;
    std::vector<WireRecord> cli_wire;
    std::vector<WireRecord> srv_wire;

    static constexpr size_t kKeepQueueDefault = ~size_t(0);

    /// cli_v2/srv_v2 drive Config::advertise_profile_transition_v2 (v1 stays
    /// advertised unless cli_v1/srv_v1 say otherwise).
    /// default_transition_cfg=true keeps the ProfileTransitionConfig
    /// defaults (interval 200 ms x 5 attempts, grace 1000 ms) instead of
    /// the fast test tuning.
    /// srv_queue_packets/srv_queue_bytes override the server's I-DRAIN-8
    /// outbound-queue bounds when != kKeepQueueDefault.
    void init(bool cli_v2, bool srv_v2, bool cli_v1 = true,
              bool srv_v1 = true, Resolver cli_resolver = nullptr,
              Resolver srv_resolver = nullptr,
              bool default_transition_cfg = false,
              size_t srv_queue_packets = kKeepQueueDefault,
              size_t srv_queue_bytes = kKeepQueueDefault) {
        const auto* desc = cat.baseline();
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;  // deterministic wire sizes
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = MimicProfile::GENERIC_UDP;
        base.catalog = &cat.catalog;
        base.mimic_config.profile = MimicProfile::GENERIC_UDP;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_config.min_padding = kTcpPadding;
        base.mimic_config.max_padding = kTcpPadding;
        if (!default_transition_cfg) {
            base.transition_config.retransmit_interval_ms = 50;
            base.transition_config.max_retransmit_attempts = 6;
            base.transition_config.grace_period_ms = 1500;  // design guidance
        }
        base.path_mtu_bytes = 1500;
        base.porthop_overhead_bytes = 20;
        base.max_application_payload = 1024;

        const Resolver def_resolver = [](const ProfileRef& r)
            -> std::optional<MimicProfile> {
            if (r.id == kBaselineId) return MimicProfile::GENERIC_UDP;
            if (r.id == kUdpAltId) return MimicProfile::GENERIC_UDP;
            if (r.id == kTcpId) return MimicProfile::GENERIC_TCP;
            if (r.id == kQuicId) return MimicProfile::QUIC_SHORT_HEADER;
            if (r.id == kStunId) return MimicProfile::STUN_MESSAGE;
            return std::nullopt;
        };

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.advertise_profile_transition = cli_v1;
        cc.advertise_profile_transition_v2 = cli_v2;
        cc.mimic_resolver = cli_resolver ? cli_resolver : def_resolver;
        cli.reset(new NcpMimicrySession(cc));

        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        sc.advertise_profile_transition = srv_v1;
        sc.advertise_profile_transition_v2 = srv_v2;
        sc.mimic_resolver = srv_resolver ? srv_resolver : def_resolver;
        if (srv_queue_packets != kKeepQueueDefault)
            sc.max_outbound_queue_packets = srv_queue_packets;
        if (srv_queue_bytes != kKeepQueueDefault)
            sc.max_outbound_queue_bytes = srv_queue_bytes;
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

    /// Drain one endpoint's reaction queue into its wire record (no delivery).
    std::vector<NcpMimicrySession::OutboundDatagram> drain(
        NcpMimicrySession& s) {
        std::vector<NcpMimicrySession::OutboundDatagram> out;
        while (auto o = s.next_outbound()) {
            (&s == cli.get() ? cli_wire : srv_wire)
                .push_back({o->bytes, o->is_control});
            out.push_back(std::move(*o));
        }
        return out;
    }

    /// Drain + deliver until quiescent (no time passes).
    void pump() {
        for (int i = 0; i < 1000; ++i) {
            bool progress = false;
            for (auto& o : drain(*cli)) { deliver(*srv, o.bytes); progress = true; }
            for (auto& o : drain(*srv)) { deliver(*cli, o.bytes); progress = true; }
            if (!progress) break;
        }
    }

    bool established() {
        if (!cli->is_established()) {
            auto hs = cli->start_handshake();
            if (hs) {
                cli_wire.push_back({hs->bytes, false});
                deliver(*srv, hs->bytes);
            }
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

    std::optional<NcpMimicrySession::OutboundDatagram> send_cli(
        const std::vector<uint8_t>& p) {
        auto o = cli->send_application(p, now);
        if (o) cli_wire.push_back({o->bytes, o->is_control});
        return o;
    }
    std::optional<NcpMimicrySession::OutboundDatagram> send_srv(
        const std::vector<uint8_t>& p) {
        auto o = srv->send_application(p, now);
        if (o) srv_wire.push_back({o->bytes, o->is_control});
        return o;
    }
    bool send_cli_deliver(const std::vector<uint8_t>& p) {
        auto o = send_cli(p);
        if (!o) return false;
        auto r = deliver(*srv, o->bytes);
        return r.kind == NcpMimicrySession::IngressKind::Data &&
               r.app_payload && *r.app_payload == p;
    }
    bool send_srv_deliver(const std::vector<uint8_t>& p) {
        auto o = send_srv(p);
        if (!o) return false;
        auto r = deliver(*cli, o->bytes);
        return r.kind == NcpMimicrySession::IngressKind::Data &&
               r.app_payload && *r.app_payload == p;
    }

    /// C1 probe: every control datagram on the wire (both directions,
    /// including retransmissions and side-band ABORTs) must carry the
    /// transition-STABLE mask (GENERIC_UDP in these fixtures).
    void expect_all_control_stable_mask() const {
        for (const auto* w : {&cli_wire, &srv_wire})
            for (const auto& r : *w)
                if (r.is_control)
                    EXPECT_EQ(probe_outer(r.bytes), OuterShape::kGenericUdp)
                        << "control datagram not wrapped in the "
                           "transition-stable mask (C1 violation)";
    }
};

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return true;
    }();
    ASSERT_TRUE(once);
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Full v2 transition GENERIC_UDP → QUIC_SHORT_HEADER (non-length-prefixed,
// session-bound target): staged message flow with per-datagram mask
// attribution, zero-gap candidate coverage in both transient windows, and
// exact stream/counter evidence.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, FullTransitionGenericToQuicShortHeader) {
    ensure_init();
    V2Pair p;
    p.init(/*cli_v2=*/true, /*srv_v2=*/true);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->stats().transition_v2_capable);

    // Baseline epoch-0 traffic.
    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(2, 64)));

    const auto ig0_cli = p.cli->stats().ingress_dropped;
    const auto ig0_srv = p.srv->stats().ingress_dropped;

    // ── PREPARE [stable] c→s ─────────────────────────────────────────────
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::PREPARE);
    // Initiator installed the pending RX candidate at start success.
    ASSERT_TRUE(p.cli->stats().pending_mimic.has_value());
    EXPECT_EQ(*p.cli->stats().pending_mimic, MimicProfile::QUIC_SHORT_HEADER);

    auto prep = p.drain(*p.cli);
    ASSERT_EQ(prep.size(), 1u);
    ASSERT_TRUE(prep[0].is_control);
    EXPECT_EQ(probe_outer(prep[0].bytes), OuterShape::kGenericUdp)
        << "PREPARE not in the transition-stable mask";
    p.deliver(*p.srv, prep[0].bytes);

    // Responder accepted: READY queued; pending RX candidate installed at
    // PREPARE accept — before any initiator new-mask transmission (C3).
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::READY);
    ASSERT_TRUE(p.srv->stats().pending_mimic.has_value());
    EXPECT_EQ(*p.srv->stats().pending_mimic, MimicProfile::QUIC_SHORT_HEADER);

    // ── READY [stable] s→c; initiator activates ──────────────────────────
    auto rdy = p.drain(*p.srv);
    ASSERT_EQ(rdy.size(), 1u);
    ASSERT_TRUE(rdy[0].is_control);
    EXPECT_EQ(probe_outer(rdy[0].bytes), OuterShape::kGenericUdp);
    p.deliver(*p.cli, rdy[0].bytes);

    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::COMMIT);
    EXPECT_EQ(p.cli->stats().active_mimic, MimicProfile::QUIC_SHORT_HEADER);

    // C1: the initiator's COMMIT and CONFIRM are emitted AFTER its
    // synchronous mask switch — and must STILL be stable-mask wrapped.
    auto cc = p.drain(*p.cli);
    ASSERT_EQ(cc.size(), 2u);
    EXPECT_TRUE(cc[0].is_control);
    EXPECT_TRUE(cc[1].is_control);
    EXPECT_EQ(probe_outer(cc[0].bytes), OuterShape::kGenericUdp)
        << "COMMIT wrapped in the new mask (C1 violation)";
    EXPECT_EQ(probe_outer(cc[1].bytes), OuterShape::kGenericUdp)
        << "CONFIRM wrapped in the new mask (C1 violation)";

    // ── W1: early new-mask DATA c→s while the responder is in READY ──────
    // The pending mask candidate must unwrap + AEAD-authenticate it (zero
    // mask-layer gap); the inner PD fence rejects pending-epoch data before
    // COMMIT — unchanged v1 inner semantics, counted, never delivered.
    auto d1 = p.send_cli(V2Pair::app_payload(3, 64));
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(probe_outer(d1->bytes), OuterShape::kQuicShort);
    const auto early0 = p.srv->stats().transition_counters.rx_rejected_early_new;
    auto r1 = p.deliver(*p.srv, d1->bytes);
    EXPECT_EQ(r1.kind, NcpMimicrySession::IngressKind::Dropped);
    EXPECT_EQ(p.srv->stats().transition_counters.rx_rejected_early_new,
              early0 + 1)
        << "pending candidate did not decode the early new-mask datagram "
           "(a mask-layer miss would have left the inner fence unreached)";

    // ── COMMIT [stable] c→s; responder activates ─────────────────────────
    p.deliver(*p.srv, cc[0].bytes);
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::COMMIT);
    EXPECT_EQ(p.srv->stats().active_mimic, MimicProfile::QUIC_SHORT_HEADER);

    // ── W2: responder new-mask DATA s→c immediately after activation ─────
    auto d2 = p.send_srv(V2Pair::app_payload(4, 64));
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(probe_outer(d2->bytes), OuterShape::kQuicShort);
    auto r2 = p.deliver(*p.cli, d2->bytes);
    ASSERT_EQ(r2.kind, NcpMimicrySession::IngressKind::Data)
        << "W2 zero-gap failure: initiator did not decode new-mask data";
    ASSERT_TRUE(r2.app_payload.has_value());
    EXPECT_EQ(*r2.app_payload, V2Pair::app_payload(4, 64));

    // ── CONFIRM [stable] both ways ───────────────────────────────────────
    auto sc = p.drain(*p.srv);  // responder's CONFIRM (post-activation: C1 pin)
    ASSERT_GE(sc.size(), 1u);
    EXPECT_EQ(probe_outer(sc[0].bytes), OuterShape::kGenericUdp)
        << "responder CONFIRM wrapped in the new mask (C1 violation)";
    p.deliver(*p.cli, sc[0].bytes);
    p.deliver(*p.srv, cc[1].bytes);  // initiator's CONFIRM
    p.pump();

    // New-epoch data now flows both ways in the QUIC_SHORT_HEADER mask.
    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(5, 64)));
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(6, 64)));

    // ── finalize (C4) ────────────────────────────────────────────────────
    p.advance(2000);
    p.pump();
    const auto c = p.cli->stats();
    const auto s = p.srv->stats();
    EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(c.profile_epoch, 1u);
    EXPECT_EQ(s.profile_epoch, 1u);
    EXPECT_EQ(c.active_profile.id, kQuicId);
    EXPECT_EQ(s.active_profile.id, kQuicId);
    EXPECT_EQ(c.transition_counters.transitions_committed, 1u);
    EXPECT_EQ(s.transition_counters.transitions_committed, 1u);
    EXPECT_EQ(c.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(s.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(c.transition_counters.transitions_uncertain, 0u);
    EXPECT_EQ(s.transition_counters.transitions_uncertain, 0u);
    // C4: old and pending candidates are dropped at finalize.
    EXPECT_FALSE(c.pending_mimic.has_value());
    EXPECT_FALSE(s.pending_mimic.has_value());

    // No epoch-confusion and no unexplained drops: the only dropped ingress
    // is the deliberately staged early-new datagram.
    EXPECT_EQ(c.transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(s.transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(p.cli->stats().ingress_dropped, ig0_cli);
    EXPECT_EQ(p.srv->stats().ingress_dropped, ig0_srv + 1)
        << "drops beyond the staged early-new datagram";

    // Exact application streams both directions.
    const std::vector<std::vector<uint8_t>> expect_srv = {
        V2Pair::app_payload(1, 64), V2Pair::app_payload(5, 64)};
    const std::vector<std::vector<uint8_t>> expect_cli = {
        V2Pair::app_payload(2, 64), V2Pair::app_payload(4, 64),
        V2Pair::app_payload(6, 64)};
    EXPECT_EQ(p.srv_app, expect_srv);
    EXPECT_EQ(p.cli_app, expect_cli);

    // C1 over the whole run: every control datagram stable-mask wrapped.
    p.expect_all_control_stable_mask();

    // Post-finalize data keeps the new mask.
    auto d7 = p.send_cli(V2Pair::app_payload(7, 64));
    ASSERT_TRUE(d7.has_value());
    EXPECT_EQ(probe_outer(d7->bytes), OuterShape::kQuicShort);
}

// ══════════════════════════════════════════════════════════════════════════════
// C1 under retransmission: every retransmitted control datagram — PREPARE,
// READY, COMMIT, CONFIRM and the bounded DRAIN courtesy re-CONFIRM — keeps
// the transition-stable mask.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, ControlMaskPinnedThroughRetransmits) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);

    // Deliver PREPARE; hold the READY.
    {
        auto q = p.drain(*p.cli);
        ASSERT_EQ(q.size(), 1u);
        p.deliver(*p.srv, q[0].bytes);
        p.drain(*p.srv);  // READY (held/dropped)
    }
    // Retransmission ticks: cli re-sends PREPARE, srv re-sends READY.
    p.advance(120);
    auto cli_rt = p.drain(*p.cli);
    auto srv_rt = p.drain(*p.srv);
    EXPECT_GE(cli_rt.size(), 1u) << "no PREPARE retransmission";
    EXPECT_GE(srv_rt.size(), 1u) << "no READY retransmission";
    for (const auto& o : cli_rt) {
        EXPECT_TRUE(o.is_control);
        EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp)
            << "PREPARE retransmit not stable-mask wrapped";
    }
    for (const auto& o : srv_rt) {
        EXPECT_TRUE(o.is_control);
        EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp)
            << "READY retransmit not stable-mask wrapped";
    }

    // Deliver the freshest READY: initiator activates → COMMIT+CONFIRM.
    p.deliver(*p.cli, srv_rt.back().bytes);
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::COMMIT);
    auto cc = p.drain(*p.cli);
    ASSERT_GE(cc.size(), 2u);
    for (const auto& o : cc)
        EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp);

    // Hold COMMIT: the initiator retransmits it (post-activation, C1 pin).
    p.advance(120);
    auto commit_rt = p.drain(*p.cli);
    EXPECT_GE(commit_rt.size(), 1u) << "no COMMIT retransmission";
    for (const auto& o : commit_rt) {
        EXPECT_TRUE(o.is_control);
        EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp)
            << "post-activation COMMIT retransmit not stable-mask wrapped";
    }
    (void)p.drain(*p.srv);  // drop stale READY retransmissions (lost in flight)

    // Deliver COMMIT: responder activates and emits exactly one CONFIRM.
    p.deliver(*p.srv, cc[0].bytes);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::COMMIT);
    auto sc = p.drain(*p.srv);
    ASSERT_EQ(sc.size(), 1u);
    EXPECT_TRUE(sc[0].is_control);
    EXPECT_EQ(probe_outer(sc[0].bytes), OuterShape::kGenericUdp);

    // Responder retransmits CONFIRM (post-activation, C1 pin).
    p.advance(120);
    auto conf_rt = p.drain(*p.srv);
    EXPECT_GE(conf_rt.size(), 1u) << "no CONFIRM retransmission";
    for (const auto& o : conf_rt) {
        EXPECT_TRUE(o.is_control);
        EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp)
            << "post-activation CONFIRM retransmit not stable-mask wrapped";
    }

    // Deliver CONFIRM to the initiator → DRAIN; deliver the initiator's
    // CONFIRM to the responder → DRAIN. A duplicate COMMIT *retransmission*
    // (fresh effective counter — a stale replay is correctly rejected by
    // the effective-counter fence) then triggers the bounded DRAIN courtesy
    // re-CONFIRM — also stable-mask wrapped.
    p.deliver(*p.cli, sc[0].bytes);
    p.deliver(*p.srv, cc[1].bytes);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::DRAIN);
    p.deliver(*p.srv, commit_rt.back().bytes);  // fresh COMMIT retransmission
    auto courtesy = p.drain(*p.srv);
    EXPECT_GE(courtesy.size(), 1u) << "no DRAIN courtesy re-CONFIRM";
    for (const auto& o : courtesy) {
        EXPECT_TRUE(o.is_control);
        EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp)
            << "courtesy re-CONFIRM not stable-mask wrapped";
    }

    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_GT(p.cli->stats().transition_counters.control_retransmits, 0u);
    EXPECT_GT(p.srv->stats().transition_counters.control_retransmits, 0u);
    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// Side-band busy ABORTs (glare): both endpoints start a transition
// concurrently; the refusals are side-band control of the OUTSTANDING local
// transition and must keep its stable mask. Neither side may activate.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, SideBandBusyAbortPinned) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    ASSERT_EQ(p.srv->start_profile_transition(kStunId, 1, p.now),
              TransitionError::NONE);
    p.pump();  // cross PREPAREs + side-band ABORT(PEER_BUSY) both ways

    const auto c = p.cli->stats();
    const auto s = p.srv->stats();
    EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(c.transition_counters.transitions_committed, 0u);
    EXPECT_EQ(s.transition_counters.transitions_committed, 0u);
    EXPECT_EQ(c.transition_counters.transitions_effective, 0u);
    EXPECT_EQ(s.transition_counters.transitions_effective, 0u);
    EXPECT_EQ(c.profile_epoch, 0u);
    EXPECT_EQ(s.profile_epoch, 0u);
    EXPECT_EQ(c.active_mimic, MimicProfile::GENERIC_UDP);
    EXPECT_EQ(s.active_mimic, MimicProfile::GENERIC_UDP);
    // Pending candidates removed on rollback.
    EXPECT_FALSE(c.pending_mimic.has_value());
    EXPECT_FALSE(s.pending_mimic.has_value());

    // At least one side-band refusal actually flowed.
    const uint64_t ctl = c.transition_counters.control_rx +
                         s.transition_counters.control_rx;
    EXPECT_GE(ctl, 3u) << "expected cross PREPAREs plus busy ABORT(s)";
    p.expect_all_control_stable_mask();

    // The session is undamaged and immediately reusable.
    EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    EXPECT_TRUE(p.send_srv_deliver(V2Pair::app_payload(2, 64)));
}

// ══════════════════════════════════════════════════════════════════════════════
// Candidate order and bounded evaluation (I-V2-3): garbage floods cost a
// bounded, counted number of unwrap attempts per datagram; the pending
// candidate is tried strictly after the active one; no failed candidate
// mutates transition state (verify-then-commit).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, CandidateOrderAndGarbageBound) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    auto garbage = [](size_t n) {
        std::vector<uint8_t> d(1 + n);
        d[0] = 'E';
        for (size_t i = 0; i < n; ++i)
            d[1 + i] = static_cast<uint8_t>((i * 131u + n * 17u + 5u) & 0xFF);
        return d;
    };

    // ── no transition outstanding: exactly ONE candidate (active) ────────
    {
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto i0 = p.srv->stats().ingress_dropped;
        for (int i = 0; i < 100; ++i) {
            auto r = p.deliver(*p.srv, garbage(8 + (i % 180)));
            EXPECT_EQ(r.kind, NcpMimicrySession::IngressKind::Dropped);
        }
        const auto du = p.srv->stats().outer_stats.packets_unwrapped.load() - u0;
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 100);
        EXPECT_EQ(du, 100u) << "unwrap attempts without transition != 1/datagram";
        EXPECT_TRUE(p.srv_app.empty());
    }

    // ── transition outstanding: at most TWO candidates (active+pending) ──
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    {
        auto q = p.drain(*p.cli);
        ASSERT_EQ(q.size(), 1u);
        p.deliver(*p.srv, q[0].bytes);  // PREPARE; responder installs pending
    }
    ASSERT_TRUE(p.srv->stats().pending_mimic.has_value());
    {
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto i0 = p.srv->stats().ingress_dropped;
        for (int i = 0; i < 100; ++i) {
            auto r = p.deliver(*p.srv, garbage(8 + (i % 180)));
            EXPECT_EQ(r.kind, NcpMimicrySession::IngressKind::Dropped);
        }
        const auto du = p.srv->stats().outer_stats.packets_unwrapped.load() - u0;
        EXPECT_EQ(p.srv->stats().ingress_dropped, i0 + 100);
        EXPECT_LE(du, 200u) << "unwrap attempts exceeded active+pending cap";
        // Garbage never disturbed the transition state.
        EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::READY);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed, 0u);
        EXPECT_TRUE(p.srv_app.empty());
    }

    // ── candidate ORDER: active first, pending second ────────────────────
    // Deliver READY so the initiator activates and emits [N] data; the
    // responder (still READY) must decode it via candidate 2 (pending):
    // exactly 2 unwrap attempts — the structurally-passing generic active
    // unwrap fails E2E AEAD, then the pending mask authenticates at the
    // mask layer and the inner PD fence counts rx_rejected_early_new.
    {
        auto q = p.drain(*p.srv);
        ASSERT_EQ(q.size(), 1u);
        p.deliver(*p.cli, q[0].bytes);  // READY → cli activates
        auto cc = p.drain(*p.cli);      // COMMIT+CONFIRM, held for later
        ASSERT_GE(cc.size(), 2u);

        auto d = p.send_cli(V2Pair::app_payload(1, 64));
        ASSERT_TRUE(d.has_value());
        ASSERT_EQ(probe_outer(d->bytes), OuterShape::kQuicShort);
        const auto u0 = p.srv->stats().outer_stats.packets_unwrapped.load();
        const auto e0 = p.srv->stats().transition_counters.rx_rejected_early_new;
        auto r = p.deliver(*p.srv, d->bytes);
        EXPECT_EQ(r.kind, NcpMimicrySession::IngressKind::Dropped);
        const auto du = p.srv->stats().outer_stats.packets_unwrapped.load() - u0;
        EXPECT_EQ(du, 2u) << "expected active(false-positive) + pending unwraps";
        EXPECT_EQ(p.srv->stats().transition_counters.rx_rejected_early_new,
                  e0 + 1);
        // Responder state untouched by the early datagram.
        EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::READY);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed, 0u);

        // Deliver the held COMMIT+CONFIRM so the transition can complete.
        p.deliver(*p.srv, cc[0].bytes);
        p.deliver(*p.srv, cc[1].bytes);
    }

    // The transition still completes cleanly afterwards (no poisoning).
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// Abort paths under v2: pre-activation aborts (local before any emission;
// local with the peer engaged) roll back cleanly with stable-mask ABORTs and
// drop the pending candidate; post-activation abort is refused (v1 rule).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, AbortPreActivationLocalAndEngaged) {
    ensure_init();

    // ── local abort before any emission ──────────────────────────────────
    {
        V2Pair p;
        p.init(true, true);
        ASSERT_TRUE(p.established());
        ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
                  TransitionError::NONE);
        ASSERT_TRUE(p.cli->stats().pending_mimic.has_value());

        ASSERT_TRUE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
        EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
        EXPECT_FALSE(p.cli->stats().pending_mimic.has_value())
            << "pending candidate survived the abort";
        EXPECT_EQ(p.cli->stats().active_mimic, MimicProfile::GENERIC_UDP);
        EXPECT_EQ(p.cli->stats().profile_epoch, 0u);
        EXPECT_EQ(p.cli->stats().transition_counters.transitions_aborted, 1u);

        // The queue holds [PREPARE, ABORT]; both are stable-mask wrapped.
        // The peer only ever receives the ABORT (the PREPARE was lost in
        // flight): an ABORT for a transition it never saw leaves it in IDLE
        // with no transition started.
        auto q = p.drain(*p.cli);
        ASSERT_EQ(q.size(), 2u);
        for (const auto& o : q) {
            EXPECT_TRUE(o.is_control);
            EXPECT_EQ(probe_outer(o.bytes), OuterShape::kGenericUdp);
        }
        const auto s0 = p.srv->stats();
        p.deliver(*p.srv, q[1].bytes);  // ABORT only
        EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(p.srv->stats().profile_epoch, 0u);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_started,
                  s0.transition_counters.transitions_started);
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_committed,
                  s0.transition_counters.transitions_committed);

        EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    }

    // ── local abort with the peer engaged (responder installed pending) ──
    {
        V2Pair p;
        p.init(true, true);
        ASSERT_TRUE(p.established());
        ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
                  TransitionError::NONE);
        auto q = p.drain(*p.cli);
        ASSERT_EQ(q.size(), 1u);
        p.deliver(*p.srv, q[0].bytes);  // PREPARE accepted, READY queued
        ASSERT_TRUE(p.srv->stats().pending_mimic.has_value());

        ASSERT_TRUE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
        p.pump();  // ABORT [stable] → responder rollback; stale READY deduped
        p.advance(2000);
        p.pump();

        const auto c = p.cli->stats();
        const auto s = p.srv->stats();
        EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(c.profile_epoch, 0u);
        EXPECT_EQ(s.profile_epoch, 0u);
        EXPECT_EQ(c.active_mimic, MimicProfile::GENERIC_UDP);
        EXPECT_EQ(s.active_mimic, MimicProfile::GENERIC_UDP);
        EXPECT_FALSE(c.pending_mimic.has_value());
        EXPECT_FALSE(s.pending_mimic.has_value());
        EXPECT_EQ(c.transition_counters.transitions_aborted, 1u);
        EXPECT_EQ(s.transition_counters.transitions_aborted, 1u);
        EXPECT_EQ(c.transition_counters.transitions_committed, 0u);
        EXPECT_EQ(s.transition_counters.transitions_committed, 0u);
        p.expect_all_control_stable_mask();

        EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
        EXPECT_TRUE(p.send_srv_deliver(V2Pair::app_payload(2, 64)));
    }
}

TEST(MimicrySessionV2, AbortPostActivationRefused) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    {
        auto q = p.drain(*p.cli);
        p.deliver(*p.srv, q[0].bytes);         // PREPARE
        auto r = p.drain(*p.srv);
        p.deliver(*p.cli, r[0].bytes);         // READY → cli activates
    }
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::COMMIT);

    // Post-activation rollback is impossible (v1 semantics): refused, and
    // the refusal itself emits nothing (COMMIT+CONFIRM were already queued
    // by the activation and are held aside here).
    auto held = p.drain(*p.cli);
    ASSERT_GE(held.size(), 2u);
    EXPECT_FALSE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
    EXPECT_FALSE(p.cli->has_outbound())
        << "post-activation abort refusal emitted a datagram";

    // The in-flight transition completes normally.
    p.deliver(*p.srv, held[0].bytes);  // COMMIT
    p.deliver(*p.srv, held[1].bytes);  // CONFIRM
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().profile_epoch, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic, MimicProfile::QUIC_SHORT_HEADER);
    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// Grace window (C3 candidate 3 + C4): old-mask data decodes during grace via
// the old-mimic candidate; after finalize the old decoder is gone and the
// same datagram fails at the MASK layer (inner counters untouched).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, GraceExpiryDropsOldAndPendingCandidates) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    // Two old-mask (GENERIC_UDP, epoch 0) data datagrams held in flight.
    auto h1 = p.send_cli(V2Pair::app_payload(1, 64));
    auto h2 = p.send_cli(V2Pair::app_payload(2, 64));
    ASSERT_TRUE(h1.has_value());
    ASSERT_TRUE(h2.has_value());
    ASSERT_EQ(probe_outer(h1->bytes), OuterShape::kGenericUdp);

    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    p.pump();  // completes the handshake; grace window open (1500 ms)
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);

    // During grace: h1 unwraps via the old-mimic candidate and the inner
    // grace path accepts the old epoch.
    auto r1 = p.deliver(*p.srv, h1->bytes);
    ASSERT_EQ(r1.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r1.app_payload.has_value());
    EXPECT_EQ(*r1.app_payload, V2Pair::app_payload(1, 64));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_old_grace, 1u);

    // Finalize: grace deadline passes, both sides reach IDLE and drop the
    // old + pending candidates (C4).
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_FALSE(p.cli->stats().pending_mimic.has_value());
    EXPECT_FALSE(p.srv->stats().pending_mimic.has_value());

    // h2 now fails at the MASK layer: the QUIC_SHORT_HEADER candidate
    // rejects the generic form structurally, the old candidate is gone, and
    // the inner PD layer never sees it (rx_rejected_old_expired untouched).
    const auto inner0 = p.srv->stats().transition_counters;
    const auto ig0 = p.srv->stats().ingress_dropped;
    auto r2 = p.deliver(*p.srv, h2->bytes);
    EXPECT_EQ(r2.kind, NcpMimicrySession::IngressKind::Dropped);
    EXPECT_EQ(p.srv->stats().ingress_dropped, ig0 + 1);
    EXPECT_EQ(p.srv->stats().transition_counters.rx_rejected_old_expired,
              inner0.rx_rejected_old_expired)
        << "post-grace old-mask datagram reached the inner layer";

    // Stream intact: exactly {payload(1)} was delivered post-transition.
    ASSERT_EQ(p.srv_app.size(), 1u);
    EXPECT_EQ(p.srv_app[0], V2Pair::app_payload(1, 64));
    EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(3, 64)));
    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// Step 5 gate matrix: non-generic transition targets are allowed iff the
// session negotiated V1∧V2 on both sides. Every other combination keeps the
// exact v1 refusal paths — initiator-side INVALID_PROFILE with zero state
// change and zero traffic, or the responder resolver-gate refusal with
// ABORT(UNKNOWN_PROFILE).
// ══════════════════════════════════════════════════════════════════════════════

namespace {

void expect_zero_transition_footprint(V2Pair& p,
                                      const NcpMimicrySession::Stats& c0,
                                      const NcpMimicrySession::Stats& s0) {
    const auto c1 = p.cli->stats();
    const auto s1 = p.srv->stats();
    EXPECT_EQ(c1.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(s1.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(c1.profile_epoch, 0u);
    EXPECT_EQ(s1.profile_epoch, 0u);
    EXPECT_EQ(c1.active_mimic, MimicProfile::GENERIC_UDP);
    EXPECT_EQ(s1.active_mimic, MimicProfile::GENERIC_UDP);
    EXPECT_FALSE(c1.pending_mimic.has_value());
    EXPECT_FALSE(s1.pending_mimic.has_value());
    EXPECT_EQ(c1.transition_counters.transitions_started,
              c0.transition_counters.transitions_started);
    EXPECT_EQ(s1.transition_counters.control_rx,
              s0.transition_counters.control_rx)
        << "a refused transition emitted control traffic";
}

} // namespace

TEST(MimicrySessionV2, GateMatrix) {
    ensure_init();

    // (v2,v2) + QUIC target: allowed (positive control; full happy-path
    // evidence is FullTransitionGenericToQuicShortHeader).
    {
        V2Pair p;
        p.init(true, true);
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->stats().transition_v2_capable);
        ASSERT_TRUE(p.srv->stats().transition_v2_capable);
        EXPECT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
                  TransitionError::NONE);
        EXPECT_EQ(p.cli->stats().transition_state,
                  ProfileTransitionState::PREPARE);
        ASSERT_TRUE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST,
                                            p.now));
        p.pump();
    }

    // (v2,v1), (v1,v2), (v1,v1): non-generic target refused with
    // INVALID_PROFILE, zero state change, zero traffic — on BOTH overloads.
    for (auto cfg : {std::make_tuple(true, false),   // cli v2, srv v1-only
                     std::make_tuple(false, true),   // cli v1-only, srv v2
                     std::make_tuple(false, false)}) {
        V2Pair p;
        p.init(std::get<0>(cfg), std::get<1>(cfg));
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->transition_capable());
        ASSERT_TRUE(p.srv->transition_capable());
        ASSERT_FALSE(p.cli->stats().transition_v2_capable);
        ASSERT_FALSE(p.srv->stats().transition_v2_capable);

        const auto c0 = p.cli->stats();
        const auto s0 = p.srv->stats();

        // Catalog overload: resolver maps the target to QUIC_SHORT_HEADER.
        EXPECT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
                  TransitionError::INVALID_PROFILE);

        // Explicit overload with a non-generic mask.
        const auto* d = p.cat.catalog.find(kQuicId, 1);
        ASSERT_NE(d, nullptr);
        EXPECT_EQ(p.cli->start_profile_transition(
                      profile_ref_from_descriptor(*d),
                      profile_layout_from_descriptor(*d),
                      MimicProfile::QUIC_SHORT_HEADER, p.now),
                  TransitionError::INVALID_PROFILE);

        EXPECT_FALSE(p.cli->has_outbound());
        p.pump();
        expect_zero_transition_footprint(p, c0, s0);
        EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    }

    // Responder resolver-gate under v1: initiator resolves the target to a
    // GENERIC mask (emits PREPARE), the v1 responder resolves the same
    // target to QUIC_SHORT_HEADER → refusal ABORT(UNKNOWN_PROFILE) before
    // READY, initiator rolls back, no divergence.
    {
        V2Pair p;
        const Resolver cli_res = [](const ProfileRef& r)
            -> std::optional<MimicProfile> {
            if (r.id == kBaselineId) return MimicProfile::GENERIC_UDP;
            if (r.id == kQuicId) return MimicProfile::GENERIC_TCP;
            return std::nullopt;
        };
        const Resolver srv_res = [](const ProfileRef& r)
            -> std::optional<MimicProfile> {
            if (r.id == kBaselineId) return MimicProfile::GENERIC_UDP;
            if (r.id == kQuicId) return MimicProfile::QUIC_SHORT_HEADER;
            return std::nullopt;
        };
        p.init(/*cli_v2=*/false, /*srv_v2=*/false, true, true,
               cli_res, srv_res);
        ASSERT_TRUE(p.established());
        ASSERT_FALSE(p.cli->stats().transition_v2_capable);
        ASSERT_FALSE(p.srv->stats().transition_v2_capable);

        ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
                  TransitionError::NONE);
        p.pump();  // PREPARE → refusal ABORT → initiator rollback

        const auto c = p.cli->stats();
        const auto s = p.srv->stats();
        EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(s.transition_counters.transitions_aborted, 1u)
            << "the refusal was not a clean pre-activation abort";
        EXPECT_EQ(s.transition_counters.transitions_committed, 0u);
        EXPECT_EQ(c.transition_counters.transitions_committed, 0u);
        EXPECT_EQ(c.profile_epoch, 0u);
        EXPECT_EQ(s.profile_epoch, 0u);
        EXPECT_EQ(c.active_mimic, MimicProfile::GENERIC_UDP);
        EXPECT_EQ(s.active_mimic, MimicProfile::GENERIC_UDP);
        EXPECT_FALSE(s.pending_mimic.has_value());
        p.expect_all_control_stable_mask();
        EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
        EXPECT_TRUE(p.send_srv_deliver(V2Pair::app_payload(2, 64)));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// v1-negotiated sessions behave EXACTLY as before: the v1 mask schedule
// wraps post-activation control with the NEW mask (GENERIC_TCP + padding —
// observably NOT the transition-stable mask), and a generic target
// transition completes end to end.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, V1NegotiatedSessionUnchanged) {
    ensure_init();
    V2Pair p;
    p.init(/*cli_v2=*/false, /*srv_v2=*/false);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->transition_capable());
    ASSERT_FALSE(p.cli->stats().transition_v2_capable);
    ASSERT_FALSE(p.srv->stats().transition_v2_capable);

    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    ASSERT_EQ(p.cli->start_profile_transition(kTcpId, 1, p.now),
              TransitionError::NONE);

    // v1 mask schedule: pre-activation control is stable-mask wrapped...
    {
        auto q = p.drain(*p.cli);
        ASSERT_EQ(q.size(), 1u);
        EXPECT_EQ(probe_outer(q[0].bytes), OuterShape::kGenericUdp);
        p.deliver(*p.srv, q[0].bytes);
        auto r = p.drain(*p.srv);
        ASSERT_EQ(r.size(), 1u);
        EXPECT_EQ(probe_outer(r[0].bytes), OuterShape::kGenericUdp);
        p.deliver(*p.cli, r[0].bytes);  // READY → cli activates
    }
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::COMMIT);

    // ...but POST-activation control (COMMIT+CONFIRM) is wrapped with the
    // NEW mask under v1 — the behavior v2's C1 pin deliberately changes.
    {
        auto q = p.drain(*p.cli);
        ASSERT_GE(q.size(), 2u);
        EXPECT_EQ(probe_outer(q[0].bytes), OuterShape::kGenericTcp)
            << "v1 post-activation COMMIT not in the new mask — "
               "v1 wire behavior changed";
        EXPECT_EQ(probe_outer(q[1].bytes), OuterShape::kGenericTcp)
            << "v1 post-activation CONFIRM not in the new mask";
        for (auto& o : q) p.deliver(*p.srv, o.bytes);
    }
    p.pump();
    p.advance(2000);
    p.pump();

    const auto c = p.cli->stats();
    const auto s = p.srv->stats();
    EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(c.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(s.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(c.profile_epoch, 1u);
    EXPECT_EQ(c.active_mimic, MimicProfile::GENERIC_TCP);
    EXPECT_EQ(s.active_mimic, MimicProfile::GENERIC_TCP);
    EXPECT_TRUE(p.send_cli_deliver(V2Pair::app_payload(2, 64)));
    EXPECT_TRUE(p.send_srv_deliver(V2Pair::app_payload(3, 64)));
}

// ══════════════════════════════════════════════════════════════════════════════
// Second arbitrary target: GENERIC_UDP → STUN_MESSAGE. Control stays pinned
// to the stable mask; data datagrams are RFC 5389-shaped on the wire.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, FullTransitionGenericToStunMessage) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);

    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    ASSERT_EQ(p.cli->start_profile_transition(kStunId, 1, p.now),
              TransitionError::NONE);
    p.pump();

    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic, MimicProfile::STUN_MESSAGE);
    EXPECT_EQ(p.srv->stats().active_mimic, MimicProfile::STUN_MESSAGE);

    // Data in the STUN mask both ways; RFC 5389 wire shape verified.
    for (int i = 0; i < 3; ++i) {
        auto d = p.send_cli(V2Pair::app_payload(10 + i, 64));
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_outer(d->bytes), OuterShape::kStun);
        EXPECT_EQ((d->bytes.size() - 1) % 4, 0u)
            << "STUN message (after the kind byte) not 4-aligned";
        auto r = p.deliver(*p.srv, d->bytes);
        ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
        EXPECT_EQ(*r.app_payload, V2Pair::app_payload(10 + i, 64));
    }
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(20, 64)));

    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(p.srv->stats().transition_counters.rx_rejected_unknown_epoch, 0u);

    // The application stream is exact.
    const std::vector<std::vector<uint8_t>> expect_srv = {
        V2Pair::app_payload(1, 64), V2Pair::app_payload(10, 64),
        V2Pair::app_payload(11, 64), V2Pair::app_payload(12, 64)};
    EXPECT_EQ(p.srv_app, expect_srv);

    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// MEDIUM-2: under v2 the effective transition grace is clamped to at least
// the retransmit budget (interval x attempts) plus a 2x-interval margin —
// post-activation control retransmits decode only via the old-grace
// candidate under C1, so grace must outlive the full retransmit schedule
// (defaults would otherwise end grace exactly at budget exhaustion, with
// zero RTT margin). v1 sessions keep the configured grace exactly; a
// configured grace above the floor is kept (floor, not a cap).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, GraceFloorClampedToRetransmitBudgetUnderV2) {
    ensure_init();

    // Default ProfileTransitionConfig: interval 200 ms, attempts 5,
    // grace 1000 ms → budget 1000 ms, margin 2 x 200 ms → floor 1400 ms.
    {
        V2Pair p;
        p.init(true, true, true, true, nullptr, nullptr,
               /*default_transition_cfg=*/true);
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->stats().transition_v2_capable);
        ASSERT_TRUE(p.srv->stats().transition_v2_capable);

        const uint32_t budget = 200u * 5u;   // interval x attempts
        const uint32_t margin = 2u * 200u;   // 2 x interval
        ASSERT_EQ(budget, 1000u);            // == default grace: the gap
        EXPECT_EQ(p.cli->effective_transition_grace_ms(), budget + margin);
        EXPECT_EQ(p.srv->effective_transition_grace_ms(), budget + margin);
    }

    // A configured grace ABOVE the floor is kept unchanged (floor, not cap):
    // the standard fixture (interval 50 ms, attempts 6, grace 1500 ms) has
    // floor 50*6 + 2*50 = 400 ms < 1500 ms.
    {
        V2Pair p;
        p.init(true, true);
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->stats().transition_v2_capable);
        EXPECT_EQ(p.cli->effective_transition_grace_ms(), 1500u);
        EXPECT_EQ(p.srv->effective_transition_grace_ms(), 1500u);
    }
}

TEST(MimicrySessionV2, GraceExactlyConfiguredUnderV1) {
    ensure_init();
    V2Pair p;
    p.init(/*cli_v2=*/false, /*srv_v2=*/false, true, true, nullptr, nullptr,
           /*default_transition_cfg=*/true);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->transition_capable());
    ASSERT_FALSE(p.cli->stats().transition_v2_capable);
    ASSERT_FALSE(p.srv->stats().transition_v2_capable);

    // No clamp under v1: the configured default grace applies exactly.
    EXPECT_EQ(p.cli->effective_transition_grace_ms(), 1000u);
    EXPECT_EQ(p.srv->effective_transition_grace_ms(), 1000u);
}

// ══════════════════════════════════════════════════════════════════════════════
// LOW-3: v2-negotiated transition to a GENERIC target
// (GENERIC_UDP → GENERIC_TCP): completes cleanly, control stays pinned to
// the transition-stable mask (C1), data switches to the new mask, no
// regression vs the v1 path.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, FullTransitionGenericToGenericTcpUnderV2) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->stats().transition_v2_capable);
    ASSERT_TRUE(p.srv->stats().transition_v2_capable);

    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(1, 64)));
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(2, 64)));

    ASSERT_EQ(p.cli->start_profile_transition(kTcpId, 1, p.now),
              TransitionError::NONE);
    ASSERT_TRUE(p.cli->stats().pending_mimic.has_value());
    EXPECT_EQ(*p.cli->stats().pending_mimic, MimicProfile::GENERIC_TCP);

    p.pump();  // PREPARE/READY/COMMIT/CONFIRM — all pinned to GENERIC_UDP

    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic, MimicProfile::GENERIC_TCP);
    EXPECT_EQ(p.srv->stats().active_mimic, MimicProfile::GENERIC_TCP);

    // C1: every control datagram of the transition carried the
    // transition-stable GENERIC_UDP mask, never the pending/new one.
    p.expect_all_control_stable_mask();

    // Data switches to the new mask (GENERIC_TCP: length prefix + exactly
    // kTcpPadding trailing pad bytes).
    for (int i = 0; i < 3; ++i) {
        auto d = p.send_cli(V2Pair::app_payload(10 + i, 64));
        ASSERT_TRUE(d.has_value());
        EXPECT_EQ(probe_outer(d->bytes), OuterShape::kGenericTcp);
        auto r = p.deliver(*p.srv, d->bytes);
        ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
        ASSERT_TRUE(r.app_payload.has_value());
        EXPECT_EQ(*r.app_payload, V2Pair::app_payload(10 + i, 64));
    }
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(20, 64)));

    // Finalize (C4): grace deadline passes, candidates dropped.
    p.advance(2000);
    p.pump();
    const auto c = p.cli->stats();
    const auto s = p.srv->stats();
    EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(c.profile_epoch, 1u);
    EXPECT_EQ(s.profile_epoch, 1u);
    EXPECT_EQ(c.active_profile.id, kTcpId);
    EXPECT_EQ(s.active_profile.id, kTcpId);
    EXPECT_EQ(c.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(s.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(c.transition_counters.transitions_uncertain, 0u);
    EXPECT_EQ(s.transition_counters.transitions_uncertain, 0u);
    EXPECT_FALSE(c.pending_mimic.has_value());
    EXPECT_FALSE(s.pending_mimic.has_value());
    EXPECT_EQ(c.transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(s.transition_counters.rx_rejected_unknown_epoch, 0u);

    // Exact application streams both directions.
    const std::vector<std::vector<uint8_t>> expect_srv = {
        V2Pair::app_payload(1, 64), V2Pair::app_payload(10, 64),
        V2Pair::app_payload(11, 64), V2Pair::app_payload(12, 64)};
    const std::vector<std::vector<uint8_t>> expect_cli = {
        V2Pair::app_payload(2, 64), V2Pair::app_payload(20, 64)};
    EXPECT_EQ(p.srv_app, expect_srv);
    EXPECT_EQ(p.cli_app, expect_cli);

    // The session keeps working on the new mask after finalize.
    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(30, 64)));
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(31, 64)));
    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// I-DRAIN-8: structural outbound-queue bounds. A control-reaction flood
// (READY retransmissions + final ABORT) against a server whose queue is
// NEVER drained must stop at the packet bound; refusals are counted with
// their byte sizes; nothing already queued is evicted.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, OutboundQueuePacketBoundFloodNoDrain) {
    ensure_init();

    // Manual bring-up under full control of the server's queue.
    auto bring_up = [](V2Pair& p) {
        auto hs = p.cli->start_handshake();
        ASSERT_TRUE(hs.has_value());
        p.deliver(*p.srv, hs->bytes);  // srv queues handshake response + caps
        for (auto& o : p.drain(*p.srv)) p.deliver(*p.cli, o.bytes);
        for (auto& o : p.drain(*p.cli)) p.deliver(*p.srv, o.bytes);
        ASSERT_TRUE(p.cli->is_established());
        ASSERT_TRUE(p.srv->is_established());
        ASSERT_EQ(p.srv->stats().outbound_queue_packets, 0u);
        ASSERT_EQ(p.srv->stats().queue_dropped_packets, 0u);
    };

    // Flood driver: start a transition, deliver only the first PREPARE,
    // then let the server's own READY retransmit schedule run for the full
    // retransmit budget WITHOUT draining the server. The server produces
    // exactly 6 READYs (initial + 5 retransmits at 50 ms) and then 1
    // final ABORT at timeout — 7 bounded enqueue attempts in total.
    auto flood_no_drain = [](V2Pair& p) {
        ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
                  TransitionError::NONE);
        for (auto& o : p.drain(*p.cli)) p.deliver(*p.srv, o.bytes);  // PREPARE
        for (int i = 0; i < 6; ++i) {  // +50..+300 ms: full budget + timeout
            p.advance(50);
            (void)p.drain(*p.cli);  // client retransmits/ABORT: not delivered
        }
    };

    // ── bounded server: 7 attempts against a 4-packet cap ───────────────
    {
        V2Pair p;
        p.init(true, true, true, true, nullptr, nullptr, false,
               /*srv_queue_packets=*/4);
        bring_up(p);
        flood_no_drain(p);

        const auto st = p.srv->stats();
        EXPECT_EQ(st.outbound_queue_packets, 4u)
            << "queue must stop exactly at the packet bound";
        EXPECT_EQ(st.queue_dropped_packets, 3u)
            << "7 enqueue attempts - 4 queued = 3 refused";
        EXPECT_GT(st.queue_dropped_bytes, 0u);
        EXPECT_LE(st.outbound_queue_packets,
                  4u);  // the bound is never exceeded, even transiently

        // Byte accounting is in lockstep with the queued datagrams.
        const uint64_t queued_bytes = st.outbound_queue_bytes;
        uint64_t drained_bytes = 0;
        size_t drained_packets = 0;
        for (auto& o : p.drain(*p.srv)) {
            drained_bytes += o.bytes.size();
            ++drained_packets;
        }
        EXPECT_EQ(drained_packets, 4u);
        EXPECT_EQ(drained_bytes, queued_bytes);
        const auto after = p.srv->stats();
        EXPECT_EQ(after.outbound_queue_packets, 0u);
        EXPECT_EQ(after.outbound_queue_bytes, 0u);
    }

    // ── control run (default bounds): identical flood, NOTHING dropped ──
    // Proves the flood really produces 7 enqueue attempts, so the 3 drops
    // above are the bound at work — not a flood that never reached the cap.
    {
        V2Pair p;
        p.init(true, true);
        bring_up(p);
        flood_no_drain(p);

        const auto st = p.srv->stats();
        EXPECT_EQ(st.queue_dropped_packets, 0u);
        EXPECT_EQ(st.queue_dropped_bytes, 0u);
        EXPECT_EQ(st.outbound_queue_packets, 7u)
            << "control run must queue all 6 READYs + final ABORT";
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// I-DRAIN-8 (byte bound): a datagram larger than the remaining byte budget
// is never queued; with a 1-byte budget every reaction is refused and
// counted, and the queue stays empty.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, OutboundQueueByteBoundRefusesAndCounts) {
    ensure_init();
    V2Pair p;
    p.init(true, true, true, true, nullptr, nullptr, false,
           V2Pair::kKeepQueueDefault, /*srv_queue_bytes=*/1);

    auto hs = p.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    p.deliver(*p.srv, hs->bytes);  // hs response + caps: both exceed 1 byte

    const auto st = p.srv->stats();
    EXPECT_EQ(st.outbound_queue_packets, 0u);
    EXPECT_EQ(st.outbound_queue_bytes, 0u);
    EXPECT_EQ(st.queue_dropped_packets, 2u)
        << "handshake response and capability advertisement must be refused";
    // Refused bytes equal the two datagrams' wire sizes; both are
    // fixed-size E2E blobs well above 1 byte.
    EXPECT_GT(st.queue_dropped_bytes, 2u);
}

// ══════════════════════════════════════════════════════════════════════════════
// I-DRAIN-8 (exact-fill boundary): the packet bound is inclusive — exactly
// `max_outbound_queue_packets` datagrams are queued, the NEXT one is the
// first refusal.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, OutboundQueueExactFillBoundary) {
    ensure_init();
    V2Pair p;
    p.init(true, true, true, true, nullptr, nullptr, false,
           /*srv_queue_packets=*/2);

    // Handshake response + caps exactly fill the 2-slot queue: no drops.
    auto hs = p.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    p.deliver(*p.srv, hs->bytes);
    {
        const auto st = p.srv->stats();
        EXPECT_EQ(st.outbound_queue_packets, 2u);
        EXPECT_EQ(st.queue_dropped_packets, 0u);
        EXPECT_GT(st.outbound_queue_bytes, 0u);
    }

    // Finish bring-up (drain the full queue into the client, caps back).
    for (auto& o : p.drain(*p.srv)) p.deliver(*p.cli, o.bytes);
    for (auto& o : p.drain(*p.cli)) p.deliver(*p.srv, o.bytes);
    ASSERT_TRUE(p.srv->is_established());
    ASSERT_EQ(p.srv->stats().outbound_queue_packets, 0u);

    // PREPARE -> READY #1 (1/2). Both endpoints run the same 50 ms
    // retransmit schedule, so the first advance makes the SERVER's own
    // READY retransmit take the second slot (2/2, still allowed), and the
    // re-ack to the client's duplicate PREPARE is the FIRST refusal.
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    for (auto& o : p.drain(*p.cli)) p.deliver(*p.srv, o.bytes);
    EXPECT_EQ(p.srv->stats().outbound_queue_packets, 1u);
    EXPECT_EQ(p.srv->stats().queue_dropped_packets, 0u);

    p.advance(50);  // srv self-retransmits READY #2; cli retransmits PREPARE
    {
        auto q = p.drain(*p.cli);
        ASSERT_GE(q.size(), 1u);
        p.deliver(*p.srv, q[0].bytes);  // duplicate PREPARE -> READY refused
        const auto st = p.srv->stats();
        EXPECT_EQ(st.outbound_queue_packets, 2u) << "exact fill at the cap";
        EXPECT_EQ(st.queue_dropped_packets, 1u)
            << "the first refusal is the re-ack to the duplicate PREPARE";
        EXPECT_GT(st.queue_dropped_bytes, 0u);
    }

    p.advance(50);  // srv retransmit refused + duplicate-PREPARE re-ack refused
    {
        auto q = p.drain(*p.cli);
        ASSERT_GE(q.size(), 1u);
        p.deliver(*p.srv, q[0].bytes);
        const auto st = p.srv->stats();
        EXPECT_EQ(st.outbound_queue_packets, 2u)
            << "queue must not grow past the cap";
        EXPECT_EQ(st.queue_dropped_packets, 3u);
    }

    // Draining still yields exactly the 2 queued datagrams, byte-consistent.
    const uint64_t queued_bytes = p.srv->stats().outbound_queue_bytes;
    uint64_t drained_bytes = 0;
    size_t drained_packets = 0;
    for (auto& o : p.drain(*p.srv)) {
        drained_bytes += o.bytes.size();
        ++drained_packets;
    }
    EXPECT_EQ(drained_packets, 2u);
    EXPECT_EQ(drained_bytes, queued_bytes);
}

// ══════════════════════════════════════════════════════════════════════════════
// I-TXD-2: exact per-datagram RX-candidate accounting. Unwrap and AEAD
// attempts are counted per datagram, bounded by the structural cap
// kMaxRxCandidates (= 4), and an AEAD attempt happens only after a
// non-empty mask unwrap (aead <= unwrap per datagram). Exact deltas are
// asserted (not just upper bounds) so a dead counter cannot fake a PASS.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, CandidateAttemptCountersExact) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    auto snap = [](NcpMimicrySession& s) {
        const auto st = s.stats();
        return std::array<uint64_t, 4>{
            st.candidate_unwrap_attempts_total, st.candidate_aead_attempts_total,
            st.candidate_unwrap_attempts_max, st.candidate_aead_attempts_max};
    };

    // Fresh session: handshake ('H') and capabilities ('C') datagrams never
    // touch the 'E' candidate path — all counters must be exactly zero.
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

    // ── no transition outstanding: exactly 1 unwrap AND 1 AEAD per garbage
    // The GENERIC_UDP mask contract is a 4-byte length-prefix strip that
    // never rejects a datagram > 4 bytes (mimicry.cpp generic fallback), so
    // garbage structurally passes the active mask and is rejected by the
    // E2E AEAD — exactly one counted unwrap + one counted AEAD attempt per
    // datagram, contained by verify-then-commit.
    {
        const auto s0 = snap(*p.srv);
        for (int i = 0; i < 100; ++i)
            EXPECT_EQ(p.deliver(*p.srv, garbage(8 + (i % 180))).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        const auto s1 = snap(*p.srv);
        EXPECT_EQ(s1[0] - s0[0], 100u) << "unwrap attempts != 1/datagram";
        EXPECT_EQ(s1[1] - s0[1], 100u)
            << "AEAD attempts != 1/datagram (generic mask passes garbage "
               "structurally, AEAD rejects)";
        EXPECT_EQ(s1[2], 1u);
        EXPECT_EQ(s1[3], 1u);
    }

    // ── transition outstanding: active + pending = 2 unwraps, 1 AEAD ─────
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    {
        auto q = p.drain(*p.cli);
        ASSERT_EQ(q.size(), 1u);
        p.deliver(*p.srv, q[0].bytes);  // PREPARE; responder installs pending
    }
    ASSERT_TRUE(p.srv->stats().pending_mimic.has_value());
    {
        const auto s0 = snap(*p.srv);
        for (int i = 0; i < 100; ++i)
            EXPECT_EQ(p.deliver(*p.srv, garbage(8 + (i % 180))).kind,
                      NcpMimicrySession::IngressKind::Dropped);
        const auto s1 = snap(*p.srv);
        EXPECT_EQ(s1[0] - s0[0], 200u) << "unwrap attempts != 2/datagram";
        // active GENERIC_UDP unwrap passes garbage structurally (-> 1 AEAD
        // rejection per datagram); the pending QUIC_SHORT candidate fails
        // closed at its session-DCID mask check and never reaches AEAD.
        EXPECT_EQ(s1[1] - s0[1], 100u) << "AEAD attempts != 1/datagram";
        EXPECT_EQ(s1[2], 2u);
        EXPECT_EQ(s1[3], 1u);
    }

    // ── early new-epoch data: 2 unwraps AND 2 AEAD attempts ─────────────
    // The real QUIC_SHORT data datagram passes the active mask's generic
    // length prefix structurally (false positive -> AEAD reject), then the
    // pending mask authenticates it and the inner PD fence rejects it as
    // early-new: both candidates reach the AEAD layer.
    {
        auto q = p.drain(*p.srv);
        ASSERT_EQ(q.size(), 1u);
        p.deliver(*p.cli, q[0].bytes);  // READY -> cli activates
        auto cc = p.drain(*p.cli);      // COMMIT+CONFIRM, held
        ASSERT_GE(cc.size(), 2u);

        auto d = p.send_cli(V2Pair::app_payload(1, 64));
        ASSERT_TRUE(d.has_value());
        const auto s0 = snap(*p.srv);
        EXPECT_EQ(p.deliver(*p.srv, d->bytes).kind,
                  NcpMimicrySession::IngressKind::Dropped);
        const auto s1 = snap(*p.srv);
        EXPECT_EQ(s1[0] - s0[0], 2u) << "expected 2 unwrap attempts";
        EXPECT_EQ(s1[1] - s0[1], 2u) << "expected 2 AEAD attempts";
        EXPECT_EQ(s1[2], 2u);
        EXPECT_EQ(s1[3], 2u);

        // Complete the transition: no poisoning from the counted failures.
        p.deliver(*p.srv, cc[0].bytes);
        p.deliver(*p.srv, cc[1].bytes);
    }

    // Structural invariants over the whole run: per-datagram maxima never
    // exceed the hard cap, and AEAD work never exceeds unwrap work.
    {
        const auto st = p.srv->stats();
        EXPECT_LE(st.candidate_unwrap_attempts_max,
                  NcpMimicrySession::kMaxRxCandidates);
        EXPECT_LE(st.candidate_aead_attempts_max,
                  NcpMimicrySession::kMaxRxCandidates);
        EXPECT_LE(st.candidate_aead_attempts_max,
                  st.candidate_unwrap_attempts_max);
        EXPECT_LE(st.candidate_aead_attempts_total,
                  st.candidate_unwrap_attempts_total);
    }

    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    p.expect_all_control_stable_mask();
}

// ══════════════════════════════════════════════════════════════════════════════
// G2.1 — FULL-WIRE replay-after-grace evidence (NcpMimicrySession level).
//
// A byte-exact captured old-profile/old-layout ciphertext datagram — the
// COMPLETE wire datagram (kind byte + old outer mask + real E2E AEAD
// ciphertext of NCP-tagged, PD-framed epoch-0 data) — is captured BEFORE a
// real transition, accepted exactly once inside the grace window, and then
// replayed after the grace deadline passed and the transition finalized.
// Required: rejection with no application payload, no transition state
// confirmation/activation, and no E2E counter/nonce reset.
//
// This deliberately complements (does not duplicate) the inner-only
// ProfileTransition.OldDataInGraceAcceptedAfterGraceRejected, which feeds
// SessionProfileContext::on_ciphertext() directly with a bare ciphertext:
// here the full datagram traverses NcpMimicrySession::on_datagram() — the
// outer RX-candidate list, the real E2E ratchet/replay layer and the inner
// PD epoch fence together. It also extends
// MimicrySessionV2.GraceExpiryDropsOldAndPendingCandidates, which replays a
// NEVER-delivered datagram after grace: here the exact datagram that was
// already ACCEPTED once is replayed (true replay), plus a fresh held
// datagram for the inner-fence path.
//
//   * Outer-candidate-removal evidence: transition to QUIC_SHORT_HEADER —
//     after finalize the old GENERIC_UDP decoder is gone and the replay is
//     rejected at the MASK layer (exactly one unwrap attempt, ZERO AEAD
//     attempts; the inner PD fence is never reached).
//   * Inner PD/E2E rejection evidence: mask-preserving transition
//     (generic.udp → generic.udp.alt, same GENERIC_UDP outer mask, new PD
//     layout/epoch) — after finalize the replay passes the outer mask
//     structurally and is rejected INSIDE: the E2E replay fence
//     (R7-SEC-04, consumed message number) for the already-delivered
//     datagram, and the PD superseded-epoch fence (rx_rejected_old_expired)
//     for a captured-but-never-delivered one.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySessionV2, FullWireReplayAfterGraceRejectedAtOuterLayer) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    // Capture a valid old-profile/old-layout FULL datagram before the
    // transition (GENERIC_UDP mask, PD epoch 0, real E2E ciphertext) and
    // hold it in flight.
    auto captured = p.send_cli(V2Pair::app_payload(1, 64));
    ASSERT_TRUE(captured.has_value());
    ASSERT_EQ(probe_outer(captured->bytes), OuterShape::kGenericUdp);
    EXPECT_EQ(captured->profile_epoch, 0u);
    EXPECT_FALSE(captured->is_control);

    // Real v2 transition GENERIC_UDP → QUIC_SHORT_HEADER, pumped to
    // completion on both sides (grace window open, 1500 ms).
    ASSERT_EQ(p.cli->start_profile_transition(kQuicId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().active_mimic, MimicProfile::QUIC_SHORT_HEADER);

    // Inside grace the captured datagram is accepted EXACTLY ONCE via the
    // old-grace RX candidate — proof the capture was a live, valid
    // datagram, not garbage that any layer would drop anyway.
    auto r1 = p.deliver(*p.srv, captured->bytes);
    ASSERT_EQ(r1.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r1.app_payload.has_value());
    EXPECT_EQ(*r1.app_payload, V2Pair::app_payload(1, 64));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_old_grace, 1u);

    // In-grace replay of the byte-exact datagram: the old-grace candidate
    // still unwraps it, but the E2E replay fence (consumed message number
    // on the current chain) rejects it — the payload is never surfaced
    // twice, and no counter moves.
    {
        const auto s0 = p.srv->stats();
        auto rr = p.deliver(*p.srv, captured->bytes);
        EXPECT_EQ(rr.kind, NcpMimicrySession::IngressKind::Dropped);
        EXPECT_FALSE(rr.app_payload.has_value());
        const auto s1 = p.srv->stats();
        EXPECT_EQ(s1.ingress_dropped, s0.ingress_dropped + 1);
        EXPECT_EQ(s1.e2e_messages_received, s0.e2e_messages_received);
        EXPECT_EQ(s1.e2e_receiving_chain_length,
                  s0.e2e_receiving_chain_length);
        EXPECT_EQ(s1.transition_counters.rx_data_old_grace,
                  s0.transition_counters.rx_data_old_grace);
        ASSERT_EQ(p.srv_app.size(), 1u);
    }

    // Advance beyond the grace deadline and finalize: both sides reach IDLE
    // and the old + pending RX candidates are removed (C4).
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_FALSE(p.srv->stats().pending_mimic.has_value());

    // REPLAY AFTER GRACE: the byte-exact captured full datagram. The only
    // remaining RX candidate (active QUIC_SHORT_HEADER) fails closed on the
    // generic wire form and the old decoder is gone: exactly ONE unwrap
    // attempt and ZERO AEAD attempts — rejection at the mask layer; the
    // E2E/PD layers are never reached (rx_rejected_old_expired untouched).
    const auto before = p.srv->stats();
    auto r2 = p.deliver(*p.srv, captured->bytes);
    EXPECT_EQ(r2.kind, NcpMimicrySession::IngressKind::Dropped);
    EXPECT_FALSE(r2.app_payload.has_value());
    const auto after = p.srv->stats();

    // Outer-candidate-removal evidence (mask-layer rejection, no inner work).
    EXPECT_EQ(after.candidate_unwrap_attempts_total,
              before.candidate_unwrap_attempts_total + 1);
    EXPECT_EQ(after.candidate_aead_attempts_total,
              before.candidate_aead_attempts_total)
        << "post-grace replay reached the AEAD layer — the old mask "
           "candidate was not removed";
    EXPECT_EQ(after.transition_counters.rx_rejected_old_expired,
              before.transition_counters.rx_rejected_old_expired)
        << "post-grace replay reached the inner PD fence";
    EXPECT_EQ(after.ingress_dropped, before.ingress_dropped + 1);

    // No application payload from the replay, ever.
    ASSERT_EQ(p.srv_app.size(), 1u);
    EXPECT_EQ(p.srv_app[0], V2Pair::app_payload(1, 64));

    // No state confirmation/activation and no transition side effects.
    EXPECT_EQ(after.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(after.transition_counters.transitions_committed,
              before.transition_counters.transitions_committed);
    EXPECT_EQ(after.transition_counters.transitions_effective,
              before.transition_counters.transitions_effective);
    EXPECT_EQ(after.transition_counters.control_rx,
              before.transition_counters.control_rx);
    EXPECT_EQ(after.transition_counters.control_duplicates,
              before.transition_counters.control_duplicates);
    EXPECT_EQ(after.profile_epoch, 1u);
    EXPECT_EQ(after.active_profile.id, kQuicId);
    EXPECT_EQ(after.active_mimic, MimicProfile::QUIC_SHORT_HEADER);
    EXPECT_FALSE(after.pending_mimic.has_value());
    EXPECT_FALSE(p.srv->has_outbound())
        << "the replay triggered an outbound reaction datagram";

    // No counter/nonce reset at the E2E layer.
    EXPECT_EQ(after.e2e_messages_received, before.e2e_messages_received);
    EXPECT_EQ(after.e2e_receiving_chain_length,
              before.e2e_receiving_chain_length);
    EXPECT_EQ(after.e2e_sending_chain_length, before.e2e_sending_chain_length);
    EXPECT_EQ(after.crypto_epoch, before.crypto_epoch);

    // A second byte-exact replay is rejected identically (idempotent).
    {
        const auto b2 = p.srv->stats();
        auto r3 = p.deliver(*p.srv, captured->bytes);
        EXPECT_EQ(r3.kind, NcpMimicrySession::IngressKind::Dropped);
        EXPECT_FALSE(r3.app_payload.has_value());
        const auto a2 = p.srv->stats();
        EXPECT_EQ(a2.candidate_unwrap_attempts_total,
                  b2.candidate_unwrap_attempts_total + 1);
        EXPECT_EQ(a2.candidate_aead_attempts_total,
                  b2.candidate_aead_attempts_total);
        EXPECT_EQ(a2.ingress_dropped, b2.ingress_dropped + 1);
        EXPECT_EQ(a2.e2e_messages_received, b2.e2e_messages_received);
    }

    // The replayed session is undamaged: new-epoch data in the new mask
    // still flows both ways with full counter continuity.
    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(2, 64)));
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(3, 64)));
    EXPECT_EQ(p.cli->stats().transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(p.srv->stats().transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    p.expect_all_control_stable_mask();
}

TEST(MimicrySessionV2, FullWireReplayAfterGraceRejectedAtInnerLayer) {
    ensure_init();
    V2Pair p;
    p.init(true, true);
    ASSERT_TRUE(p.established());

    // Two valid old-profile/old-layout FULL datagrams captured back-to-back
    // BEFORE the transition (consecutive E2E message numbers). The target
    // keeps the SAME outer mask (GENERIC_UDP) and changes only the inner
    // profile identity/PD layout, so post-grace replays pass the outer
    // layer structurally and must be rejected INSIDE.
    auto d1 = p.send_cli(V2Pair::app_payload(1, 64));
    auto d2 = p.send_cli(V2Pair::app_payload(2, 64));
    ASSERT_TRUE(d1.has_value());
    ASSERT_TRUE(d2.has_value());
    ASSERT_EQ(probe_outer(d1->bytes), OuterShape::kGenericUdp);
    ASSERT_EQ(probe_outer(d2->bytes), OuterShape::kGenericUdp);
    EXPECT_EQ(d1->profile_epoch, 0u);
    EXPECT_EQ(d2->profile_epoch, 0u);

    // Real mask-preserving transition: generic.udp → generic.udp.alt (same
    // GENERIC_UDP outer mask, different PD layout, new profile epoch).
    ASSERT_EQ(p.cli->start_profile_transition(kUdpAltId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().active_mimic, MimicProfile::GENERIC_UDP);
    EXPECT_EQ(p.srv->stats().active_profile.id, kUdpAltId);
    EXPECT_EQ(p.srv->stats().profile_epoch, 1u);

    // Inside grace: d1 is accepted EXACTLY ONCE. The mask is unchanged, so
    // the ACTIVE candidate unwraps it; the acceptance itself is the inner
    // PD old-grace path over a real E2E skipped-key decrypt.
    auto r1 = p.deliver(*p.srv, d1->bytes);
    ASSERT_EQ(r1.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r1.app_payload.has_value());
    EXPECT_EQ(*r1.app_payload, V2Pair::app_payload(1, 64));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_old_grace, 1u);

    // Advance beyond the grace deadline and finalize: epoch 1 becomes the
    // stable epoch, the old decoder is retired (C4).
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_FALSE(p.srv->stats().pending_mimic.has_value());
    ASSERT_EQ(p.srv->stats().profile_epoch, 1u);

    // REPLAY #1 after grace: the byte-exact CONSUMED datagram. It passes
    // the outer mask (the generic unwrap is structural only) and is
    // rejected by the E2E replay fence (R7-SEC-04: the message number is
    // already consumed on the current chain) BEFORE the inner PD fence —
    // exactly one unwrap AND one AEAD attempt, e2e_messages_received and
    // the receiving chain length unchanged, rx_rejected_old_expired
    // untouched.
    const auto before = p.srv->stats();
    auto r2 = p.deliver(*p.srv, d1->bytes);
    EXPECT_EQ(r2.kind, NcpMimicrySession::IngressKind::Dropped);
    EXPECT_FALSE(r2.app_payload.has_value());
    {
        const auto after = p.srv->stats();
        EXPECT_EQ(after.candidate_unwrap_attempts_total,
                  before.candidate_unwrap_attempts_total + 1);
        EXPECT_EQ(after.candidate_aead_attempts_total,
                  before.candidate_aead_attempts_total + 1)
            << "mask-preserving replay must REACH and fail the E2E "
               "AEAD/replay layer";
        EXPECT_EQ(after.e2e_messages_received, before.e2e_messages_received)
            << "replayed consumed datagram counted as received";
        EXPECT_EQ(after.e2e_receiving_chain_length,
                  before.e2e_receiving_chain_length)
            << "replay moved/reset the receiving chain";
        EXPECT_EQ(after.transition_counters.rx_rejected_old_expired,
                  before.transition_counters.rx_rejected_old_expired)
            << "the E2E replay fence fires before the PD epoch fence";
        EXPECT_EQ(after.ingress_dropped, before.ingress_dropped + 1);
    }

    // REPLAY #2 after grace: d2 is a FRESH old-profile/old-layout datagram
    // (captured pre-transition, never delivered). It authenticates at the
    // E2E layer (staged skipped key — the E2E layer counts the authentic
    // decrypt) and is then rejected by the INNER PD epoch fence: epoch 0 is
    // provably superseded after finalize (rx_rejected_old_expired +1), so
    // no payload is surfaced and no state is touched.
    auto r3 = p.deliver(*p.srv, d2->bytes);
    EXPECT_EQ(r3.kind, NcpMimicrySession::IngressKind::Dropped);
    EXPECT_FALSE(r3.app_payload.has_value());
    const auto after = p.srv->stats();
    EXPECT_EQ(after.transition_counters.rx_rejected_old_expired,
              before.transition_counters.rx_rejected_old_expired + 1)
        << "fresh old-epoch datagram after grace was not fenced by the "
           "inner PD layer";
    EXPECT_EQ(after.e2e_messages_received, before.e2e_messages_received + 1)
        << "the authentic skipped-key decrypt is counted by E2E even though "
           "the PD fence rejects the payload";
    EXPECT_EQ(after.e2e_receiving_chain_length,
              before.e2e_receiving_chain_length)
        << "a skipped-key decrypt must not move/reset the receiving chain";
    EXPECT_EQ(after.ingress_dropped, before.ingress_dropped + 2);

    // No application payload from any replay: exactly d1 was ever surfaced.
    ASSERT_EQ(p.srv_app.size(), 1u);
    EXPECT_EQ(p.srv_app[0], V2Pair::app_payload(1, 64));

    // No state confirmation/activation from old-profile replays: the
    // transition stays finalized exactly once, no control was consumed or
    // emitted in reaction.
    EXPECT_EQ(after.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(after.transition_counters.transitions_committed,
              before.transition_counters.transitions_committed);
    EXPECT_EQ(after.transition_counters.transitions_effective,
              before.transition_counters.transitions_effective);
    EXPECT_EQ(after.transition_counters.transitions_uncertain, 0u);
    EXPECT_EQ(after.transition_counters.control_rx,
              before.transition_counters.control_rx);
    EXPECT_EQ(after.transition_counters.control_duplicates,
              before.transition_counters.control_duplicates);
    EXPECT_EQ(after.profile_epoch, 1u);
    EXPECT_EQ(after.active_profile.id, kUdpAltId);
    EXPECT_EQ(after.active_mimic, MimicProfile::GENERIC_UDP);
    EXPECT_FALSE(after.pending_mimic.has_value());
    EXPECT_FALSE(p.srv->has_outbound())
        << "the replays triggered an outbound reaction datagram";

    // No counter/nonce reset anywhere at the E2E layer.
    EXPECT_EQ(after.crypto_epoch, before.crypto_epoch);
    EXPECT_EQ(after.e2e_sending_chain_length, before.e2e_sending_chain_length);

    // The live session is undamaged: new-epoch data flows with full counter
    // continuity (the next fresh message numbers, no resynchronization).
    ASSERT_TRUE(p.send_cli_deliver(V2Pair::app_payload(3, 64)));
    ASSERT_TRUE(p.send_srv_deliver(V2Pair::app_payload(4, 64)));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(p.cli->stats().transition_counters.rx_rejected_unknown_epoch, 0u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    p.expect_all_control_stable_mask();
}
