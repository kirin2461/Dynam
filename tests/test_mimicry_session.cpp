// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_session.cpp
//
// Hermetic tests for NcpMimicrySession — the per-session adapter composing
// E2ESession + SessionProfileContext + ReferenceProfileCatalog +
// TrafficMimicry + MimicryShaper over transport-neutral datagrams.
//
// Real components, hermetic datagram queues (real UDP sockets are covered by
// tests/test_udp_profile_transition.cpp, which this file does not touch).
// A manual monotonic clock drives tick(); no threads, matching the adapter's
// documented single-threaded poll-loop ownership.
//
// Evidence covered:
//   * real X25519 handshake + capability negotiation over datagrams
//   * negotiated profile_transition_v1 gating (legacy peer keeps the
//     PROTECTED raw-payload E2E wire, no NCP/PD tag, no transition control)
//   * plaintext legacy datagrams are default-dropped; the explicit insecure
//     compatibility mode is pre-handshake only (no silent downgrade)
//   * two independent sessions do not overwrite each other
//   * same E2E session across transitions (no reconnect), monotonic E2E
//     counters and crypto epoch (mask-only switch resets nothing)
//   * old/new OUTER wire evidence (GENERIC_UDP vs GENERIC_TCP+padding)
//   * graceful in-flight decode during the grace window, rejection after
//   * corrupted/replayed datagrams never confirm a transition
//   * catalog-derived per-session shaper variant, pacing delays
//   * prepared-shape cancellation on activation and abort; control packets
//     never consume data shapes
//   * datagram/MTU budget enforcement
//
// SCOPE: only stateless wire-compatible outer profiles (GENERIC_UDP,
// GENERIC_TCP) are exercised. No stateful QUIC/RTC claim is made.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_mimicry_session.hpp"

#include <algorithm>
#include <cstring>
#include <deque>
#include <optional>
#include <string>
#include <vector>

using namespace ncp;

namespace {

// ── Test catalog ────────────────────────────────────────────────────────────

constexpr const char* kBaselineId = "generic.udp";
constexpr const char* kTargetId   = "generic.tcp";
constexpr int kTcpPadding = 24;  // deterministic GENERIC_TCP outer padding

ProfileDescriptor make_descriptor(const char* id, ProtocolFamily fam,
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

/// Shared read-only catalog for all sessions of a test.
struct TestCatalog {
    ReferenceProfileCatalog catalog;
    TestCatalog() {
        auto b = catalog.register_builtin(
            make_descriptor(kBaselineId, ProtocolFamily::GENERIC_UDP, 0));
        EXPECT_TRUE(b.ok()) << (b.issues.empty() ? "" : b.issues[0].message);
        auto t = catalog.register_builtin(
            make_descriptor(kTargetId, ProtocolFamily::GENERIC_TCP, 16));
        EXPECT_TRUE(t.ok()) << (t.issues.empty() ? "" : t.issues[0].message);
    }
    const ProfileDescriptor* baseline() const {
        return catalog.find(kBaselineId, 1);
    }
};

// ── Hermetic session pair ───────────────────────────────────────────────────

struct SentRecord {
    std::vector<uint8_t> bytes;
    uint32_t epoch = 0;
    size_t payload_len = 0;
    bool is_control = false;
};

struct Pair {
    TestCatalog cat;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;  // manual monotonic ms

    std::vector<std::vector<uint8_t>> cli_app;  // data delivered to client
    std::vector<std::vector<uint8_t>> srv_app;  // data delivered to server
    std::vector<SentRecord> cli_wire;           // datagrams sent by client
    std::vector<SentRecord> srv_wire;           // datagrams sent by server
    std::vector<NcpMimicrySession::OutboundDatagram> held;

    Pair() { PairInit(false, false); }

    void PairInit(bool cli_legacy, bool insecure_plaintext,
                  bool target_mimic_dns = false) {
        const auto* desc = cat.baseline();
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;  // deterministic wire sizes
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.catalog = &cat.catalog;
        base.mimic_config.profile = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_config.min_padding = kTcpPadding;
        base.mimic_config.max_padding = kTcpPadding;
        // This file pins the v1 transition world: the GENERIC-only target
        // gate, the v1 mask schedule and the legacy wire behavior are
        // exercised here; v2 negotiation and non-generic targets are covered
        // by tests/test_mimicry_session_v2.cpp and the v2-specific tests at
        // the bottom of this file.
        base.advertise_profile_transition_v2 = false;
        base.mimic_resolver = [target_mimic_dns](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            if (r.id == kBaselineId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            if (r.id == kTargetId)
                return target_mimic_dns
                           ? TrafficMimicry::MimicProfile::DNS_QUERY
                           : TrafficMimicry::MimicProfile::GENERIC_TCP;
            return std::nullopt;
        };
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1000;
        base.path_mtu_bytes = 1500;
        base.porthop_overhead_bytes = 20;
        base.max_application_payload = 1024;
        base.allow_insecure_plaintext_legacy = insecure_plaintext;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.advertise_profile_transition = !cli_legacy;
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
        if (r.kind == NcpMimicrySession::IngressKind::Data &&
            r.app_payload) {
            (&to == cli.get() ? cli_app : srv_app).push_back(*r.app_payload);
        }
        return r;
    }

    /// Drain all queued reactions until quiescent (no time passes).
    void pump() {
        for (int i = 0; i < 1000; ++i) {
            bool progress = false;
            while (auto o = cli->next_outbound()) {
                cli_wire.push_back({o->bytes, o->profile_epoch, 0,
                                    o->is_control});
                deliver(*srv, o->bytes);
                progress = true;
            }
            while (auto o = srv->next_outbound()) {
                srv_wire.push_back({o->bytes, o->profile_epoch, 0,
                                    o->is_control});
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

    /// Deterministic application payload.
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

    /// Send data client→server; records the wire datagram.
    std::optional<NcpMimicrySession::OutboundDatagram> send_cli(
        const std::vector<uint8_t>& p) {
        auto o = cli->send_application(p, now);
        if (o) {
            cli_wire.push_back({o->bytes, o->profile_epoch, p.size(),
                                o->is_control});
        }
        return o;
    }

    std::optional<NcpMimicrySession::OutboundDatagram> send_srv(
        const std::vector<uint8_t>& p) {
        auto o = srv->send_application(p, now);
        if (o) {
            srv_wire.push_back({o->bytes, o->profile_epoch, p.size(),
                                o->is_control});
        }
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
};

// Inner PD framing mirrors src/core/src/ncp_profile_transition.cpp:
// body = 'P','D',ver(1),epoch(4),plen(2),payload,pad-to-block; the 4-byte NCP
// tag is prepended AFTER padding (unpadded).
constexpr size_t kDataHeader = 2 + 1 + 4 + 2;
constexpr size_t kNcpTag = 4;

size_t pad_to_block(size_t n, uint32_t block) {
    if (block <= 1) return n;
    const size_t rem = n % block;
    return rem ? n + (block - rem) : n;
}

// Outer mask sizes (stateless): GENERIC_UDP = 4-byte length prefix;
// GENERIC_TCP = 4-byte length prefix + kTcpPadding padding.
size_t outer_overhead(uint32_t epoch) {
    return epoch == 0 ? 4u : 4u + static_cast<size_t>(kTcpPadding);
}

size_t expected_data_datagram_size(size_t e2e_overhead, size_t payload_len,
                                   uint32_t epoch) {
    const uint32_t block = epoch == 0 ? 0 : 16;
    return 1 + outer_overhead(epoch) + e2e_overhead + kNcpTag +
           pad_to_block(kDataHeader + payload_len, block);
}

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return true;
    }();
    ASSERT_TRUE(once);
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Bring-up: real handshake, capability negotiation, protected data, stats.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, HandshakeCapsAndProtectedData) {
    ensure_init();
    Pair p;
    auto hs = p.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    p.deliver(*p.srv, hs->bytes);
    ASSERT_TRUE(p.established());
    EXPECT_TRUE(p.cli->transition_capable());
    EXPECT_TRUE(p.srv->transition_capable());

    // Capability advertisement actually flowed on the wire (kind 'C').
    bool saw_caps_c2s = false, saw_caps_s2c = false;
    for (const auto& r : p.cli_wire) if (r.bytes[0] == 'C') saw_caps_c2s = true;
    for (const auto& r : p.srv_wire) if (r.bytes[0] == 'C') saw_caps_s2c = true;
    EXPECT_TRUE(saw_caps_c2s);
    EXPECT_TRUE(saw_caps_s2c);

    // Catalog-derived shaper engaged on both ends of the same session.
    ASSERT_TRUE(p.cli->shaper_engaged());
    ASSERT_TRUE(p.srv->shaper_engaged());
    EXPECT_STREQ(p.cli->shaper_profile_name(), kBaselineId);
    EXPECT_EQ(p.cli->shaper_session_tag(), p.srv->shaper_session_tag());
    EXPECT_EQ(p.cli->shaper_epoch(), 0u);

    const auto sid_c = p.cli->e2e_session_id();
    const auto sid_s = p.srv->e2e_session_id();
    ASSERT_FALSE(sid_c.empty());
    const auto c0 = p.cli->stats();

    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(1, 100)));
    ASSERT_TRUE(p.send_srv_deliver(Pair::app_payload(2, 200)));
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(3, 48)));

    const auto c1 = p.cli->stats();
    const auto s1 = p.srv->stats();
    EXPECT_EQ(c1.transition_counters.tx_data_stable, 2u);
    EXPECT_EQ(s1.transition_counters.rx_data_stable, 2u);
    EXPECT_EQ(s1.transition_counters.tx_data_stable, 1u);
    EXPECT_EQ(c1.transition_counters.rx_data_stable, 1u);
    EXPECT_EQ(c1.profile_epoch, 0u);
    EXPECT_EQ(c1.active_profile.id, kBaselineId);
    EXPECT_FALSE(c1.pending_profile.has_value());
    EXPECT_EQ(c1.active_mimic, TrafficMimicry::MimicProfile::GENERIC_UDP);

    // Monotonic E2E counters; same session, no reconnect.
    EXPECT_GT(c1.e2e_messages_sent, c0.e2e_messages_sent);
    EXPECT_GE(c1.e2e_sending_chain_length, c0.e2e_sending_chain_length);
    EXPECT_EQ(c1.crypto_epoch, c0.crypto_epoch);
    EXPECT_EQ(p.cli->e2e_session_id(), sid_c);
    EXPECT_EQ(p.srv->e2e_session_id(), sid_s);

    // Shaper pacing delays are reported per data packet and non-negative;
    // control datagrams carry no pacing.
    bool any_pacing = false;
    for (int i = 0; i < 8; ++i) {
        auto o = p.cli->send_application(Pair::app_payload(10 + i, 64), p.now);
        ASSERT_TRUE(o.has_value());
        EXPECT_FALSE(o->is_control);
        EXPECT_GE(o->pacing_delay.count(), 0);
        if (o->pacing_delay.count() > 0) any_pacing = true;
        p.deliver(*p.srv, o->bytes);
    }
    EXPECT_TRUE(any_pacing);
    for (const auto& r : p.cli_wire)
        if (r.is_control) ADD_FAILURE() << "unexpected control during pure data";
}

// ══════════════════════════════════════════════════════════════════════════════
// Catalog-driven switch: old/new OUTER wire evidence, monotonic crypto,
// no TLS/key/counter reset on a mask-only switch, replay/corruption safety.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, CatalogDrivenSwitchWireEvidence) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    const std::string sid_c = p.cli->e2e_session_id();
    const auto before = p.cli->stats();
    const uint64_t wrapped_before = before.outer_stats.packets_wrapped.load();

    // Phase 1: stable-profile traffic (epoch 0, GENERIC_UDP outer).
    const size_t plens[3] = {37, 100, 64};
    for (int i = 0; i < 3; ++i)
        ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(i, plens[i])));

    // Calibrate the constant E2E serialization overhead from the first
    // stable datagram (deterministic: padding disabled).
    size_t e2e_overhead = 0;
    {
        const SentRecord* first = nullptr;
        for (const auto& r : p.cli_wire)
            if (!r.is_control && r.payload_len > 0) { first = &r; break; }
        ASSERT_NE(first, nullptr);
        ASSERT_EQ(first->epoch, 0u);
        e2e_overhead = first->bytes.size() -
                       (1 + outer_overhead(0) + kNcpTag + kDataHeader +
                        first->payload_len);
    }

    // Phase 2: catalog-driven transition to generic.tcp (GENERIC_TCP outer,
    // 16-byte PD block padding). pump() delivers control immediately without
    // advancing the clock, so both sides sit in DRAIN with the grace window
    // open and the new epoch already effective.
    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::PREPARE);
    p.pump();

    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);
    EXPECT_EQ(p.cli->stats().profile_epoch, 1u);   // effective epoch
    EXPECT_EQ(p.srv->stats().profile_epoch, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_TCP);
    EXPECT_EQ(p.srv->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_TCP);

    // Phase 3: traffic on the new outer mask while the grace window is open
    // (epoch 1, counted as rx_data_new).
    for (int i = 0; i < 3; ++i)
        ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(100 + i, plens[i])));
    ASSERT_TRUE(p.send_srv_deliver(Pair::app_payload(200, 90)));
    EXPECT_EQ(p.cli->stats().transition_counters.tx_data_new, 3u);
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_new, 3u);

    // Corrupted + replayed datagrams: dropped, never confirm anything, app
    // stream unaffected. The corruption must land inside the AUTHENTICATED
    // bytes: the outer mask's trailing padding is unauthenticated by design
    // (generic unwrap permits trailing mask bytes), so flipping a padding
    // byte would be a no-op rather than corruption. Calibrate the offset
    // from the actual wire layout:
    //   datagram = [kind:1][len:4 BE][serialized E2E wire][outer padding]
    //   E2E wire = ver(1) msgnum(4) prevchain(4) blob(dh) blob(hdr.nonce)
    //              blob(ad) blob(ciphertext) blob(tag) blob(nonce)
    const auto srv_before = p.srv->stats();
    ASSERT_TRUE(p.send_cli(Pair::app_payload(300, 64)));
    auto good = p.cli_wire.back().bytes;
    const size_t ct_off = [&] {
        size_t pos = 5;  // skip kind + GENERIC length prefix
        auto blob_end = [&](void) -> size_t {
            const size_t bl = (static_cast<size_t>(good[pos]) << 8) |
                              good[pos + 1];
            pos += 2 + bl;
            return pos;
        };
        pos += 1 + 4 + 4;          // version, message_number, prev chain
        blob_end();                // dh_public_key
        blob_end();                // header nonce
        blob_end();                // associated data
        const size_t ct_len = (static_cast<size_t>(good[pos]) << 8) |
                              good[pos + 1];
        return pos + 2 + ct_len / 2;  // middle of the AEAD ciphertext
    }();
    // Sanity: the corruption point is inside the length-delimited E2E wire,
    // i.e. strictly before any trailing outer padding.
    {
        const size_t wire_len = (static_cast<size_t>(good[1]) << 24) |
                                (static_cast<size_t>(good[2]) << 16) |
                                (static_cast<size_t>(good[3]) << 8) |
                                good[4];
        ASSERT_LT(ct_off, 5 + wire_len)
            << "corruption point landed in unauthenticated outer padding";
    }
    auto corrupt = good;
    corrupt[ct_off] ^= 0x01;
    EXPECT_EQ(p.deliver(*p.srv, corrupt).kind,
              NcpMimicrySession::IngressKind::Dropped)
        << "corrupted authenticated bytes were delivered";
    EXPECT_EQ(p.deliver(*p.srv, good).kind,
              NcpMimicrySession::IngressKind::Data)
        << "original datagram was not accepted after the corruption attempt";
    EXPECT_EQ(p.deliver(*p.srv, good).kind,  // exact replay
              NcpMimicrySession::IngressKind::Dropped)
        << "replayed datagram was delivered a second time";
    const auto srv_mid = p.srv->stats();
    EXPECT_EQ(srv_mid.transition_counters.rx_data_new,
              srv_before.transition_counters.rx_data_new + 1)
        << "replayed/corrupted datagram produced data";

    // Phase 4: let the grace deadline pass; the FSM finalizes to IDLE and the
    // new profile becomes the stable one.
    p.advance(2000);
    p.pump();

    const auto ca = p.cli->stats();
    const auto sa = p.srv->stats();
    EXPECT_EQ(ca.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(sa.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(ca.profile_epoch, 1u);
    EXPECT_EQ(sa.profile_epoch, 1u);
    EXPECT_EQ(ca.active_profile.id, kTargetId);
    EXPECT_EQ(sa.active_profile.id, kTargetId);
    EXPECT_EQ(ca.transition_counters.transitions_started, 1u);
    EXPECT_EQ(ca.transition_counters.transitions_committed, 1u);
    EXPECT_EQ(ca.transition_counters.transitions_effective, 1u);
    EXPECT_EQ(ca.transition_counters.transitions_uncertain, 0u);
    EXPECT_EQ(sa.transition_counters.transitions_effective, 1u);
    EXPECT_GT(ca.transition_counters.control_tx, 0u);
    EXPECT_GT(sa.transition_counters.control_rx, 0u);

    // Shaper moved to the derived target variant; epoch bumped once.
    EXPECT_STREQ(p.cli->shaper_profile_name(), kTargetId);
    EXPECT_EQ(p.cli->shaper_epoch(), 1u);

    // Mask-only switch: E2E session, crypto epoch and outer counters are
    // untouched (monotonic, never reset).
    EXPECT_EQ(p.cli->e2e_session_id(), sid_c);
    EXPECT_EQ(ca.crypto_epoch, before.crypto_epoch);
    EXPECT_EQ(p.srv->stats().crypto_epoch, before.crypto_epoch);
    EXPECT_GE(ca.e2e_sending_chain_length, before.e2e_sending_chain_length);
    EXPECT_GT(ca.outer_stats.packets_wrapped.load(), wrapped_before)
        << "outer mimicry stats reset on mask-only switch";

    // Exact old/new outer wire evidence: every data datagram matches the
    // byte-exact size formula of the epoch it was stamped with.
    bool saw_old = false, saw_new = false;
    for (const auto& r : p.cli_wire) {
        if (r.is_control || r.payload_len == 0) continue;
        const size_t expect =
            expected_data_datagram_size(e2e_overhead, r.payload_len, r.epoch);
        EXPECT_EQ(r.bytes.size(), expect)
            << "wire size mismatch for epoch " << r.epoch
            << " payload_len=" << r.payload_len;
        if (r.epoch == 0) saw_old = true;
        if (r.epoch == 1) saw_new = true;
    }
    EXPECT_TRUE(saw_old);
    EXPECT_TRUE(saw_new);
    // The new outer mask is observably different on the wire.
    EXPECT_NE(expected_data_datagram_size(e2e_overhead, 64, 0),
              expected_data_datagram_size(e2e_overhead, 64, 1));

    // Transition confirmation was not affected by the corrupted/replayed
    // datagrams; the app stream is exactly what was sent.
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv_app.size(), 7u);

    // Replayed transition control can never re-confirm or re-open anything:
    // the AEAD replay check drops it before the transition manager sees it.
    const SentRecord* last_ctl = nullptr;
    for (const auto& r : p.srv_wire) if (r.is_control) last_ctl = &r;
    ASSERT_NE(last_ctl, nullptr);
    const auto cli_ctl = p.cli->stats().transition_counters;
    EXPECT_EQ(p.deliver(*p.cli, last_ctl->bytes).kind,
              NcpMimicrySession::IngressKind::Dropped);
    const auto cli_ctl2 = p.cli->stats().transition_counters;
    EXPECT_EQ(cli_ctl2.control_rx, cli_ctl.control_rx);
    EXPECT_EQ(cli_ctl2.control_duplicates, cli_ctl.control_duplicates);
    EXPECT_EQ(cli_ctl2.transitions_effective, cli_ctl.transitions_effective);
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
}

// ══════════════════════════════════════════════════════════════════════════════
// I-EPOCH-2: a layout/mask-only transition is not a cryptographic rekey.
// Transition control consumes ordinary E2E counters, so the chains must GROW;
// the invariant is continuity (never reset), not unchanged counter values.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, LayoutTransitionPreservesCryptoEpochAndCounterContinuity) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    const auto cli_before = p.cli->stats();
    const auto srv_before = p.srv->stats();
    const auto cli_sid = p.cli->e2e_session_id();
    const auto srv_sid = p.srv->e2e_session_id();
    ASSERT_FALSE(cli_sid.empty());
    ASSERT_FALSE(srv_sid.empty());

    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();

    const auto cli_after = p.cli->stats();
    const auto srv_after = p.srv->stats();
    ASSERT_EQ(cli_after.transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(srv_after.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(cli_after.profile_epoch, 1u);
    EXPECT_EQ(srv_after.profile_epoch, 1u);

    // No implicit rekey or new E2E session at the profile epoch boundary.
    EXPECT_EQ(cli_after.crypto_epoch, cli_before.crypto_epoch);
    EXPECT_EQ(srv_after.crypto_epoch, srv_before.crypto_epoch);
    EXPECT_EQ(p.cli->e2e_session_id(), cli_sid);
    EXPECT_EQ(p.srv->e2e_session_id(), srv_sid);

    // Authenticated transition control advanced both chains without resetting
    // either one. Strict growth also proves this test exercised real control.
    EXPECT_GT(cli_after.e2e_sending_chain_length,
              cli_before.e2e_sending_chain_length);
    EXPECT_GT(cli_after.e2e_receiving_chain_length,
              cli_before.e2e_receiving_chain_length);
    EXPECT_GT(srv_after.e2e_sending_chain_length,
              srv_before.e2e_sending_chain_length);
    EXPECT_GT(srv_after.e2e_receiving_chain_length,
              srv_before.e2e_receiving_chain_length);

    // Post-transition application packets continue the very same chains by
    // exactly one message in each direction; crypto_epoch stays unchanged.
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(700, 64)));
    ASSERT_TRUE(p.send_srv_deliver(Pair::app_payload(701, 64)));
    const auto cli_data = p.cli->stats();
    const auto srv_data = p.srv->stats();
    EXPECT_EQ(cli_data.e2e_sending_chain_length,
              cli_after.e2e_sending_chain_length + 1);
    EXPECT_EQ(cli_data.e2e_receiving_chain_length,
              cli_after.e2e_receiving_chain_length + 1);
    EXPECT_EQ(srv_data.e2e_sending_chain_length,
              srv_after.e2e_sending_chain_length + 1);
    EXPECT_EQ(srv_data.e2e_receiving_chain_length,
              srv_after.e2e_receiving_chain_length + 1);
    EXPECT_EQ(cli_data.crypto_epoch, cli_before.crypto_epoch);
    EXPECT_EQ(srv_data.crypto_epoch, srv_before.crypto_epoch);
}

// ══════════════════════════════════════════════════════════════════════════════
// Two independent sessions on the same catalog: no cross-talk, independent
// transitions and independently derived shaper state.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, TwoSessionsIndependentState) {
    ensure_init();
    Pair a, b;
    ASSERT_TRUE(a.established());
    ASSERT_TRUE(b.established());

    // Independent per-session derivation (different shared secrets).
    EXPECT_NE(a.cli->shaper_session_tag(), b.cli->shaper_session_tag());
    EXPECT_NE(a.cli->e2e_session_id(), b.cli->e2e_session_id());

    ASSERT_TRUE(a.send_cli_deliver(Pair::app_payload(1, 80)));
    ASSERT_TRUE(b.send_cli_deliver(Pair::app_payload(1, 80)));

    // Transition session A only.
    ASSERT_EQ(a.cli->start_profile_transition(kTargetId, 1, a.now),
              TransitionError::NONE);
    a.pump();
    a.advance(2000);
    a.pump();
    ASSERT_EQ(a.cli->stats().profile_epoch, 1u);
    ASSERT_EQ(a.srv->stats().profile_epoch, 1u);

    // Session B untouched by session A's transition.
    const auto bc = b.cli->stats();
    EXPECT_EQ(bc.profile_epoch, 0u);
    EXPECT_EQ(bc.active_profile.id, kBaselineId);
    EXPECT_EQ(bc.active_mimic, TrafficMimicry::MimicProfile::GENERIC_UDP);
    EXPECT_EQ(bc.transition_counters.transitions_started, 0u);
    EXPECT_EQ(bc.transition_counters.transitions_committed, 0u);
    EXPECT_EQ(b.cli->shaper_epoch(), 0u);
    EXPECT_STREQ(b.cli->shaper_profile_name(), kBaselineId);

    // Wire isolation: session B datagrams keep the epoch-0 outer form.
    const auto wb = b.cli->stats();
    ASSERT_TRUE(b.send_cli_deliver(Pair::app_payload(2, 80)));
    ASSERT_TRUE(a.send_cli_deliver(Pair::app_payload(2, 80)));
    EXPECT_EQ(b.cli->stats().e2e_sending_chain_length,
              wb.e2e_sending_chain_length + 1);
    const auto& last_b = b.cli_wire.back();
    EXPECT_EQ(last_b.epoch, 0u);
    const auto& last_a = a.cli_wire.back();
    EXPECT_EQ(last_a.epoch, 1u);
    EXPECT_EQ(last_b.payload_len, last_a.payload_len);
    EXPECT_NE(last_b.bytes.size(), last_a.bytes.size())
        << "sessions' outer masks are not independent on the wire";

    // Session B transitions independently afterwards.
    ASSERT_EQ(b.cli->start_profile_transition(kTargetId, 1, b.now),
              TransitionError::NONE);
    b.pump();
    b.advance(2000);
    b.pump();
    EXPECT_EQ(b.cli->stats().profile_epoch, 1u);
    EXPECT_EQ(a.cli->stats().profile_epoch, 1u);
    EXPECT_EQ(a.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(b.cli->stats().transition_counters.transitions_effective, 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Grace window: old-layout in-flight datagrams decode during grace and are
// rejected after the old decoder is removed. E2E counters stay monotonic.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, GracefulInFlightDecodeAndExpiry) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(0, 64)));

    // Two old-profile datagrams "in flight" while the switch happens.
    auto held1 = p.send_cli(Pair::app_payload(1, 64));
    auto held2 = p.send_cli(Pair::app_payload(2, 64));
    ASSERT_TRUE(held1.has_value());
    ASSERT_TRUE(held2.has_value());
    ASSERT_EQ(held1->profile_epoch, 0u);

    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    p.pump();  // no time passes: grace window (1000 ms) is still open

    ASSERT_EQ(p.cli->stats().transition_counters.transitions_committed, 1u);
    ASSERT_EQ(p.srv->stats().transition_counters.transitions_committed, 1u);

    // Grace: the held old-epoch datagram decodes via the old RX path.
    auto r1 = p.deliver(*p.srv, held1->bytes);
    ASSERT_EQ(r1.kind, NcpMimicrySession::IngressKind::Data);
    ASSERT_TRUE(r1.app_payload.has_value());
    EXPECT_EQ(*r1.app_payload, Pair::app_payload(1, 64));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_old_grace, 1u);

    // While the grace window is open the new epoch is already effective:
    // fresh data is stamped epoch 1 and counted via the new RX path.
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(3, 64)));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_new, 1u);

    // Let the grace deadline pass; both sides finalize to IDLE and the old
    // outer decoder is removed.
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    ASSERT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);

    // The second held datagram now hits the removed old decoder.
    auto r2 = p.deliver(*p.srv, held2->bytes);
    EXPECT_EQ(r2.kind, NcpMimicrySession::IngressKind::Dropped);
    EXPECT_GE(p.srv->stats().transition_counters.rx_rejected_old_expired, 1u)
        << "expired old-epoch datagram was not rejected";
    EXPECT_EQ(p.srv_app.size(), 3u);

    // Stream continues; the new profile is now the stable one, and crypto
    // chains never regressed.
    const auto stable_before =
        p.srv->stats().transition_counters.rx_data_stable;
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(4, 64)));
    EXPECT_EQ(p.srv->stats().transition_counters.rx_data_stable,
              stable_before + 1);
    const auto c = p.cli->stats();
    const auto s = p.srv->stats();
    EXPECT_GE(s.e2e_receiving_chain_length, 1u);
    EXPECT_EQ(c.crypto_epoch, s.crypto_epoch);
}

// ══════════════════════════════════════════════════════════════════════════════
// Legacy peer (profile_transition_v1 NOT advertised): the wire stays the
// PROTECTED raw-payload E2E form (no NCP tag, no PD framing), hot-switch is
// disabled, and no transition control is ever emitted.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, LegacyPeerKeepsProtectedRawWire) {
    ensure_init();
    Pair legacy;   // client will not advertise profile_transition_v1
    legacy.PairInit(/*cli_legacy=*/true, /*insecure_plaintext=*/false);
    auto hs = legacy.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    legacy.deliver(*legacy.srv, hs->bytes);
    ASSERT_TRUE(legacy.established());
    EXPECT_FALSE(legacy.cli->transition_capable());
    EXPECT_FALSE(legacy.srv->transition_capable())
        << "server must negotiate the strict AND of both advertisements";

    // Capable reference pair for byte-exact wire comparison.
    Pair cap;
    ASSERT_TRUE(cap.established());

    const auto payload = Pair::app_payload(7, 96);
    ASSERT_TRUE(legacy.send_cli_deliver(payload));
    ASSERT_TRUE(cap.send_cli_deliver(payload));

    // Legacy datagram is exactly NCP tag + PD header (13 bytes) smaller:
    // the AEAD plaintext is the RAW payload — the protected legacy form.
    ASSERT_EQ(legacy.cli_wire.back().payload_len, payload.size());
    ASSERT_EQ(cap.cli_wire.back().payload_len, payload.size());
    EXPECT_EQ(legacy.cli_wire.back().bytes.size() + 13,
              cap.cli_wire.back().bytes.size())
        << "legacy wire format changed (expected raw payload inside AEAD)";

    // The datagram is still E2E-protected: no plaintext leakage on the wire.
    const auto& lw = legacy.cli_wire.back().bytes;
    ASSERT_GT(payload.size(), 8u);
    bool found_plaintext = false;
    for (size_t i = 0; i + payload.size() <= lw.size(); ++i) {
        if (std::memcmp(lw.data() + i, payload.data(), payload.size()) == 0) {
            found_plaintext = true;
            break;
        }
    }
    EXPECT_FALSE(found_plaintext)
        << "legacy datagram leaks the raw payload in plaintext";

    // Hot-switch is refused and nothing is emitted — never silently.
    const size_t out_before = legacy.cli_wire.size();
    EXPECT_EQ(legacy.cli->start_profile_transition(kTargetId, 1, legacy.now),
              TransitionError::NOT_SUPPORTED);
    EXPECT_FALSE(legacy.cli->has_outbound());
    legacy.pump();
    EXPECT_EQ(legacy.cli_wire.size(), out_before)
        << "a datagram was emitted after NOT_SUPPORTED";
    EXPECT_EQ(legacy.srv->stats().transition_counters.control_rx, 0u)
        << "legacy peer received transition control";

    // Server→client direction also uses the raw protected form.
    ASSERT_TRUE(legacy.send_srv_deliver(Pair::app_payload(8, 48)));
    EXPECT_EQ(legacy.cli->stats().transition_counters.rx_data_stable, 1u);
    EXPECT_EQ(legacy.cli->stats().transition_counters.tx_data_new, 0u);
    EXPECT_EQ(legacy.cli->stats().profile_epoch, 0u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Insecure plaintext compatibility mode: default-dropped, explicit opt-in,
// pre-handshake only. An established E2E session is never downgraded.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, PlaintextCompatModeGatedAndNeverDowngrades) {
    ensure_init();
    const auto plain = Pair::app_payload(1, 32);
    std::vector<uint8_t> dg;
    dg.push_back('P');
    dg.insert(dg.end(), plain.begin(), plain.end());

    // Default: dropped.
    {
        Pair p;
        auto r = p.deliver(*p.srv, dg);
        EXPECT_EQ(r.kind, NcpMimicrySession::IngressKind::Dropped);
        EXPECT_FALSE(r.app_payload.has_value());
        EXPECT_GE(p.srv->stats().ingress_dropped, 1u);
        EXPECT_TRUE(p.srv_app.empty());
    }

    // Explicit opt-in: surfaced pre-handshake, marked insecure.
    {
        Pair p;
        p.PairInit(false, /*insecure_plaintext=*/true);
        auto r = p.deliver(*p.srv, dg);
        ASSERT_EQ(r.kind, NcpMimicrySession::IngressKind::Data);
        EXPECT_TRUE(r.insecure_plaintext);
        ASSERT_TRUE(r.app_payload.has_value());
        EXPECT_EQ(*r.app_payload, plain);

        // After the E2E session is established: always dropped, no downgrade.
        auto hs = p.cli->start_handshake();
        ASSERT_TRUE(hs.has_value());
        p.deliver(*p.srv, hs->bytes);
        ASSERT_TRUE(p.established());
        const auto before = p.srv->stats();
        auto r2 = p.deliver(*p.srv, dg);
        EXPECT_EQ(r2.kind, NcpMimicrySession::IngressKind::Dropped);
        EXPECT_FALSE(r2.app_payload.has_value());
        EXPECT_EQ(p.srv->stats().e2e_messages_received,
                  before.e2e_messages_received)
            << "plaintext datagram reached the established E2E session";
        // Protected data path still works afterwards.
        EXPECT_TRUE(p.send_cli_deliver(Pair::app_payload(2, 32)));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Crypto epoch regression: Stats/context follow the ACTUAL E2E crypto epoch —
// 0 for a freshly established session, bumped by authenticated DH ratchet
// steps (host rekey and the peer's answering step), never invented by the
// adapter and never changed by a mask-only profile switch.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, CryptoEpochFollowsE2ERekey) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());
    const std::string sid = p.cli->e2e_session_id();

    // Freshly established sessions start at the E2E initial crypto epoch 0.
    EXPECT_EQ(p.cli->stats().crypto_epoch, 0u);
    EXPECT_EQ(p.srv->stats().crypto_epoch, 0u);

    // Role gate: the responder never rotates spontaneously.
    EXPECT_FALSE(p.srv->rotate_e2e_keys());

    ASSERT_TRUE(p.cli->rotate_e2e_keys());
    EXPECT_EQ(p.cli->stats().crypto_epoch, 1u);
    // In-flight fence: a second spontaneous rotation is refused until the
    // peer's authenticated DH step answers the first one.
    EXPECT_FALSE(p.cli->rotate_e2e_keys());

    // The responder follows on the first authenticated decrypt under the new
    // key material (decrypt-triggered epoch sync inside the adapter).
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(1, 64)));
    EXPECT_EQ(p.srv->stats().crypto_epoch, 1u);

    // The answering DH step opens the initiator's rotation fence again.
    ASSERT_TRUE(p.send_srv_deliver(Pair::app_payload(2, 64)));
    EXPECT_EQ(p.cli->stats().crypto_epoch, 2u);
    EXPECT_TRUE(p.cli->rotate_e2e_keys());
    EXPECT_EQ(p.cli->stats().crypto_epoch, 3u);
    // The peer commits one DH step per newly advertised ratchet key.
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(3, 64)));
    EXPECT_EQ(p.srv->stats().crypto_epoch, 2u);

    // A transition negotiated after rekeys binds the CURRENT epoch: if the
    // adapter kept a stale or invented epoch, the peer's monotonic crypto
    // fence would reject the control messages and the switch would fail.
    const uint64_t epoch_before_switch = p.cli->stats().crypto_epoch;
    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().profile_epoch, 1u);

    // The mask-only switch never touched the crypto epoch and the E2E session
    // is the same one (no reconnect).
    EXPECT_GE(p.cli->stats().crypto_epoch, epoch_before_switch);
    EXPECT_EQ(p.cli->e2e_session_id(), sid);
    ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(4, 64)));
}

// ══════════════════════════════════════════════════════════════════════════════
// Catalog-derived per-session shaper: derivation provenance, pacing, and the
// profile variant switch driven by the transition epoch observer.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, CatalogDerivedShaperVariant) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli->shaper_engaged());
    ASSERT_TRUE(p.srv->shaper_engaged());

    // Both endpoints derived the same per-session variant from the shared
    // secret; the variant comes from the catalog descriptor.
    EXPECT_EQ(p.cli->shaper_session_tag(), p.srv->shaper_session_tag());
    EXPECT_STREQ(p.cli->shaper_profile_name(), kBaselineId);
    EXPECT_STREQ(p.srv->shaper_profile_name(), kBaselineId);
    EXPECT_EQ(p.cli->shaper_epoch(), 0u);

    // Prepared shapes are clamped to the datagram budget and carry a paired
    // pacing delay sampled from the catalog-derived model.
    PreparedShape ps;
    ASSERT_TRUE(p.cli->shaper_peek_prepared(ps));
    EXPECT_EQ(ps.profile_epoch, 0u);
    EXPECT_GE(ps.bytes, 1u);
    EXPECT_LE(ps.bytes, p.cli->max_datagram_bytes());
    EXPECT_GE(ps.delay_ms, 0.0);

    // The epoch observer installs the derived target variant on activation.
    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();
    ASSERT_EQ(p.cli->stats().profile_epoch, 1u);
    EXPECT_STREQ(p.cli->shaper_profile_name(), kTargetId);
    EXPECT_STREQ(p.srv->shaper_profile_name(), kTargetId);
    EXPECT_EQ(p.cli->shaper_epoch(), 1u);
    EXPECT_EQ(p.srv->shaper_epoch(), 1u);

    // And data on the new epoch still gets pacing from the new variant.
    auto o = p.cli->send_application(Pair::app_payload(1, 64), p.now);
    ASSERT_TRUE(o.has_value());
    EXPECT_EQ(o->profile_epoch, 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Prepared-shape lifecycle: control packets never consume data shapes; the
// epoch observer cancels prepared shapes on activation AND on abort.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, PreparedShapeCancellationAndControlNoConsume) {
    ensure_init();

    // --- activation path ---
    {
        Pair p;
        ASSERT_TRUE(p.established());
        PreparedShape ps;
        ASSERT_TRUE(p.cli->shaper_peek_prepared(ps));
        ASSERT_TRUE(p.cli->shaper_has_prepared_shape());

        ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
                  TransitionError::NONE);

        // Deliver ONLY the PREPARE (a control packet): the queued data shape
        // must survive — control packets never consume data shapes.
        ASSERT_TRUE(p.cli->has_outbound());
        auto prep = p.cli->next_outbound();
        ASSERT_TRUE(prep.has_value());
        ASSERT_TRUE(prep->is_control);
        p.cli_wire.push_back({prep->bytes, prep->profile_epoch, 0, true});
        p.deliver(*p.srv, prep->bytes);
        EXPECT_TRUE(p.cli->shaper_has_prepared_shape())
            << "control packet consumed the prepared data shape";
        // The responder answered READY without touching its own shaper.
        ASSERT_TRUE(p.srv->has_outbound());
        auto ready = p.srv->next_outbound();
        ASSERT_TRUE(ready.has_value());
        EXPECT_TRUE(ready->is_control);
        EXPECT_FALSE(p.srv->shaper_has_prepared_shape());

        // Delivering READY activates the initiator: the stale shape is
        // cancelled by the epoch observer and the shaper epoch bumps.
        p.srv_wire.push_back({ready->bytes, ready->profile_epoch, 0, true});
        p.deliver(*p.cli, ready->bytes);
        EXPECT_FALSE(p.cli->shaper_has_prepared_shape())
            << "stale prepared shape survived activation";
        EXPECT_EQ(p.cli->shaper_epoch(), 1u);
        EXPECT_EQ(p.cli->stats().profile_epoch, 1u);

        p.pump();
        p.advance(2000);
        p.pump();
        EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);

        // The shaper is fully usable under the new epoch.
        PreparedShape ps2;
        ASSERT_TRUE(p.cli->shaper_peek_prepared(ps2));
        EXPECT_EQ(ps2.profile_epoch, 1u);
        EXPECT_TRUE(p.send_cli_deliver(Pair::app_payload(1, 64)));  // consumes it
        EXPECT_FALSE(p.cli->shaper_has_prepared_shape());
    }

    // --- abort path ---
    {
        Pair p;
        ASSERT_TRUE(p.established());
        PreparedShape pc, psh;
        ASSERT_TRUE(p.cli->shaper_peek_prepared(pc));
        ASSERT_TRUE(p.srv->shaper_peek_prepared(psh));

        ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
                  TransitionError::NONE);
        // Deliver PREPARE so the responder is engaged, then abort locally
        // BEFORE activation.
        ASSERT_TRUE(p.cli->has_outbound());
        auto prep = p.cli->next_outbound();
        ASSERT_TRUE(prep.has_value());
        p.deliver(*p.srv, prep->bytes);
        ASSERT_TRUE(p.srv->has_outbound());  // READY queued

        ASSERT_TRUE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
        EXPECT_FALSE(p.cli->shaper_has_prepared_shape())
            << "abort did not cancel the initiator's prepared shape";
        EXPECT_EQ(p.cli->shaper_epoch(), 0u);
        EXPECT_EQ(p.cli->stats().profile_epoch, 0u);
        EXPECT_EQ(p.cli->stats().active_profile.id, kBaselineId);

        p.pump();  // deliver ABORT (and the stale READY) both ways
        p.advance(2000);
        p.pump();

        EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(p.srv->stats().profile_epoch, 0u);
        EXPECT_EQ(p.srv->stats().active_profile.id, kBaselineId);
        EXPECT_FALSE(p.srv->shaper_has_prepared_shape())
            << "peer abort did not cancel the responder's prepared shape";
        EXPECT_EQ(p.srv->stats().transition_counters.transitions_aborted, 1u);

        // No switch happened; the stable wire form continues to work.
        EXPECT_TRUE(p.send_cli_deliver(Pair::app_payload(1, 64)));
        EXPECT_EQ(p.cli->stats().transition_counters.tx_data_new, 0u);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Datagram/MTU budget: oversized payloads are refused and counted, never
// silently truncated; conforming datagrams respect the budget byte-exactly.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, MtuBudgetEnforced) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    // Pre-check: above the configured application payload cap.
    EXPECT_FALSE(p.cli->send_application(
                     Pair::app_payload(1, 1025), p.now).has_value());
    EXPECT_EQ(p.cli->stats().mtu_budget_rejections, 1u);

    // Post-encode budget: tighten the path MTU so the encoded datagram
    // (kind + outer + E2E + NCP + PD overhead) no longer fits.
    Pair tight;
    // Rebuild with a small path MTU.
    {
        const auto* desc = tight.cat.baseline();
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.catalog = &tight.cat.catalog;
        base.mimic_config.wire_version = 3;
        base.path_mtu_bytes = 200;
        base.porthop_overhead_bytes = 20;
        base.max_application_payload = 1024;
        base.transition_config.grace_period_ms = 1000;
        auto cc = base; cc.role = NcpMimicrySession::Role::Client;
        auto sc = base; sc.role = NcpMimicrySession::Role::Server;
        tight.cli.reset(new NcpMimicrySession(cc));
        tight.srv.reset(new NcpMimicrySession(sc));
    }
    {
        auto hs = tight.cli->start_handshake();
        ASSERT_TRUE(hs.has_value());
        tight.deliver(*tight.srv, hs->bytes);
        ASSERT_TRUE(tight.established());
    }
    const size_t budget = tight.cli->max_datagram_bytes();
    ASSERT_EQ(budget, 180u);  // path 200 - actual 20-byte PH reservation

    // Small payload fits and is delivered; every emitted byte accounted for.
    auto ok = tight.cli->send_application(Pair::app_payload(1, 16), tight.now);
    ASSERT_TRUE(ok.has_value());
    EXPECT_LE(ok->bytes.size(), budget);
    EXPECT_TRUE(tight.deliver(*tight.srv, ok->bytes).app_payload.has_value());

    // A larger payload passes the pre-check but exceeds the encoded budget.
    const auto before = tight.cli->stats().mtu_budget_rejections;
    EXPECT_FALSE(tight.cli->send_application(
                     Pair::app_payload(2, 128), tight.now).has_value());
    EXPECT_EQ(tight.cli->stats().mtu_budget_rejections, before + 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// E2E crypto-epoch asymmetry (review repro t2/t5): e2e.cpp bumps
// crypto_epoch at rotate_keys() AND at commit_dh_step(), so the rotation
// initiator gains +2 per completed cycle and the responder +1 — the gap
// never shrinks. Crypto-epoch fences are PEER-epoch-relative, so transitions
// complete regardless of the gap, led by either endpoint.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, EpochGapAfterRekeysTransitionCompletes) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    // 8 full rotation cycles (rotate -> initiator data -> answering data):
    // the initiator's epoch advances twice per cycle, the responder's once.
    for (int i = 0; i < 8; ++i) {
        ASSERT_TRUE(p.cli->rotate_e2e_keys()) << "cycle " << i;
        ASSERT_TRUE(p.send_cli_deliver(Pair::app_payload(10 + i, 64)));
        ASSERT_TRUE(p.send_srv_deliver(Pair::app_payload(20 + i, 64)));
    }
    const uint64_t cli_epoch = p.cli->stats().crypto_epoch;
    const uint64_t srv_epoch = p.srv->stats().crypto_epoch;
    ASSERT_GT(cli_epoch, srv_epoch);
    ASSERT_GE(cli_epoch - srv_epoch, 6u)
        << "epoch gap did not exceed the retransmit budget";

    // Initiator-led transition MUST complete on a lossless link despite the
    // gap (the responder's READY carries its lower epoch; peer-epoch fencing
    // binds it instead of rejecting it against the local epoch).
    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().profile_epoch, 1u);
    EXPECT_EQ(p.srv->stats().profile_epoch, 1u);
    EXPECT_EQ(p.cli->stats().active_profile.id, kTargetId);
    EXPECT_EQ(p.srv->stats().active_profile.id, kTargetId);

    // Immediately afterwards, a transition led by the E2E RESPONDER (the
    // epoch-trailing endpoint) MUST also complete: the cross-transition
    // PREPARE fence tracks the peer's last completed epoch, not the local
    // one.
    ASSERT_EQ(p.srv->start_profile_transition(kBaselineId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.advance(2000);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(p.cli->stats().profile_epoch, 2u);
    EXPECT_EQ(p.srv->stats().profile_epoch, 2u);
    EXPECT_EQ(p.cli->stats().active_profile.id, kBaselineId);
    EXPECT_EQ(p.srv->stats().active_profile.id, kBaselineId);
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 2u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 2u);

    // The stream still works on the re-established baseline profile.
    EXPECT_TRUE(p.send_cli_deliver(Pair::app_payload(100, 64)));
    EXPECT_TRUE(p.send_srv_deliver(Pair::app_payload(101, 64)));
}

// ══════════════════════════════════════════════════════════════════════════════
// Fail-fast for non-generic transition target masks (review repro t3). The
// outer mask swaps synchronously at local activation; only the
// length-prefix-compatible generic masks (GENERIC_UDP / GENERIC_TCP) keep
// the follow-up COMMIT/CONFIRM decodable at the peer. A non-generic target
// (e.g. DNS_QUERY) is rejected up front — never entered, never diverged.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, NonGenericTargetMaskRejected) {
    ensure_init();

    // ---- initiator-side fail-fast: both overloads ----
    {
        Pair p;
        p.PairInit(/*cli_legacy=*/false, /*insecure_plaintext=*/false,
                   /*target_mimic_dns=*/true);  // resolver: target -> DNS_QUERY
        ASSERT_TRUE(p.established());
        ASSERT_TRUE(p.cli->transition_capable());

        const auto c0 = p.cli->stats();
        const auto s0 = p.srv->stats();

        // Catalog overload: the resolver maps the target to DNS_QUERY.
        EXPECT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
                  TransitionError::INVALID_PROFILE);

        // Explicit overload with a non-generic target mask.
        const auto* d = p.cat.catalog.find(kTargetId, 1);
        ASSERT_NE(d, nullptr);
        EXPECT_EQ(p.cli->start_profile_transition(
                      profile_ref_from_descriptor(*d),
                      profile_layout_from_descriptor(*d),
                      TrafficMimicry::MimicProfile::DNS_QUERY, p.now),
                  TransitionError::INVALID_PROFILE);

        // NO state change, NO control traffic, no transition counters moved.
        const auto c1 = p.cli->stats();
        EXPECT_EQ(c1.transition_state, ProfileTransitionState::IDLE);
        EXPECT_FALSE(c1.pending_profile.has_value());
        EXPECT_FALSE(c1.pending_mimic.has_value());
        EXPECT_EQ(c1.profile_epoch, 0u);
        EXPECT_EQ(c1.active_profile.id, kBaselineId);
        EXPECT_EQ(c1.active_mimic, TrafficMimicry::MimicProfile::GENERIC_UDP);
        EXPECT_EQ(c1.transition_counters.transitions_started, 0u);
        EXPECT_EQ(c1.transition_counters.control_tx,
                  c0.transition_counters.control_tx);
        EXPECT_FALSE(p.cli->has_outbound());
        p.pump();
        EXPECT_EQ(p.srv->stats().transition_counters.control_rx,
                  s0.transition_counters.control_rx)
            << "rejected transition emitted control traffic";
        EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);

        // Positive control inside the same session: the explicit overload
        // with a GENERIC target mask is accepted (the gate is mask-specific).
        ASSERT_EQ(p.cli->start_profile_transition(
                      profile_ref_from_descriptor(*d),
                      profile_layout_from_descriptor(*d),
                      TrafficMimicry::MimicProfile::GENERIC_TCP, p.now),
                  TransitionError::NONE);
        EXPECT_EQ(p.cli->stats().transition_state,
                  ProfileTransitionState::PREPARE);
        // Roll back pre-activation; the peer refused it anyway (its resolver
        // maps the target to DNS_QUERY — covered by the responder case below).
        ASSERT_TRUE(p.cli->abort_transition(AbortReason::LOCAL_REQUEST, p.now));
        p.pump();
        p.advance(2000);
        p.pump();
        EXPECT_EQ(p.cli->stats().transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(p.srv->stats().transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(p.cli->stats().profile_epoch, 0u);
        EXPECT_EQ(p.srv->stats().profile_epoch, 0u);
        EXPECT_EQ(p.cli->stats().active_mimic,
                  TrafficMimicry::MimicProfile::GENERIC_UDP);
        EXPECT_EQ(p.srv->stats().active_mimic,
                  TrafficMimicry::MimicProfile::GENERIC_UDP);
    }

    // ---- responder-side refusal: PREPARE for a non-generic target is
    // refused with ABORT(UNKNOWN_PROFILE) before READY ----
    {
        Pair p;
        // Rebuild with ASYMMETRIC resolvers: the client resolves the target
        // to a generic mask (so it emits PREPARE), the server resolves the
        // same target to DNS_QUERY (undecodable at the mask switch).
        const auto* desc = p.cat.baseline();
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.catalog = &p.cat.catalog;
        base.mimic_config.profile = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_config.min_padding = kTcpPadding;
        base.mimic_config.max_padding = kTcpPadding;
        base.advertise_profile_transition_v2 = false;  // v1 gate under test
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1000;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.mimic_resolver = [](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            if (r.id == kBaselineId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            if (r.id == kTargetId)
                return TrafficMimicry::MimicProfile::GENERIC_TCP;
            return std::nullopt;
        };
        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        sc.mimic_resolver = [](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            if (r.id == kBaselineId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            if (r.id == kTargetId)
                return TrafficMimicry::MimicProfile::DNS_QUERY;
            return std::nullopt;
        };
        p.cli.reset(new NcpMimicrySession(cc));
        p.srv.reset(new NcpMimicrySession(sc));
        ASSERT_TRUE(p.established());

        ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
                  TransitionError::NONE);
        EXPECT_EQ(p.cli->stats().transition_state,
                  ProfileTransitionState::PREPARE);
        p.pump();  // PREPARE -> refusal ABORT -> initiator rollback

        // The responder never entered READY: clean refusal, no activation.
        const auto s = p.srv->stats();
        EXPECT_EQ(s.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(s.transition_counters.transitions_committed, 0u);
        EXPECT_EQ(s.transition_counters.transitions_effective, 0u);
        EXPECT_EQ(s.transition_counters.transitions_aborted, 1u)
            << "the refusal was not recorded as a clean pre-activation abort";
        EXPECT_GE(s.transition_counters.control_tx, 1u)
            << "responder never emitted the refusal ABORT";
        EXPECT_FALSE(s.pending_profile.has_value());
        EXPECT_FALSE(s.pending_mimic.has_value());
        EXPECT_EQ(s.profile_epoch, 0u);
        EXPECT_EQ(s.active_profile.id, kBaselineId);
        EXPECT_EQ(s.active_mimic, TrafficMimicry::MimicProfile::GENERIC_UDP);

        // The initiator rolled back on the ABORT; no divergence.
        const auto c = p.cli->stats();
        EXPECT_EQ(c.transition_state, ProfileTransitionState::IDLE);
        EXPECT_EQ(c.transition_counters.transitions_committed, 0u);
        EXPECT_EQ(c.transition_counters.transitions_effective, 0u);
        EXPECT_EQ(c.profile_epoch, 0u);
        EXPECT_EQ(c.active_profile.id, kBaselineId);
        EXPECT_EQ(c.active_mimic, TrafficMimicry::MimicProfile::GENERIC_UDP);

        // The session is fully usable afterwards; a generic target switches.
        EXPECT_TRUE(p.send_cli_deliver(Pair::app_payload(1, 64)));
        const auto* d = p.cat.catalog.find(kTargetId, 1);
        ASSERT_NE(d, nullptr);
        ASSERT_EQ(p.cli->start_profile_transition(
                      profile_ref_from_descriptor(*d),
                      profile_layout_from_descriptor(*d),
                      TrafficMimicry::MimicProfile::GENERIC_TCP, p.now),
                  TransitionError::NONE);
        // The server still refuses (ITS resolver says DNS_QUERY): consistent
        // refusal, still no divergence.
        p.pump();
        p.advance(2000);
        p.pump();
        EXPECT_EQ(p.cli->stats().profile_epoch, 0u);
        EXPECT_EQ(p.srv->stats().profile_epoch, 0u);
        EXPECT_TRUE(p.send_cli_deliver(Pair::app_payload(2, 64)));
        EXPECT_TRUE(p.send_srv_deliver(Pair::app_payload(3, 64)));
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Transition protocol v2 — capability bit (step 1): roundtrip through the
// wire codec, strict AND semantics via negotiate(), fail-closed on a
// stripped bit, and v2-without-v1 treated as v1 (malformed advertisement).
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicrySession, V2CapabilityBitRoundtripAndSemantics) {
    ensure_init();

    // Default: bit clear, helper agrees.
    NCPCapabilities caps;
    EXPECT_FALSE(capabilities_support_profile_transition_v2(caps));

    // Set/clear is additive: only reserved[0] bit 0x02 moves.
    capabilities_set_profile_transition(caps, true);
    capabilities_set_profile_transition_v2(caps, true);
    EXPECT_TRUE(capabilities_support_profile_transition(caps));
    EXPECT_TRUE(capabilities_support_profile_transition_v2(caps));
    EXPECT_EQ(caps.reserved[0],
              NCP_CAPS_FEATURE_PROFILE_TRANSITION_V1 |
                  NCP_CAPS_FEATURE_PROFILE_TRANSITION_V2);
    capabilities_set_profile_transition_v2(caps, false);
    EXPECT_FALSE(capabilities_support_profile_transition_v2(caps));
    EXPECT_TRUE(capabilities_support_profile_transition(caps));
    EXPECT_EQ(caps.reserved[0], NCP_CAPS_FEATURE_PROFILE_TRANSITION_V1);
    capabilities_set_profile_transition_v2(caps, true);

    // Wire roundtrip preserves both bits (and only those bits).
    auto wire = caps.serialize();
    auto parsed = NCPCapabilities::deserialize(wire);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(capabilities_support_profile_transition(*parsed));
    EXPECT_TRUE(capabilities_support_profile_transition_v2(*parsed));
    EXPECT_EQ(parsed->reserved[0], caps.reserved[0]);

    // Strict AND via negotiate(): both v1+v2 → v2 negotiated.
    NCPCapabilities peer;
    capabilities_set_profile_transition(peer, true);
    capabilities_set_profile_transition_v2(peer, true);
    auto n = negotiate(caps, peer);
    EXPECT_TRUE(negotiated_support_profile_transition(n));
    EXPECT_TRUE(negotiated_support_profile_transition_v2(n));
    EXPECT_TRUE(negotiated_support_profile_transition_v2(caps, peer));

    // Stripped v2 bit on one side → v1 still negotiated, v2 NOT
    // (fail-closed downgrade, never a behavioural mismatch).
    NCPCapabilities stripped = peer;
    capabilities_set_profile_transition_v2(stripped, false);
    auto n2 = negotiate(caps, stripped);
    EXPECT_TRUE(negotiated_support_profile_transition(n2));
    EXPECT_FALSE(negotiated_support_profile_transition_v2(n2));
    EXPECT_FALSE(negotiated_support_profile_transition_v2(caps, stripped));

    // v2 advertised WITHOUT v1 is malformed: treated as v1-only — and with
    // v1 also missing that means no v2 and no v1 feature at all.
    NCPCapabilities malformed;
    capabilities_set_profile_transition_v2(malformed, true);
    auto n3 = negotiate(caps, malformed);
    EXPECT_TRUE(capabilities_support_profile_transition_v2(malformed))
        << "raw bit helper must reflect the wire bit";
    EXPECT_FALSE(negotiated_support_profile_transition_v2(n3));
    EXPECT_FALSE(negotiated_support_profile_transition_v2(caps, malformed));
    EXPECT_FALSE(negotiated_support_profile_transition(n3));
}

// ══════════════════════════════════════════════════════════════════════════════
// Session-level v2 negotiation: default config negotiates v2; a stripped
// (unadvertised) bit fails closed to v1 on BOTH sides; advertising v2
// without v1 is treated as v1-only. Stats surface the outcome.
// ══════════════════════════════════════════════════════════════════════════════

namespace {

/// Pair variant with per-side v2 advertisement control (the shared Pair
/// fixture pins v1 to keep the pre-existing tests in the v1 world).
struct PairV2Caps {
    TestCatalog cat;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;

    PairV2Caps(bool cli_v1, bool cli_v2, bool srv_v1, bool srv_v2) {
        const auto* desc = cat.baseline();
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.catalog = &cat.catalog;
        base.mimic_config.profile = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_resolver = [](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            if (r.id == kBaselineId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            if (r.id == kTargetId)
                return TrafficMimicry::MimicProfile::GENERIC_TCP;
            return std::nullopt;
        };
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1500;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.advertise_profile_transition = cli_v1;
        cc.advertise_profile_transition_v2 = cli_v2;
        cli.reset(new NcpMimicrySession(cc));

        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        sc.advertise_profile_transition = srv_v1;
        sc.advertise_profile_transition_v2 = srv_v2;
        srv.reset(new NcpMimicrySession(sc));
    }

    NcpMimicrySession::IngressResult deliver(NcpMimicrySession& to,
                                             const std::vector<uint8_t>& d) {
        return to.on_datagram(d, now);
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
};

} // namespace

TEST(MimicrySession, V2NegotiationDefaultOnBothSides) {
    ensure_init();
    PairV2Caps p(/*cli_v1=*/true, /*cli_v2=*/true,
                 /*srv_v1=*/true, /*srv_v2=*/true);
    auto hs = p.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    p.deliver(*p.srv, hs->bytes);
    ASSERT_TRUE(p.established());
    EXPECT_TRUE(p.cli->transition_capable());
    EXPECT_TRUE(p.srv->transition_capable());
    EXPECT_TRUE(p.cli->stats().transition_v2_capable);
    EXPECT_TRUE(p.srv->stats().transition_v2_capable);
}

TEST(MimicrySession, V2StrippedBitFailsClosedToV1) {
    ensure_init();
    // The server does not advertise v2 (equivalent to a middlebox stripping
    // the unknown bit): both sides must negotiate v1-only.
    PairV2Caps p(/*cli_v1=*/true, /*cli_v2=*/true,
                 /*srv_v1=*/true, /*srv_v2=*/false);
    auto hs = p.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    p.deliver(*p.srv, hs->bytes);
    ASSERT_TRUE(p.established());
    EXPECT_TRUE(p.cli->transition_capable());
    EXPECT_TRUE(p.srv->transition_capable());
    EXPECT_FALSE(p.cli->stats().transition_v2_capable)
        << "client kept v2 despite the peer not advertising it";
    EXPECT_FALSE(p.srv->stats().transition_v2_capable);

    // v1 behavior stays fully functional: a generic target transitions.
    ASSERT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NONE);
    p.pump();
    p.now += 2000;
    p.cli->tick(p.now);
    p.srv->tick(p.now);
    p.pump();
    EXPECT_EQ(p.cli->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.srv->stats().transition_counters.transitions_effective, 1u);
    EXPECT_EQ(p.cli->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_TCP);
}

TEST(MimicrySession, V2WithoutV1TreatedAsV1) {
    ensure_init();
    // Malformed advertisement: v2 bit set, v1 bit clear. The peer must
    // treat it as v1-only (which here means: legacy, no transitions).
    PairV2Caps p(/*cli_v1=*/false, /*cli_v2=*/true,
                 /*srv_v1=*/true, /*srv_v2=*/true);
    auto hs = p.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    p.deliver(*p.srv, hs->bytes);
    ASSERT_TRUE(p.established());
    EXPECT_FALSE(p.cli->transition_capable());
    EXPECT_FALSE(p.srv->transition_capable());
    EXPECT_FALSE(p.cli->stats().transition_v2_capable);
    EXPECT_FALSE(p.srv->stats().transition_v2_capable)
        << "v2 negotiated despite the peer's missing v1 bit";

    // Legacy wire: hot-switch refused, no transition control emitted.
    EXPECT_EQ(p.cli->start_profile_transition(kTargetId, 1, p.now),
              TransitionError::NOT_SUPPORTED);
    EXPECT_FALSE(p.cli->has_outbound());
}

// ══════════════════════════════════════════════════════════════════════════════
// Session mask key (step 3): HKDF("ncp-mimicry-session/mask-v1") from the E2E
// shared secret. Both endpoints of a session derive the identical key —
// observable as the identical session-stable QUIC_SHORT_HEADER DCID — and
// different sessions derive different keys. Generic masks ignore the key
// entirely (the stable GENERIC_UDP wire form is unchanged).
// ══════════════════════════════════════════════════════════════════════════════

namespace {

/// Pair whose target profile resolves to the session-bound
/// QUIC_SHORT_HEADER mask (v2 negotiated by default config).
struct PairQuicTarget {
    TestCatalog cat;
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1'000'000;
    std::vector<std::vector<uint8_t>> cli_app;
    std::vector<std::vector<uint8_t>> srv_app;

    PairQuicTarget() {
        const auto* desc = cat.baseline();
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = false;
        base.stable_profile = profile_ref_from_descriptor(*desc);
        base.stable_layout = profile_layout_from_descriptor(*desc);
        base.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.catalog = &cat.catalog;
        base.mimic_config.profile = TrafficMimicry::MimicProfile::GENERIC_UDP;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_timing_mimicry = false;
        base.mimic_resolver = [](const ProfileRef& r)
            -> std::optional<TrafficMimicry::MimicProfile> {
            if (r.id == kBaselineId)
                return TrafficMimicry::MimicProfile::GENERIC_UDP;
            if (r.id == kTargetId)
                return TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER;
            return std::nullopt;
        };
        base.transition_config.retransmit_interval_ms = 50;
        base.transition_config.max_retransmit_attempts = 6;
        base.transition_config.grace_period_ms = 1500;

        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cli.reset(new NcpMimicrySession(cc));
        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        srv.reset(new NcpMimicrySession(sc));
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

    /// Run the GENERIC_UDP → QUIC_SHORT_HEADER transition to completion.
    void transition_to_quic() {
        ASSERT_EQ(cli->start_profile_transition(kTargetId, 1, now),
                  TransitionError::NONE);
        pump();
        now += 2000;
        cli->tick(now);
        srv->tick(now);
        pump();
        ASSERT_EQ(cli->stats().transition_counters.transitions_effective, 1u);
        ASSERT_EQ(srv->stats().transition_counters.transitions_effective, 1u);
        ASSERT_EQ(cli->stats().active_mimic,
                  TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
        ASSERT_EQ(srv->stats().active_mimic,
                  TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    }
};

/// Extract the session-stable DCID from a QUIC_SHORT_HEADER datagram:
/// [kind:1][first:1][dcid:8]...
std::array<uint8_t, 8> wire_dcid(const std::vector<uint8_t>& d) {
    std::array<uint8_t, 8> dcid{};
    EXPECT_EQ(d[0], 'E');
    EXPECT_EQ(d[1] & 0x80, 0) << "not a QUIC short-header datagram";
    EXPECT_NE(d[1] & 0x40, 0) << "QUIC fixed bit clear";
    std::memcpy(dcid.data(), d.data() + 2, 8);
    return dcid;
}

} // namespace

TEST(MimicrySession, SessionMaskKeyDeterminism) {
    ensure_init();
    PairQuicTarget a;
    auto hs = a.cli->start_handshake();
    ASSERT_TRUE(hs.has_value());
    a.deliver(*a.srv, hs->bytes);
    ASSERT_TRUE(a.established());
    ASSERT_TRUE(a.cli->stats().transition_v2_capable);
    ASSERT_TRUE(a.srv->stats().transition_v2_capable);

    // Generic masks ignore the key: the stable-profile wire form is the
    // unchanged 4-byte-length-prefix GENERIC_UDP envelope.
    {
        auto o = a.cli->send_application(Pair::app_payload(1, 64), a.now);
        ASSERT_TRUE(o.has_value());
        const auto& d = o->bytes;
        ASSERT_GT(d.size(), 5u);
        const uint32_t l = (static_cast<uint32_t>(d[1]) << 24) |
                           (static_cast<uint32_t>(d[2]) << 16) |
                           (static_cast<uint32_t>(d[3]) << 8) | d[4];
        EXPECT_EQ(5u + l, d.size()) << "stable GENERIC_UDP wire form changed";
        a.deliver(*a.srv, d);
    }

    a.transition_to_quic();

    // Both endpoints of the SAME session emit the same session-stable DCID
    // → identical derived mask keys (HKDF over the same shared secret).
    auto oc = a.cli->send_application(Pair::app_payload(2, 64), a.now);
    auto os = a.srv->send_application(Pair::app_payload(3, 64), a.now);
    ASSERT_TRUE(oc.has_value());
    ASSERT_TRUE(os.has_value());
    const auto dcid_c = wire_dcid(oc->bytes);
    const auto dcid_s = wire_dcid(os->bytes);
    EXPECT_EQ(dcid_c, dcid_s)
        << "endpoints of one session derived different mask keys";
    // The DCID is stable across datagrams (connection continuity).
    auto oc2 = a.cli->send_application(Pair::app_payload(4, 64), a.now);
    ASSERT_TRUE(oc2.has_value());
    EXPECT_EQ(wire_dcid(oc2->bytes), dcid_c) << "DCID not session-stable";

    // Both directions decode (mask keys actually usable both ways).
    a.deliver(*a.srv, oc->bytes);
    a.deliver(*a.cli, os->bytes);
    ASSERT_EQ(a.srv_app.size(), 2u);
    ASSERT_EQ(a.cli_app.size(), 1u);
    EXPECT_EQ(a.srv_app.back(), Pair::app_payload(2, 64));
    EXPECT_EQ(a.cli_app.back(), Pair::app_payload(3, 64));

    // A DIFFERENT session derives a different key → different DCID.
    PairQuicTarget b;
    auto hs2 = b.cli->start_handshake();
    ASSERT_TRUE(hs2.has_value());
    b.deliver(*b.srv, hs2->bytes);
    ASSERT_TRUE(b.established());
    b.transition_to_quic();
    auto ob = b.cli->send_application(Pair::app_payload(5, 64), b.now);
    ASSERT_TRUE(ob.has_value());
    EXPECT_NE(wire_dcid(ob->bytes), dcid_c)
        << "distinct sessions share the QUIC_SHORT_HEADER DCID";

    // Cross-session forgery fails closed: session A's QUIC datagram is
    // dropped by session B (wrong session key → DCID mismatch at the mask
    // layer, before any E2E AEAD attempt).
    const auto b_before = b.srv->stats();
    auto forged = oc->bytes;
    EXPECT_EQ(b.deliver(*b.srv, forged).kind,
              NcpMimicrySession::IngressKind::Dropped);
    EXPECT_EQ(b.srv->stats().e2e_messages_received,
              b_before.e2e_messages_received)
        << "cross-session datagram reached the E2E layer";
    EXPECT_EQ(b.srv_app.size(), 0u);
}
