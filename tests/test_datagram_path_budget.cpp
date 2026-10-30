#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

#include "ncp_mimicry_session.hpp"

namespace ncp {
namespace {

struct SessionPair {
    std::unique_ptr<NcpMimicrySession> cli;
    std::unique_ptr<NcpMimicrySession> srv;
    uint64_t now = 1000;

    explicit SessionPair(bool legacy_client = false,
                         bool e2e_padding = false,
                         uint32_t pd_block = 0,
                         TrafficMimicry::MimicProfile mimic =
                             TrafficMimicry::MimicProfile::GENERIC_UDP) {
        NcpMimicrySession::Config base;
        base.e2e_config.enable_padding = e2e_padding;
        base.stable_layout.padding_block_bytes = pd_block;
        base.stable_mimic = mimic;
        base.mimic_config.profile = mimic;
        base.mimic_config.wire_version = 3;
        base.mimic_config.enable_size_mimicry = false;
        base.max_application_payload = 4096;
        base.path_mtu_bytes = 1500;
        base.porthop_overhead_bytes = 20;
        auto cc = base;
        cc.role = NcpMimicrySession::Role::Client;
        cc.advertise_profile_transition = !legacy_client;
        cli = std::make_unique<NcpMimicrySession>(cc);
        auto sc = base;
        sc.role = NcpMimicrySession::Role::Server;
        srv = std::make_unique<NcpMimicrySession>(sc);

        auto hs = cli->start_handshake();
        if (!hs) throw std::runtime_error("handshake did not start");
        (void)srv->on_datagram(hs->bytes, now);
        pump();
        if (!cli->is_established() || !srv->is_established())
            throw std::runtime_error("handshake did not complete");
    }

    void pump() {
        for (int i = 0; i < 32; ++i) {
            bool progress = false;
            while (auto o = srv->next_outbound()) {
                (void)cli->on_datagram(o->bytes, now);
                progress = true;
            }
            while (auto o = cli->next_outbound()) {
                (void)srv->on_datagram(o->bytes, now);
                progress = true;
            }
            if (!progress) return;
        }
        ADD_FAILURE() << "session pump did not quiesce";
    }

    PathState direct_ipv4() const {
        PathState p;
        p.effective_mtu = 1500;
        p.ip_version = PathIpVersion::IPv4;
        p.outer_transport = OuterTransportKind::Direct;
        p.hop_policy = PathHopPolicy::LegacyPortHop;
        return p;
    }
};

std::vector<uint8_t> payload(size_t n) {
    std::vector<uint8_t> p(n);
    for (size_t i = 0; i < n; ++i) p[i] = static_cast<uint8_t>(i * 17);
    return p;
}

TEST(DatagramPathBudget, ConfigRejectsPortHopUnderReservation) {
    NcpMimicrySession::Config c;
    EXPECT_EQ(c.porthop_overhead_bytes, 20u);
    c.porthop_overhead_bytes = 19;
    EXPECT_THROW(NcpMimicrySession{c}, std::invalid_argument);

    NcpMimicrySession::Config padding;
    padding.porthop_overhead_bytes = 20;
    padding.porthop_padding_headroom_bytes = 1;
    EXPECT_THROW(NcpMimicrySession{padding}, std::invalid_argument);
    padding.porthop_overhead_bytes = 21;
    EXPECT_NO_THROW(NcpMimicrySession{padding});
}

TEST(DatagramPathBudget, DirectIPv4ExactBoundaryAndLegacyWireSize) {
    SessionPair p;
    const auto path = p.direct_ipv4();
    // 1500 - IPv4/UDP 28 - PH 20 - kind 1 - generic 4 - E2E 93 - NCP/PD 13
    constexpr size_t kB = 1341;
    EXPECT_EQ(p.cli->max_application_datagram(path), kB);
    EXPECT_TRUE(p.cli->update_path_state(path));

    auto before = p.cli->stats().mtu_budget_rejections;
    auto bminus = p.cli->send_application(payload(kB - 1), p.now);
    auto b = p.cli->send_application(payload(kB), p.now);
    ASSERT_TRUE(bminus);
    ASSERT_TRUE(b);
    EXPECT_EQ(b->bytes.size(), 1452u);  // + PH20 + IP/UDP28 == path MTU1500
    EXPECT_FALSE(p.cli->send_application(payload(kB + 1), p.now));
    EXPECT_EQ(p.cli->stats().mtu_budget_rejections, before + 1);
    EXPECT_EQ(p.cli->max_datagram_bytes(), 1480u);
}

TEST(DatagramPathBudget, LegacyPeerKeepsByteExactRawProtectedWire) {
    SessionPair p(true);
    const auto path = p.direct_ipv4();
    constexpr size_t kB = 1354;  // no NCP/PD 13 on a legacy peer
    EXPECT_EQ(p.cli->max_application_datagram(path), kB);
    auto o = p.cli->send_application(payload(100), p.now);
    ASSERT_TRUE(o);
    EXPECT_EQ(o->bytes.size(), 100u + 93u + 4u + 1u);
}

TEST(DatagramPathBudget, IPv6TurnAndUnknownMtuFailSafe) {
    SessionPair p;
    auto path = p.direct_ipv4();
    path.ip_version = PathIpVersion::IPv6;
    EXPECT_EQ(p.cli->max_application_datagram(path), 1321u);

    path.outer_transport = OuterTransportKind::TurnChannelData;
    EXPECT_EQ(p.cli->max_application_datagram(path), 1317u);
    path.turn_channeldata_padding = true;
    EXPECT_EQ(p.cli->max_application_datagram(path), 1314u);

    path.effective_mtu = 0;
    EXPECT_EQ(p.cli->max_application_datagram(path), 1094u);

    path.outer_transport = OuterTransportKind::TurnSendData;
    EXPECT_EQ(p.cli->max_application_datagram(path), 0u);
    EXPECT_FALSE(p.cli->update_path_state(path));
    path.turn_send_data_bootstrap = true;
    EXPECT_GT(p.cli->max_application_datagram(path), 0u);
}

TEST(DatagramPathBudget, E2eAndPdPaddingBoundary) {
    SessionPair p(false, true, 16);
    const auto path = p.direct_ipv4();
    const size_t b = p.cli->max_application_datagram(path);
    // At this boundary: PD rounds 9+B to 16, NCP adds 4, E2E adds its
    // mandatory marker and rounds to 128, serialization adds 93.
    EXPECT_EQ(b, 1255u);
    EXPECT_TRUE(p.cli->update_path_state(path));
    EXPECT_TRUE(p.cli->send_application(payload(b - 1), p.now));
    auto exact = p.cli->send_application(payload(b), p.now);
    ASSERT_TRUE(exact);
    EXPECT_LE(exact->bytes.size() + 20 + 28, 1500u);
    EXPECT_EQ(exact->bytes.size() + 20 + 28, 1426u);
    EXPECT_FALSE(p.cli->send_application(payload(b + 1), p.now));
}

TEST(DatagramPathBudget, IcmpPtbOnlyLowersAndNeverRaises) {
    SessionPair p;
    ASSERT_TRUE(p.cli->update_path_state(p.direct_ipv4()));
    EXPECT_FALSE(p.cli->apply_icmp_packet_too_big(1600));
    EXPECT_FALSE(p.cli->apply_icmp_packet_too_big(1500));
    EXPECT_FALSE(p.cli->apply_icmp_packet_too_big(0));
    EXPECT_TRUE(p.cli->apply_icmp_packet_too_big(1400));
    EXPECT_EQ(p.cli->path_state().effective_mtu, 1400u);
    EXPECT_EQ(p.cli->max_application_datagram(p.cli->path_state()), 1241u);
    EXPECT_FALSE(p.cli->apply_icmp_packet_too_big(1450));
    EXPECT_EQ(p.cli->path_state().effective_mtu, 1400u);

    auto v6 = p.direct_ipv4();
    v6.ip_version = PathIpVersion::IPv6;
    ASSERT_TRUE(p.cli->update_path_state(v6));
    EXPECT_FALSE(p.cli->apply_icmp_packet_too_big(1279));
    EXPECT_TRUE(p.cli->apply_icmp_packet_too_big(1280));
    EXPECT_EQ(p.cli->path_state().effective_mtu, 1280u);
}

TEST(DatagramPathBudget, StatefulMaskBoundsAndQuicInitialFloor) {
    SessionPair short_pair(false, false, 0,
                           TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    auto path = short_pair.direct_ipv4();
    // 1341 - (62 - 4) additional mask overhead.
    EXPECT_EQ(short_pair.cli->max_application_datagram(path), 1283u);

    SessionPair stun_pair(false, false, 0,
                          TrafficMimicry::MimicProfile::STUN_MESSAGE);
    // Worst-case STUN alignment is three bytes; declared total overhead 56.
    EXPECT_EQ(stun_pair.cli->max_application_datagram(path), 1289u);

    SessionPair initial_pair(false, false, 0,
                             TrafficMimicry::MimicProfile::QUIC_INITIAL);
    path.effective_mtu = 1200;
    EXPECT_EQ(initial_pair.cli->max_application_datagram(path), 0u);
    path.effective_mtu = 1248;  // 1200 floor + kind + PH + IPv4/UDP - 1
    EXPECT_EQ(initial_pair.cli->max_application_datagram(path), 0u);
    path.effective_mtu = 1249;
    EXPECT_GT(initial_pair.cli->max_application_datagram(path), 0u);
}

TEST(DatagramPathBudget, DisabledHopAndGenericTcpPaddingAreCharged) {
    NcpMimicrySession::Config c;
    c.porthop_overhead_bytes = 20;
    NcpMimicrySession s(c);
    auto p = s.path_state();
    p.hop_policy = PathHopPolicy::Disabled;
    EXPECT_TRUE(s.update_path_state(p));
    EXPECT_EQ(s.max_application_datagram(p), 1024u);
    p.porthop_padding_headroom = 1;
    EXPECT_FALSE(s.update_path_state(p));

    SessionPair tcp(false, false, 0,
                    TrafficMimicry::MimicProfile::GENERIC_TCP);
    // Size mimicry disabled in the pair: same exact 4-byte generic prefix.
    EXPECT_EQ(tcp.cli->max_application_datagram(tcp.direct_ipv4()), 1341u);
}

}  // namespace
}  // namespace ncp
