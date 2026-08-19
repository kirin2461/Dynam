/**
 * @file test_fog.cpp
 * @brief gtest suite for ncp_fog (M7) — Cooperative Fog Mesh relay.
 */

#include <gtest/gtest.h>
#include "ncp_fog.hpp"

#include <chrono>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace ncp;

namespace {

uint64_t now_sec() {
    return static_cast<uint64_t>(
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

constexpr uint32_t kLoopback = 0x7F000001; // 127.0.0.1
constexpr uint16_t kPortA = 46300;
constexpr uint16_t kPortB = 46301;
constexpr uint16_t kPortC = 46302;
constexpr uint16_t kPortD = 46303;
constexpr uint16_t kPortE = 46304;

FogPeerInfo make_peer(const FogPeerId& id, uint16_t port, double trust = 0.5,
                      uint64_t seen = 0) {
    FogPeerInfo p;
    p.id = id;
    p.ipv4 = kLoopback;
    p.port = port;
    p.trust_score = trust;
    p.last_seen = seen;
    return p;
}

// Send raw bytes via a throwaway UDP socket (test-side frame injection).
bool raw_udp_send(uint16_t dst_port, const std::vector<uint8_t>& bytes) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(kLoopback);
    dst.sin_port = htons(dst_port);
    bool ok = ::sendto(s, bytes.data(), bytes.size(), 0,
                       reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) ==
              static_cast<ssize_t>(bytes.size());
    ::close(s);
    return ok;
}

struct NodeFixture {
    FogNode::Config cfg;
    NodeFixture(uint16_t port) {
        cfg.bind_port = port;
        cfg.id = FogPeerId::random();
        cfg.default_ttl = 8;
    }
};

} // namespace

// ===== Frame pack/parse roundtrip =====

TEST(FogFrame, PackParseRoundtrip) {
    FogFrame f;
    f.ttl = 5;
    f.type = FogMsgType::DATA;
    f.target_id = FogPeerId::random();
    f.origin_id = FogPeerId::random();
    f.seq = 0x0102030405060708ULL;
    const char* msg = "hello fog mesh";
    f.payload.assign(msg, msg + std::strlen(msg));

    std::vector<uint8_t> wire = f.pack();
    ASSERT_EQ(wire.size(), FogFrame::kHeaderSize + f.payload.size());
    EXPECT_EQ(wire[0], 'F');
    EXPECT_EQ(wire[1], 'O');
    EXPECT_EQ(wire[2], 'G');

    auto back = FogFrame::parse(wire.data(), wire.size());
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(back->ttl, f.ttl);
    EXPECT_EQ(back->type, f.type);
    EXPECT_EQ(back->target_id, f.target_id);
    EXPECT_EQ(back->origin_id, f.origin_id);
    EXPECT_EQ(back->seq, f.seq);
    EXPECT_EQ(back->payload, f.payload);
}

TEST(FogFrame, ParseRejectsGarbage) {
    // Too short.
    uint8_t tiny[10] = {'F', 'O', 'G', 1};
    EXPECT_FALSE(FogFrame::parse(tiny, sizeof(tiny)).has_value());
    // Bad magic.
    FogFrame f;
    f.target_id = FogPeerId::random();
    f.origin_id = FogPeerId::random();
    std::vector<uint8_t> wire = f.pack();
    wire[0] = 'X';
    EXPECT_FALSE(FogFrame::parse(wire.data(), wire.size()).has_value());
    // Bad version.
    wire = f.pack();
    wire[3] = 99;
    EXPECT_FALSE(FogFrame::parse(wire.data(), wire.size()).has_value());
    // Bad msg_type.
    wire = f.pack();
    wire[5] = 0;
    EXPECT_FALSE(FogFrame::parse(wire.data(), wire.size()).has_value());
    EXPECT_FALSE(FogFrame::parse(nullptr, 100).has_value());
}

// ===== PeerTable: best_relay respects trust and last_seen =====

TEST(FogPeerTable, BestRelayRespectsTrust) {
    FogPeerTable t;
    uint64_t now = 1'000'000;
    FogPeerId low = FogPeerId::random();
    FogPeerId high = FogPeerId::random();
    t.register_peer(make_peer(low, 47001, 0.3, now), now);
    t.register_peer(make_peer(high, 47002, 0.9, now), now);

    auto best = t.best_relay(FogPeerId::random(), now);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->id, high);
}

TEST(FogPeerTable, BestRelayExcludesOriginAndStale) {
    FogPeerTable t;
    uint64_t now = 1'000'000;
    FogPeerId origin = FogPeerId::random();
    FogPeerId stale = FogPeerId::random();
    FogPeerId fresh = FogPeerId::random();
    // Highest trust but it is the origin — must be excluded.
    t.register_peer(make_peer(origin, 47001, 1.0, now), now);
    // High trust but seen 120 s ago — too stale (> 60 s).
    t.register_peer(make_peer(stale, 47002, 0.95, now - 120), now - 120);
    // Lower trust but fresh — must win.
    t.register_peer(make_peer(fresh, 47003, 0.4, now - 10), now - 10);

    auto best = t.best_relay(origin, now);
    ASSERT_TRUE(best.has_value());
    EXPECT_EQ(best->id, fresh);

    // No eligible peer at all (exclude everyone).
    FogPeerTable t2;
    t2.register_peer(make_peer(origin, 47001, 1.0, now), now);
    EXPECT_FALSE(t2.best_relay(origin, now).has_value());
}

TEST(FogPeerTable, DecayReducesTrust) {
    FogPeerTable t;
    uint64_t now = 1'000'000;
    FogPeerId id = FogPeerId::random();
    t.register_peer(make_peer(id, 47001, 1.0, now), now);
    t.decay(now);            // establishes baseline
    t.decay(now + 600);      // 10 minutes later: trust ~ 0.99^10
    auto p = t.find(id);
    ASSERT_TRUE(p.has_value());
    double expected = std::pow(0.99, 10.0);
    EXPECT_NEAR(p->trust_score, expected, 1e-9);
}

// ===== ROUTE_AD merge + eviction order =====

TEST(FogPeerTable, EvictsLowestTrustWhenFull) {
    FogPeerTable t;
    uint64_t now = 1'000'000;
    FogPeerId weakest;
    for (size_t i = 0; i < FogPeerTable::kMaxPeers; ++i) {
        FogPeerId id = FogPeerId::random();
        double trust = 0.5 + (static_cast<double>(i) / FogPeerTable::kMaxPeers) * 0.5;
        if (i == 0) weakest = id; // trust 0.5 — the lowest
        t.register_peer(make_peer(id, static_cast<uint16_t>(47000 + i),
                                  trust, now), now);
    }
    ASSERT_EQ(t.size(), FogPeerTable::kMaxPeers);
    FogPeerId newcomer = FogPeerId::random();
    t.register_peer(make_peer(newcomer, 47999, 0.6, now), now);
    EXPECT_EQ(t.size(), FogPeerTable::kMaxPeers);
    EXPECT_FALSE(t.find(weakest).has_value());   // lowest trust evicted
    EXPECT_TRUE(t.find(newcomer).has_value());   // newcomer kept
}

TEST(FogNode, RouteAdMergesSenderIntoTable) {
    NodeFixture fa(kPortA), fb(kPortB);
    FogNode a(fa.cfg), b(fb.cfg);
    ASSERT_EQ(a.start(), FogError::OK);
    ASSERT_EQ(b.start(), FogError::OK);

    uint64_t now = now_sec();
    FogPeerInfo b_as_peer = make_peer(b.id(), b.bound_port(), 0.9, now);
    ASSERT_EQ(a.send_route_ad(b_as_peer, now), FogError::OK);
    ASSERT_GT(b.poll(500, now), 0);

    auto merged = b.table().find(a.id());
    ASSERT_TRUE(merged.has_value());
    EXPECT_EQ(merged->port, a.bound_port());
    EXPECT_DOUBLE_EQ(merged->trust_score, 1.0);
    a.stop();
    b.stop();
}

// ===== Two FogNodes over UDP loopback: DATA A -> B -> C =====

TEST(FogNode, UdpRelayChainABC) {
    // Explicit ports 46310-46312 to avoid clashes with other tests.
    FogNode::Config ca, cb, cc;
    ca.bind_port = 46310; ca.id = FogPeerId::random();
    cb.bind_port = 46311; cb.id = FogPeerId::random();
    cc.bind_port = 46312; cc.id = FogPeerId::random();
    FogNode a(ca), b(cb), c(cc);
    ASSERT_EQ(a.start(), FogError::OK);
    ASSERT_EQ(b.start(), FogError::OK);
    ASSERT_EQ(c.start(), FogError::OK);

    uint64_t now = now_sec();
    // A knows only B; B knows A and C; C knows B.
    a.table().register_peer(make_peer(b.id(), b.bound_port(), 0.9, now), now);
    b.table().register_peer(make_peer(a.id(), a.bound_port(), 0.9, now), now);
    b.table().register_peer(make_peer(c.id(), c.bound_port(), 0.9, now), now);
    c.table().register_peer(make_peer(b.id(), b.bound_port(), 0.9, now), now);

    const char* msg = "payload through the fog";
    std::vector<uint8_t> payload(msg, msg + std::strlen(msg));
    ASSERT_EQ(a.send_data(c.id(), payload, now), FogError::OK);

    // B receives and relays to C.
    ASSERT_GT(b.poll(500, now), 0);
    // C receives the relayed frame.
    ASSERT_GT(c.poll(500, now), 0);

    // B only relayed — nothing addressed to it.
    EXPECT_EQ(b.inbox_size(), 0u);
    EXPECT_EQ(b.relayed(), 1u);

    std::vector<uint8_t> got;
    ASSERT_TRUE(c.inbox_pop(got));
    EXPECT_EQ(got, payload);
    EXPECT_EQ(c.inbox_size(), 0u);

    a.stop(); b.stop(); c.stop();
}

// ===== TTL=0 drop =====

TEST(FogNode, TtlZeroFrameDropped) {
    FogNode::Config cb, cc;
    cb.bind_port = kPortD; cb.id = FogPeerId::random();
    cc.bind_port = kPortE; cc.id = FogPeerId::random();
    FogNode b(cb), c(cc);
    ASSERT_EQ(b.start(), FogError::OK);
    ASSERT_EQ(c.start(), FogError::OK);
    uint64_t now = now_sec();
    b.table().register_peer(make_peer(c.id(), c.bound_port(), 0.9, now), now);

    // Inject a DATA frame with ttl=0 addressed to C at B.
    FogFrame f;
    f.ttl = 0;
    f.type = FogMsgType::DATA;
    f.target_id = c.id();
    f.origin_id = FogPeerId::random();
    f.seq = 777;
    f.payload = {'x'};
    ASSERT_TRUE(raw_udp_send(b.bound_port(), f.pack()));

    ASSERT_GT(b.poll(500, now), 0);
    EXPECT_EQ(b.dropped_ttl(), 1u);
    EXPECT_EQ(b.relayed(), 0u);
    // C must not receive anything.
    EXPECT_EQ(c.poll(200, now), 0);
    EXPECT_EQ(c.inbox_size(), 0u);
    b.stop(); c.stop();
}

// ===== Duplicate (origin,seq) dropped =====

TEST(FogNode, DuplicateOriginSeqDropped) {
    FogNode::Config cc;
    cc.bind_port = 46313; cc.id = FogPeerId::random();
    FogNode c(cc);
    ASSERT_EQ(c.start(), FogError::OK);
    uint64_t now = now_sec();

    FogFrame f;
    f.ttl = 8;
    f.type = FogMsgType::DATA;
    f.target_id = c.id();
    f.origin_id = FogPeerId::random();
    f.seq = 4242;
    f.payload = {'d', 'u', 'p'};
    std::vector<uint8_t> wire = f.pack();
    ASSERT_TRUE(raw_udp_send(c.bound_port(), wire));
    ASSERT_TRUE(raw_udp_send(c.bound_port(), wire)); // exact duplicate

    c.poll(500, now);
    c.poll(100, now);
    EXPECT_EQ(c.inbox_size(), 1u);
    EXPECT_EQ(c.dropped_dup(), 1u);

    std::vector<uint8_t> got;
    ASSERT_TRUE(c.inbox_pop(got));
    EXPECT_EQ(got, f.payload);
    c.stop();
}

// ===== PING -> PONG =====

TEST(FogNode, PingAnsweredWithPong) {
    FogNode::Config ca, cb;
    ca.bind_port = 46314; ca.id = FogPeerId::random();
    cb.bind_port = 46315; cb.id = FogPeerId::random();
    FogNode a(ca), b(cb);
    ASSERT_EQ(a.start(), FogError::OK);
    ASSERT_EQ(b.start(), FogError::OK);
    uint64_t now = now_sec();
    a.table().register_peer(make_peer(b.id(), b.bound_port(), 0.9, now), now);

    ASSERT_EQ(a.send_ping(b.id(), now), FogError::OK);
    // B answers with PONG directed at A.
    ASSERT_GT(b.poll(500, now), 0);
    // A receives the PONG (drains without error, no inbox growth).
    a.poll(500, now);
    EXPECT_EQ(a.inbox_size(), 0u);
    a.stop(); b.stop();
}
