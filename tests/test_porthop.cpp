// ══════════════════════════════════════════════════════════════════════════════
// tests/test_porthop.cpp
// Tests for M2 — ncp_porthop (UDP port-hopping transport)
// Uses in-process UDP loopback on 127.0.0.1, ports 45300+.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_porthop.hpp"

#include <chrono>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace ncp;

namespace {

constexpr uint16_t kBasePort = 45300;
constexpr uint16_t kRange = 32;
constexpr uint32_t kIntervalSec = 60;
constexpr uint64_t kSessionId = 0x1122334455667788ULL;

std::vector<uint8_t> test_secret() {
    std::vector<uint8_t> s(32);
    for (size_t i = 0; i < s.size(); ++i)
        s[i] = static_cast<uint8_t>(i * 7 + 1);
    return s;
}

HopSchedule make_schedule() {
    return HopSchedule(test_secret(), kBasePort, kRange, kIntervalSec);
}

} // namespace

// ── Schedule ──────────────────────────────────────────────────────────────────

TEST(HopScheduleTest, Deterministic) {
    HopSchedule a = make_schedule();
    HopSchedule b = make_schedule();
    for (uint32_t e = 0; e < 64; ++e)
        EXPECT_EQ(a.port_for_epoch(e), b.port_for_epoch(e)) << "epoch " << e;
}

TEST(HopScheduleTest, StaysInRange) {
    HopSchedule s = make_schedule();
    for (uint32_t e = 0; e < 256; ++e) {
        uint16_t p = s.port_for_epoch(e);
        EXPECT_GE(p, kBasePort);
        EXPECT_LT(p, kBasePort + kRange);
    }
}

TEST(HopScheduleTest, DiffersAcrossEpochs) {
    HopSchedule s = make_schedule();
    std::set<uint16_t> ports;
    for (uint32_t e = 0; e < 64; ++e)
        ports.insert(s.port_for_epoch(e));
    // With a 32-port range and HMAC-derived ports, collisions happen,
    // but a single fixed port for all epochs is a broken schedule.
    EXPECT_GT(ports.size(), 1u);
}

TEST(HopScheduleTest, DiffersAcrossSecrets) {
    HopSchedule a = make_schedule();
    auto secret2 = test_secret();
    secret2[0] ^= 0xFF;
    HopSchedule b(secret2, kBasePort, kRange, kIntervalSec);
    bool any_diff = false;
    for (uint32_t e = 0; e < 64; ++e)
        if (a.port_for_epoch(e) != b.port_for_epoch(e)) any_diff = true;
    EXPECT_TRUE(any_diff);
}

// ── Frame encode/decode ───────────────────────────────────────────────────────

TEST(PortHopFrameTest, EncodeDecodeRoundtrip) {
    PortHopSession s(kSessionId, make_schedule());
    const char* msg = "hello port hopping";
    auto wire = s.encode(reinterpret_cast<const uint8_t*>(msg),
                         std::strlen(msg), PH_FLAG_ACK_REQUEST);

    ASSERT_EQ(wire.size(), PortHopSession::HEADER_SIZE + std::strlen(msg));
    EXPECT_EQ(wire[0], 'P');
    EXPECT_EQ(wire[1], 'H');
    EXPECT_EQ(wire[2], 1);

    PortHopSession peer(kSessionId, make_schedule());
    auto frame = peer.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(frame->session_id, kSessionId);
    EXPECT_EQ(frame->epoch, 0u);
    EXPECT_EQ(frame->seq, 0u);
    EXPECT_EQ(frame->flags, PH_FLAG_ACK_REQUEST);
    std::string text(frame->payload.begin(), frame->payload.end());
    EXPECT_EQ(text, msg);
}

TEST(PortHopFrameTest, SeqIncrements) {
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 0x42;
    auto w0 = s.encode(&b, 1);
    auto w1 = s.encode(&b, 1);
    auto f0 = PortHopSession::decode_raw(w0.data(), w0.size());
    auto f1 = PortHopSession::decode_raw(w1.data(), w1.size());
    ASSERT_TRUE(f0 && f1);
    EXPECT_EQ(f0->seq, 0u);
    EXPECT_EQ(f1->seq, 1u);
}

TEST(PortHopFrameTest, RejectsBadMagicAndWrongSession) {
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 1;
    auto wire = s.encode(&b, 1);

    auto bad_magic = wire;
    bad_magic[0] = 'X';
    EXPECT_FALSE(PortHopSession::decode_raw(bad_magic.data(), bad_magic.size()));

    PortHopSession other(kSessionId + 1, make_schedule());
    EXPECT_FALSE(other.decode(wire.data(), wire.size()));

    // Truncated frame.
    EXPECT_FALSE(PortHopSession::decode_raw(wire.data(), 5));
}

TEST(PortHopFrameTest, HopNotifyAdvancesEpoch) {
    PortHopSession a(kSessionId, make_schedule());
    PortHopSession b(kSessionId, make_schedule());
    // a hops to epoch 5 and notifies b.
    for (int i = 0; i < 5; ++i) a.hop();
    uint8_t payload[4] = {0, 0, 0, 5};
    auto wire = a.encode(payload, 4, PH_FLAG_HOP_NOTIFY);
    auto frame = b.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(b.current_epoch(), 5u);
}

// ── should_hop ────────────────────────────────────────────────────────────────

TEST(PortHopSessionTest, ShouldHopOnSimulatedLoss) {
    PortHopSession s(kSessionId, make_schedule());
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(s.should_hop(now));

    // Simulate 4 packets sent with ACK requested and dropped (no ACK back).
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        s.encode(&b, 1, PH_FLAG_ACK_REQUEST);

    EXPECT_EQ(s.unacked_count(), 4u);
    EXPECT_TRUE(s.should_hop(now));  // unacked > 3
}

TEST(PortHopSessionTest, AckClearsUnacked) {
    PortHopSession sender(kSessionId, make_schedule());
    PortHopSession receiver(kSessionId, make_schedule());
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        sender.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    EXPECT_EQ(sender.unacked_count(), 4u);

    // Receiver ACKs seq 3 (echoes in seq field).
    auto ack = receiver.encode(nullptr, 0, PH_FLAG_ACK);
    ack[15] = 0; ack[16] = 0; ack[17] = 0; ack[18] = 3;
    auto frame = sender.decode(ack.data(), ack.size());
    ASSERT_TRUE(frame.has_value());
    EXPECT_EQ(sender.unacked_count(), 0u);
    EXPECT_EQ(sender.last_ack_seq(), 3u);
    EXPECT_FALSE(sender.should_hop(std::chrono::steady_clock::now()));
}

TEST(PortHopSessionTest, ShouldHopOnIntervalExpiry) {
    HopSchedule sched(test_secret(), kBasePort, kRange, /*interval_sec=*/1);
    PortHopSession s(kSessionId, sched);
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(s.should_hop(now));
    EXPECT_TRUE(s.should_hop(now + std::chrono::seconds(2)));
}

TEST(PortHopSessionTest, HopResetsState) {
    PortHopSession s(kSessionId, make_schedule());
    uint8_t b = 0;
    for (int i = 0; i < 4; ++i)
        s.encode(&b, 1, PH_FLAG_ACK_REQUEST);
    s.hop();
    EXPECT_EQ(s.current_epoch(), 1u);
    EXPECT_EQ(s.unacked_count(), 0u);
    EXPECT_FALSE(s.should_hop(std::chrono::steady_clock::now()));
}

// ── Server / client over UDP loopback ─────────────────────────────────────────

class PortHopLoopbackTest : public ::testing::Test {
protected:
    void SetUp() override {
        server_ = std::make_unique<PortHopServer>(make_schedule());
        ASSERT_TRUE(server_->bind_all());
        server_->register_session(kSessionId);

        client_ = std::make_unique<PortHopClient>("127.0.0.1", make_schedule(),
                                                  kSessionId);
        ASSERT_TRUE(client_->open());
    }
    void TearDown() override {
        client_.reset();
        server_.reset();
    }
    std::unique_ptr<PortHopServer> server_;
    std::unique_ptr<PortHopClient> client_;
};

TEST_F(PortHopLoopbackTest, BindsAllPorts) {
    EXPECT_TRUE(server_->is_bound());
    // Spot-check the schedule port is actually bound: send and receive.
    std::vector<uint8_t> payload = {1, 2, 3};
    ASSERT_TRUE(client_->send(payload));
    auto recvd = server_->poll(500);
    ASSERT_EQ(recvd.size(), 1u);
    EXPECT_EQ(recvd[0].frame.session_id, kSessionId);
    EXPECT_EQ(recvd[0].frame.payload, payload);
    EXPECT_EQ(recvd[0].local_port,
              server_->has_session(kSessionId)
                  ? HopSchedule(test_secret(), kBasePort, kRange, kIntervalSec)
                        .port_for_epoch(0)
                  : 0);
    EXPECT_EQ(recvd[0].from_ip, "127.0.0.1");
    EXPECT_EQ(recvd[0].from_port, client_->local_port());
}

TEST_F(PortHopLoopbackTest, RejectsUnknownSession) {
    const uint64_t kUnknown = 0xDEADBEEFCAFEF00DULL;
    PortHopClient stranger("127.0.0.1", make_schedule(), kUnknown);
    ASSERT_TRUE(stranger.open());
    std::vector<uint8_t> payload = {9, 9, 9};
    ASSERT_TRUE(stranger.send(payload));

    auto recvd = server_->poll(300);
    EXPECT_TRUE(recvd.empty());
    EXPECT_EQ(server_->frames_rejected_unknown_session(), 1u);
    EXPECT_EQ(server_->session_frame_count(kUnknown), 0u);
    EXPECT_FALSE(server_->has_session(kUnknown));
}

TEST_F(PortHopLoopbackTest, AckRoundtripClearsUnacked) {
    std::vector<uint8_t> payload = {7};
    ASSERT_TRUE(client_->send(payload, PH_FLAG_ACK_REQUEST));

    auto recvd = server_->poll(500);
    ASSERT_EQ(recvd.size(), 1u);
    EXPECT_EQ(recvd[0].frame.flags & PH_FLAG_ACK_REQUEST, PH_FLAG_ACK_REQUEST);
    EXPECT_EQ(client_->session().unacked_count(), 1u);

    ASSERT_TRUE(server_->send_ack(kSessionId, recvd[0].frame.seq));
    auto replies = client_->poll(500);
    ASSERT_EQ(replies.size(), 1u);
    EXPECT_EQ(replies[0].frame.flags & PH_FLAG_ACK, PH_FLAG_ACK);
    EXPECT_EQ(client_->session().unacked_count(), 0u);
    EXPECT_EQ(client_->session().last_ack_seq(), recvd[0].frame.seq);
}

TEST_F(PortHopLoopbackTest, SessionSurvivesHopAcrossPorts) {
    std::vector<uint8_t> p0 = {0xA0};
    ASSERT_TRUE(client_->send(p0));

    // Hop: epoch++ → next send targets the newly scheduled port.
    uint16_t port_before = client_->current_target_port();
    client_->hop();
    uint16_t port_after = client_->current_target_port();
    EXPECT_EQ(client_->current_epoch(), 1u);
    EXPECT_EQ(port_after, make_schedule().port_for_epoch(1));
    (void)port_before;  // ports may coincide; association must not depend on it

    std::vector<uint8_t> p1 = {0xB1};
    ASSERT_TRUE(client_->send(p1));

    // Drain both datagrams.
    std::vector<PortHopReceived> all;
    for (int i = 0; i < 4 && all.size() < 2; ++i) {
        auto batch = server_->poll(300);
        all.insert(all.end(), batch.begin(), batch.end());
    }
    ASSERT_EQ(all.size(), 2u);

    // Both frames associate with the same session despite the hop.
    EXPECT_EQ(server_->session_frame_count(kSessionId), 2u);
    std::set<uint32_t> epochs;
    std::set<uint16_t> local_ports;
    for (const auto& r : all) {
        EXPECT_EQ(r.frame.session_id, kSessionId);
        epochs.insert(r.frame.epoch);
        local_ports.insert(r.local_port);
        // Source (client) identity is stable across hops.
        EXPECT_EQ(r.from_port, client_->local_port());
    }
    EXPECT_EQ(epochs.count(0u), 1u);
    EXPECT_EQ(epochs.count(1u), 1u);
    // Every received port must be a schedule-valid port for its epoch.
    auto sched = make_schedule();
    for (const auto& r : all)
        EXPECT_EQ(r.local_port, sched.port_for_epoch(r.frame.epoch));
}

TEST_F(PortHopLoopbackTest, LossTriggersShouldHopThenHopRecovers) {
    // Drop 4 packets (server receives them but never ACKs).
    std::vector<uint8_t> payload = {5};
    for (int i = 0; i < 4; ++i)
        ASSERT_TRUE(client_->send(payload, PH_FLAG_ACK_REQUEST));

    auto recvd = server_->poll(500);
    EXPECT_EQ(recvd.size(), 4u);
    EXPECT_EQ(client_->session().unacked_count(), 4u);
    EXPECT_TRUE(client_->session().should_hop(std::chrono::steady_clock::now()));

    // Hop and keep talking on the same session.
    client_->hop();
    ASSERT_TRUE(client_->send(payload));
    auto after = server_->poll(500);
    ASSERT_EQ(after.size(), 1u);
    EXPECT_EQ(after[0].frame.epoch, 1u);
    EXPECT_EQ(server_->session_frame_count(kSessionId), 5u);
}
