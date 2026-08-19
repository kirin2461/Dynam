#include <gtest/gtest.h>
#include "ncp_spa.hpp"

#include <sodium.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ncp;

// ============================================================================
// Mock access controller — records every grant call
// ============================================================================

class MockAccessController : public IAccessController {
public:
    struct Call {
        std::string ip;
        uint8_t proto;
        uint16_t port;
        uint32_t ttl;
    };

    std::vector<Call> calls;

    bool grant(const std::string& src_ip, uint8_t proto,
               uint16_t port, uint32_t ttl_sec) override {
        calls.push_back({src_ip, proto, port, ttl_sec});
        return true;
    }
};

// ============================================================================
// Fixture
// ============================================================================

class SpaTest : public ::testing::Test {
protected:
    std::shared_ptr<MockAccessController> mock;
    std::unique_ptr<SpaServer> server;

    void SetUp() override {
        mock = std::make_shared<MockAccessController>();
        server.reset(new SpaServer());
        server->set_access_controller(mock);
    }

    void authorize(const SpaClient& c) {
        std::vector<uint8_t> pk;
        ASSERT_TRUE(spa_base64_decode(c.pubkey_base64(), pk));
        ASSERT_EQ(pk.size(), 32u);
        ASSERT_TRUE(server->add_authorized_key(pk.data(), pk.size()));
    }
};

// ============================================================================
// Roundtrip: keygen -> build -> verify -> GRANTED with exact grant params
// ============================================================================

TEST_F(SpaTest, KeygenBuildVerifyRoundtrip) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    ASSERT_TRUE(client.has_key());
    authorize(client);

    auto pkt = client.build_packet(6, 22, 600);
    ASSERT_EQ(pkt.size(), SPA_PACKET_SIZE);
    EXPECT_EQ(pkt[0], 'S');
    EXPECT_EQ(pkt[1], 'P');
    EXPECT_EQ(pkt[2], SPA_VERSION);

    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::GRANTED);

    ASSERT_EQ(mock->calls.size(), 1u);
    EXPECT_EQ(mock->calls[0].ip, "192.0.2.10");
    EXPECT_EQ(mock->calls[0].proto, 6u);
    EXPECT_EQ(mock->calls[0].port, 22u);
    EXPECT_EQ(mock->calls[0].ttl, 600u);
}

// key_id must equal BLAKE2b-64(pubkey) first 8 bytes
TEST_F(SpaTest, KeyIdMatchesBlake2b64) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    std::vector<uint8_t> pk;
    ASSERT_TRUE(spa_base64_decode(client.pubkey_base64(), pk));
    std::array<uint8_t, 8> hash{};
    crypto_generichash(hash.data(), hash.size(), pk.data(), pk.size(), nullptr, 0);
    SpaKeyId id = client.key_id();
    EXPECT_EQ(std::memcmp(id.data(), hash.data(), 8), 0);
}

// ============================================================================
// Corrupted payload -> BAD_SIGNATURE
// ============================================================================

TEST_F(SpaTest, FlippedByteGivesBadSignature) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    auto pkt = client.build_packet(6, 22, 0);
    ASSERT_EQ(pkt.size(), SPA_PACKET_SIZE);
    pkt[37] ^= 0x01;  // flip one payload byte inside the signed region (port LSB)

    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::BAD_SIGNATURE);
    EXPECT_TRUE(mock->calls.empty());
}

// ============================================================================
// Unknown key_id -> UNKNOWN_KEY
// ============================================================================

TEST_F(SpaTest, UnknownKeyRejected) {
    SpaClient known, stranger;
    ASSERT_TRUE(known.generate());
    ASSERT_TRUE(stranger.generate());
    authorize(known);  // server only knows `known`

    auto pkt = stranger.build_packet(6, 22, 0);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::UNKNOWN_KEY);
    EXPECT_TRUE(mock->calls.empty());
}

// ============================================================================
// Stale timestamp -> STALE_TIMESTAMP
// ============================================================================

TEST_F(SpaTest, StaleTimestampRejected) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    const uint64_t now_s = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto pkt = client.build_packet_ts(6, 22, 0, now_s - 120);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::STALE_TIMESTAMP);
    EXPECT_TRUE(mock->calls.empty());
}

// Timestamp exactly at the edge of the window is still accepted
TEST_F(SpaTest, TimestampAtWindowEdgeAccepted) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    const uint64_t now_s = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto pkt = client.build_packet_ts(6, 22, 0, now_s - 59);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::GRANTED);
}

// ============================================================================
// Replay: same packet twice -> second is REPLAY
// ============================================================================

TEST_F(SpaTest, ReplayRejected) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    auto pkt = client.build_packet(6, 22, 0);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::GRANTED);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::REPLAY);
    EXPECT_EQ(mock->calls.size(), 1u);
}

// ============================================================================
// Two different clients — each GRANTED
// ============================================================================

TEST_F(SpaTest, TwoClientsBothGranted) {
    SpaClient alice, bob;
    ASSERT_TRUE(alice.generate());
    ASSERT_TRUE(bob.generate());
    authorize(alice);
    authorize(bob);
    EXPECT_EQ(server->authorized_key_count(), 2u);

    auto pa = alice.build_packet(6, 22, 100);
    auto pb = bob.build_packet(17, 51820, 200);

    EXPECT_EQ(server->process_packet(pa, "192.0.2.1"), SpaResult::GRANTED);
    EXPECT_EQ(server->process_packet(pb, "192.0.2.2"), SpaResult::GRANTED);

    ASSERT_EQ(mock->calls.size(), 2u);
    EXPECT_EQ(mock->calls[0].ip, "192.0.2.1");
    EXPECT_EQ(mock->calls[0].proto, 6u);
    EXPECT_EQ(mock->calls[1].ip, "192.0.2.2");
    EXPECT_EQ(mock->calls[1].proto, 17u);
    EXPECT_EQ(mock->calls[1].port, 51820u);
}

// ============================================================================
// TTL clamping: requested_ttl clamped to max_ttl; 0 -> default_ttl
// ============================================================================

TEST_F(SpaTest, TtlClampedToMax) {
    SpaServer::Config cfg;
    cfg.default_ttl_sec = 300;
    cfg.max_ttl_sec = 86400;
    server.reset(new SpaServer(cfg));
    server->set_access_controller(mock);

    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    auto pkt = client.build_packet(6, 22, 99999999);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::GRANTED);
    ASSERT_EQ(mock->calls.size(), 1u);
    EXPECT_EQ(mock->calls[0].ttl, 86400u);
}

TEST_F(SpaTest, TtlZeroUsesServerDefault) {
    SpaServer::Config cfg;
    cfg.default_ttl_sec = 300;
    cfg.max_ttl_sec = 86400;
    server.reset(new SpaServer(cfg));
    server->set_access_controller(mock);

    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    auto pkt = client.build_packet(6, 22, 0);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::GRANTED);
    ASSERT_EQ(mock->calls.size(), 1u);
    EXPECT_EQ(mock->calls[0].ttl, 300u);
}

// ============================================================================
// Bad format
// ============================================================================

TEST_F(SpaTest, BadFormatRejected) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    // wrong size
    auto pkt = client.build_packet(6, 22, 0);
    pkt.resize(128);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::BAD_FORMAT);

    // bad magic
    pkt = client.build_packet(6, 22, 0);
    pkt[0] = 'X';
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::BAD_FORMAT);

    // bad version
    pkt = client.build_packet(6, 22, 0);
    pkt[2] = 99;
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.10"), SpaResult::BAD_FORMAT);
}

// ============================================================================
// authorized_keys file loading (base64 pubkey per line, '#' comments)
// ============================================================================

TEST_F(SpaTest, LoadAuthorizedKeysFile) {
    SpaClient alice, bob;
    ASSERT_TRUE(alice.generate());
    ASSERT_TRUE(bob.generate());

    const std::string path = "test_spa_authorized_keys.tmp";
    {
        std::ofstream f(path, std::ios::trunc);
        f << "# SPA authorized keys\n";
        f << "\n";
        f << alice.pubkey_base64() << "\n";
        f << "   " << bob.pubkey_base64() << "  \n";
        f << "not-valid-base64!!!\n";  // skipped with warning
    }
    EXPECT_TRUE(server->load_authorized_keys(path));
    EXPECT_EQ(server->authorized_key_count(), 2u);
    std::remove(path.c_str());

    auto pkt = bob.build_packet(6, 443, 60);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.20"), SpaResult::GRANTED);
}

TEST_F(SpaTest, LoadAuthorizedKeysMissingFile) {
    EXPECT_FALSE(server->load_authorized_keys("definitely/does/not/exist.keys"));
}

// ============================================================================
// Key file save/load roundtrip
// ============================================================================

TEST_F(SpaTest, KeyFileSaveLoadRoundtrip) {
    SpaClient client;
    ASSERT_TRUE(client.generate());

    const std::string path = "test_spa_client.key";
    ASSERT_TRUE(client.save_keyfile(path));

    SpaClient loaded;
    ASSERT_TRUE(loaded.load_keyfile(path));
    std::remove(path.c_str());

    EXPECT_EQ(loaded.key_id(), client.key_id());
    EXPECT_EQ(loaded.pubkey_base64(), client.pubkey_base64());

    // A packet built by the loaded key must verify
    authorize(client);
    auto pkt = loaded.build_packet(6, 22, 10);
    EXPECT_EQ(server->process_packet(pkt, "192.0.2.30"), SpaResult::GRANTED);
}

// ============================================================================
// IpSetAccessController — dry_run records the exact command, executes nothing
// ============================================================================

TEST(SpaIpSetTest, DryRunRecordsExactCommands) {
    IpSetAccessController ctrl("ncp_spa_allow", true /*dry_run*/);
    std::vector<std::string> executed;
    ctrl.set_command_runner([&](const std::string& cmd) -> int {
        executed.push_back(cmd);
        return 0;
    });

    EXPECT_TRUE(ctrl.grant("203.0.113.7", 6, 22, 300));

    // In dry-run the runner must never be invoked
    EXPECT_TRUE(executed.empty());
    EXPECT_EQ(ctrl.last_command(),
              "ipset add ncp_spa_allow 203.0.113.7 timeout 300 -exist");
}

TEST(SpaIpSetTest, RealModeRunsExactCommandsViaRunner) {
    IpSetAccessController ctrl("ncp_spa_allow", false /*dry_run*/);
    std::vector<std::string> executed;
    ctrl.set_command_runner([&](const std::string& cmd) -> int {
        executed.push_back(cmd);
        return 0;
    });

    EXPECT_TRUE(ctrl.grant("203.0.113.7", 6, 22, 300));

    ASSERT_EQ(executed.size(), 2u);
    EXPECT_EQ(executed[0], "ipset create ncp_spa_allow hash:ip timeout 0 -exist");
    EXPECT_EQ(executed[1], "ipset add ncp_spa_allow 203.0.113.7 timeout 300 -exist");
    EXPECT_EQ(ctrl.last_command(), executed[1]);

    // Second grant: set already ensured, only the add runs
    EXPECT_TRUE(ctrl.grant("203.0.113.8", 17, 51820, 60));
    ASSERT_EQ(executed.size(), 3u);
    EXPECT_EQ(executed[2], "ipset add ncp_spa_allow 203.0.113.8 timeout 60 -exist");
}

TEST(SpaIpSetTest, RunnerFailurePropagates) {
    IpSetAccessController ctrl("ncp_spa_allow", false);
    ctrl.set_command_runner([](const std::string&) -> int { return 1; });
    EXPECT_FALSE(ctrl.grant("203.0.113.7", 6, 22, 300));
}

TEST(SpaIpSetTest, IptablesRuleHint) {
    EXPECT_EQ(IpSetAccessController::iptables_rule_hint(6, 22, "ncp_spa_allow"),
              "iptables -A INPUT -p tcp --dport 22 -m set ! --match-set ncp_spa_allow src -j DROP");
    EXPECT_EQ(IpSetAccessController::iptables_rule_hint(17, 51820, "s"),
              "iptables -A INPUT -p udp --dport 51820 -m set ! --match-set s src -j DROP");
}

// ============================================================================
// Full end-to-end: daemon on 127.0.0.1 + client knock
// ============================================================================

TEST_F(SpaTest, DaemonEndToEndLoopback) {
    SpaClient client;
    ASSERT_TRUE(client.generate());
    authorize(client);

    // fixed high port that is very likely free in CI
    SpaDaemon d2(*server, 54917, "127.0.0.1");
    if (!d2.start()) {
        GTEST_SKIP() << "UDP port 54917 unavailable";
    }
    EXPECT_TRUE(client.knock("127.0.0.1", 54917, 6, 22, 42));

    // give the receive loop a moment
    for (int i = 0; i < 50 && mock->calls.empty(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    d2.stop();

    ASSERT_EQ(mock->calls.size(), 1u);
    EXPECT_EQ(mock->calls[0].ip, "127.0.0.1");
    EXPECT_EQ(mock->calls[0].port, 22u);
    EXPECT_EQ(mock->calls[0].ttl, 42u);
}
