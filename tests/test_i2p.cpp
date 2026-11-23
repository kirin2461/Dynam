/**
 * @file test_i2p.cpp
 * @brief Comprehensive unit tests for I2PManager module
 * @date Phase 5: Task 5.4
 *
 * Tests for I2P functionality (without real I2P router - mock/unit tests)
 * NOTE: Tests that require SAM bridge are skipped in CI where
 *       127.0.0.1:7656 is unreachable (avoids ~2min TCP timeout per connect).
 */

#include <gtest/gtest.h>
#include "ncp_i2p.hpp"
#include <string>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#endif

namespace ncp {
namespace testing {

// Quick non-blocking check if SAM port is reachable (500ms timeout)
static bool is_sam_reachable(const char* host = "127.0.0.1", uint16_t port = 7656) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return false;
    // Set non-blocking
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    // Wait up to 500ms for connection
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = {0, 500000}; // 500ms
    int sel = select(0, nullptr, &wset, nullptr, &tv);
    bool reachable = (sel > 0);
    closesocket(sock);
    return reachable;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    struct pollfd pfd = {sock, POLLOUT, 0};
    int ret = poll(&pfd, 1, 500); // 500ms
    // POLLOUT alone is not enough: a refused connection also signals
    // POLLOUT|POLLERR. Check the actual connect result via SO_ERROR.
    int so_err = 0;
    socklen_t so_len = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &so_len);
    bool reachable = (ret > 0 && so_err == 0);
    close(sock);
    return reachable;
#endif
}

class I2PManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        config_.enabled = false;
        config_.sam_host = "127.0.0.1";
        config_.sam_port = 7656;
        config_.proxy_host = "127.0.0.1";
        config_.proxy_port = 4444;
    }

    void TearDown() override {}

    I2PManager manager_;
    I2PManager::Config config_;

    // Helper: skip test if SAM is not reachable.
    // NOTE: GTEST_SKIP() inside a helper only returns from the helper, so
    // callers must do `if (!RequireSAM()) return;` to actually stop the test.
    bool RequireSAM() {
        static int sam_status = -1; // -1 = unknown, 0 = no, 1 = yes
        if (sam_status < 0) {
            sam_status = is_sam_reachable() ? 1 : 0;
        }
        if (sam_status == 0) {
            return false;
        }
        return true;
    }
};

// ==================== Tests that do NOT require SAM ====================

TEST_F(I2PManagerTest, IsActiveStateBeforeInit) {
    EXPECT_FALSE(manager_.is_active());
}

TEST_F(I2PManagerTest, SetEnabledFalse) {
    config_.enabled = false;
    manager_.initialize(config_);  // enabled=false, won't connect
    manager_.set_enabled(false);
    EXPECT_FALSE(manager_.is_active());
}

TEST_F(I2PManagerTest, CreateTunnelWhenInactive) {
    config_.enabled = false;
    manager_.initialize(config_);
    bool result = manager_.create_tunnel(
        "test_tunnel", 12345, "test.b32.i2p",
        I2PManager::TunnelType::CLIENT);
    EXPECT_FALSE(result);
}

TEST_F(I2PManagerTest, ConfigDefaultValues) {
    I2PManager::Config default_config;
    EXPECT_EQ(default_config.sam_host, "127.0.0.1");
    EXPECT_EQ(default_config.sam_port, 7656);
    EXPECT_EQ(default_config.proxy_port, 4444);
    EXPECT_EQ(default_config.tunnel_length, 3);
    EXPECT_EQ(default_config.tunnel_quantity, 2);
    EXPECT_TRUE(default_config.enable_garlic_routing);
    EXPECT_TRUE(default_config.enable_ntcp2);
    EXPECT_TRUE(default_config.enable_ssu2);
}

TEST_F(I2PManagerTest, TunnelInfoStructure) {
    I2PManager::TunnelInfo info;
    info.tunnel_id = "test_id";
    info.type = I2PManager::TunnelType::CLIENT;
    info.local_dest = "local.b32.i2p";
    info.remote_dest = "remote.b32.i2p";
    EXPECT_EQ(info.tunnel_id, "test_id");
    EXPECT_EQ(info.type, I2PManager::TunnelType::CLIENT);
    EXPECT_EQ(info.bytes_sent, 0u);
    EXPECT_EQ(info.bytes_received, 0u);
    EXPECT_FALSE(info.is_backup);
}

TEST_F(I2PManagerTest, GetActiveTunnelsEmpty) {
    auto tunnels = manager_.get_active_tunnels();
    EXPECT_TRUE(tunnels.empty());
}

TEST_F(I2PManagerTest, StatisticsStructure) {
    auto stats = manager_.get_statistics();
    EXPECT_EQ(stats.total_sent, 0u);
    EXPECT_EQ(stats.total_received, 0u);
    EXPECT_EQ(stats.active_tunnels, 0u);
}

TEST_F(I2PManagerTest, TunnelTypeEnumValues) {
    EXPECT_NE(static_cast<int>(I2PManager::TunnelType::CLIENT),
              static_cast<int>(I2PManager::TunnelType::SERVER));
    EXPECT_NE(static_cast<int>(I2PManager::TunnelType::SERVER),
              static_cast<int>(I2PManager::TunnelType::BIDIRECTIONAL));
}

TEST_F(I2PManagerTest, EncryptionLayerEnumValues) {
    EXPECT_NE(static_cast<int>(I2PManager::EncryptionLayer::GARLIC_ROUTING),
              static_cast<int>(I2PManager::EncryptionLayer::ELGAMAL_AES));
    EXPECT_NE(static_cast<int>(I2PManager::EncryptionLayer::NTCP2),
              static_cast<int>(I2PManager::EncryptionLayer::SSU2));
}

TEST_F(I2PManagerTest, PadMessageBasic) {
    manager_.initialize(config_); // enabled=false, no connect
    std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
    auto padded = manager_.pad_message(msg, 16);
    EXPECT_GE(padded.size(), msg.size());
}

TEST_F(I2PManagerTest, EnableTrafficMixingNoCrash) {
    manager_.initialize(config_);
    EXPECT_NO_THROW(manager_.enable_traffic_mixing(true, 100));
    EXPECT_NO_THROW(manager_.enable_traffic_mixing(false, 0));
}

// ==================== Tests that REQUIRE SAM bridge ====================

TEST_F(I2PManagerTest, InitializeWithSAM) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    bool result = manager_.initialize(config_);
    EXPECT_TRUE(result);
}

TEST_F(I2PManagerTest, IsActiveAfterInit) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    EXPECT_TRUE(manager_.is_active());
}

TEST_F(I2PManagerTest, GetDestinationAfterInit) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    std::string dest = manager_.get_destination();
    EXPECT_FALSE(dest.empty());
}

TEST_F(I2PManagerTest, CreateTunnelWhenActive) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    [[maybe_unused]] bool result = manager_.create_tunnel(
        "test_tunnel", 12345, "test.b32.i2p",
        I2PManager::TunnelType::CLIENT);
    SUCCEED();
}

TEST_F(I2PManagerTest, DestroyNonExistentTunnel) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    bool result = manager_.destroy_tunnel("non_existent_tunnel_id");
    EXPECT_FALSE(result);
}

TEST_F(I2PManagerTest, SetEnabledToggle) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    manager_.set_enabled(false);
    EXPECT_FALSE(manager_.is_active());
    manager_.set_enabled(true);
}

TEST_F(I2PManagerTest, RotateTunnelsNoCrash) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    EXPECT_NO_THROW(manager_.rotate_tunnels());
}

TEST_F(I2PManagerTest, CreateServerTunnelBasic) {
    if (!RequireSAM()) { GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)"; }
    config_.enabled = true;
    manager_.initialize(config_);
    [[maybe_unused]] bool result = manager_.create_server_tunnel("test_server", 8080);
    SUCCEED();
}

// ==================== Inbound peer filter (no SAM required) ====================

TEST_F(I2PManagerTest, PeerFilter_DefaultAllows) {
    I2PPeerFilter filter;
    auto d = filter.check("peerA.b32.i2p", std::chrono::system_clock::now());
    EXPECT_TRUE(d.allow);
    EXPECT_EQ(filter.accepted_count(), 1u);
    EXPECT_EQ(filter.rejected_count(), 0u);
}

TEST_F(I2PManagerTest, PeerFilter_BlocklistRejects) {
    I2PPeerFilter::Config cfg;
    cfg.blocklist = {"evil.b32.i2p"};
    I2PPeerFilter filter(cfg);

    auto bad = filter.check("evil.b32.i2p", std::chrono::system_clock::now());
    EXPECT_FALSE(bad.allow);
    EXPECT_STREQ(bad.reason, "blocklisted");

    auto good = filter.check("friend.b32.i2p", std::chrono::system_clock::now());
    EXPECT_TRUE(good.allow);
    EXPECT_EQ(filter.rejected_count(), 1u);
}

TEST_F(I2PManagerTest, PeerFilter_AllowlistExcludesOthers) {
    I2PPeerFilter::Config cfg;
    cfg.allowlist = {"trusted.b32.i2p"};
    I2PPeerFilter filter(cfg);

    EXPECT_TRUE(filter.check("trusted.b32.i2p", std::chrono::system_clock::now()).allow);
    auto unknown = filter.check("stranger.b32.i2p", std::chrono::system_clock::now());
    EXPECT_FALSE(unknown.allow);
    EXPECT_STREQ(unknown.reason, "not-allowlisted");
}

TEST_F(I2PManagerTest, PeerFilter_TrimsWhitespace) {
    I2PPeerFilter::Config cfg;
    cfg.blocklist = {"evil.b32.i2p"};
    I2PPeerFilter filter(cfg);
    EXPECT_FALSE(filter.check("  evil.b32.i2p\r\n", std::chrono::system_clock::now()).allow);
}

TEST_F(I2PManagerTest, PeerFilter_EmptyDestinationRejected) {
    I2PPeerFilter filter;
    auto d = filter.check("   ", std::chrono::system_clock::now());
    EXPECT_FALSE(d.allow);
    EXPECT_STREQ(d.reason, "empty-destination");
}

TEST_F(I2PManagerTest, PeerFilter_ConcurrencyCapAndRelease) {
    I2PPeerFilter::Config cfg;
    cfg.max_concurrent_per_peer = 1;
    cfg.max_new_per_window = 0;  // unlimited rate for this test
    I2PPeerFilter filter(cfg);

    auto t = std::chrono::system_clock::now();
    EXPECT_TRUE(filter.check("peer.b32.i2p", t).allow);
    auto second = filter.check("peer.b32.i2p", t);
    EXPECT_FALSE(second.allow);
    EXPECT_STREQ(second.reason, "too-many-open");

    filter.release("peer.b32.i2p");
    EXPECT_TRUE(filter.check("peer.b32.i2p", t).allow);
}

TEST_F(I2PManagerTest, PeerFilter_RateWindow) {
    I2PPeerFilter::Config cfg;
    cfg.max_new_per_window = 2;
    cfg.rate_window = std::chrono::seconds(60);
    I2PPeerFilter filter(cfg);

    auto t0 = std::chrono::system_clock::now();
    EXPECT_TRUE(filter.check("peer.b32.i2p", t0).allow);
    EXPECT_TRUE(filter.check("peer.b32.i2p", t0).allow);
    auto third = filter.check("peer.b32.i2p", t0);
    EXPECT_FALSE(third.allow);
    EXPECT_STREQ(third.reason, "rate-limited");

    // After the window slides past the first two, one more is allowed.
    EXPECT_TRUE(filter.check("peer.b32.i2p", t0 + std::chrono::seconds(61)).allow);
}

TEST_F(I2PManagerTest, PeerFilter_BlockedPeersList) {
    I2PPeerFilter::Config cfg;
    cfg.blocklist = {"a.b32.i2p", "b.b32.i2p"};
    I2PPeerFilter filter(cfg);
    auto blocked = filter.blocked_peers();
    EXPECT_EQ(blocked.size(), 2u);
}

TEST_F(I2PManagerTest, PeerFilter_ResetCounters) {
    I2PPeerFilter filter;
    filter.check("peer.b32.i2p", std::chrono::system_clock::now());
    filter.reset_counters();
    EXPECT_EQ(filter.accepted_count(), 0u);
    EXPECT_EQ(filter.rejected_count(), 0u);
}

TEST_F(I2PManagerTest, AcceptInboundFailsWhenInactive) {
    // A fresh manager is initialized=false/enabled=false: no SAM traffic is
    // attempted, so this stays fast without a bridge.
    std::string peer = "sentinel";
    intptr_t h = manager_.accept_inbound_stream("sess", peer, 1);
    EXPECT_EQ(h, -1);
    EXPECT_TRUE(peer.empty());
}

TEST_F(I2PManagerTest, PeerFilterConfigRoundtrip) {
    I2PPeerFilter::Config cfg;
    cfg.allowlist = {"x.b32.i2p"};
    cfg.blocklist = {"y.b32.i2p"};
    cfg.max_concurrent_per_peer = 3;
    cfg.max_new_per_window = 10;
    manager_.set_peer_filter(cfg);

    auto got = manager_.get_peer_filter_config();
    EXPECT_EQ(got.allowlist.size(), 1u);
    EXPECT_EQ(got.blocklist.size(), 1u);
    EXPECT_EQ(got.max_concurrent_per_peer, 3u);
    EXPECT_EQ(got.max_new_per_window, 10u);
}

TEST_F(I2PManagerTest, StatisticsStartsNoRejectedPeers) {
    auto stats = manager_.get_statistics();
    EXPECT_EQ(stats.peers_rejected, 0u);
    EXPECT_EQ(stats.peers_accepted, 0u);
}

TEST_F(I2PManagerTest, AcceptedPeerCountMirrorsFilter) {
    I2PPeerFilter::Config cfg;
    cfg.max_new_per_window = 0;  // unlimited for this test
    manager_.set_peer_filter(cfg);
    EXPECT_EQ(manager_.accepted_peer_count(), 0u);
    EXPECT_EQ(manager_.rejected_peer_count(), 0u);
}

TEST_F(I2PManagerTest, InboundPeerCallbackCanBeRegistered) {
    int calls = 0;
    manager_.set_inbound_peer_callback(
        [&calls](const std::string&, bool, const char*) { ++calls; });
    // Registration alone must not fire anything.
    EXPECT_EQ(calls, 0);
    manager_.set_inbound_peer_callback(nullptr);
}

// ==================== Outbound policy (client side, no SAM required) ====================

TEST_F(I2PManagerTest, OutboundPolicy_DefaultAllowsValidDestination) {
    I2POutboundPolicy policy;
    auto d = policy.check("client", "peer.b32.i2p");
    EXPECT_TRUE(d.allow);
    EXPECT_STREQ(d.reason, "allowed");
}

TEST_F(I2PManagerTest, OutboundPolicy_BlocklistRejects) {
    I2POutboundPolicy::Config cfg;
    cfg.blocklist = {"evil.b32.i2p"};
    I2POutboundPolicy policy(cfg);

    auto bad = policy.check("client", "evil.b32.i2p");
    EXPECT_FALSE(bad.allow);
    EXPECT_STREQ(bad.reason, "blocklisted");
    EXPECT_TRUE(policy.check("client", "friend.b32.i2p").allow);
}

TEST_F(I2PManagerTest, OutboundPolicy_AllowlistExcludesOthers) {
    I2POutboundPolicy::Config cfg;
    cfg.allowlist = {"trusted.b32.i2p"};
    I2POutboundPolicy policy(cfg);

    EXPECT_TRUE(policy.check("client", "trusted.b32.i2p").allow);
    auto stranger = policy.check("client", "stranger.b32.i2p");
    EXPECT_FALSE(stranger.allow);
    EXPECT_STREQ(stranger.reason, "not-allowlisted");
}

TEST_F(I2PManagerTest, OutboundPolicy_RejectsMalformedDestination) {
    I2POutboundPolicy policy;
    auto spaced = policy.check("client", "has space.i2p");
    EXPECT_FALSE(spaced.allow);
    EXPECT_STREQ(spaced.reason, "invalid-destination");

    EXPECT_FALSE(policy.check("client", "").allow);
    EXPECT_STREQ(policy.check("client", "   ").reason, "empty-destination");
    EXPECT_FALSE(policy.check("client", "short").allow);  // below base64 min length
}

TEST_F(I2PManagerTest, OutboundPolicy_FormatValidation) {
    EXPECT_TRUE(I2POutboundPolicy::valid_destination_format("example.b32.i2p"));
    EXPECT_TRUE(I2POutboundPolicy::valid_destination_format(std::string(516, 'A')));
    EXPECT_FALSE(I2POutboundPolicy::valid_destination_format("example..i2p"));
    EXPECT_FALSE(I2POutboundPolicy::valid_destination_format(".i2p"));
    EXPECT_FALSE(I2POutboundPolicy::valid_destination_format("not a dest!"));
    EXPECT_TRUE(I2POutboundPolicy::normalize_destination("  a.b32.i2p\r\n") ==
                "a.b32.i2p");
}

TEST_F(I2PManagerTest, OutboundPolicy_PinsFirstDestination) {
    I2POutboundPolicy policy;
    EXPECT_TRUE(policy.check("srv", "a.b32.i2p").allow);
    policy.pin("srv", "a.b32.i2p");

    EXPECT_TRUE(policy.is_pinned("srv"));
    std::string pinned;
    EXPECT_TRUE(policy.pinned_destination("srv", pinned));
    EXPECT_EQ(pinned, "a.b32.i2p");

    EXPECT_TRUE(policy.check("srv", "a.b32.i2p").allow);
    auto changed = policy.check("srv", "b.b32.i2p");
    EXPECT_FALSE(changed.allow);
    EXPECT_STREQ(changed.reason, "destination-changed");

    // Explicit rotation is allowed once the pin is dropped.
    policy.unpin("srv");
    EXPECT_TRUE(policy.check("srv", "b.b32.i2p").allow);
}

TEST_F(I2PManagerTest, OutboundPolicy_PinDoesNotOverwrite) {
    I2POutboundPolicy policy;
    policy.pin("srv", "a.b32.i2p");
    policy.pin("srv", "b.b32.i2p");   // must be ignored
    std::string pinned;
    ASSERT_TRUE(policy.pinned_destination("srv", pinned));
    EXPECT_EQ(pinned, "a.b32.i2p");
}

TEST_F(I2PManagerTest, OutboundPolicy_AllowlistSkipsPinning) {
    I2POutboundPolicy::Config cfg;
    cfg.allowlist = {"a.b32.i2p", "b.b32.i2p"};
    I2POutboundPolicy policy(cfg);
    policy.pin("srv", "a.b32.i2p");
    EXPECT_TRUE(policy.check("srv", "b.b32.i2p").allow);
}

TEST_F(I2PManagerTest, OutboundPolicy_ValidationCanBeDisabled) {
    I2POutboundPolicy::Config cfg;
    cfg.validate_format = false;
    I2POutboundPolicy policy(cfg);
    EXPECT_TRUE(policy.check("s", "abc").allow);       // short but injection-safe
    EXPECT_FALSE(policy.check("s", "a b").allow);      // whitespace never allowed
}

TEST_F(I2PManagerTest, OutboundPolicyConfigRoundtrip) {
    I2POutboundPolicy::Config cfg;
    cfg.allowlist = {"a.b32.i2p"};
    cfg.blocklist = {"b.b32.i2p"};
    cfg.pin_first_destination = false;
    cfg.validate_format = false;
    manager_.set_outbound_policy(cfg);

    auto got = manager_.get_outbound_policy();
    EXPECT_EQ(got.allowlist.size(), 1u);
    EXPECT_EQ(got.blocklist.size(), 1u);
    EXPECT_FALSE(got.pin_first_destination);
    EXPECT_FALSE(got.validate_format);
    EXPECT_TRUE(manager_.pinned_destinations().empty());
}

TEST_F(I2PManagerTest, OutboundHistoryAndStatsStartEmpty) {
    EXPECT_TRUE(manager_.outbound_history().empty());
    auto stats = manager_.get_statistics();
    EXPECT_EQ(stats.outbound_established, 0u);
    EXPECT_EQ(stats.outbound_rejected, 0u);
    EXPECT_EQ(stats.outbound_failed, 0u);
}

TEST_F(I2PManagerTest, ConnectOutboundFailsWhenInactive) {
    EXPECT_EQ(manager_.connect_outbound_stream("srv", "peer.b32.i2p", 1), -1);
}

TEST_F(I2PManagerTest, OutboundStreamCallsRejectUnknownHandle) {
    EXPECT_FALSE(manager_.close_outbound_stream(424242));
    char b = 0;
    EXPECT_EQ(manager_.write_outbound_stream(424242, &b, 1), -1);
    EXPECT_EQ(manager_.read_outbound_stream(424242, &b, 1), -1);
}

TEST_F(I2PManagerTest, OutboundEventCallbackCanBeRegistered) {
    int calls = 0;
    manager_.set_outbound_event_callback(
        [&calls](const I2PManager::OutboundRecord&) { ++calls; });
    EXPECT_EQ(calls, 0);
    manager_.set_outbound_event_callback(nullptr);
}

} // namespace testing
} // namespace ncp
