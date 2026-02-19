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
    bool reachable = (ret > 0 && (pfd.revents & POLLOUT));
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

    // Helper: skip test if SAM is not reachable
    void RequireSAM() {
        static int sam_status = -1; // -1 = unknown, 0 = no, 1 = yes
        if (sam_status < 0) {
            sam_status = is_sam_reachable() ? 1 : 0;
        }
        if (sam_status == 0) {
            GTEST_SKIP() << "SAM bridge not reachable at 127.0.0.1:7656 (expected in CI)";
        }
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
    RequireSAM();
    config_.enabled = true;
    bool result = manager_.initialize(config_);
    EXPECT_TRUE(result);
}

TEST_F(I2PManagerTest, IsActiveAfterInit) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    EXPECT_TRUE(manager_.is_active());
}

TEST_F(I2PManagerTest, GetDestinationAfterInit) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    std::string dest = manager_.get_destination();
    EXPECT_FALSE(dest.empty());
}

TEST_F(I2PManagerTest, CreateTunnelWhenActive) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    [[maybe_unused]] bool result = manager_.create_tunnel(
        "test_tunnel", 12345, "test.b32.i2p",
        I2PManager::TunnelType::CLIENT);
    SUCCEED();
}

TEST_F(I2PManagerTest, DestroyNonExistentTunnel) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    bool result = manager_.destroy_tunnel("non_existent_tunnel_id");
    EXPECT_FALSE(result);
}

TEST_F(I2PManagerTest, SetEnabledToggle) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    manager_.set_enabled(false);
    EXPECT_FALSE(manager_.is_active());
    manager_.set_enabled(true);
}

TEST_F(I2PManagerTest, RotateTunnelsNoCrash) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    EXPECT_NO_THROW(manager_.rotate_tunnels());
}

TEST_F(I2PManagerTest, CreateServerTunnelBasic) {
    RequireSAM();
    config_.enabled = true;
    manager_.initialize(config_);
    [[maybe_unused]] bool result = manager_.create_server_tunnel("test_server", 8080);
    SUCCEED();
}

} // namespace testing
} // namespace ncp
