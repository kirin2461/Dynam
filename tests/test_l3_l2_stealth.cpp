#include <gtest/gtest.h>
#include "../src/core/include/ncp_l3_stealth.hpp"
#include "../src/core/include/ncp_packet_interceptor.hpp"
#include "../src/core/include/ncp_l2_stealth.hpp"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace ncp;

// ==================== L3 Stealth Tests ====================

TEST(L3StealthTest, IPIDRandomization) {
    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = true;
    cfg.ipid_strategy = L3Stealth::IPIDStrategy::CSPRNG;
    ASSERT_TRUE(stealth.initialize(cfg));

    // Create test IPv4 packet
    std::vector<uint8_t> packet(20);
    packet[0] = 0x45; // IPv4, IHL=5
    *reinterpret_cast<uint16_t*>(&packet[4]) = htons(0x1234); // Original IPID

    uint16_t original_ipid = ntohs(*reinterpret_cast<uint16_t*>(&packet[4]));
    ASSERT_TRUE(stealth.process_ipv4_packet(packet));
    uint16_t new_ipid = ntohs(*reinterpret_cast<uint16_t*>(&packet[4]));

    EXPECT_NE(original_ipid, new_ipid);
}

TEST(L3StealthTest, TTLNormalization) {
    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ttl_normalization = true;
    cfg.os_profile = L3Stealth::OSProfile::WINDOWS_10;
    ASSERT_TRUE(stealth.initialize(cfg));

    std::vector<uint8_t> packet(20);
    packet[0] = 0x45;
    packet[8] = 64; // Original TTL

    ASSERT_TRUE(stealth.process_ipv4_packet(packet));
    EXPECT_EQ(packet[8], 128); // Windows TTL
}

TEST(L3StealthTest, MSSClamping) {
    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_mss_clamping = true;
    cfg.target_mss_ipv4 = 1400;
    ASSERT_TRUE(stealth.initialize(cfg));

    // TCP SYN packet with MSS option
    std::vector<uint8_t> packet(60);
    packet[0] = 0x45; // IPv4
    packet[9] = 6;    // TCP
    packet[20 + 13] = 0x02; // SYN flag

    // Add MSS option (kind=2, len=4, mss=1460)
    packet[40] = 2;   // MSS option kind
    packet[41] = 4;   // Length
    *reinterpret_cast<uint16_t*>(&packet[42]) = htons(1460);

    ASSERT_TRUE(stealth.process_ipv4_packet(packet));
    uint16_t new_mss = ntohs(*reinterpret_cast<uint16_t*>(&packet[42]));
    EXPECT_EQ(new_mss, 1400);
}

TEST(L3StealthTest, IPv6FlowLabel) {
    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipv6_flow_label_randomization = true;
    cfg.ipv6_flow_label_strategy = L3Stealth::FlowLabelStrategy::PER_FLOW;
    ASSERT_TRUE(stealth.initialize(cfg));

    // IPv6 packet
    std::vector<uint8_t> packet(40);
    packet[0] = 0x60; // IPv6

    ASSERT_TRUE(stealth.process_ipv6_packet(packet));
    uint32_t flow_label = (static_cast<uint32_t>(packet[1] & 0x0F) << 16) |
                          (static_cast<uint32_t>(packet[2]) << 8) |
                          static_cast<uint32_t>(packet[3]);
    EXPECT_GT(flow_label, 0u);
}

TEST(L3StealthTest, Fragmentation) {
    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_fragmentation = true;
    cfg.fragment_target_mtu = 100;
    ASSERT_TRUE(stealth.initialize(cfg));

    // Large packet (200 bytes)
    std::vector<uint8_t> packet(200);
    packet[0] = 0x45;
    *reinterpret_cast<uint16_t*>(&packet[2]) = htons(200); // Total length

    std::vector<std::vector<uint8_t>> fragments;
    ASSERT_TRUE(stealth.fragment_ipv4(packet, fragments));
    EXPECT_GT(fragments.size(), 1u);
}

// ==================== L2 Stealth Tests ====================

TEST(L2StealthTest, ARPRateLimiting) {
    L2Stealth stealth;
    L2Stealth::Config cfg;
    cfg.enable_arp_rate_shaping = true;
    cfg.arp_max_rate_per_sec = 5;
    cfg.enable_logging = false;
    ASSERT_TRUE(stealth.initialize(cfg));
    ASSERT_TRUE(stealth.start());

    // Test would require actual ARP packet injection
    // For now, just verify initialization
    EXPECT_TRUE(stealth.is_running());

    stealth.stop();
}

TEST(L2StealthTest, ProtocolSuppression) {
    L2Stealth stealth;
    L2Stealth::Config cfg;
    cfg.suppress_lldp = true;
    cfg.suppress_cdp = true;
    cfg.suppress_ssdp = true;
    cfg.use_ebtables = false; // Don't actually run ebtables in test
    cfg.enable_logging = false;
    ASSERT_TRUE(stealth.initialize(cfg));

    auto config = stealth.get_config();
    EXPECT_TRUE(config.suppress_lldp);
    EXPECT_TRUE(config.suppress_cdp);
    EXPECT_TRUE(config.suppress_ssdp);
}

TEST(L2StealthTest, VLANManagement) {
    // Test VLAN interface creation (read-only check)
    EXPECT_FALSE(L2Stealth::create_vlan_interface("", 0, ""));
}

// ==================== Combined L3+L2 Test ====================

TEST(CombinedStealthTest, L3AndL2Pipeline) {
    // L3 Stealth
    L3Stealth l3;
    L3Stealth::Config l3cfg;
    l3cfg.enable_ipid_randomization = true;
    l3cfg.enable_ttl_normalization = true;
    l3cfg.enable_mss_clamping = true;
    ASSERT_TRUE(l3.initialize(l3cfg));

    // L2 Stealth
    L2Stealth l2;
    L2Stealth::Config l2cfg;
    l2cfg.enable_arp_rate_shaping = true;
    l2cfg.suppress_lldp = true;
    l2cfg.use_arptables = false;
    l2cfg.use_ebtables = false;
    l2cfg.enable_logging = false;
    ASSERT_TRUE(l2.initialize(l2cfg));
    ASSERT_TRUE(l2.start());

    // Process packet through L3
    std::vector<uint8_t> packet(60);
    packet[0] = 0x45;
    packet[8] = 64; // TTL
    packet[9] = 6;  // TCP

    ASSERT_TRUE(l3.process_ipv4_packet(packet));
    EXPECT_EQ(packet[8], 64); // TTL normalized (depends on OS profile)

    // Stats
    auto l3stats = l3.get_stats();
    EXPECT_GT(l3stats.packets_processed, 0u);

    auto l2stats = l2.get_stats();
    // L2 stats would be > 0 if we actually sent ARP packets

    l2.stop();
}

// ==================== Packet Interceptor Tests ====================

TEST(PacketInterceptorTest, Initialization) {
    PacketInterceptor interceptor;
    PacketInterceptor::Config cfg;
    cfg.backend = PacketInterceptor::Backend::NONE; // No backend for test
    cfg.enable_logging = false;
    ASSERT_TRUE(interceptor.initialize(cfg));
}

TEST(PacketInterceptorTest, BackendDetection) {
    auto backend = PacketInterceptor::detect_backend();
    // Should return NFQUEUE on Linux with HAVE_NFQUEUE, NONE otherwise
#if defined(__linux__) && defined(HAVE_NFQUEUE)
    EXPECT_EQ(backend, PacketInterceptor::Backend::NFQUEUE);
#else
    EXPECT_EQ(backend, PacketInterceptor::Backend::NONE);
#endif
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
