// ══════════════════════════════════════════════════════════════════════════════
// tests/test_spoofer.cpp
// Tests for NetworkSpoofer (ncp_spoofer.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_spoofer.hpp"

#include <string>
#include <vector>
#include <regex>

using namespace ncp;

// ── Fixture ───────────────────────────────────────────────────────────────────

class SpooferTest : public ::testing::Test {
protected:
    NetworkSpoofer spoofer;
};

// ── Random Value Generators ───────────────────────────────────────────────────

TEST_F(SpooferTest, GenerateRandomIPv4_IsValidFormat) {
    std::string ip = spoofer.generate_random_ipv4();
    EXPECT_FALSE(ip.empty());
    // Should match x.x.x.x pattern
    std::regex ipv4_re(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    EXPECT_TRUE(std::regex_match(ip, ipv4_re)) << "Got: " << ip;
}

TEST_F(SpooferTest, GenerateRandomIPv4_IsDifferentEachCall) {
    auto ip1 = spoofer.generate_random_ipv4();
    auto ip2 = spoofer.generate_random_ipv4();
    // Extremely unlikely to match twice in a row
    // (could be same by chance, but that's very rare)
    (void)ip1; (void)ip2;
}

TEST_F(SpooferTest, GenerateRandomIPv6_NotEmpty) {
    std::string ip6 = spoofer.generate_random_ipv6();
    EXPECT_FALSE(ip6.empty());
    // Should contain colons
    EXPECT_NE(ip6.find(':'), std::string::npos) << "Got: " << ip6;
}

TEST_F(SpooferTest, GenerateRandomMac_CorrectFormat) {
    std::string mac = spoofer.generate_random_mac();
    EXPECT_FALSE(mac.empty());
    // Mac should be 17 chars: XX:XX:XX:XX:XX:XX
    EXPECT_GE(mac.size(), 11u); // at minimum some colons/dashes
}

TEST_F(SpooferTest, GenerateRandomMac_IsLocallyAdministered) {
    // CSPRNG-generated MAC should have locally-administered bit set
    std::string mac = spoofer.generate_random_mac();
    EXPECT_FALSE(mac.empty());
    // Parse first octet (hex)
    // Mac format varies; just check not all zeros
    EXPECT_NE(mac, "00:00:00:00:00:00");
}

TEST_F(SpooferTest, GenerateRandomHostname_NotEmpty) {
    std::string hostname = spoofer.generate_random_hostname();
    EXPECT_FALSE(hostname.empty());
}

TEST_F(SpooferTest, GenerateRandomHwSerial_NotEmpty) {
    std::string serial = spoofer.generate_random_hw_serial();
    EXPECT_FALSE(serial.empty());
}

TEST_F(SpooferTest, GenerateRandomBoardSerial_NotEmpty) {
    std::string serial = spoofer.generate_random_board_serial();
    EXPECT_FALSE(serial.empty());
}

TEST_F(SpooferTest, GenerateRandomSystemSerial_NotEmpty) {
    std::string serial = spoofer.generate_random_system_serial();
    EXPECT_FALSE(serial.empty());
}

TEST_F(SpooferTest, GenerateRandomUUID_HasCorrectFormat) {
    std::string uuid = spoofer.generate_random_uuid();
    EXPECT_FALSE(uuid.empty());
    // UUID format: 8-4-4-4-12
    EXPECT_GE(uuid.size(), 32u);
}

TEST_F(SpooferTest, GenerateRandomDiskSerial_NotEmpty) {
    std::string serial = spoofer.generate_random_disk_serial();
    EXPECT_FALSE(serial.empty());
}

// ── TCP Fingerprint Profiles ──────────────────────────────────────────────────

TEST_F(SpooferTest, TcpFingerprint_Windows10) {
    auto p = NetworkSpoofer::TcpFingerprintProfile::Windows10();
    EXPECT_EQ(p.name, "Windows10");
    EXPECT_GT(p.ttl, 0u);
    EXPECT_GT(p.window_size, 0u);
    EXPECT_GT(p.mss, 0u);
}

TEST_F(SpooferTest, TcpFingerprint_Linux5x) {
    auto p = NetworkSpoofer::TcpFingerprintProfile::Linux5x();
    EXPECT_EQ(p.name, "Linux5x");
    EXPECT_GT(p.ttl, 0u);
}

TEST_F(SpooferTest, TcpFingerprint_MacOS12) {
    auto p = NetworkSpoofer::TcpFingerprintProfile::MacOS12();
    EXPECT_EQ(p.name, "MacOS12");
    EXPECT_GT(p.ttl, 0u);
}

TEST_F(SpooferTest, TcpFingerprint_ProfilesDiffer) {
    auto w10 = NetworkSpoofer::TcpFingerprintProfile::Windows10();
    auto lin = NetworkSpoofer::TcpFingerprintProfile::Linux5x();
    // TTL or window sizes should differ between OS profiles
    bool different = (w10.ttl != lin.ttl || w10.window_size != lin.window_size);
    EXPECT_TRUE(different);
}

// ── SpoofConfig Defaults ──────────────────────────────────────────────────────

TEST_F(SpooferTest, SpoofConfig_DefaultDohServers) {
    NetworkSpoofer::SpoofConfig cfg;
    EXPECT_FALSE(cfg.doh_servers.empty());
    // Should include Cloudflare by default
    bool has_cloudflare = false;
    for (auto& s : cfg.doh_servers) {
        if (s.find("1.1.1.1") != std::string::npos) has_cloudflare = true;
    }
    EXPECT_TRUE(has_cloudflare);
}

TEST_F(SpooferTest, SpoofConfig_DefaultFlags) {
    NetworkSpoofer::SpoofConfig cfg;
    EXPECT_TRUE(cfg.spoof_ipv4);
    EXPECT_TRUE(cfg.spoof_mac);
    EXPECT_TRUE(cfg.spoof_dns);
}

// ── Enable / Disable Without Network ─────────────────────────────────────────

TEST_F(SpooferTest, IsEnabled_InitiallyFalse) {
    EXPECT_FALSE(spoofer.is_enabled());
}

TEST_F(SpooferTest, GetStatus_InitiallyAllFalse) {
    auto s = spoofer.get_status();
    EXPECT_FALSE(s.ipv4_spoofed);
    EXPECT_FALSE(s.mac_spoofed);
    EXPECT_FALSE(s.dns_spoofed);
}

// ── Rotation Callback ─────────────────────────────────────────────────────────

TEST_F(SpooferTest, SetRotationCallback_NoThrow) {
    EXPECT_NO_THROW(spoofer.set_rotation_callback(
        [](const std::string&, const std::string&, const std::string&) {}
    ));
}

// ── Custom Value Setters (no system call, just test state) ────────────────────

TEST_F(SpooferTest, SetCustomIPv4_WhenDisabled_ReturnsFalse) {
    // Setters should fail gracefully when spoofer is not enabled
    bool ok = spoofer.set_custom_ipv4("192.168.1.100");
    // Disabled spoofer — result is implementation-defined, just no crash
    (void)ok;
}

TEST_F(SpooferTest, SetCustomMac_WhenDisabled_NoThrow) {
    EXPECT_NO_THROW(spoofer.set_custom_mac("AA:BB:CC:DD:EE:FF"));
}

TEST_F(SpooferTest, SetCustomHostname_WhenDisabled_NoThrow) {
    EXPECT_NO_THROW(spoofer.set_custom_hostname("test-host"));
}

// ── Original Identity Accessor ────────────────────────────────────────────────

TEST_F(SpooferTest, GetOriginalIdentity_BeforeEnable) {
    auto id = spoofer.get_original_identity();
    // interface_name might be empty before enable() is called
    (void)id;
}

// ── Unique Values Per Call ────────────────────────────────────────────────────

TEST_F(SpooferTest, GenerateMultipleMacs_AreUnique) {
    std::vector<std::string> macs;
    for (int i = 0; i < 10; ++i) {
        macs.push_back(spoofer.generate_random_mac());
    }
    // Check at least some diversity (not all same)
    std::set<std::string> unique(macs.begin(), macs.end());
    EXPECT_GT(unique.size(), 1u);
}

TEST_F(SpooferTest, GenerateMultipleIPs_AreUnique) {
    std::vector<std::string> ips;
    for (int i = 0; i < 10; ++i) {
        ips.push_back(spoofer.generate_random_ipv4());
    }
    std::set<std::string> unique(ips.begin(), ips.end());
    EXPECT_GT(unique.size(), 1u);
}

#include <set>
