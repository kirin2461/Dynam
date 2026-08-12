#include <gtest/gtest.h>
#include "ncp_dpi.hpp"

using ncp::DPI::build_kill_switch_filter;
using ncp::DPI::DPIConfig;

TEST(KillSwitchTest, DefaultIsOff) {
    // Safety invariant: kill switch must NEVER be on by default
    // (an iptables predecessor once locked a whole server out).
    DPIConfig cfg;
    EXPECT_FALSE(cfg.kill_switch);
    EXPECT_EQ(cfg.kill_switch_allow_port, 0);
    EXPECT_TRUE(cfg.kill_switch_allow_host.empty());
}

TEST(KillSwitchTest, FilterBlocksDirectOutbound) {
    std::string f = build_kill_switch_filter("", 0);
    EXPECT_NE(f.find("outbound"), std::string::npos);
    EXPECT_NE(f.find("!loopback"), std::string::npos);   // local proxy/Tor exempt
    EXPECT_NE(f.find("udp.DstPort != 53"), std::string::npos);  // DNS hook owns 53
    EXPECT_NE(f.find("udp.DstPort != 67"), std::string::npos);  // DHCP exempt
    EXPECT_EQ(f.find("ip.DstAddr =="), std::string::npos);      // no allow endpoint
}

TEST(KillSwitchTest, FilterWithAllowEndpoint) {
    std::string f = build_kill_switch_filter("10.0.0.1", 9050);
    EXPECT_NE(f.find("ip.DstAddr == 10.0.0.1"), std::string::npos);
    EXPECT_NE(f.find("tcp.DstPort == 9050"), std::string::npos);
}
