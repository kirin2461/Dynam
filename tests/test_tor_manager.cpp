#include <gtest/gtest.h>
#include "ncp_tor_manager.hpp"

using ncp::TorManager;
using ncp::TorLaunchConfig;

static TorLaunchConfig sample_cfg() {
    TorLaunchConfig c;
    c.tor_binary = "/usr/bin/tor";
    c.bridges = {
        "obfs4 1.2.3.4:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAA iat-mode=0",
        "obfs4 5.6.7.8:443 FEDCBA9876543210FEDCBA9876543210FEDCBA98 cert=BBB iat-mode=1",
    };
    c.obfs4_binary = "/usr/bin/lyrebird";
    c.snowflake_binary = "/usr/bin/snowflake-client";
    return c;
}

TEST(TorManagerTest, TorrcContainsBridgesAndPlugins) {
    auto cfg = sample_cfg();
    std::string rc = TorManager::build_torrc(cfg, 19050, "/tmp/ncp-tor-test");
    EXPECT_NE(rc.find("SocksPort 127.0.0.1:19050"), std::string::npos);
    EXPECT_NE(rc.find("UseBridges 1"), std::string::npos);
    EXPECT_NE(rc.find("ClientTransportPlugin obfs4 exec \"/usr/bin/lyrebird\""),
              std::string::npos);
    EXPECT_NE(rc.find("ClientTransportPlugin snowflake exec \"/usr/bin/snowflake-client\""),
              std::string::npos);
    EXPECT_NE(rc.find("Bridge obfs4 1.2.3.4:443"), std::string::npos);
    EXPECT_NE(rc.find("cert=AAA"), std::string::npos);
    EXPECT_NE(rc.find("DataDirectory \"/tmp/ncp-tor-test\""), std::string::npos);
}

TEST(TorManagerTest, TorrcWithoutBridgesHasNoUseBridges) {
    TorLaunchConfig c;
    c.tor_binary = "/usr/bin/tor";
    std::string rc = TorManager::build_torrc(c, 9050, "/tmp/x");
    EXPECT_EQ(rc.find("UseBridges"), std::string::npos);
    EXPECT_EQ(rc.find("ClientTransportPlugin"), std::string::npos);
    EXPECT_NE(rc.find("SocksPort 127.0.0.1:9050"), std::string::npos);
}

TEST(TorManagerTest, ParseBootstrapPercent) {
    EXPECT_EQ(TorManager::parse_bootstrap_percent(
                  "[notice] Bootstrapped 0% (starting): Starting"), 0);
    EXPECT_EQ(TorManager::parse_bootstrap_percent(
                  "[notice] Bootstrapped 45% (loading_descriptors): Loading"), 45);
    EXPECT_EQ(TorManager::parse_bootstrap_percent(
                  "[notice] Bootstrapped 100% (done): Done"), 100);
    EXPECT_EQ(TorManager::parse_bootstrap_percent("[notice] Some other line"), -1);
    EXPECT_EQ(TorManager::parse_bootstrap_percent(""), -1);
}

TEST(TorManagerTest, PickFreePortReturnsUsablePort) {
    uint16_t p = TorManager::pick_free_port();
    EXPECT_GT(p, 0);
}

TEST(TorManagerTest, StartFailsOnMissingBinary) {
    TorLaunchConfig c;
    c.tor_binary = "/nonexistent/tor-binary-xyz";
    c.bootstrap_timeout_sec = 2;
    TorManager m;
    std::string err;
    EXPECT_FALSE(m.start(c, &err));
    EXPECT_FALSE(err.empty());
    EXPECT_FALSE(m.running());
}

TEST(TorManagerTest, StartFailsOnEmptyBinary) {
    TorLaunchConfig c;
    TorManager m;
    std::string err;
    EXPECT_FALSE(m.start(c, &err));
    EXPECT_FALSE(m.running());
}
