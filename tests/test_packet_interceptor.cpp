// ══════════════════════════════════════════════════════════════════════════════
// tests/test_packet_interceptor.cpp
// Tests for PacketInterceptor (ncp_packet_interceptor.hpp)
//
// NOTE: Actual packet capture requires kernel privileges (NFQUEUE / WinDivert).
//       These tests cover configuration, lifecycle, and setup paths only.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_packet_interceptor.hpp"

#include <vector>
#include <string>
#include <atomic>

using namespace ncp;

// ── Fixture ───────────────────────────────────────────────────────────────────

class PacketInterceptorTest : public ::testing::Test {
protected:
    PacketInterceptor::Config make_none_config() {
        PacketInterceptor::Config cfg;
        cfg.backend = PacketInterceptor::Backend::NONE;
        cfg.enable_mtu_enforcement = false;
        cfg.enable_post_tunnel_ttl_rewrite = false;
        cfg.integrate_l3_stealth = false;
        cfg.enable_logging = false;
        return cfg;
    }
};

// ── Static Helper Tests ────────────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, DetectBackend_ReturnsValidEnum) {
    auto backend = PacketInterceptor::detect_backend();
    // Just verify it returns one of the known values
    bool valid = (backend == PacketInterceptor::Backend::AUTO     ||
                  backend == PacketInterceptor::Backend::NFQUEUE  ||
                  backend == PacketInterceptor::Backend::WINDIVERT||
                  backend == PacketInterceptor::Backend::WFP      ||
                  backend == PacketInterceptor::Backend::NONE);
    EXPECT_TRUE(valid);
}

TEST_F(PacketInterceptorTest, IsElevated_ReturnsBool) {
    bool result = PacketInterceptor::is_elevated();
    (void)result; // just ensure no crash; may be true or false in test env
}

TEST_F(PacketInterceptorTest, IsNfqueueAvailable_ReturnsBool) {
    bool result = PacketInterceptor::is_nfqueue_available();
    (void)result;
}

TEST_F(PacketInterceptorTest, IsWindivertAvailable_ReturnsBool) {
    bool result = PacketInterceptor::is_windivert_available();
    (void)result;
}

TEST_F(PacketInterceptorTest, IsWfpAvailable_ReturnsBool) {
    bool result = PacketInterceptor::is_wfp_available();
    (void)result;
}

// ── Construction ──────────────────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, DefaultConstructor_NotRunning) {
    PacketInterceptor pi;
    EXPECT_FALSE(pi.is_running());
}

TEST_F(PacketInterceptorTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ PacketInterceptor pi; });
}

// ── Initialization with NONE Backend ─────────────────────────────────────────

TEST_F(PacketInterceptorTest, Initialize_NoneBackend_Succeeds) {
    PacketInterceptor pi;
    bool ok = pi.initialize(make_none_config());
    EXPECT_TRUE(ok);
}

TEST_F(PacketInterceptorTest, Initialize_NoneBackend_NotRunningAfterInit) {
    PacketInterceptor pi;
    pi.initialize(make_none_config());
    EXPECT_FALSE(pi.is_running()); // not started yet
}

// ── Start / Stop ──────────────────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, Start_NoneBackend_Succeeds) {
    PacketInterceptor pi;
    pi.initialize(make_none_config());
    bool ok = pi.start();
    EXPECT_TRUE(ok);
    EXPECT_TRUE(pi.is_running());
    pi.stop();
}

TEST_F(PacketInterceptorTest, Stop_AfterStart) {
    PacketInterceptor pi;
    pi.initialize(make_none_config());
    pi.start();
    pi.stop();
    EXPECT_FALSE(pi.is_running());
}

TEST_F(PacketInterceptorTest, DoubleStop_IsIdempotent) {
    PacketInterceptor pi;
    pi.initialize(make_none_config());
    pi.start();
    pi.stop();
    EXPECT_NO_THROW(pi.stop());
}

TEST_F(PacketInterceptorTest, StopWithoutStart_NoThrow) {
    PacketInterceptor pi;
    EXPECT_NO_THROW(pi.stop());
}

// ── Config Management ─────────────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, GetConfig_AfterInitialize) {
    PacketInterceptor pi;
    auto cfg = make_none_config();
    cfg.enforce_mtu = 1400;
    pi.initialize(cfg);
    auto got = pi.get_config();
    EXPECT_EQ(got.enforce_mtu, 1400);
}

TEST_F(PacketInterceptorTest, UpdateConfig_BeforeStart) {
    PacketInterceptor pi;
    pi.initialize(make_none_config());
    auto cfg = make_none_config();
    cfg.enforce_mtu = 1280;
    bool ok = pi.update_config(cfg);
    EXPECT_TRUE(ok);
    EXPECT_EQ(pi.get_config().enforce_mtu, 1280);
}

TEST_F(PacketInterceptorTest, UpdateConfig_WhileRunning) {
    PacketInterceptor pi;
    pi.initialize(make_none_config());
    pi.start();
    auto cfg = make_none_config();
    cfg.target_ttl = 128;
    bool ok = pi.update_config(cfg);
    EXPECT_TRUE(ok);
    pi.stop();
}

// ── Packet Handler Registration ───────────────────────────────────────────────

TEST_F(PacketInterceptorTest, SetPacketHandler_NoThrow) {
    PacketInterceptor pi;
    EXPECT_NO_THROW(pi.set_packet_handler([](std::vector<uint8_t>& pkt, bool) {
        (void)pkt;
        return PacketInterceptor::Verdict::ACCEPT;
    }));
}

TEST_F(PacketInterceptorTest, SetPacketHandler_BeforeInit_NoThrow) {
    PacketInterceptor pi;
    int call_count = 0;
    EXPECT_NO_THROW(pi.set_packet_handler(
        [&](std::vector<uint8_t>& pkt, bool outbound) -> PacketInterceptor::Verdict {
            call_count++;
            (void)pkt;
            (void)outbound;
            return PacketInterceptor::Verdict::ACCEPT;
        }
    ));
}

TEST_F(PacketInterceptorTest, SetLogCallback_NoThrow) {
    PacketInterceptor pi;
    EXPECT_NO_THROW(pi.set_log_callback([](const std::string&) {}));
}

// ── Config Field Validation ────────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, Config_TunnelProtocol_NONE) {
    PacketInterceptor::Config cfg;
    cfg.tunnel_protocol = PacketInterceptor::TunnelProtocol::NONE;
    EXPECT_FALSE(cfg.enable_tunneling);
}

TEST_F(PacketInterceptorTest, Config_Obfuscation_KeySet) {
    PacketInterceptor::Config cfg;
    cfg.enable_protocol_obfuscation = true;
    cfg.obfuscation_key = {0x01, 0x02, 0x03, 0x04};
    EXPECT_FALSE(cfg.obfuscation_key.empty());
}

TEST_F(PacketInterceptorTest, Config_WinDivert_DefaultFilter) {
    PacketInterceptor::Config cfg;
    EXPECT_FALSE(cfg.windivert_filter.empty());
}

TEST_F(PacketInterceptorTest, Config_NfqueueDefaults) {
    PacketInterceptor::Config cfg;
    EXPECT_EQ(cfg.nfqueue_num, 0u);
    EXPECT_GT(cfg.nfqueue_max_len, 0u);
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, InitialStats_AllZero) {
    PacketInterceptor pi;
    auto s = pi.get_stats();
    EXPECT_EQ(s.packets_intercepted.load(), 0u);
    EXPECT_EQ(s.packets_modified.load(),    0u);
    EXPECT_EQ(s.bytes_processed.load(),     0u);
}

TEST_F(PacketInterceptorTest, ResetStats_NoThrow) {
    PacketInterceptor pi;
    EXPECT_NO_THROW(pi.reset_stats());
}

// ── L3Stealth Integration Setup ───────────────────────────────────────────────

TEST_F(PacketInterceptorTest, Config_L3StealthIntegration_DefaultEnabled) {
    PacketInterceptor::Config cfg;
    EXPECT_TRUE(cfg.integrate_l3_stealth);
}

TEST_F(PacketInterceptorTest, Config_L3StealthIntegration_Disable) {
    PacketInterceptor pi;
    auto cfg = make_none_config();
    cfg.integrate_l3_stealth = false;
    bool ok = pi.initialize(cfg);
    EXPECT_TRUE(ok);
    EXPECT_FALSE(pi.get_config().integrate_l3_stealth);
}

// ── Verdict Enum Completeness ─────────────────────────────────────────────────

TEST_F(PacketInterceptorTest, VerdictEnum_ValuesExist) {
    auto accept  = PacketInterceptor::Verdict::ACCEPT;
    auto drop    = PacketInterceptor::Verdict::DROP;
    auto mod     = PacketInterceptor::Verdict::MODIFIED;
    auto queue   = PacketInterceptor::Verdict::QUEUE;
    EXPECT_NE(accept, drop);
    EXPECT_NE(mod,    queue);
}
