// ══════════════════════════════════════════════════════════════════════════════
// tests/test_probe_resist.cpp
// Tests for ProbeResist (ncp_probe_resist.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_probe_resist.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <array>

using namespace ncp::DPI;

// ── Fixture ───────────────────────────────────────────────────────────────────

class ProbeResistTest : public ::testing::Test {
protected:
    ProbeResistConfig make_config() {
        ProbeResistConfig cfg;
        cfg.enable_auth = true;
        cfg.shared_secret.assign(32, 0xAA);
        cfg.enable_replay_protection = true;
        cfg.enable_rate_limit = true;
        cfg.rate_limit_per_ip = 100; // permissive for tests
        cfg.rate_limit_window_sec = 3600;
        cfg.enable_ip_reputation = true;
        cfg.ban_threshold = -20;    // hard to hit in tests
        cfg.enable_pattern_detection = false; // off to simplify
        cfg.enable_ja3_filter = false;
        return cfg;
    }
};

// ── String Conversion ─────────────────────────────────────────────────────────

TEST_F(ProbeResistTest, CoverModeToString) {
    EXPECT_STRNE(cover_mode_to_string(CoverMode::REDIRECT),   "");
    EXPECT_STRNE(cover_mode_to_string(CoverMode::MIRROR),     "");
    EXPECT_STRNE(cover_mode_to_string(CoverMode::RESET),      "");
    EXPECT_STRNE(cover_mode_to_string(CoverMode::DROP),       "");
    EXPECT_STRNE(cover_mode_to_string(CoverMode::ECHO_NGINX), "");
    EXPECT_STRNE(cover_mode_to_string(CoverMode::ECHO_IIS),   "");
    EXPECT_STRNE(cover_mode_to_string(CoverMode::ECHO_APACHE),"");
}

TEST_F(ProbeResistTest, CoverModeFromString_Roundtrip) {
    EXPECT_EQ(cover_mode_from_string("nginx"),   CoverMode::ECHO_NGINX);
    EXPECT_EQ(cover_mode_from_string("apache"),  CoverMode::ECHO_APACHE);
    EXPECT_EQ(cover_mode_from_string("redirect"),CoverMode::REDIRECT);
    EXPECT_EQ(cover_mode_from_string("reset"),   CoverMode::RESET);
    EXPECT_EQ(cover_mode_from_string("drop"),    CoverMode::DROP);
}

TEST_F(ProbeResistTest, AuthResultToString) {
    EXPECT_STRNE(auth_result_to_string(AuthResult::AUTHENTICATED),   "");
    EXPECT_STRNE(auth_result_to_string(AuthResult::REPLAY_DETECTED), "");
    EXPECT_STRNE(auth_result_to_string(AuthResult::INVALID_HMAC),    "");
    EXPECT_STRNE(auth_result_to_string(AuthResult::NO_AUTH_DATA),    "");
}

// ── Config Presets ─────────────────────────────────────────────────────────────

TEST_F(ProbeResistTest, ConfigPreset_Strict) {
    auto cfg = ProbeResistConfig::strict();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.enable_auth);
    EXPECT_TRUE(cfg.enable_replay_protection);
}

TEST_F(ProbeResistTest, ConfigPreset_Balanced) {
    auto cfg = ProbeResistConfig::balanced();
    EXPECT_TRUE(cfg.enabled);
}

TEST_F(ProbeResistTest, ConfigPreset_Permissive) {
    auto cfg = ProbeResistConfig::permissive();
    EXPECT_TRUE(cfg.enabled);
}

// ── HMAC Authentication ────────────────────────────────────────────────────────

TEST_F(ProbeResistTest, GenerateClientAuth_CorrectSize) {
    ProbeResist pr(make_config());
    auto auth = pr.generate_client_auth();
    // [nonce(16) | timestamp(4) | hmac(32)] = 52 bytes
    EXPECT_EQ(auth.size(), 52u);
}

TEST_F(ProbeResistTest, GenerateClientAuth_Nonce_IsDifferentEachCall) {
    ProbeResist pr(make_config());
    auto auth1 = pr.generate_client_auth();
    auto auth2 = pr.generate_client_auth();
    // Nonces should differ
    EXPECT_NE(auth1, auth2);
}

TEST_F(ProbeResistTest, VerifyAuth_ValidToken) {
    ProbeResist pr(make_config());
    auto auth = pr.generate_client_auth();
    EXPECT_TRUE(pr.verify_auth(auth.data(), auth.size()));
}

TEST_F(ProbeResistTest, VerifyAuth_InvalidToken) {
    ProbeResist pr(make_config());
    std::vector<uint8_t> garbage(52, 0xFF);
    EXPECT_FALSE(pr.verify_auth(garbage.data(), garbage.size()));
}

TEST_F(ProbeResistTest, VerifyAuth_EmptyData) {
    ProbeResist pr(make_config());
    EXPECT_FALSE(pr.verify_auth(nullptr, 0));
}

TEST_F(ProbeResistTest, ComputeHmac_Deterministic) {
    ProbeResist pr(make_config());
    std::vector<uint8_t> data = {1, 2, 3, 4};
    std::vector<uint8_t> key(32, 0xBB);
    auto h1 = pr.compute_hmac(data.data(), data.size(), key.data(), key.size());
    auto h2 = pr.compute_hmac(data.data(), data.size(), key.data(), key.size());
    EXPECT_EQ(h1, h2);
}

TEST_F(ProbeResistTest, ComputeHmac_DiffersForDifferentData) {
    ProbeResist pr(make_config());
    std::vector<uint8_t> key(32, 0xBB);
    std::vector<uint8_t> d1 = {1, 2, 3};
    std::vector<uint8_t> d2 = {4, 5, 6};
    auto h1 = pr.compute_hmac(d1.data(), d1.size(), key.data(), key.size());
    auto h2 = pr.compute_hmac(d2.data(), d2.size(), key.data(), key.size());
    EXPECT_NE(h1, h2);
}

// ── Replay Protection ─────────────────────────────────────────────────────────

TEST_F(ProbeResistTest, CheckAndRecordNonce_FirstTime_True) {
    ProbeResist pr(make_config());
    std::vector<uint8_t> nonce(16, 0x01);
    EXPECT_TRUE(pr.check_and_record_nonce(nonce.data(), nonce.size()));
}

TEST_F(ProbeResistTest, CheckAndRecordNonce_SecondTime_False) {
    ProbeResist pr(make_config());
    std::vector<uint8_t> nonce(16, 0x02);
    pr.check_and_record_nonce(nonce.data(), nonce.size());
    EXPECT_FALSE(pr.check_and_record_nonce(nonce.data(), nonce.size()));
}

TEST_F(ProbeResistTest, ProcessConnection_ValidAuth_Authenticated) {
    ProbeResist pr(make_config());
    auto auth = pr.generate_client_auth();
    auto result = pr.process_connection("10.0.0.1", 1234,
                                        auth.data(), auth.size(), "");
    EXPECT_EQ(result, AuthResult::AUTHENTICATED);
}

TEST_F(ProbeResistTest, ProcessConnection_NoAuthData_Rejected) {
    ProbeResist pr(make_config());
    std::vector<uint8_t> empty;
    auto result = pr.process_connection("10.0.0.2", 1234,
                                        empty.data(), empty.size(), "");
    EXPECT_NE(result, AuthResult::AUTHENTICATED);
}

TEST_F(ProbeResistTest, ProcessConnection_ReplayDetected) {
    ProbeResist pr(make_config());
    auto auth = pr.generate_client_auth();
    pr.process_connection("10.0.0.3", 1234, auth.data(), auth.size(), "");
    // Second use of same auth token → replay
    auto result = pr.process_connection("10.0.0.3", 1234, auth.data(), auth.size(), "");
    EXPECT_EQ(result, AuthResult::REPLAY_DETECTED);
}

// ── Cover Response Generation ─────────────────────────────────────────────────

TEST_F(ProbeResistTest, GenerateNginxDefault_NotEmpty) {
    auto r = ProbeResist::generate_nginx_default();
    EXPECT_FALSE(r.empty());
    // Should contain nginx signature bytes
    std::string s(r.begin(), r.end());
    EXPECT_NE(s.find("nginx"), std::string::npos);
}

TEST_F(ProbeResistTest, GenerateIisDefault_NotEmpty) {
    auto r = ProbeResist::generate_iis_default();
    EXPECT_FALSE(r.empty());
}

TEST_F(ProbeResistTest, GenerateApacheDefault_NotEmpty) {
    auto r = ProbeResist::generate_apache_default();
    EXPECT_FALSE(r.empty());
}

TEST_F(ProbeResistTest, GenerateRedirect_ContainsUrl) {
    std::string url = "https://www.example.com";
    auto r = ProbeResist::generate_redirect(url);
    EXPECT_FALSE(r.empty());
    std::string s(r.begin(), r.end());
    EXPECT_NE(s.find("example.com"), std::string::npos);
}

TEST_F(ProbeResistTest, GenerateCoverResponse_ConfiguredMode) {
    ProbeResistConfig cfg = make_config();
    cfg.cover_mode = CoverMode::ECHO_NGINX;
    ProbeResist pr(cfg);
    auto r = pr.generate_cover_response();
    EXPECT_FALSE(r.empty());
}

// ── IP Reputation / Banning ───────────────────────────────────────────────────

TEST_F(ProbeResistTest, InitialReputation_NotBanned) {
    ProbeResist pr(make_config());
    EXPECT_FALSE(pr.is_ip_banned("192.168.1.1"));
}

TEST_F(ProbeResistTest, BanIp_IsBanned) {
    ProbeResist pr(make_config());
    pr.ban_ip("192.168.1.2", 3600);
    EXPECT_TRUE(pr.is_ip_banned("192.168.1.2"));
}

TEST_F(ProbeResistTest, UnbanIp) {
    ProbeResist pr(make_config());
    pr.ban_ip("192.168.1.3", 3600);
    pr.unban_ip("192.168.1.3");
    EXPECT_FALSE(pr.is_ip_banned("192.168.1.3"));
}

TEST_F(ProbeResistTest, GetBannedIps_IncludesBanned) {
    ProbeResist pr(make_config());
    pr.ban_ip("10.1.1.1", 3600);
    auto banned = pr.get_banned_ips();
    bool found = false;
    for (auto& ip : banned) if (ip == "10.1.1.1") found = true;
    EXPECT_TRUE(found);
}

// ── JA3 Filter ────────────────────────────────────────────────────────────────

TEST_F(ProbeResistTest, JA3Allowlist_AddRemove) {
    ProbeResist pr(make_config());
    std::string ja3 = "abc123def456";
    pr.add_ja3_allowlist(ja3);
    EXPECT_TRUE(pr.is_ja3_allowed(ja3));
    pr.remove_ja3_allowlist(ja3);
    EXPECT_FALSE(pr.is_ja3_allowed(ja3));
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(ProbeResistTest, InitialStats_AllZero) {
    ProbeResist pr(make_config());
    auto s = pr.get_stats();
    EXPECT_EQ(s.total_connections.load(), 0u);
    EXPECT_EQ(s.authenticated.load(), 0u);
}

TEST_F(ProbeResistTest, StatsIncrementOnConnection) {
    ProbeResist pr(make_config());
    auto auth = pr.generate_client_auth();
    pr.process_connection("1.2.3.4", 100, auth.data(), auth.size(), "");
    auto s = pr.get_stats();
    EXPECT_GT(s.total_connections.load(), 0u);
}

TEST_F(ProbeResistTest, ResetStats) {
    ProbeResist pr(make_config());
    auto auth = pr.generate_client_auth();
    pr.process_connection("1.2.3.5", 100, auth.data(), auth.size(), "");
    pr.reset_stats();
    auto s = pr.get_stats();
    EXPECT_EQ(s.total_connections.load(), 0u);
}
