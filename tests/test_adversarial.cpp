// ══════════════════════════════════════════════════════════════════════════════
// tests/test_adversarial.cpp
// Tests for AdversarialPadding (ncp_adversarial.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_adversarial.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <numeric>

using namespace ncp::DPI;

// ── Fixture ───────────────────────────────────────────────────────────────────

class AdversarialTest : public ::testing::Test {
protected:
    std::vector<uint8_t> make_payload(size_t n = 128) {
        std::vector<uint8_t> v(n);
        for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i & 0xFF);
        return v;
    }

    // Helper: build a minimal 20-byte TCP header for mutation tests
    std::vector<uint8_t> make_tcp_header() {
        std::vector<uint8_t> h(20, 0);
        h[12] = 0x50; // data offset = 5 (20 bytes), no flags
        return h;
    }
};

// ── Strategy String Conversion ────────────────────────────────────────────────

TEST_F(AdversarialTest, StrategyToString_AllModes) {
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::RANDOM),    "");
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::HTTP_MIMIC), "");
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::TLS_MIMIC),  "");
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::QUIC_MIMIC), "");
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::DNS_MIMIC),  "");
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::ADAPTIVE),   "");
    EXPECT_STRNE(strategy_to_string(AdversarialStrategy::CUSTOM),     "");
}

TEST_F(AdversarialTest, StrategyFromString_Roundtrip) {
    EXPECT_EQ(strategy_from_string("random"),     AdversarialStrategy::RANDOM);
    EXPECT_EQ(strategy_from_string("http_mimic"), AdversarialStrategy::HTTP_MIMIC);
    EXPECT_EQ(strategy_from_string("tls_mimic"),  AdversarialStrategy::TLS_MIMIC);
    EXPECT_EQ(strategy_from_string("quic_mimic"), AdversarialStrategy::QUIC_MIMIC);
    EXPECT_EQ(strategy_from_string("dns_mimic"),  AdversarialStrategy::DNS_MIMIC);
    EXPECT_EQ(strategy_from_string("adaptive"),   AdversarialStrategy::ADAPTIVE);
}

// ── Config Presets ─────────────────────────────────────────────────────────────

TEST_F(AdversarialTest, ConfigPreset_Minimal) {
    auto cfg = AdversarialConfig::minimal();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_LE(cfg.pre_padding_max, 16u);
}

TEST_F(AdversarialTest, ConfigPreset_Balanced) {
    auto cfg = AdversarialConfig::balanced();
    EXPECT_TRUE(cfg.enabled);
}

TEST_F(AdversarialTest, ConfigPreset_Aggressive) {
    auto cfg = AdversarialConfig::aggressive();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_GT(cfg.pre_padding_max, cfg.pre_padding_min);
}

TEST_F(AdversarialTest, ConfigPreset_StealthMax) {
    auto cfg = AdversarialConfig::stealth_max();
    EXPECT_TRUE(cfg.enabled);
}

// ── Pad / Unpad Roundtrip ────────────────────────────────────────────────────

TEST_F(AdversarialTest, PadUnpad_Roundtrip_Random) {
    AdversarialConfig cfg;
    cfg.strategy = AdversarialStrategy::RANDOM;
    AdversarialPadding ap(cfg);

    auto payload = make_payload(128);
    auto padded = ap.pad(payload);
    EXPECT_GT(padded.size(), payload.size());

    auto recovered = ap.unpad(padded);
    EXPECT_EQ(recovered, payload);
}

TEST_F(AdversarialTest, PadUnpad_Roundtrip_HttpMimic) {
    AdversarialConfig cfg;
    cfg.strategy = AdversarialStrategy::HTTP_MIMIC;
    AdversarialPadding ap(cfg);

    auto payload = make_payload(64);
    auto padded = ap.pad(payload);
    auto recovered = ap.unpad(padded);
    EXPECT_EQ(recovered, payload);
}

TEST_F(AdversarialTest, PadUnpad_Roundtrip_TlsMimic) {
    AdversarialConfig cfg;
    cfg.strategy = AdversarialStrategy::TLS_MIMIC;
    AdversarialPadding ap(cfg);

    auto payload = make_payload(256);
    auto padded = ap.pad(payload);
    auto recovered = ap.unpad(padded);
    EXPECT_EQ(recovered, payload);
}

TEST_F(AdversarialTest, PadUnpad_Roundtrip_QuicMimic) {
    AdversarialConfig cfg;
    cfg.strategy = AdversarialStrategy::QUIC_MIMIC;
    AdversarialPadding ap(cfg);

    auto payload = make_payload(100);
    auto padded = ap.pad(payload);
    auto recovered = ap.unpad(padded);
    EXPECT_EQ(recovered, payload);
}

TEST_F(AdversarialTest, PadUnpad_Roundtrip_DnsMimic) {
    AdversarialConfig cfg;
    cfg.strategy = AdversarialStrategy::DNS_MIMIC;
    AdversarialPadding ap(cfg);

    auto payload = make_payload(40);
    auto padded = ap.pad(payload);
    auto recovered = ap.unpad(padded);
    EXPECT_EQ(recovered, payload);
}

TEST_F(AdversarialTest, Pad_AddsAtLeastControlHeader) {
    AdversarialPadding ap;
    auto payload = make_payload(32);
    auto padded = ap.pad(payload);
    // V2 control header = 4 bytes minimum
    EXPECT_GT(padded.size(), payload.size());
}

TEST_F(AdversarialTest, Pad_EmptyPayload) {
    AdversarialPadding ap;
    std::vector<uint8_t> empty;
    auto padded = ap.pad(empty);
    auto recovered = ap.unpad(padded);
    EXPECT_EQ(recovered, empty);
}

// ── Dummy Packet Generation / Detection ──────────────────────────────────────

TEST_F(AdversarialTest, GenerateDummyPacket_NotEmpty) {
    AdversarialPadding ap;
    auto dummy = ap.generate_dummy_packet();
    EXPECT_FALSE(dummy.empty());
}

TEST_F(AdversarialTest, IsDummyPacket_DetectsOwnDummyLegacy) {
    AdversarialPadding ap;
    auto dummy = ap.generate_dummy_packet();
    EXPECT_TRUE(ap.is_dummy_packet(dummy.data(), dummy.size()));
}

TEST_F(AdversarialTest, IsDummyPacket_ReturnsFalseForNormalData) {
    AdversarialPadding ap;
    auto payload = make_payload(64);
    auto padded = ap.pad(payload);
    EXPECT_FALSE(ap.is_dummy_packet(padded.data(), padded.size()));
}

TEST_F(AdversarialTest, SessionDummyKey_SetAndGet) {
    AdversarialPadding ap;
    auto key1 = ap.get_session_dummy_key();
    EXPECT_FALSE(key1.empty());

    // Set a custom key
    std::vector<uint8_t> new_key(32, 0xCC);
    ap.set_session_dummy_key(new_key);

    auto dummy = ap.generate_dummy_packet();
    EXPECT_FALSE(dummy.empty());
    // Dummy should be detected with the new key
    EXPECT_TRUE(ap.is_dummy_packet(dummy.data(), dummy.size()));
}

// ── TCP Header Mutation ────────────────────────────────────────────────────────

TEST_F(AdversarialTest, MutateTcpHeader_ReturnsTrueOnValidHeader) {
    AdversarialConfig cfg;
    cfg.mutate_tcp_window = true;
    AdversarialPadding ap(cfg);

    auto hdr = make_tcp_header();
    bool mutated = ap.mutate_tcp_header(hdr.data(), hdr.size());
    EXPECT_TRUE(mutated);
}

TEST_F(AdversarialTest, MutateTcpHeader_ReturnsFalseOnTooShortHeader) {
    AdversarialPadding ap;
    std::vector<uint8_t> short_hdr(10, 0);
    bool mutated = ap.mutate_tcp_header(short_hdr.data(), short_hdr.size());
    EXPECT_FALSE(mutated);
}

// ── Adaptive Strategy ─────────────────────────────────────────────────────────

TEST_F(AdversarialTest, ForceStrategy) {
    AdversarialPadding ap;
    ap.force_strategy(AdversarialStrategy::HTTP_MIMIC);
    EXPECT_EQ(ap.current_strategy(), AdversarialStrategy::HTTP_MIMIC);

    ap.force_strategy(AdversarialStrategy::TLS_MIMIC);
    EXPECT_EQ(ap.current_strategy(), AdversarialStrategy::TLS_MIMIC);
}

TEST_F(AdversarialTest, ReportFeedback_NoThrow) {
    AdversarialConfig cfg;
    cfg.strategy = AdversarialStrategy::ADAPTIVE;
    AdversarialPadding ap(cfg);

    DetectionFeedback fb;
    fb.detected = true;
    fb.confidence = 0.9;
    fb.strategy_used = AdversarialStrategy::HTTP_MIMIC;
    fb.timestamp = std::chrono::steady_clock::now();
    EXPECT_NO_THROW(ap.report_feedback(fb));
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(AdversarialTest, InitialStatsAreZero) {
    AdversarialPadding ap;
    auto stats = ap.get_stats();
    EXPECT_EQ(stats.packets_processed.load(), 0u);
    EXPECT_EQ(stats.packets_padded.load(), 0u);
}

TEST_F(AdversarialTest, StatsIncrementAfterPad) {
    AdversarialPadding ap;
    ap.pad(make_payload(64));
    auto stats = ap.get_stats();
    EXPECT_GT(stats.packets_processed.load(), 0u);
}

TEST_F(AdversarialTest, ResetStats) {
    AdversarialPadding ap;
    ap.pad(make_payload(64));
    ap.reset_stats();
    auto stats = ap.get_stats();
    EXPECT_EQ(stats.packets_processed.load(), 0u);
}

TEST_F(AdversarialTest, OverheadPercent_IsNonNegative) {
    AdversarialPadding ap;
    ap.pad(make_payload(256));
    auto stats = ap.get_stats();
    EXPECT_GE(stats.overhead_percent(), 0.0);
}

// ── Config Get/Set ─────────────────────────────────────────────────────────────

TEST_F(AdversarialTest, GetSetConfig) {
    AdversarialPadding ap;
    auto cfg = ap.get_config();
    cfg.pre_padding_min = 4;
    cfg.pre_padding_max = 8;
    ap.set_config(cfg);
    EXPECT_EQ(ap.get_config().pre_padding_min, 4u);
    EXPECT_EQ(ap.get_config().pre_padding_max, 8u);
}

// ── Size Normalization ────────────────────────────────────────────────────────

TEST_F(AdversarialTest, NormalizeSize_OutputInTargetSizes) {
    AdversarialConfig cfg;
    cfg.enable_size_normalization = true;
    cfg.target_sizes = {64, 128, 256, 512};
    AdversarialPadding ap(cfg);

    auto data = make_payload(50); // < 64
    auto normalized = ap.normalize_size(data);
    // Result should be padded to at least 64 bytes
    EXPECT_GE(normalized.size(), 64u);
}
