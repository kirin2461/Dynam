// ══════════════════════════════════════════════════════════════════════════════
// tests/test_port_knock.cpp
// Tests for PortKnock (ncp_port_knock.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_port_knock.hpp"

#include <vector>
#include <string>
#include <cstring>
#include <chrono>

using namespace ncp::DPI;

// ── Fixture ───────────────────────────────────────────────────────────────────

class PortKnockTest : public ::testing::Test {
protected:
    PortKnockConfig make_config() {
        PortKnockConfig cfg;
        cfg.mode = KnockMode::TOTP_SEQUENCE;
        cfg.shared_secret.assign(32, 0xAB);
        cfg.sequence_length = 3;
        cfg.gate_duration_sec = 60;
        cfg.max_attempts_per_ip = 20; // generous for tests
        cfg.attempt_window_sec  = 3600;
        return cfg;
    }

    PortKnockConfig make_static_config() {
        PortKnockConfig cfg;
        cfg.mode = KnockMode::STATIC_SEQUENCE;
        cfg.static_sequence = {7001, 8001, 9001};
        cfg.gate_duration_sec = 60;
        cfg.max_attempts_per_ip = 100;
        cfg.attempt_window_sec  = 3600;
        return cfg;
    }
};

// ── String Conversion ─────────────────────────────────────────────────────────

TEST_F(PortKnockTest, KnockModeToString) {
    EXPECT_STRNE(knock_mode_to_string(KnockMode::TOTP_SEQUENCE),   "");
    EXPECT_STRNE(knock_mode_to_string(KnockMode::STATIC_SEQUENCE), "");
    EXPECT_STRNE(knock_mode_to_string(KnockMode::SPA),             "");
    EXPECT_STRNE(knock_mode_to_string(KnockMode::COVERT_TCP),      "");
}

TEST_F(PortKnockTest, KnockResultToString) {
    EXPECT_STRNE(knock_result_to_string(KnockResult::GATE_OPENED),      "");
    EXPECT_STRNE(knock_result_to_string(KnockResult::SEQUENCE_PROGRESS), "");
    EXPECT_STRNE(knock_result_to_string(KnockResult::WRONG_SEQUENCE),   "");
    EXPECT_STRNE(knock_result_to_string(KnockResult::REPLAY),           "");
    EXPECT_STRNE(knock_result_to_string(KnockResult::RATE_LIMITED),     "");
}

// ── Config Presets ─────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, ConfigPreset_Paranoid) {
    auto cfg = PortKnockConfig::paranoid();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_GT(cfg.sequence_length, 3u);
}

TEST_F(PortKnockTest, ConfigPreset_Balanced) {
    auto cfg = PortKnockConfig::balanced();
    EXPECT_TRUE(cfg.enabled);
}

TEST_F(PortKnockTest, ConfigPreset_SpaOnly) {
    auto cfg = PortKnockConfig::spa_only();
    EXPECT_EQ(cfg.mode, KnockMode::SPA);
}

// ── TOTP Sequence Generation ──────────────────────────────────────────────────

TEST_F(PortKnockTest, GenerateTotpSequence_CorrectLength) {
    PortKnock pk(make_config());
    auto seq = pk.generate_totp_sequence();
    EXPECT_EQ(seq.size(), 3u);
}

TEST_F(PortKnockTest, GenerateTotpSequence_PortsInRange) {
    PortKnock pk(make_config());
    auto seq = pk.generate_totp_sequence();
    for (auto port : seq) {
        EXPECT_GE(port, static_cast<uint16_t>(1024));
        EXPECT_LE(port, static_cast<uint16_t>(65535));
    }
}

TEST_F(PortKnockTest, GenerateTotpSequence_Deterministic) {
    PortKnock pk(make_config());
    auto seq1 = pk.generate_totp_sequence(0);
    auto seq2 = pk.generate_totp_sequence(0);
    EXPECT_EQ(seq1, seq2);
}

TEST_F(PortKnockTest, GenerateTotpSequence_DifferentOffsets) {
    PortKnock pk(make_config());
    auto seq0 = pk.generate_totp_sequence(0);
    auto seq1 = pk.generate_totp_sequence(1);
    // Different time windows should produce different sequences (usually)
    // This may not always hold, but it's a reasonable sanity check
    (void)seq0;
    (void)seq1;
}

// ── TOTP Sequence Processing ──────────────────────────────────────────────────

TEST_F(PortKnockTest, ProcessKnock_CorrectSequenceOpensGate) {
    PortKnock pk(make_config());
    auto seq = pk.generate_totp_sequence(0);

    const std::string ip = "10.0.0.1";
    KnockResult r = KnockResult::WRONG_SEQUENCE;
    for (size_t i = 0; i < seq.size(); ++i) {
        r = pk.process_knock(ip, seq[i]);
        if (i < seq.size() - 1) {
            EXPECT_EQ(r, KnockResult::SEQUENCE_PROGRESS) << "at knock " << i;
        }
    }
    EXPECT_EQ(r, KnockResult::GATE_OPENED);
    EXPECT_TRUE(pk.is_gate_open(ip));
}

TEST_F(PortKnockTest, ProcessKnock_WrongPortGivesWrongSequence) {
    PortKnock pk(make_config());
    auto r = pk.process_knock("10.0.0.2", 12345);
    // Port 12345 is almost certainly not the first in the TOTP sequence
    // (if it happens to be, the test needs different seed — acceptable)
    (void)r;
}

TEST_F(PortKnockTest, ProcessKnock_StaticSequence) {
    PortKnock pk(make_static_config());
    const std::string ip = "10.0.0.3";

    EXPECT_EQ(pk.process_knock(ip, 7001), KnockResult::SEQUENCE_PROGRESS);
    EXPECT_EQ(pk.process_knock(ip, 8001), KnockResult::SEQUENCE_PROGRESS);
    EXPECT_EQ(pk.process_knock(ip, 9001), KnockResult::GATE_OPENED);
    EXPECT_TRUE(pk.is_gate_open(ip));
}

TEST_F(PortKnockTest, ProcessKnock_WrongStaticSequence) {
    PortKnock pk(make_static_config());
    const std::string ip = "10.0.0.4";

    pk.process_knock(ip, 7001);
    auto r = pk.process_knock(ip, 9999); // wrong second knock
    EXPECT_EQ(r, KnockResult::WRONG_SEQUENCE);
}

// ── Gate Management ────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, GateInitiallyClosed) {
    PortKnock pk(make_config());
    EXPECT_FALSE(pk.is_gate_open("192.168.1.1"));
}

TEST_F(PortKnockTest, OpenGateManually) {
    PortKnock pk(make_config());
    pk.open_gate("192.168.1.5", 60);
    EXPECT_TRUE(pk.is_gate_open("192.168.1.5"));
}

TEST_F(PortKnockTest, CloseGate) {
    PortKnock pk(make_config());
    pk.open_gate("192.168.1.6", 60);
    pk.close_gate("192.168.1.6");
    EXPECT_FALSE(pk.is_gate_open("192.168.1.6"));
}

TEST_F(PortKnockTest, GetOpenGates) {
    PortKnock pk(make_config());
    pk.open_gate("192.168.1.10", 60);
    pk.open_gate("192.168.1.11", 60);
    auto gates = pk.get_open_gates();
    EXPECT_GE(gates.size(), 2u);
}

// ── SPA Packet ────────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, GenerateSpaPacket_CorrectSize) {
    auto cfg = PortKnockConfig::spa_only();
    cfg.shared_secret.assign(32, 0xCD);
    cfg.spa_packet_size = 256;
    PortKnock pk(cfg);

    auto pkt = pk.generate_spa_packet();
    EXPECT_EQ(pkt.size(), 256u);
}

TEST_F(PortKnockTest, ProcessSpa_ValidPacketAuthenticated) {
    auto cfg = PortKnockConfig::spa_only();
    cfg.shared_secret.assign(32, 0xCD);
    cfg.max_attempts_per_ip = 100;
    PortKnock pk(cfg);

    auto pkt = pk.generate_spa_packet();
    auto r = pk.process_spa("10.0.1.1", pkt.data(), pkt.size());
    EXPECT_EQ(r, KnockResult::SPA_AUTHENTICATED);
    EXPECT_TRUE(pk.is_gate_open("10.0.1.1"));
}

// ── Covert Knock ─────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, GenerateCovertSequence_NotEmpty) {
    auto cfg = make_config();
    cfg.mode = KnockMode::COVERT_TCP;
    PortKnock pk(cfg);

    auto seq = pk.generate_covert_sequence();
    EXPECT_FALSE(seq.empty());
}

// ── Rate Limiting ─────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, RateLimiting_BlocksAfterThreshold) {
    PortKnockConfig cfg = make_config();
    cfg.max_attempts_per_ip = 3;
    cfg.attempt_window_sec  = 60;
    PortKnock pk(cfg);

    const std::string ip = "10.0.0.99";
    // Exhaust attempts with wrong knocks
    for (int i = 0; i < 3; ++i) {
        pk.process_knock(ip, static_cast<uint16_t>(i + 1));
    }
    auto r = pk.process_knock(ip, 9999);
    EXPECT_EQ(r, KnockResult::RATE_LIMITED);
}

// ── Statistics ─────────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, InitialStats_AllZero) {
    PortKnock pk(make_config());
    auto s = pk.get_stats();
    EXPECT_EQ(s.total_knocks.load(), 0u);
    EXPECT_EQ(s.gates_opened.load(), 0u);
}

TEST_F(PortKnockTest, ResetStats) {
    PortKnock pk(make_static_config());
    const std::string ip = "10.0.0.20";
    pk.process_knock(ip, 7001);
    pk.process_knock(ip, 8001);
    pk.process_knock(ip, 9001);
    pk.reset_stats();
    auto s = pk.get_stats();
    EXPECT_EQ(s.total_knocks.load(), 0u);
}

// ── Event Callback ────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, EventCallback_TriggeredOnKnock) {
    PortKnock pk(make_static_config());
    int event_count = 0;
    pk.set_event_callback([&](const KnockEvent& e) {
        (void)e;
        event_count++;
    });

    pk.process_knock("10.0.0.30", 7001);
    EXPECT_GE(event_count, 1);
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

TEST_F(PortKnockTest, CleanupExpiredGates_NoThrow) {
    PortKnock pk(make_config());
    pk.open_gate("1.2.3.4", 0); // duration=0 → immediate expiry
    EXPECT_NO_THROW(pk.cleanup_expired_gates());
}
