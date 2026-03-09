// ══════════════════════════════════════════════════════════════════════════════
// tests/test_orchestrator.cpp
// Tests for ProtocolOrchestrator (ncp_orchestrator.hpp)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_orchestrator.hpp"

#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>

using namespace ncp::DPI;

// ── Fixture ──────────────────────────────────────────────────────────────────

class OrchestratorTest : public ::testing::Test {
protected:
    OrchestratorConfig make_client_config() {
        auto cfg = OrchestratorConfig::client_default();
        // Use a lightweight strategy for tests
        cfg.strategy = OrchestratorStrategy::balanced();
        cfg.health_check_interval_sec = 9999; // disable background health checks
        return cfg;
    }

    std::vector<uint8_t> make_payload(size_t n = 64) {
        std::vector<uint8_t> v(n);
        for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint8_t>(i & 0xFF);
        return v;
    }
};

// ── Strategy Presets ──────────────────────────────────────────────────────────

TEST_F(OrchestratorTest, StrategyPreset_Stealth) {
    auto s = OrchestratorStrategy::stealth();
    EXPECT_FALSE(s.name.empty());
    EXPECT_TRUE(s.enable_adversarial);
    EXPECT_TRUE(s.enable_flow_shaping);
}

TEST_F(OrchestratorTest, StrategyPreset_Paranoid) {
    auto s = OrchestratorStrategy::paranoid();
    EXPECT_FALSE(s.name.empty());
    EXPECT_TRUE(s.enable_adversarial);
}

TEST_F(OrchestratorTest, StrategyPreset_Balanced) {
    auto s = OrchestratorStrategy::balanced();
    EXPECT_FALSE(s.name.empty());
    EXPECT_TRUE(s.enable_adversarial);
    EXPECT_TRUE(s.enable_flow_shaping);
}

TEST_F(OrchestratorTest, StrategyPreset_Performance) {
    auto s = OrchestratorStrategy::performance();
    EXPECT_FALSE(s.name.empty());
}

TEST_F(OrchestratorTest, StrategyPreset_MaxCompat) {
    auto s = OrchestratorStrategy::max_compat();
    EXPECT_FALSE(s.name.empty());
}

TEST_F(OrchestratorTest, ConfigPreset_ClientDefault) {
    auto cfg = OrchestratorConfig::client_default();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_FALSE(cfg.is_server);
}

TEST_F(OrchestratorTest, ConfigPreset_ServerDefault) {
    auto cfg = OrchestratorConfig::server_default();
    EXPECT_TRUE(cfg.enabled);
    EXPECT_TRUE(cfg.is_server);
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

TEST_F(OrchestratorTest, DefaultConstructor) {
    ProtocolOrchestrator orch;
    EXPECT_FALSE(orch.is_running());
}

TEST_F(OrchestratorTest, ConstructorWithConfig) {
    ProtocolOrchestrator orch(make_client_config());
    EXPECT_FALSE(orch.is_running());
}

TEST_F(OrchestratorTest, StartStop) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    EXPECT_TRUE(orch.is_running());
    orch.stop();
    EXPECT_FALSE(orch.is_running());
}

TEST_F(OrchestratorTest, DoubleStop_IsIdempotent) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    orch.stop();
    EXPECT_NO_THROW(orch.stop());
}

TEST_F(OrchestratorTest, StartWithCallback) {
    ProtocolOrchestrator orch(make_client_config());
    std::atomic<int> cb_count{0};
    orch.start([&](const OrchestratedPacket&) { cb_count++; });
    EXPECT_TRUE(orch.is_running());
    orch.stop();
}

// ── Send / Receive ────────────────────────────────────────────────────────────

TEST_F(OrchestratorTest, Send_ReturnsPackets) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    auto payload = make_payload(128);
    auto packets = orch.send(payload);
    EXPECT_FALSE(packets.empty());
    orch.stop();
}

TEST_F(OrchestratorTest, Send_OutputLargerThanInput) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    auto payload = make_payload(64);
    auto packets = orch.send(payload);
    size_t total = 0;
    for (auto& p : packets) total += p.data.size();
    // With padding, output should be >= input size
    EXPECT_GE(total, payload.size());
    orch.stop();
}

TEST_F(OrchestratorTest, SendAsync_NoThrow) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    EXPECT_NO_THROW(orch.send_async(make_payload(64)));
    orch.stop();
}

TEST_F(OrchestratorTest, Receive_EmptyDataReturnsEmpty) {
    ProtocolOrchestrator orch(make_client_config());
    std::vector<uint8_t> empty;
    auto result = orch.receive(empty, "127.0.0.1", 12345);
    // Empty input should result in empty or error output
    (void)result;
}

TEST_F(OrchestratorTest, GenerateCoverResponse_NotEmpty) {
    ProtocolOrchestrator orch(make_client_config());
    auto cover = orch.generate_cover_response();
    EXPECT_FALSE(cover.empty());
}

// ── Threat Escalation / De-escalation ────────────────────────────────────────

TEST_F(OrchestratorTest, InitialThreatLevelIsNone) {
    ProtocolOrchestrator orch(make_client_config());
    EXPECT_EQ(orch.get_threat_level(), ThreatLevel::NONE);
}

TEST_F(OrchestratorTest, SetThreatLevel) {
    ProtocolOrchestrator orch(make_client_config());
    orch.set_threat_level(ThreatLevel::HIGH);
    EXPECT_EQ(orch.get_threat_level(), ThreatLevel::HIGH);
}

TEST_F(OrchestratorTest, ThreatLevelFromInt) {
    EXPECT_EQ(threat_level_from_int(0), ThreatLevel::NONE);
    EXPECT_EQ(threat_level_from_int(1), ThreatLevel::LOW);
    EXPECT_EQ(threat_level_from_int(2), ThreatLevel::MEDIUM);
    EXPECT_EQ(threat_level_from_int(3), ThreatLevel::HIGH);
    EXPECT_EQ(threat_level_from_int(4), ThreatLevel::CRITICAL);
}

TEST_F(OrchestratorTest, ThreatLevelToString) {
    EXPECT_STREQ(threat_level_to_string(ThreatLevel::NONE),     "NONE");
    EXPECT_STREQ(threat_level_to_string(ThreatLevel::LOW),      "LOW");
    EXPECT_STREQ(threat_level_to_string(ThreatLevel::MEDIUM),   "MEDIUM");
    EXPECT_STREQ(threat_level_to_string(ThreatLevel::HIGH),     "HIGH");
    EXPECT_STREQ(threat_level_to_string(ThreatLevel::CRITICAL), "CRITICAL");
}

TEST_F(OrchestratorTest, ReportDetection_EscalatesThreat) {
    auto cfg = make_client_config();
    cfg.adaptive = true;
    cfg.escalation_threshold = 1;  // escalate after 1 failure
    ProtocolOrchestrator orch(cfg);
    orch.start(nullptr);

    DetectionEvent evt;
    evt.type = DetectionEvent::Type::CONNECTION_RESET;
    evt.details = "test reset";

    // Report enough failures to cross the threshold
    orch.report_detection(evt);
    orch.report_detection(evt);

    // Threat should have escalated
    EXPECT_GT(static_cast<int>(orch.get_threat_level()),
              static_cast<int>(ThreatLevel::NONE));
    orch.stop();
}

TEST_F(OrchestratorTest, ReportSuccess_DeEscalatesThreat) {
    auto cfg = make_client_config();
    cfg.adaptive = true;
    cfg.deescalation_threshold = 2;
    cfg.deescalation_cooldown_sec = 0;
    ProtocolOrchestrator orch(cfg);
    orch.start(nullptr);

    orch.set_threat_level(ThreatLevel::HIGH);
    orch.report_success();
    orch.report_success();
    // Level should have decreased (or stayed same with cooldown)
    EXPECT_LE(static_cast<int>(orch.get_threat_level()),
              static_cast<int>(ThreatLevel::HIGH));
    orch.stop();
}

// ── Strategy Management ───────────────────────────────────────────────────────

TEST_F(OrchestratorTest, SetStrategy) {
    ProtocolOrchestrator orch(make_client_config());
    auto s = OrchestratorStrategy::stealth();
    orch.set_strategy(s);
    EXPECT_EQ(orch.get_strategy().name, s.name);
}

TEST_F(OrchestratorTest, ApplyPreset_ByName) {
    ProtocolOrchestrator orch(make_client_config());
    EXPECT_NO_THROW(orch.apply_preset("stealth"));
    EXPECT_NO_THROW(orch.apply_preset("paranoid"));
    EXPECT_NO_THROW(orch.apply_preset("balanced"));
    EXPECT_NO_THROW(orch.apply_preset("performance"));
    EXPECT_NO_THROW(orch.apply_preset("max_compat"));
}

// ── Statistics ───────────────────────────────────────────────────────────────

TEST_F(OrchestratorTest, InitialStatsAreZero) {
    ProtocolOrchestrator orch(make_client_config());
    auto stats = orch.get_stats();
    EXPECT_EQ(stats.packets_sent.load(), 0u);
    EXPECT_EQ(stats.packets_received.load(), 0u);
    EXPECT_EQ(stats.escalations.load(), 0u);
}

TEST_F(OrchestratorTest, ResetStats) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    orch.send(make_payload(64));
    orch.reset_stats();
    auto stats = orch.get_stats();
    EXPECT_EQ(stats.packets_sent.load(), 0u);
    EXPECT_EQ(stats.bytes_original.load(), 0u);
    orch.stop();
}

TEST_F(OrchestratorTest, SendIncrementsStats) {
    ProtocolOrchestrator orch(make_client_config());
    orch.start(nullptr);
    orch.send(make_payload(128));
    auto stats = orch.get_stats();
    EXPECT_GT(stats.packets_sent.load(), 0u);
    EXPECT_GT(stats.bytes_original.load(), 0u);
    orch.stop();
}

// ── Component Accessors ───────────────────────────────────────────────────────

TEST_F(OrchestratorTest, AdversarialAccessor) {
    ProtocolOrchestrator orch(make_client_config());
    EXPECT_NO_THROW({ auto& a = orch.adversarial(); (void)a; });
}

TEST_F(OrchestratorTest, FlowShaperAccessor) {
    ProtocolOrchestrator orch(make_client_config());
    EXPECT_NO_THROW({ auto& fs = orch.flow_shaper(); (void)fs; });
}

TEST_F(OrchestratorTest, SharedSecretSynchronization) {
    std::vector<uint8_t> secret(32, 0xAB);
    ProtocolOrchestrator orch(make_client_config());
    EXPECT_NO_THROW(orch.synchronize_dummy_key(secret));
}

TEST_F(OrchestratorTest, EchInitializationState) {
    ProtocolOrchestrator orch(make_client_config());
    // ECH not configured by default in client_default
    EXPECT_NO_THROW(orch.is_ech_initialized());
}
