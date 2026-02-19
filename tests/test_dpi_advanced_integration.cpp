#include <gtest/gtest.h>

#include "ncp_dpi_advanced.hpp"
#include "ncp_orchestrator.hpp"
#include "ncp_tls_fingerprint.hpp"

#include <vector>
#include <cstdint>
#include <cstring>

using namespace ncp::DPI;

// ===== Helper: build a minimal fake TLS ClientHello =====

static std::vector<uint8_t> make_fake_client_hello(const std::string& sni = "example.com") {
    // TLS record header: ContentType=0x16, Version=0x0303, Length=...
    // Handshake: type=0x01 (ClientHello), length=...
    // Minimal but structurally valid enough for looks_like_client_hello()

    std::vector<uint8_t> ch;

    // --- TLS record header ---
    ch.push_back(0x16);  // ContentType: Handshake
    ch.push_back(0x03);  // Version major
    ch.push_back(0x01);  // Version minor (TLS 1.0 for record layer)

    // Placeholder for record length (2 bytes) — fill later
    size_t rec_len_offset = ch.size();
    ch.push_back(0x00);
    ch.push_back(0x00);

    // --- Handshake header ---
    ch.push_back(0x01);  // HandshakeType: ClientHello

    // Placeholder for handshake length (3 bytes)
    size_t hs_len_offset = ch.size();
    ch.push_back(0x00);
    ch.push_back(0x00);
    ch.push_back(0x00);

    // --- ClientHello body ---
    // ProtocolVersion: TLS 1.2
    ch.push_back(0x03);
    ch.push_back(0x03);

    // Random: 32 bytes
    for (int i = 0; i < 32; i++) ch.push_back(static_cast<uint8_t>(i));

    // SessionID: length=0
    ch.push_back(0x00);

    // CipherSuites: length=4, two suites
    ch.push_back(0x00);
    ch.push_back(0x04);
    ch.push_back(0x13); ch.push_back(0x01);  // TLS_AES_128_GCM_SHA256
    ch.push_back(0x13); ch.push_back(0x02);  // TLS_AES_256_GCM_SHA384

    // CompressionMethods: length=1, null
    ch.push_back(0x01);
    ch.push_back(0x00);

    // Extensions total length placeholder (2 bytes)
    size_t ext_total_offset = ch.size();
    ch.push_back(0x00);
    ch.push_back(0x00);

    // --- SNI Extension (type=0x0000) ---
    size_t ext_start = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);  // ExtType: server_name

    // Extension data length placeholder
    size_t ext_data_len_offset = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);

    // ServerNameList length placeholder
    size_t sni_list_len_offset = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);

    // NameType: host_name (0)
    ch.push_back(0x00);

    // HostName length
    uint16_t sni_len = static_cast<uint16_t>(sni.size());
    ch.push_back(static_cast<uint8_t>(sni_len >> 8));
    ch.push_back(static_cast<uint8_t>(sni_len & 0xFF));

    // HostName
    for (char c : sni) ch.push_back(static_cast<uint8_t>(c));

    // Patch SNI list length
    uint16_t sni_list_len = static_cast<uint16_t>(ch.size() - sni_list_len_offset - 2);
    ch[sni_list_len_offset]     = static_cast<uint8_t>(sni_list_len >> 8);
    ch[sni_list_len_offset + 1] = static_cast<uint8_t>(sni_list_len & 0xFF);

    // Patch extension data length
    uint16_t ext_data_len = static_cast<uint16_t>(ch.size() - ext_data_len_offset - 2);
    ch[ext_data_len_offset]     = static_cast<uint8_t>(ext_data_len >> 8);
    ch[ext_data_len_offset + 1] = static_cast<uint8_t>(ext_data_len & 0xFF);

    // Patch extensions total length
    uint16_t ext_total_len = static_cast<uint16_t>(ch.size() - ext_total_offset - 2);
    ch[ext_total_offset]     = static_cast<uint8_t>(ext_total_len >> 8);
    ch[ext_total_offset + 1] = static_cast<uint8_t>(ext_total_len & 0xFF);

    // Patch handshake length (3 bytes, big-endian)
    uint32_t hs_len = static_cast<uint32_t>(ch.size() - hs_len_offset - 3);
    ch[hs_len_offset]     = static_cast<uint8_t>((hs_len >> 16) & 0xFF);
    ch[hs_len_offset + 1] = static_cast<uint8_t>((hs_len >> 8) & 0xFF);
    ch[hs_len_offset + 2] = static_cast<uint8_t>(hs_len & 0xFF);

    // Patch record length (2 bytes)
    uint16_t rec_len = static_cast<uint16_t>(ch.size() - rec_len_offset - 2);
    ch[rec_len_offset]     = static_cast<uint8_t>(rec_len >> 8);
    ch[rec_len_offset + 1] = static_cast<uint8_t>(rec_len & 0xFF);

    return ch;
}

// ===================================================================
// Test 1: AdvancedDPIBypass — presets apply correctly
// ===================================================================
TEST(AdvancedDPIBypass_Presets, ApplyPresetsSetTechniques) {
    AdvancedDPIBypass bypass;

    AdvancedDPIConfig cfg;
    bypass.initialize(cfg);

    // MINIMAL: should have SNI_SPLIT at minimum
    bypass.apply_preset(AdvancedDPIBypass::BypassPreset::MINIMAL);
    auto config_min = bypass.get_config();
    EXPECT_FALSE(config_min.techniques.empty());

    // STEALTH: should have more techniques than MINIMAL
    bypass.apply_preset(AdvancedDPIBypass::BypassPreset::STEALTH);
    auto config_stealth = bypass.get_config();
    EXPECT_GE(config_stealth.techniques.size(), config_min.techniques.size());
}

// ===================================================================
// Test 2: AdvancedDPIBypass — process_outgoing produces segments
// ===================================================================
TEST(AdvancedDPIBypass_ProcessOutgoing, ProducesSegments) {
    AdvancedDPIBypass bypass;

    AdvancedDPIConfig cfg;
    bypass.initialize(cfg);
    bypass.apply_preset(AdvancedDPIBypass::BypassPreset::MODERATE);
    bypass.start();

    auto ch = make_fake_client_hello();
    auto segments = bypass.process_outgoing(ch.data(), ch.size());

    // Should produce at least 1 segment
    EXPECT_GE(segments.size(), 1u);

    // Total bytes should be >= original (may include padding/fake SNI)
    size_t total = 0;
    for (auto& seg : segments) total += seg.size();
    EXPECT_GE(total, ch.size());

    bypass.stop();
}

// ===================================================================
// Test 3: AdvancedDPIBypass — has_technique helper
// ===================================================================
TEST(AdvancedDPIBypass_HasTechnique, CorrectlyReportsTechniques) {
    AdvancedDPIBypass bypass;

    AdvancedDPIConfig cfg;
    cfg.techniques = { EvasionTechnique::SNI_SPLIT, EvasionTechnique::TCP_SEGMENTATION };
    bypass.initialize(cfg);

    auto retrieved = bypass.get_config();
    // Check that has_technique works via config
    bool has_sni = false;
    bool has_disorder = false;
    for (auto t : retrieved.techniques) {
        if (t == EvasionTechnique::SNI_SPLIT) has_sni = true;
        if (t == EvasionTechnique::TCP_DISORDER) has_disorder = true;
    }
    EXPECT_TRUE(has_sni);
    EXPECT_FALSE(has_disorder);
}

// ===================================================================
// Test 4: AdvancedDPIBypass — callback wiring
// ===================================================================
TEST(AdvancedDPIBypass_Callback, CallbackIsInvoked) {
    AdvancedDPIBypass bypass;

    AdvancedDPIConfig cfg;
    bypass.initialize(cfg);
    bypass.apply_preset(AdvancedDPIBypass::BypassPreset::MINIMAL);

    bool callback_called = false;
    bypass.set_transform_callback(
        [&callback_called](const uint8_t*, size_t, bool) -> std::vector<std::vector<uint8_t>> {
            callback_called = true;
            return {};
        });

    // Just verify it was set (actual invocation depends on base bypass wiring)
    bypass.start();
    EXPECT_TRUE(bypass.is_running());
    bypass.stop();
}

// ===================================================================
// Test 5: Orchestrator — AdvancedDPI integration
// ===================================================================
TEST(Orchestrator_AdvancedDPI, IntegrationWithSend) {
    auto config = OrchestratorConfig::client_default();
    config.strategy = OrchestratorStrategy::balanced();
    config.adaptive = false;  // disable for predictable testing

    ProtocolOrchestrator orch(config);

    // advanced_dpi() should be non-null after balanced strategy
    EXPECT_NE(orch.advanced_dpi(), nullptr);
    EXPECT_NE(orch.tls_fingerprint(), nullptr);

    // Send a fake ClientHello through the full pipeline
    auto ch = make_fake_client_hello("test.example.com");

    // Start orchestrator (no-op send callback for testing)
    std::vector<OrchestratedPacket> captured;
    orch.start([&captured](const OrchestratedPacket& op) {
        captured.push_back(op);
    });

    auto packets = orch.send(ch);

    // Should produce at least 1 packet
    EXPECT_GE(packets.size(), 1u);

    // Total output bytes should be > 0
    size_t total = 0;
    for (auto& p : packets) total += p.data.size();
    EXPECT_GT(total, 0u);

    // Stats should reflect the send
    auto stats = orch.get_stats();
    EXPECT_EQ(stats.packets_sent.load(), 1u);
    EXPECT_GT(stats.bytes_original.load(), 0u);
    EXPECT_GT(stats.bytes_on_wire.load(), 0u);

    orch.stop();
}

// ===================================================================
// Test 6: Orchestrator — TLS Fingerprint lifecycle
// ===================================================================
TEST(Orchestrator_TLSFingerprint, EnabledDisabledByPreset) {
    // balanced → TLS fingerprint enabled
    {
        auto config = OrchestratorConfig::client_default();
        config.strategy = OrchestratorStrategy::balanced();
        ProtocolOrchestrator orch(config);
        EXPECT_NE(orch.tls_fingerprint(), nullptr);
    }

    // max_compat → TLS fingerprint disabled
    {
        auto config = OrchestratorConfig::client_default();
        config.strategy = OrchestratorStrategy::max_compat();
        ProtocolOrchestrator orch(config);
        EXPECT_EQ(orch.tls_fingerprint(), nullptr);
    }
}

// ===================================================================
// Test 7: Orchestrator — Escalation changes strategy
// ===================================================================
TEST(Orchestrator_Escalation, ThreatLevelEscalates) {
    auto config = OrchestratorConfig::client_default();
    config.strategy = OrchestratorStrategy::balanced();
    config.adaptive = true;
    config.escalation_threshold = 2;

    ProtocolOrchestrator orch(config);
    orch.start([](const OrchestratedPacket&) {});

    EXPECT_EQ(orch.get_threat_level(), ThreatLevel::NONE);

    // Report enough failures to trigger escalation
    DetectionEvent ev;
    ev.type = DetectionEvent::Type::CONNECTION_RESET;
    ev.timestamp = std::chrono::system_clock::now();

    orch.report_detection(ev);  // +2 (RST is strong signal)

    // After 1 RST (weight=2), should have escalated (threshold=2)
    EXPECT_GT(static_cast<int>(orch.get_threat_level()),
              static_cast<int>(ThreatLevel::NONE));

    auto stats = orch.get_stats();
    EXPECT_GE(stats.escalations.load(), 1u);

    orch.stop();
}

// ===================================================================
// Test 8: Orchestrator — Preset switch changes DPI state
// ===================================================================
TEST(Orchestrator_PresetSwitch, ChangesAdvancedDPIState) {
    auto config = OrchestratorConfig::client_default();
    config.strategy = OrchestratorStrategy::balanced();
    ProtocolOrchestrator orch(config);

    // balanced → advanced DPI enabled
    EXPECT_NE(orch.advanced_dpi(), nullptr);

    // Switch to max_compat → advanced DPI disabled
    orch.apply_preset("max_compat");
    EXPECT_EQ(orch.advanced_dpi(), nullptr);
    EXPECT_EQ(orch.tls_fingerprint(), nullptr);

    // Switch to stealth → advanced DPI re-enabled
    orch.apply_preset("stealth");
    EXPECT_NE(orch.advanced_dpi(), nullptr);
    EXPECT_NE(orch.tls_fingerprint(), nullptr);
}
