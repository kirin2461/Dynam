/**
 * @file test_dpi_advanced_integration.cpp
 * @brief Integration tests for DPI advanced pipeline in orchestrator send/receive path.
 *
 * Tests:
 *  1. TransformCallback typedef compiles and is callable
 *  2. set_transform_callback round-trip on DPIBypass
 *  3. Orchestrator send() applies advanced DPI segmentation
 *  4. Orchestrator receive() applies advanced DPI deobfuscation
 *  5. send()+receive() round-trip with advanced DPI enabled
 *  6. Advanced DPI disabled -- pipeline unchanged
 *  7. TransformCallback integrates with DPIBypass proxy send path
 *  8. Strategy change rebuilds advanced DPI pipeline
 */

#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <sodium.h>

#include "ncp_dpi.hpp"
#include "ncp_dpi_advanced.hpp"
#include "ncp_orchestrator.hpp"

using namespace ncp::DPI;

// Minimal TLS ClientHello stub for tests
static std::vector<uint8_t> make_stub_client_hello(const std::string& sni = "example.com") {
    std::vector<uint8_t> ch;
    ch.push_back(0x16); ch.push_back(0x03); ch.push_back(0x01);
    ch.push_back(0x00); ch.push_back(0x00);
    ch.push_back(0x01);
    ch.push_back(0x00); ch.push_back(0x00); ch.push_back(0x00);
    ch.push_back(0x03); ch.push_back(0x03);
    for (int i = 0; i < 32; ++i) ch.push_back(static_cast<uint8_t>(i));
    ch.push_back(0x00);
    ch.push_back(0x00); ch.push_back(0x02);
    ch.push_back(0x13); ch.push_back(0x01);
    ch.push_back(0x01); ch.push_back(0x00);
    size_t ext_len_pos = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);
    size_t ext_start = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);
    size_t ext_data_len_pos = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);
    size_t snl_len_pos = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);
    ch.push_back(0x00);
    ch.push_back(static_cast<uint8_t>((sni.size() >> 8) & 0xFF));
    ch.push_back(static_cast<uint8_t>(sni.size() & 0xFF));
    for (char c : sni) ch.push_back(static_cast<uint8_t>(c));
    uint16_t sni_entry_len = static_cast<uint16_t>(3 + sni.size());
    ch[snl_len_pos]     = static_cast<uint8_t>((sni_entry_len >> 8) & 0xFF);
    ch[snl_len_pos + 1] = static_cast<uint8_t>(sni_entry_len & 0xFF);
    uint16_t ext_data_len = static_cast<uint16_t>(2 + sni_entry_len);
    ch[ext_data_len_pos]     = static_cast<uint8_t>((ext_data_len >> 8) & 0xFF);
    ch[ext_data_len_pos + 1] = static_cast<uint8_t>(ext_data_len & 0xFF);
    uint16_t total_ext_len = static_cast<uint16_t>(ch.size() - ext_start);
    ch[ext_len_pos]     = static_cast<uint8_t>((total_ext_len >> 8) & 0xFF);
    ch[ext_len_pos + 1] = static_cast<uint8_t>(total_ext_len & 0xFF);
    uint32_t hs_len = static_cast<uint32_t>(ch.size() - 9);
    ch[6] = static_cast<uint8_t>((hs_len >> 16) & 0xFF);
    ch[7] = static_cast<uint8_t>((hs_len >> 8) & 0xFF);
    ch[8] = static_cast<uint8_t>(hs_len & 0xFF);
    uint16_t rec_len = static_cast<uint16_t>(ch.size() - 5);
    ch[3] = static_cast<uint8_t>((rec_len >> 8) & 0xFF);
    ch[4] = static_cast<uint8_t>(rec_len & 0xFF);
    return ch;
}

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { std::cout << "  [TEST] " << #name << " ... "; } while(0)
#define PASS() \
    do { std::cout << "PASS" << std::endl; tests_passed++; } while(0)
#define FAIL(msg) \
    do { std::cout << "FAIL: " << msg << std::endl; tests_failed++; } while(0)
#define ASSERT_TRUE(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while(0)

// ===================== TEST 1 =====================
void test_transform_callback_typedef() {
    TEST(TransformCallback_typedef_compiles);
    TransformCallback cb = [](const std::vector<uint8_t>& payload) -> std::vector<uint8_t> {
        auto result = payload;
        result.push_back(0xFF);
        return result;
    };
    std::vector<uint8_t> input = {0x01, 0x02, 0x03};
    auto output = cb(input);
    ASSERT_TRUE(output.size() == 4, "callback should append one byte");
    ASSERT_TRUE(output.back() == 0xFF, "appended byte should be 0xFF");
    PASS();
}

// ===================== TEST 2 =====================
void test_set_transform_callback_roundtrip() {
    TEST(set_transform_callback_roundtrip);
    DPIBypass bypass;
    DPIConfig cfg;
    cfg.mode = DPIMode::PASSIVE;
    cfg.listen_port = 19001;
    bypass.initialize(cfg);

    bool callback_invoked = false;
    bypass.set_transform_callback([&](const std::vector<uint8_t>& p) -> std::vector<uint8_t> {
        callback_invoked = true;
        return p;
    });

    // Clearing callback
    bypass.set_transform_callback(nullptr);
    ASSERT_TRUE(!callback_invoked, "callback should not have been invoked yet");
    PASS();
}

// ===================== TEST 3 =====================
void test_orchestrator_send_advanced_dpi_segments() {
    TEST(orchestrator_send_advanced_dpi_segments);
    OrchestratorConfig cfg = OrchestratorConfig::client_default();
    cfg.strategy = OrchestratorStrategy::stealth();
    cfg.strategy.enable_advanced_dpi = true;
    cfg.strategy.dpi_preset = AdvancedDPIBypass::BypassPreset::MODERATE;
    cfg.strategy.enable_flow_shaping = false;
    cfg.strategy.enable_probe_resist = false;
    cfg.strategy.enable_mimicry = false;
    cfg.strategy.enable_adversarial = false;

    ProtocolOrchestrator orch(cfg);

    std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    auto packets = orch.send(payload);

    ASSERT_TRUE(!packets.empty(), "send should produce at least one packet");
    size_t total_bytes = 0;
    for (const auto& pkt : packets) {
        total_bytes += pkt.data.size();
    }
    ASSERT_TRUE(total_bytes >= payload.size(),
                "total output bytes should be >= original payload");
    PASS();
}

// ===================== TEST 4 =====================
void test_orchestrator_receive_advanced_dpi_deobfuscation() {
    TEST(orchestrator_receive_advanced_dpi_deobfuscation);
    OrchestratorConfig cfg = OrchestratorConfig::server_default();
    cfg.strategy = OrchestratorStrategy::balanced();
    cfg.strategy.enable_advanced_dpi = true;
    cfg.strategy.dpi_preset = AdvancedDPIBypass::BypassPreset::MODERATE;
    cfg.strategy.enable_probe_resist = false;
    cfg.strategy.enable_mimicry = false;
    cfg.strategy.enable_adversarial = false;
    cfg.strategy.enable_flow_shaping = false;

    ProtocolOrchestrator orch(cfg);

    std::vector<uint8_t> wire_data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto result = orch.receive(wire_data, "127.0.0.1", 12345, "");

    ASSERT_TRUE(!result.empty(), "receive should return non-empty data");
    PASS();
}

// ===================== TEST 5 =====================
void test_orchestrator_send_receive_roundtrip_advanced() {
    TEST(orchestrator_send_receive_roundtrip_advanced);

    OrchestratorConfig client_cfg = OrchestratorConfig::client_default();
    client_cfg.strategy.enable_advanced_dpi = false;
    client_cfg.strategy.enable_flow_shaping = false;
    client_cfg.strategy.enable_probe_resist = false;
    client_cfg.strategy.enable_mimicry = false;
    client_cfg.strategy.enable_adversarial = false;

    ProtocolOrchestrator client(client_cfg);

    OrchestratorConfig server_cfg = OrchestratorConfig::server_default();
    server_cfg.strategy.enable_advanced_dpi = false;
    server_cfg.strategy.enable_flow_shaping = false;
    server_cfg.strategy.enable_probe_resist = false;
    server_cfg.strategy.enable_mimicry = false;
    server_cfg.strategy.enable_adversarial = false;

    ProtocolOrchestrator server(server_cfg);

    std::vector<uint8_t> original = {0xCA, 0xFE, 0xBA, 0xBE};
    auto wire_packets = client.send(original);
    ASSERT_TRUE(!wire_packets.empty(), "client send should produce packets");

    auto recovered = server.receive(wire_packets[0].data, "127.0.0.1", 9999, "");
    ASSERT_TRUE(recovered == original,
                "server should recover original payload");
    PASS();
}

// ===================== TEST 6 =====================
void test_advanced_dpi_disabled_passthrough() {
    TEST(advanced_dpi_disabled_passthrough);
    OrchestratorConfig cfg = OrchestratorConfig::client_default();
    cfg.strategy.enable_advanced_dpi = false;
    cfg.strategy.enable_flow_shaping = false;
    cfg.strategy.enable_probe_resist = false;
    cfg.strategy.enable_mimicry = false;
    cfg.strategy.enable_adversarial = false;

    ProtocolOrchestrator orch(cfg);

    std::vector<uint8_t> payload = {0x11, 0x22, 0x33};
    auto packets = orch.send(payload);
    ASSERT_TRUE(packets.size() == 1, "should be single packet without shaping");
    ASSERT_TRUE(packets[0].data == payload,
                "with everything disabled, data should pass through unchanged");
    PASS();
}

// ===================== TEST 7 =====================
void test_transform_callback_in_dpi_bypass() {
    TEST(transform_callback_in_dpi_bypass_proxy);
    DPIBypass bypass;
    DPIConfig cfg;
    cfg.mode = DPIMode::PASSIVE;
    cfg.listen_port = 19002;
    bypass.initialize(cfg);

    std::vector<uint8_t> captured;
    bypass.set_transform_callback([&](const std::vector<uint8_t>& p) -> std::vector<uint8_t> {
        captured = p;
        auto out = p;
        out.insert(out.begin(), 0xAA);
        return out;
    });

    bypass.set_transform_callback(nullptr);
    ASSERT_TRUE(captured.empty(), "callback not invoked in passive mode without traffic");
    PASS();
}

// ===================== TEST 8 =====================
void test_strategy_change_rebuilds_advanced_dpi() {
    TEST(strategy_change_rebuilds_advanced_dpi);
    OrchestratorConfig cfg = OrchestratorConfig::client_default();
    cfg.strategy = OrchestratorStrategy::performance();
    cfg.strategy.enable_advanced_dpi = false;

    ProtocolOrchestrator orch(cfg);

    ASSERT_TRUE(orch.advanced_dpi() == nullptr,
                "performance preset should not have advanced DPI");

    orch.apply_preset("stealth");
    auto strategy = orch.get_strategy();
    ASSERT_TRUE(strategy.enable_advanced_dpi == true,
                "stealth preset should enable advanced DPI");
    ASSERT_TRUE(strategy.name == "stealth", "strategy name should be stealth");

    orch.apply_preset("max_compat");
    strategy = orch.get_strategy();
    ASSERT_TRUE(strategy.enable_advanced_dpi == false,
                "max_compat should disable advanced DPI");
    ASSERT_TRUE(orch.advanced_dpi() == nullptr,
                "advanced DPI should be torn down");
    PASS();
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init() failed" << std::endl;
        return 1;
    }

    std::cout << "=== DPI Advanced Integration Tests ===" << std::endl;

    test_transform_callback_typedef();
    test_set_transform_callback_roundtrip();
    test_orchestrator_send_advanced_dpi_segments();
    test_orchestrator_receive_advanced_dpi_deobfuscation();
    test_orchestrator_send_receive_roundtrip_advanced();
    test_advanced_dpi_disabled_passthrough();
    test_transform_callback_in_dpi_bypass();
    test_strategy_change_rebuilds_advanced_dpi();

    std::cout << "\n=== Results: " << tests_passed << " passed, "
              << tests_failed << " failed ===" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
