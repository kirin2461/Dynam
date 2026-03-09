/**
 * @file test_advanced_dpi.cpp
 * @brief Unit tests for AdvancedDPIBypass: process_outgoing splits,
 *        GREASE injection, decoy SNI, preset configurations, obfuscation roundtrip.
 *
 * Phase 2 completion tests.
 */

#include "../src/core/include/ncp_dpi_advanced.hpp"
#include "../src/core/include/ncp_tls_fingerprint.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <sodium.h>

using namespace ncp::DPI;

// Build a minimal ClientHello for testing
static std::vector<uint8_t> make_client_hello(const std::string& sni) {
    std::vector<uint8_t> ch;
    ch.reserve(200);
    ch.push_back(0x16);
    ch.push_back(0x03); ch.push_back(0x01);
    size_t rp = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);
    ch.push_back(0x01);
    size_t hp = ch.size();
    ch.push_back(0x00); ch.push_back(0x00); ch.push_back(0x00);
    ch.push_back(0x03); ch.push_back(0x03);
    for (int i = 0; i < 32; ++i) ch.push_back(static_cast<uint8_t>(i));
    ch.push_back(0x00);  // session_id_len = 0
    ch.push_back(0x00); ch.push_back(0x04);
    ch.push_back(0x13); ch.push_back(0x01);
    ch.push_back(0x13); ch.push_back(0x02);
    ch.push_back(0x01); ch.push_back(0x00);
    size_t ep = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);
    // SNI extension
    ch.push_back(0x00); ch.push_back(0x00);
    uint16_t sel = static_cast<uint16_t>(sni.size() + 5);
    ch.push_back(static_cast<uint8_t>(sel >> 8));
    ch.push_back(static_cast<uint8_t>(sel & 0xFF));
    uint16_t sll = static_cast<uint16_t>(sni.size() + 3);
    ch.push_back(static_cast<uint8_t>(sll >> 8));
    ch.push_back(static_cast<uint8_t>(sll & 0xFF));
    ch.push_back(0x00);
    uint16_t hl = static_cast<uint16_t>(sni.size());
    ch.push_back(static_cast<uint8_t>(hl >> 8));
    ch.push_back(static_cast<uint8_t>(hl & 0xFF));
    ch.insert(ch.end(), sni.begin(), sni.end());
    // Patch lengths
    uint16_t et = static_cast<uint16_t>(ch.size() - ep - 2);
    ch[ep] = static_cast<uint8_t>(et >> 8);
    ch[ep + 1] = static_cast<uint8_t>(et & 0xFF);
    uint32_t hsl = static_cast<uint32_t>(ch.size() - hp - 3);
    ch[hp] = static_cast<uint8_t>((hsl >> 16) & 0xFF);
    ch[hp + 1] = static_cast<uint8_t>((hsl >> 8) & 0xFF);
    ch[hp + 2] = static_cast<uint8_t>(hsl & 0xFF);
    uint16_t rl = static_cast<uint16_t>(ch.size() - 5);
    ch[rp] = static_cast<uint8_t>(rl >> 8);
    ch[rp + 1] = static_cast<uint8_t>(rl & 0xFF);
    return ch;
}

static void test_process_outgoing_splits_client_hello() {
    std::cout << "[TEST] process_outgoing splits ClientHello..." << std::flush;

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    cfg.base_config.split_at_sni = true;

    AdvancedDPIBypass bypass;
    assert(bypass.initialize(cfg));
    assert(bypass.start());

    auto ch = make_client_hello("blocked.example.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());

    assert(segments.size() >= 2);  // should split at SNI

    // Reassemble and verify total bytes
    size_t total = 0;
    for (const auto& s : segments) total += s.size();
    assert(total == ch.size());

    bypass.stop();
    std::cout << " OK (" << segments.size() << " segments)" << std::endl;
}

static void test_non_client_hello_passthrough() {
    std::cout << "[TEST] non-ClientHello passthrough..." << std::flush;

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;

    AdvancedDPIBypass bypass;
    assert(bypass.initialize(cfg));
    assert(bypass.start());

    std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    auto segments = bypass.process_outgoing(data.data(), data.size());

    assert(segments.size() == 1);
    assert(segments[0] == data);

    bypass.stop();
    std::cout << " OK" << std::endl;
}

static void test_grease_injection() {
    std::cout << "[TEST] GREASE injection..." << std::flush;

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    cfg.base_config.split_at_sni = true;
    cfg.base_config.enable_pattern_obfuscation = true;

    AdvancedDPIBypass bypass;
    assert(bypass.initialize(cfg));
    assert(bypass.start());

    auto ch = make_client_hello("grease-test.com");
    bypass.process_outgoing(ch.data(), ch.size());

    auto stats = bypass.get_stats();
    assert(stats.grease_injected > 0);

    bypass.stop();
    std::cout << " OK (injected=" << stats.grease_injected << ")" << std::endl;
}

static void test_decoy_sni() {
    std::cout << "[TEST] decoy SNI injection..." << std::flush;

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    cfg.base_config.split_at_sni = true;
    cfg.base_config.enable_decoy_sni = true;
    cfg.base_config.decoy_sni_domains = {"google.com", "cloudflare.com"};

    AdvancedDPIBypass bypass;
    assert(bypass.initialize(cfg));
    assert(bypass.start());

    auto ch = make_client_hello("real-target.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());

    // Should have: 2 decoy CH + N segments of real CH
    assert(segments.size() >= 4);  // 2 decoys + at least 2 splits

    auto stats = bypass.get_stats();
    assert(stats.fake_packets_injected == 2);

    bypass.stop();
    std::cout << " OK (fake_injected=" << stats.fake_packets_injected
              << ", total_segments=" << segments.size() << ")" << std::endl;
}

static void test_xor_obfuscation_roundtrip() {
    std::cout << "[TEST] XOR obfuscation roundtrip..." << std::flush;

    std::vector<uint8_t> key(32);
    randombytes_buf(key.data(), key.size());

    TrafficObfuscator obf(ObfuscationMode::XOR_SIMPLE, key);

    std::vector<uint8_t> data(256);
    randombytes_buf(data.data(), data.size());

    auto enc = obf.obfuscate(data.data(), data.size());
    assert(enc.size() == data.size());
    assert(enc != data);  // should be different

    auto dec = obf.deobfuscate(enc.data(), enc.size());
    assert(dec.size() == data.size());
    assert(dec == data);

    std::cout << " OK" << std::endl;
}

static void test_http_camouflage_roundtrip() {
    std::cout << "[TEST] HTTP camouflage roundtrip..." << std::flush;

    TrafficObfuscator obf(ObfuscationMode::HTTP_CAMOUFLAGE);

    const std::string payload = "secret tunnel data";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto enc = obf.obfuscate(data.data(), data.size());
    assert(enc.size() > data.size());

    // Should start with HTTP response
    std::string enc_str(enc.begin(), enc.end());
    assert(enc_str.find("HTTP/1.1 200 OK") == 0);

    auto dec = obf.deobfuscate(enc.data(), enc.size());
    assert(dec == data);

    std::cout << " OK" << std::endl;
}

static void test_presets_create() {
    std::cout << "[TEST] preset configurations create..." << std::flush;

    auto tspu = Presets::create_tspu_preset();
    assert(tspu.tspu_bypass);
    assert(!tspu.techniques.empty());
    assert(tspu.base_config.enable_tcp_split);
    assert(tspu.base_config.enable_decoy_sni);

    auto gfw = Presets::create_gfw_preset();
    assert(gfw.china_gfw_bypass);
    assert(gfw.obfuscation == ObfuscationMode::XOR_ROLLING);

    auto stealth = Presets::create_stealth_preset();
    assert(stealth.obfuscation == ObfuscationMode::HTTP_CAMOUFLAGE);

    auto aggressive = Presets::create_aggressive_preset();
    assert(aggressive.obfuscation == ObfuscationMode::CHACHA20);
    assert(aggressive.padding.enabled);

    auto compat = Presets::create_compatible_preset();
    assert(compat.techniques.size() == 1);

    auto iran = Presets::create_iran_preset();
    assert(iran.obfuscation == ObfuscationMode::HTTP_CAMOUFLAGE);

    std::cout << " OK (6 presets verified)" << std::endl;
}

static void test_tls_fingerprint_integration() {
    std::cout << "[TEST] TLS fingerprint integration..." << std::flush;

    ncp::TLSFingerprint fp(ncp::BrowserType::CHROME);
    fp.set_sni("fingerprint-test.com");

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    cfg.base_config.split_at_sni = true;

    AdvancedDPIBypass bypass;
    bypass.set_tls_fingerprint(&fp);
    assert(bypass.initialize(cfg));
    assert(bypass.start());

    auto ch = make_client_hello("fingerprint-test.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());
    assert(!segments.empty());

    bypass.stop();
    std::cout << " OK" << std::endl;
}

static void test_technique_toggle() {
    std::cout << "[TEST] technique enable/disable..." << std::flush;

    AdvancedDPIBypass bypass;
    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.techniques = { EvasionTechnique::SNI_SPLIT };
    assert(bypass.initialize(cfg));

    auto techniques = bypass.get_active_techniques();
    assert(techniques.size() == 1);
    assert(techniques[0] == EvasionTechnique::SNI_SPLIT);

    bypass.set_technique_enabled(EvasionTechnique::TIMING_JITTER, true);
    techniques = bypass.get_active_techniques();
    assert(techniques.size() == 2);

    bypass.set_technique_enabled(EvasionTechnique::SNI_SPLIT, false);
    techniques = bypass.get_active_techniques();
    assert(techniques.size() == 1);
    assert(techniques[0] == EvasionTechnique::TIMING_JITTER);

    std::cout << " OK" << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "=== Advanced DPI Bypass Tests ===" << std::endl;

    test_process_outgoing_splits_client_hello();
    test_non_client_hello_passthrough();
    test_grease_injection();
    test_decoy_sni();
    test_xor_obfuscation_roundtrip();
    test_http_camouflage_roundtrip();
    test_presets_create();
    test_tls_fingerprint_integration();
    test_technique_toggle();

    std::cout << "\nAll advanced DPI tests passed!" << std::endl;
    return 0;
}
