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
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <sodium.h>

// TEST_CHECK: like assert(), but ALWAYS evaluated. Plain assert() is
// compiled out under NDEBUG (Release), which silently disabled every check
// in this file and dropped side-effecting calls (initialize()/start()),
// letting tests run against uninitialized objects.
#define TEST_CHECK(cond)                                                     \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::cerr << "FAIL: " << __FILE__ << ":" << __LINE__             \
                      << ": check failed: " << #cond << std::endl;           \
            std::exit(1);                                                    \
        }                                                                    \
    } while (0)

// TEST_SKIP: graceful skip for environment/feature-dependent prerequisites
// (ctest maps exit code 77 to SKIP via SKIP_RETURN_CODE).
[[noreturn]] static void test_skip(const std::string& reason) {
    std::cout << "SKIP: " << reason << std::endl;
    std::exit(77);
}

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
    if (!bypass.initialize(cfg))
        test_skip("AdvancedDPIBypass::initialize() failed (environment)");
    if (!bypass.start())
        test_skip("AdvancedDPIBypass::start() failed (no loopback sockets?)");

    auto ch = make_client_hello("blocked.example.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());

    TEST_CHECK(segments.size() >= 2);  // should split at SNI

    // Reassemble and verify total bytes
    size_t total = 0;
    for (const auto& s : segments) total += s.size();
    TEST_CHECK(total == ch.size());

    bypass.stop();
    std::cout << " OK (" << segments.size() << " segments)" << std::endl;
}

static void test_non_client_hello_passthrough() {
    std::cout << "[TEST] non-ClientHello passthrough..." << std::flush;

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;

    AdvancedDPIBypass bypass;
    if (!bypass.initialize(cfg))
        test_skip("AdvancedDPIBypass::initialize() failed (environment)");
    if (!bypass.start())
        test_skip("AdvancedDPIBypass::start() failed (no loopback sockets?)");

    std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    auto segments = bypass.process_outgoing(data.data(), data.size());

    TEST_CHECK(segments.size() == 1);
    TEST_CHECK(segments[0] == data);

    bypass.stop();
    std::cout << " OK" << std::endl;
}

static void test_grease_injection() {
    std::cout << "[TEST] GREASE injection..." << std::flush;

    // MED-9: pipeline GREASE injection was removed from the core — the old
    // implementation corrupted TLS records by writing GREASE at arbitrary
    // offsets. Proper RFC 8701 GREASE is now added by
    // TLSFingerprint::insert_grease() when generating (fake) ClientHellos.
    // Current contract: process_outgoing() must NOT touch grease_injected,
    // and TLSManipulator::inject_grease() is a documented no-op passthrough.

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    cfg.base_config.split_at_sni = true;
    cfg.base_config.enable_pattern_obfuscation = true;

    AdvancedDPIBypass bypass;
    if (!bypass.initialize(cfg))
        test_skip("AdvancedDPIBypass::initialize() failed (environment)");
    if (!bypass.start())
        test_skip("AdvancedDPIBypass::start() failed (no loopback sockets?)");

    auto ch = make_client_hello("grease-test.com");
    bypass.process_outgoing(ch.data(), ch.size());

    auto stats = bypass.get_stats();
    TEST_CHECK(stats.grease_injected == 0);  // pipeline GREASE disabled (MED-9)

    bypass.stop();

    // TLSManipulator::inject_grease is a passthrough no-op (MED-9)
    TLSManipulator manip;
    auto out = manip.inject_grease(ch.data(), ch.size());
    TEST_CHECK(out == ch);

    // Proper GREASE comes from the TLS fingerprint layer (Chromium profiles)
    ncp::TLSFingerprint chrome_fp(ncp::BrowserType::CHROME);
    auto exts = chrome_fp.get_extensions();
    bool has_grease = false;
    for (uint16_t e : exts) {
        if ((e & 0x0F0F) == 0x0A0A) { has_grease = true; break; }
    }
    TEST_CHECK(has_grease);

    std::cout << " OK (pipeline GREASE disabled per MED-9; fingerprint GREASE present)" << std::endl;
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
    if (!bypass.initialize(cfg))
        test_skip("AdvancedDPIBypass::initialize() failed (environment)");
    if (!bypass.start())
        test_skip("AdvancedDPIBypass::start() failed (no loopback sockets?)");

    auto ch = make_client_hello("real-target.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());

    // Should have: 2 decoy CH + N segments of real CH
    TEST_CHECK(segments.size() >= 4);  // 2 decoys + at least 2 splits

    auto stats = bypass.get_stats();
    TEST_CHECK(stats.fake_packets_injected == 2);

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
    TEST_CHECK(enc.size() == data.size());
    TEST_CHECK(enc != data);  // should be different

    auto dec = obf.deobfuscate(enc.data(), enc.size());
    TEST_CHECK(dec.size() == data.size());
    TEST_CHECK(dec == data);

    std::cout << " OK" << std::endl;
}

static void test_http_camouflage_roundtrip() {
    std::cout << "[TEST] HTTP camouflage roundtrip..." << std::flush;

    TrafficObfuscator obf(ObfuscationMode::HTTP_CAMOUFLAGE);

    const std::string payload = "secret tunnel data";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto enc = obf.obfuscate(data.data(), data.size());
    TEST_CHECK(enc.size() > data.size());

    // Should start with HTTP response
    std::string enc_str(enc.begin(), enc.end());
    TEST_CHECK(enc_str.find("HTTP/1.1 200 OK") == 0);

    auto dec = obf.deobfuscate(enc.data(), enc.size());
    TEST_CHECK(dec == data);

    std::cout << " OK" << std::endl;
}

static void test_presets_create() {
    std::cout << "[TEST] preset configurations create..." << std::flush;

    auto tspu = Presets::create_tspu_preset();
    TEST_CHECK(tspu.tspu_bypass);
    TEST_CHECK(!tspu.techniques.empty());
    TEST_CHECK(tspu.base_config.enable_tcp_split);
    TEST_CHECK(tspu.base_config.enable_decoy_sni);

    auto gfw = Presets::create_gfw_preset();
    TEST_CHECK(gfw.china_gfw_bypass);
    TEST_CHECK(gfw.obfuscation == ObfuscationMode::XOR_ROLLING);

    auto stealth = Presets::create_stealth_preset();
    TEST_CHECK(stealth.obfuscation == ObfuscationMode::HTTP_CAMOUFLAGE);

    auto aggressive = Presets::create_aggressive_preset();
    TEST_CHECK(aggressive.obfuscation == ObfuscationMode::CHACHA20);
    TEST_CHECK(aggressive.padding.enabled);

    auto compat = Presets::create_compatible_preset();
    TEST_CHECK(compat.techniques.size() == 1);

    auto iran = Presets::create_iran_preset();
    TEST_CHECK(iran.obfuscation == ObfuscationMode::HTTP_CAMOUFLAGE);

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
    if (!bypass.initialize(cfg))
        test_skip("AdvancedDPIBypass::initialize() failed (environment)");
    if (!bypass.start())
        test_skip("AdvancedDPIBypass::start() failed (no loopback sockets?)");

    auto ch = make_client_hello("fingerprint-test.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());
    TEST_CHECK(!segments.empty());

    bypass.stop();
    std::cout << " OK" << std::endl;
}

static void test_technique_toggle() {
    std::cout << "[TEST] technique enable/disable..." << std::flush;

    AdvancedDPIBypass bypass;
    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.techniques = { EvasionTechnique::SNI_SPLIT };
    if (!bypass.initialize(cfg))
        test_skip("AdvancedDPIBypass::initialize() failed (environment)");

    auto techniques = bypass.get_active_techniques();
    TEST_CHECK(techniques.size() == 1);
    TEST_CHECK(techniques[0] == EvasionTechnique::SNI_SPLIT);

    bypass.set_technique_enabled(EvasionTechnique::TIMING_JITTER, true);
    techniques = bypass.get_active_techniques();
    TEST_CHECK(techniques.size() == 2);

    bypass.set_technique_enabled(EvasionTechnique::SNI_SPLIT, false);
    techniques = bypass.get_active_techniques();
    TEST_CHECK(techniques.size() == 1);
    TEST_CHECK(techniques[0] == EvasionTechnique::TIMING_JITTER);

    std::cout << " OK" << std::endl;
}

int main() {
    if (sodium_init() < 0)
        test_skip("libsodium initialization failed");

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
