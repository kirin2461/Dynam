/**
 * @file test_ech_pipeline.cpp
 * @brief Unit tests for ECH config parsing, apply_ech extension insertion,
 *        and AdvancedDPIBypass ECH pipeline flow.
 *
 * Phase 2/3D: Validates ECH integration into the DPI bypass pipeline.
 * Tests work both with and without OpenSSL (stub path returns original CH).
 */

#include "../src/core/include/ncp_ech.hpp"
#include "../src/core/include/ncp_dpi_advanced.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <sodium.h>

using namespace ncp::DPI;
using namespace ncp::DPI::ECH;

// Helper: build a minimal valid TLS ClientHello with SNI
static std::vector<uint8_t> make_test_client_hello(const std::string& sni) {
    std::vector<uint8_t> ch;
    ch.reserve(256);

    // TLS Record Header
    ch.push_back(0x16);  // ContentType: Handshake
    ch.push_back(0x03); ch.push_back(0x01);  // TLS 1.0 record
    size_t rec_len_pos = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);  // placeholder

    // Handshake: ClientHello
    ch.push_back(0x01);  // HandshakeType
    size_t hs_len_pos = ch.size();
    ch.push_back(0x00); ch.push_back(0x00); ch.push_back(0x00);  // placeholder

    // ClientVersion: TLS 1.2
    ch.push_back(0x03); ch.push_back(0x03);

    // Random (32 bytes)
    for (int i = 0; i < 32; ++i) ch.push_back(static_cast<uint8_t>(i));

    // Session ID: 0 length
    ch.push_back(0x00);

    // Cipher Suites: 2 suites
    ch.push_back(0x00); ch.push_back(0x04);
    ch.push_back(0x13); ch.push_back(0x01);  // TLS_AES_128_GCM_SHA256
    ch.push_back(0x13); ch.push_back(0x02);  // TLS_AES_256_GCM_SHA384

    // Compression: null
    ch.push_back(0x01); ch.push_back(0x00);

    // Extensions
    size_t ext_len_pos = ch.size();
    ch.push_back(0x00); ch.push_back(0x00);

    // SNI Extension (type 0x0000)
    ch.push_back(0x00); ch.push_back(0x00);  // type
    uint16_t sni_ext_len = static_cast<uint16_t>(sni.size() + 5);
    ch.push_back(static_cast<uint8_t>(sni_ext_len >> 8));
    ch.push_back(static_cast<uint8_t>(sni_ext_len & 0xFF));
    // SNI list
    uint16_t sni_list_len = static_cast<uint16_t>(sni.size() + 3);
    ch.push_back(static_cast<uint8_t>(sni_list_len >> 8));
    ch.push_back(static_cast<uint8_t>(sni_list_len & 0xFF));
    ch.push_back(0x00);  // host_name type
    uint16_t hn_len = static_cast<uint16_t>(sni.size());
    ch.push_back(static_cast<uint8_t>(hn_len >> 8));
    ch.push_back(static_cast<uint8_t>(hn_len & 0xFF));
    ch.insert(ch.end(), sni.begin(), sni.end());

    // Fill extension length
    uint16_t exts_total = static_cast<uint16_t>(ch.size() - ext_len_pos - 2);
    ch[ext_len_pos]     = static_cast<uint8_t>(exts_total >> 8);
    ch[ext_len_pos + 1] = static_cast<uint8_t>(exts_total & 0xFF);

    // Fill handshake length
    uint32_t hs_len = static_cast<uint32_t>(ch.size() - hs_len_pos - 3);
    ch[hs_len_pos]     = static_cast<uint8_t>((hs_len >> 16) & 0xFF);
    ch[hs_len_pos + 1] = static_cast<uint8_t>((hs_len >> 8) & 0xFF);
    ch[hs_len_pos + 2] = static_cast<uint8_t>(hs_len & 0xFF);

    // Fill record length
    uint16_t rec_len = static_cast<uint16_t>(ch.size() - 5);
    ch[rec_len_pos]     = static_cast<uint8_t>(rec_len >> 8);
    ch[rec_len_pos + 1] = static_cast<uint8_t>(rec_len & 0xFF);

    return ch;
}

// Helper: build a test ECH config blob
static std::vector<uint8_t> make_test_ech_config_blob() {
    std::vector<uint8_t> blob;

    // Version: 0xfe0d (draft ECH)
    blob.push_back(0xfe); blob.push_back(0x0d);

    // Config ID
    blob.push_back(0x42);

    // KEM ID: DHKEM_X25519_HKDF_SHA256 = 0x0020
    blob.push_back(0x00); blob.push_back(0x20);

    // Public key: 32 random bytes
    std::vector<uint8_t> pk(32);
    randombytes_buf(pk.data(), pk.size());
    uint16_t pk_len = static_cast<uint16_t>(pk.size());
    blob.push_back(static_cast<uint8_t>(pk_len >> 8));
    blob.push_back(static_cast<uint8_t>(pk_len & 0xFF));
    blob.insert(blob.end(), pk.begin(), pk.end());

    return blob;
}

static void test_parse_ech_config() {
    std::cout << "[TEST] parse_ech_config..." << std::flush;

    auto blob = make_test_ech_config_blob();
    ECHConfig config;
    bool ok = parse_ech_config(blob, config);
    assert(ok);
    assert(config.version == 0xfe0d);
    assert(config.config_id == 0x42);
    assert(config.public_key.size() == 32);
    assert(config.cipher_suites.size() >= 1);
    assert(config.cipher_suites[0].kem_id == HPKEKem::DHKEM_X25519_HKDF_SHA256);
    assert(config.raw_config == blob);

    std::cout << " OK" << std::endl;
}

static void test_parse_ech_config_too_short() {
    std::cout << "[TEST] parse_ech_config_too_short..." << std::flush;

    std::vector<uint8_t> tiny = {0xfe, 0x0d, 0x01};
    ECHConfig config;
    bool ok = parse_ech_config(tiny, config);
    assert(!ok);

    std::cout << " OK" << std::endl;
}

static void test_apply_ech_to_client_hello() {
    std::cout << "[TEST] apply_ech_to_client_hello..." << std::flush;

    auto ch = make_test_client_hello("example.com");
    assert(ch.size() > 44);
    assert(ch[0] == 0x16);
    assert(ch[5] == 0x01);

    auto blob = make_test_ech_config_blob();
    ECHConfig config;
    bool parsed = parse_ech_config(blob, config);
    assert(parsed);

    auto result = apply_ech(ch, config);

    // With OpenSSL: result should be larger (ECH extension added)
    // Without OpenSSL: stub returns original unchanged
    // Either way, result should be a valid TLS record
    assert(result.size() >= ch.size());
    assert(result[0] == 0x16);  // still a Handshake record
    assert(result[5] == 0x01);  // still a ClientHello

    // Verify TLS record length consistency
    uint16_t rec_len = (static_cast<uint16_t>(result[3]) << 8) |
                       static_cast<uint16_t>(result[4]);
    assert(rec_len == result.size() - 5);

    // Verify handshake length consistency
    uint32_t hs_len = (static_cast<uint32_t>(result[6]) << 16) |
                      (static_cast<uint32_t>(result[7]) << 8) |
                      static_cast<uint32_t>(result[8]);
    assert(hs_len == result.size() - 9);

    std::cout << " OK (result_size=" << result.size()
              << ", original=" << ch.size() << ")" << std::endl;
}

static void test_dpi_evasion_apply_ech_wrapper() {
    std::cout << "[TEST] DPIEvasion::apply_ech wrapper..." << std::flush;

    auto ch = make_test_client_hello("test.org");
    auto blob = make_test_ech_config_blob();

    auto result = DPIEvasion::apply_ech(ch, blob);
    assert(result.size() >= ch.size());
    assert(result[0] == 0x16);

    std::cout << " OK" << std::endl;
}

static void test_advanced_bypass_ech_pipeline() {
    std::cout << "[TEST] AdvancedDPIBypass ECH pipeline..." << std::flush;

    auto ech_blob = make_test_ech_config_blob();

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    cfg.base_config.split_at_sni = true;
    cfg.enable_ech = true;
    cfg.ech_config_list = ech_blob;

    AdvancedDPIBypass bypass;
    bool ok = bypass.initialize(cfg);
    assert(ok);
    ok = bypass.start();
    assert(ok);

    auto ch = make_test_client_hello("secret.example.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());

    // Should produce at least 1 segment (split or unsplit)
    assert(!segments.empty());

    // Reassemble all segments
    size_t total_bytes = 0;
    for (const auto& seg : segments) {
        total_bytes += seg.size();
    }
    // Total output should be >= original (ECH adds extension, split doesn't lose data)
    assert(total_bytes >= ch.size());

    auto stats = bypass.get_stats();
    // With OpenSSL: ech_applied should be > 0
    // Without OpenSSL: ech_applied == 0 (stub path)
    // Either way, pipeline should not crash

    bypass.stop();

    std::cout << " OK (segments=" << segments.size()
              << ", total_bytes=" << total_bytes
              << ", ech_applied=" << stats.ech_applied << ")" << std::endl;
}

static void test_set_ech_config_runtime() {
    std::cout << "[TEST] set_ech_config at runtime..." << std::flush;

    AdvancedDPIConfig cfg;
    cfg.base_config.mode = DPIMode::PROXY;
    cfg.base_config.enable_tcp_split = true;
    // ECH not enabled in initial config
    cfg.enable_ech = false;

    AdvancedDPIBypass bypass;
    bool ok = bypass.initialize(cfg);
    assert(ok);
    ok = bypass.start();
    assert(ok);

    // Enable ECH at runtime
    auto ech_blob = make_test_ech_config_blob();
    bypass.set_ech_config(ech_blob);

    auto ch = make_test_client_hello("dynamic.example.com");
    auto segments = bypass.process_outgoing(ch.data(), ch.size());
    assert(!segments.empty());

    bypass.stop();

    std::cout << " OK" << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "=== ECH Pipeline Tests ===" << std::endl;

    test_parse_ech_config();
    test_parse_ech_config_too_short();
    test_apply_ech_to_client_hello();
    test_dpi_evasion_apply_ech_wrapper();
    test_advanced_bypass_ech_pipeline();
    test_set_ech_config_runtime();

    std::cout << "\nAll ECH pipeline tests passed!" << std::endl;
    return 0;
}
