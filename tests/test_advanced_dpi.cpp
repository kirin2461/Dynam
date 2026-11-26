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


static void test_tls_padding_rfc7685() {
    std::cout << "Testing RFC 7685 ClientHello padding..." << std::endl;

    TLSManipulator manip;
    auto ch = make_client_hello("example.com");
    const size_t orig_len = ch.size();
    const size_t pad = 100;

    auto padded = manip.add_tls_padding(ch.data(), ch.size(), pad);

    // Grows by exactly extension header (4) + pad bytes
    TEST_CHECK(padded.size() == orig_len + 4 + pad);

    // Record length field covers the whole record
    size_t rec_len = (static_cast<size_t>(padded[3]) << 8) | padded[4];
    TEST_CHECK(rec_len == padded.size() - 5);

    // Handshake length (3 bytes) spans the whole record
    size_t hs_len = (static_cast<size_t>(padded[6]) << 16) |
                    (static_cast<size_t>(padded[7]) << 8) | padded[8];
    TEST_CHECK(hs_len == rec_len - 4);

    // Last extension is padding (type 21), zero-filled per RFC 7685
    size_t ext_pos = padded.size() - 4 - pad;
    TEST_CHECK(padded[ext_pos] == 0x00 && padded[ext_pos + 1] == 0x15);
    size_t ext_pad_len = (static_cast<size_t>(padded[ext_pos + 2]) << 8) | padded[ext_pos + 3];
    TEST_CHECK(ext_pad_len == pad);
    for (size_t i = 0; i < pad; ++i)
        TEST_CHECK(padded[ext_pos + 4 + i] == 0x00);

    // Only the 2-byte extensions-length field may change; every other byte
    // of the original ClientHello must stay at the same offset. The field
    // sits right before the extensions block: ep = orig_len - 2 - ext_body,
    // where make_client_hello emits a single SNI extension of 9 + sni bytes.
    const size_t sni_len = std::string("example.com").size();
    const size_t ep = orig_len - 2 - (9 + sni_len);
    size_t old_el = (static_cast<size_t>(ch[ep]) << 8) | ch[ep + 1];
    size_t new_el = (static_cast<size_t>(padded[ep]) << 8) | padded[ep + 1];
    TEST_CHECK(old_el == 9 + sni_len);            // sanity: located the field
    TEST_CHECK(new_el == old_el + 4 + pad);
    // Record and handshake length fields grow by exactly 4 + pad as well.
    size_t old_rl = (static_cast<size_t>(ch[3]) << 8) | ch[4];
    size_t new_rl = (static_cast<size_t>(padded[3]) << 8) | padded[4];
    TEST_CHECK(new_rl == old_rl + 4 + pad);
    size_t old_hs = (static_cast<size_t>(ch[6]) << 16) |
                    (static_cast<size_t>(ch[7]) << 8) | ch[8];
    size_t new_hs = (static_cast<size_t>(padded[6]) << 16) |
                    (static_cast<size_t>(padded[7]) << 8) | padded[8];
    TEST_CHECK(new_hs == old_hs + 4 + pad);
    // Every other byte of the original ClientHello stays at its offset.
    for (size_t i = 0; i < orig_len; ++i) {
        if (i <= 8 || i == ep || i == ep + 1) continue;  // length fields
        TEST_CHECK(padded[i] == ch[i]);
    }

    // Non-ClientHello input passes through unchanged
    std::vector<uint8_t> other = {0x17, 0x03, 0x03, 0x00, 0x04,
                                  0x01, 0x02, 0x03, 0x04};
    auto out2 = manip.add_tls_padding(other.data(), other.size(), 64);
    TEST_CHECK(out2 == other);

    // Zero padding is a no-op
    auto out3 = manip.add_tls_padding(ch.data(), ch.size(), 0);
    TEST_CHECK(out3 == ch);

    std::cout << " OK" << std::endl;
}

static void test_domain_fronting() {
    std::cout << "[TEST] apply_domain_fronting..." << std::flush;

    auto contains = [](const std::vector<uint8_t>& h, const std::string& str) {
        if (str.empty() || h.size() < str.size()) return false;
        for (size_t i = 0; i + str.size() <= h.size(); ++i)
            if (std::memcmp(&h[i], str.data(), str.size()) == 0) return true;
        return false;
    };

    const std::string real = "real-target.com";   // 15 chars
    const std::string front = "cdn.short.io";     // 12 chars — differ on purpose
    const int64_t delta = static_cast<int64_t>(front.size()) -
                          static_cast<int64_t>(real.size());

    // (1) TLS ClientHello: SNI rewrite with differing lengths must NOT
    //     return {} (old bug) and must keep length fields consistent.
    auto ch = make_client_hello(real);
    auto out = DPIEvasion::apply_domain_fronting(ch, front, real);
    TEST_CHECK(!out.empty());
    TEST_CHECK(static_cast<int64_t>(out.size()) ==
               static_cast<int64_t>(ch.size()) + delta);
    uint16_t rec_len = (out[3] << 8) | out[4];
    TEST_CHECK(rec_len == out.size() - 5);
    uint32_t hs_len = (out[6] << 16) | (out[7] << 8) | out[8];
    TEST_CHECK(hs_len == out.size() - 9);
    TEST_CHECK(!contains(out, real));
    TEST_CHECK(contains(out, front));

    // (2) TLS with SNI != real_domain -> input returned unchanged
    auto ch2 = make_client_hello("other.example.org");
    auto out2 = DPIEvasion::apply_domain_fronting(ch2, front, real);
    TEST_CHECK(out2 == ch2);

    // (3) HTTP/1.1 Host header (value lengths differ)
    std::string req_s = "GET / HTTP/1.1\r\nHost: real-target.com\r\n\r\n";
    std::vector<uint8_t> req(req_s.begin(), req_s.end());
    auto out3 = DPIEvasion::apply_domain_fronting(req, front, real);
    TEST_CHECK(!out3.empty());
    std::string s3(out3.begin(), out3.end());
    TEST_CHECK(s3.find("Host: cdn.short.io") != std::string::npos);
    TEST_CHECK(s3.find("real-target.com") == std::string::npos);

    // (4) Garbage input -> returned unchanged, never {}
    std::vector<uint8_t> junk = {0x00,0x11,0x22,0x33,0x44,0x55,
                                 0x66,0x77,0x88,0x99,0xaa,0xbb};
    auto out4 = DPIEvasion::apply_domain_fronting(junk, front, real);
    TEST_CHECK(out4 == junk);

    // (5) HTTP/2 HEADERS frame: HPACK :authority literal rewrite + the
    //     frame's 24-bit length patched by the size delta
    std::vector<uint8_t> h2;
    const char* preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    h2.insert(h2.end(), preface, preface + 24);
    std::vector<uint8_t> payload = {0x41, static_cast<uint8_t>(real.size())};
    payload.insert(payload.end(), real.begin(), real.end());
    uint32_t L = static_cast<uint32_t>(payload.size());
    h2.push_back(static_cast<uint8_t>((L >> 16) & 0xFF));
    h2.push_back(static_cast<uint8_t>((L >> 8) & 0xFF));
    h2.push_back(static_cast<uint8_t>(L & 0xFF));
    h2.push_back(0x01);  // HEADERS
    h2.push_back(0x04);  // END_HEADERS
    h2.push_back(0x00); h2.push_back(0x00);
    h2.push_back(0x00); h2.push_back(0x01);  // stream 1
    h2.insert(h2.end(), payload.begin(), payload.end());

    auto out5 = DPIEvasion::apply_domain_fronting(h2, front, real);
    TEST_CHECK(!out5.empty());
    TEST_CHECK(static_cast<int64_t>(out5.size()) ==
               static_cast<int64_t>(h2.size()) + delta);
    uint32_t nL = (out5[24] << 16) | (out5[25] << 8) | out5[26];
    TEST_CHECK(static_cast<int64_t>(nL) ==
               static_cast<int64_t>(payload.size()) + delta);
    TEST_CHECK(out5[27] == 0x01);
    std::string s5(out5.begin() + 33, out5.end());
    TEST_CHECK(s5.find(front) != std::string::npos);
    TEST_CHECK(s5.find(real) == std::string::npos);

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
    test_tls_padding_rfc7685();

    test_domain_fronting();

    std::cout << "\nAll advanced DPI tests passed!" << std::endl;
    return 0;
}
