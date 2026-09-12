/**
 * @file test_mimicry_roundtrip.cpp
 * @brief Unit tests for TrafficMimicry wrap/unwrap roundtrip with key exchange
 *
 * Phase 2 completion: validates that data survives wrap→unwrap cycle
 * with both default and custom TLS session keys.
 *
 * Zone F: ported from the removed ncp::ProtocolMimicry API
 * (wrap_as_tls/unwrap_tls) to the current ncp::TrafficMimicry API
 * (wrap_payload/unwrap_payload with MimicProfile::HTTPS_APPLICATION).
 */

#include "../src/core/include/ncp_mimicry.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <sodium.h>

using MimicProfile = ncp::TrafficMimicry::MimicProfile;

// Helper: wrap payload as TLS application data
static std::vector<uint8_t> wrap_as_tls(ncp::TrafficMimicry& m,
                                        const uint8_t* data, size_t size) {
    std::vector<uint8_t> payload;
    if (data != nullptr && size > 0) {
        payload.assign(data, data + size);
    }
    return m.wrap_payload(payload, MimicProfile::HTTPS_APPLICATION);
}

// Helper: unwrap TLS application data
static std::vector<uint8_t> unwrap_tls(ncp::TrafficMimicry& m,
                                       const uint8_t* data, size_t size) {
    std::vector<uint8_t> wrapped;
    if (data != nullptr && size > 0) {
        wrapped.assign(data, data + size);
    }
    return m.unwrap_payload(wrapped, MimicProfile::HTTPS_APPLICATION);
}

static void test_basic_roundtrip() {
    std::cout << "[TEST] basic_roundtrip..." << std::flush;

    ncp::TrafficMimicry alice;
    ncp::TrafficMimicry bob;

    // Sync keys: bob uses alice's key
    auto key = alice.get_tls_session_key();
    assert(key.size() == 32);
    bob.set_tls_session_key(key);

    // Test payload
    const std::string payload = "Hello from NCP tunnel!";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    // Alice wraps
    auto wrapped = wrap_as_tls(alice, data.data(), data.size());
    assert(!wrapped.empty());
    assert(wrapped.size() > data.size());  // overhead from TLS record framing

    // Bob unwraps
    auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
    assert(!unwrapped.empty());

    // Verify payload integrity
    assert(unwrapped.size() == data.size());
    assert(std::memcmp(unwrapped.data(), data.data(), data.size()) == 0);

    std::cout << " OK" << std::endl;
}

static void test_empty_data() {
    std::cout << "[TEST] empty_data_roundtrip..." << std::flush;

    ncp::TrafficMimicry m;
    auto wrapped = wrap_as_tls(m, nullptr, 0);
    // Should handle gracefully — either empty or minimal record.
    // Unwrap of the wrapped empty payload must not crash and must
    // yield an empty payload back.
    auto unwrapped = unwrap_tls(m, wrapped.data(), wrapped.size());
    assert(unwrapped.empty());

    // Unwrap of empty input must also not crash
    auto unwrapped_empty = unwrap_tls(m, nullptr, 0);
    assert(unwrapped_empty.empty());

    std::cout << " OK" << std::endl;
}

static void test_large_payload() {
    std::cout << "[TEST] large_payload_roundtrip..." << std::flush;

    ncp::TrafficMimicry alice;
    ncp::TrafficMimicry bob;

    auto key = alice.get_tls_session_key();
    bob.set_tls_session_key(key);

    // 16KB payload (TLS record max is 16384)
    std::vector<uint8_t> big_data(16000);
    randombytes_buf(big_data.data(), big_data.size());

    auto wrapped = wrap_as_tls(alice, big_data.data(), big_data.size());
    assert(!wrapped.empty());

    auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
    assert(unwrapped.size() == big_data.size());
    assert(std::memcmp(unwrapped.data(), big_data.data(), big_data.size()) == 0);

    std::cout << " OK" << std::endl;
}

static void test_key_mismatch_fails() {
    std::cout << "[TEST] key_mismatch_fails..." << std::flush;

    ncp::TrafficMimicry alice;
    ncp::TrafficMimicry bob;  // different default key

    const std::string payload = "secret data";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto wrapped = wrap_as_tls(alice, data.data(), data.size());
    assert(!wrapped.empty());

    // Bob with different key — unwrap should fail or return different data
    auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
    // Either empty (decrypt failure) or different content
    bool mismatch = unwrapped.empty() ||
                    unwrapped.size() != data.size() ||
                    std::memcmp(unwrapped.data(), data.data(), data.size()) != 0;
    assert(mismatch);

    std::cout << " OK" << std::endl;
}

static void test_set_key_validation() {
    std::cout << "[TEST] set_key_validation..." << std::flush;

    ncp::TrafficMimicry m;

    // Valid 32-byte key
    std::vector<uint8_t> good_key(32, 0xAB);
    m.set_tls_session_key(good_key);
    auto got = m.get_tls_session_key();
    assert(got.size() == 32);
    assert(std::memcmp(got.data(), good_key.data(), 32) == 0);

    // Invalid key sizes should be silently rejected
    std::vector<uint8_t> bad_key_16(16, 0xCC);
    m.set_tls_session_key(bad_key_16);
    got = m.get_tls_session_key();
    // Should still have the previous valid key
    assert(got.size() == 32);
    assert(std::memcmp(got.data(), good_key.data(), 32) == 0);

    std::vector<uint8_t> bad_key_0;
    m.set_tls_session_key(bad_key_0);
    got = m.get_tls_session_key();
    assert(got.size() == 32);
    assert(std::memcmp(got.data(), good_key.data(), 32) == 0);

    std::cout << " OK" << std::endl;
}

static void test_multiple_messages() {
    std::cout << "[TEST] multiple_messages_roundtrip..." << std::flush;

    ncp::TrafficMimicry alice;
    ncp::TrafficMimicry bob;

    auto key = alice.get_tls_session_key();
    bob.set_tls_session_key(key);

    for (int i = 0; i < 100; ++i) {
        size_t msg_len = 1 + randombytes_uniform(4096);
        std::vector<uint8_t> msg(msg_len);
        randombytes_buf(msg.data(), msg.size());

        auto wrapped = wrap_as_tls(alice, msg.data(), msg.size());
        assert(!wrapped.empty());

        auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
        assert(unwrapped.size() == msg.size());
        assert(std::memcmp(unwrapped.data(), msg.data(), msg.size()) == 0);
    }

    std::cout << " OK (100 messages)" << std::endl;
}

static void test_tls_record_structure() {
    std::cout << "[TEST] tls_record_structure..." << std::flush;

    ncp::TrafficMimicry m;

    const std::string payload = "test";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto wrapped = wrap_as_tls(m, data.data(), data.size());
    assert(wrapped.size() >= 5);

    // TLS Application Data record: ContentType = 0x17
    assert(wrapped[0] == 0x17);
    // TLS version 0x0303 (TLS 1.2 record layer)
    assert(wrapped[1] == 0x03);
    assert(wrapped[2] == 0x03);
    // Length field should match remaining data
    uint16_t rec_len = (static_cast<uint16_t>(wrapped[3]) << 8) |
                       static_cast<uint16_t>(wrapped[4]);
    assert(rec_len == wrapped.size() - 5);

    std::cout << " OK" << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium" << std::endl;
        return 1;
    }

    std::cout << "=== TrafficMimicry Roundtrip Tests ===" << std::endl;

    test_basic_roundtrip();
    test_empty_data();
    test_large_payload();
    test_key_mismatch_fails();
    test_set_key_validation();
    test_multiple_messages();
    test_tls_record_structure();

    std::cout << "\nAll mimicry roundtrip tests passed!" << std::endl;
    return 0;
}
