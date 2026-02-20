/**
 * @file test_mimicry_roundtrip.cpp
 * @brief Unit tests for ProtocolMimicry wrap/unwrap roundtrip with key exchange
 *
 * Phase 2 completion: validates that data survives wrap→unwrap cycle
 * with both default and custom TLS session keys.
 */

#include "../src/core/include/ncp_mimicry.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <sodium.h>

static void test_basic_roundtrip() {
    std::cout << "[TEST] basic_roundtrip..." << std::flush;

    ncp::ProtocolMimicry alice;
    ncp::ProtocolMimicry bob;

    // Sync keys: bob uses alice's key
    auto key = alice.get_tls_session_key();
    assert(key.size() == 32);
    bob.set_tls_session_key(key);

    // Test payload
    const std::string payload = "Hello from NCP tunnel!";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    // Alice wraps
    auto wrapped = alice.wrap_as_tls(data.data(), data.size());
    assert(!wrapped.empty());
    assert(wrapped.size() > data.size());  // overhead from TLS record framing

    // Bob unwraps
    auto unwrapped = bob.unwrap_tls(wrapped.data(), wrapped.size());
    assert(!unwrapped.empty());

    // Verify payload integrity
    assert(unwrapped.size() == data.size());
    assert(std::memcmp(unwrapped.data(), data.data(), data.size()) == 0);

    std::cout << " OK" << std::endl;
}

static void test_empty_data() {
    std::cout << "[TEST] empty_data_roundtrip..." << std::flush;

    ncp::ProtocolMimicry m;
    auto wrapped = m.wrap_as_tls(nullptr, 0);
    // Should handle gracefully — either empty or minimal record
    // unwrap of empty should also not crash
    auto unwrapped = m.unwrap_tls(nullptr, 0);

    std::cout << " OK" << std::endl;
}

static void test_large_payload() {
    std::cout << "[TEST] large_payload_roundtrip..." << std::flush;

    ncp::ProtocolMimicry alice;
    ncp::ProtocolMimicry bob;

    auto key = alice.get_tls_session_key();
    bob.set_tls_session_key(key);

    // 16KB payload (TLS record max is 16384)
    std::vector<uint8_t> big_data(16000);
    randombytes_buf(big_data.data(), big_data.size());

    auto wrapped = alice.wrap_as_tls(big_data.data(), big_data.size());
    assert(!wrapped.empty());

    auto unwrapped = bob.unwrap_tls(wrapped.data(), wrapped.size());
    assert(unwrapped.size() == big_data.size());
    assert(std::memcmp(unwrapped.data(), big_data.data(), big_data.size()) == 0);

    std::cout << " OK" << std::endl;
}

static void test_key_mismatch_fails() {
    std::cout << "[TEST] key_mismatch_fails..." << std::flush;

    ncp::ProtocolMimicry alice;
    ncp::ProtocolMimicry bob;  // different default key

    const std::string payload = "secret data";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto wrapped = alice.wrap_as_tls(data.data(), data.size());
    assert(!wrapped.empty());

    // Bob with different key — unwrap should fail or return different data
    auto unwrapped = bob.unwrap_tls(wrapped.data(), wrapped.size());
    // Either empty (decrypt failure) or different content
    bool mismatch = unwrapped.empty() ||
                    unwrapped.size() != data.size() ||
                    std::memcmp(unwrapped.data(), data.data(), data.size()) != 0;
    assert(mismatch);

    std::cout << " OK" << std::endl;
}

static void test_set_key_validation() {
    std::cout << "[TEST] set_key_validation..." << std::flush;

    ncp::ProtocolMimicry m;

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

    ncp::ProtocolMimicry alice;
    ncp::ProtocolMimicry bob;

    auto key = alice.get_tls_session_key();
    bob.set_tls_session_key(key);

    for (int i = 0; i < 100; ++i) {
        size_t msg_len = 1 + randombytes_uniform(4096);
        std::vector<uint8_t> msg(msg_len);
        randombytes_buf(msg.data(), msg.size());

        auto wrapped = alice.wrap_as_tls(msg.data(), msg.size());
        assert(!wrapped.empty());

        auto unwrapped = bob.unwrap_tls(wrapped.data(), wrapped.size());
        assert(unwrapped.size() == msg.size());
        assert(std::memcmp(unwrapped.data(), msg.data(), msg.size()) == 0);
    }

    std::cout << " OK (100 messages)" << std::endl;
}

static void test_tls_record_structure() {
    std::cout << "[TEST] tls_record_structure..." << std::flush;

    ncp::ProtocolMimicry m;

    const std::string payload = "test";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto wrapped = m.wrap_as_tls(data.data(), data.size());
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

    std::cout << "=== ProtocolMimicry Roundtrip Tests ===" << std::endl;

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
