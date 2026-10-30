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
    TEST_CHECK(key.size() == 32);
    bob.set_tls_session_key(key);

    // Test payload
    const std::string payload = "Hello from NCP tunnel!";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    // Alice wraps
    auto wrapped = wrap_as_tls(alice, data.data(), data.size());
    TEST_CHECK(!wrapped.empty());
    TEST_CHECK(wrapped.size() > data.size());  // overhead from TLS record framing

    // Bob unwraps
    auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
    TEST_CHECK(!unwrapped.empty());

    // Verify payload integrity
    TEST_CHECK(unwrapped.size() == data.size());
    TEST_CHECK(std::memcmp(unwrapped.data(), data.data(), data.size()) == 0);

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
    TEST_CHECK(unwrapped.empty());

    // Unwrap of empty input must also not crash
    auto unwrapped_empty = unwrap_tls(m, nullptr, 0);
    TEST_CHECK(unwrapped_empty.empty());

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
    TEST_CHECK(!wrapped.empty());

    auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
    TEST_CHECK(unwrapped.size() == big_data.size());
    TEST_CHECK(std::memcmp(unwrapped.data(), big_data.data(), big_data.size()) == 0);

    std::cout << " OK" << std::endl;
}

static void test_key_mismatch_fails() {
    std::cout << "[TEST] key_mismatch_fails..." << std::flush;

    ncp::TrafficMimicry alice;
    ncp::TrafficMimicry bob;  // different default key

    const std::string payload = "secret data";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto wrapped = wrap_as_tls(alice, data.data(), data.size());
    TEST_CHECK(!wrapped.empty());

    // Bob with different key — unwrap should fail or return different data
    auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
    // Either empty (decrypt failure) or different content
    bool mismatch = unwrapped.empty() ||
                    unwrapped.size() != data.size() ||
                    std::memcmp(unwrapped.data(), data.data(), data.size()) != 0;
    TEST_CHECK(mismatch);

    std::cout << " OK" << std::endl;
}

static void test_set_key_validation() {
    std::cout << "[TEST] set_key_validation..." << std::flush;

    ncp::TrafficMimicry m;

    // Valid 32-byte key
    std::vector<uint8_t> good_key(32, 0xAB);
    m.set_tls_session_key(good_key);
    auto got = m.get_tls_session_key();
    TEST_CHECK(got.size() == 32);
    TEST_CHECK(std::memcmp(got.data(), good_key.data(), 32) == 0);

    // Invalid key sizes should be silently rejected
    std::vector<uint8_t> bad_key_16(16, 0xCC);
    m.set_tls_session_key(bad_key_16);
    got = m.get_tls_session_key();
    // Should still have the previous valid key
    TEST_CHECK(got.size() == 32);
    TEST_CHECK(std::memcmp(got.data(), good_key.data(), 32) == 0);

    std::vector<uint8_t> bad_key_0;
    m.set_tls_session_key(bad_key_0);
    got = m.get_tls_session_key();
    TEST_CHECK(got.size() == 32);
    TEST_CHECK(std::memcmp(got.data(), good_key.data(), 32) == 0);

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
        TEST_CHECK(!wrapped.empty());

        auto unwrapped = unwrap_tls(bob, wrapped.data(), wrapped.size());
        TEST_CHECK(unwrapped.size() == msg.size());
        TEST_CHECK(std::memcmp(unwrapped.data(), msg.data(), msg.size()) == 0);
    }

    std::cout << " OK (100 messages)" << std::endl;
}

static void test_tls_record_structure() {
    std::cout << "[TEST] tls_record_structure..." << std::flush;

    ncp::TrafficMimicry m;

    const std::string payload = "test";
    std::vector<uint8_t> data(payload.begin(), payload.end());

    auto wrapped = wrap_as_tls(m, data.data(), data.size());
    TEST_CHECK(wrapped.size() >= 5);

    // TLS Application Data record: ContentType = 0x17
    TEST_CHECK(wrapped[0] == 0x17);
    // TLS version 0x0303 (TLS 1.2 record layer)
    TEST_CHECK(wrapped[1] == 0x03);
    TEST_CHECK(wrapped[2] == 0x03);
    // Length field should match remaining data
    uint16_t rec_len = (static_cast<uint16_t>(wrapped[3]) << 8) |
                       static_cast<uint16_t>(wrapped[4]);
    TEST_CHECK(rec_len == wrapped.size() - 5);

    std::cout << " OK" << std::endl;
}

// ==================== v2 session-bound masks ====================

using MimicConfig = ncp::TrafficMimicry::MimicConfig;

static MimicConfig v2_cfg(MimicProfile p, uint8_t key_seed) {
    MimicConfig c;
    c.profile = p;
    c.wire_version = 3;               // peers must agree (0 = random)
    c.enable_timing_mimicry = false;
    c.enable_size_mimicry = false;    // deterministic sizes for exact checks
    for (size_t i = 0; i < c.session_mask_key.size(); ++i)
        c.session_mask_key[i] = static_cast<uint8_t>(key_seed + i * 7u);
    return c;
}

// QUIC_SHORT_HEADER roundtrip + wire shape:
//   [first:1][dcid:8][pn:4][nonce:24][ct_len:4][ct = 5+payload+16]
static void test_quic_short_header_roundtrip() {
    std::cout << "[TEST] quic_short_header_roundtrip..." << std::flush;

    ncp::TrafficMimicry a(v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0x11));
    ncp::TrafficMimicry b(v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0x11));

    std::vector<uint8_t> first_dcid;
    for (size_t len : {1u, 32u, 100u, 1000u, 1400u}) {
        std::vector<uint8_t> msg(len);
        randombytes_buf(msg.data(), msg.size());

        auto w = a.wrap_payload(msg, MimicProfile::QUIC_SHORT_HEADER);
        // Exact size formula: no min-1200 padding (unlike QUIC_INITIAL).
        TEST_CHECK(w.size() == 62 + len);
        // Short-header form: 0x80 clear, fixed bit 0x40 set.
        TEST_CHECK((w[0] & 0x80) == 0);
        TEST_CHECK((w[0] & 0x40) != 0);
        // Session-stable DCID at bytes 1..8.
        std::vector<uint8_t> dcid(w.begin() + 1, w.begin() + 9);
        if (first_dcid.empty()) first_dcid = dcid;
        TEST_CHECK(dcid == first_dcid);

        auto u = b.unwrap_payload(w, MimicProfile::QUIC_SHORT_HEADER);
        TEST_CHECK(u == msg);
    }

    // Packet number increments (bytes 9..12 BE).
    auto w1 = a.wrap_payload({0xAA}, MimicProfile::QUIC_SHORT_HEADER);
    auto w2 = a.wrap_payload({0xBB}, MimicProfile::QUIC_SHORT_HEADER);
    uint32_t pn1 = (uint32_t(w1[9]) << 24) | (uint32_t(w1[10]) << 16) |
                   (uint32_t(w1[11]) << 8) | w1[12];
    uint32_t pn2 = (uint32_t(w2[9]) << 24) | (uint32_t(w2[10]) << 16) |
                   (uint32_t(w2[11]) << 8) | w2[12];
    TEST_CHECK(pn2 == pn1 + 1);

    std::cout << " OK" << std::endl;
}

// STUN_MESSAGE roundtrip + RFC 5389 shape: [type:2][len:2][cookie:4][txn:12]
// + payload attr (0x8022) + MESSAGE-INTEGRITY (0x0008, HMAC-SHA1).
static void test_stun_message_roundtrip() {
    std::cout << "[TEST] stun_message_roundtrip..." << std::flush;

    ncp::TrafficMimicry a(v2_cfg(MimicProfile::STUN_MESSAGE, 0x42));
    ncp::TrafficMimicry b(v2_cfg(MimicProfile::STUN_MESSAGE, 0x42));

    bool saw_req = false, saw_resp = false;
    for (size_t len : {1u, 2u, 3u, 4u, 5u, 48u, 100u, 555u, 1400u}) {
        std::vector<uint8_t> msg(len);
        randombytes_buf(msg.data(), msg.size());

        auto w = a.wrap_payload(msg, MimicProfile::STUN_MESSAGE);
        // 4-byte alignment per RFC 5389; exact size:
        // 20 header + 4 attr hdr + pad4(5+len) + 24 MESSAGE-INTEGRITY.
        const size_t padded = (5 + len + 3) & ~size_t(3);
        TEST_CHECK(w.size() == 48 + padded);
        TEST_CHECK(w.size() % 4 == 0);
        // Type: Binding Request / Response alternated.
        uint16_t type = (uint16_t(w[0]) << 8) | w[1];
        TEST_CHECK(type == 0x0001 || type == 0x0101);
        (type == 0x0001 ? saw_req : saw_resp) = true;
        // Magic cookie.
        TEST_CHECK(w[4] == 0x21 && w[5] == 0x12 && w[6] == 0xA4 &&
                   w[7] == 0x42);
        // Length field covers the attribute area exactly.
        uint16_t mlen = (uint16_t(w[2]) << 8) | w[3];
        TEST_CHECK(20u + mlen == w.size());
        // Payload attribute 0x8022 (reserved range).
        TEST_CHECK(w[20] == 0x80 && w[21] == 0x22);

        auto u = b.unwrap_payload(w, MimicProfile::STUN_MESSAGE);
        TEST_CHECK(u == msg);
    }
    TEST_CHECK(saw_req && saw_resp);

    std::cout << " OK" << std::endl;
}

// Fail-closed unwrap: wrong session key / wrong DCID / tampering all yield
// empty output at the mask layer (before any E2E AEAD attempt).
static void test_new_masks_fail_closed() {
    std::cout << "[TEST] new_masks_fail_closed..." << std::flush;

    const std::vector<uint8_t> msg = {'s', 'e', 'c', 'r', 'e', 't'};

    for (auto prof : {MimicProfile::QUIC_SHORT_HEADER,
                      MimicProfile::STUN_MESSAGE}) {
        ncp::TrafficMimicry a(v2_cfg(prof, 0x01));
        ncp::TrafficMimicry wrong_key(v2_cfg(prof, 0x02));
        ncp::TrafficMimicry right_key(v2_cfg(prof, 0x01));

        auto w = a.wrap_payload(msg, prof);
        TEST_CHECK(!w.empty());

        // Wrong session key → fail closed (QUIC: DCID mismatch;
        // STUN: MESSAGE-INTEGRITY HMAC mismatch).
        TEST_CHECK(wrong_key.unwrap_payload(w, prof).empty());

        // Tampered byte deep inside the authenticated region → fail closed.
        for (size_t off : {w.size() / 2, w.size() - 1}) {
            auto t = w;
            t[off] ^= 0x01;
            TEST_CHECK(right_key.unwrap_payload(t, prof).empty());
        }

        // QUIC_SHORT_HEADER: explicit wrong-DCID reject (flip a DCID byte).
        if (prof == MimicProfile::QUIC_SHORT_HEADER) {
            auto t = w;
            t[3] ^= 0xFF;  // inside [dcid:8] at bytes 1..8
            TEST_CHECK(right_key.unwrap_payload(t, prof).empty());
            // Long-header form (0x80 set) is not a short header.
            t = w;
            t[0] |= 0x80;
            TEST_CHECK(right_key.unwrap_payload(t, prof).empty());
        }
        // STUN: wrong magic cookie / wrong type fail closed.
        if (prof == MimicProfile::STUN_MESSAGE) {
            auto t = w;
            t[4] ^= 0xFF;  // magic cookie
            TEST_CHECK(right_key.unwrap_payload(t, prof).empty());
            t = w;
            t[0] = 0xFF;   // not Binding request/response
            TEST_CHECK(right_key.unwrap_payload(t, prof).empty());
        }
    }

    std::cout << " OK" << std::endl;
}

// False-positive unwrap rate vs random garbage must be ~0 (the session
// adapter tries masks as ordered RX candidates; a structural false positive
// would waste an E2E AEAD attempt per candidate).
static void test_new_masks_false_positive_rate() {
    std::cout << "[TEST] new_masks_false_positive_rate..." << std::flush;

    ncp::TrafficMimicry q(v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0x77));
    ncp::TrafficMimicry s(v2_cfg(MimicProfile::STUN_MESSAGE, 0x77));

    // Random garbage of random sizes (including sub-minimum sizes).
    const int kTrials = 20000;
    size_t fp = 0;
    for (int i = 0; i < kTrials; ++i) {
        std::vector<uint8_t> junk(randombytes_uniform(200));
        randombytes_buf(junk.data(), junk.size());
        fp += !q.unwrap_payload(junk, MimicProfile::QUIC_SHORT_HEADER).empty();
        fp += !s.unwrap_payload(junk, MimicProfile::STUN_MESSAGE).empty();
    }
    TEST_CHECK(fp == 0);

    // Cross-mask: output of every other mask must fail closed under the new
    // masks, and the new masks' output must not decode under each other.
    ncp::TrafficMimicry gen(v2_cfg(MimicProfile::GENERIC_UDP, 0x77));
    ncp::TrafficMimicry qi(v2_cfg(MimicProfile::QUIC_INITIAL, 0x77));
    const std::vector<uint8_t> msg = {'c', 'r', 'o', 's', 's'};

    auto g = gen.wrap_payload(msg, MimicProfile::GENERIC_UDP);
    TEST_CHECK(q.unwrap_payload(g, MimicProfile::QUIC_SHORT_HEADER).empty());
    TEST_CHECK(s.unwrap_payload(g, MimicProfile::STUN_MESSAGE).empty());

    auto init_w = qi.wrap_payload(msg, MimicProfile::QUIC_INITIAL);
    TEST_CHECK(q.unwrap_payload(init_w, MimicProfile::QUIC_SHORT_HEADER)
                   .empty());
    TEST_CHECK(s.unwrap_payload(init_w, MimicProfile::STUN_MESSAGE).empty());

    auto qw = q.wrap_payload(msg, MimicProfile::QUIC_SHORT_HEADER);
    auto sw = s.wrap_payload(msg, MimicProfile::STUN_MESSAGE);
    TEST_CHECK(s.unwrap_payload(qw, MimicProfile::STUN_MESSAGE).empty());
    TEST_CHECK(q.unwrap_payload(sw, MimicProfile::QUIC_SHORT_HEADER).empty());
    // QUIC_SHORT_HEADER output must not decode as QUIC_INITIAL either
    // (0x80 clear → rejected by the Initial extractor immediately).
    TEST_CHECK(qi.unwrap_payload(qw, MimicProfile::QUIC_INITIAL).empty());

    std::cout << " OK" << std::endl;
}

// Stats counters: wraps/unwraps of the new masks are accounted like any
// other profile.
static void test_new_masks_stats_counters() {
    std::cout << "[TEST] new_masks_stats_counters..." << std::flush;

    ncp::TrafficMimicry m(v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0x09));
    const auto before = m.get_stats();
    const std::vector<uint8_t> msg = {'x', 'y', 'z'};
    for (int i = 0; i < 3; ++i) {
        auto w = m.wrap_payload(msg, MimicProfile::QUIC_SHORT_HEADER);
        TEST_CHECK(!w.empty());
        auto u = m.unwrap_payload(w, MimicProfile::QUIC_SHORT_HEADER);
        TEST_CHECK(u == msg);
    }
    // Failed unwraps are counted too (caller-side observability of
    // candidate evaluation cost).
    m.unwrap_payload(std::vector<uint8_t>{1, 2, 3},
                     MimicProfile::QUIC_SHORT_HEADER);

    const auto after = m.get_stats();
    TEST_CHECK(after.packets_wrapped.load() ==
               before.packets_wrapped.load() + 3);
    TEST_CHECK(after.packets_unwrapped.load() ==
               before.packets_unwrapped.load() + 4);
    TEST_CHECK(after.bytes_original.load() ==
               before.bytes_original.load() + 3 * msg.size());
    TEST_CHECK(after.bytes_mimicked.load() ==
               before.bytes_mimicked.load() + 3 * (62 + msg.size()));

    std::cout << " OK" << std::endl;
}

// MEDIUM-1 regression: the QUIC_SHORT_HEADER mask AEAD key must be derived
// from the session mask key, NOT from the DCID — the DCID is transmitted in
// clear in every datagram, so a DCID-derived key is publicly forgeable by
// any passive observer (working pre-fix repro: derive the key from one
// sniffed datagram, forge, pass the mask layer).
static void test_quic_short_header_key_not_forgeable_from_wire() {
    std::cout << "[TEST] quic_short_header_key_not_forgeable_from_wire..."
              << std::flush;

    ncp::TrafficMimicry a(v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0x33));
    ncp::TrafficMimicry b(v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0x33));

    const std::vector<uint8_t> msg = {'f', 'o', 'r', 'g', 'e', '-', 'm', 'e'};
    auto w = a.wrap_payload(msg, MimicProfile::QUIC_SHORT_HEADER);
    TEST_CHECK(w.size() == 62 + msg.size());

    // Passive observer: read the DCID (bytes 1..8) off the wire and derive
    // the mask AEAD key the OLD (wave-1, never shipped) way.
    const uint8_t* dcid = w.data() + 1;
    uint8_t old_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t info[] = "NCP-QUIC-SHORT-KEY-v1";
    crypto_generichash(old_key, sizeof(old_key), dcid, 8,
                       info, sizeof(info) - 1);

    // Forge a datagram: the copied DCID passes the fail-fast wrong-flow
    // check; fresh nonce; attacker payload encrypted under the
    // observer-derived (old-style) key.
    const std::vector<uint8_t> evil = {'o', 'w', 'n', 'e', 'd'};
    std::vector<uint8_t> pt;
    pt.push_back(3);  // victim session's wire_version
    uint32_t pl = static_cast<uint32_t>(evil.size());
    pt.push_back((pl >> 24) & 0xFF);
    pt.push_back((pl >> 16) & 0xFF);
    pt.push_back((pl >> 8) & 0xFF);
    pt.push_back(pl & 0xFF);
    pt.insert(pt.end(), evil.begin(), evil.end());

    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    std::vector<uint8_t> ct(pt.size() +
                            crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len, pt.data(), pt.size(),
        nullptr, 0, nullptr, nonce, old_key);
    ct.resize(static_cast<size_t>(ct_len));
    sodium_memzero(old_key, sizeof(old_key));

    std::vector<uint8_t> forged;
    forged.push_back(0x40);                                    // short header
    forged.insert(forged.end(), w.begin() + 1, w.begin() + 9);   // copied DCID
    forged.insert(forged.end(), w.begin() + 9, w.begin() + 13);  // plausible PN
    forged.insert(forged.end(), nonce, nonce + sizeof(nonce));
    uint32_t cs = static_cast<uint32_t>(ct.size());
    forged.push_back((cs >> 24) & 0xFF);
    forged.push_back((cs >> 16) & 0xFF);
    forged.push_back((cs >> 8) & 0xFF);
    forged.push_back(cs & 0xFF);
    forged.insert(forged.end(), ct.begin(), ct.end());

    // The forgery MUST fail unwrap now: the AEAD key is session-keyed, so
    // the observer-derived key does not match. (Mutation check: reverting
    // the unwrap-side derivation to BLAKE2b(DCID, ...) makes this unwrap
    // return "owned" and fails this test.)
    TEST_CHECK(b.unwrap_payload(forged, MimicProfile::QUIC_SHORT_HEADER)
                   .empty());

    // Legitimate roundtrip unaffected by the key change.
    TEST_CHECK(b.unwrap_payload(w, MimicProfile::QUIC_SHORT_HEADER) == msg);

    // Zero-key behavior unchanged: zero-key standalone instances still
    // roundtrip (deterministic, unauthenticated — see the session_mask_key
    // doc warning).
    MimicConfig z = v2_cfg(MimicProfile::QUIC_SHORT_HEADER, 0);
    z.session_mask_key.fill(0);
    ncp::TrafficMimicry z1(z);
    ncp::TrafficMimicry z2(z);
    auto zw = z1.wrap_payload(msg, MimicProfile::QUIC_SHORT_HEADER);
    TEST_CHECK(z2.unwrap_payload(zw, MimicProfile::QUIC_SHORT_HEADER) == msg);

    std::cout << " OK" << std::endl;
}

// LOW-1: with an endpoint role configured, the STUN transaction-id streams
// of the two directions are distinct (role byte mixed into the HMAC input);
// role 0 (standalone use) keeps the legacy stream byte-identical. The txn id
// is not authenticated (MESSAGE-INTEGRITY is), so cross-role unwrap is
// unaffected.
static void test_stun_txid_role_separation() {
    std::cout << "[TEST] stun_txid_role_separation..." << std::flush;

    auto cfg_role = [](uint8_t role) {
        MimicConfig c = v2_cfg(MimicProfile::STUN_MESSAGE, 0x5A);
        c.endpoint_role = role;
        return c;
    };
    ncp::TrafficMimicry cli(cfg_role(1));
    ncp::TrafficMimicry srv(cfg_role(2));
    ncp::TrafficMimicry standalone(cfg_role(0));

    const std::vector<uint8_t> msg = {'r', 'o', 'l', 'e'};
    auto wc = cli.wrap_payload(msg, MimicProfile::STUN_MESSAGE);
    auto ws = srv.wrap_payload(msg, MimicProfile::STUN_MESSAGE);
    auto w0 = standalone.wrap_payload(msg, MimicProfile::STUN_MESSAGE);
    TEST_CHECK(!wc.empty() && !ws.empty() && !w0.empty());

    // Transaction id: bytes 8..19 (after type:2, length:2, cookie:4).
    auto txn = [](const std::vector<uint8_t>& x) {
        return std::vector<uint8_t>(x.begin() + 8, x.begin() + 20);
    };
    TEST_CHECK(txn(wc) != txn(ws));  // direction-distinct
    TEST_CHECK(txn(wc) != txn(w0));
    TEST_CHECK(txn(ws) != txn(w0));

    // Role 0 keeps the exact legacy stream: first datagram (counter 0) txn
    // id == HMAC-SHA256(session_mask_key, 8-byte BE zero counter)[:12].
    std::array<uint8_t, 32> key{};
    for (size_t i = 0; i < key.size(); ++i)
        key[i] = static_cast<uint8_t>(0x5A + i * 7u);
    uint8_t ctr[8] = {0};
    uint8_t full[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256(full, ctr, sizeof(ctr), key.data());
    TEST_CHECK(std::memcmp(w0.data() + 8, full, 12) == 0);
    sodium_memzero(full, sizeof(full));

    // Roundtrips unaffected in every direction/role combination.
    TEST_CHECK(srv.unwrap_payload(wc, MimicProfile::STUN_MESSAGE) == msg);
    TEST_CHECK(cli.unwrap_payload(ws, MimicProfile::STUN_MESSAGE) == msg);
    TEST_CHECK(standalone.unwrap_payload(w0, MimicProfile::STUN_MESSAGE) ==
               msg);

    std::cout << " OK" << std::endl;
}

int main() {
    if (sodium_init() < 0)
        test_skip("libsodium initialization failed");

    std::cout << "=== TrafficMimicry Roundtrip Tests ===" << std::endl;

    test_basic_roundtrip();
    test_empty_data();
    test_large_payload();
    test_key_mismatch_fails();
    test_set_key_validation();
    test_multiple_messages();
    test_tls_record_structure();
    // v2 session-bound masks (QUIC_SHORT_HEADER / STUN_MESSAGE)
    test_quic_short_header_roundtrip();
    test_stun_message_roundtrip();
    test_new_masks_fail_closed();
    test_new_masks_false_positive_rate();
    test_new_masks_stats_counters();
    test_quic_short_header_key_not_forgeable_from_wire();
    test_stun_txid_role_separation();

    std::cout << "\nAll mimicry roundtrip tests passed!" << std::endl;
    return 0;
}
