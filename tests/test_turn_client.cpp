// ══════════════════════════════════════════════════════════════════════════════
// tests/test_turn_client.cpp
// G5: unit tests for the REAL TURN-over-UDP client (ncp_turn_client.hpp).
//
// Coverage:
//   * STUN codec pinned against RFC 5769 test vectors (MESSAGE-INTEGRITY
//     HMAC-SHA1, FINGERPRINT CRC32, long-term MD5 key, XOR-MAPPED-ADDRESS).
//   * Codec boundary conditions (framing, padding, malformed input).
//   * Client state machine against an in-process fake TURN server over
//     loopback UDP: 401/nonce/MESSAGE-INTEGRITY handshake, Allocate,
//     CreatePermission, ChannelBind, Refresh (+delete), Send/Data bootstrap,
//     ChannelData echo, retransmission bounds/timeouts, unknown/replayed
//     transaction handling.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_turn_client.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace ncp::turn;

// ── Helpers ──────────────────────────────────────────────────────────────────

static std::vector<uint8_t> hexbytes(const std::string& s) {
    std::vector<uint8_t> out;
    unsigned int v = 0;
    bool have_hi = false;
    for (char c : s) {
        if (isspace(static_cast<unsigned char>(c))) continue;
        unsigned int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else continue;
        if (!have_hi) { v = d << 4; have_hi = true; }
        else { v |= d; out.push_back(static_cast<uint8_t>(v)); have_hi = false; }
    }
    return out;
}

static std::string to_hex(const uint8_t* p, size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) { s += k[p[i] >> 4]; s += k[p[i] & 0xF]; }
    return s;
}

// ══════════════════════════════════════════════════════════════════════════════
// Codec tests pinned to RFC 5769
// ══════════════════════════════════════════════════════════════════════════════

class TurnCodecTest : public ::testing::Test {};

// RFC 5769 §2.1 sample request (short-term credential; key = password).
TEST_F(TurnCodecTest, RFC5769_SampleRequest_DecodeIntegrityFingerprint) {
    const std::vector<uint8_t> msg = hexbytes(
        "00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
        "80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74"
        "00 24 00 04 6e 00 01 ff 80 29 00 08 93 2f f9 b1 51 26 3b 36"
        "00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20"
        "00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2"
        "80 28 00 04 e5 7a 3b cf");

    StunMessage m;
    std::string err;
    ASSERT_TRUE(stun_decode(msg.data(), msg.size(), m, err)) << err;
    EXPECT_EQ(m.method, kMethodBinding);
    EXPECT_EQ(m.cls, StunClass::Request);
    EXPECT_EQ(m.find_string(kAttrSoftware), "STUN test client");
    EXPECT_EQ(m.find_string(kAttrUsername), "evtj:h6vY");
    ASSERT_TRUE(m.has_message_integrity);
    ASSERT_TRUE(m.has_fingerprint);

    const std::string pw = "VOkJxbRl1RmTxUk/WvJxBt";
    EXPECT_TRUE(stun_verify_integrity(
        m, reinterpret_cast<const uint8_t*>(pw.data()), pw.size()));
    EXPECT_TRUE(stun_verify_fingerprint(m));

    // Wrong key must fail.
    const std::string bad = "wrong-password";
    EXPECT_FALSE(stun_verify_integrity(
        m, reinterpret_cast<const uint8_t*>(bad.data()), bad.size()));
}

// RFC 5769 §2.2 sample IPv4 response.
TEST_F(TurnCodecTest, RFC5769_SampleResponseIPv4_XorMappedAddress) {
    const std::vector<uint8_t> msg = hexbytes(
        "01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
        "80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20"
        "00 20 00 08 00 01 a1 47 e1 12 a6 43"
        "00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7"
        "80 28 00 04 c0 7d 4c 96");

    StunMessage m;
    std::string err;
    ASSERT_TRUE(stun_decode(msg.data(), msg.size(), m, err)) << err;
    EXPECT_EQ(m.method, kMethodBinding);
    EXPECT_EQ(m.cls, StunClass::SuccessResponse);

    const std::string pw = "VOkJxbRl1RmTxUk/WvJxBt";
    EXPECT_TRUE(stun_verify_integrity(
        m, reinterpret_cast<const uint8_t*>(pw.data()), pw.size()));
    EXPECT_TRUE(stun_verify_fingerprint(m));

    const StunAttribute* xa = m.find(kAttrXorMappedAddress);
    ASSERT_NE(xa, nullptr);
    uint32_t addr_be = 0;
    uint16_t port = 0;
    ASSERT_TRUE(decode_xor_address_ipv4(*xa, m.txn_id, addr_be, port));
    EXPECT_EQ(port, 32853);
    in_addr a{addr_be};
    char buf[INET_ADDRSTRLEN];
    ASSERT_NE(inet_ntop(AF_INET, &a, buf, sizeof(buf)), nullptr);
    EXPECT_EQ(std::string(buf), "192.0.2.1");
}

// RFC 5769 §2.4 sample request with long-term authentication.
// key = MD5("<U+30DE><U+30C8><U+30EA><U+30C3><U+30AF><U+30B9>:example.org:
//           TheMatrIX")  (password after SASLprep).
TEST_F(TurnCodecTest, RFC5769_LongTermRequest_MessageIntegrity) {
    const std::vector<uint8_t> msg = hexbytes(
        "00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e"
        "00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00"
        "00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46"
        "53 54 76 79 36 34 73 41"
        "00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00"
        "00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66");

    StunMessage m;
    std::string err;
    ASSERT_TRUE(stun_decode(msg.data(), msg.size(), m, err)) << err;
    EXPECT_EQ(m.find_string(kAttrNonce), "f//499k954d6OL34oL9FSTvy64sA");
    EXPECT_EQ(m.find_string(kAttrRealm), "example.org");

    // UTF-8 for U+30DE U+30C8 U+30EA U+30C3 U+30AF U+30B9 (マトリックス).
    const std::string user = "\xE3\x83\x9E\xE3\x83\x88\xE3\x83\xAA\xE3\x83\x83"
                             "\xE3\x82\xAF\xE3\x82\xB9";
    EXPECT_EQ(m.find_string(kAttrUsername), user);
    auto key = long_term_key(user, "example.org", "TheMatrIX");
    EXPECT_TRUE(stun_verify_integrity(m, key.data(), key.size()));
}

// MD5 long-term key pinned to an independently computed digest.
TEST_F(TurnCodecTest, LongTermKey_MD5Vector) {
    // python3: hashlib.md5(b"alice:example.org:wonderland").hexdigest()
    auto key = long_term_key("alice", "example.org", "wonderland");
    EXPECT_EQ(to_hex(key.data(), key.size()), "72f86f2053703faa0f521ce71cfe6f59");
}

TEST_F(TurnCodecTest, EncodeDecode_RoundTripWithIntegrityAndFingerprint) {
    StunMessage req;
    req.method = kMethodAllocate;
    req.cls = StunClass::Request;
    for (size_t i = 0; i < req.txn_id.size(); ++i)
        req.txn_id[i] = static_cast<uint8_t>(0xA0 + i);
    req.attributes.push_back({kAttrRequestedTransport, {17, 0, 0, 0}});
    const std::string sw = "ncp-g5";
    req.attributes.push_back({kAttrSoftware, {sw.begin(), sw.end()}});

    auto key = long_term_key("u", "r", "p");
    std::vector<uint8_t> bytes = stun_encode(req, key.data(), key.size(), true);
    ASSERT_FALSE(bytes.empty());
    EXPECT_EQ(bytes.size(), size_t(20 + 8 + 12 + 24 + 8));  // hdr+RT+SW+MI+FP

    StunMessage m;
    std::string err;
    ASSERT_TRUE(stun_decode(bytes.data(), bytes.size(), m, err)) << err;
    EXPECT_EQ(m.method, kMethodAllocate);
    EXPECT_EQ(m.cls, StunClass::Request);
    EXPECT_EQ(m.txn_id, req.txn_id);
    ASSERT_NE(m.find(kAttrRequestedTransport), nullptr);
    EXPECT_EQ(m.find(kAttrRequestedTransport)->value,
              (std::vector<uint8_t>{17, 0, 0, 0}));
    EXPECT_EQ(m.find_string(kAttrSoftware), sw);
    EXPECT_TRUE(stun_verify_integrity(m, key.data(), key.size()));
    EXPECT_TRUE(stun_verify_fingerprint(m));

    // Bit-flip inside an attribute value must break integrity (framing stays
    // intact: byte 24 is the REQUESTED-TRANSPORT value byte).
    bytes[24] ^= 0x01;
    StunMessage m2;
    ASSERT_TRUE(stun_decode(bytes.data(), bytes.size(), m2, err)) << err;
    EXPECT_FALSE(stun_verify_integrity(m2, key.data(), key.size()));
}

TEST_F(TurnCodecTest, Decode_RejectsMalformed) {
    std::string err;
    StunMessage m;

    // Too short.
    std::vector<uint8_t> tiny(19, 0);
    EXPECT_FALSE(stun_decode(tiny.data(), tiny.size(), m, err));

    // Bad magic cookie.
    auto msg = hexbytes(
        "00 01 00 00 de ad be ef b7 e7 a7 01 bc 34 d6 86 fa 87 df ae");
    EXPECT_FALSE(stun_decode(msg.data(), msg.size(), m, err));

    // Length field not matching datagram.
    msg = hexbytes(
        "00 01 00 08 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae");
    EXPECT_FALSE(stun_decode(msg.data(), msg.size(), m, err));

    // Length not multiple of 4.
    msg = hexbytes(
        "00 01 00 03 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae 00 00 00");
    EXPECT_FALSE(stun_decode(msg.data(), msg.size(), m, err));

    // Attribute overruns message.
    msg = hexbytes(
        "00 01 00 04 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
        "00 06 00 09");
    EXPECT_FALSE(stun_decode(msg.data(), msg.size(), m, err));

    // ChannelData is not a STUN message.
    auto cd = channel_data_encode(0x4001, reinterpret_cast<const uint8_t*>("ab"), 2);
    EXPECT_TRUE(is_channel_data(cd.data(), cd.size()));
    EXPECT_FALSE(stun_decode(cd.data(), cd.size(), m, err));
}

TEST_F(TurnCodecTest, Decode_RejectsFingerprintNotLast) {
    // Manually craft: FINGERPRINT followed by another attribute.
    auto msg = hexbytes(
        "00 01 00 10 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae"
        "80 28 00 04 00 00 00 00"
        "00 24 00 04 6e 00 01 ff");
    StunMessage m;
    std::string err;
    EXPECT_FALSE(stun_decode(msg.data(), msg.size(), m, err));
}

TEST_F(TurnCodecTest, ChannelData_FramingRoundTripAndPadding) {
    const std::string payload = "abcde";  // 5 bytes -> wire padded to 8
    auto cd = channel_data_encode(0x4001,
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    EXPECT_EQ(cd.size(), size_t(4 + 8));
    EXPECT_TRUE(is_channel_data(cd.data(), cd.size()));

    uint16_t ch = 0;
    const uint8_t* pl = nullptr;
    size_t pl_len = 0;
    ASSERT_TRUE(channel_data_decode(cd.data(), cd.size(), ch, pl, pl_len));
    EXPECT_EQ(ch, 0x4001);
    ASSERT_EQ(pl_len, payload.size());
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(pl), pl_len), payload);

    // STUN message is not ChannelData.
    StunMessage ind;
    ind.method = kMethodData;
    ind.cls = StunClass::Indication;
    auto stun = stun_encode(ind, nullptr, 0, false);
    EXPECT_FALSE(is_channel_data(stun.data(), stun.size()));
    const uint8_t* dummy = nullptr;
    size_t dummy_len = 0;
    EXPECT_FALSE(channel_data_decode(stun.data(), stun.size(), ch, dummy, dummy_len));

    // Channel number out of range rejected.
    auto bad = hexbytes("3f ff 00 01 41 00 00 00");
    EXPECT_FALSE(channel_data_decode(bad.data(), bad.size(), ch, dummy, dummy_len));

    // Truncated payload rejected.
    auto trunc = hexbytes("40 01 00 10 41 42");
    EXPECT_FALSE(channel_data_decode(trunc.data(), trunc.size(), ch, dummy, dummy_len));

    // Invalid encoder inputs fail closed instead of truncating lengths or
    // dereferencing a null payload.
    EXPECT_TRUE(channel_data_encode(0x4001, nullptr, 1).empty());
    EXPECT_TRUE(channel_data_encode(0x3FFF,
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size()).empty());
    std::vector<uint8_t> oversized(0x10000, 0x41);
    EXPECT_TRUE(channel_data_encode(0x4001, oversized.data(), oversized.size()).empty());
}

TEST_F(TurnCodecTest, XorAddress_RoundTrip) {
    uint32_t addr_be = 0;
    ASSERT_EQ(inet_pton(AF_INET, "203.0.113.9", &addr_be), 1);
    auto v = encode_xor_address_ipv4(addr_be, 53000, {});
    StunAttribute a{kAttrXorPeerAddress, v};
    uint32_t out_addr = 0;
    uint16_t out_port = 0;
    ASSERT_TRUE(decode_xor_address_ipv4(a, {}, out_addr, out_port));
    EXPECT_EQ(out_addr, addr_be);
    EXPECT_EQ(out_port, 53000);
}

// ══════════════════════════════════════════════════════════════════════════════
// In-process fake TURN server (loopback UDP) for client FSM tests.
//
// Uses the same codec under test for parsing/encoding; codec correctness is
// pinned independently by the RFC 5769 vectors above.
// ══════════════════════════════════════════════════════════════════════════════

class FakeTurnServer {
public:
    FakeTurnServer(std::string user, std::string pass,
                   std::string realm = "g5-test-realm",
                   std::string nonce = "g5-test-nonce-0001")
        : user_(std::move(user)), pass_(std::move(pass)),
          realm_(std::move(realm)), nonce_(std::move(nonce)) {
        key_ = long_term_key(user_, realm_, pass_);
    }

    ~FakeTurnServer() { stop(); }

    bool start() {
        sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock_ < 0) return false;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(sock_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0)
            return false;
        socklen_t alen = sizeof(a);
        if (getsockname(sock_, reinterpret_cast<sockaddr*>(&a), &alen) != 0)
            return false;
        port_ = ntohs(a.sin_port);
        running_ = true;
        th_ = std::thread([this] { run(); });
        return true;
    }

    void stop() {
        running_ = false;
        // The receive loop uses a bounded select(), so join first and close
        // only after the server thread can no longer use the descriptor.
        // Closing concurrently with sendto()/recvfrom() is a test-harness race.
        if (th_.joinable()) th_.join();
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
    }

    uint16_t port() const { return port_; }

    // ── Scripting knobs ──────────────────────────────────────────────────
    std::atomic<int>  drop_responses{0};     // drop the next N responses
    std::atomic<bool> drop_all{false};       // never respond (timeout test)
    std::atomic<bool> reject_integrity{false}; // always answer 401
    std::atomic<bool> inject_unknown_txn{false}; // send response w/ random txn id
    std::atomic<bool> replay_last_response{false}; // duplicate every response
    std::atomic<bool> echo_wrong_channel_too{false}; // extra ChannelData 0x4FFE
    std::atomic<int> data_indication_burst{1}; // Data copies per Send indication

    // ── Observation ──────────────────────────────────────────────────────
    std::atomic<int> allocate_requests{0};
    std::atomic<int> authenticated_requests{0};
    std::atomic<int> integrity_failures{0};
    std::atomic<int> send_indications{0};
    std::atomic<int> refresh_requests{0};

private:
    void send_bytes(const std::vector<uint8_t>& b, const sockaddr_in& to) {
        ::sendto(sock_, reinterpret_cast<const char*>(b.data()),
                 static_cast<int>(b.size()), 0,
                 reinterpret_cast<const sockaddr*>(&to), sizeof(to));
    }

    bool check_auth(const StunMessage& req) {
        if (reject_integrity) return false;
        if (req.find_string(kAttrUsername) != user_) return false;
        if (req.find_string(kAttrNonce) != nonce_) return false;
        if (req.find_string(kAttrRealm) != realm_) return false;
        if (!req.has_message_integrity) return false;
        return stun_verify_integrity(req, key_.data(), key_.size());
    }

    void respond(StunMessage resp, bool with_mi, const sockaddr_in& to) {
        if (drop_all) return;
        if (drop_responses.load() > 0) { --drop_responses; return; }
        if (inject_unknown_txn && resp.cls != StunClass::Indication) {
            StunMessage bogus = resp;
            bogus.cls = StunClass::ErrorResponse;
            bogus.attributes = {{kAttrErrorCode, {0, 0, 6, 0}}};  // 600
            for (auto& b : bogus.txn_id) b = static_cast<uint8_t>(rand());
            send_bytes(stun_encode(bogus, nullptr, 0, true), to);
        }
        auto bytes = stun_encode(resp, with_mi ? key_.data() : nullptr,
                                 with_mi ? key_.size() : 0, true);
        send_bytes(bytes, to);
        if (replay_last_response) send_bytes(bytes, to);  // duplicate
    }

    static StunMessage make_error(const StunMessage& req, uint32_t code,
                                  const std::string& reason) {
        StunMessage e;
        e.method = req.method;
        e.cls = StunClass::ErrorResponse;
        e.txn_id = req.txn_id;
        std::vector<uint8_t> v = {0, 0,
            static_cast<uint8_t>(code / 100), static_cast<uint8_t>(code % 100)};
        v.insert(v.end(), reason.begin(), reason.end());
        e.attributes.push_back({kAttrErrorCode, std::move(v)});
        return e;
    }

    void send_401(const StunMessage& req, const sockaddr_in& to) {
        StunMessage e = make_error(req, 401, "Unauthorized");
        e.attributes.push_back({kAttrRealm, {realm_.begin(), realm_.end()}});
        e.attributes.push_back({kAttrNonce, {nonce_.begin(), nonce_.end()}});
        respond(std::move(e), /*with_mi=*/false, to);
    }

    void run() {
        uint8_t buf[2048];
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock_, &rfds);
            timeval tv{0, 20000};  // bounded stop latency, descriptor stays live
            int ready = ::select(sock_ + 1, &rfds, nullptr, nullptr, &tv);
            if (ready <= 0) continue;
            sockaddr_in from{};
            socklen_t flen = sizeof(from);
            int n = ::recvfrom(sock_, reinterpret_cast<char*>(buf),
                               sizeof(buf), 0,
                               reinterpret_cast<sockaddr*>(&from), &flen);
            if (n <= 0) break;

            if (is_channel_data(buf, static_cast<size_t>(n))) {
                uint16_t ch = 0;
                const uint8_t* pl = nullptr;
                size_t pl_len = 0;
                if (channel_data_decode(buf, static_cast<size_t>(n),
                                        ch, pl, pl_len)) {
                    // Echo back on the bound channel (and optionally on a
                    // wrong channel to exercise client-side filtering).
                    send_bytes(channel_data_encode(ch, pl, pl_len), from);
                    if (echo_wrong_channel_too)
                        send_bytes(channel_data_encode(0x4FFE, pl, pl_len), from);
                }
                continue;
            }

            StunMessage req;
            std::string err;
            if (!stun_decode(buf, static_cast<size_t>(n), req, err)) continue;

            if (req.cls == StunClass::Indication) {
                if (req.method == kMethodSend) {
                    ++send_indications;
                    const StunAttribute* peer = req.find(kAttrXorPeerAddress);
                    const StunAttribute* data = req.find(kAttrData);
                    if (peer && data) {
                        StunMessage ind;
                        ind.method = kMethodData;
                        ind.cls = StunClass::Indication;
                        for (size_t i = 0; i < ind.txn_id.size(); ++i)
                            ind.txn_id[i] = static_cast<uint8_t>(0x40 + i);
                        ind.attributes.push_back(*peer);  // echo peer addr back
                        ind.attributes.push_back(*data);
                        const auto bytes = stun_encode(ind, nullptr, 0, true);
                        for (int i = 0; i < data_indication_burst.load(); ++i)
                            send_bytes(bytes, from);
                    }
                }
                continue;
            }

            if (req.method == kMethodAllocate) {
                ++allocate_requests;
                if (req.find(kAttrUsername) == nullptr) {
                    send_401(req, from);
                    continue;
                }
                if (!check_auth(req)) {
                    ++integrity_failures;
                    send_401(req, from);
                    continue;
                }
                ++authenticated_requests;
                StunMessage ok;
                ok.method = req.method;
                ok.cls = StunClass::SuccessResponse;
                ok.txn_id = req.txn_id;
                uint32_t loop_be = htonl(INADDR_LOOPBACK);
                ok.attributes.push_back({kAttrXorRelayedAddress,
                    encode_xor_address_ipv4(loop_be, 46000, req.txn_id)});
                ok.attributes.push_back({kAttrXorMappedAddress,
                    encode_xor_address_ipv4(from.sin_addr.s_addr,
                                            ntohs(from.sin_port), req.txn_id)});
                ok.attributes.push_back({kAttrLifetime,
                    {0, 0, 0x02, 0x58}});  // 600 s
                respond(std::move(ok), /*with_mi=*/true, from);
                continue;
            }

            // All other requests require valid auth.
            if (!check_auth(req)) {
                ++integrity_failures;
                send_401(req, from);
                continue;
            }
            ++authenticated_requests;

            if (req.method == kMethodRefresh) ++refresh_requests;

            StunMessage ok;
            ok.method = req.method;
            ok.cls = StunClass::SuccessResponse;
            ok.txn_id = req.txn_id;
            if (req.method == kMethodRefresh) {
                const StunAttribute* lt = req.find(kAttrLifetime);
                uint32_t granted = lt && lt->value.size() == 4
                    ? (static_cast<uint32_t>(lt->value[0]) << 24 |
                       static_cast<uint32_t>(lt->value[1]) << 16 |
                       static_cast<uint32_t>(lt->value[2]) << 8  |
                       static_cast<uint32_t>(lt->value[3]))
                    : 600;
                ok.attributes.push_back({kAttrLifetime,
                    {static_cast<uint8_t>(granted >> 24),
                     static_cast<uint8_t>(granted >> 16),
                     static_cast<uint8_t>(granted >> 8),
                     static_cast<uint8_t>(granted)}});
            }
            respond(std::move(ok), /*with_mi=*/true, from);
        }
    }

    std::string user_, pass_, realm_, nonce_;
    std::array<uint8_t, 16> key_{};
    int sock_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread th_;
};

// ── Fixture ──────────────────────────────────────────────────────────────────

class TurnClientFsmTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_TRUE(server_.start());
        cfg_.server_address = "127.0.0.1";
        cfg_.server_port = server_.port();
        cfg_.username = "g5user";
        cfg_.password = "g5pass-independent";  // independent creds only
        cfg_.rto_ms = 40;          // fast retransmission for tests
        cfg_.max_retransmits = 5;
        cfg_.requested_lifetime = 600;
    }

    FakeTurnServer server_{"g5user", "g5pass-independent"};
    TurnConfig cfg_;
};

TEST_F(TurnClientFsmTest, FullFlow_AllocatePermissionBindChannelDataRefresh) {
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    ASSERT_TRUE(c.allocate(&err)) << err;
    EXPECT_EQ(c.state(), TurnState::Allocated);
    // First Allocate is challenged with 401, second is authenticated.
    EXPECT_GE(server_.allocate_requests.load(), 2);
    EXPECT_GE(server_.authenticated_requests.load(), 1);
    EXPECT_EQ(server_.integrity_failures.load(), 0);
    EXPECT_TRUE(c.has_credentials_context());
    EXPECT_EQ(c.realm(), "g5-test-realm");
    EXPECT_EQ(c.nonce(), "g5-test-nonce-0001");

    in_addr relayed{c.relayed_addr_be()};
    char buf[INET_ADDRSTRLEN];
    ASSERT_NE(inet_ntop(AF_INET, &relayed, buf, sizeof(buf)), nullptr);
    EXPECT_EQ(std::string(buf), "127.0.0.1");
    EXPECT_EQ(c.relayed_port(), 46000);
    EXPECT_EQ(c.granted_lifetime(), 600u);
    EXPECT_GT(c.lifetime_remaining(), 0u);
    EXPECT_LE(c.lifetime_remaining(), 600u);

    ASSERT_TRUE(c.create_permission("127.0.0.1", 47000, &err)) << err;
    ASSERT_TRUE(c.channel_bind("127.0.0.1", 47000, 0x4010, &err)) << err;
    EXPECT_EQ(c.state(), TurnState::Bound);

    // Established application flow is ChannelData-only. Send/Data is not an
    // alternate post-bind data path, and invalid payload pointers are rejected.
    const std::string forbidden = "must-not-use-send-indication";
    EXPECT_FALSE(c.send_indication("127.0.0.1", 47000,
        reinterpret_cast<const uint8_t*>(forbidden.data()), forbidden.size(), &err));
    EXPECT_NE(err.find("bootstrap-only"), std::string::npos);
    EXPECT_EQ(server_.send_indications.load(), 0);
    EXPECT_FALSE(c.send_channel_data(nullptr, 1, &err));
    EXPECT_NE(err.find("null ChannelData"), std::string::npos);

    // ChannelData application exchange (echo).
    const std::string ping = "g5-channeldata-ping";
    ASSERT_TRUE(c.send_channel_data(
        reinterpret_cast<const uint8_t*>(ping.data()), ping.size(), &err)) << err;
    std::vector<TurnReceivedData> rx;
    ASSERT_TRUE(c.poll(2000, &rx, &err)) << err;
    ASSERT_EQ(rx.size(), 1u);
    EXPECT_TRUE(rx[0].via_channel);
    EXPECT_EQ(rx[0].channel, 0x4010);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(rx[0].payload.data()),
                          rx[0].payload.size()), ping);

    // Refresh extends the lifetime; refresh(0) deletes the allocation.
    ASSERT_TRUE(c.refresh(300, &err)) << err;
    EXPECT_EQ(c.granted_lifetime(), 300u);
    ASSERT_TRUE(c.refresh(0, &err)) << err;
    EXPECT_EQ(c.state(), TurnState::Closed);
    EXPECT_EQ(c.lifetime_remaining(), 0u);
    EXPECT_GE(server_.refresh_requests.load(), 2);

    c.close();
}

TEST_F(TurnClientFsmTest, SendIndication_DataIndication_Bootstrap) {
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    ASSERT_TRUE(c.allocate(&err)) << err;
    ASSERT_TRUE(c.create_permission("127.0.0.1", 47001, &err)) << err;

    EXPECT_FALSE(c.send_indication("127.0.0.1", 47001, nullptr, 1, &err));
    EXPECT_NE(err.find("null Send indication"), std::string::npos);
    EXPECT_EQ(server_.send_indications.load(), 0);

    const std::string boot = "g5-bootstrap-via-send-indication";
    ASSERT_TRUE(c.send_indication("127.0.0.1", 47001,
        reinterpret_cast<const uint8_t*>(boot.data()), boot.size(), &err)) << err;

    std::vector<TurnReceivedData> rx;
    ASSERT_TRUE(c.poll(2000, &rx, &err)) << err;
    ASSERT_EQ(rx.size(), 1u);
    EXPECT_FALSE(rx[0].via_channel);
    EXPECT_EQ(rx[0].peer_port, 47001);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(rx[0].payload.data()),
                          rx[0].payload.size()), boot);
    EXPECT_EQ(server_.send_indications.load(), 1);
    c.close();
}

TEST_F(TurnClientFsmTest, PendingReceiveQueue_IsBoundedAndDropsCounted) {
    cfg_.max_pending_rx = 2;
    server_.data_indication_burst = 4;
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    ASSERT_TRUE(c.allocate(&err)) << err;
    ASSERT_TRUE(c.create_permission("127.0.0.1", 47001, &err)) << err;

    const std::string boot = "bounded-bootstrap-queue";
    ASSERT_TRUE(c.send_indication("127.0.0.1", 47001,
        reinterpret_cast<const uint8_t*>(boot.data()), boot.size(), &err)) << err;
    // A following transaction receives the complete server burst before poll()
    // has a chance to drain it, exercising the actual transaction-layer queue.
    ASSERT_TRUE(c.refresh(600, &err)) << err;

    std::vector<TurnReceivedData> rx;
    ASSERT_TRUE(c.poll(0, &rx, &err)) << err;
    EXPECT_EQ(rx.size(), 2u);
    EXPECT_EQ(c.stats().data_indication_rx, 4u);
    EXPECT_EQ(c.stats().pending_rx_dropped_queue_full, 2u);
    c.close();
}

TEST_F(TurnClientFsmTest, Allocate_WrongPassword_Fails) {
    cfg_.password = "definitely-wrong";
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    EXPECT_FALSE(c.allocate(&err));
    EXPECT_EQ(c.state(), TurnState::Failed);
    EXPECT_NE(err.find("401"), std::string::npos);
    // Server kept challenging because MESSAGE-INTEGRITY never validated.
    EXPECT_GE(server_.integrity_failures.load(), 1);
    c.close();
}

TEST_F(TurnClientFsmTest, Allocate_WithoutCredentials_FailsImmediately) {
    cfg_.password.clear();
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    EXPECT_FALSE(c.allocate(&err));
    EXPECT_EQ(server_.allocate_requests.load(), 0);  // nothing was sent
    c.close();
}

TEST_F(TurnClientFsmTest, Retransmission_OnLostResponses) {
    server_.drop_responses = 2;  // server drops its first two responses
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    ASSERT_TRUE(c.allocate(&err)) << err;   // succeeds after retransmits
    EXPECT_GE(c.stats().retransmits, 2u);
    EXPECT_EQ(c.state(), TurnState::Allocated);
    c.close();
}

TEST_F(TurnClientFsmTest, TransactionTimeout_IsBounded) {
    server_.drop_all = true;
    cfg_.rto_ms = 30;
    cfg_.max_retransmits = 4;
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(c.allocate(&err));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    // Bound: sends at t=0,30,90,210 (4 sends), final wait 1.6*RTO=48 -> < 1s.
    EXPECT_LT(elapsed, 1000);
    EXPECT_EQ(c.stats().timeouts, 1u);
    EXPECT_NE(err.find("timed out"), std::string::npos);
    c.close();
}

TEST_F(TurnClientFsmTest, UnknownAndReplayedTransactions_Dropped) {
    server_.inject_unknown_txn = true;
    server_.replay_last_response = true;
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    ASSERT_TRUE(c.allocate(&err)) << err;
    // Bogus response with random transaction id was dropped as unknown.
    EXPECT_GE(c.stats().unknown_txn_dropped, 1u);
    // Duplicated 401 / success responses were dropped as replays.
    EXPECT_GE(c.stats().replayed_txn_dropped, 1u);
    c.close();
}

TEST_F(TurnClientFsmTest, ChannelData_ForUnknownChannel_IsDropped) {
    server_.echo_wrong_channel_too = true;
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    ASSERT_TRUE(c.allocate(&err)) << err;
    ASSERT_TRUE(c.create_permission("127.0.0.1", 47002, &err)) << err;
    ASSERT_TRUE(c.channel_bind("127.0.0.1", 47002, 0x4020, &err)) << err;

    const std::string ping = "x";
    ASSERT_TRUE(c.send_channel_data(
        reinterpret_cast<const uint8_t*>(ping.data()), ping.size(), &err)) << err;
    std::vector<TurnReceivedData> rx;
    ASSERT_TRUE(c.poll(1500, &rx, &err)) << err;
    // Only the bound channel's echo is surfaced; 0x4FFE copy is dropped.
    ASSERT_EQ(rx.size(), 1u);
    EXPECT_EQ(rx[0].channel, 0x4020);
    EXPECT_EQ(c.stats().channel_data_rx, 1u);
    c.close();
}

TEST_F(TurnClientFsmTest, OperationsWithoutAllocation_Rejected) {
    TurnClient c(cfg_);
    std::string err;
    ASSERT_TRUE(c.open(&err)) << err;
    EXPECT_FALSE(c.create_permission("127.0.0.1", 47000, &err));
    EXPECT_FALSE(c.channel_bind("127.0.0.1", 47000, 0x4010, &err));
    EXPECT_FALSE(c.send_channel_data(reinterpret_cast<const uint8_t*>("x"), 1, &err));
    EXPECT_FALSE(c.refresh(600, &err));
    c.close();
}
