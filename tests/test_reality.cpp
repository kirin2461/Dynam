// Tests for ncp_reality — XTLS-Reality-style fallback (M1)
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#include <sys/socket.h>
#include <unistd.h>

#include "ncp_reality.hpp"

namespace {

constexpr const char* kGateway = "cdn.example.com";

struct ClientKeys {
    std::array<uint8_t, 32> pk{};
    std::array<uint8_t, 64> sk{};
};

ClientKeys make_client_keys() {
    ClientKeys k;
    crypto_sign_keypair(k.pk.data(), k.sk.data());
    return k;
}

// Build a minimal but well-formed TLS ClientHello carrying `sni`.
std::vector<uint8_t> make_client_hello(const std::string& sni) {
    std::vector<uint8_t> body;
    // client_version + random
    body.insert(body.end(), {0x03, 0x03});
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(i));
    // session_id (empty)
    body.push_back(0x00);
    // cipher_suites: TLS_AES_128_GCM_SHA256
    body.insert(body.end(), {0x00, 0x02, 0x13, 0x01});
    // compression: null
    body.insert(body.end(), {0x01, 0x00});

    // SNI extension
    std::vector<uint8_t> sni_ext;
    const uint16_t name_len = static_cast<uint16_t>(sni.size());
    const uint16_t list_len = static_cast<uint16_t>(3 + name_len);
    sni_ext.push_back(static_cast<uint8_t>(list_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(list_len & 0xFF));
    sni_ext.push_back(0x00);  // host_name
    sni_ext.push_back(static_cast<uint8_t>(name_len >> 8));
    sni_ext.push_back(static_cast<uint8_t>(name_len & 0xFF));
    sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());

    std::vector<uint8_t> ext;
    ext.insert(ext.end(), {0x00, 0x00});  // server_name extension type
    ext.push_back(static_cast<uint8_t>(sni_ext.size() >> 8));
    ext.push_back(static_cast<uint8_t>(sni_ext.size() & 0xFF));
    ext.insert(ext.end(), sni_ext.begin(), sni_ext.end());

    body.push_back(static_cast<uint8_t>(ext.size() >> 8));
    body.push_back(static_cast<uint8_t>(ext.size() & 0xFF));
    body.insert(body.end(), ext.begin(), ext.end());

    // Handshake header
    std::vector<uint8_t> hs;
    hs.push_back(0x01);  // ClientHello
    hs.push_back(0x00);
    hs.push_back(static_cast<uint8_t>(body.size() >> 8));
    hs.push_back(static_cast<uint8_t>(body.size() & 0xFF));
    hs.insert(hs.end(), body.begin(), body.end());

    // Record header
    std::vector<uint8_t> rec;
    rec.insert(rec.end(), {0x16, 0x03, 0x01});
    rec.push_back(static_cast<uint8_t>(hs.size() >> 8));
    rec.push_back(static_cast<uint8_t>(hs.size() & 0xFF));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

// Read exactly n bytes (looping over short reads); false on EOF/error.
bool read_full(int fd, char* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        const ssize_t r = ::read(fd, buf + off, n - off);
        if (r <= 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

class RealityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { ASSERT_EQ(sodium_init(), 0); }

    ClientKeys client = make_client_keys();
    ncp::RealityAuth auth;
    ncp::RealityServer server{ncp::RealityConfig{}};

    void SetUp() override {
        auth.add_key("client-1", client.pk);
        auth.provision_secret("client-1", client.sk);

        ncp::RealityConfig cfg;
        cfg.auth = auth;
        server = ncp::RealityServer(std::move(cfg));
    }
};

TEST_F(RealityTest, TokenRoundtripAuthorized) {
    const uint64_t now = 1700000030;
    const std::string sni = ncp::RealityTokenBuilder::make_sni(
        "client-1", client.sk, kGateway, now);
    const auto hello = make_client_hello(sni);
    EXPECT_EQ(server.classify(hello.data(), hello.size(), now),
              ncp::RealityDecision::AUTHORIZED);
}

TEST_F(RealityTest, PreviousWindowStillAuthorized) {
    // now is mid-window; a token from the previous window must be accepted.
    const uint64_t now = (1700000030ull / 60) * 60 + 30;
    const std::string sni = ncp::RealityTokenBuilder::make_sni(
        "client-1", client.sk, kGateway, now - 60);  // previous window
    const auto hello = make_client_hello(sni);
    EXPECT_EQ(server.classify(hello.data(), hello.size(), now),
              ncp::RealityDecision::AUTHORIZED);
}

TEST_F(RealityTest, WrongKeyFallsBack) {
    const ClientKeys other = make_client_keys();  // not provisioned server-side
    const uint64_t now = 1700000030;
    const std::string sni = ncp::RealityTokenBuilder::make_sni(
        "client-2", other.sk, kGateway, now);
    const auto hello = make_client_hello(sni);
    EXPECT_EQ(server.classify(hello.data(), hello.size(), now),
              ncp::RealityDecision::FALLBACK);
}

TEST_F(RealityTest, StaleWindowFallsBack) {
    const uint64_t now = 1700000030;
    const std::string sni = ncp::RealityTokenBuilder::make_sni(
        "client-1", client.sk, kGateway, now - 180);  // 3 windows old
    const auto hello = make_client_hello(sni);
    EXPECT_EQ(server.classify(hello.data(), hello.size(), now),
              ncp::RealityDecision::FALLBACK);
}

TEST_F(RealityTest, GarbageSniFallsBack) {
    const uint64_t now = 1700000030;
    for (const char* bad : {"www.microsoft.com",
                            "notabase32token!.gw.cdn.example.com",
                            "short.gw.cdn.example.com",
                            "zzzzzzzzzzzzzzzzzzzzzzzzzz.gw.other-domain.net"}) {
        const auto hello = make_client_hello(bad);
        EXPECT_EQ(server.classify(hello.data(), hello.size(), now),
                  ncp::RealityDecision::FALLBACK)
            << "sni=" << bad;
    }
}

TEST_F(RealityTest, NonTlsBytesAreNotTls) {
    const char* junk = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    EXPECT_EQ(server.classify(reinterpret_cast<const uint8_t*>(junk),
                              std::strlen(junk), 1700000030),
              ncp::RealityDecision::NOT_TLS);

    const uint8_t empty[] = {0x16};
    EXPECT_EQ(server.classify(empty, 0, 1700000030), ncp::RealityDecision::NOT_TLS);
    EXPECT_EQ(server.classify(empty, sizeof(empty), 1700000030),
              ncp::RealityDecision::NOT_TLS);
    EXPECT_EQ(server.classify(nullptr, 100, 1700000030),
              ncp::RealityDecision::NOT_TLS);
}

TEST_F(RealityTest, ExtractSniRoundtrip) {
    const std::string sni = "abcdef.gw.www.microsoft.com";
    const auto hello = make_client_hello(sni);
    std::string out;
    ASSERT_TRUE(ncp::RealityServer::extract_sni(hello.data(), hello.size(), out));
    EXPECT_EQ(out, sni);
}

TEST(SpliceTest, PassesBytesBothWaysAndTerminatesOnEof) {
    int a[2] = {-1, -1};
    int b[2] = {-1, -1};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, a), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, b), 0);

    std::thread worker([fds_a = a[0], fds_b = b[0]] {
        ncp::RealityServer::splice(fds_a, fds_b);
        ::close(fds_a);
        ::close(fds_b);
    });

    // a[1] = "client" endpoint, b[1] = "target" endpoint.
    const char* fwd = "client-to-target payload";
    ASSERT_EQ(::write(a[1], fwd, std::strlen(fwd)),
              static_cast<ssize_t>(std::strlen(fwd)));
    char buf[128];
    ASSERT_TRUE(read_full(b[1], buf, std::strlen(fwd)));
    EXPECT_EQ(std::string(buf, std::strlen(fwd)), fwd);

    const char* bwd = "target-to-client reply";
    ASSERT_EQ(::write(b[1], bwd, std::strlen(bwd)),
              static_cast<ssize_t>(std::strlen(bwd)));
    ASSERT_TRUE(read_full(a[1], buf, std::strlen(bwd)));
    EXPECT_EQ(std::string(buf, std::strlen(bwd)), bwd);

    // Half-close the client side: target must observe EOF after splice
    // propagates shutdown(SHUT_WR).
    ASSERT_EQ(::shutdown(a[1], SHUT_WR), 0);
    EXPECT_EQ(::read(b[1], buf, sizeof(buf)), 0);

    // The reverse direction must still work after the half-close.
    ASSERT_EQ(::write(b[1], "x", 1), 1);
    ASSERT_EQ(::read(a[1], buf, 1), 1);
    EXPECT_EQ(buf[0], 'x');

    // Close the target side: splice must terminate.
    ::close(b[1]);
    worker.join();
    ::close(a[1]);
}

} // anonymous namespace
