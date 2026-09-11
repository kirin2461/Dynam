// Tests for ncp_reality — XTLS-Reality-style fallback (M1)
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#include "ncp_winsock_init.hpp"  // socket_t + winsock_init + winsock2 on _WIN32

#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "ncp_reality.hpp"

namespace {

constexpr const char* kGateway = "cdn.example.com";

// ---- portable socket helpers (Winsock has no socketpair/read/write on fds) ----

#ifdef _WIN32

// Winsock lacks socketpair(2): emulate a connected pair via a throwaway
// loopback TCP listener (the classic BSD-compatible trick).
bool test_socketpair(ncp::socket_t out[2]) {
    out[0] = out[1] = ncp::kInvalidSocket;
    int addr_len = 0;
    ncp::socket_t listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == ncp::kInvalidSocket) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // ephemeral
    bool ok = ::bind(listener, reinterpret_cast<sockaddr*>(&addr),
                     sizeof(addr)) != SOCKET_ERROR &&
              ::listen(listener, 1) != SOCKET_ERROR;
    addr_len = sizeof(addr);
    if (ok && ::getsockname(listener, reinterpret_cast<sockaddr*>(&addr),
                            &addr_len) == SOCKET_ERROR) {
        ok = false;
    }
    if (ok) {
        out[0] = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ok = out[0] != ncp::kInvalidSocket;
    }
    if (ok && ::connect(out[0], reinterpret_cast<sockaddr*>(&addr),
                        addr_len) == SOCKET_ERROR) {
        ok = false;
    }
    if (ok) {
        out[1] = ::accept(listener, nullptr, nullptr);
        ok = out[1] != ncp::kInvalidSocket;
    }
    ::closesocket(listener);
    if (!ok) {
        if (out[0] != ncp::kInvalidSocket) ::closesocket(out[0]);
        if (out[1] != ncp::kInvalidSocket) ::closesocket(out[1]);
        out[0] = out[1] = ncp::kInvalidSocket;
    }
    return ok;
}

int test_read(ncp::socket_t fd, char* buf, size_t n) {
    return ::recv(fd, buf, static_cast<int>(n), 0);
}
int test_write(ncp::socket_t fd, const char* buf, size_t n) {
    return ::send(fd, buf, static_cast<int>(n), 0);
}
void test_close(ncp::socket_t fd) { ::closesocket(fd); }
int test_shutdown_write(ncp::socket_t fd) { return ::shutdown(fd, SD_SEND); }

#else  // POSIX

bool test_socketpair(ncp::socket_t out[2]) {
    return ::socketpair(AF_UNIX, SOCK_STREAM, 0, out) == 0;
}
ssize_t test_read(ncp::socket_t fd, char* buf, size_t n) {
    return ::read(fd, buf, n);
}
ssize_t test_write(ncp::socket_t fd, const char* buf, size_t n) {
    return ::write(fd, buf, n);
}
void test_close(ncp::socket_t fd) { ::close(fd); }
int test_shutdown_write(ncp::socket_t fd) { return ::shutdown(fd, SHUT_WR); }

#endif

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
bool read_full(ncp::socket_t fd, char* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        const auto r = test_read(fd, buf + off, n - off);
        if (r <= 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

class RealityTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { ASSERT_GE(sodium_init(), 0); }

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
    ASSERT_TRUE(ncp::winsock_init());
    ncp::socket_t a[2] = {ncp::kInvalidSocket, ncp::kInvalidSocket};
    ncp::socket_t b[2] = {ncp::kInvalidSocket, ncp::kInvalidSocket};
    ASSERT_TRUE(test_socketpair(a));
    ASSERT_TRUE(test_socketpair(b));

    std::thread worker([fds_a = a[0], fds_b = b[0]] {
        ncp::RealityServer::splice(fds_a, fds_b);
        test_close(fds_a);
        test_close(fds_b);
    });

    // a[1] = "client" endpoint, b[1] = "target" endpoint.
    const char* fwd = "client-to-target payload";
    ASSERT_EQ(test_write(a[1], fwd, std::strlen(fwd)),
              static_cast<long>(std::strlen(fwd)));
    char buf[128];
    ASSERT_TRUE(read_full(b[1], buf, std::strlen(fwd)));
    EXPECT_EQ(std::string(buf, std::strlen(fwd)), fwd);

    const char* bwd = "target-to-client reply";
    ASSERT_EQ(test_write(b[1], bwd, std::strlen(bwd)),
              static_cast<long>(std::strlen(bwd)));
    ASSERT_TRUE(read_full(a[1], buf, std::strlen(bwd)));
    EXPECT_EQ(std::string(buf, std::strlen(bwd)), bwd);

    // Half-close the client side: target must observe EOF after splice
    // propagates shutdown of the write direction.
    ASSERT_EQ(test_shutdown_write(a[1]), 0);
    EXPECT_EQ(test_read(b[1], buf, sizeof(buf)), 0);

    // The reverse direction must still work after the half-close.
    ASSERT_EQ(test_write(b[1], "x", 1), 1);
    ASSERT_EQ(test_read(a[1], buf, 1), 1);
    EXPECT_EQ(buf[0], 'x');

    // Close the target side: splice must terminate.
    test_close(b[1]);
    worker.join();
    test_close(a[1]);
}

} // anonymous namespace
