// ═══════════════════════════════════════════════════════════════════════════
// G4 REAL QUIC transport tests (ncp_real_quic.hpp).
//
// These tests exercise REAL TLS 1.3 QUIC handshakes between two wrapper
// endpoints over UDP loopback (127.0.0.1), multi-payload bidirectional echo,
// fixed-path (no PortHop) invariants, default certificate verification, and
// rejection of plaintext garbage (it must never surface as application data).
//
// A self-signed test certificate is generated at runtime with the openssl
// CLI into a per-process temp directory; no key material is committed.
// ═══════════════════════════════════════════════════════════════════════════

#include <gtest/gtest.h>

#include "ncp_real_quic.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// ---------------------------------------------------------------------------
// Runtime self-signed certificate generation (test-only key material).
// ---------------------------------------------------------------------------
struct TestCerts {
    std::string dir;
    std::string cert;
    std::string key;
    bool ok = false;
};

TestCerts generate_test_certs() {
    TestCerts tc;
    char tmpl[] = "/tmp/ncp_real_quic_test_XXXXXX";
    if (!mkdtemp(tmpl)) return tc;
    tc.dir = tmpl;
    tc.cert = tc.dir + "/cert.pem";
    tc.key = tc.dir + "/key.pem";
    // CA:TRUE so the same PEM can act as the client's pinned CA bundle;
    // SAN covers the "localhost" SNI used by the verification tests.
    std::string cmd =
        "openssl req -x509 -newkey rsa:2048 -nodes"
        " -keyout '" + tc.key + "' -out '" + tc.cert + "' -days 2"
        " -subj '/CN=localhost'"
        " -addext 'subjectAltName=DNS:localhost,DNS:lab.dynam.test,IP:127.0.0.1'"
        " -addext 'basicConstraints=critical,CA:TRUE'"
        " >/dev/null 2>&1";
    tc.ok = (std::system(cmd.c_str()) == 0) &&
            access(tc.cert.c_str(), R_OK) == 0 &&
            access(tc.key.c_str(), R_OK) == 0;
    return tc;
}

std::vector<uint8_t> patterned_bytes(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i)
        v[i] = static_cast<uint8_t>(seed + (i * 131u) % 251u);
    return v;
}

// Sends count garbage UDP datagrams (plaintext, not QUIC) to ip:port.
void send_udp_garbage(const char* ip, uint16_t port, int count) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);

    std::mt19937 rng(0xC0FFEE);
    for (int i = 0; i < count; ++i) {
        std::vector<uint8_t> junk(64 + rng() % 1200);
        for (auto& b : junk) b = static_cast<uint8_t>(rng());
        // Some clearly-plaintext payload too (HTTP-looking).
        if (i == 0) {
            const char* text = "GET / HTTP/1.1\r\nHost: plaintext-garbage\r\n\r\n";
            std::memcpy(junk.data(), text, std::strlen(text));
        }
        sendto(fd, junk.data(), junk.size(), 0,
               reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    }
    close(fd);
}

class RealQuicTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { certs_ = generate_test_certs(); }
    static TestCerts certs_;

    ncp::RealQuicEndpoint::Config server_cfg(uint16_t port = 0) {
        ncp::RealQuicEndpoint::Config c;
        c.role = ncp::RealQuicEndpoint::Role::Server;
        c.local_address = "127.0.0.1";
        c.local_port = port;
        c.certificate_file = certs_.cert;
        c.private_key_file = certs_.key;
        c.alpn = "ncp-echo";
        return c;
    }

    ncp::RealQuicEndpoint::Config client_cfg(uint16_t port) {
        ncp::RealQuicEndpoint::Config c;
        c.role = ncp::RealQuicEndpoint::Role::Client;
        c.local_address = "127.0.0.1";
        c.remote_address = "127.0.0.1";
        c.remote_port = port;
        c.server_name = "localhost";
        c.alpn = "ncp-echo";
        return c;
    }
};
TestCerts RealQuicTest::certs_;

// Echo loop helper: drains server messages and responds on the same stream.
static void echo_loop(ncp::RealQuicEndpoint& server,
                      std::atomic<bool>& stop, int expected) {
    int echoed = 0;
    while (!stop.load() && echoed < expected) {
        ncp::RealQuicEndpoint::Message m;
        if (!server.recv_message(m, 200)) continue;
        ASSERT_TRUE(server.respond(m.connection_id, m.stream_id, m.payload));
        ++echoed;
    }
}

// ---------------------------------------------------------------------------
// 1. Real TLS 1.3 handshake + multi-payload bidirectional stream echo over
//    UDP loopback between two wrapper endpoints.
// ---------------------------------------------------------------------------
TEST_F(RealQuicTest, HandshakeAndMultiPayloadEcho) {
    ASSERT_TRUE(certs_.ok) << "openssl cert generation failed";

    ncp::RealQuicEndpoint server(server_cfg());
    ASSERT_TRUE(server.start()) << server.last_error();
    const uint16_t port = server.bound_local_port();
    ASSERT_NE(port, 0);

    // Self-signed test cert: use the explicit TEST-ONLY insecure mode here.
    auto ccfg = client_cfg(port);
    ccfg.insecure_skip_verify = true;
    ncp::RealQuicEndpoint client(ccfg);
    ASSERT_TRUE(client.start()) << client.last_error();

    ASSERT_TRUE(client.wait_connected(5000))
        << "client handshake failed: " << client.last_error();
    const uint64_t conn_id = server.wait_connection(5000);
    ASSERT_NE(conn_id, 0u) << "server never saw a handshaken client";

    // Fixed path sanity: client sees the server at exactly 127.0.0.1:port.
    const std::string remote1 = client.remote_address_str();
    EXPECT_EQ(remote1, "127.0.0.1:" + std::to_string(port));

    std::atomic<bool> stop{false};
    const int kCount = 8;
    std::thread echo_thr(echo_loop, std::ref(server), std::ref(stop), kCount);

    // Multi-payload: mixed sizes, including > 1 packet and > 1 stream window
    // chunk, each on its own bidirectional stream.
    const size_t sizes[kCount] = {1, 15, 1200, 4096, 65536, 3, 262144, 1000};
    for (int i = 0; i < kCount; ++i) {
        const auto payload = patterned_bytes(sizes[i], static_cast<uint8_t>(i));
        uint64_t sid = UINT64_MAX;
        ASSERT_TRUE(client.send_message(payload, &sid))
            << "send failed at i=" << i << ": " << client.last_error();
        ASSERT_NE(sid, UINT64_MAX);

        ncp::RealQuicEndpoint::Message echo;
        ASSERT_TRUE(client.recv_message(echo, 10000))
            << "echo timeout at i=" << i;
        EXPECT_EQ(echo.stream_id, sid);
        EXPECT_EQ(echo.payload, payload) << "payload mismatch at i=" << i;
    }

    // Fixed path invariant: remote address did not change mid-connection
    // (no PortHop, no migration).
    EXPECT_EQ(client.remote_address_str(), remote1);

    stop = true;
    echo_thr.join();

    const auto cst = client.stats();
    EXPECT_EQ(cst.messages_received, static_cast<uint64_t>(kCount));
    EXPECT_EQ(cst.messages_dropped_queue_full, 0u);
}

// ---------------------------------------------------------------------------
// 2. CA verification: pinned CA file succeeds; default system store rejects
//    the self-signed server certificate (proves verification is ON by
//    default — no silent acceptance).
// ---------------------------------------------------------------------------
TEST_F(RealQuicTest, CaVerificationEnforcedByDefault) {
    ASSERT_TRUE(certs_.ok);

    ncp::RealQuicEndpoint server(server_cfg());
    ASSERT_TRUE(server.start()) << server.last_error();
    const uint16_t port = server.bound_local_port();

    // (a) pinned CA file -> handshake succeeds without insecure mode.
    {
        auto ccfg = client_cfg(port);
        ccfg.ca_file = certs_.cert;  // self-signed CA:TRUE cert pins itself
        ASSERT_FALSE(ccfg.insecure_skip_verify);
        ncp::RealQuicEndpoint client(ccfg);
        ASSERT_TRUE(client.start()) << client.last_error();
        EXPECT_TRUE(client.wait_connected(8000))
            << "pinned-CA handshake failed: " << client.last_error();
    }

    // (b) default system CA store -> self-signed cert MUST be rejected.
    {
        auto ccfg = client_cfg(port);
        ASSERT_TRUE(ccfg.ca_file.empty());
        ASSERT_FALSE(ccfg.insecure_skip_verify);
        ncp::RealQuicEndpoint client(ccfg);
        ASSERT_TRUE(client.start()) << client.last_error();
        EXPECT_FALSE(client.wait_connected(8000))
            << "handshake unexpectedly succeeded with unverifiable cert";
        EXPECT_FALSE(client.last_error().empty());
    }
}

// ---------------------------------------------------------------------------
// 3. Plaintext garbage on the UDP path is rejected by the TLS/QUIC layer and
//    never surfaces as application data; the real handshake still works.
// ---------------------------------------------------------------------------
TEST_F(RealQuicTest, PlaintextGarbageRejectedAsApplicationData) {
    ASSERT_TRUE(certs_.ok);

    ncp::RealQuicEndpoint server(server_cfg());
    ASSERT_TRUE(server.start()) << server.last_error();
    const uint16_t port = server.bound_local_port();

    // Flood the listener with non-QUIC plaintext garbage.
    send_udp_garbage("127.0.0.1", port, 32);

    // Nothing may arrive as a message or connection.
    ncp::RealQuicEndpoint::Message m;
    EXPECT_FALSE(server.recv_message(m, 400));
    EXPECT_EQ(server.wait_connection(400), 0u);
    EXPECT_EQ(server.stats().messages_received, 0u);

    // A real client still handshakes cleanly afterwards.
    auto ccfg = client_cfg(port);
    ccfg.insecure_skip_verify = true;
    ncp::RealQuicEndpoint client(ccfg);
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(5000)) << client.last_error();
    EXPECT_NE(server.wait_connection(5000), 0u);

    // And plaintext garbage injected mid-connection is ignored.
    send_udp_garbage("127.0.0.1", port, 8);
    const auto before = server.stats().messages_received;
    EXPECT_FALSE(server.recv_message(m, 300));
    EXPECT_EQ(server.stats().messages_received, before);
}

// ---------------------------------------------------------------------------
// 4. Fixed path: client pinned to a fixed local port; local/remote 4-tuple
//    stable across the whole exchange (no PortHop / scheduled hopping).
// ---------------------------------------------------------------------------
TEST_F(RealQuicTest, FixedLocalAndRemotePathNoHopping) {
    ASSERT_TRUE(certs_.ok);

    ncp::RealQuicEndpoint server(server_cfg());
    ASSERT_TRUE(server.start()) << server.last_error();
    const uint16_t port = server.bound_local_port();

    // Pick a fixed, free client port.
    int probe = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(probe, 0);
    sockaddr_in pa{};
    pa.sin_family = AF_INET;
    pa.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &pa.sin_addr);
    ASSERT_EQ(bind(probe, reinterpret_cast<sockaddr*>(&pa), sizeof(pa)), 0);
    socklen_t sl = sizeof(pa);
    ASSERT_EQ(getsockname(probe, reinterpret_cast<sockaddr*>(&pa), &sl), 0);
    const uint16_t client_port = ntohs(pa.sin_port);
    close(probe);

    auto ccfg = client_cfg(port);
    ccfg.insecure_skip_verify = true;
    ccfg.local_port = client_port;  // pinned local path
    ncp::RealQuicEndpoint client(ccfg);
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(5000)) << client.last_error();
    ASSERT_NE(server.wait_connection(5000), 0u);

    const std::string local1 = client.local_address_str();
    const std::string remote1 = client.remote_address_str();
    EXPECT_EQ(local1, "127.0.0.1:" + std::to_string(client_port));
    EXPECT_EQ(remote1, "127.0.0.1:" + std::to_string(port));

    std::atomic<bool> stop{false};
    std::thread echo_thr(echo_loop, std::ref(server), std::ref(stop), 3);
    for (int i = 0; i < 3; ++i) {
        const auto payload = patterned_bytes(512 + i * 977, 0xA0 + i);
        ASSERT_TRUE(client.send_message(payload));
        ncp::RealQuicEndpoint::Message echo;
        ASSERT_TRUE(client.recv_message(echo, 10000));
        EXPECT_EQ(echo.payload, payload);
        // Path must be identical after every exchange.
        EXPECT_EQ(client.local_address_str(), local1);
        EXPECT_EQ(client.remote_address_str(), remote1);
    }
    stop = true;
    echo_thr.join();
}

// ---------------------------------------------------------------------------
// 5. A literal fixed remote IP remains authoritative when TLS SNI is a
//    different, deliberately unresolvable .test name.
// ---------------------------------------------------------------------------
TEST_F(RealQuicTest, LiteralRemoteIpIndependentOfSni) {
    ASSERT_TRUE(certs_.ok);
    ncp::RealQuicEndpoint server(server_cfg());
    ASSERT_TRUE(server.start()) << server.last_error();

    auto ccfg = client_cfg(server.bound_local_port());
    ccfg.ca_file = certs_.cert;
    ccfg.server_name = "lab.dynam.test";
    ncp::RealQuicEndpoint client(ccfg);
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(5000)) << client.last_error();
    EXPECT_NE(server.wait_connection(5000), 0u);
    EXPECT_EQ(client.remote_address_str(),
              "127.0.0.1:" + std::to_string(server.bound_local_port()));
}

// ---------------------------------------------------------------------------
// 6. Optional QUIC DATAGRAM (RFC 9221) exchange.
// ---------------------------------------------------------------------------
TEST_F(RealQuicTest, DatagramExchange) {
    ASSERT_TRUE(certs_.ok);

    auto scfg = server_cfg();
    scfg.enable_datagrams = true;
    ncp::RealQuicEndpoint server(scfg);
    ASSERT_TRUE(server.start()) << server.last_error();

    auto ccfg = client_cfg(server.bound_local_port());
    ccfg.insecure_skip_verify = true;
    ccfg.enable_datagrams = true;
    ncp::RealQuicEndpoint client(ccfg);
    ASSERT_TRUE(client.start()) << client.last_error();
    ASSERT_TRUE(client.wait_connected(5000)) << client.last_error();
    ASSERT_NE(server.wait_connection(5000), 0u);

    // Wait for datagram negotiation (max send length advertised).
    for (int i = 0; i < 50 && client.datagram_max_send_length() == 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_GT(client.datagram_max_send_length(), 0)
        << "QUIC DATAGRAM was not negotiated";

    const uint16_t maxd = client.datagram_max_send_length();
    const auto d1 = patterned_bytes(200, 0x11);
    // Near-maximum datagram, clamped to the negotiated limit.
    const auto d2 = patterned_bytes(std::min<size_t>(1200, maxd), 0x77);
    ASSERT_TRUE(client.send_datagram(d1)) << client.last_error();
    ASSERT_TRUE(client.send_datagram(d2)) << client.last_error();

    ncp::RealQuicEndpoint::Datagram got1, got2;
    ASSERT_TRUE(server.recv_datagram(got1, 5000));
    ASSERT_TRUE(server.recv_datagram(got2, 5000));
    // Datagrams are unordered; match by size.
    if (got1.payload.size() != d1.size()) std::swap(got1, got2);
    EXPECT_EQ(got1.payload, d1);
    EXPECT_EQ(got2.payload, d2);

    // Server -> client direction too (bidirectional datagrams).
    const auto d3 = patterned_bytes(300, 0x42);
    ASSERT_TRUE(server.send_datagram(d3, got1.connection_id));
    ncp::RealQuicEndpoint::Datagram got3;
    ASSERT_TRUE(client.recv_datagram(got3, 5000));
    EXPECT_EQ(got3.payload, d3);
}

} // namespace
