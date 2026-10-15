// Regression tests for ncp::cli::geneva_probe_fitness (v1.7.6).
//
// Live-acceptance finding (Windows VM behind slirp, stateful SNI filter):
// the GA converged at fitness ~961 on strategies whose fake prefix corrupts
// the byte stream. The DPI's TLS parser chokes on the corruption (no SNI
// match → flow passes), and the server answers the garbage with a TLS ALERT
// (15 03 01 00 02 02 2f). The old fitness counted ANY response bytes as
// "connected", so corruption strategies scored as working bypasses while
// real end-to-end handshakes (Schannel) kept failing.
//
// The fix requires a real ServerHello record (0x16 0x03..). These tests run
// the probe against a localhost mock that replays scripted responses.

#include <gtest/gtest.h>

#include "geneva_fitness.hpp"
#include "ncp_winsock_init.hpp"  // winsock_init() — required before any socket on Windows

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace {

using ncp::DPI::GenevaStrategy;
using ncp::cli::geneva_probe_fitness;

// One-shot TCP mock: accepts a single connection, drains whatever arrives,
// then sends `response` and closes. Returns the bound port via `port_out`.
class MockTlsServer {
public:
    bool start(const std::vector<uint8_t>& response, int hold_ms = 0) {
        response_ = response;
        hold_ms_ = hold_ms;
        if (!ncp::winsock_init()) return false;  // no-op on POSIX
        srv_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (srv_ < 0) return false;
        int one = 1;
        ::setsockopt(srv_, SOL_SOCKET, SO_REUSEADDR,
                     reinterpret_cast<const char*>(&one), sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(srv_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
            return false;
        socklen_t alen = sizeof(addr);
        if (::getsockname(srv_, reinterpret_cast<sockaddr*>(&addr), &alen) != 0)
            return false;
        port_ = ntohs(addr.sin_port);
        if (::listen(srv_, 1) != 0) return false;
        worker_ = std::thread([this] { serve(); });
        return true;
    }

    uint16_t port() const { return port_; }

    ~MockTlsServer() {
        if (worker_.joinable()) worker_.join();
#ifdef _WIN32
        if (srv_ >= 0) ::closesocket(srv_);
#else
        if (srv_ >= 0) ::close(srv_);
#endif
    }

private:
    void serve() {
        int c = ::accept(srv_, nullptr, nullptr);
        if (c < 0) return;
        // Drain the ClientHello (whatever the probe sends).
        uint8_t drain[2048];
#ifdef _WIN32
        DWORD rcv_ms = 2000;  // Windows SO_RCVTIMEO takes DWORD milliseconds
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&rcv_ms), sizeof(rcv_ms));
#else
        struct timeval tv{};
        tv.tv_sec = 2;
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        ::recv(c, reinterpret_cast<char*>(drain), sizeof(drain), 0);
        if (hold_ms_ > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms_));
#ifdef _WIN32
            ::closesocket(c);
#else
            ::close(c);
#endif
            return;
        }
        if (!response_.empty())
            ::send(c, reinterpret_cast<const char*>(response_.data()),
                   static_cast<int>(response_.size()), 0);
#ifdef _WIN32
        ::closesocket(c);
#else
        ::close(c);
#endif
    }

    int srv_ = -1;
    uint16_t port_ = 0;
    std::vector<uint8_t> response_;
    int hold_ms_ = 0;
    std::thread worker_;
};

GenevaStrategy empty_strategy() { return GenevaStrategy{}; }

TEST(GenevaFitness, AlertResponseIsNotConnected) {
    // TLS alert: 15 03 01 00 02 02 2f (fatal decode_error) — the exact bytes
    // observed from youtube behind the stateful filter when the stream was
    // corrupted by a fake prefix.
    MockTlsServer mock;
    ASSERT_TRUE(mock.start({0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x2f}));
    auto r = geneva_probe_fitness(empty_strategy(), "127.0.0.1", mock.port(), 4000);
    EXPECT_FALSE(r.connected);
    EXPECT_DOUBLE_EQ(r.score(), 0.0);
}

TEST(GenevaFitness, GarbageResponseIsNotConnected) {
    MockTlsServer mock;
    ASSERT_TRUE(mock.start({'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '4', '0', '3'}));
    auto r = geneva_probe_fitness(empty_strategy(), "127.0.0.1", mock.port(), 4000);
    EXPECT_FALSE(r.connected);
    EXPECT_DOUBLE_EQ(r.score(), 0.0);
}

TEST(GenevaFitness, ServerHelloResponseIsConnected) {
    // Minimal ServerHello record header: 16 03 03 + len + body bytes.
    MockTlsServer mock;
    ASSERT_TRUE(mock.start({0x16, 0x03, 0x03, 0x00, 0x2e, 0x02, 0x00, 0x00, 0x2a,
                            0x03, 0x03, 0x01, 0x02, 0x03, 0x04}));
    auto r = geneva_probe_fitness(empty_strategy(), "127.0.0.1", mock.port(), 4000);
    EXPECT_TRUE(r.connected);
    EXPECT_GT(r.score(), 0.0);
    EXPECT_DOUBLE_EQ(r.packet_loss, 0.0);
}

TEST(GenevaFitness, SilentServerIsNotConnected) {
    // Accept and hold without sending (simulates DPI drop after connect).
    MockTlsServer mock;
    ASSERT_TRUE(mock.start({}, 2500));
    auto r = geneva_probe_fitness(empty_strategy(), "127.0.0.1", mock.port(), 800);
    EXPECT_FALSE(r.connected);
}

} // namespace
