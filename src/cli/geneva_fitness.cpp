#include "geneva_fitness.hpp"

#include "ncp_blockcheck.hpp"     // BlockChecker::build_client_hello (shared TLS CH builder)
#include "ncp_winsock_init.hpp"   // winsock_init(), portable socket_t / kInvalidSocket

#include <algorithm>
#include <chrono>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define GF_CLOSE(s) ::closesocket(s)
    static int gf_err() { return WSAGetLastError(); }
    #define GF_EINPROGRESS WSAEWOULDBLOCK  // Winsock non-blocking connect reports WSAEWOULDBLOCK
    #define GF_EALREADY_WSA WSAEALREADY
#else
    #include <cerrno>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>   // IP_TTL
    #include <poll.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #define GF_CLOSE(s) ::close(s)
    static int gf_err() { return errno; }
    #define GF_EINPROGRESS EINPROGRESS
#endif

namespace ncp {
namespace cli {
namespace {

// Portable readability/writability wait. Returns >0 ready, 0 timeout, <0 error.
int gf_wait(socket_t s, short events, int timeout_ms) {
#ifdef _WIN32
    WSAPOLLFD pfd{};
    pfd.fd = s;
    pfd.events = events;
    return ::WSAPoll(&pfd, 1, timeout_ms);
#else
    pollfd pfd{};
    pfd.fd = s;
    pfd.events = events;
    return ::poll(&pfd, 1, timeout_ms);
#endif
}

void gf_set_nonblocking(socket_t s) {
#ifdef _WIN32
    u_long nb = 1;
    ::ioctlsocket(s, FIONBIO, &nb);
#else
    int fl = ::fcntl(s, F_GETFL, 0);
    if (fl >= 0) ::fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
}

// Non-blocking connect with timeout. Returns kInvalidSocket on failure.
socket_t gf_connect(const std::string& host, uint16_t port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
        return kInvalidSocket;

    socket_t out = kInvalidSocket;
    for (addrinfo* ai = res; ai && out == kInvalidSocket; ai = ai->ai_next) {
        socket_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == kInvalidSocket) continue;

        gf_set_nonblocking(s);
        int r = ::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (r < 0) {
            int e = gf_err();
#ifdef _WIN32
            bool in_progress = (e == GF_EINPROGRESS || e == GF_EALREADY_WSA || e == WSAEINVAL);
#else
            bool in_progress = (e == GF_EINPROGRESS);
#endif
            if (!in_progress) { GF_CLOSE(s); continue; }
            if (gf_wait(s, POLLOUT, timeout_ms) <= 0) { GF_CLOSE(s); continue; }
            int so_err = 0;
            socklen_t sl = sizeof(so_err);
            ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &sl);
            if (so_err != 0) { GF_CLOSE(s); continue; }
        }
        out = s;  // keep socket non-blocking: recv path uses gf_wait() first
    }
    ::freeaddrinfo(res);
    return out;
}

// Send the whole buffer (socket is non-blocking; wait for writability).
bool gf_send_all(socket_t s, const uint8_t* d, size_t n, int timeout_ms) {
    size_t sent = 0;
    while (sent < n) {
        int r = ::send(s, reinterpret_cast<const char*>(d + sent),
                       static_cast<int>(n - sent), 0);
        if (r > 0) { sent += static_cast<size_t>(r); continue; }
        if (r < 0) {
            int e = gf_err();
#ifdef _WIN32
            if (e == WSAEWOULDBLOCK) {
#else
            if (e == EAGAIN || e == EWOULDBLOCK) {
#endif
                if (gf_wait(s, POLLOUT, timeout_ms) <= 0) return false;
                continue;
            }
        }
        return false;  // RST / closed / hard error
    }
    return true;
}

// Set IP TTL (IPv4) or hop limit (IPv6) on a connected socket.
void gf_set_ttl(socket_t s, int ttl) {
    int v = ttl;
    if (::setsockopt(s, IPPROTO_IP, IP_TTL,
                     reinterpret_cast<const char*>(&v), sizeof(v)) != 0) {
        // Possibly an IPv6 socket — try hop limit instead.
        ::setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                     reinterpret_cast<const char*>(&v), sizeof(v));
    }
}

bool gf_is_ip_literal(const std::string& host) {
    if (host.empty()) return false;
    if (host.find(':') != std::string::npos) return true;  // IPv6
    return std::all_of(host.begin(), host.end(), [](char c) {
        return (c >= '0' && c <= '9') || c == '.';
    });
}

} // namespace

DPI::FitnessResult geneva_probe_fitness(const DPI::GenevaStrategy& strategy,
                                        const std::string& target_host,
                                        uint16_t target_port,
                                        int timeout_ms) noexcept {
    DPI::FitnessResult res;  // connected=false, packet_loss=1.0 by default
    try {
        if (timeout_ms <= 0) timeout_ms = 5000;
        if (!winsock_init()) return res;

        const auto t0 = std::chrono::steady_clock::now();
        const auto elapsed_ms = [&]() -> int {
            return static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count());
        };

        socket_t s = gf_connect(target_host, target_port, timeout_ms);
        if (s == kInvalidSocket) return res;
        struct SockGuard { socket_t s; ~SockGuard() { GF_CLOSE(s); } } guard{s};

        // ── Realistic TLS ClientHello (SNI omitted for IP literals) ──
        const std::string sni = gf_is_ip_literal(target_host) ? "" : target_host;
        const std::vector<uint8_t> hello = BlockChecker::build_client_hello(sni);

        // ── Transform through a PRIVATE engine: thread-safe (the GA health
        //    thread may probe concurrently) and does not skew the live
        //    engine's packet counters. ──
        DPI::GenevaEngine engine;
        std::vector<std::vector<uint8_t>> packets;
        try {
            packets = engine.apply_strategy(hello, strategy);
        } catch (...) {
            return res;  // strategy not applicable to this payload
        }
        if (packets.empty()) return res;  // e.g. pure-DROP strategy: nothing to send

        // ── TAMPER_TTL simplification: first produced packet goes out with
        //    a low TTL (fake dies mid-path, poisons stateful DPI), the rest
        //    with normal TTL — mirrors the WinDivert fake+ttl path. ──
        int fake_ttl = -1;
        for (const auto& step : strategy.steps) {
            if (step.action == DPI::GenevaAction::TAMPER_TTL) {
                int p = step.param ? static_cast<int>(step.param) : 2;
                fake_ttl = std::min(64, std::max(1, p));
                break;
            }
        }

        int budget = timeout_ms - elapsed_ms();
        if (budget <= 0) return res;

        for (size_t i = 0; i < packets.size(); ++i) {
            bool ttl_set = (fake_ttl > 0 && i == 0);
            if (ttl_set) gf_set_ttl(s, fake_ttl);
            bool ok = gf_send_all(s, packets[i].data(), packets[i].size(), budget);
            if (ttl_set) gf_set_ttl(s, 128);  // restore a sane default
            if (!ok) return res;  // RST/timeout mid-sequence
        }

        // ── Await any response bytes (ServerHello) within the budget ──
        budget = timeout_ms - elapsed_ms();
        if (budget <= 0) return res;
        int wr = gf_wait(s, POLLIN, budget);
        if (wr <= 0) return res;  // timeout or error
        uint8_t buf[16];
        int n = ::recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
        if (n <= 0) return res;  // RST or orderly close before any data

        res.connected = true;
        res.latency_ms = static_cast<double>(elapsed_ms());
        res.packet_loss = 0.0;
        res.retry_count = 0;
        return res;
    } catch (...) {
        res.connected = false;
        res.packet_loss = 1.0;
        return res;
    }
}

} // namespace cli
} // namespace ncp
