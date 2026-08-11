#include "ncp_proxy.hpp"

#include "ncp_tls_parse.hpp"
#include "ncp_quic.hpp"
#include "ncp_hostlist.hpp"
#include "ncp_dpi_detector.hpp"
#include "ncp_doh.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using ncp_socket_t = SOCKET;
    #define NCP_INVALID_SOCK INVALID_SOCKET
    #define NCP_CLOSE_SOCKET(s) closesocket(s)
    static int ncp_last_error() { return WSAGetLastError(); }
    #define NCP_EWOULDBLOCK WSAEWOULDBLOCK
    #define NCP_EINPROGRESS WSAEINPROGRESS
    #define NCP_ECONNRESET WSAECONNRESET
    #define NCP_ETIMEDOUT WSAETIMEDOUT
#else
    #include <arpa/inet.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <poll.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <unistd.h>
    using ncp_socket_t = int;
    #define NCP_INVALID_SOCK (-1)
    #define NCP_CLOSE_SOCKET(s) ::close(s)
    static int ncp_last_error() { return errno; }
    #define NCP_EWOULDBLOCK EAGAIN
    #define NCP_EINPROGRESS EINPROGRESS
    #define NCP_ECONNRESET ECONNRESET
    #define NCP_ETIMEDOUT ETIMEDOUT
#endif

namespace ncp {

// ─────────────────────────────────────────────────────────────────────────────
// Winsock lifetime (Windows only)
// ─────────────────────────────────────────────────────────────────────────────
static void ncp_net_init() {
#ifdef _WIN32
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    });
#endif
}

// poll() wrapper with unified signature. Returns >0 ready, 0 timeout, <0 error.
static int ncp_wait_readable(ncp_socket_t s, int timeout_ms, bool* is_err = nullptr) {
#ifdef _WIN32
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(s, &rfds);
    fd_set efds;
    FD_ZERO(&efds);
    FD_SET(s, &efds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int r = select(0, &rfds, nullptr, &efds, &tv);
    if (r > 0 && FD_ISSET(s, &efds) && !FD_ISSET(s, &rfds)) {
        if (is_err) *is_err = true;
        return -1;
    }
    return r;
#else
    pollfd pfd{s, POLLIN, 0};
    int r = ::poll(&pfd, 1, timeout_ms);
    if (r > 0 && (pfd.revents & (POLLERR | POLLNVAL))) {
        if (is_err) *is_err = true;
        return -1;
    }
    return r;
#endif
}

static bool ncp_send_all(ncp_socket_t s, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int r = ::send(s, reinterpret_cast<const char*>(data + sent),
#ifdef _WIN32
                       static_cast<int>(len - sent),
#else
                       len - sent,
#endif
                       0);
        if (r <= 0) return false;
        sent += static_cast<size_t>(r);
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static helpers
// ─────────────────────────────────────────────────────────────────────────────

std::vector<size_t> DesyncProxy::resolve_split_positions(
    const std::vector<DPI::ZSplitPos>& positions,
    const uint8_t* payload, size_t payload_len) {
    std::vector<size_t> out;
    if (!payload || payload_len < 2) return out;

    const bool is_tls = is_tls_client_hello(payload, payload_len);
    TlsClientHelloInfo tls;
    HttpRequestInfo http;
    if (is_tls) tls = parse_tls_client_hello(payload, payload_len);
    else http = parse_http_request(payload, payload_len);

    std::string host;
    size_t host_off = 0;
    if (tls.valid && !tls.sni.empty()) {
        host = tls.sni;
        host_off = tls.sni_value_offset;
    } else if (http.valid && !http.host.empty()) {
        host = http.host;
        host_off = http.host_value_offset;
    }

    for (const auto& sp : positions) {
        size_t pos = 0;
        bool have = false;
        switch (sp.type) {
            case DPI::ZSplitPosType::NUMERIC:
                if (sp.offset > 0) { pos = static_cast<size_t>(sp.offset); have = true; }
                break;
            case DPI::ZSplitPosType::METHOD:
                if (http.valid) { pos = http.method_end ? http.method_end : 1; have = true; }
                else { pos = 1; have = true; }
                break;
            case DPI::ZSplitPosType::HOST:
                if (!host.empty()) { pos = host_off; have = true; }
                break;
            case DPI::ZSplitPosType::ENDHOST:
                if (!host.empty()) { pos = host_off + host.size(); have = true; }
                break;
            case DPI::ZSplitPosType::SLD:
                if (!host.empty()) {
                    pos = host_off + sld_start_offset(host) +
                          (sp.offset > 0 ? static_cast<size_t>(sp.offset) : 0);
                    have = true;
                }
                break;
            case DPI::ZSplitPosType::ENDSLD: {
                if (!host.empty()) {
                    const size_t sld = sld_start_offset(host);
                    size_t dot = host.find('.', sld);
                    pos = host_off + (dot == std::string::npos ? host.size() : dot);
                    have = true;
                }
                break;
            }
            case DPI::ZSplitPosType::MIDSLD: {
                if (!host.empty()) {
                    const size_t sld = sld_start_offset(host);
                    size_t dot = host.find('.', sld);
                    const size_t sld_len =
                        (dot == std::string::npos ? host.size() : dot) - sld;
                    pos = host_off + sld + sld_len / 2;
                    have = true;
                }
                break;
            }
            case DPI::ZSplitPosType::SNIEXT:
                if (tls.valid && tls.sni_ext_offset) { pos = tls.sni_ext_offset; have = true; }
                else if (http.valid && http.host_value_offset >= 5) {
                    pos = http.host_value_offset - 5;  // "Host:" start
                    have = true;
                }
                break;
        }
        if (have && pos > 0 && pos < payload_len) out.push_back(pos);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<size_t> DesyncProxy::split_offsets_from_config(
    const DPI::DPIConfig& cfg, const uint8_t* payload, size_t payload_len) {
    std::vector<DPI::ZSplitPos> positions;
    if (cfg.enable_multi_layer_split && !cfg.split_positions.empty()) {
        for (int p : cfg.split_positions)
            positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, p});
    } else if (cfg.enable_tcp_split && cfg.split_position > 0) {
        positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, cfg.split_position});
    }
    if (cfg.split_at_sni) {
        positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::HOST, 0});
    }
    return resolve_split_positions(positions, payload, payload_len);
}

const DPI::ZapretChain* DesyncProxy::select_chain(
    const std::vector<DPI::ZapretChain>& chains,
    const std::vector<std::vector<std::string>>& chain_hostlist_patterns,
    DPI::ZProto proto, uint16_t dst_port, const std::string& host) {
    for (size_t i = 0; i < chains.size(); ++i) {
        const auto& c = chains[i];
        if (c.proto != proto) continue;
        if (!c.ports.empty()) {
            bool port_ok = false;
            for (const auto& pr : c.ports)
                if (dst_port >= pr.first && dst_port <= pr.second) { port_ok = true; break; }
            if (!port_ok) continue;
        }
        if (i < chain_hostlist_patterns.size() && !chain_hostlist_patterns[i].empty()) {
            if (host.empty()) continue;
            bool host_ok = false;
            for (const auto& pat : chain_hostlist_patterns[i])
                if (HostlistMatcher::matches_pattern(host, pat)) { host_ok = true; break; }
            if (!host_ok) continue;
        }
        return &c;
    }
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Impl
// ─────────────────────────────────────────────────────────────────────────────

class DesyncProxy::Impl {
public:
    Config cfg;
    std::atomic<bool> running{false};
    ncp_socket_t listen_sock = NCP_INVALID_SOCK;
    uint16_t bound_port_ = 0;
    std::thread accept_thread;

    struct Counters {
        std::atomic<uint64_t> total{0}, active{0}, c2s{0}, s2c{0},
            splits{0}, fake_quic{0}, quic_blocked{0}, rst_blocks{0},
            timeout_blocks{0}, udp_sessions{0};
    } cnt;

    std::mutex socks_mu;
    std::set<ncp_socket_t> open_socks;

    // loaded hostlist patterns per chain
    std::vector<std::vector<std::string>> chain_patterns;

    // DoH resolution (bypass DNS blocks)
    std::unique_ptr<DoHClient> doh;
    std::mutex doh_cache_mu;
    std::map<std::string, std::pair<std::string, std::chrono::steady_clock::time_point>> doh_cache;

    // Resolve host to a connectable address string; returns input unchanged
    // for IP literals or when DoH is disabled/fails (fallback to system DNS).
    std::string resolve_upstream(const std::string& host) {
        if (!cfg.use_doh || !doh) return host;
        in_addr a4{};
        in6_addr a6{};
        if (::inet_pton(AF_INET, host.c_str(), &a4) == 1 ||
            ::inet_pton(AF_INET6, host.c_str(), &a6) == 1)
            return host;  // already an IP literal
        {
            std::lock_guard<std::mutex> lk(doh_cache_mu);
            auto it = doh_cache.find(host);
            if (it != doh_cache.end() &&
                std::chrono::steady_clock::now() - it->second.second <
                    std::chrono::minutes(5))
                return it->second.first;
        }
        auto res = doh->resolve_ipv4(host);
        if (!res.addresses.empty()) {
            std::lock_guard<std::mutex> lk(doh_cache_mu);
            doh_cache[host] = {res.addresses.front(),
                               std::chrono::steady_clock::now()};
            return res.addresses.front();
        }
        return host;  // fallback: system DNS
    }

    void log(const std::string& msg) {
        if (cfg.log_cb) cfg.log_cb(msg);
    }

    void track(ncp_socket_t s) {
        std::lock_guard<std::mutex> lk(socks_mu);
        open_socks.insert(s);
    }
    void untrack(ncp_socket_t s) {
        std::lock_guard<std::mutex> lk(socks_mu);
        open_socks.erase(s);
    }
    void close_sock(ncp_socket_t s) {
        if (s == NCP_INVALID_SOCK) return;
#ifdef _WIN32
        ::shutdown(s, SD_BOTH);
#else
        ::shutdown(s, SHUT_RDWR);
#endif
        NCP_CLOSE_SOCKET(s);
        untrack(s);
    }

    // ── Chain → desync plan ──
    struct DesyncPlan {
        std::vector<DPI::ZSplitPos> positions;
        bool host_case = false;
    };

    DesyncPlan plan_for(DPI::ZProto proto, uint16_t dst_port, const std::string& host) {
        DesyncPlan plan;
        const DPI::ZapretChain* chain =
            select_chain(cfg.chains, chain_patterns, proto, dst_port, host);
        if (chain) {
            // split-family phases are applicable at socket level
            if (chain->phase2 == DPI::ZDesyncPhase2::MULTISPLIT ||
                chain->phase2 == DPI::ZDesyncPhase2::MULTIDISORDER ||
                chain->phase2 == DPI::ZDesyncPhase2::FAKEDSPLIT ||
                chain->phase2 == DPI::ZDesyncPhase2::FAKEDDISORDER ||
                chain->phase2 == DPI::ZDesyncPhase2::HOSTFAKESPLIT) {
                plan.positions = chain->split_positions;
                if (plan.positions.empty())
                    plan.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, 1});
                if (chain->phase2 == DPI::ZDesyncPhase2::HOSTFAKESPLIT)
                    plan.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::MIDSLD, 0});
            } else {
                plan.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, 2});
            }
        } else {
            // base DPIConfig
            if (cfg.base.enable_multi_layer_split && !cfg.base.split_positions.empty()) {
                for (int p : cfg.base.split_positions)
                    plan.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, p});
            } else if (cfg.base.enable_tcp_split && cfg.base.split_position > 0) {
                plan.positions.push_back(
                    DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, cfg.base.split_position});
            }
            if (cfg.base.split_at_sni)
                plan.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::HOST, 0});
            plan.host_case = cfg.base.enable_host_case;
        }
        return plan;
    }

    void handle_tcp(ncp_socket_t client, sockaddr_storage peer, socklen_t peer_len);
    void run_udp_session(ncp_socket_t ctrl, const sockaddr_storage& client_addr,
                         socklen_t client_len);

    // ── Networking helpers ──
    ncp_socket_t connect_target(const std::string& host_in, uint16_t port, int timeout_ms,
                                bool* reset = nullptr) {
        if (reset) *reset = false;
        const std::string host = resolve_upstream(host_in);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        const std::string port_str = std::to_string(port);
        if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res)
            return NCP_INVALID_SOCK;

        ncp_socket_t out = NCP_INVALID_SOCK;
        for (addrinfo* ai = res; ai && out == NCP_INVALID_SOCK; ai = ai->ai_next) {
            ncp_socket_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s == NCP_INVALID_SOCK) continue;

            // non-blocking connect with timeout
#ifdef _WIN32
            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);
#else
            int flags = fcntl(s, F_GETFL, 0);
            fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
            int r = ::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
            if (r < 0) {
                int e = ncp_last_error();
                if (e != NCP_EINPROGRESS && e != NCP_EWOULDBLOCK) {
                    if (e == NCP_ECONNRESET && reset) *reset = true;
                    NCP_CLOSE_SOCKET(s);
                    continue;
                }
                // wait for writable
#ifdef _WIN32
                fd_set wfds;
                FD_ZERO(&wfds);
                FD_SET(s, &wfds);
                fd_set efds;
                FD_ZERO(&efds);
                FD_SET(s, &efds);
                timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
                r = select(0, nullptr, &wfds, &efds, &tv);
                if (r <= 0 || !FD_ISSET(s, &wfds)) {
                    NCP_CLOSE_SOCKET(s);
                    continue;
                }
#else
                pollfd pfd{s, static_cast<short>(POLLOUT), 0};
                r = ::poll(&pfd, 1, timeout_ms);
                if (r <= 0 || !(pfd.revents & POLLOUT)) {
                    NCP_CLOSE_SOCKET(s);
                    continue;
                }
#endif
                int so_err = 0;
                socklen_t sl = sizeof(so_err);
                ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &sl);
                if (so_err != 0) {
                    if (so_err == ECONNRESET && reset) *reset = true;
                    NCP_CLOSE_SOCKET(s);
                    continue;
                }
            }
            // back to blocking
#ifdef _WIN32
            u_long b = 0;
            ioctlsocket(s, FIONBIO, &b);
#else
            fcntl(s, F_SETFL, flags);
#endif
            int nodelay = 1;
            ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
                         reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
            out = s;
        }
        ::freeaddrinfo(res);
        return out;
    }

    // send first payload with desync splitting
    bool send_first_payload(ncp_socket_t up, const uint8_t* data, size_t len,
                            const DesyncPlan& plan) {
        std::vector<size_t> cuts =
            resolve_split_positions(plan.positions, data, len);
        if (cuts.empty()) return ncp_send_all(up, data, len);
        size_t prev = 0;
        for (size_t cut : cuts) {
            if (cut <= prev || cut > len) continue;
            if (!ncp_send_all(up, data + prev, cut - prev)) return false;
            prev = cut;
            cnt.splits++;
            // tiny pause to force separate TCP segments
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (prev < len) return ncp_send_all(up, data + prev, len - prev);
        return true;
    }

    // relay one direction until EOF/error
    void relay(ncp_socket_t from, ncp_socket_t to, bool to_client,
               const std::string& host, bool* first_data_seen,
               std::atomic<bool>* peer_done) {
        std::vector<uint8_t> buf(16384);
        bool hello_wait = !to_client;  // server→client: watch first byte
        while (running.load()) {
            if (peer_done && peer_done->load()) break;
            int wr = ncp_wait_readable(from, hello_wait ? cfg.hello_timeout_ms : 2000);
            if (wr == 0) {
                if (hello_wait) {
                    // timeout waiting for server hello
                    hello_wait = false;
                    cnt.timeout_blocks++;
                    if (cfg.detector) cfg.detector->on_timeout(host);
                    if (cfg.auto_hostlist) cfg.auto_hostlist->record_blocked(host);
                    break;  // give up this connection
                }
                continue;
            }
            if (wr < 0) break;
            int r = ::recv(from, reinterpret_cast<char*>(buf.data()),
                           static_cast<int>(buf.size()), 0);
            if (r == 0) break;
            if (r < 0) {
                int e = ncp_last_error();
                if (hello_wait && (e == NCP_ECONNRESET)) {
                    cnt.rst_blocks++;
                    if (cfg.detector) cfg.detector->on_reset_after_hello(host);
                    if (cfg.auto_hostlist) cfg.auto_hostlist->record_blocked(host);
                }
                break;
            }
            if (hello_wait) {
                hello_wait = false;
                if (first_data_seen) *first_data_seen = true;
                if (cfg.detector) cfg.detector->on_success(host);
            }
            if (to_client) cnt.s2c += static_cast<uint64_t>(r);
            else cnt.c2s += static_cast<uint64_t>(r);
            if (!ncp_send_all(to, buf.data(), static_cast<size_t>(r))) break;
        }
        if (peer_done) *peer_done = true;
    }
};

DesyncProxy::DesyncProxy() : impl_(std::make_unique<Impl>()) {}
DesyncProxy::~DesyncProxy() { stop(); }

bool DesyncProxy::running() const { return impl_->running.load(); }
uint16_t DesyncProxy::bound_port() const { return impl_->bound_port_; }

ProxyStats DesyncProxy::stats() const {
    ProxyStats s;
    s.connections_total = impl_->cnt.total.load();
    s.connections_active = impl_->cnt.active.load();
    s.bytes_client_to_server = impl_->cnt.c2s.load();
    s.bytes_server_to_client = impl_->cnt.s2c.load();
    s.desync_splits_applied = impl_->cnt.splits.load();
    s.fake_quic_sent = impl_->cnt.fake_quic.load();
    s.quic_datagrams_blocked = impl_->cnt.quic_blocked.load();
    s.rst_blocks_detected = impl_->cnt.rst_blocks.load();
    s.timeout_blocks_detected = impl_->cnt.timeout_blocks.load();
    s.udp_sessions = impl_->cnt.udp_sessions.load();
    return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection handling (Impl members — have access to private nested Impl)
// ─────────────────────────────────────────────────────────────────────────────

namespace {

struct ProxyRequest {
    bool ok = false;
    bool udp_associate = false;
    std::string host;      // domain or numeric IP
    uint16_t port = 0;
    std::vector<uint8_t> http_head;  // plain-HTTP: rewritten request head
    bool is_http_plain = false;
};

bool read_full(ncp_socket_t s, uint8_t* buf, size_t n, int timeout_ms) {
    size_t got = 0;
    while (got < n) {
        if (ncp_wait_readable(s, timeout_ms) <= 0) return false;
        int r = ::recv(s, reinterpret_cast<char*>(buf + got),
                       static_cast<int>(n - got), 0);
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

std::string ipv4_to_str(const uint8_t* b) {
    return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
           std::to_string(b[2]) + "." + std::to_string(b[3]);
}

ProxyRequest socks5_negotiate(ncp_socket_t s, int timeout_ms) {
    ProxyRequest req;
    uint8_t hdr[2];
    if (!read_full(s, hdr, 2, timeout_ms)) return req;
    if (hdr[0] != 0x05) return req;
    const uint8_t nmethods = hdr[1];
    std::vector<uint8_t> methods(nmethods);
    if (nmethods && !read_full(s, methods.data(), nmethods, timeout_ms)) return req;
    const uint8_t reply[2] = {0x05, 0x00};  // no-auth
    if (!ncp_send_all(s, reply, 2)) return req;

    uint8_t rreq[4];
    if (!read_full(s, rreq, 4, timeout_ms)) return req;
    if (rreq[0] != 0x05) return req;
    const uint8_t cmd = rreq[1];
    const uint8_t atyp = rreq[3];
    if (cmd == 0x03) req.udp_associate = true;
    else if (cmd != 0x01) return req;

    std::string host;
    if (atyp == 0x01) {
        uint8_t b[4];
        if (!read_full(s, b, 4, timeout_ms)) return req;
        host = ipv4_to_str(b);
    } else if (atyp == 0x03) {
        uint8_t l;
        if (!read_full(s, &l, 1, timeout_ms)) return req;
        std::vector<uint8_t> d(l);
        if (!read_full(s, d.data(), l, timeout_ms)) return req;
        host.assign(reinterpret_cast<char*>(d.data()), l);
    } else if (atyp == 0x04) {
        uint8_t b[16];
        if (!read_full(s, b, 16, timeout_ms)) return req;
        char ip[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, b, ip, sizeof(ip))) return req;
        host = ip;
    } else return req;
    uint8_t pb[2];
    if (!read_full(s, pb, 2, timeout_ms)) return req;
    req.port = static_cast<uint16_t>((pb[0] << 8) | pb[1]);
    req.host = host;
    req.ok = true;
    return req;
}

void socks5_reply(ncp_socket_t s, uint8_t rep) {
    const uint8_t r[10] = {0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    ncp_send_all(s, r, sizeof(r));
}

ProxyRequest http_negotiate(ncp_socket_t s, uint8_t first_byte, int timeout_ms) {
    ProxyRequest req;
    std::vector<uint8_t> buf;
    buf.push_back(first_byte);
    buf.reserve(2048);
    while (buf.size() < 16384) {
        if (buf.size() >= 4) {
            const size_t n = buf.size();
            if (buf[n - 4] == '\r' && buf[n - 3] == '\n' &&
                buf[n - 2] == '\r' && buf[n - 1] == '\n') break;
        }
        if (ncp_wait_readable(s, timeout_ms) <= 0) return req;
        uint8_t b;
        int r = ::recv(s, reinterpret_cast<char*>(&b), 1, 0);
        if (r <= 0) return req;
        buf.push_back(b);
    }
    auto info = ncp::parse_http_request(buf.data(), buf.size());
    if (!info.valid) return req;

    if (info.is_connect) {
        const size_t colon = info.target.rfind(':');
        if (colon == std::string::npos) return req;
        req.host = info.target.substr(0, colon);
        try { req.port = static_cast<uint16_t>(std::stoi(info.target.substr(colon + 1))); }
        catch (...) { return req; }
        req.ok = true;
        return req;
    }
    // plain HTTP: absolute URI → extract host, rewrite to origin form
    if (info.target.rfind("http://", 0) != 0) return req;
    std::string rest = info.target.substr(7);
    const size_t slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    const std::string path = slash == std::string::npos ? "/" : rest.substr(slash);
    uint16_t port = 80;
    std::string host = authority;
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        host = authority.substr(0, colon);
        try { port = static_cast<uint16_t>(std::stoi(authority.substr(colon + 1))); }
        catch (...) { return req; }
    }
    if (!info.host.empty()) host = ncp::HostlistMatcher::normalize(info.host);
    req.host = host;
    req.port = port;
    req.is_http_plain = true;
    std::string head = info.method + " " + path + " HTTP/1.1\r\n";
    const size_t line_end = std::string(reinterpret_cast<char*>(buf.data()), buf.size())
                                .find("\r\n");
    if (line_end == std::string::npos) return req;
    head.append(reinterpret_cast<char*>(buf.data()) + line_end + 2,
                buf.size() - line_end - 2);
    req.http_head.assign(head.begin(), head.end());
    req.ok = true;
    return req;
}

} // namespace

// ── Impl member methods (declared via out-of-class definitions below) ──

// SOCKS5 UDP ASSOCIATE session — runs until control connection closes.
void DesyncProxy::Impl::run_udp_session(ncp_socket_t ctrl,
                                        const sockaddr_storage& client_addr,
                                        socklen_t client_len) {
    Impl* impl = this;
        ncp_socket_t udp = ::socket(client_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (udp == NCP_INVALID_SOCK) return;
        impl->track(udp);
        struct UdpGuard {
            Impl* i; ncp_socket_t s;
            ~UdpGuard() { i->close_sock(s); }
        } udp_guard{impl, udp};

        if (client_addr.ss_family == AF_INET) {
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = 0;
            if (::bind(udp, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) return;
        } else {
            sockaddr_in6 a{};
            a.sin6_family = AF_INET6;
            a.sin6_addr = in6addr_loopback;
            a.sin6_port = 0;
            if (::bind(udp, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0) return;
        }
        uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0};
        sockaddr_in bound{};
        socklen_t bl = sizeof(bound);
        ::getsockname(udp, reinterpret_cast<sockaddr*>(&bound), &bl);
        reply[8] = static_cast<uint8_t>((ntohs(bound.sin_port) >> 8) & 0xFF);
        reply[9] = static_cast<uint8_t>(ntohs(bound.sin_port) & 0xFF);
        if (!ncp_send_all(ctrl, reply, sizeof(reply))) return;

        impl->cnt.udp_sessions++;
        std::map<std::string, ncp_socket_t> upstreams;
        std::map<std::string, bool> fake_sent;
        std::vector<uint8_t> buf(65536);

        while (impl->running.load()) {
            int wr = ncp_wait_readable(udp, 1000);
            if (wr <= 0) {
                // bail out when the TCP control connection dies
                int cr = ncp_wait_readable(ctrl, 0);
                if (cr > 0) {
                    uint8_t t;
                    if (::recv(ctrl, reinterpret_cast<char*>(&t), 1, MSG_PEEK) <= 0) break;
                } else if (cr < 0) break;
                continue;
            }
            sockaddr_storage from{};
            socklen_t fl = sizeof(from);
            int r = ::recvfrom(udp, reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0,
                               reinterpret_cast<sockaddr*>(&from), &fl);
            if (r <= 0) continue;

            // client → target
            if (r < 10 || buf[0] != 0 || buf[1] != 0) continue;  // RSV
            if (buf[2] != 0) continue;  // FRAG not supported
            const uint8_t atyp = buf[3];
            size_t pos = 4;
            std::string host;
            if (atyp == 0x01) {
                host = ipv4_to_str(buf.data() + 4);
                pos = 8;
            } else if (atyp == 0x03) {
                const uint8_t l = buf[4];
                if (r < 7 + l) continue;
                host.assign(reinterpret_cast<char*>(buf.data() + 5), l);
                pos = 5 + l;
            } else if (atyp == 0x04) {
                if (r < 22) continue;
                char ip[INET6_ADDRSTRLEN];
                if (!inet_ntop(AF_INET6, buf.data() + 4, ip, sizeof(ip))) continue;
                host = ip;
                pos = 20;
            } else continue;
            if (pos + 2 > static_cast<size_t>(r)) continue;
            const uint16_t port =
                static_cast<uint16_t>((buf[pos] << 8) | buf[pos + 1]);
            pos += 2;
            const uint8_t* payload = buf.data() + pos;
            const size_t payload_len = static_cast<size_t>(r) - pos;
            const std::string key = host + ":" + std::to_string(port);

            if (port == 443 && impl->cfg.block_quic) {
                impl->cnt.quic_blocked++;
                continue;
            }

            ncp_socket_t up = NCP_INVALID_SOCK;
            auto it = upstreams.find(key);
            if (it != upstreams.end()) {
                up = it->second;
            } else {
                addrinfo hints{};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_DGRAM;
                addrinfo* res = nullptr;
                if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                                  &hints, &res) != 0 || !res) continue;
                up = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (up != NCP_INVALID_SOCK) {
                    if (::connect(up, res->ai_addr,
                                  static_cast<int>(res->ai_addrlen)) < 0) {
                        NCP_CLOSE_SOCKET(up);
                        up = NCP_INVALID_SOCK;
                    } else {
                        impl->track(up);
                        upstreams[key] = up;
                    }
                }
                ::freeaddrinfo(res);
                if (up == NCP_INVALID_SOCK) continue;
            }

            // fake QUIC Initials before first real Initial to this target
            if (port == 443 && impl->cfg.fake_quic_repeats > 0 &&
                is_quic_initial(payload, payload_len) && !fake_sent[key]) {
                fake_sent[key] = true;
                for (int i = 0; i < impl->cfg.fake_quic_repeats; ++i) {
                    auto fake = build_fake_quic_initial(1200);
                    ::send(up, reinterpret_cast<const char*>(fake.data()),
                           static_cast<int>(fake.size()), 0);
                    impl->cnt.fake_quic++;
                }
            }
            ::send(up, reinterpret_cast<const char*>(payload),
                   static_cast<int>(payload_len), 0);

            // drain all pending upstream replies
            for (auto& kv : upstreams) {
                for (;;) {
                    int ur = ncp_wait_readable(kv.second, 0);
                    if (ur <= 0) break;
                    int n = ::recv(kv.second,
                                   reinterpret_cast<char*>(buf.data() + 32768),
                                   static_cast<int>(buf.size() - 32768), 0);
                    if (n <= 0) break;
                    std::vector<uint8_t> out = {0, 0, 0};
                    const size_t colon = kv.first.rfind(':');
                    const std::string h = kv.first.substr(0, colon);
                    uint16_t p = 0;
                    try { p = static_cast<uint16_t>(
                              std::stoi(kv.first.substr(colon + 1))); }
                    catch (...) { break; }
                    in_addr a4{};
                    if (::inet_pton(AF_INET, h.c_str(), &a4) == 1) {
                        out.push_back(0x01);
                        const uint8_t* ab = reinterpret_cast<const uint8_t*>(&a4);
                        out.insert(out.end(), ab, ab + 4);
                    } else {
                        out.push_back(0x03);
                        out.push_back(static_cast<uint8_t>(h.size()));
                        out.insert(out.end(), h.begin(), h.end());
                    }
                    out.push_back(static_cast<uint8_t>(p >> 8));
                    out.push_back(static_cast<uint8_t>(p & 0xFF));
                    out.insert(out.end(), buf.data() + 32768,
                               buf.data() + 32768 + n);
                    ::sendto(udp, reinterpret_cast<const char*>(out.data()),
                             static_cast<int>(out.size()), 0,
                             reinterpret_cast<const sockaddr*>(&client_addr),
                             client_len);
                }
            }
        }
        for (auto& kv : upstreams) impl->close_sock(kv.second);
    }

void DesyncProxy::Impl::handle_tcp(ncp_socket_t client,
                                   sockaddr_storage peer, socklen_t peer_len) {
    Impl* impl = this;
        impl->cnt.total++;
        impl->cnt.active++;
        struct Guard {
            Impl* i; ncp_socket_t c;
            ~Guard() { i->close_sock(c); i->cnt.active--; }
        } guard{impl, client};

        uint8_t first = 0;
        int r = ::recv(client, reinterpret_cast<char*>(&first), 1, MSG_PEEK);
        if (r <= 0) return;

        ProxyRequest preq;
        const bool is_socks = (first == 0x05);
        if (is_socks) {
            preq = socks5_negotiate(client, impl->cfg.connect_timeout_ms);
            if (!preq.ok) { socks5_reply(client, 0x07); return; }
        } else {
            if (::recv(client, reinterpret_cast<char*>(&first), 1, 0) <= 0) return;
            preq = http_negotiate(client, first, impl->cfg.connect_timeout_ms);
            if (!preq.ok) {
                static const char bad[] =
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                ncp_send_all(client, reinterpret_cast<const uint8_t*>(bad),
                             sizeof(bad) - 1);
                return;
            }
        }

        if (preq.udp_associate) {
            run_udp_session(client, peer, peer_len);
            return;
        }

        const std::string host_norm = HostlistMatcher::normalize(preq.host);
        bool conn_reset = false;
        ncp_socket_t upstream = impl->connect_target(
            preq.host, preq.port, impl->cfg.connect_timeout_ms, &conn_reset);
        if (upstream == NCP_INVALID_SOCK) {
            if (conn_reset) {
                impl->cnt.rst_blocks++;
                if (impl->cfg.detector) impl->cfg.detector->on_connect_reset(host_norm);
                if (impl->cfg.auto_hostlist)
                    impl->cfg.auto_hostlist->record_blocked(host_norm);
            } else if (impl->cfg.detector) {
                impl->cfg.detector->on_timeout(host_norm);
            }
            if (is_socks) socks5_reply(client, 0x05);
            else {
                static const char bad[] =
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                ncp_send_all(client, reinterpret_cast<const uint8_t*>(bad),
                             sizeof(bad) - 1);
            }
            return;
        }
        impl->track(upstream);
        struct UpGuard {
            Impl* i; ncp_socket_t s;
            ~UpGuard() { i->close_sock(s); }
        } up_guard{impl, upstream};

        if (is_socks) {
            socks5_reply(client, 0x00);
        } else if (!preq.is_http_plain) {
            static const char ok[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
            if (!ncp_send_all(client, reinterpret_cast<const uint8_t*>(ok),
                              sizeof(ok) - 1))
                return;
        }

        const Impl::DesyncPlan plan =
            impl->plan_for(DPI::ZProto::TCP, preq.port, host_norm);

        std::atomic<bool> peer_done{false};
        bool first_data_seen = false;

        if (preq.is_http_plain && !preq.http_head.empty()) {
            if (!impl->send_first_payload(upstream, preq.http_head.data(),
                                          preq.http_head.size(), plan))
                return;
        }

        std::thread t_cs([&] {
            std::vector<uint8_t> buf(16384);
            bool first_payload = !preq.is_http_plain;
            while (impl->running.load() && !peer_done.load()) {
                int wr = ncp_wait_readable(client, 2000);
                if (wr < 0) break;
                if (wr == 0) continue;
                int n = ::recv(client, reinterpret_cast<char*>(buf.data()),
                               static_cast<int>(buf.size()), 0);
                if (n <= 0) break;
                impl->cnt.c2s += static_cast<uint64_t>(n);
                if (first_payload) {
                    first_payload = false;
                    if (!impl->send_first_payload(upstream, buf.data(),
                                                  static_cast<size_t>(n), plan))
                        break;
                } else if (!ncp_send_all(upstream, buf.data(),
                                         static_cast<size_t>(n))) {
                    break;
                }
            }
            peer_done = true;
        });

        std::thread t_sc([&] {
            impl->relay(upstream, client, true, host_norm,
                        &first_data_seen, &peer_done);
        });

    if (t_cs.joinable()) t_cs.join();
    if (t_sc.joinable()) t_sc.join();
}

bool DesyncProxy::start(const Config& cfg) {
    if (impl_->running.load()) return false;
    ncp_net_init();
    impl_->cfg = cfg;

    if (cfg.use_doh) {
        try {
            DoHClient::Config doh_cfg;
            doh_cfg.provider = DoHClient::Provider::CLOUDFLARE_PRIMARY;
            doh_cfg.timeout_ms = 4000;
            doh_cfg.fallback_to_system_dns = true;
            impl_->doh = std::make_unique<DoHClient>(doh_cfg);
        } catch (const std::exception& e) {
            impl_->log(std::string("proxy: DoH init failed: ") + e.what());
        }
    } else {
        impl_->doh.reset();
    }

    impl_->chain_patterns.clear();
    impl_->chain_patterns.resize(cfg.chains.size());
    for (size_t i = 0; i < cfg.chains.size(); ++i) {
        const auto& c = cfg.chains[i];
        if (c.hostlist.empty()) continue;
        HostlistMatcher m;
        std::string path = c.hostlist;
        if (!cfg.hostlist_dir.empty() && path.find('/') == std::string::npos &&
            path.find('\\') == std::string::npos)
            path = cfg.hostlist_dir + "/" + path;
        if (m.load(path) >= 0) impl_->chain_patterns[i] = m.entries();
        else impl_->log("proxy: cannot load hostlist " + path);
    }

    ncp_socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == NCP_INVALID_SOCK) return false;

    int one = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&one), sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg.port);
    if (cfg.listen_host.empty() || cfg.listen_host == "127.0.0.1" ||
        cfg.listen_host == "localhost")
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    else if (cfg.listen_host == "0.0.0.0")
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (::inet_pton(AF_INET, cfg.listen_host.c_str(), &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        NCP_CLOSE_SOCKET(s);
        return false;
    }
    if (::listen(s, 64) < 0) {
        NCP_CLOSE_SOCKET(s);
        return false;
    }
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bl);
    impl_->bound_port_ = ntohs(bound.sin_port);
    impl_->listen_sock = s;
    impl_->running.store(true);

    impl_->accept_thread = std::thread([this] {
        while (impl_->running.load()) {
            int wr = ncp_wait_readable(impl_->listen_sock, 500);
            if (wr <= 0) continue;
            sockaddr_storage peer{};
            socklen_t pl = sizeof(peer);
            ncp_socket_t c = ::accept(impl_->listen_sock,
                                      reinterpret_cast<sockaddr*>(&peer), &pl);
            if (c == NCP_INVALID_SOCK) continue;
            impl_->track(c);
            std::thread(&Impl::handle_tcp, impl_.get(), c, peer, pl)
                .detach();
        }
    });
    impl_->log("proxy: listening on " + cfg.listen_host + ":" +
               std::to_string(impl_->bound_port_));
    return true;
}

void DesyncProxy::stop() {
    if (!impl_->running.exchange(false)) return;
    if (impl_->listen_sock != NCP_INVALID_SOCK) {
        NCP_CLOSE_SOCKET(impl_->listen_sock);
        impl_->listen_sock = NCP_INVALID_SOCK;
    }
    if (impl_->accept_thread.joinable()) impl_->accept_thread.join();
    std::set<ncp_socket_t> copy;
    {
        std::lock_guard<std::mutex> lk(impl_->socks_mu);
        copy = impl_->open_socks;
    }
    for (ncp_socket_t s : copy) {
#ifdef _WIN32
        ::shutdown(s, SD_BOTH);
#else
        ::shutdown(s, SHUT_RDWR);
#endif
        NCP_CLOSE_SOCKET(s);
    }
    {
        std::lock_guard<std::mutex> lk(impl_->socks_mu);
        impl_->open_socks.clear();
    }
    impl_->bound_port_ = 0;
}

} // namespace ncp
