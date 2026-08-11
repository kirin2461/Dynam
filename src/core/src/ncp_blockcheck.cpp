#include "ncp_blockcheck.hpp"

#include "ncp_proxy.hpp"
#include "ncp_tls_parse.hpp"

#include <algorithm>
#include <chrono>
#include <initializer_list>
#include <mutex>
#include <cstring>
#include <sstream>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    using bc_socket_t = SOCKET;
    #define BC_INVALID_SOCK INVALID_SOCKET
    #define BC_CLOSE(s) closesocket(s)
    static int bc_err() { return WSAGetLastError(); }
    #define BC_ECONNRESET WSAECONNRESET
    #define BC_EINPROGRESS WSAEINPROGRESS
    #define BC_EWOULDBLOCK WSAEWOULDBLOCK
#else
    #include <arpa/inet.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <poll.h>
    #include <sys/socket.h>
    #include <unistd.h>
    using bc_socket_t = int;
    #define BC_INVALID_SOCK (-1)
    #define BC_CLOSE(s) ::close(s)
    static int bc_err() { return errno; }
    #define BC_ECONNRESET ECONNRESET
    #define BC_EINPROGRESS EINPROGRESS
    #define BC_EWOULDBLOCK EAGAIN
#endif

namespace ncp {

namespace {

void bc_net_init() {
#ifdef _WIN32
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    });
#endif
}

int bc_wait(bc_socket_t s, bool write, int timeout_ms) {
#ifdef _WIN32
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    fd_set efds;
    FD_ZERO(&efds);
    FD_SET(s, &efds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    return select(0, write ? nullptr : &fds, write ? &fds : nullptr, &efds, &tv);
#else
    pollfd pfd{s, static_cast<short>(write ? POLLOUT : POLLIN), 0};
    return ::poll(&pfd, 1, timeout_ms);
#endif
}

bc_socket_t bc_connect(const char* host, uint16_t port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host, std::to_string(port).c_str(), &hints, &res) != 0 || !res)
        return BC_INVALID_SOCK;
    bc_socket_t out = BC_INVALID_SOCK;
    for (addrinfo* ai = res; ai && out == BC_INVALID_SOCK; ai = ai->ai_next) {
        bc_socket_t s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == BC_INVALID_SOCK) continue;
#ifdef _WIN32
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
#else
        int fl = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
        int r = ::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (r < 0) {
            int e = bc_err();
            if (e != BC_EINPROGRESS && e != BC_EWOULDBLOCK) {
                BC_CLOSE(s);
                continue;
            }
            if (bc_wait(s, true, timeout_ms) <= 0) {
                BC_CLOSE(s);
                continue;
            }
            int so_err = 0;
            socklen_t sl = sizeof(so_err);
            ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &sl);
            if (so_err != 0) {
                BC_CLOSE(s);
                continue;
            }
        }
#ifdef _WIN32
        u_long b = 0;
        ioctlsocket(s, FIONBIO, &b);
#else
        fcntl(s, F_SETFL, fl);
#endif
        out = s;
    }
    ::freeaddrinfo(res);
    return out;
}

bool bc_send_all(bc_socket_t s, const uint8_t* d, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        int r = ::send(s, reinterpret_cast<const char*>(d + sent),
                       static_cast<int>(n - sent), 0);
        if (r <= 0) return false;
        sent += static_cast<size_t>(r);
    }
    return true;
}

std::string json_esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
        else if (c == '\n') o += "\\n";
        else o.push_back(c);
    }
    return o;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// TLS ClientHello builder
// ─────────────────────────────────────────────────────────────────────────────
std::vector<uint8_t> BlockChecker::build_client_hello(const std::string& sni) {
    std::vector<uint8_t> b;
    auto u8 = [&](uint8_t v) { b.push_back(v); };
    auto u16 = [&](uint16_t v) {
        b.push_back(static_cast<uint8_t>(v >> 8));
        b.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    // ── handshake body ──
    std::vector<uint8_t> hs;
    auto h8 = [&](uint8_t v) { hs.push_back(v); };
    auto h16 = [&](uint16_t v) {
        hs.push_back(static_cast<uint8_t>(v >> 8));
        hs.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    h8(0x03); h8(0x03);            // client_version TLS 1.2
    for (int i = 0; i < 32; ++i) h8(static_cast<uint8_t>(0xA0 + i));  // random
    h8(0x00);                       // session_id len
    // cipher suites
    const uint16_t ciphers[] = {0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0xCCA9, 0xCCA8};
    h16(static_cast<uint16_t>(2 * (sizeof(ciphers) / sizeof(ciphers[0]))));
    for (uint16_t cs : ciphers) h16(cs);
    h8(0x01); h8(0x00);             // compression: null

    // ── extensions ──
    std::vector<uint8_t> ext;
    auto e16 = [&](uint16_t v) {
        ext.push_back(static_cast<uint8_t>(v >> 8));
        ext.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    // server_name
    e16(0x0000);
    e16(static_cast<uint16_t>(sni.size() + 5));
    e16(static_cast<uint16_t>(sni.size() + 3));
    ext.push_back(0x00);
    e16(static_cast<uint16_t>(sni.size()));
    ext.insert(ext.end(), sni.begin(), sni.end());
    // supported_versions (TLS 1.3 + 1.2)
    e16(0x002B); e16(5); ext.push_back(4); e16(0x0304); e16(0x0303);
    // supported_groups
    e16(0x000A); e16(6); e16(0x001D); e16(0x0017);
    // ec_point_formats
    e16(0x000B); e16(2); ext.push_back(1); ext.push_back(0);
    // signature_algorithms
    e16(0x000D); e16(8); e16(0x0403); e16(0x0804); e16(0x0401); e16(0x0501);
    // key_share (x25519, 32 zero bytes — enough to elicit ServerHello/HRR)
    e16(0x0033); e16(36); e16(34); e16(0x001D); e16(32);
    for (int i = 0; i < 32; ++i) ext.push_back(static_cast<uint8_t>(i + 1));

    h16(static_cast<uint16_t>(ext.size()));
    hs.insert(hs.end(), ext.begin(), ext.end());

    // ── record ──
    u8(0x16); u8(0x03); u8(0x01);
    u16(static_cast<uint16_t>(hs.size() + 4));
    u8(0x01);                                        // ClientHello
    b.push_back(static_cast<uint8_t>((hs.size() >> 16) & 0xFF));
    b.push_back(static_cast<uint8_t>((hs.size() >> 8) & 0xFF));
    b.push_back(static_cast<uint8_t>(hs.size() & 0xFF));
    b.insert(b.end(), hs.begin(), hs.end());
    return b;
}

// ─────────────────────────────────────────────────────────────────────────────
// Probes
// ─────────────────────────────────────────────────────────────────────────────
BlockcheckProbe BlockChecker::probe_via_socks5(uint16_t proxy_port,
                                               const std::string& domain,
                                               int timeout_ms) {
    bc_net_init();
    BlockcheckProbe p;
    p.domain = domain;
    const auto t0 = std::chrono::steady_clock::now();

    bc_socket_t s = bc_connect("127.0.0.1", proxy_port, timeout_ms);
    if (s == BC_INVALID_SOCK) { p.fail_reason = "proxy"; return p; }
    struct G { bc_socket_t s; ~G() { BC_CLOSE(s); } } g{s};

    // greeting
    const uint8_t greet[3] = {0x05, 0x01, 0x00};
    if (!bc_send_all(s, greet, 3)) { p.fail_reason = "proxy"; return p; }
    uint8_t resp[2];
    if (bc_wait(s, false, timeout_ms) <= 0 ||
        ::recv(s, reinterpret_cast<char*>(resp), 2, 0) != 2 || resp[1] != 0x00) {
        p.fail_reason = "proxy";
        return p;
    }
    // CONNECT domain:443
    std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x03,
                                static_cast<uint8_t>(domain.size())};
    req.insert(req.end(), domain.begin(), domain.end());
    req.push_back(0x01); req.push_back(0xBB);  // 443
    if (!bc_send_all(s, req.data(), req.size())) { p.fail_reason = "proxy"; return p; }
    uint8_t rrep[10];
    if (bc_wait(s, false, timeout_ms) <= 0) { p.fail_reason = "timeout"; return p; }
    int rn = ::recv(s, reinterpret_cast<char*>(rrep), sizeof(rrep), 0);
    if (rn < 2) {
        p.fail_reason = (rn < 0 && bc_err() == BC_ECONNRESET) ? "rst" : "proxy";
        return p;
    }
    if (rrep[1] != 0x00) { p.fail_reason = "connect"; return p; }

    // send ClientHello, await any response
    auto ch = build_client_hello(domain);
    if (!bc_send_all(s, ch.data(), ch.size())) { p.fail_reason = "rst"; return p; }
    int wr = bc_wait(s, false, timeout_ms);
    if (wr == 0) { p.fail_reason = "timeout"; return p; }
    if (wr < 0) { p.fail_reason = "rst"; return p; }
    uint8_t buf[8];
    int n = ::recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
    if (n <= 0) {
        p.fail_reason = (n < 0 && bc_err() == BC_ECONNRESET) ? "rst" : "timeout";
        return p;
    }
    p.ok = true;
    p.latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
    return p;
}

BlockcheckProbe BlockChecker::probe_direct(const std::string& domain, int timeout_ms) {
    bc_net_init();
    BlockcheckProbe p;
    p.domain = domain;
    const auto t0 = std::chrono::steady_clock::now();
    bc_socket_t s = bc_connect(domain.c_str(), 443, timeout_ms);
    if (s == BC_INVALID_SOCK) { p.fail_reason = "connect"; return p; }
    struct G { bc_socket_t s; ~G() { BC_CLOSE(s); } } g{s};
    auto ch = build_client_hello(domain);
    if (!bc_send_all(s, ch.data(), ch.size())) { p.fail_reason = "rst"; return p; }
    int wr = bc_wait(s, false, timeout_ms);
    if (wr == 0) { p.fail_reason = "timeout"; return p; }
    if (wr < 0) { p.fail_reason = "rst"; return p; }
    uint8_t buf[8];
    int n = ::recv(s, reinterpret_cast<char*>(buf), sizeof(buf), 0);
    if (n <= 0) {
        p.fail_reason = (n < 0 && bc_err() == BC_ECONNRESET) ? "rst" : "timeout";
        return p;
    }
    p.ok = true;
    p.latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
    return p;
}

// ─────────────────────────────────────────────────────────────────────────────
// Defaults
// ─────────────────────────────────────────────────────────────────────────────
std::vector<std::string> BlockChecker::default_domains() {
    return {"youtube.com", "discord.com", "instagram.com", "x.com",
            "whatsapp.com", "rutracker.org"};
}

std::vector<BlockcheckStrategy> BlockChecker::default_strategies() {
    std::vector<BlockcheckStrategy> out;
    auto mk = [](const char* name, const char* desc) {
        BlockcheckStrategy s;
        s.name = name;
        s.description = desc;
        return s;
    };
    {
        auto s = mk("direct", "Baseline (no bypass)");
        s.is_direct = true;
        out.push_back(s);
    }
    auto mk_split = [&](const char* name, const char* desc, int pos) {
        auto s = mk(name, desc);
        s.config.enable_tcp_split = true;
        s.config.split_position = pos;
        s.config.split_at_sni = false;
        s.config.enable_noise = false;
        s.config.enable_fake_packet = false;
        s.config.enable_disorder = false;
        out.push_back(s);
    };
    mk_split("split-1", "TCP split at 1", 1);
    mk_split("split-2", "TCP split at 2", 2);
    mk_split("split-3", "TCP split at 3", 3);
    mk_split("split-5", "TCP split at 5", 5);
    {
        auto s = mk("split-sni", "Split at SNI start");
        s.config.enable_tcp_split = false;
        s.config.split_at_sni = true;
        s.config.enable_noise = false;
        s.config.enable_fake_packet = false;
        s.config.enable_disorder = false;
        out.push_back(s);
    }
    auto mk_multi = [&](const char* name, const char* desc,
                        std::initializer_list<int> positions, bool at_sni) {
        auto s = mk(name, desc);
        s.config.enable_tcp_split = false;
        s.config.enable_multi_layer_split = true;
        s.config.split_positions.assign(positions.begin(), positions.end());
        s.config.split_at_sni = at_sni;
        s.config.enable_noise = false;
        s.config.enable_fake_packet = false;
        s.config.enable_disorder = false;
        out.push_back(s);
    };
    mk_multi("multisplit-1-2", "Multisplit {1,2}", {1, 2}, false);
    mk_multi("multisplit-1-sni", "Multisplit {1,SNI}", {1}, true);
    mk_multi("multisplit-2-5", "Multisplit {2,5}", {2, 5}, false);

    // chain-based strategies (zapret markers)
    auto mk_chain = [&](const char* name, const char* desc,
                        DPI::ZSplitPosType t1, int o1,
                        DPI::ZSplitPosType t2, int o2, bool two) {
        auto s = mk(name, desc);
        s.use_chain = true;
        s.chain.proto = DPI::ZProto::TCP;
        s.chain.ports.emplace_back(443, 443);
        s.chain.phase1 = DPI::ZDesyncPhase1::NONE;
        s.chain.phase2 = DPI::ZDesyncPhase2::MULTISPLIT;
        s.chain.split_positions.push_back(DPI::ZSplitPos{t1, o1});
        if (two) s.chain.split_positions.push_back(DPI::ZSplitPos{t2, o2});
        out.push_back(s);
    };
    mk_chain("split-midsld", "Split at middle of SLD",
             DPI::ZSplitPosType::MIDSLD, 0, DPI::ZSplitPosType::NUMERIC, 0, false);
    mk_chain("multisplit-1-midsld", "Multisplit {1,midsld}",
             DPI::ZSplitPosType::NUMERIC, 1, DPI::ZSplitPosType::MIDSLD, 0, true);
    mk_chain("split-sniext", "Split at SNI extension",
             DPI::ZSplitPosType::SNIEXT, 0, DPI::ZSplitPosType::NUMERIC, 0, false);
    mk_chain("multisplit-1-sniext", "Multisplit {1,sniext}",
             DPI::ZSplitPosType::NUMERIC, 1, DPI::ZSplitPosType::SNIEXT, 0, true);
    mk_chain("split-endsld", "Split at end of SLD",
             DPI::ZSplitPosType::ENDSLD, 0, DPI::ZSplitPosType::NUMERIC, 0, false);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runner
// ─────────────────────────────────────────────────────────────────────────────
BlockcheckReport BlockChecker::run(const Config& cfg) {
    const auto t0 = std::chrono::steady_clock::now();
    BlockcheckReport rep;

    auto strategies = cfg.strategies.empty() ? default_strategies() : cfg.strategies;
    auto domains = cfg.domains.empty() ? default_domains() : cfg.domains;

    for (const auto& strat : strategies) {
        if (cfg.cancel_cb && cfg.cancel_cb()) break;
        BlockcheckStrategyResult sr;
        sr.strategy = strat.name;
        sr.description = strat.description;
        sr.total = static_cast<int>(domains.size());

        DesyncProxy proxy;
        uint16_t port = 0;
        if (!strat.is_direct) {
            DesyncProxy::Config pcfg;
            pcfg.port = 0;
            if (strat.use_chain) {
                pcfg.chains = {strat.chain};
                // neutral base — chain always matches (no hostlist)
                pcfg.base.enable_tcp_split = false;
            } else {
                pcfg.base = strat.config;
            }
            if (!proxy.start(pcfg)) {
                for (const auto& d : domains) {
                    BlockcheckProbe pr;
                    pr.domain = d;
                    pr.fail_reason = "proxy";
                    sr.probes.push_back(pr);
                }
                rep.results.push_back(sr);
                continue;
            }
            port = proxy.bound_port();
        }

        long latency_sum = 0;
        for (const auto& d : domains) {
            if (cfg.cancel_cb && cfg.cancel_cb()) break;
            BlockcheckProbe pr = strat.is_direct
                                     ? probe_direct(d, cfg.timeout_ms)
                                     : probe_via_socks5(port, d, cfg.timeout_ms);
            if (pr.ok) {
                sr.success_count++;
                latency_sum += pr.latency_ms;
            }
            if (cfg.progress_cb) cfg.progress_cb(strat.name, d, pr.ok);
            sr.probes.push_back(std::move(pr));
        }
        if (!strat.is_direct) proxy.stop();

        sr.avg_latency_ms =
            sr.success_count ? static_cast<double>(latency_sum) / sr.success_count : 0.0;
        sr.score = static_cast<long>(sr.success_count) * 100000L -
                   static_cast<long>(sr.avg_latency_ms);
        rep.results.push_back(std::move(sr));
    }

    // pick best: highest score; prefer non-direct bypass on tie
    long best_score = -1;
    for (const auto& sr : rep.results) {
        if (sr.score > best_score ||
            (sr.score == best_score && !rep.best_strategy.empty() &&
             rep.best_strategy == "direct" && sr.strategy != "direct")) {
            best_score = sr.score;
            rep.best_strategy = sr.strategy;
            rep.best_description = sr.description;
        }
    }
    for (const auto& s : strategies) {
        if (s.name == rep.best_strategy) {
            rep.best_config = s.config;
            rep.best_chain = s.chain;
            rep.best_uses_chain = s.use_chain;
            break;
        }
    }
    rep.duration_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count());
    return rep;
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON
// ─────────────────────────────────────────────────────────────────────────────
std::string BlockChecker::report_to_json(const BlockcheckReport& r) {
    std::ostringstream j;
    j << "{\n  \"best_strategy\": \"" << json_esc(r.best_strategy) << "\",\n";
    j << "  \"best_description\": \"" << json_esc(r.best_description) << "\",\n";
    j << "  \"duration_ms\": " << r.duration_ms << ",\n";
    j << "  \"results\": [\n";
    for (size_t i = 0; i < r.results.size(); ++i) {
        const auto& sr = r.results[i];
        j << "    {\"strategy\": \"" << json_esc(sr.strategy)
          << "\", \"description\": \"" << json_esc(sr.description)
          << "\", \"success\": " << sr.success_count
          << ", \"total\": " << sr.total
          << ", \"avg_latency_ms\": " << sr.avg_latency_ms
          << ", \"score\": " << sr.score
          << ", \"probes\": [";
        for (size_t k = 0; k < sr.probes.size(); ++k) {
            const auto& p = sr.probes[k];
            j << (k ? ", " : "")
              << "{\"domain\": \"" << json_esc(p.domain)
              << "\", \"ok\": " << (p.ok ? "true" : "false");
            if (!p.ok) j << ", \"fail\": \"" << json_esc(p.fail_reason) << "\"";
            else j << ", \"latency_ms\": " << p.latency_ms;
            j << "}";
        }
        j << "]}" << (i + 1 < r.results.size() ? "," : "") << "\n";
    }
    j << "  ]\n}\n";
    return j.str();
}

std::string BlockChecker::best_strategy_to_profile_json(const BlockcheckReport& r) {
    std::ostringstream j;
    j << "{\n  \"strategy\": \"" << json_esc(r.best_strategy) << "\",\n";
    j << "  \"description\": \"" << json_esc(r.best_description) << "\",\n";
    if (r.best_uses_chain) {
        j << "  \"type\": \"zapret_chain\",\n";
        j << "  \"chain_cmdline\": \"" << json_esc(DPI::chain_to_cmdline(r.best_chain))
          << "\",\n";
        j << "  \"split_positions\": [";
        for (size_t i = 0; i < r.best_chain.split_positions.size(); ++i) {
            j << (i ? ", " : "") << "\""
              << json_esc(DPI::split_pos_to_string(r.best_chain.split_positions[i]))
              << "\"";
        }
        j << "]\n";
    } else {
        j << "  \"type\": \"dpi_config\",\n";
        j << "  \"enable_tcp_split\": "
          << (r.best_config.enable_tcp_split ? "true" : "false") << ",\n";
        j << "  \"split_position\": " << r.best_config.split_position << ",\n";
        j << "  \"split_at_sni\": " << (r.best_config.split_at_sni ? "true" : "false")
          << ",\n";
        j << "  \"enable_multi_layer_split\": "
          << (r.best_config.enable_multi_layer_split ? "true" : "false") << ",\n";
        j << "  \"split_positions\": [";
        for (size_t i = 0; i < r.best_config.split_positions.size(); ++i) {
            j << (i ? ", " : "") << r.best_config.split_positions[i];
        }
        j << "]\n";
    }
    j << "}\n";
    return j.str();
}

} // namespace ncp
