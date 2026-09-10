/**
 * @file ncp_cps.cpp
 * @brief CPS chains — pre-handshake fake packet sequences (see ncp_cps.hpp)
 */

#include "ncp_cps.hpp"
#include "ncp_timer_range.hpp"
#include "ncp_winsock_init.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <thread>

#include <sodium.h>

#ifndef _WIN32
# include <arpa/inet.h>
# include <netdb.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <unistd.h>
#endif

namespace ncp {
namespace cps {

namespace {

void append_u16be(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void append_u32be(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 3; i >= 0; --i)
        v.push_back(static_cast<uint8_t>((x >> (i * 8)) & 0xFF));
}

bool valid_domain(const std::string& d) {
    if (d.empty() || d.size() > 253) return false;
    for (char ch : d) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (!std::isalnum(c) && c != '.' && c != '-') return false;
    }
    return true;
}

} // namespace

// ==================== Chain parsing ====================

std::optional<CpsChain> CpsChain::parse(const std::string& spec) {
    CpsChain chain;
    size_t pos = 0;
    while (pos <= spec.size()) {
        const size_t semi = spec.find(';', pos);
        const std::string tok =
            spec.substr(pos, semi == std::string::npos ? std::string::npos
                                                       : semi - pos);
        pos = (semi == std::string::npos) ? spec.size() + 1 : semi + 1;
        if (tok.empty()) continue;

        const size_t colon = tok.find(':');
        const std::string name = tok.substr(0, colon);
        const std::string arg =
            colon == std::string::npos ? "" : tok.substr(colon + 1);

        CpsStep st;
        if (name == "dns") {
            if (!valid_domain(arg)) return std::nullopt;
            st.kind = StepKind::DNS_QUERY;
            st.arg = arg;
        } else if (name == "quic") {
            if (!arg.empty() && !valid_domain(arg)) return std::nullopt;
            st.kind = StepKind::QUIC_INITIAL;
            st.arg = arg;
        } else if (name == "tls") {
            if (!valid_domain(arg)) return std::nullopt;
            st.kind = StepKind::TLS_CLIENT_HELLO;
            st.arg = arg;
        } else if (name == "hex") {
            if (hex_decode(arg).empty()) return std::nullopt;
            st.kind = StepKind::RAW_BYTES;
            st.arg = arg;
        } else if (name == "wait") {
            const auto range = TimerRange::parse(arg);
            if (!range || range->max_ms > 60000) return std::nullopt;
            st.kind = StepKind::WAIT;
            st.wait_min_ms = static_cast<uint32_t>(range->min_ms);
            st.wait_max_ms = static_cast<uint32_t>(range->max_ms);
        } else {
            return std::nullopt;
        }
        chain.steps.push_back(std::move(st));
    }
    if (chain.steps.empty())
        return std::nullopt;
    return chain;
}

std::string CpsChain::to_string() const {
    std::string out;
    for (size_t i = 0; i < steps.size(); ++i) {
        if (i) out += ';';
        const CpsStep& s = steps[i];
        switch (s.kind) {
        case StepKind::DNS_QUERY:        out += "dns:" + s.arg; break;
        case StepKind::QUIC_INITIAL:
            out += s.arg.empty() ? "quic" : "quic:" + s.arg;
            break;
        case StepKind::TLS_CLIENT_HELLO: out += "tls:" + s.arg; break;
        case StepKind::RAW_BYTES:        out += "hex:" + s.arg; break;
        case StepKind::WAIT:
            out += "wait:" + std::to_string(s.wait_min_ms);
            if (s.wait_max_ms > s.wait_min_ms)
                out += "-" + std::to_string(s.wait_max_ms);
            break;
        }
    }
    return out;
}

// ==================== Packet builders ====================

std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    int hi = -1;
    for (char ch : hex) {
        if (std::isspace(static_cast<unsigned char>(ch))) continue;
        const auto val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }(ch);
        if (val < 0) return {};
        if (hi < 0) {
            hi = val;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | val));
            hi = -1;
        }
    }
    if (hi >= 0 || out.empty()) return {};
    return out;
}

std::vector<uint8_t> build_dns_query(const std::string& domain) {
    if (!valid_domain(domain)) return {};
    std::vector<uint8_t> out;
    out.reserve(12 + domain.size() + 6);
    // Header: random txid, flags=0x0100 (RD), QDCOUNT=1.
    append_u16be(out, static_cast<uint16_t>(randombytes_uniform(0x10000)));
    append_u16be(out, 0x0100);
    append_u16be(out, 1);
    append_u16be(out, 0);
    append_u16be(out, 0);
    append_u16be(out, 0);
    // QNAME as labels.
    size_t start = 0;
    while (start <= domain.size()) {
        const size_t dot = domain.find('.', start);
        const size_t end = (dot == std::string::npos) ? domain.size() : dot;
        const size_t len = end - start;
        if (len == 0 || len > 63) return {};
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), domain.begin() + static_cast<long>(start),
                   domain.begin() + static_cast<long>(end));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);          // root label
    append_u16be(out, 1);      // QTYPE A
    append_u16be(out, 1);      // QCLASS IN
    return out;
}

std::vector<uint8_t> build_quic_initial(const std::string& sni) {
    (void)sni;  // SNI lives inside the (here fake) CRYPTO frames; the
                // decoy only needs a plausible long-header shape.
    std::vector<uint8_t> out;
    out.reserve(1250);
    // Long header, Initial, "packet number length" bits randomised.
    out.push_back(static_cast<uint8_t>(0xC0 | randombytes_uniform(0x10)));
    append_u32be(out, 0x00000001);            // QUIC v1
    // DCID: 8-20 random bytes.
    const uint8_t dcid_len = static_cast<uint8_t>(8 + randombytes_uniform(13));
    out.push_back(dcid_len);
    for (uint8_t i = 0; i < dcid_len; ++i)
        out.push_back(static_cast<uint8_t>(randombytes_uniform(256)));
    // SCID: 8 random bytes.
    out.push_back(8);
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>(randombytes_uniform(256)));
    out.push_back(0);                         // token length 0
    // Remaining length as a 2-byte varint (0x4000 | len), then payload.
    const size_t header_len = out.size() + 2;
    const size_t total = 1200 + randombytes_uniform(51);  // 1200..1250
    const uint16_t rem = static_cast<uint16_t>(total - header_len);
    append_u16be(out, static_cast<uint16_t>(0x4000 | rem));
    const size_t old = out.size();
    out.resize(total);
    randombytes_buf(out.data() + old, total - old);
    return out;
}

std::vector<uint8_t> build_tls_client_hello(const std::string& domain) {
    if (!valid_domain(domain)) return {};
    std::vector<uint8_t> body;
    body.reserve(256);
    body.push_back(0x03); body.push_back(0x03);   // TLS 1.2 legacy version
    for (int i = 0; i < 32; ++i)                  // random
        body.push_back(static_cast<uint8_t>(randombytes_uniform(256)));
    body.push_back(0);                            // session id len
    // cipher suites: a few common ones
    static const uint16_t suites[] = {0x1301, 0x1302, 0x1303,
                                      0xC02F, 0xC030, 0xCCA8};
    append_u16be(body, static_cast<uint16_t>(sizeof(suites)));
    for (uint16_t s : suites) append_u16be(body, s);
    body.push_back(1); body.push_back(0);         // compression: null

    // extensions: SNI + supported_versions(TLS1.3) + supported_groups
    std::vector<uint8_t> ext;
    // SNI
    std::vector<uint8_t> sni;
    append_u16be(sni, static_cast<uint16_t>(domain.size() + 3));
    sni.push_back(0);  // host_name
    append_u16be(sni, static_cast<uint16_t>(domain.size()));
    sni.insert(sni.end(), domain.begin(), domain.end());
    append_u16be(ext, 0x0000);
    append_u16be(ext, static_cast<uint16_t>(sni.size()));
    ext.insert(ext.end(), sni.begin(), sni.end());
    // supported_versions: TLS 1.3, 1.2
    append_u16be(ext, 0x002B);
    append_u16be(ext, 5);
    ext.push_back(4);
    append_u16be(ext, 0x0304);
    append_u16be(ext, 0x0303);
    // supported_groups: x25519, secp256r1
    append_u16be(ext, 0x000A);
    append_u16be(ext, 6);
    append_u16be(ext, 4);
    append_u16be(ext, 0x001D);
    append_u16be(ext, 0x0017);

    append_u16be(body, static_cast<uint16_t>(ext.size()));
    body.insert(body.end(), ext.begin(), ext.end());

    // handshake header
    std::vector<uint8_t> hs;
    hs.push_back(0x01);  // ClientHello
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xFF));
    hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
    hs.push_back(static_cast<uint8_t>(body.size() & 0xFF));
    hs.insert(hs.end(), body.begin(), body.end());

    // record header
    std::vector<uint8_t> rec;
    rec.push_back(0x16); rec.push_back(0x03); rec.push_back(0x01);
    append_u16be(rec, static_cast<uint16_t>(hs.size()));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return rec;
}

std::vector<uint8_t> build_packet(const CpsStep& step) {
    switch (step.kind) {
    case StepKind::DNS_QUERY:        return build_dns_query(step.arg);
    case StepKind::QUIC_INITIAL:     return build_quic_initial(step.arg);
    case StepKind::TLS_CLIENT_HELLO: return build_tls_client_hello(step.arg);
    case StepKind::RAW_BYTES:        return hex_decode(step.arg);
    case StepKind::WAIT:             return {};
    }
    return {};
}

// ==================== Executors ====================

namespace {

void sleep_step(const CpsStep& st) {
    TimerRange range{static_cast<double>(st.wait_min_ms),
                     static_cast<double>(st.wait_max_ms)};
    const auto ms = range.sample_ms();
    if (ms.count() > 0)
        std::this_thread::sleep_for(ms);
}

int udp_sendto(const std::vector<uint8_t>& pkt,
               const struct sockaddr* addr, socklen_t addrlen,
               socket_t sock) {
#ifdef _WIN32
    return ::sendto(sock, reinterpret_cast<const char*>(pkt.data()),
                    static_cast<int>(pkt.size()), 0, addr, addrlen);
#else
    return static_cast<int>(::sendto(sock, pkt.data(), pkt.size(), 0,
                                     addr, addrlen));
#endif
}

} // namespace

bool execute_chain_udp(const CpsChain& chain,
                       const std::string& host, uint16_t port,
                       std::string* err) {
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
#ifdef _WIN32
    if (!winsock_init()) {
        if (err) *err = "WSAStartup failed";
        return false;
    }
    if (InetPtonA(AF_INET, host.c_str(), &dst.sin_addr) != 1) {
#else
    if (::inet_pton(AF_INET, host.c_str(), &dst.sin_addr) != 1) {
#endif
        if (err) *err = "bad IPv4 address: " + host;
        return false;
    }
#ifdef _WIN32
    socket_t sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == kInvalidSocket) {
#else
    socket_t sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
#endif
        if (err) *err = "socket() failed";
        return false;
    }
    bool ok = true;
    for (const auto& st : chain.steps) {
        if (st.kind == StepKind::WAIT) {
            sleep_step(st);
            continue;
        }
        const std::vector<uint8_t> pkt = build_packet(st);
        if (pkt.empty()) continue;
        if (udp_sendto(pkt, reinterpret_cast<struct sockaddr*>(&dst),
                       sizeof(dst), sock) != static_cast<int>(pkt.size())) {
            if (err) *err = "sendto() failed";
            ok = false;
            break;
        }
    }
#ifdef _WIN32
    ::closesocket(sock);
#else
    ::close(sock);
#endif
    return ok;
}

bool execute_chain_tcp(const CpsChain& chain,
                       const std::string& host, uint16_t port,
                       std::string* err) {
    struct sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
#ifdef _WIN32
    if (!winsock_init()) {
        if (err) *err = "WSAStartup failed";
        return false;
    }
    if (InetPtonA(AF_INET, host.c_str(), &dst.sin_addr) != 1) {
#else
    if (::inet_pton(AF_INET, host.c_str(), &dst.sin_addr) != 1) {
#endif
        if (err) *err = "bad IPv4 address: " + host;
        return false;
    }
#ifdef _WIN32
    socket_t sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == kInvalidSocket) {
#else
    socket_t sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#endif
        if (err) *err = "socket() failed";
        return false;
    }
    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&dst),
                  sizeof(dst)) != 0) {
        if (err) *err = "connect() failed";
#ifdef _WIN32
        ::closesocket(sock);
#else
        ::close(sock);
#endif
        return false;
    }
    bool ok = true;
    for (const auto& st : chain.steps) {
        if (st.kind == StepKind::WAIT) {
            sleep_step(st);
            continue;
        }
        const std::vector<uint8_t> pkt = build_packet(st);
        if (pkt.empty()) continue;
        size_t sent = 0;
        while (sent < pkt.size()) {
#ifdef _WIN32
            const int n = ::send(sock,
                                 reinterpret_cast<const char*>(pkt.data() + sent),
                                 static_cast<int>(pkt.size() - sent), 0);
#else
            const ssize_t n = ::send(sock, pkt.data() + sent,
                                     pkt.size() - sent, 0);
#endif
            if (n <= 0) {
                if (err) *err = "send() failed";
                ok = false;
                break;
            }
            sent += static_cast<size_t>(n);
        }
        if (!ok) break;
    }
#ifdef _WIN32
    ::closesocket(sock);
#else
    ::close(sock);
#endif
    return ok;
}

} // namespace cps
} // namespace ncp
