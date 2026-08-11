#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP TLS/HTTP parsing helpers — pure functions, no I/O, unit-testable.
//
// Used by the desync proxy and block checker to locate split positions
// inside TLS ClientHello / HTTP request payloads.
// ═══════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

namespace ncp {

struct TlsClientHelloInfo {
    bool valid = false;
    std::string sni;            // server_name value (empty if absent)
    size_t record_len = 0;      // total TLS record length (incl. 5-byte header), 0 if unknown
    size_t sni_ext_offset = 0;  // offset of the SNI extension header (type field)
    size_t sni_value_offset = 0;// offset of the hostname bytes
    size_t sni_value_len = 0;   // hostname length
};

inline bool is_tls_client_hello(const uint8_t* data, size_t len) {
    return data && len > 5 && data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01;
}

// Parse a TLS ClientHello record, locating the SNI extension.
// Tolerant: returns valid=true with empty sni if there is no SNI extension.
inline TlsClientHelloInfo parse_tls_client_hello(const uint8_t* data, size_t len) {
    TlsClientHelloInfo info;
    if (!is_tls_client_hello(data, len)) return info;

    const size_t rec_len = 5 + ((static_cast<size_t>(data[3]) << 8) | data[4]);
    if (rec_len > len) return info;  // truncated record
    info.record_len = rec_len;

    size_t pos = 5;
    if (pos + 4 > len) return info;
    // handshake type already verified (0x01)
    const uint32_t hs_len = (static_cast<uint32_t>(data[pos + 1]) << 16) |
                            (static_cast<uint32_t>(data[pos + 2]) << 8) |
                            static_cast<uint32_t>(data[pos + 3]);
    if (hs_len + 9 > len) return info;
    pos += 4;

    if (pos + 2 + 32 + 1 > len) return info;
    pos += 2;   // client_version
    pos += 32;  // random

    const uint8_t sid_len = data[pos];
    pos += 1;
    if (pos + sid_len > len) return info;
    pos += sid_len;

    if (pos + 2 > len) return info;
    const uint16_t cs_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (pos + cs_len > len) return info;
    pos += cs_len;

    if (pos + 1 > len) return info;
    const uint8_t comp_len = data[pos];
    pos += 1;
    if (pos + comp_len > len) return info;
    pos += comp_len;

    if (pos + 2 > len) return info;
    const uint16_t ext_total = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (pos + ext_total > len) return info;

    const size_t ext_end = pos + ext_total;
    while (pos + 4 <= ext_end) {
        const uint16_t etype = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
        const uint16_t elen = (static_cast<uint16_t>(data[pos + 2]) << 8) | data[pos + 3];
        if (pos + 4 + elen > ext_end) break;
        if (etype == 0x0000 && elen >= 5) {  // server_name
            // ext data: list_len(2) + type(1) + name_len(2) + name
            const size_t name_off = pos + 4 + 5;
            const uint16_t name_len = (static_cast<uint16_t>(data[pos + 4 + 3]) << 8) |
                                      data[pos + 4 + 4];
            if (name_off + name_len <= ext_end && data[pos + 4 + 2] == 0x00) {
                info.valid = true;
                info.sni_ext_offset = pos;
                info.sni_value_offset = name_off;
                info.sni_value_len = name_len;
                info.sni.assign(reinterpret_cast<const char*>(data + name_off), name_len);
                return info;
            }
        }
        pos += 4 + elen;
    }
    info.valid = true;  // valid CH without SNI
    return info;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────────────────────────────────────

struct HttpRequestInfo {
    bool valid = false;
    bool is_connect = false;
    std::string method;          // "GET", "CONNECT", ...
    std::string target;          // request-target (origin form or authority for CONNECT)
    std::string host;            // Host header value (without port)
    size_t method_end = 0;       // offset just after method token
    size_t host_value_offset = 0;
    size_t host_value_len = 0;   // without optional :port
    size_t headers_end = 0;      // offset just after the final CRLFCRLF
};

// Parse an HTTP/1.x request header block. len need only cover the headers.
inline HttpRequestInfo parse_http_request(const uint8_t* data, size_t len) {
    HttpRequestInfo info;
    if (!data || len < 14) return info;
    const char* p = reinterpret_cast<const char*>(data);

    // request line: METHOD SP TARGET SP HTTP/1.x CRLF
    const size_t sp1 = std::string(p, len < 64 ? len : 64).find(' ');
    if (sp1 == std::string::npos || sp1 == 0 || sp1 > 10) return info;
    info.method.assign(p, sp1);
    for (char c : info.method)
        if (c < 'A' || c > 'Z') return info;

    const std::string rest(p + sp1 + 1, len - sp1 - 1);
    const size_t sp2 = rest.find(' ');
    if (sp2 == std::string::npos) return info;
    info.target = rest.substr(0, sp2);
    const size_t line_end = rest.find("\r\n");
    if (line_end == std::string::npos) return info;

    info.method_end = sp1;
    info.is_connect = (info.method == "CONNECT");

    // scan headers for Host:
    size_t hpos = sp1 + 1 + line_end + 2;
    while (hpos + 2 <= len) {
        const char* nl = static_cast<const char*>(memchr(p + hpos, '\n', len - hpos));
        if (!nl) break;
        size_t line_len = static_cast<size_t>(nl - (p + hpos));
        if (line_len >= 1 && p[hpos + line_len - 1] == '\r') line_len -= 1;
        if (line_len == 0) {  // empty line = end of headers
            info.headers_end = static_cast<size_t>(nl - p) + 1;
            break;
        }
        if (line_len >= 5 &&
            (p[hpos] == 'H' || p[hpos] == 'h') &&
            (p[hpos + 1] == 'o' || p[hpos + 1] == 'O') &&
            (p[hpos + 2] == 's' || p[hpos + 2] == 'S') &&
            (p[hpos + 3] == 't' || p[hpos + 3] == 'T') &&
            p[hpos + 4] == ':') {
            size_t v = hpos + 5;
            while (v < hpos + line_len && (p[v] == ' ' || p[v] == '\t')) ++v;
            size_t vend = hpos + line_len;
            // strip :port
            size_t colon = v;
            bool has_colon = false;
            for (size_t i = v; i < vend; ++i) {
                if (p[i] == ':') { colon = i; has_colon = true; break; }
            }
            const size_t hend = has_colon ? colon : vend;
            info.host.assign(p + v, hend - v);
            info.host_value_offset = v;
            info.host_value_len = hend - v;
        }
        hpos = static_cast<size_t>(nl - p) + 1;
    }
    info.valid = true;
    return info;
}

// ─────────────────────────────────────────────────────────────────────────────
// SLD (second-level domain) helpers for split markers
// ─────────────────────────────────────────────────────────────────────────────

// Given a hostname, return offset of the second-level domain start.
// e.g. "www.example.com" -> 4 ; "example.com" -> 0 ; "a.b.co.uk" -> 4 (approx).
inline size_t sld_start_offset(const std::string& host) {
    if (host.empty()) return 0;
    // find last two dots
    const size_t last_dot = host.rfind('.');
    if (last_dot == std::string::npos) return 0;
    const size_t prev_dot = host.rfind('.', last_dot - 1);
    if (prev_dot == std::string::npos) return 0;
    // common two-level TLDs
    const std::string tld2 = host.substr(prev_dot + 1);  // e.g. "co.uk"
    static const char* kTwoLevel[] = {"co.uk", "org.uk", "com.au", "net.au", "co.jp",
                                      "com.br", "com.cn", "com.ru", "co.kr", "com.tw"};
    for (const char* t : kTwoLevel) {
        if (tld2 == t) {
            const size_t d3 = host.rfind('.', prev_dot - 1);
            return d3 == std::string::npos ? 0 : d3 + 1;
        }
    }
    return prev_dot + 1;
}

} // namespace ncp
