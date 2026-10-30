// ═══════════════════════════════════════════════════════════════════════════
// ncp_quic_cli — minimal echo client/server CLI over ncp::RealQuicEndpoint,
// used ONLY for independent interoperability testing of the G4 real QUIC
// transport against distinct stacks (aioquic, ngtcp2) over UDP loopback.
//
// Protocol: one application message per bidirectional stream; sender writes
// payload + FIN; echo peer returns the same payload + FIN on the same stream.
// ALPN is configurable (default "ncp-echo").
//
// Build (see build.sh):
//   g++ -std=c++17 -O2 ncp_quic_cli.cpp <repo>/src/core/src/ncp_real_quic.cpp
//       -Iinclude -I<repo>/src/core/include -I<repo>/third_party/msquic/include
//       -l:libmsquic.so.2 -lpthread -o ncp_quic_cli
//
// Usage:
//   ncp_quic_cli server --port P --cert C --key K [--bind IP] [--alpn A]
//                       [--datagram] [--max-messages N] [--max-datagrams N]
//                       [--unidi N]
//   ncp_quic_cli client --host H --port P [--alpn A] [--sni NAME]
//                       (--ca FILE | --insecure) [--size N] [--count N]
//                       [--datagram [--dgram-count N] [--dgram-size N]]
//
// Exit code 0 and "INTEROP_OK" on success; nonzero and "INTEROP_FAIL"
// otherwise. Prints "CONNECTED" when the TLS 1.3 handshake completes.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_real_quic.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop = true; }

const char* arg_value(int argc, char** argv, const char* name,
                      const char* def = nullptr) {
    for (int i = 1; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    return def;
}
bool has_flag(int argc, char** argv, const char* name) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], name) == 0) return true;
    return false;
}

std::vector<uint8_t> make_payload(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i)
        v[i] = static_cast<uint8_t>(seed + (i * 131u) % 251u);
    return v;
}

// ──── Minimal HTTP/3 (RFC 9114) / QPACK (RFC 9204) helpers ────────────────
// Lab-harness only, used by --h3 mode. We never send an H3 SETTINGS frame
// (RealQuicEndpoint cannot open unidirectional streams, so no client/server
// control stream is possible), hence the RFC 9114 default
// QPACK_MAX_TABLE_CAPACITY=0 applies and the peer's encoder must not use the
// dynamic table. Only static-table indexed lines and literal lines are
// handled; Huffman-coded string literals are skipped, not decoded.

void put_varint(std::vector<uint8_t>& out, uint64_t v) {
    if (v < 64) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v < 16384) {
        out.push_back(static_cast<uint8_t>(0x40 | (v >> 8)));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    } else {  // sufficient for lab frame sizes
        out.push_back(static_cast<uint8_t>(0x80 | ((v >> 24) & 0x3F)));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    }
}

bool get_varint(const uint8_t*& p, const uint8_t* end, uint64_t& v) {
    if (p >= end) return false;
    const uint8_t b = *p++;
    const int len = 1 << (b >> 6);
    v = b & 0x3F;
    for (int i = 1; i < len; ++i) {
        if (p >= end) return false;
        v = (v << 8) | *p++;
    }
    return true;
}

// QPACK prefixed integer (prefix already consumed in `first`).
bool get_prefixed_int(const uint8_t*& p, const uint8_t* end, uint8_t first,
                      int prefix_bits, uint64_t& v) {
    const uint64_t mask = (1u << prefix_bits) - 1;
    v = first & mask;
    if (v < mask) return true;
    uint64_t m = 0;
    uint8_t b;
    do {
        if (p >= end) return false;
        b = *p++;
        v += static_cast<uint64_t>(b & 0x7F) << m;
        m += 7;
        if (m > 56) return false;
    } while (b & 0x80);
    return true;
}

// QPACK static table :status entries (RFC 9204 Appendix A); -1 = not status.
int qpack_static_status(uint64_t idx) {
    switch (idx) {
        case 24: return 103;
        case 25: return 200;
        case 26: return 304;
        case 27: return 404;
        case 28: return 503;
        default: return -1;
    }
}

struct H3FieldSection {
    bool valid = false;          // structurally valid, dynamic-table-free
    bool saw_get = false;        // :method GET (static index 17) present
    int status = -1;             // decoded :status, -1 if absent
    bool huffman_status = false; // :status present but Huffman-coded
};

H3FieldSection qpack_parse_field_section(const uint8_t* p,
                                         const uint8_t* end) {
    H3FieldSection info;
    const uint8_t* q = p;
    uint64_t dummy;
    if (q >= end) return info;
    {  // Required Insert Count (8-bit prefix)
        uint8_t f = *q++;
        if (!get_prefixed_int(q, end, f, 8, dummy)) return info;
    }
    if (q >= end) return info;
    {  // Base (sign bit + 7-bit prefix)
        uint8_t f = *q++;
        if (!get_prefixed_int(q, end, f, 7, dummy)) return info;
    }
    while (q < end) {
        const uint8_t b = *q++;
        if (b & 0x80) {  // Indexed Field Line
            uint64_t idx;
            if (!get_prefixed_int(q, end, b, 6, idx)) return info;
            if (b & 0x40) {  // static table
                const int st = qpack_static_status(idx);
                if (st > 0) info.status = st;
                if (idx == 17) info.saw_get = true;
            }
        } else if (b & 0x40) {  // Literal Field Line With Name Reference
            uint64_t name_idx;
            if (!get_prefixed_int(q, end, b, 4, name_idx)) return info;
            const bool is_static = (b & 0x10) != 0;
            if (q >= end) return info;
            const uint8_t vb = *q++;
            uint64_t vlen;
            if (!get_prefixed_int(q, end, vb, 7, vlen)) return info;
            if (static_cast<uint64_t>(end - q) < vlen) return info;
            if (is_static && qpack_static_status(name_idx) > 0) {
                if ((vb & 0x80) != 0) {
                    info.huffman_status = true;
                } else if (vlen == 3 && q[0] >= '0' && q[0] <= '9') {
                    info.status = (q[0] - '0') * 100 + (q[1] - '0') * 10 +
                                  (q[2] - '0');
                }
            }
            q += vlen;
        } else if ((b & 0xE0) == 0x20) {  // Literal Without Name Reference
            uint64_t nlen;
            if (!get_prefixed_int(q, end, b, 3, nlen)) return info;
            if (static_cast<uint64_t>(end - q) < nlen) return info;
            q += nlen;
            if (q >= end) return info;
            const uint8_t vb = *q++;
            uint64_t vlen;
            if (!get_prefixed_int(q, end, vb, 7, vlen)) return info;
            if (static_cast<uint64_t>(end - q) < vlen) return info;
            q += vlen;
        } else {
            // Post-base encodings require the dynamic table: must not occur.
            return info;
        }
    }
    info.valid = true;
    return info;
}

// Build a minimal H3 GET request HEADERS frame (QPACK static table only).
std::vector<uint8_t> h3_get_request(const std::string& authority,
                                    const std::string& path) {
    std::vector<uint8_t> fs = {0x00, 0x00};  // RIC=0, Base=0
    fs.push_back(0xC0 | 17);                 // :method GET (static 17)
    fs.push_back(0xC0 | 23);                 // :scheme https (static 23)
    fs.push_back(0x50 | 1);                  // :path, name ref static 1
    fs.push_back(static_cast<uint8_t>(path.size()));
    fs.insert(fs.end(), path.begin(), path.end());
    fs.push_back(0x50 | 0);                  // :authority, name ref static 0
    fs.push_back(static_cast<uint8_t>(authority.size()));
    fs.insert(fs.end(), authority.begin(), authority.end());
    std::vector<uint8_t> out;
    put_varint(out, 0x01);  // HEADERS frame
    put_varint(out, fs.size());
    out.insert(out.end(), fs.begin(), fs.end());
    return out;
}

// Build a minimal H3 200 response (HEADERS + DATA) with a static QPACK
// :status and an explicit content-length.
std::vector<uint8_t> h3_response_200(const std::string& body) {
    std::vector<uint8_t> fs = {0x00, 0x00};
    fs.push_back(0xC0 | 25);  // :status 200 (static 25)
    fs.push_back(0x50 | 4);   // content-length, name ref static 4
    const std::string len = std::to_string(body.size());
    fs.push_back(static_cast<uint8_t>(len.size()));
    fs.insert(fs.end(), len.begin(), len.end());
    std::vector<uint8_t> out;
    put_varint(out, 0x01);  // HEADERS frame
    put_varint(out, fs.size());
    out.insert(out.end(), fs.begin(), fs.end());
    put_varint(out, 0x00);  // DATA frame
    put_varint(out, body.size());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// True when buf starts with a structurally valid H3 HEADERS frame whose
// field section contains :method GET.
bool h3_is_get_request(const std::vector<uint8_t>& buf) {
    const uint8_t* p = buf.data();
    const uint8_t* end = p + buf.size();
    uint64_t type, len;
    if (!get_varint(p, end, type) || type != 0x01) return false;
    if (!get_varint(p, end, len)) return false;
    if (static_cast<uint64_t>(end - p) < len) return false;
    const H3FieldSection info = qpack_parse_field_section(p, p + len);
    return info.valid && info.saw_get;
}

// Walk H3 response frames. True when at least one structurally valid
// HEADERS frame with a :status field (decoded or Huffman-coded) was found.
bool h3_parse_response(const std::vector<uint8_t>& buf, int& status,
                       size_t& data_bytes, bool& huffman_status) {
    const uint8_t* p = buf.data();
    const uint8_t* end = p + buf.size();
    bool got_headers = false;
    status = -1;
    data_bytes = 0;
    huffman_status = false;
    while (p < end) {
        uint64_t type, len;
        if (!get_varint(p, end, type) || !get_varint(p, end, len))
            return false;
        if (static_cast<uint64_t>(end - p) < len) return false;
        if (type == 0x01) {  // HEADERS
            const H3FieldSection info = qpack_parse_field_section(p, p + len);
            if (!info.valid) return false;
            got_headers = true;
            if (info.status >= 0) status = info.status;
            if (info.huffman_status) huffman_status = true;
        } else if (type == 0x00) {  // DATA
            data_bytes += len;
        }
        p += len;  // unknown frame types are skipped per RFC 9114
    }
    return got_headers && (status >= 0 || huffman_status);
}

int run_server(int argc, char** argv) {
    ncp::RealQuicEndpoint::Config cfg;
    cfg.role = ncp::RealQuicEndpoint::Role::Server;
    cfg.local_address = arg_value(argc, argv, "--bind", "127.0.0.1");
    cfg.local_port = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--port", "0")));
    cfg.certificate_file = arg_value(argc, argv, "--cert", "");
    cfg.private_key_file = arg_value(argc, argv, "--key", "");
    cfg.alpn = arg_value(argc, argv, "--alpn", "ncp-echo");
    cfg.enable_datagrams = has_flag(argc, argv, "--datagram");
    const bool h3_mode = has_flag(argc, argv, "--h3");
    // H3 peers (ngtcp2) require >=3 unidirectional streams.
    cfg.peer_unidi_stream_count = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--unidi", "0")));
    const int max_messages =
        std::stoi(arg_value(argc, argv, "--max-messages", "0"));
    const int max_datagrams =
        std::stoi(arg_value(argc, argv, "--max-datagrams", "0"));

    ncp::RealQuicEndpoint server(cfg);
    if (!server.start()) {
        std::fprintf(stderr, "INTEROP_FAIL server start: %s\n",
                     server.last_error().c_str());
        return 2;
    }
    // Harness synchronization line.
    std::printf("LISTENING %s\n", server.local_address_str().c_str());
    std::fflush(stdout);

    // Quota semantics: a quota of 0 means "no requirement" for that class.
    // With no quotas at all the server runs until killed (legacy behavior).
    int handled = 0;
    int dgrams_handled = 0;
    const bool any_quota = (max_messages > 0) || (max_datagrams > 0);
    auto quotas_met = [&]() {
        const bool msgs_done = (max_messages == 0) || (handled >= max_messages);
        const bool dgrams_done =
            (max_datagrams == 0) || (dgrams_handled >= max_datagrams);
        return any_quota && msgs_done && dgrams_done;
    };
    while (!g_stop.load() && !quotas_met()) {
        ncp::RealQuicEndpoint::Message m;
        if (server.recv_message(m, 250)) {
            if (h3_mode) {
                // H3 mode: the "message" must be a complete H3 request
                // (HEADERS frame + FIN on a client request stream). Answer
                // with a minimal, well-formed H3 200 response.
                if (!h3_is_get_request(m.payload)) {
                    std::printf("H3_BAD_REQUEST stream=%llu bytes=%zu\n",
                                static_cast<unsigned long long>(m.stream_id),
                                m.payload.size());
                    std::fflush(stdout);
                    continue;
                }
                const auto resp = h3_response_200("ncp-h3-echo\n");
                if (!server.respond(m.connection_id, m.stream_id, resp)) {
                    std::fprintf(stderr, "INTEROP_FAIL h3 respond: %s\n",
                                 server.last_error().c_str());
                    return 3;
                }
                ++handled;
                std::printf("H3_RESPONDED stream=%llu status=200 body=%zu\n",
                            static_cast<unsigned long long>(m.stream_id),
                            resp.size());
                std::fflush(stdout);
                continue;
            }
            if (!server.respond(m.connection_id, m.stream_id, m.payload)) {
                std::fprintf(stderr, "INTEROP_FAIL respond: %s\n",
                             server.last_error().c_str());
                return 3;
            }
            ++handled;
            std::printf("ECHOED conn=%llu stream=%llu bytes=%zu\n",
                        static_cast<unsigned long long>(m.connection_id),
                        static_cast<unsigned long long>(m.stream_id),
                        m.payload.size());
            std::fflush(stdout);
        }
        ncp::RealQuicEndpoint::Datagram d;
        if (cfg.enable_datagrams && server.recv_datagram(d, 10)) {
            server.send_datagram(d.payload, d.connection_id);
            ++dgrams_handled;
            std::printf("ECHOED_DGRAM conn=%llu bytes=%zu\n",
                        static_cast<unsigned long long>(d.connection_id),
                        d.payload.size());
            std::fflush(stdout);
        }
    }
    if (handled > 0 || dgrams_handled > 0) {
        // Grace period: respond()/send_datagram() queue the final echo
        // asynchronously; ConnectionShutdown would abort open streams and
        // could discard in-flight echo bytes/datagrams, so give them time
        // to be delivered.
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
    std::printf("SERVER_DONE handled=%d dgrams=%d\n", handled, dgrams_handled);
    return 0;
}

int run_client(int argc, char** argv) {
    ncp::RealQuicEndpoint::Config cfg;
    cfg.role = ncp::RealQuicEndpoint::Role::Client;
    cfg.local_address = arg_value(argc, argv, "--bind", "127.0.0.1");
    cfg.remote_address = arg_value(argc, argv, "--host", "127.0.0.1");
    cfg.remote_port = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--port", "0")));
    cfg.alpn = arg_value(argc, argv, "--alpn", "ncp-echo");
    cfg.enable_datagrams = has_flag(argc, argv, "--datagram");
    cfg.peer_unidi_stream_count = static_cast<uint16_t>(
        std::stoi(arg_value(argc, argv, "--unidi", "0")));
    const char* ca = arg_value(argc, argv, "--ca", nullptr);
    const char* sni = arg_value(argc, argv, "--sni", nullptr);
    if (ca) cfg.ca_file = ca;
    else if (has_flag(argc, argv, "--insecure")) cfg.insecure_skip_verify = true;
    if (sni) cfg.server_name = sni;
    const int count = std::stoi(arg_value(argc, argv, "--count", "4"));
    const size_t base = std::stoul(arg_value(argc, argv, "--size", "512"));

    ncp::RealQuicEndpoint client(cfg);
    if (!client.start()) {
        std::fprintf(stderr, "INTEROP_FAIL client start: %s\n",
                     client.last_error().c_str());
        return 2;
    }
    if (!client.wait_connected(10000)) {
        std::fprintf(stderr, "INTEROP_FAIL handshake: %s\n",
                     client.last_error().c_str());
        return 3;
    }
    std::printf("CONNECTED local=%s remote=%s\n",
                client.local_address_str().c_str(),
                client.remote_address_str().c_str());
    std::fflush(stdout);

    if (has_flag(argc, argv, "--h3")) {
        // Minimal H3 client: send a GET request (QPACK static-table-only
        // HEADERS) on a request stream and validate the peer's H3 response
        // frames. NOTE: we cannot send an H3 control stream/SETTINGS (the
        // endpoint has no unidirectional-stream send API), so RFC 9114
        // defaults apply; this is logged for verdict qualification.
        std::printf("H3_NOTE no client control stream/SETTINGS sent "
                    "(no unidi send API); RFC 9114 defaults apply\n");
        std::fflush(stdout);
        const std::string authority =
            cfg.remote_address + ":" + std::to_string(cfg.remote_port);
        const auto req = h3_get_request(authority, "/index.html");
        uint64_t sid = UINT64_MAX;
        if (!client.send_message(req, &sid)) {
            std::fprintf(stderr, "INTEROP_FAIL h3 send: %s\n",
                         client.last_error().c_str());
            return 4;
        }
        std::printf("H3_REQUEST_SENT stream=%llu bytes=%zu\n",
                    static_cast<unsigned long long>(sid), req.size());
        std::fflush(stdout);
        ncp::RealQuicEndpoint::Message resp;
        if (!client.recv_message(resp, 15000) || resp.stream_id != sid) {
            std::fprintf(stderr, "INTEROP_FAIL h3 response timeout\n");
            return 5;
        }
        int status = -1;
        size_t data_bytes = 0;
        bool huffman_status = false;
        if (!h3_parse_response(resp.payload, status, data_bytes,
                               huffman_status)) {
            std::fprintf(stderr,
                         "INTEROP_FAIL h3 response parse (%zu bytes)\n",
                         resp.payload.size());
            return 6;
        }
        std::printf("H3_RESPONSE stream=%llu status=%d%s data_bytes=%zu\n",
                    static_cast<unsigned long long>(sid), status,
                    huffman_status ? "(huffman)" : "", data_bytes);
        std::printf("INTEROP_OK h3=1\n");
        return 0;
    }

    for (int i = 0; i < count; ++i) {
        const size_t n = base + static_cast<size_t>(i) * 977;
        const auto payload = make_payload(n, static_cast<uint8_t>(i * 17));
        uint64_t sid = UINT64_MAX;
        if (!client.send_message(payload, &sid)) {
            std::fprintf(stderr, "INTEROP_FAIL send: %s\n",
                         client.last_error().c_str());
            return 4;
        }
        ncp::RealQuicEndpoint::Message echo;
        if (!client.recv_message(echo, 15000)) {
            std::fprintf(stderr, "INTEROP_FAIL echo timeout msg=%d\n", i);
            return 5;
        }
        if (echo.payload != payload || echo.stream_id != sid) {
            std::fprintf(stderr,
                         "INTEROP_FAIL echo mismatch msg=%d "
                         "(got %zu bytes, want %zu)\n",
                         i, echo.payload.size(), payload.size());
            return 6;
        }
        std::printf("ECHO_OK stream=%llu bytes=%zu\n",
                    static_cast<unsigned long long>(sid), payload.size());
        std::fflush(stdout);
    }

    if (cfg.enable_datagrams) {
        const int dgram_count =
            std::stoi(arg_value(argc, argv, "--dgram-count", "4"));
        const size_t dgram_base =
            std::stoul(arg_value(argc, argv, "--dgram-size", "600"));
        for (int i = 0; i < 60 && client.datagram_max_send_length() == 0; ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const uint16_t maxd = client.datagram_max_send_length();
        if (maxd == 0) {
            std::fprintf(stderr, "INTEROP_FAIL datagram not negotiated\n");
            return 7;
        }
        std::printf("DGRAM_NEGOTIATED max_send_length=%u\n",
                    static_cast<unsigned>(maxd));
        std::fflush(stdout);
        for (int i = 0; i < dgram_count; ++i) {
            const size_t dn = std::min<size_t>(
                dgram_base + static_cast<size_t>(i) * 113, maxd);
            const auto d = make_payload(
                dn, static_cast<uint8_t>(0x5A + i * 7));
            if (!client.send_datagram(d)) {
                std::fprintf(stderr, "INTEROP_FAIL datagram send: %s\n",
                             client.last_error().c_str());
                return 8;
            }
            ncp::RealQuicEndpoint::Datagram echo;
            if (!client.recv_datagram(echo, 10000) || echo.payload != d) {
                std::fprintf(stderr,
                             "INTEROP_FAIL datagram echo msg=%d\n", i);
                return 9;
            }
            std::printf("DGRAM_OK bytes=%zu\n", d.size());
            std::fflush(stdout);
        }
    }

    std::printf("INTEROP_OK messages=%d\n", count);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    if (argc < 2) {
        std::fprintf(stderr, "usage: ncp_quic_cli server|client ...\n");
        return 64;
    }
    if (std::strcmp(argv[1], "server") == 0) return run_server(argc, argv);
    if (std::strcmp(argv[1], "client") == 0) return run_client(argc, argv);
    std::fprintf(stderr, "unknown mode '%s'\n", argv[1]);
    return 64;
}
