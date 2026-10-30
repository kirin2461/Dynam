// ══════════════════════════════════════════════════════════════════════════════
// tests/test_udp_profile_transition.cpp
//
// Mandatory REAL-transport evidence for the generic per-session profile
// transition layer (ncp_profile_transition.hpp):
//
//   * Transport: ncp::PortHopClient / ncp::PortHopServer over real 127.0.0.1
//     UDP sockets (dynamic port bases, bounded pumps, NO fixed sleeps as
//     correctness criteria). PortHop payloads carry serialized E2E wire bytes.
//   * Crypto: ncp::E2ESession with a real X25519 handshake + double ratchet +
//     AEAD; SessionProfileContext::Crypto is adapted 1:1 to
//     E2EUtils::serialize_message / deserialize_message. All crypto calls are
//     exception-guarded at the adapter boundary.
//   * One SessionProfileContext per protected session; received datagrams are
//     fed to contexts AFTER PortHop::poll() returned (outside PortHop locks);
//     tick() is driven from the poll loop with a real monotonic ms clock.
//   * Capability negotiation: profile_transition_v1 (NCPCapabilities
//     reserved[0] bit 0x01) established with a direct tagged capabilities
//     exchange over the real UDP link (E2E-encrypted); a legacy-negative case
//     proves the wire format is unchanged when the bit is absent.
//   * Impairments (control-datagram loss, duplicates, corruption) are applied
//     deterministically at the harness send/receive edges; the client/server
//     path itself always goes through the real sockets. Impaired runs are
//     compared against an identical no-switch control (same deterministic
//     application stream, same SHA-256). No zero-UDP-loss promises are made.
//
// SCOPE: this is loopback protocol evidence only. It is NOT live external DPI
// evidence and makes no claim about DPI systems.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_porthop.hpp"
#include "ncp_e2e.hpp"
#include "ncp_profile_transition.hpp"
#include "ncp_capabilities.hpp"
#include "ncp_mimicry_stats.hpp"

#include <sodium.h>

#include <array>
#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace ncp;

namespace {

// ── Time ────────────────────────────────────────────────────────────────────

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// ── Profiles / layouts (test-local catalog) ──────────────────────────────────

ProfileRef make_ref(const char* id, uint32_t rev, uint8_t hash_fill) {
    ProfileRef r;
    r.id = id;
    r.revision = rev;
    r.content_hash.fill(hash_fill);
    return r;
}

const ProfileRef kP0 = make_ref("baseline.udp", 1, 0xA0);
const ProfileRef kP1 = make_ref("mimic.webrtc", 2, 0xB0);
const ProfileRef kP2 = make_ref("mimic.http2", 1, 0xC0);
/// Same id/revision as kP1 but a wrong content hash — resolver must reject.
const ProfileRef kP1BadHash = make_ref("mimic.webrtc", 2, 0x66);

const ProfileLayoutParams kL0{0, 0};    // no padding (stable layout)
const ProfileLayoutParams kL1{64, 16};  // block-padded mask (16-byte blocks)
const ProfileLayoutParams kL2{48, 8};   // 8-byte blocks

/// Read-only resolver over the test-local catalog.
std::optional<ProfileLayoutParams> resolve_test_layout(const ProfileRef& ref) {
    if (ref == kP0) return kL0;
    if (ref == kP1) return kL1;
    if (ref == kP2) return kL2;
    return std::nullopt;
}

// Data-body framing mirrors src/core/src/ncp_profile_transition.cpp:
// 'P','D',ver(1),epoch(4 BE),plen(2 BE),payload,zero-pad to block.
constexpr size_t kDataBodyHeader = 2 + 1 + 4 + 2;

size_t framed_body_len(size_t payload_len, uint32_t padding_block) {
    size_t n = kDataBodyHeader + payload_len;
    if (padding_block > 1) {
        const size_t rem = n % padding_block;
        if (rem) n += padding_block - rem;
    }
    return n;
}

// ── Deterministic application stream ─────────────────────────────────────────
// payload(dir, seq): fully deterministic so an independent no-switch control
// produces byte-identical streams and identical SHA-256 digests.

size_t app_payload_len(uint32_t seq) { return 20 + (seq % 7) * 3; }

std::vector<uint8_t> make_app_payload(uint8_t dir, uint32_t seq) {
    std::vector<uint8_t> p(app_payload_len(seq));
    p[0] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(seq & 0xFF);
    p[4] = dir;
    for (size_t i = 5; i < p.size(); ++i)
        p[i] = static_cast<uint8_t>((seq * 31u + i * 7u + dir) & 0xFF);
    return p;
}

struct Sha256 {
    crypto_hash_sha256_state st;
    Sha256() { crypto_hash_sha256_init(&st); }
    void update(const std::vector<uint8_t>& v) {
        crypto_hash_sha256_update(&st, v.data(),
                                  static_cast<unsigned long long>(v.size()));
    }
    std::array<uint8_t, 32> final() {
        std::array<uint8_t, 32> out{};
        crypto_hash_sha256_state copy = st;
        crypto_hash_sha256_final(&copy, out.data());
        return out;
    }
};

std::array<uint8_t, 32> expected_stream_hash(uint8_t dir, uint32_t first_seq,
                                             uint32_t count) {
    Sha256 h;
    for (uint32_t s = first_seq; s < first_seq + count; ++s)
        h.update(make_app_payload(dir, s));
    return h.final();
}

/// Receiver-side ordered-stream tracker: no duplicates, no gaps unless a
/// datagram was intentionally impaired by the test itself.
struct AppRecvTracker {
    uint32_t expected_seq = 0;
    uint64_t received = 0;
    uint64_t duplicates = 0;
    uint64_t gaps = 0;        // sequences skipped forward (impairment-induced)
    Sha256 hash;

    void feed(const std::vector<uint8_t>& p) {
        ASSERT_GE(p.size(), 5u) << "app payload too small";
        const uint32_t seq = (static_cast<uint32_t>(p[0]) << 24) |
                             (static_cast<uint32_t>(p[1]) << 16) |
                             (static_cast<uint32_t>(p[2]) << 8) |
                             static_cast<uint32_t>(p[3]);
        if (seq < expected_seq) { ++duplicates; return; }
        if (seq > expected_seq) {
            gaps += seq - expected_seq;
            expected_seq = seq;
        }
        ++expected_seq;
        ++received;
        hash.update(p);
    }
};

// ── Dynamic loopback port base ───────────────────────────────────────────────
// PortHopServer binds one SO_REUSEPORT socket per port in [base, base+range);
// probe every port with a plain (non-reuseport) bind first so a colliding
// test binary cannot silently steal datagrams.

bool port_available(uint16_t port) {
    winsock_init();
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == kInvalidSocket) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    const bool ok = (::bind(s, reinterpret_cast<sockaddr*>(&a),
                            sizeof(a)) == 0);
#ifdef _WIN32
    ::closesocket(s);
#else
    ::close(s);
#endif
    return ok;
}

std::optional<uint16_t> pick_port_base(uint16_t range) {
    winsock_init();
    for (int attempt = 0; attempt < 32; ++attempt) {
        socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (s == kInvalidSocket) return std::nullopt;
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;  // ephemeral
        if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
#ifdef _WIN32
            ::closesocket(s);
#else
            ::close(s);
#endif
            continue;
        }
        sockaddr_in bound{};
        socklen_t blen = sizeof(bound);
        uint16_t p = 0;
        if (::getsockname(s, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
            p = ntohs(bound.sin_port);
#ifdef _WIN32
        ::closesocket(s);
#else
        ::close(s);
#endif
        if (p == 0) continue;
        uint32_t base = p;
        if (base + range > 65535) base = 65535 - range;
        if (base < 1024) base = 1024;
        bool all_free = true;
        for (uint16_t i = 0; i < range; ++i) {
            if (!port_available(static_cast<uint16_t>(base + i))) {
                all_free = false;
                break;
            }
        }
        if (all_free) return static_cast<uint16_t>(base);
    }
    return std::nullopt;
}

} // namespace

namespace {

// ── Harness ─────────────────────────────────────────────────────────────────
//
// PH payload framing (harness-level, 1-byte kind tag):
//   'H' — raw E2E key-exchange blob (real X25519 handshake over UDP)
//   'C' — serialized EncryptedMessage of CapabilitiesExchange::wrap_capabilities
//   'E' — serialized EncryptedMessage produced/consumed by SessionProfileContext
//         (NCP-tagged PROFILE_TRANSITION control or DATA inside the AEAD)
//
// 'C' and 'E' ciphertexts share the same E2ESession; every ciphertext is
// decrypted exactly once, by the consumer its kind routes it to, so ratchet
// state stays consistent.

constexpr uint8_t kKindHandshake = 'H';
constexpr uint8_t kKindCaps      = 'C';
constexpr uint8_t kKindE2E       = 'E';

struct Endpoint {
    explicit Endpoint(bool client_side) : is_client(client_side) {}

    const bool is_client;
    E2ESession e2e{[] {
        E2EConfig c;
        c.enable_padding = false;  // deterministic wire sizes
        return c;
    }()};
    KeyPair keys;
    std::unique_ptr<SessionProfileContext> ctx;
    bool ctx_peer_capable = false;

    // ---- outbound queue (kind-tagged PH payloads) ----
    struct Out {
        std::vector<uint8_t> payload;  // kind byte + body
        bool is_control = false;
        TransitionMsgType ctype = TransitionMsgType::PREPARE;  // if is_control
    };
    std::deque<Out> tx_q;
    /// Impairment: drop the next N control datagrams of a given type at the
    /// send edge (deterministic — control type known from the plaintext tap).
    std::map<TransitionMsgType, size_t> drop_controls;

    // ---- taps (assertion evidence; never alter the wire) ----
    std::vector<std::pair<TransitionMsgType, std::vector<uint8_t>>> control_pt_tap;
    std::vector<std::pair<TransitionMsgType, std::vector<uint8_t>>> control_wire_tap;
    std::deque<TransitionMsgType> pending_ctypes;  // encrypt-tap → outbound tag
    struct DataTxRecord { uint32_t epoch; size_t wire_size; size_t payload_len; };
    std::vector<DataTxRecord> data_tx_log;

    // ---- observations ----
    std::vector<SwitchEvent> events;
    std::vector<std::pair<uint64_t, AbortReason>> aborts;
    std::vector<std::pair<uint32_t, uint32_t>> epoch_changes;
    AppRecvTracker app_rx;
    uint32_t app_tx_seq = 0;
    std::vector<size_t> rx_data_wire_sizes;  // PH body sizes that yielded app data
    std::optional<NCPCapabilities> peer_caps;
    std::vector<uint8_t> last_data_plaintext;  // sender-side tap (pre-AEAD)
    std::vector<uint8_t> last_data_datagram;   // kind-tagged PH payload
};

/// Crypto adapter: SessionProfileContext::Crypto bound 1:1 to E2EUtils
/// serialize/deserialize around the real ratcheted E2ESession. Every crypto
/// call is exception-guarded; failures are transport drops / empty wires
/// (the outbound handler silently drops empty wires).
SessionProfileContext::Crypto make_crypto(Endpoint& ep) {
    SessionProfileContext::Crypto c;
    c.encrypt = [&ep](const std::vector<uint8_t>& pt) -> std::vector<uint8_t> {
        try {
            if (CapabilitiesExchange::has_magic(pt) &&
                CapabilitiesExchange::peek_type(pt) ==
                    E2EMessageType::PROFILE_TRANSITION) {
                auto body = CapabilitiesExchange::unwrap(pt);
                auto cm = ProfileTransitionCodec::decode(body);
                if (cm) {
                    ep.control_pt_tap.emplace_back(cm->type, pt);
                    ep.pending_ctypes.push_back(cm->type);
                }
            } else if (CapabilitiesExchange::has_magic(pt) &&
                       CapabilitiesExchange::peek_type(pt) ==
                           E2EMessageType::DATA) {
                ep.last_data_plaintext = pt;  // sender-side layout evidence
            } else if (!pt.empty()) {
                ep.last_data_plaintext = pt;  // legacy (untagged) payload
            }
            return E2EUtils::serialize_message(ep.e2e.encrypt(pt));
        } catch (const std::exception&) {
            return {};
        } catch (...) {
            return {};
        }
    };
    c.decrypt = [&ep](const std::vector<uint8_t>& wire)
        -> std::optional<std::vector<uint8_t>> {
        try {
            auto m = E2EUtils::deserialize_message(wire);
            if (!m) return std::nullopt;
            return ep.e2e.decrypt(*m);
        } catch (const std::exception&) {
            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    };
    c.decrypt_ex = [&ep](const std::vector<uint8_t>& wire)
        -> std::optional<std::pair<std::vector<uint8_t>, uint64_t>> {
        try {
            auto m = E2EUtils::deserialize_message(wire);
            if (!m) return std::nullopt;
            auto pt = ep.e2e.decrypt(*m);
            if (!pt) return std::nullopt;
            return std::make_pair(std::move(*pt),
                                  static_cast<uint64_t>(
                                      m->header.message_number));
        } catch (const std::exception&) {
            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    };
    c.tx_crypto_counter = [&ep] {
        return static_cast<uint64_t>(ep.e2e.get_sending_chain_length());
    };
    c.rx_crypto_counter = [&ep] {
        return static_cast<uint64_t>(ep.e2e.get_receiving_chain_length());
    };
    return c;
}

struct Session;

struct Link {
    static constexpr uint16_t kRange = 8;
    static constexpr uint32_t kHopIntervalSec = 3600;  // no hops mid-test

    std::vector<uint8_t> secret;
    std::optional<PortHopServer> server;
    std::vector<std::unique_ptr<Session>> sessions;
    uint16_t base = 0;

    Link() {
        secret.resize(32);
        for (size_t i = 0; i < secret.size(); ++i)
            secret[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    ~Link() {
        sessions.clear();  // clients before server teardown
        if (server) server->close();
    }

    HopSchedule make_schedule() const {
        return HopSchedule(secret, base, kRange, kHopIntervalSec);
    }
};

struct Session {
    explicit Session(uint64_t ph_sid)
        : sid(ph_sid), cli(/*client_side=*/true), srv(/*client_side=*/false) {}

    uint64_t sid;
    Endpoint cli, srv;
    std::unique_ptr<PortHopClient> client;
    std::array<uint8_t, PROFILE_SESSION_ID_SIZE> profile_sid{};

    // Held data datagrams (sender-side "in flight" capture for grace tests;
    // released later as REAL datagrams — receiver sees a delayed/reordered
    // UDP packet, indistinguishable from a network hold).
    std::vector<std::vector<uint8_t>> held_data;
};

bool link_start(Link& L, size_t n_sessions) {
    for (int attempt = 0; attempt < 8 && !L.server; ++attempt) {
        auto base = pick_port_base(Link::kRange);
        if (!base) return false;
        // PortHopServer is non-movable: construct in place inside optional.
        L.server.emplace(HopSchedule(L.secret, *base, Link::kRange,
                                     Link::kHopIntervalSec));
        if (L.server->bind_all()) {
            L.base = *base;
            break;
        }
        L.server->close();
        L.server.reset();
    }
    if (!L.server || !L.server->is_bound()) return false;

    for (size_t i = 0; i < n_sessions; ++i) {
        uint64_t sid = 0;
        randombytes_buf(&sid, sizeof(sid));
        sid |= 1ULL;  // any nonzero
        auto s = std::make_unique<Session>(sid);
        L.server->register_session(sid);
        s->client = std::make_unique<PortHopClient>(
            "127.0.0.1", L.make_schedule(), sid);
        if (!s->client->open()) return false;
        L.sessions.push_back(std::move(s));
    }
    return true;
}

// ---- send path ----

void ph_send(Link& L, Session& s, const Endpoint& ep,
             const uint8_t* data, size_t len) {
    if (ep.is_client) {
        s.client->send(data, len);
    } else {
        L.server->send_to_session(s.sid, data, len);
    }
}

void queue_payload(Endpoint& ep, uint8_t kind,
                   const std::vector<uint8_t>& body,
                   bool is_control = false,
                   TransitionMsgType ctype = TransitionMsgType::PREPARE) {
    Endpoint::Out o;
    o.payload.reserve(1 + body.size());
    o.payload.push_back(kind);
    o.payload.insert(o.payload.end(), body.begin(), body.end());
    o.is_control = is_control;
    o.ctype = ctype;
    ep.tx_q.push_back(std::move(o));
}

/// Flush one endpoint's outbound queue to the real socket. Control
/// impairment (drop-by-type) is applied here, at the harness send edge.
void flush(Link& L, Session& s, Endpoint& ep) {
    while (!ep.tx_q.empty()) {
        auto o = std::move(ep.tx_q.front());
        ep.tx_q.pop_front();
        if (o.is_control) {
            ep.control_wire_tap.emplace_back(o.ctype, o.payload);
            auto it = ep.drop_controls.find(o.ctype);
            if (it != ep.drop_controls.end() && it->second > 0) {
                --it->second;
                continue;  // datagram "lost": never reaches the socket
            }
        }
        ph_send(L, s, ep, o.payload.data(), o.payload.size());
    }
}

void flush_all(Link& L) {
    for (auto& sp : L.sessions) {
        flush(L, *sp, sp->cli);
        flush(L, *sp, sp->srv);
    }
}

} // namespace

namespace {

// ---- receive path ----
// PortHop::poll() returns owned frame vectors (locks released); all context
// feeding below happens strictly OUTSIDE PortHop locks.

void dispatch_handshake(Session& s, Endpoint& ep,
                        const std::vector<uint8_t>& blob) {
    try {
        if (ep.is_client) {
            // key-exchange response
            (void)s;
            ep.e2e.complete_key_exchange(blob, ep.keys);
        } else {
            auto resp = ep.e2e.process_key_exchange_request(blob, ep.keys);
            queue_payload(ep, kKindHandshake, resp);
        }
    } catch (const std::exception&) {
        // malformed handshake blob: ignore (transport-level failure)
    }
}

void dispatch_caps(Session& s, Endpoint& ep,
                   const std::vector<uint8_t>& wire) {
    try {
        auto m = E2EUtils::deserialize_message(wire);
        if (!m) return;
        auto pt = ep.e2e.decrypt(*m);
        if (!pt) return;
        auto caps = CapabilitiesExchange::parse_capabilities(*pt);
        if (!caps) return;
        ep.peer_caps = *caps;
        if (ep.ctx)
            ep.ctx->set_peer_capable(
                capabilities_support_profile_transition(*caps));
        // server answers with its own capability advertisement
        if (!ep.is_client && !ep.ctx_peer_capable) {
            // reply generated by the caps helper after dispatch; flag only
        }
        (void)s;
    } catch (const std::exception&) {
    }
}

void dispatch_e2e(Session& s, Endpoint& ep,
                  const std::vector<uint8_t>& wire) {
    (void)s;
    if (!ep.ctx) return;
    auto app = ep.ctx->on_ciphertext(wire, now_ms());
    if (app) {
        ep.rx_data_wire_sizes.push_back(wire.size());
        ep.app_rx.feed(*app);
    }
}

void dispatch(Link& L, Session& s, Endpoint& ep,
              const uint8_t* data, size_t len) {
    if (len < 1) return;
    const uint8_t kind = data[0];
    std::vector<uint8_t> body(data + 1, data + len);
    switch (kind) {
        case kKindHandshake: dispatch_handshake(s, ep, body); break;
        case kKindCaps:      dispatch_caps(s, ep, body); break;
        case kKindE2E:       dispatch_e2e(s, ep, body); break;
        default: break;  // unknown harness kind: drop
    }
    (void)L;
}

void pump_client_rx(Link& L, Session& s, int timeout_ms) {
    auto frames = s.client->poll(timeout_ms);
    for (auto& r : frames)
        dispatch(L, s, s.cli, r.frame.payload.data(), r.frame.payload.size());
}

void pump_server_rx(Link& L, int timeout_ms) {
    if (!L.server) return;
    auto frames = L.server->poll(timeout_ms);
    for (auto& r : frames) {
        for (auto& sp : L.sessions) {
            if (sp->sid == r.frame.session_id) {
                dispatch(L, *sp, sp->srv,
                         r.frame.payload.data(), r.frame.payload.size());
                break;
            }
        }
    }
}

/// One deterministic scheduling step: flush pending sends, pump real
/// sockets, drive ticks from the poll loop with the real monotonic clock.
void pump_once(Link& L, int poll_ms) {
    flush_all(L);
    for (auto& sp : L.sessions) pump_client_rx(L, *sp, 0);
    pump_server_rx(L, poll_ms);
    for (auto& sp : L.sessions) pump_client_rx(L, *sp, 0);
    flush_all(L);  // messages emitted in reaction to RX leave promptly
    const uint64_t t = now_ms();
    for (auto& sp : L.sessions) {
        if (sp->cli.ctx) sp->cli.ctx->tick(t);
        if (sp->srv.ctx) sp->srv.ctx->tick(t);
    }
}

/// Bounded pump: run until `cond` or the wall-clock budget expires.
/// Returns cond()'s final value. No fixed sleep is a correctness criterion;
/// the 1ms pause only paces the poll loop.
bool run_until(Link& L, const std::function<bool()>& cond, int budget_ms) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        pump_once(L, 2);
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    pump_once(L, 0);
    return cond();
}

bool queues_idle(Link& L) {
    for (auto& sp : L.sessions)
        if (!sp->cli.tx_q.empty() || !sp->srv.tx_q.empty()) return false;
    return true;
}

// ---- handshake / context / capabilities ----

bool do_handshake(Link& L, Session& s) {
    s.cli.keys = s.cli.e2e.generate_key_pair();
    s.srv.keys = s.srv.e2e.generate_key_pair();
    auto req = s.cli.e2e.create_key_exchange_request(s.cli.keys);
    queue_payload(s.cli, kKindHandshake, req);
    if (!run_until(L, [&] { return s.cli.e2e.is_established() &&
                                    s.srv.e2e.is_established(); }, 5000))
        return false;

    // Profile-transition session binding: first 16 bytes of a key derived
    // from the real shared secret (both sides derive independently).
    try {
        std::vector<uint8_t> bpub(
            s.srv.keys.public_key.data(),
            s.srv.keys.public_key.data() + s.srv.keys.public_key.size());
        std::vector<uint8_t> apub(
            s.cli.keys.public_key.data(),
            s.cli.keys.public_key.data() + s.cli.keys.public_key.size());
        auto sa = s.cli.e2e.compute_shared_secret(s.cli.keys, bpub);
        auto sb = s.srv.e2e.compute_shared_secret(s.srv.keys, apub);
        if (sa.size() != sb.size() ||
            std::memcmp(sa.data(), sb.data(), sa.size()) != 0) return false;
        auto sid_key = s.cli.e2e.derive_keys(
            sa, "udp-profile-transition-session-id", PROFILE_SESSION_ID_SIZE);
        std::memcpy(s.profile_sid.data(), sid_key.data(),
                    PROFILE_SESSION_ID_SIZE);
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

void make_context(Session& s, Endpoint& ep) {
    ProfileTransitionConfig cfg;
    cfg.session_id = s.profile_sid;
    cfg.retransmit_interval_ms = 60;
    cfg.max_retransmit_attempts = 6;
    cfg.grace_period_ms = 300;
    cfg.max_payload_bytes = 4096;

    ep.ctx = std::make_unique<SessionProfileContext>(
        cfg, kP0, kL0, make_crypto(ep));
    ep.ctx->set_layout_resolver(&resolve_test_layout);
    ep.ctx->set_crypto_epoch(1);

    ep.ctx->set_control_outbound_handler(
        [&ep](const std::vector<uint8_t>& wire) {
            if (wire.empty()) return;  // guarded crypto failure at boundary
            TransitionMsgType t = TransitionMsgType::PREPARE;
            if (!ep.pending_ctypes.empty()) {
                t = ep.pending_ctypes.front();
                ep.pending_ctypes.pop_front();
            }
            queue_payload(ep, kKindE2E, wire, /*is_control=*/true, t);
        });
    ep.ctx->set_switch_event_handler(
        [&ep](const SwitchEvent& e) { ep.events.push_back(e); });
    ep.ctx->set_abort_handler([&ep](uint64_t tid, AbortReason r) {
        ep.aborts.emplace_back(tid, r);
    });
    ep.ctx->add_epoch_observer([&ep](uint32_t o, uint32_t n) {
        ep.epoch_changes.emplace_back(o, n);
    });
}

/// Direct tagged capabilities exchange over the real UDP link. Both sides
/// advertise (or omit) profile_transition_v1; each applies the peer's bit
/// to its SessionProfileContext.
bool do_caps_exchange(Link& L, Session& s, bool transition_capable) {
    NCPCapabilities cli_caps;
    capabilities_set_profile_transition(cli_caps, transition_capable);
    NCPCapabilities srv_caps;
    capabilities_set_profile_transition(srv_caps, transition_capable);

    auto send_caps = [](Endpoint& ep, const NCPCapabilities& caps) {
        try {
            auto wrapped = CapabilitiesExchange::wrap_capabilities(caps);
            auto wire = E2EUtils::serialize_message(ep.e2e.encrypt(wrapped));
            queue_payload(ep, kKindCaps, wire);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    };
    if (!send_caps(s.cli, cli_caps)) return false;
    if (!send_caps(s.srv, srv_caps)) return false;

    const bool ok = run_until(L, [&] {
        return s.cli.peer_caps.has_value() && s.srv.peer_caps.has_value();
    }, 5000);
    if (!ok) return false;

    s.cli.ctx_peer_capable = transition_capable;
    s.srv.ctx_peer_capable = transition_capable;
    s.cli.ctx->set_peer_capable(
        capabilities_support_profile_transition(*s.cli.peer_caps));
    s.srv.ctx->set_peer_capable(
        capabilities_support_profile_transition(*s.srv.peer_caps));
    return true;
}

/// Full session bring-up over real UDP: PH bind/open, X25519 handshake,
/// per-session context creation, capability negotiation.
bool session_up(Link& L, Session& s, bool transition_capable = true) {
    if (!do_handshake(L, s)) return false;
    make_context(s, s.cli);
    make_context(s, s.srv);
    return do_caps_exchange(L, s, transition_capable);
}

// ---- application traffic ----

/// Queue one deterministic application datagram; logs the real wire size
/// and the profile epoch the context stamped on it.
bool send_app(Session& s, Endpoint& ep) {
    (void)s;
    const uint8_t dir = ep.is_client ? 1 : 2;
    auto payload = make_app_payload(dir, ep.app_tx_seq);
    const uint32_t epoch = ep.ctx->tx_epoch();
    auto wire = ep.ctx->encode_data(payload);
    if (!wire) return false;
    ep.data_tx_log.push_back({epoch, wire->size(), payload.size()});
    ++ep.app_tx_seq;
    std::vector<uint8_t> d;
    d.push_back(kKindE2E);
    d.insert(d.end(), wire->begin(), wire->end());
    ep.last_data_datagram = d;
    queue_payload(ep, kKindE2E, *wire);
    return true;
}

/// Encode but HOLD the datagram (simulates an in-flight packet that the
/// network delivers later). Released as a real datagram by release_held().
bool send_app_held(Session& s, Endpoint& ep) {
    const uint8_t dir = ep.is_client ? 1 : 2;
    auto payload = make_app_payload(dir, ep.app_tx_seq);
    auto wire = ep.ctx->encode_data(payload);
    if (!wire) return false;
    ++ep.app_tx_seq;
    std::vector<uint8_t> d;
    d.push_back(kKindE2E);
    d.insert(d.end(), wire->begin(), wire->end());
    s.held_data.push_back(std::move(d));
    return true;
}

void release_held(Session& s, Endpoint& ep, size_t idx) {
    if (idx >= s.held_data.size()) return;
    auto& d = s.held_data[idx];
    queue_payload(ep, kKindE2E, std::vector<uint8_t>(d.begin() + 1, d.end()));
    s.held_data.erase(s.held_data.begin() + static_cast<long>(idx));
}

bool both_idle(Session& s) {
    return s.cli.ctx->state() == ProfileTransitionState::IDLE &&
           s.srv.ctx->state() == ProfileTransitionState::IDLE;
}

/// Drive the transition to completion including grace-drain finalization.
bool settle_transition(Link& L, Session& s, int budget_ms = 5000) {
    return run_until(L, [&] {
        return both_idle(s) && queues_idle(L) &&
               s.cli.ctx->state() == ProfileTransitionState::IDLE;
    }, budget_ms);
}

TransitionError start_switch(Session& s, const ProfileRef& target,
                             const ProfileLayoutParams& layout) {
    return s.cli.ctx->start_transition(
        target, layout, TransitionDirection::BIDIRECTIONAL,
        /*reason=*/1, now_ms());
}

} // namespace

namespace {

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return sodium_init() >= 0;
    }();
    ASSERT_TRUE(once);
}

/// Bring-up prologue for every test: GTEST_SKIP (not fail) when loopback
/// UDP is unavailable. Must be invoked from the TEST body directly because
/// GTEST_SKIP only aborts the function it runs in.
#define UDP_LINK_OR_SKIP(link_var, n_sessions)                                \
    ensure_init();                                                            \
    Link link_var;                                                            \
    if (!link_start(link_var, n_sessions))                                    \
        GTEST_SKIP() << "loopback UDP sockets unavailable in this environment"

/// Snapshot of "same logical session, no reconnect" evidence.
struct SessionIdentity {
    std::string cli_sid, srv_sid;
    uint64_t cli_sent = 0, cli_recv = 0;
    uint32_t cli_chain = 0, srv_chain = 0;
};

SessionIdentity identity_of(Session& s) {
    SessionIdentity id;
    id.cli_sid = s.cli.e2e.get_session_id();
    id.srv_sid = s.srv.e2e.get_session_id();
    id.cli_sent = s.cli.e2e.get_messages_sent();
    id.cli_recv = s.cli.e2e.get_messages_received();
    id.cli_chain = s.cli.e2e.get_sending_chain_length();
    id.srv_chain = s.srv.e2e.get_sending_chain_length();
    return id;
}

void expect_same_session(Session& s, const SessionIdentity& before) {
    EXPECT_TRUE(s.cli.e2e.is_established());
    EXPECT_TRUE(s.srv.e2e.is_established());
    EXPECT_EQ(s.cli.e2e.get_session_id(), before.cli_sid) << "client reconnected";
    EXPECT_EQ(s.srv.e2e.get_session_id(), before.srv_sid) << "server reconnected";
    // Monotonic crypto chains: a profile switch never resets the ratchet.
    EXPECT_GE(s.cli.e2e.get_sending_chain_length(), before.cli_chain);
    EXPECT_GE(s.srv.e2e.get_sending_chain_length(), before.srv_chain);
    EXPECT_GE(s.cli.e2e.get_messages_sent(), before.cli_sent);
}

/// Send `count` app datagrams one direction and wait for full delivery.
bool send_app_n(Link& L, Session& s, Endpoint& from, int count,
                int budget_ms = 5000) {
    Endpoint& to = from.is_client ? s.srv : s.cli;
    const uint64_t want = to.app_rx.received + count;
    for (int i = 0; i < count; ++i) {
        if (!send_app(s, from)) return false;
        if ((i & 3) == 3) pump_once(L, 1);
    }
    return run_until(L, [&] { return to.app_rx.received >= want; }, budget_ms);
}

/// Send `count` app datagrams each direction and wait for full delivery.
bool exchange_app(Link& L, Session& s, int count, int budget_ms = 5000) {
    const uint64_t want_srv = s.srv.app_rx.received + count;
    const uint64_t want_cli = s.cli.app_rx.received + count;
    for (int i = 0; i < count; ++i) {
        if (!send_app(s, s.cli) || !send_app(s, s.srv)) return false;
        if ((i & 3) == 3) pump_once(L, 1);
    }
    return run_until(L, [&] {
        return s.srv.app_rx.received >= want_srv &&
               s.cli.app_rx.received >= want_cli;
    }, budget_ms);
}

/// Verify every logged data datagram matches the exact framing layout for
/// the epoch it was stamped with (real wire-layout evidence).
void expect_wire_layouts(const Endpoint& ep, uint32_t block_stable,
                         uint32_t block_new, uint32_t new_epoch) {
    ASSERT_FALSE(ep.data_tx_log.empty());
    // Calibrate the (constant) E2E serialization overhead from the first
    // stable-epoch datagram: wire = overhead + tag(4) + framed body.
    bool calibrated = false;
    size_t overhead = 0;
    bool saw_new_layout_difference = false;
    for (const auto& r : ep.data_tx_log) {
        const uint32_t block = (r.epoch >= new_epoch && new_epoch != 0)
                                   ? block_new : block_stable;
        const size_t framed = framed_body_len(r.payload_len, block);
        if (!calibrated) {
            overhead = r.wire_size - (NCP_MSG_TAG_SIZE + framed);
            calibrated = true;
            continue;
        }
        EXPECT_EQ(r.wire_size, overhead + NCP_MSG_TAG_SIZE + framed)
            << "wire size mismatch for payload_len=" << r.payload_len
            << " epoch=" << r.epoch;
        if (block_new > 1 && r.epoch >= new_epoch &&
            framed != framed_body_len(r.payload_len, block_stable))
            saw_new_layout_difference = true;
    }
    if (new_epoch != 0 && block_new != block_stable) {
        EXPECT_TRUE(saw_new_layout_difference)
            << "new layout never changed the observable datagram size";
    }
}

void expect_stream_intact(Session& s, uint32_t cli_msgs, uint32_t srv_msgs) {
    EXPECT_EQ(s.srv.app_rx.received, cli_msgs);
    EXPECT_EQ(s.cli.app_rx.received, srv_msgs);
    EXPECT_EQ(s.srv.app_rx.duplicates, 0u) << "duplicate app payload at server";
    EXPECT_EQ(s.cli.app_rx.duplicates, 0u) << "duplicate app payload at client";
    EXPECT_EQ(s.srv.app_rx.gaps, 0u) << "app gap at server";
    EXPECT_EQ(s.cli.app_rx.gaps, 0u) << "app gap at client";
    EXPECT_EQ(s.srv.app_rx.hash.final(), expected_stream_hash(1, 0, cli_msgs))
        << "SHA-256 of cli->srv application stream mismatch";
    EXPECT_EQ(s.cli.app_rx.hash.final(), expected_stream_hash(2, 0, srv_msgs))
        << "SHA-256 of srv->cli application stream mismatch";
}

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Control: identical traffic, no switch, no impairment. Every impaired run
// below derives its expected SHA-256 from the same deterministic generator.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, NoSwitchControlBaseline) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    const auto id0 = identity_of(s);

    ASSERT_TRUE(exchange_app(*L, s, 24));

    expect_stream_intact(s, 24, 24);
    expect_wire_layouts(s.cli, kL0.padding_block_bytes, 0, 0);
    expect_wire_layouts(s.srv, kL0.padding_block_bytes, 0, 0);
    EXPECT_EQ(s.cli.ctx->profile_epoch(), 0u);
    EXPECT_EQ(s.srv.ctx->profile_epoch(), 0u);
    EXPECT_TRUE(s.cli.events.empty());
    EXPECT_TRUE(s.srv.events.empty());
    EXPECT_EQ(s.cli.ctx->counters().control_retransmits, 0u);
    EXPECT_EQ(s.srv.ctx->counters().control_retransmits, 0u);
    EXPECT_EQ(s.cli.ctx->counters().tx_data_stable, 24u);
    EXPECT_EQ(s.srv.ctx->counters().rx_data_stable, 24u);
    expect_same_session(s, id0);

    // Capability negotiation actually happened over the wire.
    ASSERT_TRUE(s.cli.peer_caps.has_value());
    ASSERT_TRUE(s.srv.peer_caps.has_value());
    EXPECT_TRUE(capabilities_support_profile_transition(*s.cli.peer_caps));
    EXPECT_TRUE(capabilities_support_profile_transition(*s.srv.peer_caps));
}

// ══════════════════════════════════════════════════════════════════════════════
// Idle switch: no application traffic during the transition.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, IdleSwitchOverRealUdp) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    const auto id0 = identity_of(s);

    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    EXPECT_EQ(s.cli.ctx->state(), ProfileTransitionState::PREPARE);
    EXPECT_TRUE(s.cli.events.empty()) << "SwitchEvent must not fire on request";

    ASSERT_TRUE(settle_transition(*L, s));

    ASSERT_EQ(s.cli.events.size(), 1u);
    ASSERT_EQ(s.srv.events.size(), 1u);
    EXPECT_TRUE(s.cli.events[0].confirmed);
    EXPECT_TRUE(s.srv.events[0].confirmed);
    EXPECT_TRUE(s.cli.events[0].to == kP1);
    EXPECT_TRUE(s.srv.events[0].to == kP1);
    EXPECT_EQ(s.cli.ctx->profile_epoch(), 1u);
    EXPECT_EQ(s.srv.ctx->profile_epoch(), 1u);
    EXPECT_TRUE(s.cli.ctx->stable_profile() == kP1);
    EXPECT_TRUE(s.srv.ctx->stable_profile() == kP1);

    const auto ca = s.cli.ctx->counters();
    const auto cb = s.srv.ctx->counters();
    EXPECT_EQ(ca.transitions_started, 1u);
    EXPECT_EQ(ca.transitions_committed, 1u);
    EXPECT_EQ(ca.transitions_effective, 1u);
    EXPECT_EQ(ca.transitions_uncertain, 0u);
    EXPECT_EQ(cb.transitions_committed, 1u);
    EXPECT_EQ(cb.transitions_effective, 1u);
    EXPECT_GT(ca.control_tx, 0u);
    EXPECT_GT(cb.control_rx, 0u);
    expect_same_session(s, id0);

    // traffic resumes on the new profile
    ASSERT_TRUE(exchange_app(*L, s, 4));
    expect_stream_intact(s, 4, 4);
    // Post-finalize the new profile IS the stable profile: outbound data is
    // stamped with the new epoch (1) under the new layout, and accounted on
    // the STABLE buckets (tx_data_new/rx_data_new count only pre-finalize
    // new-epoch traffic — see hermetic RepeatedTransitionsEpochFence).
    EXPECT_EQ(s.cli.ctx->tx_epoch(), 1u);
    EXPECT_EQ(s.cli.ctx->counters().tx_data_stable, 4u);
    EXPECT_EQ(s.srv.ctx->counters().rx_data_stable, 4u);
    EXPECT_EQ(s.cli.ctx->counters().tx_data_new, 0u);
    EXPECT_EQ(s.srv.ctx->counters().rx_data_new, 0u);
    for (const auto& r : s.cli.data_tx_log)
        EXPECT_EQ(r.epoch, 1u) << "post-switch datagram not stamped epoch 1";
    // Real wire-layout evidence: every post-switch datagram follows the new
    // profile's block padding (16-byte blocks), not the stable layout.
    expect_wire_layouts(s.cli, kL0.padding_block_bytes,
                        kL1.padding_block_bytes, 1);
    expect_wire_layouts(s.srv, kL0.padding_block_bytes,
                        kL1.padding_block_bytes, 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Active application stream switch: traffic flows in BOTH directions before,
// during and after the transition. On loopback a single UDP socket preserves
// FIFO order, so COMMIT/CONFIRM (queued before any new-epoch data) always
// arrive first — early-new rejection is not expected and would be a defect.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, ActiveStreamSwitchWithWireLayoutEvidence) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    const auto id0 = identity_of(s);

    // Phase 1: stable-profile traffic.
    ASSERT_TRUE(exchange_app(*L, s, 6));
    EXPECT_EQ(s.cli.ctx->counters().tx_data_stable, 6u);

    // Phase 2: transition with continuous traffic.
    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(run_until(*L, [&] {
        return s.srv.ctx->state() == ProfileTransitionState::READY;
    }, 3000));
    ASSERT_TRUE(exchange_app(*L, s, 3));  // both still on the stable layout
    ASSERT_TRUE(run_until(*L, [&] {
        return s.cli.ctx->state() == ProfileTransitionState::COMMIT;
    }, 3000));
    ASSERT_TRUE(exchange_app(*L, s, 4));  // cli on NEW layout, srv old→commit
    ASSERT_TRUE(run_until(*L, [&] {
        return s.cli.ctx->state() == ProfileTransitionState::DRAIN &&
               s.srv.ctx->state() == ProfileTransitionState::DRAIN;
    }, 3000));
    ASSERT_TRUE(exchange_app(*L, s, 4));  // both on the new layout

    // Early new-layout data must never have been rejected at the server:
    // COMMIT always precedes new-epoch data on the wire (FIFO loopback).
    EXPECT_EQ(s.srv.ctx->counters().rx_rejected_early_new, 0u);
    EXPECT_EQ(s.cli.ctx->counters().rx_rejected_early_new, 0u);

    ASSERT_TRUE(settle_transition(*L, s));

    // 6+3+4+4 = 17 per direction, zero loss/duplication, identical bytes.
    expect_stream_intact(s, 17, 17);

    // Actual old/new wire layouts observed in the sender log.
    expect_wire_layouts(s.cli, kL0.padding_block_bytes,
                        kL1.padding_block_bytes, 1);
    expect_wire_layouts(s.srv, kL0.padding_block_bytes,
                        kL1.padding_block_bytes, 1);

    // Data datagrams observed arriving over UDP match the sent sizes
    // (multiset compare: sizes only, order-free).
    auto sorted = [](std::vector<size_t> v) {
        std::sort(v.begin(), v.end());
        return v;
    };
    std::vector<size_t> cli_tx_sizes;
    for (const auto& r : s.cli.data_tx_log) cli_tx_sizes.push_back(r.wire_size);
    EXPECT_EQ(sorted(s.srv.rx_data_wire_sizes), sorted(cli_tx_sizes))
        << "datagram sizes observed at the server differ from those sent";

    // Sender-side plaintext tap proves the stamped epoch flipped 0 → 1.
    ASSERT_FALSE(s.cli.last_data_plaintext.empty());
    ASSERT_TRUE(CapabilitiesExchange::has_magic(s.cli.last_data_plaintext));
    EXPECT_EQ(CapabilitiesExchange::peek_type(s.cli.last_data_plaintext),
              E2EMessageType::DATA);
    auto body = CapabilitiesExchange::unwrap(s.cli.last_data_plaintext);
    ASSERT_GE(body.size(), kDataBodyHeader);
    EXPECT_EQ(body[0], 'P');
    EXPECT_EQ(body[1], 'D');
    EXPECT_EQ(body[6], 1u);  // epoch 1, LSB of the BE u32 field

    // Per-epoch data-plane counters split exactly at the switch.
    EXPECT_EQ(s.cli.ctx->counters().tx_data_stable, 9u);
    EXPECT_EQ(s.cli.ctx->counters().tx_data_new, 8u);
    EXPECT_EQ(s.srv.ctx->counters().rx_data_new, 8u);

    expect_same_session(s, id0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Old in-flight datagrams: accepted during the grace window, rejected after
// the old decoder is removed at grace expiry. Held datagrams are released as
// REAL UDP datagrams (indistinguishable from network delay/reorder).
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, OldInFlightGraceAndDecoderRemoval) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    const auto id0 = identity_of(s);

    ASSERT_TRUE(send_app_n(*L, s, s.cli, 3));  // seq 0..2 stable
    ASSERT_EQ(s.srv.app_rx.received, 3u);

    // Two old-layout datagrams "in flight" while the switch happens.
    ASSERT_TRUE(send_app_held(s, s.cli));      // seq 3 → delivered in grace
    ASSERT_TRUE(send_app_held(s, s.cli));      // seq 4 → delivered post-grace
    ASSERT_EQ(s.held_data.size(), 2u);

    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(run_until(*L, [&] {
        return s.cli.ctx->state() == ProfileTransitionState::DRAIN &&
               s.srv.ctx->state() == ProfileTransitionState::DRAIN;
    }, 5000));

    // Grace window must still be open; deliver the first held datagram.
    ASSERT_TRUE(s.srv.ctx->in_grace_period(now_ms()))
        << "switch took longer than the grace period; enlarge grace_period_ms";
    release_held(s, s.cli, 0);  // seq 3, real datagram, old epoch
    ASSERT_TRUE(run_until(*L, [&] { return s.srv.app_rx.received >= 4; },
                          3000));
    EXPECT_EQ(s.srv.ctx->counters().rx_data_old_grace, 1u)
        << "old-layout in-flight datagram was not accepted during grace";
    // In-order so far (held datagram carried the next expected sequence).
    EXPECT_EQ(s.srv.app_rx.gaps, 0u);
    EXPECT_EQ(s.srv.app_rx.duplicates, 0u);

    // Let the grace deadline pass and both sides finalize to IDLE.
    ASSERT_TRUE(settle_transition(*L, s));
    ASSERT_FALSE(s.srv.ctx->in_grace_period(now_ms()));
    ASSERT_EQ(s.srv.ctx->state(), ProfileTransitionState::IDLE);

    // The second held datagram now hits the REMOVED old decoder.
    release_held(s, s.cli, 0);  // seq 4, old epoch, grace expired
    ASSERT_TRUE(run_until(*L, [&] {
        return s.srv.ctx->counters().rx_rejected_old_expired >= 1;
    }, 3000));
    EXPECT_EQ(s.srv.app_rx.received, 4u)
        << "expired old-epoch datagram reached the application";

    // The stream continues on the new profile; exactly the intentionally
    // expired datagram shows up as a (by-design) sequence gap.
    ASSERT_TRUE(send_app_n(*L, s, s.cli, 2));  // seq 5, 6 on the new layout
    EXPECT_EQ(s.srv.app_rx.received, 6u);
    EXPECT_EQ(s.srv.app_rx.gaps, 1u);
    EXPECT_EQ(s.srv.app_rx.duplicates, 0u);

    Sha256 expect;
    for (uint32_t seq : {0u, 1u, 2u, 3u, 5u, 6u})
        expect.update(make_app_payload(1, seq));
    EXPECT_EQ(s.srv.app_rx.hash.final(), expect.final());

    expect_same_session(s, id0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Loss + fresh retransmission of every control step. Dropped datagrams never
// reach the socket (deterministic send-edge impairment); retransmissions are
// driven by tick() from the poll loop against the real clock. Each impaired
// run ends with the SAME deterministic app stream as NoSwitchControlBaseline.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, PrepareLossFreshRetransmission) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    ASSERT_TRUE(exchange_app(*L, s, 4));
    const auto id0 = identity_of(s);

    s.cli.drop_controls[TransitionMsgType::PREPARE] = 1;  // first PREPARE lost
    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(*L, s));

    // Two logical PREPAREs: same transition_id, FRESH crypto per send.
    std::vector<const std::pair<TransitionMsgType, std::vector<uint8_t>>*>
        prepares;
    for (const auto& t : s.cli.control_wire_tap)
        if (t.first == TransitionMsgType::PREPARE) prepares.push_back(&t);
    ASSERT_GE(prepares.size(), 2u) << "no PREPARE retransmission happened";

    std::vector<uint64_t> msg_numbers;
    for (const auto* p : prepares) {
        // strip the harness kind byte, then the serialized E2E wire
        auto m = E2EUtils::deserialize_message(std::vector<uint8_t>(
            p->second.begin() + 1, p->second.end()));
        ASSERT_TRUE(m.has_value());
        msg_numbers.push_back(m->header.message_number);
    }
    for (size_t i = 1; i < msg_numbers.size(); ++i)
        EXPECT_GT(msg_numbers[i], msg_numbers[i - 1])
            << "retransmission reused a crypto counter";

    std::vector<uint64_t> tids;
    for (const auto& t : s.cli.control_pt_tap) {
        if (t.first != TransitionMsgType::PREPARE) continue;
        auto cm = ProfileTransitionCodec::decode(
            CapabilitiesExchange::unwrap(t.second));
        ASSERT_TRUE(cm.has_value());
        tids.push_back(cm->transition_id);
    }
    ASSERT_GE(tids.size(), 2u);
    EXPECT_EQ(tids[0], tids[1]) << "retransmission changed the transition_id";
    EXPECT_NE(prepares[0]->second, prepares[1]->second)
        << "retransmission reused ciphertext bytes";

    EXPECT_GE(s.cli.ctx->counters().control_retransmits, 1u);
    ASSERT_EQ(s.cli.events.size(), 1u);
    EXPECT_TRUE(s.cli.events[0].confirmed);
    ASSERT_EQ(s.srv.events.size(), 1u);

    // Same application stream as the no-switch control.
    ASSERT_TRUE(exchange_app(*L, s, 4));
    expect_stream_intact(s, 8, 8);
    expect_same_session(s, id0);
}

TEST(UdpProfileTransition, ReadyLossRecoveredByPrepareRetransmit) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    ASSERT_TRUE(exchange_app(*L, s, 4));
    const auto id0 = identity_of(s);

    s.srv.drop_controls[TransitionMsgType::READY] = 1;  // first READY lost
    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(*L, s));

    // The initiator's retransmission timer fired (PREPARE re-sent) and/or the
    // responder retransmitted READY; either way loss was recovered by FRESH
    // retransmission, and the duplicate PREPARE was deduped at the responder.
    EXPECT_GE(s.cli.ctx->counters().control_retransmits +
                  s.srv.ctx->counters().control_retransmits,
              1u);
    EXPECT_GE(s.srv.ctx->counters().control_duplicates +
                  s.cli.ctx->counters().control_duplicates,
              1u);
    ASSERT_EQ(s.cli.events.size(), 1u);
    EXPECT_TRUE(s.cli.events[0].confirmed);
    ASSERT_EQ(s.srv.events.size(), 1u);
    EXPECT_TRUE(s.srv.events[0].confirmed);

    ASSERT_TRUE(exchange_app(*L, s, 4));
    expect_stream_intact(s, 8, 8);
    expect_same_session(s, id0);
}

TEST(UdpProfileTransition, CommitAndConfirmLossRecovered) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    ASSERT_TRUE(exchange_app(*L, s, 4));
    const auto id0 = identity_of(s);

    // The initiator's COMMIT and its piggybacked CONFIRM are both lost.
    s.cli.drop_controls[TransitionMsgType::COMMIT] = 1;
    s.cli.drop_controls[TransitionMsgType::CONFIRM] = 1;
    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(*L, s));

    // Recovery evidence: the responder retransmitted READY (timeout), the
    // initiator deduped it and re-emitted COMMIT/CONFIRM.
    EXPECT_GE(s.srv.ctx->counters().control_retransmits, 1u)
        << "responder never retransmitted READY after COMMIT loss";
    EXPECT_GE(s.cli.ctx->counters().control_duplicates, 1u)
        << "initiator never deduped the retransmitted READY";
    ASSERT_EQ(s.cli.events.size(), 1u);
    EXPECT_TRUE(s.cli.events[0].confirmed);
    ASSERT_EQ(s.srv.events.size(), 1u);
    EXPECT_TRUE(s.srv.events[0].confirmed);
    EXPECT_EQ(s.cli.ctx->counters().transitions_uncertain, 0u);

    ASSERT_TRUE(exchange_app(*L, s, 4));
    expect_stream_intact(s, 8, 8);
    expect_same_session(s, id0);
}

TEST(UdpProfileTransition, ConfirmLossRecoveredByRetransmit) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    ASSERT_TRUE(exchange_app(*L, s, 4));
    const auto id0 = identity_of(s);

    s.srv.drop_controls[TransitionMsgType::CONFIRM] = 1;  // first CONFIRM lost
    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(*L, s));

    EXPECT_GE(s.cli.ctx->counters().control_retransmits +
                  s.srv.ctx->counters().control_retransmits,
              1u);
    ASSERT_EQ(s.cli.events.size(), 1u);
    EXPECT_TRUE(s.cli.events[0].confirmed)
        << "initiator stayed unconfirmed despite CONFIRM retransmission";
    EXPECT_EQ(s.cli.ctx->counters().transitions_uncertain, 0u);
    ASSERT_EQ(s.srv.events.size(), 1u);

    ASSERT_TRUE(exchange_app(*L, s, 4));
    expect_stream_intact(s, 8, 8);
    expect_same_session(s, id0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Duplicate / replay / corruption of NEW-layout datagrams, replayed as REAL
// second UDP datagrams. The AEAD + replay protection of the unchanged crypto
// session turns them into transport drops; the app stream is unaffected.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, DuplicateReplayAndCorruptNewDatagrams) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    const auto id0 = identity_of(s);

    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(*L, s));
    ASSERT_EQ(s.cli.ctx->profile_epoch(), 1u);

    // One genuine new-layout datagram, delivered once.
    ASSERT_TRUE(send_app_n(*L, s, s.cli, 1));
    ASSERT_EQ(s.srv.app_rx.received, 1u);
    ASSERT_FALSE(s.cli.last_data_datagram.empty());
    const auto good = s.cli.last_data_datagram;
    const uint64_t srv_rx_before = s.srv.ctx->counters().rx_data_new;

    // (a) Exact replay over a real socket: new PH seq, identical ciphertext.
    ph_send(*L, s, s.cli, good.data(), good.size());
    // (b) Corrupted copy: flip a bit in the AEAD auth tag (last byte).
    auto corrupt = good;
    corrupt.back() ^= 0x01;
    ph_send(*L, s, s.cli, corrupt.data(), corrupt.size());
    // (c) Truncated copy.
    ph_send(*L, s, s.cli, good.data(), good.size() / 2);

    // Give the poisoned datagrams every chance to be processed.
    pump_once(*L, 5);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pump_once(*L, 5);

    EXPECT_EQ(s.srv.app_rx.received, 1u)
        << "replayed/corrupted datagram reached the application";
    EXPECT_EQ(s.srv.ctx->counters().rx_data_new, srv_rx_before);
    EXPECT_EQ(s.srv.app_rx.duplicates, 0u);
    EXPECT_EQ(s.srv.app_rx.gaps, 0u);

    // (d) Ciphertext-level replay of the peer's CONFIRM control datagram.
    const uint64_t cli_control_rx =
        s.cli.ctx->counters().control_rx +
        s.cli.ctx->counters().control_rx_rejected +
        s.cli.ctx->counters().control_duplicates;
    const size_t cli_events = s.cli.events.size();
    for (const auto& t : s.srv.control_wire_tap) {
        if (t.first != TransitionMsgType::CONFIRM) continue;
        ph_send(*L, s, s.srv, t.second.data(), t.second.size());
        break;
    }
    pump_once(*L, 5);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    pump_once(*L, 5);
    const uint64_t cli_control_rx_after =
        s.cli.ctx->counters().control_rx +
        s.cli.ctx->counters().control_rx_rejected +
        s.cli.ctx->counters().control_duplicates;
    EXPECT_EQ(cli_control_rx_after, cli_control_rx)
        << "replayed control ciphertext produced a protocol event";
    EXPECT_EQ(s.cli.events.size(), cli_events)
        << "replay re-confirmed the transition";

    // The healthy stream continues without gaps or duplicates.
    ASSERT_TRUE(send_app_n(*L, s, s.cli, 3));
    EXPECT_EQ(s.srv.app_rx.received, 4u);
    EXPECT_EQ(s.srv.app_rx.gaps, 0u);
    EXPECT_EQ(s.srv.app_rx.duplicates, 0u);
    EXPECT_EQ(s.srv.app_rx.hash.final(), expected_stream_hash(1, 0, 4));
    expect_same_session(s, id0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Unknown target (wrong content hash): responder ABORTs UNKNOWN_PROFILE over
// the real link; both sides roll back cleanly, crypto session untouched.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, WrongProfileHashAbortsCleanly) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    ASSERT_TRUE(exchange_app(*L, s, 2));
    const auto id0 = identity_of(s);

    ASSERT_EQ(start_switch(s, kP1BadHash, kL1), TransitionError::NONE);
    ASSERT_TRUE(run_until(*L, [&] {
        return both_idle(s) && !s.cli.aborts.empty() && !s.srv.aborts.empty();
    }, 5000));

    EXPECT_EQ(s.srv.aborts[0].second, AbortReason::UNKNOWN_PROFILE);
    EXPECT_EQ(s.cli.aborts[0].second, AbortReason::UNKNOWN_PROFILE)
        << "abort reason was not relayed to the initiator";
    EXPECT_TRUE(s.cli.events.empty()) << "SwitchEvent fired for an abort";
    EXPECT_TRUE(s.srv.events.empty());
    EXPECT_EQ(s.cli.ctx->profile_epoch(), 0u);
    EXPECT_EQ(s.srv.ctx->profile_epoch(), 0u);
    EXPECT_TRUE(s.cli.ctx->stable_profile() == kP0);
    EXPECT_TRUE(s.srv.ctx->stable_profile() == kP0);
    EXPECT_EQ(s.cli.ctx->counters().transitions_committed, 0u);
    EXPECT_EQ(s.srv.ctx->counters().transitions_aborted, 1u);

    // Traffic resumes on the unchanged profile.
    ASSERT_TRUE(exchange_app(*L, s, 3));
    expect_stream_intact(s, 5, 5);
    expect_same_session(s, id0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Legacy-negative: profile_transition_v1 NOT negotiated. start_transition is
// refused locally, no control datagram ever appears on the wire, and the data
// wire format is byte-identical to the legacy (untagged) form.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, UnsupportedPeerNoWireChange) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, /*transition_capable=*/false));
    ASSERT_TRUE(s.cli.peer_caps.has_value());
    EXPECT_FALSE(capabilities_support_profile_transition(*s.cli.peer_caps));

    const uint64_t srv_e2e_rx = s.srv.e2e.get_messages_received();

    EXPECT_EQ(start_switch(s, kP1, kL1), TransitionError::NOT_SUPPORTED);
    EXPECT_EQ(s.cli.ctx->state(), ProfileTransitionState::IDLE);
    EXPECT_TRUE(s.cli.tx_q.empty());
    EXPECT_TRUE(s.cli.control_wire_tap.empty())
        << "a control datagram was emitted without the capability";
    EXPECT_TRUE(s.srv.control_wire_tap.empty());

    ASSERT_TRUE(exchange_app(*L, s, 6));

    // Every datagram on the wire was application data (no control frames).
    EXPECT_EQ(s.srv.e2e.get_messages_received(), srv_e2e_rx + 6u);

    // Wire format unchanged: the AEAD plaintext is the RAW payload — no NCP
    // tag, no profile framing, no padding.
    ASSERT_FALSE(s.cli.data_tx_log.empty());
    const size_t overhead =
        s.cli.data_tx_log[0].wire_size - s.cli.data_tx_log[0].payload_len;
    for (const auto& r : s.cli.data_tx_log)
        EXPECT_EQ(r.wire_size, r.payload_len + overhead)
            << "legacy wire format changed";
    EXPECT_EQ(s.cli.last_data_plaintext,
              make_app_payload(1, s.cli.app_tx_seq - 1))
        << "legacy plaintext is not the raw payload";
    EXPECT_FALSE(CapabilitiesExchange::has_magic(s.cli.last_data_plaintext));

    EXPECT_EQ(s.cli.ctx->counters().tx_data_stable, 6u);
    EXPECT_EQ(s.srv.ctx->counters().rx_data_stable, 6u);
    EXPECT_EQ(s.cli.ctx->counters().tx_data_new, 0u);
    EXPECT_EQ(s.cli.ctx->profile_epoch(), 0u);
    expect_stream_intact(s, 6, 6);
}

// ══════════════════════════════════════════════════════════════════════════════
// Repeated back-to-back transitions on one session.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, RepeatedTransitionsMonotonicEpochs) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));
    const auto id0 = identity_of(s);
    uint32_t cli_chain_floor = s.cli.e2e.get_sending_chain_length();

    const std::pair<ProfileRef, ProfileLayoutParams> plan[3] = {
        {kP1, kL1}, {kP2, kL2}, {kP0, kL0},
    };
    for (uint32_t round = 0; round < 3; ++round) {
        ASSERT_EQ(start_switch(s, plan[round].first, plan[round].second),
                  TransitionError::NONE) << "round " << round;
        ASSERT_TRUE(settle_transition(*L, s)) << "round " << round;
        EXPECT_EQ(s.cli.ctx->profile_epoch(), round + 1);
        EXPECT_EQ(s.srv.ctx->profile_epoch(), round + 1);
        EXPECT_TRUE(s.cli.ctx->stable_profile() == plan[round].first);
        EXPECT_TRUE(s.srv.ctx->stable_profile() == plan[round].first);
        ASSERT_TRUE(exchange_app(*L, s, 2)) << "round " << round;

        // The crypto chain never resets, never regresses.
        EXPECT_GE(s.cli.e2e.get_sending_chain_length(), cli_chain_floor);
        cli_chain_floor = s.cli.e2e.get_sending_chain_length();
    }

    EXPECT_EQ(s.cli.events.size(), 3u);
    EXPECT_EQ(s.srv.events.size(), 3u);
    for (const auto& e : s.cli.events) EXPECT_TRUE(e.confirmed);
    EXPECT_EQ(s.cli.ctx->counters().transitions_effective, 3u);
    EXPECT_EQ(s.srv.ctx->counters().transitions_effective, 3u);
    EXPECT_EQ(s.cli.epoch_changes.size(), 3u);
    EXPECT_EQ(s.cli.epoch_changes[0], std::make_pair(0u, 1u));
    EXPECT_EQ(s.cli.epoch_changes[1], std::make_pair(1u, 2u));
    EXPECT_EQ(s.cli.epoch_changes[2], std::make_pair(2u, 3u));

    expect_stream_intact(s, 6, 6);
    expect_same_session(s, id0);
}

// ══════════════════════════════════════════════════════════════════════════════
// Two parallel protected sessions on ONE PortHopServer (demuxed by session
// id): independent transitions, independent epochs, no cross-talk. Includes a
// wrong-session injection: session 1's PREPARE ciphertext re-sent through
// session 2's real socket must be an AEAD-level transport drop there.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, ParallelSessionsIndependentProfiles) {
    UDP_LINK_OR_SKIP(_link, 2);
    Link* L = &_link;
    Session& s1 = *L->sessions[0];
    Session& s2 = *L->sessions[1];
    ASSERT_TRUE(session_up(*L, s1, true));
    ASSERT_TRUE(session_up(*L, s2, true));
    const auto id1 = identity_of(s1);
    const auto id2 = identity_of(s2);

    ASSERT_TRUE(exchange_app(*L, s1, 3));
    ASSERT_TRUE(exchange_app(*L, s2, 3));

    // Transition session 1 only.
    ASSERT_EQ(start_switch(s1, kP1, kL1), TransitionError::NONE);

    // Wrong-session injection: s1's PREPARE ciphertext into s2's socket.
    // Capture it after the first pump flushed it to the wire tap.
    ASSERT_TRUE(run_until(*L, [&] {
        for (const auto& t : s1.cli.control_wire_tap)
            if (t.first == TransitionMsgType::PREPARE) return true;
        return false;
    }, 3000));
    std::vector<uint8_t> foreign;
    for (const auto& t : s1.cli.control_wire_tap)
        if (t.first == TransitionMsgType::PREPARE) foreign = t.second;
    ASSERT_FALSE(foreign.empty());
    const uint64_t s2_srv_control_rx = s2.srv.ctx->counters().control_rx;
    s2.client->send(foreign.data(), foreign.size());

    ASSERT_TRUE(settle_transition(*L, s1));
    // Let the foreign datagram be processed (bounded pump).
    pump_once(*L, 5);

    // Session 1 switched; session 2 untouched.
    EXPECT_EQ(s1.cli.ctx->profile_epoch(), 1u);
    EXPECT_EQ(s1.srv.ctx->profile_epoch(), 1u);
    EXPECT_EQ(s2.cli.ctx->profile_epoch(), 0u);
    EXPECT_EQ(s2.srv.ctx->profile_epoch(), 0u);
    EXPECT_TRUE(s2.cli.events.empty());
    EXPECT_TRUE(s2.srv.events.empty());
    EXPECT_TRUE(s2.cli.aborts.empty());
    EXPECT_EQ(s2.srv.ctx->counters().control_rx, s2_srv_control_rx)
        << "foreign-session ciphertext produced a control event";
    EXPECT_EQ(s2.srv.ctx->state(), ProfileTransitionState::IDLE);

    // Session 2 transitions independently to a DIFFERENT profile.
    ASSERT_EQ(start_switch(s2, kP2, kL2), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(*L, s2));
    EXPECT_EQ(s2.cli.ctx->profile_epoch(), 1u);
    EXPECT_TRUE(s2.cli.ctx->stable_profile() == kP2);
    // Session 1 not disturbed by session 2's transition.
    EXPECT_EQ(s1.cli.ctx->profile_epoch(), 1u);
    EXPECT_TRUE(s1.cli.ctx->stable_profile() == kP1);
    EXPECT_EQ(s1.cli.events.size(), 1u);

    // Both application streams intact end-to-end.
    ASSERT_TRUE(exchange_app(*L, s1, 3));
    ASSERT_TRUE(exchange_app(*L, s2, 3));
    expect_stream_intact(s1, 6, 6);
    expect_stream_intact(s2, 6, 6);
    expect_same_session(s1, id1);
    expect_same_session(s2, id2);

    // Wire layouts differ per session on the wire: s1 → 16-byte blocks,
    // s2 → 8-byte blocks.
    expect_wire_layouts(s1.cli, kL0.padding_block_bytes,
                        kL1.padding_block_bytes, 1);
    expect_wire_layouts(s2.cli, kL0.padding_block_bytes,
                        kL2.padding_block_bytes, 1);
}

// ══════════════════════════════════════════════════════════════════════════════
// Queued/paced shape cancellation: a real MimicryShaper prepares (queues) a
// data shape under the old profile epoch; the SessionProfileContext epoch
// observer (fired at activation, driven by the real UDP transition) cancels
// the stale queued shape and installs the new profile. The cancelled shape
// can never leak into the new epoch.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransition, ShaperQueuedShapeCancelledOnEpochFence) {
    UDP_LINK_OR_SKIP(_link, 1);
    Link* L = &_link;
    Session& s = *L->sessions[0];
    ASSERT_TRUE(session_up(*L, s, true));

    MimicryShaper shaper(StatProfile::webrtc_video(), /*seed=*/42);
    auto queued = shaper.prepare_data_shape(1400);
    ASSERT_TRUE(shaper.has_prepared_shape());
    ASSERT_EQ(queued.profile_epoch, 0u);
    ASSERT_GE(queued.bytes, 1u);
    ASSERT_LE(queued.bytes, 1400u);

    // Host coordination point: the context never touches the shaper itself;
    // the epoch observer cancels queued shape work bound to superseded epochs.
    uint32_t observed_old = UINT32_MAX, observed_new = UINT32_MAX;
    s.cli.ctx->add_epoch_observer([&](uint32_t old_epoch, uint32_t new_epoch) {
        observed_old = old_epoch;
        observed_new = new_epoch;
        shaper.cancel_prepared_shape();
        shaper.set_profile(StatProfile::voip_opus());
    });

    ASSERT_EQ(start_switch(s, kP1, kL1), TransitionError::NONE);
    ASSERT_TRUE(run_until(*L, [&] { return observed_new != UINT32_MAX; },
                          5000));

    // Activation fired the fence with (0 → 1) and cancelled the stale shape.
    EXPECT_EQ(observed_old, 0u);
    EXPECT_EQ(observed_new, 1u);
    EXPECT_FALSE(shaper.has_prepared_shape())
        << "queued shape survived the profile epoch fence";
    PreparedShape stale;
    EXPECT_FALSE(shaper.take_data_shape(stale))
        << "a cancelled shape could still be consumed";
    EXPECT_EQ(shaper.profile_epoch(), 1u);

    // The shaper remains fully usable under the new profile/epoch.
    auto fresh = shaper.prepare_data_shape(1400);
    EXPECT_TRUE(shaper.has_prepared_shape());
    EXPECT_EQ(fresh.profile_epoch, 1u);
    PreparedShape taken;
    EXPECT_TRUE(shaper.take_data_shape(taken));
    EXPECT_EQ(taken.profile_epoch, 1u);

    ASSERT_TRUE(settle_transition(*L, s));
    ASSERT_TRUE(exchange_app(*L, s, 2));
    expect_stream_intact(s, 2, 2);
}
