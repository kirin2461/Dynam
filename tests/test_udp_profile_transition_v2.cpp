// ══════════════════════════════════════════════════════════════════════════════
// tests/test_udp_profile_transition_v2.cpp
//
// Mandatory REAL-transport evidence for profile_transition_v2 (design §2.2):
// the full NcpMimicrySession adapter stack (X25519 E2E handshake + capability
// negotiation + SessionProfileContext two-phase commit + OUTER TrafficMimicry
// mask scheduling C1/C3) over real 127.0.0.1 UDP via PortHopClient/Server.
//
//   T2-happy        : GENERIC_UDP → QUIC_SHORT_HEADER under a continuous
//                     application stream; SHA-256 equality vs an identical
//                     no-switch control session; zero early-new/unknown-epoch
//                     rejections (FIFO loopback ⇒ COMMIT precedes new-epoch
//                     data — the sibling/pending candidates absorb the mask
//                     flip, never the epoch fence).
//   T2-loss20       : deterministic ~20% control-datagram loss; the impaired
//                     switch run delivers EXACTLY the control run's stream
//                     (no additional transition-induced loss) with retransmit
//                     counters proving the loss was exercised.
//   T2-commit-storm : 100% COMMIT/CONFIRM loss (drop all control after the
//                     READY). Initiator finalizes transitions_uncertain == 1
//                     keeping the QUIC mask; responder cleanly
//                     transitions_timed_out == 1 back on GENERIC_UDP. The
//                     divergent pair then CANNOT re-sync in-band — BY DESIGN:
//                     the C1 pin emits the recovery PREPARE in the diverged
//                     mask (undecodable at the rolled-back peer) and the
//                     epoch fence would reject it anyway. The test asserts
//                     this failure is BOUNDED (PREPARE retransmit budget
//                     exhausts, counted as transitions_timed_out, back to
//                     IDLE, queues drain, no crash) and demonstrates that the
//                     recovery primitive for uncertain divergence is session
//                     re-establishment: a fresh session + fresh transition
//                     re-synchronizes onto the QUIC target with matching
//                     stream hashes. (Deviation from design §2.2's literal
//                     "a subsequent fresh transition re-synchronizes",
//                     approved by the lead: in-band re-sync is impossible by
//                     construction; a protocol-level resync candidate is a
//                     future-wave item.)
//   T2-legacy       : v1-only peer (advertise_profile_transition_v2 = false)
//                     ⇒ the initiator refuses the QUIC_SHORT_HEADER target
//                     locally (INVALID_PROFILE), ZERO control traffic leaves
//                     the socket, the v1 session keeps flowing.
//
// Harness discipline follows tests/test_udp_profile_transition.cpp: bounded
// pumps, no fixed sleeps as correctness criteria, adapter contexts fed AFTER
// PortHop::poll() returned (outside PortHop locks), impairments applied
// deterministically at the harness send edge.
//
// SCOPE: loopback protocol evidence only; NOT live external DPI evidence.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_porthop.hpp"
#include "ncp_mimicry_session.hpp"

#include <sodium.h>

#include <array>
#include <chrono>
#include <cstring>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <thread>
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

// ── Profiles (test-local; no catalog ⇒ no shaper/FSM — the adapter-only v2
//    mask schedule C1/C3 is what is under test here) ─────────────────────────

ProfileRef make_ref(const char* id, uint32_t rev, uint8_t hash_fill) {
    ProfileRef r;
    r.id = id;
    r.revision = rev;
    r.content_hash.fill(hash_fill);
    return r;
}

const ProfileRef kBaseRef = make_ref("baseline.udp", 1, 0xA0);
const ProfileRef kQuicRef = make_ref("mimic.quic", 1, 0xB1);
const ProfileLayoutParams kL0{0, 0};

std::optional<TrafficMimicry::MimicProfile> resolve_v2_mimic(
    const ProfileRef& ref) {
    using MP = TrafficMimicry::MimicProfile;
    if (ref == kBaseRef) return MP::GENERIC_UDP;
    if (ref == kQuicRef) return MP::QUIC_SHORT_HEADER;
    return std::nullopt;
}

// ── Deterministic application stream (same generator as the v1 suite so the
//    no-switch control and every impaired run pin the same digests) ──────────

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

/// Receiver-side ordered-stream tracker (duplicates/gaps only ever arise from
/// intentional test impairments).
struct AppRecvTracker {
    uint32_t expected_seq = 0;
    uint64_t received = 0;
    uint64_t duplicates = 0;
    uint64_t gaps = 0;
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

// ── Dynamic loopback port base (identical to the v1 suite) ──────────────────

bool port_available(uint16_t port) {
    winsock_init();
    socket_t s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == kInvalidSocket) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    const bool ok =
        (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
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
        a.sin_port = 0;
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

// ── Harness ─────────────────────────────────────────────────────────────────

/// Deterministic control-loss policies applied at the harness send edge.
enum class DropMode {
    kNone,
    kScatter20,      ///< ~20% of control datagrams (hash of the ordinal)
    kStormAfterFirst ///< allow the first control datagram per direction
                     ///< (PREPARE / READY), drop ALL subsequent control
};

bool should_drop_control(DropMode m, uint64_t ordinal) {
    switch (m) {
        case DropMode::kNone:
            return false;
        case DropMode::kScatter20: {
            // Knuth-multiplicative hash of the per-direction control
            // ordinal, reduced mod 100: deterministic across runs, ~20%
            // drop density (ordinals 0, 5, 9, ... drop).
            return ((ordinal * 2654435761ull) % 100) < 20;
        }
        case DropMode::kStormAfterFirst:
            return ordinal > 0;
    }
    return false;
}

struct V2Endpoint {
    std::unique_ptr<NcpMimicrySession> a;
    AppRecvTracker rx;
    uint32_t tx_seq = 0;
    /// App datagrams produced by send_application(), flushed AFTER the
    /// adapter's own outbound queue so causally-earlier control datagrams
    /// (e.g. COMMIT) always precede later app data on the FIFO link.
    std::deque<std::vector<uint8_t>> data_q;
    uint64_t ctl_ordinal = 0;  ///< control datagrams drained (drop pattern)
};

struct V2Link {
    static constexpr uint16_t kRange = 8;
    static constexpr uint32_t kHopIntervalSec = 3600;  // no hops mid-test

    std::vector<uint8_t> secret;
    std::optional<PortHopServer> server;
    uint16_t base = 0;

    V2Link() {
        secret.resize(32);
        for (size_t i = 0; i < secret.size(); ++i)
            secret[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    ~V2Link() {
        sessions.clear();  // clients before server teardown
        if (server) server->close();
    }

    HopSchedule make_schedule() const {
        return HopSchedule(secret, base, kRange, kHopIntervalSec);
    }

    struct Session {
        uint64_t sid = 0;
        V2Endpoint cli, srv;
        std::unique_ptr<PortHopClient> client;
        DropMode drop = DropMode::kNone;
    };
    std::vector<std::unique_ptr<Session>> sessions;
};

bool link_start(V2Link& L, size_t n_sessions) {
    for (int attempt = 0; attempt < 8 && !L.server; ++attempt) {
        auto base = pick_port_base(V2Link::kRange);
        if (!base) return false;
        L.server.emplace(HopSchedule(L.secret, *base, V2Link::kRange,
                                     V2Link::kHopIntervalSec));
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
        sid |= 1ULL;
        auto s = std::make_unique<V2Link::Session>();
        s->sid = sid;
        L.server->register_session(sid);
        s->client = std::make_unique<PortHopClient>("127.0.0.1",
                                                    L.make_schedule(), sid);
        if (!s->client->open()) return false;
        L.sessions.push_back(std::move(s));
    }
    return true;
}

void ph_send(V2Link& L, V2Link::Session& s, bool from_client,
             const std::vector<uint8_t>& d) {
    if (from_client)
        s.client->send(d.data(), d.size());
    else
        L.server->send_to_session(s.sid, d.data(), d.size());
}

/// Drain one endpoint: adapter outbound queue (control/caps — impairment
/// applies) first, then the harness data queue (never impaired).
void flush_ep(V2Link& L, V2Link::Session& s, V2Endpoint& ep,
              bool from_client) {
    if (!ep.a) return;  // session adapters are created lazily by session_up
    while (auto o = ep.a->next_outbound()) {
        if (o->is_control &&
            should_drop_control(s.drop, ep.ctl_ordinal)) {
            ++ep.ctl_ordinal;
            continue;  // datagram "lost": never reaches the socket
        }
        if (o->is_control) ++ep.ctl_ordinal;
        ph_send(L, s, from_client, o->bytes);
    }
    while (!ep.data_q.empty()) {
        ph_send(L, s, from_client, ep.data_q.front());
        ep.data_q.pop_front();
    }
}

/// Feed polled datagrams to the adapters (outside PortHop locks) and collect
/// application payloads.
void dispatch_to(V2Endpoint& ep, const std::vector<uint8_t>& payload) {
    if (!ep.a) return;
    auto r = ep.a->on_datagram(payload, now_ms());
    if (r.kind == NcpMimicrySession::IngressKind::Data && r.app_payload)
        ep.rx.feed(*r.app_payload);
}

void pump_once(V2Link& L, int poll_ms) {
    for (auto& sp : L.sessions) {
        flush_ep(L, *sp, sp->cli, true);
        flush_ep(L, *sp, sp->srv, false);
    }
    for (auto& sp : L.sessions) {
        auto frames = sp->client->poll(0);
        for (auto& r : frames) dispatch_to(sp->cli, r.frame.payload);
    }
    if (L.server) {
        auto frames = L.server->poll(poll_ms);
        for (auto& r : frames)
            for (auto& sp : L.sessions)
                if (sp->sid == r.frame.session_id) {
                    dispatch_to(sp->srv, r.frame.payload);
                    break;
                }
    }
    for (auto& sp : L.sessions) {
        auto frames = sp->client->poll(0);
        for (auto& r : frames) dispatch_to(sp->cli, r.frame.payload);
    }
    // Messages emitted in reaction to RX leave promptly.
    for (auto& sp : L.sessions) {
        flush_ep(L, *sp, sp->cli, true);
        flush_ep(L, *sp, sp->srv, false);
    }
    const uint64_t t = now_ms();
    for (auto& sp : L.sessions) {
        if (sp->cli.a) sp->cli.a->tick(t);
        if (sp->srv.a) sp->srv.a->tick(t);
    }
}

/// Bounded pump: run until `cond` or the wall-clock budget expires. The 1 ms
/// pause only paces the poll loop; no fixed sleep is a correctness criterion.
bool run_until(V2Link& L, const std::function<bool()>& cond, int budget_ms) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(budget_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        pump_once(L, 2);
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    pump_once(L, 0);
    return cond();
}

NcpMimicrySession::Config make_adapter_cfg(NcpMimicrySession::Role role,
                                           bool advertise_v2) {
    NcpMimicrySession::Config c;
    c.role = role;
    c.e2e_config.enable_padding = false;  // deterministic wire sizes
    c.stable_profile = kBaseRef;
    c.stable_layout = kL0;
    c.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
    c.mimic_config.profile = c.stable_mimic;
    c.mimic_config.wire_version = 3;
    c.mimic_config.enable_timing_mimicry = false;
    c.mimic_resolver = &resolve_v2_mimic;
    c.advertise_profile_transition_v2 = advertise_v2;
    c.transition_config.retransmit_interval_ms = 60;
    c.transition_config.max_retransmit_attempts = 6;
    c.transition_config.grace_period_ms = 1500;  // design §2.2 guidance
    c.path_mtu_bytes = 1500;
    c.porthop_overhead_bytes = 20;
    c.max_application_payload = 1024;
    return c;
}

/// Full adapter bring-up over real UDP: X25519 handshake + capability
/// negotiation driven by the pump loop.
bool session_up(V2Link& L, V2Link::Session& s, bool cli_v2 = true,
                bool srv_v2 = true) {
    s.cli.a = std::make_unique<NcpMimicrySession>(
        make_adapter_cfg(NcpMimicrySession::Role::Client, cli_v2));
    s.srv.a = std::make_unique<NcpMimicrySession>(
        make_adapter_cfg(NcpMimicrySession::Role::Server, srv_v2));
    auto hs = s.cli.a->start_handshake();
    if (!hs) return false;
    ph_send(L, s, true, hs->bytes);
    return run_until(L,
                     [&] {
                         return s.cli.a->is_established() &&
                                s.srv.a->is_established() &&
                                s.cli.a->transition_capable() &&
                                s.srv.a->transition_capable();
                     },
                     8000);
}

/// Produce one deterministic application datagram into the harness data
/// queue (flushed after any causally-earlier control traffic).
bool send_app(V2Link::Session& s, bool from_client) {
    V2Endpoint& ep = from_client ? s.cli : s.srv;
    const uint8_t dir = from_client ? 1 : 2;
    auto payload = make_app_payload(dir, ep.tx_seq);
    auto o = ep.a->send_application(payload, now_ms());
    if (!o) return false;
    ++ep.tx_seq;
    ep.data_q.push_back(o->bytes);
    return true;
}

bool send_app_n(V2Link& L, V2Link::Session& s, bool from_client, int count,
                int budget_ms = 8000) {
    V2Endpoint& to = from_client ? s.srv : s.cli;
    const uint64_t want = to.rx.received + count;
    for (int i = 0; i < count; ++i) {
        if (!send_app(s, from_client)) return false;
        if ((i & 3) == 3) pump_once(L, 1);
    }
    return run_until(L, [&] { return to.rx.received >= want; }, budget_ms);
}

bool exchange_app(V2Link& L, V2Link::Session& s, int count,
                  int budget_ms = 8000) {
    const uint64_t want_srv = s.srv.rx.received + count;
    const uint64_t want_cli = s.cli.rx.received + count;
    for (int i = 0; i < count; ++i) {
        if (!send_app(s, true) || !send_app(s, false)) return false;
        if ((i & 3) == 3) pump_once(L, 1);
    }
    return run_until(
        L, [&] { return s.srv.rx.received >= want_srv &&
                        s.cli.rx.received >= want_cli; },
        budget_ms);
}

bool both_idle(V2Link::Session& s) {
    return s.cli.a->stats().transition_state == ProfileTransitionState::IDLE &&
           s.srv.a->stats().transition_state == ProfileTransitionState::IDLE;
}

/// Drive the transition to completion including grace-drain finalization.
bool settle_transition(V2Link& L, V2Link::Session& s, int budget_ms = 8000) {
    return run_until(
        L,
        [&] {
            return both_idle(s) && !s.cli.a->has_outbound() &&
                   !s.srv.a->has_outbound() && s.cli.data_q.empty() &&
                   s.srv.data_q.empty();
        },
        budget_ms);
}

TransitionError start_quic_switch(V2Link::Session& s) {
    return s.cli.a->start_profile_transition(
        kQuicRef, kL0, TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER,
        now_ms());
}

/// Zero-loss / zero-reorder stream assertion: received counts, no dups, no
/// gaps, SHA-256 of both directions equal to the deterministic expectation
/// (and hence to the identical no-switch control run).
void expect_stream_intact(V2Link::Session& s, uint32_t cli_msgs,
                          uint32_t srv_msgs, uint32_t first_seq = 0) {
    EXPECT_EQ(s.srv.rx.received, first_seq + cli_msgs);
    EXPECT_EQ(s.cli.rx.received, first_seq + srv_msgs);
    EXPECT_EQ(s.srv.rx.duplicates, 0u) << "duplicate app payload at server";
    EXPECT_EQ(s.cli.rx.duplicates, 0u) << "duplicate app payload at client";
    EXPECT_EQ(s.srv.rx.gaps, 0u) << "app gap at server";
    EXPECT_EQ(s.cli.rx.gaps, 0u) << "app gap at client";
    EXPECT_EQ(s.srv.rx.hash.final(),
              expected_stream_hash(1, 0, first_seq + cli_msgs))
        << "SHA-256 of cli->srv application stream mismatch";
    EXPECT_EQ(s.cli.rx.hash.final(),
              expected_stream_hash(2, 0, first_seq + srv_msgs))
        << "SHA-256 of srv->cli application stream mismatch";
}

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return sodium_init() >= 0;
    }();
    ASSERT_TRUE(once);
}

#define UDP_LINK_OR_SKIP(link_var, n_sessions)                                \
    ensure_init();                                                            \
    V2Link link_var;                                                          \
    if (!link_start(link_var, n_sessions))                                    \
        GTEST_SKIP() << "loopback UDP sockets unavailable in this environment"

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// T2-happy (design §2.2): GENERIC_UDP → QUIC_SHORT_HEADER with a continuous
// application stream, over REAL UDP. Session 0 is the identical no-switch
// control; session 1 performs the switch; both must end with byte-identical
// streams (same deterministic generator ⇒ same SHA-256).
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransitionV2, HappyPathQuicShortHeaderStreamEquality) {
    UDP_LINK_OR_SKIP(_link, 2);
    V2Link& L = _link;
    V2Link::Session& ctl = *L.sessions[0];
    V2Link::Session& sw = *L.sessions[1];
    ASSERT_TRUE(session_up(L, ctl));
    ASSERT_TRUE(session_up(L, sw));

    // v2 negotiated on both sessions (strict AND of the capability bits).
    EXPECT_TRUE(ctl.cli.a->stats().transition_v2_capable);
    EXPECT_TRUE(ctl.srv.a->stats().transition_v2_capable);
    EXPECT_TRUE(sw.cli.a->stats().transition_v2_capable);

    // ── Control run: 200 datagrams per direction, no switch ──────────────
    ASSERT_TRUE(exchange_app(L, ctl, 200));
    expect_stream_intact(ctl, 200, 200);
    EXPECT_EQ(ctl.cli.a->stats().transition_counters.control_tx, 0u)
        << "control session emitted transition control traffic";

    // ── Switch run: same stream, GENERIC_UDP → QUIC_SHORT_HEADER ─────────
    ASSERT_TRUE(exchange_app(L, sw, 60));  // stable-profile phase
    EXPECT_EQ(sw.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_UDP);

    ASSERT_EQ(start_quic_switch(sw), TransitionError::NONE);
    EXPECT_EQ(sw.cli.a->stats().transition_state,
              ProfileTransitionState::PREPARE);

    // Continuous traffic through every stage of the two-phase commit.
    ASSERT_TRUE(run_until(L,
                          [&] {
                              return sw.srv.a->stats().transition_state ==
                                     ProfileTransitionState::READY;
                          },
                          5000));
    ASSERT_TRUE(exchange_app(L, sw, 10));  // both still old mask/epoch
    // Wait until the initiator has ACTIVATED (stamps the new epoch). COMMIT
    // is a transient state on loopback — a full READY→COMMIT→CONFIRM→DRAIN
    // round trip can complete inside one pump cycle, so key on the epoch
    // flip, not on observing the state.
    ASSERT_TRUE(run_until(L,
                          [&] {
                              return sw.cli.a->stats().tx_epoch == 1u;
                          },
                          5000));
    // Initiator activated: new mask + new epoch. The COMMIT/CONFIRM control
    // datagrams were queued BEFORE these datagrams were produced, and the
    // harness flushes control first — FIFO loopback then guarantees the
    // responder activates before any new-epoch data arrives (zero-gap
    // invariant: no early-new rejection, just like v1).
    ASSERT_TRUE(exchange_app(L, sw, 10));
    ASSERT_TRUE(run_until(L,
                          [&] {
                              return sw.cli.a->stats().transition_state ==
                                         ProfileTransitionState::DRAIN &&
                                     sw.srv.a->stats().transition_state ==
                                         ProfileTransitionState::DRAIN;
                          },
                          5000));
    ASSERT_TRUE(exchange_app(L, sw, 10));  // both on QUIC_SHORT_HEADER

    EXPECT_EQ(sw.srv.a->stats().transition_counters.rx_rejected_early_new, 0u);
    EXPECT_EQ(sw.cli.a->stats().transition_counters.rx_rejected_early_new, 0u);
    EXPECT_EQ(sw.srv.a->stats().transition_counters.rx_rejected_unknown_epoch,
              0u);

    ASSERT_TRUE(settle_transition(L, sw));
    ASSERT_TRUE(exchange_app(L, sw, 110));  // 60+10+10+10+110 = 200

    // Same stream as the no-switch control, byte for byte.
    expect_stream_intact(sw, 200, 200);
    EXPECT_EQ(sw.srv.rx.hash.final(), ctl.srv.rx.hash.final());
    EXPECT_EQ(sw.cli.rx.hash.final(), ctl.cli.rx.hash.final());

    // Effective transition, QUIC_SHORT_HEADER active on both, one commit.
    const auto ca = sw.cli.a->stats().transition_counters;
    const auto cb = sw.srv.a->stats().transition_counters;
    EXPECT_EQ(ca.transitions_started, 1u);
    EXPECT_EQ(ca.transitions_committed, 1u);
    EXPECT_EQ(ca.transitions_effective, 1u);
    EXPECT_EQ(ca.transitions_uncertain, 0u);
    EXPECT_EQ(cb.transitions_effective, 1u);
    EXPECT_EQ(ca.control_retransmits, 0u);
    EXPECT_EQ(sw.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    EXPECT_EQ(sw.srv.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    EXPECT_EQ(sw.cli.a->stats().profile_epoch, 1u);
    EXPECT_EQ(sw.srv.a->stats().profile_epoch, 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// T2-loss20 (design §2.2): deterministic ~20% control-datagram loss. The
// impaired switch run must deliver exactly the control run's application
// stream — fresh-AEAD control retransmission absorbs control loss; the
// pending/old mask candidates keep data flowing meanwhile.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransitionV2, ControlLossParity20Percent) {
    UDP_LINK_OR_SKIP(_link, 2);
    V2Link& L = _link;
    V2Link::Session& ctl = *L.sessions[0];
    V2Link::Session& sw = *L.sessions[1];
    ASSERT_TRUE(session_up(L, ctl));
    ASSERT_TRUE(session_up(L, sw));
    ASSERT_TRUE(ctl.cli.a->stats().transition_v2_capable);

    ctl.drop = DropMode::kScatter20;  // no control traffic ⇒ no-op there
    sw.drop = DropMode::kScatter20;

    // Control run (no switch) under the same impairment policy.
    ASSERT_TRUE(exchange_app(L, ctl, 120));
    expect_stream_intact(ctl, 120, 120);

    // Impaired switch run: loss starts BEFORE the transition begins.
    ASSERT_TRUE(exchange_app(L, sw, 40));
    ASSERT_EQ(start_quic_switch(sw), TransitionError::NONE);
    ASSERT_TRUE(run_until(L,
                          [&] {
                              return sw.cli.a->stats().transition_state ==
                                         ProfileTransitionState::DRAIN &&
                                     sw.srv.a->stats().transition_state ==
                                         ProfileTransitionState::DRAIN;
                          },
                          12000));
    ASSERT_TRUE(exchange_app(L, sw, 20));
    ASSERT_TRUE(settle_transition(L, sw, 12000));
    ASSERT_TRUE(exchange_app(L, sw, 60));  // 40+20+60 = 120

    // Parity: the transition-induced loss over the control run is ZERO.
    expect_stream_intact(sw, 120, 120);
    EXPECT_EQ(sw.srv.rx.hash.final(), ctl.srv.rx.hash.final());
    EXPECT_EQ(sw.cli.rx.hash.final(), ctl.cli.rx.hash.final());

    // The loss was real and was absorbed by fresh retransmission.
    const auto ca = sw.cli.a->stats().transition_counters;
    const auto cb = sw.srv.a->stats().transition_counters;
    EXPECT_GT(ca.control_retransmits + cb.control_retransmits, 0u)
        << "20% control loss never triggered a retransmission — pattern bug";
    EXPECT_EQ(ca.transitions_effective, 1u);
    EXPECT_EQ(cb.transitions_effective, 1u);
    EXPECT_EQ(ca.transitions_uncertain, 0u);
    EXPECT_EQ(sw.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
}

// ══════════════════════════════════════════════════════════════════════════════
// T2-commit-storm (design §2.2 + lead-approved deviation): 100% COMMIT/CONFIRM
// loss (all control dropped after the READY). The initiator burns its
// retransmit budget and finalizes UNCERTAIN, keeping the QUIC mask; the
// responder times out cleanly and rolls back to GENERIC_UDP. With arbitrary
// (non-cross-decodable) v2 masks this divergence cannot be repaired in-band —
// BY DESIGN (C1 pins the recovery PREPARE to the diverged mask; the epoch
// fence rejects it anyway). The test asserts:
//   (1) the divergent counters/masks and that the divergence is surfaced
//       (cross-traffic dropped + counted, never silent);
//   (2) a doomed in-band recovery attempt fails BOUNDED (PREPARE budget
//       exhausts → transitions_timed_out, back to IDLE, queues drain);
//   (3) the actual recovery primitive — session re-establishment — followed
//       by a fresh transition re-synchronizes both endpoints on the QUIC
//       target with matching stream hashes.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransitionV2, CommitStormUncertainDivergenceRecovery) {
    UDP_LINK_OR_SKIP(_link, 2);
    V2Link& L = _link;
    V2Link::Session& s = *L.sessions[0];
    ASSERT_TRUE(session_up(L, s));
    ASSERT_TRUE(s.cli.a->stats().transition_v2_capable);
    ASSERT_TRUE(exchange_app(L, s, 10));

    // Arm the storm: PREPARE (cli ctl #0) and READY (srv ctl #0) pass;
    // every subsequent control datagram is lost at the send edge.
    s.drop = DropMode::kStormAfterFirst;
    ASSERT_EQ(start_quic_switch(s), TransitionError::NONE);

    // The initiator activates at READY, never gets confirmed, exhausts its
    // retransmit budget → UNCERTAIN → DRAIN → grace → finalize (keeps QUIC).
    // The responder retransmits READY into the void, times out, rolls back
    // to GENERIC_UDP. Both return to IDLE with bounded queues.
    ASSERT_TRUE(run_until(L,
                          [&] {
                              return both_idle(s) &&
                                     s.cli.a->stats()
                                             .transition_counters
                                             .transitions_uncertain == 1u &&
                                     s.srv.a->stats()
                                             .transition_counters
                                             .transitions_timed_out == 1u;
                          },
                          15000));

    // (1) Divergence, surfaced: initiator on QUIC_SHORT_HEADER at epoch 1,
    //     responder back on GENERIC_UDP at epoch 0. Cross-traffic now fails
    //     closed at the mask layer and is COUNTED, never delivered.
    EXPECT_EQ(s.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    EXPECT_EQ(s.srv.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_UDP);
    EXPECT_EQ(s.cli.a->stats().profile_epoch, 1u);
    EXPECT_EQ(s.srv.a->stats().profile_epoch, 0u);

    s.drop = DropMode::kNone;  // storm over — the link itself is healthy
    {
        const uint64_t srv_rx0 = s.srv.rx.received;
        const uint64_t cli_rx0 = s.cli.rx.received;
        const auto drop_srv0 = s.srv.a->stats().ingress_dropped;
        const auto drop_cli0 = s.cli.a->stats().ingress_dropped;
        for (int i = 0; i < 5; ++i) {
            ASSERT_TRUE(send_app(s, true));   // QUIC-wrapped → srv drops
            ASSERT_TRUE(send_app(s, false));  // GENERIC-wrapped → cli drops
        }
        pump_once(L, 2);
        pump_once(L, 2);
        EXPECT_EQ(s.srv.rx.received, srv_rx0)
            << "diverged peer's data reached the application";
        EXPECT_EQ(s.cli.rx.received, cli_rx0);
        EXPECT_GT(s.srv.a->stats().ingress_dropped, drop_srv0);
        EXPECT_GT(s.cli.a->stats().ingress_dropped, drop_cli0);
        // Drop the poisoned datagrams from the trackers' accounting scope:
        // the stream assertion below covers only the recovered session.
    }

    // (2) The in-band recovery attempt is BOUNDED: the initiator's PREPARE
    //     goes out pinned to its (diverged) QUIC mask, the responder cannot
    //     unwrap it (candidate set {GENERIC_UDP}), the retransmit budget
    //     exhausts and the initiator rolls back to IDLE — counted, bounded,
    //     no crash, no queue growth. This is the C1-pin + epoch-fence
    //     evidence that in-band re-sync is impossible by construction.
    const auto drop_srv1 = s.srv.a->stats().ingress_dropped;
    const auto ctl_rx_srv1 =
        s.srv.a->stats().transition_counters.control_rx;
    ASSERT_EQ(s.cli.a->start_profile_transition(
                  kBaseRef, kL0, TrafficMimicry::MimicProfile::GENERIC_UDP,
                  now_ms()),
              TransitionError::NONE);
    ASSERT_TRUE(run_until(L,
                          [&] {
                              return s.cli.a->stats().transition_state ==
                                         ProfileTransitionState::IDLE &&
                                     s.cli.a->stats()
                                             .transition_counters
                                             .transitions_timed_out == 1u;
                          },
                          10000));
    EXPECT_EQ(s.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER)
        << "bounded failure must not change the committed mask";
    EXPECT_EQ(s.srv.a->stats().transition_counters.control_rx, ctl_rx_srv1)
        << "undecodable PREPAREs reached the responder's control plane";
    EXPECT_GT(s.srv.a->stats().ingress_dropped, drop_srv1);
    ASSERT_TRUE(settle_transition(L, s, 5000));  // queues drain; nothing wedges

    // (3) Recovery primitive: session re-establishment, then a fresh
    //     transition re-synchronizes both endpoints on the QUIC target.
    V2Link::Session& r = *L.sessions[1];
    ASSERT_TRUE(session_up(L, r));
    ASSERT_TRUE(r.cli.a->stats().transition_v2_capable);
    ASSERT_TRUE(exchange_app(L, r, 10));
    ASSERT_EQ(start_quic_switch(r), TransitionError::NONE);
    ASSERT_TRUE(settle_transition(L, r, 12000));
    const auto rc = r.cli.a->stats().transition_counters;
    const auto rs = r.srv.a->stats().transition_counters;
    EXPECT_EQ(rc.transitions_effective, 1u);
    EXPECT_EQ(rs.transitions_effective, 1u);
    EXPECT_EQ(rc.transitions_uncertain, 0u);
    EXPECT_EQ(r.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    EXPECT_EQ(r.srv.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::QUIC_SHORT_HEADER);
    ASSERT_TRUE(exchange_app(L, r, 10));
    expect_stream_intact(r, 20, 20);
}

// ══════════════════════════════════════════════════════════════════════════════
// T2-legacy (design §2.2): a v1-only peer (advertise_profile_transition_v2 =
// false) ⇒ v2 not negotiated ⇒ the QUIC_SHORT_HEADER target is refused at the
// initiator with INVALID_PROFILE, ZERO control traffic leaves the socket, and
// the v1 session keeps flowing undisturbed.
// ══════════════════════════════════════════════════════════════════════════════

TEST(UdpProfileTransitionV2, LegacyPeerRefusalZeroControlTraffic) {
    UDP_LINK_OR_SKIP(_link, 1);
    V2Link& L = _link;
    V2Link::Session& s = *L.sessions[0];
    ASSERT_TRUE(session_up(L, s, /*cli_v2=*/true, /*srv_v2=*/false));

    // v1 negotiated (transition v1 capable, v2 gate closed on both sides).
    EXPECT_TRUE(s.cli.a->transition_capable());
    EXPECT_TRUE(s.srv.a->transition_capable());
    EXPECT_FALSE(s.cli.a->stats().transition_v2_capable);
    EXPECT_FALSE(s.srv.a->stats().transition_v2_capable);

    ASSERT_TRUE(exchange_app(L, s, 10));
    const auto c0 = s.cli.a->stats().transition_counters;
    const auto r0 = s.srv.a->stats().transition_counters;

    // The non-generic target is refused LOCALLY under the v1 schedule...
    EXPECT_EQ(start_quic_switch(s), TransitionError::INVALID_PROFILE);
    // ...with zero control traffic and zero state change.
    EXPECT_FALSE(s.cli.a->has_outbound());
    pump_once(L, 2);
    const auto c1 = s.cli.a->stats().transition_counters;
    const auto r1 = s.srv.a->stats().transition_counters;
    EXPECT_EQ(c1.control_tx, c0.control_tx);
    EXPECT_EQ(c1.control_retransmits, c0.control_retransmits);
    EXPECT_EQ(c1.transitions_started, c0.transitions_started);
    EXPECT_EQ(r1.control_rx, r0.control_rx)
        << "legacy peer received control traffic for a refused v2 target";
    EXPECT_EQ(s.cli.a->stats().transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(s.cli.a->stats().profile_epoch, 0u);
    EXPECT_EQ(s.cli.a->stats().active_mimic,
              TrafficMimicry::MimicProfile::GENERIC_UDP);

    // The v1 session is undisturbed; identical stream as the control.
    ASSERT_TRUE(exchange_app(L, s, 10));
    expect_stream_intact(s, 20, 20);
}
