// ══════════════════════════════════════════════════════════════════════════════
// tests/test_connection_director.cpp
//
// Hermetic tests for NcpConnectionDirector — the per-session production
// registry that owns one NcpMimicrySession per (PortHop) session id.
//
// Real adapters on both ends (real X25519 E2E handshake, real catalog-driven
// profile transitions); the transport is an in-memory datagram wire between
// a client-role and a server-role director. A manual monotonic clock drives
// poll(); the only real threads are the cross-thread request producers
// (RotationCoordinator callback / explicit std::thread), matching the
// director contract: foreign threads enqueue, the poll loop applies.
//
// Evidence covered:
//   * bring-up: handshake + capability pump through poll(), protected echo
//   * two-session isolation (registry keyed by session id)
//   * cross-thread rotation requests are ONLY enqueued and drained by poll
//   * bounded request queue (overflow -> BUSY/false, counted)
//   * legacy peer: transition requests refused NOT_SUPPORTED, nothing emitted
//   * pacing_delay honored via the due queue; control prioritized
//   * commit / abort / timeout feedback for requested transitions
//   * registry bounds + clear constructor validation errors
//   * stats counters; no reconnect / no crypto reset across transitions
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_connection_director.hpp"

#include <atomic>
#include <deque>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace ncp;

namespace {

constexpr NcpConnectionDirector::SessionId kSidA = 0xAAAA0001;
constexpr NcpConnectionDirector::SessionId kSidB = 0xBBBB0002;

constexpr const char* kBaselineId = "generic.udp";
constexpr const char* kTargetId   = "generic.tcp";

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return true;
    }();
    ASSERT_TRUE(once);
}

// ── Test catalog (mirrors tests/test_mimicry_session.cpp) ───────────────────

ProfileDescriptor make_descriptor(const char* id, ProtocolFamily fam,
                                  uint32_t padding_block) {
    ProfileDescriptor d;
    d.profile_id = id;
    d.revision = 1;
    d.family = fam;
    d.min_wire_version = 1;
    d.max_wire_version = 3;

    d.sizes.kind = SizeDistKind::NORMAL;
    d.sizes.mean = 700.0;
    d.sizes.stddev = 60.0;
    d.sizes.clamp_min = 64.0;
    d.sizes.clamp_max = 1200.0;

    d.iat.kind = IntervalKind::NORMAL;
    d.iat.mean_ms = 5.0;
    d.iat.stddev_ms = 1.0;

    d.padding_header.header_overhead_bytes = 0;
    d.padding_header.padding_block_bytes = padding_block;
    d.padding_header.padding_max_bytes = 64;
    d.padding_header.pad_to_block = padding_block > 0;

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1400;

    d.provenance.sample_count = 5000;
    d.provenance.window_count = 50;

    d.derivation.size_mean_rel_jitter = 0.10;
    d.derivation.iat_mean_rel_jitter = 0.10;
    d.derivation.burst_rel_jitter = 0.10;
    d.derivation.fsm_dwell_rel_jitter = 0.10;
    d.derivation.padding_extra_max_bytes = 16;
    d.derivation.header_gap_shift_max_bytes = 4;

    ReferenceProfileCatalog::update_content_hash(d);
    return d;
}

struct TestCatalog {
    ReferenceProfileCatalog catalog;
    TestCatalog() {
        auto b = catalog.register_builtin(
            make_descriptor(kBaselineId, ProtocolFamily::GENERIC_UDP, 0));
        EXPECT_TRUE(b.ok()) << (b.issues.empty() ? "" : b.issues[0].message);
        auto t = catalog.register_builtin(
            make_descriptor(kTargetId, ProtocolFamily::GENERIC_TCP, 16));
        EXPECT_TRUE(t.ok()) << (t.issues.empty() ? "" : t.issues[0].message);
    }
};

NcpMimicrySession::Config make_session_template(
    const TestCatalog& cat, NcpMimicrySession::Role role,
    bool advertise_transition) {
    const auto* desc = cat.catalog.find(kBaselineId, 1);
    EXPECT_NE(desc, nullptr);
    NcpMimicrySession::Config c;
    c.role = role;
    c.e2e_config.enable_padding = false;  // deterministic wire sizes
    c.stable_profile = profile_ref_from_descriptor(*desc);
    c.stable_layout = profile_layout_from_descriptor(*desc);
    c.stable_mimic = TrafficMimicry::MimicProfile::GENERIC_UDP;
    c.catalog = &cat.catalog;
    c.mimic_config.profile = TrafficMimicry::MimicProfile::GENERIC_UDP;
    c.mimic_config.wire_version = 3;
    c.mimic_config.enable_timing_mimicry = false;
    c.mimic_config.min_padding = 24;
    c.mimic_config.max_padding = 24;
    c.mimic_resolver = [](const ProfileRef& r)
        -> std::optional<TrafficMimicry::MimicProfile> {
        if (r.id == kBaselineId) return TrafficMimicry::MimicProfile::GENERIC_UDP;
        if (r.id == kTargetId) return TrafficMimicry::MimicProfile::GENERIC_TCP;
        return std::nullopt;
    };
    c.advertise_profile_transition = advertise_transition;
    c.allow_insecure_plaintext_legacy = false;
    c.transition_config.retransmit_interval_ms = 50;
    c.transition_config.max_retransmit_attempts = 6;
    c.transition_config.grace_period_ms = 1000;
    c.path_mtu_bytes = 1500;
    c.porthop_overhead_bytes = 20;  // PortHop frame header
    c.max_application_payload = 1024;
    return c;
}

NcpConnectionDirector::Config make_director_config(
    const TestCatalog& cat, NcpMimicrySession::Role role,
    bool advertise_transition = true) {
    NcpConnectionDirector::Config d;
    d.session_template = make_session_template(cat, role, advertise_transition);
    return d;
}

std::vector<uint8_t> app_payload(uint32_t seq, size_t len) {
    std::vector<uint8_t> p(len);
    p[0] = static_cast<uint8_t>((seq >> 24) & 0xFF);
    p[1] = static_cast<uint8_t>((seq >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((seq >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(seq & 0xFF);
    for (size_t i = 4; i < len; ++i)
        p[i] = static_cast<uint8_t>((seq * 31u + i * 7u) & 0xFF);
    return p;
}

// ── Director pair with an in-memory wire ────────────────────────────────────

struct Pair {
    TestCatalog cat;
    NcpConnectionDirector cli;  // client role, explicit session
    NcpConnectionDirector srv;  // server role, auto-accept
    uint64_t now = 1'000'000;   // manual monotonic ms

    std::vector<NcpConnectionDirector::Egress> cli_wire;
    std::vector<NcpConnectionDirector::Egress> srv_wire;

    explicit Pair(bool advertise_transition = true)
        : cli(make_director_config(cat, NcpMimicrySession::Role::Client,
                                   advertise_transition)),
          srv(make_director_config(cat, NcpMimicrySession::Role::Server)) {
        EXPECT_TRUE(cli.is_valid()) << cli.config_error();
        EXPECT_TRUE(srv.is_valid()) << srv.config_error();
    }

    /// Move all due datagrams both ways until quiescent (no time passes).
    void pump() {
        for (int i = 0; i < 200; ++i) {
            bool progress = false;
            for (auto& e : cli.poll(now)) {
                cli_wire.push_back(e);
                srv.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            for (auto& e : srv.poll(now)) {
                srv_wire.push_back(e);
                cli.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            if (!progress) break;
        }
    }

    void advance(uint64_t ms) { now += ms; }
    void advance_and_pump(uint64_t ms) {
        advance(ms);
        pump();
    }

    bool established(NcpConnectionDirector::SessionId sid = kSidA) {
        if (!cli.has_session(sid)) {
            EXPECT_EQ(cli.add_session(sid), NcpConnectionDirector::Error::NONE);
        }
        if (!cli.is_established(sid)) {
            EXPECT_EQ(cli.start_handshake(sid, now),
                      NcpConnectionDirector::Error::NONE);
            pump();
        }
        pump();
        return cli.is_established(sid) && srv.is_established(sid);
    }

    /// Application-level protected echo on the server (poll-loop driven).
    void server_echo() {
        while (auto app = srv.next_application_data()) {
            EXPECT_EQ(srv.send_application(app->session_id, app->payload, now),
                      NcpConnectionDirector::Error::NONE);
        }
    }
};

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Constructor validation: bounded defaults must be non-zero, clear errors.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, ConfigValidationErrors) {
    ensure_init();
    TestCatalog cat;

    {
        auto cfg = make_director_config(cat, NcpMimicrySession::Role::Server);
        cfg.max_sessions = 0;
        NcpConnectionDirector d(cfg);
        EXPECT_FALSE(d.is_valid());
        EXPECT_NE(d.config_error().find("max_sessions"), std::string::npos);
        // No-ops on an invalid director.
        EXPECT_EQ(d.add_session(kSidA), NcpConnectionDirector::Error::INVALID_STATE);
        EXPECT_TRUE(d.poll(0).empty());
    }
    {
        auto cfg = make_director_config(cat, NcpMimicrySession::Role::Server);
        cfg.max_pending_requests = 0;
        NcpConnectionDirector d(cfg);
        EXPECT_FALSE(d.is_valid());
        EXPECT_NE(d.config_error().find("max_pending_requests"),
                  std::string::npos);
    }
    {
        auto cfg = make_director_config(cat, NcpMimicrySession::Role::Server);
        cfg.session_template.stable_profile.id.clear();
        NcpConnectionDirector d(cfg);
        EXPECT_FALSE(d.is_valid());
        EXPECT_NE(d.config_error().find("stable_profile"), std::string::npos);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Bring-up: real handshake + capability pump through poll(), protected echo,
// registry keyed by session id, director stats.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, BringupProtectedEchoAndStats) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());
    ASSERT_TRUE(p.cli.is_valid());

    // Server registry learned the session by its PortHop session id.
    EXPECT_TRUE(p.srv.has_session(kSidA));
    EXPECT_EQ(p.srv.session_count(), 1u);
    ASSERT_EQ(p.srv.session_ids().size(), 1u);
    EXPECT_EQ(p.srv.session_ids()[0], kSidA);

    // Negotiated transition capability on both ends.
    const auto cs = p.cli.session_stats(kSidA);
    const auto ss = p.srv.session_stats(kSidA);
    ASSERT_TRUE(cs.has_value());
    ASSERT_TRUE(ss.has_value());
    EXPECT_TRUE(cs->established);
    EXPECT_TRUE(cs->transition_capable);
    EXPECT_TRUE(ss->transition_capable);
    EXPECT_EQ(cs->active_profile.id, kBaselineId);

    // Capabilities actually flowed on the wire (kind 'C' datagrams).
    bool saw_caps = false;
    for (const auto& e : p.cli_wire)
        if (!e.bytes.empty() && e.bytes[0] == 'C') saw_caps = true;
    EXPECT_TRUE(saw_caps);

    // Protected echo: client -> server inbox -> server echo -> client inbox.
    const auto msg = app_payload(42, 96);
    ASSERT_EQ(p.cli.send_application(kSidA, msg, p.now),
              NcpConnectionDirector::Error::NONE);
    p.advance_and_pump(1000);
    p.server_echo();
    p.advance_and_pump(1000);

    auto echo = p.cli.next_application_data();
    ASSERT_TRUE(echo.has_value());
    EXPECT_EQ(echo->session_id, kSidA);
    EXPECT_EQ(echo->payload, msg);

    // No plaintext on the wire: data datagrams are the outer-mimicked E2E
    // form (kind 'E'), never kind 'P'.
    bool saw_data = false;
    for (const auto& e : p.cli_wire) {
        ASSERT_FALSE(e.bytes.empty());
        ASSERT_NE(e.bytes[0], 'P') << "plaintext datagram emitted";
        if (e.bytes[0] == 'E' && !e.is_control) saw_data = true;
    }
    EXPECT_TRUE(saw_data);

    // Director-level counters.
    const auto cst = p.cli.stats();
    const auto sst = p.srv.stats();
    EXPECT_EQ(cst.sessions_created, 1u);
    EXPECT_EQ(sst.sessions_created, 1u);
    EXPECT_GT(cst.datagrams_out, 0u);
    EXPECT_GT(sst.datagrams_in, 0u);
    EXPECT_EQ(cst.app_messages_out, 1u);
    EXPECT_EQ(sst.app_messages_in, 1u);
    EXPECT_EQ(sst.app_messages_out, 1u);  // echo
    EXPECT_EQ(cst.app_messages_in, 1u);
    EXPECT_EQ(cst.ingress_unknown_session, 0u);

    // Unknown-session ingress is dropped and counted (client role never
    // auto-accepts).
    const auto junk = app_payload(1, 16);
    p.cli.on_datagram(0xDEAD, junk, p.now);
    EXPECT_EQ(p.cli.stats().ingress_unknown_session, 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Two sessions through one server director: full isolation of transition,
// shaper and crypto state.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, TwoSessionIsolation) {
    ensure_init();
    TestCatalog cat;
    NcpConnectionDirector cliA(
        make_director_config(cat, NcpMimicrySession::Role::Client));
    NcpConnectionDirector cliB(
        make_director_config(cat, NcpMimicrySession::Role::Client));
    NcpConnectionDirector srv(
        make_director_config(cat, NcpMimicrySession::Role::Server));
    uint64_t now = 1'000'000;

    auto pump_all = [&]() {
        for (int i = 0; i < 200; ++i) {
            bool progress = false;
            for (auto& e : cliA.poll(now)) {
                srv.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            for (auto& e : cliB.poll(now)) {
                srv.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            for (auto& e : srv.poll(now)) {
                if (e.session_id == kSidA)
                    cliA.on_datagram(e.session_id, e.bytes, now);
                else if (e.session_id == kSidB)
                    cliB.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            if (!progress) break;
        }
    };

    ASSERT_EQ(cliA.add_session(kSidA), NcpConnectionDirector::Error::NONE);
    ASSERT_EQ(cliB.add_session(kSidB), NcpConnectionDirector::Error::NONE);
    ASSERT_EQ(cliA.start_handshake(kSidA, now), NcpConnectionDirector::Error::NONE);
    ASSERT_EQ(cliB.start_handshake(kSidB, now), NcpConnectionDirector::Error::NONE);
    pump_all();
    ASSERT_TRUE(cliA.is_established(kSidA));
    ASSERT_TRUE(cliB.is_established(kSidB));
    ASSERT_TRUE(srv.is_established(kSidA));
    ASSERT_TRUE(srv.is_established(kSidB));
    EXPECT_EQ(srv.session_count(), 2u);

    const std::string e2e_a = cliA.session_e2e_id(kSidA);
    const std::string e2e_b = cliB.session_e2e_id(kSidB);
    ASSERT_FALSE(e2e_a.empty());
    ASSERT_FALSE(e2e_b.empty());
    EXPECT_NE(e2e_a, e2e_b);
    const uint64_t crypto_a = cliA.session_stats(kSidA)->crypto_epoch;

    // Commit feedback capture for session A.
    std::vector<std::pair<std::string, uint32_t>> commits;
    std::vector<std::pair<std::string, uint32_t>> aborts;
    cliA.set_transition_feedback(
        [&](NcpConnectionDirector::SessionId sid, const std::string& id,
            uint32_t rev) {
            EXPECT_EQ(sid, kSidA);
            commits.emplace_back(id, rev);
        },
        [&](NcpConnectionDirector::SessionId, const std::string& id,
            uint32_t rev, AbortReason) {
            aborts.emplace_back(id, rev);
        });

    // Request a transition on session A only (revision 0 => latest).
    using TR = MimicryAutoPilot::TransitionResult;
    ASSERT_EQ(cliA.enqueue_profile_transition(kSidA, kTargetId, 0),
              TR::ACCEPTED);
    pump_all();
    now += 2000;  // pass the grace window
    pump_all();

    // Feedback: exactly one commit for the target, no aborts.
    ASSERT_EQ(commits.size(), 1u);
    EXPECT_EQ(commits[0].first, kTargetId);
    EXPECT_EQ(commits[0].second, 1u);
    EXPECT_TRUE(aborts.empty());
    EXPECT_EQ(cliA.stats().transition_commits_reported, 1u);

    // Session A switched on both ends; session B untouched.
    const auto as = cliA.session_stats(kSidA);
    const auto bs = cliB.session_stats(kSidB);
    ASSERT_TRUE(as.has_value());
    ASSERT_TRUE(bs.has_value());
    EXPECT_EQ(as->profile_epoch, 1u);
    EXPECT_EQ(as->active_profile.id, kTargetId);
    EXPECT_EQ(srv.session_stats(kSidA)->profile_epoch, 1u);
    EXPECT_EQ(bs->profile_epoch, 0u);
    EXPECT_EQ(bs->active_profile.id, kBaselineId);
    EXPECT_EQ(bs->transition_counters.transitions_started, 0u);
    EXPECT_EQ(srv.session_stats(kSidB)->profile_epoch, 0u);
    EXPECT_EQ(srv.session_stats(kSidB)
                  ->transition_counters.transitions_started, 0u);

    // No reconnect / no crypto reset: the mask-only switch keeps the E2E
    // session and crypto epoch.
    EXPECT_EQ(cliA.session_e2e_id(kSidA), e2e_a);
    EXPECT_EQ(cliB.session_e2e_id(kSidB), e2e_b);
    EXPECT_EQ(cliA.session_stats(kSidA)->crypto_epoch, crypto_a);
    EXPECT_EQ(cliA.session_stats(kSidA)->active_profile.id, kTargetId);

    // Data still flows on both sessions after the transition.
    ASSERT_EQ(cliA.send_application(kSidA, app_payload(1, 64), now),
              NcpConnectionDirector::Error::NONE);
    ASSERT_EQ(cliB.send_application(kSidB, app_payload(2, 64), now),
              NcpConnectionDirector::Error::NONE);
    now += 1000;
    pump_all();
    auto da = srv.next_application_data();
    auto db = srv.next_application_data();
    ASSERT_TRUE(da.has_value());
    ASSERT_TRUE(db.has_value());
    // Inbox is FIFO across sessions; both payloads arrived intact.
    EXPECT_TRUE((da->session_id == kSidA && db->session_id == kSidB) ||
                (da->session_id == kSidB && db->session_id == kSidA));

    // Session B can transition independently afterwards.
    ASSERT_EQ(cliB.enqueue_profile_transition(kSidB, kTargetId, 1),
              TR::ACCEPTED);
    pump_all();
    now += 2000;
    pump_all();
    EXPECT_EQ(cliB.session_stats(kSidB)->profile_epoch, 1u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Cross-thread rotation requests: callbacks (incl. a real RotationCoordinator
// and a raw std::thread) ONLY enqueue; poll() applies per-session E2E key
// rotation. L2 rotations are ignored (PortHop owns the hop epoch).
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, RotationThreadQueueEnqueueOnly) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());
    const uint64_t crypto0 = p.cli.session_stats(kSidA)->crypto_epoch;

    // Real RotationCoordinator driving the director's rotation callback.
    {
        DPI::RotationCoordinator rc;
        rc.set_rotation_callback(p.cli.rotation_callback());
        rc.start();
        rc.rotate_now(DPI::RotationLayer::L7_TLS);
        rc.stop();
    }
    // Enqueue-only: nothing applied until the poll loop drains.
    EXPECT_EQ(p.cli.stats().rotations_applied, 0u);
    EXPECT_EQ(p.cli.session_stats(kSidA)->crypto_epoch, crypto0);
    EXPECT_GE(p.cli.stats().rotations_enqueued, 1u);

    p.pump();
    EXPECT_GE(p.cli.stats().rotations_applied, 1u);
    EXPECT_EQ(p.cli.session_stats(kSidA)->crypto_epoch, crypto0 + 1);

    // A raw foreign thread: enqueue must be thread-safe and deferred.
    std::thread t([&] {
        p.cli.rotation_callback()(DPI::RotationLayer::L7_TIMING);
    });
    t.join();
    EXPECT_EQ(p.cli.session_stats(kSidA)->crypto_epoch, crypto0 + 1)
        << "rotation applied off the poll loop";

    // L2 rotation: acknowledged but ignored — the PortHop hop epoch is
    // separate and never touched by the director.
    EXPECT_TRUE(p.cli.enqueue_key_rotation(DPI::RotationLayer::L2_IDENTITY));
    p.pump();
    EXPECT_EQ(p.cli.stats().l2_rotations_ignored, 1u);

    // Data still flows after key rotation (same session, ratchet continued).
    ASSERT_EQ(p.cli.send_application(kSidA, app_payload(7, 64), p.now),
              NcpConnectionDirector::Error::NONE);
    p.advance_and_pump(1000);
    auto app = p.srv.next_application_data();
    ASSERT_TRUE(app.has_value());
    EXPECT_EQ(app->payload, app_payload(7, 64));
}

// ══════════════════════════════════════════════════════════════════════════════
// Bounded cross-thread queue: overflow is refused and counted, never silent.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, BoundedRequestQueue) {
    ensure_init();
    TestCatalog cat;
    auto cfg = make_director_config(cat, NcpMimicrySession::Role::Client);
    cfg.max_pending_requests = 2;
    NcpConnectionDirector cli(cfg);
    ASSERT_TRUE(cli.is_valid());
    ASSERT_EQ(cli.add_session(kSidA), NcpConnectionDirector::Error::NONE);

    // Fill the bounded queue with rotation requests.
    EXPECT_TRUE(cli.enqueue_key_rotation(DPI::RotationLayer::L7_TLS));
    EXPECT_TRUE(cli.enqueue_key_rotation(DPI::RotationLayer::L7_TIMING));
    EXPECT_FALSE(cli.enqueue_key_rotation(DPI::RotationLayer::L7_DUMMY));
    EXPECT_EQ(cli.stats().requests_dropped_full, 1u);
    EXPECT_EQ(cli.stats().rotations_enqueued, 2u);

    // Drain: both applied (no established session -> nothing rotates, but
    // the queue is drained and accepts new requests again).
    cli.poll(1'000'000);
    EXPECT_TRUE(cli.enqueue_key_rotation(DPI::RotationLayer::L7_TLS));

    // Transition enqueue for an unknown session is retryable-BUSY, and does
    // not consume queue space.
    using TR = MimicryAutoPilot::TransitionResult;
    EXPECT_EQ(cli.enqueue_profile_transition(0x9999, kTargetId, 1), TR::BUSY);
    // Unknown profile in the catalog is INVALID_PROFILE.
    ASSERT_EQ(cli.add_session(kSidB), NcpConnectionDirector::Error::NONE);
    EXPECT_EQ(cli.enqueue_profile_transition(kSidB, "no.such.profile", 1),
              TR::INVALID_PROFILE);
}

// ══════════════════════════════════════════════════════════════════════════════
// Legacy peer (profile_transition_v1 not negotiated): transition requests are
// refused NOT_SUPPORTED and NOTHING is emitted on the wire.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, LegacyPeerTransitionRejected) {
    ensure_init();
    Pair legacy(/*advertise_transition=*/false);  // client side is legacy
    ASSERT_TRUE(legacy.established());

    const auto cs = legacy.cli.session_stats(kSidA);
    const auto ss = legacy.srv.session_stats(kSidA);
    ASSERT_TRUE(cs.has_value());
    ASSERT_TRUE(ss.has_value());
    ASSERT_FALSE(cs->transition_capable);
    ASSERT_FALSE(ss->transition_capable);

    // Refused at enqueue time (cross-thread safe pre-check).
    using TR = MimicryAutoPilot::TransitionResult;
    EXPECT_EQ(legacy.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
              TR::NOT_SUPPORTED);
    EXPECT_EQ(legacy.cli.stats().requests_enqueued, 0u);

    // Nothing control-like is emitted after the refusal; the wire stays the
    // protected legacy form. Data still flows (E2E protected, never
    // plaintext).
    const size_t wire_before = legacy.cli_wire.size();
    legacy.pump();
    EXPECT_EQ(legacy.cli_wire.size(), wire_before);
    EXPECT_EQ(ss->transition_counters.control_rx, 0u);

    ASSERT_EQ(legacy.cli.send_application(kSidA, app_payload(1, 48),
                                          legacy.now),
              NcpConnectionDirector::Error::NONE);
    legacy.advance_and_pump(1000);
    auto app = legacy.srv.next_application_data();
    ASSERT_TRUE(app.has_value());
    EXPECT_EQ(app->payload, app_payload(1, 48));
    bool saw_control = false;
    for (size_t i = wire_before; i < legacy.cli_wire.size(); ++i)
        if (legacy.cli_wire[i].is_control) saw_control = true;
    EXPECT_FALSE(saw_control) << "legacy peer received transition control";
}

// ══════════════════════════════════════════════════════════════════════════════
// Pacing: data honors pacing_delay through the bounded due queue; control is
// prioritized and emitted immediately even while paced data is pending.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, PacingDueQueueAndControlPriority) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    // Send a batch of paced data at the same instant.
    constexpr int kBatch = 8;
    for (int i = 0; i < kBatch; ++i) {
        ASSERT_EQ(p.cli.send_application(kSidA, app_payload(i, 64), p.now),
                  NcpConnectionDirector::Error::NONE);
    }
    const auto immediate = p.cli.poll(p.now);
    size_t data_now = 0;
    for (const auto& e : immediate)
        if (!e.is_control) ++data_now;
    EXPECT_LT(data_now, static_cast<size_t>(kBatch))
        << "pacing_delay was not honored: the whole batch left instantly";

    // While paced data is still pending, transition control is prioritized:
    // it is emitted immediately, before the not-yet-due data.
    using TR = MimicryAutoPilot::TransitionResult;
    ASSERT_EQ(p.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
              TR::ACCEPTED);
    const auto with_control = p.cli.poll(p.now);
    bool saw_control = false;
    bool data_before_control = false;
    for (const auto& e : with_control) {
        if (e.is_control) saw_control = true;
        else if (!saw_control) data_before_control = true;
    }
    EXPECT_TRUE(saw_control) << "control datagram stuck behind paced data";
    EXPECT_FALSE(data_before_control)
        << "control was not prioritized over due data";

    // Everything drains once the pacing delays elapse.
    p.advance_and_pump(60'000);
    size_t delivered = 0;
    while (auto app = p.srv.next_application_data()) {
        (void)app;
        ++delivered;
    }
    EXPECT_EQ(delivered, static_cast<size_t>(kBatch));

    // Finish the transition cleanly (grace finalize) for a tidy teardown.
    p.advance_and_pump(2000);
}

// ══════════════════════════════════════════════════════════════════════════════
// Commit feedback drives a real MimicryAutoPilot (manual pin -> request ->
// director applies -> adapter effective -> autopilot commit).
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, AutoPilotCommitFeedbackIntegration) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    MimicryAutoPilot::Config apc;
    apc.enabled = true;
    apc.mode = MimicryAutoPilot::Mode::MANUAL;
    apc.catalog = &p.cat.catalog;
    apc.now_fn = [&] { return static_cast<int64_t>(p.now); };
    apc.request_transition = p.cli.transition_request_handler(kSidA);
    MimicryAutoPilot ap(std::move(apc));

    p.cli.set_transition_feedback(
        [&](NcpConnectionDirector::SessionId, const std::string& id,
            uint32_t rev) { ap.commit_transition(id, rev); },
        [&](NcpConnectionDirector::SessionId, const std::string& id,
            uint32_t rev, AbortReason) { ap.abort_transition(id, rev); });

    ASSERT_TRUE(ap.set_manual_profile(kTargetId, 1));
    ap.evaluate();  // issues the request via the director's enqueue handler
    ASSERT_TRUE(ap.has_outstanding_request());
    EXPECT_EQ(p.cli.stats().requests_enqueued, 1u);

    p.pump();
    p.advance_and_pump(2000);

    EXPECT_FALSE(ap.has_outstanding_request());
    EXPECT_EQ(ap.active_profile_id(), kTargetId);
    ASSERT_EQ(ap.switch_history().size(), 1u);
    EXPECT_EQ(p.cli.session_stats(kSidA)->profile_epoch, 1u);
    EXPECT_EQ(p.cli.stats().transition_commits_reported, 1u);
    EXPECT_EQ(p.cli.stats().transition_aborts_reported, 0u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Abort feedback: (a) peer unreachable -> adapter retransmit timeout ->
// abort feedback; (b) session removed before drain -> apply-time failure ->
// abort feedback. An ACCEPTED request is never left dangling.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, AbortFeedbackPaths) {
    ensure_init();

    // (a) retransmit timeout: request accepted, control never delivered.
    {
        Pair p;
        ASSERT_TRUE(p.established());
        std::vector<AbortReason> aborts;
        p.cli.set_transition_feedback(
            [](NcpConnectionDirector::SessionId, const std::string&,
               uint32_t) {},
            [&](NcpConnectionDirector::SessionId, const std::string&,
                uint32_t, AbortReason r) { aborts.push_back(r); });

        using TR = MimicryAutoPilot::TransitionResult;
        ASSERT_EQ(p.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
                  TR::ACCEPTED);
        // Poll only the client (egress dropped): retransmits exhaust.
        for (int i = 0; i < 20 && aborts.empty(); ++i) {
            p.advance(200);
            p.cli.poll(p.now);
        }
        ASSERT_EQ(aborts.size(), 1u);
        EXPECT_EQ(aborts[0], AbortReason::TIMEOUT);
        EXPECT_EQ(p.cli.stats().transition_aborts_reported, 1u);
        // Session survived: still the same established E2E session.
        EXPECT_TRUE(p.cli.is_established(kSidA));
        EXPECT_EQ(p.cli.session_stats(kSidA)->profile_epoch, 0u);
    }

    // (b) session removed before the request drains.
    {
        Pair p;
        ASSERT_TRUE(p.established());
        std::vector<AbortReason> aborts;
        p.cli.set_transition_feedback(
            [](NcpConnectionDirector::SessionId, const std::string&,
               uint32_t) {},
            [&](NcpConnectionDirector::SessionId, const std::string&,
                uint32_t, AbortReason r) { aborts.push_back(r); });

        using TR = MimicryAutoPilot::TransitionResult;
        ASSERT_EQ(p.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
                  TR::ACCEPTED);
        ASSERT_EQ(p.cli.remove_session(kSidA), NcpConnectionDirector::Error::NONE);
        p.cli.poll(p.now);
        ASSERT_EQ(aborts.size(), 1u);
        EXPECT_EQ(aborts[0], AbortReason::PROTOCOL_ERROR);
        EXPECT_EQ(p.cli.stats().requests_failed, 1u);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Registry bounds: session cap, duplicate/unknown handling, bounded inbox.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, RegistryAndInboxBounds) {
    ensure_init();
    TestCatalog cat;
    auto cfg = make_director_config(cat, NcpMimicrySession::Role::Server);
    cfg.max_sessions = 2;
    cfg.max_inbox = 2;
    NcpConnectionDirector srv(cfg);
    ASSERT_TRUE(srv.is_valid());

    EXPECT_EQ(srv.add_session(kSidA), NcpConnectionDirector::Error::NONE);
    EXPECT_EQ(srv.add_session(kSidA),
              NcpConnectionDirector::Error::SESSION_EXISTS);
    EXPECT_EQ(srv.add_session(kSidB), NcpConnectionDirector::Error::NONE);
    EXPECT_EQ(srv.add_session(0xCCCC),
              NcpConnectionDirector::Error::TOO_MANY_SESSIONS);
    EXPECT_EQ(srv.stats().session_create_rejected, 1u);
    EXPECT_EQ(srv.remove_session(0xCCCC),
              NcpConnectionDirector::Error::NO_SUCH_SESSION);

    // Auto-accept beyond the cap is refused and counted.
    const auto junk = app_payload(1, 8);
    srv.on_datagram(0xCCCC, junk, 1'000'000);
    EXPECT_FALSE(srv.has_session(0xCCCC));
    EXPECT_EQ(srv.stats().ingress_unknown_session, 1u);

    // Bounded inbox with a full client/server round trip.
    NcpConnectionDirector cli(
        make_director_config(cat, NcpMimicrySession::Role::Client));
    uint64_t now = 1'000'000;
    ASSERT_EQ(cli.add_session(kSidA), NcpConnectionDirector::Error::NONE);
    ASSERT_EQ(cli.start_handshake(kSidA, now), NcpConnectionDirector::Error::NONE);
    auto pump = [&]() {
        for (int i = 0; i < 200; ++i) {
            bool progress = false;
            for (auto& e : cli.poll(now)) {
                srv.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            for (auto& e : srv.poll(now)) {
                cli.on_datagram(e.session_id, e.bytes, now);
                progress = true;
            }
            if (!progress) break;
        }
    };
    pump();
    ASSERT_TRUE(cli.is_established(kSidA));
    ASSERT_TRUE(srv.is_established(kSidA));

    // Four messages arrive; the bounded inbox (2) keeps the first two and
    // counts the overflow — nothing is silently lost.
    for (int i = 0; i < 4; ++i) {
        ASSERT_EQ(cli.send_application(kSidA, app_payload(i, 32), now),
                  NcpConnectionDirector::Error::NONE);
    }
    now += 60'000;
    pump();
    EXPECT_EQ(srv.stats().app_messages_in, 4u);
    EXPECT_EQ(srv.stats().inbox_dropped, 2u);
    int drained = 0;
    while (srv.next_application_data()) ++drained;
    EXPECT_EQ(drained, 2);
}

// ══════════════════════════════════════════════════════════════════════════════
// No reconnect / no crypto reset across a director-driven transition:
// E2E session id and crypto epoch survive; counters stay monotonic.
// ══════════════════════════════════════════════════════════════════════════════

TEST(ConnectionDirector, NoReconnectNoCryptoResetAcrossTransition) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    const auto before = p.cli.session_stats(kSidA);
    ASSERT_TRUE(before.has_value());
    const std::string sid_before = p.cli.session_e2e_id(kSidA);
    ASSERT_FALSE(sid_before.empty());

    ASSERT_TRUE(p.cli.send_application(kSidA, app_payload(1, 64), p.now) ==
                NcpConnectionDirector::Error::NONE);
    p.advance_and_pump(1000);
    const auto mid = p.cli.session_stats(kSidA);
    ASSERT_GT(mid->e2e_messages_sent, before->e2e_messages_sent);

    using TR = MimicryAutoPilot::TransitionResult;
    ASSERT_EQ(p.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
              TR::ACCEPTED);
    p.pump();
    p.advance_and_pump(2000);

    const auto after = p.cli.session_stats(kSidA);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->profile_epoch, 1u);
    EXPECT_EQ(after->active_profile.id, kTargetId);
    EXPECT_EQ(after->crypto_epoch, mid->crypto_epoch)
        << "mask-only switch changed the E2E crypto epoch";
    EXPECT_EQ(p.cli.session_e2e_id(kSidA), sid_before)
        << "E2E session id changed (reconnect?)";
    EXPECT_GT(after->e2e_messages_sent, mid->e2e_messages_sent)
        << "E2E message counters reset (reconnect?)";
    EXPECT_GE(after->e2e_sending_chain_length, mid->e2e_sending_chain_length);
    EXPECT_TRUE(p.cli.is_established(kSidA));
}
