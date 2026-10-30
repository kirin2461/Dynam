// ══════════════════════════════════════════════════════════════════════════════
// tests/test_orchestrator_mimicry_provider.cpp
//
// Hermetic tests for the read-only per-session UDP/mimicry telemetry path:
//
//   NcpConnectionDirector (poll loop publishes snapshots)
//     -> IMimicrySessionProvider (ncp_mimicry_session_provider.hpp)
//     -> ProtocolOrchestrator::get_stats() aggregates
//
// Real adapters on both ends (real X25519 E2E handshake, real catalog-driven
// profile transitions) with an in-memory datagram wire between a client-role
// and a server-role director — the pump pattern mirrors
// tests/test_connection_director.cpp. A manual monotonic clock drives
// poll(); the only real threads are in the cross-thread smoke test, where a
// reader thread hammers the provider while the poll thread pumps.
//
// Evidence covered:
//   * provider views reflect established session state (profile id/revision,
//     epochs, capability, counters)
//   * a real transition: pending state visible mid-transition, new active
//     profile + transitions_effective increment after commit
//   * orchestrator aggregates match the provider contents
//   * orchestrator without provider (and with an expired provider): zeros
//   * cross-thread smoke: polling/pumping vs list_sessions()/get_stats()
//
// READ-ONLY: nothing here mutates mimicry/profile state through the
// orchestrator or the provider; all actuation goes through the director.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>

#include "ncp_connection_director.hpp"
#include "ncp_mimicry_session_provider.hpp"
#include "ncp_orchestrator.hpp"
#include "ncp_profile_transition.hpp"

#include <atomic>
#include <chrono>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace ncp;

namespace {

constexpr NcpConnectionDirector::SessionId kSidA = 0xAAAA0001;

constexpr const char* kBaselineId = "generic.udp";
constexpr const char* kTargetId   = "generic.tcp";

void ensure_init() {
    static bool once = [] {
        ncp::init_library();
        return true;
    }();
    ASSERT_TRUE(once);
}

// ── Test catalog (mirrors tests/test_connection_director.cpp) ───────────────

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
    const TestCatalog& cat, NcpMimicrySession::Role role) {
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
    c.advertise_profile_transition = true;
    c.allow_insecure_plaintext_legacy = false;
    c.transition_config.retransmit_interval_ms = 50;
    c.transition_config.max_retransmit_attempts = 6;
    c.transition_config.grace_period_ms = 1000;
    c.path_mtu_bytes = 1500;
    c.porthop_overhead_bytes = 20;
    c.max_application_payload = 1024;
    return c;
}

NcpConnectionDirector::Config make_director_config(
    const TestCatalog& cat, NcpMimicrySession::Role role) {
    NcpConnectionDirector::Config d;
    d.session_template = make_session_template(cat, role);
    return d;
}

// ── Director pair with an in-memory wire ────────────────────────────────────

struct Pair {
    TestCatalog cat;
    NcpConnectionDirector cli;  // client role, explicit session
    NcpConnectionDirector srv;  // server role, auto-accept
    uint64_t now = 1'000'000;   // manual monotonic ms

    Pair()
        : cli(make_director_config(cat, NcpMimicrySession::Role::Client)),
          srv(make_director_config(cat, NcpMimicrySession::Role::Server)) {
        EXPECT_TRUE(cli.is_valid()) << cli.config_error();
        EXPECT_TRUE(srv.is_valid()) << srv.config_error();
    }

    /// Move all due datagrams both ways until quiescent (no time passes).
    void pump() {
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
};

} // namespace

// ══════════════════════════════════════════════════════════════════════════════
// Provider views reflect the established session state.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryProvider, ViewsReflectEstablishedSession) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    auto provider = p.cli.mimicry_provider();
    ASSERT_NE(provider, nullptr);

    const auto views = provider->list_sessions();
    ASSERT_EQ(views.size(), 1u);
    const MimicrySessionView& v = views[0];
    EXPECT_EQ(v.session_id, kSidA);
    EXPECT_TRUE(v.established);
    EXPECT_TRUE(v.transition_capable);
    EXPECT_EQ(v.transition_state, ProfileTransitionState::IDLE);
    EXPECT_EQ(v.active_profile_id, kBaselineId);
    EXPECT_EQ(v.active_profile_revision, 1u);
    EXPECT_FALSE(v.has_pending_profile);
    EXPECT_EQ(v.profile_epoch, 0u);
    EXPECT_EQ(v.transitions_effective, 0u);
    EXPECT_EQ(v.transitions_aborted, 0u);
    EXPECT_EQ(v.transitions_timed_out, 0u);
    EXPECT_GT(v.e2e_messages_sent, 0u);       // handshake/caps flowed
    EXPECT_GT(v.e2e_messages_received, 0u);

    // session(id) agrees with list_sessions(); unknown id -> nullopt.
    const auto one = provider->session(kSidA);
    ASSERT_TRUE(one.has_value());
    EXPECT_EQ(one->session_id, kSidA);
    EXPECT_EQ(one->active_profile_id, kBaselineId);
    EXPECT_EQ(one->crypto_epoch, v.crypto_epoch);
    EXPECT_FALSE(provider->session(0xDEADBEEF).has_value());

    // Server side sees the same session id (auto-accepted registry).
    auto srv_provider = p.srv.mimicry_provider();
    ASSERT_NE(srv_provider, nullptr);
    const auto srv_views = srv_provider->list_sessions();
    ASSERT_EQ(srv_views.size(), 1u);
    EXPECT_EQ(srv_views[0].session_id, kSidA);
    EXPECT_TRUE(srv_views[0].established);
    EXPECT_TRUE(srv_views[0].transition_capable);

    // Removal is reflected in the published snapshot.
    ASSERT_EQ(p.cli.remove_session(kSidA), NcpConnectionDirector::Error::NONE);
    EXPECT_TRUE(provider->list_sessions().empty());
    EXPECT_FALSE(provider->session(kSidA).has_value());
}

// ══════════════════════════════════════════════════════════════════════════════
// A real catalog-driven transition: the view shows the pending state while
// the transition is outstanding and the new active profile + an incremented
// transitions_effective after the commit round trip.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryProvider, TransitionPendingThenEffective) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    auto provider = p.cli.mimicry_provider();
    ASSERT_NE(provider, nullptr);
    {
        const auto v0 = provider->session(kSidA);
        ASSERT_TRUE(v0.has_value());
        ASSERT_EQ(v0->transitions_effective, 0u);
    }

    using TR = MimicryAutoPilot::TransitionResult;
    ASSERT_EQ(p.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
              TR::ACCEPTED);

    // Apply the request on the poll loop (drains the queue, emits PREPARE,
    // republishes the snapshot) but do NOT deliver the egress yet: the
    // transition is outstanding on the client.
    const auto held = p.cli.poll(p.now);
    {
        const auto v = provider->session(kSidA);
        ASSERT_TRUE(v.has_value());
        EXPECT_TRUE(v->has_pending_profile);
        EXPECT_EQ(v->pending_profile_id, kTargetId);
        EXPECT_EQ(v->pending_profile_revision, 1u);
        EXPECT_EQ(v->transition_state, ProfileTransitionState::PREPARE);
        EXPECT_EQ(v->active_profile_id, kBaselineId)
            << "active profile must not change before activation";
        EXPECT_EQ(v->transitions_effective, 0u);
    }

    // Deliver the held PREPARE, then run the commit/confirm round trip.
    for (const auto& e : held) p.srv.on_datagram(e.session_id, e.bytes, p.now);
    p.pump();
    p.advance_and_pump(2000);

    const auto v = provider->session(kSidA);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->active_profile_id, kTargetId);
    EXPECT_EQ(v->active_profile_revision, 1u);
    EXPECT_EQ(v->profile_epoch, 1u);
    EXPECT_EQ(v->transitions_effective, 1u);
    EXPECT_EQ(v->transitions_aborted, 0u);
    EXPECT_EQ(v->transitions_timed_out, 0u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Orchestrator aggregates mirror the provider contents.
// ══════════════════════════════════════════════════════════════════════════════

TEST(OrchestratorMimicryProvider, AggregatesMatchProvider) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    DPI::ProtocolOrchestrator orch;
    orch.set_mimicry_session_provider(p.cli.mimicry_provider());

    {
        const auto s = orch.get_stats();
        EXPECT_EQ(s.mimicry_sessions_active, 1u);
        EXPECT_EQ(s.mimicry_transitions_in_flight, 0u);
        EXPECT_EQ(s.mimicry_transitions_effective_total, 0u);
        EXPECT_EQ(s.mimicry_transitions_aborted_total, 0u);
        EXPECT_EQ(s.mimicry_mtu_budget_rejections_total, 0u);
    }

    // Transition in flight -> in_flight aggregate goes to 1.
    using TR = MimicryAutoPilot::TransitionResult;
    ASSERT_EQ(p.cli.enqueue_profile_transition(kSidA, kTargetId, 1),
              TR::ACCEPTED);
    const auto held = p.cli.poll(p.now);
    {
        const auto s = orch.get_stats();
        EXPECT_EQ(s.mimicry_sessions_active, 1u);
        EXPECT_EQ(s.mimicry_transitions_in_flight, 1u);
        EXPECT_EQ(s.mimicry_transitions_effective_total, 0u);
    }

    // Commit round trip -> effective total increments, in-flight clears once
    // the FSM settles back to IDLE.
    for (const auto& e : held) p.srv.on_datagram(e.session_id, e.bytes, p.now);
    p.pump();
    p.advance_and_pump(3000);  // past the 1000ms grace period + ticks
    {
        const auto s = orch.get_stats();
        EXPECT_EQ(s.mimicry_sessions_active, 1u);
        EXPECT_EQ(s.mimicry_transitions_effective_total, 1u);
        EXPECT_EQ(s.mimicry_transitions_aborted_total, 0u);
        EXPECT_EQ(s.mimicry_transitions_in_flight, 0u);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// No provider attached: zeros, no crash. Expired provider: zeros, no crash.
// ══════════════════════════════════════════════════════════════════════════════

TEST(OrchestratorMimicryProvider, NoProviderYieldsZeros) {
    ensure_init();
    DPI::ProtocolOrchestrator orch;
    const auto s = orch.get_stats();
    EXPECT_EQ(s.mimicry_sessions_active, 0u);
    EXPECT_EQ(s.mimicry_transitions_in_flight, 0u);
    EXPECT_EQ(s.mimicry_transitions_effective_total, 0u);
    EXPECT_EQ(s.mimicry_transitions_aborted_total, 0u);
    EXPECT_EQ(s.mimicry_mtu_budget_rejections_total, 0u);
}

TEST(OrchestratorMimicryProvider, ExpiredProviderYieldsZeros) {
    ensure_init();
    DPI::ProtocolOrchestrator orch;
    {
        Pair p;
        ASSERT_TRUE(p.established());
        orch.set_mimicry_session_provider(p.cli.mimicry_provider());
        const auto live = orch.get_stats();
        EXPECT_EQ(live.mimicry_sessions_active, 1u);
    }  // directors destroyed -> weak_ptr expires

    const auto s = orch.get_stats();
    EXPECT_EQ(s.mimicry_sessions_active, 0u);
    EXPECT_EQ(s.mimicry_transitions_in_flight, 0u);
    EXPECT_EQ(s.mimicry_transitions_effective_total, 0u);
    EXPECT_EQ(s.mimicry_transitions_aborted_total, 0u);
    EXPECT_EQ(s.mimicry_mtu_budget_rejections_total, 0u);
}

// ══════════════════════════════════════════════════════════════════════════════
// Cross-thread smoke: the poll thread pumps datagrams (and republishes the
// snapshot) while a reader thread hammers list_sessions()/session() and
// orchestrator get_stats(). Bounded (~2s); success == no race, no crash,
// and the reader consistently observes the one live session.
// ══════════════════════════════════════════════════════════════════════════════

TEST(MimicryProvider, CrossThreadSmoke) {
    ensure_init();
    Pair p;
    ASSERT_TRUE(p.established());

    DPI::ProtocolOrchestrator orch;
    orch.set_mimicry_session_provider(p.cli.mimicry_provider());
    auto provider = p.cli.mimicry_provider();

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> reads{0};

    std::thread reader([&] {
        while (!stop.load(std::memory_order_relaxed)) {
            const auto views = provider->list_sessions();
            // The session is never removed: the snapshot must always show it.
            if (views.size() != 1u || views[0].session_id != kSidA) {
                stop.store(true, std::memory_order_relaxed);
                FAIL() << "inconsistent snapshot: " << views.size()
                       << " sessions";
            }
            const auto one = provider->session(kSidA);
            if (!one.has_value()) {
                stop.store(true, std::memory_order_relaxed);
                FAIL() << "session(kSidA) vanished";
            }
            const auto s = orch.get_stats();
            if (s.mimicry_sessions_active > 1u) {
                stop.store(true, std::memory_order_relaxed);
                FAIL() << "impossible aggregate";
            }
            reads.fetch_add(1, std::memory_order_relaxed);
        }
    });

    // Poll thread: pump + advance for ~2s of wall time.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline &&
           !stop.load(std::memory_order_relaxed)) {
        p.advance_and_pump(20);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    stop.store(true, std::memory_order_relaxed);
    reader.join();

    EXPECT_GT(reads.load(std::memory_order_relaxed), 0u);

    // The snapshot is still coherent after the stress.
    const auto v = provider->session(kSidA);
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(v->established);
    EXPECT_EQ(v->active_profile_id, kBaselineId);
}
