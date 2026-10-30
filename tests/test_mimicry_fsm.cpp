// ============================================================================
// tests/test_mimicry_fsm.cpp
// Tests for runtime FSM-based mimicry profiles (ncp_mimicry_fsm.hpp):
// per-session seeded bootstrap, dwell sampling with fsm_dwell_scale, valid
// transition selection, explicit phases, per-state overrides, epoch-bound
// prepared shapes, control-plane isolation, clamps/finite checks,
// determinism and cross-session polymorphism. Fully hermetic: no network,
// no files, no threads.
// ============================================================================
#include <gtest/gtest.h>
#include "ncp_mimicry_fsm.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

using namespace ncp;

namespace {

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Descriptor with an explicit bootstrap→handshake→established→data FSM.
ProfileDescriptor make_descriptor() {
    ProfileDescriptor d;
    d.profile_id = "test.fsm_runtime";
    d.revision = 1;
    d.family = ProtocolFamily::TLS;

    d.sizes.kind = SizeDistKind::NORMAL;
    d.sizes.mean = 500.0;
    d.sizes.stddev = 50.0;
    d.sizes.clamp_min = 64.0;
    d.sizes.clamp_max = 1200.0;

    d.iat.kind = IntervalKind::FIXED;
    d.iat.fixed_ms = 20.0;

    d.padding_header.header_overhead_bytes = 40;
    d.padding_header.padding_block_bytes = 0;
    d.padding_header.padding_max_bytes = 0;
    d.padding_header.pad_to_block = false;

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1400;

    d.fsm.enabled = true;
    d.fsm.initial_state = "bootstrap";
    d.fsm.states = {
        {"bootstrap",   5.0,    1.0},
        {"handshake",   50.0,   0.0},   // fixed dwell (stddev 0)
        {"established", 200.0,  10.0},
        {"data",        1000.0, 100.0},
    };
    d.fsm.transitions = {
        {"bootstrap",   "handshake",   1.0},
        {"handshake",   "established", 1.0},
        {"established", "data",        1.0},
        {"data",        "data",        1.0},  // self-loop: terminal-ish
    };
    return d;
}

/// DerivedProfile with the descriptor's base models and an explicit seed.
DerivedProfile make_derived(const ProfileDescriptor& d, uint64_t seed,
                            double dwell_scale = 1.0) {
    DerivedProfile p;
    p.profile_id = d.profile_id;
    p.revision = d.revision;
    p.session_tag = seed ^ 0x9e3779b97f4a7c15ULL;
    p.rng_seed = seed;
    p.stat.name = d.profile_id;
    p.stat.sizes = d.sizes;
    p.stat.intervals = d.iat;
    p.fsm_dwell_scale = dwell_scale;
    return p;
}

/// Drive a session through a mixed dwell/transition/shape script and record
/// an exact trace (for determinism comparisons).
struct TraceEntry {
    std::string state;
    double dwell_ms;
    bool transitioned;
    size_t shape_bytes;
    double shape_delay_ms;
};

std::vector<TraceEntry> run_trace(MimicryFsmSession& s, int steps) {
    std::vector<TraceEntry> trace;
    for (int i = 0; i < steps; ++i) {
        FsmStepResult r = s.step();
        TraceEntry e;
        e.state = r.to;
        e.dwell_ms = r.dwell_ms;
        e.transitioned = r.transitioned;
        e.shape_bytes = 0;
        e.shape_delay_ms = -1.0;
        if (i % 3 == 0) {
            MimicryFsmShape sh = s.prepare_data_shape();
            e.shape_bytes = sh.total_bytes;
            e.shape_delay_ms = sh.delay_ms;
            MimicryFsmShape out;
            if (s.take_data_shape(out)) {
                e.shape_bytes = out.total_bytes;
            }
        }
        trace.push_back(e);
    }
    return trace;
}

bool traces_equal(const std::vector<TraceEntry>& a,
                  const std::vector<TraceEntry>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].state != b[i].state ||
            a[i].dwell_ms != b[i].dwell_ms ||
            a[i].transitioned != b[i].transitioned ||
            a[i].shape_bytes != b[i].shape_bytes ||
            a[i].shape_delay_ms != b[i].shape_delay_ms)
            return false;
    }
    return true;
}

} // namespace

// ── Bootstrap ───────────────────────────────────────────────────────────────

TEST(MimicryFsmBootstrap, UsesDeclaredInitialState) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 42));
    EXPECT_TRUE(s.fsm_enabled());
    EXPECT_EQ(s.current_state(), "bootstrap");
    EXPECT_EQ(s.phase(), MimicryFsmPhase::BOOTSTRAP);
    EXPECT_EQ(s.state_epoch(), 0u);
    EXPECT_EQ(s.profile_epoch(), 0u);
    EXPECT_EQ(s.seed(), 42u);
}

TEST(MimicryFsmBootstrap, SeededPickWhenNoDeclaredInitial) {
    auto d = make_descriptor();
    d.fsm.initial_state.clear();  // force seeded bootstrap pick

    // Same seed => same bootstrap state.
    for (uint64_t seed = 0; seed < 16; ++seed) {
        MimicryFsmSession a(d, make_derived(d, seed));
        MimicryFsmSession b(d, make_derived(d, seed));
        EXPECT_EQ(a.current_state(), b.current_state()) << "seed=" << seed;
    }
    // Different seeds explore different bootstrap states (polymorphism).
    std::set<std::string> seen;
    for (uint64_t seed = 0; seed < 64; ++seed) {
        MimicryFsmSession s(d, make_derived(d, seed));
        seen.insert(s.current_state());
        EXPECT_TRUE(d.fsm.states.end() !=
                    std::find_if(d.fsm.states.begin(), d.fsm.states.end(),
                                 [&](const FsmState& st) {
                                     return st.name == s.current_state();
                                 }));
    }
    EXPECT_GT(seen.size(), 1u);
}

TEST(MimicryFsmBootstrap, UnknownDeclaredInitialFallsBackToSeededPick) {
    auto d = make_descriptor();
    d.fsm.initial_state = "does_not_exist";
    MimicryFsmSession a(d, make_derived(d, 7));
    MimicryFsmSession b(d, make_derived(d, 7));
    EXPECT_EQ(a.current_state(), b.current_state());
    EXPECT_FALSE(a.current_state().empty());
}

TEST(MimicryFsmBootstrap, ExplicitSeedOverrideWins) {
    const auto d = make_descriptor();
    MimicryFsmConfig cfg;
    cfg.seed_override = 1234;
    MimicryFsmSession a(d, make_derived(d, 1), cfg);
    MimicryFsmSession b(d, make_derived(d, 999), cfg);
    EXPECT_EQ(a.seed(), 1234u);
    EXPECT_TRUE(traces_equal(run_trace(a, 40), run_trace(b, 40)));
}

// ── Determinism / polymorphism ──────────────────────────────────────────────

TEST(MimicryFsmDeterminism, SameSeedSameTrace) {
    const auto d = make_descriptor();
    MimicryFsmSession a(d, make_derived(d, 2024));
    MimicryFsmSession b(d, make_derived(d, 2024));
    EXPECT_TRUE(traces_equal(run_trace(a, 150), run_trace(b, 150)));
}

TEST(MimicryFsmDeterminism, DifferentSeedDifferentTrace) {
    const auto d = make_descriptor();
    MimicryFsmSession a(d, make_derived(d, 1));
    MimicryFsmSession b(d, make_derived(d, 2));
    EXPECT_FALSE(traces_equal(run_trace(a, 60), run_trace(b, 60)));
}

TEST(MimicryFsmDeterminism, ResetReproducesTrace) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 77));
    const auto first = run_trace(s, 60);
    s.reset(77);
    const auto second = run_trace(s, 60);
    EXPECT_TRUE(traces_equal(first, second));
}

TEST(MimicryFsmDeterminism, IndependentSessionsDoNotShareState) {
    const auto d = make_descriptor();
    MimicryFsmSession a(d, make_derived(d, 5));
    MimicryFsmSession b(d, make_derived(d, 5));
    (void)a.step();
    (void)a.step();
    a.prepare_data_shape();
    // b must be unaffected: it still equals a fresh session's first step.
    MimicryFsmSession fresh(d, make_derived(d, 5));
    EXPECT_EQ(b.current_state(), fresh.current_state());
    EXPECT_EQ(b.state_epoch(), fresh.state_epoch());
    EXPECT_DOUBLE_EQ(b.sample_dwell_ms(), fresh.sample_dwell_ms());
}

// ── Dwell sampling ──────────────────────────────────────────────────────────

TEST(MimicryFsmDwell, DwellScaleAppliedMultiplicatively) {
    const auto d = make_descriptor();  // handshake: fixed dwell 50 ms
    auto mk = [&](double scale) {
        auto p = make_derived(d, 11, scale);
        MimicryFsmSession s(d, p);
        EXPECT_DOUBLE_EQ(s.fsm_dwell_scale(), scale);
        EXPECT_TRUE(s.advance());  // bootstrap -> handshake
        return s.sample_dwell_ms();
    };
    EXPECT_DOUBLE_EQ(mk(1.0), 50.0);
    EXPECT_DOUBLE_EQ(mk(2.0), 100.0);
    EXPECT_DOUBLE_EQ(mk(0.5), 25.0);
    EXPECT_DOUBLE_EQ(mk(0.0), 0.0);
}

TEST(MimicryFsmDwell, ClampedToConfiguredMax) {
    const auto d = make_descriptor();
    MimicryFsmConfig cfg;
    cfg.max_dwell_ms = 10.0;
    MimicryFsmSession s(d, make_derived(d, 3, 100.0), cfg);  // huge scale
    for (int i = 0; i < 50; ++i) {
        const double d_ms = s.sample_dwell_ms();
        EXPECT_GE(d_ms, 0.0);
        EXPECT_LE(d_ms, 10.0);
    }
}

TEST(MimicryFsmDwell, NonFiniteAndNegativeParamsSanitised) {
    auto d = make_descriptor();
    d.fsm.states = {
        {"bootstrap", std::numeric_limits<double>::quiet_NaN(),
         std::numeric_limits<double>::infinity()},
        {"neg", -5.0, -1.0},
    };
    d.fsm.transitions = {{"bootstrap", "neg", 1.0}};
    MimicryFsmSession s(d, make_derived(d, 9));
    const double d1 = s.sample_dwell_ms();
    EXPECT_TRUE(std::isfinite(d1));
    EXPECT_GE(d1, 0.0);
    EXPECT_TRUE(s.advance());
    EXPECT_DOUBLE_EQ(s.sample_dwell_ms(), 0.0);  // negative mean -> 0
}

TEST(MimicryFsmDwell, NonFiniteScaleSanitisedToOne) {
    const auto d = make_descriptor();
    for (double bad : {std::numeric_limits<double>::quiet_NaN(),
                       std::numeric_limits<double>::infinity(),
                       -std::numeric_limits<double>::infinity(), -3.0}) {
        auto p = make_derived(d, 4);
        p.fsm_dwell_scale = bad;
        MimicryFsmSession s(d, p);
        EXPECT_DOUBLE_EQ(s.fsm_dwell_scale(), 1.0);
    }
    // Absurd finite scale is clamped to the hard bound.
    auto p = make_derived(d, 4);
    p.fsm_dwell_scale = 1e9;
    MimicryFsmSession s(d, p);
    EXPECT_DOUBLE_EQ(s.fsm_dwell_scale(), MimicryFsmSession::kMaxDwellScale);
}

TEST(MimicryFsmDwell, SampledDwellsStayWithinClamp) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 123, 1.2));
    for (int i = 0; i < 200; ++i) {
        const double d_ms = s.sample_dwell_ms();
        EXPECT_TRUE(std::isfinite(d_ms));
        EXPECT_GE(d_ms, 0.0);
        EXPECT_LE(d_ms, 600000.0);
    }
}

// ── Transitions ─────────────────────────────────────────────────────────────

TEST(MimicryFsmTransitions, WalksExplicitPhaseChain) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 1));
    EXPECT_EQ(s.current_state(), "bootstrap");
    EXPECT_TRUE(s.advance());
    EXPECT_EQ(s.current_state(), "handshake");
    EXPECT_TRUE(s.advance());
    EXPECT_EQ(s.current_state(), "established");
    EXPECT_TRUE(s.advance());
    EXPECT_EQ(s.current_state(), "data");
    EXPECT_EQ(s.state_epoch(), 3u);
}

TEST(MimicryFsmTransitions, SelfLoopAdvancesEpoch) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 1));
    while (s.current_state() != "data") ASSERT_TRUE(s.advance());
    const uint64_t before = s.state_epoch();
    EXPECT_TRUE(s.advance());  // data -> data
    EXPECT_EQ(s.current_state(), "data");
    EXPECT_EQ(s.state_epoch(), before + 1);
}

TEST(MimicryFsmTransitions, TerminalStateStays) {
    auto d = make_descriptor();
    d.fsm.states = {{"bootstrap", 1.0, 0.0}, {"leaf", 1.0, 0.0}};
    d.fsm.transitions = {{"bootstrap", "leaf", 1.0}};
    MimicryFsmSession s(d, make_derived(d, 1));
    ASSERT_TRUE(s.advance());
    EXPECT_EQ(s.current_state(), "leaf");
    const uint64_t epoch = s.state_epoch();
    for (int i = 0; i < 5; ++i) {
        EXPECT_FALSE(s.advance());
        EXPECT_EQ(s.current_state(), "leaf");
        EXPECT_EQ(s.state_epoch(), epoch);
    }
}

TEST(MimicryFsmTransitions, InvalidTransitionsAreNeverSelected) {
    auto d = make_descriptor();
    d.fsm.states = {{"x", 1.0, 0.0}, {"y", 1.0, 0.0}, {"z", 1.0, 0.0}};
    d.fsm.initial_state = "x";
    d.fsm.transitions = {
        {"x", "y", 1.0},   // the only valid edge
        {"x", "z", 0.0},   // zero probability
        {"x", "z", -1.0},  // negative
        {"x", "z", std::numeric_limits<double>::quiet_NaN()},  // non-finite
        {"x", "ghost", 1.0},  // missing target state
        {"y", "x", 1.0},
    };
    MimicryFsmSession s(d, make_derived(d, 8));
    const auto vt = s.valid_transitions();
    EXPECT_EQ(vt, std::vector<std::string>{"y"});
    for (int i = 0; i < 40; ++i) {
        ASSERT_TRUE(s.advance());
        EXPECT_TRUE(s.current_state() == "x" || s.current_state() == "y");
    }
}

TEST(MimicryFsmTransitions, WeightedSelectionIsSkewedAndDeterministic) {
    auto d = make_descriptor();
    d.fsm.states = {{"a", 0.0, 0.0}, {"b", 0.0, 0.0}};
    d.fsm.initial_state = "a";
    d.fsm.transitions = {
        {"a", "a", 0.25},
        {"a", "b", 0.75},
        {"b", "a", 1.0},
    };
    size_t to_b = 0, self = 0;
    MimicryFsmSession s(d, make_derived(d, 31337));
    for (int i = 0; i < 400; ++i) {
        const std::string from = s.current_state();
        ASSERT_TRUE(s.advance());
        if (from == "a" && s.current_state() == "b") ++to_b;
        if (from == "a" && s.current_state() == "a") ++self;
    }
    const size_t from_a = to_b + self;
    EXPECT_GT(from_a, 200u);  // b always returns to a in one step
    // 75/25 split with a fixed seed: deterministic; assert a loose hermetic
    // band around the expected ratio that the mt19937_64 stream satisfies.
    const double ratio = static_cast<double>(to_b) / from_a;
    EXPECT_GT(ratio, 0.60);
    EXPECT_LT(ratio, 0.90);
}

TEST(MimicryFsmTransitions, StepResultIsConsistent) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 21));
    const FsmStepResult r = s.step();
    EXPECT_EQ(r.from, "bootstrap");
    EXPECT_EQ(r.to, "handshake");
    EXPECT_TRUE(r.transitioned);
    EXPECT_TRUE(std::isfinite(r.dwell_ms));
    EXPECT_GE(r.dwell_ms, 0.0);
    EXPECT_EQ(r.state_epoch, s.state_epoch());
    EXPECT_EQ(r.state_epoch, 1u);
}

// ── Phases ──────────────────────────────────────────────────────────────────

TEST(MimicryFsmPhases, ExplicitProgressionInFixedOrder) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 1));
    EXPECT_EQ(s.phase(), MimicryFsmPhase::BOOTSTRAP);
    EXPECT_TRUE(s.advance_phase());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::HANDSHAKE);
    EXPECT_TRUE(s.advance_phase());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::ESTABLISHED);
    EXPECT_TRUE(s.advance_phase());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::DATA);
    EXPECT_FALSE(s.advance_phase());  // DATA is terminal
    EXPECT_EQ(s.phase(), MimicryFsmPhase::DATA);
}

TEST(MimicryFsmPhases, StateEntryAutoAdvancesPhase) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 1));
    EXPECT_EQ(s.phase(), MimicryFsmPhase::BOOTSTRAP);
    ASSERT_TRUE(s.advance());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::HANDSHAKE);
    ASSERT_TRUE(s.advance());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::ESTABLISHED);
    ASSERT_TRUE(s.advance());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::DATA);
}

TEST(MimicryFsmPhases, RegressionBlockedByDefault) {
    auto d = make_descriptor();
    d.fsm.transitions.push_back({"data", "bootstrap", 1.0});  // regression
    MimicryFsmSession s(d, make_derived(d, 1));
    while (s.current_state() != "data") ASSERT_TRUE(s.advance());
    EXPECT_EQ(s.phase(), MimicryFsmPhase::DATA);
    for (const auto& t : s.valid_transitions())
        EXPECT_NE(t, "bootstrap");
    for (int i = 0; i < 10; ++i) {
        ASSERT_TRUE(s.advance());  // only the data->data self-loop is valid
        EXPECT_EQ(s.current_state(), "data");
    }
}

TEST(MimicryFsmPhases, RegressionAllowedByConfig) {
    auto d = make_descriptor();
    // Only a regression edge out of data: without the flag it is terminal.
    d.fsm.transitions = {
        {"bootstrap", "handshake", 1.0},
        {"handshake", "established", 1.0},
        {"established", "data", 1.0},
        {"data", "bootstrap", 1.0},
    };
    MimicryFsmConfig cfg;
    cfg.allow_phase_regression = true;
    MimicryFsmSession s(d, make_derived(d, 1), cfg);
    while (s.current_state() != "data") ASSERT_TRUE(s.advance());
    ASSERT_TRUE(s.advance());
    EXPECT_EQ(s.current_state(), "bootstrap");
    // The phase itself is still monotonic: it never decreases.
    EXPECT_EQ(s.phase(), MimicryFsmPhase::DATA);
}

TEST(MimicryFsmPhases, NameConventionIsCaseInsensitive) {
    auto d = make_descriptor();
    d.fsm.states = {{"Bootstrap", 0.0, 0.0}, {"HANDSHAKE", 0.0, 0.0},
                    {"Established", 0.0, 0.0}, {"DaTa", 0.0, 0.0}};
    MimicryFsmSession s(d, make_derived(d, 1));
    EXPECT_EQ(s.phase_of_state("Bootstrap"), MimicryFsmPhase::BOOTSTRAP);
    EXPECT_EQ(s.phase_of_state("HANDSHAKE"), MimicryFsmPhase::HANDSHAKE);
    EXPECT_EQ(s.phase_of_state("Established"), MimicryFsmPhase::ESTABLISHED);
    EXPECT_EQ(s.phase_of_state("DaTa"), MimicryFsmPhase::DATA);
    EXPECT_FALSE(s.phase_of_state("unrelated").has_value());
}

TEST(MimicryFsmPhases, ExplicitMapOverridesNameConvention) {
    const auto d = make_descriptor();
    MimicryFsmConfig cfg;
    cfg.state_phases["data"] = MimicryFsmPhase::HANDSHAKE;  // demote by name
    MimicryFsmSession s(d, make_derived(d, 1), cfg);
    EXPECT_EQ(s.phase_of_state("data"), MimicryFsmPhase::HANDSHAKE);
}

TEST(MimicryFsmPhases, UnphasedStatesAreNeverGated) {
    auto d = make_descriptor();
    d.fsm.states = {{"bootstrap", 0.0, 0.0}, {"free", 0.0, 0.0}};
    d.fsm.transitions = {{"bootstrap", "free", 1.0}, {"free", "bootstrap", 1.0}};
    MimicryFsmSession s(d, make_derived(d, 1));
    for (int i = 0; i < 20; ++i) ASSERT_TRUE(s.advance());  // ping-pong works
}

TEST(MimicryFsmPhases, ToStringCoversAllPhases) {
    EXPECT_STREQ(to_string(MimicryFsmPhase::BOOTSTRAP), "bootstrap");
    EXPECT_STREQ(to_string(MimicryFsmPhase::HANDSHAKE), "handshake");
    EXPECT_STREQ(to_string(MimicryFsmPhase::ESTABLISHED), "established");
    EXPECT_STREQ(to_string(MimicryFsmPhase::DATA), "data");
}

// ── Prepared data shapes ────────────────────────────────────────────────────

TEST(MimicryFsmShapes, PrepareIsIdempotentPeek) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 55));
    const MimicryFsmShape a = s.prepare_data_shape();
    const MimicryFsmShape b = s.prepare_data_shape();
    EXPECT_TRUE(s.has_prepared_shape());
    EXPECT_EQ(a.payload_bytes, b.payload_bytes);
    EXPECT_EQ(a.total_bytes, b.total_bytes);
    EXPECT_DOUBLE_EQ(a.delay_ms, b.delay_ms);
    EXPECT_EQ(a.state_epoch, b.state_epoch);
    EXPECT_EQ(a.profile_epoch, b.profile_epoch);
    EXPECT_EQ(a.state, b.state);
}

TEST(MimicryFsmShapes, PeekDoesNotConsumeRng) {
    const auto d = make_descriptor();
    MimicryFsmSession once(d, make_derived(d, 66));
    MimicryFsmSession twice(d, make_derived(d, 66));
    (void)once.prepare_data_shape();
    (void)twice.prepare_data_shape();
    (void)twice.prepare_data_shape();  // extra peek: must not consume RNG
    (void)twice.prepare_data_shape();
    EXPECT_DOUBLE_EQ(once.sample_dwell_ms(), twice.sample_dwell_ms());
}

TEST(MimicryFsmShapes, TakeConsumesExactlyOnce) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 67));
    const MimicryFsmShape prepared = s.prepare_data_shape();
    MimicryFsmShape out;
    ASSERT_TRUE(s.take_data_shape(out));
    EXPECT_EQ(out.payload_bytes, prepared.payload_bytes);
    EXPECT_EQ(out.total_bytes, prepared.total_bytes);
    EXPECT_FALSE(s.has_prepared_shape());
    EXPECT_FALSE(s.take_data_shape(out));  // nothing left to consume
}

TEST(MimicryFsmShapes, FieldsAreSaneAndEpochBound) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 68));
    const MimicryFsmShape sh = s.prepare_data_shape();
    EXPECT_GE(sh.payload_bytes, 1u);
    EXPECT_LE(sh.payload_bytes, 1400u);  // mtu.max_payload_bytes
    EXPECT_EQ(sh.padding_bytes, 0u);     // base model: no padding
    EXPECT_EQ(sh.total_bytes, sh.payload_bytes + 40u);  // header overhead
    EXPECT_DOUBLE_EQ(sh.delay_ms, 20.0);  // FIXED iat
    EXPECT_EQ(sh.state_epoch, 0u);
    EXPECT_EQ(sh.profile_epoch, 0u);
    EXPECT_EQ(sh.state, "bootstrap");
}

TEST(MimicryFsmShapes, StaleStateEpochCannotBeConsumed) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 69));
    (void)s.prepare_data_shape();
    ASSERT_TRUE(s.advance());  // bumps state epoch, drops stale shape
    EXPECT_FALSE(s.has_prepared_shape());
    MimicryFsmShape out;
    EXPECT_FALSE(s.take_data_shape(out));
}

TEST(MimicryFsmShapes, StaleStateEpochEvenOnSelfLoop) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 70));
    while (s.current_state() != "data") ASSERT_TRUE(s.advance());
    (void)s.prepare_data_shape();
    ASSERT_TRUE(s.advance());  // data -> data still bumps the epoch
    MimicryFsmShape out;
    EXPECT_FALSE(s.take_data_shape(out));
}

TEST(MimicryFsmShapes, StaleProfileEpochCannotBeConsumed) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 71));
    (void)s.prepare_data_shape();
    EXPECT_EQ(s.profile_epoch(), 0u);
    FsmStateOverride ov;
    s.set_state_overrides({{"bootstrap", ov}});  // bumps profile epoch
    EXPECT_EQ(s.profile_epoch(), 1u);
    EXPECT_FALSE(s.has_prepared_shape());
    MimicryFsmShape out;
    EXPECT_FALSE(s.take_data_shape(out));
    // New shapes bind the new epoch and are consumable again.
    (void)s.prepare_data_shape();
    EXPECT_TRUE(s.take_data_shape(out));
    EXPECT_EQ(out.profile_epoch, 1u);
}

TEST(MimicryFsmShapes, CancelDropsShape) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 72));
    (void)s.prepare_data_shape();
    s.cancel_prepared_shape();
    EXPECT_FALSE(s.has_prepared_shape());
    MimicryFsmShape out;
    EXPECT_FALSE(s.take_data_shape(out));
}

TEST(MimicryFsmShapes, ResetDropsQueuedShape) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 73));
    (void)s.prepare_data_shape();
    s.reset(73);
    EXPECT_FALSE(s.has_prepared_shape());
    MimicryFsmShape out;
    EXPECT_FALSE(s.take_data_shape(out));
}

// ── Per-state overrides ─────────────────────────────────────────────────────

TEST(MimicryFsmOverrides, SizeOverrideKeyedByState) {
    const auto d = make_descriptor();
    FsmStateOverride ov;
    SizeDistribution sz;
    sz.kind = SizeDistKind::NORMAL;
    sz.mean = 100.0;
    sz.stddev = 5.0;
    sz.clamp_min = 90.0;
    sz.clamp_max = 110.0;
    ov.sizes = sz;

    MimicryFsmConfig cfg;
    cfg.state_overrides["data"] = ov;
    MimicryFsmSession s(d, make_derived(d, 80), cfg);

    // Effective resolution reflects the override only for "data".
    EXPECT_DOUBLE_EQ(s.effective_sizes("data").mean, 100.0);
    EXPECT_DOUBLE_EQ(s.effective_sizes("bootstrap").mean, 500.0);

    // Base state: base clamps apply.
    for (int i = 0; i < 10; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_GE(sh.payload_bytes, 64u);
        EXPECT_LE(sh.payload_bytes, 1200u);
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
    }
    // Overridden state: override clamps apply.
    while (s.current_state() != "data") ASSERT_TRUE(s.advance());
    for (int i = 0; i < 20; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_GE(sh.payload_bytes, 90u);
        EXPECT_LE(sh.payload_bytes, 110u);
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
        ASSERT_TRUE(s.advance());  // self-loop; stay in "data"
    }
}

TEST(MimicryFsmOverrides, IatOverrideAppliedPerState) {
    const auto d = make_descriptor();
    FsmStateOverride ov;
    IntervalDistribution iat;
    iat.kind = IntervalKind::FIXED;
    iat.fixed_ms = 3.5;
    ov.iat = iat;
    MimicryFsmConfig cfg;
    cfg.state_overrides["handshake"] = ov;
    MimicryFsmSession s(d, make_derived(d, 81), cfg);

    EXPECT_DOUBLE_EQ(s.prepare_data_shape().delay_ms, 20.0);  // bootstrap: base
    s.cancel_prepared_shape();
    ASSERT_TRUE(s.advance());  // -> handshake
    EXPECT_DOUBLE_EQ(s.prepare_data_shape().delay_ms, 3.5);
    EXPECT_DOUBLE_EQ(s.effective_iat("handshake").fixed_ms, 3.5);
    EXPECT_DOUBLE_EQ(s.effective_iat("bootstrap").fixed_ms, 20.0);
}

TEST(MimicryFsmOverrides, PaddingOverrideAppliedPerState) {
    const auto d = make_descriptor();
    FsmStateOverride ov;
    PaddingHeaderModel pad;
    pad.header_overhead_bytes = 20;
    pad.padding_block_bytes = 128;
    pad.padding_max_bytes = 512;
    pad.pad_to_block = true;
    ov.padding = pad;
    MimicryFsmConfig cfg;
    cfg.state_overrides["data"] = ov;
    MimicryFsmSession s(d, make_derived(d, 82), cfg);
    while (s.current_state() != "data") ASSERT_TRUE(s.advance());

    for (int i = 0; i < 30; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_EQ(sh.total_bytes % 128u, 0u) << "total=" << sh.total_bytes;
        EXPECT_LE(sh.padding_bytes, 512u);
        EXPECT_EQ(sh.total_bytes,
                  sh.payload_bytes + 20u + sh.padding_bytes);
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
        ASSERT_TRUE(s.advance());  // data self-loop
    }
    // Non-overridden states keep the base padding model.
    EXPECT_EQ(s.effective_padding("bootstrap").header_overhead_bytes, 40u);
    EXPECT_EQ(s.effective_padding("data").header_overhead_bytes, 20u);
}

TEST(MimicryFsmOverrides, PaddingCappedByMaxAndExtraBytes) {
    auto d = make_descriptor();
    d.padding_header.pad_to_block = true;
    d.padding_header.padding_block_bytes = 256;
    d.padding_header.padding_max_bytes = 0;  // no budget => no padding

    auto p = make_derived(d, 83);
    {
        MimicryFsmSession s(d, p);
        const auto sh = s.prepare_data_shape();
        EXPECT_EQ(sh.padding_bytes, 0u);  // capped to zero
    }
    // Derived extra padding budget is honoured.
    p.padding_extra_bytes = 100;
    {
        MimicryFsmSession s(d, p);
        const auto sh = s.prepare_data_shape();
        EXPECT_LE(sh.padding_bytes, 100u);
    }
}

TEST(MimicryFsmOverrides, HeaderGapShiftApplied) {
    const auto d = make_descriptor();  // base header_overhead 40, no padding
    auto p = make_derived(d, 84);
    p.header_gap_shift_bytes = -10;
    MimicryFsmSession s(d, p);
    const auto sh = s.prepare_data_shape();
    EXPECT_EQ(sh.total_bytes, sh.payload_bytes + 30u);  // 40 - 10
}

TEST(MimicryFsmOverrides, OverrideResolutionDoesNotConsumeRng) {
    const auto d = make_descriptor();
    MimicryFsmSession a(d, make_derived(d, 85));
    MimicryFsmSession b(d, make_derived(d, 85));
    (void)a.effective_sizes("data");
    (void)a.effective_iat("data");
    (void)a.effective_padding("data");
    (void)a.valid_transitions();
    EXPECT_DOUBLE_EQ(a.sample_dwell_ms(), b.sample_dwell_ms());
}

// ── MTU budget / clamps ─────────────────────────────────────────────────────

TEST(MimicryFsmClamps, PayloadRespectsMtuBudget) {
    auto d = make_descriptor();
    d.sizes.mean = 8000.0;
    d.sizes.stddev = 500.0;
    d.sizes.clamp_min = 64.0;
    d.sizes.clamp_max = 9000.0;  // way above the MTU
    d.mtu.max_payload_bytes = 500;
    d.mtu.path_mtu_bytes = 600;
    MimicryFsmSession s(d, make_derived(d, 90));
    for (int i = 0; i < 30; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_GE(sh.payload_bytes, 1u);
        EXPECT_LE(sh.payload_bytes, 500u);
        EXPECT_LE(sh.total_bytes, 600u);
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
    }
}

TEST(MimicryFsmClamps, HostileSizeDistributionSanitised) {
    auto d = make_descriptor();
    d.sizes.kind = SizeDistKind::NORMAL;
    d.sizes.mean = std::numeric_limits<double>::quiet_NaN();
    d.sizes.stddev = -1.0;
    d.sizes.clamp_min = std::numeric_limits<double>::infinity();
    d.sizes.clamp_max = std::numeric_limits<double>::quiet_NaN();
    MimicryFsmSession s(d, make_derived(d, 91));
    for (int i = 0; i < 20; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_GE(sh.payload_bytes, 1u);
        EXPECT_LE(sh.payload_bytes, 1400u);
        EXPECT_TRUE(std::isfinite(sh.delay_ms));
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
    }
}

TEST(MimicryFsmClamps, HostileIatSanitised) {
    auto d = make_descriptor();
    d.iat.kind = IntervalKind::EXPONENTIAL;
    d.iat.mean_ms = std::numeric_limits<double>::quiet_NaN();  // invalid
    MimicryFsmSession s(d, make_derived(d, 92));
    for (int i = 0; i < 20; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_TRUE(std::isfinite(sh.delay_ms));
        EXPECT_GE(sh.delay_ms, 0.0);
        EXPECT_LE(sh.delay_ms, MimicryFsmSession::kMaxIatMs);
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
    }
}

TEST(MimicryFsmClamps, PaddingNeverExceedsPathMtu) {
    auto d = make_descriptor();
    d.mtu.path_mtu_bytes = 300;
    d.mtu.max_payload_bytes = 400;  // inconsistent on purpose
    d.padding_header.header_overhead_bytes = 40;
    d.padding_header.pad_to_block = true;
    d.padding_header.padding_block_bytes = 512;
    d.padding_header.padding_max_bytes = 100000;  // hostile
    MimicryFsmSession s(d, make_derived(d, 93));
    for (int i = 0; i < 30; ++i) {
        const auto sh = s.prepare_data_shape();
        EXPECT_LE(sh.total_bytes, 300u);
        EXPECT_EQ(sh.total_bytes,
                  sh.payload_bytes + sh.padding_bytes + 40u);
        MimicryFsmShape out;
        ASSERT_TRUE(s.take_data_shape(out));
    }
}

TEST(MimicryFsmClamps, NonFiniteMaxDwellConfigFallsBack) {
    const auto d = make_descriptor();
    MimicryFsmConfig cfg;
    cfg.max_dwell_ms = std::numeric_limits<double>::quiet_NaN();
    MimicryFsmSession s(d, make_derived(d, 94, 1.0), cfg);
    const double dw = s.sample_dwell_ms();
    EXPECT_TRUE(std::isfinite(dw));
    EXPECT_GE(dw, 0.0);
}

// ── Control plane isolation ─────────────────────────────────────────────────

TEST(MimicryFsmControl, ControlPacketsDoNotAdvanceFsmOrConsumeRng) {
    const auto d = make_descriptor();
    MimicryFsmSession noisy(d, make_derived(d, 100));
    MimicryFsmSession quiet(d, make_derived(d, 100));
    for (int i = 0; i < 50; ++i) {
        noisy.note_control_packet(64);
        noisy.note_control_packet(128);
        noisy.note_control_packet();  // zero-length control packet
    }
    EXPECT_EQ(noisy.control_packets_observed(), 150u);
    EXPECT_EQ(noisy.control_bytes_observed(), 150u * 0u + 50u * 192u);
    EXPECT_EQ(noisy.current_state(), quiet.current_state());
    EXPECT_EQ(noisy.state_epoch(), quiet.state_epoch());
    // Identical downstream behaviour: control traffic left no trace.
    EXPECT_TRUE(traces_equal(run_trace(noisy, 80), run_trace(quiet, 80)));
}

TEST(MimicryFsmControl, ControlPacketsDoNotDisturbPreparedShape) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 101));
    const MimicryFsmShape before = s.prepare_data_shape();
    for (int i = 0; i < 10; ++i) s.note_control_packet(256);
    EXPECT_TRUE(s.has_prepared_shape());
    MimicryFsmShape out;
    ASSERT_TRUE(s.take_data_shape(out));
    EXPECT_EQ(out.payload_bytes, before.payload_bytes);
    EXPECT_EQ(out.total_bytes, before.total_bytes);
    EXPECT_DOUBLE_EQ(out.delay_ms, before.delay_ms);
}

TEST(MimicryFsmControl, ControlPacketsDoNotAdvancePhase) {
    const auto d = make_descriptor();
    MimicryFsmSession s(d, make_derived(d, 102));
    for (int i = 0; i < 10; ++i) s.note_control_packet(1);
    EXPECT_EQ(s.phase(), MimicryFsmPhase::BOOTSTRAP);
    EXPECT_EQ(s.state_epoch(), 0u);
}

// ── Disabled FSM ────────────────────────────────────────────────────────────

TEST(MimicryFsmDisabled, DisabledModelStillShapesData) {
    auto d = make_descriptor();
    d.fsm.enabled = false;
    MimicryFsmSession s(d, make_derived(d, 110));
    EXPECT_FALSE(s.fsm_enabled());
    EXPECT_TRUE(s.current_state().empty());
    EXPECT_FALSE(s.advance());
    EXPECT_TRUE(s.valid_transitions().empty());
    EXPECT_DOUBLE_EQ(s.sample_dwell_ms(), MimicryFsmSession::kFallbackDwellMs);
    // Shapes still work from the base models.
    const auto sh = s.prepare_data_shape();
    EXPECT_GE(sh.payload_bytes, 64u);
    EXPECT_LE(sh.payload_bytes, 1200u);
    EXPECT_TRUE(sh.state.empty());
    MimicryFsmShape out;
    EXPECT_TRUE(s.take_data_shape(out));
}

TEST(MimicryFsmDisabled, EmptyStateTableIsDisabled) {
    auto d = make_descriptor();
    d.fsm.states.clear();
    MimicryFsmSession s(d, make_derived(d, 111));
    EXPECT_FALSE(s.fsm_enabled());
    EXPECT_FALSE(s.advance());
}

// ── Catalog integration (deterministic derivation) ──────────────────────────

TEST(MimicryFsmCatalog, DerivedSessionsDeterministicAndPolymorphic) {
    auto d = make_descriptor();
    d.derivation.fsm_dwell_rel_jitter = 0.3;  // per-session dwell scale

    std::array<uint8_t, SessionSecret::kSize> b1{}, b2{};
    b1[0] = 1;
    b2[0] = 2;
    const SessionSecret s1 = SessionSecret::from_bytes(b1);
    const SessionSecret s2 = SessionSecret::from_bytes(b2);

    const DerivedProfile da = ReferenceProfileCatalog::derive_session(d, s1);
    const DerivedProfile db = ReferenceProfileCatalog::derive_session(d, s1);
    const DerivedProfile dc = ReferenceProfileCatalog::derive_session(d, s2);

    // Same secret => same derived profile => identical runtime trace.
    EXPECT_EQ(da.rng_seed, db.rng_seed);
    MimicryFsmSession a(d, da);
    MimicryFsmSession b(d, db);
    EXPECT_TRUE(traces_equal(run_trace(a, 80), run_trace(b, 80)));

    // Different secret => different session (seed/scale) and trace.
    EXPECT_TRUE(da.rng_seed != dc.rng_seed ||
                da.fsm_dwell_scale != dc.fsm_dwell_scale);
    MimicryFsmSession c(d, dc);
    EXPECT_FALSE(traces_equal(run_trace(a, 0), run_trace(c, 0)) &&
                 da.rng_seed == dc.rng_seed);
    MimicryFsmSession a2(d, da);
    MimicryFsmSession c2(d, dc);
    EXPECT_FALSE(traces_equal(run_trace(a2, 80), run_trace(c2, 80)));
}
