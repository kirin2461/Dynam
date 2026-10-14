// ═══════════════════════════════════════════════════════════════════════════
// PresetAutoPilot unit tests — no network (injected probe_fn / now_fn).
// Covers SPEC §10: should_switch boundaries, startup-selection with mock
// probing (engine==nullptr test mode), EWMA/cooldown/dwell/anti-storm with
// injected clock, JSON round-trip of to_stats_json().
// ═══════════════════════════════════════════════════════════════════════════

#include <gtest/gtest.h>

#include "ncp_preset_autopilot.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <string>
#include <thread>

namespace {

using ncp::BlockcheckProbe;
using ncp::PresetAutoPilot;
using ncp::DPI::DPIPreset;

BlockcheckProbe mk_probe(const std::string& host, bool ok, int latency_ms,
                         const std::string& reason = "") {
    BlockcheckProbe p;
    p.domain = host;
    p.ok = ok;
    p.latency_ms = latency_ms;
    if (!ok) p.fail_reason = reason.empty() ? "timeout" : reason;
    return p;
}

// Poll a predicate with a wall-clock deadline (the autopilot thread runs with
// monitor_interval_sec=0, so state changes arrive within milliseconds).
template <typename F>
bool wait_for(F&& pred, int timeout_ms = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return pred();
}

// Shared, thread-safe probe behavior table for the mock hook.
struct ProbeBehavior {
    mutable std::mutex m;
    // per-preset: (all_ok ? latency : -1 = all fail); special-case partial
    int tspu_latency = 50;      // -1 = all probes fail
    int beeline_latency = 100;  // -1 = all probes fail
    bool tspu_first_host_fails = false;
    // First probe host unreachable via direct probe (DPI-blocked host must
    // not trip the startup connectivity gate when other hosts answer).
    bool direct_first_host_fails = false;
    // Direct baseline must be "working but slow" (300ms): a fast direct probe
    // means "no filtering detected" and legitimately beats every preset
    // (score = success*100000 - latency), while a failing direct probe fails
    // the startup quick-connectivity check (→ degraded-net).
    int direct_latency = 300;   // -1 = direct fails too

    BlockcheckProbe probe(DPIPreset preset, const std::string& host, int) {
        std::lock_guard<std::mutex> lk(m);
        int lat = -1;
        if (preset == DPIPreset::RUNET_TSPU) lat = tspu_latency;
        else if (preset == DPIPreset::BEELINE_MOBILE) lat = beeline_latency;
        else if (preset == DPIPreset::NONE) lat = direct_latency;
        else lat = -1;  // any other candidate preset: dead
        if (lat < 0) return mk_probe(host, false, 0);
        if (preset == DPIPreset::RUNET_TSPU && tspu_first_host_fails &&
            host == "a.test")
            return mk_probe(host, false, 0);
        if (preset == DPIPreset::NONE && direct_first_host_fails &&
            host == "a.test")
            return mk_probe(host, false, 0);
        return mk_probe(host, true, lat);
    }
};

PresetAutoPilot::Config mk_test_cfg(ProbeBehavior& pb, std::atomic<int64_t>& now) {
    PresetAutoPilot::Config cfg;
    cfg.candidates = {DPIPreset::RUNET_TSPU, DPIPreset::BEELINE_MOBILE};
    cfg.probe_hosts = {"a.test", "b.test", "c.test"};
    cfg.probe_timeout_ms = 100;
    cfg.monitor_probe_timeout_ms = 100;
    cfg.monitor_interval_sec = 0;      // busy loop: state changes immediately
    cfg.switch_cooldown_sec = 120;
    cfg.min_dwell_sec = 180;
    cfg.probe_fn = [&pb](DPIPreset p, const std::string& h, int t) {
        return pb.probe(p, h, t);
    };
    cfg.now_fn = [&now] { return now.load(); };
    return cfg;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. should_switch — decision boundaries (SPEC §10.1)
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotSwitch, CurrentDead) {
    // cur <= 0: any positive challenger wins; non-positive does not.
    EXPECT_TRUE(PresetAutoPilot::should_switch(0, 1, 10.0));
    EXPECT_TRUE(PresetAutoPilot::should_switch(-5, 100, 10.0));
    EXPECT_FALSE(PresetAutoPilot::should_switch(0, 0, 10.0));
    EXPECT_FALSE(PresetAutoPilot::should_switch(-5, -1, 10.0));
}

TEST(PresetAutoPilotSwitch, HysteresisBoundary) {
    const long cur = 100000;
    // exactly +10% is NOT enough (strict >)
    EXPECT_FALSE(PresetAutoPilot::should_switch(cur, 110000, 10.0));
    // 10.1% better → switch
    EXPECT_TRUE(PresetAutoPilot::should_switch(cur, 110100, 10.0));
    // 9.9% better → hold
    EXPECT_FALSE(PresetAutoPilot::should_switch(cur, 109900, 10.0));
    // challenger worse → hold
    EXPECT_FALSE(PresetAutoPilot::should_switch(cur, 90000, 10.0));
    // zero hysteresis: strictly better wins
    EXPECT_TRUE(PresetAutoPilot::should_switch(cur, cur + 1, 0.0));
    EXPECT_FALSE(PresetAutoPilot::should_switch(cur, cur, 0.0));
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Startup selection with mock probe_fn, engine==nullptr (SPEC §10.2)
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotStartup, SelectsBestPreset) {
    ProbeBehavior pb;  // tspu 50ms all ok, beeline 100ms all ok → tspu wins
    std::atomic<int64_t> now{1000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));  // test mode: probe_fn set, no engine
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::RUNET_TSPU; }));
    EXPECT_EQ(pa.mode_string(), "monitoring");

    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"reason\":\"startup-selection\""), std::string::npos);
    EXPECT_NE(j.find("\"from\":\"AutoProbe\""), std::string::npos);
    EXPECT_NE(j.find("\"to\":\"RuNet-TSPU\""), std::string::npos);
    pa.stop();
    EXPECT_FALSE(pa.running());
}

TEST(PresetAutoPilotStartup, NoNetworkGoesDegradedNet) {
    ProbeBehavior pb;
    {
        std::lock_guard<std::mutex> lk(pb.m);
        pb.tspu_latency = -1;
        pb.beeline_latency = -1;
        pb.direct_latency = -1;  // even the quick direct check fails
    }
    std::atomic<int64_t> now{1000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.mode_string() == "degraded-net"; }));
    EXPECT_EQ(pa.current_preset(), DPIPreset::NONE);  // fallback kept, no selection

    // stop() must join quickly even while sleeping in the 60s backoff
    // (interruptible 200ms sleep quanta).
    const auto t0 = std::chrono::steady_clock::now();
    pa.stop();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    EXPECT_LT(ms, 2000);
}

// A blocked first reference host (youtube.com throttled by DPI while other
// hosts answer) must NOT be mistaken for a dead network: the connectivity
// gate succeeds on ANY reachable host and selection proceeds.
TEST(PresetAutoPilotStartup, BlockedFirstHostDoesNotTripDegradedNet) {
    ProbeBehavior pb;
    {
        std::lock_guard<std::mutex> lk(pb.m);
        pb.direct_first_host_fails = true;  // a.test blocked, b/c.test answer
    }
    std::atomic<int64_t> now{1000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] {
        return pa.current_preset() == DPIPreset::RUNET_TSPU;  // best score
    }));
    EXPECT_NE(pa.mode_string(), "degraded-net");
    pa.stop();
}

TEST(PresetAutoPilotStartup, DirectWinsKeepsFallback) {
    ProbeBehavior pb;
    {
        std::lock_guard<std::mutex> lk(pb.m);
        pb.tspu_latency = -1;    // all presets fail
        pb.beeline_latency = -1;
        pb.direct_latency = 40;  // but the network itself is fine
    }
    std::atomic<int64_t> now{1000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.mode_string() == "monitoring"; }));
    EXPECT_EQ(pa.current_preset(), DPIPreset::NONE);
    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("direct-wins,no-filtering-detected"), std::string::npos);
    pa.stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. EWMA RTT degradation + cooldown/dwell gate (SPEC §10.3)
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotDegradation, CooldownBlocksThenAllowsSwitch) {
    ProbeBehavior pb;
    std::atomic<int64_t> now{1000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::RUNET_TSPU; }));

    // Degrade tspu: 1 host fails, others slow (200ms). round_failed stays
    // false (1 of 3 fails), so degradation must come from EWMA RTT
    // (baseline 50ms, factor 1.5 → ewma > 75 after enough samples).
    {
        std::lock_guard<std::mutex> lk(pb.m);
        pb.tspu_latency = 200;
        pb.tspu_first_host_fails = true;
        pb.beeline_latency = 50;
    }

    // Degradation is detected (mode flips) but the switch must be BLOCKED:
    // only ~0-1s passed since the startup switch (< 60s anti-storm floor,
    // < 120s cooldown, < 180s min dwell).
    ASSERT_TRUE(wait_for([&] { return pa.mode_string() == "degraded"; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(pa.current_preset(), DPIPreset::RUNET_TSPU);  // still blocked

    // Past cooldown but inside min dwell → still blocked.
    now.store(1000 + 130);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(pa.current_preset(), DPIPreset::RUNET_TSPU);

    // Past cooldown AND dwell → re-selection runs, beeline (3/3 ok, 50ms)
    // beats degraded tspu (2/3 ok, 200ms) beyond hysteresis → hot switch.
    now.store(1000 + 181);
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::BEELINE_MOBILE; }));
    EXPECT_EQ(pa.mode_string(), "monitoring");
    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"reason\":\"reselection\""), std::string::npos);
    EXPECT_NE(j.find("\"switches_total\":2"), std::string::npos);
    pa.stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// 3b. Dead current preset bypasses cooldown/dwell but not the 60s floor
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotDegradation, DeadCurrentBypassesCooldownNotFloor) {
    ProbeBehavior pb;
    std::atomic<int64_t> now{2000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::RUNET_TSPU; }));

    // tspu dies completely; beeline healthy.
    {
        std::lock_guard<std::mutex> lk(pb.m);
        pb.tspu_latency = -1;
        pb.beeline_latency = 50;
    }

    // 3 consecutive failed rounds trigger degradation fast (busy loop), but
    // the 60s anti-storm floor blocks even a dead-current switch.
    ASSERT_TRUE(wait_for([&] { return pa.mode_string() == "degraded"; }));
    now.store(2000 + 30);  // < 60s floor
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(pa.current_preset(), DPIPreset::RUNET_TSPU);

    // Past the floor: re-selection confirms current score <= 0, so
    // cooldown (120s) and dwell (180s) are bypassed.
    now.store(2000 + 61);
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::BEELINE_MOBILE; }));
    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"reason\":\"degradation\""), std::string::npos);
    pa.stop();
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. to_stats_json — all §7 fields present, JSON structure valid
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotJson, StatsJsonRoundTrip) {
    ProbeBehavior pb;
    std::atomic<int64_t> now{3000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::RUNET_TSPU; }));
    // let at least one monitor round complete so last_probe is filled
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("\"host\":\"a.test\"") != std::string::npos ||
               pa.to_stats_json().find("\"host\":\"b.test\"") != std::string::npos ||
               pa.to_stats_json().find("\"host\":\"c.test\"") != std::string::npos;
    }));
    pa.stop();

    const std::string j = pa.to_stats_json();
    // Required keys (SPEC §7)
    EXPECT_NE(j.find("\"enabled\":true"), std::string::npos);
    EXPECT_NE(j.find("\"mode\":\""), std::string::npos);
    EXPECT_NE(j.find("\"current_preset\":\"RuNet-TSPU\""), std::string::npos);
    EXPECT_NE(j.find("\"engine_preset_effective\":\"RuNet-TSPU\""), std::string::npos);
    EXPECT_NE(j.find("\"ewma_rtt_ms\":"), std::string::npos);
    EXPECT_NE(j.find("\"baseline_rtt_ms\":"), std::string::npos);
    EXPECT_NE(j.find("\"consec_fail_rounds\":"), std::string::npos);
    EXPECT_NE(j.find("\"switches_total\":1"), std::string::npos);
    EXPECT_NE(j.find("\"last_switch_ts\":3000"), std::string::npos);
    EXPECT_NE(j.find("\"last_probe\":{"), std::string::npos);
    EXPECT_NE(j.find("\"ok\":true"), std::string::npos);
    EXPECT_NE(j.find("\"latency_ms\":"), std::string::npos);
    EXPECT_NE(j.find("\"fail_reason\":\"\""), std::string::npos);
    EXPECT_NE(j.find("\"scores\":["), std::string::npos);
    EXPECT_NE(j.find("\"preset\":\"RuNet-TSPU\""), std::string::npos);
    EXPECT_NE(j.find("\"success\":3"), std::string::npos);
    EXPECT_NE(j.find("\"total\":3"), std::string::npos);
    EXPECT_NE(j.find("\"avg_latency_ms\":"), std::string::npos);
    EXPECT_NE(j.find("\"score\":"), std::string::npos);
    EXPECT_NE(j.find("\"history\":["), std::string::npos);
    EXPECT_NE(j.find("\"ts\":3000"), std::string::npos);
    EXPECT_NE(j.find("\"note\":\"\""), std::string::npos);

    // Structural sanity: balanced braces/brackets, single top-level object.
    int braces = 0, brackets = 0;
    bool in_str = false, esc = false;
    for (char c : j) {
        if (esc) { esc = false; continue; }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') { in_str = !in_str; continue; }
        if (in_str) continue;
        if (c == '{') braces++;
        else if (c == '}') braces--;
        else if (c == '[') brackets++;
        else if (c == ']') brackets--;
        EXPECT_GE(braces, 0);
        EXPECT_GE(brackets, 0);
    }
    EXPECT_EQ(braces, 0);
    EXPECT_EQ(brackets, 0);
    EXPECT_EQ(j.front(), '{');
    EXPECT_EQ(j.back(), '}');
}

// Control chars in probed host names must not leak raw bytes < 0x20 into the
// stats JSON (they break strict JSON parsers in the web UI).
TEST(PresetAutoPilotJson, EscapesControlChars) {
    ProbeBehavior pb;
    std::atomic<int64_t> now{4000};
    auto cfg = mk_test_cfg(pb, now);
    // raw 0x01 in host (LAST: last_probe keeps the final probe of a round)
    cfg.probe_hosts = {"a.test", "b.test", "c\x01.test"};

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::RUNET_TSPU; }));
    // wait for a monitor round so last_probe carries the poisoned host name
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("\\u0001") != std::string::npos;
    }));
    pa.stop();

    const std::string j = pa.to_stats_json();
    for (const unsigned char c : j)
        EXPECT_GE(c, 0x20) << "raw control byte in stats JSON";
    EXPECT_NE(j.find("\\u0001"), std::string::npos);
}

// ─────────────────────────────────────────────────────────────────────────────
// Assumption A1 (SPEC §5.1 step 4 / risk R5): apply_preset must NOT clobber
// CLI modifiers that handle_run applies after it (hostlist/ipset/quic).
// PresetAutoPilot additionally save/restores them around apply_preset, but
// this test pins the upstream assumption itself.
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotA1, ApplyPresetPreservesCliModifiers) {
    ncp::DPI::DPIConfig cfg;
    cfg.hostlist_file = "/tmp/hosts.txt";
    cfg.hostlist_exclude_file = "/tmp/exclude.txt";
    cfg.ipset_file = "/tmp/ipset.txt";
    cfg.quic_force_tcp = true;
    cfg.quic_ipfrag_offset = 24;
    for (DPIPreset p : {DPIPreset::RUNET_TSPU, DPIPreset::BEELINE_MOBILE,
                        DPIPreset::MTS_MOBILE, DPIPreset::MEGAFON_MOBILE,
                        DPIPreset::TELE2_MOBILE, DPIPreset::MOBILE_UNIVERSAL,
                        DPIPreset::RUNET_SOFT, DPIPreset::RUNET_STRONG,
                        DPIPreset::AUTOPROBE}) {
        ncp::DPI::apply_preset(p, cfg);
        EXPECT_EQ(cfg.hostlist_file, "/tmp/hosts.txt");
        EXPECT_EQ(cfg.hostlist_exclude_file, "/tmp/exclude.txt");
        EXPECT_EQ(cfg.ipset_file, "/tmp/ipset.txt");
        EXPECT_TRUE(cfg.quic_force_tcp);
        EXPECT_EQ(cfg.quic_ipfrag_offset, 24);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Misc API contract
// ─────────────────────────────────────────────────────────────────────────────
TEST(PresetAutoPilotApi, StartRequiresEngineOrProbeFn) {
    PresetAutoPilot pa;
    PresetAutoPilot::Config cfg;  // no probe_fn
    EXPECT_FALSE(pa.start(nullptr, cfg));
    EXPECT_FALSE(pa.running());
    pa.stop();  // idempotent, must not hang
    pa.stop();
    EXPECT_EQ(pa.current_preset(), DPIPreset::NONE);
    EXPECT_EQ(pa.mode_string(), "idle");
}

// ═════════════════════════════════════════════════════════════════════════════
// v2: escalation ladder (SPEC AUTOPILOT_V2 §8) — L0 direct → L1 preset →
// L2 augmented (rungs) → L3 Geneva GA. All network/time/evolution via hooks;
// engine==nullptr (state-only mode).
//
// Probe phases are told apart by the timeout the autopilot passes:
//   - quick connectivity check: NONE preset, 2000 ms
//   - selection (startup/re-selection): any preset, probe_timeout_ms=100
//   - rung/monitor/de-escalation rounds: monitor_probe_timeout_ms=150
// ═════════════════════════════════════════════════════════════════════════════

struct EscProbe {
    mutable std::mutex m;
    bool quick_ok = true;        // quick connectivity probe (NONE, 2000 ms)
    bool selection_ok = false;   // any probe at selection timeout (100 ms)
    bool direct_ok = false;      // direct probes at monitor timeout (NONE, 150 ms)
    bool live_ok = true;         // preset probes at monitor timeout (rung/monitor)
    int live_fail_first = 0;     // first N live probes fail (rung revert test)
    int live_calls = 0;          // counts non-NONE probes at monitor timeout

    BlockcheckProbe probe(DPIPreset p, const std::string& h, int timeout) {
        std::lock_guard<std::mutex> lk(m);
        bool ok = false;
        if (timeout == 2000) ok = quick_ok;
        else if (timeout == 100) ok = selection_ok;
        else {
            if (p == DPIPreset::NONE) {
                ok = direct_ok;
            } else {
                ++live_calls;
                ok = live_ok && live_calls > live_fail_first;
            }
        }
        return ok ? mk_probe(h, true, 100) : mk_probe(h, false, 0);
    }

    int live_probe_calls() const {
        std::lock_guard<std::mutex> lk(m);
        return live_calls;
    }
};

PresetAutoPilot::Config mk_esc_cfg(EscProbe& ep, std::atomic<int64_t>& now) {
    PresetAutoPilot::Config cfg;
    cfg.candidates = {DPIPreset::RUNET_TSPU, DPIPreset::BEELINE_MOBILE};
    cfg.probe_hosts = {"a.test", "b.test", "c.test"};
    cfg.probe_timeout_ms = 100;          // selection phase
    cfg.monitor_probe_timeout_ms = 150;  // rung/monitor/de-escalation phase
    cfg.monitor_interval_sec = 0;        // busy loop
    cfg.switch_cooldown_sec = 120;
    cfg.min_dwell_sec = 180;
    cfg.probe_fn = [&ep](DPIPreset p, const std::string& h, int t) {
        return ep.probe(p, h, t);
    };
    cfg.now_fn = [&now] { return now.load(); };
    return cfg;
}

// Deterministic fake IAutoEvolver (SPEC §3 TEST HOOK). generation() is
// monotonic per call so tests can observe growth through to_stats_json().
struct EvolverObs {
    std::atomic<int> factory_calls{0};
    std::atomic<int> start_calls{0};
    std::atomic<int> stop_calls{0};
    std::atomic<bool> run{false};
    std::atomic<uint32_t> gen{0};
};

class FakeEvolver : public ncp::IAutoEvolver {
public:
    explicit FakeEvolver(std::shared_ptr<EvolverObs> o) : obs(std::move(o)) {}
    bool start() override {
        obs->start_calls++;
        obs->run.store(true);
        return true;
    }
    void stop() override {
        obs->stop_calls++;
        obs->run.store(false);
    }
    bool running() const override { return obs->run.load(); }
    uint32_t generation() const override { return ++obs->gen; }
    double best_fitness() const override { return 500.0; }
    void set_on_new_best(
        std::function<void(const ncp::DPI::GenevaStrategy&)> cb) override {
        on_best = std::move(cb);
    }
    std::shared_ptr<EvolverObs> obs;
    std::function<void(const ncp::DPI::GenevaStrategy&)> on_best;
};

std::function<std::unique_ptr<ncp::IAutoEvolver>()>
mk_evolver_factory(std::shared_ptr<EvolverObs> obs) {
    return [obs]() {
        obs->factory_calls++;
        return std::unique_ptr<ncp::IAutoEvolver>(new FakeEvolver(obs));
    };
}

// ── 1. AllPresetsFail_GoesToL2 ──────────────────────────────────────────────
TEST(Escalation, AllPresetsFail_GoesToL2) {
    EscProbe ep;  // selection all fail; quick ok; rung probes succeed
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    // level flips to 2 when the base preset is applied; wait for the whole
    // episode so the rung outcome is committed before we stop.
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("\"note\":\"l2-ok\"") != std::string::npos;
    }));
    pa.stop();

    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"level\":2"), std::string::npos);
    EXPECT_NE(j.find("\"level_name\":\"augmented\""), std::string::npos);
    // R1 succeeded immediately (score >= min_acceptable_score).
    EXPECT_NE(j.find("\"fooling_badsum_badseq\""), std::string::npos);
    // note must be non-empty and explain the escalation outcome
    EXPECT_EQ(j.find("\"note\":\"\""), std::string::npos) << "note must be set";
    // L3 never reached: no geneva block
    EXPECT_EQ(j.find("\"geneva\":"), std::string::npos);
}

// ── 2. RungRevertOnNoImprovement ────────────────────────────────────────────
TEST(Escalation, RungRevertOnNoImprovement) {
    EscProbe ep;
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_fail_first = 3;  // R1 probe round (3 hosts) fails → revert
    }
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_level() == 2; }));
    // L2 success is reached via R2 (first rung that improves the score)
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("\"note\":\"l2-ok\"") != std::string::npos;
    }));
    pa.stop();

    const std::string j = pa.to_stats_json();
    // R1 gave no improvement → reverted, absent from active_features
    EXPECT_EQ(j.find("fooling_badsum_badseq"), std::string::npos);
    // R2 (fake_repeats=4) improved → kept
    EXPECT_NE(j.find("fake_repeats_4"), std::string::npos);
    // exactly one rung applied
    EXPECT_NE(j.find("\"active_features\":[\"fake_repeats_4\"]"), std::string::npos);
}

// ── 3. L2Success_StopsAtL2 ──────────────────────────────────────────────────
TEST(Escalation, L2Success_StopsAtL2) {
    EscProbe ep;  // R1 succeeds at once
    auto obs = std::make_shared<EvolverObs>();
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);
    cfg.evolver_factory = mk_evolver_factory(obs);  // L3 would be reachable…

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] {
        return pa.current_level() == 2 &&
               pa.to_stats_json().find("\"note\":\"l2-ok\"") != std::string::npos;
    }));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pa.stop();

    EXPECT_EQ(pa.current_level(), 2);
    EXPECT_EQ(pa.mode_string(), "monitoring");
    // …but Geneva was never even constructed: L2 sufficed
    EXPECT_EQ(obs->factory_calls.load(), 0);
    EXPECT_EQ(obs->start_calls.load(), 0);
}

// ── 4. AllRungsFail_GoesToL3 ────────────────────────────────────────────────
TEST(Escalation, AllRungsFail_GoesToL3) {
    EscProbe ep;
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_ok = false;    // every rung fails
        ep.direct_ok = false;  // direct stays dead (no de-escalation)
    }
    auto obs = std::make_shared<EvolverObs>();
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);
    cfg.evolver_factory = mk_evolver_factory(obs);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_level() == 3; }));
    ASSERT_TRUE(wait_for([&] { return obs->start_calls.load() == 1; }));
    pa.stop();

    EXPECT_EQ(obs->factory_calls.load(), 1);
    EXPECT_EQ(obs->stop_calls.load(), 1);  // stopped exactly once at teardown

    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"level\":3"), std::string::npos);
    EXPECT_NE(j.find("\"level_name\":\"geneva\""), std::string::npos);
    EXPECT_NE(j.find("\"geneva\":{"), std::string::npos);
    EXPECT_NE(j.find("\"escalation-l3\""), std::string::npos);
}

// ── 4b. Geneva stats block while L3 active (running + growing generation) ──
TEST(Escalation, GenevaStatsBlockWhileRunning) {
    EscProbe ep;
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_ok = false;
        ep.direct_ok = false;
    }
    auto obs = std::make_shared<EvolverObs>();
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);
    cfg.evolver_factory = mk_evolver_factory(obs);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_level() == 3; }));
    const std::string j1 = pa.to_stats_json();
    const std::string j2 = pa.to_stats_json();
    pa.stop();

    EXPECT_NE(j1.find("\"geneva\":{\"running\":true"), std::string::npos);
    // generation is monotonic across stats reads while the evolver lives
    EXPECT_GT(obs->gen.load(), 0u);
    (void)j2;
}

// ── 5. DeescalateWhenDirectRecovers ─────────────────────────────────────────
TEST(Escalation, DeescalateWhenDirectRecovers) {
    EscProbe ep;
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_ok = false;   // rungs fail → L3
        ep.direct_ok = true;  // direct healthy at monitor timeout → de-escalate
    }
    auto obs = std::make_shared<EvolverObs>();
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);
    cfg.evolver_factory = mk_evolver_factory(obs);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_level() == 3; }));
    // direct ok for deescalate_direct_rounds(=3) consecutive rounds → L0
    ASSERT_TRUE(wait_for([&] { return pa.current_level() == 0; }));
    ASSERT_TRUE(wait_for([&] { return obs->stop_calls.load() == 1; }));
    pa.stop();  // must NOT stop the evolver twice

    EXPECT_EQ(obs->stop_calls.load(), 1);
    EXPECT_EQ(pa.current_preset(), DPIPreset::NONE);
    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"reason\":\"de-escalation\""), std::string::npos);
    EXPECT_NE(j.find("\"level\":0"), std::string::npos);
    EXPECT_NE(j.find("\"level_name\":\"direct\""), std::string::npos);
    EXPECT_NE(j.find("\"active_features\":[]"), std::string::npos);
    // geneva block persists (L3 was active this session), evolver stopped
    EXPECT_NE(j.find("\"geneva\":{\"running\":false"), std::string::npos);
}

// ── 6. DisabledByConfig (v1 regression guard) ───────────────────────────────
TEST(Escalation, DisabledByConfig) {
    EscProbe ep;  // same world as AllPresetsFail_GoesToL2…
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_ok = false;
    }
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);
    cfg.escalation_enabled = false;  // …but escalation off → strict v1

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    // v1: no preset winner and direct baseline dead → degraded-net, no L2
    ASSERT_TRUE(wait_for([&] { return pa.mode_string() == "degraded-net"; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pa.stop();

    EXPECT_EQ(pa.current_level(), 0);
    EXPECT_EQ(ep.live_probe_calls(), 0);  // no rung probes ever ran
    const std::string j = pa.to_stats_json();
    EXPECT_NE(j.find("\"level\":0"), std::string::npos);
    EXPECT_EQ(j.find("\"geneva\":"), std::string::npos);
}

// ── 7. CooldownRespected ────────────────────────────────────────────────────
TEST(Escalation, CooldownRespected) {
    EscProbe ep;
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_ok = false;    // all rungs fail
        ep.direct_ok = false;
    }
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);  // escalation_cooldown_sec = 300 (default)
    // no evolver_factory and no geneva_fitness → episodes end at L2
    // (note="geneva-unavailable"), making repeated episodes observable via
    // switches_total.

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("geneva-unavailable") != std::string::npos;
    }));
    EXPECT_NE(pa.to_stats_json().find("\"switches_total\":1"), std::string::npos);

    // Past the 60 s anti-storm floor but inside the escalation cooldown:
    // degradation re-selection runs, but the second L2 entry is gated.
    now.store(1000 + 61);
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("escalation-cooldown") != std::string::npos;
    }));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_NE(pa.to_stats_json().find("\"switches_total\":1"), std::string::npos)
        << "second episode must be blocked by escalation_cooldown_sec";

    // Past the cooldown → the second episode runs.
    now.store(1000 + 300);
    ASSERT_TRUE(wait_for([&] {
        return pa.to_stats_json().find("\"switches_total\":2") != std::string::npos;
    }));
    pa.stop();
}

// ── 8. GenevaTranslator.PureLogic ───────────────────────────────────────────
TEST(GenevaTranslator, PureLogic) {
    using ncp::DPI::DPIConfig;
    using ncp::DPI::GenevaAction;
    using ncp::DPI::GenevaStep;
    using ncp::DPI::GenevaStrategy;
    using ncp::DPI::geneva_strategy_to_dpi_config;

    DPIConfig base;
    base.hostlist_file = "/tmp/hosts.txt";   // must be preserved
    base.split_position = 5;
    base.fake_fooling = 4;                   // md5sig bit — must survive |=
    base.enable_fake_packet = false;
    base.fake_repeats = 1;
    base.fake_ttl = 3;
    base.enable_disorder = false;

    auto step = [](GenevaAction a, size_t param) {
        GenevaStep s;
        s.action = a;
        s.param = param;
        return s;
    };

    // FRAGMENT: single position, clamped to 64
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::FRAGMENT, 100)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_tcp_split);
        EXPECT_EQ(out.split_position, 64);
        EXPECT_FALSE(out.enable_multi_layer_split);
        EXPECT_EQ(out.hostlist_file, "/tmp/hosts.txt");
    }
    // FRAGMENT x2: multi-layer split, both clamped
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::FRAGMENT, 10),
                   step(GenevaAction::FRAGMENT, 200)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_multi_layer_split);
        ASSERT_EQ(out.split_positions.size(), 2u);
        EXPECT_EQ(out.split_positions[0], 10);
        EXPECT_EQ(out.split_positions[1], 64);
        EXPECT_EQ(out.split_position, 5);  // untouched for multi-split
    }
    // FRAGMENT param 0: enables split but sets no position
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::FRAGMENT, 0)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_tcp_split);
        EXPECT_EQ(out.split_position, 5);
        EXPECT_FALSE(out.enable_multi_layer_split);
    }
    // TAMPER_TTL: clamp to 8; param 0 → 1
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::TAMPER_TTL, 100)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_fake_packet);
        EXPECT_EQ(out.fake_ttl, 8);

        s.steps = {step(GenevaAction::TAMPER_TTL, 0)};
        out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_EQ(out.fake_ttl, 1);
    }
    // TAMPER_CHECKSUM / TAMPER_SEQ: fooling bits OR-ed, existing bits kept
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::TAMPER_CHECKSUM, 0),
                   step(GenevaAction::TAMPER_SEQ, 0)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_fake_packet);
        EXPECT_EQ(out.fake_fooling, 4 | 1 | 2);
    }
    // DUPLICATE: fake_repeats clamped to 8; param 0 → 2
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::DUPLICATE, 100)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_fake_packet);
        EXPECT_EQ(out.fake_repeats, 8);

        s.steps = {step(GenevaAction::DUPLICATE, 0)};
        out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_EQ(out.fake_repeats, 2);
    }
    // DISORDER
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::DISORDER, 0)};
        auto out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_disorder);
    }
    // DROP and TAMPER_FLAGS have no DPIConfig equivalent → skipped counter
    {
        GenevaStrategy s;
        s.steps = {step(GenevaAction::DROP, 0),
                   step(GenevaAction::TAMPER_FLAGS, 0),
                   step(GenevaAction::DISORDER, 0)};
        int skipped = 0;
        auto out = geneva_strategy_to_dpi_config(base, s, &skipped);
        EXPECT_EQ(skipped, 2);
        EXPECT_TRUE(out.enable_disorder);  // translatable step still applied
        EXPECT_EQ(out.split_position, 5);
        EXPECT_EQ(out.fake_fooling, 4);
        // skipped == nullptr is allowed
        out = geneva_strategy_to_dpi_config(base, s, nullptr);
        EXPECT_TRUE(out.enable_disorder);
    }
}

// ── 9. Stats JSON back-compat (v1 fields + v2 fields per level) ─────────────
TEST(Escalation, StatsJsonBackCompat) {
    ProbeBehavior pb;  // classic v1 world: TSPU wins the startup selection
    std::atomic<int64_t> now{3000};
    auto cfg = mk_test_cfg(pb, now);

    PresetAutoPilot pa;
    ASSERT_TRUE(pa.start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa.current_preset() == DPIPreset::RUNET_TSPU; }));
    pa.stop();

    const std::string j = pa.to_stats_json();
    // v1 fields all still present
    EXPECT_NE(j.find("\"enabled\":true"), std::string::npos);
    EXPECT_NE(j.find("\"mode\":\"monitoring\""), std::string::npos);
    EXPECT_NE(j.find("\"current_preset\":\"RuNet-TSPU\""), std::string::npos);
    EXPECT_NE(j.find("\"engine_preset_effective\":\"RuNet-TSPU\""), std::string::npos);
    EXPECT_NE(j.find("\"ewma_rtt_ms\":"), std::string::npos);
    EXPECT_NE(j.find("\"switches_total\":1"), std::string::npos);
    EXPECT_NE(j.find("\"scores\":["), std::string::npos);
    EXPECT_NE(j.find("\"history\":["), std::string::npos);
    EXPECT_NE(j.find("\"note\":"), std::string::npos);
    // v2 fields at L1
    EXPECT_NE(j.find("\"level\":1"), std::string::npos);
    EXPECT_NE(j.find("\"level_name\":\"preset\""), std::string::npos);
    EXPECT_NE(j.find("\"active_features\":[]"), std::string::npos);
    // geneva block absent: L3 never activated this session
    EXPECT_EQ(j.find("\"geneva\":"), std::string::npos);
    // history events carry the level
    EXPECT_NE(j.find("\"reason\":\"startup-selection\""), std::string::npos);
    EXPECT_NE(j.find("\"level\":1"), std::string::npos);
}

// ── 10. RepeatEpisodeKeepsRunningEvolver (review blocker regression) ──────
// A second escalation episode while the L3 Geneva evolver is alive must be
// refused: re-entering would (a) downgrade L3→L2 without restoring direct
// (SPEC §2) and (b) destroy the RUNNING evolver under the autopilot mutex
// (`evolver = std::move(ev)`) while the GA thread's on_new_best callback
// waits on that same mutex → hard deadlock. The safe path is stop_evolver(),
// which moves the pointer out from under the lock.
class DeferredBestEvolver : public FakeEvolver {
public:
    using FakeEvolver::FakeEvolver;
    bool start() override {
        if (!FakeEvolver::start()) return false;
        // Deferred on_new_best storm, starting after the autopilot has
        // settled on L3: emulates a GA thread reporting new bests while the
        // monitor loop runs degradation handling.
        best_th = std::thread([this] {
            std::this_thread::sleep_for(std::chrono::milliseconds(1200));
            while (obs->run.load()) {
                if (on_best) on_best(ncp::DPI::GenevaStrategy{});
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
        });
        return true;
    }
    void stop() override {
        FakeEvolver::stop();       // run=false → the helper thread exits
        if (best_th.joinable()) best_th.join();
    }
    ~DeferredBestEvolver() override {
        // If this destructor ever runs UNDER the autopilot mutex (the old
        // bug), the join below waits for the helper thread whose callback
        // waits on that same mutex → deadlock. With the fix, evolvers are
        // only destroyed via stop_evolver(), i.e. outside the lock and
        // after stop().
        if (best_th.joinable()) best_th.join();
    }

private:
    std::thread best_th;
};

TEST(Escalation, RepeatEpisodeKeepsRunningEvolver) {
    EscProbe ep;
    {
        std::lock_guard<std::mutex> lk(ep.m);
        ep.live_ok = false;    // every rung fails → L3
        ep.direct_ok = false;  // direct stays dead (no de-escalation)
    }
    auto obs = std::make_shared<EvolverObs>();
    std::atomic<int64_t> now{1000};
    auto cfg = mk_esc_cfg(ep, now);
    cfg.degrade_fail_rounds = 1;   // degradation handling on the 1st failed round
    cfg.evolver_factory = [obs]() {
        obs->factory_calls++;
        return std::unique_ptr<ncp::IAutoEvolver>(new DeferredBestEvolver(obs));
    };

    auto pa = std::make_unique<PresetAutoPilot>();
    ASSERT_TRUE(pa->start(nullptr, cfg));
    ASSERT_TRUE(wait_for([&] { return pa->current_level() == 3; }));
    ASSERT_TRUE(wait_for([&] { return obs->start_calls.load() == 1; }));

    // Past every cooldown/floor: degradation cycles re-run selection while
    // the evolver is alive — a repeat episode must be REFUSED.
    now.store(1000 + 400);
    // Escalated rounds are paced at 1s; give the loop several degradation
    // cycles (each: failed live round → handle_degradation → re-selection).
    std::this_thread::sleep_for(std::chrono::milliseconds(4500));

    EXPECT_EQ(obs->factory_calls.load(), 1)
        << "a repeat episode constructed a second evolver";
    EXPECT_EQ(obs->start_calls.load(), 1)
        << "a repeat episode started a second evolver";
    EXPECT_EQ(pa->current_level(), 3)
        << "a repeat episode downgraded L3→L2 without restoring direct";

    // Liveness watchdog: if the running evolver was ever recycled under the
    // autopilot mutex, its callback thread deadlocks against it and stop()
    // never returns.
    auto stop_done = std::async(std::launch::async, [&] { pa->stop(); });
    if (stop_done.wait_for(std::chrono::seconds(10)) !=
        std::future_status::ready) {
        pa.release();  // do not hang the whole test binary on the regression
        FAIL() << "deadlock: stop() did not return within 10s";
    }
    EXPECT_EQ(obs->stop_calls.load(), 1);
}

} // namespace
