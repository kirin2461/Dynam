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

} // namespace
