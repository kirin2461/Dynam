// ═══════════════════════════════════════════════════════════════════════════
// NCP PresetAutoPilot — preset-level auto-selection and hot-switching.
// See ncp_preset_autopilot.hpp for the design contract.
//
// Threading model (invariants):
//   - ONE background std::thread, joined in stop().
//   - ONE mutex (Impl::m); probing NEVER happens under the lock.
//   - All network access goes through BlockChecker::probe_direct /
//     BlockChecker::probe_via_socks5 / BlockChecker::run — TLS ClientHello on
//     TCP/443 only. No raw sockets here, no ICMP, no ports 53/80.
//   - Interruptible sleep in 200 ms quanta so stop() joins in ~1 s.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_preset_autopilot.hpp"
#include "ncp_proxy.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <sstream>
#include <thread>

namespace ncp {

namespace {

std::string pa_json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    static const char* hex = "0123456789abcdef";
    for (const unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                // RFC 8259: ALL control chars < 0x20 must be escaped. A raw
                // byte (e.g. \x01 in a host name) breaks the whole stats JSON
                // for strict parsers (web UI).
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[(c >> 4) & 0xF];
                    out += hex[c & 0xF];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// Hard minimum gap between ANY two switches (anti-storm floor), even when the
// current preset is completely dead (SPEC §5.2).
constexpr int64_t kAntiStormFloorSec = 60;
// Monitor interval while the network looks dead (SPEC §5.1.1).
constexpr int kDegradedNetIntervalSec = 60;
// Quick connectivity check timeout at startup (SPEC §5.1.1).
constexpr int kQuickProbeTimeoutMs = 2000;

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// Impl
// ─────────────────────────────────────────────────────────────────────────────
class PresetAutoPilot::Impl {
public:
    Config cfg;
    DPI::DPIBypass* engine = nullptr;        // non-owning
    mutable std::mutex m;                    // the ONLY mutex
    std::thread th;
    std::atomic<bool> stop_flag{false};
    std::atomic<bool> is_running{false};

    // ── under m ──
    DPI::DPIPreset current = DPI::DPIPreset::NONE;
    std::string mode = "idle";
    std::vector<CandidateScore> last_scores;
    std::vector<SwitchEvent> history;        // cap 32
    double ewma_rtt_ms = 0.0;
    double baseline_rtt_ms = 0.0;            // EWMA at the moment current was applied
    int ewma_samples = 0;
    int consec_fail_rounds = 0;
    bool last_round_all_failed = false;
    bool selection_in_progress = false;
    int64_t last_switch_ts = 0;
    int64_t last_probe_ts = 0;
    uint64_t switches_total = 0;
    BlockcheckProbe last_probe;
    std::string note;
    // DPIConfig carries no preset tag, so drift control is limited to what
    // this autopilot last pushed via update_config() ("AutoProbe" = the
    // fallback config the engine was started with).
    std::string engine_preset_effective = "AutoProbe";

    int64_t now() const {
        return cfg.now_fn ? cfg.now_fn() : static_cast<int64_t>(std::time(nullptr));
    }

    void interruptible_sleep(int sec) {
        for (int i = 0; i < sec * 5 && !stop_flag.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // One probe, dispatching to the test hook or BlockChecker (never under m).
    BlockcheckProbe direct_probe(const std::string& host, int timeout_ms) {
        if (cfg.probe_fn)
            return cfg.probe_fn(DPI::DPIPreset::NONE, host, timeout_ms);
        return BlockChecker::probe_direct(host, timeout_ms);
    }

    struct SelectionResult {
        std::vector<CandidateScore> scores;  // non-direct candidates
        long direct_score = 0;
        int direct_success = 0;
        int direct_total = 0;
    };

    // Probe every candidate preset (temp SOCKS5 desync proxy per preset via
    // BlockChecker, or the injected probe_fn in test mode) plus one direct
    // baseline. Never under the lock; cancellable via stop_flag.
    SelectionResult run_selection(bool include_current) {
        SelectionResult out;
        std::vector<DPI::DPIPreset> cands;
        std::vector<std::string> hosts;
        int timeout_ms;
        {
            std::lock_guard<std::mutex> lk(m);
            cands = cfg.candidates;
            hosts = cfg.probe_hosts;
            timeout_ms = cfg.probe_timeout_ms;
            if (include_current && current != DPI::DPIPreset::NONE &&
                std::find(cands.begin(), cands.end(), current) == cands.end())
                cands.push_back(current);
        }
        if (hosts.empty()) return out;

        if (cfg.probe_fn) {
            // Test mode: deterministic probing via the injected hook.
            for (const auto& p : cands) {
                if (stop_flag.load()) break;
                CandidateScore cs;
                cs.preset = p;
                cs.name = DPI::preset_to_string(p);
                cs.total = static_cast<int>(hosts.size());
                long lat_sum = 0;
                for (const auto& h : hosts) {
                    if (stop_flag.load()) break;
                    BlockcheckProbe pr = cfg.probe_fn(p, h, timeout_ms);
                    if (pr.ok) { cs.success_count++; lat_sum += pr.latency_ms; }
                }
                cs.avg_latency_ms = cs.success_count
                    ? static_cast<double>(lat_sum) / cs.success_count : 0.0;
                cs.score = static_cast<long>(cs.success_count) * 100000L -
                           static_cast<long>(cs.avg_latency_ms);
                out.scores.push_back(std::move(cs));
            }
            // direct baseline
            long lat_sum = 0;
            for (const auto& h : hosts) {
                if (stop_flag.load()) break;
                BlockcheckProbe pr = cfg.probe_fn(DPI::DPIPreset::NONE, h, timeout_ms);
                out.direct_total++;
                if (pr.ok) { out.direct_success++; lat_sum += pr.latency_ms; }
            }
            double avg = out.direct_success
                ? static_cast<double>(lat_sum) / out.direct_success : 0.0;
            out.direct_score = static_cast<long>(out.direct_success) * 100000L -
                               static_cast<long>(avg);
            return out;
        }

        // Real mode: BlockChecker with one strategy per candidate preset.
        BlockChecker checker;
        BlockChecker::Config bc;
        bc.domains = hosts;
        bc.timeout_ms = timeout_ms;
        bc.use_doh = cfg.use_doh;
        bc.cancel_cb = [this] { return stop_flag.load(); };
        for (const auto& p : cands) {
            BlockcheckStrategy s;
            s.name = DPI::preset_to_string(p);
            s.description = "preset:" + s.name;
            DPI::apply_preset(p, s.config);
            // apply_preset picks DPIMode::DRIVER on Windows — meaningless for
            // a temp probing proxy (DesyncProxy only reads socket-level desync
            // fields). Force PROXY so the strategy reflects the preset's
            // desync behaviour in BlockChecker's temp-proxy harness.
            s.config.mode = DPI::DPIMode::PROXY;
            assert(s.config.mode == DPI::DPIMode::PROXY);
            s.use_chain = false;
            s.is_direct = false;
            bc.strategies.push_back(std::move(s));
        }
        {
            BlockcheckStrategy d;
            d.name = "direct";
            d.description = "baseline (no bypass)";
            d.is_direct = true;
            bc.strategies.push_back(std::move(d));
        }
        BlockcheckReport rep = checker.run(bc);
        for (const auto& sr : rep.results) {
            if (sr.strategy == "direct") {
                out.direct_score = sr.score;
                out.direct_success = sr.success_count;
                out.direct_total = sr.total;
                continue;
            }
            CandidateScore cs;
            cs.preset = DPI::preset_from_string(sr.strategy);
            cs.name = sr.strategy;
            cs.success_count = sr.success_count;
            cs.total = sr.total;
            cs.avg_latency_ms = sr.avg_latency_ms;
            cs.score = sr.score;
            out.scores.push_back(std::move(cs));
        }
        return out;
    }

    static const CandidateScore* best_candidate(const SelectionResult& sel) {
        const CandidateScore* best = nullptr;
        for (const auto& s : sel.scores) {
            if (s.success_count <= 0) continue;
            if (!best || s.score > best->score) best = &s;
        }
        return best;
    }

    // Hot-apply a winning preset on top of the engine's live config (keeps
    // CLI modifiers) and commit the switch to state. Probing is done; this
    // only touches the engine and locked fields.
    void apply_winner(DPI::DPIPreset winner, const CandidateScore& ws,
                      const std::string& reason, long from_score) {
        if (engine) {
            DPI::DPIConfig new_cfg = engine->get_config();
            // Safety net for assumption A1 (verified: apply_preset does NOT
            // touch hostlist/ipset/quic fields — they are applied after
            // apply_preset in main.cpp). Save/restore anyway so a future
            // preset change cannot silently drop CLI modifiers. The running
            // backend mode is also preserved: update_config() cannot swap
            // interception backends mid-flight.
            const std::string hostlist = new_cfg.hostlist_file;
            const std::string hostlist_excl = new_cfg.hostlist_exclude_file;
            const std::string ipset = new_cfg.ipset_file;
            const bool quic_tcp = new_cfg.quic_force_tcp;
            const int quic_frag = new_cfg.quic_ipfrag_offset;
            const DPI::DPIMode run_mode = new_cfg.mode;
            DPI::apply_preset(winner, new_cfg);
            new_cfg.hostlist_file = hostlist;
            new_cfg.hostlist_exclude_file = hostlist_excl;
            new_cfg.ipset_file = ipset;
            new_cfg.quic_force_tcp = quic_tcp;
            new_cfg.quic_ipfrag_offset = quic_frag;
            new_cfg.mode = run_mode;
            if (!engine->update_config(new_cfg)) {
                // The engine rejected the config — there was NO real switch.
                // Do not record a SwitchEvent and do not touch `current`;
                // just flag the failure so the operator can see it.
                fprintf(stderr,
                        "[!] PresetAutoPilot: engine rejected update_config(); "
                        "switch to %s NOT applied\n",
                        DPI::preset_to_string(winner));
                std::lock_guard<std::mutex> lk(m);
                note = "apply-failed";
                return;
            }
        }

        const int64_t ts = now();
        std::lock_guard<std::mutex> lk(m);
        SwitchEvent ev;
        ev.ts = ts;
        // Before the first switch the engine runs the AUTOPROBE fallback
        // (MOBILE_UNIVERSAL base) — report it as "AutoProbe".
        ev.from_preset = (switches_total == 0 && current == DPI::DPIPreset::NONE)
                             ? "AutoProbe"
                             : DPI::preset_to_string(current);
        ev.to_preset = DPI::preset_to_string(winner);
        ev.reason = reason;
        ev.from_score = from_score;
        ev.to_score = ws.score;
        history.push_back(std::move(ev));
        if (history.size() > 32) history.erase(history.begin());

        current = winner;
        engine_preset_effective = DPI::preset_to_string(winner);
        baseline_rtt_ms = ws.avg_latency_ms;
        ewma_rtt_ms = ws.avg_latency_ms;
        ewma_samples = ws.avg_latency_ms > 0.0 ? 1 : 0;
        consec_fail_rounds = 0;
        last_round_all_failed = false;
        last_switch_ts = ts;
        switches_total++;
        note.clear();
        mode = "monitoring";
    }

    // ── STARTUP-SELECTION (SPEC §5.1) — runs once, no lock while probing ──
    void startup_phase() {
        std::string first_host;
        {
            std::lock_guard<std::mutex> lk(m);
            if (!cfg.probe_hosts.empty()) first_host = cfg.probe_hosts.front();
        }
        if (first_host.empty()) {
            std::lock_guard<std::mutex> lk(m);
            mode = "monitoring";
            return;
        }

        // 1. Quick connectivity check.
        BlockcheckProbe quick = direct_probe(first_host, kQuickProbeTimeoutMs);
        if (stop_flag.load()) return;
        if (!quick.ok) {
            // No network: keep the fallback config the engine started with.
            std::lock_guard<std::mutex> lk(m);
            mode = "degraded-net";
            last_probe = quick;
            last_probe_ts = now();
            return;
        }

        // 2-3. Full selection over candidate presets (background, engine is
        // already running with the fallback config).
        SelectionResult sel = run_selection(/*include_current=*/false);
        if (stop_flag.load()) return;
        const CandidateScore* winner = best_candidate(sel);

        if (!winner) {
            std::lock_guard<std::mutex> lk(m);
            last_scores = sel.scores;
            if (sel.direct_success > 0) {
                // Direct baseline wins: the network does not filter. Do NOT
                // disable protection automatically (safer, predictable).
                note = "direct-wins,no-filtering-detected";
                mode = "monitoring";
            } else {
                mode = "degraded-net";
            }
            return;
        }
        if (winner->score <= sel.direct_score && sel.direct_success > 0) {
            // A preset must beat the direct baseline to be applied.
            std::lock_guard<std::mutex> lk(m);
            last_scores = sel.scores;
            note = "direct-wins,no-filtering-detected";
            mode = "monitoring";
            return;
        }

        // 4-5. Apply winner on top of the live config + record the event.
        apply_winner(winner->preset, *winner, "startup-selection", 0);
        {
            std::lock_guard<std::mutex> lk(m);
            last_scores = sel.scores;
        }
    }

    // ── MONITOR round (SPEC §5.2) — probes current live preset ──
    void monitor_round() {
        std::vector<std::string> hosts;
        DPI::DPIPreset cur;
        int timeout_ms;
        {
            std::lock_guard<std::mutex> lk(m);
            hosts = cfg.probe_hosts;
            cur = current;
            timeout_ms = cfg.monitor_probe_timeout_ms;
        }
        if (hosts.empty()) return;

        std::vector<BlockcheckProbe> probes;
        probes.reserve(hosts.size());

        if (cfg.probe_fn) {
            // Test mode.
            for (const auto& h : hosts) {
                if (stop_flag.load()) return;
                probes.push_back(cfg.probe_fn(cur, h, timeout_ms));
            }
        } else if (engine && engine->interception_active()) {
            // System-wide interception is live: a plain direct probe passes
            // through the currently applied preset.
            for (const auto& h : hosts) {
                if (stop_flag.load()) return;
                probes.push_back(BlockChecker::probe_direct(h, timeout_ms));
            }
        } else if (engine) {
            // Passive/proxy mode (Linux default without NFQUEUE): no system
            // interception, so run the probes through a short-lived temp
            // SOCKS5 desync proxy carrying the engine's live config — the
            // same code path BlockChecker uses.
            DesyncProxy proxy;
            DesyncProxy::Config pcfg;
            pcfg.port = 0;
            pcfg.use_doh = cfg.use_doh;
            pcfg.base = engine->get_config();
            if (!proxy.start(pcfg)) {
                // Temp proxy did not come up: the whole round is unmeasurable.
                // Push a failed probe per host so the aggregation below counts
                // this as a fully failed round (round_failed=true and
                // last_round_all_failed=true), keeping degradation detection
                // (consec_fail_rounds) consistent.
                for (const auto& h : hosts) {
                    BlockcheckProbe pr;
                    pr.domain = h;
                    pr.fail_reason = "proxy";
                    probes.push_back(std::move(pr));
                }
            } else {
                const uint16_t port = proxy.bound_port();
                for (const auto& h : hosts) {
                    if (stop_flag.load()) break;
                    probes.push_back(BlockChecker::probe_via_socks5(port, h, timeout_ms));
                }
                proxy.stop();
            }
            if (stop_flag.load()) return;
        } else {
            return;  // no engine and no probe_fn: nothing to measure
        }
        if (probes.empty()) return;

        // Aggregate the round (locked, fields only).
        int fails = 0;
        int min_latency = 0;
        for (const auto& pr : probes) {
            if (pr.ok) {
                if (min_latency == 0 || pr.latency_ms < min_latency)
                    min_latency = pr.latency_ms;
            } else {
                fails++;
            }
        }
        const bool round_failed = fails > static_cast<int>(hosts.size()) / 2;

        std::lock_guard<std::mutex> lk(m);
        last_probe = probes.back();
        last_probe_ts = now();
        last_round_all_failed = (fails == static_cast<int>(probes.size()));
        if (min_latency > 0) {
            // Conservative: track the best achievable RTT of the round;
            // degradation is detected via fail rounds (and RTT vs baseline).
            const double a = cfg.ewma_alpha;
            ewma_rtt_ms = (ewma_rtt_ms <= 0.0)
                              ? static_cast<double>(min_latency)
                              : (1.0 - a) * ewma_rtt_ms + a * min_latency;
            ewma_samples++;
        }
        consec_fail_rounds = round_failed ? consec_fail_rounds + 1 : 0;
    }

    // ── Degradation handling: cooldown/dwell gate → re-selection → switch ──
    void handle_degradation(const char* reason) {
        int64_t now_ts;
        bool gate;
        bool looks_dead;
        {
            std::lock_guard<std::mutex> lk(m);
            mode = "degraded";
            if (selection_in_progress) return;
            now_ts = now();
            const int64_t since_switch = now_ts - last_switch_ts;
            // Anti-storm floor: no re-selection within 60 s of ANY switch.
            if (since_switch < kAntiStormFloorSec) return;
            gate = since_switch >= cfg.switch_cooldown_sec &&
                   since_switch >= cfg.min_dwell_sec;
            // "Current is dead" exemption: all probes of the last rounds
            // failed — re-selection may run inside the cooldown window, and
            // if the fresh score confirms current<=0 the switch bypasses
            // cooldown/dwell (floor above still applies).
            looks_dead = !gate && last_round_all_failed &&
                         consec_fail_rounds >= cfg.degrade_fail_rounds;
            if (!gate && !looks_dead) return;
            selection_in_progress = true;
        }

        SelectionResult sel = run_selection(/*include_current=*/true);
        {
            std::lock_guard<std::mutex> lk(m);
            selection_in_progress = false;
            if (!sel.scores.empty()) last_scores = sel.scores;
        }
        if (stop_flag.load()) return;

        const CandidateScore* winner = best_candidate(sel);
        if (!winner) return;  // everything failed — stay degraded

        DPI::DPIPreset cur;
        long cur_fresh_score = 0;
        {
            std::lock_guard<std::mutex> lk(m);
            cur = current;
        }
        for (const auto& s : sel.scores)
            if (s.preset == cur) cur_fresh_score = s.score;

        if (winner->preset == cur) {
            // Current preset is still the best available — reset degradation.
            std::lock_guard<std::mutex> lk(m);
            consec_fail_rounds = 0;
            ewma_rtt_ms = winner->avg_latency_ms;
            ewma_samples = winner->avg_latency_ms > 0.0 ? 1 : 0;
            if (winner->avg_latency_ms > 0.0) baseline_rtt_ms = winner->avg_latency_ms;
            mode = "monitoring";
            return;
        }

        const bool cur_dead = cur_fresh_score <= 0;
        const bool allowed =
            cur_dead ? true
                     : (gate && PresetAutoPilot::should_switch(
                                    cur_fresh_score, winner->score, cfg.hysteresis_pct));
        if (!allowed) return;

        apply_winner(winner->preset, *winner, reason, cur_fresh_score);
    }

    // ── Main loop (SPEC §4) ──
    // Exception safety: this thread MUST never let an exception escape — an
    // uncaught throw in a std::thread is std::terminate and kills the whole
    // process. Per-iteration catch keeps the loop alive through transient
    // failures (e.g. bad_alloc inside a probe round); the outer catch-all is
    // the last line of defence and parks the autopilot in "idle".
    void run_loop() {
        is_running.store(true);
        try {
            {
                std::lock_guard<std::mutex> lk(m);
                mode = "selecting";
            }
            startup_phase();

            while (!stop_flag.load()) {
                try {
                    monitor_iteration();
                } catch (const std::exception& e) {
                    fprintf(stderr,
                            "[!] PresetAutoPilot: exception in monitor "
                            "iteration: %s (continuing)\n", e.what());
                } catch (...) {
                    fprintf(stderr,
                            "[!] PresetAutoPilot: unknown exception in "
                            "monitor iteration (continuing)\n");
                }
            }
        } catch (const std::exception& e) {
            fprintf(stderr,
                    "[!] PresetAutoPilot: fatal exception, background thread "
                    "exiting: %s\n", e.what());
        } catch (...) {
            fprintf(stderr,
                    "[!] PresetAutoPilot: fatal unknown exception, background "
                    "thread exiting\n");
        }

        {
            std::lock_guard<std::mutex> lk(m);
            mode = "idle";
        }
        is_running.store(false);
    }

    // One iteration of the main loop (sleep → probe round → degradation
    // handling). May throw; run_loop() contains it per-iteration.
    void monitor_iteration() {
        int interval;
        bool net_down;
        {
            std::lock_guard<std::mutex> lk(m);
            net_down = (mode == "degraded-net");
            interval = net_down ? kDegradedNetIntervalSec
                                : cfg.monitor_interval_sec;
        }
        if (!cfg.probe_fn && interval < 1) interval = 1;
        interruptible_sleep(interval);
        if (stop_flag.load()) return;

        if (net_down) {
            // Network was dead at startup: cheap re-check every 60 s;
            // when it comes back, run the selection for real.
            std::string first_host;
            {
                std::lock_guard<std::mutex> lk(m);
                if (!cfg.probe_hosts.empty()) first_host = cfg.probe_hosts.front();
            }
            if (first_host.empty()) return;
            BlockcheckProbe q = direct_probe(first_host, kQuickProbeTimeoutMs);
            if (stop_flag.load()) return;
            if (q.ok) {
                {
                    std::lock_guard<std::mutex> lk(m);
                    mode = "selecting";
                }
                startup_phase();
            } else {
                std::lock_guard<std::mutex> lk(m);
                last_probe = q;
                last_probe_ts = now();
            }
            return;
        }

        monitor_round();
        if (stop_flag.load()) return;

        bool deg_fail = false, deg_rtt = false;
        {
            std::lock_guard<std::mutex> lk(m);
            deg_fail = consec_fail_rounds >= cfg.degrade_fail_rounds;
            deg_rtt = baseline_rtt_ms > 0.0 && ewma_samples >= 5 &&
                      ewma_rtt_ms > cfg.degrade_rtt_factor * baseline_rtt_ms;
            if (!deg_fail && !deg_rtt && mode == "degraded")
                mode = "monitoring";  // recovered on its own
        }
        if (deg_fail || deg_rtt)
            handle_degradation(deg_fail ? "degradation" : "reselection");
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// PresetAutoPilot public API
// ─────────────────────────────────────────────────────────────────────────────
PresetAutoPilot::PresetAutoPilot() : impl_(std::make_unique<Impl>()) {}
PresetAutoPilot::~PresetAutoPilot() { stop(); }

bool PresetAutoPilot::start(DPI::DPIBypass* engine, const Config& cfg_in) {
    if (!engine && !cfg_in.probe_fn) return false;  // engine required unless test mode
    std::lock_guard<std::mutex> lk(impl_->m);
    if (impl_->th.joinable()) return false;         // already started

    impl_->cfg = cfg_in;
    Config& c = impl_->cfg;
    if (c.candidates.empty()) {
        c.candidates = {
            DPI::DPIPreset::RUNET_TSPU,
            DPI::DPIPreset::BEELINE_MOBILE,
            DPI::DPIPreset::MTS_MOBILE,
            DPI::DPIPreset::MEGAFON_MOBILE,
            DPI::DPIPreset::TELE2_MOBILE,
            DPI::DPIPreset::MOBILE_UNIVERSAL,
            DPI::DPIPreset::RUNET_SOFT,
            DPI::DPIPreset::RUNET_STRONG,
        };
    }
    if (c.max_candidates > 0 && c.candidates.size() > c.max_candidates)
        c.candidates.resize(c.max_candidates);
    if (c.probe_hosts.empty()) {
        auto doms = BlockChecker::default_domains();
        if (doms.size() > 3) doms.resize(3);
        c.probe_hosts = std::move(doms);
    }
    if (c.probe_timeout_ms <= 0) c.probe_timeout_ms = 1500;
    if (c.monitor_probe_timeout_ms <= 0) c.monitor_probe_timeout_ms = 3000;
    if (c.degrade_fail_rounds <= 0) c.degrade_fail_rounds = 3;
    if (c.ewma_alpha <= 0.0 || c.ewma_alpha > 1.0) c.ewma_alpha = 0.3;

    impl_->engine = engine;
    impl_->stop_flag.store(false);
    impl_->mode = "selecting";
    impl_->th = std::thread(&Impl::run_loop, impl_.get());
    return true;
}

void PresetAutoPilot::stop() {
    impl_->stop_flag.store(true);
    if (impl_->th.joinable()) impl_->th.join();
}

bool PresetAutoPilot::running() const { return impl_->is_running.load(); }

DPI::DPIPreset PresetAutoPilot::current_preset() const {
    std::lock_guard<std::mutex> lk(impl_->m);
    return impl_->current;
}

std::string PresetAutoPilot::mode_string() const {
    std::lock_guard<std::mutex> lk(impl_->m);
    return impl_->mode;
}

std::string PresetAutoPilot::to_stats_json() const {
    std::lock_guard<std::mutex> lk(impl_->m);
    std::ostringstream j;
    j << "{\"enabled\":true"
      << ",\"mode\":\"" << pa_json_escape(impl_->mode) << "\""
      << ",\"current_preset\":\""
      << (impl_->current == DPI::DPIPreset::NONE
              ? "" : DPI::preset_to_string(impl_->current))
      << "\""
      << ",\"engine_preset_effective\":\""
      << pa_json_escape(impl_->engine_preset_effective) << "\""
      << ",\"ewma_rtt_ms\":" << impl_->ewma_rtt_ms
      << ",\"baseline_rtt_ms\":" << impl_->baseline_rtt_ms
      << ",\"consec_fail_rounds\":" << impl_->consec_fail_rounds
      << ",\"switches_total\":" << impl_->switches_total
      << ",\"last_switch_ts\":" << impl_->last_switch_ts
      << ",\"last_probe\":{\"host\":\"" << pa_json_escape(impl_->last_probe.domain)
      << "\",\"ok\":" << (impl_->last_probe.ok ? "true" : "false")
      << ",\"latency_ms\":" << impl_->last_probe.latency_ms
      << ",\"fail_reason\":\"" << pa_json_escape(impl_->last_probe.fail_reason)
      << "\"}";

    j << ",\"scores\":[";
    for (size_t i = 0; i < impl_->last_scores.size(); ++i) {
        const CandidateScore& s = impl_->last_scores[i];
        j << (i ? "," : "")
          << "{\"preset\":\"" << pa_json_escape(s.name) << "\""
          << ",\"success\":" << s.success_count
          << ",\"total\":" << s.total
          << ",\"avg_latency_ms\":" << s.avg_latency_ms
          << ",\"score\":" << s.score << "}";
    }
    j << "]";

    j << ",\"history\":[";
    // last <=16 events, newest last
    const size_t total = impl_->history.size();
    const size_t begin = total > 16 ? total - 16 : 0;
    for (size_t i = begin; i < total; ++i) {
        const SwitchEvent& ev = impl_->history[i];
        j << (i > begin ? "," : "")
          << "{\"ts\":" << ev.ts
          << ",\"from\":\"" << pa_json_escape(ev.from_preset) << "\""
          << ",\"to\":\"" << pa_json_escape(ev.to_preset) << "\""
          << ",\"reason\":\"" << pa_json_escape(ev.reason) << "\""
          << ",\"from_score\":" << ev.from_score
          << ",\"to_score\":" << ev.to_score << "}";
    }
    j << "]";

    j << ",\"note\":\"" << pa_json_escape(impl_->note) << "\"";
    j << "}";
    return j.str();
}

bool PresetAutoPilot::should_switch(long current_score, long challenger_score,
                                    double hysteresis_pct) {
    if (current_score <= 0) return challenger_score > 0;
    return challenger_score > current_score * (1.0 + hysteresis_pct / 100.0);
}

} // namespace ncp
