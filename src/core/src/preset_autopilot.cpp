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

// ── v2 escalation (SPEC AUTOPILOT_V2) ──────────────────────────────────────
const char* pa_level_name(int level) {
    switch (level) {
        case 0: return "direct";
        case 1: return "preset";
        case 2: return "augmented";
        case 3: return "geneva";
        default: return "unknown";
    }
}

// L2 augmentation rungs (SPEC §4) — fixed order, cheap → expensive.
constexpr int kNumRungs = 6;
const char* const kRungNames[kNumRungs] = {
    "fooling_badsum_badseq",  // R1
    "fake_repeats_4",         // R2
    "random_ttl",             // R3
    "midsld_split",           // R4
    "disorder_15",            // R5
    "reverse_frag",           // R6
};

void pa_apply_rung(int idx, DPI::DPIConfig& c) {
    switch (idx) {
        case 0:  // R1: badsum+badseq fooling on fake packets
            c.fake_fooling |= 1 | 2;
            c.enable_fake_packet = true;
            break;
        case 1:  // R2: repeat each fake packet 4 times
            c.fake_repeats = 4;
            break;
        case 2:  // R3: randomize fake TTL (autottl untouched — presets set it)
            c.randomize_fake_ttl = true;
            break;
        case 3:  // R4: midsld split + multi-layer split at {1} (+midsld)
            c.split_at_midsld = true;
            c.enable_multi_layer_split = true;
            c.split_positions = {1};
            break;
        case 4:  // R5: disorder with 15 ms delay
            c.enable_disorder = true;
            c.disorder_delay_ms = 15;
            break;
        case 5:  // R6: reverse fragment order
            c.enable_reverse_frag = true;
            break;
        default: break;
    }
}

// Production IAutoEvolver adapter over GenevaGA (SPEC §3/§5). Private to this
// translation unit; unit tests inject a fake via Config::evolver_factory.
class GenevaEvolver : public IAutoEvolver {
public:
    GenevaEvolver(const std::string& target, int population, int interval_sec,
                  double mutation, const DPI::FitnessEvaluator& fitness) {
        // host[:port]; empty host → discord.com; port from suffix or 443.
        std::string host = target.empty() ? "discord.com" : target;
        uint16_t port = 443;
        const size_t colon = host.find_last_of(':');
        if (colon != std::string::npos && host.find(':') == colon) {
            const std::string ps = host.substr(colon + 1);
            if (!ps.empty() && std::all_of(ps.begin(), ps.end(),
                    [](char ch) { return ch >= '0' && ch <= '9'; })) {
                host = host.substr(0, colon);
                port = static_cast<uint16_t>(std::stoi(ps) & 0xFFFF);
            }
        }
        DPI::GAConfig gc;
        gc.population_size = std::max<size_t>(
            4, std::min<size_t>(64, static_cast<size_t>(std::max(population, 0))));
        gc.evolution_interval_sec = std::max(30, interval_sec);   // clamp >= 30
        gc.mutation_rate = std::min(1.0, std::max(0.0, mutation));
        gc.fitness_timeout_ms = std::min(gc.fitness_timeout_ms, 3000);
        gc.seed_presets = true;
        ga_.set_config(gc);
        ga_.set_target(host, port);
        ga_.set_fitness_evaluator(fitness);
        // GA contract: callbacks must be registered before start(). The
        // callback fires from the GA thread — it only forwards to cb_, which
        // the autopilot sets to a mutex+flag writer (never stop()).
        ga_.on_new_best([this](const DPI::Individual& best) {
            std::function<void(const DPI::GenevaStrategy&)> cb;
            {
                std::lock_guard<std::mutex> lk(cb_m_);
                cb = cb_;
            }
            if (cb) cb(best.strategy);
        });
        ga_.initialize_population();
        ga_.inject_preset_strategies();
    }

    bool start() override { return ga_.start(); }
    void stop() override { ga_.stop(); }
    bool running() const override { return ga_.is_running(); }
    uint32_t generation() const override { return ga_.get_stats().current_generation; }
    double best_fitness() const override { return ga_.get_stats().best_fitness; }
    void set_on_new_best(std::function<void(const DPI::GenevaStrategy&)> cb) override {
        std::lock_guard<std::mutex> lk(cb_m_);
        cb_ = std::move(cb);
    }

private:
    DPI::GenevaGA ga_;
    std::mutex cb_m_;
    std::function<void(const DPI::GenevaStrategy&)> cb_;
};

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

    // ── v2 escalation state (under m unless noted) ──
    int level = 0;                          // 0 direct, 1 preset, 2 augmented, 3 geneva
    std::vector<std::string> active_features;  // applied L2 rungs (+ geneva marker)
    long live_score = 0;                    // score of the currently applied config
    int deescalate_ok_rounds = 0;           // consecutive rounds with healthy direct
    bool escalated_once = false;            // first L2/L3 entry is never cooldown-gated
    bool episode_active = false;            // escalation episode anti-reentrancy
    int64_t last_escalation_ts = 0;         // last entry into L2/L3
    std::unique_ptr<IAutoEvolver> evolver;  // L3 evolver; touched under m ONLY
                                            // (except stop(), see stop_evolver())
    bool geneva_ever_active = false;        // gates the "geneva" stats block
    bool geneva_pending = false;            // set by the evolver callback only
    DPI::GenevaStrategy geneva_pending_strategy;
    bool geneva_finished_noted = false;     // GA stopped on its own (target fitness)
    double geneva_applied_fitness = -1.0;   // <0: no geneva strategy applied yet
    // Cached evolver stats for to_stats_json() after the evolver is gone.
    uint32_t geneva_last_generation = 0;
    double geneva_last_best_fitness = 0.0;

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
    // v2: target_level is the escalation level after the switch (1 for a plain
    // preset win, 2 when the preset is the base of an L2 episode).
    void apply_winner(DPI::DPIPreset winner, const CandidateScore& ws,
                      const std::string& reason, long from_score,
                      int target_level = 1) {
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
        ev.level = target_level;
        history.push_back(std::move(ev));
        if (history.size() > 32) history.erase(history.begin());

        current = winner;
        level = target_level;
        engine_preset_effective = DPI::preset_to_string(winner);
        live_score = ws.score;
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

    // Quick connectivity check: succeed if ANY probe host answers.
    // A blocked/throttled reference host (exactly what this tool fights)
    // must not be mistaken for a dead network. Never under the lock.
    bool quick_connectivity_ok(BlockcheckProbe* last_out) {
        std::vector<std::string> hosts;
        {
            std::lock_guard<std::mutex> lk(m);
            hosts = cfg.probe_hosts;
        }
        for (const auto& h : hosts) {
            BlockcheckProbe q = direct_probe(h, kQuickProbeTimeoutMs);
            if (stop_flag.load()) return false;
            if (q.ok) return true;
            if (last_out) *last_out = q;
        }
        return false;
    }

    // ── STARTUP-SELECTION (SPEC §5.1) — runs once, no lock while probing ──
    void startup_phase() {
        {
            std::lock_guard<std::mutex> lk(m);
            if (cfg.probe_hosts.empty()) {
                mode = "monitoring";
                return;
            }
        }

        // 1. Quick connectivity check (any reachable host = network is up).
        BlockcheckProbe quick;
        if (!quick_connectivity_ok(&quick)) {
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

        // v2: presets exhausted (none reached the acceptability threshold) and
        // direct degraded too → escalation episode L1→L2(→L3). Direct healthy
        // means "no filtering" and stays L0 via the v1 direct-wins path below.
        if (cfg.escalation_enabled) {
            long min_acc;
            {
                std::lock_guard<std::mutex> lk(m);
                min_acc = cfg.min_acceptable_score;
            }
            const bool exhausted = !winner || winner->score < min_acc;
            const bool direct_ok =
                sel.direct_success > 0 && sel.direct_score >= min_acc;
            if (exhausted && !direct_ok &&
                run_escalation_episode(sel)) {
                std::lock_guard<std::mutex> lk(m);
                last_scores = sel.scores;
                return;
            }
        }

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

        // v2: presets exhausted on re-selection → escalation episode.
        {
            int lvl;
            long min_acc;
            bool evolver_alive;
            {
                std::lock_guard<std::mutex> lk(m);
                lvl = level;
                min_acc = cfg.min_acceptable_score;
                evolver_alive = (evolver != nullptr);
            }
            if (lvl >= 2 && evolver_alive) {
                // The L3 Geneva evolver is alive and keeps evolving — a second
                // episode must NOT start: it would downgrade L3→L2 without
                // restoring direct (SPEC §2) and would destroy the RUNNING
                // evolver under m (`evolver = std::move(ev)`), while the GA
                // thread's on_new_best callback waits on that same m → hard
                // deadlock. The only way down is direct recovery, handled by
                // escalated_round().
                std::lock_guard<std::mutex> lk(m);
                consec_fail_rounds = 0;
                if (mode == "degraded") mode = "monitoring";
                return;
            }
            if (cfg.escalation_enabled &&
                (!winner || winner->score < min_acc)) {
                const bool direct_ok =
                    sel.direct_success > 0 && sel.direct_score >= min_acc;
                if (!direct_ok && run_escalation_episode(sel)) return;
            }
            if (lvl >= 2) {
                // Beyond presets the only way down is direct recovery (handled
                // by escalated_round()); reset degradation tracking and stay.
                std::lock_guard<std::mutex> lk(m);
                consec_fail_rounds = 0;
                if (mode == "degraded") mode = "monitoring";
                return;
            }
        }

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

    // ═════════════════════════════════════════════════════════════════════
    // v2: escalation machinery (SPEC AUTOPILOT_V2 §4/§5)
    // ═════════════════════════════════════════════════════════════════════

    // Probe all reference hosts against the LIVE applied config and return a
    // blockcheck-scale score (success*100000 - avg_latency). Never under m.
    // hook_preset is passed to probe_fn in test mode so mocks can tell rung
    // probes (base preset) apart from direct probes (NONE).
    long probe_live_score(DPI::DPIPreset hook_preset) {
        std::vector<std::string> hosts;
        int timeout_ms;
        {
            std::lock_guard<std::mutex> lk(m);
            hosts = cfg.probe_hosts;
            timeout_ms = cfg.monitor_probe_timeout_ms;
        }
        if (hosts.empty()) return 0;

        std::vector<BlockcheckProbe> probes;
        probes.reserve(hosts.size());
        if (cfg.probe_fn) {
            for (const auto& h : hosts) {
                if (stop_flag.load()) return 0;
                probes.push_back(cfg.probe_fn(hook_preset, h, timeout_ms));
            }
        } else if (engine && engine->interception_active()) {
            for (const auto& h : hosts) {
                if (stop_flag.load()) return 0;
                probes.push_back(BlockChecker::probe_direct(h, timeout_ms));
            }
        } else if (engine) {
            // Passive/proxy mode: probe through a temp desync proxy carrying
            // the engine's live (augmented) config — same harness as the
            // v1 monitor round.
            DesyncProxy proxy;
            DesyncProxy::Config pcfg;
            pcfg.port = 0;
            pcfg.use_doh = cfg.use_doh;
            pcfg.base = engine->get_config();
            if (proxy.start(pcfg)) {
                const uint16_t port = proxy.bound_port();
                for (const auto& h : hosts) {
                    if (stop_flag.load()) break;
                    probes.push_back(BlockChecker::probe_via_socks5(port, h, timeout_ms));
                }
                proxy.stop();
            }
        } else {
            return 0;
        }
        int succ = 0;
        long lat_sum = 0;
        for (const auto& pr : probes)
            if (pr.ok) { succ++; lat_sum += pr.latency_ms; }
        const double avg = succ ? static_cast<double>(lat_sum) / succ : 0.0;
        return static_cast<long>(succ) * 100000L - static_cast<long>(avg);
    }

    // One direct (preset=NONE) probe round; healthy when a majority of hosts
    // answers. Used for the L2/L3 de-escalation check. Never under m.
    bool direct_round_healthy() {
        std::vector<std::string> hosts;
        int timeout_ms;
        {
            std::lock_guard<std::mutex> lk(m);
            hosts = cfg.probe_hosts;
            timeout_ms = cfg.monitor_probe_timeout_ms;
        }
        if (hosts.empty()) return false;
        int ok = 0;
        int total = 0;
        for (const auto& h : hosts) {
            if (stop_flag.load()) return false;
            BlockcheckProbe pr = direct_probe(h, timeout_ms);
            total++;
            if (pr.ok) ok++;
        }
        return ok > total / 2;
    }

    // Record a SwitchEvent. Caller holds m.
    void record_event_locked(const std::string& from, const std::string& to,
                             const std::string& reason, long from_score,
                             long to_score, int ev_level, int64_t ts) {
        SwitchEvent ev;
        ev.ts = ts;
        ev.from_preset = from;
        ev.to_preset = to;
        ev.reason = reason;
        ev.from_score = from_score;
        ev.to_score = to_score;
        ev.level = ev_level;
        history.push_back(std::move(ev));
        if (history.size() > 32) history.erase(history.begin());
    }

    // Move the evolver out (under m) and stop it (NOT under m — blocking join
    // of the GA thread; must never run while holding m because the GA
    // callback locks m, and never from a GA callback).
    void stop_evolver() {
        std::unique_ptr<IAutoEvolver> ev;
        {
            std::lock_guard<std::mutex> lk(m);
            if (evolver) {
                geneva_last_generation = evolver->generation();
                geneva_last_best_fitness = evolver->best_fitness();
            }
            ev = std::move(evolver);
            geneva_pending = false;
        }
        if (ev) ev->stop();
    }

    // De-escalation L2/L3 → L0: direct stayed healthy for
    // cfg.deescalate_direct_rounds consecutive monitor rounds. Stops the GA,
    // restores the AUTOPROBE fallback config (engine startup state), records
    // reason="de-escalation".
    void deescalate_to_direct() {
        stop_evolver();
        if (engine) {
            // Save/restore everything update_config() cannot hot-swap plus
            // the CLI modifiers (SPEC §11: mode/listen_port/hostlist/ipset/
            // ws_*/kill_switch stay untouched).
            const DPI::DPIConfig live = engine->get_config();
            DPI::DPIConfig fresh;
            DPI::apply_preset(DPI::DPIPreset::AUTOPROBE, fresh);
            fresh.hostlist_file = live.hostlist_file;
            fresh.hostlist_exclude_file = live.hostlist_exclude_file;
            fresh.ipset_file = live.ipset_file;
            fresh.quic_force_tcp = live.quic_force_tcp;
            fresh.quic_ipfrag_offset = live.quic_ipfrag_offset;
            fresh.mode = live.mode;
            fresh.listen_port = live.listen_port;
            fresh.nfqueue_num = live.nfqueue_num;
            fresh.kill_switch = live.kill_switch;
            fresh.kill_switch_allow_host = live.kill_switch_allow_host;
            fresh.kill_switch_allow_port = live.kill_switch_allow_port;
            fresh.ws_server_url = live.ws_server_url;
            fresh.ws_sni_override = live.ws_sni_override;
            fresh.ws_local_port = live.ws_local_port;
            fresh.ws_ping_interval_sec = live.ws_ping_interval_sec;
            fresh.ws_reconnect_delay_ms = live.ws_reconnect_delay_ms;
            fresh.ws_max_reconnect_attempts = live.ws_max_reconnect_attempts;
            if (!engine->update_config(fresh)) {
                std::lock_guard<std::mutex> lk(m);
                note = "apply-failed";   // retry on the next monitor round
                return;
            }
        }
        const int64_t ts = now();
        std::lock_guard<std::mutex> lk(m);
        record_event_locked(
            current == DPI::DPIPreset::NONE ? "Custom" : DPI::preset_to_string(current),
            "direct", "de-escalation", live_score, 0, /*level=*/0, ts);
        current = DPI::DPIPreset::NONE;
        level = 0;
        engine_preset_effective = "AutoProbe";
        active_features.clear();
        live_score = 0;
        deescalate_ok_rounds = 0;
        consec_fail_rounds = 0;
        last_round_all_failed = false;
        baseline_rtt_ms = 0.0;
        ewma_rtt_ms = 0.0;
        ewma_samples = 0;
        geneva_applied_fitness = -1.0;
        geneva_finished_noted = false;
        last_switch_ts = ts;
        switches_total++;
        note = "de-escalated:direct-healthy";
        mode = "monitoring";
    }

    // Apply a pending Geneva best strategy (set by the evolver callback) to
    // the live engine config via the core translator. Runs on the autopilot
    // thread, never in the GA callback (SPEC §5).
    void apply_geneva_pending() {
        DPI::GenevaStrategy strat;
        double fitness = -1.0;
        {
            std::lock_guard<std::mutex> lk(m);
            if (!geneva_pending) return;
            geneva_pending = false;
            strat = geneva_pending_strategy;
            if (evolver) fitness = evolver->best_fitness();
        }
        int skipped = 0;
        bool applied = true;
        if (engine) {
            // Base = the live engine config: hostlist/ipset/quic/mode/ws_*/
            // kill_switch are preserved automatically because the translator
            // only rewrites desync fields on top of `base`.
            DPI::DPIConfig nc = DPI::geneva_strategy_to_dpi_config(
                engine->get_config(), strat, &skipped);
            applied = engine->update_config(nc);
        }
        const int64_t ts = now();
        std::lock_guard<std::mutex> lk(m);
        if (!applied) {
            note = "geneva-apply-failed";
            return;
        }
        geneva_applied_fitness = fitness;
        record_event_locked(
            current == DPI::DPIPreset::NONE ? "Custom" : DPI::preset_to_string(current),
            "geneva", "geneva-best", live_score, 0, /*level=*/3, ts);
        last_switch_ts = ts;
        switches_total++;
        note = skipped > 0 ? "geneva-best-applied,skipped=" + std::to_string(skipped)
                           : "geneva-best-applied";
    }

    // Escalation episode L1→L2(→L3). Called when selection exhausted the
    // preset candidates (none reached cfg.min_acceptable_score) and direct is
    // not healthy either. Runs synchronously on the autopilot thread; probing
    // never under m. Returns true when the episode took over (level set).
    bool run_escalation_episode(const SelectionResult& sel) {
        int max_rungs;
        long min_acc;
        double hyst;
        {
            std::lock_guard<std::mutex> lk(m);
            if (!cfg.escalation_enabled || episode_active) return false;
            if (evolver) {
                // Safety net (the caller already guards this): never recycle
                // a live L3 evolver — destroying it here under m deadlocks
                // against its on_new_best callback, which locks m. Report
                // "took over" so callers do not fall through to L1 switching.
                return true;
            }
            if (escalated_once) {
                // Anti-flap (SPEC §2): min interval between L2/L3 entries,
                // and no upward move inside the plain switch cooldown.
                const int64_t t = now();
                if (t - last_escalation_ts < cfg.escalation_cooldown_sec ||
                    t - last_switch_ts < cfg.switch_cooldown_sec) {
                    note = "escalation-cooldown";
                    return false;
                }
            }
            episode_active = true;
            max_rungs = cfg.augment_max_rungs;
            min_acc = cfg.min_acceptable_score;
            hyst = cfg.hysteresis_pct;
        }
        struct EpisodeGuard {
            std::mutex& mx; bool& flag;
            ~EpisodeGuard() { std::lock_guard<std::mutex> lk(mx); flag = false; }
        } guard{m, episode_active};

        // Base preset: the highest-scoring candidate even below the threshold
        // (L2 = best preset + augmentations); fall back to the current preset
        // or the first candidate when no scores exist at all.
        DPI::DPIPreset base = DPI::DPIPreset::NONE;
        CandidateScore base_cs;
        const CandidateScore* best_any = nullptr;
        for (const auto& s : sel.scores)
            if (!best_any || s.score > best_any->score) best_any = &s;
        if (best_any) {
            base = best_any->preset;
            base_cs = *best_any;
        } else {
            std::lock_guard<std::mutex> lk(m);
            base = current != DPI::DPIPreset::NONE ? current
                     : (cfg.candidates.empty() ? DPI::DPIPreset::NONE
                                               : cfg.candidates.front());
            if (base == DPI::DPIPreset::NONE) {
                note = "escalation-no-base";
                return false;
            }
            base_cs.preset = base;
            base_cs.name = DPI::preset_to_string(base);
        }

        // ── L2: apply the base preset (event reason="escalation-l2") ──
        apply_winner(base, base_cs, "escalation-l2", 0, /*target_level=*/2);
        {
            std::lock_guard<std::mutex> lk(m);
            if (note == "apply-failed") return true;  // engine rejected; stay
            active_features.clear();
            live_score = base_cs.score;
            last_escalation_ts = now();
            escalated_once = true;
            deescalate_ok_rounds = 0;
            geneva_applied_fitness = -1.0;
            note = "presets-exhausted";
        }

        // Working config: the engine's live config (post apply_winner) or a
        // virtual one in test mode (engine==nullptr, probe_fn set).
        DPI::DPIConfig working;
        if (engine) {
            working = engine->get_config();
        } else {
            working = DPI::DPIConfig();
            DPI::apply_preset(base, working);
        }

        // Rungs R1..R6 (capped by augment_max_rungs): mutate → probe →
        // keep on improvement / revert otherwise.
        const int n_rungs = std::min(kNumRungs, std::max(max_rungs, 0));
        for (int r = 0; r < n_rungs; ++r) {
            if (stop_flag.load()) return true;
            DPI::DPIConfig mutated = working;
            pa_apply_rung(r, mutated);
            if (engine && !engine->update_config(mutated))
                continue;  // rejected: counts as a failed rung, keep `working`
            const long sc = probe_live_score(base);
            if (stop_flag.load()) return true;
            long cur_score;
            { std::lock_guard<std::mutex> lk(m); cur_score = live_score; }
            // Keep on a strict improvement (hysteresis-scaled) or on reaching
            // the acceptability threshold. With cur<=0 any positive score is
            // an improvement; a failed probe round (0 vs 0) reverts the rung.
            const bool keep =
                sc >= min_acc ||
                (cur_score > 0
                     ? sc >= static_cast<long>(cur_score * (1.0 + hyst / 100.0))
                     : sc > 0);
            if (keep) {
                working = mutated;
                std::lock_guard<std::mutex> lk(m);
                active_features.push_back(kRungNames[r]);
                live_score = sc;
            } else if (engine) {
                engine->update_config(working);  // revert rung
            }
            {
                std::lock_guard<std::mutex> lk(m);
                if (live_score >= min_acc) {
                    // L2 success: settle in MONITORING on the augmented config.
                    note = "l2-ok";
                    mode = "monitoring";
                    return true;
                }
            }
        }

        // ── L3: Geneva GA evolution (SPEC §5) ──
        bool have_factory;
        bool have_fitness;
        {
            std::lock_guard<std::mutex> lk(m);
            have_factory = static_cast<bool>(cfg.evolver_factory);
            have_fitness = static_cast<bool>(cfg.geneva_fitness);
        }
        if (!have_factory && !have_fitness) {
            std::lock_guard<std::mutex> lk(m);
            note = "geneva-unavailable";   // stay on the best L2 config found
            mode = "monitoring";
            return true;
        }

        // Do not start a GA when stop() was requested mid-episode.
        if (stop_flag.load()) return true;

        std::unique_ptr<IAutoEvolver> ev;
        if (have_factory) {
            // Copy the factory under m, invoke it WITHOUT the lock: a test
            // factory may call back into autopilot-observable state and no
            // autopilot state is touched by the construction itself.
            std::function<std::unique_ptr<IAutoEvolver>()> factory;
            {
                std::lock_guard<std::mutex> lk(m);
                factory = cfg.evolver_factory;
            }
            if (factory) ev = factory();
        } else {
            // Production adapter: GenevaGA + real fitness probes (TLS/443 to
            // geneva_target only — SPEC §11).
            std::string target;
            int population, interval;
            double mutation;
            DPI::FitnessEvaluator fitness;
            {
                std::lock_guard<std::mutex> lk(m);
                target = cfg.geneva_target;
                population = cfg.geneva_population;
                interval = cfg.geneva_interval_sec;
                mutation = cfg.geneva_mutation;
                fitness = cfg.geneva_fitness;
            }
            try {
                ev = std::make_unique<GenevaEvolver>(target, population, interval,
                                                     mutation, fitness);
            } catch (...) {
                ev.reset();
            }
        }
        if (!ev) {
            std::lock_guard<std::mutex> lk(m);
            note = "geneva-start-failed";
            mode = "monitoring";
            return true;
        }
        // Pending-slot callback: the evolver thread may ONLY write under m +
        // set the flag (SPEC §11). No stop(), no update_config() here.
        ev->set_on_new_best([this](const DPI::GenevaStrategy& s) {
            std::lock_guard<std::mutex> lk(m);
            geneva_pending_strategy = s;
            geneva_pending = true;
        });
        if (!ev->start()) {
            std::lock_guard<std::mutex> lk(m);
            note = "geneva-start-failed";
            mode = "monitoring";
            return true;
        }
        const int64_t ts = now();
        {
            std::lock_guard<std::mutex> lk(m);
            evolver = std::move(ev);
            level = 3;
            geneva_ever_active = true;
            mode = "monitoring";
            note = "geneva-evolving";
            record_event_locked(DPI::preset_to_string(base), "geneva",
                                "escalation-l3", live_score, 0, /*level=*/3, ts);
            last_switch_ts = ts;
            switches_total++;
        }
        return true;
    }

    // One monitor-round step while escalated (L2/L3): direct-recovery
    // de-escalation check, GA-finished detection and pending Geneva apply.
    // Returns true when a de-escalation to L0 happened (skip degradation
    // handling for this round).
    bool escalated_round() {
        const bool healthy = direct_round_healthy();
        int lvl;
        bool need_deesc;
        {
            std::lock_guard<std::mutex> lk(m);
            deescalate_ok_rounds = healthy ? deescalate_ok_rounds + 1 : 0;
            need_deesc = deescalate_ok_rounds >= cfg.deescalate_direct_rounds;
            lvl = level;
        }
        if (need_deesc) {
            deescalate_to_direct();
            return true;
        }
        if (lvl == 3) {
            {
                std::lock_guard<std::mutex> lk(m);
                if (evolver && !evolver->running() && !geneva_finished_noted) {
                    // GA stopped on its own (target fitness reached): keep the
                    // last applied best, just note it (SPEC §5.4).
                    geneva_finished_noted = true;
                    note = "geneva-finished";
                }
            }
            apply_geneva_pending();
        }
        return false;
    }

    // ── Main loop (SPEC §4) ──
    // Exception safety: this thread MUST never let an exception escape — an
    // uncaught throw in a std::thread is std::terminate and kills the whole
    // process. Per-iteration catch keeps the loop alive through transient
    // failures (e.g. bad_alloc inside a probe round); the outer catch-all is
    // the last line of defence and stops the background thread.
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

        // Do NOT clobber `mode` with "idle" on thread exit: operators (and
        // to_stats_json()) must keep seeing the last operational state
        // ("monitoring"/"degraded"/...). "idle" remains the initial value
        // for a never-started autopilot only.
        is_running.store(false);
    }

    // One iteration of the main loop (sleep → probe round → degradation
    // handling). May throw; run_loop() contains it per-iteration.
    void monitor_iteration() {
        int interval;
        bool net_down;
        int lvl;
        {
            std::lock_guard<std::mutex> lk(m);
            net_down = (mode == "degraded-net");
            lvl = level;
            interval = net_down ? kDegradedNetIntervalSec
                                : cfg.monitor_interval_sec;
        }
        if (!cfg.probe_fn && interval < 1) interval = 1;
        // v2: while escalated (L2/L3) floor the round cadence at 1 s even in
        // test busy-loop configs — the de-escalation check needs *consecutive
        // rounds*, and a hot loop would burn all of them (plus probe traffic)
        // in microseconds, making the escalated state unobservable.
        if (lvl >= 2 && interval < 1) interval = 1;
        interruptible_sleep(interval);
        if (stop_flag.load()) return;

        if (net_down) {
            // Network was dead at startup: cheap re-check every 60 s;
            // when it comes back (any probe host answers), run the
            // selection for real.
            {
                std::lock_guard<std::mutex> lk(m);
                if (cfg.probe_hosts.empty()) return;
            }
            BlockcheckProbe q;
            if (quick_connectivity_ok(&q)) {
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

        // v2: on L2/L3 each monitor round additionally probes direct for the
        // de-escalation check and (L3) applies pending Geneva winners.
        {
            int lvl;
            {
                std::lock_guard<std::mutex> lk(m);
                lvl = level;
            }
            if (lvl >= 2 && escalated_round()) return;  // de-escalated to L0
        }

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
    // v2 escalation sanitization (0 rounds would de-escalate instantly).
    if (c.deescalate_direct_rounds <= 0) c.deescalate_direct_rounds = 3;
    if (c.escalation_cooldown_sec < 0) c.escalation_cooldown_sec = 300;

    impl_->engine = engine;
    impl_->stop_flag.store(false);
    impl_->mode = "selecting";
    impl_->th = std::thread(&Impl::run_loop, impl_.get());
    return true;
}

void PresetAutoPilot::stop() {
    impl_->stop_flag.store(true);
    // v2 (SPEC §11): stop the evolver BEFORE joining the autopilot thread and
    // never while holding m (the GA callback locks m). Moving the pointer out
    // under m makes the monitor thread see nullptr on its next check.
    impl_->stop_evolver();
    if (impl_->th.joinable()) impl_->th.join();
}

bool PresetAutoPilot::running() const { return impl_->is_running.load(); }

int PresetAutoPilot::current_level() const {
    std::lock_guard<std::mutex> lk(impl_->m);
    return impl_->level;
}

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
          << ",\"to_score\":" << ev.to_score
          << ",\"level\":" << ev.level << "}";
    }
    j << "]";

    j << ",\"note\":\"" << pa_json_escape(impl_->note) << "\"";

    // ── v2 escalation fields (SPEC §3) ──
    j << ",\"level\":" << impl_->level
      << ",\"level_name\":\"" << pa_level_name(impl_->level) << "\""
      << ",\"active_features\":[";
    for (size_t i = 0; i < impl_->active_features.size(); ++i)
        j << (i ? "," : "") << "\"" << pa_json_escape(impl_->active_features[i]) << "\"";
    if (impl_->level == 3 && impl_->geneva_applied_fitness >= 0.0)
        j << (impl_->active_features.empty() ? "" : ",")
          << "\"geneva:best=" << impl_->geneva_applied_fitness << "\"";
    j << "]";
    if (impl_->geneva_ever_active) {
        bool running = false;
        uint32_t gen = impl_->geneva_last_generation;
        double best = impl_->geneva_last_best_fitness;
        if (impl_->evolver) {
            running = impl_->evolver->running();
            gen = impl_->evolver->generation();
            best = impl_->evolver->best_fitness();
        }
        j << ",\"geneva\":{\"running\":" << (running ? "true" : "false")
          << ",\"generation\":" << gen
          << ",\"best_fitness\":" << best << "}";
    }
    j << "}";
    return j.str();
}

bool PresetAutoPilot::should_switch(long current_score, long challenger_score,
                                    double hysteresis_pct) {
    if (current_score <= 0) return challenger_score > 0;
    return challenger_score > current_score * (1.0 + hysteresis_pct / 100.0);
}

} // namespace ncp
