#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP PresetAutoPilot — preset-level auto-selection and hot-switching.
//
// Startup: probes candidate DPI presets via BlockChecker (temp local SOCKS5
// desync proxy per preset, TLS ClientHello on TCP/443 only) and hot-applies
// the winner through DPIBypass::update_config() — no engine restart.
// Monitor: periodic direct TLS/443 probes of reference hosts pass through the
// live system-wide interception (WinDivert/NFQUEUE), so they measure the
// currently applied preset. EWMA RTT + failure tracking; on degradation a
// re-selection runs and a better preset is hot-switched with cooldown,
// minimum dwell time and score hysteresis (anti-flap).
//
// Invariants (same as ncp_autopilot.hpp — do not break):
//   - ABI-STABLE header: no members behind build-flag #ifdefs.
//   - Single internal mutex; probing NEVER happens under the lock.
//   - Probing is TCP/443 TLS ClientHello only. No ICMP, no 53/80, no TUN.
//   - Opt-in: created only when auto mode requested (--auto / --preset auto).
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_dpi.hpp"
#include "ncp_blockcheck.hpp"
#include "ncp_geneva_ga.hpp"        // DPI::FitnessEvaluator, DPI::GenevaStrategy

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ncp {

// ─────────────────────────────────────────────────────────────────────────────
// IAutoEvolver — minimal online-evolution interface used by PresetAutoPilot
// v2 escalation level L3 (Geneva GA). Declared publicly so unit tests can
// inject a deterministic fake via Config::evolver_factory.
// Threading contract: set_on_new_best() callback fires from the evolver's own
// thread — implementations of the callback must only write under a mutex and
// set a pending flag (never call stop() from it). stop() is blocking and must
// NOT be called from the evolver's own callbacks.
// ─────────────────────────────────────────────────────────────────────────────
class IAutoEvolver {
public:
    virtual ~IAutoEvolver() = default;
    virtual bool start() = 0;          // запуск эволюции (false = не удалось)
    virtual void stop() = 0;           // блокирующая остановка; НЕ вызывать из его же коллбэков
    virtual bool running() const = 0;
    virtual uint32_t generation() const = 0;
    virtual double best_fitness() const = 0;      // шкала FitnessResult::score (0..1000)
    // Коллбэк на новую лучшую стратегию; вызывается ПОТОКОМ эволюционера —
    // внутри только запись под мьютекс + флаг pending (никаких stop()).
    virtual void set_on_new_best(std::function<void(const DPI::GenevaStrategy&)> cb) = 0;
};

class PresetAutoPilot {
public:
    struct CandidateScore {
        DPI::DPIPreset preset = DPI::DPIPreset::NONE;
        std::string name;            // preset_to_string
        int success_count = 0;
        int total = 0;
        double avg_latency_ms = 0.0;
        long score = 0;              // success*100000 - avg_latency (blockcheck formula)
    };

    struct SwitchEvent {
        int64_t ts = 0;              // unix time
        std::string from_preset;
        std::string to_preset;
        std::string reason;          // "startup-selection" | "degradation" | "reselection"
                                     // v2: | "escalation-l2" | "escalation-l3"
                                     //     | "geneva-best" | "de-escalation"
        long from_score = 0;
        long to_score = 0;
        int level = 1;               // v2: escalation level AFTER the event (0..3)
    };

    struct Config {
        // Candidates for selection (order preserved). Default: all named
        // presets except NONE/AUTOPROBE: tspu, beeline, mts, megafon, tele2,
        // mobile, runet_soft, runet_strong.
        std::vector<DPI::DPIPreset> candidates;
        size_t max_candidates = 6;               // cap after CLI --auto-candidates
        // Reference hosts for probes. Default: BlockChecker::default_domains()
        // trimmed to first 3 (startup) — full list configurable via CLI.
        std::vector<std::string> probe_hosts;
        int probe_timeout_ms = 1500;             // per-probe (startup selection)
        int monitor_interval_sec = 30;           // period between monitor rounds
        int monitor_probe_timeout_ms = 3000;
        // Degradation: N consecutive failed monitor rounds (round = failed if
        // >half of probe_hosts fail) OR ewma_rtt > degrade_rtt_factor * baseline.
        int degrade_fail_rounds = 3;
        double degrade_rtt_factor = 1.5;
        double ewma_alpha = 0.3;
        // Anti-flap:
        int switch_cooldown_sec = 120;           // min interval between switches
        int min_dwell_sec = 180;                 // min time on a preset before leaving it
        double hysteresis_pct = 10.0;            // new preset must score >= current*(1+h/100)
        bool use_doh = false;                    // mirror --doh for probing proxies
        // TEST HOOK: when set, replaces all network probing.
        // Args: (preset, host, timeout_ms) — is_direct probes pass preset=NONE.
        std::function<BlockcheckProbe(DPI::DPIPreset, const std::string&, int)> probe_fn;
        // TEST HOOK: when set, replaces the wall clock (unix seconds) used for
        // cooldown/dwell/anti-storm decisions and event timestamps.
        // Production default: time(nullptr).
        std::function<int64_t()> now_fn;

        // ── v2: эскалация на функции движка (SPEC AUTOPILOT_V2 §3) ──
        bool escalation_enabled = true;        // CLI --no-auto-escalate отключает (→ чистый v1)
        int escalation_cooldown_sec = 300;     // мин. интервал между входами на L2/L3
        int deescalate_direct_rounds = 3;      // direct здоров N раундов → де-эскалация
        long min_acceptable_score = 90000;     // порог «здоровья» (blockcheck-шкала: success*100000 - rtt)
        int augment_max_rungs = 6;             // cap rungs за эпизод L2

        // L3 (Geneva). Пустой host → "discord.com". Порт из строки host:port или 443.
        std::string geneva_target;             // CLI --geneva-target
        int geneva_population = 20;            // CLI --geneva-population
        int geneva_interval_sec = 60;          // CLI --geneva-interval (evolution interval, clamp >= 30)
        double geneva_mutation = 0.15;         // CLI --geneva-mutation
        // Продакшн: CLI передаёт ncp::cli::geneva_probe_fitness. nullptr → L3 недоступен.
        // (Тип — ncp::DPI::FitnessEvaluator из ncp_geneva_ga.hpp; в SPEC §3
        // указан как GenevaGA::FitnessEvaluator — это namespace-level alias.)
        DPI::FitnessEvaluator geneva_fitness = nullptr;
        // TEST HOOK: фабрика эволюционера. Когда задана — GenevaGA не создаётся,
        // используется фейк (deterministic unit tests, SPEC §8).
        std::function<std::unique_ptr<IAutoEvolver>()> evolver_factory;
    };

    PresetAutoPilot();
    ~PresetAutoPilot();                          // calls stop()

    PresetAutoPilot(const PresetAutoPilot&) = delete;
    PresetAutoPilot& operator=(const PresetAutoPilot&) = delete;

    // Start background thread. `engine` must outlive this object and is used
    // ONLY via get_config()/update_config()/interception_active() (all
    // mutex-protected inside DPIBypass). Non-owning.
    // Engine is expected to be already started with the fallback config.
    // TEST MODE: engine may be nullptr ONLY when cfg.probe_fn is set — then
    // no engine calls are made (selection decisions and state only).
    bool start(DPI::DPIBypass* engine, const Config& cfg);
    void stop();                                 // joins the thread; idempotent
    bool running() const;

    DPI::DPIPreset current_preset() const;       // NONE until first selection
    int current_level() const;                   // v2: 0 direct, 1 preset, 2 augmented, 3 geneva
    std::string mode_string() const;             // "selecting"|"monitoring"|"degraded"|"idle"

    // JSON fragment WITHOUT enclosing braces content wrappers — a full object:
    // {"enabled":true,"mode":"monitoring",...}  (see SPEC §7 for exact fields).
    std::string to_stats_json() const;

    // Decision logic, exposed for unit tests (no network, no thread needed):
    // returns true if `challenger` should replace `current` given hysteresis.
    static bool should_switch(long current_score, long challenger_score,
                              double hysteresis_pct);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ncp
