// ═══════════════════════════════════════════════════════════════════════════
// NCP MimicryAutoPilot / ConnectionDirector — implementation.
// See ncp_mimicry_autopilot.hpp for the contract. No threads, no network,
// no nDPI, no global strategy application — deterministic evaluate() only.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_mimicry_autopilot.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <deque>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

namespace ncp {

namespace {

int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool provided(double v) { return !std::isnan(v); }

double clamp01(double v) { return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v); }

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string canonical_of(const std::string& id, uint32_t rev) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u", rev);
    return id + "@" + buf;
}

const char* mode_string(MimicryAutoPilot::Mode m) {
    switch (m) {
        case MimicryAutoPilot::Mode::DISABLED: return "disabled";
        case MimicryAutoPilot::Mode::MANUAL: return "manual";
        case MimicryAutoPilot::Mode::AUTO: return "auto";
        case MimicryAutoPilot::Mode::LOCKED: return "locked";
        case MimicryAutoPilot::Mode::FALLBACK_ONLY: return "fallback_only";
    }
    return "unknown";
}

const char* state_string(MimicryAutoPilot::State s) {
    switch (s) {
        case MimicryAutoPilot::State::DISABLED: return "disabled";
        case MimicryAutoPilot::State::SELECTING: return "selecting";
        case MimicryAutoPilot::State::MONITORING: return "monitoring";
        case MimicryAutoPilot::State::WAITING_TRANSITION: return "waiting_transition";
        case MimicryAutoPilot::State::DEGRADED: return "degraded";
    }
    return "unknown";
}

} // namespace

struct MimicryAutoPilot::Impl {
    using Cancel = std::pair<std::string, uint32_t>;

    struct Candidate {
        std::string profile_id;
        uint32_t revision = 0;
        std::string canonical;  // "profile_id@revision"
        double score = 0.0;
    };

    struct Outstanding {
        std::string profile_id;
        uint32_t revision = 0;
        int64_t deadline_ms = 0;
        std::string reason;
    };

    explicit Impl(Config c) : cfg(std::move(c)) {
        // Sanity clamps (deterministic behaviour even for odd configs).
        if (cfg.max_candidates == 0) cfg.max_candidates = 1;
        if (cfg.max_switch_events == 0) cfg.max_switch_events = 1;
        if (cfg.ewma_alpha <= 0.0 || cfg.ewma_alpha > 1.0) cfg.ewma_alpha = 0.3;
        if (cfg.failure_threshold == 0) cfg.failure_threshold = 1;
        if (cfg.cooldown_ms < 0) cfg.cooldown_ms = 0;
        if (cfg.min_dwell_ms < 0) cfg.min_dwell_ms = 0;
        if (cfg.min_request_interval_ms < 0) cfg.min_request_interval_ms = 0;
        if (cfg.transition_timeout_ms <= 0) cfg.transition_timeout_ms = 5000;
        if (cfg.busy_retry_ms < 0) cfg.busy_retry_ms = 0;
        if (cfg.min_availability < 0.0 || cfg.min_availability > 1.0)
            cfg.min_availability = 0.5;
        if (cfg.goodput_ref_bps <= 0.0) cfg.goodput_ref_bps = 1.0;
        mode = cfg.mode;
        legacy_peer = !cfg.peer_supports_profiles;
        if (!transitions_enabled())
            state = State::DISABLED;
        else
            state = State::SELECTING;  // initial selection pending
    }

    bool transitions_enabled() const {
        return cfg.enabled && mode != Mode::DISABLED && !legacy_peer &&
               static_cast<bool>(cfg.request_transition);
    }

    int64_t now() const { return cfg.now_fn ? cfg.now_fn() : steady_now_ms(); }

    // ---- health ----

    static bool metrics_valid(const UdpMetrics& m) {
        bool any = false;
        const double vals[4] = {m.rtt_ms, m.loss_ratio, m.jitter_ms, m.throughput_bps};
        for (double v : vals) {
            if (!provided(v)) continue;
            any = true;
            if (!std::isfinite(v)) return false;
        }
        if (!any) return false;  // empty sample carries no information
        if (provided(m.loss_ratio) && (m.loss_ratio < 0.0 || m.loss_ratio > 1.0))
            return false;
        if (provided(m.rtt_ms) && m.rtt_ms < 0.0) return false;
        if (provided(m.jitter_ms) && m.jitter_ms < 0.0) return false;
        if (provided(m.throughput_bps) && m.throughput_bps < 0.0) return false;
        return true;
    }

    double sample_health(const UdpMetrics& m) const {
        double penalty = 0.0;
        if (provided(m.loss_ratio)) penalty += cfg.w_loss * clamp01(m.loss_ratio);
        if (provided(m.rtt_ms) && cfg.rtt_ref_ms > 0.0)
            penalty += cfg.w_rtt * clamp01(m.rtt_ms / cfg.rtt_ref_ms);
        if (provided(m.jitter_ms) && cfg.jitter_ref_ms > 0.0)
            penalty += cfg.w_jitter * clamp01(m.jitter_ms / cfg.jitter_ref_ms);
        if (provided(m.throughput_bps) && cfg.throughput_floor_bps > 0.0 &&
            m.throughput_bps < cfg.throughput_floor_bps)
            penalty += cfg.w_throughput *
                       clamp01(1.0 - m.throughput_bps / cfg.throughput_floor_bps);
        return clamp01(1.0 - penalty);
    }

    /// Degradation trigger: live-health streak OR offline-evidence streak.
    bool unhealthy() const {
        return consecutive_unhealthy >= cfg.failure_threshold ||
               evidence_blocked_streak >= cfg.failure_threshold;
    }

    // ---- gates ----

    /// Anti-storm floor: minimum interval between transition REQUESTS.
    /// Never bypassed, not even for a dead current profile.
    bool floor_ok(int64_t now_ms) const {
        return !ever_requested ||
               (now_ms - last_request_ms) >= cfg.min_request_interval_ms;
    }
    bool cooldown_ok(int64_t now_ms) const {
        return !ever_committed ||
               (now_ms - last_switch_ms) >= cfg.cooldown_ms;
    }
    bool dwell_ok(int64_t now_ms) const {
        return !has_active || (now_ms - active_since_ms) >= cfg.min_dwell_ms;
    }

    // ---- scoring / candidates (catalog used READ-ONLY) ----

    double base_score(const ProfileDescriptor& d) const {
        return cfg.candidate_score_fn ? cfg.candidate_score_fn(d) : 1.0;
    }

    /// Base score + injected evidence terms. When check_gates is true a
    /// failed hard gate (or evidence_fn returning false) yields ok=false.
    double full_score(const ProfileDescriptor& d, bool check_gates, bool& ok) const {
        ok = true;
        double s = base_score(d);
        if (!std::isfinite(s) || s < 0.0) {
            ok = false;
            return 0.0;
        }
        if (cfg.candidate_evidence_fn) {
            CandidateEvidence ev;
            if (!cfg.candidate_evidence_fn(d, ev)) {
                ok = false;
                return 0.0;
            }
            if (check_gates &&
                !(ev.encode_supported && ev.decode_supported &&
                  ev.handshake_compatible && ev.rehearsal_passed &&
                  ev.mtu_compatible && ev.transition_compatible)) {
                ok = false;
                return 0.0;
            }
            if (provided(ev.goodput_bps))
                s += cfg.w_goodput * (ev.goodput_bps / cfg.goodput_ref_bps);
            if (provided(ev.overhead_ratio))
                s -= cfg.w_overhead * clamp01(ev.overhead_ratio);
            if (provided(ev.stability)) s += cfg.w_stability * clamp01(ev.stability);
            if (provided(ev.switch_cost) && ev.switch_cost > 0.0)
                s -= cfg.w_switch_cost * ev.switch_cost;
        }
        if (!std::isfinite(s) || s < 0.0) {
            ok = false;
            return 0.0;
        }
        return s;
    }

    /// Score of the current active profile for hysteresis comparison;
    /// -1 when it is no longer present in the catalog.
    double current_score() const {
        if (!has_active || !cfg.catalog) return -1.0;
        const ProfileDescriptor* cur = cfg.catalog->find(active_id, active_rev);
        if (!cur) return -1.0;
        bool ok = false;
        const double s = full_score(*cur, /*check_gates=*/false, ok);
        return ok ? s : -1.0;
    }

    bool capability_covered(const ProfileDescriptor& d) const {
        for (const auto& req : d.required_capabilities)
            if (std::find(cfg.local_capabilities.begin(), cfg.local_capabilities.end(),
                          req) == cfg.local_capabilities.end())
                return false;
        return true;
    }

    bool family_eligible(ProtocolFamily f) const {
        if (cfg.eligible_families.empty()) return true;
        return std::find(cfg.eligible_families.begin(), cfg.eligible_families.end(), f) !=
               cfg.eligible_families.end();
    }

    std::vector<Candidate> gather_candidates() {
        std::vector<Candidate> out;
        if (!cfg.catalog) return out;

        std::vector<std::string> canonical_ids;
        if (cfg.eligible_families.empty()) {
            canonical_ids = cfg.catalog->list();
        } else {
            for (ProtocolFamily f : cfg.eligible_families) {
                auto part = cfg.catalog->list_by_family(f);
                canonical_ids.insert(canonical_ids.end(), part.begin(), part.end());
            }
            std::sort(canonical_ids.begin(), canonical_ids.end());
            canonical_ids.erase(
                std::unique(canonical_ids.begin(), canonical_ids.end()),
                canonical_ids.end());
        }

        for (const auto& cid : canonical_ids) {
            const size_t at = cid.rfind('@');
            if (at == std::string::npos || at + 1 >= cid.size()) continue;
            uint32_t rev = 0;
            try {
                rev = static_cast<uint32_t>(std::stoul(cid.substr(at + 1)));
            } catch (...) {
                continue;
            }
            const std::string pid = cid.substr(0, at);
            if (excluded.count(cid)) continue;
            if (std::find(cfg.exclude_profile_ids.begin(), cfg.exclude_profile_ids.end(),
                          pid) != cfg.exclude_profile_ids.end())
                continue;
            const ProfileDescriptor* d = cfg.catalog->find(pid, rev);
            if (!d) continue;
            if (!d->is_wire_compatible(cfg.wire_version)) continue;
            if (!family_eligible(d->family)) continue;
            if (!capability_covered(*d)) continue;
            bool ok = false;
            const double s = full_score(*d, /*check_gates=*/true, ok);
            if (!ok) continue;
            out.push_back(Candidate{pid, rev, cid, s});
        }

        std::stable_sort(out.begin(), out.end(),
                         [](const Candidate& a, const Candidate& b) {
                             if (a.score != b.score) return a.score > b.score;
                             return a.canonical < b.canonical;
                         });
        if (out.size() > cfg.max_candidates) out.resize(cfg.max_candidates);
        last_candidates_considered = out.size();
        last_candidates = out;  // bounded by max_candidates; used for stats
        return out;
    }

    // ---- state helpers ----

    void enter_degraded(int64_t now_ms) {
        state = State::DEGRADED;
        degraded_retry_at_ms = now_ms + cfg.cooldown_ms;
    }

    void fail_maybe_degraded(int64_t now_ms) {
        if (request_failures >= cfg.failure_threshold)
            enter_degraded(now_ms);
        else if (state != State::DEGRADED)
            state = State::SELECTING;
    }

    void record_event(int64_t now_ms, const std::string& from, const std::string& to,
                      const std::string& reason) {
        history.push_back(SwitchEvent{now_ms, from, to, reason});
        while (history.size() > cfg.max_switch_events) history.pop_front();
    }

    Config cfg;
    mutable std::mutex mu;
    bool issuing = false;  // reentrancy / single-outstanding guard

    Mode mode = Mode::AUTO;
    State state = State::DISABLED;
    bool legacy_peer = false;

    bool has_active = false;
    std::string active_id;
    uint32_t active_rev = 0;
    int64_t active_since_ms = 0;
    int64_t last_switch_ms = 0;
    bool ever_committed = false;

    bool has_prev_stable = false;
    std::string prev_stable_id;
    uint32_t prev_stable_rev = 0;

    bool manual_lock = false;
    std::string manual_id;
    uint32_t manual_rev = 0;
    bool rollback_pending = false;

    double ewma_health = 1.0;
    uint32_t consecutive_unhealthy = 0;
    uint32_t evidence_blocked_streak = 0;

    std::set<std::string> excluded;  // canonical ids rejected by the director
    uint32_t request_failures = 0;
    int64_t degraded_retry_at_ms = 0;
    int64_t busy_until_ms = 0;
    int64_t last_request_ms = 0;
    bool ever_requested = false;

    bool has_outstanding = false;
    Outstanding outstanding;

    size_t last_candidates_considered = 0;
    std::vector<Candidate> last_candidates;  // bounded (max_candidates)

    std::deque<SwitchEvent> history;  // bounded (max_switch_events)
    std::string last_reason;

    bool has_availability = false;
    uint32_t avail_reachable = 0;
    uint32_t avail_total = 0;
    bool has_dpi_evidence = false;
    OfflineDpiEvidence last_evidence;

    uint64_t c_requests = 0;
    uint64_t c_commits = 0;
    uint64_t c_aborts = 0;
    uint64_t c_busy = 0;
    uint64_t c_disabled = 0;
    uint64_t c_rejected = 0;  // NOT_SUPPORTED + INVALID_PROFILE
    uint64_t c_timeouts = 0;
    uint64_t c_cancels = 0;
    uint64_t c_rollbacks = 0;
    uint64_t c_switches = 0;
    uint64_t c_malformed = 0;
    uint64_t c_samples = 0;
    uint64_t c_selections = 0;
};

// ═══════════════════════════════════════════════════════════════════════════

MimicryAutoPilot::MimicryAutoPilot(Config cfg) : impl_(new Impl(std::move(cfg))) {}
MimicryAutoPilot::~MimicryAutoPilot() { delete impl_; }

bool MimicryAutoPilot::should_switch(double current_score, double challenger_score,
                                     double hysteresis_pct) {
    if (!std::isfinite(challenger_score) || challenger_score < 0.0) return false;
    if (!std::isfinite(current_score) || current_score < 0.0) return true;
    const double margin = current_score * (hysteresis_pct / 100.0);
    return challenger_score > current_score + margin + 1e-9;
}

// ---- inputs ----

bool MimicryAutoPilot::ingest_metrics(const UdpMetrics& m) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (!Impl::metrics_valid(m)) {
        ++impl_->c_malformed;
        return false;
    }
    ++impl_->c_samples;
    const double h = impl_->sample_health(m);
    impl_->ewma_health =
        impl_->cfg.ewma_alpha * h + (1.0 - impl_->cfg.ewma_alpha) * impl_->ewma_health;
    if (h < impl_->cfg.health_floor)
        ++impl_->consecutive_unhealthy;
    else
        impl_->consecutive_unhealthy = 0;
    return true;
}

void MimicryAutoPilot::report_success() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->consecutive_unhealthy = 0;
    impl_->ewma_health = impl_->cfg.ewma_alpha * 1.0 +
                         (1.0 - impl_->cfg.ewma_alpha) * impl_->ewma_health;
}

void MimicryAutoPilot::report_degradation() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    ++impl_->consecutive_unhealthy;
}

bool MimicryAutoPilot::ingest_reference_availability(uint32_t reachable,
                                                     uint32_t total) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (total == 0 || reachable > total) {
        ++impl_->c_malformed;
        return false;
    }
    impl_->has_availability = true;
    impl_->avail_reachable = reachable;
    impl_->avail_total = total;
    const double frac = static_cast<double>(reachable) / static_cast<double>(total);
    if (frac >= impl_->cfg.min_availability)
        impl_->consecutive_unhealthy = 0;
    else
        ++impl_->consecutive_unhealthy;
    return true;
}

void MimicryAutoPilot::ingest_offline_dpi_evidence(const OfflineDpiEvidence& e) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->has_dpi_evidence = true;
    impl_->last_evidence = e;
    // OFFLINE verdict: never touches ewma_health (live health).
    if (e.blocked)
        ++impl_->evidence_blocked_streak;
    else
        impl_->evidence_blocked_streak = 0;
}

// ---- decision tick ----

void MimicryAutoPilot::evaluate() {
    std::vector<Impl::Cancel> cancels;
    Impl::Candidate chosen;
    std::string reason;
    bool do_request = false;

    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        Impl& im = *impl_;
        if (im.issuing) return;  // reentrant call from a callback: ignore

        if (!im.transitions_enabled()) {
            im.state = State::DISABLED;
            return;
        }
        const int64_t now = im.now();
        if (im.state == State::DISABLED)
            im.state = im.has_active ? State::MONITORING : State::SELECTING;

        // Outstanding request timeout: implicit abort (+ cancellation hook).
        if (im.has_outstanding && now >= im.outstanding.deadline_ms) {
            cancels.push_back({im.outstanding.profile_id, im.outstanding.revision});
            im.has_outstanding = false;
            ++im.c_timeouts;
            ++im.request_failures;
            im.fail_maybe_degraded(now);
        }
        if (im.has_outstanding) {
            im.state = State::WAITING_TRANSITION;
            return;  // one outstanding request at a time
        }

        // Recovery: degraded but the active profile looks healthy again.
        if (im.state == State::DEGRADED && im.has_active && !im.unhealthy() &&
            im.ewma_health >= im.cfg.health_floor)
            im.state = State::MONITORING;

        // 1) Operator-pinned manual profile takes priority.
        if (im.manual_lock &&
            (!im.has_active || im.active_id != im.manual_id ||
             im.active_rev != im.manual_rev)) {
            const ProfileDescriptor* d =
                im.cfg.catalog ? im.cfg.catalog->find(im.manual_id, im.manual_rev)
                               : nullptr;
            if (!d) {
                im.manual_lock = false;  // pinned profile vanished: drop the lock
                im.rollback_pending = false;
                ++im.c_rejected;
                ++im.request_failures;
                im.last_reason = "manual-profile-missing";
                im.fail_maybe_degraded(now);
            } else if (im.floor_ok(now)) {  // anti-storm floor still applies
                chosen = Impl::Candidate{im.manual_id, im.manual_rev,
                                         canonical_of(im.manual_id, im.manual_rev),
                                         0.0};
                bool ok = false;
                chosen.score = im.full_score(*d, /*check_gates=*/false, ok);
                reason = "manual";
                do_request = true;
            } else {
                im.state = State::SELECTING;
            }
        }
        // 2) Rollback to the previous stable profile (via a real request).
        else if (im.rollback_pending) {
            const ProfileDescriptor* d =
                (im.has_prev_stable && im.cfg.catalog)
                    ? im.cfg.catalog->find(im.prev_stable_id, im.prev_stable_rev)
                    : nullptr;
            if (!d) {
                im.rollback_pending = false;
                ++im.c_rejected;
                ++im.request_failures;
                im.last_reason = "rollback-unavailable";
                im.fail_maybe_degraded(now);
            } else if (im.floor_ok(now)) {
                chosen = Impl::Candidate{
                    im.prev_stable_id, im.prev_stable_rev,
                    canonical_of(im.prev_stable_id, im.prev_stable_rev), 0.0};
                bool ok = false;
                chosen.score = im.full_score(*d, /*check_gates=*/false, ok);
                reason = "rollback";
                do_request = true;
            } else {
                im.state = State::SELECTING;
            }
        }
        // 3) Automatic selection (AUTO: fallback + improvement; FALLBACK_ONLY:
        //    fallback only. LOCKED/MANUAL never reach here.)
        else if (im.mode == Mode::AUTO || im.mode == Mode::FALLBACK_ONLY) {
            const bool dead = im.unhealthy();
            if (im.state == State::DEGRADED) {
                if (now < im.degraded_retry_at_ms || now < im.busy_until_ms) {
                    // backed off; nothing to do this tick
                } else {
                    im.request_failures = 0;
                    im.state = State::SELECTING;
                }
            }
            if (im.state != State::DEGRADED) {
                const bool want = !im.has_active || dead || im.mode == Mode::AUTO;
                if (!want || now < im.busy_until_ms) {
                    if (im.state == State::SELECTING && im.has_active && !dead)
                        im.state = State::MONITORING;
                } else if (im.request_failures >= im.cfg.failure_threshold) {
                    im.enter_degraded(now);
                } else {
                    ++im.c_selections;
                    auto candidates = im.gather_candidates();
                    if (candidates.empty()) {
                        if (!im.has_active || dead)
                            im.enter_degraded(now);
                        else
                            im.state = State::MONITORING;
                    } else {
                        const Impl::Candidate* best = &candidates.front();
                        if (dead && im.has_active) {
                            // Fallback means LEAVING the unhealthy profile.
                            // Equal scores are acceptable here: hysteresis is
                            // an improvement gate, not a reason to remain on a
                            // dead profile. Never select the active profile as
                            // its own fallback when another eligible one exists.
                            if (best->profile_id == im.active_id &&
                                best->revision == im.active_rev) {
                                best = nullptr;
                                for (const auto& c : candidates) {
                                    if (c.profile_id != im.active_id ||
                                        c.revision != im.active_rev) {
                                        best = &c;
                                        break;
                                    }
                                }
                            }
                        }
                        if (!best) {
                            im.enter_degraded(now);
                        } else {
                            const bool already_active =
                                !dead && im.has_active &&
                                best->profile_id == im.active_id &&
                                best->revision == im.active_rev;
                            const double cur = im.current_score();
                            const bool hysteresis_blocked =
                                !dead && im.has_active && cur >= 0.0 &&
                                !should_switch(cur, best->score,
                                               im.cfg.hysteresis_pct);
                            if (already_active || hysteresis_blocked) {
                                im.state = State::MONITORING;
                            } else if (!im.floor_ok(now) || !im.cooldown_ok(now) ||
                                       (!dead && !im.dwell_ok(now))) {
                                // Anti-storm floor / cooldown always apply;
                                // dwell is bypassed only for a dead profile.
                                im.state = dead ? State::SELECTING
                                                : State::MONITORING;
                            } else {
                                reason = !im.has_active
                                             ? "initial"
                                             : (dead ? "degradation"
                                                     : "improvement");
                                chosen = *best;
                                do_request = true;
                            }
                        }
                    }
                }
            }
        } else {
            // MANUAL / LOCKED: monitoring only.
            if (im.has_active && im.state != State::WAITING_TRANSITION)
                im.state = State::MONITORING;
        }

        if (do_request) im.issuing = true;
    }

    // Cancellation hooks fire before any new request, never under the lock.
    if (impl_->cfg.cancel_transition)
        for (const auto& c : cancels)
            impl_->cfg.cancel_transition(c.first, c.second);

    if (!do_request) return;

    // The ONE side effect: request a transition (outside the lock).
    const TransitionResult r =
        impl_->cfg.request_transition(chosen.profile_id, chosen.revision);

    std::lock_guard<std::mutex> lk(impl_->mu);
    Impl& im = *impl_;
    im.issuing = false;
    ++im.c_requests;
    im.ever_requested = true;
    const int64_t now = im.now();
    im.last_request_ms = now;

    switch (r) {
        case TransitionResult::ACCEPTED:
            im.outstanding = Impl::Outstanding{chosen.profile_id, chosen.revision,
                                               now + im.cfg.transition_timeout_ms,
                                               reason};
            im.has_outstanding = true;
            im.last_reason = reason;
            im.state = State::WAITING_TRANSITION;
            break;
        case TransitionResult::BUSY:
            // NOT a switch: active profile and health accounting untouched.
            ++im.c_busy;
            im.busy_until_ms = now + im.cfg.busy_retry_ms;
            im.state = im.unhealthy() || !im.has_active ? State::SELECTING
                                                        : State::MONITORING;
            break;
        case TransitionResult::NOT_SUPPORTED:
        case TransitionResult::INVALID_PROFILE:
            ++im.c_rejected;
            ++im.request_failures;
            if (reason == "manual")
                im.manual_lock = false;
            else if (reason == "rollback")
                im.rollback_pending = false;
            else
                im.excluded.insert(chosen.canonical);
            im.fail_maybe_degraded(now);
            break;
        case TransitionResult::DISABLED:
            ++im.c_disabled;
            im.busy_until_ms = now + im.cfg.cooldown_ms;
            if (im.unhealthy() || !im.has_active)
                im.enter_degraded(now);
            else
                im.state = State::MONITORING;
            break;
    }
}

// ---- transition completion ----

bool MimicryAutoPilot::commit_transition(const std::string& profile_id,
                                         uint32_t revision) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    Impl& im = *impl_;
    if (!im.has_outstanding || im.outstanding.profile_id != profile_id ||
        im.outstanding.revision != revision)
        return false;
    const int64_t now = im.now();
    // The pinned descriptor must still exist in the catalog.
    if (im.cfg.catalog && !im.cfg.catalog->find(profile_id, revision)) {
        im.has_outstanding = false;
        ++im.c_aborts;
        ++im.request_failures;
        im.fail_maybe_degraded(now);
        return false;
    }
    const std::string reason = im.outstanding.reason;
    const std::string from =
        im.has_active ? canonical_of(im.active_id, im.active_rev) : std::string();
    // The profile we leave becomes the previous stable rollback target.
    if (im.has_active &&
        !(im.active_id == profile_id && im.active_rev == revision)) {
        im.prev_stable_id = im.active_id;
        im.prev_stable_rev = im.active_rev;
        im.has_prev_stable = true;
    }
    im.has_outstanding = false;
    im.has_active = true;
    im.active_id = profile_id;
    im.active_rev = revision;
    im.active_since_ms = now;
    im.last_switch_ms = now;
    im.ever_committed = true;
    ++im.c_commits;
    ++im.c_switches;
    if (reason == "rollback") ++im.c_rollbacks;
    im.record_event(now, from, canonical_of(profile_id, revision), reason);
    im.last_reason = reason;
    if (reason == "rollback") im.rollback_pending = false;
    im.consecutive_unhealthy = 0;
    im.evidence_blocked_streak = 0;
    im.request_failures = 0;
    im.ewma_health = 1.0;  // fresh health window on the new profile
    im.state = State::MONITORING;
    return true;
}

bool MimicryAutoPilot::abort_transition(const std::string& profile_id,
                                        uint32_t revision) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    Impl& im = *impl_;
    if (!im.has_outstanding || im.outstanding.profile_id != profile_id ||
        im.outstanding.revision != revision)
        return false;
    const int64_t now = im.now();
    // A failed apply is a failure, never a switch: no SwitchEvent recorded.
    if (im.outstanding.reason == "rollback") im.rollback_pending = false;
    im.has_outstanding = false;
    ++im.c_aborts;
    ++im.request_failures;
    im.fail_maybe_degraded(now);
    return true;
}

// ---- baseline / operator controls ----

bool MimicryAutoPilot::adopt_active_profile(const std::string& profile_id,
                                            uint32_t revision) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    Impl& im = *impl_;
    if (!im.cfg.catalog) return false;
    if (!im.cfg.catalog->find(profile_id, revision)) return false;  // bounded check
    const int64_t now = im.now();
    im.has_active = true;
    im.active_id = profile_id;
    im.active_rev = revision;
    im.active_since_ms = now;
    im.last_switch_ms = now;
    im.ever_committed = true;  // dwell/cooldown baseline applies from now
    im.consecutive_unhealthy = 0;
    im.evidence_blocked_streak = 0;
    im.request_failures = 0;
    im.ewma_health = 1.0;
    im.last_reason = "adopt";
    if (im.transitions_enabled()) im.state = State::MONITORING;
    return true;
}

bool MimicryAutoPilot::set_manual_profile(const std::string& profile_id,
                                          uint32_t revision) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    Impl& im = *impl_;
    if (im.mode == Mode::LOCKED || !im.transitions_enabled()) return false;
    if (!im.cfg.catalog || !im.cfg.catalog->find(profile_id, revision)) return false;
    im.manual_lock = true;
    im.manual_id = profile_id;
    im.manual_rev = revision;
    return true;
}

void MimicryAutoPilot::clear_manual_profile() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->manual_lock = false;
}

bool MimicryAutoPilot::has_manual_profile() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->manual_lock;
}

bool MimicryAutoPilot::request_rollback() {
    std::lock_guard<std::mutex> lk(impl_->mu);
    Impl& im = *impl_;
    if (im.mode == Mode::LOCKED || !im.transitions_enabled()) return false;
    if (!im.has_prev_stable || im.has_outstanding) return false;
    im.rollback_pending = true;
    return true;
}

void MimicryAutoPilot::set_mode(Mode m) {
    std::vector<Impl::Cancel> cancels;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        Impl& im = *impl_;
        // Conservative: switching to a non-transitioning mode drops any
        // outstanding request through the cancellation hook.
        if ((m == Mode::DISABLED || m == Mode::LOCKED || m == Mode::MANUAL) &&
            im.has_outstanding) {
            cancels.push_back({im.outstanding.profile_id, im.outstanding.revision});
            im.has_outstanding = false;
            ++im.c_cancels;
        }
        im.mode = m;
        if (!im.transitions_enabled())
            im.state = State::DISABLED;
        else if (im.state == State::DISABLED)
            im.state = im.has_active ? State::MONITORING : State::SELECTING;
    }
    if (impl_->cfg.cancel_transition)
        for (const auto& c : cancels) impl_->cfg.cancel_transition(c.first, c.second);
}

MimicryAutoPilot::Mode MimicryAutoPilot::mode() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->mode;
}

void MimicryAutoPilot::set_enabled(bool enabled) {
    std::vector<Impl::Cancel> cancels;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        Impl& im = *impl_;
        im.cfg.enabled = enabled;
        if (im.has_outstanding &&
            (!enabled || im.mode == Mode::DISABLED || im.legacy_peer)) {
            cancels.push_back({im.outstanding.profile_id, im.outstanding.revision});
            im.has_outstanding = false;
            ++im.c_cancels;
        }
        if (!im.transitions_enabled())
            im.state = State::DISABLED;
        else if (im.state == State::DISABLED)
            im.state = im.has_active ? State::MONITORING : State::SELECTING;
    }
    if (impl_->cfg.cancel_transition)
        for (const auto& c : cancels) impl_->cfg.cancel_transition(c.first, c.second);
}

void MimicryAutoPilot::notify_legacy_peer(bool legacy) {
    std::vector<Impl::Cancel> cancels;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        Impl& im = *impl_;
        im.legacy_peer = legacy;
        if (legacy && im.has_outstanding) {
            cancels.push_back({im.outstanding.profile_id, im.outstanding.revision});
            im.has_outstanding = false;
            ++im.c_cancels;
        }
        if (!im.transitions_enabled())
            im.state = State::DISABLED;
        else if (im.state == State::DISABLED)
            im.state = im.has_active ? State::MONITORING : State::SELECTING;
    }
    if (impl_->cfg.cancel_transition)
        for (const auto& c : cancels) impl_->cfg.cancel_transition(c.first, c.second);
}

// ---- introspection ----

MimicryAutoPilot::State MimicryAutoPilot::state() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->state;
}

const char* MimicryAutoPilot::state_string() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return ncp::state_string(impl_->state);
}

bool MimicryAutoPilot::has_active_profile() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->has_active;
}

std::string MimicryAutoPilot::active_profile_id() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->has_active ? impl_->active_id : std::string();
}

uint32_t MimicryAutoPilot::active_profile_revision() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->has_active ? impl_->active_rev : 0;
}

bool MimicryAutoPilot::has_previous_stable() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->has_prev_stable;
}

bool MimicryAutoPilot::has_outstanding_request() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->has_outstanding;
}

std::vector<MimicryAutoPilot::SwitchEvent> MimicryAutoPilot::switch_history() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return std::vector<SwitchEvent>(impl_->history.begin(), impl_->history.end());
}

std::string MimicryAutoPilot::to_stats_json() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    const Impl& im = *impl_;
    const int64_t now = im.now();

    const auto remaining = [now](int64_t until) -> int64_t {
        return until > now ? until - now : 0;
    };
    int64_t cooldown_rem = 0;
    if (im.ever_committed)
        cooldown_rem = remaining(im.last_switch_ms + im.cfg.cooldown_ms);
    const int64_t dwell_rem =
        im.has_active ? remaining(im.active_since_ms + im.cfg.min_dwell_ms) : 0;
    const int64_t floor_rem =
        im.ever_requested ? remaining(im.last_request_ms +
                                      im.cfg.min_request_interval_ms)
                          : 0;

    char num[64];
    std::string j;
    j.reserve(768);
    j += "{";
    j += "\"enabled\":" + std::string(im.cfg.enabled ? "true" : "false");
    j += ",\"mode\":\"";
    j += mode_string(im.mode);
    j += "\"";
    j += ",\"legacy_peer\":" + std::string(im.legacy_peer ? "true" : "false");
    j += ",\"state\":\"";
    j += ncp::state_string(im.state);
    j += "\"";
    if (im.has_active)
        j += ",\"active_profile\":\"" +
             json_escape(canonical_of(im.active_id, im.active_rev)) + "\"";
    else
        j += ",\"active_profile\":null";
    if (im.has_outstanding)
        j += ",\"pending_request\":\"" +
             json_escape(canonical_of(im.outstanding.profile_id,
                                      im.outstanding.revision)) +
             "\"";
    else
        j += ",\"pending_request\":null";
    if (im.has_prev_stable)
        j += ",\"previous_stable\":\"" +
             json_escape(canonical_of(im.prev_stable_id, im.prev_stable_rev)) + "\"";
    else
        j += ",\"previous_stable\":null";
    if (im.manual_lock)
        j += ",\"manual_profile\":\"" +
             json_escape(canonical_of(im.manual_id, im.manual_rev)) + "\"";
    else
        j += ",\"manual_profile\":null";
    j += ",\"last_reason\":\"" + json_escape(im.last_reason) + "\"";

    std::snprintf(num, sizeof(num), "%.6f", im.ewma_health);
    j += ",\"ewma_health\":" + std::string(num);
    j += ",\"consecutive_unhealthy\":" + std::to_string(im.consecutive_unhealthy);
    j += ",\"evidence_blocked_streak\":" + std::to_string(im.evidence_blocked_streak);
    j += ",\"request_failures\":" + std::to_string(im.request_failures);
    j += ",\"candidates_considered\":" + std::to_string(im.last_candidates_considered);
    j += ",\"excluded_candidates\":" + std::to_string(im.excluded.size());
    j += ",\"anti_storm_remaining_ms\":" + std::to_string(floor_rem);
    j += ",\"cooldown_remaining_ms\":" + std::to_string(cooldown_rem);
    j += ",\"dwell_remaining_ms\":" + std::to_string(dwell_rem);
    j += ",\"busy_remaining_ms\":" + std::to_string(remaining(im.busy_until_ms));

    // Reference-host availability aggregate (no host identities).
    if (im.has_availability) {
        j += ",\"reference_availability\":{\"reachable\":" +
             std::to_string(im.avail_reachable) +
             ",\"total\":" + std::to_string(im.avail_total) + "}";
    } else {
        j += ",\"reference_availability\":null";
    }

    // Last DPI evidence — explicitly tagged as OFFLINE, never live health.
    if (im.has_dpi_evidence) {
        std::snprintf(num, sizeof(num), "%llu",
                      static_cast<unsigned long long>(im.last_evidence.observed_epoch));
        j += ",\"last_offline_dpi_evidence\":{\"offline\":true,\"blocked\":" +
             std::string(im.last_evidence.blocked ? "true" : "false") +
             ",\"observed_epoch\":" + num + ",\"source\":\"" +
             json_escape(im.last_evidence.source) + "\"}";
    } else {
        j += ",\"last_offline_dpi_evidence\":null";
    }

    // Scores of the last bounded candidate round.
    j += ",\"candidate_scores\":[";
    for (size_t i = 0; i < im.last_candidates.size(); ++i) {
        if (i) j += ",";
        std::snprintf(num, sizeof(num), "%.6f", im.last_candidates[i].score);
        j += "{\"profile\":\"" + json_escape(im.last_candidates[i].canonical) +
             "\",\"score\":" + num + "}";
    }
    j += "]";

    // Recent committed switches (most recent last), bounded.
    j += ",\"recent_switches\":[";
    {
        const size_t n = im.history.size();
        const size_t first = n > 3 ? n - 3 : 0;
        bool comma = false;
        for (size_t i = first; i < n; ++i) {
            const SwitchEvent& e = im.history[i];
            if (comma) j += ",";
            comma = true;
            j += "{\"ts_ms\":" + std::to_string(e.ts_ms) + ",\"from\":\"" +
                 json_escape(e.from) + "\",\"to\":\"" + json_escape(e.to) +
                 "\",\"reason\":\"" + json_escape(e.reason) + "\"}";
        }
    }
    j += "]";

    const uint64_t failed =
        im.c_rejected + im.c_aborts + im.c_timeouts + im.c_disabled;
    j += ",\"counters\":{";
    j += "\"requests\":" + std::to_string(im.c_requests);
    j += ",\"commits\":" + std::to_string(im.c_commits);
    j += ",\"aborts\":" + std::to_string(im.c_aborts);
    j += ",\"busy\":" + std::to_string(im.c_busy);
    j += ",\"disabled_results\":" + std::to_string(im.c_disabled);
    j += ",\"rejected\":" + std::to_string(im.c_rejected);
    j += ",\"timeouts\":" + std::to_string(im.c_timeouts);
    j += ",\"cancels\":" + std::to_string(im.c_cancels);
    j += ",\"switches\":" + std::to_string(im.c_switches);
    j += ",\"rollbacks\":" + std::to_string(im.c_rollbacks);
    j += ",\"failed_transitions\":" + std::to_string(failed);
    j += ",\"samples\":" + std::to_string(im.c_samples);
    j += ",\"malformed_metrics\":" + std::to_string(im.c_malformed);
    j += ",\"selections\":" + std::to_string(im.c_selections);
    j += "}}";
    return j;
}

} // namespace ncp
