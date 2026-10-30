#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP MimicryAutoPilot / ConnectionDirector — UDP reference-profile selection.
//
// This is a SEPARATE control loop from PresetAutoPilot (which is TCP/443
// probe-driven and hot-applies DPI presets). MimicryAutoPilot never probes
// the network, never uses nDPI as a runtime health signal and never touches
// the global Orchestrator / set_strategy. Its only inputs are:
//   - per-session UDP quality metrics (RTT / loss / jitter / throughput)
//     or explicit degradation/success samples supplied by the session owner;
//   - an offline DPI-evidence verdict (explicitly NOT live health);
//   - a reference-host availability AGGREGATE (one blocked host is not a
//     dead network);
//   - the set of available ProfileDescriptor records read (READ-ONLY) from
//     a ReferenceProfileCatalog, plus deterministic per-candidate
//     evidence/gate metadata (CandidateEvidence) injected by the integrator.
//
// Output: a deterministic, rate-limited stream of transition REQUESTS via
// the Config::request_transition callback. A request is only a request —
// the current profile changes exclusively when the embedding
// ConnectionDirector later confirms it through commit_transition() (or when
// an already-on-wire profile is adopted via adopt_active_profile()).
// abort_transition() / timeout / cancellation leave the active profile
// untouched, and a failed apply NEVER produces a successful SwitchEvent.
//
// Hard guarantees:
//   - Opt-in: disabled unless Config::enabled, mode != DISABLED, a
//     non-legacy peer and a request_transition callback.
//   - No background thread: decisions happen only inside evaluate(), which
//     reads an injectable clock (Config::now_fn) — deterministic under a
//     fake clock and trivially integrable into an event loop.
//   - At most ONE outstanding transition request at any time.
//   - Anti-flap: anti-storm floor between requests (NEVER bypassed),
//     cooldown between committed switches, minimum dwell before leaving a
//     healthy profile (bypassed only when the current profile is dead),
//     score hysteresis, bounded candidate list, failure threshold.
//   - Legacy peer or disabled: NO callback invocations, NO wire changes.
//   - No stealth/undetectability claims: this is a profile-selection aid,
//     not an invisibility mechanism.
// ═══════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <vector>

#include "ncp_reference_profile_catalog.hpp"  // ProfileDescriptor, ReferenceProfileCatalog (read-only)

namespace ncp {

class MimicryAutoPilot {
public:
    // ─────────────────────────────────────────────────────────────────────
    // Result of a transition request, returned by the embedding
    // ConnectionDirector through Config::request_transition.
    // Defined locally on purpose: no dependency on any future
    // transition-manager header.
    // ─────────────────────────────────────────────────────────────────────
    enum class TransitionResult : uint32_t {
        ACCEPTED = 0,       ///< request taken; commit/abort must follow
        BUSY,               ///< director busy; NOT a switch, active unchanged, retried later
        NOT_SUPPORTED,      ///< director cannot apply this profile at all
        DISABLED,           ///< transitions currently disabled globally
        INVALID_PROFILE,    ///< profile_id/revision unknown or unusable
    };

    // ─────────────────────────────────────────────────────────────────────
    // Operator policy / operating mode.
    // ─────────────────────────────────────────────────────────────────────
    enum class Mode : uint32_t {
        DISABLED = 0,   ///< no requests, no auto-selection
        MANUAL,         ///< operator-pinned profile only; no auto-selection
        AUTO,           ///< degradation fallback + improvement-driven switches
        LOCKED,         ///< monitoring only; NEVER switches (manual included)
        FALLBACK_ONLY,  ///< switches only when the current profile is degraded
    };

    // ─────────────────────────────────────────────────────────────────────
    // Control-loop states.
    // ─────────────────────────────────────────────────────────────────────
    enum class State : uint32_t {
        DISABLED = 0,        ///< opt-out / locked-off / legacy peer — no requests
        SELECTING,           ///< picking a candidate / waiting to (re)issue a request
        MONITORING,          ///< active profile healthy; watching session metrics
        WAITING_TRANSITION,  ///< one outstanding request; awaiting commit/abort
        DEGRADED,            ///< current profile unhealthy, no (better) candidate applied
    };

    // ─────────────────────────────────────────────────────────────────────
    // One per-session UDP metrics sample. A field left NaN means
    // "not provided". The sample is malformed (rejected, counted, ignored)
    // if EVERY field is absent, or any PROVIDED field is non-finite or out
    // of range (loss_ratio outside [0,1], negative rtt/jitter/throughput).
    // ─────────────────────────────────────────────────────────────────────
    struct UdpMetrics {
        /// "Field not provided" sentinel (NaN). A provided field must be
        /// finite and in range or the whole sample is malformed.
        static double absent() { return std::numeric_limits<double>::quiet_NaN(); }

        double rtt_ms = absent();
        double loss_ratio = absent();       ///< 0..1
        double jitter_ms = absent();
        double throughput_bps = absent();
        uint64_t packets = 0;               ///< packets observed in this window
    };

    // ─────────────────────────────────────────────────────────────────────
    // Offline DPI-evidence verdict. Explicitly OFFLINE metadata (lab /
    // offline analysis), never a live health signal: ingesting it does not
    // change the live EWMA health, it only feeds a separate blocked-verdict
    // streak used by the degradation trigger.
    // ─────────────────────────────────────────────────────────────────────
    struct OfflineDpiEvidence {
        bool blocked = false;          ///< offline verdict: this profile shape is blocked
        uint64_t observed_epoch = 0;   ///< when the offline evidence was produced
        std::string source;            ///< opaque origin label (e.g. "lab-ml-v3")
    };

    // ─────────────────────────────────────────────────────────────────────
    // Deterministic per-candidate gate/score metadata, injected by the
    // integrator (Config::candidate_evidence_fn). No network involved.
    // Any false compatibility flag is a HARD GATE (candidate ineligible).
    // Optional score terms are NaN when unknown.
    // ─────────────────────────────────────────────────────────────────────
    struct CandidateEvidence {
        bool encode_supported = true;       ///< local encoder can produce this shape
        bool decode_supported = true;       ///< local decoder path supports it
        bool handshake_compatible = true;   ///< handshake/rehearsal constraints ok
        bool rehearsal_passed = true;       ///< offline rehearsal gate
        bool mtu_compatible = true;         ///< fits the path MTU budget
        bool transition_compatible = true;  ///< director can transition current -> this

        double goodput_bps = UdpMetrics::absent();     ///< expected goodput
        double overhead_ratio = UdpMetrics::absent();  ///< 0..1 padding/header overhead
        double stability = UdpMetrics::absent();       ///< 0..1 historical stability
        double switch_cost = UdpMetrics::absent();     ///< >= 0 cost of moving to it
    };

    // ─────────────────────────────────────────────────────────────────────
    // One committed profile change. Created ONLY by a successful
    // commit_transition(); a failed/aborted/timed-out apply never appears
    // here.
    // ─────────────────────────────────────────────────────────────────────
    struct SwitchEvent {
        int64_t ts_ms = 0;
        std::string from;     ///< "id@rev" or "" for the initial selection
        std::string to;       ///< "id@rev"
        std::string reason;   ///< "initial"|"improvement"|"degradation"|"manual"|"rollback"
    };

    struct Config {
        // Opt-in master switch. When false the loop is in State::DISABLED and
        // request_transition is NEVER invoked.
        bool enabled = false;
        Mode mode = Mode::AUTO;
        // Set false when the peer does not speak reference-profile
        // transitions (legacy peer): no requests, no wire changes.
        bool peer_supports_profiles = true;

        // Catalog consulted READ-ONLY for available ProfileDescriptor
        // records. Non-owning; must outlive this object. nullptr == empty.
        const ReferenceProfileCatalog* catalog = nullptr;

        // THE only side effect of the decision loop. Called (never under
        // the internal lock) with the pinned (profile_id, revision). Must
        // be set when enabled; a missing callback keeps the loop DISABLED.
        std::function<TransitionResult(const std::string& profile_id,
                                       uint32_t revision)> request_transition;

        // Optional cancellation hook: invoked (never under the internal
        // lock) when an outstanding request is dropped locally — on
        // set_enabled(false), legacy-peer notification, mode change to
        // DISABLED/LOCKED/MANUAL, or request timeout. When NOT set, the
        // embedding ConnectionDirector MUST treat the absence of a
        // commit/abort before the transition timeout as an implicit
        // cancellation of the pending apply.
        std::function<void(const std::string& profile_id, uint32_t revision)>
            cancel_transition;

        // TEST HOOK / event-loop clock: milliseconds, monotonic within the
        // process. Default: steady_clock. All cooldown/dwell/timeout logic
        // uses only this clock.
        std::function<int64_t()> now_fn;

        // TEST HOOK: deterministic base score per candidate descriptor
        // ("injected scores"). Higher is better; non-finite or negative
        // scores disqualify the candidate. Default: 1.0 (neutral).
        std::function<double(const ProfileDescriptor&)> candidate_score_fn;

        // TEST HOOK / integration point: deterministic per-candidate
        // evidence + hard gates (encode/decode/handshake/rehearsal/MTU/
        // transition compatibility) and optional goodput/overhead/
        // stability/switch-cost score terms. Return false = candidate
        // ineligible. Default: no evidence, all gates pass.
        std::function<bool(const ProfileDescriptor&, CandidateEvidence& out)>
            candidate_evidence_fn;

        // ---- candidate eligibility ----
        uint32_t wire_version = 0;                 ///< matched against descriptor wire range
        std::vector<std::string> local_capabilities;  ///< must cover required_capabilities
        std::vector<ProtocolFamily> eligible_families;  ///< empty = all families eligible
        std::vector<std::string> exclude_profile_ids;   ///< never selected
        size_t max_candidates = 4;                 ///< bounded candidate list per selection

        // ---- score composition (weights default to 0 = base score only) ----
        double w_goodput = 0.0;        ///< += w * goodput_bps/goodput_ref_bps
        double w_overhead = 0.0;       ///< -= w * overhead_ratio
        double w_stability = 0.0;      ///< += w * stability
        double w_switch_cost = 0.0;    ///< -= w * switch_cost
        double goodput_ref_bps = 1e6;  ///< normalisation reference for goodput

        // ---- health model (per ingested sample, deterministic) ----
        double ewma_alpha = 0.3;             ///< EWMA smoothing of sample health
        double health_floor = 0.6;           ///< sample health below this = unhealthy sample
        double w_loss = 0.5;                 ///< penalty weights (clamped total <= 1)
        double w_rtt = 0.3;
        double w_jitter = 0.2;
        double w_throughput = 0.2;           ///< extra penalty when below floor
        double rtt_ref_ms = 150.0;           ///< rtt == rtt_ref => full rtt penalty
        double jitter_ref_ms = 40.0;
        double throughput_floor_bps = 0.0;   ///< 0 = throughput not penalised
        // Reference-host availability aggregate: healthy iff
        // reachable/total >= min_availability. One blocked host out of many
        // is therefore NOT treated as a dead network.
        double min_availability = 0.5;

        // ---- anti-flap ----
        int64_t min_request_interval_ms = 1000;  ///< anti-storm floor between
                                                 ///< requests; NEVER bypassed
        int64_t cooldown_ms = 60000;         ///< min interval between committed switches
        int64_t min_dwell_ms = 90000;        ///< min time on a profile before leaving it;
                                             ///< bypassed ONLY when current is dead
        double hysteresis_pct = 10.0;        ///< challenger must beat current by this margin
        uint32_t failure_threshold = 3;      ///< unhealthy samples / failed attempts before action
        int64_t transition_timeout_ms = 5000;///< outstanding request deadline (auto-abort)
        int64_t busy_retry_ms = 2000;        ///< delay before re-asking after BUSY
        size_t max_switch_events = 16;       ///< bound on the switch history
    };

    explicit MimicryAutoPilot(Config cfg);
    ~MimicryAutoPilot();

    MimicryAutoPilot(const MimicryAutoPilot&) = delete;
    MimicryAutoPilot& operator=(const MimicryAutoPilot&) = delete;

    // ---- inputs (called by the session owner) ----

    /// Feed one per-session UDP metrics window. Returns false (and counts
    /// the sample as malformed) when the sample is non-finite/out-of-range
    /// or carries no metric at all. Never triggers network activity.
    bool ingest_metrics(const UdpMetrics& m);

    /// Explicit health signals for owners that already classify windows.
    void report_success();
    void report_degradation();

    /// Reference-host availability aggregate. reachable > total or
    /// total == 0 is malformed (returns false). One blocked host out of
    /// many does NOT count as degradation (see Config::min_availability).
    bool ingest_reference_availability(uint32_t reachable, uint32_t total);

    /// Offline DPI-evidence verdict. OFFLINE metadata only: does not touch
    /// the live EWMA health; a blocked verdict feeds a separate streak that
    /// can trigger fallback selection.
    void ingest_offline_dpi_evidence(const OfflineDpiEvidence& e);

    // ---- deterministic decision tick ----

    /// Advance the control loop using Config::now_fn(). This is the ONLY
    /// place transition requests are issued. Safe to call on every event-
    /// loop iteration; work is gated by the configured intervals.
    void evaluate();

    // ---- transition completion (separate commit API) ----

    /// Confirm a previously ACCEPTED request. Only a commit changes the
    /// current profile (and records a SwitchEvent). Returns false when
    /// there is no matching outstanding request or the pinned descriptor
    /// vanished from the catalog (then the outstanding request is aborted,
    /// active unchanged, no event recorded).
    bool commit_transition(const std::string& profile_id, uint32_t revision);

    /// Abort the outstanding request (director rejected/failed midway).
    /// Active profile unchanged; NO SwitchEvent recorded. Returns false
    /// when ids do not match.
    bool abort_transition(const std::string& profile_id, uint32_t revision);

    // ---- baseline / operator controls ----

    /// Declare the profile that is ALREADY on the wire (e.g. session
    /// started before this controller). Bounded validation: the exact
    /// (profile_id, revision) must exist in the catalog. Establishes the
    /// baseline for dwell/hysteresis/cooldown. Records no SwitchEvent.
    bool adopt_active_profile(const std::string& profile_id, uint32_t revision);

    /// Operator pin (manual profile lock). While set, the loop requests a
    /// transition to exactly this profile (normal request path, anti-storm
    /// floor still applies) and auto-selection is suppressed. Validated
    /// against the catalog. Refused (false) in LOCKED mode / when disabled.
    bool set_manual_profile(const std::string& profile_id, uint32_t revision);
    void clear_manual_profile();
    bool has_manual_profile() const;

    /// Roll back to the previous stable profile through a NEW transition
    /// request (never an instant local apply). Returns false when there is
    /// no previous stable profile, a request is outstanding, or transitions
    /// are disabled/locked.
    bool request_rollback();

    void set_mode(Mode m);   ///< DISABLED/LOCKED/MANUAL cancel an outstanding request
    Mode mode() const;
    void set_enabled(bool enabled);   ///< false => DISABLED, outstanding cancelled
    void notify_legacy_peer(bool legacy);  ///< legacy => DISABLED-like, no requests

    // ---- introspection ----

    State state() const;
    const char* state_string() const;  ///< "disabled"|"selecting"|"monitoring"|...
    bool has_active_profile() const;
    std::string active_profile_id() const;     ///< "" when none
    uint32_t active_profile_revision() const;  ///< 0 when none
    bool has_previous_stable() const;
    bool has_outstanding_request() const;
    std::vector<SwitchEvent> switch_history() const;  ///< bounded copy

    /// Decision helper exposed for unit tests: should `challenger` replace
    /// `current` given the configured hysteresis margin?
    static bool should_switch(double current_score, double challenger_score,
                              double hysteresis_pct);

    /// JSON object with loop state and counters. Contains NO peer
    /// addresses, NO secrets, NO payload data — ids, revisions, timings,
    /// scores and counters only. The last DPI evidence is explicitly tagged
    /// "offline":true.
    std::string to_stats_json() const;

private:
    struct Impl;
    Impl* impl_;  // raw owning pointer (deleted in dtor), mirrors catalog ABI style
};

} // namespace ncp
