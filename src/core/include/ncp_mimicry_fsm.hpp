#pragma once

/**
 * @file ncp_mimicry_fsm.hpp
 * @brief Runtime FSM-based mimicry profiles (per-session, seeded, epoch-bound)
 *
 * Turns the *static* catalog-side timing FSM (FsmModel / FsmState /
 * FsmTransition in ncp_reference_profile_catalog.hpp) plus a DerivedProfile
 * into a live per-session runtime:
 *
 *  - Independent per-session state: every MimicryFsmSession owns its RNG
 *    stream, current state, phase, epochs and prepared-shape queue. No
 *    threads, no global/static mutable state; two sessions never share
 *    anything except the caller-owned immutable descriptor.
 *  - Deterministic seeded bootstrap: the RNG is seeded from
 *    DerivedProfile::rng_seed. When the model declares an initial_state it
 *    is used verbatim; otherwise the bootstrap state is picked uniformly
 *    from the model's states by the seeded RNG. Same (descriptor, derived,
 *    config) always yields the same bootstrap and the same entire trace.
 *  - Dwell sampling: every state's dwell is sampled as
 *    N(dwell_mean_ms, dwell_stddev_ms) scaled by the per-session
 *    DerivedProfile::fsm_dwell_scale, then clamped to
 *    [0, config.max_dwell_ms]; non-finite model values are sanitised.
 *  - Valid transition selection: only transitions leaving the current
 *    state, with a finite probability > 0 and an existing target state are
 *    candidates; selection is probability-weighted and deterministic for
 *    the session seed. Terminal states (no valid outgoing transition)
 *    keep the session in place.
 *  - Explicit phases: BOOTSTRAP -> HANDSHAKE -> ESTABLISHED -> DATA.
 *    Phases advance explicitly via advance_phase() and implicitly when a
 *    transition enters a state mapped to a later phase (explicit
 *    config.state_phases map first, then name convention
 *    "bootstrap"/"handshake"/"established"/"data"). Phase regression is
 *    rejected during transition selection unless
 *    config.allow_phase_regression is set.
 *  - Per-state size/IAT/padding overrides: caller-supplied, keyed by state
 *    name (FsmStateOverrideMap). Overrides live purely in the runtime API —
 *    the catalog schema is untouched. When a state's size or IAT model is
 *    overridden the joint size<->IAT sampler is bypassed for that state
 *    (the joint model encodes the *base* marginals and would silently
 *    contradict the override).
 *  - Epoch-bound state and prepared data shapes: every FSM transition bumps
 *    state_epoch(); installing new overrides bumps profile_epoch(). A
 *    prepared shape carries both epochs and the state it was prepared in;
 *    take_data_shape() refuses (and drops) any shape whose epochs are
 *    stale, so a shape prepared under a superseded state/epoch can never
 *    be consumed.
 *  - Control packets never advance the FSM, never touch the RNG and never
 *    consume or disturb a queued prepared shape (note_control_packet() is
 *    accounting-only; prepare_data_shape() is an idempotent peek).
 *  - Safe clamps / finite checks on every externally supplied value
 *    (dwell scale, dwell params, probabilities, sizes, IATs, padding,
 *    MTU budget).
 */

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "ncp_reference_profile_catalog.hpp"  // FsmModel/FsmState/FsmTransition/DerivedProfile/ProfileDescriptor

namespace ncp {

// ==================== Phases ====================

/// Explicit session lifecycle phases, in fixed monotonic order.
enum class MimicryFsmPhase : uint8_t {
    BOOTSTRAP    = 0,
    HANDSHAKE    = 1,
    ESTABLISHED  = 2,
    DATA         = 3,
};

const char* to_string(MimicryFsmPhase p) noexcept;

// ==================== Per-state runtime overrides ====================

/**
 * Caller-supplied per-state overrides. Keyed by state name; the catalog
 * schema (ProfileDescriptor) is NOT extended — overrides exist only at
 * runtime. Any field left unset falls back to the descriptor/base model.
 */
struct FsmStateOverride {
    std::optional<SizeDistribution> sizes;      ///< overrides descriptor.sizes / derived.stat.sizes
    std::optional<IntervalDistribution> iat;    ///< overrides descriptor.iat / derived.stat.intervals
    std::optional<PaddingHeaderModel> padding;  ///< overrides descriptor.padding_header
};

/// Overrides keyed by FSM state name. Unknown names are ignored.
using FsmStateOverrideMap = std::map<std::string, FsmStateOverride>;

// ==================== Config ====================

struct MimicryFsmConfig {
    /// Per-state size/IAT/padding overrides (keyed by state name).
    FsmStateOverrideMap state_overrides;

    /// Explicit state -> phase assignment. States absent here are classified
    /// by name convention (exact lowercase match of "bootstrap",
    /// "handshake", "established", "data"); states matching neither are
    /// unphased and never gated.
    std::map<std::string, MimicryFsmPhase> state_phases;

    /// Allow transitions into a state mapped to an EARLIER phase.
    /// Default false: phases are monotonic (bootstrap -> ... -> data).
    bool allow_phase_regression = false;

    /// Hard cap for a single sampled dwell, ms (finite, >= 0; sanitised).
    double max_dwell_ms = 600000.0;  // 10 min, mirrors catalog interval bound

    /// Optional explicit RNG seed. When unset, DerivedProfile::rng_seed is
    /// used (recommended: it is the deterministic per-session seed produced
    /// by ReferenceProfileCatalog::derive_session()).
    std::optional<uint64_t> seed_override;
};

// ==================== Prepared data shape ====================

/// A queued, not-yet-consumed data shape prepared under specific epochs.
struct MimicryFsmShape {
    size_t payload_bytes = 0;    ///< sampled payload size, [1, mtu.max_payload_bytes]
    size_t padding_bytes = 0;    ///< padding applied on top of payload+header
    size_t total_bytes = 0;      ///< payload + header + padding, <= path MTU
    double delay_ms = 0.0;       ///< paired inter-arrival delay, [0, kMaxIatMs]
    uint64_t state_epoch = 0;    ///< FSM state epoch the shape was prepared in
    uint64_t profile_epoch = 0;  ///< override/profile epoch the shape was prepared in
    std::string state;           ///< FSM state the shape was prepared in
};

/// Result of one dwell-sample + transition step.
struct FsmStepResult {
    bool transitioned = false;   ///< false on a terminal state (no valid edge)
    std::string from;            ///< state before the step
    std::string to;              ///< state after the step (== from when terminal)
    double dwell_ms = 0.0;       ///< dwell sampled for `from` (scaled, clamped)
    uint64_t state_epoch = 0;    ///< state epoch after the step
};

// ==================== Session ====================

/**
 * Per-session runtime FSM mimicry session.
 *
 * Construct from an immutable ProfileDescriptor (borrowed; must outlive the
 * session) and its DerivedProfile. All sampling is deterministic for the
 * session seed; different sessions (different DerivedProfile) are
 * polymorphic. Not thread-safe by design: one session object per protected
 * session, owned and driven by that session's context.
 */
class MimicryFsmSession {
public:
    /// Hard IAT cap for prepared shapes (mirrors JointSizeIatSampler).
    static constexpr double kMaxIatMs = 600000.0;
    /// Sanitisation bounds for the per-session dwell scale.
    static constexpr double kMaxDwellScale = 100.0;
    /// Fallback dwell for degenerate/disabled models, ms.
    static constexpr double kFallbackDwellMs = 0.0;

    MimicryFsmSession(const ProfileDescriptor& descriptor,
                      const DerivedProfile& derived,
                      MimicryFsmConfig config = {});
    ~MimicryFsmSession() = default;

    MimicryFsmSession(const MimicryFsmSession&) = delete;
    MimicryFsmSession& operator=(const MimicryFsmSession&) = delete;

    // ---- bootstrap / state ----

    /// True when the descriptor carries a usable FSM (enabled, >= 1 state).
    bool fsm_enabled() const noexcept;
    /// Current FSM state name; empty when the FSM is disabled.
    const std::string& current_state() const noexcept;
    /// Current lifecycle phase (monotonic unless allow_phase_regression).
    MimicryFsmPhase phase() const noexcept;
    /// Bumped by every applied FSM transition.
    uint64_t state_epoch() const noexcept;
    /// Bumped by set_state_overrides(); prepared shapes are bound to it.
    uint64_t profile_epoch() const noexcept;
    /// Sanitised per-session dwell scale actually in use.
    double fsm_dwell_scale() const noexcept;
    /// The session seed actually in use.
    uint64_t seed() const noexcept;

    /// Re-seed and re-bootstrap (deterministic for the new seed). Drops any
    /// queued prepared shape; phase returns to the bootstrap classification
    /// of the new initial state. Epochs are preserved (the dropped shape can
    /// never be consumed afterwards because the queue is cleared).
    void reset(uint64_t seed);

    // ---- phases ----

    /// Explicit phase progression BOOTSTRAP -> HANDSHAKE -> ESTABLISHED ->
    /// DATA. Returns false when already in DATA. Never regresses.
    bool advance_phase() noexcept;

    /// Phase a state maps to: explicit config map, else name convention,
    /// else nullopt (unphased).
    std::optional<MimicryFsmPhase> phase_of_state(
        const std::string& state) const;

    // ---- dwell + transitions ----

    /// Sample the current state's dwell (N(mean, stddev) * fsm_dwell_scale),
    /// clamped to [0, config.max_dwell_ms]. Consumes RNG exactly once per
    /// call. Returns kFallbackDwellMs when the FSM is disabled.
    double sample_dwell_ms();

    /// Select and apply a probability-weighted valid transition out of the
    /// current state. Returns false (and stays) on a terminal state.
    bool advance();

    /// Convenience: sample the current state's dwell, then advance().
    FsmStepResult step();

    /// Candidate target states for the current state after all validity
    /// filters (existing target, finite probability > 0, phase gate).
    /// Exposed for inspection/tests; does not consume RNG.
    std::vector<std::string> valid_transitions() const;

    // ---- effective per-state parameters (override resolution) ----

    SizeDistribution effective_sizes(const std::string& state) const;
    IntervalDistribution effective_iat(const std::string& state) const;
    PaddingHeaderModel effective_padding(const std::string& state) const;

    /// Install a new override map. Bumps profile_epoch() and drops any
    /// queued prepared shape, so stale-epoch shapes can never be consumed
    /// under the new overrides.
    void set_state_overrides(FsmStateOverrideMap overrides);

    // ---- prepared data shapes (epoch-bound) ----

    /// Prepare (idempotently) the next data shape for the CURRENT state and
    /// epochs and return a copy. Repeated calls return the queued shape
    /// unchanged and consume no RNG — the control path may inspect pacing
    /// without consuming anything. The first call consumes RNG once
    /// (size/IAT pair) even when the FSM is disabled (base models are used).
    MimicryFsmShape prepare_data_shape();

    /// Consume the queued shape for a data packet. Returns false when
    /// nothing is queued or the queued shape belongs to a stale state or
    /// profile epoch (the stale shape is dropped, never consumed).
    bool take_data_shape(MimicryFsmShape& out);

    /// Drop the queued shape without consuming it.
    void cancel_prepared_shape() noexcept;

    /// True when a (current-epoch) shape is queued.
    bool has_prepared_shape() const noexcept;

    // ---- control plane ----

    /// Account for a control packet. Guaranteed side-effect free w.r.t. the
    /// FSM, the RNG stream and the prepared-shape queue: control traffic
    /// never advances state, never consumes or disturbs a queued shape.
    void note_control_packet(size_t bytes = 0) noexcept;
    uint64_t control_packets_observed() const noexcept;
    uint64_t control_bytes_observed() const noexcept;

private:
    const FsmState* find_state(const std::string& name) const noexcept;
    void bootstrap();  // seeded initial-state selection + phase classification
    static double sanitize_scale(double s) noexcept;
    static SizeDistribution sanitize_sizes(SizeDistribution s) noexcept;
    static IntervalDistribution sanitize_iat(IntervalDistribution i) noexcept;
    /// Effective (override-resolved, sanitised) sampling models for a state.
    /// When sizes or iat are overridden the joint sampler is cleared: it
    /// encodes the base marginals and would contradict the override.
    StatProfile resolved_stat_for_state(const std::string& state) const;

    const ProfileDescriptor& desc_;  // borrowed, immutable, must outlive
    DerivedProfile derived_;
    MimicryFsmConfig cfg_;

    std::mt19937_64 rng_;
    uint64_t seed_ = 0;
    double dwell_scale_ = 1.0;  // sanitised

    bool fsm_enabled_ = false;
    std::string current_state_;
    MimicryFsmPhase phase_ = MimicryFsmPhase::BOOTSTRAP;
    uint64_t state_epoch_ = 0;
    uint64_t profile_epoch_ = 0;

    bool prepared_valid_ = false;
    MimicryFsmShape prepared_{};

    uint64_t control_packets_ = 0;
    uint64_t control_bytes_ = 0;
};

} // namespace ncp
