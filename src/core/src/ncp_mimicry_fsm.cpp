#include "ncp_mimicry_fsm.hpp"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <limits>

namespace ncp {
namespace {

constexpr double kMinPositive = 1e-9;  // keeps std distributions out of UB

double clampd(double v, double lo, double hi) {
    return v < lo ? lo : (v > hi ? hi : v);
}

bool finite(double v) { return std::isfinite(v); }

std::string lower_ascii(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

// ==================== Phases ====================

const char* to_string(MimicryFsmPhase p) noexcept {
    switch (p) {
        case MimicryFsmPhase::BOOTSTRAP:   return "bootstrap";
        case MimicryFsmPhase::HANDSHAKE:   return "handshake";
        case MimicryFsmPhase::ESTABLISHED: return "established";
        case MimicryFsmPhase::DATA:        return "data";
    }
    return "unknown";
}

// ==================== Construction / bootstrap ====================

MimicryFsmSession::MimicryFsmSession(const ProfileDescriptor& descriptor,
                                     const DerivedProfile& derived,
                                     MimicryFsmConfig config)
    : desc_(descriptor),
      derived_(derived),
      cfg_(std::move(config)) {
    seed_ = cfg_.seed_override.has_value() ? *cfg_.seed_override
                                           : derived_.rng_seed;
    dwell_scale_ = sanitize_scale(derived_.fsm_dwell_scale);
    if (!finite(cfg_.max_dwell_ms) || cfg_.max_dwell_ms < 0.0)
        cfg_.max_dwell_ms = 600000.0;

    fsm_enabled_ = desc_.fsm.enabled && !desc_.fsm.states.empty();

    rng_.seed(seed_);
    bootstrap();
}

void MimicryFsmSession::bootstrap() {
    current_state_.clear();
    phase_ = MimicryFsmPhase::BOOTSTRAP;
    if (!fsm_enabled_) return;

    // Deterministic seeded bootstrap: prefer the declared initial_state when
    // it exists; otherwise pick uniformly from the model states using the
    // seeded RNG (same seed => same bootstrap state).
    const FsmState* initial = nullptr;
    if (!desc_.fsm.initial_state.empty())
        initial = find_state(desc_.fsm.initial_state);

    if (initial) {
        current_state_ = initial->name;
    } else {
        std::uniform_int_distribution<size_t> pick(
            0, desc_.fsm.states.size() - 1);
        current_state_ = desc_.fsm.states[pick(rng_)].name;
    }

    // Entering a state mapped to a later phase advances the session phase
    // (monotonic only; never regresses below BOOTSTRAP here).
    if (const auto p = phase_of_state(current_state_))
        if (*p > phase_) phase_ = *p;
}

void MimicryFsmSession::reset(uint64_t seed) {
    seed_ = seed;
    rng_.seed(seed_);
    prepared_valid_ = false;  // queued shapes derive from the old rng stream
    prepared_ = MimicryFsmShape{};
    bootstrap();
}

const FsmState* MimicryFsmSession::find_state(const std::string& name) const
    noexcept {
    for (const auto& s : desc_.fsm.states)
        if (s.name == name) return &s;
    return nullptr;
}

// ==================== Sanitisation ====================

double MimicryFsmSession::sanitize_scale(double s) noexcept {
    if (!finite(s) || s < 0.0) return 1.0;
    return clampd(s, 0.0, kMaxDwellScale);
}

SizeDistribution MimicryFsmSession::sanitize_sizes(SizeDistribution s)
    noexcept {
    if (!finite(s.clamp_min) || s.clamp_min < 1.0) s.clamp_min = 1.0;
    if (!finite(s.clamp_max) || s.clamp_max < s.clamp_min)
        s.clamp_max = std::max(s.clamp_min, 1.0);
    if (!finite(s.mean)) s.mean = s.clamp_min;
    if (!finite(s.stddev) || s.stddev <= 0.0) s.stddev = kMinPositive;
    for (auto& c : s.components) {
        if (!finite(c.weight) || c.weight < 0.0) c.weight = 0.0;
        if (!finite(c.mean)) c.mean = s.clamp_min;
        if (!finite(c.stddev) || c.stddev <= 0.0) c.stddev = kMinPositive;
    }
    return s;
}

IntervalDistribution MimicryFsmSession::sanitize_iat(IntervalDistribution i)
    noexcept {
    if (!finite(i.mean_ms) || i.mean_ms <= 0.0) i.mean_ms = kMinPositive;
    if (!finite(i.stddev_ms) || i.stddev_ms <= 0.0) i.stddev_ms = kMinPositive;
    if (!finite(i.fixed_ms) || i.fixed_ms < 0.0) i.fixed_ms = 0.0;
    return i;
}

// ==================== State accessors ====================

bool MimicryFsmSession::fsm_enabled() const noexcept { return fsm_enabled_; }

const std::string& MimicryFsmSession::current_state() const noexcept {
    return current_state_;
}

MimicryFsmPhase MimicryFsmSession::phase() const noexcept { return phase_; }

uint64_t MimicryFsmSession::state_epoch() const noexcept { return state_epoch_; }

uint64_t MimicryFsmSession::profile_epoch() const noexcept {
    return profile_epoch_;
}

double MimicryFsmSession::fsm_dwell_scale() const noexcept {
    return dwell_scale_;
}

uint64_t MimicryFsmSession::seed() const noexcept { return seed_; }

// ==================== Phases ====================

std::optional<MimicryFsmPhase> MimicryFsmSession::phase_of_state(
    const std::string& state) const {
    const auto it = cfg_.state_phases.find(state);
    if (it != cfg_.state_phases.end()) return it->second;

    const std::string n = lower_ascii(state);
    if (n == "bootstrap")   return MimicryFsmPhase::BOOTSTRAP;
    if (n == "handshake")   return MimicryFsmPhase::HANDSHAKE;
    if (n == "established") return MimicryFsmPhase::ESTABLISHED;
    if (n == "data")        return MimicryFsmPhase::DATA;
    return std::nullopt;  // unphased: never gated
}

bool MimicryFsmSession::advance_phase() noexcept {
    if (phase_ == MimicryFsmPhase::DATA) return false;
    phase_ = static_cast<MimicryFsmPhase>(static_cast<uint8_t>(phase_) + 1);
    return true;
}

// ==================== Dwell + transitions ====================

double MimicryFsmSession::sample_dwell_ms() {
    if (!fsm_enabled_) return kFallbackDwellMs;
    const FsmState* st = find_state(current_state_);
    if (!st) return kFallbackDwellMs;  // defensive: state table mutated

    double mean = finite(st->dwell_mean_ms) ? st->dwell_mean_ms : 0.0;
    if (mean < 0.0) mean = 0.0;
    double stddev = finite(st->dwell_stddev_ms) ? st->dwell_stddev_ms : 0.0;
    if (stddev < 0.0) stddev = 0.0;

    double dwell = 0.0;
    if (stddev > 0.0) {
        std::normal_distribution<double> d(mean * dwell_scale_,
                                           stddev * dwell_scale_);
        dwell = d(rng_);
        if (!finite(dwell)) dwell = mean * dwell_scale_;  // paranoia
    } else {
        dwell = mean * dwell_scale_;  // fixed dwell, no RNG consumed
    }
    if (dwell < 0.0) dwell = 0.0;
    return clampd(dwell, 0.0, cfg_.max_dwell_ms);
}

std::vector<std::string> MimicryFsmSession::valid_transitions() const {
    std::vector<std::string> out;
    if (!fsm_enabled_) return out;
    for (const auto& t : desc_.fsm.transitions) {
        if (t.from != current_state_) continue;
        if (!finite(t.probability) || t.probability <= 0.0) continue;
        if (!find_state(t.to)) continue;
        if (!cfg_.allow_phase_regression) {
            if (const auto p = phase_of_state(t.to))
                if (*p < phase_) continue;  // monotonic phases
        }
        out.push_back(t.to);
    }
    return out;
}

bool MimicryFsmSession::advance() {
    if (!fsm_enabled_) return false;

    // Gather valid candidates with clamped weights.
    struct Cand { const FsmTransition* t; double w; };
    std::vector<Cand> cands;
    double total = 0.0;
    for (const auto& t : desc_.fsm.transitions) {
        if (t.from != current_state_) continue;
        if (!finite(t.probability) || t.probability <= 0.0) continue;
        if (!find_state(t.to)) continue;
        if (!cfg_.allow_phase_regression) {
            if (const auto p = phase_of_state(t.to))
                if (*p < phase_) continue;
        }
        const double w = clampd(t.probability, kMinPositive, 1.0);
        cands.push_back({&t, w});
        total += w;
    }
    if (cands.empty() || !(total > 0.0)) return false;  // terminal state

    std::uniform_real_distribution<double> pick(0.0, 1.0);
    const double u = pick(rng_) * total;
    double acc = 0.0;
    const FsmTransition* chosen = cands.back().t;
    for (const auto& c : cands) {
        acc += c.w;
        if (u <= acc) { chosen = c.t; break; }
    }

    current_state_ = chosen->to;
    ++state_epoch_;
    // A stale prepared shape can never be consumed: it is bound to the
    // pre-transition state epoch, which take_data_shape() rejects. Drop it
    // eagerly so it also cannot be observed via has_prepared_shape().
    prepared_valid_ = false;
    prepared_ = MimicryFsmShape{};

    if (const auto p = phase_of_state(current_state_))
        if (*p > phase_) phase_ = *p;
    return true;
}

FsmStepResult MimicryFsmSession::step() {
    FsmStepResult r;
    r.from = current_state_;
    r.dwell_ms = sample_dwell_ms();
    r.transitioned = advance();
    r.to = current_state_;
    r.state_epoch = state_epoch_;
    return r;
}

// ==================== Effective per-state parameters ====================

StatProfile MimicryFsmSession::resolved_stat_for_state(
    const std::string& state) const {
    StatProfile sp = derived_.stat;  // jittered per-session base models
    bool overridden = false;
    const auto it = cfg_.state_overrides.find(state);
    if (it != cfg_.state_overrides.end()) {
        const FsmStateOverride& ov = it->second;
        if (ov.sizes.has_value()) { sp.sizes = *ov.sizes; overridden = true; }
        if (ov.iat.has_value())   { sp.intervals = *ov.iat; overridden = true; }
    }
    if (overridden) {
        // The joint size<->IAT sampler encodes the BASE marginals; honouring
        // a per-state override requires the 1-D marginal path.
        sp.size_iat_joint = JointSizeIatSampler{};
    }
    sp.sizes = sanitize_sizes(sp.sizes);
    sp.intervals = sanitize_iat(sp.intervals);
    return sp;
}

SizeDistribution MimicryFsmSession::effective_sizes(
    const std::string& state) const {
    return resolved_stat_for_state(state).sizes;
}

IntervalDistribution MimicryFsmSession::effective_iat(
    const std::string& state) const {
    return resolved_stat_for_state(state).intervals;
}

PaddingHeaderModel MimicryFsmSession::effective_padding(
    const std::string& state) const {
    const auto it = cfg_.state_overrides.find(state);
    if (it != cfg_.state_overrides.end() && it->second.padding.has_value())
        return *it->second.padding;
    return desc_.padding_header;
}

void MimicryFsmSession::set_state_overrides(FsmStateOverrideMap overrides) {
    cfg_.state_overrides = std::move(overrides);
    ++profile_epoch_;         // stale-epoch shapes can never be consumed
    prepared_valid_ = false;  // drop the old-epoch shape eagerly
    prepared_ = MimicryFsmShape{};
}

// ==================== Prepared data shapes ====================

MimicryFsmShape MimicryFsmSession::prepare_data_shape() {
    if (prepared_valid_) return prepared_;  // idempotent peek, no RNG use

    StatProfile sp = resolved_stat_for_state(current_state_);

    double size = 0.0, iat = 0.0;
    sp.sample_size_iat(rng_, size, iat);  // (size, iat) sampled as one pair

    // ---- payload clamp: [1, mtu.max_payload_bytes] ----
    uint64_t max_payload = desc_.mtu.max_payload_bytes;
    if (max_payload < 1) max_payload = 1;
    if (!finite(size)) size = 1.0;
    size = clampd(size, 1.0, static_cast<double>(max_payload));
    const size_t payload = static_cast<size_t>(size);

    // ---- IAT clamp: [0, kMaxIatMs] ----
    if (!finite(iat)) iat = 0.0;
    iat = clampd(iat, 0.0, kMaxIatMs);

    // ---- padding + header accounting ----
    const PaddingHeaderModel pad = effective_padding(current_state_);
    uint64_t path_mtu = desc_.mtu.path_mtu_bytes;
    if (path_mtu < 2) path_mtu = 2;  // header + at least one payload byte

    // Bounded signed per-session header/gap template shift.
    int64_t header = static_cast<int64_t>(pad.header_overhead_bytes) +
                     static_cast<int64_t>(derived_.header_gap_shift_bytes);
    if (header < 0) header = 0;
    uint64_t header_u = static_cast<uint64_t>(header);
    // Header must leave room for at least one payload byte.
    if (header_u > path_mtu - 1) header_u = path_mtu - 1;

    // Payload must fit the path MTU even for an inconsistent descriptor
    // (max_payload_bytes larger than what the MTU can carry).
    const uint64_t pay_budget = path_mtu - header_u;  // >= 1
    uint64_t pay = payload;
    if (pay > pay_budget) pay = pay_budget;

    uint64_t total = pay + header_u;  // <= path_mtu
    uint64_t padding = 0;

    if (pad.pad_to_block && pad.padding_block_bytes > 1) {
        const uint64_t block = pad.padding_block_bytes;
        const uint64_t rem = total % block;
        if (rem != 0) padding = block - rem;
    }

    // Hard cap: padding_max_bytes + bounded per-session extra padding.
    const uint64_t pad_cap = static_cast<uint64_t>(pad.padding_max_bytes) +
                             static_cast<uint64_t>(derived_.padding_extra_bytes);
    if (padding > pad_cap) padding = pad_cap;

    // Never exceed the path MTU.
    if (padding > path_mtu - total) padding = path_mtu - total;
    total += padding;

    MimicryFsmShape shape;
    shape.payload_bytes = static_cast<size_t>(pay);
    shape.padding_bytes = static_cast<size_t>(padding);
    shape.total_bytes = static_cast<size_t>(total);
    shape.delay_ms = iat;
    shape.state_epoch = state_epoch_;
    shape.profile_epoch = profile_epoch_;
    shape.state = current_state_;

    prepared_ = shape;
    prepared_valid_ = true;
    return prepared_;
}

bool MimicryFsmSession::take_data_shape(MimicryFsmShape& out) {
    if (!prepared_valid_) return false;
    if (prepared_.state_epoch != state_epoch_ ||
        prepared_.profile_epoch != profile_epoch_) {
        // Stale epoch: drop, never consume.
        prepared_valid_ = false;
        prepared_ = MimicryFsmShape{};
        return false;
    }
    out = prepared_;
    prepared_valid_ = false;
    prepared_ = MimicryFsmShape{};
    return true;
}

void MimicryFsmSession::cancel_prepared_shape() noexcept {
    prepared_valid_ = false;
    prepared_ = MimicryFsmShape{};
}

bool MimicryFsmSession::has_prepared_shape() const noexcept {
    return prepared_valid_;
}

// ==================== Control plane ====================

void MimicryFsmSession::note_control_packet(size_t bytes) noexcept {
    // Accounting only: no RNG draw, no FSM transition, no shape interaction.
    ++control_packets_;
    control_bytes_ += static_cast<uint64_t>(bytes);
}

uint64_t MimicryFsmSession::control_packets_observed() const noexcept {
    return control_packets_;
}

uint64_t MimicryFsmSession::control_bytes_observed() const noexcept {
    return control_bytes_;
}

} // namespace ncp
