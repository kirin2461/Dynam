# Method 4 — Adversarial Feature-Projection Shaper (AFPS)

Lane: statistical traffic shaping / mimicry / anti-ML timing & size.
Status: **design sketch** (no build in this environment). Merged by the
coordinator with the other four method lanes.

---

## 1. Technique name + idea

**Adversarial Feature-Projection Shaper (AFPS)** — a closed-loop controller
that sits on top of the existing statistical profiles and picks each
`(packet_size, inter_arrival)` pair so that the *empirical, sliding-window
feature vector* of our flow stays inside the interior of the genuine
reference population's envelope, maximizing the worst-case margin against a
small **ensemble** of cheap flow discriminators.

Today every shaper in the tree is *open-loop*: `MimicryShaper::plan()` draws
chunks i.i.d. from a fixed `StatProfile`
(`src/core/src/ncp_mimicry_stats.cpp:333`), the joint sampler encodes one
*analytic* size↔IAT correlation (`:125`), and the FSM walks a first-order
Markov chain (`ncp_mimicry_fsm.hpp:242`). None of them ever look at what an
observer would *actually compute from the packets we just emitted*. An ML
flow classifier is trained on exactly that: window-level empirical statistics
(and their temporal/cross-feature structure). A stationary fixed profile is,
by construction, a trainable distribution — the solver converges on it after
enough sessions, because per-session RNG reseeding changes the *seed*, not
the *distribution*. AFPS is the first component here that models the
observer's discriminative statistic and *actively drives our flow's feature
trajectory into the region where every candidate classifier in the ensemble
is least confident* — a margin-maximizing (minimax) action selection, not a
distribution match.

---

## 2. How it works and why it degrades an ML/statistical classifier

### 2.1 The gap AFPS targets

`StatProfile` gives us two *marginals* plus an optional 2-D Gaussian-mixture
joint (`ncp_mimicry_stats.cpp:184`, `:243`, `:125`). What a classifier
actually keys on is different, and lives in the gap:

| What the profile controls | What the classifier reads |
|---|---|
| Marginal `size`, `iat` means/spreads | **Windowed** size distribution, KS-vs-reference |
| Analytic Pearson rho of a GMM component (`:176`) | **Empirical** size↔IAT correlation of the last W packets |
| Per-draw independence | **Autocorrelation** of IAT (burstiness memory, lag 1..k) |
| Clamp envelope `[clamp_min, clamp_max]` | **Tail mass** and skew (a profile that never emits tails is anomalous) |
| One static parameter set per epoch | **Inter-session** spread of those parameters (population heterogeneity) |

A classifier does not need global rho; it needs the windowed feature. Matching
the reference *mean* while differing in *spread, shape, or temporal memory*
is still separable. AFPS constrains the windowed feature vector directly.

### 2.2 Mechanism

Per emitted data packet, `plan_next()` runs a **draw → project → select** loop:

1. **Draw** `C` candidate `(bytes, delay_ms)` pairs from the base
   `StatProfile` via the existing joint sampler (`sample_size_iat`,
   `ncp_mimicry_stats.cpp:243`). This keeps AFPS a *layer on top of* the
   current profiles — it never invents sizes from nothing.
2. **Project.** For each candidate, compute the *hypothetical* post-send
   feature vector `F'` incrementally from a ring buffer of the last `W`
   shapes (O(k), allocation-free). This is exactly the vector a shadow
   classifier would compute over the window.
3. **Score margins.** Evaluate `F'` against `K` cheap discriminators and
   convert each into a signed **margin** `m_k ∈ [-1, 1]` (higher = harder to
   classify). The ensemble, by design, mirrors an attacker's plausible
   feature subsets:
   - `m_ks` — KS distance to the reference size CDF (reuses the
     `AdversaryTester::ks_distance` math, `ncp_adversary_tester.cpp:169`);
   - `m_env` — diagonal-Mahalanobis distance of `F'` from the reference
     envelope center (weights per feature);
   - `m_var` — size-variance ratio ≈ 1 (`ncp_adversary_tester.cpp:401`);
   - `m_cov` — timing CoV within tolerance of reference
     (`:198`), catching the "too smooth" shaping artifact;
   - `m_burst` — burst-anomaly (`:220`);
   - `m_ar` — lag-1 IAT autocorrelation plausibility (the temporal-memory
     feature ET-BERT/FlowPic-style models exploit and that *no* marginal
     profile controls).
4. **Select** the candidate maximizing `min_k m_k` — the **minimax** action —
   subject to a hard `ShapeBudget` (padding overhead, added latency,
   packets/window).
5. **Escalate** if the best `min_k m_k` still falls below `margin_floor`:
   spend budget on one calibrated **cover** packet (reusing
   `FlowShaper::generate_dummy`, `ncp_flow_shaper.hpp:232`) sized to pull the
   window back toward the envelope interior. If even that cannot clear the
   floor, emit the best-margin action and count the shortfall (honest
   telemetry, §6).
6. **Observe** the *actually sent* `(bytes, delay)` to advance the ring
   buffer — feedback is on real emissions, not on candidates.

### 2.3 Why this lowers classifier accuracy — stated precisely

- **It removes the low-support region a classifier uses for confident
  labels.** Benign flows have noise, but their feature vectors sit in the
  high-density interior of the genuine distribution. Open-loop shaping often
  parks our vectors in the *tails* (constant-ish sizes from
  `VolumeNormalizer` bucket rounding, `ncp_volume_normalizer.cpp:48`;
  over-smoothed timing from the RTT equalizer, `ncp_rtt_equalizer.cpp:73`).
  Those tails are exactly where a classifier gets a high-confidence
  "tunnel" label. Projecting to the interior attacks **confidence (softmax
  margin)**, which is what real filters threshold on
  (`docs/DPI_EVIDENCE_GATE.md`), not merely the hard label.
- **Minimax over an ensemble defeats overfitting to one detector.** The
  current shadow classifier collapses six metrics into one hardcoded weighted
  score (`HeuristicScores::aggregate_stealth`,
  `ncp_adversary_tester.hpp:58`); beating it exactly is a known failure mode
  (the weights are public). Selecting on `min_k` hedges against an *unknown*
  classifier: we don't optimize to fool our detector, we optimize to be far
  from every detector's boundary.
- **Continuous projection instead of quantization.** Bucket/block rounding
  produces a discrete histogram a classifier can memorize; AFPS projects
  continuously and adds a calibrated tail allowance so the *absence* of tail
  events (an over-constrained fingerprint) is itself avoided.
- **Population sampling via slow drift.** The envelope center is re-drawn per
  session from within the genuine population's own spread (`drift_sigma`):
  each single window stays KS-plausible, but the *pooled* inter-session
  distribution matches natural heterogeneity rather than one machine's
  identical output. This raises the cost of a fleet-level classifier that
  pools sessions — **and this is the weakest of the four claims** (see §6:
  a classifier retrained on the drift manifold follows it).

---

## 3. Difference from existing profiles / shapers

| Existing component | What it does | Why AFPS is not a duplicate |
|---|---|---|
| `MimicryShaper::plan()` / `prepare_data_shape` — `ncp_mimicry_stats.cpp:333`, `:372` | i.i.d. chunking from a fixed `StatProfile`; epoch-fenced queued shape | Open-loop, no observer model, samples the *marginal/joint* not the *windowed* feature; AFPS adds a selection stage on top of the same draws |
| `JointSizeIatSampler` — `:125`, rho at `:176` | 2-D Gaussian-mixture with analytic size↔IAT coupling | Controls *analytic* rho of one draw; AFPS constrains *empirical windowed* rho + IAT autocorrelation + tail mass, which the GMM cannot express |
| `MimicryFsmSession` — `ncp_mimicry_fsm.hpp:242` | first-order Markov chain over discrete states with dwell sampling | State-machine realism (phase structure); AFPS is continuous, moment-constrained, and *closed-loop* against a feature model — complementary, wrap the FSM as the base sampler |
| `FlowShaper` — `ncp_flow_shaper.hpp:221`, `:190` | burst model, dummy/keepalive injection, ratio balancing | No notion of a classifier; AFPS *consumes* `generate_dummy()` as its escalation lever (`:232`) and contributes the decision of *when/why* to spend it |
| `AdversaryTester` (shadow classifier) — `ncp_adversary_tester.cpp:367` | measures 6 heuristics **after** a window, fires `DetectionFeedback` | It is a *detector with hardcoded weights*; AFPS is a *controller* that predicts the window score for a candidate **before** send and selects on an ensemble `min` margin. AFPS re-uses its metric math but is not fed the same single aggregate |
| `VolumeNormalizer` — `ncp_volume_normalizer.cpp:48` | coarse bucket rounding + cover traffic | Quantizes sizes into a memorizable histogram; AFPS projects continuously and treats quantization as an artifact to avoid |
| `RTTEqualizer` — `ncp_rtt_equalizer.cpp:73`; `TimeCorrelationBreaker` — `ncp_time_correlation_breaker.cpp:39`; `BehavioralCloak` | per-scalar ACK-delay / CV-jitter / burst-ratio nudges | All act on one scalar at a time; AFPS selects jointly over the whole feature vector via minimax |

Net: AFPS is the only component in the tree that (a) is closed-loop on the
*actual emitted* shapes, (b) optimizes a **worst-case margin across an
ensemble** rather than matching one reference, and (c) constrains
*temporal/cross-feature* structure (IAT autocorrelation, windowed rho, tail
mass) — the precise features ML flow classifiers exploit and that fixed
profiles leave unconstrained.

---

## 4. C++ reference sketch

Style mirrors `MimicryShaper::plan()`: pure math, no new deps (`<random>`,
`<array>`, `<cmath>`, `<vector>`, `<functional>` only). It is a **layer over**
`StatProfile`/`MimicryShaper`, so it composes with the FSM and the catalog
path unchanged. It also **exposes features + outcomes for the AutoPilot
ML-learner** (size/error learning), so the learner can score candidates by
prediction instead of brute-forcing draws in the hot path.

```cpp
// ncp_adversarial_feature_shaper.hpp  (sketch)
#pragma once
#include "ncp_mimicry_stats.hpp"     // StatProfile, MimicryShaper, JointSizeIatSampler
#include <array>
#include <cmath>
#include <cstdint>
#include <functional>
#include <random>
#include <vector>

namespace ncp {

// Window-level feature vector — 1:1 with what an ML flow classifier reads.
// All fields are O(1) from a ring buffer of the last W (size, iat) pairs.
struct FlowFeatureVector {
    double size_mean = 0, size_var = 0, size_skew = 0;
    double size_ks_to_ref = 1;      // vs current StatProfile CDF
    double iat_mean = 0, iat_cv = 0;
    double iat_autocorr1 = 0;       // lag-1 temporal memory (classifier gold)
    double burst_ratio = 1;
    double size_iat_rho = 0;        // EMPIRICAL windowed rho
    double up_down_ratio = 1;
    static constexpr size_t kCount = 10;
    std::array<double, kCount> as_array() const;   // for the learner
};

// Reference population envelope: per-feature mean/spread + distance weight.
struct RefEnvelope {
    static constexpr size_t kFeatures = FlowFeatureVector::kCount;
    std::array<double, kFeatures> mean{};
    std::array<double, kFeatures> stddev{};   // 0 => feature ignored
    std::array<double, kFeatures> weight{};   // diagonal Mahalanobis weight
    // Build analytically from a StatProfile's moments (cheap, offline-free)...
    static RefEnvelope from_profile(const StatProfile& p, const SizeBudget&);
    // ...or from genuine reference captures (preferred; feeds the learner).
    static RefEnvelope from_samples(
        const std::vector<std::pair<double, double>>& genuine_size_iat);
};

struct SizeBudget {
    double max_pad_overhead      = 0.15;  // <=15% extra bytes
    double max_added_latency_ms  = 40.0;
    size_t max_packets_per_window = 512;
};

struct ShapeAction {
    size_t bytes = 1;
    double delay_ms = 0.0;
    double margin = 0.0;   // min over ensemble; higher = harder to classify
    uint64_t epoch = 0;
    bool used_cover = false;
};

// One cheap discriminator's signed margin for a hypothetical feature vector.
struct ComponentMargin { double ks, env, var, cov, burst, ar; };

class AdversarialFeatureProjection {
public:
    struct Config {
        size_t window         = 256;   // feature window W
        size_t candidate_draws = 8;    // C
        double margin_floor   = 0.35;  // escalate below this
        double drift_sigma    = 0.05;  // per-session envelope-center drift
        double tail_allowance = 0.04;  // keep 4% of mass in the tails
        SizeBudget budget;
        uint64_t seed = 0;
    };

    AdversarialFeatureProjection(StatProfile base, RefEnvelope env,
                                 Config cfg);

    // Observe an ACTUALLY SENT (bytes, delay). Advances the ring buffer and
    // the running moments. Called by the sender right after the send.
    void observe(size_t bytes, double delay_ms, bool is_upload);

    // Plan the next shape — the analogue of MimicryShaper::plan().
    ShapeAction plan_next(size_t remaining_payload, size_t mtu_bytes);

    // ---- Exposed for the AutoPilot ML learner (size/error learning) ----
    FlowFeatureVector features() const;
    ComponentMargin    component_margins(const FlowFeatureVector&) const;
    // Realized outcome row the learner trains size/error models on:
    //   {candidate_bytes, candidate_iat, realized_margin, rtt_penalty_ms,
    //    pad_overhead, epoch}
    struct OutcomeRow {
        double bytes, iat_ms, margin, rtt_penalty_ms, pad_overhead;
        uint64_t epoch;
    };
    void set_outcome_sink(std::function<void(const OutcomeRow&)>);
    // Optional: let the learner supply a margin PREDICTOR so plan_next() can
    // score candidates in O(1) instead of recomputing the ensemble per draw.
    void set_margin_predictor(
        std::function<double(const FlowFeatureVector&, const ShapeAction&)>);

    uint64_t epoch() const noexcept { return env_epoch_; }
    void set_envelope(RefEnvelope e) { env_ = std::move(e); ++env_epoch_; }

private:
    // Incremental windowed moments (ring buffer; allocation-free hot path).
    struct Window {
        std::vector<double> size, iat;
        size_t head = 0, count = 0;
        double sum_s = 0, sum_s2 = 0, sum_i = 0, sum_i2 = 0;
        double sum_si = 0, sum_ii_lag = 0;   // cross + lag-1 IAT
        void    push(double s, double i);
        void    moments(FlowFeatureVector&) const;
    };

    double margin_of(const ComponentMargin&) const;   // -> min over ensemble
    bool   within_budget(const ShapeAction&, const SizeBudget&) const;

    StatProfile                     base_;
    RefEnvelope                     env_;
    Config                          cfg_;
    std::mt19937_64                 rng_;
    Window                          win_;
    uint64_t                        env_epoch_ = 0;
    double                          pad_used_ = 0.0;   // rolling, per window
    std::function<void(const OutcomeRow&)> outcome_sink_;
    std::function<double(const FlowFeatureVector&, const ShapeAction&)>
                                    margin_predictor_;
};

} // namespace ncp
```

```cpp
// ncp_adversarial_feature_shaper.cpp  (sketch of the core selection loop)
ShapeAction AdversarialFeatureProjection::plan_next(size_t remaining,
                                                    size_t mtu) {
    const size_t m = mtu ? mtu : 1;
    std::vector<ShapeAction> cand;
    cand.reserve(cfg_.candidate_draws);

    // 1) DRAW candidates from the base profile's joint sampler.
    double s = 0, i = 0;
    for (size_t k = 0; k < cfg_.candidate_draws; ++k) {
        base_.sample_size_iat(rng_, s, i);            // ncp_mimicry_stats.cpp:243
        ShapeAction a;
        a.bytes = static_cast<size_t>(std::llround(s));
        if (a.bytes == 0) a.bytes = 1;
        if (a.bytes > m)   a.bytes = m;
        if (a.bytes > remaining) a.bytes = remaining;
        a.delay_ms = std::isfinite(i) ? std::max(0.0, i) : 0.0;
        a.epoch = env_epoch_;
        cand.push_back(a);
    }

    // 2) PROJECT + 3) SCORE margins for each candidate's hypothetical window.
    auto score = [&](const ShapeAction& a) {
        FlowFeatureVector f = win_.peek_with(a.bytes, a.delay_ms);  // virtual push
        if (margin_predictor_) return margin_predictor_(f, a);       // learner path
        return margin_of(component_margins(f));                      // cold path
    };

    // 4) SELECT argmax_k min_margin, subject to budget.
    ShapeAction best; double best_m = -2.0;
    for (auto& a : cand) {
        if (!within_budget(a, cfg_.budget)) continue;
        a.margin = score(a);
        if (a.margin > best_m) { best_m = a.margin; best = a; }
    }

    // 5) ESCALATE: spend one cover packet if the floor is not met.
    if (best_m < cfg_.margin_floor) {
        ShapeAction cover = best;
        cover.used_cover = true;
        cover.bytes = pick_cover_size(env_, win_, m);   // toward envelope interior
        cover.margin = score(cover);
        if (cover.margin > best_m && within_budget(cover, cfg_.budget))
            best = cover;
        // else: keep best and let the caller count the shortfall (§6 telemetry)
    }

    // 6) OBSERVE is called by the sender after the real send; emit the row.
    if (outcome_sink_) outcome_sink_(OutcomeRow{
        (double)best.bytes, best.delay_ms, best.margin,
        /*rtt_penalty_ms*/ 0.0, pad_used_, best.epoch});
    return best;
}
```

`margin_of()` is `std::min({m_ks, m_env, m_var, m_cov, m_burst, m_ar})`;
`component_margins()` reuses the arithmetic in
`ncp_adversary_tester.cpp:169/198/220` so the numbers stay consistent with the
shadow classifier the team already trusts.

---

## 5. Integration points

- **Base sampler.** Constructed with an existing `StatProfile` (built-ins at
  `ncp_mimicry_stats.cpp:264`–`:326`, or a catalog-derived profile). It
  *wraps* `StatProfile::sample_size_iat` (`:243`); no change to the profile
  format or the signed catalog path.
- **UDP mimicry data path.** In `NcpMimicrySession::send_application`
  (`ncp_mimicry_session.cpp:1087`) the code already chooses between
  `MimicryFsmSession::prepare_data_shape` (`:1114`) and
  `MimicryShaper::prepare_data_shape` (`:1119`). AFPS slots in as a third
  source: it takes the FSM/shaper's `(size, delay)` as its *base draw* and
  returns a projected `ShapeAction`; the epoch field mirrors
  `PreparedShape::profile_epoch` (`ncp_mimicry_stats.hpp:191`) so stale shapes
  are rejected the same way.
- **FlowShaper (TCP/burst path).** AFPS's `plan_next` can drive
  `FlowShaper::shape_sync` (`ncp_flow_shaper.hpp:221`) target size/timing, and
  its escalation lever calls `FlowShaper::generate_dummy` (`:232`).
  `ShapedPacket::delay_before_send` (`:192`) carries the chosen `delay_ms`.
- **Shadow classifier as one margin component.** `component_margins()` borrows
  the metric math from `ncp_adversary_tester.cpp` (`ks_distance` `:169`,
  `timing_coefficient_of_variation` `:198`, `burst_anomaly_score` `:220`), so
  AFPS and the shadow classifier stay numerically aligned rather than
  drifting apart.
- **AutoPilot ML learner (size/error learning) — cooperation, not
  duplication.** AFPS exposes (a) `features()` / `component_margins()` as the
  *state*, (b) `OutcomeRow` via `set_outcome_sink` as the *(action, outcome)*
  training row, and (c) `set_margin_predictor` so the learner can serve
  predicted margins back, collapsing the per-packet `C`-candidate cost to one
  prediction. The learner thus models "margin as a function of (current
  window features, candidate shape)" — the size/error objective — while AFPS
  stays the controller. No member is added behind a build flag; the surface is
  ABI-stable in the style of `ncp_autopilot.hpp:12`–`19`.
- **Threat-model hooks.** Counters for "shortfall below `margin_floor`" and
  "cover packets spent" belong in the existing observability surfaces
  (`docs/MIMICRY_THREAT_MODEL.md:289`) so failures are countable, not silent.

---

## 6. Testability + honest caveats

### 6.1 What is testable (and how)

- **Determinism / replay.** Seeded `rng_`; for a fixed seed and fixed input
  stream, `plan_next()` is bit-identical — same invariant as
  `MimicryShaper::reset` (`ncp_mimicry_stats.cpp:357`). Unit test: replay a
  recorded `(bytes,delay)` sequence.
- **Envelope conformance (POLICY_PASS-style).** For a
  `RefEnvelope::from_samples` over a held-out genuine capture, assert the
  fraction of emitted windows whose `min_k margin ≥ margin_floor` exceeds a
  frozen threshold. This is an *internal* claim (`POLICY_PASS`,
  `docs/MIMICRY_THREAT_MODEL.md:239`), not an external one.
- **Shadow-classifier regression vs baseline.** Feed identical payload
  schedules through (a) plain `MimicryShaper::plan` and (b)
  `AdversaryTester::run_strategy_benchmark`-style evaluation of AFPS output;
  assert AFPS raises `HeuristicScores::aggregate_stealth`
  (`ncp_adversary_tester.hpp:58`) and lowers KS/CoV deviation. Freeze
  thresholds before the run (pre-registration, cf.
  `docs/MIMICRY_CORRELATION_PREREGISTRATION.md`).
- **Budget invariants.** B-1 / B / B+1 style tests on `SizeBudget`: padding
  overhead, added latency, packets/window never exceeded; escalation never
  bypasses the hard cap.
- **Epoch safety.** A shape prepared under epoch N cannot be consumed under
  N+1 (mirror of the `take_data_shape` stale-epoch rule,
  `ncp_mimicry_stats.cpp:403`).

### 6.2 Honest caveats — do not overclaim

- **This is not undetectability.** AFPS reduces the accuracy/confidence of a
  *specific class* of classifier — window-level size/timing statistics against
  a *known* reference population. It does not address byte-content models,
  TLS/QUIC fingerprinting, or raw-byte deep models.
- **`CORRELATION_EQUIVALENT` is not claimed.** A multi-point, long-storage
  adversary (AC4, `docs/MIMICRY_THREAT_MODEL.md:163`) still wins: slow drift
  and tail controls reduce correlation evidence, they do not erase it. The
  drift/"population sampling" argument is the weakest of the four mechanisms —
  a classifier retrained on the drift manifold follows it; it only raises the
  *cost* of pooling, not the possibility.
- **The envelope is a single point of failure.** If `from_samples` is built
  from the wrong population (wrong region, wrong protocol mix, stale capture),
  projection can make us *more* anomalous — sitting at the interior of the
  wrong distribution. Envelope quality must be gated like the reference
  captures in `docs/DPI_EVIDENCE_GATE.md`.
- **Over-constraint is itself a fingerprint.** Always sitting exactly at the
  envelope interior removes the tail events that genuinely occur;
  `tail_allowance` exists to prevent a "too clean" signal, but the tradeoff is
  empirical and unproven here.
- **Cost.** `C`-candidate projection per packet is CPU-bound; mitigated only
  once the learner's `margin_predictor` is warm. Budget/latency overhead is
  real and user-visible on thin links.
- **Proxy ≠ adversary.** The ensemble is our best guess at an unknown
  classifier. Minimax over our own detectors does not bound performance
  against the *actual* censor classifier; any accuracy claim must be a
  scoped `CLASSIFICATION_MATCH` with a fresh evidence pointer, or it defaults
  to `NOT_VERIFIABLE` (`docs/MIMICRY_THREAT_MODEL.md:37`).
