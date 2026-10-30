# Preregistration: Correlation-Resistance Evaluation of Mimicry Profiles (G0)

This document **preregisters** the evaluation of whether Dynam's mimicry
stack resists an observer who performs *traffic correlation across two
network taps*. It is written before any confirmatory data collection. Its
purpose is to freeze hypotheses, features, detectors, endpoints, statistical
procedures, and decision rules so that later results cannot be tuned into
existence. Deviations from this document must be logged and labeled as
exploratory.

**Status of repo support.** The measurement and feature *sources* exist in
the repository (see §3); a dedicated two-tap correlation harness with an
AUC/TOST evaluation pipeline does **not** yet exist (a repository-wide
search for `AUC`/`TOST` finds only unrelated matches). Building that harness
is part of executing this preregistration, not a prerequisite for it.

Related documents: `docs/DPI_EVIDENCE_GATE.md` (external-classifier evidence
rules this preregistration inherits), `docs/MIMICRY_THREAT_MODEL.md`,
`docs/MIMICRY_TRANSITION_SECURITY_SPEC.md`.

---

## 1. Scope and non-claims

- **In scope:** an observer who sees packet metadata (sizes, timings,
  directions; headers where visible) on **both** links of a relayed flow and
  tries to decide whether the two observed flows are the same session
  (flow correlation / confirmation), and whether the relayed traffic is
  Dynam-protected (detection).
- **Out of scope / explicitly not claimed:**
  - **No universal invisibility.** No result here may be reported as "Dynam
    is undetectable" or "invisible to DPI". Claims are limited to the frozen
    detector, the frozen feature set, the tested profiles, and the tested
    network conditions, at the measured statistical power.
  - Payload-content analysis, endpoint compromise, active probing, and
    protocol-fingerprint attacks outside the frozen detector.
  - Any detector retrained or re-featured after confirmatory data exists is
    a new study requiring an amendment to this preregistration.

## 2. Topology

```
        Tap T1 (client side)                Tap T2 (destination side)
              |                                   |
   client  ======= link A =======  relay  ======= link B =======  destination
   (Dynam)                         (relay)                         (server)
```

- The client runs Dynam (NCP + mimicry + PortHop + profile transitions);
  the relay forwards; the destination is an ordinary server.
- **Tap T1** observes all packets between client and relay.
- **Tap T2** observes all packets between relay and destination.
- The adversary model is a *passive observer with access to both taps*
  (the standard flow-correlation adversary; cf. the motivation documented in
  `src/core/include/ncp_time_correlation_breaker.hpp`: low-latency
  correlation with CV < 0.1 of inter-event gaps allows >90% linking
  accuracy; the defense target is to deny that signal).
- A *session pair* is one capture at T1 plus one capture at T2 over the same
  wall-clock window. Pairs are either **linked** (same underlying session)
  or **unlinked** (independent sessions), with ground truth known to the
  experimenters but hidden from the detector.
- Reference (control) condition: the same topology and traffic mix with
  Dynam's mimicry/shaping disabled (plain protected transport), so the
  endpoint measures the *marginal* effect of the mimicry layer rather than
  of encryption alone.

## 3. Frozen feature set

Features are computed per capture from packet metadata only. The list below
is **frozen**; adding or removing a feature after confirmatory data exists
invalidates confirmatory claims.

**Per-tap features** (computed independently on T1 and T2 captures):

1. Packet-size summary statistics: mean, stddev, skew, selected quantiles,
   and a fixed histogram over the wire size range (the clamp envelope used
   by `StatProfile` / `JointSizeIatSampler::kMaxSizeBytes` in
   `src/core/include/ncp_mimicry_stats.hpp` defines the bin range).
2. Inter-arrival-time (IAT) summary: mean, stddev, **coefficient of
   variation** (the same CV the `TimeCorrelationBreaker` defends,
   `src/core/include/ncp_time_correlation_breaker.hpp`), quantiles.
3. Size↔IAT joint statistics: Pearson/Spearman correlation of consecutive
   (size, IAT) pairs (the coupling the `JointSizeIatSampler` encodes,
   `ncp_mimicry_stats.hpp`).
4. Direction ratio and burstiness (packets per fixed window, max/mean burst
   length).
5. PortHop surface features: count of distinct destination ports per window
   and hop-rate estimate (`src/core/include/ncp_porthop.hpp` hop schedule).

**Cross-tap (correlation) features** (computed per candidate T1×T2 pairing):

6. Cross-correlation of the two per-direction packet-time series at a fixed
   lag grid (peak value and peak lag).
7. Mutual information / Spearman correlation between the two packet-size
   sequences after fixed resampling to a common time grid.
8. IAT-sequence correlation (the classic flow-correlation feature).
9. Cross-layer coherence mismatches visible at T1 (the check battery of
   `src/core/include/ncp_cross_layer_correlator.hpp`:
   `MAC_VS_TTL`, `TTL_VS_OS_PROFILE`, `TCP_WINDOW_VS_PROFILE`,
   `TLS_VS_HOSTNAME`, `TLS_VS_USER_AGENT`, `MSS_VS_MTU`, `IPV6_VS_PROFILE`)
   exported as per-check mismatch confidence values. The correlator's
   `auto_fix` behavior is disabled during capture analysis; checks are used
   read-only as features.

**Excluded from features:** payloads, plaintext headers protected by header
protection, any feature derived from ground-truth session labels, and any
feature whose definition requires tuning on the confirmatory set.

**Measurement sources (existing, unchanged by this preregistration):**
`scripts/lab/metrics.py` (per-run timing/counter collection),
`scripts/lab/pcap_assert.py` (pcap assertions),
`scripts/lab/udp_dpi_gate.py` (external nDPI classification — may be used as
a *secondary* classifier verdict, not as the correlation detector),
`src/core/src/ncp_cross_layer_correlator.cpp` (coherence checks),
`src/core/src/ncp_mimicry_stats.cpp` (profile distributions),
`src/core/src/ncp_time_correlation_breaker.cpp` (CV statistics).

## 4. Frozen detectors

- **Reference detector R:** logistic regression on features 6–8 only (the
  classic cross-tap correlation signal), with fixed regularization, trained
  on the tuning set. R represents the baseline adversary.
- **Candidate detector C:** gradient-boosted trees (or an equivalently
  specified fixed-capacity model) on the full frozen feature vector of §3,
  hyperparameters fixed from the tuning phase only.
- Both detectors output a per-pair score; the score threshold is irrelevant
  because the endpoint is AUC (ranking quality), not a decision rate.
- Detector code, seeds, and hyperparameters are frozen in the harness
  repository state referenced by the confirmatory report.

## 5. Hypotheses and primary endpoint

Let AUC_D(C) be the candidate detector's AUC for distinguishing linked from
unlinked session pairs under the **Dynam** condition, and AUC_R the same
under the **reference** condition (mimicry disabled). DeLong-style paired
comparison on the same pairs.

- **Primary endpoint:** Δ = AUC_R − AUC_D(C), the AUC difference of the
  candidate detector between the reference and the Dynam condition.
- **H1 (equivalence of detectability):** the mimicry layer reduces
  correlation-detectability to within a negligible margin of a target bound.
  Operationally tested as **TOST (two one-sided tests)** on Δ at the
  equivalence margin:
  - **Margin: ±0.05 AUC around the preregistered target Δ₀.** Both the
    target Δ₀ (minimum AUC drop the study claims) and the acceptability of
    the ±0.05 band **must be approved by the security review owner before
    any confirmatory capture is collected**; the approval and its rationale
    are recorded as an amendment to this document. Without that approval the
    confirmatory phase must not start.
  - Equivalence/non-inferiority conclusion requires both one-sided tests to
    reject at the preregistered alpha.
- **Secondary endpoints:** AUC_D(R) (reference detector under Dynam),
  per-feature ablation AUCs, external nDPI verdict agreement
  (per `docs/DPI_EVIDENCE_GATE.md` capture rules), detection AUC under each
  individual mimicry profile and during an in-flight profile transition.

## 6. Alpha, power, sample size

- **Alpha:** 0.05 per one-sided TOST component (equivalently a 90% two-sided
  CI for Δ must lie inside the approved margin).
- **Target power:** ≥ 0.80 (0.90 preferred) for the primary TOST.
- **Sample size:** derived from a **pilot** phase (independent, small-N
  captures) that estimates the variance of paired AUC differences; the
  required number of independent session pairs N is computed from the pilot
  with a standard AUC-variance estimator and is recorded as an amendment
  before confirmatory collection. Pilot data may not be pooled into the
  confirmatory set.
- **Unit of independence:** one session pair (T1 capture + T2 capture).
  Repeated runs of one session, slices of one PCAP, and derived corruptions
  are **not** independent evidence (same rule as the DPI evidence gate,
  `docs/DPI_EVIDENCE_GATE.md` §Capture requirements). Each capture gets a
  unique session id and a SHA-256 manifest entry.

## 7. Tuning vs. confirmatory data

- **Tuning set:** collected first; used for training both detectors, feature
  sanity checks, ablations, and the pilot-based power calculation. Unlimited
  iteration is allowed here, and all of it is exploratory.
- **Confirmatory set:** collected after (a) features, detectors,
  hyperparameters, and thresholds are frozen, (b) the Δ₀/±0.05 margin
  approval is recorded, and (c) N is fixed. Collected with non-overlapping
  sessions, fresh relay/client hosts or at minimum fresh key material and
  session ids, and — where feasible — on different days/network conditions
  than the tuning set.
- **No reuse:** no session, capture, or derived artifact may appear in both
  sets. Any accidental overlap is handled per §8 exclusions.
- **Blinding:** confirmatory captures are labeled by an operator different
  from the analyst where practical; the analysis script consumes a blinded
  manifest and reveals labels only at evaluation.

### 7.1 Confirmatory lock procedure (mandatory)

The confirmatory phase is blocked until a named security review owner and an
independent data operator sign a machine-readable **lock artifact**. The lock
must be created after the pilot-based power calculation but before any
confirmatory capture, and must contain:

1. UTC timestamp and the identities/roles of the approving security owner and
   data operator (the current `Owner: TBD` state cannot satisfy this rule);
2. approved Δ₀, equivalence margin, alpha, target power, planned N, profile
   list, clock-alignment tolerance, and lag-grid resolution;
3. SHA-256 hashes of the detector/feature/analysis source, frozen
   hyperparameters and seeds, capture manifests, and the effective
   configuration/catalog used for the study;
4. explicit paths or object-store identities of the physically separate
   tuning and confirmatory datasets, plus the expected confirmatory session-ID
   namespace;
5. a declaration that no confirmatory capture existed when the lock was
   signed.

The artifact is stored read-only with the study evidence and referenced by
hash in the confirmatory report. Any later change to a locked item starts a
new study/amendment and requires a fresh, non-overlapping confirmatory set;
it is never a silent edit. The collector verifies before every capture that
its session ID and output location belong to the locked confirmatory
namespace. The analyst must not have write access to the raw confirmatory
store, and the data operator must not change detector code or statistical
parameters.

Tuning/pilot and confirmatory data are separated by **different capture
sessions, directories/buckets, manifests, and access credentials**, not merely
by a flag in one combined file. Host/key rotation alone is not a substitute
for this physical/logical access boundary. Any crossover, write-after-lock,
or missing lock field invalidates confirmatory status and leaves the result
exploratory.

## 8. Exclusion criteria (preregistered)

A capture or session pair is excluded only if, before unblinding:

1. the capture is empty, truncated, or contains non-UDP contamination where
   the protocol under test is UDP (same spirit as the TShark non-emptiness /
   protocol-purity check of the DPI gate);
2. the session failed to establish (no completed E2E handshake), logged at
   capture time;
3. the two taps' clocks cannot be aligned within the preregistered tolerance
   (clock skew makes cross-tap features meaningless);
4. relay malfunction (crash, packet-forwarding outage) is in the capture log;
5. a manifest hash mismatch or duplicated session id is detected.

All exclusions are counted and reported with reasons; excluded pairs are
never replaced selectively after labels are known.

## 9. Multiplicity

- The primary endpoint (§5) is tested once at the preregistered alpha.
- Secondary endpoints (per-profile AUCs, per-feature ablations, nDPI
  agreement) are corrected with **Holm–Bonferroni** across the family of
  secondary tests actually reported.
- Any additional test run on the confirmatory set is labeled exploratory and
  carries no confirmatory claim regardless of p-value.

## 10. Decision rules

- **SUPPORTED (within margin):** TOST significant at alpha on the
  confirmatory set with N achieved ≥ planned → "for the frozen detector and
  feature set, Dynam's mimicry reduced cross-tap correlation detectability
  to within the approved margin of the target", with the CI reported.
- **REFUTED:** the CI excludes the margin on the harmful side → the
  detectability reduction claim is rejected for this detector/feature set.
- **INCONCLUSIVE:** the achieved sample size is below the powered N, or
  post-hoc power is < 0.80, or exclusions exceed 20% of collected pairs →
  the result is reported as **INCONCLUSIVE (underpowered)** and no claim in
  either direction is made. A follow-up study requires its own amendment.
- Under no outcome may a report state or imply universal invisibility,
  immunity to DPI, or resistance to detectors outside the frozen set (§1).

## 11. Open decisions (to be resolved before confirmatory collection)

1. **Δ₀ and margin approval:** the exact target AUC drop Δ₀ and acceptance
   of the ±0.05 TOST band require sign-off by the security review owner.
   *(Owner: TBD; status: OPEN — blocks confirmatory phase.)*
2. **Harness implementation:** the two-tap capture/alignment pipeline and
   the DeLong/TOST evaluation code do not exist yet; they must be built and
   validated on synthetic data before the pilot. *(Status: OPEN.)*
3. **Profile list:** the exact set of mimicry profiles (from
   `docs/MIMICRY_PROFILES.md` / the reference profile catalog) included in
   the secondary per-profile family must be enumerated before tuning data
   collection. *(Status: OPEN.)*
4. **Clock-alignment tolerance** for exclusion rule 8.3 and the tap lag grid
   resolution for feature 6. *(Status: OPEN; to be fixed with the pilot.)*
5. **nDPI role:** whether the external classifier verdict is reported as a
   secondary endpoint or only as a sanity control. *(Status: OPEN.)*
