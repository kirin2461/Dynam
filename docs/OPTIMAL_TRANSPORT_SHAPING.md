# Optimal-Transport Size Shaping (W1 + exact quantile)

Status: implemented, unit-tested, and built through CMake in the main tree
(see [Verification status](#verification-status)).

Files:

| Path | Role |
|---|---|
| `src/core/include/ncp_optimal_transport.hpp` | Public API |
| `src/core/src/ncp_optimal_transport.cpp` | W1/KS metrics, `QuantileShaper`, histogram expansion |
| `src/core/include/ncp_flow_shaper.hpp` | `enable_quantile_shaping`, `shaping_*()` accessors |
| `src/core/src/ncp_flow_shaper.cpp` | Actuator: draws target sizes, chunks payloads |
| `src/core/include/ncp_adversary_tester.hpp` | `HeuristicScores::w1_distance`, reweighted `aggregate_stealth()` |
| `src/core/src/ncp_adversary_tester.cpp` | Per-window W1 against `ReferenceProfile` |
| `tests/test_optimal_transport.cpp` | 23 metric/shaper tests |
| `tests/test_flow_shaper.cpp` | 4 integration tests (appended) |
| `tests/test_bypass_features.cpp` | 4 scorer tests (appended) |

---

## 1. Why two metrics instead of one

A statistical traffic classifier compares the observed packet-size
distribution to a reference with some statistic. The module supports two, and
they answer different questions.

### Kolmogorov–Smirnov distance

```
D = sup_x |F_obs(x) - F_ref(x)|
```

`0 <= D <= 1`, scale-free. It is the largest vertical gap between the two CDFs.
It says nothing about *where* the gap is or how far the values moved.

### Wasserstein-1 distance

In one dimension the optimal-transport cost has a closed form:

```
W1(P,Q) = inf over couplings E|X - Y| = integral |F_P(x) - F_Q(x)| dx
```

Measured in bytes for packet sizes. By the Kantorovich–Rubinstein duality,

```
W1(P,Q) = sup { E_P[f] - E_Q[f] : f is 1-Lipschitz }
```

so `W1 <= e` bounds the error of **every** 1-Lipschitz statistic at once: mean,
median, trimmed means, any smoothed rate estimator. A KS bound of 0.05 does not
imply anything about the mean.

### The difference, concretely

Two different metrics carry the name "KS" here, and they react differently to a
uniform shift:

| Metric | Compares | Reaction to a uniform shift |
|---|---|---|
| `ks_distance_samples(a, b)` (`ncp_optimal_transport.cpp:69`) | two samples at all pooled breakpoints | one atom is `1/n`, so a half-step shift gives `1/n` (≈ 0.09 for `n = 11`) |
| `AdversaryTester::ks_distance` (`ncp_adversary_tester.cpp:169`) | a window against the six-point `ReferenceProfile` staircase | +150 bytes → `D = 0.52`; a shift that crosses no boundary → `D = 0` |

Concrete case, shipped as `OptimalTransport.W1_CatchesWhatKSAtFixedRateAllows`:
reference samples evenly spaced 150 bytes apart, observed shifted by 75 (half a
step). `ks_distance_samples` reaches only `1/11 ≈ 0.09`, inside the "good
mimicry" band, while every sample — and therefore the mean — is displaced by
75 bytes. `W1` prices that displacement exactly.

The bucketed scorer has the opposite weakness: it is blind to anything that
does not cross one of its six boundaries. Shift every reference size by −63
bytes (64→1, 128→65, 256→193, 512→449, 1024→961, 1460→1397) and `D = 0.0`
while the mean is off by 63 bytes. Inside `(256, 512]` up to 255 bytes move
uncharged, inside `(1024, 1460]` up to 435. It measures the distance between
two vectors of six prefix masses, not the shape of the distribution — which is
exactly the gap W1 closes.

The module ships the first property as a test
(`OptimalTransport.W1_CatchesWhatKSAtFixedRateAllows`) because it is the single
most important one to keep from regressing. The bucketed blind spot is not
tested yet; see [Known limitations](#7-known-limitations-and-open-items).

---

## 2. API reference

Header: `ncp_optimal_transport.hpp`, namespace `ncp::DPI`.

### `double w1_distance(const std::vector<double>& a, const std::vector<double>& b)`

Exact 1-D Wasserstein-1 distance between two empirical samples.

- Both empty → `0.0`.
- Exactly one empty → `+infinity` (`std::numeric_limits<double>::infinity()`); there is
  no finite transport cost to an empty distribution.
- Input order is irrelevant; both are copied and sorted.
- Complexity `O((n+m) log(n+m))` plus one binary search per merged breakpoint.

The integral is evaluated exactly, not approximated: on the merged set of
distinct sample values both CDFs are step functions, so `integral |F_a - F_b|`
is a finite sum of `width * |F_a(x_i) - F_b(x_i)|`.

### `double w1_distance_sizes(const std::vector<size_t>&, const std::vector<size_t>&)`

Convenience overload for packet sizes; converts element-wise to `double`
(the conversion is explicit to avoid C4244 narrowing warnings on MSVC).

### `double ks_distance_samples(const std::vector<double>& a, const std::vector<double>& b)`

The KS distance between two samples, provided so callers can compare both
metrics on the same inputs. Returns `0.0` if both are empty, `1.0` if exactly
one is.

> **Not a hypothesis test.** No p-value is computed; the Kolmogorov
> distribution is not used. This is a distance, and the rest of the module
> treats it as one.

### `class QuantileShaper`

Streaming, thread-safe generator of target sizes.

```cpp
explicit QuantileShaper(std::vector<size_t> reference_sizes);  // throws std::invalid_argument if empty
size_t next();                        // next target size
void   reset();                       // restart at a fresh block
size_t block_size() const;            // n
const std::vector<size_t>& reference() const;  // sorted ascending, duplicates preserved
size_t emitted() const;
```

Construction sorts the input once; the multiset (including duplicates) is the
shape. `next()` walks a permutation of that multiset:

- A **complete block** of `block_size()` calls emits exactly the reference
  multiset once. The empirical distribution of a complete block is therefore
  *identical* to the reference, so `W1 = 0` and `KS = 0` — exactly, not
  approximately.
- A **partial block** is a prefix of a permutation, i.e. sampling without
  replacement. No size can appear more often than the reference contains it.
- Each epoch gets a fresh Fisher–Yates permutation, seeded from
  `randombytes_uniform` (libsodium). Order within a block does not affect any
  marginal statistic, but a *fixed* order would be a learnable repeating
  pattern — a monotone ramp of sizes is a worse shape than no shaping at all.

`reset()` clears the counter and returns to the start of a fresh block.
Concurrency: `next()` is serialised by an internal mutex; `reference()` is
lock-free for callers because `ref_` is immutable after construction (it is
non-`const` only because the constructor sorts it).

### `std::vector<size_t> expand_size_histogram(const std::vector<std::pair<size_t,double>>&, size_t resolution = 256)`

Turns a weighted size histogram `{size, weight}` into a reference multiset of
roughly `resolution` entries.

- Buckets with non-positive weight are skipped; a fully degenerate histogram
  yields one entry per listed bucket.
- Each surviving bucket contributes `round(share * resolution)` entries, at
  least one, so every listed size stays represented.
- Output is sorted ascending.

Rounding means the realised proportions differ from the input weights by at
most `#buckets / resolution` (≈ 0.023 for the six-bucket web profile at
resolution 256). Tests account for this with a 0.03 tolerance.

---

## 3. `FlowShaper` integration

### Configuration

```cpp
struct FlowShaperConfig {
    bool enable_size_shaping    = true;   // master switch for reshape_size()
    bool enable_quantile_shaping = true;  // exact block replay vs i.i.d. sampling
    // ...
};
```

`enable_quantile_shaping = false` restores the legacy behaviour: each target
size is drawn independently from the histogram, so only the *expected*
distribution matches and any finite window deviates by sampling noise.

The shaper is rebuilt whenever the size distribution changes — at construction
and in `update_config()` (which also fills in profile defaults). Rebuild takes
the config write lock, so it cannot race a draw.

### Public additions

```cpp
size_t shaping_block_size() const;          // 0 when quantile shaping is off
std::vector<size_t> shaping_reference() const;  // copy of the replayed multiset
```

Both take a shared lock on the config. `shaping_reference()` is a *copy*
because `QuantileShaper::reference()` returns a reference into the shaper,
which `update_config()` can replace.

### Chunking rule

`reshape_size(packet)` emits one packet per shaper draw:

1. `target = select_target_size()` (a shaper draw).
2. Take `min(target, remaining)` bytes of payload.
3. If fewer than `target` bytes remain, pad with CSPRNG bytes to exactly
   `target`.
4. Repeat until the payload is exhausted.

Consequences:

- **Every emitted packet is exactly one target size.** This is what makes the
  block guarantee hold for split packets too. Drawing one size per *source*
  packet and repeating it would deposit many copies of a single size into the
  empirical distribution and destroy the shape being targeted.
- A payload larger than its draw is split, and each chunk consumes its own
  draw, so the sizes stay in the reference multiset.
- `stats.packets_split` counts source packets that produced more than one
  chunk, not chunks.

**Chunk cap.** At `kMaxShapedChunks = 256` chunks the loop stops and emits the
remainder as one padded packet of at least the remaining size. This bounds work
for pathological inputs (a reference of tiny sizes against a multi-megabyte
payload) and is the only path that can emit a size not equal to a draw.

### Sequence semantics

`select_target_size()` is public and **consumes a draw**. External callers
advance the block sequence; a caller mixing its own `select_target_size()` calls
with `shape_sync()` will disturb the block boundary. The block guarantee is
stated in *emitted packets*, not source packets.

Also note: `reshape_size()` acquires the config read lock once per draw. A
concurrent `update_config()` can therefore land between draws of a single
source packet, so one source packet may straddle two reference configurations.
Each draw is still a valid size from one of them, but block continuity is not
guaranteed across a configuration change. This only matters if
`update_config()` is called while shaping is live.

### Threading

- `next()` serialises on the shaper mutex; `select_target_size()` holds the
  config read lock while doing so.
- `shape_sync()` takes a snapshot of the config under a shared lock and then
  works from the snapshot, except for size draws.
- `impl_->quantile` is written only under the config write lock.

---

## 4. `AdversaryTester` integration

`HeuristicScores` gains one field and keeps the weight vector summing to 1.0:

| Component | Weight before | Weight after |
|---|---|---|
| entropy | 0.25 | 0.25 |
| chi-squared | 0.25 | 0.25 |
| KS (`ks_distance`) | **0.15** | **0.10** |
| W1 (`w1_distance`) | — | **0.05** |
| size variance ratio | 0.10 | 0.10 |
| timing CoV | 0.15 | 0.15 |
| burst anomaly | 0.10 | 0.10 |

The W1 component is

```cpp
w = 1.0 / (1.0 + std::fabs(w1_distance) / W1_SCALE_BYTES);   // W1_SCALE_BYTES = 75.0
```

so 75 bytes of mean displacement costs half of that term, and the term is
saturating rather than linear — a 3 kB displacement cannot dominate the score.

### Reconstructing the reference

`ReferenceProfile` stores only a CDF at bucket boundaries (`web_browsing`:
boundaries 64/128/256/512/1024/1460, CDF 0.35/0.52/0.68/0.82/0.93/1.0), not
weights. The per-window W1 is computed against the distribution that CDF
literally encodes: consecutive CDF differences become the mass of each boundary
value, which is then expanded with `expand_size_histogram(hist, 256)`.

**This places each bucket's mass at its upper boundary**, which biases W1
upward against the true underlying distribution. A browser mode at 52 bytes is
priced as 64. The bias is bounded by one bucket width, and the 300-byte
threshold in `AdversaryTesterW1.ReferenceShapedFlowScoresLow` is set with that
in mind: a flow emitting the `web_browsing` proportions measures ≈ 264 bytes,
not ≈ 0. A constant 1460-byte flow measures ≈ 1088.

W1 is recomputed on every window evaluation. It is **not** part of
`SizeErrorFeatures`, so the online learner's 8-feature model is unchanged.

### Backward compatibility

`aggregate_stealth()` is a public scoring function, so the reweighting changes
every caller's score:

- A flow that was already shape-accurate loses at most 0.05 (the maximum the
  W1 term can contribute).
- A flow with displaced sizes gains a small penalty on top of the reduced KS
  share.

Any project-side threshold calibrated against the old weights should be
re-checked. `to_feedback()`'s 0.5 detection cut-off is unchanged.

---

## 5. Guarantees and non-guarantees

| Claim | Status |
|---|---|
| A complete block of `block_size()` **emitted** packets reproduces the reference multiset exactly | Guaranteed, provided no source packet hit the 256-chunk cap |
| `W1 = 0` between a complete block and `shaping_reference()` | Guaranteed by the above |
| Partial blocks never over-represent a size | Guaranteed (sampling without replacement) |
| Emitted order is a fresh permutation per block | Guaranteed (Fisher–Yates per epoch) |
| Every emitted packet is a reference size | Guaranteed except the chunk-cap tail, which is padded up |
| `W1` against a `ReferenceProfile` is zero for a reference-shaped flow | **Not** guaranteed: the CDF reconstruction is discretised to bucket boundaries; expect up to one bucket width |
| `QuantumShaper` output matches `ReferenceProfile`-based scoring | **Not** guaranteed: `SizeDistribution` and `ReferenceProfile` are two independent size catalogs and do not agree (see §7) |
| KS or W1 come with significance levels | Not implemented; both are distances only |

---

## 6. Cost

| Operation | Cost |
|---|---|
| `w1_distance(a, b)` | `O((n+m) log(n+m))` time, `O(n+m)` memory (two copies + merged points) |
| `ks_distance_samples(a, b)` | same shape |
| `QuantileShaper::next()` | `O(1)` amortised; `O(n)` once per block for the permutation |
| `QuantileShaper` construction | `O(n log n)` sort |
| `reshape_size()` | one draw + one copy/pad per emitted packet |

Memory: one `size_t` per reference entry (256 by default), plus one permutation
of the same size.

`AdversaryTester::evaluate_window_locked()` now does one extra sort of the
window's sizes per evaluation. Windows are `window_packets` long (default is
small enough that this is not measurable against the entropy/chi-squared work
already done per packet), but it is not free at very large window sizes; the
existing `TODO(R13)` note about pre-sorting `ks_distance()` applies to W1 as
well.

---

## 7. Known limitations and open items

1. **Two size catalogs.** `SizeDistribution` (52/150/350/580/1200/1460) feeds
   the shaper; `ReferenceProfile` (64/128/256/512/1024/1460) feeds the scorer.
   They describe the same traffic class with different numbers, so a perfectly
   shaped flow still measures `W1 ≈ 264` against the scorer's reference.
   Unifying them — or deriving both from one catalog — would take that residual
   to zero and is the single highest-value follow-up.
2. **W1 is not a learner feature.** Adding it would change
   `SizeErrorFeatures` dimensionality and invalidate existing weights; that is
   a deliberate migration, not a drop-in.
3. **Bucket-boundary atoms.** The reference reconstruction assumes each
   bucket's mass sits at its upper boundary. A uniform-within-bucket assumption
   would give a different and arguably smaller bias, but is more assumption,
   not less.
4. **No block atomicity across config changes.** See §3, "Sequence semantics".
5. **Chunk-cap tail.** One emitted packet per pathological source packet may
   exceed the drawn size.
6. **Residual W1 for a block-exact flow is pinned by a threshold, not by
   design.** `ReferenceShapedFlowScoresLow` encodes the current ≈ 264-byte
   residual as `< 300`; item 1 is what would remove the residual and the
   threshold with it.
7. **Bucketed KS is blind inside a bucket.** `AdversaryTester::ks_distance`
   samples both CDFs only at the six reference boundaries, so a displacement
   that crosses none of them scores `D = 0` (see §1). A test pinning that
   behaviour — and the fact that W1 charges it — is not written yet.

---

## 8. Test map

### `tests/test_optimal_transport.cpp` (23 tests)

| Group | What it pins down |
|---|---|
| `OptimalTransport.*` | W1 equals the gap for point masses; translation shifts W1 by exactly the shift; a hand-computed 2-point case; symmetry; empty-input conventions; sizes overload equivalence; input-order invariance; W1 equals the mean sorted displacement for equal-size samples; the KS-vs-W1 discrepancy |
| `QuantileShaper.*` | empty reference throws; block size and stored reference; a full block reproduces the multiset exactly (`W1 == 0`); consecutive blocks are exact and differently ordered; `reset()`; partial-block multiplicity bound; single-element reference is constant |
| `ExpandSizeHistogram.*` | proportions within tolerance; zero-weight buckets dropped; empty input; sorted output |

### `tests/test_flow_shaper.cpp` (4 added)

| Test | Property |
|---|---|
| `QuantileShaping_OneBlockMatchesReferenceCdf` | empirical CDF of one block vs an **independently recomputed** CDF from `config.size_dist.buckets` (not via `expand_size_histogram`); plus exact multiset equality with `shaping_reference()` and `W1 == 0` |
| `QuantileShaping_SplitPacketsEmitOnlyReferenceSizes` | every chunk of a 4096-byte payload is a reference size; no payload bytes are lost |
| `QuantileShaping_DisabledReportsNoBlock` | the flag actually disengages the shaper |
| `QuantileShaping_TwoBlocksSameMultisetDifferentOrder` | identical multiset, different permutation |

### `tests/test_bypass_features.cpp` (4 added)

| Test | Property |
|---|---|
| `AdversaryTesterW1.UniformMaxSizeFlowScoresFarFromReference` | constant 1460-byte flow measures `W1 > 800` |
| `AdversaryTesterW1.ReferenceShapedFlowScoresLow` | a flow at reference proportions measures `W1 < 300` |
| `AdversaryTesterW1.UniformPaddingScoresWorseThanReferenceMix` | the same two flows compared in one unit: uniform > 2x mixed |
| `HeuristicScoresW1.DisplacedSizesLowerStealth` | the weight arithmetic: 600 bytes of displacement costs exactly `0.05 * (1 - 1/9)` of `aggregate_stealth()` |

### Falsification

Validated by rebuilding against a sabotaged pair of files: a copy of the header
with `W_W1` set to `0.0`, and a copy of `ncp_adversary_tester.cpp` with the
22-line W1 computation block removed. Result:

```
[  FAILED  ] AdversaryTesterW1.UniformMaxSizeFlowScoresFarFromReference
[  FAILED  ] AdversaryTesterW1.UniformPaddingScoresWorseThanReferenceMix
[  FAILED  ] HeuristicScoresW1.DisplacedSizesLowerStealth
[  PASSED  ] 48 tests.
```

`ReferenceShapedFlowScoresLow` **passed** in that run, and that is expected: it
asserts an upper bound, and a stubbed `w1_distance` of 0 satisfies `0 < 300`.
A bound cannot distinguish "correctly low" from "never computed". That is
exactly why `UniformPaddingScoresWorseThanReferenceMix` exists — it compares the
two flows and fails on `0 vs 0`, as the run above shows.

Any future change to the weights or the reference reconstruction should repeat
this two-file sabotage. A test that passes both with and without the term is
not testing the term.

### Falsification of the shaper guarantee

Second sabotage, on the actuator: a copy of `ncp_flow_shaper.cpp` with
`select_target_size()` forced to ignore the shaper (`if (false && impl_->quantile)`,
i.e. legacy i.i.d. sampling). Result:

```
[  FAILED  ] FlowShaperTest.QuantileShaping_OneBlockMatchesReferenceCdf
[  FAILED  ] FlowShaperTest.QuantileShaping_TwoBlocksSameMultisetDifferentOrder
[  PASSED  ] 57 tests.
```

Under i.i.d. sampling the block CDF deviates by up to 0.055 (over the 0.03
tolerance) and the multiset equality fails outright. The exact-multiset
assertion is the one that is *deterministically* sensitive: an i.i.d. sampler
could in principle land inside a 0.03 CDF band on a lucky seed, but it cannot
reproduce a 256-entry multiset.

The same methodology was applied earlier to the Geneva overhead term, where the
first version of the ranking test passed on a tie because `max_element` returns
the first of equal maxima. Two tests defeated that; see
`docs/ARCHITECTURE.md`.

---

## 9. Tuning knobs

| Constant | Where | Default | Effect |
|---|---|---|---|
| `resolution` | `expand_size_histogram` | 256 | block length; larger = finer proportions, longer warm-up before the shape is exact |
| `enable_quantile_shaping` | `FlowShaperConfig` | `true` | exact block replay vs i.i.d. sampling |
| `enable_size_shaping` | `FlowShaperConfig` | `true` | master switch |
| `kMaxShapedChunks` | `ncp_flow_shaper.cpp` | 256 | bound on chunks per source packet |
| `W1_SCALE_BYTES` | `HeuristicScores::aggregate_stealth` | 75.0 | bytes of displacement that halve the W1 term |
| `W_W1` | same | 0.05 | maximum contribution of W1 to the stealth score |

---

## 10. Verification status

Built and run through the tree's own CMake project (`build-win`, MSVC 18.13 /
CMake 4.3.1, `-G "Visual Studio 18 2026" -A x64`, vcpkg `x64-windows`,
`Release`):

| Suite | Result |
|---|---|
| `ncp_core`, `ncp-cli`, all test targets | build |
| `ctest -C Release` | 8/8 pass |
| `ncp_tests` — `OptimalTransport.*`, `QuantileShaper.*`, `ExpandSizeHistogram.*`, `AdversaryTesterW1.*`, `HeuristicScoresW1.*` | 29/29 pass |
| `ncp_tests` — full binary (1413 tests) | 1405 pass, 8 skipped (I2P needs a SAM router), 0 fail |

Two pre-existing tree defects had to be fixed for the suite to run at all:

- `i2p.cpp:1472,1710` passed `void*` to Winsock `recv()`, which wants `char*`.
- Hand-built `NcpMimicrySession::Config` fixtures omitted `server_identity`, so
  with `require_server_identity = true` (the default since the identity-signed
  handshake landed) every such handshake failed as "did not complete". The
  shared key now lives in `tests/test_identity.hpp`.

Reproduce:

```
cmake --build build-win --config Release
build-win\bin\Release\ncp_tests.exe --gtest_filter=OptimalTransport.*:QuantileShaper.*:ExpandSizeHistogram.*:AdversaryTesterW1.*:HeuristicScoresW1.*
```

The falsification runs in §8 were done in the earlier isolated harness
(`%TEMP%\opencode\geneva-iso`, MSVC 14.52); the tree build replaces only the
"does it compile and link" question, not those sabotage results.
