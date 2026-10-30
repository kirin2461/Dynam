# Stateful QUIC/RTC Mimicry Profiles — Transition Protocol v2 Design

Status: design (no code yet). Audience: implementation agent.
Scope: the final stage of the Dynam mimicry subsystem — seamless per-session
profile transitions whose targets may be **arbitrary outer masks** (including
non-length-prefixed, session-stateful QUIC/RTC-shaped masks), plus the
stateful profile models themselves.

Verified against (all landed, tested, reviewed):
- `src/core/include/ncp_profile_transition.hpp` / `src/core/src/ncp_profile_transition.cpp`
  (transition protocol v1; SessionProfileContext inner PD framing; codec;
  retransmission; grace; effective_counter fencing).
- `src/core/src/ncp_mimicry_session.cpp` / `ncp_mimicry_session.hpp`
  (adapter; synchronous `active_mimic` swap in `on_profile_activation()`;
  RX candidates = active + grace-old; `is_transition_target_mimic()`
  GENERIC-only gate at both `start_profile_transition()` overloads and the
  responder resolver gate).
- `src/core/include/ncp_mimicry_fsm.hpp` (MimicryFsmSession; phases;
  per-state overrides; timing-only integration).
- `src/core/include/ncp_reference_profile_catalog.hpp` (ProfileDescriptor,
  ProtocolFamily QUIC=3/WEBRTC=5/STUN=10, signed+versioned).
- `src/core/include/ncp_capabilities.hpp` (`NCP_CAPS_FEATURE_PROFILE_TRANSITION_V1
  = 0x01` in `reserved[0]`; `negotiate()` already ANDs all of `reserved[0]`).
- `src/core/include/ncp_mimicry.hpp` + `src/core/src/mimicry.cpp`
  (MimicProfile enum; GENERIC_UDP/GENERIC_TCP share the 4-byte length-prefix
  format; QUIC_INITIAL is self-describing: DCID-derived XChaCha20 key,
  per-packet random DCID, min-1200B padding; SKYPE/ZOOM length-prefixed;
  DNS/TLS/BitTorrent/WebSocket structured).

---

## 0. Root cause restated (why v1 is GENERIC-only)

The adapter wraps outbound control with `active_mimic`
(`ncp_mimicry_session.cpp` control-outbound handler, line ~296) and swaps
`active_mimic` synchronously at local activation (`on_profile_activation()`),
i.e. the initiator swaps **before** its COMMIT+CONFIRM are emitted
(`ProfileTransitionManager` READY case sends COMMIT+CONFIRM immediately after
`activate()`). A responder still in READY decodes only with the OLD mask.
GENERIC_UDP/GENERIC_TCP happen to share the identical 4-byte length-prefix
format, so a new-mask COMMIT cross-unwraps correctly. Any non-length-prefixed
target (QUIC_INITIAL, STUN-style, TLS, DNS) makes COMMIT undecodable → the
responder never activates, the initiator keeps the new profile → silent
permanent divergence. Hence the fail-fast gate.

The defect is not the mask set; it is that **control decodability depends on
outer-mask compatibility across the switch**. v2 removes that dependency.

---

## 1. Q1 — Transition protocol v2 for arbitrary masks

### 1.1 Options considered

**Option A — control-in-stable-mask.** Every control datagram of an
outstanding transition is wrapped in the mask that was stable when the
transition started, until finalize/abort. Data TX switches to the new mask at
local activation. Both sides add `pending_mimic` as an RX candidate no later
than the instant the peer can first transmit it.

**Option B — pending-candidate-only.** Keep v1 activation timing AND v1
"control wrapped with `active_mimic`" behavior; both sides merely add
`pending_mimic` as an RX candidate while a transition is outstanding, so the
new-mask COMMIT/CONFIRM decodes.

### 1.2 Decision: **Option A** (with v1 data-TX timing retained)

Option B works on the happy path, but it keeps the fundamental coupling this
stage exists to remove: control liveness depends on the *pairwise*
cross-decodability and false-positive behavior of two arbitrary mask formats,
for every present and future mask, under retransmission, duplication and
corruption. Each new stateful mask would require a fresh decodability proof
against every other mask. Option A reduces the correctness obligation to one
local rule — *control never changes mask mid-transition* — which holds for
any target mask by construction, with no cross-mask reasoning at all.

Within Option A we keep the **v1 data-TX timing** (data switches to the new
mask at local activation: initiator on READY receipt, responder on COMMIT
receipt) instead of delaying data TX until peer confirmation. Rationale:

- The pending RX candidate (required by Option A anyway) already covers early
  new-mask data with zero gap (see the causality argument in §1.5), so the
  delayed-TX variant buys no decodability.
- Delayed TX would add a third mask-schedule state ("activated but TX-old")
  to the adapter and a second switch point per transition, doubling the
  transient-window surface that §2 must bound.
- Keeping data timing identical to v1 maximizes code/test reuse: the inner
  `SessionProfileContext` (PD framing, epochs, grace, counters) and the
  `ProfileTransitionManager` FSM are **byte-for-byte untouched** by v2. v2 is
  a pure adapter-layer outer-mask scheduling change.

### 1.3 v2 mask schedule (exact rules)

Terminology per endpoint: `stable_mimic` = mask active when the transition
entered PREPARE (initiator) / READY (responder); `pending_mimic` = resolved
target mask; `active_mimic` = current data-TX mask; `old_mimic` =
pre-activation mask kept as grace decoder.

1. **C1 (control mask pin).** While a transition is outstanding
   (`state != IDLE`), every outbound transition-control datagram — PREPARE,
   READY, COMMIT, CONFIRM, ABORT, all retransmissions, and side-band
   busy/unknown-profile ABORTs — is wrapped with `transition_stable_mimic`,
   a snapshot of `active_mimic` taken at transition start. Never with
   `pending_mimic`/`active_mimic` post-activation. When no transition is
   outstanding, control is wrapped with `active_mimic` (today's behavior).
2. **C2 (data TX).** Data datagrams are wrapped with `active_mimic`.
   `active_mimic` switches to `pending_mimic` at local activation (existing
   `on_profile_activation()` observer — unchanged).
3. **C3 (RX candidates, ordered, deduplicated, hard cap 4).** An inbound
   'E' datagram is tried against, in order:
   1. `active_mimic`
   2. `pending_mimic` — present iff a transition is outstanding AND the
      pending mask is resolved. Installed: initiator at
      `start_profile_transition()` success; responder when PREPARE is
      accepted (first observation of `pending_profile()`). Both are **no
      later than** the peer's first possible new-mask transmission
      (responder: READY entry precedes any initiator activation, which
      requires READY; initiator: its install precedes its COMMIT, which
      precedes any responder activation). Removed on rollback/finalize.
   3. `old_mimic` — present iff activated and inside the grace window
      (existing rule).
   4. sibling mask variant of `active_mimic` — only for stateful families
      (§3.4); absent in plain v2.
   First candidate whose unwrap yields **AEAD-valid** plaintext wins. A
   structurally failing candidate costs one bounded unwrap attempt; a
   structurally passing candidate that fails E2E AEAD costs one unwrap + one
   AEAD attempt and is counted; neither mutates ratchet/FSM state
   (verify-then-commit, already guaranteed: a failed candidate-1 attempt
   never mutated ratchet state — see `handle_e2e()` comment).
4. **C4 (finalization).** On DRAIN→IDLE finalize: `old_mimic` and
   `pending_mimic` are dropped (existing `cleanup_after_finalize()`);
   `active_mimic` becomes the next transition's `transition_stable_mimic`.

Note: `transition_stable_mimic` needs no new field — while a transition is
outstanding, pre-activation it equals `active_mimic`, post-activation it
equals `old_mimic`. The control-outbound handler selects
`mgr.has_outstanding() ? (activated ? *old_mimic : active_mimic) : active_mimic`.

### 1.4 Message-flow diagram (v2, BIDIRECTIONAL, arbitrary target mask M_new)

Mask annotations: `[S]` = wrapped in transition-stable (old) mask,
`[N]` = wrapped in new mask. I = initiator, R = responder.

```
 I                                                R
 | active=S                                        | active=S
 | -- PREPARE [S] ------------------------------> | accept PREPARE (resolver ok)
 |                                                | state=READY; RX: {S, N-pending}
 | <-- READY [S] -------------------------------- |
 | ACTIVATE: active=N, old=S (grace starts)       |
 | state=COMMIT; RX: {N, S-grace}                 |
 | -- COMMIT [S] ------------------------------>  |  (STABLE mask: decodable in READY)
 | -- CONFIRM [S] ----------------------------->  | ACTIVATE: active=N, old=S
 |                                                | state=COMMIT→DRAIN (on CONFIRM)
 | == data [N] =================================> | unwrap via pending candidate N ✔
 | <========================================= data [N] == |  (R TXs new post-activation;
 |   I unwraps via active=N ✔                     |   I's pending candidate installed
 | <-- CONFIRM [S] ------------------------------ |   before its COMMIT — zero gap)
 | state=DRAIN (effective)                        |
 | ... old-mask stragglers accepted both ways until grace deadline ...
 | grace expiry: finalize → IDLE; drop old/pending candidates; stable=N
```

Loss/retransmit cases (all control in `[S]`):
- COMMIT lost → initiator retransmits COMMIT `[S]`; responder (READY or
  COMMIT) always decodes `[S]`. Identical to v1 retransmission, but now safe
  for any mask because the retransmit is never in the new mask.
- CONFIRM lost → responder retransmits CONFIRM `[S]` (retransmit state);
  initiator decodes via active=N? No — `[S]` unwraps via the **old_mimic
  grace candidate** (initiator activated). The bounded DRAIN courtesy
  re-CONFIRM logic is unchanged; those replies are also `[S]`.
- Pre-activation ABORT `[S]`: decodable by both sides in every pre-activation
  state. Post-activation ABORT is ignored (unchanged v1 semantics).
- Post-activation timeout (all CONFIRMs lost): `become_uncertain()` → DRAIN →
  finalize, new profile kept, `transitions_uncertain++` — unchanged v1
  semantics; surfaced via SwitchEvent.confirmed==false.

### 1.5 State / RX-candidate tables

Initiator (transition start mask S, target N):

| state    | control TX mask | data TX mask | RX candidates (ordered)     |
|----------|-----------------|--------------|-----------------------------|
| IDLE     | active (S)      | S            | {S}                          |
| PREPARE  | S               | S            | {S, N(pending)}              |
| COMMIT   | S               | N            | {N(active), S(old, grace)}   |
| DRAIN    | S (courtesy)    | N            | {N, S(grace)}                |
| IDLE′    | active (N)      | N            | {N}                          |

Responder:

| state    | control TX mask | data TX mask | RX candidates (ordered)   |
|----------|-----------------|--------------|---------------------------|
| IDLE     | active (S)      | S            | {S}                        |
| READY    | S               | S            | {S, N(pending)}            |
| COMMIT   | S               | N            | {N, S(grace)}              |
| DRAIN    | S               | N            | {N, S(grace)}              |
| IDLE′    | active (N)      | N            | {N}                        |

Zero-gap argument: the initiator can first TX `[N]` only after READY receipt;
the responder installed candidate N before sending READY. The responder can
first TX `[N]` only after COMMIT receipt; the initiator's candidate set
post-activation is {N active, S grace}. Both directions are covered before
the peer's first possible `[N]` datagram → **no systematic transient loss**.

### 1.6 Unwrap ambiguity between candidates

- **Ordering**: fixed priority active → pending → old(-grace) → sibling.
  First AEAD-valid candidate wins; evaluation stops.
- **False-positive unwraps**: a wrong candidate may (rarely) pass mask-level
  structure (e.g. GENERIC's 4-byte length prefix on random bytes). The
  unwrapped bytes then fail E2E AEAD → counted, dropped, **no state
  mutation** (double-ratchet state commits only on successful AEAD;
  transition confirmation additionally requires the inner PD epoch and
  verify-then-commit). Worst-case cost per datagram = 4 bounded unwraps +
  ≤4 AEAD attempts; all counted (`ingress_dropped` / outer_stats), no
  unbounded work. New stateful masks (§3) carry mask-level authentication
  (STUN MESSAGE-INTEGRITY-style HMAC; QUIC AEAD), so false positives fail at
  the mask layer without spending an E2E AEAD attempt.
- **Identical-format candidates** (GENERIC_UDP vs GENERIC_TCP): unwraps are
  byte-identical, so attribution ambiguity is harmless by construction.
- **Content protection**: unchanged — NCP tag, PD epoch fence, E2E AEAD and
  replay window are all evaluated only after a candidate unwrap and are
  authoritative.

### 1.7 Directions (TX_ONLY / RX_ONLY)

Unchanged from v1: the adapter issues only BIDIRECTIONAL transitions; the
direction machinery stays inside `SessionProfileContext` (inner PD layout
switch) where the existing per-direction `tx_uses_new` / `rx_accepts_new`
semantics (including the documented TX_ONLY transient rejection behavior)
apply verbatim. v2 adds no outer-mask behavior per direction: an outer-mask
switch is inherently session-wide and therefore always rides a BIDIRECTIONAL
transition. A host wanting a layout-only switch (no mask change) passes a
target whose resolved mask equals the current one — `pending_mimic ==
active_mimic`, deduplicated out of the candidate list.

### 1.8 Retransmission mask

All control retransmissions rebuild the body (fresh `effective_counter`,
fresh AEAD — unchanged) and are wrapped in `transition_stable_mimic` per C1.
Data is never retransmitted by this layer. No special-casing.

### 1.9 Capability negotiation: session-wide `PROFILE_TRANSITION_V2` bit

- New additive feature bit in `ncp_capabilities.hpp`:
  `NCP_CAPS_FEATURE_PROFILE_TRANSITION_V2 = 0x02` (reserved[0] bit 1), with
  `capabilities_set_profile_transition_v2()` /
  `capabilities_support_profile_transition_v2()` helpers mirroring v1.
- **Strict AND semantics for free**: `negotiate()` already computes
  `feature_bits = local.reserved[0] & peer.reserved[0]`; the adapter computes
  `v2 = advertise_v2 && peer_v2_bit`. Fail-closed on a stripped bit, exactly
  like v1. V2 ⇒ V1: a peer advertising 0x02 without 0x01 is malformed; the
  adapter treats v2 as negotiated only when **both** bits AND to true.
- **Session-wide, not per-transition.** The control codec
  (`PROFILE_TRANSITION_WIRE_VERSION`, wire format) is **unchanged** — v2
  alters only outer-mask scheduling, which is not visible inside the AEAD.
  Per-transition negotiation would require new wire fields and create a
  per-transition downgrade surface for zero benefit; the session-wide bit is
  agreed before any transition can start (caps exchange precedes
  `start_profile_transition()`, which is gated on `transition_capable()`).
- **Mixed v1↔v2 pairs fall back to v1 behavior in full**: the v1 mask
  schedule (control wrapped with `active_mimic`) **and** the GENERIC-only
  target gate both remain in force. Both endpoints compute the gate from the
  same ANDed bits, so there is no gate skew; a v2 initiator paired with a v1
  responder proposing a non-generic target gets the responder's v1-mode
  `ABORT(UNKNOWN_PROFILE)` — fail-closed, no divergence.
- `Stats` gains `bool transition_v2_capable`.

---

## 2. Q2 — Additional-loss budget

**Criterion**: a transition run must induce no data loss beyond an identical
no-switch control run experiencing the same injected impairments.

### 2.1 Transient windows in the v2 design

| Window | Definition | RX coverage | Residual loss vs no-switch |
|--------|-----------|-------------|-----------------------------|
| W0: PREPARE→READY | negotiation in flight | both TX/RX on S; candidates {S,N} | none (no mask change yet) |
| W1: initiator READY→grace-end | initiator TXs `[N]`, responder may still TX `[S]` until its COMMIT receipt | R has N candidate since READY; I has S grace candidate since activation | none systematic (§1.5) |
| W2: responder COMMIT→grace-end | responder TXs `[N]` | I active=N | none systematic |
| W3: control-loss exhaustion | retransmit budget (default 5 × 200 ms = 1000 ms) burned without CONFIRM | — | **uncertain divergence** (pre-existing v1 semantic): responder rolls back, initiator keeps N; data `[N]`→R undecodable until a NEW transition re-syncs. Bounded, counted (`transitions_uncertain`, peer's `ingress_dropped`), never silent. |

Config guidance: `grace_period_ms` (default 1000) must be ≥
`retransmit_interval_ms × max_retransmit_attempts` + RTT margin so old-mask
control/datagrams remain decodable for the full retransmit budget. With the
defaults they are equal; v2 tests pin grace = 1500 ms to leave margin.

Quantified budget statement: for any injected control-loss rate p < p_exhaust
(p_exhaust ≈ 1 − (1−p)^5 per handshake step), the expected transition-induced
data loss is **0 datagrams** — every data datagram either travels in the
receiver's active mask or in a mask present in its candidate set from a
causally earlier install point. Above p_exhaust the loss is the divergence
tail (W3), identical in character to v1 and bounded by the abort/recovery
transition.

### 2.2 Proof test (real UDP loopback)

New file `tests/test_udp_profile_transition_v2.cpp`, harness cloned from
`tests/test_udp_profile_transition.cpp` (real `PortHopClient/Server` over
127.0.0.1 UDP, real X25519 E2E, monotonic-clock `tick()`, deterministic
impairment at harness edges only):

1. **T2-happy**: GENERIC_UDP → QUIC_SHORT_HEADER (non-length-prefixed
   target), bidirectional, 200-datagram deterministic application stream.
   Assert: received stream SHA-256 == the identical **no-switch** control
   run's SHA-256; `transition_counters.transitions_effective == 1`;
   `rx_rejected_unknown_epoch == 0`; `rx_rejected_early_new == 0`.
2. **T2-loss20**: same transition with 20% deterministic drop applied to
   control datagrams only. Assert: data delivery ratio ≥ the identical
   impaired no-switch control run's ratio; transition still reaches
   `transitions_effective` (retransmits absorb the loss);
   `control_retransmits > 0`.
3. **T2-commit-storm**: 100% COMMIT/CONFIRM loss (drop all control after
   READY). Assert: initiator finalizes `transitions_uncertain == 1`,
   responder cleanly `transitions_timed_out == 1` / aborted; a subsequent
   fresh transition re-synchronizes; no crash, no queue growth (bounded
   queues invariant).
4. **T2-legacy**: v2 initiator, v1-only responder (bit 0x02 stripped).
   Assert: non-generic target refused — local `INVALID_PROFILE` or responder
   `ABORT(UNKNOWN_PROFILE)` — zero state change both sides, wire behavior
   identical to current v1 tests.

Hermetic counterparts (no sockets) live in `tests/test_mimicry_session_v2.cpp`
(two in-process `NcpMimicrySession` instances, direct datagram plumbing —
the pattern of `test_mimicry_session.cpp`): candidate-order checks, mask
attribution on every control retransmit (assert each emitted control
datagram's outer mask == stable mask by unwrap-probing), abort paths, grace
expiry candidate removal, GENERIC-gate lift/limit matrix (§4 step 5).

---

## 3. Q3 — Stateful profile models

### 3.1 (a) Mask formats: minimal extension — new MimicProfile entries, session-bound

PaddingHeaderModel + FSM per-state overrides on a GENERIC envelope **cannot**
produce an externally distinguishable QUIC/STUN wire shape: the DPI-visible
byte structure (first-byte form, header layout, connection-id continuity,
magic cookie) is exactly what the mask layer owns, and a length-prefixed
generic envelope looks like neither QUIC nor STUN. New mask formats are
therefore unavoidable; the minimal extension is:

**New `TrafficMimicry::MimicProfile` entries, appended at the enum end
(existing numeric values frozen):**

- `QUIC_SHORT_HEADER` — QUIC 1-RTT-like: first byte `0x40|spin|rand`
  (0x80 clear → short header), **session-stable 8-byte DCID** (connection
  continuity = the statefulness DPI expects; derived, see below), 4-byte
  packet number from the existing per-instance `quic_packet_number_`
  counter, then XChaCha20-Poly1305 over
  `[wire_version][4-byte payload length][payload]`, key =
  `BLAKE2b(DCID, "NCP-QUIC-SHORT-KEY-v1")` — same self-describing unwrap
  pattern as the existing QUIC_INITIAL, so no extractor API change. Unwrap
  additionally requires DCID == session DCID (fail-fast wrong-flow reject).
- `STUN_MESSAGE` — RFC 5389-shaped: type Binding/Shared-secret
  request|response alternated by send direction, magic cookie
  `0x2112A442`, 96-bit transaction id = HMAC-SHA256(session key, counter)
  truncated, payload carried in a `0x8022`-style (reserved-range) attribute
  with `[wire_version][length][payload]`, plus a MESSAGE-INTEGRITY-shaped
  HMAC-SHA1 attribute over the message for **mask-level authentication**
  (fail-closed unwrap, DPI-plausible because MESSAGE-INTEGRITY is real STUN).
  4-byte alignment per RFC 5389.
- (Optional, same step, RTC media) `SRTP_LIKE` — RTP fixed header
  (V=2, PT from config, per-session SSRC from session key, seq/timestamp
  counters), payload verbatim, no inner AEAD (E2E AEAD is authoritative);
  unwrap = structural parse + seq window only. Kept optional: WEBRTC profiles
  can ship with STUN_MESSAGE + QUIC_SHORT_HEADER first.

**Session binding (new, additive `MimicConfig` field):
`std::array<uint8_t,32> session_mask_key{}`; zero = legacy behavior.** The
adapter derives it once per established session:
`HKDF(E2E shared secret, "ncp-mimicry-session/mask-v1")` — same derivation
pattern as `kSessionIdContext`/`kShaperSecretContext` in
`finalize_handshake()`. Both endpoints derive identical keys; masks become
per-session authenticated and non-replayable across sessions. The existing
`QUIC_INITIAL` (per-packet random DCID, no continuity) keeps its exact wire
format and stays usable as a *bootstrap/handshake-phase* variant.

No existing wire format changes: GENERIC_* and all current masks are
byte-identical; new masks exist only behind new enum values selected via new
profiles.

### 3.2 (b) FsmModel state machines

Reuses the existing catalog `FsmModel` + runtime `MimicryFsmSession`
(phases BOOTSTRAP/HANDSHAKE/ESTABLISHED/DATA, per-state size/iat/padding
overrides via `FsmStateOverrideMap`, seeded dwell, phase gating). The two
reference models:

**QUIC (`ref.quic.v1`, family QUIC)** — states and default phase mapping:
- `bootstrap` (phase BOOTSTRAP): Initial-shaped datagrams, sizes
  N(1200, 0) clamp [1200, 1350] (QUIC min-datagram), dwell 0.
- `handshake` (phase HANDSHAKE): large burst sizes N(1100, 150), iat
  N(15, 8) ms, dwell N(250, 80) ms.
- `established` (phase ESTABLISHED): short-header, mixed sizes
  N(600, 250), iat N(30, 20), dwell N(2000, 800).
- `data` (phase DATA): short-header, app-shaped sizes N(450, 200) clamp
  [64, 1280], iat N(25, 15), terminal-dwell (self-loop p=1).
Transitions: bootstrap→handshake (1.0), handshake→established (1.0),
established→data (1.0), data→data (1.0). `allow_phase_regression=false`.

**RTC/WebRTC (`ref.webrtc.v1`, family WEBRTC)** — states:
- `handshake`: STUN-sized datagrams N(80, 30) clamp [48, 200], symmetric
  iat N(500, 200) (connectivity checks), dwell N(1500, 400).
- `established`: DTLS-handshake-sized bursts N(900, 300), iat N(40, 15),
  dwell N(600, 200).
- `data`: SRTP-shaped: audio N(220, 40) @ iat N(20, 3) (20 ms ptime), or
  video N(900, 250) @ iat N(16, 8); dwell terminal self-loop.
BurstModel enabled for `data` (mean burst 3, gap 33 ms — frame bursts).

Both models are expressed entirely in the existing schema — no
`ProfileDescriptor` fields are added, so canonical serialization, content
hashes and signatures of existing descriptors are untouched.

### 3.3 (c) Catalog descriptors

- Ship the two reference descriptors as **BUILTIN** via a new
  `register_reference_builtins()` (trusted compile-time path, alongside
  `register_legacy_builtins()`), so CLI/tests work out of the box.
- Externally supplied QUIC/RTC descriptors go through the normal
  `SignaturePolicy::ENFORCE` path unchanged.
- Add capability strings to `default_capabilities()`:
  `"stateful-mask"` (descriptor requires session-bound mask support) and
  `"profile-transition-v2"` (descriptor is only a valid *transition target*
  for v2-negotiated sessions). The built-ins carry both in
  `required_capabilities`; validation enforces presence, and the adapter
  refuses to select a descriptor requiring `profile-transition-v2` when the
  session is v1 (defense in depth on top of the wire gate).

### 3.4 Mask-variant selection (where "stateful" meets the wire)

A stateful profile = one profile whose FSM state selects among that family's
mask variants. Minimal wiring, catalog schema untouched:

- Fixed built-in family variant maps (constant, not host-configurable in v2
  scope): QUIC → {bootstrap/handshake: `QUIC_INITIAL`,
  established/data: `QUIC_SHORT_HEADER`}; WEBRTC → {handshake:
  `STUN_MESSAGE`, established: `STUN_MESSAGE`, data: `SRTP_LIKE` (or
  STUN_MESSAGE if SRTP_LIKE deferred)}.
- TX: in `send_application()`, when the FSM is engaged and the active
  profile's family has a variant map, wrap data with
  `variant_for(fsm->current_state())` instead of `active_mimic` for that
  datagram. `active_mimic` itself still flips only at profile activation
  (transition semantics untouched; variant selection is per-datagram within
  the active profile).
- RX: the candidate list gains the **sibling variant** of `active_mimic`
  (4th candidate, §1.3 C3). RX never depends on the receiver's own FSM state
  — variant sets are a pure function of the hash-bound active profile
  descriptor's family, so both endpoints always agree on the acceptance set
  even if their FSM instances are at different states (they are independent;
  dwell sampling is seeded-identical but timing diverges). Hard cap 4
  candidates stands.
- Control datagrams are **never** variant-wrapped: C1 (stable mask) applies;
  a control datagram arriving in a variant mask still decodes because the
  stable mask is in every candidate set during the transition.

---

## 4. Q4 — Rollout plan (ordered, per-step tests + regression risks)

Each step lands independently testable; steps 2–3 and 4 can proceed in
parallel after step 1; step 5 depends on 4; step 6 depends on 2+4; step 7 on
6; step 8 integrates all.

**Step 1 — V2 capability bit.**
Files: `src/core/include/ncp_capabilities.hpp` (bit 0x02 + helpers);
`src/core/include/ncp_mimicry_session.hpp` (`Config::advertise_profile_transition_v2`,
`Stats::transition_v2_capable`); `src/core/src/ncp_mimicry_session.cpp`
(AND negotiation in `handle_caps`/`queue_caps`; v2 flag stored; **no
behavior change yet**).
Tests: extend `tests/test_mimicry_session.cpp` — bit roundtrip, AND
semantics, strip-bit fail-closed, v2-without-v1 treated as v1.
Risk: negligible (additive; `negotiate()` already ANDs `reserved[0]`).

**Step 2 — New masks.**
Files: `src/core/include/ncp_mimicry.hpp` (enum append `QUIC_SHORT_HEADER`,
`STUN_MESSAGE` [, `SRTP_LIKE`]; `MimicConfig::session_mask_key`);
`src/core/src/mimicry.cpp` (wrapper/extractor pairs; wire_version applies).
Tests: `tests/test_mimicry_roundtrip.cpp` — roundtrips, wrong-key/
wrong-DCID fail-closed unwrap, false-positive unwrap rate vs random garbage
and vs other masks' output, MTU/padding behavior, stats counters.
Risk: mask-layer bugs are contained (E2E AEAD still authoritative); enum
append keeps existing values stable.

**Step 3 — Session-bound mask key.**
Files: `src/core/src/ncp_mimicry_session.cpp` (`kMaskKeyContext` HKDF in
`finalize_handshake()`, set into `TrafficMimicry` config);
`src/core/include/ncp_mimicry_session.hpp` (doc).
Tests: `test_mimicry_session.cpp` — two sessions derive identical keys;
different sessions differ; stable profile unchanged (generic masks ignore the
key).
Risk: key-derivation mismatch would break all new-mask sessions — caught by
step-2+3 combined roundtrip over a real E2E pair.

**Step 4 — v2 mask schedule in the adapter (core change).**
Files: `src/core/src/ncp_mimicry_session.cpp` —
control-outbound handler selects `transition_stable_mimic` per C1;
`handle_e2e()` candidate list per C3 (active → pending → old-grace);
pending install points (start success / PREPARE-accept via
`sync_pending_mimic()`); abort/finalize cleanup; all gated on the negotiated
v2 flag with the v1 path **byte-identical**.
`src/core/include/ncp_mimicry_session.hpp` — contract docs.
Tests: new `tests/test_mimicry_session_v2.cpp` (hermetic pair): full
transition GENERIC_UDP→QUIC_SHORT_HEADER; control-mask attribution probe on
every emission incl. retransmits and side-band ABORTs; candidate order/
false-positive counts; abort pre/post activation; grace expiry; v1-negotiated
session behaves exactly as before (regression: rerun
`test_mimicry_session.cpp` + `test_udp_profile_transition.cpp` unmodified —
they must pass unchanged).
Risk: this is the highest-blast-radius step; mitigated by the v2 gate and by
leaving `SessionProfileContext`/manager untouched.

**Step 5 — Gated lift of the GENERIC-only enforcement.**
Files: `src/core/src/ncp_mimicry_session.cpp` — `is_transition_target_mimic()`
gate becomes: non-generic targets allowed iff session v2-negotiated;
unchanged refusal paths otherwise (initiator `INVALID_PROFILE`, responder
resolver-gate → `ABORT(UNKNOWN_PROFILE)`).
Tests: matrix in `test_mimicry_session_v2.cpp`:
(v2,v2)+QUIC target → allowed; (v2,v1)/(v1,v2)+(v1,v1) → refused with zero
state change/traffic; resolver returning non-generic under v1 → refused.
Risk: gate skew — mitigated because both sides AND the same bits; T2-legacy
proves it over real UDP.

**Step 6 — FSM-driven mask variants.**
Files: `src/core/src/ncp_mimicry_session.cpp` (family variant maps,
per-datagram variant selection in `send_application()`, 4th RX candidate);
`src/core/include/ncp_mimicry_session.hpp` (docs + optional
`Config::disable_mask_variants` escape hatch).
Tests: extend `tests/test_mimicry_session_fsm.cpp` — variant selection per
FSM state, control never variant-wrapped, sibling-candidate decode across
FSM-state skew between endpoints (force divergent FSM states, assert
decode), candidate cap respected.
Risk: RX/TX variant-set asymmetry — mitigated by deriving sets from the
hash-bound descriptor family only.

**Step 7 — Built-in reference descriptors + capability registry.**
Files: `src/core/src/ncp_reference_profile_catalog.cpp`
(`register_reference_builtins()`, two `default_capabilities()` strings);
`src/core/include/ncp_reference_profile_catalog.hpp` (declaration).
Tests: `tests/test_reference_profile_catalog.cpp` — built-ins validate,
hash-stable, list_by_family(QUIC/WEBRTC); descriptors requiring
`profile-transition-v2` rejected as targets under v1 sessions (adapter
test).
Risk: none to existing descriptors (schema frozen).

**Step 8 — Real-UDP evidence + CLI + docs.**
Files: `tests/test_udp_profile_transition_v2.cpp` (§2.2);
`tests/CMakeLists.txt`; `src/cli/ncp_mimicry_cli.hpp` (+ `--mimicry-v2 off`
operator kill-switch if desired) and `tests/test_cli_mimicry_flags.cpp`;
`docs/MIMICRY_PROFILES.md` (new profiles section).
Tests: §2.2 suite; CLI parse/validation tests.
Risk: loopback timing flakiness — follow the existing harness discipline
(bounded pumps, no fixed sleeps as correctness criteria).

Regression suite to run green at every step: `test_profile_transition`,
`test_udp_profile_transition`, `test_mimicry_session`,
`test_mimicry_session_fsm`, `test_mimicry_roundtrip`,
`test_reference_profile_catalog`, `test_cli_mimicry_flags`.

---

## 5. Q5 — Risks / invariants checklist

### 5.1 Existing invariants that MUST remain true (unchanged code paths)

- **Fresh-AEAD retransmits**: every control (re)send rebuilds the body and
  re-encrypts (fresh ratchet counter/nonce/tag); v2 changes only the outer
  mask of the same ciphertext pipeline.
- **effective_counter binding / peer-epoch-relative crypto fences**:
  `ProfileTransitionManager` untouched; counter claims still sampled fresh,
  upper-bound-validated against the crypto stream.
- **One outstanding transition**: unchanged (BUSY/glare paths untouched).
- **No plaintext fallback**: `kKindPlaintext` gating and the
  established-session downgrade refusal are untouched; v2 adds no plaintext
  path. Legacy (no-v1-bit) wire format unchanged.
- **No global orchestrator mutation**: mask state remains per-session
  (`NcpMimicrySession::Impl::outer`); session mask key is per-session; no
  new shared/static mutable state.
- **Verify-then-commit**: candidate unwrap → E2E AEAD → only then any state
  effect; failed candidates never touch ratchet/FSM/transition state.
- **Bounded queues**: `out_q` behavior unchanged; retransmission budgets
  unchanged; DRAIN courtesy CONFIRMs still capped.
- **Inner layer untouched**: `ncp_profile_transition.{hpp,cpp}` and the PD
  wire framing are byte-identical; the control codec stays at
  `PROFILE_TRANSITION_WIRE_VERSION = 1`.

### 5.2 New invariants introduced by v2

- **I-V2-1 (control mask pin)**: every control datagram of an outstanding
  transition is wrapped in `transition_stable_mimic`. Test: attribution
  probe on every emitted control datagram (step 4 tests).
- **I-V2-2 (candidate precedence)**: the pending mask is in the RX candidate
  set no later than the peer's first possible transmission of it (install
  points §1.3 C3). Test: zero-gap assertion in T2-happy
  (`rx_rejected_unknown_epoch == 0`, `ingress_dropped` delta == 0 vs
  control).
- **I-V2-3 (candidate bound)**: ≤ 4 ordered candidates per datagram; every
  candidate attempt bounded and counted; no candidate evaluation mutates
  state before AEAD success.
- **I-V2-4 (session mask binding)**: stateful-mask unwrap requires the
  session-derived key/DCID; wrong-session datagrams fail closed at the mask
  layer. Mask/key material never resets on profile switch (mask-only
  transition never touches E2E/TLS state — existing rule, now extended to
  `session_mask_key`).
- **I-V2-5 (variant determinism)**: the accepted mask-variant set is a pure
  function of the hash-bound active profile descriptor's family — never of
  runtime FSM state or overrides — so endpoints cannot drift apart.
- **I-V2-6 (fail-closed negotiation)**: non-generic transition targets are
  possible iff both peers advertised V1∧V2; any other combination keeps the
  GENERIC-only gate and the exact v1 wire behavior.

### 5.3 Top risks

1. **Unwrap false-positive amplification** (candidate list on garbage
   flood): bounded by I-V2-3 and mask-level auth on the new masks
   (STUN HMAC / QUIC AEAD / DCID check) which reject before E2E AEAD; still
   the main CPU-amplification surface — counters + cap are mandatory.
2. **Negotiation skew / downgrade**: a stripped V2 bit silently reduces to
   v1 (fail-closed, correct) but an operator could misread it as a v2
   session — mitigated by `Stats::transition_v2_capable` surfacing and the
   T2-legacy evidence test.
3. **Variant-set drift** (FSM-driven masks): if variant acceptance ever
   depended on local runtime state, endpoints would systematically drop each
   other's datagrams; I-V2-5 forbids this — acceptance is family-derived
   only. This is the invariant reviewers should attack first.

---

## Appendix A — exact adapter changes (implementation map)

All in `src/core/src/ncp_mimicry_session.cpp` unless noted:

1. `Impl` gains: `bool v2_negotiated = false;`
   `std::array<uint8_t,32> mask_key{};` (step 3).
2. `handle_caps()`: `v2_negotiated = cfg.advertise_profile_transition_v2 &&
   capabilities_support_profile_transition_v2(*caps) && <v1 negotiated>`.
   `queue_caps()`: set both bits per config. (step 1)
3. Control-outbound handler: mask =
   `v2_negotiated && ctx->manager().has_outstanding()
      ? (ctx->manager().is_activated() ? *old_mimic : active_mimic)
      : active_mimic` (C1; `old_mimic` is guaranteed set when activated).
   (step 4)
4. `handle_e2e()`: candidate list per C3 with pending between active and
   old-grace; dedupe equal masks; cap 4. (steps 4, 6)
5. `is_transition_target_mimic()`: `return is_generic(p) || v2_gate_open;`
   where `v2_gate_open` is evaluated at the call sites (initiator:
   `v2_negotiated`; responder resolver gate: `v2_negotiated`). (step 5)
6. `finalize_handshake()`: derive `mask_key` via
   `e2e.derive_keys(shared, "ncp-mimicry-session/mask-v1", 32)` and set
   `MimicConfig::session_mask_key`. (step 3)
7. `send_application()`: variant selection (step 6) — `variant_for()`
   consults the family map only when `fsm` is engaged and v2 negotiated.
8. `Stats`: add `transition_v2_capable`. (step 1)

No changes to: `ncp_profile_transition.*`, `ncp_e2e.*`,
`ncp_mimicry_fsm.*`, catalog schema/serialization.
