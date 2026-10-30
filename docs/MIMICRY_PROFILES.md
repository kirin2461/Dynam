# Mimicry Profile Subsystem

Status: implemented (generic UDP transition path). Stateful QUIC/RTC profiles are
intentionally **not** started until the generic transition integration is fully
validated.

This document describes the native Dynam implementation of the AIVPN-derived
mimicry-profile concepts. AIVPN (Rust) was used as the source of protocol
invariants and test oracles only — no Rust code was mechanically ported;
all mechanisms are implemented natively in C++17 for Dynam's architecture.

## Components

| Component | Files | Role |
|---|---|---|
| `ReferenceProfileCatalog` | `ncp_reference_profile_catalog.{hpp,cpp}` | Versioned, signed catalog of reference flow profiles; validation; deterministic per-session derivation; backward-compatible adapter to legacy `StatProfile`. |
| `ProfileTransitionManager` / `SessionProfileContext` | `ncp_profile_transition.{hpp,cpp}` | Seamless in-session switch of UDP/mimicry layout without reconnect. Owns stable/pending/draining profile state per session. |
| `MimicryAutoPilot` | `ncp_mimicry_autopilot.{hpp,cpp}` | Decision loop (scoring, hysteresis, cooldown, dwell, anti-storm). Separate from the TCP `PresetAutoPilot`; never calls global `set_strategy()`; changes apply only through the transition API on commit. |
| `MimicryFsmSession` | `ncp_mimicry_fsm.{hpp,cpp}` | Epoch-bound FSM profile runtime (bootstrap → handshake → established → data), deterministic same-seed traces, per-session polymorphism. |
| `NcpMimicrySession` | `ncp_mimicry_session.{hpp,cpp}` | Production adapter composing `E2ESession` + `SessionProfileContext` + catalog + per-session `TrafficMimicry`/`MimicryShaper` over the PortHop UDP transport. |
| `MimicryCatalogIo` | `ncp_mimicry_catalog_io.{hpp,cpp}` | Deterministic binary container for external catalog files; `load_file()` / `validate_file()` / `save_file()`. |
| `NcpConnectionDirector` | `ncp_connection_director.{hpp,cpp}` | Per-session registry and poll-loop ownership wiring the adapter into the CLI PortHop path. |

## Trust and signature model

Descriptors carry a canonical BLAKE2b-256 content hash and an optional detached
Ed25519 signature (`ArtifactSignature`). Externally supplied descriptors are
policy-checked:

- `ENFORCE` (default): a valid signature from a trusted key is required.
- `WARN_ONLY`: accept, record a warning issue.
- `DEV_UNSIGNED`: accept unsigned (development builds only).

Built-in descriptors (`TrustClass::BUILTIN`) use the trusted compile-time path
and skip signature enforcement. The catalog enforces capacity limits on all
paths, including built-ins.

## Per-session derivation

Profiles are never used raw. For each session the catalog derives a
`DerivedProfile` via HKDF/HMAC over the descriptor content and a session secret:
`rng_seed`, `burst_scale`, `fsm_dwell_scale`, `header_gap_shift_bytes`,
`padding_extra_bytes`, all clamped by the descriptor's signed `DerivationBounds`.
Same profile + same session secret ⇒ identical trace; different sessions ⇒
polymorphic but bounded variation. All derivation inputs — including
`fsm_dwell_rel_jitter` and `header_gap_shift_max_bytes` — are covered by the
signed canonical serialization.

## Joint size↔IAT and prepared shapes

`StatProfile` supports an optional joint size↔IAT model (2D Gaussian mixture
coupling packet size and inter-arrival time). Shapes are prepared per profile
epoch:

- `prepare_data_shape()` is idempotent; `take_data_shape()` is one-shot;
  `cancel_prepared_shape()` aborts.
- Control packets never consume a prepared data shape.
- A shape prepared under epoch N is rejected after the profile epoch advances
  (stale-epoch rejection); `set_profile()` increments the epoch and drops any
  queued shape.
- Legacy RNG ordering is preserved when no joint model is present.

## Transition protocol

In-session layout switch without reconnect, over the existing E2E channel:

```
PREPARE → READY → COMMIT → CONFIRM/DRAIN
                 ↘ ABORT / TIMEOUT
```

Invariants:

- One outstanding transition per session; TX and RX layouts are tracked
  independently (`TransitionDirection`: BIDIRECTIONAL / TX_ONLY / RX_ONLY).
- `crypto_epoch`, `profile_epoch`, PortHop epoch, packet counters and the
  transition sequence are separate domains.
- Every retransmitted control message is a **fresh AEAD packet** (fresh
  counter/nonce/tag) carrying the same logical `transition_id`.
- `effective_counter` binds control messages to the actual E2E crypto packet
  counter of the direction — replayed or self-fed plaintext cannot confirm a
  transition.
- ABORT is safe before activation; after activation, going back is only
  possible as a new transition (previous-stable rollback).
- The outer mask for a `ProfileRef` is resolved locally on each endpoint via
  `mimic_resolver`; it is **not negotiated on the wire**. Deployments must
  configure the resolver (or catalog) consistently on both peers — only
  length-prefix-compatible generic masks (GENERIC_UDP/GENERIC_TCP) are
  accepted as transition targets, and this is enforced on both the initiator
  and the responder accept path.
- Legacy peers without the `profile_transition_v1` capability bit
  (`NCP_CAPS_FEATURE_PROFILE_TRANSITION_V1`, negotiated with AND-semantics in
  `NegotiatedConfig::feature_bits`) never see a silent wire-format change: the
  protected raw E2E data path is preserved and plaintext fallback is forbidden.

## Evidence model

- **Hermetic tests**: `SessionProfileContext` pairs in-process (23 scenarios).
- **Real UDP tests**: `test_udp_profile_transition.cpp` drives real
  `PortHopClient`/`PortHopServer` loopback sockets with a real X25519
  handshake and tagged capability exchange (14 scenarios: no-switch baseline,
  idle/active switch, in-flight grace, control loss/retransmit,
  duplicate/replay/corruption, wrong profile hash, legacy peer, repeated
  transitions, parallel sessions, shaper cancellation).
- **PCAP/TShark/nDPI**: live captures of established sessions are verified with
  external tools (see `docs/DPI_EVIDENCE_GATE.md`). nDPI is an offline/CI
  evidence source, never a runtime health signal. An `Unknown` nDPI verdict on
  generic profiles is a valid negative control — it is **not** a DPI-pass
  claim and says nothing about TSPU-class classifiers.
- **Impairment**: UDP impairment runs are compared against an identical
  no-switch control. The goal is the absence of *additional*
  transition-induced loss — not zero UDP loss.

## Operator surface

The flags below are wired in `ncp porthop` secure mode (see
`docs/CLI_COMMANDS.md` for the full reference):

```
--mimicry-profile <id>        --mimicry-catalog <path>     --mimicry-auto
--mimicry-allowed <csv>       --mimicry-locked             --mimicry-require-signed
--mimicry-switch-cooldown <s> --mimicry-min-dwell <s>      --mimicry-hysteresis <pct>
--mimicry-transition-grace <ms>  --mimicry-stats-json <path>
--mimicry-transition <id>     --mimicry-allow-unsigned-dev (DEV ONLY)
```

- `--mimicry-catalog <path>` loads an external signed catalog container
  (`MimicryCatalogIo::load_file`, policy-checked) BEFORE session creation;
  its profile ids become usable by `--mimicry-profile` /
  `--mimicry-transition`. Validation failures print the container error and
  every per-descriptor registration issue.
- External catalog records are signature-enforced by default
  (`SignaturePolicy::ENFORCE`; `--mimicry-require-signed` states this
  explicitly). `--mimicry-allow-unsigned-dev` switches to `DEV_UNSIGNED`
  with a loud warning — development/lab use only.
- `--mimicry-allowed <csv>` is a CLI-level allow-list: the requested
  `--mimicry-profile`/`--mimicry-transition` must be on it, and an attached
  autopilot excludes every off-list profile id from its candidate set.
- Control mode defaults to MANUAL (only explicit `--mimicry-transition`
  requests). `--mimicry-auto` attaches a `MimicryAutoPilot` in AUTO mode
  (transition requests go through
  `NcpConnectionDirector::transition_request_handler`);
  `--mimicry-locked` attaches it in LOCKED mode (monitoring only, no
  transitions; forbids `--mimicry-transition`). The one-shot CLI covers the
  interactive verbs: select = `--mimicry-transition`, lock =
  `--mimicry-locked`; mid-session unlock/rollback commands are intentionally
  not part of it.
- The autopilot knobs (`--mimicry-switch-cooldown`, `--mimicry-min-dwell`,
  `--mimicry-hysteresis`) map to `MimicryAutoPilot::Config::cooldown_ms` /
  `min_dwell_ms` / `hysteresis_pct` and require an attached autopilot.
  `--mimicry-transition-grace` maps to the adapter's
  `ProfileTransitionConfig::grace_period_ms`.
- On teardown (client) and shutdown (serve) a compact stats JSON is printed
  to stdout, or written to `--mimicry-stats-json <path>` (atomic
  tmp+rename). It contains: current/pending profile id+revision,
  `transition_state`, transitions effective/aborted/timed_out (plus
  started/committed/uncertain), `crypto_epoch`, `profile_epoch`,
  `mtu_budget_rejections`, director aggregate counters, and the autopilot
  block when attached. No secrets, no key material, no peer addresses.

Catalog tooling subcommand:

```
ncp mimicry-catalog validate <path>   # full validation; exit 0 valid / 1 invalid
ncp mimicry-catalog list <path>       # per-descriptor id@rev, family, signature
                                      # status (+ key id), validation issues
```

The legacy `ncp mimic <type>` command (TrafficMimicry profile save) is
unchanged and independent of this surface.

Stats JSON exposes: current/pending profile, transition state and reason,
switch/failure/rollback counters, cooldown/dwell state, score breakdown, crypto
epoch before/after, and — separately — last offline DPI evidence.

## Transition protocol v2 — arbitrary (stateful) masks

v1 restricts transition targets to length-prefix-compatible generic masks
(GENERIC_UDP/GENERIC_TCP) because control messages were wrapped in the
post-activation mask, which a not-yet-activated peer cannot decode for
non-generic targets. v2 removes that coupling by construction (full design:
`docs/MIMICRY_QUIC_RTC_DESIGN.md`):

- **C1 control pin**: while a transition is outstanding, every control
  datagram (PREPARE/READY/COMMIT/CONFIRM/ABORT, retransmits and side-band
  ABORTs) is wrapped in the mask that was stable at transition start.
- **C2 data TX**: data switches to the new mask at local activation (as v1).
- **C3 RX candidates** (ordered, deduplicated, hard cap 4): active → pending
  (installed no later than the peer's first possible new-mask transmission)
  → old (grace window) → sibling family variant (stateful families only).
  AEAD verification is authoritative; a failed candidate never mutates
  ratchet/FSM state.
- **Negotiation**: `NCP_CAPS_FEATURE_PROFILE_TRANSITION_V2 = 0x02`,
  strict-AND with v2⇒v1 enforced. Mixed v1↔v2 pairs fall back to full v1
  behavior including the GENERIC-only gate — fail-closed, no skew.
  `--mimicry-v2 off` is the operator kill-switch.

### Stateful masks and profiles

- `QUIC_SHORT_HEADER` (enum 13): QUIC-short-header-shaped datagrams with a
  session-stable derived DCID and mask-level AEAD; session key via HKDF from
  the E2E secret (`ncp-mimicry-session/mask-v1`).
- `STUN_MESSAGE` (enum 14): RFC 5389-shaped Binding request/response with
  magic cookie and a MESSAGE-INTEGRITY-style HMAC (SHA-256 truncated to 160
  bits — this libsodium build has no HMAC-SHA1).
- FSM-driven per-datagram mask variants: for stateful families the adapter
  selects the mask variant from the engaged FSM state (e.g. QUIC
  bootstrap/handshake → Initial-shaped, established/data → short-header).
  The RX sibling-candidate set is a pure function of the hash-bound profile
  descriptor family, never of runtime FSM state. `Config::disable_mask_variants`
  is the escape hatch.
- Built-in reference descriptors `ref.quic.v1` and `ref.webrtc.v1`
  (hash-stable, capability-gated: they require `profile-transition-v2` and
  are refused as targets under v1 sessions on both endpoints).

### Uncertain-divergence recovery — by design

A COMMIT-storm corner (initiator activates, responder never receives COMMIT
and times out) leaves the endpoints on different masks/epochs. In-band
re-sync is **impossible by construction** (the C1 control pin plus the epoch
fences reject it) — this is a deliberate fail-closed tradeoff of two-phase
commit over lossy links. The recovery primitive is a fresh session
establishment followed by a fresh transition; `CommitStormUncertainDivergenceRecovery`
in `tests/test_udp_profile_transition_v2.cpp` proves the bounded failure and
the fresh-session recovery. A protocol-level resync (post-finalize
uncertain-fallback candidate + REsync message) is a possible future
extension, deliberately not implemented.

## What this subsystem does not claim

- No claim of undetectability against any specific DPI deployment.
- nDPI confidence scores are classification evidence, not stealth probability.
- The E2E ECDH handshake remains unauthenticated against active MitM
  (documented in `docs/KNOWN_ISSUES.md`).
- GPU offload for the hot packet path was evaluated and rejected (small
  packets, branchy state, batching latency and IAT jitter); GPU remains an
  option for offline PCAP/ML analysis only.
