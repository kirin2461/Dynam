# Mimicry Subsystem Threat Model (Gate G0)

Status: design gate G0 — normative for all externally visible security claims
of the mimicry subsystem. No code in this document; it defines adversary
classes, trust boundaries, assets, and the verdict taxonomy that every
mimicry-related claim in code comments, docs, CLI output and CI reports MUST
use. Companion documents: `docs/MIMICRY_PROFILES.md`,
`docs/MIMICRY_QUIC_RTC_DESIGN.md`, `docs/DPI_EVIDENCE_GATE.md`,
`docs/MIMICRY_TRANSPORT_ADR.md`.

Scope: the UDP mimicry subsystem — the PortHop transport
(`ncp_porthop.{hpp,cpp}`), the outer-mask layer (`ncp_mimicry.{hpp,cpp}`),
the signed profile catalog and transition protocol
(`ncp_reference_profile_catalog.*`, `ncp_profile_transition.*`,
`ncp_mimicry_session.*`), the FSM/shaper timing models, and their CLI
surface. The TCP desync pipeline, Geneva, ECH and DoH subsystems have their
own trust properties and are covered only where they share a boundary.

---

## 1. Claim discipline — no unqualified "invisibility"

The words **"invisible", "undetectable", "unblockable", "stealth"** (and their
translations) are **banned as unqualified claims** anywhere in this subsystem:
documentation, CLI help, stats JSON field names, log messages, test names,
commit messages, and external communication. A statement about the system's
behavior against observation is valid only when it carries:

1. a **verdict** from §5 (one of `CLASSIFICATION_MATCH`, `INTEROP_PASS`,
   `PROBE_EQUIVALENT`, `POLICY_PASS`, `CORRELATION_EQUIVALENT`,
   `NOT_VERIFIABLE`);
2. an **evidence pointer** (test file + scenario, or gate report id per
   `docs/DPI_EVIDENCE_GATE.md`);
3. a **scope**: the exact adversary class (§4), toolchain, capture set and
   date/session range the verdict was measured under.

Any claim lacking a currently-executed evidence pointer defaults to
`NOT_VERIFIABLE`. A claim whose evidence later fails (regression, toolchain
upgrade flipping an nDPI verdict) is **downgraded to `NOT_VERIFIABLE`
loudly** — the failing gate/test stays red — never silently re-scoped.
nDPI verdicts are classification evidence, not stealth probability; an
`Unknown` verdict on a negative control is a valid control, not a pass
(established rule, `docs/DPI_EVIDENCE_GATE.md`).

Rationale: this subsystem operates against adaptive, stateful censors whose
capabilities are not publicly enumerable. An absolute claim is unfalsifiable
and therefore unscientific; a verdict-scoped claim is testable, regressible
and honest about its boundary.

---

## 2. Assets

Ordered by impact of compromise. "Loss" = confidentiality (C), integrity (I),
or availability (A) of the asset.

| # | Asset | C/I/A | Compromise consequence |
|---|-------|-------|------------------------|
| A1 | E2E session keys (double-ratchet chains, X25519[/hybrid] shared secret) | C,I | Full plaintext recovery + forgery for that session |
| A2 | Per-session mask key (`session_mask_key`, HKDF from A1) | C,I | Mask-layer unwrap/forgery for stateful masks (QUIC_SHORT_HEADER AEAD, STUN MESSAGE-INTEGRITY); traffic becomes attributable to the mask format |
| A3 | PortHop schedule secret (HMAC-SHA256 hop schedule) | C,I | Predictable port rotation → cheap flow following and shaping |
| A4 | Catalog signing keys + `SignaturePolicy` enforcement | I | Forged/malicious descriptors become installable (attacker-chosen timing/size models, downgrade to weak profiles) |
| A5 | Profile/epoch consistency between endpoints | I,A | Desynchronized masks/epochs → systematic drop or uncertain divergence (W3 window, design doc §2.1) |
| A6 | Bounded work / bounded queues (CPU, memory, `out_q`) | A | Resource exhaustion via garbage floods or candidate-unwrap amplification |
| A7 | Traffic metadata shape (sizes, IAT, burst, volume, 5-tuple stability) | C | Flow classification/correlation against the reference-protocol model |
| A8 | Operator configuration confidentiality (resolver/catalog mapping, allowed-profile list) | C | Observer learns the mimicry menu, reducing search space |
| A9 | Endpoint identity / reachability of the server | C,A | Server enumeration → blocking or probing focus |

Notes:

- A2 is derived from A1 (`HKDF(E2E secret, "ncp-mimicry-session/mask-v1")`),
  so A2 compromise without A1 compromise implies an implementation defect —
  that path is audited specifically.
- A4 is a supply-chain boundary: external descriptors are signed (Ed25519,
  canonical BLAKE2b-256 content hash) and policy-checked
  (`ENFORCE`/`WARN_ONLY`/`DEV_UNSIGNED`); built-ins use the trusted
  compile-time path.
- A7 is the *only* asset whose protection is statistical; every claim about
  it is verdict-scoped per §1.

---

## 3. Trust boundaries

| Boundary | Between | Crossing rules |
|----------|---------|----------------|
| TB0 | Application ↔ `NcpMimicrySession` adapter | Application payloads are untrusted in size (pre-check `max_application_payload`, post-encode budget check, counted refusals, never truncated — see `docs/MIMICRY_TRANSPORT_ADR.md`) |
| TB1 | Adapter ↔ E2E (`E2ESession`) | E2E AEAD is authoritative for content; verify-then-commit: no ratchet/FSM/transition state mutates before AEAD success. **The X25519 ECDH handshake is unauthenticated against active MitM** (tracked in `docs/KNOWN_ISSUES.md`); the peer is trusted only up to that fact |
| TB2 | Inner PD/layout (`SessionProfileContext`) ↔ outer mask (`TrafficMimicry`) | The mask carries no trust: wrong-candidate unwraps that fail E2E AEAD are counted and dropped with zero state mutation; stateful masks add mask-level authentication (DCID check / MESSAGE-INTEGRITY-style HMAC) to reject before spending an E2E AEAD attempt |
| TB3 | Mask ↔ PortHop framing | PH frame validation (magic/session_id/epoch, optional header protection) is syntactic only; it authenticates nothing beyond possession of the hop secret |
| TB4 | Endpoint ↔ network | **Fully untrusted.** All adversary classes in §4 live here. Every datagram is assumed observed, recordable, delayable, duplicable, modifiable, forgeable |
| TB5 | Catalog supply ↔ endpoint | External descriptors cross only through `MimicryCatalogIo::load_file()` + signature policy; capacity limits enforced on all paths including built-ins |
| TB6 | Operator config ↔ runtime | CLI flags (`--mimicry-*`) and resolver mappings are trusted-local; they are never negotiated on the wire. Misconfiguration symmetric on both peers is an operator error class, not an adversary success, but fail-closed gates (GENERIC-only under v1, v2 AND-semantics) bound its blast radius |

The outer transport / relay boundary introduced by the TURN profile is
defined in `docs/MIMICRY_TRANSPORT_ADR.md` (D6): the TURN server is a TB4
resident — it is an **untrusted relay with its own credential domain**,
never a trust extension of the NCP session.

---

## 4. Adversary classes

Each class lists assumed capabilities, then what this subsystem claims and
explicitly does not claim against it. Classes are cumulative only where
stated; "in-path" does not automatically imply "correlation-grade storage".

### AC1 — Passive observer / offline classifier

Capabilities: full packet capture at one or more points; offline tooling
(nDPI, commercial DPI, ML classifiers); arbitrary compute on recorded
captures; knowledge of this design and of the mask formats (no security by
obscurity); no active injection.

Claims: verdict-scoped only — `CLASSIFICATION_MATCH` for specific
mask/classifier/capture-set combinations; `POLICY_PASS` for budget/shape
conformance. Session-content confidentiality (A1/A2) is cryptographic, not
verdict-scoped.

Non-claims: statistical indistinguishability from genuine
WebRTC/QUIC/STUN populations; resistance to classifiers other than the
evaluated ones; any property of classifiers inside a specific provider's
TSPU deployment (§6).

### AC2 — Active prober

Capabilities: everything AC1 has, plus sending arbitrary datagrams to the
endpoint, replaying recorded datagrams (same or different session), scanning
ports in the PH range, and timing responses.

Claims: fail-closed ingress — replayed/foreign datagrams fail at the
strongest available layer (session DCID check, mask-level HMAC/AEAD, E2E
AEAD + replay window, epoch fences), counted, no state mutation
(verify-then-commit); bounded per-datagram work (≤ 4 ordered mask candidates,
each a bounded unwrap; `ingress_dropped` and outer-mask counters).
`PROBE_EQUIVALENT` for a defined probe battery only.

Non-claims: endpoint non-existence (a prober CAN learn that *something*
listens); zero response surface; protection of the pre-handshake phase
beyond the documented drop rules (kind 'P' plaintext is dropped by default).

### AC3 — In-path enforcer

Capabilities: AC1+AC2 plus dropping, delaying, reordering, duplicating,
truncating, throttling (token-bucket shaping per 5-tuple/flow), and
long-running QoS penalties against flows it dislikes.

Claims: liveness degradation is **bounded and surfaced, never silent** —
transition retransmit budgets, grace windows, `transitions_uncertain` /
`ingress_dropped` counters, and the fail-closed uncertain-divergence
semantics (fresh-session recovery, proven in
`tests/test_udp_profile_transition_v2.cpp`). Port hopping limits the
durability of per-port shaping. The datagram budget (POLICY_PASS) keeps
every emitted datagram inside path MTU, removing fragmentation-based
selective-drop surfaces.

Non-claims: throughput preservation under targeted throttling; delivery
under 100% loss of a specific mask class (an enforcer that drops *all*
QUIC-shaped UDP drops the session — availability under total class-blocking
is out of scope, §6); covertness of the hop schedule against an enforcer
that correlates by payload size across ports (that is AC4).

### AC4 — Correlation adversary

Capabilities: multi-point observation (both ends of a flow, or
ingress/egress of a relay), long-term storage, cross-session and cross-day
linkage, size/timing/volume/burst analysis, and access to reference captures
of the genuine protocol for model training.

Claims: per-session polymorphism (HKDF-derived bounded variation per
session: rng_seed, burst/dwell scale, padding shifts — same profile,
different trace across sessions) raises the cost of *trivial* templates.
Any stronger statement requires a `CORRELATION_EQUIVALENT` verdict from a
pre-registered experiment (session-disjoint train/validation/eval, frozen
thresholds, genuine-reference captures, published sample sizes — the
methodology of `docs/DPI_EVIDENCE_GATE.md` §Interpretation).

Non-claims (default `NOT_VERIFIABLE`): resistance to flow correlation,
website-fingerprinting-style attacks, volume-based deanonymization, or
end-to-end timing confirmation. The shaper/FSM reduces shape variance; it
does not erase information.

### AC5 — DoS adversary

Capabilities: flooding with garbage or structurally-valid datagrams at line
rate, amplification attempts, state-exhaustion attempts against per-session
structures.

Claims: bounded work invariants — hard cap 4 RX candidates per datagram,
each bounded; mask-level authentication on stateful masks rejects cheap
garbage before E2E AEAD; bounded queues and retransmission budgets; strict
parser caps (`MAX_CONTROL_BODY_BYTES = 256`,
`MAX_PROFILE_DATA_PAYLOAD_BYTES = 65535`); no allocation growth keyed by
attacker input (capacity limits enforced in the catalog, per-session state
created only after the E2E handshake). PH demultiplexing is by session_id
over pre-bound sockets; no per-datagram socket creation.

Non-claims: bandwidth exhaustion resistance (impossible at this layer);
protection against DoS on the underlying path itself.

### AC6 — Compromised or malicious peer

Capabilities: a party that completed (or observed) a legitimate E2E
handshake and then acts adversarially — feeding malformed control,
attempting transition glare/storms, replaying old control, proposing
downgrade targets; or supplying a malicious catalog to the operator.

Claims: the transition protocol's defenses are designed for a misbehaving
*peer*, not just a network: `effective_counter` fencing binds control to the
live crypto stream (replayed/self-fed plaintext cannot confirm a
transition); one-outstanding-transition and BUSY/glare rules bound control
storms; strict-AND capability negotiation makes stripped-bit downgrades
fail-closed to v1/legacy behavior with no silent wire change; the
responder-side resolver gate independently refuses unacceptable targets
(`ABORT(UNKNOWN_PROFILE)`); catalog signatures + policy bound malicious
descriptors at TB5; a mask-only switch never touches E2E key state, so peer
mischief cannot downgrade content protection.

Non-claims: protection of data the peer legitimately receives (a
compromised peer knows the plaintext it was sent — inherent); detection of a
peer that is honest-but-curious at the application layer; defense against a
MitM that owned the initial ECDH exchange (KNOWN_ISSUES — such a "peer" is
indistinguishable from a legitimate one at this layer).

---

## 5. Verdict taxonomy

A verdict is a *scoped, evidence-backed* statement. The set is closed: new
verdict kinds require an edit of this document plus their evidence
procedure. Verdicts are per-(session-set, toolchain, date) and expire when
evidence is invalidated (§1).

| Verdict | Meaning | Required evidence | Explicitly does NOT imply |
|---------|---------|-------------------|---------------------------|
| `CLASSIFICATION_MATCH` | Every flow of the evaluated captures is classified by the named offline tool(s) (TShark + nDPI `ndpiReader`) as one of the expected protocol labels with `Confidence: DPI`, with no known-VPN labels/risks and no unrelated protocols in the summary | `scripts/lab/udp_dpi_gate.py` report, exit 0, on independent captures with unique session ids and valid negative controls (`docs/DPI_EVIDENCE_GATE.md`) | Statistical indistinguishability; any other classifier; any TSPU-class result; active-probe resistance; correlation resistance |
| `INTEROP_PASS` | The shaped traffic is accepted and processed without protocol error by a real, independent implementation of the mimicked protocol (e.g. a reference TURN server relays the allocation; a QUIC stack parses the datagrams) | Automated interop test against the named implementation+version, or captured manual run with version pinned | Classification match; behavioral equivalence under probing; that the peer implementation "believes" the traffic semantically |
| `PROBE_EQUIVALENT` | For a **defined, enumerated probe battery**, the endpoint's externally observable responses (or non-responses) match the reference implementation's within the battery's stated tolerance | Probe-battery spec (probes, expected responses, tolerances) + executed run, both version-pinned in `tests/` | Equivalence under probes outside the battery; equivalence of timing distributions unless the battery includes them |
| `POLICY_PASS` | Traffic conforms to a stated internal policy: datagram budget / no fragmentation, port policy, no plaintext emission, mask-format conformance, bounded work | Focused tests cited by file+scenario (e.g. B-1/B/B+1 budget tests, control-mask attribution probes) | Any external-observer property at all — POLICY_PASS is an internal correctness claim |
| `CORRELATION_EQUIVALENT` | Under a pre-registered multi-point experiment, the correlation metrics named in the protocol match reference-traffic values within frozen thresholds | Session-disjoint train/validation/eval capture sets, frozen thresholds committed before the final run, genuine-reference captures, published sample sizes and negative controls | Generalization to other correlation methods, other vantage points, or other time ranges |
| `NOT_VERIFIABLE` | Default verdict of every claim without a currently-passing evidence pointer. Also the mandated verdict for any statement about adversaries or deployments Dynam cannot test (§6) | — | — |

Claim record format (docs, reports, CLI stats annotations):

```
claim := VERDICT "(" scope ")" "evidence:" <pointer> ["as-of:" <date-or-commit>]
```

Example: `CLASSIFICATION_MATCH(mask=STUN_MESSAGE, tool=nDPI 4.x,
captures=gate-report-2024-... ) evidence: scripts/lab/udp_dpi_gate.py
manifest <id>`.

---

## 6. Out of scope

The following are **outside this threat model**. Any behavior statement
about them is `NOT_VERIFIABLE` by definition:

1. **Provider-specific DPI / TSPU internals.** Dynam does not possess, and
   this document does not model, the classifier sets, update cadence,
   whitelists, QoS policies or active-probe fleets of any specific national
   or ISP deployment. A `CLASSIFICATION_MATCH` against nDPI says nothing
   about TSPU-class systems (already codified in
   `docs/DPI_EVIDENCE_GATE.md` and `docs/MIMICRY_PROFILES.md`).
2. **ISP/state-grade correlation infrastructure** (backbone taps,
   long-horizon storage, cross-provider joins). AC4 claims are limited to
   executed experiments.
3. **Endpoint compromise of the host OS**, side channels (cache, power,
   EM), and physical access.
4. **The unauthenticated ECDH handshake MitM window** — tracked in
   `docs/KNOWN_ISSUES.md`; until closed, TB1 states the exact trust placed
   in a peer.
5. **Application-layer semantics** (what the tunneled traffic *does*),
   legal/policy questions, and operator Operational Security outside the
   configured surface.
6. **Availability under total blocking** of an entire protocol class or of
   UDP itself.
7. **The TURN relay operator as a trusted party** — the relay is TB4
   infrastructure; its credential domain is isolated by decision D6 of
   `docs/MIMICRY_TRANSPORT_ADR.md`, but its logging/CoTAM-visible metadata
   is not defended by this subsystem.

---

## 7. Observability hooks (verdict-relevant counters)

Threat-model-visible failures MUST be countable, not silent. Existing
surfaces used as evidence in claims:

- `Stats::mtu_budget_rejections` — budget enforcement (POLICY_PASS).
- `Stats::ingress_dropped`, `TrafficMimicry::MimicStats` — prober/garbage
  handling (AC2/AC5).
- `transition_counters.transitions_uncertain` / `transitions_timed_out` —
  enforcer-induced divergence (AC3); recovery proven by
  `CommitStormUncertainDivergenceRecovery`.
- `Stats::transition_v2_capable` — negotiated-mask surface actually in use
  (guards against operators misreading a stripped-bit v1 fallback as v2).
- Stats JSON (operator surface, `docs/MIMICRY_PROFILES.md`) — contains no
  secrets, no key material, no peer addresses; it is safe to attach to
  evidence reports.

Review rule: a PR that changes any of the above counters' semantics, or adds
a new externally visible claim, must name the affected verdict(s) and update
the evidence pointer or mark the claim `NOT_VERIFIABLE`.
