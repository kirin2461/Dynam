# ADR-G0-01: Mimicry Transport — Layered Datagram Budget, QUIC Path Scope, TURN Relay

Status: **Accepted** as design gate G0 (normative for implementation; the
QUIC-path and TURN decisions describe work that is not yet coded — where a
decision contradicts current defaults, the ADR wins and the code is brought
into line in the corresponding implementation step).
Audience: implementation agents and reviewers of the mimicry transport work.
Companion: `docs/MIMICRY_THREAT_MODEL.md` (verdict taxonomy used below),
`docs/MIMICRY_QUIC_RTC_DESIGN.md`, `docs/MIMICRY_PROFILES.md`,
`docs/DPI_EVIDENCE_GATE.md`.

Verified against (landed code, read for this ADR):
- `src/core/src/ncp_mimicry_session.cpp` / `ncp_mimicry_session.hpp` —
  `datagram_budget()` = `path_mtu_bytes - porthop_overhead_bytes`
  (defaults 1500 / 16), pre-check `max_application_payload` (default 1024)
  and hard post-encode budget check in `send_application()`, counted via
  `Stats::mtu_budget_rejections`, never truncated.
- `src/core/include/ncp_porthop.hpp` — 20-byte PH header
  (`HEADER_SIZE = 2+1+8+4+4+1`), flags incl. `PH_FLAG_CONTENT_PADDING`
  (payload || pad || padlen(1)), `HopSchedule` HMAC-SHA256 port rotation,
  loss/timer-triggered hops, interval ranges.
- `src/core/src/mimicry.cpp` — exact mask wire formats:
  GENERIC_UDP/GENERIC_TCP = 4-byte BE length prefix (+ optional
  size-mimicry padding for TCP); QUIC_INITIAL = self-describing,
  per-packet random DCID, min-1200-byte total datagram; QUIC_SHORT_HEADER =
  first byte (0x40|spin|rand) + 8-byte session DCID + 4-byte PN + 24-byte
  nonce + 4-byte CT length + XChaCha20-Poly1305(16) over
  `[wire_version][len:4][payload]` (62 bytes fixed overhead);
  STUN_MESSAGE = 20-byte header + payload attribute
  `[wire_version][len:4][payload]` 4-byte-aligned + MESSAGE-INTEGRITY-style
  attribute (4+20; HMAC-SHA256 truncated to 160 bits) — 53..56 bytes
  overhead.
- `src/core/include/ncp_profile_transition.hpp` — PD framing caps
  (`MAX_PROFILE_DATA_PAYLOAD_BYTES = 65535`, `MAX_CONTROL_BODY_BYTES = 256`).

No TURN client code exists in the tree today; §5 is the binding decision set
for its introduction.

---

## 1. Context

A data datagram traverses these layers, top to bottom:

```
application payload
  └─ E2E AEAD (E2ESession; NCP tag; double-ratchet counter/nonce/tag)
      └─ PD layout (SessionProfileContext: data/control framing, epochs)
          └─ kind byte ('E'/'H'/'C'/'P') + outer mask (TrafficMimicry profile)
              └─ PH frame + optional content padding (PortHopSession)
                  └─ outer transport (direct UDP, or TURN-encapsulated)
                      └─ UDP (8) / IPv4 (20) or IPv6 (40)
```

Every layer adds bounded overhead. The failure mode this ADR removes is
**budget ambiguity**: today the adapter enforces one budget
(`path_mtu_bytes - porthop_overhead_bytes`), but the reservation is a bare
number, TURN encapsulation or an IPv6 path would silently invalidate
assumptions, and the QUIC-shaped masks introduce a *floor* (min-1200-byte
Initial datagrams) in addition to overhead. Meanwhile the QUIC family
conflicts with PortHop semantics (connection continuity is the DPI-visible
invariant of a QUIC-shaped flow), and a TURN relay profile needs pinned
rules before anyone ships "wrap it in Send indications".

---

## 2. D1 — Layered budget and `max_application_datagram(path_state)`

**Decision.** There is exactly one authoritative sizing API at the
transport boundary, owned by the session adapter:

```
size_t max_application_datagram(const PathState& path_state);
```

It returns the maximum application-payload size such that the fully
encoded datagram — after **all** layers in §1, in that order — fits
`path_state.effective_mtu` (the largest UDP payload the path currently
carries without fragmentation, see D4 for who computes it). Semantics:

1. **Order of application is fixed and non-commutative**: application →
   E2E → PD/layout → kind/mask → PH/padding → outer transport → UDP/IP.
   Each layer subtracts its own worst-case bound (§3) from the budget it
   passes upward; layers never reason about other layers' internals.
2. **Refuse, never truncate, always count.** A payload above the budget is
   rejected before encoding (pre-check) and the fully encoded datagram is
   re-checked after encoding (the existing hard check in
   `send_application()`); violations increment `mtu_budget_rejections` and
   emit nothing. This is existing behavior, here made normative for every
   new transport/mask.
3. **`PathState`** carries: `effective_mtu`, IP version (UDP/IP header
   bound), outer-transport kind (direct / TURN-relayed) with its per-kind
   overhead, and the PH policy in force (D5). It is re-evaluated on:
   handshake completion, relay activation/refresh, PMTUD update, profile
   activation that changes the mask floor, and hop-policy change. A stale
   `PathState` must fail safe: unknown MTU ⇒ conservative default
   (1280-byte IPv6 minimum MTU basis).
4. **Mask floors are budget constraints, not overhead.** QUIC_INITIAL
   forces `datagram ≥ 1200` bytes; therefore a QUIC_INITIAL-capable path
   requires `effective_mtu ≥ 1200 + transport encapsulation`, and
   `max_application_datagram()` on such a path is computed against that
   floor — a path whose budget is below the floor makes the mask
   unselectable (profile validation fails closed, counted), rather than
   emitting undersized Initials.
5. **Fragmentation is forbidden**: no IP fragmentation and no layer may
   split one application payload across datagrams. One payload → at most
   one datagram → at most one UDP/IP packet.
6. Existing `Config::path_mtu_bytes` / `porthop_overhead_bytes` /
   `max_application_payload` remain the legacy inputs; the implementation
   step maps them onto `PathState` (direct-UDP IPv4/IPv6) without changing
   current wire behavior. Note the current default reservation
   (`porthop_overhead_bytes = 16`) is **smaller than the actual PH header
   (20 bytes)** — tolerated today only because `max_application_payload`
   (1024) sits far below the budget; the implementation step MUST validate
   `porthop_overhead_bytes ≥ PH_HEADER_SIZE + configured padding headroom`
   at config time (fail closed), per §3.

Claim class: `POLICY_PASS` (internal correctness; says nothing about any
observer — see `docs/MIMICRY_THREAT_MODEL.md` §5).

## 3. D2 — Overhead bounds (normative table)

Per-layer worst-case bounds charged by `max_application_datagram()`.
Constants are from the landed code cited above; new masks/transports must
extend this table in the same PR that adds them.

| Layer | Bound (bytes) | Source |
|-------|---------------|--------|
| IP | 20 (IPv4) / 40 (IPv6) | path_state.ip_version |
| UDP | 8 | fixed |
| Outer transport: direct | 0 | — |
| Outer transport: TURN ChannelData | 4 (+ up to 3 pad when UDP padding is applied) | RFC 8656 §11.4 (established data path, D6) |
| Outer transport: TURN Send/Data indication | 36 (STUN header 20 + XOR-PEER-ADDRESS 12 (IPv4) + DATA attr header 4); 48 with an IPv6 peer address (XOR-PEER-ADDRESS 24) | bootstrap only (D6); accounted when bootstrap is active |
| PH frame | 20 (`HEADER_SIZE`) + `pad_max + 1` when content padding enabled | `ncp_porthop.hpp` |
| kind byte | 1 | adapter wire format |
| Outer mask: GENERIC_UDP / GENERIC_TCP | 4 (+ `max_padding` when `enable_size_mimicry`) | `mimicry.cpp` |
| Outer mask: QUIC_SHORT_HEADER | 62 | layout above |
| Outer mask: STUN_MESSAGE | 56 (incl. max 3-byte alignment pad) | layout above |
| Outer mask: QUIC_INITIAL | overhead is subsumed by the 1200-byte floor (D1.4) | `mimicry.cpp` |
| E2E + PD/layout | declared by `E2ESession`/`SessionProfileContext` as a single bounded constant per crypto epoch state; never estimated from payload content | `ncp_e2e.*`, `ncp_profile_transition.*` |

Rules:

- Bounds are **worst-case constants or config-derived maxima**, never
  sampled, averaged, or measured from emitted traffic.
- The sum across layers is computed with saturating arithmetic; overflow ⇒
  budget 0 ⇒ all sends refused (fail closed, counted).
- Control datagrams (transition control, handshake, caps) use the same
  budget; `MAX_CONTROL_BODY_BYTES = 256` keeps control far below any legal
  budget.

## 4. D3 — Boundary tests (B-1 / B / B+1)

**Decision.** Every budget-enforcing layer ships tests at three exact
points, for every mask × outer-transport × IP-version combination that is
config-valid:

- **B-1**: largest payload whose encoded datagram is one byte under the
  budget → MUST be accepted and emitted; receiver decodes it bit-exactly.
- **B**: payload whose encoded datagram is exactly the budget → MUST be
  accepted and emitted (the budget is inclusive); decoded bit-exactly.
- **B+1**: first payload whose encoded datagram exceeds the budget → MUST
  be refused: `send_application()` returns empty, **zero bytes emitted on
  the wire**, `mtu_budget_rejections` increments by exactly 1, no session
  state change.

Test placement: hermetic pairs in the `test_mimicry_session*` family for
the mask/kind/PD/E2E stack; `test_udp_profile_transition*` harnesses for
the full PortHop+UDP stack; mask-format roundtrips in
`test_mimicry_roundtrip.cpp` for the mask-layer bound (including the
QUIC_INITIAL floor: on a 1200-floor mask, B is measured against
`max(budget, 1200)` and payloads too large to fit even with the floor are
B+1-rejected). New transports (TURN) add their encapsulation row to the
same test matrix rather than a bespoke test.

Additional pinned cases: budget change mid-session (PathState update)
re-sizes immediately; saturating-overflow config refuses everything;
`PH_FLAG_CONTENT_PADDING` at `pad_max` still passes B.

## 5. D4 — QUIC owns external PMTUD

**Decision.** On any path where the outer transport is QUIC-shaped
(QUIC-family masks today; a real QUIC shim if one is ever introduced),
**the QUIC layer — and only the QUIC layer — performs external path MTU
discovery**, in the QUIC style: probe datagrams padded to a candidate size
(QUIC PING/PADDING-equivalent), effective MTU raised only on acknowledged
probes, per RFC 9000 §14 / DPLPMTUD (RFC 8899) semantics.

- The NCP stack does **not** emit its own PMTUD probes on such a path and
  does not run parallel PLPMTUD; it consumes `path_state.effective_mtu`
  from the QUIC layer.
- **ICMP PTB is never required and never trusted upward**: a PTB may lower
  `effective_mtu` (clamped to the 1200-byte QUIC floor), never raise it.
  PTB blackholing therefore degrades gracefully instead of stalling.
- On non-QUIC paths the stack keeps its current behavior: configured
  `path_mtu_bytes` (conservative default), no active probing; the
  `max_application_datagram()` contract is unchanged because it reads only
  `path_state`.
- The QUIC floor (1200) and the mask floor (D1.4) coincide by design; a
  QUIC path whose discovered MTU falls below 1200 is declared unusable for
  QUIC-family masks (fail closed, counted, surfaced in stats).

## 6. D5 — QUIC initial scope: fixed path; `hop_policy = disabled`

**Problem.** The QUIC-shaped masks get their DPI-visible continuity from a
**session-stable DCID on a stable 5-tuple**. Port hopping rotates the port
mid-session; to any observer that is a brand-new flow with a reused DCID —
the single most recognizable anti-pattern possible (worse than not
mimicking QUIC at all), and it also breaks the W1/W2 zero-gap reasoning of
the transition protocol, which assumes one 5-tuple per session.

**Decision.**

1. When the active or allowed profile set contains a QUIC-family profile
   (descriptor family QUIC, or mask QUIC_INITIAL/QUIC_SHORT_HEADER), the
   session's path is **fixed**: `hop_policy = disabled`. One 5-tuple for
   the session lifetime.
2. **Legacy hop options fail, loudly, at configuration/validation time**
   when combined with a QUIC-family profile: any configured HopSchedule
   rotation (interval or range), `HOP_NOTIFY` use, and loss-triggered
   hopping (`should_hop()` path) is a configuration error — startup
   refusal with a clear message, or profile-activation refusal if
   requested mid-session — never silently ignored, never applied. Fail
   closed per `docs/MIMICRY_THREAT_MODEL.md` (misconfiguration must not
   produce a half-hopped QUIC flow).
3. `hop_policy` is part of `PathState` (D1.3), so `max_application_datagram()`
   and the B-1/B/B+1 tests see it; a mid-session change of hop policy on a
   QUIC-family active profile is refused.
4. **Connection migration, NAT rebinding support and multi-path are out of
   initial scope.** The future mechanism is **`quic_migration_v1`**, a
   separate ADR + design, and it MUST NOT be built by re-enabling PortHop
   machinery over QUIC masks: QUIC migration is connection-ID-driven with
   path validation (RFC 9000 §9), not port-epoch-schedule-driven. Reusing
   hop epochs would couple migration timing to the shaper-visible port
   stream and reintroduce exactly the anti-pattern above. Until
   `quic_migration_v1` lands, a change of path under a QUIC-family profile
   is a **new session** (same recovery primitive as the uncertain-
   divergence rule in `docs/MIMICRY_PROFILES.md`).

## 7. D6 — TURN relay profile (initial scope)

**Problem.** A relayed path is needed for NAT-strict deployments and as a
reachability fallback. TURN (RFC 8656) over UDP is the only candidate whose
wire shape is already in the mask family (STUN). Unpinned choices here —
credential coupling, indication vs channel mixing, TCP fallback — would
create fingerprint, key-isolation and budget problems respectively.

**Decision.**

1. **TURN over UDP only.** The relay transport is UDP. TURN over TCP, TLS
   or DTLS is **out of initial scope**: configuring any of them fails
   validation. (Rationale: TCP/TLS changes the entire byte-stream shape
   the mimicry subsystem is built around — a datagram, budget and mask
   discipline — and a TLS-wrapped relay adds a second, un-mimicked TLS
   stack to the threat surface. Revisit in a separate ADR if needed.)
2. **Independent long-term credentials.** Relay authentication uses the
   TURN long-term credential mechanism (RFC 8656 §9.2 /
   RFC 5389 §10: `MESSAGE-INTEGRITY` over `MD5(username:realm:password)`
   — carried out by the TURN client against the relay's realm/nonce).
   These credentials live in a **separate credential domain**: they are
   provisioned independently, stored separately, and are **never derived
   from, equal to, or wrapped by** the NCP E2E session keys, the
   `session_mask_key`, or the PortHop secret. A compromised relay
   credential compromises relay access only — no NCP session, mask or hop
   material (asset isolation per threat-model §2/§3; the relay itself is
   TB4-untrusted).
3. **Established data path: ChannelData only.** After a channel is bound
   (`ChannelBind` success), all session data travels as ChannelData
   messages (4-byte overhead, §3). **Send/Data indications are permitted
   exclusively during bootstrap** — the window before the channel binding
   completes (Allocate → CreatePermission → ChannelBind). Once the channel
   is bound, receiving or emitting a Send/Data indication on the session
   data path is a protocol violation: drop, count, surface.
4. **No random alternation.** The encapsulation choice is **not**
   randomized per datagram and does not alternate between ChannelData and
   Send/Data on the established path. Alternation is both a fingerprint
   anomaly (real TURN clients pin to ChannelData after binding for the
   overhead saving) and a state/correlation hazard (two parallel sequence
   surfaces). Determinism here is the mimicry-correct behavior.
5. **Budget integration.** Relay activation produces a new `PathState`
   (D1.3): outer-transport overhead becomes ChannelData (4) or, while
   bootstrap indications are in use, the indication bound (§3);
   `effective_mtu` is re-derived for the relayed path. The B-1/B/B+1
   matrix (D3) gains the TURN rows.
6. **Interop claim discipline.** Conformance of the TURN client against a
   reference TURN server is claimed as `INTEROP_PASS` (pinned server +
   version) and its wire shape as `CLASSIFICATION_MATCH` only through the
   evidence gate; both per `docs/MIMICRY_THREAT_MODEL.md` §5. No stealth
   claim attaches to "a TURN server accepted our traffic".

## 8. Migration constraints (all transport changes)

Binding rules whenever the outer transport or path changes (relay on/off,
relay change, path change, future `quic_migration_v1`):

- **A transport change is a new `PathState`**: budget, hop policy and mask
  floors are recomputed before the first datagram on the new path; sends
  are refused (not mis-sized) while the new state is uncomputed.
- **Relay switch = profile/transport transition, not silent fallback.**
  Falling back from relayed to direct (or vice versa) mid-session goes
  through the transition protocol machinery (or a fresh session when the
  masks involved require it); a silent transport swap is forbidden because
  it changes the observer-visible 5-tuple/encapsulation without any
  epoch-bound event.
- **TURN allocations are time-limited**: lifetime refresh is mandatory;
  allocation expiry under traffic is a path failure event (new PathState /
  new session), never a silent degradation to Send/Data or to direct.
- **Credential rotation** (relay password change) does not touch NCP
  session state (D6.2 isolation); it requires a re-allocation, which is a
  new PathState.
- **Legacy peers**: all of the above is negotiated/configured locally;
  nothing in this ADR changes any byte of the NCP wire protocol, the
  transition control codec (`PROFILE_TRANSITION_WIRE_VERSION = 1`), or the
  capability bits.

---

## 9. Alternatives considered (summary)

| Alternative | Rejected because |
|-------------|------------------|
| Single global MTU constant, truncation of oversized payloads | Silent data corruption; violates refuse-and-count (D1.2) and makes evidence claims untestable |
| Per-layer independent budgets | Layers would each fit locally while the composed datagram overflows; the budget must be composed top-down (D1.1) |
| NCP-run PLPMTUD on QUIC paths + ICMP PTB trust | Two PMTUD owners race; PTB is routinely spoofed/blackholed; QUIC already standardizes probe-based PMTUD (D4) |
| Keep PortHop enabled under QUIC masks | Stable-DCID-over-rotating-ports is a stronger fingerprint than no mimicry; breaks transition zero-gap reasoning (D5) |
| Build migration by re-enabling hop epochs over QUIC | Couples migration to a DPI-visible port schedule; QUIC migration is CID-driven — separate `quic_migration_v1` design (D5.4) |
| TURN over TCP/TLS "for reachability" | Breaks the datagram/budget/mask discipline; second TLS stack on the threat surface; deferred to a separate ADR (D6.1) |
| Derive TURN credentials from the E2E secret | Compromise cascade across credential domains; violates asset isolation (D6.2, threat-model §2) |
| Random ChannelData/Send alternation "for diversity" | Anomalous vs real TURN clients; doubles the sequence/correlation surface (D6.4) |
| Send/Data as permanent data path (simpler, no ChannelBind) | 36–48-byte overhead vs 4; diverges from real client behavior on established paths (D6.3) |

## 10. Consequences

- `max_application_datagram(path_state)` becomes the single sizing entry
  point; existing `datagram_budget()` semantics are preserved as the
  direct-UDP instance. Implementation steps must keep
  `mtu_budget_rejections` semantics unchanged (counted refusals, zero
  emission).
- Config validation gains fail-closed checks: PH reservation ≥
  PH header + padding headroom (D1.6); QUIC-family profile ⇒
  `hop_policy = disabled` with legacy hop options refused (D5.2); TURN
  over TCP/TLS/DTLS refused (D6.1).
- The B-1/B/B+1 test matrix (D3) is mandatory for every new mask and
  every new outer transport; it is the `POLICY_PASS` evidence for the
  budget claim.
- Any externally visible claim resulting from TURN/QUIC work is
  verdict-scoped per `docs/MIMICRY_THREAT_MODEL.md` §5 — by default
  `NOT_VERIFIABLE` until its evidence lands.
- Out of initial scope, explicitly deferred: `quic_migration_v1`
  (separate ADR), TURN over TCP/TLS/DTLS (separate ADR if ever),
  NCP-active PMTUD on non-QUIC paths, protocol-level resync of uncertain
  divergence (unchanged from `docs/MIMICRY_PROFILES.md`).

## 11. Mandatory implementation exit gates

The following are **blocking acceptance gates**, not optional follow-ups:

1. **G3 legacy sensitivity:** the byte-exact legacy transport regression must
   pass, while the existing external target controls retain their preregistered
   sensitivity: functional Dynam scenarios may pass, but a target that was
   externally classified incorrectly must not be relabeled PASS without fresh
   capture evidence. A local classifier/unit test cannot satisfy this gate.
2. **G3 enforcer smoke:** the Suricata/nftables harness must execute at least
   once in an authorized disposable environment and prove both directions of
   control: an allowed control passes and a blocked control is actually
   dropped by the independent enforcer. Until that run exists the harness is a
   design artifact and `POLICY_PASS` remains NOT VERIFIED.
3. **G4 independent interoperability:** a real QUIC implementation must
   interoperate with Dynam in both client and server roles. Mask roundtrips,
   syntactic Initials, or nDPI labels cannot satisfy this gate.
4. **G5 reference-relay interoperability:** Allocate, CreatePermission,
   ChannelBind, Refresh, ChannelData and expiry behavior must pass against a
   pinned independent TURN server. Established application flow must contain
   no Send/Data indications.

These gates require their respective runtime environments. If an environment
is unavailable, implementation may continue and the corresponding verdict
remains NOT VERIFIED; it must never be converted into a local PASS by
inspection alone.
