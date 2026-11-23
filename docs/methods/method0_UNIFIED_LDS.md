# Unified Method — Layered Divergence Stack (LDS)

> Synthesis of the five method proposals produced in parallel (Task 5). Each agent
> designed one layer independently; this document merges them into **one coherent
> method** with a single selection/feedback loop, resolving overlaps and defining
> precedence. Engineering design only — nothing here is built or runtime-tested.

## The five parts

| # | Agent | Technique | Layer | Doc |
|---|-------|-----------|-------|-----|
| 1 | TLS | **BSCH** — Boundary-Straddle ClientHello | TLS record framing | `methods/method1_tls_clienthello.md` |
| 2 | TCP/IP | **DLO** — TTL-Staged Dual-Layer Overlap | L3/L4 packet | `methods/method2_tcpip_desync.md` |
| 3 | QUIC | **QPD** — QUIC Initial Parser-Divergence | QUIC/UDP | `methods/method3_quic_udp.md` |
| 4 | Mimicry | **AFPS** — Adversarial Feature-Projection Shaper | Traffic statistics | `methods/method4_mimicry_antiml.md` |
| 5 | Transport | **ATS-DF** — Adaptive Transport Selection + Decoy-Fronted Framing | Transport selection | `methods/method5_transport_obfs.md` |

## The merged method

**Layered Divergence Stack (LDS)** applies the five parts as a *pipeline* whose
configuration is driven by one feedback-aware selector. Each layer solves a
failure mode the others cannot, and they compose without conflict because they
operate at disjoint layers:

```
           ┌─────────────────────────────────────────────┐
           │  ATS-DF  (choose transport, front prefix)    │  layer 5
           └───────────────────────┬─────────────────────┘
                                   ▼
           ┌─────────────────────────────────────────────┐
           │  BSCH  (re-frame ClientHello into records)  │  layer 1
           └───────────────────────┬─────────────────────┘
                                   ▼
           ┌─────────────────────────────────────────────┐
           │  DLO   (TCP seqovl + IPv4/6 overlap poison) │  layer 2
           └───────────────────────┬─────────────────────┘
                                   ▼
           ┌─────────────────────────────────────────────┐
           │  QPD   (coalesced decoy+real QUIC Initial)  │  layer 3 (UDP path)
           └───────────────────────┬─────────────────────┘
                                   ▼
           ┌─────────────────────────────────────────────┐
           │  AFPS  (shape size/IAT to defeat ML)        │  layer 4 (all paths)
           └─────────────────────────────────────────────┘
                                   ▲
                        feedback ──┘  (success/failure → ATS-DF + AutoPilot ML)
```

### Precedence & conflicts (resolved)

1. **ATS-DF is the outermost decision.** It picks the transport and sets the
   per-session front prefix. BSCH/DLO/QPD are then applied *inside* whatever
   transport it chose — except QUIC, where QPD replaces BSCH+DLO (different wire
   protocol). Rule: `if transport == Quic → QPD; else → BSCH ∘ DLO`.
2. **AFPS is orthogonal and always on** — it shapes `(size, iat)` regardless of
   protocol, and its candidate selection consumes the same classifier margins
   BSCH/DLO are trying to exploit. No conflict.
3. **Shared signal, no duplicated learner.** ATS-DF's health scores and the
   AutoPilot ML feature (Task 1) read the *same* `OutcomeRow` sink AFPS exposes.
   One learner serves three consumers → no duplicated feedback logic.
4. **Header protection is reused, not reinvented.** ATS-DF's front prefix and
   DLO's poison-copy staging both use the existing `HeaderProtection` /
   `autottl` primitives. No new crypto.

### Why the stack, not a single trick

Each lab result in the repo motivates one layer:
- Positional TCP splits score **0% vs the reassembly model** → needs DLO (layer 2).
- Cheap DPIs read SNI from "the first record" → BSCH (layer 1) survives
  re-coalescing where TCP splits don't.
- QUIC has no visible SNI and separate fakes are droppable → QPD (layer 3)
  removes the second packet entirely.
- Fixed statistical profiles are memorizable by an ML classifier → AFPS (layer 4).
- Transport choice under a selective adversary is static → ATS-DF (layer 5).

## Implementation mapping

| Layer | New/changed files | Interface |
|-------|-------------------|-----------|
| 5 ATS-DF | `ncp_transport_manager.{hpp,cpp}`, `ncp_connection_director.cpp` | `AdaptiveTransportSelector::choose/report_*` |
| 1 BSCH | new `ncp_tls_boundary_straddle.hpp`, hook in `dpi_advanced.cpp` `process_outgoing` | `straddle_client_hello()` |
| 2 DLO | `ncp_desync_confuse.cpp` (new builder) | `desync::dlo(...)` + `DPIConfig::enable_dlo` |
| 3 QPD | `ncp_quic.{hpp,cpp}` (new builder), `ncp_dpi.cpp` UDP path | `build_coalesced_initial()` |
| 4 AFPS | `ncp_mimicry_stats.cpp`, `NcpMimicrySession::send_application` | `AfpsShaper::plan()` |
| feedback | `autopilot.cpp` (Task 1) consumes `OutcomeRow` | — |

## Rollout order (each step independently shippable + testable)

1. **DLO** — pure packet builder, testable by pcap assertions with no network.
2. **QPD** — one function, unit-testable (coalesce invariants).
3. **BSCH** — header-only, unit-testable (record re-framing invariants).
4. **AFPS** — pure math, unit-testable with a fake classifier.
5. **ATS-DF** — policy layer; needs 1–4 present to be meaningful.
6. **Feedback wiring** — tie ATS-DF + AFPS + AutoPilot to one sink.

## Honest caveats

- **No layer claims a guaranteed real-world bypass.** Several explicitly concede
  defeat by a *fully conformant* reassembler (BSCH, QPD). The stack's premise is
  divergence between a cheap middlebox and a compliant endpoint — validated only
  in `docker/dpi-emu.py` and unit tests.
- **Interaction risk.** Layers were designed independently; the composition
  (BSCH inside an ATS-DF transport, DLO poison copies under AFPS timing) is
  *unproven* — it needs a combined lab matrix run before any claim.
- **Nothing built or run.** No toolchain on the design host.
