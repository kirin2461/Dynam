# NCP C++ Architecture

## Overview
NCP C++ (Dynam) is a multi-layered network anonymization platform built on a three-layer architecture. All code uses the `ncp::` namespace, modern C++17 with `constexpr`/`noexcept` optimization.

> **Note**: Security audit in progress — see [AUDIT.md](../AUDIT.md) for current findings.

## Three-Layer Architecture

### Layer 1: Core Library (libncp_core) — 42 modules
**Purpose**: All network operations, cryptography, anonymization, and security logic.
**49 public headers** in `src/core/include/`, **46 implementation files** in `src/core/src/`.

#### Cryptography & Security
- **CSPRNG**: Libsodium wrapper for cryptographically secure randomness.
- **E2E Encryption**: X25519-based key exchange with Kyber1024 hybrid support.
- **Secure Memory**: RAII-based secure buffers with automatic zeroing and page locking.

#### DPI Bypass & Evasion
- **DPI Advanced**: Multi-technique pipeline (15+ evasion methods).
- **Geneva Subsystem**: Modular engine for evolving evasion strategies (GA + Engine).
- **TLS/ECH**: Browser fingerprinting and Encrypted Client Hello support.

#### Stealth & Defense
- **Paranoid Mode**: Integrated 8-layer protection.
- **Flow Shaper**: Timing and size normalization.
- **License**: GNU AGPLv3


- **L2/L3 Stealth**: Low-level network stealth.

### Layer 2: CLI Tool
**Status**: Core commands implemented (`status`, `help`, `run`, `stop`, `rotate`).
- Built using RAII `Application` class to manage lifecycles.

### Layer 3: GUI Application
**Status**: Planned integration with Qt6 for visual management.

---

## Protocol Orchestrator Pipeline
The Protocol Orchestrator (`ncp_orchestrator.hpp`) chains all protection components:

1. **Send Pipeline**: Payload → TLS FP → DPI Advanced → Adversarial Padding → Mimicry → Flow Shaping → Network.
2. **Receive Pipeline**: Wire → Auth Verify → Dummy Check → Mimicry Unwrap → Unpad → Payload.

---

## Additions in the 1.7.x hardening wave

### Inbound peer policy (I2P server side)
`I2PPeerFilter` (`ncp_i2p.hpp`) is a socket-free policy object that decides
whether an inbound I2P stream is accepted: blocklist, optional allowlist,
per-peer concurrency cap and a sliding-window rate limit. `I2PManager` wires it
into a real accept path:

- `accept_inbound_stream(session_id, peer_dest, timeout)` opens its own SAM
  control connection, issues `STREAM ACCEPT … SILENT=false`, reads the
  `PEER DESTINATION=` line, applies the filter, and returns a raw stream
  handle (or `-1` when rejected/timed out).
- `read_inbound_stream()` / `close_inbound_stream()` own the accepted socket;
  the filter's release hook is called on close.
- `set_inbound_peer_callback(cb)` observes every inbound peer in real time —
  `cb(dest, allowed, reason)` fires for admits and rejects alike, outside all
  internal locks, so the caller can log/alert/persist.
- Counters: `Statistics::peers_accepted` / `Statistics::peers_rejected`, plus
  `accepted_peer_count()` / `rejected_peer_count()`.

Placement: server tunnels only. Client tunnels are unaffected.

Known limit: the policy is per-destination, not per-router. I2P gives the
server no router identity for an inbound stream; a peer that rotates
destinations appears as a new peer each time. Rate limits are therefore the
backstop for that case.

### Outbound destination policy (I2P client side)
`I2POutboundPolicy` (`ncp_i2p.hpp`) is the mirror image for dialling out:

- **blocklist / allowlist** — a destination that is refused is never
  interpolated into a SAM command;
- **format validation** — rejects whitespace/control bytes (command
  injection), malformed `.i2p` hostnames and implausible base64 destinations;
- **first-use pinning** (default on) — the first destination a session
  connects to is pinned. A later `connect_outbound_stream()` from the same
  session to a different destination is refused with `destination-changed`
  unless the operator allowlisted it or called `clear_pinned_destinations()`.
  That is the server-impersonation case: a named tunnel cannot be silently
  re-pointed.

`I2PManager::connect_outbound_stream(session_id, dest, timeout)` opens a SAM
connection, issues `STREAM CONNECT … SILENT=false`, reads the far-end
`PEER DESTINATION=` line, and aborts with `destination-mismatch` if a full
base64 destination was requested and the far end is not byte-identical. It
refuses to send anything for a session ID this manager did not create.
`write_outbound_stream()` / `read_outbound_stream()` /
`close_outbound_stream()` own the stream socket.

Every attempt lands in a bounded audit ring (`outbound_history()`) with
`session_id`, destination, outcome, reason and bytes sent (filled at close);
`set_outbound_event_callback()` fires in real time, outside all locks.
Counters appear as `Statistics::outbound_established` / `outbound_rejected` /
`outbound_failed`.

### Adaptive size/error learning
`SizeErrorLearner` (`ncp_adversary_tester.hpp`) is an online logistic model
over windowed features: mean size, size CV, small/large fractions, connection
error rate, timing CoV, burst anomaly and KS distance. It is dependency-free,
inspectable (9 weights) and falls back to a transparent prior until enough
samples exist.

Integration point: `AdversaryTester::set_size_learner()` attaches a learner.
Every `evaluate_flow()` then:

1. derives `SizeErrorFeatures` from the current window (plus `record_error()`
   counts) and the window's heuristic scores (timing, burst, KS),
2. stores `TestReport::learned_detection_probability`,
3. updates the model from the heuristic verdict.

The orchestrator does not consume the estimate yet; wiring it into strategy
selection is the remaining step.

### Per-host detector reports
`DpiDetector` gained `host_reports()` (per-host blocked state, consecutive
timeouts, event count), `set_block_ttl()` (lazy block expiry) and `reset_all()`.
The GUI/CLI detector feed can render a host table from a single call instead of
reconstructing state from the event ring.

### Size-shape metric: W1 and exact quantile shaping
`ncp_optimal_transport.{hpp,cpp}` adds the 1-D Wasserstein-1 distance and a
streaming quantile shaper. `FlowShaper` now draws target sizes from a per-block
permutation of the reference multiset (`enable_quantile_shaping`, on by
default), so a complete block of emitted packets reproduces the reference size
multiset exactly instead of only in expectation; payloads larger than a draw
are split, one draw per chunk.

`HeuristicScores` gained `w1_distance` and the weight vector was rebalanced
(KS 0.15 → 0.10, W1 0.05; total still 1.0). Callers with calibrated
thresholds should re-check them — the maximum shift is 0.05.

Note that `SizeDistribution` (shaper) and `ReferenceProfile` (scorer) are two
independent size catalogs, so a block-exact flow still measures a residual
W1 of up to one bucket width against the scorer's reference.

Full description, guarantees, tuning knobs and the falsification record:
[`OPTIMAL_TRANSPORT_SHAPING.md`](OPTIMAL_TRANSPORT_SHAPING.md).

---

## Technical Specifications
- **C++ Standard**: C++17
- **Cryptography**: Libsodium (XChaCha20-Poly1305, Ed25519)
- **Networking**: Raw Sockets, libpcap/Npcap
- **Logging**: Internal RAII Logger (Thread-safe)

