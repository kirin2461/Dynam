# NCP-CPP Security Audit

> **Auditor**: AI Code Review
> **Date Updated**: 2026-11-16
> **Status**: Ongoing (Regularly updated with core fixes)

---

## Summary

> **2026-11-16 — R17 review**: Code review of `a5dfdd3^..HEAD` (protected transports + adaptive client, +53.7K LOC) found **2 high + 3 medium + 4 low + 1 efficiency** issues, plus 2 cleanups. **R17-01..09 fixed** on `fix/r17-findings` (not yet compiled or tested); R17-10 and the cleanups left open as quality items. These findings come from reading the code only; nothing was built, run or reproduced. See [R17 Findings](#r17-findings-2026-11-16) below.

> **2026-09-12 — R16 wave**: External audit (~90K LOC) found **11 critical + ~20 high + ~14 minor** issues — **all fixed** across 6 fix zones (`fix/zone-a`..`f`), merged into `integration`. Tests: 786 → **812 passed**, 8/8 ctest targets green, TSan clean. Full details: [r16.md](r16.md).

| Severity | Count | Status |
|---|---|---|
| 🔴 Critical | 15 | 8 FIXED, 5 Open, 2 Obsolete (R16) |
| 🟠 Logic/Race | 42 | 20 FIXED, 22 Open |
| 🟡 Quality | 30 | 15 FIXED, 15 Open |

---

## Key Fixed Findings

### 🔴 #5 — `ncp_probe_resist.cpp`: Timing Oracle in Auth Verification
- **Status**: ✅ FIXED
- **Verification**: Early-return replaced with constant-time `sodium_memcmp`.

### 🔴 #64 — `ncp_port_knock.cpp`: Fallback HMAC is XOR
- **Status**: ✅ FIXED
- **Verification**: XOR replaced with libsodium `crypto_auth()`.

### 🔴 #22 — `ncp_probe_resist.cpp`: CSPRNG raw /dev/urandom
- **Status**: ✅ FIXED
- **Verification**: Replaced with `randombytes_buf()` from libsodium.

### 🔴 #55 — `doh.cpp`: SSL_CTX Double-Free
- **Status**: ✅ FIXED
- **Verification**: Correct lifetime management via pImpl.

---

## Open Findings (Priority)

### 🔴 #1 — `ncp_dpi.cpp`: `apply_tcp_split` off-by-one buffer read
- **Status**: 🚫 OBSOLETE (2026-09-12, R16)
- **Description**: Potential OOB read in TCP segment splitting logic.
- **Resolution**: No function named `apply_tcp_split` exists in the codebase. The actual analogue, `send_with_fragmentation`, contains exhaustive bounds checks and passed 2.5M fuzzing iterations under ASan/UBSan (see [r16.md](r16.md)).


### 🔴 #2 — `ncp_dpi.cpp`: `process_tls_client_hello` unbounded SNI extraction
- **Status**: 🚫 OBSOLETE (2026-09-12, R16)
- **Description**: Crafted ClientHello can cause OOB read due to missing bounds check on SNI length.
- **Resolution**: No function named `process_tls_client_hello` exists in the codebase. The actual analogue, `find_sni_hostname_offset`, performs exhaustive bounds validation and passed 2.5M fuzzing iterations under ASan/UBSan (see [r16.md](r16.md)).

---

## R17 Findings (2026-11-16)

**Scope**: `a5dfdd3^..HEAD` (commits `98159d5`, `a5dfdd3`, `999f62e`, 2026-10-29..31).
**Read in full**: all changed non-test sources: e2e, porthop, blockcheck, autopilot, license, ech_retry, orchestrator, mimicry, mimicry_stats, connection_director, mimicry_session, transport_config, quic_director_adapter, catalog_io, and the porthop/blockcheck/autopilot/mimicry-catalog parts of `src/cli/main.cpp`.
**Skimmed only**: `ncp_profile_transition.cpp`, `ncp_turn_*`, `ncp_real_quic.cpp`, FSM code, lab scripts.
**Not reviewed**: tests, `third_party/msquic`, docs.
**Method**: Code reading only. No build, run or reproduction. Severities are the reviewer's estimates.

> **Note on fixes (2026-11-16)**: R17-01..09 are fixed on branch `fix/r17-findings`. The machine the fixes were written on has no C++ toolchain, so **none of the fixes have been compiled or tested**. Build and run `ctest` before merging. Fix summary:
> - **R17-01**: server director replaces a session when a KX request carries a *different* peer public key (`NcpMimicrySession::is_new_peer_handshake`); retransmits with the same key are still dropped.
> - **R17-02**: `PortHopSession::note_peer_epoch()`; the server records the highest client epoch and stamps replies with `max(own, peer)`. Its own epoch, schedule and replay fence are untouched. Regression test added.
> - **R17-03**: server-side failures are scoped per connection (`connection_error()`, `connections_failed`), already-polled egress for other connections is kept, client role stays sticky. The two "fatal" adapter tests were updated to the new contract.
> - **R17-04**: CLI clamps `--parallel` to 1..16, matching `AutoPilot::load()`.
> - **R17-05**: caps resent every 500 ms (max 8) until peer caps arrive; a duplicate peer caps triggers a reply; a client-side caps that overtakes the handshake response is held (≤4 KiB) and replayed after establishment.
> - **R17-06**: insertion-order deque drives eviction; cleared on reset/handshake, rebuilt from the map on state import.
> - **R17-07**: `bc_recv_full` reports Timeout/Reset/Closed; a reset is reported as `rst` again (TLS read and SOCKS CONNECT reply).
> - **R17-08**: `#` is a comment only at line start or after whitespace. Regression test added.
> - **R17-09**: `ProfileTransitionCounters::last_abort_reason`; the director reports it, falling back to `TIMEOUT` only when none is recorded.

| ID | Severity | Location | Issue | Status |
|---|---|---|---|---|
| R17-01 | 🟠 High | `ncp_mimicry_session.cpp:1146` | Secure PortHop server allows one handshake per session id per lifetime | Fixed (unverified) |
| R17-02 | 🟠 High | `ncp_porthop.cpp:238` | Epoch replay fence drops all server frames after 5 client hops | Fixed (unverified) |
| R17-03 | 🟡 Medium | `ncp_quic_director_adapter.cpp:66` | One error permanently disables the QUIC adapter for all connections | Fixed (unverified) |
| R17-04 | 🟡 Medium | `src/cli/main.cpp:4103` | `learn-batch --parallel` not clamped; learns above 16 falsely reported failed | Fixed (unverified) |
| R17-05 | 🟡 Medium | `ncp_mimicry_session.cpp:813` | Capabilities datagram never retransmitted; transitions disabled if lost/reordered | Fixed (unverified) |
| R17-06 | ⚪ Low-Med | `e2e.cpp:572` | Skipped-key cap evicts smallest DH key, not oldest entry | Fixed (unverified) |
| R17-07 | ⚪ Low | `ncp_blockcheck.cpp:306` | RST no longer distinguished from timeout in blockcheck reports | Fixed (unverified) |
| R17-08 | ⚪ Low | `ncp_transport_config.cpp:166` | `#` inside a value silently truncates it | Fixed (unverified) |
| R17-09 | ⚪ Low | `ncp_connection_director.cpp:297` | Every adapter abort reported as `TIMEOUT` | Fixed (unverified) |
| R17-10 | ⚪ Efficiency | `ncp_connection_director.cpp:576` | `poll()` rebuilds stats map for all sessions every tick | Open |

### 🟠 R17-01 — `ncp_mimicry_session.cpp:1146`: one E2E handshake per session id
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: The secure `porthop serve` loop never removes a director session, and the adapter drops any handshake request once a `ctx` exists for that id.
- **Failure scenario**: Start `ncp porthop serve --mimicry-profile webrtc_video`. Run `ncp porthop client --mimicry-profile webrtc_video` once (works), then again with the default session id `0x1122334455667788`. The new `H` request is dropped as a duplicate; the client prints `Secure mimicry handshake timed out` after 5 s. The id stays unusable until the server restarts.
- **Fix direction**: Remove/expire sessions on close or idle timeout, or accept a fresh handshake for an existing id (re-key).

### 🟠 R17-02 — `ncp_porthop.cpp:238`: epoch replay fence starves the client after 5 hops
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: The new epoch replay fence (window 4) assumes peers exchange HOP_NOTIFY, but nothing sends `PH_FLAG_HOP_NOTIFY` and the server never hops, so server frames always carry epoch 0.
- **Failure scenario**: A long-lived `PortHopClient` hops every 60 s via `should_hop()`/`hop()`. After the 5th hop `min_accepted_epoch()` is 1, so every server ACK/echo (epoch 0) is fenced. Missing ACKs push `unacked_` above 3, triggering more hops; the link goes permanently silent. The one-shot CLI hops ~3 times per run, so this mainly hits library and long-running users.
- **Fix direction**: Actually send/handle HOP_NOTIFY so the server tracks the client epoch, or fence per-direction epochs separately.

### 🟡 R17-03 — `ncp_quic_director_adapter.cpp:66`: sticky `last_error` kills the adapter
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: `fail()` sets `last_error`, and every entry point returns early while it is non-empty. In `collect()`, an overflow also discards the remaining egress items already removed by `director.poll()`.
- **Failure scenario**: One peer sends a malformed bundle (bad count or trailing bytes), or one connection exceeds `max_pending_egress`. `pump()` returns false forever for every connection; already-polled control/data datagrams are lost. One bad client takes down service for all sessions.
- **Fix direction**: Scope errors per connection; drop only the offending input; never discard already-polled egress.

### 🟡 R17-04 — `src/cli/main.cpp:4103`: unclamped `--parallel` in learn-batch/learn-preset
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: The worker pool is sized from the CLI's own `cfg.max_parallel_learns`, which is not clamped; `AutoPilot::load()` clamps its internal copy to 16.
- **Failure scenario**: `ncp autopilot learn-batch <32 domains> --parallel 32` starts 32 workers. ~16 `learn()` calls hit the `learn_active` cap and print `no working strategy (marked degraded)` though they were never probed or marked degraded. The banner reports `parallel 32`.
- **Fix direction**: Clamp in the CLI with the same limit (or read back the clamped value from AutoPilot).

### 🟡 R17-05 — `ncp_mimicry_session.cpp:813`: capabilities datagram sent once
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: The capabilities datagram has no retransmission. If lost, or reordered ahead of the handshake response, `e2e.decrypt` fails and transition negotiation is off for the session.
- **Failure scenario**: The server queues the handshake response, then caps. UDP reorders them (or drops caps); the client receives `C` before it is established and drops it. `transition_capable()` stays false; `--mimicry-transition` and the autopilot get `NOT_SUPPORTED` for the rest of the session.
- **Fix direction**: Retransmit caps until acknowledged, or buffer early `C` until the handshake completes.

### ⚪ R17-06 — `e2e.cpp:572`: wrong skipped-key eviction order
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: Skipped keys are now keyed by `(dh_public_key, msg_num)`, but cap eviction still removes `skipped_keys.begin()`, which is the lexicographically smallest DH key, not the oldest entry.
- **Failure scenario**: Under heavy loss near the 2000-key cap across several DH chains, if the current chain's key sorts first, its fresh skipped keys are evicted while stale old-chain keys survive. Delayed current-chain messages then fail to decrypt.
- **Fix direction**: Track insertion order (e.g. a FIFO alongside the map) and evict the oldest.

### ⚪ R17-07 — `ncp_blockcheck.cpp:306`: RST diagnosis lost
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: Every failure while waiting for the server response is now reported as `timeout`; the old `rst` diagnosis is gone. Same in `probe_direct`; SOCKS CONNECT-reply failures now report `proxy`.
- **Failure scenario**: A DPI box injects RST after the ClientHello. Previously `fail_reason` was `rst`; now `bc_recv_full` returns false and it reports `timeout`. The JSON report no longer distinguishes RST injection from blackholing.
- **Fix direction**: Have `bc_recv_full` return the failure kind (ECONNRESET vs timeout vs EOF) and map it to `fail_reason`.

### ⚪ R17-08 — `ncp_transport_config.cpp:166`: `#` inside values truncates silently
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: Comment stripping uses `raw.find('#')` on the whole line.
- **Failure scenario**: `credential_ref: vault#turn-prod` parses as `vault`; `remote: host#1` parses as `host`. The config validates but binds the wrong secret-store entry or remote, with no error.
- **Fix direction**: Only treat `#` as a comment at line start or when preceded by whitespace; support quoting.

### ⚪ R17-09 — `ncp_connection_director.cpp:297`: all aborts reported as TIMEOUT
- **Status**: ✅ FIXED on `fix/r17-findings` (not compiled or run — see note)
- **Description**: `check_feedback()` maps every adapter abort to `AbortReason::TIMEOUT`, including peer ABORTs and `UNKNOWN_PROFILE`/`PEER_BUSY` refusals.
- **Failure scenario**: The responder refuses a PREPARE with `ABORT(UNKNOWN_PROFILE)`. The director fires `aborted_cb(..., TIMEOUT)`, the CLI prints `aborted (timeout)`, and the autopilot treats a hard refusal as a transient timeout and retries.
- **Fix direction**: Propagate the real abort reason from the adapter.

### ⚪ R17-10 — `ncp_connection_director.cpp:576`: per-tick stats rebuild (efficiency)
- **Status**: 🔓 OPEN
- **Description**: Every `poll()` calls `publish_views()`, which rebuilds a fresh `unordered_map` of `stats()` snapshots for every session, plus `refresh_gates()` under `req_mutex`, even when nothing changed.
- **Impact**: Client pumps every 0–25 ms, server every 50 ms; each tick does `max_sessions` full `adapter->stats()` copies and map allocations on the data-path hot loop.
- **Fix direction**: Publish only on change, or at a fixed low rate.

### R17 Cleanups (non-defects)
- learn-batch CSV parsing in `src/cli/main.cpp` duplicates `ncp::cli::split_csv` in `src/cli/ncp_mimicry_cli.hpp`.
- `QUIC_SHORT_HEADER` wrap/unwrap in `src/core/src/mimicry.cpp` (~lines 1325, 1395) re-derives the DCID and AEAD key with two BLAKE2b calls per datagram; cache when `session_mask_key` is set.

---
**Next Audit Step**: Reproduce R17-01/R17-02 (two sequential clients against `ncp porthop serve --mimicry-profile`; a client forced through ≥5 hops). Then a full read of the skimmed R17 areas (`ncp_profile_transition.cpp`, `ncp_turn_*`, `ncp_real_quic.cpp`, FSM). Carried over: review `security.cpp` and `spoofer.cpp` implementations.

