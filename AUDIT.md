# NCP-CPP Security Audit

> **Auditor**: AI Code Review
> **Date Updated**: 2026-11-16
> **Status**: Ongoing (Regularly updated with core fixes)

---

## Summary

> **2026-11-16 — R19 (CLI safety + full-review attempt)**: Two multi-agent full-codebase review runs **produced no findings** — all 12 reviewer agents died (first run: server-side `API Error 500` on all 8; second run: 4 agents stalled and were stopped with zero output). Nothing from those runs is recorded as a finding. R19 instead records what was verified directly: a CLI help-handling gap where `--help` starts real engines, plus local build/test evidence and a blockcheck fix from another session. See [R19](#r19-2026-11-16--cli-safety-build-and-test-evidence).

> **2026-11-16 — R18 review (`spoofer.cpp`)**: Review of what `NetworkSpoofer` actually changes on the OS. Default `ncp run` changes **DNS only**; MAC/IP/hostname change only with `--full-spoof`. Hardware-identity spoofing (board serial, SMBIOS, disk serial, DHCP client ID) is broken, cosmetic or harmful. **1 high + 5 medium + 3 low, all open.** Code reading only; nothing was run. See [R18 Findings](#r18-findings-2026-11-16--networkspoofer).

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

## R18 Findings (2026-11-16) — NetworkSpoofer

**Scope**: `src/core/src/spoofer.cpp`, `src/core/include/ncp_spoofer.hpp`, `src/core/src/smbios_hook.cpp`, and how `ncp run` configures the spoofer (`src/cli/main.cpp:1506–1600`).
**Method**: Code reading only. Nothing was run, on Windows or Linux. Severities are the reviewer's estimates.

### What the spoofer really does today

| Identity | Default `ncp run` | `--full-spoof` | Real effect |
|---|---|---|---|
| DNS servers | **on** (only resolvers that answered a probe) | on | Really changed: `netsh` (Windows), `/etc/resolv.conf` (Linux). Restored on stop. |
| MAC address | off | on | Really changed if the driver honours it: Windows writes `NetworkAddress` in the adapter registry key and bounces the adapter (5–10 s drop); Linux `ip link set address`. Random locally administered unicast MAC. Many Wi-Fi drivers ignore `NetworkAddress`. |
| IPv4 / IPv6 | off | on | Really changed to a random static address with a hard-coded `/24`; replaces DHCP. |
| Hostname | off (no default name configured) | only if rotation/custom name set | `SetComputerNameEx` (Windows, full effect after reboot) / `sethostname` (Linux). |
| Board serial (`spoof_hw_info`) | off | on | **No effect**: Windows stub returns success; Linux `/sys/class/dmi/id/*` is read-only. |
| SMBIOS | off | off | **Cosmetic**: registry key rebuilt from firmware at boot; Linux `/sys` read-only. |
| Disk serial | off in CLI (library default **on**) | off | **Harmful on Windows** (see R18-01); not implemented on Linux. |
| DHCP client ID | off in CLI (library default **on**) | off | **Broken** on Windows (invalid `netsh` option); Linux relies on `dhclient`. |
| TCP fingerprint | off | off | System-wide sysctl/registry changes; Linux also changes interface MTU. Not restored. |

| ID | Severity | Location | Issue | Status |
|---|---|---|---|---|
| R18-01 | 🟠 High | `spoofer.cpp:1148` | `apply_disk_serial` overwrites value `"0"` of `Services\disk\Enum` (the disk enumeration list), not a serial | Open |
| R18-02 | 🟡 Medium | `spoofer.cpp:913` | `apply_hw_info` reports success on Windows without doing anything | Open |
| R18-03 | 🟡 Medium | `spoofer.cpp:1066` | SMBIOS spoof writes a boot-volatile registry key; UUID stored in `SystemProductName`; Linux writes read-only `/sys` files | Open |
| R18-04 | 🟡 Medium | `spoofer.cpp:704`, `main.cpp:1562` | Restore covers only MAC/IP/DNS/hostname; partial `enable()` failure drops the spoofer without restoring what was already changed | Open |
| R18-05 | 🟡 Medium | `spoofer.cpp:1171` | DHCP client ID: Windows `netsh … dhcpclientid=` is not a valid option; Linux assumes `dhclient` | Open |
| R18-06 | 🟡 Medium | `ncp_spoofer.hpp:40–62` | Library defaults turn on MAC/IP/hw/disk/DHCP-ID spoofing; any caller other than the CLI that uses `SpoofConfig{}` gets all of them | Open |
| R18-07 | ⚪ Low | `spoofer.cpp:737` | IPv4 spoof/restore hard-codes `255.255.255.0` and drops the gateway; restoring a DHCP address as static | Open |
| R18-08 | ⚪ Low | `spoofer.cpp:1205` | TCP fingerprint: Windows `TcpWindowSize` ignored on modern Windows; Linux changes interface MTU; never restored | Open |
| R18-09 | ⚪ Low | `spoofer.cpp` (all `apply_*` via `execute_command_safe`) | Success is detected by searching command output for the English word `"Error"`; localized Windows output and exit codes are ignored | Open |

### 🟠 R18-01 — `spoofer.cpp:1148`: disk-serial spoof corrupts the disk enumeration key
- **Status**: 🔓 OPEN (not reproduced)
- **Description**: On Windows, `apply_disk_serial` opens `HKLM\SYSTEM\CurrentControlSet\Services\disk\Enum` and writes the generated serial into value `"0"`. That value holds the device instance path of the first enumerated disk (e.g. `SCSI\Disk&Ven_…`), not a serial number.
- **Failure scenario**: A caller enables `spoof_disk_serial` (default **true** in `SpoofConfig`). Value `"0"` is replaced with a random string. Software that reads disk enumeration from this key gets a bogus device path; the real disk serial is unchanged, so the spoof achieves nothing while risking breakage. Not restored on stop.
- **Fix direction**: Remove the write. Return "not supported" on all platforms (a real disk serial can't be changed from user mode). Default `spoof_disk_serial = false`.

### 🟡 R18-02 — `spoofer.cpp:913`: `apply_hw_info` is a no-op that reports success on Windows
- **Status**: 🔓 OPEN (not reproduced)
- **Description**: Windows branch is `return true;`. Linux writes `/sys/class/dmi/id/board_serial`, which is read-only.
- **Failure scenario**: `ncp run --full-spoof` sets `spoof_hw_info = true`; on Windows `status.hw_info_spoofed` becomes true and the user is told hardware info is spoofed when nothing changed.
- **Fix direction**: Return false with an explicit "not supported" status on both platforms; surface it in CLI/web output.

### 🟡 R18-03 — `spoofer.cpp:1066`: SMBIOS spoof is cosmetic and partly wrong
- **Status**: 🔓 OPEN (not reproduced)
- **Description**: Windows writes `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, which Windows rebuilds from firmware at every boot; WMI and most software read SMBIOS from firmware tables, not this key. The generated UUID is written into `SystemProductName` (the product name field). Linux writes read-only `/sys/class/dmi/id/*`. The 8-argument overload ignores six of its parameters.
- **Failure scenario**: User enables SMBIOS spoofing and believes the machine identity changed; it did not for WMI/firmware readers, and the product name now shows a UUID until reboot.
- **Fix direction**: Mark as "not supported" (or document as `LD_PRELOAD`-only on Linux via `smbios_hook.cpp`, per-process). Stop writing the UUID into `SystemProductName`.

### 🟡 R18-04 — `spoofer.cpp:704`, `main.cpp:1562`: incomplete restore
- **Status**: 🔓 OPEN (not reproduced)
- **Description**: `restore_original_identity()` only restores MAC, IPv4, DNS and hostname. IPv6, hw info, SMBIOS, disk serial, DHCP client ID and TCP fingerprint are never restored. In `ncp run`, if `enable()` returns false after some changes succeeded, the CLI calls `g_app.spoofer.reset()`; `enabled_` was set before returning, so the destructor does call `disable()`, but only the four restorable items are undone.
- **Failure scenario**: `--full-spoof` sets a random IPv6 and the IPv4 step fails; the CLI prints a warning and continues. The random IPv6 stays on the adapter after NCP exits.
- **Fix direction**: Track every applied change in a journal (what was changed, original value) and undo all of them in reverse order on `disable()`. Persist the journal to disk so a crash can be recovered on next start (`ncp spoof restore`).

### 🟡 R18-05 — `spoofer.cpp:1171`: DHCP client ID spoof does not work
- **Status**: 🔓 OPEN (not reproduced)
- **Description**: Windows runs `netsh interface ipv4 set interface "<name>" dhcpclientid=<id>`; `dhcpclientid` is not a valid `netsh` parameter, so the command fails. Linux edits `/etc/dhcp/dhclient.conf` and runs `systemctl restart dhclient`; most current distributions use NetworkManager/systemd-networkd and have no `dhclient` service.
- **Fix direction**: Mark Windows as not supported. On Linux, detect the DHCP client in use (NetworkManager `ipv4.dhcp-client-id`, systemd-networkd `ClientIdentifier=`) or report not supported.

### 🟡 R18-06 — `ncp_spoofer.hpp:40–62`: dangerous library defaults
- **Status**: 🔓 OPEN
- **Description**: `SpoofConfig` defaults: `spoof_ipv4/ipv6/mac/dns/hw_info = true`, `spoof_disk_serial = true`, `spoof_dhcp_client_id = true`. The CLI overrides them, but any other caller (GUI, tests, future code) constructing `SpoofConfig{}` gets network-breaking changes and the harmful R18-01 write.
- **Fix direction**: Default every field to `false`; callers opt in explicitly. Match the CLI's safe defaults.

### ⚪ R18-07 — `spoofer.cpp:737`: IPv4 spoof/restore loses network settings
- **Status**: 🔓 OPEN
- **Description**: Spoof and restore both use `netsh … static <ip> 255.255.255.0` (Linux `ip addr replace <ip>/24`). The original mask and gateway are not saved, and a DHCP-assigned address is restored as a static one.
- **Fix direction**: Save mask, gateway and DHCP mode; restore DHCP with `netsh … source=dhcp` / NetworkManager when the original was DHCP.

### ⚪ R18-08 — `spoofer.cpp:1205`: TCP fingerprint changes are global and unrestored
- **Status**: 🔓 OPEN
- **Description**: Windows sets `DefaultTTL`, `TcpWindowSize` (ignored since Vista's auto-tuning) and writes `TcpMaxSegmentSize` on the `Interfaces` parent key rather than a specific interface. Linux sets global sysctls and changes the interface MTU to `mss + 40`. None of it is restored.
- **Fix direction**: Remove the ineffective Windows values, don't touch MTU, and add these to the restore journal (R18-04).

### ⚪ R18-09 — success detection by searching for `"Error"`
- **Status**: 🔓 OPEN
- **Description**: `apply_*` functions decide success with `result.find("Error") == npos`. On non-English Windows `netsh`/`reg` print localized messages (e.g. Russian "Ошибка"), so failures are reported as success, and the status/restore logic is based on wrong data.
- **Fix direction**: Have `execute_command_safe` return the process exit code and use it.

### Suggested order
1. R18-01 and R18-06 (stop the harmful write, safe defaults) — small.
2. R18-02, R18-03, R18-05 (report "not supported" honestly) — small; also update README/README.ru claims and the web UI so they don't advertise these as working.
3. R18-09 (exit codes) — needed for R18-04 to be reliable.
4. R18-04 + R18-07 + R18-08 (restore journal) — medium.

---

## R19 (2026-11-16) — CLI safety, build and test evidence

### Status of the full-codebase review

Two attempts to review the whole codebase with parallel subagents did **not** produce findings:

| Run | Agents | Outcome |
|---|---|---|
| 1 | 8 reviewers (dpi, crypto, net, mimicry, stealth, orch, extras, web) | All 8 failed with `API Error: 500 clientFormat is not defined` (server-side). 0 results. crypto and extras had read their 11 files each before dying; the other 6 read nothing. |
| 2 | 4 reviewers (dpi, net, mimicry, web) | Stalled with no output and were stopped manually. Transcripts contain **0** `StructuredOutput` calls and **0** severity values — no partial findings exist. |

**Nothing from these runs is recorded as a finding.** The areas remain unreviewed by this round: DPI core, crypto, transports, mimicry, stealth, orchestration, auxiliary protocols, web. The findings below were verified directly by reading the code.

| ID | Severity | Location | Issue | Status |
|---|---|---|---|---|
| R19-01 | 🟠 High | `src/cli/main.cpp:3300` (`handle_dpi`) | `ncp dpi --help` does not print help: it starts the DPI engine in WinDivert **DRIVER** mode on Windows | Open |
| R19-02 | 🟡 Medium | `src/cli/main.cpp:2637`, `3027` | `ncp stop --help` / `ncp rotate --help` ignore `--help` and act (stop services / rotate MAC+IP+DNS identity) | Open |
| R19-03 | ⚪ Low | `src/cli/main.cpp` (`handle_crypto`, `handle_network`, `handle_license`, `handle_i2p`, `handle_mimic`, `handle_status`) | `--help` is treated as an unknown action / ignored instead of printing usage | Open |
| R19-04 | 🟠 High | `src/core/src/ncp_blockcheck.cpp:241–248` | TLS ClientHello had wrong extension lengths → every probe rejected with `decode_error` | **Fixed** (by another session, uncommitted) |

### 🟠 R19-01 — `ncp dpi --help` starts the DPI engine
- **Status**: 🔓 OPEN (verified by reading; not executed)
- **Description**: The dispatcher (`parse_and_execute`, `main.cpp:207`) only intercepts `--help`/`-h` as the **first** argument. `ncp dpi --help` passes `--help` to `handle_dpi`, which has no help check. It sets `config.mode = DPI::DPIMode::DRIVER` on Windows (`main.cpp:3309`), then calls `dpi->initialize(config)` and `dpi->start()` (`main.cpp:3381`).
- **Failure scenario**: A user (or an audit agent) runs `ncp dpi --help` to see the options. On an elevated Windows prompt the WinDivert driver opens and starts intercepting packets; with `--kill-switch` among the parsed options, traffic can be blocked. Running "help" changes the network.
- **Fix direction**: Check `has_flag(args, "--help") || has_flag(args, "-h")` at the top of every handler and print usage. Better: intercept `--help` anywhere in `argv` in `parse_and_execute` and dispatch to a per-command usage function, so no handler can forget.

### 🟡 R19-02 — `ncp stop --help` / `ncp rotate --help` act instead of printing help
- **Status**: 🔓 OPEN (verified by reading)
- **Description**: Both handlers start with `(void)args;` — they ignore all arguments. `handle_stop` (`main.cpp:2637`) stops running services and signals another `ncp run` instance to shut down. `handle_rotate` (`main.cpp:3027`) calls `g_app.spoofer->rotate_all()`, which applies new IPv4/IPv6/MAC/DNS/hostname when spoofing is active.
- **Failure scenario**: `ncp rotate --help` during an active `--full-spoof` session bounces the adapter (MAC change) and replaces the IP — the user loses connectivity while asking for help.
- **Fix direction**: Same as R19-01.

### ⚪ R19-03 — other handlers ignore `--help`
- **Status**: 🔓 OPEN
- **Description**: `handle_crypto`, `handle_network`, `handle_license`, `handle_i2p`, `handle_mimic` and `handle_status` read `args[0]` as the action. `--help` becomes the action name and falls into "Unknown action" or the default path. Harmless (no system change found on these paths) but inconsistent.
- **Fix direction**: Covered by the dispatcher-level fix in R19-01.

### 🟠 R19-04 — blockcheck ClientHello was malformed (fixed by another session)
- **Status**: ✅ FIXED in the working tree, **not committed**. Change and write-up made by another Claude session (`FIX-blockcheck-clienthello.md`, file timestamps 06:38–06:44); recorded here for traceability, not authored in this round.
- **Description**: `BlockChecker::build_client_hello()` wrote `supported_groups`, `signature_algorithms` and `key_share` with extension length fields that omitted the inner 2-byte list length. TLS servers reject this with `decode_error`, so every blockcheck probe and Geneva GA fitness evaluation failed regardless of strategy.
- **Consistency check**: matches `ncp_functional_check` → `[FAIL] direct probe example.com ok` observed in this round's local run (log in `test-evidence/`). Not re-verified after the fix.

### Local build and test evidence (Windows, MSVC 14.52, Release)

Logs: `test-evidence/` (not committed).

| Binary | Result |
|---|---|
| `ncp_tests.exe` | 1267 passed, 0 failed, 8 skipped (I2P: no SAM bridge) |
| `test_advanced_dpi`, `test_ech_pipeline`, `test_l3_stealth`, `test_mimicry_roundtrip` | exit 0, custom harness, no failures printed |
| `test_dpi_fixes` | 7 passed |
| `test_dpi_advanced_integration` | 8 passed, 0 failed |
| `ncp_functional_check` | **68 passed, 3 failed** — `direct probe example.com ok`, `network stats non-zero`, `live learn youtube.com` (all need live internet; environmental, not classified as defects) |

**Caveat on driver-path tests**: tests ran non-elevated. Every WinDivert open logged `error=5 Access denied`, and `test_dpi_advanced_integration` logged "this build has no WinDivert". Driver-mode behaviour was **not** exercised; whether the cause is elevation, missing SDK linkage, or both is unresolved.

---
**Next Audit Step**: Re-run the full-codebase review (R19 areas listed above) once the agent API errors are resolved, starting with crypto and extras (their files were already read). Fix R19-01/R19-02 (dispatcher-level `--help`), then R18-01/R18-06. Reproduce R17-01/R17-02 (two sequential clients against `ncp porthop serve --mimicry-profile`; a client forced through ≥5 hops). Then a full read of the skimmed R17 areas (`ncp_profile_transition.cpp`, `ncp_turn_*`, `ncp_real_quic.cpp`, FSM). Carried over: review `security.cpp`.

