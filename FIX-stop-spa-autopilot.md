# Fix: `ncp stop` cross-process shutdown, SPA dry-run, AutoPilot false degraded-net

**Date**: 2026-11-22
**Files changed**:
- `src/cli/main.cpp` — `ncp stop` state-file control channel, honest exit reporting, `spa serve --dry-run`, `ncp_pid_alive`
- `src/core/include/ncp_blockcheck.hpp` — `BlockcheckProbe::tcp_connected`
- `src/core/src/ncp_blockcheck.cpp` — set it in `probe_direct`
- `src/core/src/preset_autopilot.cpp` — connectivity gate, zero-evidence escalation guard, `escalations_total`
- `tests/test_preset_autopilot.cpp` — 2 new tests, 1 updated

**Status**: Fixed, rebuilt, full suite green (1415 tests, 0 failed), verified live in driver mode.

---

## 1. `ncp stop` could not stop `ncp run`

Observed in a second console while `ncp run` was active:

```
[*] Sending shutdown signal to ncp run (pid 27688)...
[!] Graceful signal unavailable; terminating process
[+] ncp run stopped, settings restored
```

Three compounding defects:

1. `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` only reaches a process
   that leads its own process group. `ncp run` started from a shell does not,
   so the call always failed and the code fell through to `TerminateProcess`.
2. After `TerminateProcess` the command still printed
   "settings restored" — but the shutdown path (hostname/DNS restore) never
   ran. The `run` log showed no `Shutdown complete`.
3. `ncp_pid_alive()` used `OpenProcess` as the liveness test. A terminated
   process object stays openable while any other handle to it exists (e.g. the
   parent shell's `Process` object), so a finished `ncp run` still looked alive.

### Fix

`%APPDATA%\ncp\run_state.json` is now also a control channel:

- `ncp stop` writes `"stop":1` into the state file (pid/started/modules kept).
- The `ncp run` wait loop polls it every second and exits through the normal
  cleanup path on `"stop":1`.
- `ncp stop` waits on a `SYNCHRONIZE` handle and reports success **only** when
  `GetExitCodeProcess` returns 0. Forced kills and non-zero exits are reported
  as failures with an explicit "settings may not be restored" warning.
- An elevated `ncp run` cannot be opened from a non-elevated `ncp stop`
  (`ERROR_ACCESS_DENIED`): the request is queued, but the command says it
  cannot verify and asks for elevation instead of pretending it worked.
- `ncp_pid_alive()` now treats a signaled process object as dead (stale-state
  detection works even while the parent holds a handle).

The CTRL_BREAK relay was dropped: broadcasting to group 0 also hits every
other process attached to the console.

Verified (run8): `[+] ncp run stopped, settings restored`, exit 0, 15 s;
run log `[*] Stop requested by ncp stop` → `[+] Shutdown complete`; WinDivert
service removed, state file gone, no `ncp` process left.

## 2. `ncp spa serve --dry-run` started listening anyway

`--dry-run` only switched the ipset controller into log-only mode; the daemon
still started and blocked in its poll loop. Now a dry run prints the
configuration and returns, like `reality serve --dry-run`. Verified: exit 0,
`[*] Dry run — configuration OK, not listening.`

## 3. AutoPilot reported `degraded-net` while the network was healthy

The startup connectivity gate used a full TLS probe (`probe_direct`). Under
system-wide interception that probe is itself shaped by the live preset: TCP
completes but the server's ServerHello never arrives within 2 s, so a healthy
link was declared dead. `blockcheck` and `curl` on the same host succeeded.

Two changes:

1. `BlockcheckProbe::tcp_connected` is set once the TCP handshake completes.
   `quick_connectivity_ok()` treats "TCP up, TLS timed out" as reachable and
   lets the selection stage decide instead of jumping to `degraded-net`.
2. Escalation must not swap the live preset on zero evidence. When every
   candidate scored 0 the probes measured nothing at all; applying an arbitrary
   candidate (observed: `RuNet-TSPU`, whose fake+ttl=1 preset breaks TLS on
   this ISP) took working traffic down. Now L2 keeps the live/fallback
   configuration and only probes augmentation rungs on top of it. The episode
   counter `escalations_total` was added to the stats JSON so episodes remain
   observable without a preset switch.

Live evidence (run6/run8, driver mode, `--auto`): `engine_preset_effective`
stayed `AutoProbe`, `switches_total: 0`, `escalations_total: 1`, no
`degraded-net`, and `https://1.1.1.1/` kept answering 301 throughout.

Side observation from the same runs: with the full `ncp run` stack, TLS to
`example.com` times out through the driver even though it is 200 in ~0.1–8 s
without the engine, and 200 in ~0.2 s through `ncp proxy` with the same preset.
`1.1.1.1` stays reachable but 100× slower. This points at the packet-shaping
modules (Behavioral Cloak / Time Breaker / Volume Normalizer) rather than the
preset or the link; it is tracked separately.

## Tests

- `PresetAutoPilotStartup.ShapedTlsProbeDoesNotTripDegradedNet` — new.
- `Escalation.ZeroEvidenceKeepsLiveConfig` — new.
- `Escalation.CooldownRespected` — now observes episodes via
  `escalations_total` instead of `switches_total` (a no-evidence episode no
  longer records a switch).
