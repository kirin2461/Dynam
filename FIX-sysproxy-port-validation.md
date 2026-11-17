# Fix: `ncp sysproxy on --port` accepted invalid ports and wrote them to the registry

**Date**: 2026-11-16
**File changed**: `src/cli/main.cpp` (one branch in `handle_sysproxy`, +7 lines)
**Status**: Fixed, rebuilt, verified. No test regressions.

---

## Summary

`ncp sysproxy on --port` performed no range validation. Any integer was cast to
`uint16_t` and written straight into the Windows per-user WinINET settings.
Port `0` was accepted and persisted; so was any negative value, which wraps
through the cast.

This is worse than a bad error message: the command **succeeded**, so the user
saw `[+] System proxy set to 127.0.0.1:0` and had every proxy-aware application
on the machine — browsers, Electron apps, Discord — pointed at a port that
cannot accept connections.

Reproduced against the live system before fixing:

```
$ ncp sysproxy on --port 0
[+] System proxy set to 127.0.0.1:0
    Applications (Discord etc.) now route through the NCP proxy.
    Restore with: ncp sysproxy off

$ ncp sysproxy status
System proxy (ncp): ACTIVE
Windows WinINET: ProxyEnable=1 ProxyServer=127.0.0.1:0
```

The registry value was confirmed directly:

```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings
ProxyServer : 127.0.0.1:0
ProxyEnable : 1
```

## Root cause

`handle_sysproxy` passed the parsed integer directly into the apply function:

```cpp
if (action == "on") {
    int port = get_option_int(args, "--port", 1080);
    std::string err;
    if (!sysproxy_apply(static_cast<uint16_t>(port), &err)) { ... }
```

`get_option_int` returns whatever `std::stoi` yields — no bounds check. The
`static_cast<uint16_t>` then silently truncates: `0` stays `0`, and a negative
value becomes a large positive one (`-5` → `65531`). `sysproxy_apply` itself
validates nothing; it formats `"127.0.0.1:" + port` and writes it.

The `--port` flag also feeds `ncp proxy`'s default, where 0 is equally invalid,
so validation belongs at the CLI boundary where the value is first trusted.

## The change

```diff
     if (action == "on") {
         int port = get_option_int(args, "--port", 1080);
+        // Reject out-of-range ports before they reach the registry: a port of 0
+        // (or a negative value wrapping through uint16_t) would be written to
+        // the system proxy setting as-is and break every proxy-aware app.
+        if (port < 1 || port > 65535) {
+            std::cerr << "[!] Invalid port " << port
+                      << " (must be 1-65535); system proxy left unchanged\n";
+            return;
+        }
         std::string err;
         if (!sysproxy_apply(static_cast<uint16_t>(port), &err)) {
```

The check runs **before** `sysproxy_apply`, so an invalid port cannot reach
`sysproxy_write_state` (which saves the previous settings) or the registry. The
failure is total and side-effect-free: nothing is saved, nothing is written,
nothing needs restoring.

## Verification

| Invocation | Before | After |
|---|---|---|
| `sysproxy on --port 0` | written, `127.0.0.1:0`, ACTIVE | `[!] Invalid port 0 (must be 1-65535); system proxy left unchanged` |
| `sysproxy on --port -5` | written as wrapped uint16 | rejected |
| `sysproxy on --port 70000` | wrapped via uint16 | rejected |
| `sysproxy on --port 1080` | worked | **still works** |

Confirmed no side effects — after all three rejections the system state was
untouched:

```
$ ncp sysproxy status
System proxy (ncp): inactive
Windows WinINET: ProxyEnable=0 ProxyServer=
```

And the valid path still round-trips correctly:

```
$ ncp sysproxy on --port 1080
[+] System proxy set to 127.0.0.1:1080
System proxy (ncp): ACTIVE
Windows WinINET: ProxyEnable=1 ProxyServer=127.0.0.1:1080

$ ncp sysproxy off
[+] System proxy settings restored
System proxy (ncp): inactive
Windows WinINET: ProxyEnable=0 ProxyServer=
```

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (53231 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to baseline. The 8 skips are `I2PManagerTest.*` (no I2P SAM bridge on
`127.0.0.1:7656`), environmental.

## Note on the local system during testing

The reproduction above necessarily modified the real HKCU Internet Settings of
the machine it was run on. The state file written by `sysproxy_write_state` made
this fully reversible, and `ncp sysproxy off` restored the previous values —
`ProxyEnable=0`, `ProxyServer=` empty — which is the original configuration.
Final verified state is inactive.

This is also a good argument for the fix: the safety contract in the comment
above `ncp_sysproxy_state_file()` says previous settings are always saved before
anything is changed *and* `off` restores exactly what was there. That contract
held, which is why the bad write was recoverable. A port that can never work
should not have been written in the first place.

## Why the test suite did not catch this

No test covers `sysproxy` argument validation. The command touches real OS state
by design, so it is not something the gtest suite exercises — it needs either a
unit-level test of the validation branch or a fixture that redirects the
registry root.

A test asserting that `--port 0/-5/70000` returns before `sysproxy_apply` is
reached would catch a regression. Not added in this change; noted as a gap.

## Note for the other CLI fixes on this branch

This is the same class of defect as `FIX-crypto-random-argument.md`: an argument
that is parsed but never validated, failing silently or semi-silently instead of
reporting an error. Worth a sweep of every `get_option_int` call site for the
same missing-bounds problem.
