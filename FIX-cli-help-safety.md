# Fix: `--help` could start engines and change the network (R19-01/02/03)

**Date**: 2026-11-16
**Files changed**: `src/cli/main.cpp`
**Source**: `AUDIT.md` R19-01, R19-02, R19-03
**Status**: Fixed, built, verified by running each command.

---

## Summary

Only the **first** argv element was checked for `--help` (in `parse_and_execute`).
Everything after it went straight to the handler, and most handlers have no help
check of their own. So asking a command for its options could perform its action:

| Command | What it actually did |
|---|---|
| `ncp dpi --help` | **Started the DPI engine**, opening the WinDivert driver and beginning packet interception |
| `ncp rotate --help` | Rotated identity — bounced the adapter, replaced IPv4/IPv6/MAC/DNS |
| `ncp stop --help` | Stopped every running service |
| `ncp crypto/network/license/i2p/mimic/status --help` | Treated `--help` as an unknown action |

`ncp dpi --help` is the serious one: on an elevated prompt it began intercepting
traffic. Running "help" changed the machine's network behaviour.

## The change

Intercepted at the **dispatcher**, so no handler can forget:

```cpp
std::vector<std::string> args(argv + 2, argv + argc);

// R19-01/02/03: a help request must never change the system. Handlers
// such as `dpi` (starts the WinDivert driver), `stop` (stops services)
// and `rotate` (bounces the adapter) have no help check of their own,
// so intercept `--help`/`-h` here — anywhere in argv, not just first —
// and print usage without invoking the handler.
for (const auto& a : args) {
    if (a == "--help" || a == "-h") {
        it->second.help();
        return;
    }
}
it->second.handler(args);
```

Each command gained a `help()` member holding its own usage text, and a set of
`*_print_usage()` functions. The fix is structural, not per-handler: a handler
added later cannot reintroduce the bug, because the dispatcher never calls it
when `--help` appears anywhere in the arguments.

## Verification

Ran each command and checked what it did, not just its exit code — exit 0 is
correct for help and would have looked identical before the fix.

```
ncp dpi --help  →  Usage: ncp dpi [options] …
                   (no WinDivert / init / "DPI bypass started" lines)
ncp rotate --help → Usage: ncp rotate …
                    "…may bounce the network adapter…"
ncp stop --help   → Usage: ncp stop …
                    "Stops every running NCP service…"
```

For `ncp dpi --help`, the output was grepped for `windivert|initializ|starting|
DPI bypass started` — **no matches**, confirming the engine no longer starts.

All nine commands (`dpi stop rotate crypto status network license i2p mimic`)
now exit 0 and print usage.

### Test suite

```
[==========] 1283 tests from 161 test suites ran.
[  PASSED  ] 1275 tests.
[  SKIPPED ] 8 tests.
```
0 failed. `ctest -C Release`: 8/8.

## Why the test suite did not catch this

No test invokes the CLI binary at all. `ncp_tests` exercises library classes;
`ncp_functional_check` calls APIs, not the executable. Shell-level behaviour —
help handling, exit codes, argument parsing — is untested across the board,
which is the same gap behind the other CLI fixes on this branch.
