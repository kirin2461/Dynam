# Fix: port options silently truncated through `uint16_t` at four call sites

**Date**: 2026-11-16
**File changed**: `src/cli/main.cpp` (`get_option_port` helper + 4 call sites)
**Status**: Fixed, rebuilt, verified. No test regressions.

---

## Summary

Follow-on to `FIX-sysproxy-port-validation.md`. That fix validated one call
site; this sweeps the rest. Four commands read a port option, cast it straight
to `uint16_t`, and never check the range — so an out-of-range value either wraps
to a different port or is silently replaced.

The worst case found:

```
$ ncp proxy --port -1
[proxy] proxy: listening on 127.0.0.1:65535
[+] NCP desync proxy active
```

The user asked for port `-1` and got **65535**. No warning. And:

```
$ ncp proxy --port 0
[proxy] proxy: listening on 127.0.0.1:29300
```

Asked for `0`, got **29300** — an ephemeral port assigned by the kernel. Both
are silent substitutions of a value the user never typed, on a command whose
whole job is to listen where they asked.

## Root cause

`get_option_int` returns whatever `std::stoi` produced, with no bounds check.
Four sites then narrow it directly:

```cpp
config.listen_port = static_cast<uint16_t>(get_option_int(args, "--port", 8881));
config.target_port = static_cast<uint16_t>(get_option_int(args, "--target-port", 443));
cfg.sam_port       = static_cast<uint16_t>(get_option_int(args, "--sam-port", 7656));
cfg.port           = static_cast<uint16_t>(get_option_int(args, "--port", 1080));
```

`static_cast<uint16_t>` is a truncating conversion. `-1` becomes `65535`;
`0` is a legal request for "any free port" to the OS, so the proxy binds
somewhere unpredictable; `70000` becomes `4464`. None of these produce an error.

The comments above these lines (`// FIX C4244: Explicit cast ...`) show the cast
was added to silence a compiler narrowing warning — the warning was correct, and
silencing it hid the missing range check.

## The change

Added one helper next to `get_option_int`, and routed all four sites through it:

```cpp
// Read a TCP/UDP port option and validate it at the CLI boundary.
// Returns -1 when the value is present but out of range, so callers can fail
// instead of truncating it through static_cast<uint16_t> (a negative value
// would wrap to a large port, and 0 can never accept a connection).
static int get_option_port(const std::vector<std::string>& args,
                           const std::string& option, int default_val) {
    std::string val = get_option(args, option);
    if (val.empty()) return default_val;
    int port = 0;
    try {
        port = std::stoi(val);
    } catch (...) {
        std::cerr << "[!] Invalid " << option << " value: " << val
                  << " (must be 1-65535)\n";
        return -1;
    }
    if (port < 1 || port > 65535) {
        std::cerr << "[!] Invalid " << option << " " << port
                  << " (must be 1-65535)\n";
        return -1;
    }
    return port;
}
```

Each call site now fails before constructing its config:

```diff
-    config.listen_port = static_cast<uint16_t>(get_option_int(args, "--port", 8881));
+    int listen_port = get_option_port(args, "--port", 8881);
+    if (listen_port < 0) return;
+    config.listen_port = static_cast<uint16_t>(listen_port);
```

`-1` is the sentinel because a valid port can never be negative, so the `if
(port < 0) return;` check cannot misfire on a legal value. The cast is retained
after validation, so C4244 stays quiet — the difference is that the value is now
known-good when it reaches it.

## Verification

| Invocation | Before | After |
|---|---|---|
| `proxy --port -1` | bound **65535**, no error | `[!] Invalid --port -1 (must be 1-65535)` |
| `proxy --port 0` | bound **29300**, no error | `[!] Invalid --port 0 (must be 1-65535)` |
| `proxy --port 70000` | truncated, no error | `[!] Invalid --port 70000 (must be 1-65535)` |
| `dpi --port 0` | (already rejected downstream) | `[!] Invalid --port 0 (must be 1-65535)`, earlier and clearer |
| `i2p start --sam-port -1` | truncated, no error | `[!] Invalid --sam-port -1 (must be 1-65535)` |
| `i2p start --sam-port abc` | fell back to default | `[!] Invalid --sam-port value: abc (must be 1-65535)` |

Valid paths confirmed unchanged:

```
$ ncp proxy --port 18080
[proxy] proxy: listening on 127.0.0.1:18080

$ ncp dpi --port 8881
[DPI] Initialize DPI (mode=driver, listen_port=8881, fragment_size=2)
```

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (52775 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to baseline. The 8 skips are `I2PManagerTest.*` (no I2P SAM bridge on
`127.0.0.1:7656`), environmental.

## Remaining sites, deliberately not changed

`get_option_int` is used for ~40 other options. Most are not ports and already
clamp or clamp-adjacent at the call site (`std::max(1, ...)`,
`std::min(8, ...)`). The four changed here were the only ones that narrow a port
through `uint16_t` without a check.

One is still worth a look in a follow-up: `stegodns --port` and `fog --port`
read via `get_option_int` and are validated downstream rather than at the CLI
boundary. Not broken today, but the same class.

## Why the test suite did not catch this

Same gap as the previous two CLI fixes: no test exercises CLI argument parsing.
The proxy, DPI and I2P classes are unit-tested at their API, where ports are
already `uint16_t` and therefore cannot be out of range — the truncation happens
in the layer above, which nothing covers.

`get_option_port` is a pure function over a string vector, so it is directly
testable without touching the network. Not added in this change; noted as a gap.
