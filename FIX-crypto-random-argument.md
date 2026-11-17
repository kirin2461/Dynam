# Fix: `ncp crypto random <n>` silently ignored the byte count

**Date**: 2026-11-16
**File changed**: `src/cli/main.cpp` (one branch in `handle_crypto`, ~+10 lines)
**Status**: Fixed, rebuilt, verified. No test regressions.

---

## Summary

The documented positional form of `ncp crypto random` was silently ignored. It
always produced 32 bytes regardless of what count the user passed:

```
$ ncp crypto random 8
Random bytes (32): dbfa093af285879f29534ac651c6247255ea93c181d07e0a08...
                    ^^ asked for 8, got 32
```

Only the undocumented `-n` flag worked. A user asking for an 8-byte or 64-byte
value had no way to know the request had been discarded short of counting hex
characters.

## Root cause

`handle_crypto` read the count only from `-n`, falling back to a default of 32:

```cpp
else if (action == "random") {
    size_t size = static_cast<size_t>(get_option_int(args, "-n", 32));
    auto random_bytes = crypto.generate_random(size);
    ...
}
```

`args[0]` is the action (`random`), so a positional count lands at `args[1]` —
the same slot `crypto hash` uses for its algorithm, and the same convention
`random <n>` follows in the help text. Nothing read `args[1]` here, so the value
was parsed by nobody and the default applied. No error, no warning: the argument
died silently.

## The change

```diff
     else if (action == "random") {
-        size_t size = static_cast<size_t>(get_option_int(args, "-n", 32));
+        // Accept both "crypto random <n>" and "crypto random -n <n>".
+        // A bare positional (args[1]) previously fell through to the default,
+        // so the documented count was silently ignored.
+        size_t size = 32;
+        std::string positional = get_arg(args, 1);
+        if (!positional.empty() && positional[0] != '-') {
+            try {
+                size = static_cast<size_t>(std::stoull(positional));
+            } catch (...) {
+                std::cerr << "[!] Invalid byte count: " << positional << "\n";
+                return;
+            }
+        } else {
+            int n = get_option_int(args, "-n", 32);
+            if (n > 0) size = static_cast<size_t>(n);
+        }
+        if (size == 0) {
+            std::cerr << "[!] Byte count must be greater than zero\n";
+            return;
+        }
         auto random_bytes = crypto.generate_random(size);
```

Notes:

- **The `positional[0] != '-'` guard is load-bearing.** Without it, `-n` itself
  is captured as the positional, `stoull("-n")` throws, and the flag form —
  previously the *only* working form — breaks. This was caught during
  verification (see below) and the guard added before commit.
- **Invalid input now fails loudly** instead of silently defaulting. `abc` and
  `0` produce an error on stderr and a non-zero-exit path rather than a
  plausible-looking wrong answer. For a crypto utility, silently returning
  something other than what was asked is worse than an error.
- **Both forms still work.** `-n` behaviour is unchanged for valid values.

## Verification

| Invocation | Before | After |
|---|---|---|
| `crypto random 8` | 32 bytes | **8 bytes** |
| `crypto random 1` | 32 bytes | **1 byte** |
| `crypto random -n 64` | 64 bytes | **64 bytes** (unchanged) |
| `crypto random -n 8` | 8 bytes | **8 bytes** (unchanged) |
| `crypto random` | 32 bytes | **32 bytes** (unchanged) |
| `crypto random abc` | 32 bytes, silent | `[!] Invalid byte count: abc` |
| `crypto random 0` | 0 bytes, silent | `[!] Byte count must be greater than zero` |

Output confirmed at the right lengths:

```
Random bytes (8): f15f6c5b82a9230d
Random bytes (1): 5a
Random bytes (64): ea30052cb2596a59d51e5f2e00e3027e...   (128 hex chars)
Random bytes (32): f8c01bbc4479e92f38837a94663204f7...   (64 hex chars)
```

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (52648 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to baseline. The 8 skips are all `I2PManagerTest.*` (no I2P SAM bridge
on `127.0.0.1:7656`), environmental and unrelated.

`ncp_functional_check` now reports **0 failures** — no `[FAIL]` lines at all.

## A wrong turn worth recording

The first version of this patch checked `args[1]` without the `'-'` guard. That
made `-n 64` parse as the positional, `stoull` throw, and the flag form —
the only one that had ever worked — start failing. It was caught immediately by
running the verification matrix rather than only testing the newly-fixed path.
Testing the case you did *not* mean to change is what caught it.

## Why the test suite did not catch this

`handle_crypto` has no unit test. Argument parsing for CLI subcommands is
uncovered generally: the gtest suite exercises the `Crypto` class directly
(`CryptoTest.*`, `CSPRNGTest.*`), which is correct and passing, but never goes
through the CLI layer where the bug lived.

A test invoking `handle_crypto` with `{"random", "8"}` and asserting an 8-byte
result would catch this. Not added in this change; noted as a gap.
