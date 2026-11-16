# Fix: malformed TLS ClientHello in `BlockChecker::build_client_hello`

**Date**: 2026-11-16
**File changed**: `src/core/src/ncp_blockcheck.cpp` (one function, 3 lines)
**Status**: Fixed, rebuilt, verified against live servers, no test regressions.

---

## Summary

`BlockChecker::build_client_hello()` emitted a TLS ClientHello whose extension
length fields did not match the bytes it actually wrote. Every real TLS server
rejected it with a fatal `decode_error` alert, so **every** probe built on this
function reported failure — regardless of domain or strategy.

`ncp blockcheck` is the feature that auto-selects the best DPI bypass strategy.
Because all of its probes were rejected at the TLS layer, it reported all 14
strategies as failed on every domain, every time. The feature could never
succeed. `geneva_fitness.cpp` shares the same builder, so Geneva GA fitness was
broken the same way.

## Root cause

Three extensions were written with an incorrect length field. TLS extension data
for these types is a `2-byte list length` followed by the entries; the builder
omitted that prefix from the declared length.

| Extension | Type | Declared | Correct | Problem |
|---|---|---|---|---|
| `supported_groups` | `0x000A` | `6` | `6` (with `4` list prefix) | list-length prefix missing |
| `signature_algorithms` | `0x000D` | `8` | `10` (with `8` list prefix) | list-length prefix missing |
| `key_share` | `0x0033` | ext `36`, shares `34` | ext `38`, shares `36` | off by 2 at both levels |

The `supported_versions` extension (`0x002B`) was already correct — it includes
its `4`-byte list prefix — which is why the mistake was easy to miss by
reading.

## The change

```diff
     // supported_versions (TLS 1.3 + 1.2)
     e16(0x002B); e16(5); ext.push_back(4); e16(0x0304); e16(0x0303);
-    // supported_groups
-    e16(0x000A); e16(6); e16(0x001D); e16(0x0017);
+    // supported_groups (extension_data = 2-byte list length + entries)
+    e16(0x000A); e16(6); e16(4); e16(0x001D); e16(0x0017);
     // ec_point_formats
     e16(0x000B); e16(2); ext.push_back(1); ext.push_back(0);
-    // signature_algorithms
-    e16(0x000D); e16(8); e16(0x0403); e16(0x0804); e16(0x0401); e16(0x0501);
-    // key_share (x25519, 32 zero bytes — enough to elicit ServerHello/HRR)
-    e16(0x0033); e16(36); e16(34); e16(0x001D); e16(32);
+    // signature_algorithms (extension_data = 2-byte list length + algorithms)
+    e16(0x000D); e16(10); e16(8); e16(0x0403); e16(0x0804); e16(0x0401); e16(0x0501);
+    // key_share (x25519; extension_data = 2-byte client_shares length + entry)
+    e16(0x0033); e16(38); e16(36); e16(0x001D); e16(32);
```

No API change, no behaviour change for valid inputs, no wire-format change to
any Dynam protocol. This only affects the probe ClientHello.

## Verification

### Byte-level proof, before and after

The shipped and corrected hellos were rebuilt by hand and sent to
`example.com:443`:

| Build | Server response | Meaning |
|---|---|---|
| As shipped | `15 03 01 00 02 02 32` | fatal alert, **description 50 = `decode_error`** |
| Corrected | `16 03 03 00 5a 02` | **`ServerHello`** |

The failure was systematic, not host-specific. Before the fix, all four tested
domains failed identically:

```
example.com       -> "fail": "tls"
www.google.com    -> "fail": "tls"
www.cloudflare.com-> "fail": "tls"
github.com        -> "fail": "tls"
```

### After the fix

```
$ ncp blockcheck --domains example.com --timeout 5000 --json
{
  "best_strategy": "direct",
  "best_validated": true,
  "early_exit_taken": true,
  "results": [
    {"strategy": "direct", "success": 1, "total": 1, "ok": true, "latency_ms": 63, "validated": true},
    {"strategy": "split-1", "success": 1, "total": 1, "ok": true, "latency_ms": 83, "validated": true}
  ]
}
```

`best_strategy` is now selected and validated — previously it was always `""`.

`ncp_functional_check`:

```
[PASS] direct probe example.com ok        # was: [FAIL]
```

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (53218 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to the pre-fix baseline (1275 / 1267 / 8 skipped, 0 failed). The 8
skips are all `I2PManagerTest.*`, which skip because no I2P SAM bridge is
listening on `127.0.0.1:7656` — environmental, unrelated to this change.

## Why the test suite did not catch this

The existing tests validate the builder against **its own parser** — build a
hello, parse it back, compare. Both sides shared the same wrong lengths, so they
agreed and the tests passed. `tests/test_bypass_features.cpp` (`ProxySplit.*`)
only exercises split-offset arithmetic over the internally-built hello and never
validates it against a real TLS server.

Only `ncp_functional_check` performed a live probe, and that is where it showed
up. A regression test that sends the hello to a real server (or compares against
a known-good byte vector captured from a real client) would have caught this;
none exists today.

## Related finding, not fixed here

`Network::get_stats()` returns zeros on Windows. The `/proc/net/dev` fallback in
`src/core/src/network.cpp:1135` is inside `#ifndef _WIN32`, so on Windows the
function returns the never-populated `stats_`. This is the remaining
`[FAIL] network stats non-zero` in `ncp_functional_check`. Separate issue, left
untouched.
