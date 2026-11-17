# Fix: `Network::get_stats()` always returned zeros on Windows

**Date**: 2026-11-16
**File changed**: `src/core/src/network.cpp` (one function, +21 lines)
**Status**: Fixed, rebuilt, verified. No test regressions.

---

## Summary

`Network::get_stats()` reported zero packets and zero bytes on Windows. When no
capture session had populated the internal `stats_` counter, the function was
supposed to fall back to system-wide interface counters — but that fallback was
wrapped in `#ifndef _WIN32`, so Windows fell straight through to returning the
never-populated `stats_`.

Everything that surfaces network statistics to the user was therefore reporting
zeros on Windows: `ncp network stats`, the GUI counters, and
`ncp_functional_check`'s `network stats non-zero` assertion.

## Root cause

`src/core/src/network.cpp:1135` — the fallback existed only for Linux:

```cpp
NetworkStats Network::get_stats() const {
#ifndef _WIN32
    if (stats_.packets_sent == 0 && ...) {
        // read /proc/net/dev
        return sys;
    }
#endif
    return stats_;   // <-- Windows always landed here
}
```

The Linux path parses `/proc/net/dev` to aggregate non-loopback interface
counters. Windows has an equivalent, and the project already had it available:
`iphlpapi.h` is included at the top of the file and `iphlpapi` is already in
`target_link_libraries` in `src/core/CMakeLists.txt:378`. No build-system change
was needed.

## The change

Added an `#else` branch mirroring the Linux semantics, using `GetIfTable2`:

```diff
         return sys;
     }
+#else
+    // Windows: when no capture session populated stats_, report system-wide
+    // counters from the IP Helper API (aggregate of non-loopback interfaces),
+    // mirroring the Linux /proc/net/dev path above.
+    if (stats_.packets_sent == 0 && stats_.packets_received == 0 &&
+        stats_.bytes_sent == 0 && stats_.bytes_received == 0) {
+        NetworkStats sys;
+        PMIB_IF_TABLE2 table = nullptr;
+        if (GetIfTable2(&table) == NO_ERROR && table) {
+            for (ULONG i = 0; i < table->NumEntries; ++i) {
+                const MIB_IF_ROW2& row = table->Table[i];
+                if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
+                sys.bytes_received += row.InOctets;
+                sys.packets_received += row.InUcastPkts + row.InNUcastPkts;
+                sys.bytes_sent += row.OutOctets;
+                sys.packets_sent += row.OutUcastPkts + row.OutNUcastPkts;
+            }
+            FreeMibTable(table);
+        }
+        return sys;
+    }
 #endif
     return stats_;
```

Notes on the implementation:

- **Same trigger condition as Linux.** The fallback only applies when a capture
  session has not populated `stats_`. Live capture counters still win.
- **Same aggregation rule as Linux.** Loopback is excluded, so the numbers
  reflect real network traffic rather than localhost chatter.
- **Multicast included.** `InNUcastPkts` / `OutNUcastPkts` are added alongside
  the unicast counters, matching what `/proc/net/dev` totals include.
- **Table is freed.** `FreeMibTable` is called on the success path; on failure
  the table is null and nothing is leaked.

Behaviour is otherwise unchanged: one `get_stats()` call returns one snapshot,
it does not modify state, and it remains `const`.

## Verification

### `ncp_functional_check`

Before:
```
[FAIL] network stats non-zero
```

After:
```
[PASS] network stats non-zero
```

The full functional check is now clean on both previously failing assertions:

```
[PASS] direct probe youtube fails (DNS blocked here)
[PASS] direct probe example.com ok
[PASS] network stats non-zero
```

### `ncp network stats`

Before:
```
Network Statistics:
  Packets sent: 0
  Packets received: 0
  Bytes sent: 0
  Bytes received: 0
```

After:
```
Network Statistics:
  Packets sent: 72576
  Packets received: 161448
  Bytes sent: 404581266
  Bytes received: 76265466
```

Real counters, and they move between invocations.

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (52987 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to the baseline. The 8 skips are all `I2PManagerTest.*`, which skip
because no I2P SAM bridge is listening on `127.0.0.1:7656` — environmental and
unrelated.

## Why the test suite did not catch this

`get_stats()` has no unit test. The only assertion covering it lived in
`ncp_functional_check`, which is a manually-run binary rather than part of the
gtest suite, so it was not gating CI.

A unit test asserting that `get_stats()` returns non-zero bytes on a machine
with active networking would catch a regression here. Not added in this change;
noted as a gap.

## Platform scope

The `#else` branch is Windows-only. Linux behaviour is untouched — the
`#ifndef _WIN32` branch is byte-for-byte unchanged, and macOS continues to route
through the existing non-Windows path.
