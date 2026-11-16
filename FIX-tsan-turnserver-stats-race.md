# Fix: TSan data race in `TurnServerStats`

**Date**: 2026-11-16
**File changed**: `src/core/include/ncp_turn_server.hpp`
**CI failure**: `sanitizers (tsan)` on PR #137
**Status**: Fixed, built, local suite green. **Not verifiable on this machine** in
the way CI runs it — see Limitations.

---

## Summary

`sanitizers (tsan)` failed with **18 data-race warnings**. All 18 trace to one
root cause, so this is one bug, not eighteen.

Every warning is a read/write race on a `TurnServerStats` counter:

| Where | Role |
|---|---|
| `ncp_turn_server.cpp:589` (`do_allocate`) — `stats_.allocations_active = allocations_.size()` | writer |
| `ncp_turn_server.cpp:443` (`destroy_allocation`) — `--stats_.allocations_active` | writer |
| `tests/test_turn_server.cpp:708`, `:751` and the gtest assertion frames | reader |

The test harness (`ServerRunner` in `tests/test_turn_server.cpp`) runs
`server.poll()` on a background thread. The test body then asserts on
`srv.server.stats().field`, which returns a **reference** to the live struct.
`poll()` is the writer; the test thread is the reader; the fields were plain
`uint64_t`. That is a genuine data race in the shipped header — the test merely
exposes it.

Not caused by this branch: `git diff 167052f..HEAD -- src/core/src/ncp_turn_server.cpp`
is empty. The defect has been in the tree since the TURN work landed.

## Why CI failed but the tests "passed"

```
[==========] 1325 tests from 165 test suites ran. (56960 ms total)
[  PASSED  ] 1315 tests.
ThreadSanitizer: reported 18 warnings
```

1315 of 1325 passed — no assertion failed. TSan reports warnings on stderr and
exits with a non-zero status by default, so `ctest` marks `ncp_tests` failed.
The `grep` annotations in `ci.yml` are what surface the reports.

## The change

The counters became `std::atomic<uint64_t>`, with `<atomic>` added to the
header:

```cpp
// Counters are atomic because stats() hands out a reference that callers read
// from their own thread while poll() — the owner thread — updates them. With
// plain uint64_t this was a real data race, not a test artifact…
struct TurnServerStats {
    std::atomic<uint64_t> allocations_active{0};   // live allocations (gauge)
    std::atomic<uint64_t> allocations_total{0};
    …
};
```

Every existing operation on these fields is already atomic-friendly — `++`,
`--`, `=`, `+=`, `> 0` — so **no call site changed**. Only the declaration did.

Alternatives considered and rejected:

- **A mutex.** `stats_` is touched on the per-datagram path; a lock there costs
  more than relaxed atomic increments do, and the reader only needs individual
  fields, not a consistent snapshot.
- **A lock-free `uint64_t` cast.** Not portable; `std::atomic<uint64_t>` is the
  correct expression of the intent.

Side effect: `TurnServerStats` is now non-copyable. Nothing copies it —
`stats()` returns `const TurnServerStats&` and all 27 call sites read individual
fields. Verified by grep across `src/` and `tests/`.

## Verification

**Built**: `ncp_core`, `ncp-cli`, `ncp_tests` all compile clean with the atomic
change.

**Local suite** (Windows, Release):

```
[==========] 1283 tests from 161 test suites ran. (53215 ms total)
[  PASSED  ] 1275 tests.
[  SKIPPED ] 8 tests.
```

**Gtest assertion compatibility** — the real risk. `tests/test_turn_server.cpp`
is POSIX-only (`if(NOT WIN32)` in `tests/CMakeLists.txt`), so it cannot be built
here, and the assertions compare these fields with `EXPECT_EQ`/`EXPECT_GE`
against `unsigned`. Since `std::atomic<uint64_t>` is not implicitly convertible,
a compile error there would only have appeared in CI.

To rule that out I built a standalone probe reproducing the exact assertion
forms from the turn tests:

```cpp
EXPECT_GE(stats().auth_challenges_401, 1u);   // test_turn_server.cpp:247
EXPECT_EQ(stats().allocations_active, 0u);    // :248
const auto& st = server.stats();              // :653
EXPECT_GE(st.send_indications_relayed, 1u);
if (g_stats.allocations_active > 0) --g_stats.allocations_active;
```

Result: compiles and runs green. So the assertion forms in the POSIX tests will
compile against the new type.

## Limitations — state plainly

- **The race itself was not re-run under TSan.** There is no Linux/TSan toolchain
  on this machine (TSan is unavailable on Windows). The fix removes the race by
  construction — atomics on both sides — and the CI job on the next push is the
  real confirmation.
- **`tests/test_turn_server.cpp` was not compiled here.** The probe above
  reproduces its assertion *forms*, not the file itself.
- The local suite proves no regression on Windows; it does not prove the TSan
  warning count goes to zero.

## Follow-up

`std::atomic<uint64_t>` values stream and compare fine in gtest, but a failure
message will print the wrapper rather than a bare number. If that hurts
diagnostics, add a `static_cast<uint64_t>()` at the assertion sites; not worth
touching 27 call sites pre-emptively.
