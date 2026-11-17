# Test: regression coverage for the ClientHello extension-length bug

**Date**: 2026-11-16
**File changed**: `tests/test_bypass_features.cpp` (+91 lines, 2 tests)
**Status**: Added, verified to catch the original bug.

---

## Why this test exists

`FIX-blockcheck-clienthello.md` fixed a bug that had silently broken every
`ncp blockcheck` probe: `build_client_hello()` declared extension lengths that
did not match the bytes it wrote, so real TLS servers rejected the hello with a
fatal `decode_error`.

The bug survived because the existing tests could not see it. They built a hello
and parsed it back **with the matching parser** — both sides shared the same
wrong numbers, so they agreed and passed:

```cpp
auto ch = BlockChecker::build_client_hello("example.com");
auto info = parse_tls_client_hello(ch.data(), ch.size());
// Both use the same (wrong) length constants — this always succeeds.
```

Only `ncp_functional_check`, which probes a live server, caught it — and that
binary is not part of the gtest suite, so nothing gated the fix.

This change adds coverage at the wire-format level, which does not depend on
network availability and does not depend on the parser agreeing with the builder.

## The two tests

### `ClientHello.ExtensionLengthsTileExactly`

Walks the record structurally and requires the declared lengths to account for
every byte, exactly:

- the handshake length must equal `buffer_size - 9`
- the extensions block length must reach the end of the record
- every extension's declared length must fit inside the block
- **the extensions must tile the block with no gaps or overruns**

Plus targeted checks for the three extensions that were wrong:

| Extension | Type | Assertion |
|---|---|---|
| `supported_groups` | `0x000A` | inner list length + 2 == declared length |
| `signature_algorithms` | `0x000D` | inner list length + 2 == declared length |
| `key_share` | `0x0033` | client_shares length + 2 == declared length |

A malformed length breaks the tiling arithmetic, so the test fails on the
structure rather than on a specific hardcoded constant. That means it also
catches new length bugs introduced in extensions that do not exist yet.

### `ClientHello.ServerNameExtensionIsWellFormed`

Asserts the SNI hostname is present in the raw bytes and that the parser
recovers exactly what was written (`info.sni == host`,
`info.sni_value_len == host.size()`). This catches record-level length errors
that would truncate the payload.

## Verification that the test actually works

A regression test that passes is not evidence of anything — it has to fail on
the bug. This was verified directly:

**Step 1** — temporarily restored the original buggy lengths:

```cpp
e16(0x000A); e16(6); e16(0x001D); e16(0x0017);
e16(0x000D); e16(8); e16(0x0403); ...
e16(0x0033); e16(36); e16(34); ...
```

**Step 2** — rebuilt and ran. The test failed with a precise diagnosis:

```
[ RUN      ] ClientHello.ExtensionLengthsTileExactly
test_bypass_features.cpp(538): error: Expected equality of these values:
  list + 2
    Which is: 31
  elen
    Which is: 6
extension 10 list length mismatch
[  FAILED  ] ClientHello.ExtensionLengthsTileExactly (0 ms)
```

`extension 10` is `0x000A` (`supported_groups`) — the exact extension that was
mangled, named in the failure message.

**Step 3** — restored the fix, rebuilt, re-ran:

```
[       OK ] ClientHello.ExtensionLengthsTileExactly (0 ms)
[       OK ] ClientHello.ServerNameExtensionIsWellFormed (0 ms)
[  PASSED  ] 2 tests.
```

The working tree was confirmed clean against `HEAD` after restoring
(`git diff --numstat` → empty), so the committed fix is the state on disk.

## Suite totals

Before: `1275 tests from 159 test suites` / 1267 passed / 8 skipped / 0 failed
After: `1277 tests from 160 test suites` / 1269 passed / 8 skipped / 0 failed

The two new tests are the only delta. The 8 skips remain `I2PManagerTest.*`
(no I2P SAM bridge on `127.0.0.1:7656`), environmental.

## Limitation

These tests verify the hello is *structurally well-formed*, not that a live
server accepts it. A malformed-but-self-consistent hello would still pass —
that was precisely the original bug's shape, and structural checks catch it only
because the tiling math exposes the inconsistency.

Full confidence still comes from the live probe in `ncp_functional_check`
(`direct probe example.com ok`), which now passes. Ideally that check would run
in CI too; it currently depends on outbound network access and a reachable
target, which is why it is a separate binary.
