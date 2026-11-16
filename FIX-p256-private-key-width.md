# Fix: P-256 private key truncated to 31 bytes when the scalar starts with 0x00

**Date**: 2026-11-16
**File changed**: `src/core/src/e2e.cpp`
**Surfaced by**: the `sanitizers (tsan)` CI job, immediately after the
`TurnServerStats` race fix
**Status**: Fixed and **proven statistically** — 3000 keygens, 0 deviations.

---

## Summary

`E2EExtendedTest.ECDH_P256_KeyGeneration` failed in CI:

```
tests/test_e2e_extended.cpp:136: Failure
Expected equality of these values:
  keypair.private_key.size()
    Which is: 31
  32
ECDH P-256 private key must be 32 bytes
```

An ECDH P-256 private key is a 256-bit scalar: **always 32 bytes**. The code
serialised it with `BN_num_bytes()`, which returns the number of *significant*
bytes. When the scalar's most significant byte is `0x00` — roughly one key in
256 — that leading zero is not counted, and the key comes out **31 bytes**.

This is not a new bug. It has been in the code since the P-256 key path was
written; it simply needs many keygens to trigger, so earlier runs got lucky.
Every CI run does thousands of keygens, which is why it eventually landed.

## Root cause

```cpp
size_t priv_len = static_cast<size_t>(BN_num_bytes(priv_bn.get()));
kp.private_key = SecureMemory(priv_len);      // 31 when the top byte is 0
BN_bn2bin(priv_bn.get(), kp.private_key.data());
```

`BN_bn2bin` writes only the significant bytes too, so the buffer and the data
agree with each other — but both are the wrong width. That is why this stayed
invisible: nothing inside this function looks inconsistent.

The second-order effect is worse than the size assertion. `private_key` is
consumed by `ec_p256_pkey_from_private(priv_raw, priv_len, …)`, so a truncated
scalar is fed into the DH path as a shorter big-endian integer. A 31-byte
buffer holding the same value is numerically identical after `BN_bin2bn`, so DH
still works — but any consumer that requires fixed-width, and any
size-validating checkpoint, sees a malformed key.

## The change

Both OpenSSL branches (3.x and 1.1.x) now use `BN_bn2binpad`, which left-pads
to a caller-specified width:

```cpp
constexpr size_t kP256ScalarBytes = 32;
kp.private_key = SecureMemory(kP256ScalarBytes);
if (BN_bn2binpad(priv_bn.get(), kp.private_key.data(),
                 static_cast<int>(kP256ScalarBytes)) !=
    static_cast<int>(kP256ScalarBytes)) {
    throw std::runtime_error("P256 ratchet: private key padding failed");
}
```

A third site had been **accommodating** the bug rather than fixing it:

```diff
-        // P-256 private scalars are serialized via BN_num_bytes(), so a
-        // leading zero byte trims the encoding below 32 bytes.
-        case KeyExchangeProtocol::ECDH_P256: return len >= 1 && len <= 32;
+        // ...fixed-width 32 bytes (BN_bn2binpad)...
+        case KeyExchangeProtocol::ECDH_P256: return len == 32;
```

`ratchet_priv_size_valid()` accepted anything from 1 to 32 bytes. That range
existed precisely because of this bug, and it meant a truncated scalar passed
validation instead of being rejected. It now requires exactly 32.

## Verification — and why it needed statistics

40 consecutive passing runs prove nothing for a 1-in-256 defect; that is a ~85%
chance of missing it. So the fix was measured instead of sampled.

A temporary probe (since removed) generated **3000 P-256 keypairs** and
histogrammed the private-key size.

**With the fix:**

```
priv_size=32 count=3000
[       OK ] P256Probe.PrivateScalarIsAlways32Bytes (151 ms)
[  PASSED  ] 1 test.
```

**With the fix reverted** (stashed, rebuilt, re-run) — proving the probe actually
detects the defect rather than passing vacuously:

```
priv_size=31 count=5
priv_size=32 count=2995
more than one scalar width seen
[  FAILED  ] P256Probe.PrivateScalarIsAlways32Bytes (158 ms)
```

5 of 3000 ≈ 0.17%, consistent with a 1-in-512 rate for a zero top byte on a
scalar whose high byte is uniform. The probe fails on the old code and passes on
the new one.

The fix was then restored (`git stash pop`), the probe file deleted, and
`tests/CMakeLists.txt` reverted — `git diff --numstat tests/CMakeLists.txt` is
empty, so no build-system change leaked into the commit.

### Suite state

```
[==========] 1283 tests from 161 test suites ran. (52768 ms total)
[  PASSED  ] 1275 tests.
[  SKIPPED ] 8 tests.
```

0 failed. The E2E suites specifically: 48 tests, all passing.

## Relationship to the TSAN fix

These are two separate commits for two separate defects, both surfaced by the
same CI job in sequence:

1. **`ba73dd2`** — `TurnServerStats` data race. That fix removed all 18 TSAN
   warnings (`ThreadSanitizer: reported 18 warnings` → zero).
2. **this commit** — the P-256 truncation, which then became the only remaining
   failure in `ncp_tests`.

Worth noting: fixing the race did not cause this failure — it *exposed* it. TSan
reorders and slows execution, which shifts how many keygens land where. The bug
was always there.

## Limitations

- **Not run under TSan.** No Linux/TSan toolchain here; confirmation is the next
  CI run.
- The statistical probe was **temporary and is not committed**. If this class of
  bug recurs, a permanent property test over a few thousand keygens is cheap
  (~150 ms) and worth adding — noted, not done.
- OpenSSL 1.1.x branch is fixed but **not compiled here** (this machine builds
  against OpenSSL 3.x).
