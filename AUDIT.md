# NCP-CPP Security Audit

> **Auditor**: AI Code Review
> **Date Updated**: 2026-09-12
> **Status**: Ongoing (Regularly updated with core fixes)

---

## Summary

> **2026-09-12 — R16 wave**: External audit (~90K LOC) found **11 critical + ~20 high + ~14 minor** issues — **all fixed** across 6 fix zones (`fix/zone-a`..`f`), merged into `integration`. Tests: 786 → **812 passed**, 8/8 ctest targets green, TSan clean. Full details: [r16.md](r16.md).

| Severity | Count | Status |
|---|---|---|
| 🔴 Critical | 15 | 8 FIXED, 5 Open, 2 Obsolete (R16) |
| 🟠 Logic/Race | 42 | 20 FIXED, 22 Open |
| 🟡 Quality | 30 | 15 FIXED, 15 Open |

---

## Key Fixed Findings

### 🔴 #5 — `ncp_probe_resist.cpp`: Timing Oracle in Auth Verification
- **Status**: ✅ FIXED
- **Verification**: Early-return replaced with constant-time `sodium_memcmp`.

### 🔴 #64 — `ncp_port_knock.cpp`: Fallback HMAC is XOR
- **Status**: ✅ FIXED
- **Verification**: XOR replaced with libsodium `crypto_auth()`.

### 🔴 #22 — `ncp_probe_resist.cpp`: CSPRNG raw /dev/urandom
- **Status**: ✅ FIXED
- **Verification**: Replaced with `randombytes_buf()` from libsodium.

### 🔴 #55 — `doh.cpp`: SSL_CTX Double-Free
- **Status**: ✅ FIXED
- **Verification**: Correct lifetime management via pImpl.

---

## Open Findings (Priority)

### 🔴 #1 — `ncp_dpi.cpp`: `apply_tcp_split` off-by-one buffer read
- **Status**: 🚫 OBSOLETE (2026-09-12, R16)
- **Description**: Potential OOB read in TCP segment splitting logic.
- **Resolution**: No function named `apply_tcp_split` exists in the codebase. The actual analogue, `send_with_fragmentation`, contains exhaustive bounds checks and passed 2.5M fuzzing iterations under ASan/UBSan (see [r16.md](r16.md)).


### 🔴 #2 — `ncp_dpi.cpp`: `process_tls_client_hello` unbounded SNI extraction
- **Status**: 🚫 OBSOLETE (2026-09-12, R16)
- **Description**: Crafted ClientHello can cause OOB read due to missing bounds check on SNI length.
- **Resolution**: No function named `process_tls_client_hello` exists in the codebase. The actual analogue, `find_sni_hostname_offset`, performs exhaustive bounds validation and passed 2.5M fuzzing iterations under ASan/UBSan (see [r16.md](r16.md)).

---
**Next Audit Step**: Review `security.cpp` and `spoofer.cpp` implementations.

