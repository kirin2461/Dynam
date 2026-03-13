# NCP-CPP Security Audit

> **Auditor**: AI Code Review
> **Date Updated**: 2026-03-13
> **Status**: Ongoing (Regularly updated with core fixes)

---

## Summary
| Severity | Count | Status |
|---|---|---|
| 🔴 Critical | 15 | 8 FIXED, 7 Open |
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
- **Status**: ⬜ Open
- **Description**: Potential OOB read in TCP segment splitting logic.


### 🔴 #2 — `ncp_dpi.cpp`: `process_tls_client_hello` unbounded SNI extraction
- **Status**: ⬜ Open
- **Description**: Crafted ClientHello can cause OOB read due to missing bounds check on SNI length.

---
**Next Audit Step**: Review `security.cpp` and `spoofer.cpp` implementations.

