# Known Issues and Improvement Recommendations

## 🔴 Critical Issues

### 1. ECH (Encrypted Client Hello) Implementation
**Status**: ✅ Resolved (2026-11-26). Full implementation in `src/core/src/ncp_ech.cpp`
(~1.5k lines): OpenSSL HPKE (built against OpenSSL 3.5.9) with libsodium fallback,
integrated into `ncp_orchestrator.cpp` and `AdvancedDPIBypass`.

Fixed in this pass:
- HPKE `apply_ech` now rewrites the outer SNI to `config.public_name` (it previously
  left the real SNI in the plaintext outer CH, defeating ECH's purpose against passive DPI).
- HPKE `parse_ech_config` now parses the full draft-18 wire format and unwraps
  `ECHConfigList` (it previously accepted only the legacy simplified layout, so
  DNS-sourced configs produced garbage fields). All fields are reset per parse
  (stale `cipher_suites` accumulation across reuse is gone).
- `ncp_ech_fetch.cpp` read `maximum_name_length` as uint16 instead of uint8, so every
  real wire-format config failed to parse; corrected to uint8 per draft-18.

Remaining: live-server integration tests (see Testing Requirements).

### 2. Global Variables in CLI (Legacy)
**Note**: Mostly resolved by introducing the `Application` class. Some legacy pointers remain in `main.cpp` for signal handling.

## ⚠️ Security Concerns

### 3. Domain Fronting
**Status**: ⚠️ Partially improved (2026-11-26).
- `apply_domain_fronting` (`src/core/src/dpi_advanced.cpp`) rewritten: TLS SNI via the
  length-safe `ECH::rewrite_sni` helper, HTTP/1.1 `Host` header value swap, and a
  best-effort HTTP/2 HPACK `:authority` literal rewrite with 24-bit frame-length patching.
  It never returns an empty packet (the old implementation returned `{}` on any length
  mismatch, truncating the stream).
- Covered by `test_advanced_dpi` → `test_domain_fronting` (TLS of differing SNI lengths,
  HTTP/1.1, HTTP/2 frame, garbage input, SNI mismatch passthrough).
- Still missing: modern CDN routing verification; `enable_domain_fronting`
  (`ncp_doh.hpp`) is never read; `query_with_fronting` degrades silently to a direct
  query when fronting fails.

### 4. SNI Parsing Edge Cases
- Truncated or malformed TLS records can lead to parsing errors.
- Improved bounds checking is required in `TLSManipulator`.

## 📝 Code Quality Issues

### 5. Error Handling
- Some internal components still use silent returns.
- Integration of a unified error reporting system is planned.

## 🔬 Testing Requirements
1. **ECH Subsystem**: Full integration tests with live servers.
2. **Geneva Engine**: Verify GA convergence in various network scenarios.
3. **Memory Safety**: Continuous ASan monitoring.
