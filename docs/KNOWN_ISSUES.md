# Known Issues and Improvement Recommendations

## 🔴 Critical Issues

### 1. Incomplete ECH (Encrypted Client Hello) Implementation
**Location**: `src/core/src/dpi_advanced.cpp` (lines 613-650)
**Current Status**:
- ECH implementation is a simplified stub.
- HPKE encryption integration with OpenSSL 3.2+ is ongoing.
- ECHConfig parsing from DNS records needs optimization.

### 2. Global Variables in CLI (Legacy)
**Note**: Mostly resolved by introducing the `Application` class. Some legacy pointers remain in `main.cpp` for signal handling.

## ⚠️ Security Concerns

### 3. Domain Fronting
- Simple SNI replacement works, but lacks modern CDN routing verification.
- Needs HTTP/2 pseudo-header manipulation for better compatibility with Cloudflare/Fastly.

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


Update KNOWN_ISSUES.md to reflect current project status and resolved CLI refactoring
