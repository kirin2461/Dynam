# NCP C++ Architecture

## Overview

NCP C++ (Dynam) is a multi-layered network anonymization platform built on a three-layer architecture. All code uses the `ncp::` namespace, modern C++17 with `constexpr`/`noexcept` optimization.

## Three-Layer Architecture

### Layer 1: Core Library (libncp_core) - 17 modules

**Purpose**: All network operations, cryptography, anonymization, and security logic.

**Modules**:

| Module | Header | Purpose |
|--------|--------|---------|
| Cryptography | `ncp_crypto.hpp` | Ed25519, Curve25519, ChaCha20-Poly1305, X25519, AEAD |
| DPI Bypass | `ncp_dpi.hpp` | TCP fragmentation, fake packets, disorder, SNI splitting |
| DPI Advanced | `ncp_dpi_advanced.hpp` | RuNet presets (Soft/Strong), advanced bypass |
| Network Spoofing | `ncp_spoofer.hpp` | IPv4/IPv6/MAC/DNS spoofing, identity rotation |
| Network Operations | `ncp_network.hpp` | libpcap capture, raw sockets, bypass techniques |
| Paranoid Mode | `ncp_paranoid.hpp` | 8-layer protection system (TINFOIL_HAT level) |
| Traffic Mimicry | `ncp_mimicry.hpp` | HTTP/TLS/WebSocket protocol emulation |
| TLS Fingerprinting | `ncp_tls_fingerprint.hpp` | JA3/JA3S fingerprint randomization |
| I2P Integration | `ncp_i2p.hpp` | Garlic routing, SAM bridge, tunnel management |
| E2E Encryption | `ncp_e2e.hpp` | X448, ECDH_P256, forward secrecy |
| Secure Memory | `ncp_secure_memory.hpp` | Memory-safe containers, auto-zeroing, mlock |
| DNS over HTTPS | `ncp_doh.hpp` | Encrypted DNS via DoH providers |
| Security | `ncp_security.hpp` | System hardening, process protection, anti-forensics |
| Database | `ncp_db.hpp` | SQLite3 + SQLCipher encrypted storage |
| License | `ncp_license.hpp` | Hardware ID-based offline validation |
| Logging | `ncp_logger.hpp` | Structured logging with severity levels |
| Configuration | `ncp_config.hpp` | Runtime configuration management |

**Key Features**:
- Statically linked library
- Header-only public interface
- Memory-safe C++17 with `constexpr`/`noexcept`
- `ncp::` namespace throughout

### Layer 2: CLI Tool

**Status**: Implemented

**Purpose**: Command-line interface with PARANOID mode auto-activation.

**Key Feature**: The `run` command automatically enables all 8 protection layers:
1. Entry obfuscation (bridge nodes, guard rotation)
2. Multi-anonymization (VPN -> Tor -> I2P)
3. Traffic obfuscation (constant rate, morphing)
4. Timing protection (random delays, batching)
5. Metadata stripping
6. Advanced crypto (post-quantum, forward secrecy)
7. Anti-correlation (traffic splitting, multi-circuit)
8. System protection (memory wipe, secure delete)

Plus: network isolation, forensic resistance, traffic analysis resistance.

### Layer 3: GUI Application (Qt6)

**Status**: Planned

**Purpose**: Cross-platform desktop interface with dark theme.

---

## Module Structure

```
src/core/
├── CMakeLists.txt
├── include/
│   ├── ncp_crypto.hpp
│   ├── ncp_dpi.hpp
│   ├── ncp_dpi_advanced.hpp
│   ├── ncp_spoofer.hpp
│   ├── ncp_network.hpp
│   ├── ncp_paranoid.hpp
│   ├── ncp_mimicry.hpp
│   ├── ncp_tls_fingerprint.hpp
│   ├── ncp_i2p.hpp
│   ├── ncp_e2e.hpp
│   ├── ncp_secure_memory.hpp
│   ├── ncp_doh.hpp
│   ├── ncp_security.hpp
│   ├── ncp_db.hpp
│   ├── ncp_license.hpp
│   ├── ncp_logger.hpp
│   └── ncp_config.hpp
└── src/
    └── (implementations)
```

---

## Dependency Hierarchy

```
System Libraries (libc, libc++, Kernel APIs)
    ↓
External Dependencies
├─ libsodium     (Core cryptography)
├─ OpenSSL 3     (TLS, DoH)
├─ SQLite3       (Encrypted database)
├─ libpcap       (Packet capture)
└─ GTest         (Unit testing)
    ↓
libncp_core (Static Library) - 17 modules
    ↓
┌───┴────┬─────────┐
↓        ↓         ↓
CLI     Qt6 GUI  Custom
Tool    (future)  Apps
```

## Build System

- **CMake** 3.20+ with modular structure
- **Conan** for dependency management
- Dependencies: libsodium/1.0.18, openssl/3.1.4, sqlite3/3.44.0, gtest/1.14.0

## API Design

All public APIs use `ncp::` namespace:

```cpp
namespace ncp {
  class Crypto { /* Ed25519, ChaCha20, etc. */ };
  class NetworkSpoofer { /* IPv4/IPv6/MAC/DNS spoofing */ };
  class ParanoidMode { /* 8-layer protection */ };
  class Network { /* Packet capture, bypass */ };
  namespace DPI { class DPIBypass { /* TCP fragmentation */ }; }
  class I2PManager { /* Garlic routing */ };
  class Database { /* SQLite3 + SQLCipher */ };
  class License { /* HWID-based validation */ };
}
```

## Security Design

### Paranoid Mode Protection Layers

| Layer | Protection | Implementation |
|-------|-----------|---------------|
| 1 | Entry Obfuscation | Bridge nodes, guard rotation (6h) |
| 2 | Multi-Anonymization | VPN chain -> Tor -> I2P |
| 3 | Traffic Obfuscation | Constant rate (128 kbps), morphing |
| 4 | Timing Protection | Random delays (50-500ms), batching |
| 5 | Metadata Stripping | Header sanitization, fingerprint removal |
| 6 | Advanced Crypto | Post-quantum (Kyber1024), forward secrecy |
| 7 | Anti-Correlation | Traffic splitting, 3 simultaneous circuits |
| 8 | System Protection | Memory wipe, disk cache disable, secure delete |

### Additional Security Features

- **Network Isolation**: Kill switch, IPv6/WebRTC blocking, per-domain isolation
- **Forensic Resistance**: Encrypted memory, no logs, crash dump prevention
- **Traffic Analysis Resistance**: Packet padding (1500 bytes), WFP defense
- **DPI Bypass**: TCP fragmentation, fake packets, SNI splitting, RuNet presets

### Cryptographic Primitives

- **Signatures**: Ed25519
- **Key Exchange**: Curve25519, X25519, X448, ECDH_P256
- **Encryption**: ChaCha20-Poly1305 (AEAD)
- **Hashing**: SHA-256 (via OpenSSL)
- **Post-quantum**: Kyber1024, Dilithium5 (via liboqs, optional)
- **Database**: SQLCipher (transparent encryption at rest)

## Testing

- **Unit Tests**: GoogleTest in `tests/` directory
- **Fuzz Tests**: Fuzzing for crypto, network, parser modules in `tests/fuzz/`
- **CI/CD**: GitHub Actions (Ubuntu, macOS, Windows matrix)

## Compliance

- **C++ Standard**: C++17
- **Compiler**: GCC 9+, Clang 10+, MSVC 2019+
- **Platforms**: Linux, macOS, Windows (x86_64, ARM64)
