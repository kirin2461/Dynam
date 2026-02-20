# NCP C++ Architecture

## Overview

NCP C++ (Dynam) is a multi-layered network anonymization platform built on a three-layer architecture. All code uses the `ncp::` namespace, modern C++17 with `constexpr`/`noexcept` optimization.

## Three-Layer Architecture

### Layer 1: Core Library (libncp_core) - 21 modules

**Purpose**: All network operations, cryptography, anonymization, and security logic.

**Modules**:

| Module | Header | Purpose |
|--------|--------|---------|
| Cryptography | `ncp_crypto.hpp` | Ed25519, Curve25519, ChaCha20-Poly1305, X25519, AEAD |
| DPI Bypass | `ncp_dpi.hpp` | TCP fragmentation, fake packets, disorder, SNI splitting |
| DPI Advanced | `ncp_dpi_advanced.hpp` | 15+ evasion techniques, TCPManipulator, TLSManipulator, TrafficObfuscator, 6 country presets |
| TLS Fingerprinting | `ncp_tls_fingerprint.hpp` | Browser profile emulation (Chrome/Firefox/Safari/Edge), JA3/JA3S/JA4, per-connection rotation |
| Encrypted Client Hello | `ncp_ech.hpp` | ECH draft with HPKE (X25519+HKDF-SHA256+AES-128-GCM), config parsing, extension insertion |
| Protocol Orchestrator | `ncp_orchestrator.hpp` | Unified send/receive pipeline with adaptive threat-level strategy switching |
| Adversarial Padding | `ncp_adversarial.hpp` | Packet-level adversarial bytes to defeat ML classifiers |
| Flow Shaping | `ncp_flow_shaper.hpp` | Timing/size shaping with dummy packet injection |
| Probe Resistance | `ncp_probe_resist.hpp` | Server-side active probe defense with HMAC auth |
| Network Spoofing | `ncp_spoofer.hpp` | IPv4/IPv6/MAC/DNS spoofing, identity rotation, HW serials |
| Network Operations | `ncp_network.hpp` | libpcap capture, raw sockets, bypass techniques |
| Paranoid Mode | `ncp_paranoid.hpp` | 8-layer protection system (TINFOIL_HAT level) |
| Traffic Mimicry | `ncp_mimicry.hpp` | HTTP/TLS/WebSocket/DNS/QUIC protocol emulation |
| I2P Integration | `ncp_i2p.hpp` | Garlic routing, SAM bridge, tunnel management |
| E2E Encryption | `ncp_e2e.hpp` | X448, ECDH_P256, forward secrecy |
| Secure Memory | `ncp_secure_memory.hpp` | Memory-safe containers, auto-zeroing, mlock |
| Secure Buffer | `ncp_secure_buffer.hpp` | RAII buffer with sodium_memzero, mlock/VirtualLock |
| CSPRNG | `ncp_csprng.hpp` | Header-only libsodium wrapper (random_bytes, uniform, shuffle) |
| DNS over HTTPS | `ncp_doh.hpp` | Encrypted DNS via DoH providers |
| Database | `ncp_db.hpp` | SQLite3 + SQLCipher encrypted storage |
| License | `ncp_license.hpp` | Hardware ID-based offline validation |

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

## Protocol Orchestrator Pipeline

The Protocol Orchestrator (`ncp_orchestrator.hpp`) is the central integration point that chains all DPI evasion and traffic protection components into a single `send()`/`receive()` API.

### Send Pipeline (Client → Server)

```
Payload
  ↓
[TLS Fingerprint Rotation]     ← per-connection browser profile switch
  ↓
[AdvancedDPIBypass]            ← ClientHello processing:
  │  ├── GREASE injection       ← RFC 8701 randomization
  │  ├── ECH application        ← Encrypted Client Hello (HPKE)
  │  ├── Decoy SNI              ← fake ClientHellos (google.com, etc.)
  │  ├── SNI split / multi-split ← TCP segmentation at SNI offset
  │  ├── Padding                ← random padding per segment
  │  └── Obfuscation            ← ChaCha20/XOR/HTTP camouflage
  ↓
[Adversarial Padding]          ← ML classifier evasion bytes
  ↓
[Protocol Mimicry]             ← wrap as HTTPS/DNS/QUIC traffic
  ↓
[Probe Auth Token]             ← HMAC prepend (client → server)
  ↓
[Flow Shaping]                 ← timing/size normalization + dummies
  ↓
Network
```

### Receive Pipeline (Server → Client)

```
Wire Data
  ↓
[Probe Auth Verify]            ← HMAC strip + authenticate
  ↓
[Flow Dummy Check]             ← drop dummy packets
  ↓
[Mimicry Unwrap]               ← remove protocol wrapper
  ↓
[Adversarial Dummy Check]      ← drop adversarial dummy packets
  ↓
[Adversarial Unpad]            ← remove padding
  ↓
Payload
```

### Adaptive Threat-Level Switching

| Threat Level | Strategy | Features Enabled |
|---|---|---|
| NONE | max_compat | Mimicry, TLS FP, Probe Resist (permissive) |
| LOW | performance | + Adversarial (minimal) |
| MEDIUM | balanced | + Flow Shaping, AdvancedDPI (moderate), ECH |
| HIGH | stealth | + All techniques, aggressive adversarial, flow dummies |
| CRITICAL | stealth | Same as HIGH (ceiling) |

Escalation/deescalation is automatic based on connection failures/successes.

---

## DPI Advanced Architecture

### Component Hierarchy

```
AdvancedDPIBypass
├── TCPManipulator              # TCP-level operations
│   ├── split_segments()         — split at arbitrary positions
│   ├── create_overlap()         — overlapping TCP segments
│   ├── add_oob_marker()         — out-of-band data markers
│   └── shuffle_segments()       — randomize segment order
├── TLSManipulator              # TLS-level operations
│   ├── create_fake_client_hello()       — decoy CH with random browser profile
│   ├── create_fingerprinted_client_hello() — CH with caller-controlled profile
│   ├── find_sni_split_points()  — locate SNI offset in CH
│   ├── split_tls_record()       — fragment TLS records
│   ├── inject_grease()          — RFC 8701 GREASE values
│   ├── add_tls_padding()        — random padding
│   └── set_tls_fingerprint()    — external TLSFingerprint* forwarding
├── TrafficObfuscator           # Traffic encryption/wrapping
│   ├── obfuscate()              — XOR/ChaCha20/HTTP camouflage
│   ├── deobfuscate()            — reverse obfuscation
│   └── rotate_key()             — key rotation
├── ECH::apply_ech()            # Encrypted Client Hello insertion
│   ├── parse_ech_config()       — parse ECHConfigList blob
│   └── apply_ech()              — insert ECH extension into CH
└── DPIBypass (base)            # Base proxy/driver functionality
    ├── Proxy mode
    ├── Driver mode (nfqueue)
    └── Packet forwarding
```

### TLS Fingerprint Integration

```
ncp::TLSFingerprint (owned by ProtocolOrchestrator)
    ↓  set_tls_fingerprint(&fp)
AdvancedDPIBypass
    ↓  forwards to
TLSManipulator
    ↓  uses for
create_fake_client_hello()        — randomizes profile per call
create_fingerprinted_client_hello() — uses caller's fixed profile
```

TLSFingerprint provides:
- Browser-specific cipher suite lists
- Extension ordering matching real browsers
- JA3/JA3S/JA4 hash generation
- ALPN protocol lists (h2, http/1.1)
- Supported groups / signature algorithms

---

## Module Structure

```
src/core/
├── CMakeLists.txt
├── include/
│   ├── ncp_crypto.hpp
│   ├── ncp_dpi.hpp
│   ├── ncp_dpi_advanced.hpp
│   ├── ncp_tls_fingerprint.hpp
│   ├── ncp_ech.hpp
│   ├── ncp_orchestrator.hpp
│   ├── ncp_adversarial.hpp
│   ├── ncp_flow_shaper.hpp
│   ├── ncp_probe_resist.hpp
│   ├── ncp_spoofer.hpp
│   ├── ncp_network.hpp
│   ├── ncp_paranoid.hpp
│   ├── ncp_mimicry.hpp
│   ├── ncp_i2p.hpp
│   ├── ncp_e2e.hpp
│   ├── ncp_secure_memory.hpp
│   ├── ncp_secure_buffer.hpp
│   ├── ncp_csprng.hpp
│   ├── ncp_doh.hpp
│   ├── ncp_db.hpp
│   ├── ncp_license.hpp
│   ├── ncp_logger.hpp
│   └── ncp_config.hpp
└── src/
    └── (implementations)

tests/
├── test_mimicry_roundtrip.cpp   # 7 tests: wrap/unwrap, key exchange
├── test_ech_pipeline.cpp        # 6 tests: ECH config, apply_ech, pipeline
├── test_advanced_dpi.cpp        # 9 tests: splits, GREASE, presets, obfuscation
├── test_csprng.cpp              # 18 tests: CSPRNG
└── fuzz/                        # LibFuzzer tests
```

---

## Dependency Hierarchy

```
System Libraries (libc, libc++, Kernel APIs)
    ↓
External Dependencies
├─ libsodium     (Core cryptography + CSPRNG)
├─ OpenSSL 3.2+  (TLS, DoH, ECH/HPKE)
├─ SQLite3       (Encrypted database)
├─ libpcap       (Packet capture)
└─ GTest         (Unit testing)
    ↓
libncp_core (Static Library) - 21 modules
    ↓
┌──────────────────────────────────────┐
│         ProtocolOrchestrator         │
│  ┌──────┬──────┬────────┬────────┐   │
│  │Adver-│ Flow │ Probe  │Traffic │   │
│  │sarial│Shaper│Resist  │Mimicry │   │
│  └──────┴──────┴────────┴────────┘   │
│  ┌──────────────────────────────┐     │
│  │     AdvancedDPIBypass        │     │
│  │  ┌────┬──────┬──────┬─────┐ │     │
│  │  │TCP │ TLS  │Obfus │ ECH │ │     │
│  │  │Mani│Manip+│cator │     │ │     │
│  │  │    │TLS FP│      │     │ │     │
│  │  └────┴──────┴──────┴─────┘ │     │
│  └──────────────────────────────┘     │
└──────────────────────────────────────┘
    ↓
┌───┴────┬─────────┐
↓        ↓         ↓
CLI     Qt6 GUI  Custom
Tool    (future)  Apps
```

## Build System

- **CMake** 3.20+ with modular structure
- **Conan** for dependency management
- Dependencies: libsodium/1.0.18, openssl/3.1.4+, sqlite3/3.44.0, gtest/1.14.0

## API Design

All public APIs use `ncp::` namespace:

```cpp
namespace ncp {
  class Crypto { /* Ed25519, ChaCha20, etc. */ };
  class NetworkSpoofer { /* IPv4/IPv6/MAC/DNS spoofing */ };
  class ParanoidMode { /* 8-layer protection */ };
  class Network { /* Packet capture, bypass */ };
  class TLSFingerprint { /* JA3/JA4, browser profiles */ };
  class ProtocolMimicry { /* wrap/unwrap TLS session */ };
  namespace DPI {
    class DPIBypass { /* TCP fragmentation */ };
    class AdvancedDPIBypass { /* 15+ evasion techniques */ };
    class ProtocolOrchestrator { /* unified pipeline */ };
    namespace ECH { /* Encrypted Client Hello */ }
  }
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

### DPI Evasion Security

- **TLS Fingerprint rotation**: Per-connection browser profile switching prevents JA3-based tracking
- **ECH (Encrypted Client Hello)**: Prevents SNI leakage to network observers; uses HPKE with X25519
- **GREASE injection**: RFC 8701 randomization defeats TLS extension fingerprinting
- **Decoy SNI**: Fake ClientHellos with benign domains (google.com, cloudflare.com) confuse DPI
- **Adaptive strategy**: Automatic escalation from max_compat → stealth upon detection events

### Additional Security Features

- **Network Isolation**: Kill switch, IPv6/WebRTC blocking, per-domain isolation
- **Forensic Resistance**: Encrypted memory, no logs, crash dump prevention
- **Traffic Analysis Resistance**: Packet padding (1500 bytes), WFP defense
- **DPI Bypass**: TCP fragmentation, fake packets, SNI splitting, 6 country presets

### Cryptographic Primitives

- **Signatures**: Ed25519
- **Key Exchange**: Curve25519, X25519, X448, ECDH_P256
- **Encryption**: ChaCha20-Poly1305 (AEAD), XChaCha20-Poly1305
- **HPKE (ECH)**: X25519 + HKDF-SHA256 + AES-128-GCM
- **Hashing**: SHA-256 (via OpenSSL)
- **Post-quantum**: Kyber1024, Dilithium5 (via liboqs, optional)
- **Database**: SQLCipher (transparent encryption at rest)
- **CSPRNG**: libsodium `randombytes_*` (zero std::mt19937)

## Testing

- **Unit Tests**: GoogleTest in `tests/` directory
  - `test_mimicry_roundtrip.cpp` — 7 tests: wrap/unwrap, key exchange, TLS record structure
  - `test_ech_pipeline.cpp` — 6 tests: config parsing, apply_ech, pipeline flow
  - `test_advanced_dpi.cpp` — 9 tests: splits, GREASE, decoy SNI, obfuscation, presets
  - `test_csprng.cpp` — 18 tests: bounds, distribution, uniqueness, shuffle
  - Core module tests: crypto, DPI, networking, E2E, Paranoid, SecureMemory, I2P
- **Fuzz Tests**: Fuzzing for crypto, network, parser modules in `tests/fuzz/`
- **CI/CD**: GitHub Actions (Ubuntu, macOS, Windows matrix)

## Compliance

- **C++ Standard**: C++17
- **Compiler**: GCC 9+, Clang 10+, MSVC 2019+
- **Platforms**: Linux, macOS, Windows (x86_64, ARM64)
