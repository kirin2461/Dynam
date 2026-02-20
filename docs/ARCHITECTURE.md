# NCP C++ Architecture

## Overview

NCP C++ (Dynam) is a multi-layered network anonymization platform built on a three-layer architecture. All code uses the `ncp::` namespace, modern C++17 with `constexpr`/`noexcept` optimization.

> **Note**: Security audit in progress — see [AUDIT.md](../AUDIT.md) for 87 known findings.

## Three-Layer Architecture

### Layer 1: Core Library (libncp_core) — 42 modules

**Purpose**: All network operations, cryptography, anonymization, and security logic.

**49 public headers** in `src/core/include/`, **46 implementation files** in `src/core/src/`.

#### Cryptography & Security (7 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| CSPRNG | `ncp_csprng.hpp` | header-only | 3.7KB | libsodium wrapper: random_bytes, uniform, shuffle |
| Cryptography | `ncp_crypto.hpp` + `ncp_crypto_constants.hpp` | `crypto.cpp` | 14KB | Ed25519, Curve25519, ChaCha20-Poly1305, X25519, AEAD |
| E2E Encryption | `ncp_e2e.hpp` + `ncp_e2e_caps_patch.hpp` | `e2e.cpp` | 71KB | X25519 (✅), X448/P256 (⚠️), Kyber1024 (⚠️) |
| Secure Memory | `ncp_secure_memory.hpp` | `ncp_secure_memory.cpp` | 7KB | Auto-zeroing containers, mlock |
| Secure Buffer | `ncp_secure_buffer.hpp` | `secure_buffer.cpp` | 4KB | RAII buffer, sodium_memzero, VirtualLock |
| Security Manager | `ncp_security.hpp` | `security.cpp` | 47KB | Comprehensive security operations |
| Capabilities | `ncp_capabilities.hpp` | header-only | 25KB | Runtime capability detection, feature flags |

#### DPI Bypass & Evasion (4 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| DPI Bypass | `ncp_dpi.hpp` | `ncp_dpi.cpp` | 49KB | TCP fragmentation, fake packets, disorder, SNI splitting |
| DPI Advanced | `ncp_dpi_advanced.hpp` | `dpi_advanced.cpp` | 45KB | 15+ techniques, TCPManipulator, TLSManipulator, 6 presets |
| Geneva Engine | `ncp_geneva_engine.hpp` | `ncp_geneva_engine.cpp` | 15KB | Packet manipulation based on Geneva framework |
| Geneva GA | `ncp_geneva_ga.hpp` | `ncp_geneva_ga.cpp` | 26KB | Genetic algorithm for evolving evasion strategies |

#### TLS & ECH (5 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| TLS Fingerprinting | `ncp_tls_fingerprint.hpp` | `tls_fingerprint.cpp` | 43KB | JA3/JA3S/JA4, browser profiles, per-connection rotation |
| TLS Record Padding | `ncp_tls_record_padding.hpp` | `tls_record_padding.cpp` | 8KB | TLS record-level padding |
| ECH | `ncp_ech.hpp` | `ncp_ech.cpp` | 21KB | HPKE (⚠️ server decrypt broken — AUDIT #76) |
| ECH Cache | `ncp_ech_cache.hpp` | `ncp_ech_cache.cpp` | 11KB | ECH config caching |
| ECH Fetch + Retry | `ncp_ech_fetch.hpp` + `ncp_ech_retry.hpp` | `ncp_ech_fetch.cpp` + `ncp_ech_retry.cpp` | 26KB | Config fetching, retry with fallback |

#### Network & Spoofing (7 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| Network Spoofing | `ncp_spoofer.hpp` | `spoofer.cpp` | 43KB | IPv4/IPv6/MAC/DNS, SMBIOS, disk serial |
| Network Ops | `ncp_network.hpp` + `ncp_network_backend.hpp` | `network.cpp` | 11KB | libpcap, raw sockets, typed handles |
| Raw Socket | — | `network_raw_socket.cpp` | 12KB | Low-level packet construction |
| ARP Spoofing | `ncp_arp.hpp` | `ncp_arp.cpp` | 17KB | ARP cache poisoning |
| DHCP Spoofing | `ncp_dhcp_spoofer.hpp` (in src/) | `dhcp_spoofer.cpp` | 15KB | DHCP client ID spoofing |
| SMBIOS Hook | — | `smbios_hook.cpp` | 5.5KB | Hardware serial spoofing |
| Identity | `ncp_identity.hpp` | `ncp_identity.cpp` | 9KB | Unified identity management |

#### Traffic Shaping & Obfuscation (7 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| Traffic Mimicry | `ncp_mimicry.hpp` | `mimicry.cpp` | 57KB | HTTP/TLS/WS/DNS/QUIC emulation (🚧 partial) |
| Protocol Morphing | `ncp_protocol_morph.hpp` | `ncp_protocol_morph.cpp` | 17KB | Runtime protocol transformation |
| Adversarial Padding | `ncp_adversarial.hpp` | `ncp_adversarial.cpp` | 26KB | ML classifier evasion |
| Adversary Tester | `ncp_adversary_tester.hpp` | `ncp_adversary_tester.cpp` | 21KB | Adversarial technique testing |
| Flow Shaping | `ncp_flow_shaper.hpp` | `ncp_flow_shaper.cpp` | 27KB | Timing/size shaping, dummy injection |
| Burst Morphing | `ncp_burst_morpher.hpp` | `ncp_burst_morpher.cpp` | 27KB | Burst pattern transformation |
| Entropy Masking | `ncp_entropy_masking.hpp` | `ncp_entropy_masking.cpp` | 9KB | Entropy normalization |

#### Stealth & Defense (7 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| L2 Stealth | `ncp_l2_stealth.hpp` | `ncp_l2_stealth.cpp` | 15KB | Data link layer stealth |
| L3 Stealth | `ncp_l3_stealth.hpp` | `ncp_l3_stealth.cpp` | 30KB | Network layer stealth |
| Packet Interceptor | `ncp_packet_interceptor.hpp` | `ncp_packet_interceptor.cpp` | 36KB | Packet interception/modification |
| Paranoid Mode | `ncp_paranoid.hpp` | `ncp_paranoid.cpp` | 28KB | 8-layer protection (TINFOIL_HAT) |
| Port Knocking | `ncp_port_knock.hpp` | `ncp_port_knock.cpp` | 25KB | Crypto port knock + TOTP |
| Probe Resistance | `ncp_probe_resist.hpp` | `ncp_probe_resist.cpp` | 30KB | Active probe defense |
| Timing Protection | `ncp_timing.hpp` | `ncp_timing.cpp` | 11KB | Anti-timing analysis |
| Dummy Traffic | `ncp_dummy.hpp` | `ncp_dummy.cpp` | 10KB | Cover traffic generation |

#### Orchestration & Infrastructure (5 modules)

| Module | Header | Impl. | Size | Purpose |
|--------|--------|-------|------|---------|
| Orchestrator | `ncp_orchestrator.hpp` + `ncp_orchestrator_caps_patch.hpp` | `ncp_orchestrator.cpp` | 32KB | Unified pipeline, threat-level switching |
| Rotation Coordinator | `ncp_rotation_coordinator.hpp` | `ncp_rotation_coordinator.cpp` | 15KB | Identity/key/circuit rotation |
| Thread Pool | `ncp_thread_pool.hpp` | `ncp_thread_pool.cpp` | 2KB | Worker thread management |
| DoH | `ncp_doh.hpp` | `doh.cpp` | 42KB | DNS over HTTPS |
| WebSocket Tunnel | `ncp_ws_tunnel.hpp` | `ncp_ws_tunnel.cpp` | 13KB | WebSocket tunneling |
| I2P | `ncp_i2p.hpp` | `i2p.cpp` | 30KB | Garlic routing, SAM bridge (🚧) |

#### Utility (5 modules)

| Module | Header | Impl. | Purpose |
|--------|--------|-------|---------|
| Database | `ncp_db.hpp` | `db.cpp` | SQLite3 + SQLCipher |
| License | `ncp_license.hpp` | `license.cpp` | HWID-based validation |
| Logger | `ncp_logger.hpp` | — | Configurable logging |
| Configuration | `ncp_config.hpp` | — | App configuration |
| WinSock RAII | `ncp_winsock_raii.hpp` | — | Windows socket init |

### Layer 2: CLI Tool

**Status**: Partially implemented (26KB `main.cpp`)

- ✅ Working: `status`, `help`
- 🚧 In development: all other commands (stubs being refactored)

The `run` command (when complete) will activate all 8 PARANOID protection layers.

### Layer 3: GUI Application (Qt6)

**Status**: Planned (ENABLE_GUI=OFF by default)

---

## Protocol Orchestrator Pipeline

The Protocol Orchestrator (`ncp_orchestrator.hpp`) chains all protection components into a unified `send()`/`receive()` API.

> ⚠️ Known issues: auth token stripping breaks legacy clients (AUDIT #72), no strategy lock during send (AUDIT #73)

### Send Pipeline (Client → Server)

```
Payload
  ↓
[TLS Fingerprint Rotation]     ← per-connection browser profile switch
  ↓
[AdvancedDPIBypass]            ← ClientHello processing:
  │  ├── GREASE injection       ← RFC 8701 randomization
  │  ├── ECH application        ← Encrypted Client Hello (⚠️ server decrypt broken)
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

| Threat Level | Strategy | Features Enabled | Notes |
|---|---|---|---|
| NONE | max_compat | Mimicry, TLS FP, Probe Resist (permissive) | |
| LOW | performance | + Adversarial (minimal) | |
| MEDIUM | balanced | + Flow Shaping, AdvancedDPI (moderate), ECH | |
| HIGH | stealth | + All techniques, aggressive adversarial, flow dummies | |
| CRITICAL | stealth | Same as HIGH | ⚠️ No differentiation (AUDIT #75) |

---

## DPI Advanced Architecture

### Component Hierarchy

```
AdvancedDPIBypass
├── TCPManipulator
│   ├── split_segments()
│   ├── create_overlap()
│   ├── add_oob_marker()
│   └── shuffle_segments()
├── TLSManipulator
│   ├── create_fake_client_hello()
│   ├── create_fingerprinted_client_hello()
│   ├── find_sni_split_points()
│   ├── split_tls_record()
│   ├── inject_grease()
│   ├── add_tls_padding()
│   └── set_tls_fingerprint()
├── TrafficObfuscator
│   ├── obfuscate()
│   ├── deobfuscate()
│   └── rotate_key()
├── ECH::apply_ech()
│   ├── parse_ech_config()
│   └── apply_ech()
├── GenevaEngine              # NEW — not in previous docs
│   ├── apply_strategy()
│   └── parse_strategy()
├── GenevaGA                  # NEW — not in previous docs
│   ├── evolve()
│   ├── evaluate_fitness()
│   └── crossover() / mutate()
└── DPIBypass (base)
    ├── Proxy mode
    ├── Driver mode (nfqueue)
    └── Packet forwarding
```

---

## Module Structure (actual file listing)

```
src/core/
├── CMakeLists.txt
├── include/                     # 49 headers
│   ├── ncp_adversarial.hpp
│   ├── ncp_adversary_tester.hpp
│   ├── ncp_arp.hpp
│   ├── ncp_burst_morpher.hpp
│   ├── ncp_capabilities.hpp
│   ├── ncp_config.hpp
│   ├── ncp_crypto.hpp
│   ├── ncp_crypto_constants.hpp
│   ├── ncp_csprng.hpp
│   ├── ncp_db.hpp
│   ├── ncp_doh.hpp
│   ├── ncp_dpi.hpp
│   ├── ncp_dpi_advanced.hpp
│   ├── ncp_dummy.hpp
│   ├── ncp_e2e.hpp
│   ├── ncp_e2e_caps_patch.hpp
│   ├── ncp_ech.hpp
│   ├── ncp_ech_cache.hpp
│   ├── ncp_ech_fetch.hpp
│   ├── ncp_ech_retry.hpp
│   ├── ncp_entropy_masking.hpp
│   ├── ncp_flow_shaper.hpp
│   ├── ncp_geneva_engine.hpp
│   ├── ncp_geneva_ga.hpp
│   ├── ncp_i2p.hpp
│   ├── ncp_identity.hpp
│   ├── ncp_l2_stealth.hpp
│   ├── ncp_l3_stealth.hpp
│   ├── ncp_license.hpp
│   ├── ncp_logger.hpp
│   ├── ncp_mimicry.hpp
│   ├── ncp_network.hpp
│   ├── ncp_network_backend.hpp
│   ├── ncp_orchestrator.hpp
│   ├── ncp_orchestrator_caps_patch.hpp
│   ├── ncp_packet_interceptor.hpp
│   ├── ncp_paranoid.hpp
│   ├── ncp_port_knock.hpp
│   ├── ncp_probe_resist.hpp
│   ├── ncp_protocol_morph.hpp
│   ├── ncp_rotation_coordinator.hpp
│   ├── ncp_secure_buffer.hpp
│   ├── ncp_secure_memory.hpp
│   ├── ncp_security.hpp
│   ├── ncp_spoofer.hpp
│   ├── ncp_thread_pool.hpp
│   ├── ncp_timing.hpp
│   ├── ncp_tls_fingerprint.hpp
│   ├── ncp_tls_record_padding.hpp
│   ├── ncp_winsock_raii.hpp
│   └── ncp_ws_tunnel.hpp
└── src/                         # 46 implementation files
    └── (see above modules)

tests/                           # 22 test files
├── crypto_test.cpp
├── test_advanced_dpi.cpp
├── test_critical_fixes.cpp
├── test_csprng.cpp
├── test_dpi.cpp
├── test_dpi_advanced_integration.cpp
├── test_e2e.cpp
├── test_e2e_extended.cpp
├── test_ech.cpp
├── test_ech_cache.cpp
├── test_ech_pipeline.cpp
├── test_i2p.cpp
├── test_integration.cpp
├── test_l3_l2_stealth.cpp
├── test_l3_stealth.cpp
├── test_license.cpp
├── test_mimicry_roundtrip.cpp
├── test_network.cpp
├── test_paranoid.cpp
├── test_secure_memory.cpp
├── integration/
├── fuzz/
└── scripts/
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
├─ Npcap SDK     (Windows packet capture)
└─ GTest         (Unit testing)
    ↓
libncp_core (Static Library) — 42 modules
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
│  ┌──────────────────────────────┐     │
│  │       Geneva Engine + GA     │     │
│  └──────────────────────────────┘     │
│  ┌──────────────┬───────────────┐     │
│  │  L2 Stealth  │  L3 Stealth   │     │
│  └──────────────┴───────────────┘     │
│  ┌──────────────────────────────┐     │
│  │     Security + Capabilities   │     │
│  └──────────────────────────────┘     │
└──────────────────────────────────────┘
    ↓
┌───┴────┬─────────┐
↓        ↓         ↓
CLI     Qt6 GUI  Custom
Tool   (planned)  Apps
```

## API Design

All public APIs use flat `ncp::` namespace:

```cpp
namespace ncp {
  // Cryptography & Security
  class Crypto;
  class E2EEncryption;
  class SecureBuffer;
  struct Capabilities;

  // DPI & Evasion
  class DPIBypass;
  class AdvancedDPIBypass;
  class GenevaEngine;
  class GenevaGA;
  class TLSFingerprint;

  // ECH
  namespace ECH { /* apply_ech, parse_ech_config */ }
  class ECHCache;
  class ECHFetcher;
  class ECHRetryManager;

  // Network & Spoofing
  class NetworkSpoofer;
  class Network;
  class ARPSpoofer;
  class IdentityManager;

  // Traffic
  class ProtocolMimicry;
  class ProtocolMorph;
  class AdversarialPadding;
  class FlowShaper;
  class BurstMorpher;
  class EntropyMasking;

  // Stealth & Defense
  class L2Stealth;
  class L3Stealth;
  class PacketInterceptor;
  class ParanoidMode;
  class PortKnock;
  class ProbeResist;

  // Orchestration
  class ProtocolOrchestrator;
  class RotationCoordinator;
  class ThreadPool;

  // Infrastructure
  class DoHClient;
  class I2PManager;
  class WebSocketTunnel;
  class Database;
  class License;
}
```

## Testing

22 test files in `tests/` directory:

| Test File | Focus |
|-----------|-------|
| `crypto_test.cpp` | Core cryptography |
| `test_dpi.cpp` | Basic DPI bypass |
| `test_advanced_dpi.cpp` | Advanced DPI techniques |
| `test_dpi_advanced_integration.cpp` | DPI pipeline integration |
| `test_csprng.cpp` | CSPRNG (18 tests) |
| `test_e2e.cpp` + `test_e2e_extended.cpp` | E2E encryption |
| `test_ech.cpp` + `test_ech_cache.cpp` + `test_ech_pipeline.cpp` | ECH subsystem |
| `test_mimicry_roundtrip.cpp` | Mimicry wrap/unwrap |
| `test_paranoid.cpp` | Paranoid mode |
| `test_secure_memory.cpp` | Secure containers |
| `test_i2p.cpp` | I2P integration |
| `test_l3_stealth.cpp` + `test_l3_l2_stealth.cpp` | Stealth modules |
| `test_critical_fixes.cpp` | Regression tests |
| `test_integration.cpp` | Cross-module integration |
| `test_license.cpp` | License validation |
| `test_network.cpp` | Network operations |
| `tests/fuzz/` | LibFuzzer tests |
| `tests/integration/` | Integration test suite |

## Compliance

- **C++ Standard**: C++17 (supports 20, 23)
- **Compiler**: GCC 9+, Clang 10+, MSVC 2019+
- **Platforms**: Linux, macOS, Windows (x86_64, ARM64)
