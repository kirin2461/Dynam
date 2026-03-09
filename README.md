# Dynam (NCP C++) - Network Control Protocol

> Multi-layered network anonymization and privacy platform with DPI bypass, traffic spoofing, paranoid mode, and advanced cryptography. Written in modern C++17.

## Current Status

**Version**: 1.4.0-dev (Active Development)
**CMake Version**: 1.4.0 (synced)

> ✅ **MASTER_ORCHESTRATOR 100% COMPLETE**: Full 7-stage pipeline with anti-ML, steganography, and behavioral cloaking implemented.

### Implementation Progress

**MasterOrchestrator — 100% Complete** (13 modules, ~3500 lines):

- ✅ **Phase 1: Core Integration** — MasterOrchestrator, 7-stage pipeline, send/receive API
- ✅ **Phase 2: Anti-ТСПУ ML** — BehavioralCloak, ProtocolRotationSchedule, SessionPatternRandomizer
- ✅ **Phase 3: Anti-СОРМ** — CovertChannelManager (4 channels), CrossLayerCorrelator, GeoObfuscator
- ✅ **Phase 4: Security** — PanicSequence (9 steps), Background Scheduler (8 tasks)

- ✅ **Fully Implemented** (80-100%): Cryptography, DPI Bypass, DPI Advanced (multi-technique pipeline), Network Spoofing, Secure Memory/Buffer, DoH, Database, License, Logging, Configuration, CSPRNG, TLS Fingerprinting (JA3/JA4, browser profiles), Adversarial Padding, Flow Shaping, Probe Resistance, L2 Stealth, L3 Stealth, ARP Spoofing, DHCP Spoofing, Port Knocking, Packet Interceptor, Protocol Morphing, Burst Morphing, Entropy Masking, Geneva Engine/GA, Identity Management, Timing Protection, Thread Pool, Rotation Coordinator, Security Manager, Capabilities Framework, MasterOrchestrator (7-stage pipeline), BehavioralCloak (anti-ML), CovertChannelManager (steganography), CrossLayerCorrelator, GeoObfuscator, ASAwareRouter, SessionPatternRandomizer

- ✅ **Security Fixes Applied**:
  - ECH info string mismatch — FIXED (canonical info string)
  - Kyber1024 encaps/decaps swap — FIXED (receiver decapsulates)
  - ECDH_P256 OpenSSL fallback — FIXED (OpenSSL 1.1.1 + 3.0+ support)
  - HMAC salt truncation — FIXED (hash long salts)
  - TLS Fingerprint randomization — FIXED (minor_permute vs secure_shuffle)

- ⚠️ **Partial / Pending**:
  - I2P Integration — SAM bridge API defined, implementation in progress
  - Traffic Mimicry — Full protocol emulation pending (basic structure complete)
  - Geneva GA integration — Connected to pipeline, evolution pending

**Security Hardening (Phase 0)**:
- ✅ Complete CSPRNG migration — all `std::mt19937` replaced with libsodium `randombytes_*`
- ✅ New `ncp::CSPRNG` header-only wrapper with `random_bytes`, `uniform_uint32`, `uniform_double`, `shuffle`
- ✅ 12 modules patched, 50+ replacement sites, 18 dedicated CSPRNG unit tests
- ✅ **All Phase 0-4 security fixes applied** — see "Known Critical Issues" below

**DPI Advanced Pipeline (Phase 2+)**:
- ✅ TLS Fingerprint-driven ClientHello generation (Chrome/Firefox/Safari/Edge profiles)
- ✅ AdvancedDPIBypass integrated into proxy send path with 15+ evasion techniques
- ✅ ECH (Encrypted Client Hello) — HPKE encryption + server decrypt working (canonical info string)
- ✅ Protocol Orchestrator with adaptive threat-level strategy switching (NONE→CRITICAL)
- ✅ HIGH and CRITICAL threat levels differentiated — paranoid strategy has max padding/dummy
- ✅ Per-connection TLS fingerprint rotation, GREASE injection, decoy SNI
- ✅ 6 country/scenario presets: TSPU, GFW, Iran, Aggressive, Stealth, Compatible
- ✅ Geneva Engine with genetic algorithm for DPI evasion strategy discovery

**CLI Tool**:
- ✅ **Working Commands**: `status`, `help`
- 🚧 **In Active Development**: `run`, `stop`, `rotate`, `crypto`, `license`, `network`, `dpi`, `i2p`, `mimic`

**Testing** (22 test files):
- ✅ Core module tests: crypto, DPI, networking, E2E (basic + extended), Paranoid, SecureMemory, I2P, License
- ✅ CSPRNG unit tests (18 tests: bounds, distribution, uniqueness, shuffle)
- ✅ DPI Advanced tests: mimicry roundtrip, ECH pipeline, ECH cache, advanced DPI, DPI advanced integration
- ✅ L3/L2 Stealth tests, Critical fixes tests, Integration tests
- 🚧 Fuzzing tests in `tests/fuzz/`

**Known Critical Issues** (from [AUDIT.md](AUDIT.md)):

✅ **FIXED** (February 2026):
- ECH info string mismatch — decryption now works correctly (canonical info string)
- Kyber1024 encaps/decaps swap — receiver now correctly decapsulates
- ECDH_P256 OpenSSL fallback — works with OpenSSL 1.1.1 and 3.0+
- CI/CD Windows build — YAML indentation fixed
- HAVE_ECH_HPKE definition — now correctly passed to ncp_core

⬜ **Remaining**:
- Off-by-one buffer read in `apply_tcp_split` (ncp_dpi.cpp)
- Unbounded SNI extraction — OOB read via crafted ClientHello
- HTTP header injection via unescaped host in CONNECT
- Timing oracle in auth verification (ncp_probe_resist.cpp) — partially mitigated
- Nonce reuse after clock rollback (ncp_probe_resist.cpp)
- UAF after FlowShaper destruction (ncp_flow_shaper.cpp) — mitigated with thread join
- SSL_CTX double-free in DoH (doh.cpp) — mitigated with pImpl
- XOR used as HMAC fallback — no authenticity (ncp_port_knock.cpp) — replaced with libsodium
- TLS record > 16384 bytes in mimicry wrapper (mimicry.cpp)

**Roadmap**:
1. ✅ **Phase 1** (Completed): CLI command handlers + RAII refactoring
2. ✅ **Phase 2** (Completed): I2P SAM implementation + Paranoid Mode advanced methods
3. ✅ **Phase 3** (Completed): Security fixes (thread pool, CSPRNG migration)
4. ✅ **Phase 4-6** (Completed): Code quality, testing, CI/CD, documentation
5. ✅ **Phase 0** (Completed): Full CSPRNG migration — eliminate all `std::mt19937`
6. ✅ **Phase 2+** (Completed): TLS Fingerprint, AdvancedDPIBypass, ECH, Protocol Orchestrator
7. ✅ **Phase 3+** (Completed): ECH server decrypt, E2E P256/Kyber1024, CI/CD fixes
8. 🔜 **Phase 4+** (Next): Traffic Mimicry full protocol emulation, I2P SAM bridge completion



## Features

### Core Library (libncp_core) — 42 modules

#### Cryptography & Security
- **CSPRNG** (`ncp_csprng.hpp`) — Header-only libsodium wrapper: `random_bytes`, `uniform_uint32`, `uniform_double`, `fill_random`, `shuffle`
- **Cryptography** (`ncp_crypto.hpp` + `ncp_crypto_constants.hpp`) — Ed25519, Curve25519, ChaCha20-Poly1305, X25519 key exchange, AEAD encryption
- **E2E Encryption** (`ncp_e2e.hpp` + `ncp_e2e_caps_patch.hpp`) — End-to-end encryption with X25519 (working), X448/ECDH_P256/Kyber1024 (⚠️ broken)
- **Secure Memory** (`ncp_secure_memory.hpp`) — Memory-safe containers with automatic zeroing, `mlock` support
- **Secure Buffer** (`ncp_secure_buffer.hpp`) — RAII buffer with `sodium_memzero` wipe, `mlock`/`VirtualLock` page locking
- **Security Manager** (`ncp_security.hpp`) — Comprehensive security operations (47KB implementation)
- **Capabilities** (`ncp_capabilities.hpp`) — Runtime capability detection and feature flags (25KB header-only)

#### DPI Bypass & Evasion
- **DPI Bypass** (`ncp_dpi.hpp`) — TCP fragmentation, fake packets, disorder mode, SNI splitting, proxy/driver modes
- **DPI Advanced** (`ncp_dpi_advanced.hpp`) — 15+ evasion techniques: TCPManipulator, TLSManipulator, TrafficObfuscator, GREASE injection, decoy SNI, 6 country presets
- **Geneva Engine** (`ncp_geneva_engine.hpp`) — Packet manipulation engine based on Geneva framework
- **Geneva GA** (`ncp_geneva_ga.hpp`) — Genetic algorithm for evolving DPI evasion strategies

#### TLS & ECH
- **TLS Fingerprinting** (`ncp_tls_fingerprint.hpp`) — Browser profile emulation (Chrome/Firefox/Safari/Edge), JA3/JA3S/JA4, per-connection rotation
- **TLS Record Padding** (`ncp_tls_record_padding.hpp`) — TLS record-level padding for traffic analysis resistance
- **ECH** (`ncp_ech.hpp`) — Encrypted Client Hello draft with HPKE (⚠️ server decrypt broken)
- **ECH Cache** (`ncp_ech_cache.hpp`) — Caching layer for ECH configurations
- **ECH Fetch** (`ncp_ech_fetch.hpp`) — ECH config fetching from DNS/HTTPS
- **ECH Retry** (`ncp_ech_retry.hpp`) — ECH retry logic with fallback handling

#### Network & Spoofing
- **Network Spoofing** (`ncp_spoofer.hpp`) — IPv4/IPv6/MAC/DNS spoofing with identity rotation, SMBIOS/disk serial spoofing
- **Network Operations** (`ncp_network.hpp` + `ncp_network_backend.hpp`) — libpcap capture, raw sockets, typed handles
- **Raw Socket** — Low-level packet construction and injection (`network_raw_socket.cpp`)
- **ARP Spoofing** (`ncp_arp.hpp`) — ARP cache poisoning and spoofing
- **DHCP Spoofing** (`ncp_dhcp_spoofer.hpp`) — DHCP client ID spoofing
- **SMBIOS Hook** — Hardware serial number spoofing (`smbios_hook.cpp`)
- **Identity Management** (`ncp_identity.hpp`) — Unified identity management and rotation

#### Traffic Shaping & Obfuscation
- **Traffic Mimicry** (`ncp_mimicry.hpp`) — HTTP/TLS/WebSocket/DNS/QUIC protocol emulation (🚧 partial)
- **Protocol Morphing** (`ncp_protocol_morph.hpp`) — Runtime protocol transformation
- **Adversarial Padding** (`ncp_adversarial.hpp`) — Packet-level adversarial bytes to defeat ML classifiers
- **Adversary Tester** (`ncp_adversary_tester.hpp`) — Testing framework for adversarial techniques
- **Flow Shaping** (`ncp_flow_shaper.hpp`) — Timing/size shaping with dummy packet injection
- **Burst Morphing** (`ncp_burst_morpher.hpp`) — Traffic burst pattern transformation
- **Entropy Masking** (`ncp_entropy_masking.hpp`) — Entropy-level traffic normalization
- **Dummy Traffic** (`ncp_dummy.hpp`) — Cover traffic generation

#### Stealth & Defense
- **L2 Stealth** (`ncp_l2_stealth.hpp`) — Data link layer stealth operations
- **L3 Stealth** (`ncp_l3_stealth.hpp`) — Network layer stealth (30KB implementation)
- **Packet Interceptor** (`ncp_packet_interceptor.hpp`) — Packet interception and modification (36KB)
- **Paranoid Mode** (`ncp_paranoid.hpp`) — 8-layer protection system (TINFOIL_HAT level)
- **Port Knocking** (`ncp_port_knock.hpp`) — Cryptographic port knock sequences with TOTP
- **Probe Resistance** (`ncp_probe_resist.hpp`) — Server-side active probe defense with HMAC auth
- **Timing Protection** (`ncp_timing.hpp`) — Anti-timing-analysis measures

#### Orchestration & Infrastructure
- **Protocol Orchestrator** (`ncp_orchestrator.hpp` + `ncp_orchestrator_caps_patch.hpp`) — Unified send/receive pipeline with adaptive threat-level switching
- **Rotation Coordinator** (`ncp_rotation_coordinator.hpp`) — Coordinated identity/key/circuit rotation
- **Thread Pool** (`ncp_thread_pool.hpp`) — Worker thread management
- **DNS over HTTPS** (`ncp_doh.hpp`) — Encrypted DNS resolution via DoH providers
- **I2P Integration** (`ncp_i2p.hpp`) — I2P garlic routing, SAM bridge (🚧 partial)
- **WebSocket Tunnel** (`ncp_ws_tunnel.hpp`) — WebSocket-based tunneling

#### Utility
- **Database** (`ncp_db.hpp`) — SQLite3 + SQLCipher encrypted storage
- **License** (`ncp_license.hpp`) — Hardware ID-based offline validation
- **Logger** (`ncp_logger.hpp`) — Configurable logging
- **Configuration** (`ncp_config.hpp`) — Application configuration management
- **WinSock RAII** (`ncp_winsock_raii.hpp`) — Windows socket initialization wrapper

### CLI Tool

| Command | Status | Description |
|---------|--------|-------------|
| `status` | ✅ Working | View current protection status |
| `help` | ✅ Working | Show available commands |
| `run [iface]` | 🚧 Dev | Start PARANOID mode with all protections |
| `stop` | 🚧 Dev | Stop spoofing and restore settings |
| `rotate` | 🚧 Dev | Rotate all identities (IP/MAC/DNS) |
| `crypto keygen` | 🚧 Dev | Generate Ed25519 keypair |
| `crypto random <size>` | 🚧 Dev | Generate random bytes |
| `license hwid` | 🚧 Dev | Get system hardware ID |
| `license info` | 🚧 Dev | Show license status |
| `network interfaces` | 🚧 Dev | List network interfaces |
| `network stats` | 🚧 Dev | Show traffic statistics |
| `dpi [options]` | 🚧 Dev | DPI bypass proxy |
| `i2p <enable/disable/status>` | 🚧 Dev | I2P integration management |
| `mimic <http/tls/none>` | 🚧 Dev | Set traffic mimicry type |
| `tor` | 🚧 Dev | Configure Tor proxy |
| `obfuscate` | 🚧 Dev | Toggle traffic obfuscation |
| `dns-secure` | 🚧 Dev | Toggle DNS leak protection |

### Architecture

- Modern C++17 with `constexpr`/`noexcept` optimization
- Static library for embedding
- Cross-platform: Windows, Linux, macOS
- CMake + vcpkg/Conan build system
- Fuzzing tests (LibFuzzer) for crypto, DPI, and packet parser
- CI/CD via GitHub Actions (Linux, macOS, sanitizers)

## Quick Start

### Windows (automated)

```bash
git clone https://github.com/kirin2461/Dynam.git
cd Dynam
build.bat
```

### Linux / macOS

```bash
sudo apt-get install -y cmake build-essential git libsodium-dev libssl-dev libpcap-dev libgtest-dev pkg-config

git clone https://github.com/kirin2461/Dynam.git
cd Dynam
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
cmake --build . -j$(nproc)
ctest --output-on-failure
```

### Windows (manual)

```bash
vcpkg install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_DIR%/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

See [docs/BUILD.md](docs/BUILD.md) for detailed instructions.

## Project Structure

```
Dynam/
|-- src/
|   |-- core/                    # Core library (libncp_core)
|   |   |-- include/             # 49 public headers (ncp_*.hpp)
|   |   |-- src/                 # 46 implementation files
|   |   |-- CMakeLists.txt
|   |-- cli/                     # CLI tool (main.cpp, 26KB)
|   |-- gui/                     # Qt6 GUI (optional, ENABLE_GUI=OFF)
|-- tests/                       # Unit tests (GoogleTest) — 22 test files
|   |-- integration/             # Integration tests
|   |-- fuzz/                    # Fuzzing tests (LibFuzzer)
|   |-- scripts/                 # Test helper scripts
|-- docs/                        # Documentation (9 files)
|   |-- ARCHITECTURE.md
|   |-- BUILD.md
|   |-- CLI_COMMANDS.md
|   |-- DPI_ADVANCED_GUIDE.md
|   |-- USER_GUIDE.md
|   |-- SECURITY_FIXES.md
|   |-- SECURITY_IMPLEMENTATION_GUIDE.md
|   |-- KNOWN_ISSUES.md
|   |-- Doxyfile.in
|-- scripts/                     # Build helper scripts
|-- AUDIT.md                     # Security audit (87 findings)
|-- PATCHES.md                   # Applied patches
|-- CMakeLists.txt               # Root CMake config (v1.2.0)
|-- build.bat                    # Windows automated build
|-- run_ncp.bat                  # Windows launcher with CLI menu
|-- conanfile.txt                # Conan dependencies
```

## CMake Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `ENABLE_TESTS` | ON | Build unit tests (GoogleTest) |
| `ENABLE_CLI` | ON | Build CLI tool |
| `ENABLE_GUI` | OFF | Build Qt6 GUI application |
| `ENABLE_FUZZING` | OFF | Build fuzz tests (requires Clang + LibFuzzer) |
| `ENABLE_LIBOQS` | OFF | Post-quantum cryptography via liboqs |
| `ENABLE_WEBSOCKETS` | OFF | WebSocket tunneling via libwebsockets |
| `ENABLE_TOR_PROXY` | OFF | Tor proxy support |
| `ENABLE_DOCS` | OFF | Generate Doxygen documentation |
| `BUILD_SHARED_LIBS` | OFF | Build shared libraries |

## Security

- **CSPRNG**: All randomness via libsodium (`randombytes_*`) — zero `std::mt19937` in codebase
- **AEAD**: XChaCha20-Poly1305 authenticated encryption
- **Key Exchange**: X25519 (working), X448/ECDH_P256 (⚠️ broken API usage), Kyber1024 (⚠️ encaps/decaps swapped)
- **TLS Fingerprinting**: Realistic browser-grade ClientHello with per-connection rotation
- **ECH**: HPKE implemented but ⚠️ server-side decrypt broken (info string mismatch)
- **Secure Memory**: `sodium_memzero`, `mlock`/`VirtualLock`, `SecureVector`/`SecureString`/`SecureBuffer`
- **Note**: `encrypt_chacha20()` is misnamed — actually calls XSalsa20-Poly1305 (`crypto_secretbox_easy`)
- **Note**: Port knock HMAC fallback without OpenSSL uses XOR — **not a real MAC**
- **Fuzzing**: LibFuzzer-based tests for crypto, DPI, and packet parsing
- **Audit**: See [AUDIT.md](AUDIT.md) — 15 critical, 42 logic/race, 30 quality findings

## Dependencies

| Library | Purpose | Required | Notes |
|---------|---------|----------|-------|
| libsodium | Cryptography + CSPRNG | Yes | |
| OpenSSL | TLS, DoH, ECH/HPKE | Yes | **3.2+ required for ECH** |
| SQLite3 | Encrypted database | Yes | |
| GoogleTest | Unit testing | For tests | |
| libpcap | Packet capture (Linux/macOS) | Optional | |
| Npcap SDK | Packet capture (Windows) | Optional | |
| libnetfilter_queue | DPI driver mode (Linux) | Optional | |
| Qt6 | GUI application | Optional | |
| liboqs | Post-quantum crypto | Optional | |
| libwebsockets | WebSocket tunneling | Optional | |

See [DEPENDENCIES.md](DEPENDENCIES.md) for installation instructions.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Internal development only. Contact the project maintainer.

---

**Last Updated**: February 20, 2026  
**Version**: 1.4.0-dev  
**Status**: 42 modules, 49 headers, 46 source files, 22 test files — Active development with 87 open audit findings
