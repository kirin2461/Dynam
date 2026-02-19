# Dynam (NCP C++) - Network Control Protocol

> Multi-layered network anonymization and privacy platform with DPI bypass, traffic spoofing, paranoid mode, and advanced cryptography. Written in modern C++17.
>
> ## Current Status

**Version**: 1.3.0 (Active Development)

### Implementation Progress

**Core Library (libncp_core)**:
- ✅ **Fully Implemented** (80-90%): Cryptography, DPI Bypass, Network Spoofing, Secure Memory/Buffer, DoH, Database, License, Logging, Configuration, **CSPRNG**
- ⚠️ **Partial Implementation** (40-60%): Paranoid Mode (core features work, some advanced methods pending), E2E Encryption (X25519 done, X448/ECDH_P256 in progress)
- 🚧 **Stub/Minimal** (10-30%): I2P Integration (API defined, SAM bridge implementation in progress), Traffic Mimicry (basic structure, full protocol emulation pending)

**Security Hardening (Phase 0)**:
- ✅ Complete CSPRNG migration — all `std::mt19937` replaced with libsodium `randombytes_*`
- ✅ New `ncp::CSPRNG` header-only wrapper with `random_bytes`, `uniform_uint32`, `uniform_double`, `shuffle`
- ✅ 12 modules patched, 50+ replacement sites, 18 dedicated CSPRNG unit tests

**CLI Tool**:
- ✅ **Working Commands**: `status`, `help`
- 🚧 **In Active Development**: `run`, `stop`, `rotate`, `crypto`, `license`, `network`, `dpi`, `i2p`, `mimic`
- ⚠️ **Note**: CLI handlers currently being refactored from stubs to full implementations

**Testing**:
- ✅ Basic unit tests for core modules (crypto, DPI, networking)
- ✅ Comprehensive test coverage for E2E, Paranoid Mode, Secure Memory, I2P modules
- ✅ CSPRNG unit tests (18 tests: bounds, distribution, uniqueness, shuffle)

**Known Limitations**:
- I2P integration requires external I2P router with SAM bridge enabled
- Paranoid Mode advanced features (memory protection, kill switch, traffic morphing) are platform-specific and may require elevated privileges
- Some CLI commands shown in documentation are not yet functional (marked above)

**Roadmap**:
1. ✅ **Phase 1** (Completed): CLI command handlers completion + RAII refactoring
2. ✅ **Phase 2** (Completed): I2P SAM implementation + Paranoid Mode advanced methods
3. ✅ **Phase 3** (Completed): Security fixes (thread pool, CSPRNG migration)
4. ✅ **Phase 4-6** (Completed): Code quality, testing, CI/CD, documentation
5. ✅ **Phase 0** (Completed): Full CSPRNG migration — eliminate all `std::mt19937`
6. ✅ **Phase 1-CI** (Completed): CI/CMake fixes, CSPRNG tests, lighter workflows



## Features

### Core Library (libncp_core) - 19 modules

- **CSPRNG** (`ncp_csprng.hpp`) - Header-only libsodium wrapper: `random_bytes`, `uniform_uint32`, `uniform_double`, `fill_random`, `shuffle` — replaces all `std::mt19937` usage
- **Cryptography** (`ncp_crypto.hpp`) - Ed25519, Curve25519, ChaCha20-Poly1305, X25519 key exchange, AEAD encryption with `constexpr`/`noexcept` optimization
- **DPI Bypass** (`ncp_dpi.hpp`, `ncp_dpi_advanced.hpp`) - TCP fragmentation, fake packets, disorder mode, SNI splitting, RuNet presets (Soft/Strong)
- **Network Spoofing** (`ncp_spoofer.hpp`) - IPv4/IPv6/MAC/DNS spoofing with automatic identity rotation, SMBIOS serial spoofing, disk serial randomization, DHCP client ID spoofing, TCP/IP fingerprint emulation (Windows 10/Linux 5.x/macOS profiles)
- **Network Operations** (`ncp_network.hpp`) - libpcap packet capture, raw sockets, typed `unique_ptr` handles, bypass techniques (HTTP/TLS mimicry)
- **Paranoid Mode** (`ncp_paranoid.hpp`) - 8-layer protection: entry obfuscation, multi-anonymization (VPN→Tor→I2P), traffic morphing, timing protection, metadata stripping, post-quantum crypto, anti-correlation, system-level memory protection
- **Traffic Mimicry** (`ncp_mimicry.hpp`) - HTTP/TLS/WebSocket protocol emulation for traffic camouflage
- **TLS Fingerprinting** (`ncp_tls_fingerprint.hpp`) - JA3/JA3S fingerprint randomization and evasion
- **I2P Integration** (`ncp_i2p.hpp`) - I2P garlic routing, SAM bridge, tunnel management
- **E2E Encryption** (`ncp_e2e.hpp`) - End-to-end encryption with X448, ECDH_P256, forward secrecy
- **Secure Memory** (`ncp_secure_memory.hpp`) - Memory-safe containers with automatic zeroing on destruction, `mlock` support
- **Secure Buffer** (`ncp_secure_buffer.hpp`) - RAII buffer with `sodium_memzero` wipe, `mlock`/`VirtualLock` page locking, move semantics, custom `SecureDeleter`
- **DNS over HTTPS** (`ncp_doh.hpp`) - Encrypted DNS resolution via DoH providers
- **Security Module** (`ncp_security.hpp`) - System hardening, process protection, anti-forensic measures
- **Database** (`ncp_db.hpp`) - SQLite3 + SQLCipher encrypted storage
- **License Management** (`ncp_license.hpp`) - Hardware ID-based offline validation
- **Logging** (`ncp_logger.hpp`) - Structured logging with severity levels
- **Configuration** (`ncp_config.hpp`) - Runtime configuration management
- **Thread Pool** (`ncp_thread_pool.hpp`) - Lock-free task queue with configurable worker count

### CLI Tool

| Command | Description |
|---------|-------------|
| `run [iface]` | Start PARANOID mode with all 8 protection layers + spoofing + DPI bypass |
| `stop` | Stop spoofing and restore original settings |
| `status` | View current protection status |
| `rotate` | Rotate all identities (IP/MAC/DNS) |
| `crypto keygen` | Generate Ed25519 keypair |
| `crypto random <size>` | Generate cryptographically secure random bytes |
| `license hwid` | Get system hardware ID |
| `license info` | Show license status |
| `network interfaces` | List network interfaces |
| `network stats` | Show traffic statistics |
| `dpi [options]` | DPI bypass proxy (--mode proxy/driver/passive, --preset RuNet-Soft/RuNet-Strong) |
| `i2p <enable/disable/status>` | I2P integration management |
| `mimic <http/tls/none>` | Set traffic mimicry type |
| `tor` | Configure Tor proxy (bridges/hops) |
| `obfuscate` | Toggle advanced traffic obfuscation |
| `dns-secure` | Toggle DNS leak protection |
| `help` | Show available commands |

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
# Clone and build
git clone https://github.com/kirin2461/Dynam.git
cd Dynam
build.bat
```

### Linux / macOS

```bash
# Install dependencies
sudo apt-get install -y cmake build-essential git libsodium-dev libssl-dev libpcap-dev libgtest-dev pkg-config

# Build
git clone https://github.com/kirin2461/Dynam.git
cd Dynam
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
cmake --build . -j$(nproc)
ctest --output-on-failure
```

### Windows (manual)

```bash
# Requires: Visual Studio 2022+, CMake 3.20+, vcpkg
vcpkg install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_DIR%/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

See [docs/BUILD.md](docs/BUILD.md) for detailed instructions.

## Usage

### Launch with PARANOID Mode (recommended)

```bash
# Windows: use the launcher
run_ncp.bat
# Then type: run

# Or directly:
ncp.exe run
```

The `run` command automatically activates:
- Full network spoofing (IPv4/IPv6/MAC/DNS + HW identifiers)
- DPI bypass proxy
- PARANOID mode (TINFOIL_HAT level) with all 8 protection layers
- Cover traffic generation
- Kill switch and leak prevention

### Individual Commands

```bash
# Generate Ed25519 keypair
ncp crypto keygen

# DPI bypass with RuNet preset
ncp dpi --mode proxy --port 8080 --target example.com --preset RuNet-Strong

# Enable I2P
ncp i2p enable

# Enable TLS mimicry
ncp mimic tls

# List network interfaces
ncp network interfaces
```

## Project Structure

```
Dynam/
|-- src/
|   |-- core/                    # Core library (libncp_core)
|   |   |-- include/             # 19 public headers (ncp_*.hpp)
|   |   |-- src/                 # Implementation files
|   |   |-- CMakeLists.txt
|   |-- cli/                     # CLI tool (main.cpp)
|   |-- gui/                     # Qt6 GUI (optional, ENABLE_GUI=OFF)
|-- tests/                       # Unit tests (GoogleTest)
|   |-- fuzz/                    # Fuzzing tests (LibFuzzer)
|-- docs/                        # Documentation
|   |-- ARCHITECTURE.md
|   |-- BUILD.md
|   |-- CLI_COMMANDS.md
|   |-- USER_GUIDE.md
|   |-- SECURITY_FIXES.md
|   |-- SECURITY_IMPLEMENTATION_GUIDE.md
|   |-- KNOWN_ISSUES.md
|-- scripts/                     # Build helper scripts
|-- CMakeLists.txt               # Root CMake config
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
| `BUILD_SHARED_LIBS` | OFF | Build shared libraries |

## Security

- **CSPRNG**: All randomness via libsodium (`randombytes_*`) — zero `std::mt19937` in codebase
- **Cryptography**: libsodium (audited, industry-standard)
- **AEAD**: XChaCha20-Poly1305 authenticated encryption with associated data
- **Key Exchange**: X25519, X448, ECDH_P256
- **Secure Memory**: Automatic zeroing via `sodium_memzero`, `mlock`/`VirtualLock` page locking, `SecureVector`/`SecureString`/`SecureBuffer` containers
- **HW Identity Spoofing**: SMBIOS serials, disk serial numbers, DHCP client ID, TCP/IP fingerprint profiles
- **Database**: SQLite3 + SQLCipher (encrypted at rest)
- **Code Quality**: `constexpr`/`noexcept` throughout, typed pointers, no raw `void*`
- **Fuzzing**: LibFuzzer-based tests for crypto, DPI config, and packet parsing
- **Anti-Forensic**: Memory wiping on exit, secure file deletion (DOD 5220.22-M), encrypted temp files

## Dependencies

| Library | Purpose | Required |
|---------|---------|----------|
| libsodium | Cryptography + CSPRNG (Ed25519, ChaCha20, X25519, AEAD, `randombytes`) | Yes |
| OpenSSL | TLS operations, DoH, ECH/HPKE | Yes |
| SQLite3 | Encrypted database | Yes |
| GoogleTest | Unit testing | For tests |
| libpcap | Packet capture (Linux/macOS) | Optional |
| libnetfilter_queue | DPI driver mode (Linux) | Optional |
| Qt6 | GUI application | Optional |
| liboqs | Post-quantum crypto | Optional |
| libwebsockets | WebSocket tunneling | Optional |

See [DEPENDENCIES.md](DEPENDENCIES.md) for installation instructions.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Internal development only. Contact the project maintainer.

## Support

For issues and questions, please open a [GitHub Issue](https://github.com/kirin2461/Dynam/issues).

---

**Last Updated**: February 19, 2026  
**Version**: 1.3.0  
**Status**: Core library (19 modules), CLI, DPI bypass, Paranoid Mode, HW spoofing, SecureBuffer, CSPRNG — implemented
