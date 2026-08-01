# Dynam (NCP C++) - Network Control Protocol

> Multi-layered network anonymization and privacy platform with DPI bypass, traffic spoofing, paranoid mode, and advanced cryptography. Written in modern C++17.

## Current Status

**Version**: 1.5.0-dev (Active Development)
**CMake Version**: 1.5.0 (synced)

- ✅ **Build**: Linux (GCC 9+) and Windows (MSVC, WinDivert) via CMake + Ninja.
- ✅ **Tests**: 604 tests — 596 passed, 8 skipped (I2P integration tests require a live SAM bridge), 0 failed.
- ✅ **MASTER_ORCHESTRATOR 100% COMPLETE**: Full 7-stage pipeline with anti-ML, steganography, and behavioral cloaking implemented.
- ✅ **Web GUI**: Flask-based control panel in `web/` (license activation, module toggles, live logs, start/stop).

### Implementation Progress

**MasterOrchestrator — 100% Complete** (13 modules, ~3500 lines):
- ✅ **Phase 1: Core Integration** — MasterOrchestrator, 7-stage pipeline, send/receive API
- ✅ **Phase 2: Anti-ТСПУ ML** — BehavioralCloak, ProtocolRotationSchedule, SessionPatternRandomizer
- ✅ **Phase 3: Anti-СОРМ** — CovertChannelManager (4 channels), CrossLayerCorrelator, GeoObfuscator
- ✅ **Phase 4: Security** — PanicSequence (9 steps), Background Scheduler (8 tasks)

- ✅ **Fully Implemented & Tested**: Cryptography, DPI Bypass, DPI Advanced (multi-technique pipeline), Network Spoofing, Secure Memory/Buffer, DoH, Database, License, Logging, Configuration, CSPRNG, TLS Fingerprinting (JA3/JA4, browser profiles), Adversarial Padding, Flow Shaping, Probe Resistance, L2 Stealth, L3 Stealth, ARP Spoofing, DHCP Spoofing, Port Knocking, Packet Interceptor, Protocol Morphing, Burst Morphing, Entropy Masking, Geneva Engine/GA (crossover/mutation/selection, sync + background evolution), Identity Management, Timing Protection, Thread Pool, Rotation Coordinator, Security Manager, Capabilities Framework, I2P (SAM protocol client), Traffic Mimicry.

- ✅ **Security Fixes Applied**:
  - ECH info string mismatch — FIXED (canonical info string)
  - Kyber1024 encaps/decaps swap — FIXED (receiver decapsulates)
  - ECDH_P256 OpenSSL fallback — FIXED (OpenSSL 1.1.1 + 3.0+ support)
  - HMAC salt truncation — FIXED (hash long salts)
  - TLS Fingerprint randomization — FIXED (minor_permute vs secure_shuffle)
  - Timing oracle in auth verification — FIXED (constant-time memcmp)
  - XOR used as HMAC fallback — FIXED (libsodium crypto_auth)

- ⚠️ **Known Limitations**:
  - I2P — SAM client implemented and unit-tested; live integration tests need a running I2P router with SAM bridge (port 7656). Without it, I2P tests self-skip.
  - SQLite database encryption (`SQLITE_HAS_CODEC`) requires SQLCipher; stock SQLite builds run unencrypted and report it explicitly.

## Building

### Linux

```bash
sudo apt install build-essential cmake ninja-build libssl-dev libsodium-dev libsqlite3-dev
cmake -B build -G Ninja -DENABLE_TESTS=ON -DENABLE_CLI=ON -DENABLE_GUI=OFF
cmake --build build
```

Binaries: `build/bin/ncp` (CLI), `build/bin/ncp_tests` (test suite).

### Windows

Requirements: MSVC (Visual Studio 2019+), CMake, [WinDivert](https://reqrypt.org/windivert.html) 2.x (`WinDivert.dll` next to `ncp.exe` for DPI bypass / packet interception), vcpkg or manual installs of OpenSSL and libsodium.

```powershell
cmake -B build -DENABLE_TESTS=ON -DENABLE_CLI=ON
cmake --build build --config Release
```

## Testing

```bash
cd build
./bin/ncp_tests            # full suite: 604 tests
```

The suite is host-safe: paranoid-mode tests never touch the firewall, and no test requires root network changes. I2P tests skip automatically when no SAM bridge is reachable.

## CLI Tool

```bash
ncp run [--interface <if>] [--preset <name>] [--kill-switch]
ncp status | stop | rotate | help
ncp crypto <action> [args]
ncp network <action>
ncp license <action>
ncp dpi / i2p / mimic ...
```

> **⚠️ Kill switch is opt-in.** Paranoid mode can install a firewall rule dropping **all** non-loopback traffic (`iptables -A OUTPUT ! -o lo -j DROP` / Windows equivalent). If the process dies unexpectedly, the rule can persist and lock the machine off the network entirely — including SSH. `ncp run` arms it **only** when `--kill-switch` is passed explicitly.

### DPI presets

`--preset` selects a provider profile (e.g. `tspu`, `beeline`, ...). See `ncp dpi` output for the full list.

## Web GUI

```bash
cd web
pip install -r requirements.txt
python3 server.py    # http://127.0.0.1:8085
```

Features: license activation (Ed25519-signed keys, `NCP-XXXXX` format), DPI preset selection, per-module toggles, live log stream over WebSocket, start/stop of the `ncp` core. GUI-launched instances always run with `--no-kill-switch`.

License keys are issued with `web/ncp_keygen.py` (Ed25519):

```bash
python3 web/ncp_keygen.py generate-keypair --out private_key.b64
python3 web/ncp_keygen.py issue --key private_key.b64 --plan ultimate --days 0 --modules all
```

## Architecture
- Modern C++17 with `constexpr`/`noexcept` optimization.
- Three-layer architecture: Core Library, CLI, Web GUI.
- 7-stage Protocol Orchestrator pipeline.

## License
Licensed under the GNU Affero General Public License v3.0 (AGPLv3). See [LICENSE](LICENSE) for details.

---
**Last Updated**: August 1, 2026
**Version**: 1.5.0-dev
