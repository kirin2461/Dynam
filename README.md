# Dynam (NCP C++) - Network Control Protocol

> Multi-layered network anonymization and privacy platform with DPI bypass, traffic spoofing, paranoid mode, and advanced cryptography. Written in modern C++17.

## Current Status

**Version**: 1.5.0-dev (Active Development)
**CMake Version**: 1.5.0 (synced)

- ✅ **Build**: Linux (GCC 9+) and Windows (mingw-w64 cross-build verified — statically linked `ncp.exe`; MSVC also supported) via CMake + Ninja.
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
sudo apt install build-essential cmake ninja-build \
    libssl-dev libsodium-dev libsqlite3-dev libwebsockets-dev \
    libpcap-dev libnetfilter-queue-dev
cmake -B build -G Ninja -DENABLE_TESTS=ON -DENABLE_CLI=ON -DENABLE_GUI=OFF
cmake --build build
```

> `libwebsockets-dev` is **required** (secure tunneling). `libpcap-dev` and
> `libnetfilter-queue-dev` are optional but enable L2 features and the NFQUEUE
> DPI-bypass backend respectively.

Binaries: `build/bin/ncp` (CLI), `build/bin/ncp_tests` (test suite).

### Windows

#### Option A — cross-compile from Linux (verified)

Tested on Ubuntu 20.04 with mingw-w64 (produces a statically linked `ncp.exe`
with ECH/HPKE support):

```bash
sudo apt install mingw-w64
# Use the POSIX-threaded variant (std::thread/std::mutex support):
sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
```

Build the dependencies for mingw (versions verified to work):

- **libsodium 1.0.20** — `./configure --host=x86_64-w64-mingw32 --prefix=/opt/win-deps`
- **OpenSSL 3.5.1** — `./Configure mingw64 --prefix=/opt/win-deps --cross-compile-prefix=x86_64-w64-mingw32- no-shared no-tests no-apps`
- **libwebsockets 4.3.3** — CMake with the toolchain file below, `-DLWS_WITH_SHARED=OFF -DLWS_WITH_ZLIB=OFF`

Then configure and build:

```bash
cmake -B build-win -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
    -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=OFF -DENABLE_CLI=ON
cmake --build build-win     # -> build-win/bin/ncp.exe
```

#### Option B — MSVC (native)

Requirements: Visual Studio 2019+, CMake, and vcpkg:

```powershell
vcpkg install libsodium:x64-windows openssl:x64-windows libwebsockets:x64-windows
cmake -B build -DENABLE_CLI=ON -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

#### Runtime requirement (both options)

Packet interception on Windows uses **WinDivert**: download
[WinDivert 2.x](https://reqrypt.org/windivert.html) and place `WinDivert.dll`
and `WinDivert64.sys` next to `ncp.exe`, then run as Administrator:

```powershell
ncp.exe run --preset tspu
```

> The legacy WFP (Windows Filtering Platform) backend is compiled only when a
> full WFP SDK is available (`HAVE_WFP_SDK` CMake check). mingw-w64 < v10 ships
> an incomplete `fwpmu.h`, so WFP code is disabled there automatically
> (`NCP_NO_WFP`) — WinDivert is the real interception backend regardless.

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

Features: license activation (Ed25519-signed keys, `NCP-XXXXX` format), DPI preset selection, per-module toggles, live log stream over WebSocket, start/stop of the `ncp` core. The **Bypass** section adds: one-click desync proxy start/stop, automatic strategy selection (blockcheck) with per-strategy apply, availability checker for popular sites, auto-hostlist management, zapret strategy import with preview, DPI detector event feed, signed auto-update and autostart toggle. GUI-launched instances always run with `--no-kill-switch`.

License keys are issued with `web/ncp_keygen.py` (Ed25519):

```bash
python3 web/ncp_keygen.py generate-keypair --out private_key.b64
python3 web/ncp_keygen.py issue --key private_key.b64 --plan ultimate --days 0 --modules all
```

## Bypass Features (no admin required)

### Local desync proxy — `ncp proxy`

SOCKS5/HTTP proxy on localhost that applies DPI-desync (TCP split at
byte/SNI/midSLD positions, zapret chains, fake QUIC, DoH resolution) to
relay traffic. Works without root/admin rights — point your browser or app
at `127.0.0.1:1080` (SOCKS5 with UDP ASSOCIATE, or HTTP CONNECT).

```bash
ncp proxy --port 1080 --doh                      # default: split-2 + split-at-SNI
ncp proxy --split-pos 5                          # split ClientHello at byte 5
ncp proxy --multisplit 1,2,5 --split-sni         # multi-layer split
ncp proxy --chain "--dpi-desync=fake,multisplit --dpi-desync-split-pos=midsld"
ncp proxy --block-quic                           # drop UDP/443 (force TCP fallback)
ncp proxy --fake-quic 3                          # 3 fake QUIC Initials per target
ncp proxy --autohostlist /etc/ncp/autohostlist.txt --detector-log /etc/ncp/detector_events.jsonl
```

### Automatic strategy selection — `ncp blockcheck`

zapret `blockcheck` equivalent: probes a set of domains through every
built-in strategy (split-1/2/3/5, split-SNI, multisplit variants, midSLD /
SNI-extension / end-SLD chain splits), scores them, and reports the winner:

```bash
ncp blockcheck                                   # built-in domain list
ncp blockcheck --domains example.com,foo.org --json --out report.json
ncp blockcheck --apply                           # best strategy as profile JSON
```

### AutoPilot — adaptive self-learning engine (`ncp autopilot`)

AutoPilot turns one-shot blockcheck into a continuous, per-host learning loop:

- **Learns** the best desync strategy for each host by live probing (TLS
  ClientHello over TCP/443 through a temporary local proxy — no admin, no
  firewall changes) and persists it to `~/.ncp/autopilot.json`
  (`%APPDATA%\ncp\autopilot.json` on Windows).
- **Applies** learned strategies inside `ncp proxy --autopilot` (or whenever
  the DB is enabled): a learned record takes precedence over chains and the
  base strategy; longest-suffix matching covers subdomains automatically.
- **Watches** live traffic: RST-after-ClientHello and server-hello timeouts
  are reported back per host. Three consecutive failures mark the record
  *degraded* — connections instantly fall back to chains/base while a
  background janitor re-learns the host (rate-limited, exponential backoff).
- **Self-extends**: repeated failures on an unknown host create a placeholder
  that the janitor learns automatically.

```bash
ncp autopilot learn www.youtube.com --doh   # probe & store best strategy
ncp autopilot status                        # human-readable DB view
ncp autopilot status --json                 # machine-readable (GUI-ready)
ncp autopilot enable                        # proxy picks it up automatically
ncp proxy --doh --autopilot                 # learned strategies + live feedback
ncp autopilot reset [domain]                # drop one record / all
```

Probing is plain TCP/443 only — no TUN, no VPN, no packet injection. Use
`--doh` (both in `learn` and `proxy`) on networks with poisoned DNS so that
learning happens in the same DNS reality the proxy runs in.

### zapret strategy import — `ncp import-zapret`

Parses zapret CLI flags (`--dpi-desync`, `--dpi-desync-split-pos`,
`--dpi-desync-fooling`, `--dpi-desync-ttl/-autottl`, `--dpi-desync-fake-*`,
`--hostlist*`, `--new`, `--filter-tcp/udp/l3/l7`, ...) into an NCP
`ZapretChain` profile and prints it as JSON:

```bash
ncp import-zapret --args "--filter-tcp=443 --dpi-desync=split2 --dpi-desync-split-pos=midsld"
ncp import-zapret --file strategies.txt
```

### Hostlists

Exact + suffix domain matching (`*.example.com`, bare `example.com`,
two-level TLD aware). Auto-hostlist records hosts where DPI blocking was
detected (timeout / RST injection) and feeds them back into chain
selection (`--hostlist` rules).

### Passive DPI detector

Counts RST injections, post-ClientHello resets and connect timeouts per
host; emits JSONL events (`rst_injection`, `timeout_block`,
`tcp_reset_pre`, `block_cleared`) consumable by the GUI.

### QUIC / HTTP3 handling

* fake QUIC Initial packets (WinDivert path and proxy UDP ASSOCIATE),
* force-TCP: `--quic-block` / proxy `--block-quic` drops UDP/443,
* IP-level fragmentation of QUIC Initials: `--quic-frag <offset>`
  (IPv4, 8-byte aligned, checksums recomputed).

### Auto-update

Signed releases: the GUI checks GitHub Releases for a `manifest.json`
asset, verifies SHA-256 and an **Ed25519 signature** (same key pair as
license issuance) before installing. Compromised or tampered binaries are
rejected.

### Windows tray & autostart

Frozen GUI build (`ncp-gui.exe`) shows a system-tray icon (open panel /
quit) and can register itself in autostart (HKCU `Run` on Windows,
`~/.config/autostart/ncp.desktop` on Linux) — toggled from the GUI.

## Architecture
- Modern C++17 with `constexpr`/`noexcept` optimization.
- Three-layer architecture: Core Library, CLI, Web GUI.
- 7-stage Protocol Orchestrator pipeline.

## License
Licensed under the GNU Affero General Public License v3.0 (AGPLv3). See [LICENSE](LICENSE) for details.

---
**Last Updated**: August 11, 2026
**Version**: 1.5.0-dev
