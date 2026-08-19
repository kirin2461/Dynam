# Dynam (NCP C++) - Network Control Protocol

> Multi-layered network anonymization and privacy platform with DPI bypass, traffic spoofing, paranoid mode, and advanced cryptography. Written in modern C++17.

## Current Status

**Version**: 1.5.0-dev (Active Development)
**CMake Version**: 1.5.0 (synced)

- ✅ **Build**: Linux (GCC 9+) and Windows (mingw-w64 cross-build verified — statically linked `ncp.exe`; MSVC also supported) via CMake + Ninja.
- ✅ **Tests**: 604 tests — 596 passed, 8 skipped (I2P integration tests require a live SAM bridge), 0 failed.
- ✅ **MASTER_ORCHESTRATOR 100% COMPLETE**: Full 7-stage pipeline with anti-ML, steganography, and behavioral cloaking implemented.
- ✅ **Web GUI**: Flask-based control panel in `web/` (license activation, module toggles, live logs, start/stop, live per-module engine stats).
- ✅ **Licensing**: automatic 7-day trial on first launch (all 19 modules), Ed25519-signed keys issued by the standalone `ncp-keygen` tool.
- ✅ **Desktop GUI**: Qt6 app (`ncp-qt.exe`) with charts, license panel and tray integration.
- ✅ **Docker testbeds**: three isolated topologies (3-node midbox, 2-node combined Server/DPI, DPI Lab) — the full combat matrix runs without touching the host network.
- ✅ **DPI Lab**: userspace NFQUEUE DPI emulator with TCP reassembly (buffer-limit + strict/permissive OOO policies), 4 automated suites (desync formation / DPI-model bypass matrix / endpoint compatibility / performance), tc-netem impairment profiles, IPv6 smoke tests.

### Implementation Progress

**MasterOrchestrator — 100% Complete** (13 modules, ~3500 lines):
- ✅ **Phase 1: Core Integration** — MasterOrchestrator, 7-stage pipeline, send/receive API
- ✅ **Phase 2: Anti-ТСПУ ML** — BehavioralCloak, ProtocolRotationSchedule, SessionPatternRandomizer
- ✅ **Phase 3: Anti-СОРМ** — CovertChannelManager (4 channels), CrossLayerCorrelator, GeoObfuscator
- ✅ **Phase 4: Security** — PanicSequence (9 steps), Background Scheduler (8 tasks)

- ✅ **Fully Implemented & Tested**: Cryptography, DPI Bypass (incl. midSLD splits, zapret chains, fake/fooling), DPI Advanced (multi-technique pipeline), Network Spoofing, Secure Memory/Buffer, DoH, Database, License, Logging, Configuration, CSPRNG, TLS Fingerprinting (JA3/JA4, browser profiles), Adversarial Padding, Flow Shaping, Probe Resistance, L2 Stealth, L3 Stealth, ARP Spoofing, DHCP Spoofing, Port Knocking, SPA (Ed25519 Single Packet Authorization + ipset gate control), XTLS-Reality Fallback, Stego-DNS Discovery, UDP Port-Hopping, Statistical Traffic Mimicry Profiles, TCP State Confusion (desync), AEMM Reed-Solomon Erasure Coding, Fog Mesh Relay, Semantic Fluid Transport, eBPF/XDP Kernel Filtering, Packet Interceptor, Protocol Morphing, Burst Morphing, Entropy Masking, Geneva Engine/GA (crossover/mutation/selection, sync + background evolution), Identity Management, Timing Protection, Thread Pool, Rotation Coordinator, Security Manager, Capabilities Framework, I2P (SAM protocol client), Traffic Mimicry.

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

## Install via npm

Prebuilt `ncp` binaries from [GitHub Releases](https://github.com/kirin2461/Dynam/releases)
are distributed as the npm package [`dynam-ncp`](https://www.npmjs.com/package/dynam-ncp):

[![npm version](https://img.shields.io/npm/v/dynam-ncp)](https://www.npmjs.com/package/dynam-ncp)

```bash
npm install -g dynam-ncp

dynam-ncp --help             # or just `ncp`
sudo dynam-ncp run           # PARANOID mode (all protection layers)
dynam-ncp proxy --port 1080  # local SOCKS5/HTTP desync proxy (no admin needed)
dynam-ncp spa keygen --out my_spa
```

Supported platforms: `linux-x64`, `darwin-x64`, `darwin-arm64` (via Rosetta 2),
`win32-x64`. The postinstall script downloads and verifies the matching release
asset; on unsupported platforms the install succeeds with a warning so you can
build from source instead. Details and environment variables: [`npm/README.md`](npm/README.md).

## Testing

```bash
cd build
./bin/ncp_tests            # full suite: 604 tests
```

The suite is host-safe: paranoid-mode tests never touch the firewall, and no test requires root network changes. I2P tests skip automatically when no SAM bridge is reachable. The DPI Lab adds 22 reassembler unit tests (`scripts/lab/test_reassembler.py`).

## Docker Testbeds & DPI Lab

L2/L3 spoofing, traffic interception and desync testing run in isolated containers — the host network is never affected.

### Topologies

| Compose file | Topology | Use |
|---|---|---|
| `docker-compose.yml` | client → dpi-router → target (3-node midbox) | full integration matrix |
| `docker-compose.2node.yml` | client ↔ combined Server/DPI (one bridge) | quick combat runs |
| `docker-compose.lab.yml` (+ `docker-compose.lab-v6.yml`) | client ↔ dpi-emu (userspace DPI) | DPI Lab suites 1–4, dual-stack IPv6 |

```bash
docker compose -f docker-compose.lab.yml up -d --build      # IPv4 lab
docker compose -f docker-compose.lab.yml -f docker-compose.lab-v6.yml up -d   # dual-stack
```

### DPI emulator models (`docker/dpi-emu.py`)

| Model | Behavior |
|---|---|
| `string` | legacy per-packet `iptables -m string` match + `tcp-reset` (baseline DPI) |
| `reassemble` | NFQUEUE userspace **TCP reassembly** up to `BUFFER_LIMIT` (give-up→allow), out-of-order/overlap policies `strict` / `permissive-first` / `permissive-last`, TLS SNI + HTTP Host stream parser, forged RST via raw socket, JSONL verdict log |
| `off` | allow-all (desync formation testing) |

GRO/TSO/GSO are disabled on the veth pairs — otherwise the kernel reassembles
split segments before netfilter and the DPI never sees the desync as crafted.

### Lab suites (`scripts/lab/`)

| Suite | Goal | Checks |
|---|---|---|
| `suite1_correctness.sh` | desync packet **formation** (DPI off) | split positions vs TLS record/SNI, seq/ack continuity, zero retransmits (`pcap_assert.py`) |
| `suite2_dpi_models.sh` | **bypass matrix**: ncp modes × DPI models × impairment | N runs/cell, success rate, median/p95 handshake & TTFB (`metrics.py`) |
| `suite3_compat.sh` | **endpoint compatibility** | TLS 1.2-only / TLS 1.3 / HTTP/1.1 / HTTP/2 (nghttpd + SSLKEYLOGFILE-decrypted pcap) / QUIC smoke |
| `suite4_perf.sh` | **performance & resilience** | N=20 downloads of 5/50 MB, per-core CPU, retransmits, speed |
| `impairment.sh` | network impairment | tc-netem profiles: `clean`, `delay50`, `wan` (100 ms ± 20 + 1% loss), `loss5`, `reorder` (25%), `mtu1400`, `mtu576` (MSS clamp) |

`pcap_assert.py` automates packet-level assertions: split positions relative
to the TLS record and SNI, TCP seq/ack validation, retransmit detection,
TLS 1.2/1.3 negotiation, ALPN, HTTP/2 frames (via `--keylog`
SSLKEYLOGFILE decryption), QUIC datagrams, RST injection, and skips
HelloRetryRequest ServerHellos when reading negotiation results.

### Latest combat results (2026-08-17, full matrix run)

- `tspu` / `chain` bypass the string-match DPI at **100 %** under clean,
  delay50, loss5 and reorder profiles; `direct` is always blocked (control ✓).
- Positional splits score **0 % against the reassembly model** in clean
  conditions — overlap / bad-checksum / multidisorder strategies are the
  answer (reorder-profile leaks of 10–30 % show the reassembler degrading).
- `auto` preset: **0 % bypass in every cell** despite correct packet
  formation (suite1 PASS) — under investigation.
- TLS 1.3 **HelloRetryRequest**: the post-HRR second ClientHello is sent
  without desync → DPI RST. Servers requesting a different key-share group
  break the bypass until this is covered.
- **HTTP/2 over desync verified** (ALPN h2, TLS 1.3, HTTP 200 against
  nghttpd); **IPv6 is an open bypass path** — the DPI logic is IPv4-only.
- Performance: ~103 MB/s on 50 MB downloads through the desync proxy,
  handshake overhead +2–8 ms vs direct, success rate 1.0 on the `wan`
  profile, single-digit retransmits per 20 runs.

## CLI Tool

```bash
ncp run [--interface <if>] [--preset <name>] [--kill-switch]
ncp status | stop | rotate | help
ncp crypto <action> [args]
ncp network <action>
ncp license <action>
ncp dpi / i2p / mimic ...
ncp spa <keygen|serve|knock>
ncp reality serve [--dry-run]
ncp stegodns <encode|decode>
ncp porthop <serve|client>
ncp fog node
ncp xdp <compile|attach|detach|stats|drop|probe>
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

Features: license activation (Ed25519-signed keys, `NCP-XXXXX` format), DPI preset selection, per-module toggles, live log stream over WebSocket, start/stop of the `ncp` core, **live per-module engine statistics** (the engine exports real counters via `ncp run --stats-file` every 2 s — DPI pipeline, Geneva GA, WF Defense, Volume Normalizer, Behavioral Cloak, Time Breaker, RTT Equalizer, Session Fragmenter, Cross-Layer, Covert Channel, Protocol Rotation, AS Router). The **Bypass** section adds: one-click desync proxy start/stop, automatic strategy selection (blockcheck) with per-strategy apply, availability checker for popular sites, auto-hostlist management, zapret strategy import with preview, DPI detector event feed, signed auto-update and autostart toggle. GUI-launched instances always run with `--no-kill-switch`.

## Licensing (trial + keys)

**7-day trial, zero setup.** On first launch, both the CLI (`ncp run`) and the
web GUI automatically issue a trial license covering **all 19 modules**
(including the full Geneva engine). The trial file lives at
`%APPDATA%\ncp\trial.json` (Windows) / `~/ncp/trial.json` (Linux), is bound
to the machine hostname and integrity-protected with a keyed SHA-256 MAC.
After 7 days the protection modules stop until a key is entered. The Qt GUI
never hard-blocks: its license panel is informational.

**Issuing keys (owner-only).** Keys are Ed25519-signed (`NCP-XXXXX-...`
format) and are minted by the key generator — `web/ncp_keygen.py` or the
frozen `ncp-keygen.exe`:

```bash
# one-time: generate a key pair (prints the public key to embed in builds)
ncp-keygen.exe generate-keypair --out ncp_private_key.b64

# issue a key valid for N days (0 = lifetime)
ncp-keygen.exe issue --plan ultimate --modules all --days 365
ncp-keygen.exe issue --plan pro --modules dpi_bypass,pipeline --days 30
```

The generator reads the Ed25519 **private key from `ncp_private_key.b64`
placed next to the executable** (or `--key <path>`) — it is never embedded in
the binary. **Never distribute `ncp-keygen.exe` or `ncp_private_key.b64` to
end users**; send customers only the key text. Users activate it in the web
GUI (License section); the key is stored in `%APPDATA%\ncp\license.json`
and is honored by all three apps (CLI, web GUI, Qt GUI).

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

### Single Packet Authorization — `ncp spa`

Enterprise-grade SPA (upgrade over classic port knocking, which is vulnerable
to replay and timing analysis): the protected service port stays a black hole
for scanners until the client sends a **single Ed25519-signed UDP packet**
(256 bytes: key-id, timestamp, nonce, requested proto/port/TTL + 64-byte
signature + CSPRNG padding). The server verifies the signature against an
authorized-keys file, rejects replays (per-key nonce cache + ±60 s timestamp
window), and only then dynamically opens access — for that source IP only —
via **ipset** with automatic TTL expiry:

```bash
ncp spa keygen --out client                        # Ed25519 keypair + authorized_keys line
ncp spa serve --authorized-keys keys.txt \
    --port 54117 --set-name ncp_spa_allow \
    --default-ttl 300 --max-ttl 86400              # [--dry-run] to log without applying
ncp spa knock <server-ip> --key client.key \
    --allow-port 443 --ttl 300                     # open tcp/443 for this IP only
```

Server-side gate rule (printed by `serve` at startup):

```bash
iptables -A INPUT -p tcp --dport 443 -m set ! --match-set ncp_spa_allow src -j DROP
```

Verified in the Docker DPI Lab: pre-knock connections time out (DROP), a valid
knock returns HTTP 200 through the gate, replayed packets are rejected
(REPLAY), unknown keys are rejected (UNKNOWN_KEY), and access closes
automatically on TTL expiry. Asymmetric design: the server stores only public
keys, so a server compromise does not leak client signing capability.

### Enterprise anti-censorship modules

Nine complementary modules implementing the enterprise feature set. All are
covered by unit tests (70+ cases) and verified in the Docker DPI Lab.

#### XTLS-Reality-style fallback — `ncp reality serve`

Dest-mapping front server: the first bytes of every connection must be a TLS
ClientHello. Authorized clients embed an Ed25519 token in the left-most SNI
label (`<token26>.gw.<domain>`, token = first 26 base32 chars of the
signature over `"ncp-reality" || domain || 60-second time window`) and are
forwarded to the internal service; everyone else — scanners, active probers,
censors — is transparently spliced to a real fallback site, so the server
presents a genuine TLS session with a real, whitelisted domain:

```bash
ncp reality serve --listen 8443 --fallback www.microsoft.com:443 \
    --internal 127.0.0.1:8080 --key-file clients.txt [--dry-run]
# key file: '<key_id> <base64-ed25519-secret-64B>' per line
```

Note: a 26-char base32 token carries only ~130 bits of the 512-bit signature,
so verification re-computes the deterministic Ed25519 signature server-side
and compares in constant time — the server must hold the client secret keys
(`provision_secret()`); pubkey-only entries are accepted but skipped.
Lab-verified: an authorized ClientHello reaches the internal service,
unknown/bare SNI is spliced to the fallback bytes, non-TLS garbage is dropped.

#### Steganographic DNS discovery — `ncp stegodns`

Publishes bootstrap node parameters (IPv4, port, SPA public key, expiry —
43 bytes) inside an innocent-looking SPF TXT record. The payload is
XChaCha20-Poly1305-sealed (key = BLAKE2b(passphrase)) and Ed25519-signed,
then base32-encoded into
`v=spf1 ip4:<blob> include:<blob>._ncp.<domain> ~all`:

```bash
ncp stegodns encode --ip 203.0.113.7 --port 4433 --spa-pubkey <b64> \
    --passphrase <s> --signing-key spa.key --domain example.com
ncp stegodns decode --txt '<record>' --passphrase <s> --verify-pubkey <b64>
```

To a censor the record is indistinguishable from an ordinary SPF policy.
`expires = 0` means "never". Lab-verified cross-container roundtrip.

#### UDP Port-Hopping transport — `ncp porthop`

QUIC-style port hopping for UDP: both sides derive the current port
deterministically — `port(epoch) = base + HMAC-SHA256(secret, epoch)[0..2] % range`.
Frames carry `PH | ver | session_id(8) | epoch(4) | seq(4) | flags | payload`;
the client hops when >3 segments are unacknowledged or the hop interval
expires; the server binds the whole port range (SO_REUSEPORT, up to 64
ports) and demultiplexes by session id, dropping unknown sessions:

```bash
ncp porthop serve --base-port 40000 --range 16 --secret <s> [--hop-interval 60]
ncp porthop client --host <ip> --base-port 40000 --range 16 --secret <s> \
    --message "hello" [--session-id 0x1122334455667788]
```

Lab-verified: cross-container echo with ACKs; when the current port is
firewalled mid-session the client hops to the next scheduled port
(40015 → 40006) and the session continues.

#### Statistical traffic mimicry (`ncp_mimicry_stats`)

Traffic shaping from measurable statistical profiles: packet-size
distributions (normal / lognormal / discrete mixtures with clamping) and
inter-arrival models (exponential / normal / fixed). Built-in profiles:
`webrtc_video` (90 % N(1200,180) + 8 % N(400,80) + 2 % N(8000,1500),
Exp(33 ms)), `zoom_call`, `youtube_stream`, `voip_opus`.
`MimicryShaper::plan(len)` splits an outgoing buffer into timed chunks that
statistically match the chosen cover protocol (seeded `mt19937_64`).

#### TCP State Confusion (`ncp::desync`)

Wire-level desynchronization segment builders (zapret techniques, as a
reusable library): **overlap** (same-seq decoy + real pair), **TTL-limited
fake** (ttl 1..3 — crosses on-path DPI, dies before the server),
**out-of-window fake** (seq + 16 MiB), **badseq fake** (seq − 1, zapret
badseq analogue) and optional poisoned TCP checksum 0xDEAD (badsum).
`serialize_segment()` produces full IPv4+TCP packets for the raw-socket
sender. Lab-verified on the wire: all five injections captured with the
expected seq/ttl/checksum fields.

#### AEMM Reed-Solomon erasure core (`ncp_aemm`)

Adaptive Forward Error Correction for lossy paths: GF(2^8) (poly 0x11D),
Cauchy generator matrix, encodes K data shards into N, recovers the block
from any K shards via GF submatrix inversion. AVX2 4-bit-nibble path
(`vpshufb`) where available; measured 57 MB/s scalar, 69 MB/s AVX2. Shard
header: `RS | k | n | idx | block_id | orig_len | blake2b-8`.

#### Cooperative Fog Mesh — `ncp fog node`

Multi-hop volunteer relay overlay: framed as
`FOG | ver | ttl | type | target(16) | origin(16) | seq(8) | payload`,
with TTL decrement, loop-guard (10k-entry origin/seq FIFO), PING/PONG
liveness and ROUTE_AD table gossip. Peer table holds up to 256 entries with
trust decay (×0.99/min), lowest-trust eviction and best-relay selection:

```bash
ncp fog node --id <32-hex> --port 5000 --peer <ip:port> [--peer ...]
```

Lab-verified: cross-container PING→PONG liveness and DATA delivery;
multi-hop relay covered by loopback unit tests.

#### Semantic Fluid Transport (`ncp_semfluid`)

Payload embedding into high-entropy fields of routine HTTP requests —
Windows telemetry POST, Chrome component update GET, CDN image GET, OAuth
token POST, video manifest GET. Payload chunks (43 bytes + BLAKE2b-4
checksum) are base62-encoded into fixed-width 64-char cookie values
(`MSFPC`, `_uetsid`) that are statistically indistinguishable from real
browser cookies; `wrap()/unwrap()/parse_request()` round-trip the stream.

#### eBPF/XDP kernel packet filtering — `ncp xdp`

Kernel-level UDP statistics and selective dropping at the earliest possible
point in the network stack. Ships a libbpf-free legacy eBPF program
(`bpf/xdp_udpmon_kern.c`, iproute2-loadable) with a per-port HASH statistics
map and an ARRAY config map (drop port), plus a `XdpManager` that compiles
(clang), attaches/detaches (`xdpgeneric`), finds pinned maps by structural
match and reads counters via raw `bpf(2)` syscalls:

```bash
ncp xdp compile --out /tmp/xdp_udpmon.o      # clang -target bpf
ncp xdp attach --iface eth0 --obj /tmp/xdp_udpmon.o
ncp xdp stats [--pin /sys/fs/bpf/...]        # per-port packets/bytes
ncp xdp drop --port 4433 [--clear]           # selective drop switch
ncp xdp detach --iface eth0 ; ncp xdp probe  # kernel capability check
```

Verified in a disposable host network namespace: exact packet/byte counters,
selective drop on the configured port with control traffic unaffected.
Requires `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` (or root) and a kernel with
`CONFIG_BPF_SYSCALL`.

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

The GUI build (`ncp-qt.exe`; an optional frozen web-UI build may ship as `ncp-gui.exe`) shows a system-tray icon (open panel /
quit) and can register itself in autostart (HKCU `Run` on Windows,
`~/.config/autostart/ncp.desktop` on Linux) — toggled from the GUI.

## Architecture
- Modern C++17 with `constexpr`/`noexcept` optimization.
- Three-layer architecture: Core Library, CLI, Web GUI.
- 7-stage Protocol Orchestrator pipeline.

## License
Licensed under the GNU Affero General Public License v3.0 (AGPLv3). See [LICENSE](LICENSE) for details.

---
**Last Updated**: August 17, 2026
**Version**: 1.5.0-dev (suite builds v1.9.4)
