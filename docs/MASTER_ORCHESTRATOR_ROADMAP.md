# MasterOrchestrator — Full Pipeline Architecture & Implementation Guide

> **Purpose**: Self-contained document for implementing the MasterOrchestrator
> without any prior context. Everything needed — architecture, code locations,
> APIs, threat models, and step-by-step instructions — is here.
>
> **Date**: 2026-02-20 | **Repo**: `kirin2461/Dynam` | **Branch**: `main`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Current State](#2-current-state)
3. [Threat Model](#3-threat-model)
4. [Full Pipeline Diagram](#4-full-pipeline-diagram)
5. [Pending Fixes (9 items)](#5-pending-fixes)
6. [New Modules (14 items)](#6-new-modules)
7. [MasterOrchestrator API](#7-masterorchestrator-api)
8. [Send Pipeline](#8-send-pipeline)
9. [Receive Pipeline](#9-receive-pipeline)
10. [Background Scheduler](#10-background-scheduler)
11. [Adaptive Escalation](#11-adaptive-escalation)
12. [Panic Sequence](#12-panic-sequence)
13. [Implementation Phases](#13-implementation-phases)
14. [File Inventory](#14-file-inventory)
15. [Testing Strategy](#15-testing-strategy)

---

## 1. Overview

### What is MasterOrchestrator?

A top-level controller that owns **all 7 stages** of the Dynam pipeline.
Currently, each stage works independently. MasterOrchestrator unifies them
into a single `send()`/`receive()` API with:

- **Adaptive threat response** — escalate/de-escalate across ALL layers
- **Background rotation scheduler** — keys, identities, tunnels, strategies
- **Cross-layer correlation checks** — prevent ML classifiers from correlating events
- **Panic sequence** — emergency wipe of all keys, sessions, and identity

### Where it fits

```
main.cpp (30 lines — DO NOT MODIFY)
  └── Application (CLI + config loading)
        └── MasterOrchestrator (NEW)
              ├── Stage 2: E2E Encryption
              ├── Stage 3: Identity Cloaking
              ├── Stage 4: ProtocolOrchestrator (existing 32KB — DO NOT MODIFY)
              ├── Stage 4+: Obfuscation Layer
              ├── Stage 5: Transport
              ├── Stage 6: Network Layer
              └── Stage 7: Security & Monitoring
```

`main.cpp` → `Application` → `MasterOrchestrator`. The existing
`ProtocolOrchestrator` (ncp_orchestrator.hpp/cpp) remains untouched as
Stage 4 inside MasterOrchestrator.

---

## 2. Current State

### Existing modules (48 headers in `src/core/include/`)

| Stage | Headers | Status |
|-------|---------|--------|
| 2: Encryption | `ncp_e2e.hpp`, `ncp_e2e_caps_patch.hpp`, `ncp_crypto.hpp`, `ncp_crypto_constants.hpp`, `ncp_csprng.hpp`, `ncp_secure_buffer.hpp`, `ncp_secure_memory.hpp` | ✅ Implemented |
| 3: Identity | `ncp_spoofer.hpp`, `ncp_identity.hpp`, `ncp_rotation_coordinator.hpp`, `ncp_l2_stealth.hpp` | ✅ Implemented (bugs: see Fix #2) |
| 4: Protocol Orch | `ncp_orchestrator.hpp`, `ncp_orchestrator_caps_patch.hpp`, `ncp_adversarial.hpp`, `ncp_adversary_tester.hpp`, `ncp_flow_shaper.hpp`, `ncp_probe_resist.hpp`, `ncp_mimicry.hpp`, `ncp_tls_fingerprint.hpp`, `ncp_dpi_advanced.hpp`, `ncp_dpi.hpp`, `ncp_ech.hpp`, `ncp_ech_cache.hpp`, `ncp_ech_fetch.hpp`, `ncp_ech_retry.hpp` | ✅ Implemented |
| 4+: Obfuscation | `ncp_geneva_engine.hpp`, `ncp_geneva_ga.hpp`, `ncp_entropy_masking.hpp`, `ncp_dummy.hpp`, `ncp_timing.hpp`, `ncp_burst_morpher.hpp`, `ncp_protocol_morph.hpp`, `ncp_tls_record_padding.hpp` | ✅ Implemented (not wired to orchestrator) |
| 5: Transport | `ncp_i2p.hpp`, `ncp_doh.hpp`, `ncp_ws_tunnel.hpp`, `ncp_port_knock.hpp` | ✅ Implemented |
| 6: Network | `ncp_arp.hpp`, `ncp_packet_interceptor.hpp`, `ncp_l3_stealth.hpp`, `ncp_network.hpp`, `ncp_network_backend.hpp` | ✅ Implemented (bugs: see Fix #3) |
| 7: Security | `ncp_paranoid.hpp`, `ncp_security.hpp`, `ncp_capabilities.hpp`, `ncp_license.hpp` | ✅ Implemented |
| Infra | `ncp_config.hpp`, `ncp_logger.hpp`, `ncp_db.hpp`, `ncp_thread_pool.hpp`, `ncp_winsock_raii.hpp` | ✅ Implemented |

### What's missing

- No unified pipeline — each stage must be manually wired
- Geneva GA (15KB engine + 26KB GA) is **not connected** to the orchestrator
- Stage 4+ obfuscation modules are standalone, not in send/receive path
- No cross-layer correlation checking
- No covert channel (steganography) integration
- No anti-SORM-3 metadata protection
- No anti-ML behavioral cloaking

---

## 3. Threat Model

Dynam must defeat **three separate systems** simultaneously:

### 3.1 ТСПУ (DPI) — Real-time blocking

| Detection Method | What it Analyzes | Current Defense |
|-----------------|------------------|-----------------|
| Signature matching | Protocol headers, magic bytes | TrafficMimicry |
| SNI inspection | Server Name Indication in TLS ClientHello | ECH |
| JA3/JA4 fingerprint | TLS ClientHello parameters | TLSFingerprint |
| ML flow classifier | Packet sizes, timing, burst patterns, entropy | FlowShaper (partial) |
| Active probing | Send crafted requests to suspected proxies | ProbeResist |
| TLS-in-TLS detection | Nested encryption patterns | AdvancedDPIBypass |
| Protocol whitelist | Block anything that isn't known-good | TrafficMimicry |

**Gap**: ML classifiers (deployed Jan 2026, see Forbes.ru 2026-01-18) analyze
behavioral patterns that FlowShaper's synthetic profiles don't match.
Needs: BehavioralCloak, SessionPatternRandomizer.

### 3.2 СОРМ-3 — Metadata collection (stored 3 years)

| What SORM-3 Collects | How to Defend |
|----------------------|---------------|
| Source/dest IP addresses | NetworkSpoofer + I2P + GeoObfuscator |
| Source/dest ports | SessionFragmenter (port rotation) |
| Session timestamps (sec precision) | TimeCorrelationBreaker |
| Session duration | SessionFragmenter (max 2min) |
| Bytes transferred | VolumeNormalizer |
| NAT translation tables | MetadataSanitizer (NAT rotation) |
| DNS queries (plaintext) | DoH + DNSLeakPrevention |
| Geolocation (IP + cell tower) | GeoObfuscator |
| Device identifiers (IMEI, MAC) | NetworkSpoofer + L2Stealth |

**Gap**: Currently no defense against timestamp correlation, volume analysis,
NAT binding tracking, or DNS leaks (WebRTC/IPv6).

### 3.3 ML Traffic Classifier — Academic attacks

| Attack | Paper | Accuracy | Defense Needed |
|--------|-------|----------|----------------|
| dMAP (Cross-layer RTT) | NDSS 2025 | 92-98% | RTTEqualizer |
| Website Fingerprinting | Multiple (Tor survey 2025) | 95%+ | WFDefense (Palette) |
| Encrypted traffic classification | Nature 2025 | 96% | BehavioralCloak + EntropyMasking |

**Gap**: dMAP is the most critical — it detects ANY proxy by measuring
RTT difference between TCP (transport) and TLS (application) layers.
Protocol-agnostic, works against all known tools including Shadowsocks,
VMess, VLESS, Tor bridges.

---

## 4. Full Pipeline Diagram

### SEND path (plaintext → wire)

```
PLAINTEXT
    │
    ▼
┌─ STAGE 7: SECURITY PRE-FLIGHT ──────────────────────────────┐
│  CrossLayerCorrelator.begin_transaction()        [NEW #8]    │
│  SecurityMonitor.check_environment()                         │
│  ParanoidMode.verify_no_debugger()                           │
└──────────────────────────────────┬───────────────────────────┘
                                   │
┌─ STAGE 2: E2E ENCRYPTION ────────┼───────────────────────────┐
│  E2ESession.encrypt(peer_id, plaintext)                      │
│    X25519 + Kyber1024 key exchange                           │
│    XChaCha20-Poly1305 AEAD                                   │
│    Double Ratchet rotation (5min)                             │
│  Deps: ncp_e2e.hpp, ncp_crypto.hpp, ncp_csprng.hpp           │
└──────────────────────────────────┬───────────────────────────┘
                                   │
┌─ STAGE 4: PROTOCOL ORCHESTRATOR ─┼── (EXISTING, DO NOT MODIFY) ─┐
│  Step 1: AdversarialPadding.pad()                               │
│  Step 2: TrafficMimicry.wrap_payload()                          │
│  Step 2.5: AdvancedDPIBypass.process_outgoing()                 │
│  Step 3: ProbeResist.generate_client_auth()                     │
│  Step 4: TLSFingerprint.apply()                                 │
│  Step 5: FlowShaper.enqueue()                                   │
│  Step 6: ECH.encrypt_client_hello()                             │
│  Output: vector<OrchestratedPacket>                             │
└──────────────────────────────────┬──────────────────────────────┘
                                   │
┌─ STAGE 4+: OBFUSCATION LAYER ────┼───────────────────────────┐
│  GenevaEngine.apply(best_strategy)               [FIX #1]    │
│  EntropyMasking.mask()                                       │
│  BehavioralCloak.shape_packet()                  [NEW #6]    │
│  SessionPatternRandomizer.apply_timing()         [NEW]       │
│  DummyInjector.inject_dummies()                              │
│  TimingObfuscator.apply_jitter()                             │
│  BurstMorpher.morph()                                        │
│  ProtocolMorph.select_profile()                              │
│  RTTEqualizer.equalize_tcp_ack()                 [NEW]       │
│  WFDefense.defend()                              [NEW]       │
│  VolumeNormalizer.normalize()                    [NEW]       │
│  TimeCorrelationBreaker.break_correlation()      [NEW]       │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                          ┌────────▼────────┐
                          │  threat_level   │
                          │  >= CRITICAL?   │
                          └───┬─────────┬───┘
                          YES │         │ NO
                              ▼         ▼
┌─ COVERT CHANNEL FALLBACK ──────┐  ┌─ NORMAL PATH ─────────────────┐
│  CovertChannelManager:  [#7]   │  │  (continue below)             │
│  ├─ DNSCovertChannel           │  │                               │
│  ├─ TLSRecordPadding           │  │                               │
│  ├─ HTTPHeaderSteg             │  │                               │
│  └─ HLSVideoSteg               │  │                               │
└────────────┬───────────────────┘  └──────────┬────────────────────┘
             └──────────┬──────────────────────┘
                        │
┌─ STAGE 5: TRANSPORT ──┼──────────────────────────────────────┐
│  ProtocolRotationSchedule                        [NEW #9]    │
│    06-12h→HTTP/2, 12-18h→WS, 18-02h→HTTPS, 02-06h→rawTLS   │
│  ASAwareRouter.select_route()                    [NEW]       │
│    CDN_RELAY / I2P_GARLIC / WS_TUNNEL / DIRECT               │
│  GeoObfuscator — first hop always domestic       [NEW]       │
│  SessionFragmenter — max 2min TCP, rotate ports  [NEW]       │
│  DNSLeakPrevention — block plaintext/WebRTC/IPv6 [NEW]       │
│  I2PManager (SAM v3.3, garlic routing)                       │
│  DoHResolver (Cloudflare/Google/Quad9 + cert pin)            │
│  WSTunnel, PortKnock                                         │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌─ STAGE 3: IDENTITY ───┼──────────────────────────────────────┐
│  MetadataSanitizer — NAT rotation, volume norm   [NEW]       │
│  NetworkSpoofer — MAC/IP/hostname/SMBIOS         [FIX #2]    │
│  IdentityRotation — timed (30min)                            │
│  RotationCoordinator — sync atomically                       │
│  L2Stealth — DHCP fingerprint, OUI randomization             │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌─ STAGE 6: NETWORK ────┼──────────────────────────────────────┐
│  L3Stealth — TTL/window/checksum manipulation                │
│  ARPManager — ARP cache poisoning (LAN)                      │
│  PacketInterceptor — WinDivert/WFP/raw          [FIX #3]    │
│  NetworkBackend.send_raw()                                   │
└───────────────────────┬──────────────────────────────────────┘
                        │
┌─ STAGE 7: SECURITY POST-FLIGHT ──┼───────────────────────────┐
│  CrossLayerCorrelator.end_transaction()          [NEW #8]    │
│  ProbeHoneypot — reverse proxy to real server    [NEW]       │
│  SecurityMonitor.log_send()                                  │
└──────────────────────────────────┬───────────────────────────┘
                                   │
                                 WIRE
```

### RECEIVE path (wire → plaintext)

```
WIRE
  │
  Stage 6:  NetworkBackend.recv_raw() → L3Stealth.strip()
  Stage 3:  (identity already applied — transparent)
  Stage 5:  I2P.demux() / DoH.resolve() / WSTunnel.unwrap()
  Covert:   CovertChannelManager.extract() (if stego mode)
  Stage 4+: BurstMorpher.unmorph() → TimingObfuscator.strip()
            DummyInjector.filter_dummies()
            EntropyMasking.unmask()
            GenevaEngine.reassemble()
  Stage 4:  ProtocolOrchestrator.receive()
            ├─ ECH unwrap
            ├─ AdvancedDPIBypass.process_incoming()
            ├─ ProbeResist.validate_auth()
            ├─ TrafficMimicry.unwrap_payload()
            └─ AdversarialPadding.unpad()
  Stage 2:  E2ESession.decrypt() → plaintext
  │
  PLAINTEXT
```

---

## 5. Pending Fixes

These are bugs/issues in **existing** code that must be fixed.

### Fix #1: Geneva GA Deadlock

- **File**: `src/core/src/ncp_geneva_ga.cpp`
- **Problem**: `evolution_loop()` calls `on_generation_` and `on_re_evolution_`
  callbacks while holding `population_mutex_`. Those callbacks may call
  `get_best_strategy()` which also locks `population_mutex_` → deadlock.
  Also locks `stats_mutex_` recursively in same callbacks.
- **Status**: Deadlock itself was fixed (snapshot pattern), but Geneva GA
  is **not integrated** into the orchestrator pipeline.
- **Solution**:
  ```cpp
  // In MasterOrchestrator, connect Geneva GA to adaptive feedback:
  void on_detection(DetectionEvent e) {
      auto best = geneva_ga_->get_best_strategy();
      protocol_orch_->apply_geneva(best);
      geneva_ga_->report_fitness(e.type == SUCCESS ? 1.0 : 0.0);
  }
  // Run GA callbacks through scheduler (never under population_mutex_):
  geneva_ga_ = std::make_unique<GenevaGA>(GenevaGA::Config{
      .on_generation = [this](auto stats) {
          scheduler_.post([this, stats]() { update_geneva_stats(stats); });
      }
  });
  ```

### Fix #2: Spoofer Data Race

- **File**: `src/core/src/spoofer.cpp`, `src/core/src/ncp_identity.cpp`
- **Problem**: `status_` and `config_` are shared state. Only `bool` fields
  are atomic. Other fields (strings, vectors) have data races when
  `rotation_thread_func()` reads while `rotate_all()` writes.
- **Status**: Partially fixed with snapshot-pattern in `rotation_thread_func()`.
  But `rotate_all()` itself still has race with `get_identity()`.
- **Solution**:
  ```cpp
  // In MasterOrchestrator, serialize all identity access:
  mutable std::mutex identity_mutex_;
  void rotate_identity() {
      std::lock_guard<std::mutex> lock(identity_mutex_);
      cross_layer_->notify_rotation_start();
      spoofer_->rotate_all();
      cross_layer_->notify_rotation_end();
  }
  ```

### Fix #3: pcap.h Missing #ifdef

- **File**: `src/core/src/network.cpp` (line 14), `src/core/include/ncp_network.hpp`
- **Problem**: `#include <pcap.h>` is not wrapped in `#if NCP_HAS_PCAP`.
  CI runners without Npcap SDK fail with C1083. Linker was fixed
  (CMakeLists.txt), but preprocessor still tries to include the header.
- **Solution**:
  ```cpp
  // In network.cpp and ncp_network.hpp:
  #if NCP_HAS_PCAP
  #include <pcap.h>
  #endif
  // Wrap ALL pcap-dependent code in same guard:
  #if NCP_HAS_PCAP
  void Network::start_capture(...) { /* pcap code */ }
  #endif
  ```
  Also in CMakeLists.txt: `add_compile_definitions($<$<BOOL:${PCAP_FOUND}>:NCP_HAS_PCAP>)`

### Fix #4: Randomization Inconsistency in TLS Fingerprint

- **File**: `src/core/src/tls_fingerprint.cpp`
- **Problem**: Individual methods (`randomize_ciphers()`, `randomize_extensions()`,
  `shuffle_order()`) use full Fisher-Yates shuffle via `secure_shuffle()`.
  But `randomize_all()` only does minor permutations — much less random.
- **Solution**: Make `randomize_all()` call the individual methods:
  ```cpp
  void TLSFingerprint::Impl::randomize_all() {
      randomize_ciphers();
      randomize_extensions();
      shuffle_order();
      // Instead of the current minor permutation logic
  }
  ```

### Fix #5: HMAC Salt Silent Truncation

- **File**: `src/core/src/ncp_orchestrator.cpp` (derive_dummy_key_from_secret_)
- **Problem**: `crypto_auth_hmacsha256_init()` accepts any salt length, but
  internally libsodium may truncate salts exceeding `crypto_auth_hmacsha256_KEYBYTES`
  (32 bytes). No assertion or check exists.
- **Solution**:
  ```cpp
  // Option A: Static assert (if salt is compile-time)
  static_assert(salt.size() <= crypto_auth_hmacsha256_KEYBYTES);
  // Option B: Hash long salts before use
  if (salt.size() > 32) {
      uint8_t hashed_salt[32];
      crypto_hash_sha256(hashed_salt, salt.data(), salt.size());
      // Use hashed_salt instead
  }
  ```

### Fix #6: Adversarial Traffic Shaping (BehavioralCloak)

- **Status**: Planned as Stage 1c, never implemented
- **Problem**: `FlowShaper::web_browsing()` uses synthetic profiles.
  ML classifiers trained on real traffic can distinguish them.
- **Solution**: New module `ncp_behavioral_cloak.hpp` — see [New Module #1](#61-behavioralcloak)

### Fix #7: Steganography Engine (CovertChannelManager)

- **Status**: `ICovertChannel` interface was designed. `DNSCovertChannel` was
  partially implemented with libsodium crypto_secretbox. Other channels (HLS,
  HTTP header, TLS padding) exist as headers but no implementations.
- **Solution**: New module `ncp_covert_channel.hpp` — see [New Module #2](#62-covertchannelmanager)

### Fix #8: Cross-Layer Correlation

- **Status**: Planned as Stage 5b, never started
- **Problem**: Without correlation checks, ML can correlate events across
  layers: MAC rotation at same time as tunnel rebuild = fingerprint.
- **Solution**: New module `ncp_cross_layer.hpp` — see [New Module #3](#63-crosslayercorrelator)

### Fix #9: Protocol Rotation Schedule

- **Status**: Designed (HTTP/2 mornings, WebSocket daytime, raw TLS nights),
  never implemented
- **Solution**: New module in `ncp_protocol_rotation.hpp` — see [New Module #4](#64-protocolrotationschedule)

---

## 6. New Modules

### 6.1 BehavioralCloak

**File**: `src/core/include/ncp_behavioral_cloak.hpp` + `.cpp`

**Threat**: ТСПУ ML classifier (deployed Jan 2026) detects tunnel traffic
by comparing packet patterns to real browser traffic models.

**Concept**: Record real Chrome/Firefox browsing sessions. Extract statistical
profiles (inter-request delay, request/response sizes, bursts per page,
session duration, idle periods). Apply these profiles to tunnel traffic.

**API**:
```cpp
namespace ncp {

struct BrowsingProfile {
    struct Distribution { double mean; double stddev; double min; double max; };
    Distribution inter_request_delay_ms;   // 50-3000ms
    Distribution request_size_bytes;        // GET ~200B, POST ~2KB
    Distribution response_size_bytes;       // HTML ~50KB, JS ~100KB
    Distribution requests_per_page;         // 20-80
    Distribution session_duration_sec;      // 120-1800
    Distribution idle_between_sessions_sec; // 10-300
    float scroll_pause_probability;         // 0.3-0.7
};

class BehavioralCloak {
public:
    explicit BehavioralCloak(const BrowsingProfile& profile = BrowsingProfile::chrome_default());
    void shape_packet(DPI::OrchestratedPacket& pkt);
    void set_profile(const BrowsingProfile& profile);
    static BrowsingProfile chrome_default();
    static BrowsingProfile firefox_default();
};

} // namespace ncp
```

**Implementation steps**:
1. Create `BrowsingProfile` presets by capturing real traffic with Wireshark
2. Implement `shape_packet()`: adjust `pkt.delay` to match profile timing
3. Add idle injection between "pages" (groups of packets)
4. Wire into MasterOrchestrator after Stage 4 output
5. Test: run ML classifier (sklearn RandomForest) on shaped vs unshaped traffic

**Dependencies**: `ncp_flow_shaper.hpp` (similar timing concepts), `ncp_csprng.hpp`

---

### 6.2 CovertChannelManager

**File**: `src/core/include/ncp_covert_channel.hpp` + `.cpp`

**Threat**: At CRITICAL threat level, all standard protocols are blocked.
Need fallback to steganographic channels.

**API**:
```cpp
namespace ncp {

class ICovertChannel {
public:
    virtual ~ICovertChannel() = default;
    virtual bool send(const std::vector<uint8_t>& data) = 0;
    virtual std::vector<uint8_t> receive() = 0;
    virtual size_t max_payload_per_message() const = 0;
    virtual std::string channel_name() const = 0;
};

class CovertChannelManager {
public:
    void register_channel(std::unique_ptr<ICovertChannel> ch);
    ICovertChannel* select_channel(DPI::ThreatLevel level);
    void send_via_stego(const std::vector<DPI::OrchestratedPacket>& packets);
    void wipe();  // Emergency cleanup
};

// Concrete channels:
class DNSCovertChannel : public ICovertChannel { /* DNS TXT/CNAME */ };
class TLSPaddingChannel : public ICovertChannel { /* TLS record padding */ };
class HTTPHeaderChannel : public ICovertChannel { /* HTTP header encoding */ };
class HLSVideoChannel  : public ICovertChannel { /* HLS stuffing bytes */ };

} // namespace ncp
```

**Implementation steps**:
1. Implement `ICovertChannel` base interface
2. Implement `DNSCovertChannel` first (already partially done: encode data
   in DNS TXT/CNAME queries, encrypt with `crypto_secretbox_xsalsa20poly1305`)
3. Implement `TLSPaddingChannel` (hide data in TLS record padding bytes)
4. Wire `CovertChannelManager` into MasterOrchestrator send path
5. Add threat-level-based channel selection

**Dependencies**: `ncp_doh.hpp` (DNS resolver), `ncp_crypto.hpp`, `ncp_tls_record_padding.hpp`

---

### 6.3 CrossLayerCorrelator

**File**: `src/core/include/ncp_cross_layer.hpp` + `.cpp`

**Threat**: ML classifiers can correlate simultaneous events across layers
(MAC change + tunnel rebuild = fingerprint).

**API**:
```cpp
namespace ncp {

class CrossLayerCorrelator {
public:
    void begin_transaction();  // Call before each send
    void end_transaction();    // Call after each send — verify no leaks

    void notify_rotation_start();  // Called by identity rotation
    void notify_rotation_end();
    void notify_tunnel_rebuild();  // Called by I2P/transport
    void notify_dns_query();       // Called by DoH
    void notify_mimicry_change();  // Called by ProtocolMorph

    bool check_all();  // Returns false if correlation detected

    struct Config {
        std::chrono::milliseconds min_decorrelation_window = std::chrono::milliseconds(5000);
    };
    explicit CrossLayerCorrelator(const Config& cfg = {});

private:
    // Track timestamps of events, ensure minimum gap between
    // events on different layers
    struct EventLog {
        std::chrono::steady_clock::time_point timestamp;
        std::string layer;
        std::string event_type;
    };
    std::vector<EventLog> recent_events_;
    Config config_;
    mutable std::mutex mutex_;
};

} // namespace ncp
```

**Implementation steps**:
1. Implement event logging with ring buffer (last 100 events)
2. `check_all()`: iterate pairs, flag if two events from different layers
   occur within `min_decorrelation_window`
3. Wire `notify_*` calls into Spoofer, I2PManager, DoHResolver, ProtocolMorph
4. Call `begin_transaction()`/`end_transaction()` in MasterOrchestrator::send()
5. If correlation detected: delay next rotation by random offset

**Dependencies**: None (standalone module)

---

### 6.4 ProtocolRotationSchedule

**File**: `src/core/include/ncp_protocol_rotation.hpp` + `.cpp`

**Threat**: Fixed protocol profile is a fingerprint. Real users switch apps.

**API**:
```cpp
namespace ncp {

class ProtocolRotationSchedule {
public:
    struct TimeSlot {
        int hour_start;  // 0-23
        int hour_end;    // 0-23
        DPI::TrafficMimicry::MimicProfile profile;
        std::string description;
    };

    ProtocolRotationSchedule();  // Default: HTTP/2 → WS → HTTPS → rawTLS
    explicit ProtocolRotationSchedule(std::vector<TimeSlot> slots);

    DPI::TrafficMimicry::MimicProfile current_profile() const;
    void set_slots(std::vector<TimeSlot> slots);

    // Default schedule:
    // 06:00-12:00 → HTTP/2         (office traffic)
    // 12:00-18:00 → WebSocket      (messenger-like)
    // 18:00-02:00 → HTTPS stream   (streaming/video)
    // 02:00-06:00 → raw TLS        (minimal traffic)
    static std::vector<TimeSlot> default_schedule();
};

} // namespace ncp
```

**Implementation steps**:
1. Implement `current_profile()` using `std::chrono::system_clock` local time
2. Wire into MasterOrchestrator: before Stage 4, set mimicry profile
3. Add jitter to transition times (±15min) to avoid synchronized switching

**Dependencies**: `ncp_mimicry.hpp` (MimicProfile enum)

---

### 6.5 SessionPatternRandomizer

**File**: `src/core/include/ncp_session_pattern.hpp` + `.cpp`

**Threat**: ТСПУ and SORM-3 detect 24/7 tunnels (real users have sessions).

**API**:
```cpp
namespace ncp {

class SessionPatternRandomizer {
public:
    struct Config {
        std::chrono::seconds min_session_duration{60};
        std::chrono::seconds max_session_duration{1800};
        std::chrono::seconds min_idle{30};
        std::chrono::seconds max_idle{300};
    };

    void apply_session_timing(std::vector<DPI::OrchestratedPacket>& packets);
    void schedule_next_session();  // Connect/disconnect cycle
    bool is_in_session() const;
};

} // namespace ncp
```

**Implementation steps**:
1. State machine: IDLE → CONNECTING → ACTIVE → DISCONNECTING → IDLE
2. In ACTIVE: pass packets normally
3. In IDLE: drop or queue packets, send cover traffic
4. Transition timings from CSPRNG within configured ranges

**Dependencies**: `ncp_csprng.hpp`, `ncp_timing.hpp`

---

### 6.6 ASAwareRouter

**File**: `src/core/include/ncp_as_router.hpp` + `.cpp`

**Threat**: ТСПУ blocks traffic to datacenter IP ranges (Hetzner, DO, AWS).

**API**:
```cpp
namespace ncp {

enum class RouteType { CDN_RELAY, I2P_GARLIC, WS_TUNNEL, DIRECT };

class ASAwareRouter {
public:
    RouteType select_route(
        const DPI::OrchestratedPacket& pkt,
        DPI::TrafficMimicry::MimicProfile transport_profile);

    void add_cdn_endpoint(const std::string& url);  // Cloudflare Workers etc
    void add_domestic_relay(const std::string& ip, uint16_t port);
    void set_blocklist(const std::vector<std::string>& as_numbers);
};

} // namespace ncp
```

**Implementation steps**:
1. Maintain AS blocklist (known-blocked ranges)
2. On send: check dest IP against blocklist
3. If blocked: route through CDN relay (Cloudflare Workers / Fastly Compute)
4. Fallback: I2P garlic routing

**Dependencies**: `ncp_i2p.hpp`, `ncp_doh.hpp`, `ncp_ws_tunnel.hpp`

---

### 6.7 RTTEqualizer

**File**: `src/core/include/ncp_rtt_equalizer.hpp` + `.cpp`

**Threat**: dMAP (NDSS 2025) detects proxies by measuring Δ(TCP_RTT, TLS_RTT)
with 92-98% accuracy. This is protocol-agnostic.

**Concept**: Add artificial delay to TCP ACK packets so that the observed
transport-layer RTT matches the application-layer RTT.

**API**:
```cpp
namespace ncp {

class RTTEqualizer {
public:
    struct Config {
        bool enabled = true;
        std::chrono::microseconds max_added_delay{200000};  // 200ms cap
        std::chrono::microseconds jitter_range{5000};       // ±5ms
    };

    explicit RTTEqualizer(const Config& cfg = {});

    // Call on every outgoing TCP ACK
    std::chrono::microseconds calculate_ack_delay();

    // Feed RTT measurements
    void update_transport_rtt(std::chrono::microseconds rtt);
    void update_application_rtt(std::chrono::microseconds rtt);

private:
    // Exponential moving average of both RTTs
    std::chrono::microseconds transport_rtt_ema_{0};
    std::chrono::microseconds application_rtt_ema_{0};
    Config config_;
};

} // namespace ncp
```

**Implementation steps**:
1. Hook into TCP stack (via PacketInterceptor or WinDivert)
2. Measure transport RTT: SYN→SYN-ACK round trip
3. Measure application RTT: TLS request→response round trip
4. On each ACK: if app_rtt > transport_rtt, delay ACK by (app_rtt - transport_rtt + jitter)
5. EMA smoothing to avoid jitter-induced false positives
6. Test: run dMAP reference implementation against equalized traffic

**Dependencies**: `ncp_packet_interceptor.hpp`, `ncp_csprng.hpp`

**References**:
- Paper: "The Discriminative Power of Cross-layer RTTs" (NDSS 2025)
- URL: https://www.ndss-symposium.org/ndss-paper/the-discriminative-power-of-cross-layer-rtts-in-fingerprinting-proxy-traffic/

---

### 6.8 WFDefense

**File**: `src/core/include/ncp_wf_defense.hpp` + `.cpp`

**Threat**: Website Fingerprinting (WF) attacks identify which site a user
visits even through encrypted tunnels, with 95%+ accuracy.

**Concept**: Palette defense (IEEE S&P 2024) — group traffic patterns into
clusters, pad/delay all traces to match the cluster centroid.

**API**:
```cpp
namespace ncp {

class WFDefense {
public:
    struct TrafficCluster {
        std::string name;
        std::vector<size_t> typical_sizes;        // per-packet sizes
        std::vector<std::chrono::microseconds> typical_delays;
        size_t typical_burst_count;
    };

    void load_clusters(const std::string& path);  // Pre-computed clusters
    void defend(std::vector<DPI::OrchestratedPacket>& trace);

private:
    TrafficCluster find_nearest_cluster(
        const std::vector<DPI::OrchestratedPacket>& trace);
    std::vector<TrafficCluster> clusters_;
};

} // namespace ncp
```

**Implementation steps**:
1. Collect traffic traces from 100+ popular websites
2. Cluster traces using k-means on feature vectors (packet sizes, timing, bursts)
3. Save cluster centroids to JSON file
4. At runtime: match current trace to nearest cluster, pad to match
5. Test: run Deep Fingerprinting (DF) attack on defended traces

**Dependencies**: `ncp_csprng.hpp`

**References**:
- Paper: "Real-Time Website Fingerprinting Defense via Traffic Cluster Anonymization"
  (IEEE S&P 2024, THU)

---

### 6.9 MetadataSanitizer

**File**: `src/core/include/ncp_metadata_sanitizer.hpp` + `.cpp`

**Threat**: SORM-3 stores metadata (IP, port, duration, volume, NAT binding)
for 3 years and correlates it with user identity.

**API**:
```cpp
namespace ncp {

class MetadataSanitizer {
public:
    struct Config {
        std::chrono::seconds nat_rotation_interval{300};  // 5min
        size_t volume_bucket_bytes = 2 * 1024 * 1024;     // 2MB
    };

    void rotate_nat_binding();           // Change source port
    void normalize_volume(DPI::OrchestratedPacket& pkt);
    void fragment_session_metadata();    // Break SORM session correlation
};

} // namespace ncp
```

**Dependencies**: `ncp_network_backend.hpp`, `ncp_csprng.hpp`

---

### 6.10 VolumeNormalizer

**File**: `src/core/include/ncp_volume_normalizer.hpp` + `.cpp`

**Threat**: SORM-3 traffic volume correlation (unique download sizes = fingerprint).

**API**:
```cpp
namespace ncp {

class VolumeNormalizer {
public:
    enum Bucket : size_t {
        WEB_PAGE  = 2 * 1024 * 1024,   // 2MB
        VIDEO_SEG = 10 * 1024 * 1024,   // 10MB
        DOWNLOAD  = 50 * 1024 * 1024,   // 50MB
    };

    void normalize(DPI::OrchestratedPacket& pkt);
    void generate_cover_volume(std::chrono::seconds interval);

private:
    Bucket nearest_bucket(size_t size);
};

} // namespace ncp
```

**Dependencies**: `ncp_csprng.hpp`, `ncp_dummy.hpp` (cover traffic)

---

### 6.11 SessionFragmenter

**File**: `src/core/include/ncp_session_fragmenter.hpp` + `.cpp`

**Threat**: SORM-3 long-lived TCP sessions = VPN fingerprint.

**API**:
```cpp
namespace ncp {

class SessionFragmenter {
public:
    struct Config {
        std::chrono::seconds max_session_life{120};  // 2 min max
        std::chrono::seconds reconnect_jitter_min{5};
        std::chrono::seconds reconnect_jitter_max{30};
        bool rotate_src_port = true;
        int max_concurrent_streams = 6;  // Like Chrome
    };

    // Returns true if current session should be torn down
    bool should_fragment() const;

    // Get next source port for new connection
    uint16_t next_src_port();
};

} // namespace ncp
```

**Dependencies**: `ncp_csprng.hpp`, `ncp_network_backend.hpp`

---

### 6.12 GeoObfuscator

**File**: `src/core/include/ncp_geo_obfuscator.hpp` + `.cpp`

**Threat**: SORM-3 flags domestic→foreign traffic patterns.

**Concept**: First hop is always a domestic (Russian) relay.
SORM sees: Moscow → Moscow (domestic CDN). The CDN then forwards
through encrypted tunnel to actual destination.

**API**:
```cpp
namespace ncp {

class GeoObfuscator {
public:
    enum Strategy {
        DOMESTIC_CDN,      // Yandex Cloud / VK Cloud relay
        DOMESTIC_RELAY,    // Self-hosted relay in RU
        GEO_MATCHED_EXIT,  // Exit in same city as entry
        MULTI_HOP,         // Gradual geographic exit
    };

    Strategy select_strategy(const std::string& dest_ip);
    std::string get_first_hop();
    void add_domestic_relay(const std::string& ip, uint16_t port);
};

} // namespace ncp
```

**Dependencies**: `ncp_i2p.hpp`, `ncp_network.hpp`

---

### 6.13 DNSLeakPrevention

**File**: `src/core/include/ncp_dns_leak_prevention.hpp` + `.cpp`

**Threat**: A single plaintext DNS query exposes user intent to SORM-3.

**API**:
```cpp
namespace ncp {

class DNSLeakPrevention {
public:
    void enforce();           // Redirect all DNS, block leaks
    void monitor_leaks(std::function<void(const std::string&)> on_leak);

private:
    void redirect_all_dns();  // WFP/iptables: port 53 → localhost
    void block_ipv6_leaks();  // Disable IPv6 DNS resolution
    void block_webrtc_stun(); // Block STUN server connections
    void block_dns_prefetch();// Block browser DNS prefetch
};

} // namespace ncp
```

**Implementation steps**:
1. On Windows: WFP filter to redirect all outgoing UDP:53 to localhost
2. On Linux: iptables -t nat REDIRECT to localhost:5353
3. Localhost resolver → DoHResolver (existing `ncp_doh.hpp`)
4. Monitor: pcap/WinDivert check for any UDP:53 escaping → panic callback
5. IPv6: disable via sysctl / netsh
6. WebRTC: not applicable for CLI tool, but document for library users

**Dependencies**: `ncp_doh.hpp`, `ncp_packet_interceptor.hpp`

---

### 6.14 ProbeHoneypot

**File**: `src/core/include/ncp_probe_honeypot.hpp` + `.cpp`

**Threat**: ТСПУ actively probes suspected proxy servers (send HTTP requests,
check response). Current ProbeResist generates a cover page, but it doesn't
match a real server exactly.

**Concept**: Full reverse proxy to a real website. When an unauthorized
client connects, forward request to real nginx/apache and return its
exact response (headers, timing, favicon, cert chain).

**API**:
```cpp
namespace ncp {

class ProbeHoneypot {
public:
    struct Config {
        std::string real_server = "www.google.com";
        uint16_t real_port = 443;
        bool copy_response_timing = true;  // Match real server latency
    };

    // Returns real server response for unauthorized requests
    std::vector<uint8_t> handle_probe(const std::vector<uint8_t>& request);
};

} // namespace ncp
```

**Dependencies**: `ncp_probe_resist.hpp` (extends existing functionality)

---

### 6.15 TimeCorrelationBreaker

**File**: `src/core/include/ncp_time_correlation.hpp` + `.cpp`

**Threat**: SORM-3 correlates user actions with packet timestamps (sec precision).

**API**:
```cpp
namespace ncp {

class TimeCorrelationBreaker {
public:
    struct Config {
        std::chrono::milliseconds min_delay{50};
        std::chrono::milliseconds max_delay{500};
        std::chrono::seconds batch_window{1};  // Batch send interval
        bool enable_cover_traffic = true;
        double cover_packets_per_sec = 2.0;
    };

    void break_correlation(DPI::OrchestratedPacket& pkt);
    void batch_send(std::vector<DPI::OrchestratedPacket>& pkts);
    void start_cover_traffic(DPI::OrchestratorSendCallback cb);
    void stop_cover_traffic();
};

} // namespace ncp
```

**Dependencies**: `ncp_csprng.hpp`, `ncp_dummy.hpp`, `ncp_timing.hpp`

---

## 7. MasterOrchestrator API

**File**: `src/core/include/ncp_master_orchestrator.hpp` + `.cpp`

```cpp
namespace ncp {

struct MasterConfig {
    // Stage 2
    E2ESession::Config e2e;
    // Stage 3
    NetworkSpoofer::Config spoofer;
    IdentityRotation::Config identity;
    // Stage 4 (existing)
    DPI::OrchestratorConfig protocol;
    // Stage 4+ (new)
    BehavioralCloak::Config behavioral;
    SessionPatternRandomizer::Config session_pattern;
    RTTEqualizer::Config rtt;
    WFDefense::Config wf;
    VolumeNormalizer::Config volume;
    TimeCorrelationBreaker::Config time_corr;
    // Stage 5
    ProtocolRotationSchedule::Config rotation;
    ASAwareRouter::Config as_router;
    GeoObfuscator::Config geo;
    SessionFragmenter::Config fragmenter;
    DNSLeakPrevention::Config dns_leak;
    I2PManager::Config i2p;
    DoHResolver::Config doh;
    // Stage 6
    L3Stealth::Config l3;
    // Stage 7
    CrossLayerCorrelator::Config cross_layer;
    ProbeHoneypot::Config honeypot;
    SecurityMonitor::Config security;
    ParanoidMode::Config paranoid;
    // Covert
    CovertChannelManager::Config covert;
    // Meta
    MetadataSanitizer::Config metadata;
};

class MasterOrchestrator {
public:
    explicit MasterOrchestrator(const MasterConfig& cfg);
    ~MasterOrchestrator();

    // === Lifecycle ===
    void start();   // Stages 7→6→5→4→3→2 (bottom-up)
    void stop();    // Stages 2→3→4→5→6→7 (top-down)
    void panic();   // Emergency: wipe keys, restore identity, stop all

    // === Data path ===
    void send(const std::string& peer_id, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> receive(
        const std::vector<uint8_t>& wire_data,
        const std::string& source_ip,
        uint16_t source_port);

    // === Feedback ===
    void report_detection(const DPI::DetectionEvent& event);
    void report_success();

    // === Accessors ===
    DPI::ThreatLevel threat_level() const;
    MasterStats stats() const;

private:
    // All stages owned via unique_ptr — see Section 14 for full list
    // ...
    RotationScheduler scheduler_;
    mutable std::mutex identity_mutex_;
};

} // namespace ncp
```

---

## 8. Send Pipeline

See Section 4 diagram. Key implementation notes:

1. **Thread safety**: Snapshot `OrchestratorStrategy` under lock before
   processing (same pattern as existing `prepare_payload()`).
2. **Ordering matters**: E2E encrypt BEFORE protocol obfuscation.
   Stage 4 sees ciphertext, not plaintext.
3. **Covert branch**: Check threat level AFTER obfuscation.
   If CRITICAL, divert to steganography path.
4. **RTTEqualizer**: Must hook into TCP ACK path, which is below
   the normal send pipeline. Requires PacketInterceptor integration.

---

## 9. Receive Pipeline

See Section 4 diagram. Key implementation notes:

1. **Reverse order**: Unwrap layers in exact reverse of send.
2. **Dummy filtering**: Must happen before E2E decrypt (dummies have
   no valid ciphertext).
3. **Auth validation**: ProbeResist validates auth BEFORE unwrapping
   mimicry (auth header is outermost layer after mimicry wrap).

---

## 10. Background Scheduler

```
Every 1min   │ CrossLayerCorrelator.check_all()
Every 1min   │ SecurityMonitor.health_check()
Every 5min   │ E2ESession.rotate_keys()
Every 15min  │ TLSFingerprint.rotate()
Every 30min  │ IdentityRotation.rotate_all()   (under identity_mutex_)
Every 30min  │ I2PManager.rotate_tunnels()
Every 60min  │ GenevaGA.evolve_one_generation()
```

Implement using `ncp_thread_pool.hpp` with a timer queue.
Each task runs in the thread pool, never on the main send/receive path.

---

## 11. Adaptive Escalation

| Threat Level | Strategy | Active Modules |
|-------------|----------|----------------|
| NONE/LOW | performance | FlowShaper OFF, Geneva OFF, Mimicry basic |
| MEDIUM | balanced | FlowShaper ON, Geneva GA ON, BehavioralCloak ON |
| HIGH | stealth | +Identity rotate, +I2P rotate, +BurstMorpher, +SessionRandomizer, +ASAwareRouter→CDN |
| CRITICAL | paranoid | +Covert channels, +ParanoidMode, +Constant rate, +Memory wipe, +All rotations→5min |

Escalation trigger: `consecutive_failures_ >= escalation_threshold` (default: 3)
De-escalation trigger: `consecutive_successes_ >= deescalation_threshold` (default: 20)
Cooldown: `deescalation_cooldown_sec` (default: 300)

When threat changes, `MasterOrchestrator::on_threat_change()` propagates
to ALL stages, not just ProtocolOrchestrator.

---

## 12. Panic Sequence

```
MasterOrchestrator::panic():
  1. E2ESession.wipe_all_sessions()     // sodium_memzero on all keys
  2. CovertChannelManager.wipe()        // Clear stego buffers
  3. ProtocolOrchestrator.stop()        // Stop DPI pipeline
  4. I2PManager.emergency_close()       // Close all tunnels
  5. NetworkSpoofer.restore_all()       // Restore original MAC/IP
  6. ParanoidMode.full_wipe()           // tmpfiles, /dev/shm, process name
  7. SecurityMonitor.log_panic()        // Record event (encrypted log)
```

Triggered by: manual CLI command, debugger detection, DNS leak detection,
or threat level held at CRITICAL for >10 minutes.

---

## 13. Implementation Phases

### Phase 1: Core Integration (Week 1-2)
**Goal**: Wire existing modules into MasterOrchestrator.

1. Create `ncp_master_orchestrator.hpp/.cpp`
2. Implement `start()`/`stop()` with all existing modules
3. Implement `send()` pipeline: E2E → ProtocolOrchestrator → NetworkBackend
4. Implement `receive()` pipeline (reverse)
5. Apply Fix #1 (Geneva GA integration)
6. Apply Fix #2 (Spoofer mutex)
7. Apply Fix #3 (pcap #ifdef)

### Phase 2: Anti-ТСПУ ML (Week 3-4)
**Goal**: Defeat ML traffic classifiers.

1. Implement BehavioralCloak (anti-ML profiles)
2. Implement SessionPatternRandomizer (anti-24/7)
3. Implement ProtocolRotationSchedule (time-of-day)
4. Apply Fix #4 (randomize_all → Fisher-Yates)
5. Apply Fix #5 (HMAC salt truncation)

### Phase 3: Anti-СОРМ (Week 5-6)
**Goal**: Break metadata correlation.

1. Implement MetadataSanitizer (NAT rotation)
2. Implement VolumeNormalizer (traffic volume normalization)
3. Implement SessionFragmenter (TCP session splitting)
4. Implement DNSLeakPrevention (DNS/WebRTC/IPv6)
5. Implement TimeCorrelationBreaker (timestamp decorrelation)

### Phase 4: Advanced Defense (Week 7-8)
**Goal**: Defeat state-of-art academic attacks.

1. Implement RTTEqualizer (anti-dMAP, NDSS 2025)
2. Implement WFDefense (anti-Website Fingerprinting)
3. Implement CrossLayerCorrelator
4. Implement GeoObfuscator
5. Implement ASAwareRouter

### Phase 5: Fallback & Resilience (Week 9-10)
**Goal**: Steganography and probe resistance.

1. Implement CovertChannelManager + DNSCovertChannel
2. Implement TLSPaddingChannel, HTTPHeaderChannel
3. Implement ProbeHoneypot
4. Full integration testing
5. Panic sequence testing

---

## 14. File Inventory

### Existing (48 files — DO NOT MODIFY unless fixing specific bugs)

See `src/core/include/` directory listing.

### New files to create (14 files)

| File | Module | Phase | Est. Lines |
|------|--------|-------|------------|
| `ncp_master_orchestrator.hpp/.cpp` | MasterOrchestrator | 1 | 800-1000 |
| `ncp_behavioral_cloak.hpp/.cpp` | BehavioralCloak | 2 | 300-400 |
| `ncp_session_pattern.hpp/.cpp` | SessionPatternRandomizer | 2 | 200-300 |
| `ncp_protocol_rotation.hpp/.cpp` | ProtocolRotationSchedule | 2 | 100-150 |
| `ncp_metadata_sanitizer.hpp/.cpp` | MetadataSanitizer | 3 | 200-300 |
| `ncp_volume_normalizer.hpp/.cpp` | VolumeNormalizer | 3 | 150-200 |
| `ncp_session_fragmenter.hpp/.cpp` | SessionFragmenter | 3 | 200-300 |
| `ncp_dns_leak_prevention.hpp/.cpp` | DNSLeakPrevention | 3 | 300-400 |
| `ncp_time_correlation.hpp/.cpp` | TimeCorrelationBreaker | 3 | 200-300 |
| `ncp_rtt_equalizer.hpp/.cpp` | RTTEqualizer | 4 | 300-400 |
| `ncp_wf_defense.hpp/.cpp` | WFDefense | 4 | 400-500 |
| `ncp_cross_layer.hpp/.cpp` | CrossLayerCorrelator | 4 | 200-300 |
| `ncp_geo_obfuscator.hpp/.cpp` | GeoObfuscator | 4 | 200-300 |
| `ncp_as_router.hpp/.cpp` | ASAwareRouter | 4 | 200-300 |
| `ncp_covert_channel.hpp/.cpp` | CovertChannelManager | 5 | 500-700 |
| `ncp_probe_honeypot.hpp/.cpp` | ProbeHoneypot | 5 | 200-300 |

**Total new code**: ~4,000-6,000 lines

---

## 15. Testing Strategy

### Unit tests (per module)

| Module | Test File | Key Tests |
|--------|-----------|----------|
| BehavioralCloak | `test_behavioral_cloak.cpp` | Profile matching, timing distribution |
| RTTEqualizer | `test_rtt_equalizer.cpp` | RTT convergence, delay bounds |
| WFDefense | `test_wf_defense.cpp` | Cluster matching, padding correctness |
| CrossLayerCorrelator | `test_cross_layer.cpp` | Correlation detection, false positive rate |
| SessionFragmenter | `test_session_fragmenter.cpp` | Session duration limits, port rotation |
| DNSLeakPrevention | `test_dns_leak.cpp` | Leak detection, redirect correctness |
| CovertChannelManager | `test_covert_channel.cpp` | Encode/decode roundtrip, capacity |

### Integration tests

| Test | Description |
|------|-------------|
| `test_full_pipeline.cpp` | send() → receive() roundtrip through all stages |
| `test_escalation.cpp` | Threat NONE→CRITICAL→NONE with all stage reactions |
| `test_panic.cpp` | Panic sequence: verify all keys wiped, identity restored |
| `test_ml_resistance.cpp` | Feed traffic to sklearn classifier, verify <50% accuracy |
| `test_dmap_resistance.cpp` | Measure Δ(TCP_RTT, TLS_RTT) after RTTEqualizer |

### CI integration

Add to `.github/workflows/`:
```yaml
- name: Test MasterOrchestrator
  run: ctest --test-dir build -R test_master
```

---

## References

- dMAP: https://www.ndss-symposium.org/ndss-paper/the-discriminative-power-of-cross-layer-rtts-in-fingerprinting-proxy-traffic/
- Palette WF Defense: IEEE S&P 2024 (THU)
- СОРМ-3: https://www.tadviser.ru/index.php/СОРМ
- ТСПУ ML: Forbes.ru 2026-01-18, Habr.com 2026-02-03
- WF Survey: arXiv:2510.11804 (2025)
- Encrypted Traffic Classification: Nature Scientific Reports 2025
