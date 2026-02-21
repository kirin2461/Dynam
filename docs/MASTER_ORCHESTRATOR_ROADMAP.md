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
╔══════════════════════════════════════════════════════════════════════════════════════╗
║              DYNAM NCP v2.0.0 — ОБЪЕДИНЁННЫЙ ПОЛНЫЙ PIPELINE                       ║
║         (pipe.docx + DYNAM_FULL_PIPELINE_DIAGRAM.md → единый поток)                ║
╚══════════════════════════════════════════════════════════════════════════════════════╝


═══════════════════════════════════════════════════════════════════════════════════
 ФАЗА 0: ИНИЦИАЛИЗАЦИЯ (IDENTITY CLOAKING)                [ParanoidMode::start]
═══════════════════════════════════════════════════════════════════════════════════

  ┌─────────────────────┐
  │   ncp run --iface   │  CLI → ArgumentParser → handle_run()
  │     eth0 --preset   │
  │      max_stealth    │
  └─────────┬───────────┘
            │
            ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.1  DEVICE PROFILE SELECTION                              │
  │  DeviceIdentityCloaker::select_profile()                    │
  │                                                             │
  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
  │  │ iPhone15 │  │SamsungS24│  │ Win11    │  │ MacBookPro│   │
  │  │ OUI:F018 │  │ OUI:4C3C │  │ OUI:DC53 │  │ OUI:A483 │   │
  │  │ TTL:64   │  │ TTL:64   │  │ TTL:128  │  │ TTL:64   │   │
  │  │ Win:65535│  │ Win:65535│  │ Win:65535│  │ Win:65535│   │
  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.2  INTERFACE DOWN → ip link set eth0 down                │
  │       Switch CAM aging → забывает реальный MAC              │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.3  NETWORK IDENTITY SPOOFING                             │
  │  NetworkSpoofer::apply()                      [FIX #2]      │
  │                                                             │
  │  ┌─ L2 ─────────────────────────────────────────────────┐  │
  │  │  MAC: F0:18:98:XX:XX:XX (Apple OUI)                  │  │
  │  │  IPv6: ОТКЛЮЧЁН (sysctl disable_ipv6=1)              │  │
  │  │  OUI рандомизация (L2Stealth)                        │  │
  │  └──────────────────────────────────────────────────────┘  │
  │  ┌─ L3 ─────────────────────────────────────────────────┐  │
  │  │  TTL: 64 (iOS)  DF bit: 1                            │  │
  │  └──────────────────────────────────────────────────────┘  │
  │  ┌─ L4 ─────────────────────────────────────────────────┐  │
  │  │  TCP Window: 65535  MSS: 1460  WScale: 6  SACK: on   │  │
  │  └──────────────────────────────────────────────────────┘  │
  │  ┌─ OS Identity ────────────────────────────────────────┐  │
  │  │  Hostname: "iPhone" (opt 12)                         │  │
  │  │  DHCP FP: 1,121,3,6,15,119,252,95,44,46 (opt 55)    │  │
  │  │  Vendor: "Apple" (opt 60)                            │  │
  │  │  SMBIOS: spoofed                                     │  │
  │  └──────────────────────────────────────────────────────┘  │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.4  INTERFACE UP + DHCP                                   │
  │  ip link set eth0 up → dhclient                             │
  │  DHCP Discover → Offer → Request → Ack                      │
  │  Оператор видит: "iPhone подключился"                       │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.5  ARP ANNOUNCEMENT                                      │
  │  ARPController::send_gratuitous_arp()                       │
  │  → Роутер ARP-кэш: 10.0.0.7 = F0:18:98:XX (Apple)         │
  │  → start_arp_keepalive(30s) + start_arp_watcher()           │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.6  DPI BYPASS ENGINE INIT                                │
  │  AdvancedDPIBypass::initialize(config)                      │
  │  AdvancedDPIBypass::apply_max_stealth_preset()              │
  │                                                             │
  │  ✓ EntropyController          ✓ RandomizedTLSFingerprint    │
  │  ✓ GenevaEngine               ✓ DummyPacketInjector         │
  │  ✓ TCPManipulator             ✓ TLSManipulator              │
  │  ✓ TrafficObfuscator          ✓ BehavioralCloak     [#6]    │
  │  ✓ CovertChannelManager                              [#7]   │
  │  ✓ CrossLayerCorrelator                              [#8]   │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  0.7  ENCRYPTED DNS (DoH)                                   │
  │  EncryptedDNSResolver::init("https://1.1.1.1/dns-query")   │
  │  DoHResolver (Cloudflare/Google/Quad9 + cert pin)           │
  │  DNSLeakPrevention — блок plaintext DNS/WebRTC/IPv6  [NEW]  │
  │  Системный DNS → 127.0.0.1 (локальный DoH proxy)           │
  └─────────────────────┬───────────────────────────────────────┘
                        │
                        ▼
          ╔═════════════════════════════════╗
          ║  СИСТЕМА ГОТОВА К РАБОТЕ        ║
          ║  Оператор видит: "iPhone"       ║
          ║  SORM видит: "Apple device"     ║
          ╚═══════════════╤═════════════════╝


═══════════════════════════════════════════════════════════════════════════════════
 ФАЗА 1: ОБРАБОТКА ИСХОДЯЩЕГО ТРАФИКА
═══════════════════════════════════════════════════════════════════════════════════

  Приложение (браузер, мессенджер, etc.)
            │
            │  Данные: "GET / HTTP/1.1\r\nHost: target.com"
            │  Размер: ~80 bytes, Энтропия: ~4.5 bits/byte
            ▼

  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 1: ПРЕДПОЛЁТНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ         [#8]    ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  CrossLayerCorrelator.begin_transaction()                     ┃
  ┃  SecurityMonitor.check_environment()                         ┃
  ┃  ParanoidMode.verify_no_debugger()                           ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 2: СКВОЗНОЕ ШИФРОВАНИЕ (E2E)                          ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  E2ESession.encrypt(peer_id, plaintext)                      ┃
  ┃    Обмен ключами: X25519 + Kyber1024 (пост-квантовый)        ┃
  ┃    AEAD: XChaCha20-Poly1305                                  ┃
  ┃    Double Ratchet ротация каждые 5 мин                       ┃
  ┃  Зависимости: ncp_e2e.hpp, ncp_crypto.hpp, ncp_csprng.hpp   ┃
  ┃                                                              ┃
  ┃  Размер: ~88+ bytes (+nonce + auth tag)                      ┃
  ┃  Энтропия: ~7.95 bits/byte ← ОПАСНО для DPI                 ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 3: ENTROPY MASKING (EntropyController)                ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  1. calculate_bit_density() → 0.50 (опасно для GFW)          ┃
  ┃  2. apply_zero_padding(30%) → +26 bytes нулей                ┃
  ┃  3. inject_ascii_bytes(40%) → printable ASCII                ┃
  ┃  4. prepend length header (4 bytes)                          ┃
  ┃                                                              ┃
  ┃  ┌──────┬────────┬─────────────┬───────────┐                 ┃
  ┃  │ORIG  │ENCRYPT │ASCII-INJECT │ZERO-PAD   │                 ┃
  ┃  │LEN 4B│ ~88B   │  (inline)   │  ~26B     │                 ┃
  ┃  └──────┴────────┴─────────────┴───────────┘                 ┃
  ┃                                                              ┃
  ┃  Размер: ~118 bytes (+34%)                                   ┃
  ┃  Энтропия: ~4.8 bits/byte ← SAFE (выглядит как HTML)        ┃
  ┃  Bit density: 0.38 ← SAFE (не 0.50)                         ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 4: ОРКЕСТРАТОР ПРОТОКОЛОВ (НЕ ИЗМЕНЯТЬ)               ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  Шаг 4.1: AdversarialPadding.pad()                          ┃
  ┃  Шаг 4.2: TrafficMimicry.wrap_payload()                     ┃
  ┃  Шаг 4.3: AdvancedDPIBypass.process_outgoing()              ┃
  ┃  Шаг 4.4: ProbeResist.generate_client_auth()                ┃
  ┃  Шаг 4.5: TLSFingerprint.apply()                            ┃
  ┃           ├─ generate_client_hello("microsoft.com")          ┃
  ┃           ├─ SNI: microsoft.com                              ┃
  ┃           ├─ Cipher Suites: [12 + GREASE, shuffled]          ┃
  ┃           ├─ JA4: уникальный на каждое соединение            ┃
  ┃           └─ Padding: [50-150 bytes random]                  ┃
  ┃  Шаг 4.6: FlowShaper.enqueue()                              ┃
  ┃  Шаг 4.7: ECH.encrypt_client_hello()                        ┃
  ┃  Выход: vector<OrchestratedPacket> (~450-550 bytes)          ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 5: ОБФУСКАЦИЯ + GENEVA + ПОВЕДЕНЧЕСКАЯ МАСКИРОВКА     ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃                                                              ┃
  ┃  5.1 GenevaEngine.apply(best_strategy)          [FIX #1]     ┃
  ┃      Strategy: UNIVERSAL                                     ┃
  ┃      DUPLICATE(0) → 2 пакета                                ┃
  ┃      FRAGMENT(0,64) → 8 фрагментов на пакет                 ┃
  ┃      FRAGMENT(1,64) → ещё 8 фрагментов (копия)              ┃
  ┃      TAMPER_TTL(0) → F01.TTL = random(1-64)                  ┃
  ┃      DISORDER → shuffle all 16 fragments                     ┃
  ┃      Выход: ~16 фрагментов по ~64 bytes (перемешаны)         ┃
  ┃      DPI НЕ МОЖЕТ собрать без TCP reassembly                 ┃
  ┃                                                              ┃
  ┃  5.2 EntropyMasking.mask()                                   ┃
  ┃                                                              ┃
  ┃  5.3 BehavioralCloak.shape_packet()             [NEW #6]     ┃
  ┃                                                              ┃
  ┃  5.4 SessionPatternRandomizer.apply_timing()    [NEW]        ┃
  ┃                                                              ┃
  ┃  5.5 DummyInjector.inject_dummies()                          ┃
  ┃      Profile: HIGH_STEALTH (ratio=1.0)                       ┃
  ┃      [D]=dummy [R]=real                                      ┃
  ┃      ┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐     ┃
  ┃      │D││R││R││D││R││D││R││R││D││R││D││D││R││R││D│      ┃
  ┃      └─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘└─┘     ┃
  ┃      Dummy marker: 0xDEADBEEF + random data (70% ASCII)     ┃
  ┃      Выход: ~30 пакетов (16 real + ~14 dummy)                ┃
  ┃                                                              ┃
  ┃  5.6 TimingObfuscator.apply_jitter()                         ┃
  ┃      Имитация паттерна загрузки веб-страницы:                ┃
  ┃      Packets                                                 ┃
  ┃       ▲                                                      ┃
  ┃      8│ ███                                                  ┃
  ┃      6│ ████                                                 ┃
  ┃      4│ ████                                ███              ┃
  ┃      2│ █████          ███                  ████             ┃
  ┃       └──────────────────────────────────────────→ Time      ┃
  ┃        burst 1      burst 2              burst 3             ┃
  ┃        (page load)  (AJAX)               (navigate)          ┃
  ┃      → ML-классификатор: "обычный web browsing"              ┃
  ┃                                                              ┃
  ┃  5.7 BurstMorpher.morph()                                    ┃
  ┃  5.8 ProtocolMorph.select_profile()                          ┃
  ┃  5.9 RTTEqualizer.equalize_tcp_ack()            [NEW]        ┃
  ┃  5.10 WFDefense.defend()                        [NEW]        ┃
  ┃  5.11 VolumeNormalizer.normalize()              [NEW]        ┃
  ┃  5.12 TimeCorrelationBreaker.break_correlation() [NEW]       ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
           ┌────────────────────┐
           │   threat_level     │
           │   >= CRITICAL?     │
           └───┬────────────┬───┘
           ДА  │            │ НЕТ
               ▼            ▼
  ┌─ СКРЫТЫЙ КАНАЛ (ОТКАТ) ──────┐  ┌─ ОБЫЧНЫЙ ПУТЬ ──────────────┐
  │  CovertChannelManager: [#7]  │  │  (продолжение → STAGE 6)    │
  │  ├─ DNSCovertChannel         │  │                              │
  │  ├─ TLSRecordPadding         │  │                              │
  │  ├─ HTTPHeaderSteg           │  │                              │
  │  └─ HLSVideoSteg             │  │                              │
  └────────────┬─────────────────┘  └──────────┬───────────────────┘
               └──────────┬────────────────────┘
                          │
                          ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 6: ТРАНСПОРТ                                          ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃                                                              ┃
  ┃  6.1 ProtocolRotationSchedule                   [NEW #9]     ┃
  ┃      06-12ч → HTTP/2                                         ┃
  ┃      12-18ч → WebSocket                                      ┃
  ┃      18-02ч → HTTPS                                          ┃
  ┃      02-06ч → rawTLS                                         ┃
  ┃                                                              ┃
  ┃  6.2 ASAwareRouter.select_route()               [NEW]        ┃
  ┃      CDN_RELAY / I2P_GARLIC / WS_TUNNEL / DIRECT            ┃
  ┃                                                              ┃
  ┃  6.3 GeoObfuscator — первый хоп всегда внутренний [NEW]      ┃
  ┃                                                              ┃
  ┃  6.4 SessionFragmenter — макс. 2мин TCP, ротация портов [NEW]┃
  ┃                                                              ┃
  ┃  6.5 I2PManager (SAM v3.3, чесночная маршрутизация)          ┃
  ┃  6.6 DoHResolver (Cloudflare/Google/Quad9 + cert pin)        ┃
  ┃  6.7 WSTunnel + PortKnock                                    ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 7: ИДЕНТИЧНОСТЬ (RUNTIME)                             ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  MetadataSanitizer — ротация NAT, норм. объёма   [NEW]       ┃
  ┃  IdentityRotation — по таймеру (30 мин)                      ┃
  ┃  RotationCoordinator — атомарная синхронизация               ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 8: СЕТЬ (NETWORK OUTPUT)                              ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃                                                              ┃
  ┃  L3Stealth — манипуляция TTL/window/checksum                 ┃
  ┃  ARPManager — отравление ARP-кэша (LAN)                      ┃
  ┃  PacketInterceptor — WinDivert/WFP/raw          [FIX #3]     ┃
  ┃                                                              ┃
  ┃  ┌─ Ethernet Frame ────────────────────────────────────┐     ┃
  ┃  │ Src MAC: F0:18:98:XX:XX:XX (Apple)                  │     ┃
  ┃  │ Dst MAC: [router MAC]                               │     ┃
  ┃  ├─ IP Header ─────────────────────────────────────────┤     ┃
  ┃  │ Src IP: 10.0.0.7  Dst IP: 104.16.XX.XX (CDN)       │     ┃
  ┃  │ TTL: 64 (iOS)                                       │     ┃
  ┃  ├─ TCP Header ────────────────────────────────────────┤     ┃
  ┃  │ Dst Port: 443  Window: 65535 (iOS)                   │     ┃
  ┃  ├─ TLS ───────────────────────────────────────────────┤     ┃
  ┃  │ SNI: microsoft.com   JA4: [Chrome-like]              │     ┃
  ┃  │ Payload: [entropy-masked E2E-encrypted fragment]     │     ┃
  ┃  └─────────────────────────────────────────────────────┘     ┃
  ┃                                                              ┃
  ┃  NetworkBackend.send_raw()                                   ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  STAGE 9: ПОСТПОЛЁТНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ         [#8]    ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  CrossLayerCorrelator.end_transaction()                      ┃
  ┃  ProbeHoneypot — обратный прокси к реальному серверу  [NEW]  ┃
  ┃  SecurityMonitor.log_send()                                  ┃
  ┗━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                  ПРОВОД
                    │
  → Оператор/ТСПУ видит: "iPhone → Cloudflare (HTTPS)"
  → SORM видит: "Apple device, web browsing"
  → ML-классификатор: "Web browsing pattern, не VPN"


═══════════════════════════════════════════════════════════════════════════════════
 ФАЗА 2: ОБРАБОТКА ВХОДЯЩЕГО ТРАФИКА                      [process_incoming]
═══════════════════════════════════════════════════════════════════════════════════

  Cloudflare CDN ──→ наш интерфейс
            │
            ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  IN.1  FILTER DUMMY PACKETS                                 │
  │        DummyPacketInjector::filter_dummy_packets()          │
  │        packet[0:4] == 0xDEADBEEF ? → DROP                  │
  │                                                             │
  │  IN.2  DEOBFUSCATE                                          │
  │        TrafficObfuscator::deobfuscate()                     │
  │        Извлечь nonce (8 bytes) → ChaCha20 decrypt           │
  │                                                             │
  │  IN.3  UNMASK ENTROPY                                       │
  │        EntropyController::unmask_entropy()                   │
  │        Извлечь original_length (4 bytes) → trim padding     │
  │                                                             │
  │  IN.4  E2E DECRYPT                                          │
  │        E2ESession.decrypt(peer_id, ciphertext)              │
  │        XChaCha20-Poly1305 verify tag + decrypt              │
  │        Double Ratchet advance                                │
  │        → Оригинальные данные приложения                     │
  └─────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════════
 ФАЗА 3: ПЕРИОДИЧЕСКАЯ РОТАЦИЯ ИДЕНТИЧНОСТИ   [IdentityRotation, каждые 15-30 мин]
═══════════════════════════════════════════════════════════════════════════════════

  ┌──────────────────────────────────────────────────────────────┐
  │  TIMER: 15-30 минут (configurable)                           │
  │                                                              │
  │  R.1  Сохранить состояние сессий (E2E ratchet state)         │
  │  R.2  DHCP Release (отпустить IP)                            │
  │  R.3  Interface DOWN                                         │
  │  R.4  Выбрать НОВЫЙ профиль устройства (другой OUI)          │
  │  R.5  Применить: MAC + hostname + DHCP FP + TTL + Window     │
  │       + SMBIOS (NetworkSpoofer + L2Stealth)                  │
  │  R.6  Пауза 60-180 секунд (anti-correlation)                │
  │  R.7  Interface UP → DHCP Discover → новый IP                │
  │  R.8  Gratuitous ARP → закрепить новый MAC                   │
  │  R.9  RotationCoordinator — атомарная синхронизация           │
  │  R.10 Восстановить сессии через новый tunnel                 │
  │  R.11 CrossLayerCorrelator — проверка отсутствия корреляций  │
  │                                                              │
  │  Для оператора: "iPhone отключился, Galaxy подключился"      │
  │  Для СОРМ: два РАЗНЫХ устройства, нет корреляции             │
  └──────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════════
 ФАЗА 4: GRACEFUL SHUTDOWN                          [handle_stop / SIGINT]
═══════════════════════════════════════════════════════════════════════════════════

  SIGINT / SIGTERM / ncp stop
            │
            ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  S.1  STOP THREADS                                           │
  │       ARP keepalive/watcher, DPI bypass, Identity rotation   │
  │       CrossLayerCorrelator, SessionPatternRandomizer         │
  │                                                              │
  │  S.2  SECURE MEMORY CLEANUP                                  │
  │       sodium_memzero() на все ключи                          │
  │       E2E session keys + ratchet state → зануление           │
  │       munlock() разблокировать страницы памяти               │
  │                                                              │
  │  S.3  NETWORK CLEANUP                                        │
  │       DHCP Release → Interface DOWN                          │
  │                                                              │
  │  S.4  RESTORE ORIGINAL IDENTITY                              │
  │       Реальный MAC, hostname, sysctl (TTL/Window/IPv6)       │
  │       Interface UP → DHCP → IP с реальным MAC                │
  │                                                              │
  │  S.5  LOG CLEANUP                                            │
  │       Удалить /tmp/ncp_dhclient.conf                         │
  │       Очистить dmesg логи (если root)                        │
  │       Очистить bash_history                                  │
  └──────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════════
 ФОНОВЫЕ ПРОЦЕССЫ (параллельно во время Фаз 1-3)
═══════════════════════════════════════════════════════════════════════════════════

  Thread 1: ARP Keepalive
  ├─ Каждые 30с: Gratuitous ARP → поддерживать MAC в кэше роутера
  └─ При проб от IDS: автоответ с поддельным MAC

  Thread 2: Identity Rotation Timer
  ├─ Каждые 15-30 мин: полная ротация MAC/hostname/DHCP/TTL/SMBIOS
  └─ Пауза 60-180с между старой и новой идентичностью

  Thread 3: Anti-Probing Defense (ProbeHoneypot)               [NEW]
  ├─ Слушать входящие TLS подключения
  ├─ Без PSK → проксировать на microsoft.com (fallback)
  └─ С PSK → обрабатывать как туннель

  Thread 4: Statistics Collector
  ├─ MimicStats: overhead, packets wrapped/unwrapped
  ├─ GenevaStats: packets duplicated/fragmented
  ├─ DummyInjectorStats: real vs dummy packets
  └─ EntropyController: before/after entropy values

  Thread 5: CrossLayerCorrelator                               [NEW #8]
  ├─ Мониторинг корреляций между слоями в реальном времени
  └─ Алерт при обнаружении утечки метаданных

  Thread 6: SessionPatternRandomizer                           [NEW]
  └─ Рандомизация тайминга сессий


═══════════════════════════════════════════════════════════════════════════════════
 ЧТО ВИДИТ ОПЕРАТОР НА КАЖДОМ УРОВНЕ
═══════════════════════════════════════════════════════════════════════════════════

  ┌─────────────────┬────────────────────────────────────────────┐
  │ Уровень         │ Что видит оператор                         │
  ├─────────────────┼────────────────────────────────────────────┤
  │ L1 Физический   │ Порт коммутатора (не скрыть)               │
  │ L2 Канальный    │ MAC: F0:18:98:XX (Apple Inc.)              │
  │ L3 Сетевой      │ IP: 10.0.0.7 → 104.16.XX.XX (Cloudflare)  │
  │                 │ TTL: 64 (iOS)                              │
  │ L4 Транспортный │ TCP :443, Window 65535 (iOS)               │
  │ L5 Сессионный   │ TLS 1.3, SNI: microsoft.com, ECH           │
  │                 │ JA4: Chrome-like fingerprint                │
  │ L7 Прикладной   │ ████████ (E2E + XChaCha20-Poly1305)       │
  ├─────────────────┼────────────────────────────────────────────┤
  │ DHCP лог        │ "iPhone" получил 10.0.0.7                  │
  │ DNS лог         │ (пусто — DoH + leak prevention)            │
  │ SORM-3          │ "Apple device, HTTPS browsing to CDN"      │
  │ ТСПУ (DPI)      │ "TLS 1.3 к microsoft.com через Cloudflare" │
  │ ML-классификатор│ "Web browsing pattern, не VPN"             │
  │ Timing analysis │ "Нормальные burst-паттерны"        [NEW]   │
  │ Volume analysis │ "Нормализованные объёмы"           [NEW]   │
  │ Correlation     │ "Нет межслойных корреляций"        [NEW]   │
  └─────────────────┴────────────────────────────────────────────┘

  Вердикт оператора: ЛЕГИТИМНЫЙ ТРАФИК ✓


═══════════════════════════════════════════════════════════════════════════════════
 ФАЗА 5: ТЕСТОВЫЙ СТЕНД САМОДИАГНОСТИКИ          [SelfTestBench — ncp selftest]
═══════════════════════════════════════════════════════════════════════════════════

  Цель: атаковать СОБСТВЕННЫЙ трафик, чтобы найти дыры ДО того, как их
  найдёт ТСПУ/РКН. Три скрипта + один thread в pipeline.

  ┌─────────────────────────────────────────────────────────────┐
  │  ЗАПУСК:  ncp selftest --iface eth0 --duration 3600        │
  │           ncp selftest --pcap capture.pcap                 │
  │                                                             │
  │  Режимы:                                                    │
  │    --live    захват с интерфейса в реальном времени          │
  │    --pcap    анализ ранее записанного дампа                  │
  │    --full    все 5 тестов последовательно                    │
  │    --quick   только TEST 1 + TEST 2 (~2 мин)               │
  └─────────────────────────────────────────────────────────────┘


  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  TEST 1: dMAP / RTT FINGERPRINT                              ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  Файл: tools/selftest/test_rtt.py (~100 строк)              ┃
  ┃                                                              ┃
  ┃  Что делает:                                                 ┃
  ┃    1. Из pcap извлекает TCP_RTT (SYN→SYN/ACK) для каждого   ┃
  ┃       flow и App_RTT (TLS request→response)                  ┃
  ┃    2. Вычисляет Δ = App_RTT − TCP_RTT                        ┃
  ┃    3. Строит гистограмму Δ для:                              ┃
  ┃       ├─ трафика через пайплайн (NCP)                        ┃
  ┃       └─ прямого HTTPS (baseline)                            ┃
  ┃    4. Считает KS-test (Kolmogorov-Smirnov) между ними       ┃
  ┃                                                              ┃
  ┃  Метрики:                                                    ┃
  ┃    ┌──────────────┬────────────┬────────────┐                ┃
  ┃    │ Метрика      │ PASS       │ FAIL       │                ┃
  ┃    ├──────────────┼────────────┼────────────┤                ┃
  ┃    │ KS p-value   │ > 0.05     │ ≤ 0.05     │                ┃
  ┃    │ mean(Δ) diff │ < 10ms     │ ≥ 10ms     │                ┃
  ┃    │ var(Δ) ratio │ 0.5 - 2.0  │ вне        │                ┃
  ┃    └──────────────┴────────────┴────────────┘                ┃
  ┃                                                              ┃
  ┃  Если FAIL → RTTEqualizer не работает или не включён         ┃
  ┃  Зависимости: scapy, scipy.stats, numpy                     ┃
  ┃                                                              ┃
  ┃  Пример вывода:                                              ┃
  ┃  ┌──────────────────────────────────────────────────┐        ┃
  ┃  │  [TEST 1] dMAP RTT Fingerprint                   │        ┃
  ┃  │  Flows analyzed: 247                              │        ┃
  ┃  │  mean(Δ_ncp)  = 14.3ms                            │        ┃
  ┃  │  mean(Δ_direct)= 2.1ms                            │        ┃
  ┃  │  KS statistic = 0.73, p-value = 0.0001            │        ┃
  ┃  │  ❌ FAIL — proxy clearly detectable by dMAP       │        ┃
  ┃  │  → Включить RTTEqualizer (Stage 5.9)             │        ┃
  ┃  └──────────────────────────────────────────────────┘        ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  TEST 2: VPN-vs-WEB КЛАССИФИКАТОР (простой ML)               ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  Файл: tools/selftest/test_vpn_detect.py (~150 строк)       ┃
  ┃                                                              ┃
  ┃  Что делает:                                                 ┃
  ┃    1. Из pcap извлекает для каждого flow 15 фич:             ┃
  ┃       ├─ mean_pkt_size, std_pkt_size                         ┃
  ┃       ├─ mean_iat, std_iat (inter-arrival time)              ┃
  ┃       ├─ up_down_ratio (bytes up / bytes down)               ┃
  ┃       ├─ max_burst_size, burst_count                         ┃
  ┃       ├─ idle_gap_count, max_idle_gap                        ┃
  ┃       ├─ session_duration                                    ┃
  ┃       ├─ mean_entropy (payload Shannon entropy)              ┃
  ┃       ├─ pkt_count, total_bytes                              ┃
  ┃       └─ unique_dst_ports, unique_dst_ips                    ┃
  ┃                                                              ┃
  ┃    2. Метки: NCP=1, обычный_HTTPS=0                          ┃
  ┃    3. sklearn RandomForestClassifier(n_estimators=100)       ┃
  ┃       5-fold cross-validation                                ┃
  ┃                                                              ┃
  ┃  Метрики:                                                    ┃
  ┃    ┌──────────────────┬────────────┬────────────┐            ┃
  ┃    │ Метрика          │ PASS       │ FAIL       │            ┃
  ┃    ├──────────────────┼────────────┼────────────┤            ┃
  ┃    │ Accuracy         │ < 65%      │ ≥ 65%      │            ┃
  ┃    │ ROC-AUC          │ < 0.70     │ ≥ 0.70     │            ┃
  ┃    │ TPR @ 1% FPR     │ < 10%      │ ≥ 10%      │            ┃
  ┃    └──────────────────┴────────────┴────────────┘            ┃
  ┃                                                              ┃
  ┃  Feature importance → показывает КАКОЙ фичой ты светишься:   ┃
  ┃  ┌──────────────────────────────────────────────────┐        ┃
  ┃  │  [TEST 2] VPN Detection Classifier               │        ┃
  ┃  │  Flows: 500 NCP + 500 direct                      │        ┃
  ┃  │  Accuracy: 58.2% (5-fold CV)                      │        ┃
  ┃  │  ROC-AUC:  0.61                                   │        ┃
  ┃  │  TPR@1%FPR: 3.2%                                  │        ┃
  ┃  │  ✅ PASS — трафик неотличим от обычного HTTPS     │        ┃
  ┃  │                                                    │        ┃
  ┃  │  Top features (если бы FAIL):                      │        ┃
  ┃  │    1. mean_iat (0.23) → TimingObfuscator           │        ┃
  ┃  │    2. burst_count (0.18) → BurstMorpher             │        ┃
  ┃  │    3. mean_entropy (0.15) → EntropyMasking          │        ┃
  ┃  └──────────────────────────────────────────────────┘        ┃
  ┃                                                              ┃
  ┃  Зависимости: scapy, sklearn, numpy                         ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  TEST 3: WEBSITE FINGERPRINTING                              ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  Файл: tools/selftest/test_wf.py (~200 строк)              ┃
  ┃                                                              ┃
  ┃  Что делает:                                                 ┃
  ┃    1. Для каждого из N сайтов (default: 20) собирает         ┃
  ┃       трассы (50+ визитов через пайплайн)                    ┃
  ┃    2. Извлекает sequence features:                           ┃
  ┃       ├─ signed packet sizes (up=+, down=−)                  ┃
  ┃       ├─ inter-packet delays                                 ┃
  ┃       ├─ cumulative bytes curve                              ┃
  ┃       └─ burst statistics                                    ┃
  ┃    3. Обучает kNN (k=5) + RandomForest на site labels        ┃
  ┃                                                              ┃
  ┃  Метрики:                                                    ┃
  ┃    ┌────────────────────┬──────────────┬──────────────┐      ┃
  ┃    │ Метрика            │ PASS         │ FAIL         │      ┃
  ┃    ├────────────────────┼──────────────┼──────────────┤      ┃
  ┃    │ Top-1 accuracy     │ < 15%        │ ≥ 15%        │      ┃
  ┃    │ (при 20 сайтах     │ (random=5%)  │              │      ┃
  ┃    │  random baseline)  │              │              │      ┃
  ┃    │ Top-5 accuracy     │ < 40%        │ ≥ 40%        │      ┃
  ┃    └────────────────────┴──────────────┴──────────────┘      ┃
  ┃                                                              ┃
  ┃  Пример вывода:                                              ┃
  ┃  ┌──────────────────────────────────────────────────┐        ┃
  ┃  │  [TEST 3] Website Fingerprinting                  │        ┃
  ┃  │  Sites: 20, Traces per site: 50                   │        ┃
  ┃  │  Top-1 accuracy: 11.3%  (random: 5.0%)           │        ┃
  ┃  │  Top-5 accuracy: 31.2%  (random: 25.0%)          │        ┃
  ┃  │  ✅ PASS — сайты неразличимы через туннель       │        ┃
  ┃  │                                                    │        ┃
  ┃  │  Если FAIL, наиболее различимые сайты:            │        ┃
  ┃  │    youtube.com  (acc=67%) → VolumeNormalizer       │        ┃
  ┃  │    vk.com       (acc=43%) → BurstMorpher            │        ┃
  ┃  └──────────────────────────────────────────────────┘        ┃
  ┃                                                              ┃
  ┃  Зависимости: scapy, sklearn, numpy                         ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  TEST 4: SORM METADATA ANOMALY                               ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  Файл: tools/selftest/test_sorm_meta.py (~120 строк)        ┃
  ┃                                                              ┃
  ┃  Что делает:                                                 ┃
  ┃    Симулирует взгляд аналитика СОРМ на метаданные:           ┃
  ┃    1. Из pcap генерирует «лог СОРМ»:                         ┃
  ┃       ├─ sessions: src_ip, dst_ip, port, bytes, duration     ┃
  ┃       ├─ DNS queries (если утекли)                           ┃
  ┃       └─ connection frequency / timing                       ┃
  ┃                                                              ┃
  ┃    2. Проверяет эвристики:                                   ┃
  ┃       ├─ Есть ли plaintext DNS? (→ DNSLeakPrevention)        ┃
  ┃       ├─ Сессии > 2мин? (→ SessionFragmenter)                ┃
  ┃       ├─ > 70% трафика к 1 IP/AS? (→ ASAwareRouter)         ┃
  ┃       ├─ Нет idle gaps > 5мин? (→ SessionPatternRandomizer)  ┃
  ┃       ├─ Аномальная регулярность? (→ TimeCorrelationBreaker) ┃
  ┃       └─ Объём за час > 2σ от нормы? (→ VolumeNormalizer)   ┃
  ┃                                                              ┃
  ┃    3. DBSCAN кластеризация «абонентов»                       ┃
  ┃       (NCP-абонент vs обычные)                               ┃
  ┃                                                              ┃
  ┃  Метрики:                                                    ┃
  ┃    ┌──────────────────────┬────────────┬────────────┐        ┃
  ┃    │ Проверка             │ PASS       │ FAIL       │        ┃
  ┃    ├──────────────────────┼────────────┼────────────┤        ┃
  ┃    │ Plaintext DNS        │ 0 запросов │ > 0        │        ┃
  ┃    │ Max session duration │ ≤ 120s     │ > 120s     │        ┃
  ┃    │ Single-dest ratio    │ < 70%      │ ≥ 70%      │        ┃
  ┃    │ Min idle gap         │ ≥ 1 за час │ 0          │        ┃
  ┃    │ Timing regularity    │ CV > 0.3   │ CV ≤ 0.3   │        ┃
  ┃    │ DBSCAN cluster       │ mixed      │ isolated   │        ┃
  ┃    └──────────────────────┴────────────┴────────────┘        ┃
  ┃  (CV = coefficient of variation межсессионных интервалов)    ┃
  ┃                                                              ┃
  ┃  Зависимости: scapy, sklearn (DBSCAN), numpy                ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                    │
                    ▼
  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  TEST 5: FINGERPRINT FRESHNESS                               ┃
  ┃  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ┃
  ┃  Файл: tools/selftest/test_fingerprint_age.py (~80 строк)   ┃
  ┃                                                              ┃
  ┃  Что делает:                                                 ┃
  ┃    Проверяет актуальность всех профилей маскировки:          ┃
  ┃                                                              ┃
  ┃    1. JA3/JA4 — сравнивает с актуальными базами:             ┃
  ┃       ├─ Скачать ja3er.com top-50 fingerprints               ┃
  ┃       ├─ Наш JA3 есть в top-50? → PASS                      ┃
  ┃       └─ Наш JA3 в top-50 полгода назад, но не сейчас? WARN │
  ┃                                                              ┃
  ┃    2. DHCP fingerprint — сравнить с fingerbank.org:           ┃
  ┃       ├─ Наш DHCP FP → определяется как "iPhone 15"? PASS   ┃
  ┃       └─ Определяется как "Unknown"? → FAIL                  ┃
  ┃                                                              ┃
  ┃    3. TCP/IP stack fingerprint (p0f-style):                  ┃
  ┃       ├─ TTL + Window + MSS + WScale + options order         ┃
  ┃       ├─ Соответствует заявленной ОС? → PASS                 ┃
  ┃       └─ Конфликт (TTL=64 но Window=65535+WScale=8)? → FAIL │
  ┃                                                              ┃
  ┃    4. Возраст профиля:                                       ┃
  ┃       ├─ Профиль обновлён < 60 дней назад? → PASS            ┃
  ┃       ├─ 60-120 дней? → WARN                                 ┃
  ┃       └─ > 120 дней? → FAIL (устарел)                        ┃
  ┃                                                              ┃
  ┃  Метрики:                                                    ┃
  ┃    ┌─────────────────────┬────────────┬────────────┐         ┃
  ┃    │ Проверка            │ PASS       │ FAIL       │         ┃
  ┃    ├─────────────────────┼────────────┼────────────┤         ┃
  ┃    │ JA3 in top-50       │ ✓          │ ✗          │         ┃
  ┃    │ JA4 consistency     │ match      │ mismatch   │         ┃
  ┃    │ DHCP→device match   │ correct OS │ unknown/   │         ┃
  ┃    │                     │            │ wrong OS   │         ┃
  ┃    │ p0f OS match        │ correct    │ conflict   │         ┃
  ┃    │ Profile age         │ < 60 days  │ > 120 days │         ┃
  ┃    └─────────────────────┴────────────┴────────────┘         ┃
  ┃                                                              ┃
  ┃  Зависимости: requests (для ja3er.com API), json             ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛


  ┌─────────────────────────────────────────────────────────────┐
  │  СВОДНЫЙ ОТЧЁТ                                              │
  │                                                              │
  │  ncp selftest --full выводит:                                │
  │                                                              │
  │  ╔══════════════════════════════════════════════════════╗    │
  │  ║  NCP SELF-TEST REPORT — 2026-02-21 10:50 MSK        ║    │
  │  ╠══════════════════════════════════════════════════════╣    │
  │  ║  TEST 1  dMAP RTT         ❌ FAIL  (Δ=12.1ms)       ║    │
  │  ║  TEST 2  VPN Classifier   ✅ PASS  (acc=57%)        ║    │
  │  ║  TEST 3  Website FP       ✅ PASS  (top1=9%)        ║    │
  │  ║  TEST 4  SORM Metadata    ⚠️ WARN  (session>120s)   ║    │
  │  ║  TEST 5  FP Freshness     ✅ PASS  (age=12 days)    ║    │
  │  ╠══════════════════════════════════════════════════════╣    │
  │  ║  OVERALL: 2/5 PASS, 1 WARN, 1 FAIL                  ║    │
  │  ║                                                      ║    │
  │  ║  РЕКОМЕНДАЦИИ:                                       ║    │
  │  ║  1. Включить RTTEqualizer (Stage 5.9)                ║    │
  │  ║  2. Уменьшить max_session в SessionFragmenter        ║    │
  │  ╚══════════════════════════════════════════════════════╝    │
  └─────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════════
 ФОНОВЫЙ SELF-TEST (Thread 7)                       [SelfTestMonitor — continuous]
═══════════════════════════════════════════════════════════════════════════════════

  Thread 7: SelfTestMonitor (непрерывный мониторинг)            [NEW]
  ├─ Каждые 10 мин: мини-TEST 1 (RTT check на последних 100 flows)
  ├─ Каждые 30 мин: мини-TEST 2 (feature extraction на скользящем окне)
  ├─ Каждые 60 мин: TEST 5 (fingerprint freshness check)
  ├─ При обнаружении FAIL:
  │   ├─ CrossLayerCorrelator.alert("selftest_fail", test_id)
  │   ├─ Если TEST 1 FAIL → автоматически включить RTTEqualizer
  │   ├─ Если TEST 2 FAIL → поднять threat_level на один уровень
  │   ├─ Если TEST 5 FAIL → форсировать ротацию профиля
  │   └─ Логировать в encrypted audit log
  └─ Данные для тестов берутся из PacketInterceptor ring buffer
     (последние 10000 пакетов, без записи на диск)


═══════════════════════════════════════════════════════════════════════════════════
 МАТРИЦА ДЕТЕКТИРУЕМОСТИ                          [Detection Matrix — reference]
═══════════════════════════════════════════════════════════════════════════════════

  ┌──────────────────────┬──────────┬───────────┬─────────┬───────────────────────┐
  │ Вектор атаки         │ Без NCP  │ С NCP     │ Статус  │ Модуль защиты         │
  │                      │          │ (полный)  │         │                       │
  ├──────────────────────┼──────────┼───────────┼─────────┼───────────────────────┤
  │ Сигнатура протокола  │ ❌ виден │ ✅ скрыт  │ Готов   │ TrafficMimicry        │
  │ SNI inspection       │ ❌ виден │ ✅ скрыт  │ Готов   │ ECH                   │
  │ JA3/JA4 fingerprint  │ ❌ виден │ ✅ скрыт  │ Готов   │ TLSFingerprint        │
  │ Энтропия payload     │ ❌ 7.95  │ ✅ 4.8    │ Готов   │ EntropyMasking        │
  │ Active probing       │ ❌ виден │ ✅ скрыт  │ Готов   │ ProbeResist+Honeypot  │
  │ Burst patterns       │ ⚠️ частич│ ✅ скрыт  │ Готов   │ BurstMorpher          │
  │ Timing patterns      │ ❌ виден │ ✅ скрыт  │ Готов   │ TimingObfuscator      │
  │ Session duration     │ ❌ 24/7  │ ✅ 2мин   │ [NEW]   │ SessionFragmenter     │
  │ DNS leaks            │ ❌ виден │ ✅ скрыт  │ [NEW]   │ DNSLeakPrevention     │
  │ Volume fingerprint   │ ❌ виден │ ⚠️ частич │ [NEW]   │ VolumeNormalizer      │
  │ Timestamp correlation│ ❌ виден │ ⚠️ частич │ [NEW]   │ TimeCorrelationBreaker│
  │ dMAP (RTT)           │ ❌ 96%   │ ⚠️ ~70%?  │ [NEW]   │ RTTEqualizer          │
  │ Website FP           │ ❌ 95%   │ ⚠️ ~15%?  │ [NEW]   │ WFDefense             │
  │ ML flow classifier   │ ❌ 90%+  │ ⚠️ ~58%?  │ [NEW]   │ BehavioralCloak       │
  │ Cross-layer корр.    │ ❌ виден │ ✅ скрыт  │ [NEW]   │ CrossLayerCorrelator  │
  │ Dest IP (AS/geo)     │ ❌ виден │ ⚠️ частич │ [NEW]   │ GeoObfuscator+AS     │
  │ Абонент (договор)    │ ❌ виден │ ❌ виден  │ N/A     │ (физический уровень)  │
  └──────────────────────┴──────────┴───────────┴─────────┴───────────────────────┘

  Обозначения:
    ✅ скрыт  — модуль реализован и работает, детекция маловероятна
    ⚠️ частич — модуль есть, но нет эмпирической проверки (нужен selftest)
    ❌ виден  — не защищено / невозможно защитить на уровне софта
    [NEW]     — модуль спроектирован, ещё не реализован
    ?         — оценка предварительная, требует TEST 1-5 для подтверждения


═══════════════════════════════════════════════════════════════════════════════════
 ФАЙЛОВАЯ СТРУКТУРА ТЕСТОВОГО СТЕНДА
═══════════════════════════════════════════════════════════════════════════════════

  tools/selftest/
  ├── __init__.py
  ├── test_rtt.py                  # TEST 1: dMAP RTT fingerprint
  ├── test_vpn_detect.py           # TEST 2: VPN-vs-Web classifier
  ├── test_wf.py                   # TEST 3: Website fingerprinting
  ├── test_sorm_meta.py            # TEST 4: SORM metadata anomaly
  ├── test_fingerprint_age.py      # TEST 5: Fingerprint freshness
  ├── feature_extractor.py         # Общий экстрактор фич из pcap
  ├── report_generator.py          # Генерация сводного отчёта
  ├── requirements.txt             # scapy, sklearn, scipy, numpy
  └── README.md                    # Инструкция по запуску

  src/core/include/
  └── ncp_selftest_monitor.hpp     # Thread 7: непрерывный мониторинг

  src/core/src/
  └── ncp_selftest_monitor.cpp     # Реализация SelfTestMonitor

  Общий объём: ~800 строк Python + ~300 строк C++


═══════════════════════════════════════════════════════════════════════════════════
 МАППИНГ ИСТОЧНИКОВ (откуда что взято)
═══════════════════════════════════════════════════════════════════════════════════

  ┌────────────────────────────────┬──────────┬──────────────────┐
  │ Компонент                      │ pipe.docx│ DYNAM_FULL v1.1  │
  ├────────────────────────────────┼──────────┼──────────────────┤
  │ Фаза 0 (инициализация)        │          │        ✓         │
  │ STAGE 1 (security pre-flight)  │    ✓     │                  │
  │ STAGE 2 (E2E encryption)       │    ✓     │   ✓ (ChaCha20)   │
  │ STAGE 3 (entropy masking)      │    ✓     │        ✓         │
  │ STAGE 4 (orchestrator)         │    ✓     │   ✓ (TLS wrapper)│
  │ STAGE 5 (obfuscation+Geneva)   │    ✓     │        ✓         │
  │ Covert Channels                │    ✓     │                  │
  │ STAGE 6 (transport)            │    ✓     │                  │
  │ STAGE 7 (identity runtime)     │    ✓     │                  │
  │ STAGE 8 (network output)       │    ✓     │        ✓         │
  │ STAGE 9 (security post-flight) │    ✓     │                  │
  │ Входящий трафик                │          │        ✓         │
  │ Ротация идентичности           │    ✓     │        ✓         │
  │ Graceful shutdown              │          │        ✓         │
  │ Фоновые процессы               │    ✓     │        ✓         │
  │ Таблица "что видит оператор"   │    ✓     │        ✓         │
  └────────────────────────────────┴──────────┴──────────────────┘
```


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
