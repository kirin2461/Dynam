# Dynam (NCP C++) - Network Control Protocol

> Multi-layered network anonymization and privacy platform with DPI bypass, traffic spoofing, paranoid mode, and advanced cryptography. Written in modern C++17.

## Current Status

**Version**: 1.5.0-dev (Active Development)
**CMake Version**: 1.5.0 (synced)

> ✅ **MASTER_ORCHESTRATOR 100% COMPLETE**: Full 7-stage pipeline with anti-ML, steganography, and behavioral cloaking implemented.

### Implementation Progress

**MasterOrchestrator — 100% Complete** (13 modules, ~3500 lines):
- ✅ **Phase 1: Core Integration** — MasterOrchestrator, 7-stage pipeline, send/receive API
- ✅ **Phase 2: Anti-ТСПУ ML** — BehavioralCloak, ProtocolRotationSchedule, SessionPatternRandomizer
- ✅ **Phase 3: Anti-СОРМ** — CovertChannelManager (4 channels), CrossLayerCorrelator, GeoObfuscator
- ✅ **Phase 4: Security** — PanicSequence (9 steps), Background Scheduler (8 tasks)

- ✅ **Fully Implemented** (90-100%): Cryptography, DPI Bypass, DPI Advanced (multi-technique pipeline), Network Spoofing, Secure Memory/Buffer, DoH, Database, License, Logging, Configuration, CSPRNG, TLS Fingerprinting (JA3/JA4, browser profiles), Adversarial Padding, Flow Shaping, Probe Resistance, L2 Stealth, L3 Stealth, ARP Spoofing, DHCP Spoofing, Port Knocking, Packet Interceptor, Protocol Morphing, Burst Morphing, Entropy Masking, Geneva Engine/GA, Identity Management, Timing Protection, Thread Pool, Rotation Coordinator, Security Manager, Capabilities Framework.

- ✅ **Security Fixes Applied**:
  - ECH info string mismatch — FIXED (canonical info string)
  - Kyber1024 encaps/decaps swap — FIXED (receiver decapsulates)
  - ECDH_P256 OpenSSL fallback — FIXED (OpenSSL 1.1.1 + 3.0+ support)
  - HMAC salt truncation — FIXED (hash long salts)
  - TLS Fingerprint randomization — FIXED (minor_permute vs secure_shuffle)
  - Timing oracle in auth verification — FIXED (constant-time memcmp)
  - XOR used as HMAC fallback — FIXED (libsodium crypto_auth)

- ⚠️ **Partial / Pending**:
  - I2P Integration — SAM bridge API defined, implementation in progress
  - Traffic Mimicry — Full protocol emulation pending (basic structure complete)
  - Geneva GA integration — Connected to pipeline, evolution pending
  

## Features

### Core Library (libncp_core) — 42 modules

#### Cryptography & Security
- **CSPRNG** (`ncp_csprng.hpp`) — Header-only libsodium wrapper.
- **Cryptography** (`ncp_crypto.hpp`) — Ed25519, Curve25519, ChaCha20-Poly1305.
- **E2E Encryption** (`ncp_e2e.hpp`) — X25519 (working), Kyber1024/P256 (P0 fixes applied).
- **Secure Memory** (`ncp_secure_memory.hpp`) — Memory-safe containers.
- **Security Manager** (`ncp_security.hpp`) — Comprehensive security operations.

#### DPI Bypass & Evasion
- **DPI Advanced** (`ncp_dpi_advanced.hpp`) — 15+ evasion techniques, TCP/TLS manipulation.
- **Geneva Engine** (`ncp_geneva_engine.hpp`) — Genetic algorithm for DPI evasion strategy discovery.
- **TLS Fingerprinting** (`ncp_tls_fingerprint.hpp`) — Browser profile emulation (Chrome/Firefox/Safari/Edge).
- **ECH** (`ncp_ech.hpp`) — Encrypted Client Hello draft with HPKE.

#### Network & Stealth
- **Network Spoofing** (`ncp_spoofer.hpp`) — IPv4/IPv6/MAC/DNS/Hardware spoofing.
- **Paranoid Mode** (`ncp_paranoid.hpp`) — 8-layer protection system.
- **L2/L3 Stealth** — Data link and network layer stealth operations.

### CLI Tool
- ✅ **Working Commands**: `status`, `help`, `run`, `stop`, `rotate`.
- 🚧 **In Development**: `crypto`, `license`, `network`, `dpi`, `i2p`.

## Architecture
- Modern C++17 with `constexpr`/`noexcept` optimization.
- Three-layer architecture: Core Library, CLI, GUI (Planned).
- 7-stage Protocol Orchestrator pipeline.

---
**Last Updated**: March 13, 2026
**Version**: 1.5.0-dev
