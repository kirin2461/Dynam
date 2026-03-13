# NCP C++ Architecture

## Overview
NCP C++ (Dynam) is a multi-layered network anonymization platform built on a three-layer architecture. All code uses the `ncp::` namespace, modern C++17 with `constexpr`/`noexcept` optimization.

> **Note**: Security audit in progress — see [AUDIT.md](../AUDIT.md) for current findings.

## Three-Layer Architecture

### Layer 1: Core Library (libncp_core) — 42 modules
**Purpose**: All network operations, cryptography, anonymization, and security logic.
**49 public headers** in `src/core/include/`, **46 implementation files** in `src/core/src/`.

#### Cryptography & Security
- **CSPRNG**: Libsodium wrapper for cryptographically secure randomness.
- **E2E Encryption**: X25519-based key exchange with Kyber1024 hybrid support.
- **Secure Memory**: RAII-based secure buffers with automatic zeroing and page locking.

#### DPI Bypass & Evasion
- **DPI Advanced**: Multi-technique pipeline (15+ evasion methods).
- **Geneva Subsystem**: Modular engine for evolving evasion strategies (GA + Engine).
- **TLS/ECH**: Browser fingerprinting and Encrypted Client Hello support.

#### Stealth & Defense
- **Paranoid Mode**: Integrated 8-layer protection.
- **Flow Shaper**: Timing and size normalization.
- **License**: GNU AGPLv3


- **L2/L3 Stealth**: Low-level network stealth.

### Layer 2: CLI Tool
**Status**: Core commands implemented (`status`, `help`, `run`, `stop`, `rotate`).
- Built using RAII `Application` class to manage lifecycles.

### Layer 3: GUI Application
**Status**: Planned integration with Qt6 for visual management.

---

## Protocol Orchestrator Pipeline
The Protocol Orchestrator (`ncp_orchestrator.hpp`) chains all protection components:

1. **Send Pipeline**: Payload → TLS FP → DPI Advanced → Adversarial Padding → Mimicry → Flow Shaping → Network.
2. **Receive Pipeline**: Wire → Auth Verify → Dummy Check → Mimicry Unwrap → Unpad → Payload.

---

## Technical Specifications
- **C++ Standard**: C++17
- **Cryptography**: Libsodium (XChaCha20-Poly1305, Ed25519)
- **Networking**: Raw Sockets, libpcap/Npcap
- **Logging**: Internal RAII Logger (Thread-safe)

