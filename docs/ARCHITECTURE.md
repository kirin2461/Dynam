# NCP C++ Architecture

## Overview

NCP C++ is built on a three-layer architecture designed for security, performance, and maintainability.

## Three-Layer Architecture

### Layer 1: Core Library (libncp_core)

**Purpose**: All business logic and cryptographic operations

**Components**:
- **Cryptography Module** (`ncp_crypto.hpp`)
  - Ed25519 key generation and signing
  - Curve25519 key exchange
  - ChaCha20-Poly1305 authenticated encryption
  - Random number generation
  - Integration with libsodium

- **License Management** (`ncp_license.hpp`)
  - Hardware ID (HWID) generation
  - Offline license validation
  - Online license server integration
  - License file generation and parsing
  - Expiration checking

- **Network Operations** (`ncp_network.hpp`)
  - Packet capture (libpcap/Npcap)
  - Raw socket operations
  - DPI evasion techniques
  - Fragmented packet injection
  - Network interface enumeration
  - TCP/UDP manipulation

- **Database Layer** (`ncp_db.hpp`)
  - SQLite3 with SQLCipher encryption
  - Transaction management
  - Query execution and data retrieval
  - Schema management
  - Prepared statements

**Key Features**:
- Statically linked library for easy distribution
- Header-only public interface
- Memory-safe C++17 implementation
- Zero external binary dependencies (except native libs)

### Layer 2: GUI Application (Qt6)

**Status**: Planned for Phase 4

**Purpose**: Cross-platform desktop interface

**Components**:
- Dashboard (monitoring and status)
- Settings panel (configuration)
- License management UI
- Real-time statistics and graphs

**Technologies**:
- Qt6 Widgets (C++)
- Dark theme UI
- Cross-platform (Windows/Linux/macOS)

### Layer 3: CLI Tool

**Status**: Phase 1 (basic structure), Phase 5 (full implementation)

**Purpose**: Command-line automation and scripting

**Features**:
- Cryptographic operations
- License validation
- Network interface management
- System administration tasks
- Docker/CI/CD integration

## Dependency Hierarchy

```
System Libraries (libc, libc++, Kernel APIs)
        ↓
External Dependencies (Conan managed)
    ├─ libsodium (Cryptography)
    ├─ OpenSSL 3 (Additional crypto, TLS)
    ├─ SQLite3 (Database)
    ├─ libpcap (Packet capture)
    └─ GTest (Unit testing)
        ↓
    libncp_core
    (Static Library)
        ↓
    ┌───┴────┬─────────┐
    ↓        ↓         ↓
   Qt6      CLI       Custom
   GUI      Tool      Apps
```

## Build System

### CMake

- **Version**: 3.20+ (modern, modular CMake)
- **Structure**:
  - Root `CMakeLists.txt`: Main configuration, options, subdirectories
  - `src/core/CMakeLists.txt`: Core library build
  - `src/cli/CMakeLists.txt`: CLI tool build
  - `src/gui/CMakeLists.txt`: GUI application build (Phase 4)
  - `tests/CMakeLists.txt`: Unit tests build

### Conan

- **Version**: 2.x
- **Purpose**: C++ dependency management
- **Packages**:
  ```
  libsodium/1.0.18        (Cryptography)
  openssl/3.1.4           (Additional crypto)
  sqlite3/3.44.0          (Database)
  libpcap/1.10.3          (Network capture)
  gtest/1.14.0            (Testing)
  ```

## Module Organization

### `src/core/` Structure

```
src/core/
├── CMakeLists.txt           # Build configuration
├── include/
│   ├── ncp_crypto.hpp       # Public crypto API
│   ├── ncp_license.hpp      # Public license API
│   ├── ncp_network.hpp      # Public network API
│   └── ncp_db.hpp           # Public database API
└── src/
    ├── crypto.cpp           # Crypto implementation
    ├── license.cpp          # License management
    ├── network.cpp          # Network operations
    └── db.cpp               # Database operations
```

## API Design

### Public Interface (Header-Only)

```cpp
// All public APIs in namespace NCP
namespace NCP {
    // Crypto operations
    class Crypto { /* ... */ };
    
    // License management
    class License { /* ... */ };
    
    // Network operations
    class Network { /* ... */ };
    
    // Database access
    class Database { /* ... */ };
}
```

### Usage Pattern

```cpp
#include "ncp_crypto.hpp"
#include "ncp_license.hpp"

int main() {
    try {
        NCP::Crypto crypto;
        auto kp = crypto.generate_keypair();
        
        NCP::License license;
        std::string hwid = license.get_hwid();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
```

## Testing Strategy

### Unit Tests (Google Test)

- **Location**: `tests/` directory
- **Framework**: GTest + CMake
- **Coverage**:
  - Cryptographic functions
  - License validation
  - Database operations
  - Network operations

### CI/CD Pipeline

- **Platform**: GitHub Actions
- **Trigger**: Push to main/develop, Pull requests
- **Matrix**: Ubuntu, macOS, Windows
- **Steps**:
  1. Install dependencies
  2. Install Conan packages
  3. Configure CMake
  4. Build project
  5. Run unit tests
  6. Archive artifacts

## Performance Considerations

- **Memory**: Stack-based allocation for small data, heap for large buffers
- **Cryptography**: libsodium (constant-time, side-channel resistant)
- **Database**: Connection pooling planned for future
- **Network**: Event-driven, non-blocking I/O for capture operations

## Security Design

### Cryptographic Primitives
- **Signatures**: Ed25519 (public-key cryptography)
- **Key Exchange**: Curve25519 (ECDH)
- **Encryption**: ChaCha20-Poly1305 (AEAD)
- **Hashing**: SHA-256 (via OpenSSL)
- **KDF**: PBKDF2 (key derivation)

### Database Security
- **Encryption**: SQLCipher (transparent encryption at rest)
- **Access**: Session-level encryption keys
- **Isolation**: Per-connection encryption context

### License Security
- **HWID Validation**: Hardware fingerprinting
- **Signature Verification**: Ed25519 offline validation
- **Expiration Checking**: Secure timestamp comparison
- **Binding**: License tied to specific hardware

## Future Enhancements

### Phase 2+
- Obfuscation using LLVM passes
- Hardware acceleration (AVX-512 crypto)
- Multi-threaded cryptographic operations
- Advanced DPI evasion techniques
- Machine learning-based threat detection

## Compliance

- **C++ Standard**: C++17
- **Compiler**: GCC 9+, Clang 10+, MSVC 2019+
- **Platforms**: Linux, macOS, Windows (x86_64, ARM64)
- **Code Style**: ClangFormat (configured in .clang-format)
- **Static Analysis**: clang-tidy, cppcheck
