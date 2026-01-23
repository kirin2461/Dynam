# NCP C++ - Network Control Protocol

> Professional C++ implementation of the Network Control Protocol with high-performance cryptography, DPI bypass, and license management.

## 🚀 Features

- **Core Library (libncp_core)**
  - Modern C++17 implementation
  - Ed25519, Curve25519, ChaCha20-Poly1305 cryptography
  - Hardware ID-based offline license validation
  - SQLite3 + SQLCipher encrypted database
  - libpcap-based network packet capture and raw socket operations

- **CLI Tool**
  - Command-line interface for automation
  - Cryptographic operations (keygen, signing, encryption)
  - License validation and HWID detection
  - Network interface enumeration

- **Extensible Architecture**
  - Static library for embedding in other projects
  - Well-defined C++ API
  - Cross-platform (Windows, Linux, macOS)
  - CMake-based build system

## 📋 Build Status

[![NCP C++ CI/CD](https://github.com/kirin2461/ncp-cpp/workflows/NCP%20C%2B%2B%20CI%2FCD/badge.svg)](https://github.com/kirin2461/ncp-cpp/actions)

| Platform | Status |
|----------|--------|
| Linux    | ✅ Building |
| macOS    | ✅ Building |
| Windows  | ✅ Building |

## 🛠️ Quick Start

### Prerequisites

```bash
# Linux (Ubuntu/Debian)
sudo apt-get install -y cmake build-essential git python3-pip
pip3 install conan

# macOS
brew install cmake conan

# Windows
# Install Visual Studio 2019+, CMake 3.20+, Python, and Conan
pip install conan
```

### Build

```bash
git clone https://github.com/kirin2461/ncp-cpp.git
cd ncp-cpp

mkdir build && cd build
conan install .. --build=missing
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
cmake --build . -j$(nproc)
ctest --output-on-failure
```

See [BUILD.md](docs/BUILD.md) for detailed build instructions.

## 📦 Usage

### CLI Tool

```bash
# Generate Ed25519 keypair
./build/bin/ncp crypto keygen

# Get system HWID
./build/bin/ncp license hwid

# List network interfaces
./build/bin/ncp network interfaces

# Generate random bytes
./build/bin/ncp crypto random 32
```

### As a Library

```cpp
#include "ncp_core/ncp_crypto.hpp"

int main() {
    NCP::Crypto crypto;
    
    // Generate keypair
    auto kp = crypto.generate_keypair();
    
    // Sign message
    std::string message = "Hello, World!";
    auto signature = crypto.sign_message(message, kp.secret_key);
    
    // Verify signature
    bool valid = crypto.verify_signature(message, signature, kp.public_key);
    
    return 0;
}
```

## 📂 Project Structure

```
ncp-cpp/
├── src/
│   ├── core/              # Core library (libncp_core)
│   │   ├── include/       # Public headers
│   │   └── src/           # Implementation
│   ├── gui/               # Qt6 GUI (Phase 4)
│   └── cli/               # CLI tool
├── tests/                 # Unit tests
├── docs/                  # Documentation
├── CMakeLists.txt         # Main CMake configuration
└── conanfile.txt          # Conan dependencies
```

## 🔧 Development Phases

### ✅ Phase 1: Infrastructure (Complete)
- CMake + Conan configuration
- Project structure
- Dependency integration
- Unit test framework
- CI/CD pipeline (GitHub Actions)

### 📊 Phase 2: Core Library (Upcoming)
- Implement cryptographic functions (Ed25519, ChaCha20, PBKDF2)
- HWID generation and offline license validation
- SQLCipher database integration
- Complete API documentation

### 🌐 Phase 3: DPI Bypass Module (Upcoming)
- Packet capture with libpcap/Npcap
- Raw socket operations
- Platform-specific network APIs
- Integration tests

### 🎨 Phase 4: Qt6 GUI (Upcoming)
- Qt6 setup and CMake integration
- Dark theme UI
- Dashboard, Settings, License Panel
- libncp_core integration

### 💻 Phase 5: CLI Tool (Upcoming)
- Enhanced command-line interface
- Automation support
- Docker containerization

### 🔬 Phase 6: Testing & Release (Upcoming)
- End-to-end testing
- Multi-platform binary builds
- Installer creation
- User documentation

## 🔐 Security

- **Cryptography**: libsodium (industry-standard, audited)
- **Database**: SQLite3 + SQLCipher (encrypted)
- **Code**: Modern C++17 with memory safety practices
- **Compilation**: No exceptions to warnings policy

## 📝 License

This project is proprietary. All rights reserved.

## 🤝 Contributing

Internal development only. Contact the project maintainer.

## 📞 Support

For issues and questions, please open a GitHub issue.

---

**Last Updated**: January 23, 2026
**Phase**: 1 (Infrastructure) ✅
