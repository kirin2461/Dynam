# NCP C++ - Network Control Protocol

## Overview
NCP (Network Control Protocol) is a C++ CLI tool for network management, including network spoofing, DPI bypass, cryptographic operations, and license management. Built with CMake and C++17.

## Project Architecture
```
ncp-cpp/
├── src/core/          # Core library (libncp_core) - crypto, network, DPI, etc.
│   ├── include/       # Public headers (ncp_crypto.hpp, ncp_dpi.hpp, etc.)
│   └── src/           # Implementation files
├── src/cli/           # CLI application (main.cpp)
├── src/gui/           # Qt6 GUI (disabled, requires Qt6)
├── tests/             # Unit tests (disabled by default)
├── docs/              # Documentation
├── scripts/           # Build scripts
├── CMakeLists.txt     # Root build configuration
└── conanfile.txt      # Conan package dependencies
```

## Build System
- **Language**: C++17
- **Build system**: CMake 3.20+
- **Compiler**: Clang (cpp-clang20 module)
- **Build directory**: `build/`

### Build Commands
```bash
cd build
cmake --build . -j$(nproc)
```

### CMake Configuration
```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_CLI=ON \
  -DENABLE_GUI=OFF \
  -DENABLE_TESTS=OFF \
  -DENABLE_LIBOQS=OFF \
  -DENABLE_WEBSOCKETS=OFF \
  -DENABLE_TOR_PROXY=OFF \
  -DCMAKE_PREFIX_PATH="/nix/store/130agh12814rhg991rxq2a6kj65iy1z2-libsodium-1.0.20-dev;/nix/store/jllya56jcp6cg2hzjayhi8m0kzy4zgky-libsodium-1.0.20"
```

## Dependencies
- **libsodium** (required) - Cryptographic operations
- **libpcap** (optional) - Packet capture
- **liboqs** (optional, disabled) - Post-quantum cryptography
- **libwebsockets** (optional, disabled) - WebSocket tunneling
- **Qt6** (optional, disabled) - GUI application

## Workflow
- **Build and Run NCP CLI**: Builds the project and runs `./bin/ncp help`

## Recent Changes
- 2026-02-11: Initial Replit setup, fixed compilation errors in e2e.cpp and dpi_advanced.cpp
