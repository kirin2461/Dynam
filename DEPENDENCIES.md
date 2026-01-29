# Dependencies Installation Guide

This document describes all dependencies required for building NCP C++ (Dynam) with full features.

## Core Dependencies (Required)

### 1. **libsodium** - Cryptographic library
```bash
# Ubuntu/Debian
sudo apt-get install libsodium-dev

# Fedora/RHEL
sudo dnf install libsodium-devel

# macOS
brew install libsodium

# Build from source
git clone https://github.com/jedisct1/libsodium.git
cd libsodium
./configure
make && sudo make install
```

### 2. **OpenSSL** - TLS and cryptographic operations
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# macOS
brew install openssl
```

### 3. **CMake** - Build system
```bash
# Ubuntu/Debian
sudo apt-get install cmake

# Fedora/RHEL
sudo dnf install cmake

# macOS
brew install cmake
```

## Optional Dependencies (Advanced Features)

### 4. **liboqs** - Post-quantum cryptography (Kyber1024, Dilithium5)
**Status**: Enables real post-quantum key exchange and signatures

```bash
# Build from source (recommended)
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

**CMake option**: `ENABLE_LIBOQS=ON` (default: ON)

**What you get**:
- ✅ Real Kyber1024 key encapsulation mechanism
- ✅ CRYSTALS-Dilithium5 post-quantum signatures
- ❌ Without liboqs: Falls back to random placeholder (NOT SECURE)

### 5. **libwebsockets** - WebSocket tunneling
**Status**: Enables WebSocket-based traffic tunneling

```bash
# Ubuntu/Debian
sudo apt-get install libwebsockets-dev

# Fedora/RHEL
sudo dnf install libwebsockets-devel

# macOS
brew install libwebsockets

# Build from source
git clone https://github.com/warmcat/libwebsockets.git
cd libwebsockets
mkdir build && cd build
cmake ..
make && sudo make install
```

**CMake option**: `ENABLE_WEBSOCKETS=ON` (default: ON)

**What you get**:
- ✅ WebSocket protocol tunneling
- ✅ HTTP/HTTPS upgrade support
- ✅ Bypass WebSocket-aware DPI systems

### 6. **Tor** - Anonymous proxy support
**Status**: Runtime dependency for Tor proxy integration

```bash
# Ubuntu/Debian
sudo apt-get install tor

# Fedora/RHEL
sudo dnf install tor

# macOS
brew install tor

# Start Tor service
sudo systemctl start tor  # Linux
# or
tor  # macOS/manual
```

**CMake option**: `ENABLE_TOR_PROXY=ON` (default: ON)

**What you get**:
- ✅ SOCKS5 proxy through Tor network
- ✅ .onion hidden service support
- ✅ Traffic anonymization

## Qt6 (For GUI)

```bash
# Ubuntu/Debian
sudo apt-get install qt6-base-dev

# Fedora/RHEL
sudo dnf install qt6-qtbase-devel

# macOS
brew install qt@6
```

**CMake option**: `ENABLE_GUI=OFF` (disable if Qt6 not needed)

## Build Configuration

### Full build with all features:
```bash
mkdir build && cd build
cmake -DENABLE_LIBOQS=ON -DENABLE_WEBSOCKETS=ON -DENABLE_TOR_PROXY=ON ..
make -j$(nproc)
```

### Minimal build (core only):
```bash
mkdir build && cd build
cmake -DENABLE_LIBOQS=OFF -DENABLE_WEBSOCKETS=OFF -DENABLE_TOR_PROXY=OFF -DENABLE_GUI=OFF ..
make -j$(nproc)
```

### Check what's enabled:
```bash
cmake ..
# Look for status messages:
# "liboqs found - Post-quantum crypto enabled"
# "libwebsockets found - WebSocket tunneling enabled"
# "Tor found at /usr/bin/tor"
```

## Troubleshooting

### liboqs not found
```bash
# Make sure liboqs is installed to /usr/local
# Update library cache
sudo ldconfig

# Check if installed:
pkg-config --modversion liboqs
```

### libwebsockets not found
```bash
# Install development package
sudo apt-get install libwebsockets-dev

# Or build from source with proper install prefix
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
```

### Tor executable not found
```bash
# Install tor package
sudo apt-get install tor

# Verify installation
which tor
```

## Platform-Specific Notes

### Linux
- All dependencies available in package managers
- Use `sudo ldconfig` after installing libraries from source

### macOS
- Use Homebrew for easiest installation
- May need to set `CMAKE_PREFIX_PATH` for Qt6:
  ```bash
  cmake -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt@6 ..
  ```

### Windows
- Use vcpkg for dependency management:
  ```cmd
  vcpkg install libsodium openssl
  ```
- liboqs: Build from source using Visual Studio
- Tor: Download Tor Browser Bundle or Expert Bundle

## Summary Table

| Dependency | Required | Feature Enabled | Install Command (Ubuntu) |
|------------|----------|-----------------|-------------------------|
| libsodium | ✅ Yes | Core crypto | `apt-get install libsodium-dev` |
| OpenSSL | ✅ Yes | TLS, HTTPS DoH | `apt-get install libssl-dev` |
| CMake | ✅ Yes | Build system | `apt-get install cmake` |
| liboqs | ⭕ Optional | Post-quantum crypto | Build from source |
| libwebsockets | ⭕ Optional | WebSocket tunneling | `apt-get install libwebsockets-dev` |
| Tor | ⭕ Optional | Anonymous proxy | `apt-get install tor` |
| Qt6 | ⭕ Optional | GUI application | `apt-get install qt6-base-dev` |

## Security Note

⚠️ **Important**: When building without `liboqs`, post-quantum features (Kyber1024, Dilithium) will fall back to insecure placeholders. For production deployments, always build with `ENABLE_LIBOQS=ON`.
