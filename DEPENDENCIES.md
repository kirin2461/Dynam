# Dependencies Installation Guide

All dependencies required for building NCP C++ (Dynam).

## Core Dependencies (Required)

### 1. **libsodium** - Cryptographic library

Used for: Ed25519, Curve25519, ChaCha20-Poly1305, X25519, AEAD encryption.

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

Used for: TLS operations, DNS over HTTPS (DoH), certificate handling.

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# macOS
brew install openssl
```

### 3. **SQLite3** - Encrypted database

Used for: Local encrypted database storage (with SQLCipher support).

```bash
# Ubuntu/Debian
sudo apt-get install libsqlite3-dev

# Fedora/RHEL
sudo dnf install sqlite-devel

# macOS
brew install sqlite3

# Windows (vcpkg)
vcpkg install sqlite3:x64-windows
```

### 4. **CMake** (3.20+) - Build system

```bash
# Ubuntu/Debian
sudo apt-get install cmake

# Fedora/RHEL
sudo dnf install cmake

# macOS
brew install cmake
```

## Test Dependencies

### 5. **GoogleTest** - Unit testing framework

Required for running tests (`-DENABLE_TESTS=ON`).

```bash
# Ubuntu/Debian
sudo apt-get install libgtest-dev

# Fedora/RHEL
sudo dnf install gtest-devel

# macOS
brew install googletest
```

## Optional Dependencies (Advanced Features)

### 6. **libpcap** - Packet capture (Linux/macOS)

Used for: Raw packet capture in NetworkManager.

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# macOS
brew install libpcap
```

### 7. **libnetfilter_queue** - DPI driver mode (Linux only)

Used for: NFQUEUE-based DPI bypass in driver mode.

```bash
# Ubuntu/Debian
sudo apt-get install libnetfilter-queue-dev

# Fedora/RHEL
sudo dnf install libnetfilter_queue-devel
```

### 8. **liboqs** - Post-quantum cryptography

Used for: Kyber1024 key encapsulation, CRYSTALS-Dilithium5 signatures.

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

> Without liboqs, post-quantum features fall back to insecure placeholders.

### 9. **libwebsockets** - WebSocket tunneling

Used for: WebSocket-based traffic tunneling, HTTP/HTTPS upgrade support.

```bash
# Ubuntu/Debian
sudo apt-get install libwebsockets-dev

# Fedora/RHEL
sudo dnf install libwebsockets-devel

# macOS
brew install libwebsockets
```

**CMake option**: `ENABLE_WEBSOCKETS=ON` (default: ON)

### 10. **Tor** - Anonymous proxy support

Runtime dependency for Tor proxy integration.

```bash
# Ubuntu/Debian
sudo apt-get install tor

# Fedora/RHEL
sudo dnf install tor

# macOS
brew install tor
```

**CMake option**: `ENABLE_TOR_PROXY=ON` (default: ON)

### 11. **Qt6** - GUI application

```bash
# Ubuntu/Debian
sudo apt-get install qt6-base-dev

# Fedora/RHEL
sudo dnf install qt6-qtbase-devel

# macOS
brew install qt@6
```

**CMake option**: `ENABLE_GUI=OFF` (disable if Qt6 not needed)

---

## Quick Install (All Required)

### Ubuntu/Debian

```bash
sudo apt-get install -y cmake build-essential git \
  libsodium-dev libssl-dev libsqlite3-dev libgtest-dev \
  libpcap-dev
```

### Fedora/RHEL

```bash
sudo dnf install -y cmake gcc-c++ git \
  libsodium-devel openssl-devel sqlite-devel gtest-devel \
  libpcap-devel
```

### macOS

```bash
brew install cmake libsodium openssl sqlite3 googletest libpcap
```

### Windows (vcpkg)

```bash
vcpkg install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows
```

### Conan (alternative)

```bash
conan install . --build=missing
```

Dependencies from `conanfile.txt`: libsodium/1.0.18, openssl/3.1.4, sqlite3/3.44.0, gtest/1.14.0

---

## Build Configuration

### Full build with all features

```bash
mkdir build && cd build
cmake -DENABLE_LIBOQS=ON -DENABLE_WEBSOCKETS=ON -DENABLE_TOR_PROXY=ON -DENABLE_TESTS=ON ..
make -j$(nproc)
```

### Minimal build (core only)

```bash
mkdir build && cd build
cmake -DENABLE_LIBOQS=OFF -DENABLE_WEBSOCKETS=OFF -DENABLE_TOR_PROXY=OFF -DENABLE_GUI=OFF ..
make -j$(nproc)
```

---

## Summary Table

| Dependency | Required | Purpose | Install (Ubuntu) |
|-----------|----------|---------|-----------------|
| libsodium | Yes | Core crypto (Ed25519, ChaCha20) | `apt-get install libsodium-dev` |
| OpenSSL | Yes | TLS, DoH | `apt-get install libssl-dev` |
| SQLite3 | Yes | Encrypted database | `apt-get install libsqlite3-dev` |
| CMake | Yes | Build system | `apt-get install cmake` |
| GoogleTest | For tests | Unit testing | `apt-get install libgtest-dev` |
| libpcap | Optional | Packet capture (Linux/macOS) | `apt-get install libpcap-dev` |
| libnetfilter_queue | Optional | DPI driver mode (Linux) | `apt-get install libnetfilter-queue-dev` |
| liboqs | Optional | Post-quantum crypto | Build from source |
| libwebsockets | Optional | WebSocket tunneling | `apt-get install libwebsockets-dev` |
| Tor | Optional | Anonymous proxy | `apt-get install tor` |
| Qt6 | Optional | GUI application | `apt-get install qt6-base-dev` |

## Troubleshooting

### liboqs not found

```bash
sudo ldconfig
pkg-config --modversion liboqs
```

### SQLite3 not found

```bash
# Ensure development package is installed
sudo apt-get install libsqlite3-dev
pkg-config --modversion sqlite3
```

### Tor executable not found

```bash
sudo apt-get install tor
which tor
```

## Platform Notes

### Windows
- Use vcpkg: `vcpkg install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows`
- Or use Conan: `conan install . --build=missing`
- liboqs: Build from source using Visual Studio
- Tor: Download Expert Bundle from torproject.org

### macOS
- Use Homebrew for all dependencies
- May need `CMAKE_PREFIX_PATH` for Qt6: `cmake -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt@6 ..`

### Linux
- All dependencies available in package managers
- Use `sudo ldconfig` after installing libraries from source
