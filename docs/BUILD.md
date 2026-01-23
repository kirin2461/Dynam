# NCP C++ Build Guide

## Prerequisites

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y \
    cmake \
    build-essential \
    git \
    python3-pip \
    pkg-config \
    libssl-dev

pip3 install conan
```

### macOS
```bash
brew install cmake conan libsodium openssl
```

### Windows
- Install [Visual Studio 2019+](https://visualstudio.microsoft.com/) with C++ tools
- Install [CMake](https://cmake.org/download/) (3.20+)
- Install [Python](https://www.python.org/)
- Install [Conan](https://conan.io/): `pip install conan`

## Building from Source

### 1. Clone the repository
```bash
git clone https://github.com/kirin2461/ncp-cpp.git
cd ncp-cpp
```

### 2. Install dependencies with Conan
```bash
mkdir build
cd build
conan install .. --build=missing
```

### 3. Configure with CMake
```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON -DENABLE_CLI=ON
```

**CMake Options:**
- `CMAKE_BUILD_TYPE`: Debug or Release (default: Release)
- `ENABLE_TESTS`: Enable unit tests (default: ON)
- `ENABLE_GUI`: Enable Qt6 GUI application (default: OFF)
- `ENABLE_CLI`: Enable CLI tool (default: ON)
- `BUILD_SHARED_LIBS`: Build shared libraries instead of static (default: OFF)

### 4. Build
```bash
cmake --build . -j$(nproc)  # Linux/macOS
cmake --build . -j%NUMBER_OF_PROCESSORS%  # Windows
```

### 5. Run tests
```bash
ctest --output-on-failure
```

### 6. Install
```bash
cmake --install .
```

## Output

After successful build:
- Core library: `build/lib/libncp_core.a` (static) or `.so`/`.dll` (shared)
- CLI tool: `build/bin/ncp` or `ncp.exe`
- Unit tests: `build/bin/ncp_tests` or `ncp_tests.exe`

## Troubleshooting

### Conan: libsodium not found
```bash
conan install .. --build=missing --build="*"
```

### CMake: GTEST not found
Make sure `--build=missing` is used with Conan:
```bash
conan install .. --build=missing
```

### Build fails on Linux
Ensure development packages are installed:
```bash
sudo apt-get install libssl-dev libsodium-dev libpcap-dev
```

## Running the CLI

```bash
./build/bin/ncp help
./build/bin/ncp crypto keygen
./build/bin/ncp license hwid
./build/bin/ncp network interfaces
```
