# NCP C++ Setup Guide

Быстрый старт для Dynam (NCP C++).

## Быстрый старт

### 1. Установка зависимостей

**Linux (Ubuntu/Debian):**

```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential git \
    libsodium-dev libssl-dev libsqlite3-dev libgtest-dev \
    libpcap-dev pkg-config
```

**macOS:**

```bash
brew install cmake libsodium openssl sqlite3 googletest libpcap
```

**Windows:**

- Установи [CMake](https://cmake.org/download/) (3.20+)
- Установи [Visual Studio 2022](https://visualstudio.microsoft.com/) (с C++ tools)
- Установи [vcpkg](https://github.com/microsoft/vcpkg)

```bash
vcpkg install libsodium:x64-windows openssl:x64-windows sqlite3:x64-windows gtest:x64-windows
```

Или используй Conan:

```bash
pip install conan
conan install . --build=missing
```

### 2. Сборка проекта

**Linux/macOS:**

```bash
git clone https://github.com/kirin2461/Dynam.git
cd Dynam
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
cmake --build . -j$(nproc)
```

**Windows (build.bat):**

```bash
git clone https://github.com/kirin2461/Dynam.git
cd Dynam
build.bat
```

`build.bat` автоматически устанавливает зависимости через Conan и запускает CMake.

**Windows (ручная сборка):**

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_DIR%/scripts/buildsystems/vcpkg.cmake -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### 3. Запуск тестов

```bash
cd build
ctest --output-on-failure
```

### 4. Запуск

**Рекомендуемый способ (PARANOID Mode):**

```bash
# Windows
run_ncp.bat
# Или напрямую
ncp.exe run

# Linux/macOS
sudo ./ncp run
```

Команда `run` автоматически включает PARANOID режим со всеми 8 слоями защиты, спуфингом (включая HW-идентификаторы) и DPI bypass.

**Другие команды:**

```bash
ncp help            # Показать все команды
ncp status          # Текущий статус
ncp crypto keygen   # Генерация ключей
ncp dpi --preset RuNet-Strong  # DPI bypass
```

Полный список команд: [docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md)

## Структура проекта

```
Dynam/
├── src/
│   ├── core/           # Core library (libncp_core) - 18 модулей
│   │   ├── include/    # Public headers (ncp_*.hpp)
│   │   └── src/        # Implementation
│   ├── cli/            # CLI application (ncp)
│   └── gui/            # Qt6 GUI (опционально)
├── tests/              # Unit tests + fuzz tests
│   └── fuzz/           # Fuzzing tests (LibFuzzer)
├── docs/               # Documentation
├── scripts/            # Build/utility scripts
├── build.bat           # Windows build script
├── run_ncp.bat         # Windows run script
├── CMakeLists.txt      # Build configuration
├── conanfile.txt       # Conan dependencies
└── DEPENDENCIES.md     # Dependencies guide
```

## CMake опции

| Опция | По умолчанию | Описание |
|-------|-------------|----------|
| `ENABLE_TESTS` | ON | Сборка тестов |
| `ENABLE_CLI` | ON | Сборка CLI приложения |
| `ENABLE_GUI` | OFF | Сборка GUI (требует Qt6) |
| `ENABLE_LIBOQS` | OFF | Post-quantum криптография |
| `ENABLE_WEBSOCKETS` | OFF | WebSocket tunneling |
| `ENABLE_TOR_PROXY` | OFF | Tor proxy интеграция |
| `ENABLE_FUZZING` | OFF | Fuzzing тесты (Clang + LibFuzzer) |
| `BUILD_SHARED_LIBS` | OFF | Сборка разделяемых библиотек |

```bash
# Без GUI
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_GUI=OFF

# С fuzzing тестами (требует Clang)
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_FUZZING=ON

# Только тесты
cmake .. -DENABLE_CLI=OFF -DENABLE_GUI=OFF -DENABLE_TESTS=ON

# Debug сборка
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

## Troubleshooting

**libsodium not found:**

```bash
# Conan
conan remove '*' -f
conan install .. --build=missing
# Или установи вручную
sudo apt-get install libsodium-dev
```

**SQLite3 not found:**

```bash
sudo apt-get install libsqlite3-dev
```

**CMake error: Could not find Qt6:**

```bash
brew install qt6       # macOS
sudo apt-get install qt6-base-dev  # Linux
```

**Permission denied на Linux:**

```bash
sudo chmod +x ./bin/ncp
# Для run требуются права root
sudo ./ncp run
```

## Дальше

- [README.md](README.md) - Полное описание проекта
- [DEPENDENCIES.md](DEPENDENCIES.md) - Детальный гайд по зависимостям
- [docs/CLI_COMMANDS.md](docs/CLI_COMMANDS.md) - Справочник CLI команд
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Архитектура проекта
- [docs/BUILD.md](docs/BUILD.md) - Детальные инструкции сборки
