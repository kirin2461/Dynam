# NCP C++ Setup Guide

## Быстрый старт за 10 минут

### 1. Установка зависимостей

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential git python3-pip libpcap-dev pkg-config
pip install conan
```

**macOS:**
```bash
brew install cmake pcap python@3
pip install conan
```

**Windows:**
- Установи [CMake](https://cmake.org/download/) (3.20+)
- Установи [Visual Studio 2022](https://visualstudio.microsoft.com/) (с C++ tools)
- Установи [Python 3.10+](https://www.python.org/)
- `pip install conan`

### 2. Сборка проекта

```bash
git clone https://github.com/kirin2461/ncp-cpp.git
cd ncp-cpp

mkdir build && cd build

# Установка зависимостей
conan install .. --build=missing

# Конфигурация CMake
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON -DENABLE_CLI=ON

# Сборка
cmake --build . -j$(nproc)  # Linux/macOS
# или
cmake --build . --config Release -j  # Windows
```

### 3. Запуск тестов

```bash
ctest --output-on-failure

# Или прямой запуск
./bin/test_crypto  # Linux/macOS
# или
.\bin\test_crypto.exe  # Windows
```

### 4. Запуск CLI

```bash
./bin/ncp-cli
# Output: NCP CLI v1.0.0
```

## Структура репо

```
ncp-cpp/
├── src/core/        # Core library (libncp_core)
│   ├── include/     # Public headers
│   └── src/         # Implementation
├── src/cli/         # CLI application
├── src/gui/         # Qt6 GUI (в разработке)
├── tests/           # Unit tests
└── CMakeLists.txt   # Build configuration
```

## Первые шаги разработки

### Добавить новый модуль в Core

1. Создать `src/core/include/ncp_mymodule.hpp`
2. Реализовать `src/core/src/mymodule.cpp`
3. Добавить в `src/core/CMakeLists.txt` в `add_library()`
4. Написать тесты в `tests/test_mymodule.cpp`

### Запуск CMake конфигурации с опциями

```bash
# Без GUI
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_GUI=OFF

# Только тесты
cmake .. -DENABLE_CLI=OFF -DENABLE_GUI=OFF -DENABLE_TESTS=ON

# Debug сборка
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

## Troubleshooting

**Ошибка: libsodium not found**
```bash
conan remove '*' -f  # Очистить кэш
conan install .. --build=missing
```

**CMake error: Could not find Qt6**
```bash
brew install qt6  # macOS
sudo apt-get install qt6-base-dev  # Linux
```

**Permission denied на Linux**
```bash
chmod +x ./bin/ncp-cli
```

## Дальше

- Смотри `README.md` для полного описания
- Смотри `docs/architecture.md` для архитектуры
- Смотри `CMakeLists.txt` для конфигурации сборки

