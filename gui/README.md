# Dynam GUI — Qt6 Desktop Application

Полноценный десктопный интерфейс для Dynam NCP с интеграцией ONNX-модуля.

## Возможности

- **Монитор Трафика** — реалтайм отслеживание соединений, stealth-скоры, ONNX-обнаружение
- **Конфигуратор** — настройки ONNX модели, DPI bypass стратегий, прокси, логирования
- **Журнал Событий** — фильтруемые логи с поиском и цветовым кодированием
- **Тестировщик Атак** — визуализация AdversaryTester с выбором типа атаки, итераций, интенсивности
- **Статистика** — агрегатные метрики трафика, скрытности, ONNX, атак
- **Настройки** — переключение языков (RU/EN) и тем (Dark/Light)

## Структура

```
gui/
├── CMakeLists.txt          # Сборка Qt6 проекта
├── src/
│   ├── main.cpp            # Точка входа
│   ├── MainWindow.hpp/cpp  # Главное окно с табами
│   ├── core/
│   │   ├── I18nManager.hpp/cpp    # Интернационализация
│   │   ├── ThemeManager.hpp/cpp   # Управление темами
│   │   ├── RestClient.hpp/cpp     # REST API клиент
│   │   └── WebSocketClient.hpp/cpp # WebSocket для реалтайма
│   ├── models/
│   │   ├── TrafficModel.hpp/cpp   # Модель трафика
│   │   ├── ConfigModel.hpp/cpp    # Модель конфигурации
│   │   └── LogModel.hpp/cpp       # Модель логов
│   └── widgets/
│       ├── TrafficMonitorWidget.hpp/cpp
│       ├── ConfigWidget.hpp/cpp
│       ├── LogWidget.hpp/cpp
│       ├── AdversaryTesterWidget.hpp/cpp
│       ├── StatsWidget.hpp/cpp
│       └── SettingsWidget.hpp/cpp
├── resources/
│   └── resources.qrc       # Qt ресурсы
└── translations/
    ├── dynam_ru.ts         # Русский перевод
    └── dynam_en.ts         # Английский перевод
```

## Сборка

### Требования

- Qt 6.5+
- CMake 3.21+
- C++17 компилятор

### Linux/macOS

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
./dynam-gui
```

### Windows (Visual Studio)

```bash
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
Release\dynam-gui.exe
```

### macOS (App Bundle)

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
# Создать .app бандл:
macdeployqt dynam-gui.app -qmldir=.
```

## Запуск

```bash
# Запуск с параметрами
./dynam-gui --server http://127.0.0.1:8085 --lang ru

# Параметры:
#   --server URL    URL backend сервера (по умолчанию: http://127.0.0.1:8085)
#   --lang LANG     Язык интерфейса (ru, en)
```

## API Endpoints

GUI общается с backend через REST API и WebSocket:

### REST API

- `GET /api/traffic` — данные о трафике
- `GET/PUT /api/config` — конфигурация
- `POST /api/adversary/run` — запуск теста AdversaryTester
- `GET /api/logs?limit=N` — логи
- `DELETE /api/logs` — очистка логов
- `GET /api/stats` — статистика
- `GET /api/health` — проверка здоровья

### WebSocket

Подключение: `ws://127.0.0.1:8085/ws`

Сообщения:

```json
{"type": "traffic", "data": {...}}
{"type": "log", "data": {...}}
{"type": "stats", "data": {...}}
{"type": "adversary", "data": {"progress": 50, "status": "running"}}
```

## Интеграция с ONNX

GUI отображает результаты ONNX-модуля:

- `P(NCP)` — вероятность обнаружения NCP-obfuscated трафика
- `Stealth Score` — комбинированный скор (эвристика + ONNX)
- `ONNX Detected` — флаг обнаружения моделью

Настройки ONNX в конфигураторе:

- **Model Path** — путь к `.onnx` файлу
- **Detection Threshold** — порог классификации (0.0-1.0)
- **Weight** — вес ONNX в комбинированном score (0.0-1.0)
- **Enabled** — вкл/выкл ONNX-модуль

## Темы

GUI поддерживает две темы:

- **Dark** (по умолчанию) — Catppuccin Mocha палитра
- **Light** — Catppuccin Latte палитра

Темы применяются через `ThemeManager` с полным Qt stylesheet.

## i18n

Поддерживаются два языка:

- **Русский** (ru) — по умолчанию для RU региона
- **English** (en)

Переключение в реальном времени без перезапуска приложения.

## Лицензия

AGPL-3.0-only
