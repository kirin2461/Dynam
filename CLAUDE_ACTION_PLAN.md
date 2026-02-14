# CLAUDE ACTION PLAN — Dynam (NCP C++)

> Подробный план действий для Claude по доработке проекта Dynam.
> Приоритеты: 🔴 Критический | 🟠 Высокий | 🟡 Средний | 🟢 Низкий
> Каждая задача содержит: файлы, что делать, контекст, ограничения.

---

## ОБЩИЙ КОНТЕКСТ ПРОЕКТА

Dynam (NCP C++) — платформа сетевой анонимизации на C++17.
- **Структура**: `src/core/` (libncp_core, 18 модулей) + `src/cli/` (CLI tool) + `tests/`
- **Сборка**: CMake 3.20+, vcpkg/Conan, статическая библиотека
- **Зависимости**: libsodium (обязательно), OpenSSL (обязательно), SQLite3, libpcap (опционально), liboqs (опционально), libnetfilter_queue (опционально)
- **Паттерны кода**: pImpl idiom, namespace `ncp`, C++17, `constexpr`/`noexcept` где возможно
- **Naming**: заголовки `ncp_*.hpp`, реализации в `src/core/src/`, include через `"../include/ncp_*.hpp"` или `"ncp_*.hpp"`

---

## ФАЗА 1: CLI — КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ 🔴

### Задача 1.1: Реализовать все command handlers в main.cpp

**Файл**: `src/cli/main.cpp`

**Проблема**: Все 10 command handlers — пустые стабы с `"implementation pending"`. CLI бинарник не делает ничего.

**Что сделать** — реализовать каждый handler, используя уже существующие классы из libncp_core:

#### 1.1.1 `handle_run()`
```
Должен:
1. Получить имя сетевого интерфейса из args[2] (опционально)
2. Создать и настроить NetworkSpoofer (ncp_spoofer.hpp)
   - Вызвать spoofer.initialize(interface_name)
   - Включить IPv4/IPv6/MAC/DNS spoofing
3. Создать и запустить DPI::DPIBypass (ncp_dpi.hpp)
   - Настроить DPIConfig с RuNet-Strong пресетом по умолчанию
   - apply_preset(DPIPreset::RUNET_STRONG, config)
   - dpi.initialize(config) + dpi.start()
4. Создать и активировать ParanoidMode (ncp_paranoid.hpp)
   - set_threat_level(ThreatLevel::TINFOIL_HAT)
   - activate()
5. Установить signal handler (SIGINT/SIGTERM → g_running = false)
6. Присвоить глобальные указатели g_spoofer, g_dpi_bypass, g_paranoid
7. Войти в цикл ожидания while(g_running) с sleep
8. При выходе: deactivate paranoid, stop DPI, stop spoofer
```

#### 1.1.2 `handle_stop()`
```
Должен:
1. Проверить g_running
2. Установить g_running = false
3. Если g_paranoid — deactivate()
4. Если g_dpi_bypass — shutdown()
5. Если g_spoofer — restore original settings
6. Обнулить глобальные указатели
7. Вывести статус восстановления
```

#### 1.1.3 `handle_status()`
```
Уже частично реализован — дополнить:
1. Показать текущий ThreatLevel из ParanoidMode
2. Показать DPI stats (get_stats())
3. Показать статус спуфинга (текущий IP/MAC)
4. Показать активные I2P туннели
5. Показать mimicry mode
```

#### 1.1.4 `handle_rotate()`
```
Должен:
1. Если g_spoofer — вызвать rotate_identity() для IP/MAC/DNS
2. Если g_paranoid — rotate_all_circuits()
3. Вывести новые значения
```

#### 1.1.5 `handle_crypto()`
```
Подкоманды (args[2]):
- "keygen": Crypto().generate_keypair(), вывести hex public/secret key
- "random <size>": Crypto().generate_random(size), вывести hex
- "hash <file>": прочитать файл, hash_blake2b(), вывести
- "sign <file> <keyfile>": подписать файл Ed25519
- "verify <file> <sigfile> <pubkeyfile>": проверить подпись
```

#### 1.1.6 `handle_network()`
```
Подкоманды:
- "interfaces": перечислить сетевые интерфейсы через NetworkManager
- "stats": показать трафик stats если запущен
- "capture <iface> <count>": захват пакетов через libpcap (если доступен)
```

#### 1.1.7 `handle_license()`
```
Подкоманды:
- "hwid": LicenseManager().get_hardware_id(), вывести
- "info": показать статус лицензии
- "activate <key>": активировать лицензию
- "validate": проверить текущую лицензию
```

#### 1.1.8 `handle_dpi()`
```
Параметры через ArgumentParser:
- --mode proxy|driver|passive (default: proxy)
- --port <num> (default: 8080)
- --target <host> (default: "")
- --target-port <num> (default: 443)
- --preset RuNet-Soft|RuNet-Strong|none
- --fragment-size <num>
- --split-position <num>
- --fake-ttl <num>

1. Создать DPIConfig
2. Если есть --preset: apply_preset()
3. Применить остальные параметры из CLI
4. config.validate() — проверить конфиг
5. dpi.initialize(config) + dpi.start()
6. Войти в цикл ожидания (g_running)
7. По выходу: dpi.shutdown()
```

#### 1.1.9 `handle_i2p()`
```
Подкоманды:
- "enable": I2PManager().initialize(default_config), set_enabled(true)
- "disable": set_enabled(false)
- "status": показать is_active(), get_destination(), get_statistics()
```

#### 1.1.10 `handle_mimic()`
```
Принимает args[2]: "http", "tls", "websocket", "none"
1. Создать/получить TrafficMimicry instance
2. Установить тип мимикрии
3. Вывести подтверждение
```

**Важно**:
- Заменить глобальные raw-указатели на `std::unique_ptr<>`
- Добавить proper cleanup в signal handler
- Обрабатывать исключения в каждом handler через try/catch

---

## ФАЗА 2: СТАБЫ И ЗАГЛУШКИ — РЕАЛИЗАЦИЯ 🟠

### Задача 2.1: I2P модуль — полная реализация

**Файлы**: `src/core/src/i2p.cpp`, `src/core/include/ncp_i2p.hpp`

**Контекст**: Заголовок объявляет ~30 методов, реализовано только 5, из них `create_tunnel()` — заглушка.

**Что реализовать** (приоритет по важности):

```
ВЫСОКИЙ ПРИОРИТЕТ:
1. Реализовать SAM Bridge подключение в initialize():
   - TCP подключение к sam_host:sam_port
   - Отправить "HELLO VERSION" SAM handshake
   - Парсить ответ SESSION STATUS
   - Хранить SAM socket в Impl

2. create_tunnel() — реальное создание через SAM:
   - Отправить "SESSION CREATE STYLE=STREAM ..." для CLIENT
   - Отправить "SESSION CREATE STYLE=STREAM ..." для SERVER
   - Сохранить tunnel info в tunnels_ map
   - Генерить реальный tunnel_id

3. create_server_tunnel() — серверный туннель:
   - SAM "SESSION CREATE" + "STREAM ACCEPT"

4. get_active_tunnels() — вернуть из tunnels_ map

5. destroy_tunnel() — закрыть SAM сессию

6. get_destination() — получить реальный .b32.i2p адрес из SAM

СРЕДНИЙ ПРИОРИТЕТ:
7. create_ephemeral_destination() — "DEST GENERATE" через SAM
8. lookup_destination() — "NAMING LOOKUP" через SAM
9. rotate_tunnels() — пересоздать все активные туннели
10. get_statistics() — собрать реальную статистику

НИЗКИЙ ПРИОРИТЕТ:
11. create_garlic_message() — garlic encryption через NaCl/libsodium
12. send_garlic_message() — отправка через SAM STREAM
13. publish_leaseset() — публикация через SAM
14. enable_traffic_mixing() — задержки + dummy traffic
15. send_dummy_traffic() — периодическая отправка шума
16. pad_message() — PKCS7-style padding до target_size
```

**Ограничения**:
- SAM Bridge API: https://geti2p.net/en/docs/api/samv3
- Не требовать наличие I2P роутера при сборке
- Все сетевые операции — в try/catch
- Impl должен хранить SAM socket, session ID, destination keys

### Задача 2.2: Paranoid Mode — реализовать пустые методы

**Файл**: `src/core/src/ncp_paranoid.cpp`

**Контекст**: 15+ методов — пустые `{}` или `(void)param;`. Заголовок объявляет 8 уровней защиты.

**Что реализовать**:

```
КРИТИЧЕСКИЙ (методы вызываются в activate()):
1. setup_kill_switch():
   - Linux: iptables правила блокировки не-VPN/Tor трафика
     system("iptables -P OUTPUT DROP") + whitelist правила
   - Windows: WFP (Windows Filtering Platform) через API
   - Сохранить оригинальные правила для восстановления
   
2. enable_memory_protection():
   - mlockall(MCL_CURRENT | MCL_FUTURE) на Linux
   - VirtualLock на критических буферах Windows
   - Отключить core dumps: setrlimit(RLIMIT_CORE, 0)
   - prctl(PR_SET_DUMPABLE, 0) на Linux

3. setup_bridge_nodes():
   - Загрузить список Tor bridge nodes из конфига
   - Валидировать формат bridge lines
   - Сохранить в impl_->bridge_nodes

4. configure_multi_hop():
   - Настроить цепочку: VPN → Tor → I2P на основе layered_config_
   - Сформировать HopChain objects
   - Сохранить в impl_->active_circuits

ВЫСОКИЙ ПРИОРИТЕТ:
5. inject_dummy_traffic(bytes_per_second):
   - Генерировать случайные данные через randombytes_buf()
   - Отправлять через cover traffic socket
   - Поддерживать constant rate через token bucket

6. shred_file(path, passes):
   - Открыть файл, получить размер
   - passes раз перезаписать: нулями, единицами, случайными данными
   - fsync() после каждого прохода
   - unlink/DeleteFile после всех проходов
   - Поддержать стандарт DOD 5220.22-M (7 проходов)

7. strip_metadata(data):
   - Для JPEG: удалить EXIF данные (искать 0xFFE1 маркер)
   - Для PNG: удалить tEXt/iTXt/zTXt chunks
   - Для PDF: удалить /Author, /Creator, /Producer

8. clear_all_traces():
   - Очистить temp файлы: /tmp/ncp_*, %TEMP%\ncp_*
   - Удалить лог файлы
   - Очистить clipboard
   - bash_history: export HISTFILE=/dev/null

9. enable_traffic_morphing():
   - Внедрить padding до fixed_packet_size (из TrafficAnalysisResistance)
   - Добавить jitter к размерам пакетов

10. configure_website_fingerprinting_defense():
    - Реализовать CS-BuFLO: буферизация + constant rate + padding
    - Использовать cover_traffic_rate_kbps из конфига

СРЕДНИЙ ПРИОРИТЕТ:
11. wipe_memory_on_exit() — sodium_memzero на всех SecureMemory
12. clear_system_traces() — очистка DNS cache, ARP cache
13. destroy_all_evidence() — shred_file на все .db, .log, .conf
14. overwrite_memory_region() — использовать sodium_memzero вместо std::fill
15. remove_browser_fingerprints() — модификация HTTP headers
```

### Задача 2.3: E2E — реализовать X448 и ECDH_P256

**Файл**: `src/core/src/e2e.cpp`

**Контекст**: X448 и ECDH_P256 бросают runtime_error. OpenSSL уже подключён в проекте.

**Что сделать**:
```
1. В generate_key_pair() для X448:
   - EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL)
   - EVP_PKEY_keygen_init() + EVP_PKEY_keygen()
   - EVP_PKEY_get_raw_public_key() / EVP_PKEY_get_raw_private_key()
   - Сохранить в KeyPair.public_key / private_key

2. В generate_key_pair() для ECDH_P256:
   - EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)
   - EC_KEY_generate_key()
   - Извлечь public/private ключи

3. В compute_shared_secret() для X448:
   - EVP_PKEY_derive_init() + EVP_PKEY_derive_set_peer()
   - EVP_PKEY_derive() для вычисления shared secret

4. В compute_shared_secret() для ECDH_P256:
   - ECDH_compute_key() или EVP_PKEY_derive API

Ограничения:
- Использовать только OpenSSL 1.1.1+ API (EVP_PKEY)
- Оборачивать OpenSSL ресурсы в RAII (unique_ptr с custom deleter)
- Обязательно очищать приватные ключи через OPENSSL_clear_free()
- #include <openssl/evp.h>, <openssl/ec.h>, <openssl/x509.h>
```

---

## ФАЗА 3: ИСПРАВЛЕНИЯ БЕЗОПАСНОСТИ 🟠

### Задача 3.1: Thread Pool вместо detach() в DPI Proxy

**Файл**: `src/core/src/ncp_dpi.cpp`

**Проблема**: `std::thread(...).detach()` при каждом новом соединении — утечка ресурсов.

**Что сделать**:
```
1. Использовать уже существующий ThreadPool из ncp_thread_pool.hpp/.cpp

2. В Impl добавить:
   - std::unique_ptr<ThreadPool> thread_pool_;
   - Инициализировать в конструкторе: thread_pool_ = make_unique<ThreadPool>(num_threads)
   - num_threads = std::thread::hardware_concurrency() или 8 (что меньше)

3. Заменить:
   БЫЛО:  std::thread(&Impl::handle_proxy_connection, this, client_sock).detach();
   СТАЛО: thread_pool_->enqueue([this, client_sock]() { handle_proxy_connection(client_sock); });

4. В shutdown():
   - Сначала running = false
   - Закрыть listen socket (чтобы accept() вернул ошибку)
   - Дождаться завершения всех задач thread pool
   - thread_pool_.reset()

5. Добавить лимит на максимальное количество одновременных соединений:
   - std::atomic<int> active_connections_{0};
   - Проверять перед enqueue: if (active_connections_ >= MAX_CONNECTIONS) { CLOSE_SOCKET(client_sock); continue; }
   - Инкрементить в начале handle_proxy_connection, декрементить в конце (RAII guard)
```

### Задача 3.2: Заменить std::mt19937 на криптографический PRNG

**Файлы**: `src/core/src/ncp_paranoid.cpp`

**Проблема**: `std::mt19937` — предсказуемый PRNG в security-критическом контексте.

**Что сделать**:
```
1. В ParanoidMode::Impl заменить:
   БЫЛО:  std::mt19937 rng{std::random_device{}()};
   СТАЛО: (удалить полностью)

2. Для add_random_delay():
   БЫЛО:  std::uniform_int_distribution<int> dist(...); auto delay = dist(impl_->rng);
   СТАЛО: uint32_t rand_val; randombytes_buf(&rand_val, sizeof(rand_val));
          int delay = min_delay + (rand_val % (max_delay - min_delay + 1));

3. Для calculate_safe_delay() — аналогично

4. Для create_isolated_circuit():
   БЫЛО:  circuit_id = "circuit_" + std::to_string(size)
   СТАЛО: uint8_t id_bytes[16]; randombytes_buf(id_bytes, 16);
          circuit_id = hex_encode(id_bytes, 16);

5. #include <sodium.h> добавить в ncp_paranoid.cpp
```

### Задача 3.3: Глобальные указатели → RAII

**Файл**: `src/cli/main.cpp`

```
1. Заменить:
   БЫЛО:
   NetworkSpoofer* g_spoofer = nullptr;
   DPI::DPIBypass* g_dpi_bypass = nullptr;
   ParanoidMode* g_paranoid = nullptr;

   СТАЛО:
   std::unique_ptr<NetworkSpoofer> g_spoofer;
   std::unique_ptr<DPI::DPIBypass> g_dpi_bypass;
   std::unique_ptr<ParanoidMode> g_paranoid;

2. В signal_handler — НЕ делать cleanup (signal handler должен быть минимальным):
   - Только g_running = false;
   
3. Cleanup делать в main() после выхода из цикла ожидания:
   - g_paranoid->deactivate(); g_paranoid.reset();
   - g_dpi_bypass->shutdown(); g_dpi_bypass.reset();
   - g_spoofer.reset();
```

---

## ФАЗА 4: КАЧЕСТВО КОДА 🟡

### Задача 4.1: Нормализовать include-пути

**Файлы**: все .cpp в `src/core/src/`

**Проблема**: Смешанные стили — `"ncp_paranoid.hpp"` vs `"../include/ncp_e2e.hpp"`

```
Привести ВСЕ includes к единому стилю — относительному от src/:
  #include "core/include/ncp_paranoid.hpp"
  
ИЛИ (если CMake include_directories настроен):
  #include "ncp_paranoid.hpp"

Выбрать стиль на основе target_include_directories в src/core/CMakeLists.txt.
Текущий CMake: target_include_directories включает ${CMAKE_CURRENT_SOURCE_DIR}/include,
значит правильный стиль: #include "ncp_paranoid.hpp" (без ../include/).

Файлы для исправления (используют ../include/):
- src/core/src/e2e.cpp: #include "../include/ncp_e2e.hpp" → #include "ncp_e2e.hpp"
- src/core/src/e2e.cpp: #include "../include/ncp_secure_memory.hpp" → #include "ncp_secure_memory.hpp"
- src/core/src/i2p.cpp: #include "../include/ncp_i2p.hpp" → #include "ncp_i2p.hpp"
- src/core/src/crypto.cpp: #include "../include/ncp_crypto.hpp" → #include "ncp_crypto.hpp"
- src/core/src/crypto.cpp: #include "../include/ncp_secure_memory.hpp" → #include "ncp_secure_memory.hpp"

Проверить ВСЕ .cpp файлы на аналогичные проблемы.
```

### Задача 4.2: Добавить noexcept и constexpr где уместно

**Файлы**: все заголовки в `src/core/include/`

```
Кандидаты на noexcept:
- Все деструкторы (уже implicit, но стоит явно)
- Геттеры: is_active(), get_config(), get_stats(), get_destination()
- Простые сеттеры без allocation: set_enabled(), set_threat_level()

Кандидаты на constexpr:
- Статические utility функции
- Строковые константы пресетов
- Значения по умолчанию в конфигах

Пример:
БЫЛО:  bool is_active() const;
СТАЛО: bool is_active() const noexcept;
```

### Задача 4.3: Убрать (void) cast стабы

**Файл**: `src/core/src/ncp_paranoid.cpp`

```
Найти все `(void)parameter;` паттерны и либо:
а) Реализовать функцию (см. Фазу 2)
б) Если пока не реализуемо — оставить но добавить [[maybe_unused]]
   и залогировать через ncp_logger:
   
БЫЛО:
void ParanoidMode::inject_dummy_traffic(size_t bytes_per_second) {
    (void)bytes_per_second;
}

СТАЛО (если не реализуемо прямо сейчас):
void ParanoidMode::inject_dummy_traffic([[maybe_unused]] size_t bytes_per_second) {
    NCP_LOG_WARN("inject_dummy_traffic: not yet implemented");
}
```

---

## ФАЗА 5: ТЕСТЫ 🟡

### Задача 5.1: Тесты для E2E модуля

**Файл**: создать `tests/test_e2e.cpp`

```cpp
// Тесты:
// 1. X25519 key generation + shared secret computation
// 2. Key derivation (derive_keys) — проверить длину и уникальность
// 3. Encrypt/decrypt roundtrip — зашифровать, расшифровать, сравнить
// 4. Encrypt с неправильным ключом — должен бросить exception
// 5. Decrypt с повреждённым ciphertext — должен бросить exception
// 6. Session ID uniqueness — два E2ESession должны иметь разные ID
// 7. Wrong key size — должен бросить exception
// 8. Empty plaintext — должен корректно зашифровать/расшифровать
```

### Задача 5.2: Тесты для Paranoid Mode

**Файл**: создать `tests/test_paranoid.cpp`

```cpp
// Тесты:
// 1. activate/deactivate — state transitions
// 2. set_threat_level — проверить что конфиг обновляется
// 3. sanitize_http_headers — проверить удаление User-Agent, X-Forwarded-For
// 4. create_isolated_circuit — возвращает уникальный ID
// 5. destroy_circuit — удаляет из списка
// 6. rotate_all_circuits — очищает список
// 7. cover_traffic start/stop — не крашится, thread корректно завершается
// 8. panic_callback — вызывается при canary_trigger
// 9. enable_request_batching — сохраняет параметры
// 10. perform_security_audit — возвращает валидный SecurityAudit
```

### Задача 5.3: Тесты для SecureBuffer/SecureMemory

**Файл**: создать `tests/test_secure_memory.cpp`

```cpp
// Тесты:
// 1. Allocation/deallocation — не крашится
// 2. Move semantics — перемещение корректно, оригинал обнулён
// 3. Memory zeroing — после деструктора данные обнулены
// 4. mlock/munlock — не крашится (может fail без привилегий — допустимо)
// 5. Copy prohibited — не компилируется (static_assert или compile test)
// 6. Resize — данные сохраняются при увеличении
// 7. Edge case: zero-size allocation
```

### Задача 5.4: Тесты для I2P модуля

**Файл**: создать `tests/test_i2p.cpp`

```cpp
// Тесты (без реального I2P роутера — mock):
// 1. initialize с default config — возвращает true
// 2. is_active() — false до initialize, true после
// 3. set_enabled(false) → is_active() = false
// 4. get_destination() — не пустой после initialize
// 5. create_tunnel() — возвращает true при active
// 6. create_tunnel() — возвращает false при !active
```

### Задача 5.5: Обновить tests/CMakeLists.txt

**Файл**: `tests/CMakeLists.txt`

```
Добавить новые тесты:
add_executable(test_e2e test_e2e.cpp)
target_link_libraries(test_e2e PRIVATE ncp_core GTest::gtest_main)
add_test(NAME E2ETest COMMAND test_e2e)

add_executable(test_paranoid test_paranoid.cpp)
target_link_libraries(test_paranoid PRIVATE ncp_core GTest::gtest_main)
add_test(NAME ParanoidTest COMMAND test_paranoid)

add_executable(test_secure_memory test_secure_memory.cpp)
target_link_libraries(test_secure_memory PRIVATE ncp_core GTest::gtest_main)
add_test(NAME SecureMemoryTest COMMAND test_secure_memory)

add_executable(test_i2p test_i2p.cpp)
target_link_libraries(test_i2p PRIVATE ncp_core GTest::gtest_main)
add_test(NAME I2PTest COMMAND test_i2p)
```

---

## ФАЗА 6: ДОПОЛНИТЕЛЬНЫЕ УЛУЧШЕНИЯ 🟢

### Задача 6.1: Добавить ncp_logger использование во все модули

**Контекст**: `ncp_logger.hpp` существует, но большинство модулей используют `std::cout`/`std::clog`.

```
Заменить во всех .cpp файлах:
- std::cout << "[!] ..." → NCP_LOG_WARN(...)
- std::cerr << "Error: ..." → NCP_LOG_ERROR(...)
- std::clog << "[DPI] ..." → NCP_LOG_INFO(...)

Приоритет файлов: main.cpp, ncp_dpi.cpp, ncp_paranoid.cpp, i2p.cpp
```

### Задача 6.2: Добавить GitHub Actions CI

**Файл**: создать `.github/workflows/build.yml`

```yaml
# Matrix build: Ubuntu + Windows + macOS
# Шаги:
# 1. checkout
# 2. Install dependencies (apt/brew/vcpkg)
# 3. cmake configure
# 4. cmake build
# 5. ctest
```

### Задача 6.3: Удалить файлы-сироты из core/CMakeLists.txt

**Файл**: `src/core/CMakeLists.txt`

**Проблема**: В CMake перечислены `NetworkManager.cpp`, `ConnectionMonitor.cpp`, `InterfaceSelector.cpp` как root sources, но эти файлы, возможно, не существуют или не используются CLI.

```
Проверить наличие этих файлов:
- src/core/NetworkManager.cpp
- src/core/ConnectionMonitor.cpp
- src/core/InterfaceSelector.cpp

Если не существуют — удалить из NCP_CORE_ROOT_SOURCES.
Если существуют — проверить что они нужны и корректно компилируются.
```

### Задача 6.4: README — привести в соответствие с реальностью

**Файл**: `README.md`

```
1. Добавить секцию "Current Status" с честным описанием:
   - Core library: 80% implemented
   - CLI: refactoring in progress
   - I2P: stub only
   - Paranoid Mode: partial implementation

2. Убрать или пометить как "planned" примеры CLI команд, которые не работают

3. Обновить версию если будет существенный прогресс
```

---

## ПОРЯДОК ВЫПОЛНЕНИЯ (РЕКОМЕНДУЕМЫЙ)

```
Итерация 1 (Критическое):
  → 3.3 (глобальные указатели) — маленькая задача, быстрый win
  → 1.1.8 (handle_dpi) — DPI уже реализован, нужен только CLI glue
  → 1.1.5 (handle_crypto) — crypto модуль готов, простая обёртка
  → 1.1.7 (handle_license) — license модуль готов

Итерация 2 (CLI completion):
  → 1.1.1 (handle_run) — основная команда
  → 1.1.2 (handle_stop)
  → 1.1.3 (handle_status) — дополнить
  → 1.1.4 (handle_rotate)
  → 1.1.6 (handle_network)
  → 1.1.9 (handle_i2p)
  → 1.1.10 (handle_mimic)

Итерация 3 (Security fixes):
  → 3.1 (thread pool в DPI)
  → 3.2 (CSPRNG вместо mt19937)
  → 4.1 (нормализация include)

Итерация 4 (Paranoid Mode):
  → 2.2 задачи 1-4 (критические пустые методы)
  → 2.2 задачи 5-10 (высокий приоритет)

Итерация 5 (E2E + I2P):
  → 2.3 (X448 + ECDH_P256 через OpenSSL)
  → 2.1 (I2P SAM реализация)

Итерация 6 (Тесты):
  → 5.1-5.5 (все новые тесты)

Итерация 7 (Polish):
  → 4.2, 4.3, 6.1-6.4
```

---

## ОГРАНИЧЕНИЯ И ПРАВИЛА

1. **НЕ менять публичный API** заголовков без крайней необходимости — сохранять обратную совместимость
2. **Всегда использовать libsodium** для крипто-операций (randombytes_buf, sodium_memzero и т.д.)
3. **OpenSSL** — только для TLS операций и алгоритмов, отсутствующих в libsodium (X448, ECDH_P256)
4. **Каждый коммит** должен компилироваться — не ломать build
5. **Стиль кода**: 4 пробела, `snake_case` для функций/переменных, `PascalCase` для классов
6. **namespace**: всё в `ncp::`, DPI в `ncp::DPI::`
7. **Error handling**: исключения (std::runtime_error) для критических ошибок, return false/nullopt для ожидаемых
8. **Платформенный код**: `#ifdef _WIN32` / `#ifdef __linux__` / `#ifdef __APPLE__`
9. **Потокобезопасность**: std::mutex для shared state, std::atomic для простых флагов
10. **Тесты**: GoogleTest framework, файлы `test_*.cpp` в `tests/`
