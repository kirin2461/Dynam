# 🔬 Ultra Deep Research: Dynam (NCP C++) — kirin2461/Dynam

**Дата исследования**: 27 ноября 2026  
**Репозиторий**: https://github.com/kirin2461/Dynam  
**Лицензия**: AGPLv3  
**Язык**: C++17  
**Последняя версия**: v1.8.0 (23 ноября 2026)

---

## 📋 Executive Summary

**Dynam** (также известен как **NCP — Network Control Protocol**) — это масштабная open-source платформа сетевой анонимизации и обхода DPI (Deep Packet Inspection), написана на современном C++17. Проект создан российским разработчиком **kirin2461** (Москва) и представляет собой один из самых амбициозных и технически глубоких проектов в области антицензуры на сегодняшний день.

**Ключевые цифры:**
- ⭐ 15 звёзд, 2 форка
- 📝 328+ коммитов, 114 веток, 13 тегов
- 🧪 1464 теста (1456 пройдено, 8 пропущено, 0 упавших)
- 📦 ~90,000+ строк кода (по данным аудита R16)
- 🕐 Активная разработка: март 2026 — настоящее время (9 месяцев)
- 🌍 Платформы: Windows 10/11, Linux, macOS

---

## 🏗️ Архитектура проекта

### Трёхуровневая архитектура

```
┌─────────────────────────────────────────────────────┐
│                 Web GUI (Flask/WebSocket)            │
│         + Qt6 Desktop GUI (ncp-qt.exe)              │
├─────────────────────────────────────────────────────┤
│              CLI Application (ncp / ncp.exe)         │
├─────────────────────────────────────────────────────┤
│        Core Library (libncp_core) — 18+ модулей     │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐  │
│  │DPI Core │ │ Geneva   │ │  ECH   │ │ Crypto   │  │
│  │ Engine  │ │ Engine   │ │  HPKE  │ │ Engine   │  │
│  ├─────────┤ ├──────────┤ ├────────┤ ├──────────┤  │
│  │Spoofing │ │ Mimicry  │ │  SPA   │ │  Covert  │  │
│  │ Module  │ │  Module  │ │ Auth   │ │ Channels │  │
│  ├─────────┤ ├──────────┤ ├────────┤ ├──────────┤  │
│  │  Flow   │ │Behavioral│ │ Reality│ │  TURN    │  │
│  │ Shaping │ │  Cloak   │ │ Style  │ │  Server  │  │
│  └─────────┘ └──────────┘ └────────┘ └──────────┘  │
└─────────────────────────────────────────────────────┘
```

### Структура директорий

| Директория | Назначение |
|---|---|
| `src/core/` | Ядро: 18+ модулей (libncp_core) |
| `src/cli/` | CLI-приложение (ncp) |
| `src/gui/` | Qt6 десктопное GUI |
| `web/` | Flask-based Web GUI |
| `bpf/` | eBPF/XDP программы для обработки пакетов в ядре |
| `docker/` | DPI Lab, тестовые стенды |
| `deploy/` | Автоустановщик (install.sh + docker-compose) |
| `tests/` | Unit + fuzz тесты |
| `deps/` | Vendored зависимости (WFP SDK headers) |
| `docs/` | Документация |
| `cmake/` | Toolchain файлы (вкл. mingw-w64 cross-compile) |
| `npm/` | npm-пакет для дистрибуции |

---

## 🧠 Ключевые модули и возможности

### 1. DPI Bypass Engine (15+ техник)

**Пакетные техники (driver mode — WinDivert/NFQUEUE):**
- **TCP Split** — разбиение ClientHello на позиции byte/SNI/midSLD
- **Multi-split** — многослойное разбиение
- **Fake TLS** — поддельные пакеты с bad checksum/badseq/low-TTL
- **Overlap** — same-seq decoy + real pair
- **Disorder** — перестановка сегментов
- **Reverse Fragmentation** — обратная фрагментация
- **Zapret chains** — совместимость с цепочками zapret
- **Fake QUIC** — генерация фейковых QUIC Initial пакетов

**Техники на уровне протокола:**
- **ECH (Encrypted Client Hello)** — HPKE по RFC 9180, шифрование SNI
- **Domain Fronting** — безопасный outer SNI rewrite
- **TLS Fingerprint Randomization** — эмуляция JA3/JA4 профилей (Chrome/Firefox/Safari/Edge)
- **Adversarial Padding** — adversarial-обученные паддинги

### 2. Geneva Genetic Algorithm Engine

Автоматический поиск DPI-bypass стратегий с помощью генетического алгоритма (вдохновлён проектом Geneva). Модуль `ncp_geneva_engine` эволюционирует стратегии обхода.

### 3. Anti-ТСПУ ML (Machine Learning)

- **BehavioralCloak** — поведенческая маскировка трафика
- **ProtocolRotationSchedule** — ротация протоколов по расписанию
- **SessionPatternRandomizer** — рандомизация паттернов сессий

### 4. Anti-СОРМ (Anti-SORM)

- **CovertChannelManager** — 4 скрытых канала передачи данных
- **CrossLayerCorrelator** — анализ межслойных корреляций
- **GeoObfuscator** — географическая обфускация

### 5. Синтез стратегий на лету (v1.8.0)

Модуль `ncp_strategy_synth` строит desync-стратегию под каждый адрес из трёх генов:
- **Split** — позиция разбиения
- **Order** — порядок сегментов
- **Fake** — тип фейкового пакета

Лестница из 12 кандидатов упорядочивается по **сглаженным по Лапласу** глобальным win-rate. Это математически обоснованный подход к адаптации.

### 6. Криптография

| Компонент | Технология |
|---|---|
| Симметричное шифрование | ChaCha20-Poly1305, XChaCha20-Poly1305 (libsodium) |
| Key exchange | X25519, Curve25519, P-256, P-384, X448 |
| Подписи | Ed25519 |
| Post-quantum | Kyber1024 KEM, CRYSTALS-Dilithium5 (liboqs) |
| ECH | HPKE (RFC 9180) |
| CSPRNG | libsodium randombytes_* (полная замена mt19937) |
| Header protection | HKDF-SHA256 per-session prefixes (в стиле AWG 3.1) |

### 7. Network Spoofing

- **MAC/IP/Hostname** — спуфинг идентификаторов
- **ARP Spoofing** — L2 stealth
- **DHCP Spoofing** — DHCP client ID ротация
- **Hardware Identity** — board serial, SMBIOS, disk serial (аудит R18 нашёл проблемы)

### 8. SPA (Single Packet Authorization)

Ed25519-подписанный UDP-пакет (256 байт) — современный аналог port knocking:
- Ключ-id, timestamp, nonce, requested proto/port/TTL
- 64-byte подпись + CSPRNG padding
- Per-key nonce cache + ±60s timestamp window
- Защита от replay-атак

### 9. Enterprise-модули

- **XTLS-Reality style** — авторизация через SNI-токен
- **Dynam TURN** — native TURN сервер/клиент
- **SSH AutoDeploy** — автоматическое развёртывание
- **Server Identity Pinning** — TOFU в стиле SSH (Ed25519)
- **I2P** — SAM bridge клиент (интеграция с I2P-сетью)
- **Traffic Mimicry** — имитация легитимного трафика
- **Traffic Shaping** — Wasserstein-1 distance, оптимальный транспорт

---

## 🧪 Тестирование и DPI Lab

### DPI Lab — Userspace эмулятор

Полноценный эмулятор DPI с TCP-реассемблированием:
- **NFQUEUE** режим с буферными лимитами
- **Strict/Permissive** OOO (out-of-order) политики
- 4 автоматических тестовых сьюта:

| Suite | Цель | Проверки |
|---|---|---|
| suite1_correctness | Формирование desync-пакетов | Позиции split vs TLS record/SNI, seq/ack, ретрансмиты |
| suite2_dpi_models | Матрица bypass | ncp modes × DPI models × impairments |
| suite3_compat | Совместимость | TLS 1.2/1.3, HTTP/1.1/2, QUIC |
| suite4_perf | Производительность | N=20 downloads, CPU, ретрансмиты |

### Боевые результаты (2026-08-17)

- **tspu / chain** обходят string-match DPI на **100%** при clean, delay50, loss5, reorder
- Positional splits — **0% против reassembly model** (нужны overlap/bad-checksum/multidisorder)
- **HTTP/2 over desync verified** (ALPN h2, TLS 1.3)
- **IPv6 — открытый путь обхода** (DPI логика IPv4-only)
- ~103 MB/s при 50 MB downloads, overhead +2-8 ms

### Docker-топологии

- **3-node midbox** — классический mid-box DPI
- **2-node combined Server/DPI** — inline DPI
- **DPI Lab** — изолированный полигон

---

## 🔒 Безопасность и аудиты

### История аудитов (R8–R19)

Проект прошёл через **12 раундов аудита** с публичной документацией:

| Раунд | Дата | Масштаб | Результат |
|---|---|---|---|
| R8 | 2026-03 | Source review | Исправлено |
| R9 | 2026-03 | Independent review | Исправлено |
| R10–R15 | 2026-03–09 | Various | Исправлено |
| **R16** | **2026-09-12** | **~90K LOC external audit** | **11 critical + ~20 high + ~14 minor → ВСЕ ИСПРАВЛЕНЫ** |
| R17 | 2026-11-16 | +53.7K LOC | 2 high + 3 medium + 4 low + 1 efficiency → ИСПРАВЛЕНЫ |
| R18 | 2026-11-16 | spoofer.cpp | 1 high + 5 medium + 3 low (открыты) |
| R19 | 2026-11-16 | CLI safety | Исправлено |

### Ключевые исправленные уязвимости

1. **Timing Oracle** в auth verification → заменён на constant-time `sodium_memcmp`
2. **XOR как HMAC fallback** → заменён на libsodium `crypto_auth()`
3. **CSPRNG: raw /dev/urandom** → `randombytes_buf()` из libsodium
4. **SSL_CTX Double-Free** в DoH → корректное управление временем жизни через pImpl
5. **Off-by-one buffer read** в TCP split → bounds checks + 2.5M fuzzing итераций
6. **License MITM** (нет проверки hostname) → исправлено
7. **ECH HPKE double-encap** → исправлено
8. **XSS в веб-панели** (W-01..W-08) → исправлено
9. **Гонка данных** в TurnServerStats → атомарные счётчики (TSAN clean)
10. **blockcheck не работал вообще** (неверные длины расширений ClientHello → fatal decode_error) → исправлено в v1.8.0

### CSPRNG миграция (Phase 0)

Полная замена `std::mt19937` на libsodium `randombytes_*` во всех модулях — 12 коммитов, 0 mt19937 осталось в `src/` и `examples/`.

---

## 👤 Автор: kirin2461

| Факт | Детали |
|---|---|
| **Локация** | Москва (хочет переехать в Канаду) |
| **GitHub** | github.com/kirin2461 (Developer Program Member) |
| **Telegram** | @kirin2461, @Jealous1488no |
| **Организация** | DynamNetWorkSystems |
| **Bio** | "Little mental broken" / "Idk what to write here" |
| **Contributions** | 654 за последний год |
| **Другие проекты** | ProjectSofia (SOAR + LLM CASCADE AI), Nemaxks (React/TS приложение) |

### Стилистика разработки

Автор работает **интенсивными burst-сессиями** (49 коммитов за один день — январь 2026), с длинными паузами. Активно использует AI-инструменты (Claude/assistant) для код-ревью и фикса — многие PR содержат `@kirin2461-OSS @claude` в описаниях.

---

## 📊 Сравнение с аналогами

| Характеристика | Dynam | GoodbyeDPI | Zapret | ByeDPI | ShadowDPI |
|---|---|---|---|---|---|
| **Язык** | C++17 | C | C | C | C++20 |
| **Платформы** | Win/Lin/Mac | Windows | Linux/Win | Cross-platform | Windows x64 |
| **DPI техник** | 15+ | ~5 | ~10 | ~5 | ~5 |
| **Geneva GA** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Post-quantum crypto** | ✅ (Kyber1024) | ❌ | ❌ | ❌ | ❌ |
| **ECH/HPKE** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Anti-ML** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Anti-SORM/Covert channels** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GUI** | Web + Qt6 | ❌ | ❌ | ❌ | ❌ |
| **DPI Lab** | ✅ | ❌ | blockcheck | ❌ | ✅ (benchmark) |
| **SPA** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Лицензия** | AGPLv3 | GPL | MIT | GPL | GPLv3 |
| **Масштаб** | ~90K+ LOC | ~5K LOC | ~30K LOC | ~10K LOC | ~10K LOC |

**Dynam — на порядки масштабнее** любого из аналогов. Это не просто DPI-bypass, а целая платформа с 18+ модулями, генетическим алгоритмом, anti-ML, постквантовой криптографией, скрытыми каналами и полной инфраструктурой тестирования.

---

## 🔗 Экосистема и связи

### Попытка коллаборации с sing-box

В марте 2026 kirin2461 открыл issue [#540](https://github.com/SagerNet/sing-box/issues/3909) в sing-box с предложением совместной разработки DPI-resistant транспорта. Issue был закрыт без обсуждения.

### Теоретический репозиторий

[kirin2461/Some-theorical-stuff-](https://github.com/kirin2461/Some-theorical-stuff-) содержит философские и теоретические работы:
- Теория когнитивной архитектуры
- Модель угроз и границы доверия
- Философия Kirin2461
- Теория сети на основе Dynam

### Связанные организации

- **DynamNetWorkSystems** — GitHub-организация
- **InfraMap** — концепция платформы (из теоретического репозитория)
- **ProjectSofia** — AI-ассистент с когнитивной архитектурой (SOAR + LLM CASCADE)

---

## 📈 История версий

| Версия | Дата | Ключевые изменения |
|---|---|---|
| v1.0 (Initial) | Март 2026 | Initial commit: полный исходный код |
| v1.5.3 | Июль 2026 | In-app help system, DNS DHCP recovery |
| v1.6.0 | Август 2026 | 604 теста, Web GUI, DPI Lab, licensing |
| v1.7.0 | Сентябрь 2026 | AWG 3.1 hardening, scoped trust (NUC), auto-installer |
| v1.7.1 | Сентябрь 2026 | R16 audit fixes |
| v1.7.2 | Октябрь 2026 | Version stamping, macOS OpenSSL 4.x fix |
| v1.7.3 | Октябрь 2026 | Windows 10/11, Linux, macOS binaries |
| v1.7.5 | Октябрь 2026 | Preset AutoPilot |
| v1.7.6 | Октябрь 2026 | Auto-detect preset, GUI engine fix |
| **v1.8.0** | **23 ноября 2026** | **Синтез стратегий, адаптивный клиент, защищённые транспорты, 1464 теста** |

---

## ⚠️ Критический анализ

### Сильные стороны

1. **Невероятная техническая глубина** — от eBPF/XDP до постквантовой криптографии
2. **Зрелая тестовая инфраструктура** — 1464 теста, fuzz testing, Docker DPI Lab
3. **Прозрачность аудитов** — 12 публичных раундов, все findings задокументированы
4. **Современный стек** — C++17 constexpr/noexcept, CMake, GoogleTest, libsodium
5. **Кроссплатформенность** — Windows/Linux/macOS с cross-compile поддержкой
6. **Математический подход** — Wasserstein-1 distance, Laplace smoothing, genetic algorithms
7. **Полный цикл разработки** — от теории (Some-theorical-stuff) до продакшн-бинарников

### Риски и проблемы

1. **Масштаб vs. один разработчик** — ~90K LOC, 18+ модулей, один автор. Высокий bus factor.
2. **AI-assisted разработка** — много AI-ассистированного кода; качество варьируется (аудит R18 нашёл "косметические" спуфинг-модули)
3. **Модули-заглушки** — некоторые модули (NFQUEUE driver mode, check_memory_integrity) были стабами до R16
4. **Лицензирование (коммерческое)** — Ed25519-подписанные ключи, trial-период — необычно для open-source
5. **Нет подтверждения реального обхода** — сам автор подчёркивает: "результаты DPI Lab не означают подтверждённый внешний обход блокировок конкретных сервисов"
6. **Секретность автора** — минимальная публичная информация, только Telegram
7. **Низкая adoption** — 15 звёзд за 9 месяцев; нет упоминаний в сообществе (Hacker News, Reddit)
8. **Spoofer проблемы** — R18 показал: hardware-identity spoofing "broken, cosmetic or harmful"

### Вопрос доверия

Проект выглядит как **pet project чрезвычайно мотивированного и технически одарённого разработчика**. Он демонстрирует глубокое понимание сетевых протоколов, криптографии и системного программирования. Однако масштаб проекта и скорость разработки (328 коммитов за 9 месяцев) вызывают вопросы о том, насколько весь код действительно протестирован и безопасен.

---

## 🎯 Выводы

**Dynam** — это **уникальный проект** в ландшафте антицензурных инструментов. Ни один другой open-source проект не сочетает такой набор возможностей:

- Генетический алгоритм для поиска стратегий
- Постквантовая криптография
- Encrypted Client Hello (HPKE)
- Anti-ML и anti-SORM модули
- Полноценный DPI Lab с TCP реассемблированием
- 15+ техник обхода DPI на пакетном уровне

**Для кого:**
- Технические специалисты, интересующиеся обходом DPI
- Исследователи сетевой безопасности
- Разработчики в области anti-censorship
- Люди в регионах с активной интернет-цензурой

**Для кого НЕ подходит:**
- Нетехнические пользователи (нужна сборка или использование CLI)
- Те, кому нужен простой "установил и забыл" (хотя v1.7.6+ AutoPilot приближается)
- Те, кому критична независимая верификация безопасности (проект молодой, один разработчик)

**Рекомендация:** Проект заслуживает внимания как **исследовательская платформа** и как **вдохновение для community-driven развития**. Для продакшн-использования в критических сценариях рекомендуется дождаться большего community review и независимого аудита.

---

*Исследование проведено на основе публичных данных из GitHub, release notes, аудитов, документации и веб-поиска.*
