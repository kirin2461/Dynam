# NCP User Guide

## Быстрый старт

### Установка

```bash
# Linux / macOS
sudo apt-get install -y cmake build-essential git libsodium-dev libssl-dev libpcap-dev libgtest-dev
git clone https://github.com/kirin2461/Dynam.git
cd Dynam && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=ON
cmake --build . -j$(nproc)
```

```bash
# Windows
git clone https://github.com/kirin2461/Dynam.git
cd Dynam
build.bat
```

### Запуск

```bash
# Полная защита (рекомендуется)
ncp run

# Только DPI bypass
ncp dpi --mode proxy --port 8080 --target example.com --preset RuNet-Strong

# Статус
ncp status
```

---

## Режимы работы

### PARANOID Mode (рекомендуется)

Команда `ncp run` активирует все 8 уровней защиты:

1. **Entry Obfuscation** — bridge nodes, guard rotation
2. **Multi-Anonymization** — VPN → Tor → I2P chain
3. **Traffic Obfuscation** — constant rate, morphing
4. **Timing Protection** — random delays, batching
5. **Metadata Stripping** — header sanitization
6. **Advanced Crypto** — post-quantum, forward secrecy
7. **Anti-Correlation** — traffic splitting, multi-circuit
8. **System Protection** — memory wipe, secure delete

Plus: Protocol Orchestrator с адаптивным переключением стратегий.

### DPI Bypass Mode

Обход DPI без полной защиты:

```bash
# Пресет для России (ТСПУ)
ncp dpi --mode proxy --preset RuNet-Strong --port 8080 --target blocked-site.com

# Кастомная настройка
ncp dpi --mode proxy --split-at-sni --fragment-size 2 --fake-ttl 3
```

---

## DPI Bypass: Техники

### Базовые техники

| Техника | Описание | Команда |
|---------|----------|---------|
| SNI Split | Разделение ClientHello в позиции SNI | `--split-at-sni` |
| Fake Packets | Фейковые пакеты с низким TTL | `--fake-ttl 2` |
| Fragmentation | TCP фрагментация | `--fragment-size 2` |
| Noise | Добавление шума | `--noise 128` |

### Продвинутые техники

| Техника | Описание |
|---------|----------|
| **TLS Fingerprinting** | Генерация ClientHello по профилям реальных браузеров (Chrome/Firefox/Safari/Edge) с JA3/JA4 fingerprints |
| **ECH (Encrypted Client Hello)** | Шифрование SNI через HPKE — DPI не может прочитать целевой домен |
| **GREASE Injection** | RFC 8701 — рандомизация TLS extensions для обхода fingerprinting |
| **Decoy SNI** | Фейковые ClientHello с невинными доменами (google.com) перед настоящим |
| **Multi-layer Split** | Разделение пакета в нескольких позициях |
| **Traffic Obfuscation** | ChaCha20/XOR/HTTP camouflage шифрование |
| **Timing Jitter** | Рандомизация задержек между сегментами |

### Пресеты

| Пресет | Для чего | Эффективность |
|--------|----------|---------------|
| TSPU | Россия (ТСПУ) | ⭐⭐⭐⭐⭐ |
| GFW | Китай (Great Firewall) | ⭐⭐⭐⭐ |
| Iran | Иран | ⭐⭐⭐ |
| Aggressive | Максимальный обход | ⭐⭐⭐⭐⭐ |
| Stealth | Минимальный след | ⭐⭐⭐⭐ |
| Compatible | Совместимость | ⭐⭐ |

---

## Protocol Orchestrator

Orchestrator — единый pipeline для всех защитных компонентов. Работает автоматически:

### Стратегии

- **max_compat** — минимальная защита, максимальная совместимость
- **performance** — базовая защита, минимальное влияние на скорость
- **balanced** — средняя защита + AdvancedDPI + ECH
- **stealth** — максимальная защита, все техники включены

### Адаптивное переключение

Orchestrator автоматически переключает стратегию при:
- **Escalation**: CONNECTION_RESET, TLS_ALERT, PROBE_RECEIVED → повышение уровня
- **Deescalation**: 20+ успешных соединений → понижение уровня

Таймаут cooldown: 5 минут между deescalations.

---

## TLS Fingerprinting

NCP генерирует ClientHello, неотличимые от реальных браузеров:

- **Chrome** — актуальный набор cipher suites и extensions
- **Firefox** — отличный от Chrome порядок extensions
- **Safari** — уникальные supported_groups
- **Edge** — Chromium-based профиль

Per-connection rotation: каждое соединение может получить рандомный профиль для защиты от JA3 tracking.

---

## ECH (Encrypted Client Hello)

ECH шифрует SNI extension в ClientHello, делая его невидимым для DPI.

**Требования**: OpenSSL 3.2+ с HPKE support.

**Без OpenSSL 3.2+**: Pipeline работает нормально, ECH просто не применяется.

ECH config можно получить:
- Из DNS HTTPS записи целевого домена
- Hardcoded для известных CDN (Cloudflare, etc.)
- Сгенерировать для собственного сервера

---

## Команды CLI

| Команда | Описание |
|---------|----------|
| `ncp run [iface]` | Полная защита (8 уровней + DPI + Orchestrator) |
| `ncp stop` | Остановить и восстановить настройки |
| `ncp status` | Текущий статус защиты |
| `ncp rotate` | Ротация всех идентификаторов |
| `ncp crypto keygen` | Генерация Ed25519 keypair |
| `ncp crypto random <size>` | Криптографически случайные байты |
| `ncp license hwid` | Hardware ID системы |
| `ncp license info` | Информация о лицензии |
| `ncp network interfaces` | Список сетевых интерфейсов |
| `ncp network stats` | Статистика трафика |
| `ncp dpi [options]` | DPI bypass proxy |
| `ncp i2p <enable/disable/status>` | I2P управление |
| `ncp mimic <http/tls/none>` | Traffic mimicry |
| `ncp tor` | Настройка Tor proxy |
| `ncp obfuscate` | Обфускация трафика |
| `ncp dns-secure` | DNS leak protection |
| `ncp help` | Справка |

---

## Мониторинг и статистика

### DPI Statistics

```
Packets total: 1234
Packets fragmented: 987
Fake packets sent: 456
GREASE injected: 123
ECH applied: 89
TLS records split: 654
Bytes obfuscated: 567890
```

### Orchestrator Statistics

```
Threat level: MEDIUM
Strategy: balanced
TLS fingerprints applied: 42
ECH encryptions: 38
Advanced DPI segments: 156
Overhead: 12.5%
Escalations: 1
Deescalations: 0
```

---

## Безопасность

- Все рандомные данные через libsodium CSPRNG (zero `std::mt19937`)
- Ключи шифрования обнуляются через `sodium_memzero` при уничтожении
- TLS session keys в `ProtocolMimicry` защищены secure memory
- ECH private keys хранятся в SecureBuffer
- Kill switch при потере VPN соединения
- Secure file deletion (DOD 5220.22-M)

---

## Troubleshooting

### Сайты не открываются
1. Используйте `--preset RuNet-Soft` вместо `RuNet-Strong`
2. Увеличьте `--fragment-size 8`
3. Отключите fake packets

### DPI блокирует
1. Включите TLS Fingerprint (Chrome профиль)
2. Включите ECH (если OpenSSL 3.2+)
3. Используйте Aggressive preset
4. Добавьте больше decoy SNI доменов

### Низкая скорость
1. Отключите timing jitter
2. Используйте Stealth preset
3. Отключите обфускацию трафика

### ECH не применяется
1. Проверьте OpenSSL: `openssl version` → нужна 3.2+
2. Проверьте ECH config blob
3. Посмотрите `stats.ech_applied` — должно быть > 0

---

## Ссылки

- [docs/ARCHITECTURE.md](ARCHITECTURE.md) — Архитектура системы
- [docs/DPI_ADVANCED_GUIDE.md](DPI_ADVANCED_GUIDE.md) — Подробное руководство по DPI
- [docs/BUILD.md](BUILD.md) — Инструкции по сборке
- [docs/SECURITY_FIXES.md](SECURITY_FIXES.md) — Исправления безопасности
- [docs/CLI_COMMANDS.md](CLI_COMMANDS.md) — Полный список команд CLI
