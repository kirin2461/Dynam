# NCP CLI Commands Reference

Полный справочник команд NCP CLI v1.0.0.

## Содержание

- [Общая информация](#общая-информация)
- [Команда run (PARANOID Mode)](#команда-run-paranoid-mode)
- [Спуфинг сети](#спуфинг-сети)
- [Криптографические операции](#криптографические-операции)
- [Управление лицензиями](#управление-лицензиями)
- [Сетевые операции](#сетевые-операции)
- [Обход DPI](#обход-dpi)
- [I2P интеграция](#i2p-интеграция)
- [Маскировка трафика](#маскировка-трафика)
- [Дополнительные команды](#дополнительные-команды)

---

## Общая информация

### Запуск CLI

```bash
# Windows
ncp.exe <command> [options]

# Linux/macOS
./ncp <command> [options]
```

### Получение справки

```bash
ncp help
```

### Список всех команд

| Команда | Описание |
|---------|----------|
| `run [iface]` | Запуск PARANOID режима со всеми слоями защиты + спуфинг + DPI bypass |
| `stop` | Остановка спуфинга и восстановление настроек |
| `status` | Показать текущий статус защиты |
| `rotate` | Ротация всех идентичностей (IP/MAC/DNS) |
| `crypto keygen` | Генерация ключевой пары Ed25519 |
| `crypto random <size>` | Генерация криптографически безопасных случайных байтов |
| `license hwid` | Получить Hardware ID системы |
| `license info` | Показать статус лицензии |
| `network interfaces` | Список сетевых интерфейсов |
| `network stats` | Статистика трафика |
| `dpi [options]` | DPI bypass прокси (--mode proxy/driver/passive, --preset RuNet-Soft/RuNet-Strong) |
| `i2p <enable/disable/status>` | Управление I2P интеграцией |
| `mimic <http/tls/none>` | Установить тип маскировки трафика |
| `tor` | Настройка Tor прокси (bridges/hops) |
| `obfuscate` | Переключить продвинутую обфускацию трафика |
| `dns-secure` | Переключить защиту от DNS утечек |
| `help` | Показать справку |

---

## Команда run (PARANOID Mode)

```bash
ncp run [iface]
```

**Описание:** Главная команда. Автоматически активирует **PARANOID режим** (уровень TINFOIL_HAT) со всеми 8 слоями защиты:

| Слой | Название | Описание |
|------|----------|----------|
| 1 | Entry Obfuscation | Bridge-ноды, ротация entry guards (каждые 6 часов) |
| 2 | Multi-Anonymization | VPN chain (2 hop) -> Tor -> I2P |
| 3 | Traffic Obfuscation | Constant rate traffic (128 kbps), морфинг, рандомизация размеров |
| 4 | Timing Protection | Случайные задержки (50-500ms), батчинг (по 10 пакетов) |
| 5 | Metadata Stripping | Удаление всех заголовков, fingerprints |
| 6 | Advanced Crypto | Post-quantum, forward secrecy, deniable encryption, рекиинг каждые 15 мин |
| 7 | Anti-Correlation | Разделение трафика, 3 одновременных circuit, запрет переиспользования |
| 8 | System Protection | Memory wipe, отключение disk cache/swap, secure delete (7 проходов) |

Дополнительно при `run` активируются:
- **Network Isolation**: kill switch, блокировка IPv6/WebRTC/локальных соединений, изоляция per-domain/per-tab
- **Forensic Resistance**: шифрование памяти, предотвращение memory dumps, шифрование temp файлов, отключение логов
- **Traffic Analysis Resistance**: padding до 1500 байт, burst suppression, WFP defense, dummy packets
- **Advanced Features**: obfs4, meek, snowflake транспорты
- **Spoofing**: полный спуфинг IPv4/IPv6/MAC/DNS
- **DPI Bypass**: TCP фрагментация, fake packets, disorder mode

**Пример:**

```bash
# Запуск на конкретном интерфейсе
ncp run eth0

# Интерактивный выбор интерфейса
ncp run
```

> **Примечание:** Команда `run` требует прав администратора/root. Нажмите `Ctrl+C` для остановки.

---

## Спуфинг сети

### Остановка спуфинга

```bash
ncp stop
```

Останавливает спуфинг, деактивирует PARANOID режим и восстанавливает оригинальные настройки. При остановке:
- Очистка всех следов (clear_all_traces)
- Деактивация cover traffic
- Остановка DPI bypass
- Восстановление оригинальных IP/MAC/DNS

### Статус спуфинга

```bash
ncp status
```

### Ротация идентичностей

```bash
ncp rotate
```

Генерирует новые случайные значения для всех спуфированных параметров.

---

## Криптографические операции

### Генерация ключевой пары Ed25519

```bash
ncp crypto keygen
```

### Генерация случайных байтов

```bash
ncp crypto random <size>
```

**Примеры:**

```bash
ncp crypto random 32  # для ключа шифрования
ncp crypto random 16  # для IV/nonce
```

---

## Управление лицензиями

### Получение Hardware ID

```bash
ncp license hwid
```

### Информация о лицензии

```bash
ncp license info
```

Лицензия проверяется офлайн по файлу `license.dat`.

---

## Сетевые операции

### Список сетевых интерфейсов

```bash
ncp network interfaces
```

### Сетевая статистика

```bash
ncp network stats
```

---

## Обход DPI

```bash
ncp dpi [options]
```

**Опции:**

| Опция | Описание | По умолчанию |
|-------|----------|-------------|
| `--mode` | Режим: `proxy`, `driver`, `passive` | `proxy` |
| `--port` | Порт прокси | `8080` |
| `--target` | Целевой хост | - |
| `--target-port` | Целевой порт | `443` |
| `--fragment-size` | Размер фрагмента TCP | `2` |
| `--split-position` | Позиция разделения ClientHello | - |
| `--split-at-sni` | Разделение по SNI | - |
| `--enable-fake` / `--disable-fake` | Fake пакеты с низким TTL | включено |
| `--enable-disorder` / `--disable-disorder` | Disorder порядка пакетов | включено |
| `--preset` / `--profile` | RuNet-Soft / RuNet-Strong | - |

**Примеры:**

```bash
# Мягкий RuNet режим
ncp dpi --mode proxy --port 8080 --target example.com --preset RuNet-Soft

# Агрессивный RuNet режим
ncp dpi --mode proxy --port 8080 --target example.com --preset RuNet-Strong

# Режим драйвера (Linux, требует root и NFQUEUE)
ncp dpi --mode driver
```

> При команде `run` DPI bypass запускается автоматически.

---

## I2P интеграция

```bash
ncp i2p enable    # Включить I2P
ncp i2p disable   # Выключить I2P
ncp i2p status    # Статус I2P
```

Управление интеграцией с I2P (garlic routing, SAM bridge).

---

## Маскировка трафика

```bash
ncp mimic http    # HTTP маскировка
ncp mimic tls     # TLS маскировка
ncp mimic none    # Отключить
```

### Tor прокси

```bash
ncp tor
```

Настройка Tor прокси с поддержкой bridges и выбором количества hops.

---

## Дополнительные команды

### Обфускация трафика

```bash
ncp obfuscate
```

Переключает продвинутую обфускацию трафика.

### DNS защита

```bash
ncp dns-secure
```

Переключает защиту от DNS утечек (DNS over HTTPS).

---

## Коды возврата

| Код | Описание |
|-----|----------|
| 0 | Успешное выполнение |
| 1 | Неизвестная команда |

## Требования

- Права администратора/root для команд спуфинга и `run`
- Установленные зависимости: libsodium, openssl, sqlite3
- libpcap (Linux/macOS) для packet capture
- Qt6 для GUI (опционально)
