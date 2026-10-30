# NCP CLI Commands Reference

Справочник команд NCP CLI v1.5.0-dev.

> **Важно**: Основные команды управления уже реализованы в рамках класса `Application`.

## Статус реализации

| Команда | Статус | Описание |
|---------|--------|----------|
| `status` | ✅ Работает | Показать текущий статус защиты |
| `help` | ✅ Работает | Показать справку |
| `run [iface]` | ✅ Работает | Запуск PARANOID режима на интерфейсе |
| `stop` | ✅ Работает | Остановка спуфинга и возвращение настроек |
| `rotate` | ✅ Работает | Ротация всех идентичностей (IP/MAC/DNS) |
| `crypto` | 🚧 В разработке | Операции с ключами и шифрованием |
| `license` | 🚧 В разработке | Управление лицензиями |
| `network` | 🚧 В разработке | Сетевая статистика и интерфейсы |
| `dpi` | 🚧 В разработке | Ручное управление DPI Bypass |
| `i2p` | 🚧 В разработке | Управление I2P SAM Bridge |

---

## Описание команд

### Команда `run`
Активирует 7-стадийный пайплайн Protocol Orchestrator. Включает TLS Fingerprinting, Advanced DPI Bypass и Flow Shaping.

### Команда `rotate`
Вызывает `RotationCoordinator` для немедленной смены всех параметров анонимизации, включая MAC-адрес и сессионные ключи.


### Команда `status`
Выводит информацию о текущем Threat Level, активном интерфейсе и статистике заблокированных зондов (Probe Resistance).


### Команда `porthop` — secure mimicry mode

UDP-транспорт PortHop поддерживает явный защищённый режим мимикрии
(`NcpConnectionDirector` + `NcpMimicrySession` поверх кадров PortHop):

```bash
ncp porthop serve  --base-port 20000 --range 50 --secret <s> \
    --mimicry-profile voip_opus
ncp porthop client --host 127.0.0.1 --base-port 20000 --range 50 \
    --secret <s> --message "hello" \
    --mimicry-profile voip_opus --mimicry-transition youtube_stream
```

- `--mimicry-profile <id>` — включает per-session E2E-защищённую мимикрийную
  сессию, ключованную PortHop session id. Обе стороны должны включить режим
  явно. Встроенные профили: `webrtc_video`, `zoom_call`, `youtube_stream`,
  `voip_opus`.
- `--mimicry-transition <id>` — (только client) после handshake запрашивает
  согласованную «горячую» смену профиля без переподключения
  (PREPARE → READY → COMMIT → CONFIRM, см. `docs/MIMICRY_PROFILES.md`).
  Во время handshake запрос может вернуть BUSY — это штатно, CLI выдерживает
  паузу на capability negotiation.
- Без `--mimicry-profile` сохраняется прежний legacy RAW demo-режим
  (plaintext echo) — он не изменён и не используется совместно с защищённым
  режимом.

Дополнительные флаги secure-режима (serve и/или client, см. `ncp porthop --help`):

- `--mimicry-catalog <path>` — загрузить внешний подписанный каталог
  (`MimicryCatalogIo::load_file`) ДО создания сессии; id профилей из файла
  становятся доступны для `--mimicry-profile`/`--mimicry-transition`.
- `--mimicry-allowed <csv>` — allow-list id профилей: запрошенные
  `--mimicry-profile`/`--mimicry-transition` должны входить в список, а
  подключённый автопилот исключает все профили вне списка из кандидатов.
- `--mimicry-require-signed` — явно требовать доверенную Ed25519-подпись
  внешних записей (это и так поведение по умолчанию, SignaturePolicy::ENFORCE).
- `--mimicry-allow-unsigned-dev` — DEV ONLY: принимать неподписанные внешние
  записи (DEV_UNSIGNED, выводится громкое предупреждение).
- `--mimicry-auto` / `--mimicry-locked` — (client) подключить
  `MimicryAutoPilot` в режиме AUTO (автовыбор через
  `director.transition_request_handler`) или LOCKED (только мониторинг,
  смены профиля запрещены, несовместим с `--mimicry-transition`).
  По умолчанию — MANUAL: только явный `--mimicry-transition`.
- `--mimicry-switch-cooldown <s>`, `--mimicry-min-dwell <s>`,
  `--mimicry-hysteresis <pct>` — параметры автопилота
  (`cooldown_ms`/`min_dwell_ms`/`hysteresis_pct`); требуют
  `--mimicry-auto` или `--mimicry-locked`.
- `--mimicry-transition-grace <ms>` — grace-окно приёма старого layout после
  активации transition (`ProfileTransitionConfig::grace_period_ms`).
- `--mimicry-stats-json <path>` — записать итоговый JSON со статистикой
  сессии в файл (атомарно, tmp+rename); без флага JSON печатается в stdout
  при завершении client-сессии и при остановке serve. Поля:
  текущий/pending профиль (id+revision), `transition_state`, счётчики
  transitions effective/aborted/timed_out, `crypto_epoch`, `profile_epoch`,
  `mtu_budget_rejections`, агрегированные счётчики директора и блок
  автопилота (если подключён). Секреты и адреса пиров не выводятся.

### Команда `mimicry-catalog` — внешние каталоги профилей

```bash
ncp mimicry-catalog validate <path>   # полная валидация; exit 0/1 = valid/invalid
ncp mimicry-catalog list <path>       # id@revision, family, подпись (key id), issues
```

Обе команды работают с детерминированным бинарным контейнером NCPMCAT
(`MimicryCatalogIo`); `validate` ничего не регистрирует и не трогает trust
store. Легаси-команда `ncp mimic <type>` не изменена.

Гарантии защищённого режима: смена профиля не сбрасывает E2E ratchet,
replay window, счётчики и crypto epoch; plaintext fallback после
установленного E2E запрещён; legacy-пир без capability
`profile_transition_v1` продолжает работать в защищённом raw-режиме без
молчаливого изменения wire format.

> Ограничение: целевыми профилями transition могут быть только
> length-prefix-совместимые generic-маски (GENERIC_UDP/GENERIC_TCP) —
> это enforced на обоих концах, а не только задокументировано.
