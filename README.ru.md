# Dynam (NCP C++) — Network Control Protocol

[English](README.md) | **Русский**

> Многоуровневая платформа сетевой анонимизации и приватности: обход DPI, спуфинг трафика, параноидальный режим и современная криптография. Написана на современном C++17.

## Текущий статус

**Версия**: 1.6.0
**Версия CMake**: 1.5.0 (синхронизирована)

- ✅ **Сборка**: Linux (GCC 9+) и Windows (проверен кросс-билд mingw-w64 — статически слинкованный `ncp.exe`; поддерживается и MSVC) через CMake + Ninja.
- ✅ **Тесты**: 604 теста — 596 пройдено, 8 пропущено (интеграционные тесты I2P требуют живой SAM-мост), 0 упавших.
- ✅ **MASTER_ORCHESTRATOR на 100% готов**: полный 7-стадийный конвейер с anti-ML, стеганографией и поведенческой маскировкой.
- ✅ **Веб-интерфейс**: панель управления на Flask в `web/` (активация лицензии, переключатели модулей, живые логи, старт/стоп, живая статистика движка по модулям).
- ✅ **Лицензирование**: автоматический 7-дневный триал при первом запуске (все 19 модулей), ключи с подписью Ed25519 выпускаются отдельной утилитой `ncp-keygen`.
- ✅ **Десктопный GUI**: приложение Qt6 (`ncp-qt.exe`) с графиками, панелью лицензии и значком в трее.
- ✅ **Docker-тестовые стенды**: три изолированные топологии (3-узловой midbox, 2-узловой комбинированный Server/DPI, DPI Lab) — вся боевая матрица гоняется, не трогая сеть хоста.
- ✅ **DPI Lab**: юзерспейсный NFQUEUE-эмулятор DPI с TCP-реассемблированием (лимит буфера + политики strict/permissive для out-of-order), 4 автоматических набора тестов (формирование десинка / матрица обхода DPI-моделей / совместимость с эндпоинтами / производительность), профили tc-netem, дымовые тесты IPv6.

### Что нового в 1.5.3 – 1.6.0

- **v1.6.0 — избирательный пакетный обход (в стиле winws2).** WinDivert driver-режим получил опции `--hostlist` / `--hostlist-exclude` / `--ipset`: обход применяется только к доменам из списка (суффиксное совпадение по SNI) или к IP назначения (CIDR) — всё остальное идёт напрямую, без замедления. В веб-интерфейсе — новая карточка «Пакетный режим (WinDivert)» в разделе «Обход».
- **v1.5.5 — защита от «сломанного интернета».** Остановка приложения/прокси (и любой краш) теперь всегда восстанавливает системный прокси Windows; при старте лечатся «застывшие» настройки; preflight-проверка DoH не даёт включить системный прокси, если это убьёт интернет. Geneva GA останавливается с понятной подсказкой, если цель вообще не резолвится (DNS полностью заблокирован).
- **v1.5.4 — каскад DoH-эндпоинтов.** Движок перебирает 6 DoH-эндпоинтов с ограниченными таймаутами (1.5 с на подключение / 2 с на чтение) вместо одного захардкоженного провайдера; самотест проверяет 8 резолверов; исправлен шум в логах.
- **v1.5.3 — встроенная справка.** Понятные человеческие гайды по каждой функции (раздел «Справка», контекстные кнопки «?»), автовосстановление DNS на DHCP, таймаут blockcheck увеличен до 600 с.

### Прогресс реализации

**MasterOrchestrator — готов на 100%** (13 модулей, ~3500 строк):
- ✅ **Фаза 1: Базовая интеграция** — MasterOrchestrator, 7-стадийный конвейер, API отправки/приёма
- ✅ **Фаза 2: Anti-ТСПУ ML** — BehavioralCloak, ProtocolRotationSchedule, SessionPatternRandomizer
- ✅ **Фаза 3: Anti-СОРМ** — CovertChannelManager (4 канала), CrossLayerCorrelator, GeoObfuscator
- ✅ **Фаза 4: Безопасность** — PanicSequence (9 шагов), фоновый планировщик (8 задач)

- ✅ **Полностью реализовано и покрыто тестами**: криптография, обход DPI (включая midSLD-сплиты, zapret-цепочки, fake/fooling), продвинутый DPI, сетевой спуфинг, защищённая память/буферы, DoH, база данных, лицензии, логирование, конфигурация, CSPRNG, TLS-фингерпринтинг (JA3/JA4, браузерные профили), adversarial padding, flow shaping, probe resistance, L2/L3-стелс, ARP/DHCP-спуфинг, port knocking, SPA (Ed25519 Single Packet Authorization + управление ipset), XTLS-Reality fallback, Stego-DNS discovery, UDP port-hopping, статистические профили мимикрии трафика, TCP state confusion (desync), AEMM Reed-Solomon erasure coding, Fog Mesh relay, Semantic Fluid Transport, eBPF/XDP фильтрация в ядре, перехватчик пакетов, морфинг протоколов, burst-морфинг, маскировка энтропии, Geneva Engine/GA (кроссовер/мутация/селекция, синхронная и фоновая эволюция), управление идентичностью, защита по таймингам, пул потоков, координатор ротации, менеджер безопасности, фреймворк возможностей, I2P (клиент SAM-протокола), мимикрия трафика.

- ✅ **Исправленные проблемы безопасности**:
  - Несовпадение info-строки ECH — ИСПРАВЛЕНО (каноническая info-строка)
  - Перепутанные encaps/decaps в Kyber1024 — ИСПРАВЛЕНО (получатель декапсулирует)
  - OpenSSL-фолбэк ECDH_P256 — ИСПРАВЛЕНО (поддержка OpenSSL 1.1.1 + 3.0+)
  - Усечение соли HMAC — ИСПРАВЛЕНО (длинные соли хешируются)
  - Рандомизация TLS-фингерпринта — ИСПРАВЛЕНО (minor_permute вместо secure_shuffle)
  - Тайминг-оракул при проверке авторизации — ИСПРАВЛЕНО (memcmp постоянного времени)
  - XOR как фолбэк HMAC — ИСПРАВЛЕНО (libsodium crypto_auth)

- ⚠️ **Известные ограничения**:
  - I2P — SAM-клиент реализован и покрыт юнит-тестами; живым интеграционным тестам нужен запущенный I2P-роутер с SAM-мостом (порт 7656). Без него I2P-тесты сами пропускаются.
  - Шифрование базы SQLite (`SQLITE_HAS_CODEC`) требует SQLCipher; на стандартной SQLite база работает без шифрования и честно об этом сообщает.

## Сборка

### Linux

```bash
sudo apt install build-essential cmake ninja-build \
    libssl-dev libsodium-dev libsqlite3-dev libwebsockets-dev \
    libpcap-dev libnetfilter-queue-dev
cmake -B build -G Ninja -DENABLE_TESTS=ON -DENABLE_CLI=ON -DENABLE_GUI=OFF
cmake --build build
```

> `libwebsockets-dev` **обязателен** (защищённое туннелирование). `libpcap-dev` и
> `libnetfilter-queue-dev` опциональны, но включают L2-функции и NFQUEUE-бэкенд
> обхода DPI соответственно.

Бинарники: `build/bin/ncp` (CLI), `build/bin/ncp_tests` (набор тестов).

### Windows

#### Вариант A — кросс-компиляция из Linux (проверено)

Тестировано на Ubuntu 20.04 с mingw-w64 (получается статически слинкованный
`ncp.exe` с поддержкой ECH/HPKE):

```bash
sudo apt install mingw-w64
# Используйте POSIX-вариант потоков (поддержка std::thread/std::mutex):
sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix
sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
```

Соберите зависимости под mingw (проверенные версии):

- **libsodium 1.0.20** — `./configure --host=x86_64-w64-mingw32 --prefix=/opt/win-deps`
- **OpenSSL 3.5.1** — `./Configure mingw64 --prefix=/opt/win-deps --cross-compile-prefix=x86_64-w64-mingw32- no-shared no-tests no-apps`
- **libwebsockets 4.3.3** — CMake с тулчейн-файлом ниже, `-DLWS_WITH_SHARED=OFF -DLWS_WITH_ZLIB=OFF`

Затем сконфигурируйте и соберите:

```bash
cmake -B build-win -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
    -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=OFF -DENABLE_CLI=ON
cmake --build build-win     # -> build-win/bin/ncp.exe
```

#### Вариант B — MSVC (нативно)

Требования: Visual Studio 2019+, CMake и vcpkg:

```powershell
vcpkg install libsodium:x64-windows openssl:x64-windows libwebsockets:x64-windows
cmake -B build -DENABLE_CLI=ON -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

#### Требование для запуска (оба варианта)

Перехват пакетов на Windows использует **WinDivert**: скачайте
[WinDivert 2.x](https://reqrypt.org/windivert.html) и положите `WinDivert.dll`
и `WinDivert64.sys` рядом с `ncp.exe`, затем запускайте от имени администратора:

```powershell
ncp.exe run --preset tspu
```

> Устаревший WFP-бэкенд (Windows Filtering Platform) компилируется только при
> наличии полного WFP SDK (проверка `HAVE_WFP_SDK` в CMake). В mingw-w64 < v10
> файл `fwpmu.h` неполный, поэтому там WFP-код отключается автоматически
> (`NCP_NO_WFP`) — реальным бэкендом перехвата в любом случае является WinDivert.

## Установка через npm

Готовые бинарники `ncp` из [GitHub Releases](https://github.com/kirin2461/Dynam/releases)
распространяются как npm-пакет [`dynam-ncp`](https://www.npmjs.com/package/dynam-ncp):

[![npm version](https://img.shields.io/npm/v/dynam-ncp)](https://www.npmjs.com/package/dynam-ncp)

```bash
npm install -g dynam-ncp

dynam-ncp --help             # или просто `ncp`
sudo dynam-ncp run           # ПАРАНОИДАЛЬНЫЙ режим (все уровни защиты)
dynam-ncp proxy --port 1080  # локальный SOCKS5/HTTP desync-прокси (без прав админа)
dynam-ncp spa keygen --out my_spa
```

Поддерживаемые платформы: `linux-x64`, `darwin-x64`, `darwin-arm64` (через Rosetta 2),
`win32-x64`. Скрипт postinstall скачивает и проверяет подходящий ассет релиза;
на неподдерживаемых платформах установка завершается с предупреждением, и можно
собрать из исходников. Подробности и переменные окружения: [`npm/README.md`](npm/README.md).

## Тестирование

```bash
cd build
./bin/ncp_tests            # полный набор: 604 теста
```

Набор безопасен для хоста: тесты параноидального режима никогда не трогают файрвол,
и ни один тест не требует root-изменений сети. I2P-тесты автоматически пропускаются,
когда SAM-мост недоступен. DPI Lab добавляет 22 юнит-теста реассемблера (`scripts/lab/test_reassembler.py`).

## Docker-стенды и DPI Lab

L2/L3-спуфинг, перехват трафика и тестирование десинка выполняются в изолированных контейнерах — сеть хоста никогда не затрагивается.

### Топологии

| Compose-файл | Топология | Назначение |
|---|---|---|
| `docker-compose.yml` | client → dpi-router → target (3-узловой midbox) | полная интеграционная матрица |
| `docker-compose.2node.yml` | client ↔ комбинированный Server/DPI (один мост) | быстрые боевые прогоны |
| `docker-compose.lab.yml` (+ `docker-compose.lab-v6.yml`) | client ↔ dpi-emu (юзерспейсный DPI) | наборы DPI Lab 1–4, dual-stack IPv6 |

```bash
docker compose -f docker-compose.lab.yml up -d --build      # IPv4-лаборатория
docker compose -f docker-compose.lab.yml -f docker-compose.lab-v6.yml up -d   # dual-stack
```

### Модели DPI-эмулятора (`docker/dpi-emu.py`)

| Модель | Поведение |
|---|---|
| `string` | классический попакетный `iptables -m string` + `tcp-reset` (базовый DPI) |
| `reassemble` | юзерспейсное **TCP-реассемблирование** NFQUEUE до `BUFFER_LIMIT` (при превышении — allow), политики out-of-order/overlap `strict` / `permissive-first` / `permissive-last`, парсер TLS SNI + HTTP Host, поддельный RST через raw-сокет, JSONL-лог вердиктов |
| `off` | пропускать всё (тестирование формирования десинка) |

GRO/TSO/GSO отключены на veth-парах — иначе ядро собирает разрезанные сегменты
до netfilter, и DPI никогда не увидит десинк в задуманном виде.

### Наборы тестов лаборатории (`scripts/lab/`)

| Набор | Цель | Проверки |
|---|---|---|
| `suite1_correctness.sh` | **формирование** десинк-пакетов (DPI выкл.) | позиции сплита относительно TLS record/SNI, непрерывность seq/ack, ноль ретрансмитов (`pcap_assert.py`) |
| `suite2_dpi_models.sh` | **матрица обхода**: режимы ncp × модели DPI × impairments | N прогонов на ячейку, процент успеха, медиана/p95 handshake и TTFB (`metrics.py`) |
| `suite3_compat.sh` | **совместимость с эндпоинтами** | TLS 1.2-only / TLS 1.3 / HTTP/1.1 / HTTP/2 (nghttpd + расшифровка pcap через SSLKEYLOGFILE) / дымовой тест QUIC |
| `suite4_perf.sh` | **производительность и устойчивость** | N=20 загрузок по 5/50 МБ, CPU на ядро, ретрансмиты, скорость |
| `impairment.sh` | ухудшение сети | профили tc-netem: `clean`, `delay50`, `wan` (100 мс ± 20 + 1% потерь), `loss5`, `reorder` (25%), `mtu1400`, `mtu576` (MSS clamp) |

`pcap_assert.py` автоматизирует пакетные проверки: позиции сплита относительно
TLS record и SNI, валидация TCP seq/ack, обнаружение ретрансмитов,
согласование TLS 1.2/1.3, ALPN, HTTP/2-фреймы (через `--keylog`
SSLKEYLOGFILE-расшифровку), QUIC-датаграммы, инъекцию RST; ServerHello с
HelloRetryRequest пропускаются при чтении результатов согласования.

### Свежие боевые результаты (17.08.2026, полный прогон матрицы)

- `tspu` / `chain` обходят DPI со string-match на **100%** в профилях clean,
  delay50, loss5 и reorder; `direct` всегда заблокирован (контроль ✓).
- Позиционные сплиты дают **0% против модели с реассемблированием** в чистых
  условиях — ответ: overlap / bad-checksum / multidisorder-стратегии
  (утечки 10–30% в профиле reorder показывают деградацию реассемблера).
- Пресет `auto`: **0% обхода в каждой ячейке** при корректном формировании
  пакетов (suite1 PASS) — в работе.
- TLS 1.3 **HelloRetryRequest**: второй ClientHello после HRR отправляется
  без десинка → RST от DPI. Серверы, запрашивающие другую группу key-share,
  ломают обход, пока это не закрыто.
- **HTTP/2 поверх десинка подтверждён** (ALPN h2, TLS 1.3, HTTP 200 против
  nghttpd); **IPv6 — открытый путь обхода** — логика DPI работает только с IPv4.
- Производительность: ~103 МБ/с на загрузках 50 МБ через desync-прокси,
  оверхед на handshake +2–8 мс против прямого соединения, success rate 1.0 в
  профиле `wan`, единичные ретрансмиты на 20 прогонов.

## CLI-утилита

```bash
ncp run [--interface <if>] [--preset <name>] [--kill-switch]
ncp status | stop | rotate | help
ncp crypto <действие> [аргументы]
ncp network <действие>
ncp license <действие>
ncp dpi / i2p / mimic ...
ncp spa <keygen|serve|knock>
ncp reality serve [--dry-run]
ncp stegodns <encode|decode>
ncp porthop <serve|client>
ncp fog node
ncp xdp <compile|attach|detach|stats|drop|probe>
```

> **⚠️ Kill switch — только по явному запросу.** Параноидальный режим может установить правило файрвола, роняющее **весь** не-loopback трафик (`iptables -A OUTPUT ! -o lo -j DROP` / эквивалент на Windows). Если процесс внезапно умрёт, правило может остаться и полностью отрезать машину от сети — включая SSH. `ncp run` включает его **только** при явном флаге `--kill-switch`.

### Пресеты DPI

`--preset` выбирает профиль провайдера (например, `tspu`, `beeline`, ...). Полный список — в выводе `ncp dpi`.

### Пакетный обход с избирательным десинком (Windows, WinDivert)

На Windows `ncp run` / `ncp dpi` используют **WinDivert driver-режим**: фейковые пакеты (badsum/badseq/низкий TTL), TCP-сплиты, reverse-frag и disorder применяются прямо «на проводе» — без системного прокси и без зависимости от DoH; работает даже когда провайдер блокирует весь DNS. Начиная с v1.6.0 десинк можно **ограничить хостлистом/ipset** (как в winws2):

```bash
ncp run --hostlist C:\ncp\hostlist.txt            # обход ТОЛЬКО для доменов из списка
ncp run --hostlist-exclude C:\ncp\exclude.txt     # обход для всех, КРОМЕ списка
ncp run --ipset C:\ncp\ipset.txt                  # ограничение по IP назначения (CIDR)
```

Домены сравниваются по суффиксу (`example.com` покрывает `www.example.com`).
ipset-фильтр действует и на QUIC/UDP-путь десинка (у QUIC нет видимого SNI).
Пустой или отсутствующий файл отключает функцию (каждый перехваченный
ClientHello десинкается, как раньше). Те же списки настраиваются из
веб-интерфейса — карточка «Пакетный режим (WinDivert)» в разделе «Обход»,
использует автохостлист из раздела «Хостлисты».

## Веб-интерфейс

```bash
cd web
pip install -r requirements.txt
python3 server.py    # http://127.0.0.1:8085
```

Возможности: активация лицензии (ключи с подписью Ed25519, формат `NCP-XXXXX`), выбор DPI-пресета, переключатели модулей, поток логов по WebSocket, старт/стоп ядра `ncp`, **живая статистика движка по модулям** (движок экспортирует реальные счётчики через `ncp run --stats-file` каждые 2 с — DPI-конвейер, Geneva GA, WF Defense, Volume Normalizer, Behavioral Cloak, Time Breaker, RTT Equalizer, Session Fragmenter, Cross-Layer, Covert Channel, Protocol Rotation, AS Router). Раздел «Обход» добавляет: запуск/остановку desync-прокси в один клик, автоматический подбор стратегии (blockcheck) с применением выбранной, проверку доступности популярных сайтов, управление автохостлистом, импорт zapret-стратегий с предпросмотром, ленту событий DPI-детектора, управление фильтрами пакетного режима (хостлист/ipset), встроенную справку простым языком («Справка»), подписанное автообновление и переключатель автозапуска. Экземпляры, запущенные из GUI, всегда работают с `--no-kill-switch`.

## Лицензирование (триал + ключи)

**7-дневный триал, ноль настройки.** При первом запуске и CLI (`ncp run`), и
веб-интерфейс автоматически выпускают триальную лицензию на **все 19 модулей**
(включая полный движок Geneva). Файл триала лежит в
`%APPDATA%\ncp\trial.json` (Windows) / `~/ncp/trial.json` (Linux), привязан
к имени машины и защищён keyed SHA-256 MAC. Через 7 дней модули защиты
останавливаются до ввода ключа. Qt GUI никогда не блокирует жёстко: его
панель лицензии носит информационный характер.

**Выпуск ключей (только для владельца).** Ключи подписаны Ed25519 (формат
`NCP-XXXXX-...`) и выпускаются генератором ключей — `web/ncp_keygen.py` или
замороженным `ncp-keygen.exe`:

```bash
# один раз: сгенерировать пару ключей (печатает публичный ключ для встраивания в сборки)
ncp-keygen.exe generate-keypair --out ncp_private_key.b64

# выпустить ключ на N дней (0 = бессрочный)
ncp-keygen.exe issue --plan ultimate --modules all --days 365
ncp-keygen.exe issue --plan pro --modules dpi_bypass,pipeline --days 30
```

Генератор читает приватный ключ Ed25519 **из файла `ncp_private_key.b64`,
лежащего рядом с исполняемым файлом** (или `--key <путь>`) — он никогда не
встраивается в бинарник. **Никогда не распространяйте `ncp-keygen.exe` или
`ncp_private_key.b64` среди пользователей**; клиентам отправляйте только текст
ключа. Активация — в веб-интерфейсе (раздел «Лицензия»); ключ хранится в
`%APPDATA%\ncp\license.json` и признаётся всеми тремя приложениями
(CLI, веб-GUI, Qt GUI).

## Функции обхода (без прав администратора)

### Локальный desync-прокси — `ncp proxy`

SOCKS5/HTTP-прокси на localhost, применяющий DPI-десинк (TCP-сплит по позиции
байта/SNI/midSLD, zapret-цепочки, фейковый QUIC, DoH-резолв) к проксируемому
трафику. Работает без root/админа — направьте браузер или программу на
`127.0.0.1:1080` (SOCKS5 с UDP ASSOCIATE или HTTP CONNECT).

```bash
ncp proxy --port 1080 --doh                      # по умолчанию: split-2 + split-at-SNI
ncp proxy --split-pos 5                          # сплит ClientHello на байте 5
ncp proxy --multisplit 1,2,5 --split-sni         # многоуровневый сплит
ncp proxy --chain "--dpi-desync=fake,multisplit --dpi-desync-split-pos=midsld"
ncp proxy --block-quic                           # ронять UDP/443 (принудительный откат на TCP)
ncp proxy --fake-quic 3                          # 3 фейковых QUIC Initial на цель
ncp proxy --autohostlist /etc/ncp/autohostlist.txt --detector-log /etc/ncp/detector_events.jsonl
```

### Автоматический подбор стратегии — `ncp blockcheck`

Эквивалент zapret `blockcheck`: проверяет набор доменов через каждую
встроенную стратегию (split-1/2/3/5, split-SNI, варианты multisplit,
цепочечные сплиты midSLD / SNI-extension / end-SLD), оценивает их и
показывает победителя:

```bash
ncp blockcheck                                   # встроенный список доменов
ncp blockcheck --domains example.com,foo.org --json --out report.json
ncp blockcheck --apply                           # лучшая стратегия в виде профиля JSON
```

### AutoPilot — адаптивный самообучающийся движок (`ncp autopilot`)

AutoPilot превращает разовый blockcheck в непрерывный цикл обучения по каждому хосту:

- **Обучается** лучшей стратегии десинка для каждого хоста живыми пробами (TLS
  ClientHello по TCP/443 через временный локальный прокси — без админа и без
  изменений файрвола) и сохраняет в `~/.ncp/autopilot.json`
  (`%APPDATA%\ncp\autopilot.json` на Windows).
- **Применяет** выученные стратегии внутри `ncp proxy --autopilot` (или везде,
  где включена БД): выученная запись имеет приоритет над цепочками и базовой
  стратегией; совпадение по самому длинному суффиксу автоматически покрывает
  поддомены.
- **Следит** за живым трафиком: RST после ClientHello и таймауты server-hello
  репортятся по каждому хосту. Три подряд неудачи помечают запись
  *деградировавшей* — соединения мгновенно откатываются на цепочки/базу, пока
  фоновый «дворник» переобучает хост (с rate-limit и экспоненциальным backoff).
- **Саморасширяется**: повторные неудачи на неизвестном хосте создают
  заглушку, которую «дворник» обучает автоматически.

```bash
ncp autopilot learn www.youtube.com --doh   # проба и сохранение лучшей стратегии
ncp autopilot status                        # человекочитаемый вид БД
ncp autopilot status --json                 # машиночитаемый (для GUI)
ncp autopilot enable                        # прокси подхватывает автоматически
ncp proxy --doh --autopilot                 # выученные стратегии + живая обратная связь
ncp autopilot reset [domain]                # сбросить одну запись / все
```

Пробы — только чистый TCP/443: без TUN, без VPN, без инъекции пакетов.
Используйте `--doh` (и в `learn`, и в `proxy`) в сетях с отравленным DNS,
чтобы обучение происходило в той же DNS-реальности, в которой работает прокси.

### Импорт стратегий zapret — `ncp import-zapret`

Разбирает CLI-флаги zapret (`--dpi-desync`, `--dpi-desync-split-pos`,
`--dpi-desync-fooling`, `--dpi-desync-ttl/-autottl`, `--dpi-desync-fake-*`,
`--hostlist*`, `--new`, `--filter-tcp/udp/l3/l7`, ...) в профиль NCP
`ZapretChain` и печатает его как JSON:

```bash
ncp import-zapret --args "--filter-tcp=443 --dpi-desync=split2 --dpi-desync-split-pos=midsld"
ncp import-zapret --file strategies.txt
```

### Хостлисты

Точное и суффиксное совпадение доменов (`*.example.com`, голый `example.com`,
с учётом двухуровневых TLD). Автохостлист записывает хосты, где обнаружена
DPI-блокировка (таймаут / инъекция RST), и подпитывает ими выбор цепочек
(правила `--hostlist`).

### Single Packet Authorization — `ncp spa`

SPA корпоративного уровня (апгрейд классического port knocking, уязвимого к
replay и анализу таймингов): порт защищаемого сервиса остаётся «чёрной дырой»
для сканеров, пока клиент не отправит **один UDP-пакет с подписью Ed25519**
(256 байт: key-id, метка времени, nonce, запрошенные proto/port/TTL +
64-байтовая подпись + CSPRNG-заполнение). Сервер проверяет подпись по файлу
авторизованных ключей, отклоняет повторы (кэш nonce по ключу + окно ±60 с) и
только затем динамически открывает доступ — только для этого исходного IP —
через **ipset** с автоматическим истечением TTL:

```bash
ncp spa keygen --out client                        # пара ключей Ed25519 + строка authorized_keys
ncp spa serve --authorized-keys keys.txt \
    --port 54117 --set-name ncp_spa_allow \
    --default-ttl 300 --max-ttl 86400              # [--dry-run] — логировать без применения
ncp spa knock <ip-сервера> --key client.key \
    --allow-port 443 --ttl 300                     # открыть tcp/443 только для этого IP
```

Правило-гейт на стороне сервера (печатается `serve` при запуске):

```bash
iptables -A INPUT -p tcp --dport 443 -m set ! --match-set ncp_spa_allow src -j DROP
```

Проверено в Docker DPI Lab: соединения до «стука» уходят в таймаут (DROP),
валидный «стук» возвращает HTTP 200 через гейт, повторные пакеты отклоняются
(REPLAY), неизвестные ключи отклоняются (UNKNOWN_KEY), доступ закрывается
автоматически по истечении TTL. Асимметричный дизайн: сервер хранит только
публичные ключи, поэтому компрометация сервера не раскрывает клиентскую
возможность подписи.

### Корпоративные антицензурные модули

Девять взаимодополняющих модулей, реализующих корпоративный набор функций.
Все покрыты юнит-тестами (70+ кейсов) и проверены в Docker DPI Lab.

#### Фолбэк в стиле XTLS-Reality — `ncp reality serve`

Фронт-сервер с dest-mapping: первые байты каждого соединения обязаны быть TLS
ClientHello. Авторизованные клиенты встраивают Ed25519-токен в крайний левый
SNI-лейбл (`<token26>.gw.<домен>`, токен = первые 26 base32-символов подписи
над `"ncp-reality" || домен || 60-секундное окно времени`) и перенаправляются
на внутренний сервис; все остальные — сканеры, активные пробы, цензоры —
прозрачно сплайсятся на реальный фолбэк-сайт, так что сервер предъявляет
подлинную TLS-сессию с настоящим «белым» доменом:

```bash
ncp reality serve --listen 8443 --fallback www.microsoft.com:443 \
    --internal 127.0.0.1:8080 --key-file clients.txt [--dry-run]
# файл ключей: '<key_id> <base64-ed25519-secret-64B>' на строку
```

Примечание: 26-символьный base32-токен несёт лишь ~130 бит из 512-битной
подписи, поэтому проверка пересчитывает детерминированную подпись Ed25519 на
стороне сервера и сравнивает за постоянное время — сервер должен хранить
клиентские секретные ключи (`provision_secret()`); записи только с публичными
ключами принимаются, но пропускаются. Проверено в лаборатории:
авторизованный ClientHello доходит до внутреннего сервиса, неизвестный/пустой
SNI сплайсится на байты фолбэка, не-TLS мусор отбрасывается.

#### Стеганографический DNS-discovery — `ncp stegodns`

Публикует параметры bootstrap-узла (IPv4, порт, публичный ключ SPA, срок
действия — 43 байта) внутри безобидно выглядящей SPF TXT-записи. Полезная
нагрузка запечатана XChaCha20-Poly1305 (ключ = BLAKE2b(парольная фраза)) и
подписана Ed25519, затем base32-кодируется в
`v=spf1 ip4:<blob> include:<blob>._ncp.<домен> ~all`:

```bash
ncp stegodns encode --ip 203.0.113.7 --port 4433 --spa-pubkey <b64> \
    --passphrase <s> --signing-key spa.key --domain example.com
ncp stegodns decode --txt '<запись>' --passphrase <s> --verify-pubkey <b64>
```

Для цензора запись неотличима от обычной SPF-политики. `expires = 0` означает
«бессрочно». Проверен кросс-контейнерный roundtrip в лаборатории.

#### UDP-транспорт с port-hopping — `ncp porthop`

QUIC-стиль перескока портов для UDP: обе стороны детерминированно вычисляют
текущий порт — `port(epoch) = base + HMAC-SHA256(secret, epoch)[0..2] % range`.
Кадры несут `PH | ver | session_id(8) | epoch(4) | seq(4) | flags | payload`;
клиент перескакивает, когда >3 сегментов не подтверждены или истёк интервал
перескока; сервер слушает весь диапазон портов (SO_REUSEPORT, до 64 портов) и
демультиплексирует по session id, отбрасывая неизвестные сессии:

```bash
ncp porthop serve --base-port 40000 --range 16 --secret <s> [--hop-interval 60]
ncp porthop client --host <ip> --base-port 40000 --range 16 --secret <s> \
    --message "привет" [--session-id 0x1122334455667788]
```

Проверено в лаборатории: кросс-контейнерное эхо с ACK; когда текущий порт
блокируется файрволом посреди сессии, клиент перескакивает на следующий
запланированный порт (40015 → 40006), и сессия продолжается.

#### Статистическая мимикрия трафика (`ncp_mimicry_stats`)

Шейпинг трафика по измеримым статистическим профилям: распределения размеров
пакетов (нормальное / логнормальное / дискретные смеси с ограничением) и модели
межпакетных интервалов (экспоненциальная / нормальная / фиксированная).
Встроенные профили: `webrtc_video` (90% N(1200,180) + 8% N(400,80) + 2%
N(8000,1500), Exp(33 мс)), `zoom_call`, `youtube_stream`, `voip_opus`.
`MimicryShaper::plan(len)` разбивает исходящий буфер на приуроченные куски,
статистически соответствующие выбранному протоколу-прикрытию
(сидированный `mt19937_64`).

#### TCP State Confusion (`ncp::desync`)

Билдеры сегментов wire-level десинхронизации (техники zapret, оформленные как
переиспользуемая библиотека): **overlap** (пара decoy + real с одним seq),
**фейк с ограниченным TTL** (ttl 1..3 — проходит on-path DPI, умирает до
сервера), **фейк вне окна** (seq + 16 МиБ), **фейк badseq** (seq − 1, аналог
zapret badseq) и опционально отравленная контрольная сумма TCP 0xDEAD
(badsum). `serialize_segment()` формирует полные IPv4+TCP пакеты для
raw-сокет отправителя. Проверено «на проводе» в лаборатории: все пять инъекций
захвачены с ожидаемыми полями seq/ttl/checksum.

#### Ядро AEMM Reed-Solomon (`ncp_aemm`)

Адаптивное прямое исправление ошибок (FEC) для каналов с потерями: GF(2^8)
(полином 0x11D), порождающая матрица Коши, кодирует K шардов данных в N,
восстанавливает блок из любых K шардов через обращение подматрицы GF.
AVX2-путь с 4-битными нибблами (`vpshufb`) где доступен; замерено 57 МБ/с
скалярно, 69 МБ/с AVX2. Заголовок шарда: `RS | k | n | idx | block_id |
orig_len | blake2b-8`.

#### Кооперативный Fog Mesh — `ncp fog node`

Многохоповый оверлей добровольных ретрансляторов: кадрирование
`FOG | ver | ttl | type | target(16) | origin(16) | seq(8) | payload`,
декремент TTL, защита от петель (FIFO на 10 тыс. записей origin/seq),
PING/PONG-живучесть и gossip таблицы ROUTE_AD. Таблица пиров держит до 256
записей с затуханием доверия (×0.99/мин), вытеснением наименее доверенных и
выбором лучшего ретранслятора:

```bash
ncp fog node --id <32-hex> --port 5000 --peer <ip:port> [--peer ...]
```

Проверено в лаборатории: кросс-контейнерные PING→PONG и доставка DATA;
многохоповая ретрансляция покрыта loopback юнит-тестами.

#### Semantic Fluid Transport (`ncp_semfluid`)

Встраивание полезной нагрузки в высокоэнтропийные поля рутинных HTTP-запросов —
телеметрия Windows (POST), обновление компонентов Chrome (GET), загрузка
картинки с CDN (GET), OAuth-токен (POST), видео-манифест (GET). Куски данных
(43 байта + контрольная сумма BLAKE2b-4) base62-кодируются в значения cookie
фиксированной ширины 64 символа (`MSFPC`, `_uetsid`), статистически
неотличимые от настоящих браузерных cookie; `wrap()/unwrap()/parse_request()`
восстанавливают поток.

#### Фильтрация пакетов в ядре eBPF/XDP — `ncp xdp`

Статистика UDP и избирательное отбрасывание на самом раннем возможном уровне
сетевого стека. Поставляется libbpf-независимая legacy eBPF-программа
(`bpf/xdp_udpmon_kern.c`, загружаемая через iproute2) с HASH-картой статистики
по портам и ARRAY-картой конфигурации (порт для drop), плюс `XdpManager`,
который компилирует (clang), присоединяет/отсоединяет (`xdpgeneric`), находит
закреплённые карты структурным сравнением и читает счётчики через прямые
syscall `bpf(2)`:

```bash
ncp xdp compile --out /tmp/xdp_udpmon.o      # clang -target bpf
ncp xdp attach --iface eth0 --obj /tmp/xdp_udpmon.o
ncp xdp stats [--pin /sys/fs/bpf/...]        # пакеты/байты по портам
ncp xdp drop --port 4433 [--clear]           # избирательный drop
ncp xdp detach --iface eth0 ; ncp xdp probe  # проверка возможностей ядра
```

Проверено в одноразовом сетевом namespace хоста: точные счётчики
пакетов/байт, избирательный drop на заданном порту при нетронутом контрольном
трафике. Требует `CAP_SYS_ADMIN` + `CAP_NET_ADMIN` (или root) и ядро с
`CONFIG_BPF_SYSCALL`.

### Пассивный детектор DPI

Считает инъекции RST, ресеты после ClientHello и таймауты подключения по
хостам; испускает события JSONL (`rst_injection`, `timeout_block`,
`tcp_reset_pre`, `block_cleared`), потребляемые GUI.

### Обработка QUIC / HTTP3

* фейковые пакеты QUIC Initial (путь WinDivert и proxy UDP ASSOCIATE),
* force-TCP: `--quic-block` / прокси `--block-quic` роняет UDP/443,
* IP-фрагментация QUIC Initial: `--quic-frag <offset>`
  (IPv4, выравнивание по 8 байтам, контрольные суммы пересчитываются).

### Автообновление

Подписанные релизы: GUI проверяет GitHub Releases на наличие ассета
`manifest.json`, верифицирует SHA-256 и **подпись Ed25519** (та же пара
ключей, что для выпуска лицензий) перед установкой. Скомпрометированные или
подделанные бинарники отклоняются.

### Трей и автозапуск на Windows

Сборка GUI (`ncp-qt.exe`; опциональная замороженная сборка веб-интерфейса может
поставляться как `ncp-gui.exe`) показывает значок в системном трее (открыть
панель / выйти) и умеет регистрировать себя в автозапуске (HKCU `Run` на
Windows, `~/.config/autostart/ncp.desktop` на Linux) — переключается из GUI.

## Архитектура
- Современный C++17 с оптимизациями `constexpr`/`noexcept`.
- Трёхслойная архитектура: Core Library, CLI, Web GUI.
- 7-стадийный конвейер Protocol Orchestrator.

## Лицензия
Лицензируется под GNU Affero General Public License v3.0 (AGPLv3). Подробности — в [LICENSE](LICENSE).

---
**Последнее обновление**: 27 августа 2026
**Версия**: 1.6.0
