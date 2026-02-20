# Advanced DPI Bypass Guide

Комплексное руководство по продвинутым техникам обхода DPI в NCP.

## Содержание

- [Введение](#введение)
- [Архитектура](#архитектура)
- [TLS Fingerprint](#tls-fingerprint)
- [Encrypted Client Hello (ECH)](#encrypted-client-hello-ech)
- [Protocol Orchestrator](#protocol-orchestrator)
- [Техники обхода](#техники-обхода)
- [Пресеты](#пресеты)
- [Настройка](#настройка)
- [Примеры использования](#примеры-использования)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)

---

## Введение

Advanced DPI Bypass — это расширенная система обхода глубокой инспекции пакетов (DPI), реализующая более 15 различных техник обхода для противодействия современным системам цензуры.

### Основные возможности

- ✅ **15+ техник обхода**: TCP-сегментация, SNI-сплиттинг, GREASE, фейковые пакеты и др.
- ✅ **TLS Fingerprinting**: Генерация реалистичных ClientHello по профилям Chrome/Firefox/Safari/Edge
- ✅ **ECH (Encrypted Client Hello)**: Шифрование SNI через HPKE для предотвращения утечки
- ✅ **Protocol Orchestrator**: Единый pipeline с адаптивным переключением стратегий по уровню угрозы
- ✅ **6 готовых пресетов**: TSPU/ТСПУ, GFW, Iran, Aggressive, Stealth, Compatible
- ✅ **Криптографическая обфускация**: ChaCha20, XOR, HTTP-камуфляж
- ✅ **Адаптивная фрагментация**: автоматическая подстройка под DPI
- ✅ **Timing jitter**: рандомизация временных паттернов
- ✅ **Decoy SNI**: отправка фейковых доменов с рандомными профилями
- ✅ **Multi-layer split**: множественное разделение пакетов
- ✅ **22 unit теста**: mimicry roundtrip, ECH pipeline, advanced DPI

---

## Архитектура

### Компоненты

```
ProtocolOrchestrator (unified pipeline)
├── TLSFingerprint              # Профили браузеров
│   ├── Chrome / Firefox / Safari / Edge
│   ├── JA3/JA3S/JA4 fingerprints
│   ├── Per-connection rotation
│   └── GREASE / ALPN / supported_versions
├── AdvancedDPIBypass           # Основной DPI pipeline
│   ├── TCPManipulator          # TCP-уровень
│   │   ├── Сегментация
│   │   ├── Overlapping
│   │   └── Disorder
│   ├── TLSManipulator          # TLS-уровень (с TLSFingerprint)
│   │   ├── SNI splitting
│   │   ├── GREASE injection
│   │   ├── Fingerprinted ClientHello
│   │   └── Fake ClientHello (decoy)
│   ├── ECH Integration         # Encrypted Client Hello
│   │   ├── Config parsing
│   │   ├── HPKE encryption
│   │   └── Extension insertion
│   └── TrafficObfuscator       # Шифрование
│       ├── ChaCha20
│       ├── XOR Rolling
│       └── HTTP Camouflage
├── AdversarialPadding          # ML classifier evasion
├── FlowShaper                  # Timing/size shaping
├── ProbeResist                 # Active probe defense
└── TrafficMimicry              # Protocol wrapping
```

### Процесс обработки пакета (ClientHello)

```
Outgoing ClientHello
    ↓
[TLS Fingerprint Rotation]  ← Browser profile switch (Chrome→Firefox→...)
    ↓
[GREASE Injection]          ← RFC 8701 random extension values
    ↓
[ECH Application]           ← HPKE encrypt SNI (ext 0xfe0d)
    ↓
[Decoy SNI]                 ← Fake ClientHellos (google.com, etc.)
    ↓
[SNI Split / Multi-split]   ← TCP segmentation at SNI offset
    ↓
[Padding]                   ← Random padding per segment
    ↓
[Obfuscation]               ← ChaCha20/XOR/HTTP wrap
    ↓
[Adversarial Padding]       ← Anti-ML bytes
    ↓
[Mimicry Wrap]              ← Protocol disguise
    ↓
[Flow Shaping]              ← Timing normalization + dummies
    ↓
Network
```

---

## TLS Fingerprint

### Описание

Модуль `ncp::TLSFingerprint` генерирует реалистичные TLS ClientHello, неотличимые от реальных браузеров. Каждый профиль содержит:

- Cipher suites в правильном порядке
- Extensions в порядке, характерном для данного браузера
- ALPN протоколы (h2, http/1.1)
- Supported groups / signature algorithms
- Key share (x25519)
- GREASE значения в правильных позициях

### Поддерживаемые профили

| Профиль | JA3 Hash | Особенности |
|---------|----------|-------------|
| Chrome | Актуальный Chrome 120+ | GREASE в начале, большой список cipher suites |
| Firefox | Актуальный Firefox 120+ | Отличный порядок extensions, нет GREASE по умолчанию |
| Safari | Актуальный Safari 17+ | Уникальный порядок supported_groups |
| Edge | Chromium-based | Близок к Chrome, различия в session tickets |

### Использование

```cpp
#include <ncp_tls_fingerprint.hpp>

// Создание с профилем
ncp::TLSFingerprint fp(ncp::BrowserType::CHROME);
fp.set_sni("example.com");

// Получение данных для ClientHello
auto ciphers = fp.get_cipher_suites();
auto extensions = fp.get_extensions();
auto alpn = fp.get_alpn();
auto ja3 = fp.generate_ja3();

// Смена профиля
fp.set_profile(ncp::BrowserType::FIREFOX);

// Per-connection rotation (через Orchestrator)
// Автоматически при strategy.tls_rotate_per_connection = true
```

### Интеграция с AdvancedDPIBypass

```cpp
ncp::TLSFingerprint fp(ncp::BrowserType::CHROME);

AdvancedDPIBypass bypass;
bypass.set_tls_fingerprint(&fp);  // Forwarded to TLSManipulator
bypass.initialize(config);
bypass.start();

// TLSManipulator теперь использует fp для:
// - create_fake_client_hello() — рандомизирует профиль per-call (decoy)
// - create_fingerprinted_client_hello() — использует fp как есть
```

---

## Encrypted Client Hello (ECH)

### Описание

ECH (Encrypted Client Hello) шифрует SNI и другие чувствительные extensions в ClientHello, предотвращая их чтение DPI. Реализация использует HPKE (Hybrid Public Key Encryption) через OpenSSL 3.2+.

### Cipher Suite

- **KEM**: DHKEM_X25519_HKDF_SHA256 (0x0020)
- **KDF**: HKDF-SHA256
- **AEAD**: AES-128-GCM

### Конфигурация ECH

```cpp
// Вариант 1: В конфигурации AdvancedDPIBypass
AdvancedDPIConfig cfg;
cfg.enable_ech = true;
cfg.ech_config_list = ech_config_blob;  // Из DNS HTTPS record

AdvancedDPIBypass bypass;
bypass.initialize(cfg);

// Вариант 2: Динамическое обновление ECH config
bypass.set_ech_config(new_ech_config_blob);

// Вариант 3: Через Protocol Orchestrator
OrchestratorConfig orch_cfg = OrchestratorConfig::client_default();
orch_cfg.ech_enabled = true;
orch_cfg.ech_config_data = ech_config_blob;
```

### Как работает

1. Парсинг ECHConfigList blob → `ECHConfig` (version, config_id, public_key, cipher_suites)
2. Поиск блока extensions в ClientHello
3. HPKE шифрование внутренних extensions
4. Вставка ECH extension (type 0xfe0d) в ClientHello
5. Обновление длин TLS Record / Handshake

### Без OpenSSL 3.2+

Если OpenSSL не поддерживает HPKE, используется stub-реализация: `apply_ech()` возвращает оригинальный ClientHello без изменений. Pipeline продолжает работать корректно.

---

## Protocol Orchestrator

### Описание

Protocol Orchestrator (`ncp::DPI::ProtocolOrchestrator`) — единый entry point для отправки и приёма данных. Автоматически управляет всеми компонентами:

- Adversarial Padding
- Flow Shaping
- Probe Resistance
- Traffic Mimicry
- TLS Fingerprinting
- AdvancedDPIBypass (включая ECH)

### Стратегии

| Стратегия | Когда | Компоненты |
|-----------|-------|------------|
| `max_compat` | ThreatLevel::NONE | Mimicry, TLS FP, Probe (permissive) |
| `performance` | ThreatLevel::LOW | + Adversarial (minimal) |
| `balanced` | ThreatLevel::MEDIUM | + Flow Shaping, AdvancedDPI (moderate), ECH |
| `stealth` | ThreatLevel::HIGH/CRITICAL | + Все техники, aggressive adversarial, flow dummies |

### Адаптивное переключение

```cpp
// Создание orchestrator
OrchestratorConfig cfg = OrchestratorConfig::client_default();
cfg.ech_enabled = true;
cfg.on_strategy_change = [](ThreatLevel old_lvl, ThreatLevel new_lvl, const std::string& reason) {
    std::cout << "Strategy changed: " << threat_level_to_string(old_lvl)
              << " -> " << threat_level_to_string(new_lvl)
              << " (" << reason << ")" << std::endl;
};

ProtocolOrchestrator orch(cfg);
orch.start(send_callback);

// Отправка данных (весь pipeline автоматически)
auto packets = orch.send(payload);
for (auto& pkt : packets) {
    // pkt.data — данные для отправки
    // pkt.delay — задержка перед отправкой
    // pkt.is_dummy — true если это dummy packet
}

// Feedback от сети
orch.report_success();  // Соединение прошло
orch.report_detection({DetectionEvent::Type::CONNECTION_RESET});  // Блокировка

// Ручное управление
orch.set_threat_level(ThreatLevel::HIGH);
orch.apply_preset("stealth");

// Доступ к компонентам
auto& fp = orch.tls_fingerprint();
fp.set_profile(ncp::BrowserType::FIREFOX);

auto* adv = orch.advanced_dpi();
if (adv) adv->set_technique_enabled(EvasionTechnique::FAKE_SNI, true);
```

---

## Техники обхода

### 1. SNI Splitting

**Описание**: Разделяет TLS ClientHello в позиции SNI hostname.

**Принцип работы**: DPI-системы часто ищут SNI в определённой позиции. Разделение ClientHello ломает эту логику.

**Конфигурация**:
```cpp
config.enable_tcp_split = true;
config.split_at_sni = true;
config.split_position = 1;  // Агрессивное разделение
```

**Эффективность**: ⭐⭐⭐⭐⭐ (работает против большинства DPI)

---

### 2. Fake Packets (TTL Tricks)

**Описание**: Отправляет фейковые пакеты с низким TTL, которые не достигают сервера, но обманывают DPI.

**Принцип работы**: DPI видит фейковый TLS ClientHello с низким TTL, который не достигает сервера. Настоящий пакет с нормальным TTL отправляется следом.

**Конфигурация**:
```cpp
config.enable_fake_packet = true;
config.fake_ttl = 2;  // Пакет умрёт на 2-3 хопе
config.randomize_fake_ttl = true;  // Рандомизация TTL
```

**Эффективность**: ⭐⭐⭐⭐ (эффективно против ТСПУ)

---

### 3. TLS Fingerprint-driven ClientHello

**Описание**: Генерация реалистичных ClientHello на основе TLS fingerprint реальных браузеров.

**Принцип работы**: DPI может детектировать нестандартные TLS клиенты по набору cipher suites, extensions и их порядку. TLSFingerprint генерирует ClientHello, неотличимый от настоящего браузера.

**Конфигурация**:
```cpp
ncp::TLSFingerprint fp(ncp::BrowserType::CHROME);
bypass.set_tls_fingerprint(&fp);

// Для decoy: каждый fake ClientHello получает рандомный профиль
// Для настоящего: используется профиль caller'а
```

**Эффективность**: ⭐⭐⭐⭐⭐ (обходит JA3/JA4 fingerprinting)

---

### 4. GREASE Injection

**Описание**: Инжектирует случайные GREASE-значения (RFC 8701) в TLS ClientHello.

**Конфигурация**:
```cpp
config.enable_pattern_obfuscation = true;
```

**Эффективность**: ⭐⭐⭐⭐ (обходит extension fingerprinting)

---

### 5. ECH (Encrypted Client Hello)

**Описание**: Шифрует SNI extension в ClientHello, делая его невидимым для DPI.

**Принцип работы**: HPKE шифрует внутренние extensions ClientHello. DPI видит только зашифрованный blob вместо SNI.

**Конфигурация**:
```cpp
config.enable_ech = true;
config.ech_config_list = ech_blob;  // Из DNS HTTPS record
```

**Эффективность**: ⭐⭐⭐⭐⭐ (DPI не может прочитать SNI)

---

### 6. Timing Jitter

**Описание**: Добавляет случайные задержки между сегментами пакета.

**Конфигурация**:
```cpp
config.enable_timing_jitter = true;
config.timing_jitter_min_us = 100;
config.timing_jitter_max_us = 1000;
```

**Эффективность**: ⭐⭐⭐ (медленнее, но эффективно)

---

### 7. Decoy SNI

**Описание**: Отправляет фейковые ClientHello с невинными доменами перед настоящим. Каждый decoy генерируется с **рандомным браузерным профилем** через TLSFingerprint.

**Конфигурация**:
```cpp
config.enable_decoy_sni = true;
config.decoy_sni_domains = {
    "google.com",
    "cloudflare.com",
    "amazon.com"
};
```

**Эффективность**: ⭐⭐⭐⭐ (хорошо против signature-based DPI)

---

### 8. Multi-layer Split

**Описание**: Разделяет пакет в нескольких позициях одновременно.

**Конфигурация**:
```cpp
config.enable_multi_layer_split = true;
config.split_positions = {2, 5, 10, 40, 120};
```

**Эффективность**: ⭐⭐⭐⭐⭐ (очень эффективно против GFW)

---

### 9. Traffic Obfuscation

**Описание**: Шифрует трафик с помощью ChaCha20, XOR или оборачивает в HTTP.

**Конфигурация**:
```cpp
config.obfuscation = ObfuscationMode::CHACHA20;
```

**Эффективность**: ⭐⭐⭐⭐⭐ (максимальная защита, но нужен совместимый клиент)

---

## Пресеты

### TSPU Preset (Russian DPI / ТСПУ)

**Для чего**: Обход российских систем ТСПУ (Технические Средства Противодействия Угрозам).

**Характеристики**:
- Fragment size: **1 byte** (максимальная фрагментация)
- Fake TTL: **2** (пакеты умирают на провайдере)
- Split randomization: **1-5 bytes**
- Noise: **128 bytes**
- Decoy SNI: google.com, cloudflare.com (с рандомными TLS fingerprints)
- Timing jitter: **100-500 μs**
- GREASE injection: enabled
- ECH: enabled (если сконфигурирован)

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_tspu_preset();
config.base_config.target_host = "blocked-site.com";

AdvancedDPIBypass bypass;
ncp::TLSFingerprint fp(ncp::BrowserType::CHROME);
bypass.set_tls_fingerprint(&fp);
bypass.initialize(config);
bypass.start();
```

**Эффективность**: ⭐⭐⭐⭐⭐ (протестировано против ТСПУ 2024-2026)

---

### GFW Preset (China Great Firewall)

**Характеристики**: Multi-layer split [2, 40, 120], XOR Rolling, TCP disorder, GREASE

```cpp
auto config = ncp::DPI::Presets::create_gfw_preset();
```

### Iran Preset

**Характеристики**: HTTP Camouflage, SNI splitting, TLS GREASE

```cpp
auto config = ncp::DPI::Presets::create_iran_preset();
```

### Aggressive Preset

**Характеристики**: Все техники, ChaCha20, 256 bytes noise, Fragment size 1, Padding

```cpp
auto config = ncp::DPI::Presets::create_aggressive_preset();
```

### Stealth Preset

**Характеристики**: Минимальный след, HTTP camouflage, Low timing jitter (50-150 μs)

```cpp
auto config = ncp::DPI::Presets::create_stealth_preset();
```

### Compatible Preset

**Характеристики**: Только SNI split, Fragment size 8

```cpp
auto config = ncp::DPI::Presets::create_compatible_preset();
```

---

## Настройка

### Базовая конфигурация

```cpp
#include <ncp_dpi_advanced.hpp>

using namespace ncp::DPI;

AdvancedDPIConfig config;
config.base_config.mode = DPIMode::PROXY;
config.base_config.listen_port = 8080;
config.base_config.target_host = "example.com";
config.base_config.target_port = 443;
config.base_config.enable_tcp_split = true;
config.base_config.split_at_sni = true;
config.base_config.fragment_size = 2;

AdvancedDPIBypass bypass;
bypass.initialize(config);
bypass.start();
```

### С TLS Fingerprint и ECH

```cpp
// TLS Fingerprint
ncp::TLSFingerprint fp(ncp::BrowserType::CHROME);

// ECH config (из DNS HTTPS record или hardcoded)
std::vector<uint8_t> ech_config = fetch_ech_config_from_dns("example.com");

AdvancedDPIConfig config;
config.base_config.mode = DPIMode::PROXY;
config.base_config.enable_tcp_split = true;
config.base_config.split_at_sni = true;
config.base_config.enable_pattern_obfuscation = true;  // GREASE
config.base_config.enable_decoy_sni = true;
config.base_config.decoy_sni_domains = {"google.com", "cloudflare.com"};
config.enable_ech = true;
config.ech_config_list = ech_config;

AdvancedDPIBypass bypass;
bypass.set_tls_fingerprint(&fp);
bypass.set_log_callback([](const std::string& msg) {
    std::cout << "[DPI] " << msg << std::endl;
});
bypass.initialize(config);
bypass.start();

// Обработка ClientHello
auto segments = bypass.process_outgoing(client_hello.data(), client_hello.size());
// segments[0..N-1] — отправить по wire с jitter delay
```

### Через Protocol Orchestrator (рекомендуется)

```cpp
#include <ncp_orchestrator.hpp>

using namespace ncp::DPI;

OrchestratorConfig cfg = OrchestratorConfig::client_default();
cfg.ech_enabled = true;
cfg.ech_config_data = ech_config_blob;
cfg.strategy = OrchestratorStrategy::stealth();  // All defenses ON
cfg.on_strategy_change = [](ThreatLevel old_l, ThreatLevel new_l, const std::string& r) {
    std::cout << threat_level_to_string(old_l) << " -> "
              << threat_level_to_string(new_l) << ": " << r << std::endl;
};

ProtocolOrchestrator orch(cfg);
orch.start([](const OrchestratedPacket& pkt) {
    // Send pkt.data to wire with pkt.delay
});

// Отправка (весь pipeline автоматически)
auto packets = orch.send(payload);

// Приём (reverse pipeline)
auto data = orch.receive(wire_data, source_ip, source_port);

// Adaptive: report network events
orch.report_success();
orch.report_detection({DetectionEvent::Type::CONNECTION_RESET});
```

---

## Примеры использования

### Пример 1: Минимальный TSPU обход

```cpp
auto config = Presets::create_tspu_preset();
config.base_config.listen_port = 8080;
config.base_config.target_host = "blocked-site.ru";

AdvancedDPIBypass bypass;
bypass.initialize(config);
bypass.start();
```

### Пример 2: TSPU + TLS Fingerprint + ECH

```cpp
auto config = Presets::create_tspu_preset();
config.enable_ech = true;
config.ech_config_list = ech_blob;

ncp::TLSFingerprint fp(ncp::BrowserType::FIREFOX);

AdvancedDPIBypass bypass;
bypass.set_tls_fingerprint(&fp);
bypass.set_log_callback([](const std::string& msg) {
    std::cout << "[DPI] " << msg << "\n";
});
bypass.initialize(config);
bypass.start();

while (true) {
    auto stats = bypass.get_stats();
    std::cout << "GREASE: " << stats.grease_injected
              << ", ECH: " << stats.ech_applied
              << ", Fake: " << stats.fake_packets_injected
              << ", Splits: " << stats.tls_records_split << "\n";
    std::this_thread::sleep_for(std::chrono::seconds(5));
}
```

### Пример 3: Через Orchestrator с адаптивной защитой

```cpp
OrchestratorConfig cfg = OrchestratorConfig::client_default();
cfg.ech_enabled = true;
cfg.adaptive = true;  // Автоматическое переключение стратегий

ProtocolOrchestrator orch(cfg);
orch.start(send_callback);

// Orchestrator сам:
// - Переключит на stealth при повторных блокировках
// - Вернётся к balanced при стабильной связи
// - Ротирует TLS fingerprint при tls_rotate_per_connection
```

### Пример 4: Динамическое управление техниками

```cpp
AdvancedDPIBypass bypass;
bypass.initialize(config);
bypass.start();

// Включить ECH на ходу
bypass.set_ech_config(new_ech_blob);

// Переключить технику
bypass.set_technique_enabled(EvasionTechnique::FAKE_SNI, true);
bypass.set_technique_enabled(EvasionTechnique::TIMING_JITTER, false);

// Применить пресет
bypass.apply_preset(BypassPreset::AGGRESSIVE);
```

---

## Troubleshooting

### Проблема: Сайты не открываются

1. Попробуйте Compatible preset: `Presets::create_compatible_preset()`
2. Отключите aggressive features: `enable_fake_packet = false`, `enable_noise = false`
3. Увеличьте `fragment_size` (8 вместо 1)

### Проблема: Низкая скорость

1. Увеличьте fragment_size: `config.base_config.fragment_size = 8;`
2. Отключите timing jitter: `config.base_config.enable_timing_jitter = false;`
3. Отключите obfuscation: `config.obfuscation = ObfuscationMode::NONE;`
4. Используйте Stealth preset (оптимизирован)

### Проблема: DPI всё равно блокирует

1. Включите TLS Fingerprint: `bypass.set_tls_fingerprint(&fp);` (Chrome profile)
2. Включите ECH: `config.enable_ech = true;`
3. Попробуйте Aggressive preset с ECH
4. Добавьте больше decoy SNI доменов
5. Включите adaptive fragmentation

### Проблема: ECH не работает

1. Проверьте версию OpenSSL: нужна 3.2+ с HPKE support
2. Без OpenSSL 3.2+ — ECH использует stub (возвращает оригинальный ClientHello)
3. Проверьте ECH config blob — должен начинаться с `0xfe0d`
4. Pipeline работает корректно даже без ECH

---

## Performance

### Бенчмарки

| Preset       | Latency | CPU Usage | Memory  | Эффективность |
|--------------|---------|-----------|---------|---------------|
| Compatible   | +0.5ms  | <1%       | 1KB     | ⭐⭐          |
| Stealth      | +1ms    | 2%        | 1.5KB   | ⭐⭐⭐⭐      |
| TSPU         | +2ms    | 5%        | 2KB     | ⭐⭐⭐⭐⭐    |
| GFW          | +1.5ms  | 4%        | 2KB     | ⭐⭐⭐⭐      |
| Aggressive   | +3ms    | 8%        | 3KB     | ⭐⭐⭐⭐⭐    |
| + ECH        | +0.1ms  | +1%       | +0.5KB  | +⭐           |
| + TLS FP     | +0ms    | +0.1%     | +0.2KB  | +⭐           |

---

## Статистика

```cpp
auto stats = bypass.get_stats();

std::cout << "Total packets: " << stats.base_stats.packets_total << "\n";
std::cout << "Fragmented: " << stats.base_stats.packets_fragmented << "\n";
std::cout << "Fake packets: " << stats.fake_packets_injected << "\n";
std::cout << "GREASE injected: " << stats.grease_injected << "\n";
std::cout << "ECH applied: " << stats.ech_applied << "\n";
std::cout << "TLS records split: " << stats.tls_records_split << "\n";
std::cout << "TCP segments: " << stats.tcp_segments_split << "\n";
std::cout << "Bytes obfuscated: " << stats.bytes_obfuscated << "\n";
std::cout << "Bytes padded: " << stats.bytes_padding << "\n";
std::cout << "Timing delays: " << stats.timing_delays_applied << "\n";
```

Orchestrator stats:
```cpp
auto orch_stats = orch.get_stats();
std::cout << "TLS FP applied: " << orch_stats.tls_fingerprints_applied << "\n";
std::cout << "ECH encryptions: " << orch_stats.ech_encryptions << "\n";
std::cout << "DPI segments: " << orch_stats.advanced_dpi_segments << "\n";
std::cout << "Threat level: " << threat_level_to_string(orch_stats.current_threat) << "\n";
std::cout << "Strategy: " << orch_stats.current_strategy_name << "\n";
std::cout << "Overhead: " << orch_stats.total_overhead_pct << "%\n";
```

---

## Тесты

### Unit тесты (22 теста)

**test_mimicry_roundtrip.cpp** (7 тестов):
- basic_roundtrip — Alice wrap → Bob unwrap с shared key
- empty_data — graceful handling nullptr/0
- large_payload — 16KB roundtrip
- key_mismatch_fails — разные ключи → unwrap не совпадает
- set_key_validation — 32-byte accept, invalid reject
- multiple_messages — 100 случайных сообщений
- tls_record_structure — ContentType, version, length

**test_ech_pipeline.cpp** (6 тестов):
- parse_ech_config — парсинг blob
- parse_ech_config_too_short — reject
- apply_ech_to_client_hello — extension insertion + length check
- DPIEvasion::apply_ech wrapper
- AdvancedDPIBypass ECH pipeline
- set_ech_config at runtime

**test_advanced_dpi.cpp** (9 тестов):
- process_outgoing splits ClientHello
- non-ClientHello passthrough
- GREASE injection (stats check)
- decoy SNI (fake packets count)
- XOR obfuscation roundtrip
- HTTP camouflage roundtrip
- preset configurations (6 presets)
- TLS fingerprint integration
- technique toggle (enable/disable)

---

## CLI Usage

```bash
# TSPU preset
./ncp dpi --mode proxy --preset RuNet-Strong --port 8080 --target example.com

# Custom config
./ncp dpi --mode proxy --split-at-sni --fragment-size 2 --fake-ttl 3

# Monitoring
./ncp dpi --mode proxy --preset RuNet-Strong --stats-interval 5
```

---

## FAQ

**Q: Какой preset выбрать для России?**  
A: `Presets::create_tspu_preset()` — оптимизирован для ТСПУ. Для максимальной защиты добавьте ECH и TLS Fingerprint.

**Q: Нужен ли OpenSSL 3.2+ для ECH?**  
A: Для полноценного ECH — да. Без него pipeline работает нормально, просто ECH extension не вставляется.

**Q: Как работает TLS Fingerprint rotation?**  
A: В Orchestrator при `tls_rotate_per_connection = true` — каждый ClientHello получает рандомный профиль (Chrome/Firefox/Safari/Edge).

**Q: Можно ли комбинировать с VPN?**  
A: Да, DPI bypass работает перед VPN для обхода блокировки VPN-серверов.

**Q: Как проверить, что ECH работает?**  
A: `stats.ech_applied > 0` в AdvancedDPIStats. Также можно проверить Wireshark: ищите extension type 0xfe0d в ClientHello.

---

## Ссылки

- [RFC 8701 - GREASE](https://datatracker.ietf.org/doc/html/rfc8701)
- [ECH Draft](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)
- [HPKE RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180)
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
- [zapret](https://github.com/bol-van/zapret)
- [Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)

---

## License

MIT License - see main repository LICENSE file.
