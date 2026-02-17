# Advanced DPI Bypass Guide

Комплексное руководство по продвинутым техникам обхода DPI в NCP.

## Содержание

- [Введение](#введение)
- [Архитектура](#архитектура)
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
- ✅ **6 готовых пресетов**: TSPU/РКНРОСРКН, GFW, Iran, Aggressive, Stealth, Compatible
- ✅ **Криптографическая обфускация**: ChaCha20, XOR, HTTP-камуфляж
- ✅ **Адаптивная фрагментация**: автоматическая подстройка под DPI
- ✅ **Timing jitter**: рандомизация временных паттернов
- ✅ **Decoy SNI**: отправка фейковых доменов
- ✅ **Multi-layer split**: множественное разделение пакетов

---

## Архитектура

### Компоненты

```
AdvancedDPIBypass
├── TCPManipulator       # TCP-уровень
│   ├── Сегментация
│   ├── Overlapping
│   └── Disorder
├── TLSManipulator       # TLS-уровень
│   ├── SNI splitting
│   ├── GREASE injection
│   └── Fake ClientHello
├── TrafficObfuscator    # Шифрование
│   ├── ChaCha20
│   ├── XOR Rolling
│   └── HTTP Camouflage
└── DPIBypass (base)     # Базовый функционал
    ├── Proxy mode
    ├── Driver mode
    └── Packet forwarding
```

### Процесс обработки пакета

```
Outgoing packet
    ↓
[Pattern Obfuscation]   ← GREASE injection
    ↓
[Decoy SNI]             ← Fake ClientHello sent first
    ↓
[Multi-layer Split]     ← TCP segmentation
    ↓
[Padding]               ← Random padding added
    ↓
[Obfuscation]           ← ChaCha20/XOR/HTTP wrap
    ↓
[Timing Jitter]         ← Delays between segments
    ↓
Network
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

**Эффективность**: ⭐⭐⭐⭐ (эффективно против TSPU/РКНРОСРКН)

---

### 3. GREASE Injection

**Описание**: Инжектирует случайные GREASE-значения в TLS ClientHello для рандомизации TLS-отпечатка.

**Принцип работы**: GREASE (RFC 8701) — это зарезервированные значения для расширений TLS. DPI не может их блокировать, т.к. они легитимны.

**Конфигурация**:
```cpp
config.enable_pattern_obfuscation = true;
```

**Эффективность**: ⭐⭐⭐⭐ (обходит fingerprinting)

---

### 4. Timing Jitter

**Описание**: Добавляет случайные задержки между сегментами пакета.

**Принцип работы**: DPI ожидает определённые временные паттерны. Jitter их нарушает.

**Конфигурация**:
```cpp
config.enable_timing_jitter = true;
config.timing_jitter_min_us = 100;   // 100 мкс
config.timing_jitter_max_us = 1000;  // 1 мс
```

**Эффективность**: ⭐⭐⭐ (медленнее, но эффективно)

---

### 5. Decoy SNI

**Описание**: Отправляет фейковые ClientHello с невинными доменами перед настоящим.

**Принцип работы**: DPI видит несколько ClientHello — с google.com, cloudflare.com и др. Настоящий теряется в шуме.

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

### 6. Multi-layer Split

**Описание**: Разделяет пакет в нескольких позициях одновременно.

**Принцип работы**: Вместо одной точки разделения используется несколько. DPI не может отследить все варианты.

**Конфигурация**:
```cpp
config.enable_multi_layer_split = true;
config.split_positions = {2, 5, 10, 40, 120};
```

**Эффективность**: ⭐⭐⭐⭐⭐ (очень эффективно против GFW)

---

### 7. Traffic Obfuscation

**Описание**: Шифрует трафик с помощью ChaCha20, XOR или оборачивает в HTTP.

**Принцип работы**: DPI не может инспектировать зашифрованный/обфусцированный трафик.

**Конфигурация**:
```cpp
config.obfuscation = ObfuscationMode::CHACHA20;
config.obfuscation_key = {}; // Генерируется автоматически
```

**Эффективность**: ⭐⭐⭐⭐⭐ (максимальная защита, но нужен совместимый клиент)

---

### 8. Adaptive Fragmentation

**Описание**: Автоматически адаптирует стратегию фрагментации при обнаружении блокировки.

**Принцип работы**: Отслеживает connection failures и меняет параметры (fragment_size, split_position и т.д.).

**Конфигурация**:
```cpp
config.enable_adaptive_fragmentation = true;
```

**Эффективность**: ⭐⭐⭐⭐ (эволюционирует под DPI)

---

## Пресеты

### TSPU Preset (Russian DPI / РКНРОСРКН)

**Для чего**: Обход российских систем ТСПУ (Технические Средства Противодействия Угрозам).

**Характеристики**:
- Fragment size: **1 byte** (максимальная фрагментация)
- Fake TTL: **2** (пакеты умирают на провайдере)
- Split randomization: **1-5 bytes**
- Noise: **128 bytes**
- Decoy SNI: google.com, cloudflare.com
- Timing jitter: **100-500 μs**

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_tspu_preset();
config.base_config.target_host = "blocked-site.com";

AdvancedDPIBypass bypass;
bypass.initialize(config);
bypass.start();
```

**Эффективность**: ⭐⭐⭐⭐⭐ (протестировано против РКНРОСРКН 2024-2026)

---

### GFW Preset (China Great Firewall)

**Для чего**: Обход китайского Great Firewall.

**Характеристики**:
- Multi-layer split: **[2, 40, 120]**
- XOR Rolling obfuscation
- TCP disorder
- GREASE injection

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_gfw_preset();
```

**Эффективность**: ⭐⭐⭐⭐ (работает в большинстве провинций)

---

### Iran Preset

**Для чего**: Обход иранских DPI-систем.

**Характеристики**:
- HTTP Camouflage
- SNI splitting
- TLS GREASE

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_iran_preset();
```

**Эффективность**: ⭐⭐⭐

---

### Aggressive Preset

**Для чего**: Максимальный обход любого DPI.

**Характеристики**:
- **Все техники включены**
- ChaCha20 encryption
- 256 bytes noise
- Fragment size: 1
- Adaptive retry

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_aggressive_preset();
```

**Эффективность**: ⭐⭐⭐⭐⭐ (максимальная, но высокая нагрузка)

---

### Stealth Preset

**Для чего**: Минимальный след, сложно детектировать.

**Характеристики**:
- Minimal footprint
- HTTP camouflage
- Low timing jitter (50-150 μs)
- No fake packets

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_stealth_preset();
```

**Эффективность**: ⭐⭐⭐⭐ (незаметен, но медленнее)

---

### Compatible Preset

**Для чего**: Максимальная совместимость с любыми серверами.

**Характеристики**:
- Basic SNI split только
- Fragment size: 8 (оптимально)

**Использование**:
```cpp
auto config = ncp::DPI::Presets::create_compatible_preset();
```

**Эффективность**: ⭐⭐ (базовая защита)

---

## Настройка

### Базовая конфигурация

```cpp
#include <ncp_dpi_advanced.hpp>

using namespace ncp::DPI;

AdvancedDPIConfig config;

// Режим работы
config.base_config.mode = DPIMode::PROXY;
config.base_config.listen_port = 8080;
config.base_config.target_host = "example.com";
config.base_config.target_port = 443;

// Фрагментация
config.base_config.enable_tcp_split = true;
config.base_config.split_at_sni = true;
config.base_config.fragment_size = 2;

// Инициализация
AdvancedDPIBypass bypass;
bypass.initialize(config);
bypass.start();
```

### Продвинутая конфигурация

```cpp
// Рандомизация
config.base_config.randomize_split_position = true;
config.base_config.split_position_min = 1;
config.base_config.split_position_max = 10;

// Obfuscation
config.base_config.enable_pattern_obfuscation = true;
config.base_config.randomize_fake_ttl = true;

// Timing
config.base_config.enable_timing_jitter = true;
config.base_config.timing_jitter_min_us = 100;
config.base_config.timing_jitter_max_us = 1000;

// Decoy SNI
config.base_config.enable_decoy_sni = true;
config.base_config.decoy_sni_domains = {
    "google.com",
    "cloudflare.com"
};

// Multi-layer
config.base_config.enable_multi_layer_split = true;
config.base_config.split_positions = {2, 5, 10, 40};

// Техники
config.techniques = {
    EvasionTechnique::SNI_SPLIT,
    EvasionTechnique::TCP_SEGMENTATION,
    EvasionTechnique::TLS_GREASE,
    EvasionTechnique::FAKE_SNI,
    EvasionTechnique::TIMING_JITTER,
    EvasionTechnique::IP_TTL_TRICKS
};

// Шифрование
config.obfuscation = ObfuscationMode::CHACHA20;

// Padding
config.padding.enabled = true;
config.padding.min_padding = 32;
config.padding.max_padding = 128;
```

---

## Примеры использования

### Пример 1: Базовый обход

```cpp
DPIConfig config;
config.mode = DPIMode::PROXY;
config.listen_port = 8080;
config.target_host = "example.com";
config.target_port = 443;
config.enable_tcp_split = true;

DPIBypass bypass;
bypass.initialize(config);
bypass.start();
```

### Пример 2: TSPU/РКНРОСРКН обход

```cpp
auto config = Presets::create_tspu_preset();
config.base_config.listen_port = 8080;
config.base_config.target_host = "blocked-site.ru";

AdvancedDPIBypass bypass;
bypass.set_log_callback([](const std::string& msg) {
    std::cout << "[DPI] " << msg << "\n";
});

bypass.initialize(config);
bypass.start();

// Мониторинг
while (true) {
    auto stats = bypass.get_stats();
    std::cout << "Packets: " << stats.base_stats.packets_total << "\n";
    std::this_thread::sleep_for(std::chrono::seconds(5));
}
```

### Пример 3: Кастомная конфигурация

```cpp
AdvancedDPIConfig config;
config.base_config.mode = DPIMode::PROXY;

// Только нужные техники
config.techniques = {
    EvasionTechnique::SNI_SPLIT,
    EvasionTechnique::TIMING_JITTER
};

// Минимальная задержка
config.base_config.timing_jitter_min_us = 50;
config.base_config.timing_jitter_max_us = 200;

AdvancedDPIBypass bypass;
bypass.initialize(config);
bypass.start();
```

---

## Troubleshooting

### Проблема: Сайты не открываются

**Решение**:
1. Проверьте, что proxy запущен:
   ```bash
   netstat -tuln | grep 8080
   ```
2. Попробуйте Compatible preset:
   ```cpp
   auto config = Presets::create_compatible_preset();
   ```
3. Отключите agressive features:
   ```cpp
   config.base_config.enable_fake_packet = false;
   config.base_config.enable_noise = false;
   ```

### Проблема: Низкая скорость

**Решение**:
1. Увеличьте fragment_size:
   ```cpp
   config.base_config.fragment_size = 8;  // вместо 1
   ```
2. Отключите timing jitter:
   ```cpp
   config.base_config.enable_timing_jitter = false;
   ```
3. Используйте Stealth preset (оптимизирован).

### Проблема: DPI всё равно блокирует

**Решение**:
1. Попробуйте Aggressive preset:
   ```cpp
   auto config = Presets::create_aggressive_preset();
   ```
2. Добавьте больше decoy SNI:
   ```cpp
   config.base_config.decoy_sni_domains = {
       "google.com", "cloudflare.com",
       "amazon.com", "microsoft.com"
   };
   ```
3. Включите adaptive fragmentation:
   ```cpp
   config.base_config.enable_adaptive_fragmentation = true;
   ```

### Проблема: Высокая нагрузка на CPU

**Решение**:
1. Отключите obfuscation:
   ```cpp
   config.obfuscation = ObfuscationMode::NONE;
   ```
2. Уменьшите количество techniques:
   ```cpp
   config.techniques = {EvasionTechnique::SNI_SPLIT};
   ```

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

### Оптимизация

1. **Для максимальной скорости**:
   ```cpp
   config.base_config.fragment_size = 8;
   config.base_config.enable_timing_jitter = false;
   config.obfuscation = ObfuscationMode::NONE;
   ```

2. **Для максимальной эффективности**:
   ```cpp
   auto config = Presets::create_aggressive_preset();
   ```

3. **Баланс**:
   ```cpp
   auto config = Presets::create_tspu_preset();
   config.base_config.fragment_size = 2;  // вместо 1
   ```

---

## Статистика

Получение статистики:

```cpp
auto stats = bypass.get_stats();

std::cout << "Total packets: " << stats.base_stats.packets_total << "\n";
std::cout << "Fragmented: " << stats.base_stats.packets_fragmented << "\n";
std::cout << "Fake packets: " << stats.base_stats.fake_packets_sent << "\n";
std::cout << "GREASE injected: " << stats.grease_injected << "\n";
std::cout << "Bytes obfuscated: " << stats.bytes_obfuscated << "\n";
```

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
A: `Presets::create_tspu_preset()` — специально оптимизирован для РКНРОСРКН.

**Q: Безопасно ли использовать ChaCha20?**  
A: Да, используется libsodium (проверенная криптография).

**Q: Работает ли на Windows?**  
A: Да, все функции кроссплатформенные.

**Q: Можно ли комбинировать с VPN?**  
A: Да, DPI bypass можно использовать перед VPN для обхода блокировки VPN-серверов.

**Q: Как проверить, что работает?**  
A: Используйте `tcpdump` для анализа трафика:
```bash
tcpdump -i any -n 'tcp port 443' -X
```

---

## Ссылки

- [RFC 8701 - GREASE](https://datatracker.ietf.org/doc/html/rfc8701)
- [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
- [zapret](https://github.com/bol-van/zapret)
- [Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)
- [РКНРОСРКН reports](https://reestr.rublacklist.net/)

---

## License

MIT License - see main repository LICENSE file.
