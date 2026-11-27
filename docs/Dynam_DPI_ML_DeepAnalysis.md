# 🔬 Deep Analysis: DPI Bypass и ML части Dynam/NCP

**Дата**: 27 ноября 2026  
**Объект**: Модули DPI bypass, anti-ML, traffic shaping проекта Dynam

---

## 📖 Содержание

1. [DPI Bypass Engine — пакетный уровень](#1-dpi-bypass-engine)
2. [Geneva Engine — генетический алгоритм](#2-geneva-engine)
3. [Anti-ML: Adversarial Padding](#3-adversarial-padding)
4. [Anti-ML: Behavioral Cloak](#4-behavioral-cloak)
5. [Anti-ML: Flow Shaper](#5-flow-shaper)
6. [Anti-ML: Optimal Transport (Wasserstein-1)](#6-optimal-transport)
7. [Traffic Mimicry — протокольная маскировка](#7-traffic-mimicry)
8. [Covert Channels — скрытые каналы](#8-covert-channels)
9. [Master Orchestrator — 7-стадийный пайплайн](#9-master-orchestrator)
10. [Strategy Synthesis (v1.8.0)](#10-strategy-synthesis)
11. [Итоговая оценка](#11-оценка)

---

## 1. DPI Bypass Engine {#1-dpi-bypass-engine}

### Архитектура

Ядро DPI bypass — это `DPIConfig` + `ncp_dpi.cpp` + `dpi_advanced.cpp`. Поддерживает 4 режима:

| Режим | Механизм | Нужен admin? |
|---|---|---|
| **DRIVER** | WinDivert (Windows) / NFQUEUE (Linux) — перехват на уровне ядра | ✅ Да |
| **PROXY** | SOCKS5/HTTP прокси на localhost (порт 8881) | ❌ Нет |
| **PASSIVE** | Пассивный мониторинг + DPI detector | ❌ Нет |
| **WS_TUNNEL** | WebSocket-туннель с domain fronting | ❌ Нет |

### 15+ техник обхода

#### Пакетные техники (DRIVER mode):

```
┌─────────────────────────────────────────────────────────┐
│              Wire-level packet manipulation              │
├──────────────────┬──────────────────────────────────────┤
│ TCP Split        │ Разбиение ClientHello на позиции:    │
│                  │ - byte N (split_position)            │
│                  │ - на SNI offset (split_at_sni)       │
│                  │ - midSLD — середина домена 2-го      │
│                  │   уровня (split_at_midsld)           │
│                  │ → defeat per-packet SNI string match │
├──────────────────┼──────────────────────────────────────┤
│ Multi-split      │ Разбиение на нескольких позициях     │
│                  │ одновременно (split_positions vec)   │
├──────────────────┼──────────────────────────────────────┤
│ Fake packet      │ Поддельный пакет с:                  │
│                  │ - badsum (неверный checksum)         │
│                  │ - badseq (неверный seq number)       │
│                  │ - low TTL (1-3, умирает на DPI)     │
│                  │ - md5sig (TCP MD5 option)            │
│                  │ → DPI видит фейк, сервер — нет      │
├──────────────────┼──────────────────────────────────────┤
│ Disorder         │ Перестановка сегментов               │
│                  │ + задержка disorder_delay_ms (15ms)  │
├──────────────────┼──────────────────────────────────────┤
│ Reverse frag     │ Второй фрагмент отправляется         │
│                  │ ПЕРВЫМ (как GoodbyeDPI --reverse-    │
│                  │ frag); эффективен на Beeline/TSPU    │
├──────────────────┼──────────────────────────────────────┤
│ Overlap          │ Same-seq decoy + real pair           │
├──────────────────┼──────────────────────────────────────┤
│ Auto-TTL         │ Автоматический подбор TTL фейка      │
│                  │ по входящим SYN-ACK:                 │
│                  │ fake_ttl = path_hops + delta         │
└──────────────────┴──────────────────────────────────────┘
```

#### Пресеты для российских операторов:

| Пресет | Описание |
|---|---|
| `RUNET_SOFT` | Мягкий: split + noise |
| `RUNET_STRONG` | Сильный: multi-split + fake + disorder |
| `RUNET_TSPU` | Anti-TSPU: fake+disorder+multisplit (домашние ISP) |
| `BEELINE_MOBILE` | Beeline: reverse-frag + higher TTL + DNS fix |
| `MTS_MOBILE` | MTS: fake+disorder, auto-ttl 4-8 |
| `MEGAFON_MOBILE` | Megafon: split+fake+OOB, ttl=6 |
| `TELE2_MOBILE` | Tele2/t2: split+fake, minor tweaks |
| `MOBILE_UNIVERSAL` | Универсальный мобильный |
| `AUTOPROBE` | Авто-подбор стратегии |

#### Протокольные техники (PROXY mode):

- **ECH (Encrypted Client Hello)** — HPKE по RFC 9180, шифрование SNI
- **Domain Fronting** — outer SNI rewrite + HTTP Host header swap + HPACK :authority
- **Fake QUIC** — генерация фейковых QUIC Initial пакетов
- **DoH (DNS-over-HTTPS)** — шифрование DNS-запросов
- **TLS Fingerprint** — эмуляция JA3/JA4 (Chrome/Firefox/Safari/Edge)

### Критический анализ DPI части

**✅ Сильные стороны:**
1. **Огромный набор техник** — 15+ на пакетном уровне + протокольные. Ни один конкурент не даёт такого ассортимента.
2. **Пресеты под российских операторов** — уникальная фича, заточенная под реальные условия.
3. **Selective desync** — hostlist/ipset фильтрация (не ломаем банки/госсайты).
4. **Auto-TTL** — адаптивный подбор TTL на основе входящих пакетов.
5. **Zapret-совместимость** — импорт стратегий из zapret.

**⚠️ Проблемы:**
1. **`blockcheck` не работал вообще** до v1.8.0 — `build_client_hello()` генерировал неверные длины расширений → каждый TLS-сервер отвечал fatal `decode_error` → все 14 стратегий падали. Это значит, что автоподбор стратегий был сломан ~7 месяцев.
2. **NFQUEUE driver mode был стабом** до R16 (сентябрь 2026) — Linux-версия DRIVER mode «притворялась работающей», не устанавливая iptables-правила.
3. **SNI offset misinterpretation** (R16-A03) — `find_sni_hostname_offset` возвращал позицию length-поля, но `windivert_loop` интерпретировал его как позицию самого SNI → hostlist и selective desync были мертвы.
4. **Auto-TTL неэффективен в DRIVER mode** (WinDivert) — WinDivert перехватывает OUTBOUND пакеты до routing, поэтому наблюдаемый TTL = локальный OS default (128), а не path TTL.

---

## 2. Geneva Engine {#2-geneva-engine}

### Что это

Генетический алгоритм, вдохновлённый проектом **Geneva** (censorship.ai), для автоматического эволюционирования стратегий обхода DPI.

### Архитектура

```cpp
enum class GenevaAction {
    DUPLICATE,         // Дублирование пакета
    FRAGMENT,          // Фрагментация
    TAMPER_TTL,        // Модификация IP TTL
    TAMPER_SEQ,        // Модификация TCP sequence number
    TAMPER_FLAGS,      // Модификация TCP flags
    TAMPER_CHECKSUM,   // Corruption IP checksum
    DROP,              // Дроп пакета
    DISORDER           // Перестановка пакетов
};

struct GenevaStrategy {
    std::vector<GenevaStep> steps;
    // Пресеты:
    static GenevaStrategy tspu_2026();     // Российский TSPU
    static GenevaStrategy gfw_2025();      // Китайский GFW
    static GenevaStrategy iran_dpi();      // Иранский DPI
    static GenevaStrategy universal();     // Универсальный
};
```

### Как работает

Стратегия — последовательность шагов (`GenevaStep`), каждый:
1. Выбирает целевой пакет (target_index)
2. Применяет действие (action) с параметром

Пример: `[FRAGMENT(pos=5), TAMPER_TTL(target=1), DISORDER]`
→ разбивает ClientHello на 5 байт + остаток, подменяет TTL первого фрагмента, переставляет.

### Оценка

**✅ Сильные стороны:**
- Пресеты для конкретных цензоров (TSPU, GFW, Iran) — уникально
- Безопасный лимит: MAX_PACKETS = 1024 (защита от экспоненциального DoS)
- CSPRNG вместо mt19937 (исправлено в CSPRNG migration)

**⚠️ Проблемы:**
1. **Нет реального эволюционного цикла** в текущей реализации. В оригинальном Geneva есть: популяция → фитнес → мутация → селекция. Здесь — фиксированные пресеты + применение. Генетический алгоритм *вдохновляет*, но *не эволюционирует в рантайме*.
2. **Неясна обратная связь** — как engine узнаёт, что стратегия сработала? В `GenevaStats` только счётчики пакетов, нет счётчиков успешных обходов.
3. **8 действий — довольно бедный набор** по сравнению с Geneva research (там ещё есть `[IP+TCP]`, payload injection, etc.)

---

## 3. Adversarial Padding (Anti-ML) {#3-adversarial-padding}

### Концепция

Основан на исследовании **AdvTraffic (2025)**: 16-32 байт adversarial pre-padding снижают точность ET-BERT (transformer-based traffic classifier) с 99% до 25% при overhead всего 3.4%.

**Ключевой инсайт**: Transformer-модели опираются на первые 32 байт payload для классификации протокола. Corrupting этого окна → classifier misclassifies flow.

### Стратегии padding

```cpp
enum class AdversarialStrategy {
    RANDOM,       // Чистый рандом — baseline, ~60% evasion
    HTTP_MIMIC,   // Имитирует начало HTTP/1.1 → classifier в HTTP bucket
    TLS_MIMIC,    // Имитирует TLS record header → blends with HTTPS
    QUIC_MIMIC,   // Имитирует QUIC Initial → blends with QUIC
    DNS_MIMIC,    // Имитирует DNS query → small packet cover
    ADAPTIVE,     // Ротация стратегий по feedback — highest evasion
    CUSTOM        // Пользовательский паттерн
};
```

### Wire format (V2)

```
┌──────────────────────────────────────────────────────────┐
│ [ctrl0..ctrl3][pre_padding][original_payload][post_pad]  │
├──────────────────────────────────────────────────────────┤
│ ctrl0: [strategy:4 bits][pre_len bits 11..8]            │
│ ctrl1: [pre_len bits 7..0]         → 12-bit (max 4095) │
│ ctrl2: [payload_len bits 15..8]                         │
│ ctrl3: [payload_len bits 7..0]     → 16-bit (max 65535) │
└──────────────────────────────────────────────────────────┘
```

### Adaptive режим

```
Every N packets (adaptive_window_packets = 100):
  → evaluate DetectionFeedback
  → if detection confidence > threshold (0.7)
  → switch to next strategy from adaptive_pool
```

### Оценка

**✅ Сильные стороны:**
1. **Математически обоснованный подход** — ссылка на конкретное исследование (AdvTraffic 2025)
2. **Несколько mimic-стратегий** — не просто рандом, а осмысленные имитации протоколов
3. **V2 wire format** — аккуратный 4-байт header с auto-detect версии
4. **TCP header mutation** — рандомизация window, options, timestamps

**⚠️ Проблемы:**
1. **НЕТ реального ML-классификатора внутри** — `DetectionFeedback` приходит «извне». Если нет внешнего тестера, ADAPTIVE режим просто вращает стратегии вслепую.
2. **Adversarial padding работает только между двумя NCP-нодами** — на стороне DPI это просто «странные» байты в начале пакета, которые сами по себе являются аномалией.
3. **4-байт header — потенциальная сигнатура** — если DPI выучит этот паттерн, все NCP-пакеты будут детектироваться.

---

## 4. Behavioral Cloak (Anti-ML) {#4-behavioral-cloak}

### Концепция

Формирует трафик NCP так, чтобы он совпадал с burst/idle/ratio паттернами реального Chrome-браузинга. Бьёт ML-классификаторы, которые извлекают **поведенческие фичи**: burst length, idle gap distribution, upload/download ratio, packet-size histogram.

### Модели поведения

```cpp
struct BrowsingBehaviorModel {
    // Burst characteristics
    uint32_t burst_min_packets = 5;
    uint32_t burst_max_packets = 30;
    double   burst_interval_min_ms = 50.0;   // inter-packet delay within burst
    double   burst_interval_max_ms = 200.0;

    // Idle (between bursts)
    double idle_min_ms = 2000.0;
    double idle_max_ms = 8000.0;

    // Upload/download ratio
    double upload_ratio = 0.15;  // 15% up, 85% down

    // Packet-size distribution
    double pct_small  = 0.30;   // <200 bytes
    double pct_medium = 0.40;   // 200-1000 bytes
    double pct_large  = 0.30;   // >1000 bytes
};
```

Три предустановленных модели:

| Модель | Описание |
|---|---|
| `chrome_casual` | Серфинг: 5-30 pkt bursts, 2-8s idle |
| `chrome_streaming` | Видео: 50-200 pkt bursts, 0.1-1s idle |
| `chrome_social` | Соцсети: 3-10 pkt bursts, 5-30s idle |

### State machine

```
     ┌─────────┐    packet arrives     ┌───────────┐
     │  IDLE   │ ────────────────────→ │  BURSTING  │
     │         │ ←──────────────────── │            │
     └─────────┘  burst complete +     └───────────┘
       idle gap   idle timeout
```

### Критический баг → фикс

**Проблема**: `shape_packet()` запускался **inline** на DPI capture thread. Модельные burst intervals (50-200ms — это application think-time, который OS уже производит сама) применялись к каждому пакету → 3-сегментный ClientHello добавлял ~600ms задержки на handshake.

**Фикс в v1.8.0**: `max_inline_delay_us = 2000` (2ms), clamp на всех call sites до 50ms. Burst-end idle gap НЕ применяется inline — вместо него `get_idle_duration()` запрашивается отдельно.

### Оценка

**✅ Сильные стороны:**
1. **Реалистичные модели** — параметры основаны на реальных Chrome browsing sessions
2. **Dummy packet injection** — keepalive-пакеты в idle periods
3. **Ratio shaping** — поддержание upload/download ratio

**⚠️ Проблемы:**
1. **Статические модели** — нет обучения на реальных trace'ах. Модели — hardcoded parameters, а не trained profiles.
2. **Настоящий Chrome генерирует трафик не по этим правилам** — реальный burst pattern зависит от тысячи факторов (JS execution, rendering, TCP stack behavior). Попытка воспроизвести «среднее» поведение сама по себе является статистической аномалией.
3. **Max inline delay 2ms — слишком мало для реального поведения** — настоящий Chrome имеет think-time 50-200ms, но это не применимо inline.

---

## 5. Flow Shaper (Anti-ML) {#5-flow-shaper}

### Концепция

ML-классификаторы (ET-BERT, FlowPic, AppNet) анализируют **целые потоки**, а не отдельные пакеты. Flow Shaper ресейпает все 5 измерений:
1. Packet size distribution (histogram)
2. Inter-arrival time distribution
3. Upload/download byte ratio
4. Burst patterns
5. Flow duration and idle periods

### Профили потоков

```cpp
enum class FlowProfile {
    WEB_BROWSING,   // burst(10-30 pkts) → pause(2-8s) → burst
    VIDEO_STREAM,   // constant downstream ~5Mbps
    MESSENGER,      // rare small packets, periodic typing
    GAMING,         // 50-100B at constant 20-60Hz
    FILE_DOWNLOAD,  // large downstream, minimal upstream
    CUSTOM
};
```

### Burst model с распределениями

```cpp
struct BurstModel {
    Distribution timing_distribution = Distribution::PARETO;
    double pareto_alpha = 1.5;
    // Также: GAUSSIAN, EXPONENTIAL
};
```

Выбор Pareto-распределения — это грамотный выбор: реальный интернет-трафик следует heavy-tailed distribution, а не Gaussian.

### Оценка

**✅ Сильные стороны:**
1. **5-мерное shaping** — комплексный подход
2. **Pareto distribution** — математически корректный выбор для burst timing
3. **Quantile shaping** (через Optimal Transport) — точное воспроизведение reference distribution

---

## 6. Optimal Transport / Wasserstein-1 {#6-optimal-transport}

### Математика

Это **самая математически грамотная часть** всего проекта. Реализует:

**Wasserstein-1 (earth mover's distance)** в 1D:

```
W1(P,Q) = ∫ |F_P(x) - F_Q(x)| dx
```

**Ключевое свойство** (Kantorovich-Rubinstein duality):
> W1 ≤ e ограничивает ошибку *любого* 1-Lipschitz функционала одновременно — mean, median, trimmed means, any smoothed rate estimator.

**Почему это лучше KS:**
> Kolmogorov-Smirnov distance bound sup|F_obs - F_ref|, что ничего не говорит о mean. На 1500-byte MTU KS of 0.05 всё ещё допускает 75-byte error в mean packet size.

### QuantileShaper

Реализует **monotone rearrangement** T = F_ref^(-1) ∘ F_obs:

```cpp
class QuantileShaper {
    // Каждый блок из n пакетов воспроизводит reference multiset
    // в пермутированном порядке. Эмпирическое распределение полного
    // блока IDENTICAL reference → W1 и KS = 0 (не bound, а exactly zero).
    size_t next();  // -> target size
};
```

### Оценка

**✅ Это выдающаяся работа:**
1. **Математически строгое обоснование** — не heuristic, а proven bound
2. **Exact quantile shaping** — не approximation, а точное воспроизведение distribution
3. **O(n log n)** сложность — эффективно
4. **Thread-safe** — mutex-based

**Это единственная часть проекта, которая выглядит как результат серьёзной академической работы.** Автор явно понимает теорию оптимального транспорта.

---

## 7. Traffic Mimicry {#7-traffic-mimicry}

### Профили маскировки

```cpp
enum class MimicProfile {
    HTTP_GET, HTTP_POST,
    HTTPS_CLIENT_HELLO, HTTPS_APPLICATION,
    DNS_QUERY, DNS_RESPONSE,
    QUIC_INITIAL,
    WEBSOCKET,
    BITTORRENT,
    SKYPE, ZOOM,
    GENERIC_TCP, GENERIC_UDP,
    QUIC_SHORT_HEADER,  // v2: session-stable DCID
    STUN_MESSAGE        // v2: RFC 5389 + MESSAGE-INTEGRITY
};
```

### TLS Session State Machine

```cpp
enum class TlsSessionPhase {
    IDLE,                // Нет TLS records
    CLIENT_HELLO_SENT,   // ClientHello (0x16) emitted
    HANDSHAKE_COMPLETE,  // Fake ServerHello+Finished emitted
    APPLICATION_DATA     // Ready for 0x17
};
```

**Issue #57 fix**: Orchestrator отправлял 0x17 (Application Data) без prior 0x16 (Handshake) → instant DPI anomaly signal. Теперь state machine гарантирует правильную последовательность.

### Wire versions

| Version | Changes |
|---|---|
| v1 | Legacy: XOR ClientHello, no ct_len in QUIC, payload-leak BT |
| v2 | AEAD-only ClientHello, QUIC ct_len field, safe BT info_hash |
| v3 | XChaCha20-Poly1305 for Application Data, atomic state |

### Оценка

**✅ Сильные стороны:**
1. **Огромный набор профилей** (15+) — от HTTP до Skype/Zoom
2. **Stateful session masks** (v2) — QUIC_SHORT_HEADER с per-session DCID, STUN с MESSAGE-INTEGRITY
3. **Session key binding** — HKDF-derived per-session mask key prevents fingerprinting

**⚠️ Проблемы:**
1. **BT (BitTorrent) профиль** — `info_hash` был payload-leak в v1 (исправлено в v2)
2. **Skype/Zoom профили** — нет данных, насколько реально они совпадают с настоящими Skype/Zoom паттернами
3. **Никто не верифицировал** эти профили против реальных pcap-дампов соответствующих приложений

---

## 8. Covert Channels {#8-covert-channels}

### Типы каналов

```cpp
enum class CovertChannelType {
    DNS_SUBDOMAIN,      // <base32data>.example.com
    DNS_TXT_RECORD,     // TXT record queries/responses
    HTTP_HEADER_STEGO,  // Data in HTTP header ordering/values
    HTTP_COOKIE_STEGO,  // Cookie values using allowed chars
    HTTPS_PADDING       // TLS record padding bytes
};
```

### Как работает DNS covert channel

```
Payload: "SECRET_DATA"
→ base32 encode → "knqxc3tpeb2gs3a"
→ split into labels (max 63 chars each)
→ "knqxc3tp.eb2gs3a.cdn-static.example.com"
→ DNS query
```

### Оценка

**✅ Сильные стороны:**
- 5 типов каналов с automatic fallback
- Base32 encoding (RFC 4648, no padding) — корректный DNS label format
- Activation при threat_level >= CRITICAL

**⚠️ Проблемы:**
- **Крайне низкая пропускная способность** — 1000 bytes/sec target
- **DNS covert channel — хорошо известная техника** — современные DPI/TSPU могут детектировать DNS tunneling по статистике запросов
- **Нет шифрования канала** — только encoding

---

## 9. Master Orchestrator {#9-master-orchestrator}

### 7-стадийный пайплайн

```
Input packet
    │
    ▼
┌─────────────────────┐
│ Phase 1: Adversarial │  ← Anti-ML padding
│      Padding         │
├─────────────────────┤
│ Phase 2: Flow        │  ← Flow-level shaping
│      Shaper          │
├─────────────────────┤
│ Phase 2+: TLS        │  ← JA3/JA4 emulation
│      Fingerprint     │
├─────────────────────┤
│ Phase 2+: Advanced   │  ← Multi-technique bypass
│      DPI Bypass      │
├─────────────────────┤
│ Phase 3D: ECH        │  ← Encrypted Client Hello
├─────────────────────┤
│ Mimicry              │  ← Protocol wrapping
├─────────────────────┤
│ Phase 3: Probe       │  ← Anti-probe (server-side)
│      Resistance      │
└─────────────────────┘
    │
    ▼
Output packet (on wire)
```

### Стратегии

```cpp
static OrchestratorStrategy stealth();      // Max protection, higher overhead
static OrchestratorStrategy paranoid();     // CRITICAL: max entropy + constant rate
static OrchestratorStrategy balanced();     // Good protection, moderate overhead
static OrchestratorStrategy performance();  // Min overhead, basic protection
static OrchestratorStrategy max_compat();   // Maximum compatibility
```

### Адаптивное управление threat level

```
Adaptive escalation:
  - escalation_threshold = 3 detection events → raise threat
  - deescalation_threshold = 20 successful sends → lower threat
  - deescalation_cooldown_sec = 300 (5 min)
```

---

## 10. Strategy Synthesis (v1.8.0) {#10-strategy-synthesis}

### Алгоритм

```
For each destination address:
  1. Build strategy from 3 genes:
     - Split gene: position (byte/SNI/midSLD)
     - Order gene: in-order / disorder / reverse
     - Fake gene: none / badsum / badseq / low-TTL

  2. Ladder of 12 candidates
     ordered by Laplace-smoothed global win rates:
     P(win) = (successes + 1) / (trials + 2)  [Laplace smoothing]

  3. Trial:
     - Success = client payload past end of ClientHello record
     - Failure = ClientHello retransmitted at same seq,
                 or silent flow (>3s) to same destination

  4. Exhaustion → new round
```

### Оценка

**✅ Это mathematically elegant:**
- Laplace smoothing предотвращает overfitting на малых выборках
- Per-destination стратегии (не global)
- Clean success/failure определение
- Round-based exploration

**⚠️ Проблемы:**
- **12 кандидатов — это hardcoded число**, не ясно, как оно было выбрано
- **Только 3 гена** — реальное пространство стратегий гораздо шире
- **Нет true exploration** (no Thompson sampling, no UCB) — просто sorted ladder

---

## 11. Итоговая оценка {#11-оценка}

### DPI часть

| Аспект | Оценка | Комментарий |
|---|---|---|
| Набор техник | ⭐⭐⭐⭐⭐ | 15+ техник, пресеты под RU-операторов |
| Качество реализации | ⭐⭐⭐ | Серьёзные баги до R16 (blockcheck не работал, NFQUEUE stub) |
| Кроссплатформа | ⭐⭐⭐⭐ | Win/Lin/Mac, но DRIVER mode имеет разную зрелость |
| Адаптивность | ⭐⭐⭐⭐ | Strategy synthesis v1.8.0 — сильный подход |
| Тестирование | ⭐⭐⭐⭐ | DPI Lab, 4 suite, combat results |

### ML часть (Anti-ML)

| Аспект | Оценка | Комментарий |
|---|---|---|
| Adversarial Padding | ⭐⭐⭐⭐ | Основан на AdvTraffic research, но нет внутреннего классификатора |
| Behavioral Cloak | ⭐⭐⭐ | Хорошие модели, но static/hardcoded, не trained |
| Flow Shaper | ⭐⭐⭐⭐ | 5-dimensional shaping, Pareto distribution |
| Optimal Transport | ⭐⭐⭐⭐⭐ | **Выдающаяся работа** — Wasserstein-1, exact quantile |
| Traffic Mimicry | ⭐⭐⭐⭐ | 15+ профилей, session-stable masks, но без верификации на реальных trace'ах |
| Covert Channels | ⭐⭐⭐ | Базовая реализация, хорошо известна DPI |
| Geneva Engine | ⭐⭐⭐ | Нет настоящего эволюционного цикла, только presets |
| Orchestrator | ⭐⭐⭐⭐ | Чистая 7-стадийная архитектура, adaptive threat management |

### Общий вердикт

**DPI часть** — это серьёзная engineering work с впечатляющим набором техник, но с историей критических багов, которые были исправлены только через 6+ месяцев после релиза.

**ML часть** — это **самая интересная часть проекта**, особенно Optimal Transport / Wasserstein-1. Это академический уровень математики в production коде. Однако:

1. **Нет верификации против реальных ML-классификаторов** — все модули основаны на теоретических исследованиях, но никто не замерял реальную evasion rate против ET-BERT/FlowPic/AppNet.
2. **Behavioral модели hardcoded** — не обучены на реальных трафик-trace'ах.
3. **Adversarial padding работает только NCP-to-NCP** — против standalone DPI без server-side NCP он бесполезен.

**Главный вопрос**: работает ли это реально против ТСПУ? Автор сам подчёркивает: «Эти результаты по-прежнему не означают подтверждённый внешний обход блокировок конкретных сервисов».

DPI Lab показывает 100% bypass против userspace DPI emulator — но emulator ≠ real TSPU hardware.
