# 🛠️ ONNX Shadow Classifier — Implementation Guide for Dynam/NCP

**Дата**: 27 ноября 2026  
**Цель**: Реализовать Phase 3 — ONNX Runtime shadow classifiers для AdversaryTester

---

## 📋 Содержание

1. [Архитектура: что и зачем](#1-архитектура)
2. [Модели-кандидаты](#2-модели)
3. [Датасеты для обучения](#3-датасеты)
4. [ONNX Runtime C++ API](#4-onnx-runtime)
5. [Точка интеграции в Dynam](#5-интеграция)
6. [Performance requirements](#6-performance)
7. [Пошаговый план реализации](#7-план)
8. [Архитектурные решения](#8-решения)

---

## 1. Архитектура {#1-архитектура}

### Текущее состояние (Phase 1-2)

```
Обфусцированный пакет
       │
       ▼
┌─────────────────────┐
│  AdversaryTester    │  ← 6 эвристических метрик
│  (heuristic-v1)     │     entropy, chi², KS, W1, variance, timing
│                     │
│  aggregate_stealth  │  ← weighted sum → DetectionFeedback
│  = 0.25×entropy     │
│  + 0.25×chi²        │
│  + 0.10×KS          │
│  + 0.05×W1          │
│  + 0.10×size_var    │
│  + 0.15×timing      │
│  + 0.10×burst       │
└─────────────────────┘
       │
       ▼
 DetectionFeedback
 (detected=true/false, confidence=0-1)
       │
       ▼
 AdversarialPadding::report_feedback()
 → переключение стратегии
```

### Целевое состояние (Phase 3)

```
Обфусцированный пакет
       │
       ▼
┌──────────────────────────────────────────┐
│           AdversaryTester                │
│                                          │
│  ┌──────────────────┐  ┌──────────────┐  │
│  │ HeuristicScores  │  │ ONNX Shadow  │  │
│  │ (6 метрик)       │  │ Classifier   │  │
│  │                  │  │              │  │
│  │ entropy, chi²    │  │ ET-BERT-tiny │  │
│  │ KS, W1, var,     │  │ FlowPic-lite │  │
│  │ timing, burst    │  │              │  │
│  └────────┬─────────┘  └──────┬───────┘  │
│           │                    │          │
│           ▼                    ▼          │
│  ┌────────────────────────────────────┐   │
│  │     Combined Detection Score       │   │
│  │  w1 × heuristic + w2 × onnx_score │   │
│  └────────────────────────────────────┘   │
└──────────────────┬───────────────────────┘
                   │
                   ▼
          DetectionFeedback → AdversarialPadding
```

---

## 2. Модели-кандидаты {#2-модели}

### 2.1 ET-BERT-tiny (packet-level classifier)

**Оригинал**: ET-BERT (WWW 2022, 334+ цитирований)
- **Репозиторий**: https://github.com/linwhitehat/ET-BERT
- **Архитектура**: 12 Transformer blocks, 12 attention heads, dim=768, 512 tokens
- **Точность**: 98.9% F1 (ISCX-VPN), 97.4% (CSTNET-TLS 1.3)
- **Проблема**: ~110M параметров — слишком большой для inline

**Что нужно для Dynam**: ET-BERT-tiny
- **Цель**: 2-4 Transformer blocks, dim=128-256, ~0.5-2M параметров
- **Input**: первые 128-512 байт payload (Datagram2Token encoded)
- **Output**: P(VPN) / P(Tor) / P(Browsing) / P(Video) / P(Chat) / P(Normal)
- **Latency target**: < 100μs per inference on CPU

**Ключевая особенность**:
> Transformer-модели достигают performance plateau после первых 32 байт.
> (AdvTraffic, 2025) — значит, даже tiny-модель на первых 32-128 байтах
> будет опасным противником.

**Datagram2Token pipeline** (как ET-BERT получает input):
```
Raw bytes → Byte-Pair Encoding (BPE) → Token IDs → Embedding → Transformer
```
Для tiny-версии можно упростить:
```
Raw bytes → Fixed-size tokenization (4-byte tokens) → Embedding → Mini-Transformer
```

### 2.2 FlowPic-lite (flow-level classifier)

**Оригинал**: FlowPic (IEEE TNSM 2021)
- **Репозиторий**: https://github.com/talshapira/FlowPic
- **Архитектура**: LeNet-5 variant (2 conv + 2 FC layers)
- **Input**: 2D histogram 1500×1500 (packet_size × time_of_arrival)
- **Точность**: 96%+ traffic categorization, 99.7% app identification
- **Проблема**: 1500×1500 = 2.25M float input — тяжёлый

**Что нужно для Dynam**: FlowPic-lite
- **Уменьшить**: до 64×64 или 32×32 histogram
- **Архитектура**: 2-3 conv layers (3×3) + 1 FC → softmax
- **~50K-200K параметров**
- **Input**: packet sizes + inter-arrival times за sliding window (5-15 сек)
- **Output**: P(VoIP) / P(Video) / P(Chat) / P(Browsing) / P(File) / P(NCP-obfuscated)
- **Latency target**: < 50μs per inference

**Что уже есть в Dynam**: FlowShaper собирает ровно эти данные (packet sizes, IATs, burst patterns) → `FlowSnapshot` в AdversaryTester

### 2.3 LightGBM-classifier (fastest option)

**Референс**: [rishik1072/encrypted-traffic-classification](https://github.com/rishik1072/encrypted-traffic-classification-UROP)
- **Модель**: LightGBM, K=10 features
- **Точность**: 0.95 Macro-F1
- **Latency**: 0.0026 ms per inference
- **Model size**: 0.15 MB

**Features** (zero-payload, только metadata):
- Packet length mean/std/min/max
- Inter-arrival time mean/std
- Upload/download ratio
- Burst count, burst duration
- Flow duration
- Small/large packet fraction

**Плюс**: можно экспортировать LightGBM → ONNX через `onnxmltools`  
**Минус**: только flow-level, не packet-level

### 2.4 Рекомендуемый выбор

| Модель | Уровень | Точность | Latency | Сложность | Приоритет |
|---|---|---|---|---|---|
| **LightGBM→ONNX** | Flow | 0.95 F1 | **0.003 ms** | Простая | **Phase 3a** (сначала) |
| **FlowPic-lite** | Flow | 0.90+ | ~0.05 ms | Средняя | **Phase 3b** |
| **ET-BERT-tiny** | Packet | 0.85+ | ~0.1 ms | Сложная | **Phase 3c** (потом) |

---

## 3. Датасеты для обучения {#3-датасеты}

### 3.1 Публичные датасеты

| Датасет | Размер | Классы | Шифрование | Ссылка |
|---|---|---|---|---|
| **ISCX-VPN-2016** | 31,560 flows | 7 (Email, Chat, VoIP, Streaming, File, Browsing, VPN) | VPN + non-VPN | https://www.unb.ca/cic/datasets/vpn.html |
| **ISCX-Tor-2016** | ~20,000 flows | 7 + Tor | Tor + non-Tor | https://www.unb.ca/cic/datasets/tor.html |
| **USTC-TFC2016** | ~280,000 flows | 12 apps | Mixed | Available via Google Drive (NetMamba repo) |
| **CSTNET-TLS 1.3** | 118 apps | 118 | TLS 1.3 | https://github.com/linwhitehat/ET-BERT/tree/main/datasets |
| **Cross-Platform** | Multi-device | 12 | Mixed | Via NetMamba repo |

### 3.2 Что нужно для Dynam

Для задачи "детекция NCP-obfuscated трафика" нужен **бинарный** классификатор:
```
Class 0: Normal traffic (Chrome, Firefox, regular HTTPS)
Class 1: NCP-obfuscated traffic (adversarial padding, flow shaping, mimicry)
```

**Проблема**: такого датасета не существует. Нужно создать:

1. **Взять ISCX-VPN-2016** как base normal traffic
2. **Прогнать через Dynam's pipeline**: AdversarialPadding → FlowShaper → Mimicry
3. **Пометить результат** как Class 1
4. **Обучить бинарный классификатор**: normal vs NCP-obfuscated

**Пайплайн генерации датасета**:
```python
# 1. Загрузить pcap
flows = parse_pcap("ISCX-VPN-2016/browse/normal.pcap")

# 2. Для каждого flow, применить NCP pipeline
for flow in flows:
    obfuscated = ncp_pipeline(flow, 
        adversarial_strategy=ADAPTIVE,
        flow_profile=WEB_BROWSING,
        mimic_profile=HTTPS_APPLICATION)
    label = 1  # NCP-obfuscated
    
# 3. Оригинальные flows → label = 0
# 4. Сохранить как training dataset
```

---

## 4. ONNX Runtime C++ API {#4-onnx-runtime}

### 4.1 Зависимость

```cmake
# CMakeLists.txt
option(ENABLE_ONNXRUNTIME "Enable ONNX Runtime shadow classifiers" OFF)

if(ENABLE_ONNXRUNTIME)
    find_package(onnxruntime REQUIRED)
    # или:
    # include(FetchContent)
    # FetchContent_Declare(onnxruntime URL ...)
    target_link_libraries(ncp_core PRIVATE onnxruntime)
    target_compile_definitions(ncp_core PRIVATE NCP_HAS_ONNXRUNTIME)
endif()
```

### 4.2 Минимальный API

```cpp
#ifdef NCP_HAS_ONNXRUNTIME
#include <onnxruntime_cxx_api.h>

class OnnxShadowClassifier {
public:
    OnnxShadowClassifier() = default;
    
    bool load(const std::string& model_path) {
        try {
            env_ = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "ncp-shadow");
            Ort::SessionOptions opts;
            opts.SetIntraOpNumThreads(1);  // Critical: single thread for latency
            opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
            session_ = std::make_unique<Ort::Session>(*env_, model_path.c_str(), opts);
            
            // Cache input/output names
            Ort::AllocatorWithDefaultOptions alloc;
            input_name_ = session_->GetInputName(0, alloc);
            output_name_ = session_->GetOutputName(0, alloc);
            input_shape_ = session_->GetInputTypeInfo(0)
                .GetTensorTypeAndShapeInfo().GetShape();
            
            loaded_ = true;
            return true;
        } catch (const Ort::Exception& e) {
            return false;
        }
    }
    
    // Run inference, return class probabilities
    std::vector<float> predict(const float* input, size_t input_size) {
        if (!loaded_) return {};
        
        auto mem = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        auto tensor = Ort::Value::CreateTensor<float>(
            mem, const_cast<float*>(input), input_size,
            input_shape_.data(), input_shape_.size());
        
        auto outputs = session_->Run(
            Ort::RunOptions{nullptr},
            &input_name_, &tensor, 1,
            &output_name_, 1);
        
        float* data = outputs[0].GetTensorMutableData<float>();
        auto shape = outputs[0].GetTensorTypeAndShapeInfo().GetShape();
        size_t n = 1;
        for (auto d : shape) n *= d;
        return std::vector<float>(data, data + n);
    }
    
    bool is_loaded() const { return loaded_; }

private:
    std::unique_ptr<Ort::Env> env_;
    std::unique_ptr<Ort::Session> session_;
    std::vector<int64_t> input_shape_;
    const char* input_name_ = nullptr;
    const char* output_name_ = nullptr;
    bool loaded_ = false;
};
#endif
```

### 4.3 Platform-specific notes

| Платформа | Установка ONNX Runtime |
|---|---|
| **Ubuntu/Debian** | `apt install libonnxruntime-dev` |
| **macOS** | `brew install onnxruntime` |
| **Windows (vcpkg)** | `vcpkg install onnxruntime:x64-windows` |
| **Cross-compile (mingw)** | Static link из release tarball |

---

## 5. Точка интеграции в Dynam {#5-интеграция}

### 5.1 Где встроить в AdversaryTester

Текущий `AdversaryTester` имеет:
- `record_packet(size, iat, content_bytes)` — accumulating FlowSnapshot
- `evaluate()` — called every `window_packets` (default 50)
- `HeuristicScores` → `aggregate_stealth()` → `DetectionFeedback`

**Новый код**:
```cpp
struct AdversaryTesterConfig {
    // ... existing fields ...
    
    // Phase 3: ONNX shadow classifiers
    std::string flow_classifier_model;  // path to .onnx file
    std::string packet_classifier_model;  // path to .onnx file
    double onnx_weight = 0.6;  // weight of ONNX vs heuristic in combined score
    size_t flow_window_seconds = 10;  // FlowPic time window
};

class AdversaryTester {
    // ...
#ifdef NCP_HAS_ONNXRUNTIME
    OnnxShadowClassifier flow_classifier_;
    OnnxShadowClassifier packet_classifier_;
#endif
    
    double evaluate_with_onnx(const FlowSnapshot& snap) {
#ifdef NCP_HAS_ONNXRUNTIME
        if (flow_classifier_.is_loaded()) {
            // Build FlowPic-lite input: 64×64 histogram
            auto histogram = build_flowpic(snap, 64, 64, flow_window_seconds);
            auto probs = flow_classifier_.predict(histogram.data(), histogram.size());
            // probs[NCP_CLASS] = probability that this is NCP-obfuscated traffic
            return probs[NCP_CLASS];
        }
#endif
        return 0.0;  // No ONNX available
    }
};
```

### 5.2 Combined score

```cpp
double combined_stealth(const HeuristicScores& h, double onnx_score) {
    double heuristic = h.aggregate_stealth();  // 0.0 = detected, 1.0 = invisible
    double onnx_stealth = 1.0 - onnx_score;    // same scale
    
    // Weighted combination (configurable)
    double w_heur = 1.0 - config.onnx_weight;  // 0.4
    double w_onnx = config.onnx_weight;         // 0.6
    
    return w_heur * heuristic + w_onnx * onnx_stealth;
}
```

### 5.3 Feedback loop

```
For each window of 50 packets:
  1. Collect FlowSnapshot (sizes, IATs, content)
  2. Compute HeuristicScores (existing)
  3. Compute ONNX score (new)
  4. Combined score → DetectionFeedback
  5. → AdversarialPadding::report_feedback()
     → strategy switch if detected
```

---

## 6. Performance requirements {#6-performance}

### 6.1 Latency budget

Dynam работает на скорости **~103 MB/s** (из DPI Lab benchmarks).

| Операция | Latency | Допустимо? |
|---|---|---|
| LightGBM inference | **0.003 ms** | ✅ Да, per-flow |
| FlowPic-lite (64×64) | ~0.05 ms | ✅ Да, per-window (10s) |
| ET-BERT-tiny (128 tokens) | ~0.1 ms | ⚠️ Per-packet, может bottleneck |
| Existing heuristic eval | < 0.01 ms | ✅ |

**Вывод**:
- **LightGBM**: можно запускать **per packet** без проблем
- **FlowPic-lite**: запускать **per window** (every 50 packets / 10 sec) — без проблем
- **ET-BERT-tiny**: запускать **every N-th packet** (например, каждый 10-й) или только при handshake

### 6.2 Memory budget

| Модель | RAM |
|---|---|
| LightGBM ONNX | ~0.15 MB |
| FlowPic-lite | ~1-5 MB (model + buffers) |
| ET-BERT-tiny | ~10-30 MB (model + inference buffers) |

### 6.3 Constraints

- Inference runs on **packet capture thread** (WinDivert callback)
- Must not block packet processing
- Solution: **pre-allocate all buffers**, no dynamic allocation during inference
- ONNX Runtime session is created once, reused

---

## 7. Пошаговый план реализации {#7-план}

### Phase 3a: LightGBM Flow Classifier (1-2 недели)

**Цель**: Быстрый flow-level классификатор для валидации pipeline

```
Шаг 1: Подготовить датасет
├── Скачать ISCX-VPN-2016
├── Извлечь features (10 metadata features)
├── Прогнать через Dynam's pipeline → label=1
├── Сохранить как CSV: features,label
└── Split: 80% train / 20% test

Шаг 2: Обучить модель (Python)
├── LightGBM, K=10 features
├── Binary: normal vs NCP-obfuscated
├── Цель: F1 > 0.90
└── Сохранить: model_lightgbm.pkl

Шаг 3: Экспорт в ONNX
├── import onnxmltools
├── onnx_model = convert_lightgbm(model, target_opset=12)
├── Save: shadow_flow_classifier.onnx
└── Verify: Python output == C++ output

Шаг 4: Интеграция в C++
├── Добавить OnnxShadowClassifier class
├── #ifdef NCP_HAS_ONNXRUNTIME guards
├── Load model in AdversaryTester constructor
├── Evaluate per-window (every 50 packets)
├── Combined score: w1×heuristic + w2×onnx
├── Unit tests: mock ONNX, verify feedback loop
└── CMake: ENABLE_ONNXRUNTIME option

Шаг 5: Валидация
├── DPI Lab: запустить NCP pipeline с ONNX enabled
├── Замерить: latency overhead, detection rate
├── Сравнить: heuristic-only vs heuristic+ONNX
└── Document: results in AUDIT.md
```

### Phase 3b: FlowPic-lite CNN (3-4 недели)

```
Шаг 1: Подготовить FlowPic dataset
├── Для каждого flow из ISCX-VPN:
│   ├── Build 64×64 histogram (size × time)
│   └── Save as .npz
├── NCP-obfuscated flows → build same histograms
└── Dataset: ~50K images, binary classification

Шаг 2: Обучить FlowPic-lite (Python/PyTorch)
├── Architecture:
│   Conv2d(1, 16, 5) → ReLU → MaxPool(2)
│   Conv2d(16, 32, 5) → ReLU → MaxPool(2)
│   Flatten → Linear(32*13*13, 64) → ReLU
│   Linear(64, 2) → Softmax
├── ~200K parameters
├── Train: 50 epochs, lr=0.001, Adam
└── Цель: accuracy > 0.90

Шаг 3: Export to ONNX
├── torch.onnx.export(model, dummy_input, "shadow_flowpic.onnx")
├── Verify: Python ≈ C++ output (atol=1e-4)
└── Optimize: onnxruntime.transformers.optimizer

Шаг 4: Интеграция
├── Add flowpic_builder(): FlowSnapshot → 64×64 histogram
├── Add OnnxShadowClassifier instance for FlowPic
├── Run per-window (10-sec sliding window)
├── Combined: weighted heuristic + flowpic + lightgbm
└── Test with DPI Lab
```

### Phase 3c: ET-BERT-tiny Packet Classifier (6-8 недель)

```
Шаг 1: Fine-tune ET-BERT tiny
├── Start from: ET-BERT pretrained weights (if available)
├── Or: train mini-Transformer from scratch
├── Architecture:
│   2 Transformer blocks, 4 heads, dim=128
│   Input: 128 bytes → 32 tokens (4 bytes each)
│   Output: softmax over 6 classes
├── ~1M parameters
└── Train on: ISCX-VPN + NCP-augmented data

Шаг 2: Export + Optimize
├── torch.onnx.export → et_bert_tiny.onnx
├── Quantize: INT8 (onnxruntime.quantization)
├── Latency test: target < 100μs
└── Verify accuracy: target > 0.85 F1

Шаг 3: Интеграция
├── Datagram2Token: raw bytes → int64 token IDs
├── Run per-packet or every N-th packet
├── Pre-allocate token buffer (no allocation in hot path)
└── Combined: 3-way (heuristic + flowpic + etbert)
```

---

## 8. Архитектурные решения {#8-решения}

### 8.1 Где хранить модели

```
~/.ncp/models/
├── shadow_flow_classifier.onnx  (Phase 3a, 0.15 MB)
├── shadow_flowpic.onnx          (Phase 3b, ~2 MB)
└── shadow_etbert_tiny.onnx      (Phase 3c, ~10 MB)
```

### 8.2 Graceful degradation

```cpp
// Все три классификатора опциональны. Любой/все могут отсутствовать.
// Если ONNX не скомпилирован → heuristic-only (текущее поведение)
// Если ONNX скомпилирован, но модель не найдена → skip, log warning
// Если модель загружена → использовать в combined score
```

### 8.3 Thread safety

```cpp
// OnnxShadowClassifier: 
// - Ort::Session is thread-safe for inference (per ONNX Runtime docs)
// - Pre-allocate input/output buffers per thread
// - No shared mutable state during inference
```

### 8.4 Feedback loop closure

```cpp
// Без ONNX:
//   AdversarialPadding adaptive → blind strategy rotation (no real feedback)
//
// С ONNX:
//   AdversarialPadding adaptive → ONNX tells us "still detected" → switch strategy
//   → ONNX tells us "not detected" → keep current strategy
//   
// Это ЗАМЫКАЕТ feedback loop.
// AdversarialPadding становится реально адаптивным.
```

---

## 📁 Необходимые файлы для реализации

### Новые файлы

| Файл | Назначение |
|---|---|
| `src/core/include/ncp_onnx_classifier.hpp` | ONNX Runtime wrapper |
| `src/core/src/ncp_onnx_classifier.cpp` | Реализация |
| `src/core/include/ncp_flowpic_builder.hpp` | FlowSnapshot → FlowPic histogram |
| `src/core/src/ncp_flowpic_builder.cpp` | Реализация |
| `src/core/include/ncp_datagram_tokenizer.hpp` | Raw bytes → token IDs (ET-BERT) |
| `src/core/src/ncp_datagram_tokenizer.cpp` | Реализация |
| `models/README.md` | Документация по моделям |
| `scripts/train_shadow_classifier.py` | Training pipeline |
| `scripts/export_to_onnx.py` | PyTorch → ONNX export |
| `scripts/validate_onnx.py` | Python vs C++ output verification |

### Модифицируемые файлы

| Файл | Изменение |
|---|---|
| `src/core/include/ncp_adversary_tester.hpp` | Добавить ONNX fields + combined score |
| `src/core/src/ncp_adversary_tester.cpp` | Добавить evaluate_with_onnx() |
| `src/core/CMakeLists.txt` | ENABLE_ONNXRUNTIME option + link |
| `CMakeLists.txt` | Top-level option |
| `DEPENDENCIES.md` | Document ONNX Runtime dependency |
| `tests/test_adversary_tester.cpp` | Tests for ONNX integration |

---

## 🔑 Ключевые выводы

1. **Начинать с LightGBM** — самый быстрый путь к working prototype (1-2 недели)
2. **Датасет — главный bottleneck** — нужно сгенерировать NCP-obfuscated трафик из ISCX-VPN
3. **ONNX Runtime integration — тривиальна** — ~200 строк C++, API хорошо документирован
4. **Производительность не проблема** — LightGBM 0.003ms, FlowPic 0.05ms, оба fit в budget
5. **Главная ценность — замыкание feedback loop** — AdversarialPadding становится реально адаптивным
