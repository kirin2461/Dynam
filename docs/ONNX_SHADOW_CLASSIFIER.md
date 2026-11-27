# ONNX Shadow Classifier for Dynam/NCP

**Phase 3** of the Anti-ML Pipeline — ONNX Runtime shadow classifiers that close the feedback loop for `AdversarialPadding`.

## Status

| Component | Status | Notes |
|---|---|---|
| **Training pipeline** | ✅ Complete | Python scripts for data generation, training, ONNX export |
| **Trained model** | ✅ Complete | RandomForest, AUC=0.9914, F1=0.9584, 8.6μs inference |
| **C++ wrapper** | ✅ Complete | `OnnxShadowClassifier` with pImpl, thread-safe |
| **CMake integration** | ✅ Complete | `ENABLE_ONNXRUNTIME` option |
| **Tests** | ✅ Complete | Stub + ONNX tests |

## Quick Start

### 1. Train the model

```bash
cd dynam-onnx
python scripts/train_final.py
```

Output:
- `models/shadow_flow_classifier.onnx` (712 KB)
- `models/shadow_flow_classifier_metadata.json`

### 2. Validate

```bash
python scripts/validate_onnx.py
```

### 3. Integrate into Dynam

Copy files:
```bash
# C++ source
cp src/ncp_onnx_classifier.hpp <dynam>/src/core/include/
cp src/ncp_onnx_classifier.cpp <dynam>/src/core/src/

# CMake
cp cmake/ncp_onnx_classifier.cmake <dynam>/cmake/

# Tests
cp tests/test_onnx_classifier.cpp <dynam>/tests/
```

Add to `<dynam>/CMakeLists.txt`:
```cmake
option(ENABLE_ONNXRUNTIME "Enable ONNX Runtime shadow classifiers" OFF)
if(ENABLE_ONNXRUNTIME)
    include(cmake/ncp_onnx_classifier.cmake)
endif()
```

Add to `<dynam>/src/core/CMakeLists.txt`:
```cmake
target_sources(ncp_core PRIVATE src/ncp_onnx_classifier.cpp)
if(ENABLE_ONNXRUNTIME)
    target_link_libraries(ncp_core PRIVATE onnxruntime::onnxruntime)
    target_compile_definitions(ncp_core PRIVATE NCP_HAS_ONNXRUNTIME)
endif()
```

### 4. Use in AdversaryTester

```cpp
#include "ncp_onnx_classifier.hpp"

// In AdversaryTester:
OnnxClassifierConfig onnx_cfg;
onnx_cfg.model_path = "~/.ncp/models/shadow_flow_classifier.onnx";
onnx_cfg.enabled = true;
onnx_cfg.weight = 0.6;  // 60% ONNX, 40% heuristic

OnnxShadowClassifier onnx_clf(onnx_cfg);
onnx_clf.load();

// In evaluate():
auto features = SizeErrorLearner::from_snapshot(snapshot, error_rate);
std::vector<float> onnx_input = {
    features.size_mean, features.size_cv, features.frac_small,
    features.frac_large, features.error_rate, features.timing_cov,
    features.burst_anomaly, features.ks_distance, upload_ratio, burst_rate
};
auto onnx_pred = onnx_clf.predict(onnx_input);

double combined = onnx_clf.combined_stealth(heuristic_stealth, onnx_pred);
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│               AdversaryTester                     │
│                                                   │
│  FlowSnapshot (50 packets)                        │
│       │                                           │
│       ├──→ HeuristicScores (6 metrics)            │
│       │         │                                 │
│       │         └──→ aggregate_stealth()          │
│       │                   │                       │
│       ├──→ OnnxShadowClassifier                   │
│       │         │                                 │
│       │         └──→ predict(features)            │
│       │                   │                       │
│       └──→ combined_stealth(heuristic, onnx)      │
│                     │                             │
│                     ▼                             │
│            DetectionFeedback                      │
│                     │                             │
│                     ▼                             │
│      AdversarialPadding::report_feedback()        │
│      → strategy switch if detected                │
└──────────────────────────────────────────────────┘
```

## Model Details

| Property | Value |
|---|---|
| Algorithm | RandomForest (50 trees, max_depth=10) |
| ROC-AUC | 0.9914 |
| F1 Score | 0.9584 |
| Accuracy | 96% |
| Model size | 712 KB |
| Inference latency | **8.6 μs median** |
| Input features | 10 (metadata only, zero-payload) |
| Output | tensor[batch, 2]: [P(normal), P(NCP-obfuscated)] |

### Feature Importance (gain)

| Feature | Importance |
|---|---|
| size_cv | 25,297 |
| burst_rate | 18,286 |
| timing_cov | 10,141 |
| upload_ratio | 6,142 |
| frac_small | 3,817 |
| size_mean | 3,586 |

**Key insight**: `size_cv` (coefficient of variation of packet sizes) is the #1 discriminator. NCP's quantile shaping reduces size variance, making it detectable. `timing_cov` (inter-arrival time variation) is #3 — NCP's flow shaping regularizes timing.

## Dependencies

### Required
- **ONNX Runtime** ≥ 1.15 — **mandatory**, project does not compile without it.
  - Ubuntu: `sudo apt install libonnxruntime-dev`
  - macOS: `brew install onnxruntime`
  - Windows: `vcpkg install onnxruntime:x64-windows` or NuGet `Microsoft.ML.OnnxRuntime`

There are **no stubs or fallbacks**. If ONNX Runtime is not found, CMake fails with a fatal error.

### Training (Python)
```bash
pip install lightgbm scikit-learn onnxmltools skl2onnx onnx numpy onnxruntime
```

## Design Decisions

1. **No stubs**: Every code path is real. ONNX Runtime is a hard dependency — the project does not compile without it. No `#ifdef` guards, no no-op fallbacks.

2. **Thread safety**: `predict()` is safe to call from multiple threads. ONNX Runtime's `Ort::Session` is thread-safe for inference.

3. **Pre-allocated buffers**: No dynamic allocation during inference. Memory info and shapes are cached at load time.

4. **Separate feature struct**: `OnnxShadowFeatures` (10 fields) matches the trained model exactly. This is NOT the same as `SizeErrorFeatures` (8 fields). Use `extract_onnx_features()` from `ncp_onnx_integration.hpp`.

## Files

```
dynam-onnx/
├── README.md                          # This file
├── src/
│   ├── ncp_onnx_classifier.hpp        # C++ header
│   └── ncp_onnx_classifier.cpp        # C++ implementation
├── cmake/
│   └── ncp_onnx_classifier.cmake      # CMake integration
├── scripts/
│   ├── train_shadow_classifier.py     # v1: LightGBM training
│   ├── train_final.py                 # v2: Auto-selects best model
│   └── validate_onnx.py              # ONNX model validation
├── tests/
│   └── test_onnx_classifier.cpp       # C++ unit tests
└── models/
    ├── shadow_flow_classifier.onnx    # Trained model (712 KB)
    └── shadow_flow_classifier_metadata.json
```

## Future Work (Phase 3b/3c)

- **Phase 3b**: FlowPic-lite CNN (flow-level image classifier, 64×64 histogram)
- **Phase 3c**: ET-BERT-tiny (packet-level transformer, first 128 bytes)

## References

- [ET-BERT](https://github.com/linwhitehat/ET-BERT) — Transformer for encrypted traffic (WWW 2022)
- [FlowPic](https://github.com/talshapira/FlowPic) — CNN for traffic images (IEEE TNSM 2021)
- [AdvTraffic](https://arxiv.org/abs/2510.25810) — Adversarial pre-padding (2025)
- [ONNX Runtime C++ API](https://onnxruntime.ai/docs/api-cpp/)
