# C++ Math Modules — Pied Piper Edition

## Обзор

**9 математических модулей** реализованы на C++ для максимальной производительности.

| # | Модуль | Файл | Назначение |
|---|--------|------|------------|
| 1 | Fractal | `ncp_fractal.hpp` | Fractional Gaussian noise (Davies-Harte), Hurst exponent, MF-DFA |
| 2 | Chaotic | `ncp_chaotic.hpp` | Lorenz system, CSS modulation, Lyapunov exponents, Takens embedding |
| 3 | Ergodic | `ncp_ergodic.hpp` | Arnold cat map, Baker map, irrational rotation, Birkhoff convergence |
| 4 | Topological | `ncp_topological.hpp` | Vietoris-Rips, persistence diagram, Wasserstein-1, Sinkhorn |
| 5 | Tropical | `ncp_tropical.hpp` | Min-plus semiring, tropical polynomials, tropical LP, DPI evasion |
| 6 | P-adic | `ncp_padic.hpp` | Ultrametric distance, Mahler expansion, p-adic Fourier, clustering |
| 7 | Cluster | `ncp_cluster.hpp` | Fomin-Zelevinsky mutations, Laurent phenomenon, protocol mutation |
| 8 | Mirror | `ncp_mirror.hpp` | Bridgeland stability, wall-crossing, mirror morph (A↔B side) |
| 9 | Anabelian | `ncp_anabelian.hpp` | π₁^ét reconstruction, topology, outer automorphisms, dessins |

## Архитектура

```
dynam-src/src/core/
├── include/
│   ├── ncp_math_base.hpp          # Base types (MathContext, TransformMetrics)
│   ├── ncp_fractal.hpp            # Module 1: Fractal traffic
│   ├── ncp_chaotic.hpp            # Module 2: Chaotic embedding
│   ├── ncp_ergodic.hpp            # Module 3: Ergodic mixing
│   ├── ncp_topological.hpp        # Module 4: Topological morphing
│   ├── ncp_tropical.hpp           # Module 5: Tropical geometry
│   ├── ncp_padic.hpp              # Module 6: P-adic analysis
│   ├── ncp_cluster.hpp            # Module 7: Cluster algebra
│   ├── ncp_mirror.hpp             # Module 8: Mirror symmetry
│   ├── ncp_anabelian.hpp          # Module 9: Anabelian geometry
│   ├── ncp_math_all.hpp           # Master include + self_test()
│   └── ncp_math_c_api.hpp         # C API declarations
├── src/
│   └── ncp_math_c_api.cpp         # C API implementation
└── libncp_math.so                 # Compiled shared library
```

## Компиляция

```bash
cd dynam-src/src/core

# Compile shared library
g++ -std=c++17 -O2 -fPIC -shared -I include \
    -o libncp_math.so src/ncp_math_c_api.cpp -lm

# Compile test executable
g++ -std=c++17 -O2 -Wall -I include -o test_math test_math_modules.cpp -lm

# Run tests
./test_math
```

## Использование из C++

```cpp
#include "ncp_math_all.hpp"

using namespace ncp::Math;

// Fractal generation
FractalConfig cfg;
cfg.hurst = 0.75;
cfg.length = 1000;
FractalTrafficGenerator gen(cfg);
auto result = gen.generate_fgn();
double H = gen.compute_hurst(result.data);

// Chaotic embedding
ChaoticConfig cha_cfg;
cha_cfg.epsilon = 0.01;
ChaoticEmbedder embedder(cha_cfg);
auto embedded = embedder.embed(data);
double lyap = embedder.largest_lyapunov(data);

// Topological persistence
TopologicalMorpher morpher;
auto diagram = morpher.persistence_diagram(data);
double W1 = morpher.wasserstein_distance(diag1, diag2);

// Run all tests
bool ok = ncp::Math::self_test();
```

## Использование из Python (через ctypes)

```python
from src.math.cpp_backend import CppMathBackend
import numpy as np

backend = CppMathBackend("libncp_math.so")

# Self-test
assert backend.self_test()

# Fractal
data = backend.fractal_generate(1000, hurst=0.75)
hurst = backend.fractal_hurst(data)

# Chaotic
embedded = backend.chaotic_transform(data, epsilon=0.01)
lyapunov = backend.chaotic_lyapunov(data)

# Ergodic
mixed = backend.ergodic_arnold(data, iterations=100)
guarantee = backend.ergodic_guarantee(data)

# Topological
births, deaths = backend.topo_persistence(data)
W1 = backend.topo_wasserstein(births1, deaths1, births2, deaths2)

# Tropical
a = backend.tropical_add(5.0, 3.0)      # = 3.0
b = backend.tropical_multiply(5.0, 3.0) # = 8.0

# P-adic
v = backend.padic_valuation(24, p=2)    # = 3
labels = backend.padic_cluster(data, threshold=0.5)

# Mirror
morphed = backend.mirror_morph(data)
stability = backend.mirror_stability(500.0, 100.0, 7.5)
```

## Производительность (Benchmark)

```
┌────────────────────────────────┬─────────────────────────────┐
│ Operation                      │ C++ Performance             │
├────────────────────────────────┼─────────────────────────────┤
│ Fractal Generate (N=10000)     │ 5.0 ms  (2M samples/sec)   │
│ Hurst Computation (N=10000)    │ 0.2 ms                      │
│ Chaotic Transform (N=5000)     │ 1.5 ms                      │
│ Ergodic Arnold (N=5000)        │ 5.1 ms                      │
│ Persistence Diagram (N=2000)   │ 0.2 ms  (460 pairs)         │
│ Mirror Morph (N=3000)          │ 83.4 ms                     │
│ P-adic Clustering (N=1000)     │ 469.6 ms                    │
└────────────────────────────────┴─────────────────────────────┘
```

**Python оркестрация + C++ ядро = максимальная скорость для real-time обработки трафика.**

## API Endpoints (Python FastAPI)

Все 9 модулей доступны через REST API:

```
POST /api/math/fractal/transform
POST /api/math/fractal/generate
GET  /api/math/fractal/hurst

POST /api/math/chaotic/transform
GET  /api/math/chaotic/lyapunov

POST /api/math/ergodic/transform
GET  /api/math/ergodic/convergence
GET  /api/math/ergodic/guarantee

POST /api/math/topological/transform
GET  /api/math/topological/diagram
GET  /api/math/topological/wasserstein

POST /api/math/tropical/transform
POST /api/math/tropical/optimize

POST /api/math/padic/transform
GET  /api/math/padic/expansion
GET  /api/math/padic/clustering

POST /api/math/cluster/transform
POST /api/math/cluster/mutate
GET  /api/math/cluster/classification

POST /api/math/mirror/transform
POST /api/math/mirror/stability

POST /api/math/anabelian/transform
POST /api/math/anabelian/reconstruct

POST /api/math/director/apply
GET  /api/math/director/strategy

POST /api/math/pipeline/create
POST /api/math/pipeline/execute
GET  /api/math/pipeline/list
```

## Интеграция с dynam-src

Модули интегрированы в основной репозиторий `dynam-src` (112 модулей).

Для использования в существующем коде:

```cpp
// В ncp_orchestrator.hpp или другом модуле
#include "ncp_math_all.hpp"

class Orchestrator {
    FractalTrafficGenerator fractal_;
    ChaoticEmbedder chaotic_;
    TopologicalMorpher topo_;
    
    void apply_math_transforms(PacketBuffer& buf) {
        std::vector<double> data(buf.begin(), buf.end());
        
        // Apply fractal structure
        auto fgn = fractal_.transform(data, 0.75);
        
        // Apply chaotic embedding
        auto embedded = chaotic_.embed(fgn.data);
        
        // Compute persistence for verification
        auto diagram = topo_.persistence_diagram(embedded.data);
        
        // Write back
        std::copy(embedded.data.begin(), embedded.data.end(), buf.begin());
    }
};
```

## Зависимости

- **C++17** (std::optional, std::variant, structured bindings)
- **STL only** (vector, cmath, algorithm, complex) — no external libs
- **Header-only** (кроме C API wrapper)

## Лицензия

Same as dynam-src project.
