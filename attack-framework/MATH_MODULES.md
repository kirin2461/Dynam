# Математические модули Attack Framework

## Обзор

Реализовано **9 математических модулей** для обхода DPI через продвинутую математику:

| # | Модуль | Класс | Назначение |
|---|--------|-------|------------|
| 1 | `fractal.py` | `FractalTrafficGenerator` | Генерация самоподобного трафика (fGn) |
| 2 | `chaotic.py` | `ChaoticEmbedder` | Скрытие данных в хаотических аттракторах |
| 3 | `ergodic.py` | `ErgodicShaper` | Эргодическое перемешивание трафика |
| 4 | `topological.py` | `TopologicalMorpher` | Топологический морфинг через persistent homology |
| 5 | `tropical.py` | `TropicalGeometry` | Тропическая геометрия для оптимизации |
| 6 | `padic.py` | `PadicAnalysis` | P-адический анализ для кластеризации |
| 7 | `cluster.py` | `ClusterAlgebra` | Cluster mutations для протокольных мутаций |
| 8 | `mirror.py` | `MirrorSymmetry` | Mirror symmetry для wall-crossing |
| 9 | `anabelian.py` | `AnabelianReconstruction` | Anabelian geometry для топологии сети |

---

## Модуль 1: Fractal Traffic Generator

### Описание
Генерирует самоподобный трафик с заданным Hurst exponent через Davies-Harte метод (circulant embedding).

### Ключевые функции
- `compute_hurst(data)` - вычисление Hurst exponent (R/S analysis)
- `generate_fgn(length, hurst)` - генерация fractional Gaussian noise
- `match_distribution(target_hurst, length)` - подгонка трафика под целевой Hurst
- `multifractal_spectrum(data, q_range)` - MF-DFA анализ

### Пример использования
```python
from src.math.fractal import FractalTrafficGenerator, FractalConfig

# Конфигурация
config = FractalConfig(
    target_hurst=0.75,  # self-similar
    embedding_dim=10,
    time_delay=1
)

# Создание генератора
generator = FractalTrafficGenerator(config)

# Генерация трафика
data = np.random.randn(1000)
result = generator.match_distribution(target_hurst=0.75, length=1000)

print(f"Generated {len(result['generated_data'])} samples")
print(f"Actual Hurst: {result['actual_hurst']:.3f}")
print(f"Multifractal width: {result['multifractal_width']:.3f}")
```

### API Endpoints
```
POST /api/math/fractal/transform
POST /api/math/fractal/generate
GET  /api/math/fractal/hurst
```

---

## Модуль 2: Chaotic Embedder

### Описание
Скрывает данные в хаотических аттракторах через CSS modulation. Использует Lorenz system для генерации хаотической последовательности.

### Ключевые функции
- `lorenz_step(state, dt)` - шаг системы Лоренца (σ=10, ρ=28, β=8/3)
- `css_modulate(signal, chaotic)` - CSS modulation
- `takens_embedding(data)` - embedding через time-delay
- `lyapunov_exponents(data)` - вычисление показателей Ляпунова

### Пример использования
```python
from src.math.chaotic import ChaoticEmbedder, ChaoticConfig

config = ChaoticConfig(
    sigma=10.0, rho=28.0, beta=8/3,
    embedding_dim=3, time_delay=1,
    epsilon=0.01
)

embedder = ChaoticEmbedder(config)

# Встраивание данных
data = np.array([1, 2, 3, 4, 5], dtype=np.uint8)
context = MathContext(target="api")

embedded = embedder.transform(data, context)
metrics = embedder.compute_metrics(data, embedded)

print(f"Stealth score: {metrics['stealth_score']:.3f}")
print(f"Embedding capacity: {metrics['embedding_capacity']:.3f}")
```

### API Endpoints
```
POST /api/math/chaotic/transform
POST /api/math/chaotic/embed
GET  /api/math/chaotic/lyapunov
```

---

## Модуль 3: Ergodic Shaper

### Описание
Применяет эргодические преобразования (Arnold cat map, Baker map) для перемешивания трафика с гарантией равномерного распределения.

### Ключевые функции
- `arnold_cat_map(x, y, iterations)` - Arnold cat map [2 1; 1 1] mod 1
- `baker_map(x, y, iterations)` - Baker map
- `birkhoff_convergence(data)` - оценка сходимости (Birkhoff ergodic theorem)
- `ergodic_guarantee(data)` - stealth guarantee на основе mixing time

### Пример использования
```python
from src.math.ergodic import ErgodicShaper, ErgodicConfig

config = ErgodicConfig(
    map_type="arnold",
    iterations=100,
    target_distribution="uniform"
)

shaper = ErgodicShaper(config)

# Эргодическое перемешивание
data = np.random.randn(100)
context = MathContext(target="api")

shaped = shaper.transform(data, context)
metrics = shaper.compute_metrics(data, shaped)

convergence = shaper.birkhoff_convergence(shaped)
guarantee = shaper.ergodic_guarantee(shaped)

print(f"Convergence: {convergence:.3f}")
print(f"Stealth guarantee: {guarantee:.3f}")
```

### API Endpoints
```
POST /api/math/ergodic/transform
GET  /api/math/ergodic/convergence
GET  /api/math/ergodic/guarantee
```

---

## Модуль 4: Topological Morpher

### Описание
Применяет persistent homology (Vietoris-Rips filtration) для топологического анализа и морфинга трафика. Вычисляет Wasserstein distance между persistence diagrams.

### Ключевые функции
- `vietoris_rips_complex(points, max_dim, max_radius)` - построение VR complex
- `persistence_diagram(data)` - вычисление persistence diagram
- `wasserstein_distance(diag1, diag2)` - Wasserstein-1 distance (Hungarian algorithm)
- `homotopy_morph(data1, data2, steps)` - гомотопический морфинг

### Пример использования
```python
from src.math.topological import TopologicalMorpher, TopologicalConfig

config = TopologicalConfig(
    max_homology_dim=1,
    max_filtration_radius=2.0,
    num_homotopy_steps=10
)

morpher = TopologicalMorpher(config)

# Topological morphing
data = np.random.randn(50)
context = MathContext(target="api")

morphed = morpher.transform(data, context)
metrics = morpher.compute_metrics(data, morphed)

# Persistence diagram
diagram = morpher.persistence_diagram(morphed)
print(f"Persistence pairs: {len(diagram)}")

# Wasserstein distance
diagram1 = morpher.persistence_diagram(data)
diagram2 = morpher.persistence_diagram(morphed)
distance = morpher.wasserstein_distance(diagram1, diagram2)
print(f"Wasserstein distance: {distance:.3f}")
```

### API Endpoints
```
POST /api/math/topological/transform
GET  /api/math/topological/diagram
GET  /api/math/topological/wasserstein
```

---

## Модуль 5: Tropical Geometry

### Описание
Применяет тропическую геометрию (min-plus semiring) для оптимизации. Используется для piecewise-linear аппроксимации и тропического линейного программирования.

### Ключевые функции
- `tropical_add(x, y)` - tropical addition (min)
- `tropical_multiply(x, y)` - tropical multiplication (+)
- `tropical_polynomial(coefficients, exponents, x)` - evaluation
- `tropical_linear_program(c, A, b)` - решение тропической LP

### Пример использования
```python
from src.math.tropical import TropicalGeometry, TropicalConfig

config = TropicalConfig()

geometry = TropicalGeometry(config)

# Тропическая арифметика
result_add = geometry.tropical_add(5.0, 3.0)  # = min(5, 3) = 3.0
result_mul = geometry.tropical_multiply(5.0, 3.0)  # = 5 + 3 = 8.0

# Тропический полином
coefficients = np.array([1.0, 2.0, 3.0])
exponents = np.array([0, 1, 2])
x = 2.0
value = geometry.tropical_polynomial(coefficients, exponents, x)

# Тропическое LP
c = np.array([1.0, 2.0])
A = np.array([[1.0, 0.0], [0.0, 1.0]])
b = np.array([3.0, 4.0])
result = geometry.tropical_linear_program(c, A, b)
print(f"Optimal value: {result['optimal_value']:.3f}")
print(f"Optimal point: {result['optimal_point']}")
```

### API Endpoints
```
POST /api/math/tropical/transform
POST /api/math/tropical/optimize
```

---

## Модуль 6: P-adic Analysis

### Описание
Применяет p-адический анализ для ультраметрической кластеризации и мульти-шкального анализа. Используется для топологического анализа сетевой структуры.

### Ключевые функции
- `padic_expansion(x, p, num_terms)` - p-адическое разложение
- `padic_distance(x, y, p)` - p-адическое расстояние
- `padic_fourier(data, p)` - p-адическое преобразование Фурье
- `ultrametric_clustering(data, threshold)` - ультраметрическая кластеризация

### Пример использования
```python
from src.math.padic import PadicAnalysis, PadicConfig

config = PadicConfig(prime=2, num_terms=10)

analysis = PadicAnalysis(config)

# P-адическое разложение
expansion = analysis.padic_expansion(37, p=2)
print(f"37 in 2-adic: {expansion}")  # 1 + 0*2 + 0*4 + 0*8 + 1*16 + 1*32

# P-адическое расстояние
distance = analysis.padic_distance(37, 10, p=2)
print(f"2-adic distance: {distance:.3f}")

# Ультраметрическая кластеризация
data = np.random.randn(20)
clusters = analysis.ultrametric_clustering(data, threshold=0.5)
print(f"Number of clusters: {clusters['num_clusters']}")
```

### API Endpoints
```
POST /api/math/padic/transform
GET  /api/math/padic/expansion
GET  /api/math/padic/clustering
```

---

## Модуль 7: Cluster Algebra

### Описание
Применяет cluster algebra (Fomin-Zelevinsky mutations) для протокольных мутаций. Используется для перехода между протоколами через sequence of mutations.

### Ключевые функции
- `mutation(k, x_vars, exchange_matrix)` - cluster mutation в направлении k
- `protocol_mutation(protocol_features, target_protocol)` - мутация протокола
- `finite_type_classification()` - классификация конечного типа (Dynkin)

### Пример использования
```python
from src.math.cluster import ClusterAlgebra, ClusterAlgebraConfig

config = ClusterAlgebraConfig(
    initial_rank=3,
    mutation_sequence=["H", "D", "Q"]
)

algebra = ClusterAlgebra(config)

# Cluster mutation
k = 0
x_vars = np.array([1.0, 2.0, 3.0])
B = np.array([
    [0, 1, -1],
    [-1, 0, 1],
    [1, -1, 0]
], dtype=np.int32)

new_x, new_B = algebra.mutation(k, x_vars, B)
print(f"New cluster variables: {new_x}")
print(f"New exchange matrix:\n{new_B}")

# Protocol mutation
http_features = {
    "header_size": 200,
    "payload_ratio": 0.8,
    "encryption": 0.0
}
dns_features = algebra.protocol_mutation(http_features, "DNS")
print(f"DNS features: {dns_features}")
```

### API Endpoints
```
POST /api/math/cluster/transform
POST /api/math/cluster/mutate
GET  /api/math/cluster/classification
```

---

## Модуль 8: Mirror Symmetry

### Описание
Применяет mirror symmetry (Kontsevich-Soibelman) для wall-crossing analysis. Используется для перехода между stability conditions в derived category.

### Ключевые функции
- `wall_crossing(parameters, central_charge)` - проверка пересечения стены
- `cross_wall(data, target_stability)` - переход через стену
- `traffic_stability(features)` - анализ stability трафика

### Пример использования
```python
from src.math.mirror import MirrorSymmetry, MirrorConfig, StabilityCondition

config = MirrorConfig(
    mirror_dim=3,
    central_charge_fn="linear"
)

mirror = MirrorSymmetry(config)

# Traffic stability analysis
features = {
    "packet_size": 500,
    "arrival_rate": 100,
    "entropy": 7.5
}
stability = mirror.traffic_stability(features)
print(f"Stability: {stability['stability']}")
print(f"Phase: {stability['phase']:.3f}")

# Wall crossing
data = np.random.randn(10)
target = StabilityCondition.STABLE
crossed = mirror.cross_wall(data, target)
print(f"Crossed wall: {len(crossed)} times")
```

### API Endpoints
```
POST /api/math/mirror/transform
POST /api/math/mirror/wall_crossing
POST /api/math/mirror/stability
```

---

## Модуль 9: Anabelian Reconstruction

### Описание
Применяет anabelian geometry (Grothendieck) для реконструкции топологии сети из этального фундаментального группы π₁^ét. Используется для topology-aware routing.

### Ключевые функции
- `etale_fundamental_group(data)` - вычисление π₁^ét
- `reconstruct_topology(traffic_samples)` - реконструкция топологии
- `topology_stealth(data)` - analysis topology-based stealth

### Пример использования
```python
from src.math.anabelian import AnabelianReconstruction, AnabelianConfig

config = AnabelianConfig(
    base_prime=2,
    max_genus=5
)

anabelian = AnabelianReconstruction(config)

# Reconstruction from traffic
samples = [
    np.random.randn(50),
    np.random.randn(50),
    np.random.randn(50)
]
topology = anabelian.reconstruct_from_traffic(samples)

print(f"Nodes: {len(topology.nodes)}")
print(f"Edges: {len(topology.edges)}")
print(f"Betti numbers: {topology.betti_numbers}")
print(f"Genus: {topology.genus}")

# Topology stealth
data = np.random.randn(100)
stealth = anabelian.topology_stealth(data)
print(f"Stealth score: {stealth['stealth_score']:.3f}")
print(f"Topological complexity: {stealth['topological_complexity']:.3f}")
```

### API Endpoints
```
POST /api/math/anabelian/transform
POST /api/math/anabelian/reconstruct
POST /api/math/anabelian/stealth
```

---

## Интеграция с API

Все 9 модулей интегрированы в FastAPI через `register_math_routes(app)`:

```python
from fastapi import FastAPI
from src.api.math_routes import register_math_routes

app = FastAPI(title="Attack Framework Math API")
register_math_routes(app)
```

---

## Зависимости

```txt
numpy>=1.24.0
scipy>=1.11.0
giotto-tda>=0.6.0        # Persistent homology
POT>=0.9.0               # Optimal transport (Wasserstein)
scikit-learn>=1.3.0      # Clustering, metrics
```

---

## Архитектура

```
src/math/
├── base.py                    # MathTransform ABC, MathContext
├── fractal.py                 # FractalTrafficGenerator
├── chaotic.py                 # ChaoticEmbedder
├── ergodic.py                 # ErgodicShaper
├── topological.py             # TopologicalMorpher
├── tropical.py                # TropicalGeometry
├── padic.py                   # PadicAnalysis
├── cluster.py                 # ClusterAlgebra
├── mirror.py                  # MirrorSymmetry
├── anabelian.py               # AnabelianReconstruction
├── orchestration/
│   ├── __init__.py
│   ├── math_director.py       # MathDirector (orchestration)
│   └── pipeline.py            # Pipeline management
└── __init__.py                # Экспорты
```

---

## Статус

✅ **Все 9 модулей полностью реализованы**

- Полностью функциональный код (не заглушки)
- Интегрированы в FastAPI
- Документация с примерами
- Готовы к использованию в distributed модулях
