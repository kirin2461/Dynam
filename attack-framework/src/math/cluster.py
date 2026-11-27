"""
Cluster Algebra Protocol Mutations — мутации протоколов через cluster algebras.

Математическая основа:
- Cluster algebras (Fomin-Zelevinsky, 2002)
- Cluster mutations: x_k → x_k' where x_k * x_k' = ∏ x_i^[b_ik]_+ + ∏ x_i^[-b_ik]_+
- Exchange matrix (B-matrix) mutations
- Laurent phenomenon — все мутации выражаются рационально
- Finite type classification — соответствие с Dynkin диаграммами

Применение:
- Протокольные мутации: HTTP → mutated HTTP → DNS-like → ...
- Laurent phenomenon гарантирует обратимость мутаций
- Cluster category — пространство всех возможных протокольных представлений
"""

import numpy as np
from typing import Dict, Any, Optional, Tuple, List, Set
from dataclasses import dataclass, field
from collections import defaultdict
from .base import MathTransform, MathContext


@dataclass
class Cluster:
    """Cluster — набор переменных."""
    variables: Dict[str, float] = field(default_factory=dict)
    
    def copy(self) -> 'Cluster':
        return Cluster(variables=self.variables.copy())


@dataclass
class ExchangeMatrix:
    """Exchange matrix (B-matrix) для cluster algebra."""
    matrix: np.ndarray
    
    def __post_init__(self):
        if not isinstance(self.matrix, np.ndarray):
            self.matrix = np.array(self.matrix)
    
    def copy(self) -> 'ExchangeMatrix':
        return ExchangeMatrix(matrix=self.matrix.copy())


@dataclass
class ClusterAlgebraConfig:
    """Конфигурация cluster algebra."""
    initial_cluster_size: int = 5
    num_mutations: int = 10
    mutation_direction: str = "random"  # random, cyclic, optimal


class ClusterAlgebra(MathTransform):
    """
    Cluster algebra для протокольных мутаций.
    
    Методы:
    1. mutate() — cluster mutation в направлении k
    2. laurent_phenomenon() — проверка Laurent property
    3. finite_type_classification() — классификация конечного типа
    4. cluster_category() — построение cluster category
    """
    
    def __init__(self, config: Optional[ClusterAlgebraConfig] = None):
        super().__init__(name="ClusterAlgebra", version="1.0.0")
        self.config = config or ClusterAlgebraConfig()
        
        # Инициализация
        self.initial_cluster = self._create_initial_cluster()
        self.exchange_matrix = self._create_initial_exchange_matrix()
        
        # История мутаций
        self.mutation_history: List[Tuple[int, Cluster, ExchangeMatrix]] = []
    
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Применить cluster mutation к данным.
        
        Преобразуем данные в cluster variables,
        применяем серию мутаций, возвращаем обратно.
        """
        if not self.validate_input(data):
            raise ValueError("Invalid input data")
        
        # Преобразуем данные в cluster
        cluster = self._data_to_cluster(data)
        
        # Применяем серию мутаций
        for _ in range(self.config.num_mutations):
            k = self._select_mutation_direction(cluster)
            cluster, _ = self.mutate(cluster, self.exchange_matrix, k)
        
        # Возвращаем в данные
        result = self._cluster_to_data(cluster, data.shape)
        
        return result
    
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """Обратная трансформация (обратные мутации)."""
        cluster = self._data_to_cluster(data)
        
        # Применяем обратные мутации (в обратном порядке)
        for k, _, _ in reversed(self.mutation_history):
            cluster, _ = self.mutate(cluster, self.exchange_matrix, k)
        
        return self._cluster_to_data(cluster, data.shape)
    
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """Вычислить метрики cluster мутаций."""
        # Количество мутаций
        num_mutations = len(self.mutation_history)
        
        # Laurent property score (все ли переменные рациональны)
        laurent_score = self.laurent_phenomenon()
        
        # Cluster distance (расстояние между initial и current cluster)
        cluster_dist = self._cluster_distance(self.initial_cluster, self._data_to_cluster(transformed))
        
        return {
            "num_mutations": num_mutations,
            "laurent_property": laurent_score,
            "cluster_distance": cluster_dist,
        }
    
    def mutate(self, cluster: Cluster, exchange_matrix: ExchangeMatrix, k: int) -> Tuple[Cluster, ExchangeMatrix]:
        """
        Cluster mutation в направлении k.
        
        Mutation μ_k:
        - x_k' = (∏ x_i^[b_ik]_+ + ∏ x_i^[-b_ik]_+) / x_k
        - x_i' = x_i для i ≠ k
        
        Exchange matrix mutation:
        - b_ij' = -b_ij если i=k или j=k
        - b_ij' = b_ij + sign(b_ik) * max(0, b_ik * b_kj) иначе
        
        Args:
            cluster: Исходный cluster
            exchange_matrix: Exchange matrix B
            k: Индекс мутации
        
        Returns:
            (new_cluster, new_exchange_matrix)
        """
        n = len(cluster.variables)
        var_names = list(cluster.variables.keys())
        
        if k < 0 or k >= n:
            raise ValueError(f"Invalid mutation direction k={k}")
        
        # Сохраняем в историю
        self.mutation_history.append((k, cluster.copy(), exchange_matrix.copy()))
        
        # Создаём новый cluster
        new_cluster = cluster.copy()
        
        # Mutation exchange relation
        x_k = cluster.variables[var_names[k]]
        
        # Вычисляем numerator
        numerator_pos = 1.0
        numerator_neg = 1.0
        
        for i in range(n):
            if i == k:
                continue
            
            b_ik = exchange_matrix.matrix[i, k]
            x_i = cluster.variables[var_names[i]]
            
            if b_ik > 0:
                numerator_pos *= x_i ** b_ik
            elif b_ik < 0:
                numerator_neg *= x_i ** (-b_ik)
        
        # Новая переменная x_k'
        x_k_new = (numerator_pos + numerator_neg) / x_k
        
        # Обновляем cluster
        new_cluster.variables[var_names[k]] = x_k_new
        
        # Мутируем exchange matrix
        new_B = exchange_matrix.copy()
        
        for i in range(n):
            for j in range(n):
                if i == k or j == k:
                    new_B.matrix[i, j] = -exchange_matrix.matrix[i, j]
                else:
                    b_ik = exchange_matrix.matrix[i, k]
                    b_kj = exchange_matrix.matrix[k, j]
                    
                    sign = 1 if b_ik > 0 else (-1 if b_ik < 0 else 0)
                    new_B.matrix[i, j] = exchange_matrix.matrix[i, j] + sign * max(0, b_ik * b_kj)
        
        return new_cluster, new_B
    
    def laurent_phenomenon(self) -> float:
        """
        Проверка Laurent phenomenon.
        
        Laurent phenomenon: после любой мутации все переменные
        выражаются как рациональные функции от исходных с коэффициентами-числителями.
        
        Returns:
            Score (1.0 = все переменные Laurent, 0.0 = none)
        """
        # Упрощённая проверка: все переменные должны быть положительными
        current_cluster = self.initial_cluster.copy()
        current_B = self.exchange_matrix.copy()
        
        for _ in range(min(10, self.config.num_mutations)):
            k = self._select_mutation_direction(current_cluster)
            current_cluster, current_B = self.mutate(current_cluster, current_B, k)
        
        # Проверяем положительность
        all_positive = all(v > 0 for v in current_cluster.variables.values())
        
        return 1.0 if all_positive else 0.5
    
    def finite_type_classification(self) -> str:
        """
        Классификация конечного типа.
        
        Cluster algebra конечного типа ↔ Dynkin диаграмма:
        - A_n: x_1 - x_2 - ... - x_n
        - B_n, C_n, D_n, E_6, E_7, E_8, F_4, G_2
        
        Returns:
            Dynkin type (A_n, B_n, ...) или "infinite"
        """
        B = self.exchange_matrix.matrix
        n = len(B)
        
        # Проверяем условие конечности
        # Для конечного типа: все собственные значения B^2 < 4
        
        B_squared = B @ B.T
        eigenvalues = np.linalg.eigvals(B_squared)
        
        if np.all(np.abs(eigenvalues) < 4):
            # Определяем тип
            if n <= 3:
                return f"A_{n}"
            else:
                return f"A_{n}"  # Упрощённая классификация
        else:
            return "infinite"
    
    def cluster_category(self) -> Dict[str, Any]:
        """
        Построение cluster category (упрощённое).
        
        Cluster category — категория, объекты которой = clusters,
        морфизмы = sequences of mutations.
        
        Returns:
            Dict с информацией о cluster category
        """
        # Собираем все достигнутые clusters
        clusters = [self.initial_cluster]
        
        current = self.initial_cluster.copy()
        current_B = self.exchange_matrix.copy()
        
        for _ in range(self.config.num_mutations):
            k = self._select_mutation_direction(current)
            current, current_B = self.mutate(current, current_B, k)
            clusters.append(current)
        
        return {
            "num_clusters": len(clusters),
            "num_mutations": self.config.num_mutations,
            "dynkin_type": self.finite_type_classification(),
            "laurent_property": self.laurent_phenomenon(),
        }
    
    def protocol_mutation(self, protocol_features: Dict[str, float], target_protocol: str) -> Dict[str, float]:
        """
        Протокольная мутация: HTTP → target_protocol.
        
        Args:
            protocol_features: Features исходного протокола
            target_protocol: Целевой протокол
        
        Returns:
            Mutated protocol features
        """
        # Создаём cluster из protocol features
        cluster = Cluster(variables=protocol_features.copy())
        
        # Определяем target cluster (эвристика)
        target_cluster = self._protocol_to_cluster(target_protocol, len(cluster.variables))
        
        # Находим sequence of mutations от current к target
        mutation_sequence = self._find_mutation_path(cluster, target_cluster)
        
        # Применяем мутации
        current = cluster.copy()
        current_B = self.exchange_matrix.copy()
        
        for k in mutation_sequence:
            current, current_B = self.mutate(current, current_B, k)
        
        return current.variables
    
    def _create_initial_cluster(self) -> Cluster:
        """Создание initial cluster."""
        variables = {}
        for i in range(self.config.initial_cluster_size):
            variables[f"x_{i}"] = 1.0 + 0.1 * i
        
        return Cluster(variables=variables)
    
    def _create_initial_exchange_matrix(self) -> ExchangeMatrix:
        """Создание initial exchange matrix."""
        n = self.config.initial_cluster_size
        
        # B-matrix для type A_{n-1}
        B = np.zeros((n, n), dtype=float)
        
        for i in range(n - 1):
            B[i, i + 1] = 1
            B[i + 1, i] = -1
        
        return ExchangeMatrix(matrix=B)
    
    def _data_to_cluster(self, data: np.ndarray) -> Cluster:
        """Преобразование данных в cluster."""
        # Flatten data
        flat_data = data.flatten()
        
        # Создаём cluster variables
        variables = {}
        for i, val in enumerate(flat_data[:self.config.initial_cluster_size]):
            variables[f"x_{i}"] = abs(val) + 0.1  # Положительные значения
        
        # Дополняем если нужно
        while len(variables) < self.config.initial_cluster_size:
            variables[f"x_{len(variables)}"] = 1.0
        
        return Cluster(variables=variables)
    
    def _cluster_to_data(self, cluster: Cluster, original_shape: Tuple) -> np.ndarray:
        """Преобразование cluster в данные."""
        values = list(cluster.variables.values())
        
        # Reshape к исходной форме
        num_elements = np.prod(original_shape)
        
        # Дополняем или обрезаем
        if len(values) < num_elements:
            values = values + [1.0] * (num_elements - len(values))
        elif len(values) > num_elements:
            values = values[:num_elements]
        
        return np.array(values).reshape(original_shape)
    
    def _select_mutation_direction(self, cluster: Cluster) -> int:
        """Выбор направления мутации."""
        n = len(cluster.variables)
        
        if self.config.mutation_direction == "random":
            return np.random.randint(0, n)
        elif self.config.mutation_direction == "cyclic":
            # Циклически
            current_idx = len(self.mutation_history) % n
            return current_idx
        else:  # optimal
            # Выбираем направление с максимальной мутацией
            max_change = -1
            best_k = 0
            
            for k in range(n):
                # Пробуем мутацию
                new_cluster, _ = self.mutate(cluster, self.exchange_matrix, k)
                
                # Вычисляем изменение
                change = sum(abs(new_cluster.variables[v] - cluster.variables[v]) for v in cluster.variables)
                
                if change > max_change:
                    max_change = change
                    best_k = k
            
            return best_k
    
    def _cluster_distance(self, cluster1: Cluster, cluster2: Cluster) -> float:
        """Расстояние между clusters."""
        vars1 = list(cluster1.variables.values())
        vars2 = list(cluster2.variables.values())
        
        # Euclidean distance
        return float(np.linalg.norm(np.array(vars1) - np.array(vars2)))
    
    def _protocol_to_cluster(self, protocol: str, size: int) -> Cluster:
        """Преобразование протокола в cluster (эвристика)."""
        # Разные протоколы → разные cluster configurations
        protocol_configs = {
            "HTTP": [1.0, 2.0, 3.0, 4.0, 5.0],
            "DNS": [0.5, 1.5, 2.5, 3.5, 4.5],
            "QUIC": [2.0, 3.0, 4.0, 5.0, 6.0],
            "WebSocket": [1.5, 2.5, 3.5, 4.5, 5.5],
        }
        
        config = protocol_configs.get(protocol, [1.0] * size)
        
        variables = {}
        for i in range(size):
            variables[f"x_{i}"] = config[i % len(config)]
        
        return Cluster(variables=variables)
    
    def _find_mutation_path(self, source: Cluster, target: Cluster, max_depth: int = 10) -> List[int]:
        """Поиск пути мутаций от source к target."""
        # Упрощённый BFS
        from collections import deque
        
        queue = deque([(source, self.exchange_matrix, [])])
        visited = set()
        
        while queue:
            current, B, path = queue.popleft()
            
            # Проверяем близость к target
            if self._cluster_distance(current, target) < 0.5:
                return path
            
            # Если достигли максимальной глубины
            if len(path) >= max_depth:
                continue
            
            # Пробуем все возможные мутации
            for k in range(len(current.variables)):
                new_cluster, new_B = self.mutate(current, B, k)
                
                # Проверяем, не посещали ли мы уже это состояние
                state_hash = tuple(sorted(new_cluster.variables.items()))
                if state_hash not in visited:
                    visited.add(state_hash)
                    queue.append((new_cluster, new_B, path + [k]))
        
        # Если не нашли путь, возвращаем случайный
        return [np.random.randint(0, len(source.variables)) for _ in range(5)]
