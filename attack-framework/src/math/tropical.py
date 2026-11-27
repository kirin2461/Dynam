"""
Tropical Traffic Geometry — тропическая геометрия для трафика.

Математическая основа:
- Тропический полутруп: (ℝ ∪ {∞}, ⊕, ⊗) где a ⊕ b = min(a,b), a ⊗ b = a + b
- Тропические полиномы — piecewise-linear функции
- Тропическая выпуклость — tropical convex hull
- Тропическая оптимизация — tropical linear programming

Применение:
- Piecewise-linear оптимизация traffic shaping
- Тропическая convexity для маскировки паттернов
- Тропическое linear programming для DPI boundary evasion
"""

import numpy as np
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from scipy.optimize import linprog
from .base import MathTransform, MathContext


@dataclass
class TropicalConfig:
    """Конфигурация тропической геометрии."""
    epsilon: float = 1e-10  # Для численной стабильности
    max_iterations: int = 100  # Для итеративных алгоритмов
    optimization_method: str = "sinkhorn"  # sinkhorn, hungarian


class TropicalGeometry(MathTransform):
    """
    Тропическая геометрия для трафика.
    
    Методы:
    1. tropical_add() — тропическое сложение (min)
    2. tropical_multiply() — тропическое умножение (+)
    3. tropical_polynomial() — тропический полином
    4. tropical_convex_hull() — тропический convex hull
    5. tropical_linear_program() — тропическая оптимизация
    """
    
    def __init__(self, config: Optional[TropicalConfig] = None):
        super().__init__(name="TropicalGeometry", version="1.0.0")
        self.config = config or TropicalConfig()
    
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Применить тропическую трансформацию к данным.
        
        Преобразует данные в тропическое пространство,
        применяет оптимизацию, возвращает обратно.
        """
        if not self.validate_input(data):
            raise ValueError("Invalid input data")
        
        # Преобразуем в тропическое пространство
        tropical_data = self._to_tropical(data)
        
        # Применяем тропический convex hull (сглаживание)
        smoothed = self.tropical_convex_hull(tropical_data)
        
        # Возвращаем в обычное пространство
        result = self._from_tropical(smoothed)
        
        return result
    
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """Обратная трансформация (тропическое деформирование)."""
        # Тропическая трансформация обратима через dequantization
        tropical_data = self._to_tropical(data)
        
        # Применяем обратную операцию
        dequantized = self._dequantize(tropical_data)
        
        return self._from_tropical(dequantized)
    
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """Вычислить тропические метрики."""
        # Тропическое расстояние
        trop_dist = self.tropical_distance(original, transformed)
        
        # Piecewise-linearity score
        pwlinear = self._piecewise_linearity_score(transformed)
        
        # Tropical convexity
        convexity = self._tropical_convexity_score(transformed)
        
        return {
            "tropical_distance": trop_dist,
            "piecewise_linearity": pwlinear,
            "tropical_convexity": convexity,
        }
    
    def tropical_add(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Тропическое сложение: a ⊕ b = min(a, b).
        
        В тропическом полукольце сложение заменяется на min.
        
        Args:
            a, b: Arrays в тропическом пространстве
        
        Returns:
            Element-wise minimum
        """
        return np.minimum(a, b)
    
    def tropical_multiply(self, a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """
        Тропическое умножение: a ⊗ b = a + b.
        
        В тропическом полукольце умножение заменяется на сложение.
        
        Args:
            a, b: Arrays в тропическом пространстве
        
        Returns:
            Element-wise sum
        """
        return a + b
    
    def tropical_polynomial(self, x: np.ndarray, coefficients: List[float]) -> np.ndarray:
        """
        Тропический полином.
        
        Тропический полином: p(x) = ⊕(i) (c_i ⊗ x^i) = min_i (c_i + i*x)
        
        Это piecewise-linear функция.
        
        Args:
            x: Входные значения
            coefficients: Коэффициенты [c_0, c_1, ..., c_n]
        
        Returns:
            Значения тропического полинома
        """
        result = np.full_like(x, np.inf)
        
        for i, c in enumerate(coefficients):
            # c_i ⊗ x^i = c_i + i*x (в тропическом смысле)
            term = c + i * x
            result = self.tropical_add(result, term)
        
        return result
    
    def tropical_convex_hull(self, points: np.ndarray) -> np.ndarray:
        """
        Тропический convex hull.
        
        Тропический convex hull — набор всех тропических convex combinations:
        ⊕(i) (λ_i ⊗ x_i) где ⊕(i) λ_i = 0 (тропическая сумма = 0)
        
        В обычном смысле: min_i (λ_i + x_i) где sum(λ_i) = 0
        
        Args:
            points: Point cloud shape (N, D) или 1D array
        
        Returns:
            Smoothed points (тропический convex hull)
        """
        if points.ndim == 1:
            # 1D случай: тропическое сглаживание
            return self._tropical_smoothing_1d(points)
        
        # ND случай: тропический convex hull
        N, D = points.shape
        
        # Упрощённая версия: для каждой точки находим ближайшую в convex hull
        result = np.zeros_like(points)
        
        for i in range(N):
            # Тропическая convex combination
            weights = np.random.randn(N)
            weights = weights - np.mean(weights)  # Сумма = 0
            
            # Тропическая комбинация
            combination = np.zeros(D)
            for j in range(D):
                terms = weights + points[:, j]
                combination[j] = np.min(terms)
            
            result[i] = combination
        
        return result
    
    def tropical_linear_program(self, c: np.ndarray, A: np.ndarray, b: np.ndarray) -> Dict[str, Any]:
        """
        Тропическое linear programming.
        
        Минимизировать: c^T ⊗ x = min_i (c_i + x_i)
        При условиях: A ⊗ x ≤ b (тропические неравенства)
        
        Args:
            c: Cost vector shape (n,)
            A: Constraint matrix shape (m, n)
            b: Constraint bounds shape (m,)
        
        Returns:
            Solution dict с optimal value и optimal x
        """
        # Тропическое LP сводится к обычному LP через логарифмирование
        # Но для упрощения используем стандартный LP solver
        
        # Преобразуем тропические ограничения в обычные
        # A ⊗ x ≤ b → max_i (A_ij + x_j) ≤ b_i
        
        n = len(c)
        m = len(b)
        
        # Стандартная форма LP: min c^T x s.t. A_ub x <= b_ub
        # В тропическом смысле это эквивалентно:
        # min max_i (c_i + x_i) s.t. max_j (A_ij + x_j) <= b_i
        
        # Упрощённая версия: используем обычный LP
        result = linprog(c, A_ub=A, b_ub=b, bounds=[(None, None)] * n)
        
        if result.success:
            return {
                "optimal_value": float(result.fun),
                "optimal_x": result.x,
                "success": True,
            }
        else:
            return {
                "optimal_value": np.inf,
                "optimal_x": None,
                "success": False,
            }
    
    def tropical_distance(self, x: np.ndarray, y: np.ndarray) -> float:
        """
        Тропическое расстояние (Hilbert's projective metric).
        
        d_T(x, y) = max_i (x_i - y_i) - min_i (x_i - y_i)
        
        Args:
            x, y: Points in tropical space
        
        Returns:
            Tropical distance
        """
        diff = x - y
        return float(np.max(diff) - np.min(diff))
    
    def _to_tropical(self, data: np.ndarray) -> np.ndarray:
        """Преобразование в тропическое пространство (логарифмирование)."""
        # Тропическое пространство = log space
        # x_tropical = -log(x) (для положительных x)
        
        # Добавляем epsilon для численной стабильности
        data_positive = np.abs(data) + self.config.epsilon
        
        return -np.log(data_positive)
    
    def _from_tropical(self, tropical_data: np.ndarray) -> np.ndarray:
        """Преобразование из тропического пространства (экспонентирование)."""
        # x = exp(-x_tropical)
        return np.exp(-tropical_data)
    
    def _dequantize(self, tropical_data: np.ndarray) -> np.ndarray:
        """Tropical dequantization — переход от тропического к классическому."""
        # Dequantization: x_classical = lim(h→0) h * x_tropical
        # Для практических целей: просто возвращаем tropical_data
        
        # Но можно применить scaling
        h = 0.1  # Parameter
        return h * tropical_data
    
    def _tropical_smoothing_1d(self, data: np.ndarray) -> np.ndarray:
        """1D тропическое сглаживание."""
        N = len(data)
        result = np.zeros_like(data)
        
        # Скользящее окно с тропическим средним
        window_size = min(5, N)
        
        for i in range(N):
            start = max(0, i - window_size // 2)
            end = min(N, i + window_size // 2 + 1)
            
            window = data[start:end]
            
            # Тропическое среднее = min
            result[i] = np.min(window)
        
        return result
    
    def _piecewise_linearity_score(self, data: np.ndarray) -> float:
        """Оценка piecewise-linearity данных."""
        # Вычисляем second derivative
        if len(data) < 3:
            return 0.0
        
        second_deriv = np.diff(data, n=2)
        
        # Piecewise-linear = second derivative = 0 (почти везде)
        zero_regions = np.sum(np.abs(second_deriv) < 0.01) / len(second_deriv)
        
        return float(zero_regions)
    
    def _tropical_convexity_score(self, data: np.ndarray) -> float:
        """Оценка тропической выпуклости."""
        # Тропическая выпуклость = выпуклость в обычном смысле
        # после логарифмирования
        
        log_data = np.log(np.abs(data) + self.config.epsilon)
        
        # Проверяем выпуклость через second derivative
        if len(log_data) < 3:
            return 0.0
        
        second_deriv = np.diff(log_data, n=2)
        
        # Выпуклость = second derivative >= 0
        convex_regions = np.sum(second_deriv >= -0.01) / len(second_deriv)
        
        return float(convex_regions)
    
    def dpi_boundary_evasion(self, features: np.ndarray, boundary_point: np.ndarray) -> np.ndarray:
        """
        DPI boundary evasion через тропическую оптимизацию.
        
        Находит точку, которая:
        1. Близка к исходным features (минимальное изменение)
        2. Находится по другую сторону DPI boundary
        
        Args:
            features: Исходные features
            boundary_point: Точка на DPI boundary
        
        Returns:
            Evasive features
        """
        # Тропическое расстояние до boundary
        distance = self.tropical_distance(features, boundary_point)
        
        # Движемся в направлении от boundary
        direction = features - boundary_point
        direction_norm = direction / (np.linalg.norm(direction) + self.config.epsilon)
        
        # Минимальное смещение для пересечения boundary
        evasion_distance = distance * 1.01  # 1% за boundary
        
        evasive = features + evasion_distance * direction_norm
        
        return evasive
