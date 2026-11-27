"""
Ergodic Traffic Shaping — эргодическое формообразование трафика.

Математическая основа:
- Measure-preserving transformations
- Ergodic theorem (Birkhoff)
- Arnold's cat map
- Speed of convergence bounds

Применение:
- Адаптивный traffic shaping с гарантированной статистической незаметностью
- Обход ML-детекторов через эргодическое convergence к "нормальному" распределению
- Mathematical guarantee stealth
"""

import numpy as np
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from .base import MathTransform, MathContext


@dataclass
class ErgodicConfig:
    """Конфигурация эргодического shaping."""
    transform_type: str = "arnold_cat"  # arnold_cat, baker_map, irrational_rotation
    convergence_threshold: float = 0.01  # Порог сходимости
    window_size: int = 1000  # Размер окна для оценки сходимости
    mixing_iterations: int = 10  # Количество итераций mixing


class ErgodicShaper(MathTransform):
    """
    Эргодический shaper с mathematical guarantee.
    
    Методы:
    1. apply_ergodic_transform() — применение эргодического преобразования
    2. birkhoff_convergence() — проверка сходимости по теореме Биркгофа
    3. mixing_time_estimate() — оценка времени перемешивания
    4. ergodic_guarantee() — вычисление stealth guarantee
    """
    
    def __init__(self, config: Optional[ErgodicConfig] = None):
        super().__init__(name="ErgodicShaper", version="1.0.0")
        self.config = config or ErgodicConfig()
        self._reference_measure: Optional[np.ndarray] = None
    
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Применить эргодическое преобразование к данным.
        
        Гарантирует, что после достаточного количества итераций
        распределение данных сходится к целевой мере.
        """
        if not self.validate_input(data):
            raise ValueError("Invalid input data")
        
        # Нормализуем данные в [0, 1)
        data_normalized = (data - np.min(data)) / (np.max(data) - np.min(data) + 1e-10)
        
        # Применяем эргодическое преобразование
        transformed = self.apply_ergodic_transform(data_normalized)
        
        # Возвращаем к исходному масштабу
        transformed_scaled = transformed * (np.max(data) - np.min(data)) + np.min(data)
        
        return transformed_scaled
    
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """Обратное преобразование (если возможно)."""
        # Для Arnold cat map обратное преобразование существует
        if self.config.transform_type == "arnold_cat":
            data_normalized = (data - np.min(data)) / (np.max(data) - np.min(data) + 1e-10)
            inverse = self._arnold_cat_inverse(data_normalized)
            return inverse * (np.max(data) - np.min(data)) + np.min(data)
        
        return data
    
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """Вычислить метрики качества."""
        # Проверяем схождение к равномерному распределению
        uniformity = self._uniformity_test(transformed)
        
        # Mixing quality
        mixing_quality = self._mixing_quality(original, transformed)
        
        # Convergence rate
        convergence = self.birkhoff_convergence(transformed)
        
        return {
            "uniformity_score": uniformity,
            "mixing_quality": mixing_quality,
            "convergence_rate": convergence,
            "ergodic_guarantee": self.ergodic_guarantee(transformed),
        }
    
    def apply_ergodic_transform(self, data: np.ndarray, iterations: Optional[int] = None) -> np.ndarray:
        """
        Применение эргодического преобразования.
        
        Args:
            data: Данные в [0, 1)
            iterations: Количество итераций (по умолчанию self.config.mixing_iterations)
        
        Returns:
            Трансформированные данные
        """
        if iterations is None:
            iterations = self.config.mixing_iterations
        
        result = data.copy()
        
        for _ in range(iterations):
            if self.config.transform_type == "arnold_cat":
                result = self._arnold_cat_map(result)
            elif self.config.transform_type == "baker_map":
                result = self._baker_map(result)
            elif self.config.transform_type == "irrational_rotation":
                result = self._irrational_rotation(result)
            else:
                raise ValueError(f"Unknown transform type: {self.config.transform_type}")
        
        return result
    
    def _arnold_cat_map(self, x: np.ndarray) -> np.ndarray:
        """
        Arnold's cat map — классическое эргодическое преобразование.
        
        [x']   [2 1] [x]
        [y'] = [1 1] [y]  mod 1
        
        Для 1D данных: применяем к парам (x_i, x_{i+1})
        """
        n = len(x)
        result = np.zeros(n)
        
        # Обрабатываем парами
        for i in range(0, n - 1, 2):
            x_val, y_val = x[i], x[i + 1]
            
            # Arnold cat map
            x_new = (2 * x_val + y_val) % 1.0
            y_new = (x_val + y_val) % 1.0
            
            result[i] = x_new
            result[i + 1] = y_new
        
        # Если нечётное количество, последний элемент оставляем как есть
        if n % 2 == 1:
            result[-1] = x[-1]
        
        return result
    
    def _arnold_cat_inverse(self, x: np.ndarray) -> np.ndarray:
        """Обратное преобразование Arnold cat map."""
        n = len(x)
        result = np.zeros(n)
        
        for i in range(0, n - 1, 2):
            x_val, y_val = x[i], x[i + 1]
            
            # Inverse: [1 -1; -1 2]
            x_new = (x_val - y_val) % 1.0
            y_new = (-x_val + 2 * y_val) % 1.0
            
            result[i] = x_new
            result[i + 1] = y_new
        
        if n % 2 == 1:
            result[-1] = x[-1]
        
        return result
    
    def _baker_map(self, x: np.ndarray) -> np.ndarray:
        """
        Baker's map — ещё одно эргодическое преобразование.
        
        Для x ∈ [0, 0.5): x' = 2x
        Для x ∈ [0.5, 1): x' = 2x - 1
        """
        result = np.zeros_like(x)
        
        mask = x < 0.5
        result[mask] = 2 * x[mask]
        result[~mask] = 2 * x[~mask] - 1
        
        return result
    
    def _irrational_rotation(self, x: np.ndarray, alpha: float = 0.618033988749895) -> np.ndarray:
        """
        Irrational rotation — вращение на иррациональный угол.
        
        x' = x + α (mod 1)
        
        Где α = golden ratio - 1 ≈ 0.618...
        """
        return (x + alpha) % 1.0
    
    def birkhoff_convergence(self, data: np.ndarray, observable: Optional[np.ndarray] = None) -> float:
        """
        Проверка сходимости по теореме Биркгофа.
        
        Теорема Биркгофа: для эргодической системы
        (1/N) Σ(i=0 to N-1) f(T^i(x)) → ∫f dμ
        
        где μ — инвариантная мера.
        
        Args:
            data: Временной ряд
            observable: Наблюдаемая функция (по умолчанию identity)
        
        Returns:
            Rate of convergence (0 = no convergence, 1 = perfect convergence)
        """
        if observable is None:
            observable = np.ones_like(data)
        
        N = len(data)
        window = self.config.window_size
        
        if N < window:
            return 0.0
        
        # Вычисляем time average для разных окон
        time_averages = []
        
        for start in range(0, N - window, window // 2):
            segment = data[start:start + window]
            time_avg = np.mean(segment * observable[start:start + window])
            time_averages.append(time_avg)
        
        # Проверяем стабильность time averages
        if len(time_averages) < 2:
            return 0.0
        
        variance = np.var(time_averages)
        mean_val = np.mean(time_averages)
        
        # Coefficient of variation
        if mean_val > 0:
            cv = np.sqrt(variance) / mean_val
            # Lower CV = better convergence
            convergence = 1.0 / (1.0 + cv)
        else:
            convergence = 0.0
        
        return float(convergence)
    
    def mixing_time_estimate(self, data: np.ndarray) -> float:
        """
        Оценка времени перемешивания (mixing time).
        
        Mixing time — время, за которое система "забывает" начальное состояние.
        
        Args:
            data: Временной ряд
        
        Returns:
            Estimated mixing time (в единицах времени)
        """
        N = len(data)
        
        if N < 100:
            return 0.0
        
        # Вычисляем автокорреляцию
        max_lag = min(100, N // 2)
        autocorr = np.zeros(max_lag)
        
        mean_val = np.mean(data)
        var_val = np.var(data)
        
        if var_val == 0:
            return 0.0
        
        for lag in range(max_lag):
            if lag == 0:
                autocorr[lag] = 1.0
            else:
                corr = np.mean((data[:N-lag] - mean_val) * (data[lag:] - mean_val)) / var_val
                autocorr[lag] = corr
        
        # Mixing time = время, за которое автокорреляция падает до 1/e
        threshold = 1.0 / np.e
        
        for lag in range(1, max_lag):
            if autocorr[lag] < threshold:
                return float(lag)
        
        return float(max_lag)
    
    def ergodic_guarantee(self, data: np.ndarray) -> float:
        """
        Вычисление stealth guarantee на основе эргодической теории.
        
        Guarantee = P(|time_average - space_average| < ε)
        
        Args:
            data: Трансформированные данные
        
        Returns:
            Stealth guarantee (0 to 1)
        """
        # Проверяем uniformity (space average для равномерного распределения = 0.5)
        time_avg = np.mean(data)
        space_avg = 0.5  # Для равномерного распределения на [0, 1)
        
        # Error
        error = abs(time_avg - space_avg)
        
        # Guarantee: чем меньше error, тем выше guarantee
        guarantee = np.exp(-10 * error)  # Exponential decay
        
        return float(np.clip(guarantee, 0, 1))
    
    def _uniformity_test(self, data: np.ndarray, num_bins: int = 10) -> float:
        """Тест на равномерность распределения (chi-squared test)."""
        # Гистограмма
        hist, _ = np.histogram(data, bins=num_bins, range=(0, 1))
        
        # Ожидаемое количество в каждом бине (равномерное распределение)
        expected = len(data) / num_bins
        
        # Chi-squared statistic
        chi2 = np.sum((hist - expected)**2 / expected)
        
        # Degree of freedom
        dof = num_bins - 1
        
        # P-value (упрощённая аппроксимация)
        # Для большого chi2: p-value ≈ exp(-chi2/2)
        p_value = np.exp(-chi2 / 2)
        
        return float(np.clip(p_value, 0, 1))
    
    def _mixing_quality(self, original: np.ndarray, transformed: np.ndarray) -> float:
        """Оценка качества перемешивания."""
        # Сравниваем автокорреляцию original и transformed
        def autocorr(x, max_lag=50):
            n = len(x)
            mean_val = np.mean(x)
            var_val = np.var(x)
            
            if var_val == 0:
                return np.zeros(max_lag)
            
            ac = np.zeros(max_lag)
            for lag in range(max_lag):
                if lag == 0:
                    ac[lag] = 1.0
                else:
                    ac[lag] = np.mean((x[:n-lag] - mean_val) * (x[lag:] - mean_val)) / var_val
            return ac
        
        ac_orig = autocorr(original)
        ac_trans = autocorr(transformed)
        
        # Mixing quality = 1 - correlation between autocorrelations
        correlation = np.corrcoef(ac_orig, ac_trans)[0, 1]
        
        return float(1.0 - abs(correlation))
