"""
Fractal Traffic Generation — генерация трафика с фрактальными свойствами.

Математическая основа:
- Hurst exponent (H) через R/S analysis
- Fractional Gaussian Noise (fGn) — метод Davies-Harte
- Multifractal spectrum через MF-DFA (Multifractal Detrended Fluctuation Analysis)

Применение:
- Генерация cover traffic с точной фрактальной структурой
- Маскировка под легитимный трафик (H ≈ 0.7-0.8 для HTTPS)
- Обход fractal-based DPI detection
"""

import numpy as np
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from .base import MathTransform, MathContext


@dataclass
class FractalConfig:
    """Конфигурация фрактальной генерации."""
    hurst_target: float = 0.75  # Целевой Hurst exponent
    sample_length: int = 1000   # Длина временного ряда
    method: str = "davies_harte"  # Метод генерации: davies_harte, hosking, cholesky
    multifractal: bool = False  # Использовать мультифрактальный анализ


class FractalTrafficGenerator(MathTransform):
    """
    Генератор фрактального трафика.
    
    Методы:
    1. compute_hurst() — вычисление Hurst exponent через R/S analysis
    2. generate_fgn() — генерация Fractional Gaussian Noise
    3. multifractal_spectrum() — мультифрактальный спектр
    4. match_distribution() — подбор параметров под целевое распределение
    """
    
    def __init__(self, config: Optional[FractalConfig] = None):
        super().__init__(name="FractalTrafficGenerator", version="1.0.0")
        self.config = config or FractalConfig()
        self._hurst_cache: Dict[str, float] = {}
    
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Применить фрактальную трансформацию к данным.
        
        Генерирует фрактальный шум с заданным Hurst exponent.
        """
        if not self.validate_input(data):
            raise ValueError("Invalid input data")
        
        # Генерируем fGn с целевым Hurst
        n = len(data)
        fgn = self.generate_fgn(n, self.config.hurst_target)
        
        # Масштабируем под исходные данные
        mean, std = np.mean(data), np.std(data)
        fgn_scaled = fgn * std + mean
        
        return fgn_scaled
    
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """Обратная трансформация (детрендинг)."""
        # Удаляем фрактальную структуру
        hurst = self.compute_hurst(data)
        if hurst > 0.5:
            # Long-range dependence — применяем differencing
            diff_data = np.diff(data)
            return np.concatenate([[data[0]], diff_data])
        return data
    
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """Вычислить метрики качества."""
        hurst_orig = self.compute_hurst(original)
        hurst_trans = self.compute_hurst(transformed)
        
        return {
            "hurst_original": hurst_orig,
            "hurst_transformed": hurst_trans,
            "hurst_error": abs(hurst_orig - hurst_trans),
            "mean_error": abs(np.mean(original) - np.mean(transformed)),
            "std_ratio": np.std(transformed) / np.std(original) if np.std(original) > 0 else 0.0,
        }
    
    def compute_hurst(self, data: np.ndarray, min_n: int = 10, max_n: Optional[int] = None) -> float:
        """
        Вычисление Hurst exponent через R/S (Rescaled Range) analysis.
        
        Алгоритм:
        1. Разбить series на подсерии разной длины n
        2. Для каждой подсерии вычислить R/S statistic
        3. H = slope(log(R/S) vs log(n))
        
        Args:
            data: Временной ряд
            min_n: Минимальная длина подсерии
            max_n: Максимальная длина подсерии
        
        Returns:
            Hurst exponent H ∈ [0, 1]
            H < 0.5: anti-persistent (mean-reverting)
            H = 0.5: random walk (no memory)
            H > 0.5: persistent (long-range dependence)
        """
        N = len(data)
        if max_n is None:
            max_n = N // 2
        
        # Размеры подсерий (степени 2)
        ns = []
        rs_values = []
        
        n = min_n
        while n <= max_n:
            # Разбиваем на подсерии длины n
            num_subseries = N // n
            if num_subseries < 1:
                break
            
            rs_subseries = []
            for i in range(num_subseries):
                subseries = data[i*n:(i+1)*n]
                
                # Mean
                mean = np.mean(subseries)
                
                # Cumulative deviation from mean
                Y = np.cumsum(subseries - mean)
                
                # Range R
                R = np.max(Y) - np.min(Y)
                
                # Standard deviation S
                S = np.std(subseries)
                
                if S > 0:
                    rs_subseries.append(R / S)
            
            if rs_subseries:
                ns.append(n)
                rs_values.append(np.mean(rs_subseries))
            
            n *= 2
        
        if len(ns) < 2:
            return 0.5  # Недостаточно данных
        
        # Linear regression: log(R/S) = H * log(n) + c
        log_ns = np.log(ns)
        log_rs = np.log(rs_values)
        
        # H = slope
        H = np.polyfit(log_ns, log_rs, 1)[0]
        
        return float(np.clip(H, 0, 1))
    
    def generate_fgn(self, n: int, H: float) -> np.ndarray:
        """
        Генерация Fractional Gaussian Noise (fGn).
        
        Метод Davies-Harte (circulant embedding):
        1. Построить covariance matrix для fGn
        2. Circulant embedding
        3. FFT → комплексные коэффициенты
        4. Умножить на Gaussian noise
        5. IFFT → fGn
        
        Args:
            n: Длина временного ряда
            H: Hurst exponent
        
        Returns:
            Fractional Gaussian Noise (numpy array)
        """
        if H <= 0 or H >= 1:
            raise ValueError("Hurst exponent must be in (0, 1)")
        
        # Автоковариационная функция fGn
        # γ(k) = 0.5 * (|k+1|^(2H) - 2|k|^(2H) + |k-1|^(2H))
        def acf(k):
            return 0.5 * (abs(k+1)**(2*H) - 2*abs(k)**(2*H) + abs(k-1)**(2*H))
        
        # Circulant embedding (метод Davies-Harte)
        m = 2 * n  # Размер circulant matrix
        
        # Первая строка covariance matrix
        gamma = np.array([acf(k) for k in range(m)])
        
        # FFT covariance
        eigenvalues = np.fft.rfft(gamma).real
        
        # Проверка положительной определённости
        if np.any(eigenvalues < 0):
            # Fallback: использовать Cholesky decomposition
            return self._generate_fgn_cholesky(n, H)
        
        # Генерация комплексных Gaussian
        w = np.random.randn(m) + 1j * np.random.randn(m)
        
        # Умножить на sqrt(eigenvalues)
        w[:n+1] *= np.sqrt(eigenvalues[:n+1])
        w[n+1:] = np.conj(w[1:n-1][::-1])  # Symmetry
        
        # IFFT
        z = np.fft.ifft(w).real
        
        # Нормализация
        z = z[:n]
        z = (z - np.mean(z)) / np.std(z)
        
        return z
    
    def _generate_fgn_cholesky(self, n: int, H: float) -> np.ndarray:
        """Fallback: генерация fGn через Cholesky decomposition."""
        # Covariance matrix
        cov = np.zeros((n, n))
        for i in range(n):
            for j in range(n):
                cov[i, j] = 0.5 * (abs(i-j+1)**(2*H) - 2*abs(i-j)**(2*H) + abs(i-j-1)**(2*H))
        
        # Cholesky decomposition
        try:
            L = np.linalg.cholesky(cov)
            z = np.random.randn(n)
            return L @ z
        except np.linalg.LinAlgError:
            # Если матрица не positive definite, используем eigenvalue decomposition
            eigenvalues, eigenvectors = np.linalg.eigh(cov)
            eigenvalues = np.maximum(eigenvalues, 0)  # Clip negative eigenvalues
            L = eigenvectors @ np.diag(np.sqrt(eigenvalues))
            z = np.random.randn(n)
            return L @ z
    
    def multifractal_spectrum(self, data: np.ndarray, q_range: Tuple[int, int] = (-5, 5)) -> Dict[str, np.ndarray]:
        """
        Вычисление мультифрактального спектра через MF-DFA.
        
        Алгоритм:
        1. Вычислить profile Y(k) = Σ(i=1 to k) [x(i) - <x>]
        2. Разбить на boxes длины s
        3. Для каждого q вычислить q-th order fluctuation function F_q(s)
        4. h(q) = slope(log(F_q) vs log(s))
        5. τ(q) = q*h(q) - 1
        6. Multifractal spectrum: f(α) = q*α - τ(q), где α = dτ/dq
        
        Args:
            data: Временной ряд
            q_range: Диапазон q значений
        
        Returns:
            Словарь с q, h(q), τ(q), α, f(α)
        """
        N = len(data)
        
        # Profile
        mean_val = np.mean(data)
        Y = np.cumsum(data - mean_val)
        
        # Scales (степени 2)
        scales = []
        s = 10
        while s < N // 4:
            scales.append(s)
            s *= 2
        
        scales = np.array(scales)
        q_values = np.arange(q_range[0], q_range[1] + 1)
        
        # Fluctuation function F_q(s)
        F_q = np.zeros((len(q_values), len(scales)))
        
        for i, q in enumerate(q_values):
            for j, s in enumerate(scales):
                # Разбить на boxes
                num_boxes = N // s
                if num_boxes < 1:
                    continue
                
                variance_sum = 0
                for v in range(num_boxes):
                    segment = Y[v*s:(v+1)*s]
                    # Detrend (linear fit)
                    x = np.arange(s)
                    coeffs = np.polyfit(x, segment, 1)
                    trend = np.polyval(coeffs, x)
                    residue = segment - trend
                    variance_sum += np.mean(residue**2)
                
                F_s = (variance_sum / num_boxes)**(1/2)
                
                if q != 0:
                    F_q[i, j] = F_s**q
                else:
                    F_q[i, j] = np.log(F_s) if F_s > 0 else 0
        
        # Scaling exponents h(q)
        h_q = np.zeros(len(q_values))
        for i in range(len(q_values)):
            valid = F_q[i, :] > 0
            if np.sum(valid) > 1:
                log_s = np.log(scales[valid])
                log_F = np.log(F_q[i, valid])
                h_q[i] = np.polyfit(log_s, log_F, 1)[0] / q_values[i] if q_values[i] != 0 else 0
        
        # Mass exponent τ(q)
        tau_q = q_values * h_q - 1
        
        # Singularity strength α = dτ/dq
        alpha = np.gradient(tau_q, q_values)
        
        # Multifractal spectrum f(α)
        f_alpha = q_values * alpha - tau_q
        
        return {
            "q": q_values,
            "h_q": h_q,
            "tau_q": tau_q,
            "alpha": alpha,
            "f_alpha": f_alpha,
        }
    
    def match_distribution(self, target_hurst: float, data_length: int = 1000) -> Dict[str, Any]:
        """
        Подбор параметров для генерации трафика с целевым Hurst exponent.
        
        Args:
            target_hurst: Целевой Hurst exponent
            data_length: Длина генерируемого ряда
        
        Returns:
            Словарь с параметрами и статистикой
        """
        # Генерируем fGn с целевым Hurst
        fgn = self.generate_fgn(data_length, target_hurst)
        
        # Проверяем Hurst
        actual_hurst = self.compute_hurst(fgn)
        
        # Multifractal analysis
        mfs = self.multifractal_spectrum(fgn)
        
        # Multifractal width (Δα = α_max - α_min)
        alpha_range = mfs["alpha"]
        valid_f = mfs["f_alpha"] > 0
        if np.sum(valid_f) > 1:
            mf_width = np.max(alpha_range[valid_f]) - np.min(alpha_range[valid_f])
        else:
            mf_width = 0.0
        
        return {
            "target_hurst": target_hurst,
            "actual_hurst": actual_hurst,
            "hurst_error": abs(target_hurst - actual_hurst),
            "multifractal_width": mf_width,
            "mean": np.mean(fgn),
            "std": np.std(fgn),
            "generated_data": fgn,
        }
