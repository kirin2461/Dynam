"""
Chaotic Packet Embedding — встраивание данных в хаотические последовательности.

Математическая основа:
- Система Лоренца (σ=10, ρ=28, β=8/3)
- Chaos Shift Keying (CSS) — модуляция данных хаосом
- Takens' embedding theorem — реконструкция аттрактора
- Lyapunov exponents — показатель хаотичности

Применение:
- Covert channels через "естественный" хаотический трафик
- Обход statistical analysis — хаос неотличим от шума
- Скрытая передача ключей/команд
"""

import numpy as np
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from scipy.integrate import odeint
from .base import MathTransform, MathContext


@dataclass
class ChaoticConfig:
    """Конфигурация хаотической системы."""
    sigma: float = 10.0      # Параметр Лоренца σ
    rho: float = 28.0        # Параметр Лоренца ρ
    beta: float = 8.0/3.0    # Параметр Лоренца β
    dt: float = 0.01         # Временной шаг
    initial_condition: Tuple[float, float, float] = (1.0, 1.0, 1.0)
    embedding_dim: int = 3   # Размерность вложения (Takens)
    time_delay: int = 10     # Задержка для вложения


class ChaoticEmbedder(MathTransform):
    """
    Хаотический embedder для covert channels.
    
    Методы:
    1. lorenz_system() — генерация хаотической траектории
    2. chaos_shift_keying() — CSS модуляция
    3. takens_embedding() — реконструкция аттрактора
    4. lyapunov_exponents() — вычисление показателей Ляпунова
    5. chaotic_sync() — синхронизация хаотических систем
    """
    
    def __init__(self, config: Optional[ChaoticConfig] = None):
        super().__init__(name="ChaoticEmbedder", version="1.0.0")
        self.config = config or ChaoticConfig()
        self._trajectory_cache: Dict[str, np.ndarray] = {}
    
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Встроить данные в хаотическую последовательность.
        
        Использует CSS (Chaos Shift Keying):
        - Бит 0 → траектория начинается с (x₀, y₀, z₀)
        - Бит 1 → траектория начинается с (x₀+ε, y₀, z₀)
        """
        if not self.validate_input(data):
            raise ValueError("Invalid input data")
        
        # Преобразуем данные в биты
        bits = self._bytes_to_bits(data.tobytes() if data.dtype != np.uint8 else data.astype(np.uint8).tobytes())
        
        # Генерируем хаотическую последовательность с модуляцией
        chaotic_signal = self.chaos_shift_keying(bits)
        
        return chaotic_signal
    
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """Извлечь данные из хаотической последовательности."""
        # Демодуляция CSS
        bits = self._chaos_shift_keying_demod(data)
        
        # Преобразуем биты в байты
        bytes_data = self._bits_to_bytes(bits)
        
        return np.frombuffer(bytes_data, dtype=np.uint8)
    
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """Вычислить метрики качества."""
        # Lyapunov exponent для transformed
        lyap = self.lyapunov_exponents(transformed[:1000])
        
        # Correlation dimension
        corr_dim = self._correlation_dimension(transformed[:1000])
        
        return {
            "lyapunov_exponent": lyap[0] if len(lyap) > 0 else 0.0,
            "correlation_dimension": corr_dim,
            "chaos_indicator": "chaotic" if lyap[0] > 0 else "periodic" if len(lyap) > 0 else 0.0,
        }
    
    def lorenz_system(self, state: np.ndarray, t: float, sigma: float, rho: float, beta: float) -> np.ndarray:
        """
        Система Лоренца (differential equations).
        
        dx/dt = σ(y - x)
        dy/dt = x(ρ - z) - y
        dz/dt = xy - βz
        
        Args:
            state: [x, y, z]
            t: время
            sigma, rho, beta: параметры
        
        Returns:
            [dx/dt, dy/dt, dz/dt]
        """
        x, y, z = state
        return np.array([
            sigma * (y - x),
            x * (rho - z) - y,
            x * y - beta * z
        ])
    
    def generate_trajectory(self, n_points: int = 10000) -> np.ndarray:
        """
        Генерация хаотической траектории системы Лоренца.
        
        Args:
            n_points: Количество точек
        
        Returns:
            Trajectory array shape (n_points, 3)
        """
        t = np.arange(0, n_points * self.config.dt, self.config.dt)
        
        # Интегрирование ODE
        trajectory = odeint(
            self.lorenz_system,
            self.config.initial_condition,
            t,
            args=(self.config.sigma, self.config.rho, self.config.beta)
        )
        
        return trajectory
    
    def chaos_shift_keying(self, bits: List[int]) -> np.ndarray:
        """
        Chaos Shift Keying (CSS) — модуляция данных хаосом.
        
        Принцип:
        - Для бита 0: используем траекторию с начальным условием (x₀, y₀, z₀)
        - Для бита 1: используем траекторию с начальным условием (x₀+ε, y₀, z₀)
        - Разница ε мала, но детектируема при синхронизации
        
        Args:
            bits: Список бит (0 или 1)
        
        Returns:
            Хаотический сигнал с встроенными данными
        """
        epsilon = 0.01  # Малое возмущение для бита 1
        segment_length = 100  # Длина сегмента на один бит
        
        signal = []
        
        for bit in bits:
            # Начальное условие
            if bit == 0:
                ic = self.config.initial_condition
            else:
                ic = (
                    self.config.initial_condition[0] + epsilon,
                    self.config.initial_condition[1],
                    self.config.initial_condition[2]
                )
            
            # Генерируем сегмент траектории
            t = np.arange(0, segment_length * self.config.dt, self.config.dt)
            segment = odeint(
                self.lorenz_system,
                ic,
                t,
                args=(self.config.sigma, self.config.rho, self.config.beta)
            )
            
            # Используем x-координату как сигнал
            signal.extend(segment[:, 0])
            
            # Обновляем начальное условие для next segment (continuity)
            ic = segment[-1]
        
        return np.array(signal)
    
    def _chaos_shift_keying_demod(self, signal: np.ndarray) -> List[int]:
        """Демодуляция CSS."""
        segment_length = 100
        epsilon_threshold = 0.005
        
        bits = []
        num_segments = len(signal) // segment_length
        
        # Эталонная траектория (бит 0)
        ref_trajectory = self.generate_trajectory(segment_length)[:, 0]
        
        for i in range(num_segments):
            segment = signal[i*segment_length:(i+1)*segment_length]
            
            # Сравнение с эталоном
            diff = np.mean(np.abs(segment - ref_trajectory[:len(segment)]))
            
            # Классификация
            if diff < epsilon_threshold:
                bits.append(0)
            else:
                bits.append(1)
        
        return bits
    
    def takens_embedding(self, time_series: np.ndarray, dim: Optional[int] = None, delay: Optional[int] = None) -> np.ndarray:
        """
        Takens' embedding theorem — реконструкция аттрактора из временного ряда.
        
        Теорема Такенса: если исходная система имеет размерность d,
        то реконструкция из временного ряда с размерностью m > 2d
        топологически эквивалентна исходному аттрактору.
        
        Args:
            time_series: 1D временной ряд
            dim: Размерность вложения (по умолчанию self.config.embedding_dim)
            delay: Задержка (по умолчанию self.config.time_delay)
        
        Returns:
            Embedded array shape (N - (dim-1)*delay, dim)
        """
        if dim is None:
            dim = self.config.embedding_dim
        if delay is None:
            delay = self.config.time_delay
        
        N = len(time_series)
        embedded_length = N - (dim - 1) * delay
        
        if embedded_length <= 0:
            raise ValueError("Time series too short for embedding")
        
        embedded = np.zeros((embedded_length, dim))
        
        for i in range(dim):
            embedded[:, i] = time_series[i*delay:i*delay + embedded_length]
        
        return embedded
    
    def lyapunov_exponents(self, time_series: np.ndarray, max_dim: int = 3) -> np.ndarray:
        """
        Вычисление показателей Ляпунова (Lyapunov exponents).
        
        Показатель Ляпунова λ характеризует скорость расхождения траекторий:
        - λ > 0: хаос (экспоненциальное расхождение)
        - λ = 0: граница (periodic or quasi-periodic)
        - λ < 0: сходимость (stable fixed point)
        
        Метод: Wolf algorithm (упрощённая версия)
        
        Args:
            time_series: Временной ряд
            max_dim: Максимальная размерность
        
        Returns:
            Array of Lyapunov exponents
        """
        # Takens embedding
        embedded = self.takens_embedding(time_series, dim=max_dim)
        
        N, dim = embedded.shape
        
        if N < 100:
            return np.zeros(dim)
        
        # Упрощённый алгоритм: оцениваем скорость расхождения близких точек
        lyap = np.zeros(dim)
        
        for d in range(dim):
            # Находим ближайшие пары точек
            distances = []
            
            for i in range(N - 10):
                # Ищем ближайшую точку (не себя)
                dists = np.linalg.norm(embedded[i+10:] - embedded[i], axis=1)
                if len(dists) == 0:
                    continue
                
                min_idx = np.argmin(dists) + i + 10
                min_dist = dists[np.argmin(dists)]
                
                if min_dist > 0:
                    # Измеряем расхождение через evolution time
                    evolution_steps = min(50, N - min_idx - 1)
                    if evolution_steps > 0:
                        final_dist = np.linalg.norm(
                            embedded[min_idx + evolution_steps] - embedded[i + evolution_steps]
                        )
                        if final_dist > 0 and min_dist > 0:
                            # Lyapunov exponent ≈ log(final_dist / initial_dist) / time
                            lyap_est = np.log(final_dist / min_dist) / evolution_steps
                            distances.append(lyap_est)
            
            if distances:
                lyap[d] = np.median(distances)
        
        return lyap
    
    def _correlation_dimension(self, time_series: np.ndarray, max_r: float = 1.0, num_r: int = 20) -> float:
        """
        Вычисление correlation dimension (Grassberger-Procaccia algorithm).
        
        Correlation dimension D₂ характеризует фрактальную размерность аттрактора.
        
        Алгоритм:
        1. Вложить временной ряд в m-мерное пространство
        2. Для каждого r вычислить C(r) = (2/N(N-1)) * Σ(i<j) Θ(r - ||x_i - x_j||)
        3. D₂ = slope(log(C) vs log(r))
        
        Args:
            time_series: Временной ряд
            max_r: Максимальный радиус
            num_r: Количество значений r
        
        Returns:
            Correlation dimension
        """
        embedded = self.takens_embedding(time_series, dim=3)
        N = len(embedded)
        
        if N < 100:
            return 0.0
        
        # Radii
        r_values = np.linspace(0.01, max_r, num_r)
        C_values = []
        
        for r in r_values:
            count = 0
            total = 0
            
            # Sample pairs (для скорости)
            sample_size = min(1000, N)
            indices = np.random.choice(N, sample_size, replace=False)
            
            for i in indices:
                for j in indices:
                    if i < j:
                        dist = np.linalg.norm(embedded[i] - embedded[j])
                        if dist < r:
                            count += 1
                        total += 1
            
            if total > 0:
                C_values.append(count / total)
            else:
                C_values.append(0)
        
        C_values = np.array(C_values)
        
        # Filter out zeros
        valid = C_values > 0
        if np.sum(valid) < 2:
            return 0.0
        
        # Linear regression: log(C) = D₂ * log(r) + const
        log_r = np.log(r_values[valid])
        log_C = np.log(C_values[valid])
        
        D2 = np.polyfit(log_r, log_C, 1)[0]
        
        return float(D2)
    
    def _bytes_to_bits(self, bytes_data: bytes) -> List[int]:
        """Преобразовать байты в биты."""
        bits = []
        for byte in bytes_data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        return bits
    
    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Преобразовать биты в байты."""
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= (bits[i + j] << j)
            bytes_data.append(byte)
        return bytes(bytes_data)
