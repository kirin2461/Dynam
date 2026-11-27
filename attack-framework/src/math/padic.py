"""
p-adic Traffic Analysis — p-адический анализ трафика.

Математическая основа:
- p-адические числа ℚₚ с ультраметрической метрикой |x-y|_p
- p-адический анализ (Mahler expansion, p-adic wavelets)
- Адельная структура A_ℚ = ℝ × ∏' ℚₚ
- Harmonic analysis на ℚₚ

Применение:
- Ультраметрическая кластеризация трафика
- p-адическое представление для обхода DPI
- Адельная signature для multi-completion analysis
"""

import numpy as np
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from collections import defaultdict
from .base import MathTransform, MathContext


@dataclass
class PadicConfig:
    """Конфигурация p-адического анализа."""
    prime: int = 2  # Простое число p
    precision: int = 10  # Точность (количество p-адических цифр)
    num_primes: int = 3  # Количество простых для adele ring


class PadicAnalysis(MathTransform):
    """
    p-адический анализ трафика.
    
    Методы:
    1. padic_expansion() — p-адическое разложение
    2. ultrametric_distance() — ультраметрическое расстояние
    3. mahler_expansion() — разложение Маглера (p-адические wavelets)
    4. padic_fourier() — p-адический анализ Фурье
    5. adele_ring() — аделевое представление
    """
    
    def __init__(self, config: Optional[PadicConfig] = None):
        super().__init__(name="PadicAnalysis", version="1.0.0")
        self.config = config or PadicConfig()
        self._primes = self._generate_primes(self.config.num_primes)
    
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Применить p-адическую трансформацию к данным.
        
        Преобразует данные в p-адическое представление,
        применяет ультраметрическую обработку, возвращает обратно.
        """
        if not self.validate_input(data):
            raise ValueError("Invalid input data")
        
        # Преобразуем в p-адическое представление
        padic_data = self._to_padic(data)
        
        # Применяем p-адическое сглаживание
        smoothed = self._padic_smoothing(padic_data)
        
        # Возвращаем в обычное пространство
        result = self._from_padic(smoothed)
        
        return result
    
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """Обратная p-адическая трансформация."""
        padic_data = self._to_padic(data)
        restored = self._padic_restore(padic_data)
        return self._from_padic(restored)
    
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """Вычислить p-адические метрики."""
        # Ультраметрическое расстояние
        ultrametric = self.ultrametric_distance(original, transformed)
        
        # p-адическая энтропия
        entropy = self._padic_entropy(transformed)
        
        # Ultrametric clustering score
        clustering = self._ultrametric_clustering_score(transformed)
        
        return {
            "ultrametric_distance": ultrametric,
            "padic_entropy": entropy,
            "ultrametric_clustering": clustering,
        }
    
    def padic_expansion(self, x: float, p: Optional[int] = None) -> List[int]:
        """
        p-адическое разложение числа.
        
        x = a_0 + a_1*p + a_2*p^2 + ... + a_n*p^n
        
        где a_i ∈ {0, 1, ..., p-1}
        
        Args:
            x: Число для разложения
            p: Простое число (по умолчанию self.config.prime)
        
        Returns:
            Coefficients [a_0, a_1, ..., a_n]
        """
        if p is None:
            p = self.config.prime
        
        # Для отрицательных чисел используем p-адическое представление
        if x < 0:
            # p-адическое представление отрицательных чисел
            # x = -|x| = (p^n - |x|) - p^n для достаточно большого n
            x = int(abs(x))
            is_negative = True
        else:
            x = int(x)
            is_negative = False
        
        coefficients = []
        
        for _ in range(self.config.precision):
            coefficients.append(x % p)
            x = x // p
            if x == 0:
                break
        
        # Дополняем нулями до нужной точности
        while len(coefficients) < self.config.precision:
            coefficients.append(0)
        
        return coefficients
    
    def ultrametric_distance(self, x: np.ndarray, y: np.ndarray, p: Optional[int] = None) -> float:
        """
        Ультраметрическое расстояние |x - y|_p.
        
        |x|_p = p^(-v_p(x))
        
        где v_p(x) — p-адическая valuation (наибольшая степень p, делящая x)
        
        Ультраметрическое неравенство: |x + y|_p ≤ max(|x|_p, |y|_p)
        
        Args:
            x, y: Числа или arrays
            p: Простое число
        
        Returns:
            Ultrametric distance
        """
        if p is None:
            p = self.config.prime
        
        # Вычисляем для каждого элемента
        if isinstance(x, np.ndarray) and isinstance(y, np.ndarray):
            diff = x - y
            valuations = np.array([self._p_adic_valuation(d, p) for d in diff.flatten()])
            distances = p ** (-valuations)
            return float(np.max(distances))
        else:
            diff = x - y
            valuation = self._p_adic_valuation(diff, p)
            return float(p ** (-valuation))
    
    def mahler_expansion(self, data: np.ndarray, num_coefficients: int = 10) -> np.ndarray:
        """
        Разложение Маглера (p-адические wavelets).
        
        f(x) = Σ(n=0 to ∞) a_n * C(n, x)
        
        где C(n, x) = binomial(x, n) — binomial coefficients
        
        Это p-адический аналог разложения Фурье.
        
        Args:
            data: Входные данные (функция на ℤₚ)
            num_coefficients: Количество коэффициентов
        
        Returns:
            Mahler coefficients [a_0, a_1, ..., a_n]
        """
        N = len(data)
        coefficients = np.zeros(num_coefficients)
        
        # Вычисляем Mahler coefficients
        # a_n = Σ(k=0 to n) (-1)^(n-k) * C(n, k) * f(k)
        
        for n in range(min(num_coefficients, N)):
            coeff = 0.0
            for k in range(n + 1):
                binomial = self._binomial_coefficient(n, k)
                sign = (-1) ** (n - k)
                if k < N:
                    coeff += sign * binomial * data[k]
            coefficients[n] = coeff
        
        return coefficients
    
    def padic_fourier(self, data: np.ndarray, p: Optional[int] = None) -> np.ndarray:
        """
        p-адический анализ Фурье.
        
        f̂(χ) = ∫ f(x) χ(x) dμ(x)
        
        где χ — характер на ℚₚ, μ — Haar measure
        
        Упрощённая версия: используем дискретное преобразование
        
        Args:
            data: Входные данные
            p: Простое число
        
        Returns:
            Fourier coefficients
        """
        if p is None:
            p = self.config.prime
        
        N = len(data)
        
        # p-адические характеры: χ_k(x) = exp(2πi * {k*x}_p)
        # где {x}_p — дробная часть в p-адическом смысле
        
        fourier_coeffs = np.zeros(N, dtype=complex)
        
        for k in range(N):
            # Вычисляем характер
            chi = np.zeros(N, dtype=complex)
            for n in range(N):
                # p-адическая дробная часть
                frac_part = self._p_adic_fractional_part(k * n, p)
                chi[n] = np.exp(2j * np.pi * frac_part)
            
            # Fourier coefficient
            fourier_coeffs[k] = np.sum(data * chi) / N
        
        return fourier_coeffs
    
    def adele_ring(self, data: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Адельное представление данных.
        
        Аделевое кольцо: A_ℚ = ℝ × ∏' ℚₚ
        
        Представляем данные одновременно в ℝ и нескольких ℚₚ.
        
        Args:
            data: Входные данные
        
        Returns:
            Dict с real component и p-adic components
        """
        adele = {
            "real": data.copy(),
        }
        
        # p-адические компоненты
        for p in self._primes:
            padic_component = np.array([self._to_padic_value(x, p) for x in data])
            adele[f"padic_{p}"] = padic_component
        
        return adele
    
    def ultrametric_clustering(self, data: np.ndarray, threshold: float = 0.5) -> List[List[int]]:
        """
        Ультраметрическая кластеризация.
        
        В ультраметрическом пространстве кластеры имеют иерархическую структуру.
        
        Args:
            data: Данные для кластеризации
            threshold: Порог расстояния
        
        Returns:
            List of clusters (каждый кластер — список индексов)
        """
        N = len(data)
        
        # Вычисляем попарные ультраметрические расстояния
        distances = np.zeros((N, N))
        for i in range(N):
            for j in range(N):
                distances[i, j] = self.ultrametric_distance(data[i], data[j])
        
        # Иерархическая кластеризация (упрощённая)
        clusters = [[i] for i in range(N)]
        
        # Объединяем близкие кластеры
        while True:
            merged = False
            
            for i in range(len(clusters)):
                for j in range(i + 1, len(clusters)):
                    # Среднее расстояние между кластерами
                    dist = 0.0
                    count = 0
                    for idx_i in clusters[i]:
                        for idx_j in clusters[j]:
                            dist += distances[idx_i, idx_j]
                            count += 1
                    
                    if count > 0:
                        avg_dist = dist / count
                        
                        if avg_dist < threshold:
                            # Объединяем кластеры
                            clusters[i] = clusters[i] + clusters[j]
                            clusters.pop(j)
                            merged = True
                            break
                
                if merged:
                    break
            
            if not merged:
                break
        
        return clusters
    
    def _p_adic_valuation(self, x: float, p: int) -> int:
        """p-адическая valuation v_p(x)."""
        if x == 0:
            return float('inf')
        
        x = int(abs(x))
        v = 0
        
        while x % p == 0 and x > 0:
            x //= p
            v += 1
        
        return v
    
    def _to_padic(self, data: np.ndarray) -> np.ndarray:
        """Преобразование в p-адическое представление."""
        # Квантуем данные в целые числа
        quantized = np.round(data * 1000).astype(int)
        
        # Преобразуем в p-адическое представление
        padic_values = np.array([self._to_padic_value(x, self.config.prime) for x in quantized])
        
        return padic_values
    
    def _from_padic(self, padic_data: np.ndarray) -> np.ndarray:
        """Преобразование из p-адического представления."""
        # Обратное преобразование
        restored = np.array([self._from_padic_value(x, self.config.prime) for x in padic_data])
        
        # Деквантуем
        return restored / 1000.0
    
    def _to_padic_value(self, x: int, p: int) -> float:
        """Преобразование целого числа в p-адическое значение."""
        coeffs = self.padic_expansion(x, p)
        
        # Преобразуем коэффициенты в число
        value = 0.0
        for i, coeff in enumerate(coeffs):
            value += coeff * (p ** i)
        
        return value
    
    def _from_padic_value(self, padic_value: float, p: int) -> int:
        """Обратное преобразование из p-адического значения."""
        # Упрощённое восстановление
        return int(padic_value) % (p ** self.config.precision)
    
    def _padic_smoothing(self, padic_data: np.ndarray) -> np.ndarray:
        """p-адическое сглаживание."""
        # В ультраметрическом пространстве сглаживание = кластеризация
        clusters = self.ultrametric_clustering(padic_data, threshold=0.3)
        
        smoothed = padic_data.copy()
        
        # Заменяем значения в каждом кластере на среднее
        for cluster in clusters:
            if len(cluster) > 1:
                cluster_values = padic_data[cluster]
                mean_value = np.mean(cluster_values)
                smoothed[cluster] = mean_value
        
        return smoothed
    
    def _padic_restore(self, padic_data: np.ndarray) -> np.ndarray:
        """Восстановление из p-адического представления."""
        # Обратная операция к smoothing
        return padic_data
    
    def _padic_entropy(self, data: np.ndarray) -> float:
        """p-адическая энтропия."""
        # Вычисляем распределение p-адических valuation
        valuations = [self._p_adic_valuation(x, self.config.prime) for x in data]
        
        # Гистограмма
        unique, counts = np.unique(valuations, return_counts=True)
        probabilities = counts / len(valuations)
        
        # Энтропия Шеннона
        entropy = -np.sum(probabilities * np.log(probabilities + 1e-10))
        
        return float(entropy)
    
    def _ultrametric_clustering_score(self, data: np.ndarray) -> float:
        """Оценка качества ультраметрической кластеризации."""
        clusters = self.ultrametric_clustering(data)
        
        # Score = количество кластеров / количество точек
        score = len(clusters) / len(data)
        
        return float(score)
    
    def _generate_primes(self, num_primes: int) -> List[int]:
        """Генерация первых num_primes простых чисел."""
        primes = []
        candidate = 2
        
        while len(primes) < num_primes:
            is_prime = True
            for p in primes:
                if p * p > candidate:
                    break
                if candidate % p == 0:
                    is_prime = False
                    break
            
            if is_prime:
                primes.append(candidate)
            
            candidate += 1
        
        return primes
    
    def _binomial_coefficient(self, n: int, k: int) -> int:
        """Биномиальный коэффициент C(n, k)."""
        if k < 0 or k > n:
            return 0
        if k == 0 or k == n:
            return 1
        
        # Упрощённое вычисление
        result = 1
        for i in range(k):
            result = result * (n - i) // (i + 1)
        
        return result
    
    def _p_adic_fractional_part(self, x: int, p: int) -> float:
        """p-адическая дробная часть {x}_p."""
        # Упрощённая версия
        return (x % p) / p
