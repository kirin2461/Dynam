"""
Math Director — координация всех математических трансформаций.

Выбирает оптимальную комбинацию математических модулей на основе:
- Типа DPI (из DPI fingerprinting)
- Текущих условий сети
- Целевого stealth score
- Доступных ресурсов
"""

import numpy as np
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..base import MathTransform, MathContext
from ..fractal import FractalTrafficGenerator
from ..chaotic import ChaoticEmbedder
from ..ergodic import ErgodicShaper
from ..topological import TopologicalMorpher
from ..tropical import TropicalGeometry
from ..padic import PadicAnalysis
from ..cluster import ClusterAlgebra
from ..mirror import MirrorSymmetry
from ..anabelian import AnabelianReconstruction


class MathStrategy(Enum):
    """Математическая стратегия."""
    MINIMAL = "minimal"  # Только базовые трансформации
    STANDARD = "standard"  # Стандартный набор
    ADVANCED = "advanced"  # Продвинутые трансформации
    MAXIMUM = "maximum"  # Все доступные трансформации
    CUSTOM = "custom"  # Пользовательская комбинация


@dataclass
class DirectorConfig:
    """Конфигурация Math Director."""
    target_stealth: float = 0.9
    max_transforms: int = 5
    timeout_seconds: int = 30
    adaptive: bool = True


@dataclass
class TransformResult:
    """Результат применения трансформации."""
    transform_name: str
    input_data: np.ndarray
    output_data: np.ndarray
    metrics: Dict[str, float]
    execution_time_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "transform_name": self.transform_name,
            "metrics": self.metrics,
            "execution_time_ms": self.execution_time_ms,
        }


class MathDirector:
    """
    Координатор математических трансформаций.
    
    Методы:
    1. select_strategy() — выбор стратегии на основе DPI fingerprint
    2. apply_transforms() — применение выбранных трансформаций
    3. optimize_pipeline() — оптимизация порядка трансформаций
    4. verify_stealth() — проверка достижения target stealth
    """
    
    def __init__(self, config: Optional[DirectorConfig] = None):
        self.config = config or DirectorConfig()
        
        # Инициализация всех трансформаций
        self.transforms = {
            "fractal": FractalTrafficGenerator(),
            "chaotic": ChaoticEmbedder(),
            "ergodic": ErgodicShaper(),
            "topological": TopologicalMorpher(),
            "tropical": TropicalGeometry(),
            "padic": PadicAnalysis(),
            "cluster": ClusterAlgebra(),
            "mirror": MirrorSymmetry(),
            "anabelian": AnabelianReconstruction(),
        }
        
        # История применённых трансформаций
        self.history: List[TransformResult] = []
        
        # Текущая стратегия
        self.current_strategy: Optional[MathStrategy] = None
    
    def select_strategy(self, dpi_fingerprint: Dict[str, Any]) -> MathStrategy:
        """
        Выбор математической стратегии на основе DPI fingerprint.
        
        Args:
            dpi_fingerprint: Результат DPI fingerprinting
        
        Returns:
            Выбранная стратегия
        """
        # Упрощённая логика выбора
        dpi_system = dpi_fingerprint.get("dpi_system", "unknown")
        confidence = dpi_fingerprint.get("confidence", 0.0)
        
        if confidence < 0.3:
            # Низкая уверенность — используем minimal
            strategy = MathStrategy.MINIMAL
        elif confidence < 0.6:
            # Средняя уверенность — standard
            strategy = MathStrategy.STANDARD
        elif confidence < 0.8:
            # Высокая уверенность — advanced
            strategy = MathStrategy.ADVANCED
        else:
            # Очень высокая уверенность — maximum
            strategy = MathStrategy.MAXIMUM
        
        # Специфичные стратегии для разных DPI
        if dpi_system == "qosmos":
            # Qosmos использует ML — используем adversarial transforms
            strategy = MathStrategy.ADVANCED
        elif dpi_system == "fortinet":
            # Fortinet strict — используем maximum
            strategy = MathStrategy.MAXIMUM
        
        self.current_strategy = strategy
        
        return strategy
    
    def get_transforms_for_strategy(self, strategy: MathStrategy) -> List[str]:
        """Получить список трансформаций для стратегии."""
        strategy_transforms = {
            MathStrategy.MINIMAL: ["fractal", "ergodic"],
            MathStrategy.STANDARD: ["fractal", "chaotic", "ergodic"],
            MathStrategy.ADVANCED: ["fractal", "chaotic", "ergodic", "topological", "tropical"],
            MathStrategy.MAXIMUM: list(self.transforms.keys()),
        }
        
        return strategy_transforms.get(strategy, [])
    
    async def apply_transforms(
        self,
        data: np.ndarray,
        context: MathContext,
        strategy: Optional[MathStrategy] = None,
        custom_transforms: Optional[List[str]] = None
    ) -> np.ndarray:
        """
        Применение математических трансформаций к данным.
        
        Args:
            data: Входные данные
            context: Контекст трансформации
            strategy: Стратегия (если None, используется текущая)
            custom_transforms: Пользовательский список трансформаций
        
        Returns:
            Трансформированные данные
        """
        # Определяем список трансформаций
        if custom_transforms:
            transform_names = custom_transforms
        else:
            if strategy is None:
                strategy = self.current_strategy or MathStrategy.STANDARD
            
            transform_names = self.get_transforms_for_strategy(strategy)
        
        # Применяем трансформации последовательно
        result = data.copy()
        
        for transform_name in transform_names:
            if transform_name not in self.transforms:
                continue
            
            transform = self.transforms[transform_name]
            
            # Засекаем время
            start_time = datetime.now()
            
            try:
                # Применяем трансформацию
                result = transform.transform(result, context)
                
                # Вычисляем метрики
                metrics = transform.compute_metrics(data, result)
                
                # Записываем в историю
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
                
                transform_result = TransformResult(
                    transform_name=transform_name,
                    input_data=data,
                    output_data=result,
                    metrics=metrics,
                    execution_time_ms=execution_time,
                )
                
                self.history.append(transform_result)
                
                # Проверяем, достигли ли target stealth
                if self.config.adaptive:
                    stealth = metrics.get("stealth_score", 0.0)
                    if stealth >= self.config.target_stealth:
                        break
            
            except Exception as e:
                # Если трансформация не удалась, пропускаем
                continue
        
        return result
    
    def optimize_pipeline(self, transform_names: List[str]) -> List[str]:
        """
        Оптимизация порядка трансформаций.
        
        Использует эвристики для определения оптимального порядка:
        - Сначала быстрые трансформации
        - Потом трансформации с высоким stealth gain
        - В конце дорогие трансформации
        
        Args:
            transform_names: Список трансформаций
        
        Returns:
            Оптимизированный список
        """
        # Упрощённая эвристика
        # В реальности здесь будет ML-based optimization
        
        # Приоритеты трансформаций
        priorities = {
            "fractal": 1,  # Быстрая, эффективная
            "ergodic": 2,  # Быстрая, хороший stealth
            "chaotic": 3,  # Средняя скорость
            "tropical": 4,  # Средняя скорость
            "padic": 5,  # Средняя скорость
            "cluster": 6,  # Медленная
            "topological": 7,  # Медленная, но эффективная
            "mirror": 8,  # Медленная
            "anabelian": 9,  # Очень медленная
        }
        
        # Сортируем по приоритету
        sorted_transforms = sorted(
            transform_names,
            key=lambda x: priorities.get(x, 10)
        )
        
        return sorted_transforms
    
    def verify_stealth(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, Any]:
        """
        Проверка достижения target stealth.
        
        Args:
            original: Исходные данные
            transformed: Трансформированные данные
        
        Returns:
            Stealth verification result
        """
        # Вычисляем aggregate stealth score
        stealth_scores = []
        
        for transform_result in self.history:
            stealth = transform_result.metrics.get("stealth_score", 0.0)
            stealth_scores.append(stealth)
        
        if stealth_scores:
            avg_stealth = sum(stealth_scores) / len(stealth_scores)
            max_stealth = max(stealth_scores)
        else:
            avg_stealth = 0.0
            max_stealth = 0.0
        
        return {
            "target_stealth": self.config.target_stealth,
            "achieved_stealth": avg_stealth,
            "max_stealth": max_stealth,
            "target_achieved": avg_stealth >= self.config.target_stealth,
            "num_transforms_applied": len(self.history),
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику Math Director."""
        total_transforms = len(self.history)
        
        transform_counts = {}
        for result in self.history:
            name = result.transform_name
            transform_counts[name] = transform_counts.get(name, 0) + 1
        
        avg_execution_time = (
            sum(r.execution_time_ms for r in self.history) / total_transforms
            if total_transforms > 0 else 0
        )
        
        return {
            "total_transforms_applied": total_transforms,
            "transform_counts": transform_counts,
            "avg_execution_time_ms": avg_execution_time,
            "current_strategy": self.current_strategy.value if self.current_strategy else None,
            "registered_transforms": list(self.transforms.keys()),
        }
    
    def reset(self):
        """Сброс истории."""
        self.history = []
        self.current_strategy = None
