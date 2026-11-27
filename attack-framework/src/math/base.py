"""
Base classes for mathematical transformations.

Все математические модули наследуются от MathTransform.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import numpy as np


@dataclass
class MathContext:
    """Контекст для математической трансформации."""
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    features: Optional[np.ndarray] = None
    parameters: Dict[str, Any] = field(default_factory=dict)


class MathTransform(ABC):
    """
    Базовый класс для всех математических трансформаций.
    
    Каждая трансформация:
    1. Принимает входные данные (трафик, features)
    2. Применяет математическую операцию
    3. Возвращает трансформированные данные
    4. Предоставляет метрики качества
    """
    
    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self._parameters: Dict[str, Any] = {}
    
    @abstractmethod
    def transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Применить трансформацию к данным.
        
        Args:
            data: Входные данные (feature vector, time series, etc.)
            context: Контекст трансформации
        
        Returns:
            Трансформированные данные
        """
        pass
    
    @abstractmethod
    def inverse_transform(self, data: np.ndarray, context: MathContext) -> np.ndarray:
        """
        Обратная трансформация (если применимо).
        
        Args:
            data: Трансформированные данные
            context: Контекст трансформации
        
        Returns:
            Восстановленные данные
        """
        pass
    
    @abstractmethod
    def compute_metrics(self, original: np.ndarray, transformed: np.ndarray) -> Dict[str, float]:
        """
        Вычислить метрики качества трансформации.
        
        Args:
            original: Исходные данные
            transformed: Трансформированные данные
        
        Returns:
            Словарь с метриками (MSE, correlation, etc.)
        """
        pass
    
    def set_parameters(self, **kwargs):
        """Установить параметры трансформации."""
        self._parameters.update(kwargs)
    
    def get_parameters(self) -> Dict[str, Any]:
        """Получить текущие параметры."""
        return self._parameters.copy()
    
    def validate_input(self, data: np.ndarray) -> bool:
        """Валидация входных данных."""
        if data is None or data.size == 0:
            return False
        return True
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name}, version={self.version})"
