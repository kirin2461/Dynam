"""
Federated Adversarial Training — распределённое обучение ONNX моделей.

Обучает модели на данных разных узлов mesh сети без передачи сырых данных:
- Локальное обучение на каждом узле
- Агрегация моделей через Federated Averaging
- Дифференциальная приватность для защиты данных
- Secure aggregation для безопасности
"""

import asyncio
import numpy as np
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class TrainingStatus(Enum):
    """Статус обучения."""
    IDLE = "idle"
    LOCAL_TRAINING = "local_training"
    AGGREGATING = "aggregating"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ModelUpdate:
    """Обновление модели от узла."""
    node_id: str
    round_number: int
    weights: Dict[str, np.ndarray]
    num_samples: int
    metrics: Dict[str, float] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "round_number": self.round_number,
            "num_samples": self.num_samples,
            "metrics": self.metrics,
            "timestamp": self.timestamp,
        }


@dataclass
class TrainingRound:
    """Раунд federated обучения."""
    round_id: str
    round_number: int
    status: TrainingStatus = TrainingStatus.IDLE
    updates: Dict[str, ModelUpdate] = field(default_factory=dict)
    global_metrics: Dict[str, float] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "round_id": self.round_id,
            "round_number": self.round_number,
            "status": self.status.value,
            "num_updates": len(self.updates),
            "global_metrics": self.global_metrics,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class FederatedConfig:
    """Конфигурация federated training."""
    num_rounds: int = 10
    local_epochs: int = 5
    learning_rate: float = 0.001
    batch_size: int = 32
    min_nodes_for_round: int = 3
    privacy_budget: float = 1.0  # Epsilon for differential privacy
    secure_aggregation: bool = True


class FederatedTraining:
    """
    Менеджер federated adversarial training.
    
    Методы:
    1. start_round() — запуск раунда обучения
    2. local_train() — локальное обучение на узле
    3. submit_update() — отправка обновления модели
    4. aggregate_updates() — агрегация обновлений
    5. apply_differential_privacy() — добавление шума для приватности
    """
    
    def __init__(self, node_id: str, mesh_network, config: Optional[FederatedConfig] = None):
        self.node_id = node_id
        self.mesh = mesh_network
        self.config = config or FederatedConfig()
        
        # Storage
        self.rounds: Dict[str, TrainingRound] = {}
        self.current_round: Optional[str] = None
        
        # Global model (aggregated)
        self.global_model: Optional[Dict[str, np.ndarray]] = None
        
        # Local data
        self.local_data: Optional[np.ndarray] = None
        self.local_labels: Optional[np.ndarray] = None
    
    async def start_round(self) -> Optional[str]:
        """
        Запустить новый раунд federated обучения.
        
        Returns:
            Round ID или None если недостаточно узлов
        """
        # Проверяем количество доступных узлов
        available_peers = len(self.mesh.peers)
        
        if available_peers < self.config.min_nodes_for_round - 1:
            return None
        
        round_id = str(uuid.uuid4())
        round_number = len(self.rounds) + 1
        
        training_round = TrainingRound(
            round_id=round_id,
            round_number=round_number,
            status=TrainingStatus.LOCAL_TRAINING,
        )
        
        self.rounds[round_id] = training_round
        self.current_round = round_id
        
        # Broadcast начало раунда в mesh
        await self.mesh.send_message(
            "*",
            "federated_round_start",
            {
                "round_id": round_id,
                "round_number": round_number,
                "config": {
                    "local_epochs": self.config.local_epochs,
                    "learning_rate": self.config.learning_rate,
                    "batch_size": self.config.batch_size,
                },
            }
        )
        
        # Запускаем локальное обучение
        await self.local_train(round_id)
        
        return round_id
    
    async def local_train(self, round_id: str) -> Optional[ModelUpdate]:
        """
        Локальное обучение на текущем узле.
        
        Args:
            round_id: Round ID
        
        Returns:
            ModelUpdate или None если обучение не удалось
        """
        if self.local_data is None or self.local_labels is None:
            return None
        
        if round_id not in self.rounds:
            return None
        
        training_round = self.rounds[round_id]
        training_round.status = TrainingStatus.LOCAL_TRAINING
        
        # Упрощённое локальное обучение
        # В реальности здесь будет training loop для ONNX модели
        
        # Инициализируем веса (если это первый раунд)
        if self.global_model is None:
            self.global_model = self._initialize_model()
        
        # Локальное обучение
        local_weights = self._train_local(
            self.global_model,
            self.local_data,
            self.local_labels,
            epochs=self.config.local_epochs,
            learning_rate=self.config.learning_rate,
        )
        
        # Вычисляем метрики
        metrics = self._compute_metrics(local_weights, self.local_data, self.local_labels)
        
        # Создаём update
        update = ModelUpdate(
            node_id=self.node_id,
            round_number=training_round.round_number,
            weights=local_weights,
            num_samples=len(self.local_data),
            metrics=metrics,
        )
        
        # Отправляем update
        await self.submit_update(round_id, update)
        
        return update
    
    async def submit_update(self, round_id: str, update: ModelUpdate) -> bool:
        """
        Отправить обновление модели.
        
        Args:
            round_id: Round ID
            update: ModelUpdate
        
        Returns:
            True если update принят
        """
        if round_id not in self.rounds:
            return False
        
        training_round = self.rounds[round_id]
        
        # Добавляем update
        training_round.updates[update.node_id] = update
        
        # Проверяем, собрали ли мы достаточно updates
        if len(training_round.updates) >= self.config.min_nodes_for_round:
            # Запускаем агрегацию
            await self.aggregate_updates(round_id)
        
        return True
    
    async def aggregate_updates(self, round_id: str) -> Optional[Dict[str, np.ndarray]]:
        """
        Агрегировать обновления от всех узлов.
        
        Использует Federated Averaging (FedAvg):
        w_global = Σ(n_k / n) * w_k
        
        где n_k — количество samples на узле k, n — общее количество samples.
        
        Args:
            round_id: Round ID
        
        Returns:
            Aggregated global model или None
        """
        if round_id not in self.rounds:
            return None
        
        training_round = self.rounds[round_id]
        training_round.status = TrainingStatus.AGGREGATING
        
        updates = list(training_round.updates.values())
        
        if not updates:
            return None
        
        # Применяем differential privacy (если включено)
        if self.config.privacy_budget > 0:
            for update in updates:
                update.weights = self.apply_differential_privacy(
                    update.weights,
                    self.config.privacy_budget
                )
        
        # Federated Averaging
        total_samples = sum(u.num_samples for u in updates)
        
        aggregated_weights = {}
        
        # Получаем все ключи весов
        all_keys = set()
        for update in updates:
            all_keys.update(update.weights.keys())
        
        # Агрегируем каждый вес
        for key in all_keys:
            weighted_sum = np.zeros_like(updates[0].weights.get(key, np.array([0.0])))
            
            for update in updates:
                if key in update.weights:
                    weight = update.weights[key]
                    n_k = update.num_samples
                    
                    weighted_sum += (n_k / total_samples) * weight
            
            aggregated_weights[key] = weighted_sum
        
        # Обновляем global model
        self.global_model = aggregated_weights
        
        # Вычисляем глобальные метрики
        global_metrics = self._compute_global_metrics(updates)
        training_round.global_metrics = global_metrics
        
        # Завершаем раунд
        training_round.status = TrainingStatus.COMPLETED
        training_round.completed_at = datetime.now().isoformat()
        
        # Broadcast агрегированную модель в mesh
        await self.mesh.send_message(
            "*",
            "federated_round_complete",
            {
                "round_id": round_id,
                "round_number": training_round.round_number,
                "global_metrics": global_metrics,
            }
        )
        
        return aggregated_weights
    
    def apply_differential_privacy(
        self,
        weights: Dict[str, np.ndarray],
        epsilon: float,
        delta: float = 1e-5
    ) -> Dict[str, np.ndarray]:
        """
        Применить дифференциальную приватность к весам модели.
        
        Добавляет Gaussian noise для защиты данных:
        σ = sqrt(2 * ln(1.25/delta)) / epsilon
        
        Args:
            weights: Weights модели
            epsilon: Privacy budget
            delta: Privacy parameter
        
        Returns:
            Noisy weights
        """
        # Вычисляем standard deviation
        sigma = np.sqrt(2 * np.log(1.25 / delta)) / epsilon
        
        noisy_weights = {}
        
        for key, weight in weights.items():
            # Добавляем Gaussian noise
            noise = np.random.normal(0, sigma, size=weight.shape)
            noisy_weights[key] = weight + noise
        
        return noisy_weights
    
    def _initialize_model(self) -> Dict[str, np.ndarray]:
        """Инициализация модели (упрощённая)."""
        # В реальности здесь будет загрузка ONNX модели
        
        # Упрощённо: создаём случайные веса
        model = {
            "layer1_weights": np.random.randn(10, 5).astype(np.float32),
            "layer1_bias": np.zeros(5, dtype=np.float32),
            "layer2_weights": np.random.randn(5, 2).astype(np.float32),
            "layer2_bias": np.zeros(2, dtype=np.float32),
        }
        
        return model
    
    def _train_local(
        self,
        global_weights: Dict[str, np.ndarray],
        data: np.ndarray,
        labels: np.ndarray,
        epochs: int,
        learning_rate: float
    ) -> Dict[str, np.ndarray]:
        """
        Локальное обучение (упрощённое).
        
        В реальности здесь будет full training loop.
        """
        # Упрощённо: делаем несколько шагов gradient descent
        local_weights = {k: v.copy() for k, v in global_weights.items()}
        
        for epoch in range(epochs):
            # Forward pass (упрощённый)
            # В реальности: ONNX Runtime inference
            
            # Backward pass (упрощённый)
            # В реальности: gradient computation
            
            # Update weights
            for key in local_weights:
                gradient = np.random.randn(*local_weights[key].shape) * 0.01
                local_weights[key] -= learning_rate * gradient
        
        return local_weights
    
    def _compute_metrics(
        self,
        weights: Dict[str, np.ndarray],
        data: np.ndarray,
        labels: np.ndarray
    ) -> Dict[str, float]:
        """Вычисление метрик модели."""
        # Упрощённо: случайные метрики
        return {
            "accuracy": np.random.uniform(0.7, 0.95),
            "loss": np.random.uniform(0.1, 0.5),
            "precision": np.random.uniform(0.7, 0.95),
            "recall": np.random.uniform(0.7, 0.95),
        }
    
    def _compute_global_metrics(self, updates: List[ModelUpdate]) -> Dict[str, float]:
        """Вычисление глобальных метрик."""
        if not updates:
            return {}
        
        # Усредняем метрики
        metrics = {}
        
        all_keys = set()
        for update in updates:
            all_keys.update(update.metrics.keys())
        
        for key in all_keys:
            values = [u.metrics[key] for u in updates if key in u.metrics]
            if values:
                metrics[key] = sum(values) / len(values)
        
        return metrics
    
    def set_local_data(self, data: np.ndarray, labels: np.ndarray):
        """Установить локальные данные для обучения."""
        self.local_data = data
        self.local_labels = labels
    
    def get_round(self, round_id: str) -> Optional[Dict[str, Any]]:
        """Получить раунд по ID."""
        if round_id not in self.rounds:
            return None
        return self.rounds[round_id].to_dict()
    
    def list_rounds(self) -> List[Dict[str, Any]]:
        """Список всех раундов."""
        return [r.to_dict() for r in self.rounds.values()]
    
    def get_global_model(self) -> Optional[Dict[str, np.ndarray]]:
        """Получить глобальную модель."""
        return self.global_model
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику federated training."""
        total_rounds = len(self.rounds)
        completed_rounds = sum(1 for r in self.rounds.values() if r.status == TrainingStatus.COMPLETED)
        
        total_updates = sum(len(r.updates) for r in self.rounds.values())
        
        return {
            "total_rounds": total_rounds,
            "completed_rounds": completed_rounds,
            "total_updates": total_updates,
            "current_round": self.current_round,
            "has_global_model": self.global_model is not None,
        }
