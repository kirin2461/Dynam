"""
Mesh Math Integration — интеграция математических модулей с mesh сетью.

Координирует использование математических трансформаций через mesh:
- Распределение математических задач между узлами
- Агрегация результатов математических вычислений
- Синхронизация параметров математических модулей
- Load balancing для math operations
"""

import asyncio
import numpy as np
import uuid
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from ..math.base import MathTransform, MathContext


class MathTaskStatus(Enum):
    """Статус математической задачи."""
    PENDING = "pending"
    COMPUTING = "computing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class MathTask:
    """Математическая задача для распределённого вычисления."""
    task_id: str
    transform_name: str
    input_data: np.ndarray
    parameters: Dict[str, Any] = field(default_factory=dict)
    assigned_to: str = ""
    status: MathTaskStatus = MathTaskStatus.PENDING
    result: Optional[np.ndarray] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "transform_name": self.transform_name,
            "assigned_to": self.assigned_to,
            "status": self.status.value,
            "metrics": self.metrics,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


@dataclass
class MathAggregation:
    """Результат агрегации математических вычислений."""
    aggregation_id: str
    task_ids: List[str]
    aggregated_result: np.ndarray
    aggregated_metrics: Dict[str, float] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "aggregation_id": self.aggregation_id,
            "num_tasks": len(self.task_ids),
            "aggregated_metrics": self.aggregated_metrics,
            "created_at": self.created_at,
        }


@dataclass
class MeshMathConfig:
    """Конфигурация mesh math integration."""
    max_concurrent_tasks: int = 10
    task_timeout_seconds: int = 60
    aggregation_method: str = "average"  # average, weighted, max, min


class MeshMathIntegration:
    """
    Интеграция математических модулей с mesh сетью.
    
    Методы:
    1. distribute_transform() — распределение трансформации по mesh
    2. compute_distributed() — распределённое вычисление
    3. aggregate_results() — агрегация результатов
    4. sync_parameters() — синхронизация параметров
    """
    
    def __init__(self, node_id: str, mesh_network, config: Optional[MeshMathConfig] = None):
        self.node_id = node_id
        self.mesh = mesh_network
        self.config = config or MeshMathConfig()
        
        # Storage
        self.tasks: Dict[str, MathTask] = {}
        self.aggregations: Dict[str, MathAggregation] = {}
        
        # Registered transforms
        self.transforms: Dict[str, MathTransform] = {}
    
    def register_transform(self, transform: MathTransform):
        """
        Зарегистрировать математическую трансформацию.
        
        Args:
            transform: MathTransform instance
        """
        self.transforms[transform.name] = transform
    
    async def distribute_transform(
        self,
        data: np.ndarray,
        transform_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Распределить математическую трансформацию по mesh сети.
        
        Разбивает данные на чанки и отправляет разным узлам.
        
        Args:
            data: Входные данные
            transform_name: Имя зарегистрированной трансформации
            parameters: Параметры трансформации
        
        Returns:
            Список task IDs
        """
        if transform_name not in self.transforms:
            raise ValueError(f"Transform {transform_name} not registered")
        
        # Получаем список доступных узлов
        peers = list(self.mesh.peers.keys())
        
        if not peers:
            # Если нет пиров, выполняем локально
            task_id = await self._create_local_task(data, transform_name, parameters)
            return [task_id]
        
        # Разбиваем данные на чанки
        num_chunks = min(len(peers) + 1, self.config.max_concurrent_tasks)
        chunks = np.array_split(data, num_chunks)
        
        task_ids = []
        
        # Создаём задачи для каждого чанка
        for i, chunk in enumerate(chunks):
            if i < len(peers):
                # Отправляем на удалённый узел
                task_id = await self._create_remote_task(
                    chunk,
                    transform_name,
                    parameters,
                    peers[i]
                )
            else:
                # Выполняем локально
                task_id = await self._create_local_task(chunk, transform_name, parameters)
            
            task_ids.append(task_id)
        
        return task_ids
    
    async def compute_distributed(
        self,
        data: np.ndarray,
        transform_name: str,
        parameters: Optional[Dict[str, Any]] = None
    ) -> np.ndarray:
        """
        Распределённое вычисление математической трансформации.
        
        Args:
            data: Входные данные
            transform_name: Имя трансформации
            parameters: Параметры
        
        Returns:
            Результат вычисления
        """
        # Распределяем задачу
        task_ids = await self.distribute_transform(data, transform_name, parameters)
        
        # Ждём завершения всех задач
        results = await self._wait_for_tasks(task_ids)
        
        # Агрегируем результаты
        aggregated = await self.aggregate_results(task_ids)
        
        return aggregated.aggregated_result
    
    async def aggregate_results(self, task_ids: List[str]) -> MathAggregation:
        """
        Агрегировать результаты математических задач.
        
        Args:
            task_ids: Список task IDs
        
        Returns:
            MathAggregation
        """
        # Собираем результаты
        results = []
        all_metrics = {}
        
        for task_id in task_ids:
            if task_id not in self.tasks:
                continue
            
            task = self.tasks[task_id]
            
            if task.status != MathTaskStatus.COMPLETED or task.result is None:
                continue
            
            results.append(task.result)
            
            # Собираем метрики
            for key, value in task.metrics.items():
                if key not in all_metrics:
                    all_metrics[key] = []
                all_metrics[key].append(value)
        
        if not results:
            raise ValueError("No completed tasks to aggregate")
        
        # Агрегируем результаты
        if self.config.aggregation_method == "average":
            aggregated_result = np.mean(results, axis=0)
        elif self.config.aggregation_method == "weighted":
            # Weighted by task metrics (если есть)
            aggregated_result = np.average(results, axis=0)
        elif self.config.aggregation_method == "max":
            aggregated_result = np.max(results, axis=0)
        elif self.config.aggregation_method == "min":
            aggregated_result = np.min(results, axis=0)
        else:
            aggregated_result = np.mean(results, axis=0)
        
        # Агрегируем метрики
        aggregated_metrics = {}
        for key, values in all_metrics.items():
            aggregated_metrics[key] = sum(values) / len(values) if values else 0
        
        # Создаём aggregation
        aggregation_id = str(uuid.uuid4())
        
        aggregation = MathAggregation(
            aggregation_id=aggregation_id,
            task_ids=task_ids,
            aggregated_result=aggregated_result,
            aggregated_metrics=aggregated_metrics,
        )
        
        self.aggregations[aggregation_id] = aggregation
        
        return aggregation
    
    async def sync_parameters(self, transform_name: str) -> bool:
        """
        Синхронизировать параметры математического модуля между узлами.
        
        Args:
            transform_name: Имя трансформации
        
        Returns:
            True если синхронизация успешна
        """
        if transform_name not in self.transforms:
            return False
        
        transform = self.transforms[transform_name]
        parameters = transform.get_parameters()
        
        # Broadcast параметры в mesh
        await self.mesh.send_message(
            "*",
            "math_sync_parameters",
            {
                "transform_name": transform_name,
                "parameters": parameters,
            }
        )
        
        return True
    
    async def _create_local_task(
        self,
        data: np.ndarray,
        transform_name: str,
        parameters: Optional[Dict[str, Any]]
    ) -> str:
        """Создание локальной математической задачи."""
        task_id = str(uuid.uuid4())
        
        task = MathTask(
            task_id=task_id,
            transform_name=transform_name,
            input_data=data,
            parameters=parameters or {},
            assigned_to=self.node_id,
        )
        
        self.tasks[task_id] = task
        
        # Выполняем задачу
        asyncio.create_task(self._execute_task(task_id))
        
        return task_id
    
    async def _create_remote_task(
        self,
        data: np.ndarray,
        transform_name: str,
        parameters: Optional[Dict[str, Any]],
        peer_id: str
    ) -> str:
        """Создание удалённой математической задачи."""
        task_id = str(uuid.uuid4())
        
        task = MathTask(
            task_id=task_id,
            transform_name=transform_name,
            input_data=data,
            parameters=parameters or {},
            assigned_to=peer_id,
        )
        
        self.tasks[task_id] = task
        
        # Отправляем задачу на удалённый узел
        await self.mesh.send_message(
            peer_id,
            "math_task",
            {
                "task_id": task_id,
                "transform_name": transform_name,
                "parameters": parameters or {},
                "data_shape": data.shape,
                "data_dtype": str(data.dtype),
            }
        )
        
        return task_id
    
    async def _execute_task(self, task_id: str):
        """Выполнение математической задачи."""
        if task_id not in self.tasks:
            return
        
        task = self.tasks[task_id]
        task.status = MathTaskStatus.COMPUTING
        
        try:
            # Получаем трансформацию
            if task.transform_name not in self.transforms:
                raise ValueError(f"Transform {task.transform_name} not registered")
            
            transform = self.transforms[task.transform_name]
            
            # Устанавливаем параметры
            if task.parameters:
                transform.set_parameters(**task.parameters)
            
            # Создаём контекст
            context = MathContext(
                target="distributed",
                parameters=task.parameters,
            )
            
            # Выполняем трансформацию
            result = transform.transform(task.input_data, context)
            
            # Вычисляем метрики
            metrics = transform.compute_metrics(task.input_data, result)
            
            # Сохраняем результат
            task.result = result
            task.metrics = metrics
            task.status = MathTaskStatus.COMPLETED
            task.completed_at = datetime.now().isoformat()
            
            # Broadcast завершение в mesh
            await self.mesh.send_message(
                "*",
                "math_task_completed",
                {
                    "task_id": task_id,
                    "metrics": metrics,
                }
            )
        
        except Exception as e:
            task.status = MathTaskStatus.FAILED
            task.metrics = {"error": str(e)}
    
    async def _wait_for_tasks(self, task_ids: List[str], timeout: Optional[int] = None) -> List[np.ndarray]:
        """Ожидание завершения задач."""
        timeout = timeout or self.config.task_timeout_seconds
        
        start_time = datetime.now()
        
        while True:
            # Проверяем статус всех задач
            all_completed = True
            
            for task_id in task_ids:
                if task_id not in self.tasks:
                    continue
                
                task = self.tasks[task_id]
                
                if task.status not in [MathTaskStatus.COMPLETED, MathTaskStatus.FAILED]:
                    all_completed = False
                    break
            
            if all_completed:
                break
            
            # Проверяем timeout
            elapsed = (datetime.now() - start_time).total_seconds()
            if elapsed > timeout:
                break
            
            await asyncio.sleep(0.1)
        
        # Собираем результаты
        results = []
        
        for task_id in task_ids:
            if task_id not in self.tasks:
                continue
            
            task = self.tasks[task_id]
            
            if task.status == MathTaskStatus.COMPLETED and task.result is not None:
                results.append(task.result)
        
        return results
    
    def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Получить задачу по ID."""
        if task_id not in self.tasks:
            return None
        return self.tasks[task_id].to_dict()
    
    def list_tasks(self, status: Optional[MathTaskStatus] = None) -> List[Dict[str, Any]]:
        """Список задач."""
        tasks = []
        
        for task in self.tasks.values():
            if status is None or task.status == status:
                tasks.append(task.to_dict())
        
        return tasks
    
    def get_aggregation(self, aggregation_id: str) -> Optional[Dict[str, Any]]:
        """Получить агрегацию по ID."""
        if aggregation_id not in self.aggregations:
            return None
        return self.aggregations[aggregation_id].to_dict()
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику mesh math integration."""
        total_tasks = len(self.tasks)
        
        status_counts = {}
        for status in MathTaskStatus:
            status_counts[status.value] = sum(1 for t in self.tasks.values() if t.status == status)
        
        return {
            "total_tasks": total_tasks,
            "status_counts": status_counts,
            "registered_transforms": list(self.transforms.keys()),
            "total_aggregations": len(self.aggregations),
        }
