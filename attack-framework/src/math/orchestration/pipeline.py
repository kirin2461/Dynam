"""
Math Pipeline — управление пайплайнами математических трансформаций.

Пайплайн — это последовательность математических трансформаций,
применяемых к данным в определённом порядке с определёнными параметрами.

Функции:
- Создание и сохранение пайплайнов
- Выполнение пайплайнов
- Валидация пайплайнов
- Экспорт/импорт пайплайнов
"""

import json
import numpy as np
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from ..base import MathTransform, MathContext


@dataclass
class PipelineStep:
    """Шаг пайплайна."""
    transform_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    order: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "transform_name": self.transform_name,
            "parameters": self.parameters,
            "enabled": self.enabled,
            "order": self.order,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PipelineStep':
        return cls(
            transform_name=data["transform_name"],
            parameters=data.get("parameters", {}),
            enabled=data.get("enabled", True),
            order=data.get("order", 0),
        )


@dataclass
class MathPipeline:
    """Математический пайплайн."""
    name: str
    description: str = ""
    steps: List[PipelineStep] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    version: str = "1.0.0"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MathPipeline':
        steps = [PipelineStep.from_dict(s) for s in data.get("steps", [])]
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            steps=steps,
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat()),
            version=data.get("version", "1.0.0"),
        )
    
    def add_step(self, transform_name: str, parameters: Optional[Dict[str, Any]] = None, enabled: bool = True) -> int:
        """Добавить шаг в пайплайн."""
        step = PipelineStep(
            transform_name=transform_name,
            parameters=parameters or {},
            enabled=enabled,
            order=len(self.steps),
        )
        self.steps.append(step)
        self.updated_at = datetime.now().isoformat()
        return step.order
    
    def remove_step(self, order: int) -> bool:
        """Удалить шаг из пайплайна."""
        for i, step in enumerate(self.steps):
            if step.order == order:
                self.steps.pop(i)
                # Обновляем order для оставшихся шагов
                for j, s in enumerate(self.steps):
                    s.order = j
                self.updated_at = datetime.now().isoformat()
                return True
        return False
    
    def enable_step(self, order: int) -> bool:
        """Включить шаг."""
        for step in self.steps:
            if step.order == order:
                step.enabled = True
                self.updated_at = datetime.now().isoformat()
                return True
        return False
    
    def disable_step(self, order: int) -> bool:
        """Отключить шаг."""
        for step in self.steps:
            if step.order == order:
                step.enabled = False
                self.updated_at = datetime.now().isoformat()
                return True
        return False
    
    def reorder_steps(self, new_order: List[int]) -> bool:
        """Изменить порядок шагов."""
        if len(new_order) != len(self.steps):
            return False
        
        # Проверяем, что все order валидны
        orders = [s.order for s in self.steps]
        if set(new_order) != set(orders):
            return False
        
        # Создаём временный список
        temp_steps = {s.order: s for s in self.steps}
        
        # Обновляем order
        for new_idx, old_order in enumerate(new_order):
            temp_steps[old_order].order = new_idx
        
        # Сортируем по новому order
        self.steps = sorted(self.steps, key=lambda s: s.order)
        self.updated_at = datetime.now().isoformat()
        
        return True


class PipelineManager:
    """
    Менеджер пайплайнов.
    
    Методы:
    1. create_pipeline() — создание пайплайна
    2. execute_pipeline() — выполнение пайплайна
    3. save_pipeline() — сохранение пайплайна
    4. load_pipeline() — загрузка пайплайна
    5. validate_pipeline() — валидация пайплайна
    """
    
    def __init__(self, storage_dir: str = "pipelines"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Загруженные пайплайны
        self.pipelines: Dict[str, MathPipeline] = {}
    
    def create_pipeline(self, name: str, description: str = "") -> MathPipeline:
        """Создать новый пайплайн."""
        pipeline = MathPipeline(
            name=name,
            description=description,
        )
        self.pipelines[name] = pipeline
        return pipeline
    
    def execute_pipeline(
        self,
        pipeline_name: str,
        data: np.ndarray,
        transforms: Dict[str, MathTransform],
        context: MathContext
    ) -> np.ndarray:
        """
        Выполнить пайплайн.
        
        Args:
            pipeline_name: Имя пайплайна
            data: Входные данные
            transforms: Доступные трансформации
            context: Контекст выполнения
        
        Returns:
            Трансформированные данные
        """
        if pipeline_name not in self.pipelines:
            raise ValueError(f"Pipeline {pipeline_name} not found")
        
        pipeline = self.pipelines[pipeline_name]
        
        # Валидация
        is_valid, errors = self.validate_pipeline(pipeline, transforms)
        if not is_valid:
            raise ValueError(f"Pipeline validation failed: {errors}")
        
        # Выполняем шаги
        result = data.copy()
        
        # Сортируем шаги по order
        sorted_steps = sorted(pipeline.steps, key=lambda s: s.order)
        
        for step in sorted_steps:
            if not step.enabled:
                continue
            
            if step.transform_name not in transforms:
                continue
            
            transform = transforms[step.transform_name]
            
            # Устанавливаем параметры
            if step.parameters:
                transform.set_parameters(**step.parameters)
            
            # Применяем трансформацию
            result = transform.transform(result, context)
        
        return result
    
    def save_pipeline(self, pipeline_name: str) -> str:
        """
        Сохранить пайплайн в файл.
        
        Args:
            pipeline_name: Имя пайплайна
        
        Returns:
            Путь к файлу
        """
        if pipeline_name not in self.pipelines:
            raise ValueError(f"Pipeline {pipeline_name} not found")
        
        pipeline = self.pipelines[pipeline_name]
        
        # Сохраняем в JSON
        file_path = self.storage_dir / f"{pipeline_name}.json"
        
        with open(file_path, 'w') as f:
            json.dump(pipeline.to_dict(), f, indent=2)
        
        return str(file_path)
    
    def load_pipeline(self, file_path: str) -> MathPipeline:
        """
        Загрузить пайплайн из файла.
        
        Args:
            file_path: Путь к файлу
        
        Returns:
            Загруженный пайплайн
        """
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        pipeline = MathPipeline.from_dict(data)
        self.pipelines[pipeline.name] = pipeline
        
        return pipeline
    
    def validate_pipeline(
        self,
        pipeline: MathPipeline,
        transforms: Dict[str, MathTransform]
    ) -> tuple[bool, List[str]]:
        """
        Валидация пайплайна.
        
        Args:
            pipeline: Пайплайн для валидации
            transforms: Доступные трансформации
        
        Returns:
            (is_valid, errors)
        """
        errors = []
        
        if not pipeline.steps:
            errors.append("Pipeline has no steps")
            return False, errors
        
        # Проверяем, что все трансформации существуют
        for step in pipeline.steps:
            if step.transform_name not in transforms:
                errors.append(f"Transform {step.transform_name} not found")
        
        # Проверяем order
        orders = [s.order for s in pipeline.steps]
        if len(orders) != len(set(orders)):
            errors.append("Duplicate step orders")
        
        if orders != list(range(len(orders))):
            errors.append("Step orders are not sequential")
        
        return len(errors) == 0, errors
    
    def list_pipelines(self) -> List[Dict[str, Any]]:
        """Список всех пайплайнов."""
        return [p.to_dict() for p in self.pipelines.values()]
    
    def get_pipeline(self, name: str) -> Optional[MathPipeline]:
        """Получить пайплайн по имени."""
        return self.pipelines.get(name)
    
    def delete_pipeline(self, name: str) -> bool:
        """Удалить пайплайн."""
        if name not in self.pipelines:
            return False
        
        del self.pipelines[name]
        
        # Удаляем файл если есть
        file_path = self.storage_dir / f"{name}.json"
        if file_path.exists():
            file_path.unlink()
        
        return True
    
    def export_pipeline(self, name: str) -> str:
        """Экспорт пайплайна в JSON строку."""
        if name not in self.pipelines:
            raise ValueError(f"Pipeline {name} not found")
        
        pipeline = self.pipelines[name]
        return json.dumps(pipeline.to_dict(), indent=2)
    
    def import_pipeline(self, json_str: str) -> MathPipeline:
        """Импорт пайплайна из JSON строки."""
        data = json.loads(json_str)
        pipeline = MathPipeline.from_dict(data)
        self.pipelines[pipeline.name] = pipeline
        return pipeline
