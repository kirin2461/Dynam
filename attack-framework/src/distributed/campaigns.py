"""
Distributed Attack Campaigns — распределённые атаки через mesh сеть.

Координирует атаки между несколькими узлами mesh сети:
- Распределение задач между узлами
- Консенсус по целям
- Агрегация результатов
- Load balancing
"""

import asyncio
import uuid
from typing import Dict, Any, Optional, List, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CampaignStatus(Enum):
    """Статус кампании."""
    PENDING = "pending"
    VOTING = "voting"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskStatus(Enum):
    """Статус задачи."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AttackTask:
    """Задача в распределённой кампании."""
    task_id: str
    campaign_id: str
    assigned_to: str
    attack_type: str
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "campaign_id": self.campaign_id,
            "assigned_to": self.assigned_to,
            "attack_type": self.attack_type,
            "target": self.target,
            "parameters": self.parameters,
            "status": self.status.value,
            "result": self.result,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


@dataclass
class DistributedCampaign:
    """Распределённая кампания."""
    campaign_id: str
    target: str
    attack_types: List[str]
    initiated_by: str
    status: CampaignStatus = CampaignStatus.PENDING
    votes: Dict[str, bool] = field(default_factory=dict)
    tasks: Dict[str, AttackTask] = field(default_factory=dict)
    results: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target": self.target,
            "attack_types": self.attack_types,
            "initiated_by": self.initiated_by,
            "status": self.status.value,
            "votes": self.votes,
            "tasks": {k: v.to_dict() for k, v in self.tasks.items()},
            "results": self.results,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


@dataclass
class CampaignConfig:
    """Конфигурация distributed campaigns."""
    min_votes_for_approval: int = 3
    voting_timeout_minutes: int = 10
    task_timeout_minutes: int = 30
    max_concurrent_tasks: int = 10


class DistributedCampaigns:
    """
    Менеджер распределённых кампаний.
    
    Методы:
    1. propose_campaign() — предложение кампании
    2. vote_on_campaign() — голосование по кампании
    3. start_campaign() — запуск кампании
    4. assign_task() — назначение задачи
    5. complete_task() — завершение задачи
    6. aggregate_results() — агрегация результатов
    """
    
    def __init__(self, node_id: str, mesh_network, config: Optional[CampaignConfig] = None):
        self.node_id = node_id
        self.mesh = mesh_network
        self.config = config or CampaignConfig()
        
        # Storage
        self.campaigns: Dict[str, DistributedCampaign] = {}
        
        # Known peers
        self.known_peers: Set[str] = set()
    
    async def propose_campaign(
        self,
        target: str,
        attack_types: List[str],
        parameters: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Предложить распределённую кампанию.
        
        Args:
            target: Цель атаки
            attack_types: Список типов атак
            parameters: Дополнительные параметры
        
        Returns:
            Campaign ID
        """
        campaign_id = str(uuid.uuid4())
        
        campaign = DistributedCampaign(
            campaign_id=campaign_id,
            target=target,
            attack_types=attack_types,
            initiated_by=self.node_id,
        )
        
        # Инициатор автоматически голосует "за"
        campaign.votes[self.node_id] = True
        campaign.status = CampaignStatus.VOTING
        
        self.campaigns[campaign_id] = campaign
        
        # Broadcast предложение в mesh
        await self.mesh.send_message(
            "*",
            "campaign_proposal",
            {
                "campaign_id": campaign_id,
                "target": target,
                "attack_types": attack_types,
                "initiated_by": self.node_id,
                "parameters": parameters or {},
            }
        )
        
        return campaign_id
    
    async def vote_on_campaign(self, campaign_id: str, approve: bool) -> bool:
        """
        Голосовать по кампании.
        
        Args:
            campaign_id: Campaign ID
            approve: True для одобрения, False для отклонения
        
        Returns:
            True если голосование успешно
        """
        if campaign_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[campaign_id]
        
        if campaign.status != CampaignStatus.VOTING:
            return False
        
        # Записываем голос
        campaign.votes[self.node_id] = approve
        
        # Проверяем, набрано ли достаточно голосов
        approve_count = sum(1 for v in campaign.votes.values() if v)
        reject_count = sum(1 for v in campaign.votes.values() if not v)
        
        # Если набрано достаточно голосов за
        if approve_count >= self.config.min_votes_for_approval:
            campaign.status = CampaignStatus.APPROVED
            
            # Автоматически запускаем кампанию
            await self.start_campaign(campaign_id)
        
        # Если набрано достаточно голосов против
        elif reject_count >= self.config.min_votes_for_approval:
            campaign.status = CampaignStatus.REJECTED
        
        # Broadcast голос в mesh
        await self.mesh.send_message(
            "*",
            "campaign_vote",
            {
                "campaign_id": campaign_id,
                "voter": self.node_id,
                "approve": approve,
            }
        )
        
        return True
    
    async def start_campaign(self, campaign_id: str) -> bool:
        """
        Запустить кампанию.
        
        Args:
            campaign_id: Campaign ID
        
        Returns:
            True если кампания запущена
        """
        if campaign_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[campaign_id]
        
        if campaign.status not in [CampaignStatus.APPROVED, CampaignStatus.PENDING]:
            return False
        
        campaign.status = CampaignStatus.RUNNING
        campaign.started_at = datetime.now().isoformat()
        
        # Разбиваем кампанию на задачи
        await self._create_tasks(campaign)
        
        # Назначаем задачи узлам
        await self._assign_tasks(campaign)
        
        # Broadcast запуск в mesh
        await self.mesh.send_message(
            "*",
            "campaign_started",
            {
                "campaign_id": campaign_id,
                "target": campaign.target,
                "tasks": [t.to_dict() for t in campaign.tasks.values()],
            }
        )
        
        return True
    
    async def _create_tasks(self, campaign: DistributedCampaign):
        """Создание задач для кампании."""
        # Создаём задачу для каждого типа атаки
        for attack_type in campaign.attack_types:
            task_id = str(uuid.uuid4())
            
            task = AttackTask(
                task_id=task_id,
                campaign_id=campaign.campaign_id,
                assigned_to="",  # Будет назначено позже
                attack_type=attack_type,
                target=campaign.target,
            )
            
            campaign.tasks[task_id] = task
    
    async def _assign_tasks(self, campaign: DistributedCampaign):
        """Назначение задач узлам mesh."""
        # Получаем список доступных узлов
        peers = list(self.mesh.peers.keys())
        
        if not peers:
            # Если нет пиров, назначаем все задачи себе
            for task in campaign.tasks.values():
                task.assigned_to = self.node_id
                task.status = TaskStatus.ASSIGNED
            return
        
        # Load balancing: round-robin
        peer_idx = 0
        for task in campaign.tasks.values():
            task.assigned_to = peers[peer_idx % len(peers)]
            task.status = TaskStatus.ASSIGNED
            peer_idx += 1
    
    async def assign_task(self, campaign_id: str, task_id: str, peer_id: str) -> bool:
        """
        Назначить задачу конкретному узлу.
        
        Args:
            campaign_id: Campaign ID
            task_id: Task ID
            peer_id: Peer ID
        
        Returns:
            True если задача назначена
        """
        if campaign_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[campaign_id]
        
        if task_id not in campaign.tasks:
            return False
        
        task = campaign.tasks[task_id]
        task.assigned_to = peer_id
        task.status = TaskStatus.ASSIGNED
        
        # Отправляем задачу назначенному узлу
        await self.mesh.send_message(
            peer_id,
            "task_assignment",
            {
                "campaign_id": campaign_id,
                "task_id": task_id,
                "task": task.to_dict(),
            }
        )
        
        return True
    
    async def complete_task(self, campaign_id: str, task_id: str, result: Dict[str, Any]) -> bool:
        """
        Завершить задачу.
        
        Args:
            campaign_id: Campaign ID
            task_id: Task ID
            result: Результат задачи
        
        Returns:
            True если задача завершена
        """
        if campaign_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[campaign_id]
        
        if task_id not in campaign.tasks:
            return False
        
        task = campaign.tasks[task_id]
        task.result = result
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.now().isoformat()
        
        # Добавляем результат в кампанию
        campaign.results.append({
            "task_id": task_id,
            "assigned_to": task.assigned_to,
            "result": result,
        })
        
        # Проверяем, все ли задачи завершены
        all_completed = all(t.status == TaskStatus.COMPLETED for t in campaign.tasks.values())
        
        if all_completed:
            await self._complete_campaign(campaign_id)
        
        # Broadcast завершение задачи в mesh
        await self.mesh.send_message(
            "*",
            "task_completed",
            {
                "campaign_id": campaign_id,
                "task_id": task_id,
                "result": result,
            }
        )
        
        return True
    
    async def _complete_campaign(self, campaign_id: str):
        """Завершение кампании."""
        campaign = self.campaigns[campaign_id]
        
        campaign.status = CampaignStatus.COMPLETED
        campaign.completed_at = datetime.now().isoformat()
        
        # Агрегируем результаты
        aggregated = await self.aggregate_results(campaign_id)
        
        # Broadcast завершение кампании в mesh
        await self.mesh.send_message(
            "*",
            "campaign_completed",
            {
                "campaign_id": campaign_id,
                "aggregated_results": aggregated,
            }
        )
    
    async def aggregate_results(self, campaign_id: str) -> Dict[str, Any]:
        """
        Агрегировать результаты кампании.
        
        Args:
            campaign_id: Campaign ID
        
        Returns:
            Aggregated results
        """
        if campaign_id not in self.campaigns:
            return {}
        
        campaign = self.campaigns[campaign_id]
        
        # Упрощённая агрегация: усредняем метрики
        metrics = {}
        
        for result in campaign.results:
            task_result = result.get("result", {})
            
            for key, value in task_result.items():
                if isinstance(value, (int, float)):
                    if key not in metrics:
                        metrics[key] = []
                    metrics[key].append(value)
        
        # Вычисляем средние
        aggregated = {}
        for key, values in metrics.items():
            aggregated[key] = sum(values) / len(values) if values else 0
        
        # Добавляем общую статистику
        aggregated["total_tasks"] = len(campaign.tasks)
        aggregated["completed_tasks"] = sum(1 for t in campaign.tasks.values() if t.status == TaskStatus.COMPLETED)
        aggregated["success_rate"] = aggregated.get("success_rate", 0)
        
        return aggregated
    
    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Получить кампанию по ID."""
        if campaign_id not in self.campaigns:
            return None
        return self.campaigns[campaign_id].to_dict()
    
    def list_campaigns(self, status: Optional[CampaignStatus] = None) -> List[Dict[str, Any]]:
        """
        Список кампаний.
        
        Args:
            status: Фильтр по статусу (опционально)
        
        Returns:
            List of campaign dicts
        """
        campaigns = []
        
        for campaign in self.campaigns.values():
            if status is None or campaign.status == status:
                campaigns.append(campaign.to_dict())
        
        return campaigns
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику distributed campaigns."""
        total = len(self.campaigns)
        
        status_counts = {}
        for status in CampaignStatus:
            status_counts[status.value] = sum(1 for c in self.campaigns.values() if c.status == status)
        
        total_tasks = sum(len(c.tasks) for c in self.campaigns.values())
        completed_tasks = sum(
            sum(1 for t in c.tasks.values() if t.status == TaskStatus.COMPLETED)
            for c in self.campaigns.values()
        )
        
        return {
            "total_campaigns": total,
            "status_counts": status_counts,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "completion_rate": completed_tasks / total_tasks if total_tasks > 0 else 0,
        }
