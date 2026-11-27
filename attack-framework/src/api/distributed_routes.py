"""
Distributed API routes — REST API для distributed модулей.

Endpoints для:
- Invitation System
- Distributed Campaigns
- Federated Training
- Mesh Math Integration
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import numpy as np

from ..distributed.invitation import InvitationSystem, InvitationConfig
from ..distributed.campaigns import DistributedCampaigns, CampaignConfig
from ..distributed.federated import FederatedTraining, FederatedConfig
from ..distributed.mesh_math import MeshMathIntegration, MeshMathConfig


# ─── Pydantic Models ────────────────────────────────────────────────────

class InvitationRequest(BaseModel):
    expires_hours: Optional[int] = None
    max_uses: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CampaignRequest(BaseModel):
    target: str
    attack_types: List[str]
    parameters: Dict[str, Any] = Field(default_factory=dict)


class FederatedTrainRequest(BaseModel):
    data: List[List[float]]
    labels: List[int]


# ─── Route Registration ─────────────────────────────────────────────────

def register_distributed_routes(app: FastAPI, node_id: str, mesh_network):
    """Register all distributed module routes."""
    
    # Инициализация distributed модулей
    invitation_system = InvitationSystem(node_id)
    distributed_campaigns = DistributedCampaigns(node_id, mesh_network)
    federated_training = FederatedTraining(node_id, mesh_network)
    mesh_math = MeshMathIntegration(node_id, mesh_network)
    
    # ═══════════════════════════════════════════════════════════════
    # INVITATION SYSTEM
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/distributed/invitation/create")
    async def invitation_create(request: InvitationRequest):
        """Создать приглашение."""
        try:
            invitation = invitation_system.create_invitation(
                expires_hours=request.expires_hours,
                max_uses=request.max_uses,
                metadata=request.metadata
            )
            return invitation.to_dict()
        except RuntimeError as e:
            raise HTTPException(status_code=429, detail=str(e))
    
    @app.get("/api/distributed/invitation/validate/{code}")
    async def invitation_validate(code: str):
        """Валидация приглашения."""
        is_valid = invitation_system.validate_invitation(code)
        return {"is_valid": is_valid}
    
    @app.post("/api/distributed/invitation/use/{code}")
    async def invitation_use(code: str, user_id: str):
        """Использовать приглашение."""
        success = invitation_system.use_invitation(code, user_id)
        if not success:
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")
        return {"status": "used"}
    
    @app.post("/api/distributed/invitation/revoke/{code}")
    async def invitation_revoke(code: str):
        """Отозвать приглашение."""
        success = invitation_system.revoke_invitation(code)
        if not success:
            raise HTTPException(status_code=404, detail="Invitation not found")
        return {"status": "revoked"}
    
    @app.get("/api/distributed/invitation/list")
    async def invitation_list(status: Optional[str] = None):
        """Список приглашений."""
        from ..distributed.invitation import InvitationStatus
        
        status_filter = InvitationStatus(status) if status else None
        invitations = invitation_system.list_invitations(status_filter)
        
        return {"invitations": invitations}
    
    @app.get("/api/distributed/invitation/stats")
    async def invitation_stats():
        """Статистика invitation system."""
        return invitation_system.get_stats()
    
    # ═══════════════════════════════════════════════════════════════
    # DISTRIBUTED CAMPAIGNS
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/distributed/campaign/propose")
    async def campaign_propose(request: CampaignRequest):
        """Предложить распределённую кампанию."""
        campaign_id = await distributed_campaigns.propose_campaign(
            target=request.target,
            attack_types=request.attack_types,
            parameters=request.parameters
        )
        return {"campaign_id": campaign_id}
    
    @app.post("/api/distributed/campaign/vote/{campaign_id}")
    async def campaign_vote(campaign_id: str, approve: bool):
        """Голосовать по кампании."""
        success = await distributed_campaigns.vote_on_campaign(campaign_id, approve)
        if not success:
            raise HTTPException(status_code=400, detail="Voting failed")
        return {"status": "voted"}
    
    @app.post("/api/distributed/campaign/start/{campaign_id}")
    async def campaign_start(campaign_id: str):
        """Запустить кампанию."""
        success = await distributed_campaigns.start_campaign(campaign_id)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to start campaign")
        return {"status": "started"}
    
    @app.post("/api/distributed/campaign/task/{campaign_id}/{task_id}/complete")
    async def campaign_task_complete(campaign_id: str, task_id: str, result: Dict[str, Any]):
        """Завершить задачу."""
        success = await distributed_campaigns.complete_task(campaign_id, task_id, result)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to complete task")
        return {"status": "completed"}
    
    @app.get("/api/distributed/campaign/{campaign_id}")
    async def campaign_get(campaign_id: str):
        """Получить кампанию."""
        campaign = distributed_campaigns.get_campaign(campaign_id)
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        return campaign
    
    @app.get("/api/distributed/campaign/list")
    async def campaign_list(status: Optional[str] = None):
        """Список кампаний."""
        from ..distributed.campaigns import CampaignStatus
        
        status_filter = CampaignStatus(status) if status else None
        campaigns = distributed_campaigns.list_campaigns(status_filter)
        
        return {"campaigns": campaigns}
    
    @app.get("/api/distributed/campaign/{campaign_id}/results")
    async def campaign_results(campaign_id: str):
        """Получить агрегированные результаты кампании."""
        results = await distributed_campaigns.aggregate_results(campaign_id)
        return results
    
    @app.get("/api/distributed/campaign/stats")
    async def campaign_stats():
        """Статистика distributed campaigns."""
        return distributed_campaigns.get_stats()
    
    # ═══════════════════════════════════════════════════════════════
    # FEDERATED TRAINING
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/distributed/federated/start_round")
    async def federated_start_round():
        """Запустить новый раунд federated обучения."""
        round_id = await federated_training.start_round()
        if not round_id:
            raise HTTPException(status_code=400, detail="Not enough peers for training")
        return {"round_id": round_id}
    
    @app.post("/api/distributed/federated/set_data")
    async def federated_set_data(request: FederatedTrainRequest):
        """Установить локальные данные для обучения."""
        data = np.array(request.data, dtype=np.float32)
        labels = np.array(request.labels, dtype=np.int32)
        
        federated_training.set_local_data(data, labels)
        
        return {"status": "data_set", "num_samples": len(data)}
    
    @app.post("/api/distributed/federated/local_train/{round_id}")
    async def federated_local_train(round_id: str):
        """Выполнить локальное обучение."""
        update = await federated_training.local_train(round_id)
        if not update:
            raise HTTPException(status_code=400, detail="Local training failed")
        return update.to_dict()
    
    @app.post("/api/distributed/federated/aggregate/{round_id}")
    async def federated_aggregate(round_id: str):
        """Агрегировать обновления от всех узлов."""
        aggregated = await federated_training.aggregate_updates(round_id)
        if not aggregated:
            raise HTTPException(status_code=400, detail="Aggregation failed")
        return {"status": "aggregated"}
    
    @app.get("/api/distributed/federated/round/{round_id}")
    async def federated_round_get(round_id: str):
        """Получить раунд обучения."""
        training_round = federated_training.get_round(round_id)
        if not training_round:
            raise HTTPException(status_code=404, detail="Round not found")
        return training_round
    
    @app.get("/api/distributed/federated/rounds")
    async def federated_rounds_list():
        """Список всех раундов."""
        rounds = federated_training.list_rounds()
        return {"rounds": rounds}
    
    @app.get("/api/distributed/federated/global_model")
    async def federated_global_model():
        """Получить глобальную модель."""
        model = federated_training.get_global_model()
        if not model:
            raise HTTPException(status_code=404, detail="Global model not found")
        
        # Конвертируем numpy arrays в lists
        model_serializable = {
            k: v.tolist() if isinstance(v, np.ndarray) else v
            for k, v in model.items()
        }
        
        return {"model": model_serializable}
    
    @app.get("/api/distributed/federated/stats")
    async def federated_stats():
        """Статистика federated training."""
        return federated_training.get_stats()
    
    # ═══════════════════════════════════════════════════════════════
    # MESH MATH INTEGRATION
    # ═══════════════════════════════════════════════════════════════
    
    @app.post("/api/distributed/mesh_math/register_transform")
    async def mesh_math_register(transform_name: str):
        """Зарегистрировать математическую трансформацию."""
        # Получаем трансформацию из math routes
        # В реальности здесь будет injection из math_routes
        return {"status": "registered", "transform_name": transform_name}
    
    @app.post("/api/distributed/mesh_math/distribute")
    async def mesh_math_distribute(data: List[float], transform_name: str, parameters: Dict[str, Any] = {}):
        """Распределить математическую задачу по mesh."""
        data_array = np.array(data, dtype=np.float32)
        
        task_ids = await mesh_math.distribute_transform(
            data_array,
            transform_name,
            parameters
        )
        
        return {"task_ids": task_ids}
    
    @app.post("/api/distributed/mesh_math/compute")
    async def mesh_math_compute(data: List[float], transform_name: str, parameters: Dict[str, Any] = {}):
        """Распределённое вычисление математической трансформации."""
        data_array = np.array(data, dtype=np.float32)
        
        result = await mesh_math.compute_distributed(
            data_array,
            transform_name,
            parameters
        )
        
        return {"result": result.tolist()}
    
    @app.post("/api/distributed/mesh_math/aggregate")
    async def mesh_math_aggregate(task_ids: List[str]):
        """Агрегировать результаты математических задач."""
        aggregation = await mesh_math.aggregate_results(task_ids)
        return aggregation.to_dict()
    
    @app.get("/api/distributed/mesh_math/task/{task_id}")
    async def mesh_math_task_get(task_id: str):
        """Получить математическую задачу."""
        task = mesh_math.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        return task
    
    @app.get("/api/distributed/mesh_math/tasks")
    async def mesh_math_tasks_list(status: Optional[str] = None):
        """Список математических задач."""
        from ..distributed.mesh_math import MathTaskStatus
        
        status_filter = MathTaskStatus(status) if status else None
        tasks = mesh_math.list_tasks(status_filter)
        
        return {"tasks": tasks}
    
    @app.get("/api/distributed/mesh_math/stats")
    async def mesh_math_stats():
        """Статистика mesh math integration."""
        return mesh_math.get_stats()
