"""
Attack Manager — orchestrates automated attack campaigns.

Modes:
- Single: Run one attack type against a target
- Campaign: Run multiple attacks in sequence
- Auto: Continuous testing with adaptive attack selection
- Stress: High-intensity testing with concurrent attacks
"""

import asyncio
import random
import uuid
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import json

from .base_attack import BaseAttack, AttackConfig, AttackResult, AttackStatus
from ..attacks.implementations import get_attack, get_all_attacks, ATTACK_REGISTRY


class CampaignMode(Enum):
    SINGLE = "single"           # One attack type
    CAMPAIGN = "campaign"       # Sequential multi-attack
    AUTO = "auto"               # Adaptive selection
    STRESS = "stress"           # High-intensity concurrent


class CampaignStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class CampaignConfig:
    """Configuration for an attack campaign."""
    name: str
    target: str
    mode: CampaignMode
    attacks: List[str] = field(default_factory=lambda: list(ATTACK_REGISTRY.keys()))
    iterations: int = 100
    intensity: int = 5
    duration_seconds: int = 0       # 0 = unlimited
    concurrent: int = 1
    auto_stop_on_detection_rate: float = 0.0  # 0 = disabled
    adaptive: bool = False          # Adjust attack selection based on results
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignProgress:
    """Real-time campaign progress."""
    campaign_id: str
    status: CampaignStatus
    total_iterations: int
    completed_iterations: int
    current_attack: str
    results: List[AttackResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None
    
    @property
    def progress_percent(self) -> float:
        if self.total_iterations == 0:
            return 0.0
        return (self.completed_iterations / self.total_iterations) * 100
    
    @property
    def success_rate(self) -> float:
        if not self.results:
            return 0.0
        successful = sum(1 for r in self.results if r.status == AttackStatus.SUCCESS)
        return successful / len(self.results)
    
    @property
    def avg_stealth(self) -> float:
        if not self.results:
            return 0.0
        return sum(r.stealth_score for r in self.results) / len(self.results)
    
    @property
    def detection_rate(self) -> float:
        return 1.0 - self.success_rate
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "status": self.status.value,
            "total_iterations": self.total_iterations,
            "completed_iterations": self.completed_iterations,
            "current_attack": self.current_attack,
            "progress_percent": self.progress_percent,
            "success_rate": self.success_rate,
            "avg_stealth": self.avg_stealth,
            "detection_rate": self.detection_rate,
            "results_count": len(self.results),
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


@dataclass
class CampaignSummary:
    """Summary of a completed campaign."""
    campaign_id: str
    name: str
    target: str
    mode: str
    status: str
    total_attacks: int
    successful: int
    detected: int
    errors: int
    success_rate: float
    avg_stealth: float
    min_stealth: float
    max_stealth: float
    duration_seconds: float
    attacks_used: List[str]
    start_time: str
    end_time: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "target": self.target,
            "mode": self.mode,
            "status": self.status,
            "total_attacks": self.total_attacks,
            "successful": self.successful,
            "detected": self.detected,
            "errors": self.errors,
            "success_rate": self.success_rate,
            "avg_stealth": self.avg_stealth,
            "min_stealth": self.min_stealth,
            "max_stealth": self.max_stealth,
            "duration_seconds": self.duration_seconds,
            "attacks_used": self.attacks_used,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


class AttackManager:
    """
    Orchestrates attack campaigns with support for:
    - Single/campaign/auto/stress modes
    - Real-time progress tracking
    - Adaptive attack selection
    - Auto-stop on detection rate
    - Callbacks for UI updates
    """
    
    def __init__(self):
        self._campaigns: Dict[str, CampaignProgress] = {}
        self._running_tasks: Dict[str, asyncio.Task] = {}
        self._progress_callbacks: List[Callable] = []
        self._lock = asyncio.Lock()
    
    def on_progress(self, callback: Callable):
        """Register a progress callback."""
        self._progress_callbacks.append(callback)
    
    async def _notify_progress(self, progress: CampaignProgress):
        """Notify all callbacks of progress update."""
        for cb in self._progress_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(progress)
                else:
                    cb(progress)
            except Exception:
                pass
    
    def get_campaign(self, campaign_id: str) -> Optional[CampaignProgress]:
        """Get campaign progress by ID."""
        return self._campaigns.get(campaign_id)
    
    def get_all_campaigns(self) -> Dict[str, CampaignProgress]:
        """Get all campaigns."""
        return self._campaigns.copy()
    
    async def start_campaign(self, config: CampaignConfig) -> str:
        """Start a new attack campaign."""
        campaign_id = str(uuid.uuid4())[:8]
        
        progress = CampaignProgress(
            campaign_id=campaign_id,
            status=CampaignStatus.RUNNING,
            total_iterations=config.iterations,
            completed_iterations=0,
            current_attack=config.attacks[0] if config.attacks else "unknown",
            start_time=datetime.now(),
        )
        
        self._campaigns[campaign_id] = progress
        
        task = asyncio.create_task(self._run_campaign(campaign_id, config))
        self._running_tasks[campaign_id] = task
        
        return campaign_id
    
    async def stop_campaign(self, campaign_id: str):
        """Stop a running campaign."""
        task = self._running_tasks.get(campaign_id)
        if task:
            task.cancel()
        
        progress = self._campaigns.get(campaign_id)
        if progress:
            progress.status = CampaignStatus.STOPPED
            progress.end_time = datetime.now()
    
    async def _run_campaign(self, campaign_id: str, config: CampaignConfig):
        """Internal campaign execution loop."""
        progress = self._campaigns[campaign_id]
        
        try:
            if config.mode == CampaignMode.SINGLE:
                await self._run_single(campaign_id, config)
            elif config.mode == CampaignMode.CAMPAIGN:
                await self._run_campaign_mode(campaign_id, config)
            elif config.mode == CampaignMode.AUTO:
                await self._run_auto(campaign_id, config)
            elif config.mode == CampaignMode.STRESS:
                await self._run_stress(campaign_id, config)
            
            progress.status = CampaignStatus.COMPLETED
            
        except asyncio.CancelledError:
            progress.status = CampaignStatus.STOPPED
        except Exception as e:
            progress.status = CampaignStatus.ERROR
            progress.error = str(e)
        finally:
            progress.end_time = datetime.now()
            progress.current_attack = "completed"
            await self._notify_progress(progress)
    
    async def _run_single(self, campaign_id: str, config: CampaignConfig):
        """Run a single attack type."""
        progress = self._campaigns[campaign_id]
        attack_type = config.attacks[0] if config.attacks else "ecs"
        
        attack = get_attack(attack_type)
        if not attack:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        attack_config = AttackConfig(
            target=config.target,
            iterations=config.iterations,
            intensity=config.intensity,
            params=config.params,
        )
        
        for i in range(config.iterations):
            if progress.status == CampaignStatus.STOPPED:
                break
            
            progress.current_attack = attack_type
            result = await attack.execute(config.target, attack_config)
            progress.results.append(result)
            progress.completed_iterations = i + 1
            
            await self._notify_progress(progress)
            
            # Check auto-stop
            if config.auto_stop_on_detection_rate > 0:
                if progress.detection_rate >= config.auto_stop_on_detection_rate:
                    break
            
            await asyncio.sleep(0.05)  # Rate limiting
    
    async def _run_campaign_mode(self, campaign_id: str, config: CampaignConfig):
        """Run attacks sequentially."""
        progress = self._campaigns[campaign_id]
        
        attacks_per_type = config.iterations // len(config.attacks)
        
        for attack_type in config.attacks:
            if progress.status == CampaignStatus.STOPPED:
                break
            
            attack = get_attack(attack_type)
            if not attack:
                continue
            
            attack_config = AttackConfig(
                target=config.target,
                iterations=attacks_per_type,
                intensity=config.intensity,
                params=config.params,
            )
            
            for i in range(attacks_per_type):
                progress.current_attack = attack_type
                result = await attack.execute(config.target, attack_config)
                progress.results.append(result)
                progress.completed_iterations += 1
                
                await self._notify_progress(progress)
                await asyncio.sleep(0.05)
    
    async def _run_auto(self, campaign_id: str, config: CampaignConfig):
        """Adaptive attack selection based on results."""
        progress = self._campaigns[campaign_id]
        
        # Start with equal weights
        weights = {at: 1.0 for at in config.attacks}
        
        for i in range(config.iterations):
            if progress.status == CampaignStatus.STOPPED:
                break
            
            # Weighted random selection
            attack_type = random.choices(
                list(weights.keys()),
                weights=list(weights.values())
            )[0]
            
            attack = get_attack(attack_type)
            if not attack:
                continue
            
            attack_config = AttackConfig(
                target=config.target,
                iterations=1,
                intensity=config.intensity,
                params=config.params,
            )
            
            progress.current_attack = attack_type
            result = await attack.execute(config.target, attack_config)
            progress.results.append(result)
            progress.completed_iterations = i + 1
            
            # Adapt weights based on result
            if result.status == AttackStatus.SUCCESS:
                weights[attack_type] *= 1.1  # Increase weight for successful attacks
            else:
                weights[attack_type] *= 0.9  # Decrease weight for detected attacks
            
            await self._notify_progress(progress)
            await asyncio.sleep(0.05)
    
    async def _run_stress(self, campaign_id: str, config: CampaignConfig):
        """High-intensity concurrent attacks."""
        progress = self._campaigns[campaign_id]
        
        semaphore = asyncio.Semaphore(config.concurrent)
        
        async def run_one(attack_type: str, idx: int):
            async with semaphore:
                attack = get_attack(attack_type)
                if not attack:
                    return
                
                attack_config = AttackConfig(
                    target=config.target,
                    iterations=1,
                    intensity=config.intensity,
                    params=config.params,
                )
                
                progress.current_attack = attack_type
                result = await attack.execute(config.target, attack_config)
                
                async with self._lock:
                    progress.results.append(result)
                    progress.completed_iterations += 1
                
                await self._notify_progress(progress)
        
        tasks = []
        for i in range(config.iterations):
            attack_type = random.choice(config.attacks)
            tasks.append(run_one(attack_type, i))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    def get_summary(self, campaign_id: str) -> Optional[CampaignSummary]:
        """Get summary of a completed campaign."""
        progress = self._campaigns.get(campaign_id)
        if not progress:
            return None
        
        results = progress.results
        attacks_used = list(set(r.attack_type for r in results))
        
        stealths = [r.stealth_score for r in results] if results else [0]
        
        duration = 0
        if progress.start_time and progress.end_time:
            duration = (progress.end_time - progress.start_time).total_seconds()
        
        return CampaignSummary(
            campaign_id=campaign_id,
            name=campaign_id,
            target=results[0].target if results else "",
            mode="auto",
            status=progress.status.value,
            total_attacks=len(results),
            successful=sum(1 for r in results if r.status == AttackStatus.SUCCESS),
            detected=sum(1 for r in results if r.status == AttackStatus.DETECTED),
            errors=sum(1 for r in results if r.status == AttackStatus.ERROR),
            success_rate=progress.success_rate,
            avg_stealth=progress.avg_stealth,
            min_stealth=min(stealths),
            max_stealth=max(stealths),
            duration_seconds=duration,
            attacks_used=attacks_used,
            start_time=progress.start_time.isoformat() if progress.start_time else "",
            end_time=progress.end_time.isoformat() if progress.end_time else "",
        )
