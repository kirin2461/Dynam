"""
Base attack module — abstract base class for all attack types.

Each attack implements:
- execute(target, params) -> AttackResult
- validate_target(target) -> bool
- get_metrics() -> dict

All attacks are READ-ONLY — they test resilience without modifying the target.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
import time
from datetime import datetime


class AttackStatus(Enum):
    SUCCESS = "success"          # Attack bypassed detection
    DETECTED = "detected"        # Attack was detected/blocked
    PARTIAL = "partial"          # Partial success
    FAILED = "failed"            # Attack failed
    TIMEOUT = "timeout"          # Attack timed out
    ERROR = "error"              # Unexpected error


class AttackSeverity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AttackResult:
    """Result of a single attack execution."""
    attack_id: str
    attack_type: str
    target: str
    status: AttackStatus
    severity: AttackSeverity
    stealth_score: float = 0.0           # 0.0 (detected) - 1.0 (invisible)
    detection_probability: float = 0.0    # ML detector confidence
    latency_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_type": self.attack_type,
            "target": self.target,
            "status": self.status.value,
            "severity": self.severity.value,
            "stealth_score": self.stealth_score,
            "detection_probability": self.detection_probability,
            "latency_ms": self.latency_ms,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "error": self.error,
        }


@dataclass
class AttackConfig:
    """Configuration for an attack."""
    target: str
    iterations: int = 100
    intensity: int = 5            # 1-10 scale
    timeout_ms: int = 5000
    concurrent: int = 1
    params: Dict[str, Any] = field(default_factory=dict)


class BaseAttack(ABC):
    """Abstract base class for all attacks."""
    
    def __init__(self, name: str, description: str, category: str):
        self.name = name
        self.description = description
        self.category = category  # dpi, network, web, ml, dns, tls
        self._metrics: Dict[str, Any] = {}
        self._executions: List[AttackResult] = []
    
    @abstractmethod
    async def execute(self, target: str, config: AttackConfig) -> AttackResult:
        """Execute the attack against the target."""
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate that the target is appropriate for this attack."""
        pass
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get attack-specific metrics."""
        return self._metrics.copy()
    
    def get_execution_history(self) -> List[AttackResult]:
        """Get history of all executions."""
        return self._executions.copy()
    
    def get_success_rate(self) -> float:
        """Calculate success rate from execution history."""
        if not self._executions:
            return 0.0
        successful = sum(1 for r in self._executions if r.status == AttackStatus.SUCCESS)
        return successful / len(self._executions)
    
    def get_avg_stealth(self) -> float:
        """Calculate average stealth score."""
        if not self._executions:
            return 0.0
        return sum(r.stealth_score for r in self._executions) / len(self._executions)
    
    def reset(self):
        """Reset execution history and metrics."""
        self._executions.clear()
        self._metrics.clear()
