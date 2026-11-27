"""
Invitation System — система приглашений для P2P mesh.

Обеспечивает безопасное подключение новых узлов к mesh сети.

Функции:
- Генерация приглашений с ограниченным сроком действия
- Валидация приглашений
- Отслеживание использований
- Rate limiting для предотвращения злоупотреблений
"""

import secrets
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class InvitationStatus(Enum):
    """Статус приглашения."""
    ACTIVE = "active"
    USED = "used"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class Invitation:
    """Приглашение для подключения к mesh."""
    code: str
    created_by: str
    created_at: str
    expires_at: str
    max_uses: int = 1
    uses: int = 0
    status: InvitationStatus = InvitationStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    used_by: List[str] = field(default_factory=list)
    
    def is_valid(self) -> bool:
        """Проверить валидность приглашения."""
        if self.status != InvitationStatus.ACTIVE:
            return False
        if self.uses >= self.max_uses:
            return False
        expires = datetime.fromisoformat(self.expires_at)
        return datetime.now() < expires
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "max_uses": self.max_uses,
            "uses": self.uses,
            "status": self.status.value,
            "is_valid": self.is_valid(),
            "metadata": self.metadata,
        }


@dataclass
class InvitationConfig:
    """Конфигурация invitation system."""
    default_expiration_hours: int = 24
    default_max_uses: int = 1
    code_length: int = 32
    enable_rate_limiting: bool = True
    max_invitations_per_hour: int = 10


class InvitationSystem:
    """
    Система приглашений для P2P mesh.
    
    Методы:
    1. create_invitation() — создание приглашения
    2. validate_invitation() — валидация приглашения
    3. use_invitation() — использование приглашения
    4. revoke_invitation() — отзыв приглашения
    5. list_invitations() — список приглашений
    """
    
    def __init__(self, node_id: str, config: Optional[InvitationConfig] = None):
        self.node_id = node_id
        self.config = config or InvitationConfig()
        
        # Storage
        self.invitations: Dict[str, Invitation] = {}
        
        # Rate limiting
        self._creation_times: List[datetime] = []
    
    def create_invitation(
        self,
        expires_hours: Optional[int] = None,
        max_uses: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Invitation:
        """
        Создать приглашение.
        
        Args:
            expires_hours: Время жизни в часах (по умолчанию из config)
            max_uses: Максимальное количество использований
            metadata: Дополнительные метаданные
        
        Returns:
            Invitation object
        """
        # Rate limiting
        if self.config.enable_rate_limiting:
            if not self._check_rate_limit():
                raise RuntimeError("Rate limit exceeded")
        
        # Generate code
        code = self._generate_code()
        
        # Calculate expiration
        expires_hours = expires_hours or self.config.default_expiration_hours
        max_uses = max_uses or self.config.default_max_uses
        
        now = datetime.now()
        expires_at = now + timedelta(hours=expires_hours)
        
        invitation = Invitation(
            code=code,
            created_by=self.node_id,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            max_uses=max_uses,
            metadata=metadata or {},
        )
        
        self.invitations[code] = invitation
        self._creation_times.append(now)
        
        return invitation
    
    def validate_invitation(self, code: str) -> bool:
        """
        Валидация приглашения.
        
        Args:
            code: Invitation code
        
        Returns:
            True если приглашение валидно
        """
        if code not in self.invitations:
            return False
        
        invitation = self.invitations[code]
        return invitation.is_valid()
    
    def use_invitation(self, code: str, user_id: str) -> bool:
        """
        Использовать приглашение.
        
        Args:
            code: Invitation code
            user_id: ID пользователя, использующего приглашение
        
        Returns:
            True если успешно использовано
        """
        if code not in self.invitations:
            return False
        
        invitation = self.invitations[code]
        
        if not invitation.is_valid():
            return False
        
        # Increment uses
        invitation.uses += 1
        invitation.used_by.append(user_id)
        
        # Check if max uses reached
        if invitation.uses >= invitation.max_uses:
            invitation.status = InvitationStatus.USED
        
        return True
    
    def revoke_invitation(self, code: str) -> bool:
        """
        Отозвать приглашение.
        
        Args:
            code: Invitation code
        
        Returns:
            True если успешно отозвано
        """
        if code not in self.invitations:
            return False
        
        invitation = self.invitations[code]
        invitation.status = InvitationStatus.REVOKED
        
        return True
    
    def get_invitation(self, code: str) -> Optional[Invitation]:
        """Получить приглашение по коду."""
        return self.invitations.get(code)
    
    def list_invitations(self, status: Optional[InvitationStatus] = None) -> List[Dict[str, Any]]:
        """
        Список приглашений.
        
        Args:
            status: Фильтр по статусу (опционально)
        
        Returns:
            List of invitation dicts
        """
        invitations = []
        
        for inv in self.invitations.values():
            if status is None or inv.status == status:
                invitations.append(inv.to_dict())
        
        return invitations
    
    def cleanup_expired(self):
        """Очистка просроченных приглашений."""
        now = datetime.now()
        
        for code, invitation in list(self.invitations.items()):
            expires = datetime.fromisoformat(invitation.expires_at)
            if now >= expires and invitation.status == InvitationStatus.ACTIVE:
                invitation.status = InvitationStatus.EXPIRED
    
    def _generate_code(self) -> str:
        """Генерация invitation code."""
        random_bytes = secrets.token_bytes(self.config.code_length)
        code = secrets.token_urlsafe(self.config.code_length)
        
        # Добавляем checksum
        checksum = hashlib.sha256(random_bytes).hexdigest()[:8]
        
        return f"{code}-{checksum}"
    
    def _check_rate_limit(self) -> bool:
        """Проверка rate limit."""
        now = datetime.now()
        one_hour_ago = now - timedelta(hours=1)
        
        # Удаляем старые записи
        self._creation_times = [t for t in self._creation_times if t > one_hour_ago]
        
        # Проверяем лимит
        return len(self._creation_times) < self.config.max_invitations_per_hour
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику invitation system."""
        total = len(self.invitations)
        active = sum(1 for inv in self.invitations.values() if inv.status == InvitationStatus.ACTIVE)
        used = sum(1 for inv in self.invitations.values() if inv.status == InvitationStatus.USED)
        expired = sum(1 for inv in self.invitations.values() if inv.status == InvitationStatus.EXPIRED)
        revoked = sum(1 for inv in self.invitations.values() if inv.status == InvitationStatus.REVOKED)
        
        total_uses = sum(inv.uses for inv in self.invitations.values())
        
        return {
            "total_invitations": total,
            "active": active,
            "used": used,
            "expired": expired,
            "revoked": revoked,
            "total_uses": total_uses,
        }
