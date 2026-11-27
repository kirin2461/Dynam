"""
P2P Mesh Network — децентрализованная mesh сеть поверх обычной сети.

Режимы работы:
1. TCP/UDP mode (по умолчанию) — прямое соединение между узлами
2. I2P mode (опционально) — через I2P router для анонимности

TCP/UDP mode требует систему приглашений (invitations) для безопасности.
I2P mode не требует приглашений (анонимная сеть).

Архитектура:
- Transport Layer: TCP/UDP или I2P (выбираемый)
- Mesh Layer: единый API для peer discovery, routing, coordination
- Application Layer: distributed campaigns, federated learning, etc.
"""

import asyncio
import json
import hashlib
import secrets
import socket
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import uuid


class TransportMode(Enum):
    """Режим транспорта."""
    TCP = "tcp"           # Прямое TCP соединение
    UDP = "udp"           # UDP с reliability layer
    I2P = "i2p"           # Через I2P router


class PeerState(Enum):
    """Состояние пира."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    VERIFIED = "verified"
    SUSPECTED = "suspected"


@dataclass
class PeerInfo:
    """Информация о пире."""
    peer_id: str
    address: str
    port: int
    transport: TransportMode
    state: PeerState = PeerState.DISCONNECTED
    last_seen: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    reputation: float = 1.0
    invited_by: Optional[str] = None
    invitation_code: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "peer_id": self.peer_id,
            "address": self.address,
            "port": self.port,
            "transport": self.transport.value,
            "state": self.state.value,
            "last_seen": self.last_seen,
            "capabilities": self.capabilities,
            "reputation": self.reputation,
        }


@dataclass
class Invitation:
    """Приглашение для подключения к mesh."""
    code: str
    created_by: str
    created_at: str
    expires_at: str
    max_uses: int = 1
    uses: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Проверить валидность приглашения."""
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
        }


@dataclass
class MeshMessage:
    """Сообщение в mesh сети."""
    msg_id: str
    sender_id: str
    recipient_id: str  # "*" для broadcast
    msg_type: str
    payload: Dict[str, Any]
    timestamp: str
    ttl: int = 10  # hops
    signature: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "msg_type": self.msg_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
            "signature": self.signature,
        }


class MeshNetwork:
    """
    P2P Mesh Network — децентрализованная mesh сеть.
    
    Поддерживает два режима:
    1. TCP/UDP — прямое соединение, требует invitations
    2. I2P — анонимное соединение через I2P router
    """
    
    def __init__(
        self,
        node_id: Optional[str] = None,
        transport: TransportMode = TransportMode.TCP,
        listen_port: int = 8765,
        i2p_enabled: bool = False,
    ):
        self.node_id = node_id or self._generate_node_id()
        self.transport = transport
        self.listen_port = listen_port
        self.i2p_enabled = i2p_enabled
        
        # Peers
        self.peers: Dict[str, PeerInfo] = {}
        self.invitations: Dict[str, Invitation] = {}
        
        # Message handlers
        self._message_handlers: Dict[str, List[Callable]] = {}
        self._seen_messages: Set[str] = set()
        
        # Server
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        
        # I2P (если включен)
        self._i2p_session = None
        
        # Known messages for routing
        self._message_queue: asyncio.Queue = asyncio.Queue()
    
    def _generate_node_id(self) -> str:
        """Генерация уникального ID узла."""
        return f"dynam-{secrets.token_hex(8)}"
    
    async def start(self):
        """Запустить mesh network."""
        if self._running:
            return
        
        self._running = True
        
        # Запустить сервер
        if self.transport == TransportMode.TCP:
            self._server = await asyncio.start_server(
                self._handle_connection,
                '0.0.0.0',
                self.listen_port
            )
        elif self.transport == TransportMode.I2P and self.i2p_enabled:
            # I2P SAM connection
            await self._start_i2p()
        
        # Запустить background tasks
        asyncio.create_task(self._peer_maintenance())
        asyncio.create_task(self._message_processor())
        
        print(f"[Mesh] Node {self.node_id} started on port {self.listen_port}")
    
    async def stop(self):
        """Остановить mesh network."""
        self._running = False
        
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        
        if self._i2p_session:
            await self._stop_i2p()
        
        # Disconnect all peers
        for peer in list(self.peers.values()):
            await self.disconnect_peer(peer.peer_id)
        
        print(f"[Mesh] Node {self.node_id} stopped")
    
    # ═══════════════════════════════════════════════════════════════
    # INVITATION SYSTEM (для TCP/UDP mode)
    # ═══════════════════════════════════════════════════════════════
    
    def create_invitation(
        self,
        expires_hours: int = 24,
        max_uses: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Invitation:
        """
        Создать приглашение для подключения.
        
        Args:
            expires_hours: Время жизни приглашения в часах
            max_uses: Максимальное количество использований
            metadata: Дополнительные метаданные
        
        Returns:
            Invitation object
        """
        code = secrets.token_urlsafe(32)
        
        invitation = Invitation(
            code=code,
            created_by=self.node_id,
            created_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(hours=expires_hours)).isoformat(),
            max_uses=max_uses,
            metadata=metadata or {},
        )
        
        self.invitations[code] = invitation
        return invitation
    
    async def accept_invitation(self, invitation_code: str, peer_address: str, peer_port: int) -> bool:
        """
        Принять приглашение и подключиться к пиру.
        
        Args:
            invitation_code: Код приглашения
            peer_address: Адрес пира
            peer_port: Порт пира
        
        Returns:
            True если подключение успешно
        """
        # Проверить приглашение
        if invitation_code not in self.invitations:
            print(f"[Mesh] Invalid invitation code")
            return False
        
        invitation = self.invitations[invitation_code]
        if not invitation.is_valid():
            print(f"[Mesh] Invitation expired or max uses reached")
            return False
        
        # Подключиться к пиру
        peer = PeerInfo(
            peer_id=f"peer-{secrets.token_hex(4)}",
            address=peer_address,
            port=peer_port,
            transport=self.transport,
            state=PeerState.CONNECTING,
            invited_by=invitation.created_by,
            invitation_code=invitation_code,
        )
        
        try:
            reader, writer = await asyncio.open_connection(peer_address, peer_port)
            
            # Отправить handshake с invitation code
            handshake = {
                "type": "handshake",
                "node_id": self.node_id,
                "invitation_code": invitation_code,
                "capabilities": ["attack", "relay", "storage"],
            }
            writer.write(json.dumps(handshake).encode() + b"\n")
            await writer.drain()
            
            # Получить ответ
            response = await reader.readline()
            response_data = json.loads(response.decode())
            
            if response_data.get("status") == "accepted":
                peer.state = PeerState.VERIFIED
                peer.peer_id = response_data.get("peer_id")
                self.peers[peer.peer_id] = peer
                
                # Обновить invitation
                invitation.uses += 1
                
                print(f"[Mesh] Connected to peer {peer.peer_id}")
                
                # Запустить обработку connection
                asyncio.create_task(self._handle_peer_connection(peer, reader, writer))
                
                return True
            else:
                print(f"[Mesh] Connection rejected: {response_data.get('reason')}")
                writer.close()
                return False
        
        except Exception as e:
            print(f"[Mesh] Connection failed: {e}")
            return False
    
    def revoke_invitation(self, code: str) -> bool:
        """Отозвать приглашение."""
        if code in self.invitations:
            del self.invitations[code]
            return True
        return False
    
    # ═══════════════════════════════════════════════════════════════
    # CONNECTION HANDLING
    # ═══════════════════════════════════════════════════════════════
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обработка входящего соединения."""
        addr = writer.get_extra_info('peername')
        print(f"[Mesh] Incoming connection from {addr}")
        
        try:
            # Прочитать handshake
            data = await reader.readline()
            handshake = json.loads(data.decode())
            
            if handshake.get("type") != "handshake":
                writer.write(json.dumps({"status": "rejected", "reason": "invalid handshake"}).encode() + b"\n")
                writer.close()
                return
            
            # Проверить invitation code (для TCP mode)
            invitation_code = handshake.get("invitation_code")
            if self.transport == TransportMode.TCP:
                if invitation_code not in self.invitations:
                    writer.write(json.dumps({"status": "rejected", "reason": "invalid invitation"}).encode() + b"\n")
                    writer.close()
                    return
                
                invitation = self.invitations[invitation_code]
                if not invitation.is_valid():
                    writer.write(json.dumps({"status": "rejected", "reason": "invitation expired"}).encode() + b"\n")
                    writer.close()
                    return
            
            # Принять соединение
            peer_id = handshake.get("node_id")
            peer = PeerInfo(
                peer_id=peer_id,
                address=addr[0],
                port=addr[1],
                transport=self.transport,
                state=PeerState.VERIFIED,
                capabilities=handshake.get("capabilities", []),
                invited_by=invitation_code if invitation_code else None,
            )
            
            self.peers[peer_id] = peer
            
            # Отправить acceptance
            writer.write(json.dumps({
                "status": "accepted",
                "peer_id": self.node_id,
                "capabilities": ["attack", "relay", "storage"],
            }).encode() + b"\n")
            await writer.drain()
            
            # Обновить invitation
            if invitation_code and invitation_code in self.invitations:
                self.invitations[invitation_code].uses += 1
            
            print(f"[Mesh] Peer {peer_id} connected")
            
            # Обработка connection
            await self._handle_peer_connection(peer, reader, writer)
        
        except Exception as e:
            print(f"[Mesh] Connection error: {e}")
            writer.close()
    
    async def _handle_peer_connection(self, peer: PeerInfo, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Обработка соединения с пиром."""
        try:
            while self._running and peer.state == PeerState.VERIFIED:
                data = await reader.readline()
                if not data:
                    break
                
                message = json.loads(data.decode())
                await self._process_message(message, peer)
        
        except Exception as e:
            print(f"[Mesh] Peer {peer.peer_id} connection error: {e}")
        
        finally:
            peer.state = PeerState.DISCONNECTED
            writer.close()
            print(f"[Mesh] Peer {peer.peer_id} disconnected")
    
    # ═══════════════════════════════════════════════════════════════
    # MESSAGING
    # ═══════════════════════════════════════════════════════════════
    
    async def send_message(
        self,
        recipient_id: str,
        msg_type: str,
        payload: Dict[str, Any],
        ttl: int = 10
    ) -> str:
        """
        Отправить сообщение в mesh.
        
        Args:
            recipient_id: ID получателя ("*" для broadcast)
            msg_type: Тип сообщения
            payload: Данные сообщения
            ttl: Time-to-live (количество hops)
        
        Returns:
            Message ID
        """
        msg = MeshMessage(
            msg_id=str(uuid.uuid4()),
            sender_id=self.node_id,
            recipient_id=recipient_id,
            msg_type=msg_type,
            payload=payload,
            timestamp=datetime.now().isoformat(),
            ttl=ttl,
        )
        
        # Подписать сообщение
        msg.signature = self._sign_message(msg)
        
        # Отправить
        if recipient_id == "*":
            # Broadcast
            await self._broadcast_message(msg)
        elif recipient_id in self.peers:
            # Direct send
            await self._send_to_peer(self.peers[recipient_id], msg)
        else:
            # Route through mesh
            await self._route_message(msg)
        
        return msg.msg_id
    
    async def _broadcast_message(self, msg: MeshMessage):
        """Отправить сообщение всем пирям."""
        for peer in self.peers.values():
            if peer.state == PeerState.VERIFIED:
                await self._send_to_peer(peer, msg)
    
    async def _send_to_peer(self, peer: PeerInfo, msg: MeshMessage):
        """Отправить сообщение конкретному пиру."""
        # Реализация зависит от transport
        # Упрощённая версия
        print(f"[Mesh] Sending {msg.msg_type} to {peer.peer_id}")
    
    async def _route_message(self, msg: MeshMessage):
        """Маршрутизировать сообщение через mesh."""
        # Простая flooding routing
        if msg.ttl > 0:
            msg.ttl -= 1
            await self._broadcast_message(msg)
    
    async def _process_message(self, message: Dict[str, Any], peer: PeerInfo):
        """Обработка входящего сообщения."""
        msg = MeshMessage(**message)
        
        # Проверить signature
        if not self._verify_signature(msg, peer):
            print(f"[Mesh] Invalid signature from {peer.peer_id}")
            return
        
        # Проверить duplicate
        if msg.msg_id in self._seen_messages:
            return
        self._seen_messages.add(msg.msg_id)
        
        # Обработать или forward
        if msg.recipient_id == self.node_id or msg.recipient_id == "*":
            # Для нас
            await self._handle_message(msg, peer)
        elif msg.ttl > 0:
            # Forward
            await self._route_message(msg)
    
    async def _handle_message(self, msg: MeshMessage, peer: PeerInfo):
        """Обработка сообщения для нас."""
        handlers = self._message_handlers.get(msg.msg_type, [])
        for handler in handlers:
            try:
                await handler(msg, peer)
            except Exception as e:
                print(f"[Mesh] Message handler error: {e}")
    
    def register_handler(self, msg_type: str, handler: Callable):
        """Зарегистрировать обработчик сообщений."""
        if msg_type not in self._message_handlers:
            self._message_handlers[msg_type] = []
        self._message_handlers[msg_type].append(handler)
    
    # ═══════════════════════════════════════════════════════════════
    # SECURITY
    # ═══════════════════════════════════════════════════════════════
    
    def _sign_message(self, msg: MeshMessage) -> str:
        """Подписать сообщение."""
        # Упрощённая подпись (в реальности использовать Ed25519)
        data = f"{msg.msg_id}{msg.sender_id}{msg.timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _verify_signature(self, msg: MeshMessage, peer: PeerInfo) -> bool:
        """Проверить подпись сообщения."""
        # Упрощённая проверка
        expected = self._sign_message(msg)
        return msg.signature == expected
    
    # ═══════════════════════════════════════════════════════════════
    # I2P INTEGRATION (опционально)
    # ═══════════════════════════════════════════════════════════════
    
    async def _start_i2p(self):
        """Запустить I2P транспорт."""
        if not self.i2p_enabled:
            return
        
        # Подключиться к I2P SAM API
        print("[Mesh] Starting I2P transport...")
        # Реализация зависит от I2P library
    
    async def _stop_i2p(self):
        """Остановить I2P транспорт."""
        if self._i2p_session:
            print("[Mesh] Stopping I2P transport...")
            # Закрыть I2P session
    
    # ═══════════════════════════════════════════════════════════════
    # MAINTENANCE
    # ═══════════════════════════════════════════════════════════════
    
    async def _peer_maintenance(self):
        """Фоновая поддержка соединений."""
        while self._running:
            # Проверить timeout для peers
            now = datetime.now()
            for peer in list(self.peers.values()):
                if peer.last_seen:
                    last_seen = datetime.fromisoformat(peer.last_seen)
                    if (now - last_seen).total_seconds() > 300:  # 5 minutes
                        peer.state = PeerState.DISCONNECTED
            
            # Очистить expired invitations
            for code, invitation in list(self.invitations.items()):
                if not invitation.is_valid():
                    del self.invitations[code]
            
            await asyncio.sleep(60)
    
    async def _message_processor(self):
        """Обработка очереди сообщений."""
        while self._running:
            try:
                msg = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                # Process message
            except asyncio.TimeoutError:
                pass
    
    # ═══════════════════════════════════════════════════════════════
    # STATUS & STATS
    # ═══════════════════════════════════════════════════════════════
    
    def get_status(self) -> Dict[str, Any]:
        """Получить статус mesh network."""
        return {
            "node_id": self.node_id,
            "transport": self.transport.value,
            "i2p_enabled": self.i2p_enabled,
            "peers_count": len([p for p in self.peers.values() if p.state == PeerState.VERIFIED]),
            "total_peers": len(self.peers),
            "invitations_count": len([i for i in self.invitations.values() if i.is_valid()]),
            "running": self._running,
        }
    
    def get_peers(self) -> List[Dict[str, Any]]:
        """Получить список пиров."""
        return [peer.to_dict() for peer in self.peers.values()]
    
    def get_invitations(self) -> List[Dict[str, Any]]:
        """Получить список приглашений."""
        return [inv.to_dict() for inv in self.invitations.values() if inv.is_valid()]
    
    # ═══════════════════════════════════════════════════════════════
    # PEER MANAGEMENT
    # ═══════════════════════════════════════════════════════════════
    
    async def disconnect_peer(self, peer_id: str):
        """Отключить пира."""
        if peer_id in self.peers:
            peer = self.peers[peer_id]
            peer.state = PeerState.DISCONNECTED
            # Close connection
            print(f"[Mesh] Disconnected peer {peer_id}")
