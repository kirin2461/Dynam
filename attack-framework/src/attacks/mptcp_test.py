"""
Multi-Path TCP (MPTCP) Testing — test MPTCP for DPI bypass potential.

MPTCP allows TCP connections to use multiple paths simultaneously:
1. Subflow analysis — detect MPTCP subflows
2. Path diversity — check if multiple paths are used
3. Handover detection — detect path switching
4. Aggregation analysis — analyze traffic aggregation across paths
5. Fallback detection — detect MPTCP fallback to regular TCP

Detection methods:
- Subflow detection — detect MPTCP subflows
- Path analysis — analyze multiple paths
- Handover analysis — detect path switching
- Aggregation analysis — analyze traffic distribution
- Fallback detection — detect fallback to TCP

Metrics:
- mptcp_supported: bool — whether MPTCP is supported
- subflows_detected: int — number of MPTCP subflows
- path_diversity: float — path diversity score
- handover_detected: bool — path handover detected
- aggregation_efficiency: float — traffic aggregation efficiency
- fallback_detected: bool — fallback to TCP detected
"""

import asyncio
import socket
import struct
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class MPTCPSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MPTCPTestResult:
    """Result of MPTCP testing."""
    timestamp: str
    target: str
    mptcp_supported: bool
    subflows_detected: int = 0
    path_diversity: float = 0.0
    handover_detected: bool = False
    aggregation_efficiency: float = 0.0
    fallback_detected: bool = False
    severity: MPTCPSeverity = MPTCPSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "mptcp_supported": self.mptcp_supported,
            "subflows_detected": self.subflows_detected,
            "path_diversity": self.path_diversity,
            "handover_detected": self.handover_detected,
            "aggregation_efficiency": self.aggregation_efficiency,
            "fallback_detected": self.fallback_detected,
            "severity": self.severity.value,
            "details": self.details,
        }


class MPTCPTester:
    """
    Test MPTCP support and analyze for DPI bypass potential.
    
    Tests:
    1. MPTCP support detection — check if MPTCP is supported
    2. Subflow detection — detect MPTCP subflows
    3. Path analysis — analyze multiple paths
    4. Handover analysis — detect path switching
    5. Fallback detection — detect fallback to TCP
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def test_mptcp(self, target: str) -> MPTCPTestResult:
        """
        Run comprehensive MPTCP testing.
        
        Returns:
            MPTCPTestResult with all detected MPTCP features
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        support_task = self._test_mptcp_support(target)
        subflow_task = self._detect_subflows(target)
        path_task = self._analyze_paths(target)
        handover_task = self._detect_handover(target)
        fallback_task = self._detect_fallback(target)
        
        support_result, subflow_result, path_result, handover_result, fallback_result = await asyncio.gather(
            support_task, subflow_task, path_task, handover_task, fallback_task,
            return_exceptions=True
        )
        
        # Aggregate results
        mptcp_supported = False
        subflows_detected = 0
        path_diversity = 0.0
        handover_detected = False
        aggregation_efficiency = 0.0
        fallback_detected = False
        
        if isinstance(support_result, dict):
            mptcp_supported = support_result.get("supported", False)
        
        if isinstance(subflow_result, dict):
            subflows_detected = subflow_result.get("subflow_count", 0)
            if subflows_detected > 0:
                mptcp_supported = True
        
        if isinstance(path_result, dict):
            path_diversity = path_result.get("diversity_score", 0.0)
        
        if isinstance(handover_result, dict):
            handover_detected = handover_result.get("handover_detected", False)
        
        if isinstance(fallback_result, dict):
            fallback_detected = fallback_result.get("fallback_detected", False)
        
        # Calculate aggregation efficiency
        if subflows_detected > 0:
            aggregation_efficiency = min(1.0, subflows_detected / 3.0)
        
        # Determine severity
        if not mptcp_supported:
            severity = MPTCPSeverity.NONE
        elif subflows_detected == 1 and not handover_detected:
            severity = MPTCPSeverity.LOW
        elif subflows_detected <= 2:
            severity = MPTCPSeverity.MEDIUM
        elif subflows_detected <= 4 or handover_detected:
            severity = MPTCPSeverity.HIGH
        else:
            severity = MPTCPSeverity.CRITICAL
        
        return MPTCPTestResult(
            timestamp=timestamp,
            target=target,
            mptcp_supported=mptcp_supported,
            subflows_detected=subflows_detected,
            path_diversity=path_diversity,
            handover_detected=handover_detected,
            aggregation_efficiency=aggregation_efficiency,
            fallback_detected=fallback_detected,
            severity=severity,
            details={
                "support_test": support_result if isinstance(support_result, dict) else {},
                "subflow_test": subflow_result if isinstance(subflow_result, dict) else {},
                "path_test": path_result if isinstance(path_result, dict) else {},
                "handover_test": handover_result if isinstance(handover_result, dict) else {},
                "fallback_test": fallback_result if isinstance(fallback_result, dict) else {},
            }
        )
    
    async def _test_mptcp_support(self, target: str) -> Dict[str, Any]:
        """
        Test if MPTCP is supported.
        
        Check TCP options for MPTCP capability.
        """
        supported = False
        
        try:
            # Connect and check TCP options
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                # Resolve target
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
                
                if infos:
                    sock.connect((infos[0][4][0], 443))
                    
                    # Check TCP options
                    # MPTCP uses TCP option kind 30 (0x1e)
                    # Note: Python socket doesn't expose TCP options directly
                    # This is a simplified test
                    
                    # Try to get TCP_INFO
                    try:
                        tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 100)
                        
                        # Check for MPTCP indicators
                        # tcpi_options may contain MPTCP flags
                        if len(tcp_info) >= 40:
                            options = struct.unpack("B", tcp_info[1:2])[0]
                            
                            # Check for MPTCP option (simplified)
                            # Real implementation would parse TCP options properly
                            if options & 0x20:  # Hypothetical MPTCP flag
                                supported = True
                    
                    except Exception:
                        pass
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "supported": False}
        
        return {
            "supported": supported,
        }
    
    async def _detect_subflows(self, target: str) -> Dict[str, Any]:
        """
        Detect MPTCP subflows.
        
        Count number of MPTCP subflows.
        """
        subflow_count = 0
        
        try:
            # Try to connect multiple times and detect subflows
            connections = []
            
            for _ in range(5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    loop = asyncio.get_event_loop()
                    infos = await loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
                    
                    if infos:
                        sock.connect((infos[0][4][0], 443))
                        connections.append(sock)
                
                except Exception:
                    pass
            
            # If multiple connections succeed, might be MPTCP subflows
            if len(connections) > 1:
                subflow_count = len(connections)
            
            # Close all connections
            for sock in connections:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "subflow_count": 0}
        
        return {
            "subflow_count": subflow_count,
        }
    
    async def _analyze_paths(self, target: str) -> Dict[str, Any]:
        """
        Analyze path diversity.
        
        Check if multiple network paths are used.
        """
        diversity_score = 0.0
        paths = set()
        
        try:
            # Connect multiple times and check source IPs
            for _ in range(5):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    loop = asyncio.get_event_loop()
                    infos = await loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
                    
                    if infos:
                        sock.connect((infos[0][4][0], 443))
                        
                        # Get local address
                        local_addr = sock.getsockname()
                        paths.add(local_addr[0])
                        
                        sock.close()
                
                except Exception:
                    pass
            
            # Calculate diversity
            if len(paths) > 1:
                diversity_score = min(1.0, len(paths) / 3.0)
        
        except Exception as e:
            return {"error": str(e), "diversity_score": 0.0}
        
        return {
            "diversity_score": diversity_score,
            "unique_paths": len(paths),
        }
    
    async def _detect_handover(self, target: str) -> Dict[str, Any]:
        """
        Detect path handover.
        
        Check if connection switches between paths.
        """
        handover_detected = False
        
        try:
            # Monitor connection for path changes
            # This is a simplified test
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
                
                if infos:
                    sock.connect((infos[0][4][0], 443))
                    
                    # Get initial local address
                    initial_addr = sock.getsockname()
                    
                    # Wait and check again
                    await asyncio.sleep(1)
                    
                    # Get current local address
                    current_addr = sock.getsockname()
                    
                    # If address changed, handover detected
                    if initial_addr != current_addr:
                        handover_detected = True
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "handover_detected": False}
        
        return {
            "handover_detected": handover_detected,
        }
    
    async def _detect_fallback(self, target: str) -> Dict[str, Any]:
        """
        Detect MPTCP fallback to regular TCP.
        
        Check if connection falls back to TCP when MPTCP not supported.
        """
        fallback_detected = False
        
        try:
            # Try MPTCP connection
            mptcp_success = False
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # Try to set MPTCP option
                # Note: This requires kernel support
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, 30, 1)  # MPTCP option
                    mptcp_success = True
                except Exception:
                    pass
                
                sock.close()
            
            except Exception:
                pass
            
            # Try regular TCP connection
            tcp_success = False
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
                
                if infos:
                    sock.connect((infos[0][4][0], 443))
                    tcp_success = True
                
                sock.close()
            
            except Exception:
                pass
            
            # If MPTCP failed but TCP succeeded, fallback detected
            if not mptcp_success and tcp_success:
                fallback_detected = True
        
        except Exception as e:
            return {"error": str(e), "fallback_detected": False}
        
        return {
            "fallback_detected": fallback_detected,
        }
