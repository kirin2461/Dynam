"""
IPv6 Transition Mechanisms Testing — test IPv6 transition for DPI bypass.

IPv6 transition mechanisms can bypass IPv4-only DPI:
1. 6to4 tunneling — encapsulate IPv6 in IPv4
2. Teredo tunneling — encapsulate IPv6 in UDP/IPv4
3. NAT64/DNS64 — translate IPv6 to IPv4
4. ISATAP — encapsulate IPv6 in IPv4
5. 6in4/6rd — various IPv6-in-IPv4 tunneling

Detection methods:
- 6to4 detection — detect 6to4 tunneling
- Teredo detection — detect Teredo tunneling
- NAT64 detection — detect NAT64 translation
- ISATAP detection — detect ISATAP tunneling
- General tunnel detection — detect IPv6 tunnels

Metrics:
- ipv6_supported: bool — whether IPv6 is supported
- tunnel_detected: bool — IPv6 tunnel detected
- tunnel_type: str — type of tunnel (6to4, teredo, nat64, etc.)
- tunnel_reliability: float — tunnel reliability score
- bypass_potential: float — potential for DPI bypass
"""

import asyncio
import socket
import struct
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class IPv6Severity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IPv6TransitionResult:
    """Result of IPv6 transition mechanism testing."""
    timestamp: str
    target: str
    ipv6_supported: bool
    tunnel_detected: bool = False
    tunnel_type: str = ""
    tunnel_reliability: float = 0.0
    bypass_potential: float = 0.0
    severity: IPv6Severity = IPv6Severity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "ipv6_supported": self.ipv6_supported,
            "tunnel_detected": self.tunnel_detected,
            "tunnel_type": self.tunnel_type,
            "tunnel_reliability": self.tunnel_reliability,
            "bypass_potential": self.bypass_potential,
            "severity": self.severity.value,
            "details": self.details,
        }


class IPv6TransitionTester:
    """
    Test IPv6 transition mechanisms for DPI bypass potential.
    
    Tests:
    1. IPv6 support detection — check if IPv6 is available
    2. 6to4 detection — detect 6to4 tunneling
    3. Teredo detection — detect Teredo tunneling
    4. NAT64 detection — detect NAT64 translation
    5. ISATAP detection — detect ISATAP tunneling
    """
    
    # Well-known IPv6 transition addresses
    TEREDO_SERVER = "64:ff9b::"  # NAT64 prefix
    SIXTO4_RELAY = "192.88.99.1"  # 6to4 relay
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def test_ipv6_transition(self, target: str) -> IPv6TransitionResult:
        """
        Run comprehensive IPv6 transition testing.
        
        Returns:
            IPv6TransitionResult with all detected mechanisms
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        ipv6_task = self._test_ipv6_support(target)
        sixto4_task = self._detect_6to4(target)
        teredo_task = self._detect_teredo(target)
        nat64_task = self._detect_nat64(target)
        isatap_task = self._detect_isatap(target)
        
        ipv6_result, sixto4_result, teredo_result, nat64_result, isatap_result = await asyncio.gather(
            ipv6_task, sixto4_task, teredo_task, nat64_task, isatap_task,
            return_exceptions=True
        )
        
        # Aggregate results
        ipv6_supported = False
        tunnel_detected = False
        tunnel_type = ""
        tunnel_reliability = 0.0
        
        if isinstance(ipv6_result, dict):
            ipv6_supported = ipv6_result.get("supported", False)
        
        if isinstance(sixto4_result, dict) and sixto4_result.get("detected", False):
            tunnel_detected = True
            tunnel_type = "6to4"
            tunnel_reliability = sixto4_result.get("reliability", 0.0)
        
        if isinstance(teredo_result, dict) and teredo_result.get("detected", False):
            tunnel_detected = True
            tunnel_type = "teredo"
            tunnel_reliability = teredo_result.get("reliability", 0.0)
        
        if isinstance(nat64_result, dict) and nat64_result.get("detected", False):
            tunnel_detected = True
            tunnel_type = "nat64"
            tunnel_reliability = nat64_result.get("reliability", 0.0)
        
        if isinstance(isatap_result, dict) and isatap_result.get("detected", False):
            tunnel_detected = True
            tunnel_type = "isatap"
            tunnel_reliability = isatap_result.get("reliability", 0.0)
        
        # Calculate bypass potential
        bypass_potential = 0.0
        if tunnel_detected:
            bypass_potential = tunnel_reliability * 0.8
            if not ipv6_supported:
                bypass_potential += 0.2  # Tunnel more valuable if no native IPv6
        
        # Determine severity
        if not tunnel_detected:
            severity = IPv6Severity.NONE
        elif tunnel_reliability < 0.3:
            severity = IPv6Severity.LOW
        elif tunnel_reliability < 0.6:
            severity = IPv6Severity.MEDIUM
        elif tunnel_reliability < 0.8:
            severity = IPv6Severity.HIGH
        else:
            severity = IPv6Severity.CRITICAL
        
        return IPv6TransitionResult(
            timestamp=timestamp,
            target=target,
            ipv6_supported=ipv6_supported,
            tunnel_detected=tunnel_detected,
            tunnel_type=tunnel_type,
            tunnel_reliability=tunnel_reliability,
            bypass_potential=bypass_potential,
            severity=severity,
            details={
                "ipv6_test": ipv6_result if isinstance(ipv6_result, dict) else {},
                "6to4_test": sixto4_result if isinstance(sixto4_result, dict) else {},
                "teredo_test": teredo_result if isinstance(teredo_result, dict) else {},
                "nat64_test": nat64_result if isinstance(nat64_result, dict) else {},
                "isatap_test": isatap_result if isinstance(isatap_result, dict) else {},
            }
        )
    
    async def _test_ipv6_support(self, target: str) -> Dict[str, Any]:
        """
        Test if IPv6 is supported.
        
        Check if target has IPv6 address and is reachable via IPv6.
        """
        supported = False
        
        try:
            # Try to resolve IPv6 address
            loop = asyncio.get_event_loop()
            
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(target, 443, socket.AF_INET6, socket.SOCK_STREAM),
                    timeout=self.timeout
                )
                
                if infos:
                    # Try to connect via IPv6
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    try:
                        sock.connect((infos[0][4][0], 443))
                        supported = True
                    finally:
                        sock.close()
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "supported": False}
        
        return {
            "supported": supported,
        }
    
    async def _detect_6to4(self, target: str) -> Dict[str, Any]:
        """
        Detect 6to4 tunneling.
        
        6to4 encapsulates IPv6 in IPv4 using 2002::/16 prefix.
        """
        detected = False
        reliability = 0.0
        
        try:
            # Check for 6to4 relay
            # Try to connect to 6to4 relay
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send probe to 6to4 relay
                sock.sendto(b"\x00", (self.SIXTO4_RELAY, 17))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    if data:
                        detected = True
                        reliability = 0.5
                except socket.timeout:
                    pass
                
                sock.close()
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "reliability": reliability,
        }
    
    async def _detect_teredo(self, target: str) -> Dict[str, Any]:
        """
        Detect Teredo tunneling.
        
        Teredo encapsulates IPv6 in UDP/IPv4 using 2001::/32 prefix.
        """
        detected = False
        reliability = 0.0
        
        try:
            # Check for Teredo server
            # Try to connect to Teredo server
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send probe to Teredo server
                sock.sendto(b"\x00", ("teredo.ipv6.microsoft.com", 3544))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    if data:
                        detected = True
                        reliability = 0.7
                except socket.timeout:
                    pass
                
                sock.close()
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "reliability": reliability,
        }
    
    async def _detect_nat64(self, target: str) -> Dict[str, Any]:
        """
        Detect NAT64 translation.
        
        NAT64 translates IPv6 to IPv4 using 64:ff9b::/96 prefix.
        """
        detected = False
        reliability = 0.0
        
        try:
            # Try to resolve target via NAT64 prefix
            loop = asyncio.get_event_loop()
            
            try:
                # Construct NAT64 address
                # Resolve IPv4 first
                ipv4_infos = await loop.getaddrinfo(target, 443, socket.AF_INET, socket.SOCK_STREAM)
                
                if ipv4_infos:
                    ipv4_addr = ipv4_infos[0][4][0]
                    
                    # Construct NAT64 address
                    # Format: 64:ff9b::IPv4
                    parts = ipv4_addr.split(".")
                    nat64_addr = f"64:ff9b::{parts[0]}{parts[1]}:{parts[2]}{parts[3]}"
                    
                    # Try to connect via NAT64
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    
                    try:
                        sock.connect((nat64_addr, 443))
                        detected = True
                        reliability = 0.9
                    finally:
                        sock.close()
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "reliability": reliability,
        }
    
    async def _detect_isatap(self, target: str) -> Dict[str, Any]:
        """
        Detect ISATAP tunneling.
        
        ISATAP encapsulates IPv6 in IPv4 using ::0:5efe:IPv4 format.
        """
        detected = False
        reliability = 0.0
        
        try:
            # Check for ISATAP router
            # Try to resolve ISATAP router
            loop = asyncio.get_event_loop()
            
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo("isatap", 443, socket.AF_INET6, socket.SOCK_STREAM),
                    timeout=self.timeout
                )
                
                if infos:
                    detected = True
                    reliability = 0.6
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "reliability": reliability,
        }
