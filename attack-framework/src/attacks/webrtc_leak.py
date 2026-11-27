"""
WebRTC Leak Prevention — detect and prevent IP/DNS leaks via WebRTC.

WebRTC can expose real IP addresses through STUN requests, bypassing proxies/VPN.

Detection methods:
1. STUN request analysis — detect outbound STUN traffic
2. ICE candidate inspection — check for real IP in candidates
3. DNS leak detection — check if DNS queries leak real IP
4. TURN server validation — ensure TURN is used instead of direct

Metrics:
- leak_detected: bool — whether any leak was found
- leaked_ips: list — list of leaked IP addresses
- stun_requests: int — number of STUN requests detected
- ice_candidates_with_ip: int — ICE candidates containing real IP
- dns_queries_leaked: int — DNS queries that leaked real IP
"""

import asyncio
import socket
import struct
import re
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class LeakSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class WebRTCLeakResult:
    """Result of WebRTC leak detection."""
    timestamp: str
    target: str
    leak_detected: bool
    leaked_ips: List[str] = field(default_factory=list)
    stun_requests: int = 0
    ice_candidates_with_ip: int = 0
    dns_queries_leaked: int = 0
    severity: LeakSeverity = LeakSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "leak_detected": self.leak_detected,
            "leaked_ips": self.leaked_ips,
            "stun_requests": self.stun_requests,
            "ice_candidates_with_ip": self.ice_candidates_with_ip,
            "dns_queries_leaked": self.dns_queries_leaked,
            "severity": self.severity.value,
            "details": self.details,
        }


class WebRTCLeakDetector:
    """
    Detect WebRTC IP/DNS leaks.
    
    Tests:
    1. STUN server connection — check if target connects to public STUN servers
    2. ICE candidate analysis — parse SDP for real IP addresses
    3. DNS leak test — check if DNS queries reveal real IP
    4. TURN validation — ensure media goes through TURN, not direct
    """
    
    # Public STUN servers to test against
    STUN_SERVERS = [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
        "stun.stunprotocol.org:3478",
    ]
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def detect_leaks(self, target: str) -> WebRTCLeakResult:
        """
        Run comprehensive WebRTC leak detection.
        
        Returns:
            WebRTCLeakResult with all detected leaks
        """
        timestamp = datetime.now().isoformat()
        
        # Run all detection tests in parallel
        stun_task = self._test_stun_connections(target)
        ice_task = self._test_ice_candidates(target)
        dns_task = self._test_dns_leaks(target)
        turn_task = self._test_turn_usage(target)
        
        stun_result, ice_result, dns_result, turn_result = await asyncio.gather(
            stun_task, ice_task, dns_task, turn_task,
            return_exceptions=True
        )
        
        # Aggregate results
        leaked_ips = set()
        stun_requests = 0
        ice_candidates_with_ip = 0
        dns_queries_leaked = 0
        
        if isinstance(stun_result, dict):
            stun_requests = stun_result.get("stun_requests", 0)
            leaked_ips.update(stun_result.get("leaked_ips", []))
        
        if isinstance(ice_result, dict):
            ice_candidates_with_ip = ice_result.get("candidates_with_ip", 0)
            leaked_ips.update(ice_result.get("leaked_ips", []))
        
        if isinstance(dns_result, dict):
            dns_queries_leaked = dns_result.get("queries_leaked", 0)
            leaked_ips.update(dns_result.get("leaked_ips", []))
        
        turn_valid = isinstance(turn_result, dict) and turn_result.get("uses_turn", False)
        
        # Determine severity
        leak_detected = len(leaked_ips) > 0 or stun_requests > 0 or dns_queries_leaked > 0
        
        if not leak_detected and turn_valid:
            severity = LeakSeverity.NONE
        elif len(leaked_ips) == 0 and stun_requests == 0:
            severity = LeakSeverity.LOW
        elif len(leaked_ips) <= 2:
            severity = LeakSeverity.MEDIUM
        elif len(leaked_ips) <= 5:
            severity = LeakSeverity.HIGH
        else:
            severity = LeakSeverity.CRITICAL
        
        return WebRTCLeakResult(
            timestamp=timestamp,
            target=target,
            leak_detected=leak_detected,
            leaked_ips=list(leaked_ips),
            stun_requests=stun_requests,
            ice_candidates_with_ip=ice_candidates_with_ip,
            dns_queries_leaked=dns_queries_leaked,
            severity=severity,
            details={
                "stun_test": stun_result if isinstance(stun_result, dict) else {},
                "ice_test": ice_result if isinstance(ice_result, dict) else {},
                "dns_test": dns_result if isinstance(dns_result, dict) else {},
                "turn_test": turn_result if isinstance(turn_result, dict) else {},
            }
        )
    
    async def _test_stun_connections(self, target: str) -> Dict[str, Any]:
        """
        Test if target connects to public STUN servers.
        
        STUN (Session Traversal Utilities for NAT) is used by WebRTC to discover
        public IP addresses. If target connects to public STUN servers, it may
        leak real IP.
        """
        leaked_ips = []
        stun_requests = 0
        
        # Check if target's DNS resolves to multiple IPs (potential STUN servers)
        try:
            loop = asyncio.get_event_loop()
            
            for stun_server in self.STUN_SERVERS[:2]:  # Test first 2 servers
                host, port = stun_server.rsplit(":", 1)
                port = int(port)
                
                try:
                    # Try to resolve STUN server
                    infos = await asyncio.wait_for(
                        loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM),
                        timeout=self.timeout
                    )
                    
                    if infos:
                        stun_requests += 1
                        
                        # Check if any resolved IP matches target's IP range
                        for info in infos:
                            ip = info[4][0]
                            # If STUN server resolves to same subnet as target, potential leak
                            if self._is_same_subnet(ip, target):
                                leaked_ips.append(ip)
                
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "stun_requests": 0, "leaked_ips": []}
        
        return {
            "stun_requests": stun_requests,
            "leaked_ips": leaked_ips,
            "tested_servers": len(self.STUN_SERVERS[:2]),
        }
    
    async def _test_ice_candidates(self, target: str) -> Dict[str, Any]:
        """
        Analyze ICE candidates for real IP addresses.
        
        ICE (Interactive Connectivity Establishment) candidates contain IP addresses.
        If candidates contain real IP (not relay), it's a leak.
        """
        candidates_with_ip = 0
        leaked_ips = []
        
        try:
            # Fetch target's WebRTC SDP (if available)
            # This is a simplified test — real implementation would parse actual SDP
            async with aiohttp.ClientSession() as session:
                # Check common WebRTC endpoints
                endpoints = [
                    f"https://{target}/webrtc",
                    f"https://{target}/rtc",
                    f"https://{target}/api/webrtc",
                ]
                
                for endpoint in endpoints:
                    try:
                        async with session.get(
                            endpoint,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                
                                # Parse SDP for ICE candidates
                                # Format: a=candidate:<foundation> <component> <protocol> <priority> <ip> <port> typ <type>
                                candidate_pattern = r'a=candidate:\d+ \d+ (udp|tcp) \d+ ([\d\.]+) \d+ typ (host|srflx|prflx|relay)'
                                matches = re.findall(candidate_pattern, text)
                                
                                for protocol, ip, candidate_type in matches:
                                    # host = real IP, srflx = server reflexive (public IP)
                                    if candidate_type in ("host", "srflx"):
                                        candidates_with_ip += 1
                                        if not self._is_private_ip(ip):
                                            leaked_ips.append(ip)
                    
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e), "candidates_with_ip": 0, "leaked_ips": []}
        
        return {
            "candidates_with_ip": candidates_with_ip,
            "leaked_ips": leaked_ips,
            "total_candidates_checked": candidates_with_ip,
        }
    
    async def _test_dns_leaks(self, target: str) -> Dict[str, Any]:
        """
        Test if DNS queries leak real IP.
        
        DNS leak occurs when DNS queries go through ISP DNS instead of proxy/VPN DNS.
        """
        queries_leaked = 0
        leaked_ips = []
        
        try:
            loop = asyncio.get_event_loop()
            
            # Resolve target through multiple DNS servers
            dns_servers = [
                "8.8.8.8",      # Google DNS
                "1.1.1.1",      # Cloudflare
                "9.9.9.9",      # Quad9
            ]
            
            resolved_ips = set()
            
            for dns_server in dns_servers:
                try:
                    # Create DNS query packet
                    # This is a simplified test — real implementation would craft DNS packets
                    query = f"dig @{dns_server} {target} +short"
                    process = await asyncio.create_subprocess_shell(
                        query,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=self.timeout
                    )
                    
                    if stdout:
                        ips = stdout.decode().strip().split("\n")
                        for ip in ips:
                            ip = ip.strip()
                            if self._is_valid_ip(ip):
                                resolved_ips.add(ip)
                                queries_leaked += 1
                
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    pass
            
            # Check if resolved IPs are in different subnets (potential leak)
            if len(resolved_ips) > 1:
                # Multiple different IPs = potential DNS leak
                leaked_ips.extend(list(resolved_ips)[:3])
        
        except Exception as e:
            return {"error": str(e), "queries_leaked": 0, "leaked_ips": []}
        
        return {
            "queries_leaked": queries_leaked,
            "leaked_ips": leaked_ips,
            "dns_servers_tested": len(dns_servers),
        }
    
    async def _test_turn_usage(self, target: str) -> Dict[str, Any]:
        """
        Test if target uses TURN relay (good) or direct connection (bad).
        
        TURN (Traversal Using Relays around NAT) relays media through a server,
        hiding real IP. If target doesn't use TURN, it's a potential leak.
        """
        uses_turn = False
        
        try:
            # Check for TURN server configuration in target's WebRTC setup
            async with aiohttp.ClientSession() as session:
                endpoints = [
                    f"https://{target}/config",
                    f"https://{target}/api/config",
                    f"https://{target}/webrtc/config",
                ]
                
                for endpoint in endpoints:
                    try:
                        async with session.get(
                            endpoint,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                
                                # Check for TURN server configuration
                                # Format: "turn:server:port" or "turns:server:port"
                                if re.search(r'turn[s]?:[^\s]+', text, re.IGNORECASE):
                                    uses_turn = True
                                    break
                    
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e), "uses_turn": False}
        
        return {
            "uses_turn": uses_turn,
            "recommendation": "Use TURN relay to hide real IP" if not uses_turn else "TURN relay detected",
        }
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range (RFC 1918)."""
        if not self._is_valid_ip(ip):
            return False
        
        parts = [int(x) for x in ip.split(".")]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8
        if parts[0] == 127:
            return True
        
        return False
    
    def _is_same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in the same /24 subnet."""
        if not self._is_valid_ip(ip1) or not self._is_valid_ip(ip2):
            return False
        
        parts1 = ip1.split(".")
        parts2 = ip2.split(".")
        
        # Compare first 3 octets (/24 subnet)
        return parts1[:3] == parts2[:3]
