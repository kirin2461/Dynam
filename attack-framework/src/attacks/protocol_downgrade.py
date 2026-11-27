"""
Protocol Downgrade Attack — test protocol downgrade vulnerabilities.

Protocol downgrade attacks force connections to use weaker protocols:
1. TLS downgrade — force TLS 1.0/1.1 instead of 1.3
2. HTTP downgrade — force HTTP instead of HTTPS
3. QUIC downgrade — force TCP instead of QUIC
4. Cipher downgrade — force weak ciphers
5. Algorithm downgrade — force weak algorithms

Detection methods:
- TLS version test — check if TLS downgrade is possible
- HTTP downgrade test — check if HTTP downgrade is possible
- QUIC downgrade test — check if QUIC downgrade is possible
- Cipher test — check if weak ciphers are accepted
- Algorithm test — check if weak algorithms are accepted

Metrics:
- tls_downgrade_possible: bool — TLS downgrade possible
- http_downgrade_possible: bool — HTTP downgrade possible
- quic_downgrade_possible: bool — QUIC downgrade possible
- weak_ciphers_accepted: bool — weak ciphers accepted
- weak_algorithms_accepted: bool — weak algorithms accepted
- downgrade_risk: float — overall downgrade risk score
"""

import asyncio
import socket
import ssl
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class DowngradeSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ProtocolDowngradeResult:
    """Result of protocol downgrade testing."""
    timestamp: str
    target: str
    tls_downgrade_possible: bool = False
    http_downgrade_possible: bool = False
    quic_downgrade_possible: bool = False
    weak_ciphers_accepted: bool = False
    weak_algorithms_accepted: bool = False
    downgrade_risk: float = 0.0
    severity: DowngradeSeverity = DowngradeSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "tls_downgrade_possible": self.tls_downgrade_possible,
            "http_downgrade_possible": self.http_downgrade_possible,
            "quic_downgrade_possible": self.quic_downgrade_possible,
            "weak_ciphers_accepted": self.weak_ciphers_accepted,
            "weak_algorithms_accepted": self.weak_algorithms_accepted,
            "downgrade_risk": self.downgrade_risk,
            "severity": self.severity.value,
            "details": self.details,
        }


class ProtocolDowngradeTester:
    """
    Test protocol downgrade vulnerabilities.
    
    Tests:
    1. TLS downgrade — check if TLS downgrade is possible
    2. HTTP downgrade — check if HTTP downgrade is possible
    3. QUIC downgrade — check if QUIC downgrade is possible
    4. Cipher downgrade — check if weak ciphers are accepted
    5. Algorithm downgrade — check if weak algorithms are accepted
    """
    
    # Weak ciphers to test
    WEAK_CIPHERS = [
        "RC4-SHA",
        "RC4-MD5",
        "DES-CBC3-SHA",
        "DES-CBC-SHA",
        "EXP-RC4-MD5",
        "EXP-DES-CBC-SHA",
    ]
    
    # Weak TLS versions
    WEAK_TLS_VERSIONS = [
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
    ]
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def test_downgrade(self, target: str) -> ProtocolDowngradeResult:
        """
        Run comprehensive protocol downgrade testing.
        
        Returns:
            ProtocolDowngradeResult with all detected vulnerabilities
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        tls_task = self._test_tls_downgrade(target)
        http_task = self._test_http_downgrade(target)
        quic_task = self._test_quic_downgrade(target)
        cipher_task = self._test_weak_ciphers(target)
        algo_task = self._test_weak_algorithms(target)
        
        tls_result, http_result, quic_result, cipher_result, algo_result = await asyncio.gather(
            tls_task, http_task, quic_task, cipher_task, algo_task,
            return_exceptions=True
        )
        
        # Aggregate results
        tls_downgrade_possible = False
        http_downgrade_possible = False
        quic_downgrade_possible = False
        weak_ciphers_accepted = False
        weak_algorithms_accepted = False
        
        if isinstance(tls_result, dict):
            tls_downgrade_possible = tls_result.get("downgrade_possible", False)
        
        if isinstance(http_result, dict):
            http_downgrade_possible = http_result.get("downgrade_possible", False)
        
        if isinstance(quic_result, dict):
            quic_downgrade_possible = quic_result.get("downgrade_possible", False)
        
        if isinstance(cipher_result, dict):
            weak_ciphers_accepted = cipher_result.get("weak_accepted", False)
        
        if isinstance(algo_result, dict):
            weak_algorithms_accepted = algo_result.get("weak_accepted", False)
        
        # Calculate downgrade risk
        downgrade_risk = 0.0
        if tls_downgrade_possible:
            downgrade_risk += 0.3
        if http_downgrade_possible:
            downgrade_risk += 0.3
        if quic_downgrade_possible:
            downgrade_risk += 0.2
        if weak_ciphers_accepted:
            downgrade_risk += 0.1
        if weak_algorithms_accepted:
            downgrade_risk += 0.1
        
        downgrade_risk = min(1.0, downgrade_risk)
        
        # Determine severity
        if downgrade_risk == 0.0:
            severity = DowngradeSeverity.NONE
        elif downgrade_risk < 0.3:
            severity = DowngradeSeverity.LOW
        elif downgrade_risk < 0.6:
            severity = DowngradeSeverity.MEDIUM
        elif downgrade_risk < 0.8:
            severity = DowngradeSeverity.HIGH
        else:
            severity = DowngradeSeverity.CRITICAL
        
        return ProtocolDowngradeResult(
            timestamp=timestamp,
            target=target,
            tls_downgrade_possible=tls_downgrade_possible,
            http_downgrade_possible=http_downgrade_possible,
            quic_downgrade_possible=quic_downgrade_possible,
            weak_ciphers_accepted=weak_ciphers_accepted,
            weak_algorithms_accepted=weak_algorithms_accepted,
            downgrade_risk=downgrade_risk,
            severity=severity,
            details={
                "tls_test": tls_result if isinstance(tls_result, dict) else {},
                "http_test": http_result if isinstance(http_result, dict) else {},
                "quic_test": quic_result if isinstance(quic_result, dict) else {},
                "cipher_test": cipher_result if isinstance(cipher_result, dict) else {},
                "algorithm_test": algo_result if isinstance(algo_result, dict) else {},
            }
        )
    
    async def _test_tls_downgrade(self, target: str) -> Dict[str, Any]:
        """
        Test if TLS downgrade is possible.
        
        Try to connect with older TLS versions.
        """
        downgrade_possible = False
        supported_versions = []
        
        try:
            # Try each weak TLS version
            for tls_version in self.WEAK_TLS_VERSIONS:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.maximum_version = tls_version
                    context.minimum_version = tls_version
                    
                    sock = socket.create_connection((target, 443), timeout=self.timeout)
                    
                    try:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            version = ssock.version()
                            supported_versions.append(version)
                            downgrade_possible = True
                    finally:
                        sock.close()
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "downgrade_possible": False}
        
        return {
            "downgrade_possible": downgrade_possible,
            "supported_versions": supported_versions,
        }
    
    async def _test_http_downgrade(self, target: str) -> Dict[str, Any]:
        """
        Test if HTTP downgrade is possible.
        
        Try to connect via HTTP instead of HTTPS.
        """
        downgrade_possible = False
        
        try:
            # Try HTTP connection
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"http://{target}",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False
                    ) as resp:
                        # If HTTP works (even with redirect), downgrade possible
                        if resp.status < 400:
                            downgrade_possible = True
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "downgrade_possible": False}
        
        return {
            "downgrade_possible": downgrade_possible,
        }
    
    async def _test_quic_downgrade(self, target: str) -> Dict[str, Any]:
        """
        Test if QUIC downgrade is possible.
        
        Check if server falls back to TCP when QUIC not available.
        """
        downgrade_possible = False
        
        try:
            # Try TCP connection
            try:
                sock = socket.create_connection((target, 443), timeout=self.timeout)
                sock.close()
                
                # If TCP works, QUIC downgrade is possible
                # (server doesn't require QUIC)
                downgrade_possible = True
            
            except Exception:
                pass
        
        except Exception as e:
            return {"error": str(e), "downgrade_possible": False}
        
        return {
            "downgrade_possible": downgrade_possible,
        }
    
    async def _test_weak_ciphers(self, target: str) -> Dict[str, Any]:
        """
        Test if weak ciphers are accepted.
        
        Try to connect with weak ciphers.
        """
        weak_accepted = False
        accepted_ciphers = []
        
        try:
            # Try each weak cipher
            for cipher in self.WEAK_CIPHERS:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.set_ciphers(cipher)
                    
                    sock = socket.create_connection((target, 443), timeout=self.timeout)
                    
                    try:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            accepted_ciphers.append(cipher)
                            weak_accepted = True
                    finally:
                        sock.close()
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "weak_accepted": False}
        
        return {
            "weak_accepted": weak_accepted,
            "accepted_ciphers": accepted_ciphers,
        }
    
    async def _test_weak_algorithms(self, target: str) -> Dict[str, Any]:
        """
        Test if weak algorithms are accepted.
        
        Check for weak signature algorithms, key exchange, etc.
        """
        weak_accepted = False
        
        try:
            # Connect and check certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((target, 443), timeout=self.timeout)
            
            try:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Check certificate algorithm
                        # Look for weak algorithms in certificate
                        cert_str = str(cert)
                        
                        if "MD5" in cert_str or "SHA1" in cert_str:
                            weak_accepted = True
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "weak_accepted": False}
        
        return {
            "weak_accepted": weak_accepted,
        }
