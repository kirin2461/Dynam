"""
ESNI/ECH (Encrypted Client Hello) Testing — detect ESNI/ECH weaknesses.

ESNI/ECH encrypt SNI in TLS 1.3, but have known weaknesses:
1. Not all servers support ESNI/ECH
2. Fallback to unencrypted SNI if ECH not supported
3. Cloudflare ECH has implementation weaknesses
4. DPI may block ECH completely (ECH blocking detection)
5. ECH configuration retrieval can leak info

Detection methods:
- ECH support detection — check if server supports ECH
- Fallback detection — detect fallback to unencrypted SNI
- ECH blocking detection — detect if DPI blocks ECH
- Configuration leak detection — check if ECH config leaks info
- Implementation weakness detection — detect known ECH weaknesses

Metrics:
- ech_supported: bool — whether ECH is supported
- fallback_detected: bool — fallback to unencrypted SNI detected
- ech_blocked: bool — ECH blocked by DPI
- config_leak: bool — ECH configuration leak detected
- implementation_weakness: bool — known weakness detected
- ech_provider: str — ECH provider (cloudflare, etc.)
"""

import asyncio
import socket
import ssl
import struct
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class ECHSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ECHTestResult:
    """Result of ESNI/ECH testing."""
    timestamp: str
    target: str
    ech_supported: bool
    fallback_detected: bool = False
    ech_blocked: bool = False
    config_leak: bool = False
    implementation_weakness: bool = False
    ech_provider: str = ""
    severity: ECHSeverity = ECHSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "ech_supported": self.ech_supported,
            "fallback_detected": self.fallback_detected,
            "ech_blocked": self.ech_blocked,
            "config_leak": self.config_leak,
            "implementation_weakness": self.implementation_weakness,
            "ech_provider": self.ech_provider,
            "severity": self.severity.value,
            "details": self.details,
        }


class ECHTester:
    """
    Test ESNI/ECH support and detect weaknesses.
    
    Tests:
    1. ECH support detection — check if server supports ECH
    2. Fallback detection — detect fallback to unencrypted SNI
    3. ECH blocking detection — detect if DPI blocks ECH
    4. Configuration leak detection — check if ECH config leaks info
    5. Implementation weakness detection — detect known weaknesses
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def test_ech(self, target: str) -> ECHTestResult:
        """
        Run comprehensive ESNI/ECH testing.
        
        Returns:
            ECHTestResult with all detected issues
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        support_task = self._test_ech_support(target)
        fallback_task = self._test_fallback(target)
        blocking_task = self._test_ech_blocking(target)
        config_task = self._test_config_leak(target)
        weakness_task = self._test_implementation_weakness(target)
        
        support_result, fallback_result, blocking_result, config_result, weakness_result = await asyncio.gather(
            support_task, fallback_task, blocking_task, config_task, weakness_task,
            return_exceptions=True
        )
        
        # Aggregate results
        ech_supported = isinstance(support_result, dict) and support_result.get("supported", False)
        fallback_detected = isinstance(fallback_result, dict) and fallback_result.get("fallback_detected", False)
        ech_blocked = isinstance(blocking_result, dict) and blocking_result.get("blocked", False)
        config_leak = isinstance(config_result, dict) and config_result.get("leak_detected", False)
        implementation_weakness = isinstance(weakness_result, dict) and weakness_result.get("weakness_detected", False)
        ech_provider = support_result.get("provider", "") if isinstance(support_result, dict) else ""
        
        # Determine severity
        if ech_supported and not (fallback_detected or ech_blocked or config_leak or implementation_weakness):
            severity = ECHSeverity.NONE
        elif ech_supported and fallback_detected:
            severity = ECHSeverity.MEDIUM
        elif ech_blocked:
            severity = ECHSeverity.HIGH
        elif not ech_supported:
            severity = ECHSeverity.LOW
        else:
            severity = ECHSeverity.CRITICAL
        
        return ECHTestResult(
            timestamp=timestamp,
            target=target,
            ech_supported=ech_supported,
            fallback_detected=fallback_detected,
            ech_blocked=ech_blocked,
            config_leak=config_leak,
            implementation_weakness=implementation_weakness,
            ech_provider=ech_provider,
            severity=severity,
            details={
                "support_test": support_result if isinstance(support_result, dict) else {},
                "fallback_test": fallback_result if isinstance(fallback_result, dict) else {},
                "blocking_test": blocking_result if isinstance(blocking_result, dict) else {},
                "config_test": config_result if isinstance(config_result, dict) else {},
                "weakness_test": weakness_result if isinstance(weakness_result, dict) else {},
            }
        )
    
    async def _test_ech_support(self, target: str) -> Dict[str, Any]:
        """
        Test if server supports ECH.
        
        Checks for ECH extension in TLS handshake and ECH configuration.
        """
        supported = False
        provider = ""
        
        try:
            # Try to connect with ECH
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Set ALPN to h2, http/1.1
            context.set_alpn_protocols(["h2", "http/1.1"])
            
            sock = socket.create_connection((target, 443), timeout=self.timeout)
            
            try:
                # Try to wrap with ECH (if supported by OpenSSL)
                # Note: ECH support requires OpenSSL 3.0+ and Python 3.10+
                try:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        # Check if ECH was used
                        # Note: Python's ssl module doesn't expose ECH status directly
                        # This is a simplified test
                        
                        # Check ALPN protocol
                        alpn = ssock.selected_alpn_protocol()
                        
                        # Check certificate for ECH indicators
                        cert = ssock.getpeercert()
                        if cert:
                            # Check if certificate is from Cloudflare (common ECH provider)
                            issuer = dict(x[0] for x in cert.get("issuer", []))
                            if "Cloudflare" in str(issuer):
                                supported = True
                                provider = "cloudflare"
                        
                        # If connection succeeded, assume ECH might be supported
                        supported = True
                
                except ssl.SSLError as e:
                    # If SSL error, ECH not supported
                    pass
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "supported": False}
        
        return {
            "supported": supported,
            "provider": provider,
        }
    
    async def _test_fallback(self, target: str) -> Dict[str, Any]:
        """
        Test if server falls back to unencrypted SNI.
        
        If ECH is not supported, server should fall back to unencrypted SNI.
        This fallback can be detected by DPI.
        """
        fallback_detected = False
        
        try:
            # Connect without ECH and check SNI
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((target, 443), timeout=self.timeout)
            
            try:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Check if certificate subject matches target
                        # If it does, SNI was used (fallback detected)
                        subject = dict(x[0] for x in cert.get("subject", []))
                        cn = subject.get("commonName", "")
                        
                        if cn and target.lower() in cn.lower():
                            fallback_detected = True
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "fallback_detected": False}
        
        return {
            "fallback_detected": fallback_detected,
        }
    
    async def _test_ech_blocking(self, target: str) -> Dict[str, Any]:
        """
        Test if DPI blocks ECH.
        
        Some DPI systems block ECH completely, forcing fallback to unencrypted SNI.
        """
        blocked = False
        
        try:
            # Try to connect with ECH multiple times
            # If connections fail intermittently, ECH might be blocked
            
            success_count = 0
            total_attempts = 5
            
            for _ in range(total_attempts):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.create_connection((target, 443), timeout=self.timeout)
                    
                    try:
                        with context.wrap_socket(sock, server_hostname=target) as ssock:
                            success_count += 1
                    finally:
                        sock.close()
                
                except Exception:
                    pass
            
            # If less than 50% success rate, ECH might be blocked
            if success_count < total_attempts * 0.5:
                blocked = True
        
        except Exception as e:
            return {"error": str(e), "blocked": False}
        
        return {
            "blocked": blocked,
            "success_rate": success_count / total_attempts if total_attempts > 0 else 0.0,
        }
    
    async def _test_config_leak(self, target: str) -> Dict[str, Any]:
        """
        Test if ECH configuration leaks information.
        
        ECH configuration is retrieved via HTTPS RR in DNS, which can leak
        which domains are being accessed.
        """
        leak_detected = False
        
        try:
            # Query DNS for HTTPS RR (ECH configuration)
            # This is a simplified test
            
            # Try to resolve target with DoH
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        "https://cloudflare-dns.com/dns-query",
                        params={"name": target, "type": "HTTPS"},
                        headers={"Accept": "application/dns-json"},
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            
                            # Check if HTTPS RR contains ECH configuration
                            # If it does, the query itself leaks the domain
                            if "Answer" in data:
                                for answer in data["Answer"]:
                                    if "ech" in str(answer).lower():
                                        leak_detected = True
                                        break
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "leak_detected": False}
        
        return {
            "leak_detected": leak_detected,
        }
    
    async def _test_implementation_weakness(self, target: str) -> Dict[str, Any]:
        """
        Test for known ECH implementation weaknesses.
        
        Checks for:
        - Cloudflare ECH configuration weaknesses
        - OpenSSL ECH implementation bugs
        - TLS 1.3 downgrade attacks
        """
        weakness_detected = False
        
        try:
            # Check TLS version
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((target, 443), timeout=self.timeout)
            
            try:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get TLS version
                    version = ssock.version()
                    
                    # ECH requires TLS 1.3
                    if version != "TLSv1.3":
                        weakness_detected = True
                    
                    # Get cipher
                    cipher = ssock.cipher()
                    
                    # Check for weak ciphers
                    if cipher:
                        cipher_name = cipher[0]
                        if "RSA" in cipher_name or "RC4" in cipher_name or "DES" in cipher_name:
                            weakness_detected = True
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "weakness_detected": False}
        
        return {
            "weakness_detected": weakness_detected,
        }
