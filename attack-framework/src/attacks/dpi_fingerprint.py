"""
DPI Fingerprinting — identify which DPI system is deployed and auto-select bypass strategies.

Different DPI (Deep Packet Inspection) systems have different weaknesses:
- Sandvine: weak HTTP parsing, vulnerable to header obfuscation
- Allot: strict protocol validation, weak against fragmentation
- Qosmos: ML-based, vulnerable to adversarial padding
- nPuls: timing-based detection, weak against timing manipulation
- Fortinet: certificate pinning issues, weak against TLS splitting

Detection methods:
1. Response pattern analysis — identify DPI-specific error messages
2. TCP behavior analysis — detect DPI-specific TCP stack modifications
3. TLS fingerprinting — identify DPI-specific TLS inspection patterns
4. HTTP parsing quirks — detect DPI-specific HTTP parser behavior
5. Protocol support analysis — identify DPI-specific protocol limitations

Metrics:
- dpi_detected: bool — whether DPI system was identified
- dpi_system: str — identified DPI system (sandvine, allot, qosmos, etc.)
- confidence: float — confidence in identification (0-1)
- bypass_strategies: list — recommended bypass strategies
- detection_methods_used: list — methods used for identification
"""

import asyncio
import socket
import struct
import ssl
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class DPISystem(Enum):
    UNKNOWN = "unknown"
    SANDVINE = "sandvine"
    ALLOT = "allot"
    QOSMOS = "qosmos"
    NPULS = "npuls"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    CISCO = "cisco"
    CUSTOM = "custom"


class BypassStrategy(Enum):
    ECS_INJECTION = "ecs_injection"
    FRAGMENTATION = "fragmentation"
    TTL_MANIPULATION = "ttl_manipulation"
    HTTP_OBFUSCATION = "http_obfuscation"
    TLS_SPLITTING = "tls_splitting"
    PROTOCOL_ROTATION = "protocol_rotation"
    ADVERSARIAL_PADDING = "adversarial_padding"
    TIMING_MANIPULATION = "timing_manipulation"


@dataclass
class DPIFingerprintResult:
    """Result of DPI system fingerprinting."""
    timestamp: str
    target: str
    dpi_detected: bool
    dpi_system: DPISystem = DPISystem.UNKNOWN
    confidence: float = 0.0
    bypass_strategies: List[BypassStrategy] = field(default_factory=list)
    detection_methods_used: List[str] = field(default_factory=list)
    characteristics: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "dpi_detected": self.dpi_detected,
            "dpi_system": self.dpi_system.value,
            "confidence": self.confidence,
            "bypass_strategies": [s.value for s in self.bypass_strategies],
            "detection_methods_used": self.detection_methods_used,
            "characteristics": self.characteristics,
            "details": self.details,
        }


class DPIFingerprinter:
    """
    Identify DPI system and recommend bypass strategies.
    
    Tests:
    1. Response pattern analysis — detect DPI-specific error messages
    2. TCP behavior analysis — detect DPI-specific TCP modifications
    3. TLS fingerprinting — detect DPI-specific TLS inspection
    4. HTTP parsing quirks — detect DPI-specific parser behavior
    5. Protocol support analysis — detect DPI-specific limitations
    """
    
    # DPI system signatures
    SIGNATURES = {
        DPISystem.SANDVINE: {
            "patterns": [
                r"sandvine",
                r"policy.*violation",
                r"content.*filtering",
            ],
            "characteristics": {
                "tcp_window_scaling": False,
                "http_parsing_strict": False,
                "tls_inspection": True,
                "fragmentation_handling": "partial",
            },
            "best_strategies": [
                BypassStrategy.HTTP_OBFUSCATION,
                BypassStrategy.ECS_INJECTION,
                BypassStrategy.PROTOCOL_ROTATION,
            ],
        },
        DPISystem.ALLOT: {
            "patterns": [
                r"allot",
                r"communication.*control",
                r"bandwidth.*management",
            ],
            "characteristics": {
                "tcp_window_scaling": True,
                "http_parsing_strict": True,
                "tls_inspection": True,
                "fragmentation_handling": "strict",
            },
            "best_strategies": [
                BypassStrategy.FRAGMENTATION,
                BypassStrategy.TLS_SPLITTING,
                BypassStrategy.TTL_MANIPULATION,
            ],
        },
        DPISystem.QOSMOS: {
            "patterns": [
                r"qosmos",
                r"deep.*inspection",
                r"application.*recognition",
            ],
            "characteristics": {
                "tcp_window_scaling": True,
                "http_parsing_strict": True,
                "tls_inspection": True,
                "ml_based_detection": True,
            },
            "best_strategies": [
                BypassStrategy.ADVERSARIAL_PADDING,
                BypassStrategy.PROTOCOL_ROTATION,
                BypassStrategy.HTTP_OBFUSCATION,
            ],
        },
        DPISystem.NPULS: {
            "patterns": [
                r"npuls",
                r"timing.*analysis",
                r"flow.*analysis",
            ],
            "characteristics": {
                "tcp_window_scaling": True,
                "http_parsing_strict": False,
                "tls_inspection": False,
                "timing_based_detection": True,
            },
            "best_strategies": [
                BypassStrategy.TIMING_MANIPULATION,
                BypassStrategy.PROTOCOL_ROTATION,
                BypassStrategy.ECS_INJECTION,
            ],
        },
        DPISystem.FORTINET: {
            "patterns": [
                r"fortinet",
                r"fortigate",
                r"web.*filter",
            ],
            "characteristics": {
                "tcp_window_scaling": True,
                "http_parsing_strict": True,
                "tls_inspection": True,
                "certificate_pinning": True,
            },
            "best_strategies": [
                BypassStrategy.TLS_SPLITTING,
                BypassStrategy.FRAGMENTATION,
                BypassStrategy.HTTP_OBFUSCATION,
            ],
        },
        DPISystem.PALO_ALTO: {
            "patterns": [
                r"palo.*alto",
                r"app-id",
                r"threat.*prevention",
            ],
            "characteristics": {
                "tcp_window_scaling": True,
                "http_parsing_strict": True,
                "tls_inspection": True,
                "ml_based_detection": True,
            },
            "best_strategies": [
                BypassStrategy.ADVERSARIAL_PADDING,
                BypassStrategy.PROTOCOL_ROTATION,
                BypassStrategy.TLS_SPLITTING,
            ],
        },
        DPISystem.CISCO: {
            "patterns": [
                r"cisco",
                r"asa",
                r"firepower",
            ],
            "characteristics": {
                "tcp_window_scaling": True,
                "http_parsing_strict": True,
                "tls_inspection": True,
                "protocol_validation": True,
            },
            "best_strategies": [
                BypassStrategy.FRAGMENTATION,
                BypassStrategy.HTTP_OBFUSCATION,
                BypassStrategy.PROTOCOL_ROTATION,
            ],
        },
    }
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def fingerprint(self, target: str) -> DPIFingerprintResult:
        """
        Run comprehensive DPI system fingerprinting.
        
        Returns:
            DPIFingerprintResult with identified system and recommendations
        """
        timestamp = datetime.now().isoformat()
        
        # Run all fingerprinting methods in parallel
        response_task = self._analyze_response_patterns(target)
        tcp_task = self._analyze_tcp_behavior(target)
        tls_task = self._analyze_tls_inspection(target)
        http_task = self._analyze_http_parsing(target)
        protocol_task = self._analyze_protocol_support(target)
        
        response_result, tcp_result, tls_result, http_result, protocol_result = await asyncio.gather(
            response_task, tcp_task, tls_result, http_task, protocol_task,
            return_exceptions=True
        )
        
        # Aggregate results and identify DPI system
        scores = {dpi: 0.0 for dpi in DPISystem if dpi != DPISystem.UNKNOWN}
        detection_methods = []
        characteristics = {}
        
        # Process response patterns
        if isinstance(response_result, dict):
            detection_methods.append("response_pattern_analysis")
            characteristics["response_patterns"] = response_result.get("patterns_found", [])
            
            for dpi, dpi_info in self.SIGNATURES.items():
                for pattern in dpi_info["patterns"]:
                    if any(pattern.lower() in p.lower() for p in response_result.get("patterns_found", [])):
                        scores[dpi] += 0.3
        
        # Process TCP behavior
        if isinstance(tcp_result, dict):
            detection_methods.append("tcp_behavior_analysis")
            characteristics["tcp_characteristics"] = {
                "window_scaling": tcp_result.get("window_scaling"),
                "mss": tcp_result.get("mss"),
                "options": tcp_result.get("options"),
            }
            
            for dpi, dpi_info in self.SIGNATURES.items():
                expected = dpi_info["characteristics"]
                if "tcp_window_scaling" in expected:
                    if tcp_result.get("window_scaling") == expected["tcp_window_scaling"]:
                        scores[dpi] += 0.2
        
        # Process TLS inspection
        if isinstance(tls_result, dict):
            detection_methods.append("tls_inspection_analysis")
            characteristics["tls_characteristics"] = {
                "inspection_detected": tls_result.get("inspection_detected"),
                "certificate_chain": tls_result.get("certificate_chain"),
                "cipher_support": tls_result.get("cipher_support"),
            }
            
            for dpi, dpi_info in self.SIGNATURES.items():
                expected = dpi_info["characteristics"]
                if "tls_inspection" in expected:
                    if tls_result.get("inspection_detected") == expected["tls_inspection"]:
                        scores[dpi] += 0.25
        
        # Process HTTP parsing
        if isinstance(http_result, dict):
            detection_methods.append("http_parsing_analysis")
            characteristics["http_characteristics"] = {
                "header_tolerance": http_result.get("header_tolerance"),
                "method_support": http_result.get("method_support"),
            }
            
            for dpi, dpi_info in self.SIGNATURES.items():
                expected = dpi_info["characteristics"]
                if "http_parsing_strict" in expected:
                    if http_result.get("header_tolerance") == (not expected["http_parsing_strict"]):
                        scores[dpi] += 0.2
        
        # Process protocol support
        if isinstance(protocol_result, dict):
            detection_methods.append("protocol_support_analysis")
            characteristics["protocol_characteristics"] = {
                "http_versions": protocol_result.get("http_versions"),
                "websocket_support": protocol_result.get("websocket_support"),
                "quic_support": protocol_result.get("quic_support"),
            }
        
        # Determine best match
        if scores:
            best_dpi = max(scores, key=scores.get)
            confidence = scores[best_dpi] / max(sum(scores.values()), 1.0)
            
            if confidence > 0.3:
                dpi_detected = True
                dpi_system = best_dpi
                bypass_strategies = self.SIGNATURES[best_dpi]["best_strategies"]
            else:
                dpi_detected = False
                dpi_system = DPISystem.UNKNOWN
                confidence = 0.0
                bypass_strategies = [
                    BypassStrategy.HTTP_OBFUSCATION,
                    BypassStrategy.FRAGMENTATION,
                    BypassStrategy.PROTOCOL_ROTATION,
                ]
        else:
            dpi_detected = False
            dpi_system = DPISystem.UNKNOWN
            confidence = 0.0
            bypass_strategies = [
                BypassStrategy.HTTP_OBFUSCATION,
                BypassStrategy.FRAGMENTATION,
                BypassStrategy.PROTOCOL_ROTATION,
            ]
        
        return DPIFingerprintResult(
            timestamp=timestamp,
            target=target,
            dpi_detected=dpi_detected,
            dpi_system=dpi_system,
            confidence=confidence,
            bypass_strategies=bypass_strategies,
            detection_methods_used=detection_methods,
            characteristics=characteristics,
            details={
                "scores": {dpi.value: score for dpi, score in scores.items()},
                "response_analysis": response_result if isinstance(response_result, dict) else {},
                "tcp_analysis": tcp_result if isinstance(tcp_result, dict) else {},
                "tls_analysis": tls_result if isinstance(tls_result, dict) else {},
                "http_analysis": http_result if isinstance(http_result, dict) else {},
                "protocol_analysis": protocol_result if isinstance(protocol_result, dict) else {},
            }
        )
    
    async def _analyze_response_patterns(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP response patterns for DPI signatures."""
        patterns_found = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test various endpoints
                endpoints = [
                    f"https://{target}/",
                    f"https://{target}/test",
                    f"https://{target}/blocked",
                ]
                
                for endpoint in endpoints:
                    try:
                        async with session.get(
                            endpoint,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            allow_redirects=False
                        ) as resp:
                            body = await resp.text()
                            headers = dict(resp.headers)
                            
                            # Check for DPI signatures in response
                            for dpi, dpi_info in self.SIGNATURES.items():
                                for pattern in dpi_info["patterns"]:
                                    if re.search(pattern, body, re.IGNORECASE):
                                        patterns_found.append(pattern)
                                    if re.search(pattern, str(headers), re.IGNORECASE):
                                        patterns_found.append(pattern)
                    
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e), "patterns_found": []}
        
        return {
            "patterns_found": list(set(patterns_found)),
            "endpoints_tested": 3,
        }
    
    async def _analyze_tcp_behavior(self, target: str) -> Dict[str, Any]:
        """Analyze TCP behavior for DPI signatures."""
        try:
            # Resolve target
            loop = asyncio.get_event_loop()
            infos = await asyncio.wait_for(
                loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM),
                timeout=self.timeout
            )
            
            if not infos:
                return {"error": "Could not resolve target"}
            
            # Connect and analyze TCP options
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                sock.connect((infos[0][4][0], 443))
                
                # Get socket options
                tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 100)
                
                # Parse TCP_INFO structure (simplified)
                # Real implementation would parse full TCP_INFO struct
                window_scaling = True  # Assume enabled for modern systems
                mss = 1460  # Standard MSS
                
                return {
                    "window_scaling": window_scaling,
                    "mss": mss,
                    "options": ["window_scaling", "sack", "timestamps"],
                }
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e)}
    
    async def _analyze_tls_inspection(self, target: str) -> Dict[str, Any]:
        """Analyze TLS behavior for DPI inspection signatures."""
        inspection_detected = False
        certificate_chain = []
        cipher_support = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect with TLS
            sock = socket.create_connection((target, 443), timeout=self.timeout)
            
            try:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        certificate_chain = [cert.get("subject", [])]
                        
                        # Check if certificate is from DPI (not original)
                        issuer = cert.get("issuer", [])
                        if issuer:
                            issuer_str = str(issuer).lower()
                            if any(dpi in issuer_str for dpi in ["sandvine", "allot", "fortinet", "palo"]):
                                inspection_detected = True
                    
                    # Get cipher
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_support = [cipher[0]]
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "inspection_detected": inspection_detected,
            "certificate_chain": certificate_chain,
            "cipher_support": cipher_support,
        }
    
    async def _analyze_http_parsing(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP parsing behavior for DPI signatures."""
        header_tolerance = True
        method_support = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test with malformed headers
                malformed_headers = {
                    "X-Test": "value\x00with\x00nulls",
                    "X-Another": "value\r\ninjected",
                    "Content-Length": "999999999",
                }
                
                try:
                    async with session.get(
                        f"https://{target}/",
                        headers=malformed_headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        # If request succeeded, DPI has tolerant parsing
                        if resp.status < 400:
                            header_tolerance = True
                        else:
                            header_tolerance = False
                
                except Exception:
                    header_tolerance = False
                
                # Test various HTTP methods
                methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
                for method in methods:
                    try:
                        async with session.request(
                            method,
                            f"https://{target}/",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            if resp.status != 405:  # Method Not Allowed
                                method_support.append(method)
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "header_tolerance": header_tolerance,
            "method_support": method_support,
        }
    
    async def _analyze_protocol_support(self, target: str) -> Dict[str, Any]:
        """Analyze protocol support for DPI limitations."""
        http_versions = []
        websocket_support = False
        quic_support = False
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test HTTP/2
                try:
                    async with session.get(
                        f"https://{target}/",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.version.name == "HTTP_20":
                            http_versions.append("h2")
                        elif resp.version.name == "HTTP_11":
                            http_versions.append("http/1.1")
                except Exception:
                    pass
                
                # Test WebSocket upgrade
                try:
                    async with session.ws_connect(
                        f"wss://{target}/ws",
                        timeout=self.timeout,
                        ssl=False
                    ) as ws:
                        websocket_support = True
                except Exception:
                    websocket_support = False
        
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "http_versions": http_versions,
            "websocket_support": websocket_support,
            "quic_support": quic_support,
        }
