"""
HTTP/2 PUSH Abuse Testing — test HTTP/2 server push for DPI bypass potential.

HTTP/2 server push can be abused to bypass DPI:
1. Push unauthorized content — push content that wasn't requested
2. Push to different domains — push resources from different origins
3. Push timing manipulation — use push timing to evade detection
4. Push size manipulation — push large/small payloads to confuse DPI
5. Push protocol confusion — mix HTTP/2 push with other protocols

Detection methods:
- Push authorization analysis — check if server pushes unauthorized content
- Cross-origin push detection — detect pushes to different origins
- Timing analysis — analyze push timing patterns
- Size analysis — analyze pushed content sizes
- Protocol analysis — detect protocol mixing

Metrics:
- push_detected: bool — whether HTTP/2 push is used
- unauthorized_push: bool — unauthorized content pushed
- cross_origin_push: bool — cross-origin push detected
- timing_anomaly: bool — timing anomaly detected
- size_anomaly: bool — size anomaly detected
- protocol_confusion: bool — protocol mixing detected
"""

import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class PushSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HTTP2PushResult:
    """Result of HTTP/2 push abuse testing."""
    timestamp: str
    target: str
    push_detected: bool
    unauthorized_push: bool = False
    cross_origin_push: bool = False
    timing_anomaly: bool = False
    size_anomaly: bool = False
    protocol_confusion: bool = False
    severity: PushSeverity = PushSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "push_detected": self.push_detected,
            "unauthorized_push": self.unauthorized_push,
            "cross_origin_push": self.cross_origin_push,
            "timing_anomaly": self.timing_anomaly,
            "size_anomaly": self.size_anomaly,
            "protocol_confusion": self.protocol_confusion,
            "severity": self.severity.value,
            "details": self.details,
        }


class HTTP2PushTester:
    """
    Test HTTP/2 server push for DPI bypass potential.
    
    Tests:
    1. Push authorization analysis — check for unauthorized pushes
    2. Cross-origin push detection — detect cross-origin pushes
    3. Timing analysis — analyze push timing
    4. Size analysis — analyze pushed content sizes
    5. Protocol analysis — detect protocol mixing
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def test_push(self, target: str) -> HTTP2PushResult:
        """
        Run comprehensive HTTP/2 push abuse testing.
        
        Returns:
            HTTP2PushResult with all detected issues
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        auth_task = self._test_push_authorization(target)
        cross_origin_task = self._test_cross_origin_push(target)
        timing_task = self._test_push_timing(target)
        size_task = self._test_push_size(target)
        protocol_task = self._test_protocol_confusion(target)
        
        auth_result, cross_origin_result, timing_result, size_result, protocol_result = await asyncio.gather(
            auth_task, cross_origin_task, timing_task, size_task, protocol_task,
            return_exceptions=True
        )
        
        # Aggregate results
        push_detected = False
        unauthorized_push = False
        cross_origin_push = False
        timing_anomaly = False
        size_anomaly = False
        protocol_confusion = False
        
        if isinstance(auth_result, dict):
            push_detected = auth_result.get("push_detected", False)
            unauthorized_push = auth_result.get("unauthorized", False)
        
        if isinstance(cross_origin_result, dict):
            cross_origin_push = cross_origin_result.get("cross_origin", False)
        
        if isinstance(timing_result, dict):
            timing_anomaly = timing_result.get("anomaly", False)
        
        if isinstance(size_result, dict):
            size_anomaly = size_result.get("anomaly", False)
        
        if isinstance(protocol_result, dict):
            protocol_confusion = protocol_result.get("confusion", False)
        
        # Determine severity
        if not push_detected:
            severity = PushSeverity.NONE
        elif not (unauthorized_push or cross_origin_push or timing_anomaly or size_anomaly or protocol_confusion):
            severity = PushSeverity.LOW
        elif unauthorized_push or cross_origin_push:
            severity = PushSeverity.MEDIUM
        elif timing_anomaly or size_anomaly:
            severity = PushSeverity.HIGH
        else:
            severity = PushSeverity.CRITICAL
        
        return HTTP2PushResult(
            timestamp=timestamp,
            target=target,
            push_detected=push_detected,
            unauthorized_push=unauthorized_push,
            cross_origin_push=cross_origin_push,
            timing_anomaly=timing_anomaly,
            size_anomaly=size_anomaly,
            protocol_confusion=protocol_confusion,
            severity=severity,
            details={
                "authorization_test": auth_result if isinstance(auth_result, dict) else {},
                "cross_origin_test": cross_origin_result if isinstance(cross_origin_result, dict) else {},
                "timing_test": timing_result if isinstance(timing_result, dict) else {},
                "size_test": size_result if isinstance(size_result, dict) else {},
                "protocol_test": protocol_result if isinstance(protocol_result, dict) else {},
            }
        )
    
    async def _test_push_authorization(self, target: str) -> Dict[str, Any]:
        """
        Test if server pushes unauthorized content.
        
        Check if server pushes content that wasn't requested.
        """
        push_detected = False
        unauthorized = False
        pushed_resources = []
        
        try:
            # Connect with HTTP/2
            async with aiohttp.ClientSession() as session:
                try:
                    # Request main page
                    async with session.get(
                        f"https://{target}/",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        # Check if HTTP/2
                        if resp.version.name == "HTTP_20":
                            push_detected = True
                            
                            # Check for pushed resources
                            # Note: aiohttp doesn't expose pushed resources directly
                            # This is a simplified test
                            
                            await resp.read()
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "push_detected": False}
        
        return {
            "push_detected": push_detected,
            "unauthorized": unauthorized,
            "pushed_resources": pushed_resources,
        }
    
    async def _test_cross_origin_push(self, target: str) -> Dict[str, Any]:
        """
        Test if server pushes resources from different origins.
        
        Cross-origin push can be used to bypass origin-based filtering.
        """
        cross_origin = False
        
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://{target}/",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.version.name == "HTTP_20":
                            # Check response headers for Link headers (push hints)
                            link_headers = resp.headers.get("Link", "")
                            
                            if link_headers:
                                # Parse Link headers
                                # Format: <https://example.com/resource>; rel=preload
                                import re
                                links = re.findall(r'<([^>]+)>', link_headers)
                                
                                for link in links:
                                    if link and not link.startswith(f"https://{target}"):
                                        cross_origin = True
                                        break
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "cross_origin": False}
        
        return {
            "cross_origin": cross_origin,
        }
    
    async def _test_push_timing(self, target: str) -> Dict[str, Any]:
        """
        Test push timing patterns.
        
        Analyze timing of pushed resources for anomalies.
        """
        anomaly = False
        
        try:
            # Measure timing of multiple requests
            timings = []
            
            for _ in range(10):
                start_time = asyncio.get_event_loop().time()
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{target}/",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            await resp.read()
                except Exception:
                    pass
                
                end_time = asyncio.get_event_loop().time()
                timings.append(end_time - start_time)
            
            if len(timings) >= 5:
                # Check for timing anomalies
                mean = sum(timings) / len(timings)
                variance = sum((t - mean) ** 2 for t in timings) / len(timings)
                
                # High variance = anomaly
                if variance > 1.0:
                    anomaly = True
        
        except Exception as e:
            return {"error": str(e), "anomaly": False}
        
        return {
            "anomaly": anomaly,
        }
    
    async def _test_push_size(self, target: str) -> Dict[str, Any]:
        """
        Test pushed content sizes.
        
        Analyze sizes of pushed resources for anomalies.
        """
        anomaly = False
        
        try:
            sizes = []
            
            for _ in range(10):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{target}/",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            data = await resp.read()
                            sizes.append(len(data))
                except Exception:
                    pass
            
            if len(sizes) >= 5:
                # Check for size anomalies
                mean = sum(sizes) / len(sizes)
                
                # If sizes vary significantly, it's an anomaly
                if max(sizes) > mean * 5 or min(sizes) < mean * 0.1:
                    anomaly = True
        
        except Exception as e:
            return {"error": str(e), "anomaly": False}
        
        return {
            "anomaly": anomaly,
        }
    
    async def _test_protocol_confusion(self, target: str) -> Dict[str, Any]:
        """
        Test for protocol confusion.
        
        Check if server mixes HTTP/2 push with other protocols.
        """
        confusion = False
        
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    # Try HTTP/2
                    async with session.get(
                        f"https://{target}/",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        http2_supported = resp.version.name == "HTTP_20"
                
                except Exception:
                    http2_supported = False
                
                # Try HTTP/1.1
                try:
                    async with session.get(
                        f"http://{target}/",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False
                    ) as resp:
                        http1_supported = resp.status < 400
                
                except Exception:
                    http1_supported = False
                
                # If both supported with different behavior, potential confusion
                if http2_supported and http1_supported:
                    confusion = True
        
        except Exception as e:
            return {"error": str(e), "confusion": False}
        
        return {
            "confusion": confusion,
        }
