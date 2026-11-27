"""
WebSocket Tunnel Detection — detect WebSocket-based tunneling and analyze stealth.

WebSocket tunnels (ws-tunnel, wstunnel, websockify) are popular for bypassing DPI,
but can be detected through:
1. Frame pattern analysis — binary vs text frame distribution
2. Timing correlation — WebSocket traffic timing correlates with proxied traffic
3. Frame size distribution — tunnel frames have different size patterns than normal WS
4. Ping/pong analysis — tunnel implementations handle ping/pong differently
5. Subprotocol negotiation — tunnel protocols use specific subprotocols

Detection methods:
- Frame analysis — analyze WebSocket frame patterns
- Traffic correlation — correlate WS frames with proxied traffic patterns
- Size distribution — detect anomalous frame size distributions
- Behavior analysis — detect tunnel-specific behaviors

Metrics:
- tunnel_detected: bool — whether WebSocket tunnel was detected
- confidence: float — confidence in detection (0-1)
- frame_analysis: dict — frame pattern analysis results
- timing_correlation: float — timing correlation score
- size_distribution_anomaly: bool — anomalous frame size distribution
- tunnel_type: str — detected tunnel type (wstunnel, websockify, etc.)
"""

import asyncio
import time
import struct
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class TunnelSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class WebSocketTunnelResult:
    """Result of WebSocket tunnel detection."""
    timestamp: str
    target: str
    tunnel_detected: bool
    confidence: float = 0.0
    tunnel_type: str = ""
    frame_analysis: Dict[str, Any] = field(default_factory=dict)
    timing_correlation: float = 0.0
    size_distribution_anomaly: bool = False
    severity: TunnelSeverity = TunnelSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "tunnel_detected": self.tunnel_detected,
            "confidence": self.confidence,
            "tunnel_type": self.tunnel_type,
            "frame_analysis": self.frame_analysis,
            "timing_correlation": self.timing_correlation,
            "size_distribution_anomaly": self.size_distribution_anomaly,
            "severity": self.severity.value,
            "details": self.details,
        }


class WebSocketTunnelDetector:
    """
    Detect WebSocket-based tunneling and analyze stealth.
    
    Tests:
    1. Frame analysis — analyze WebSocket frame patterns
    2. Traffic correlation — correlate WS with proxied traffic
    3. Size distribution — detect anomalous frame sizes
    4. Behavior analysis — detect tunnel-specific behaviors
    5. Subprotocol detection — detect tunnel subprotocols
    """
    
    # Known WebSocket tunnel paths
    TUNNEL_PATHS = [
        "/ws", "/websocket", "/ws-tunnel", "/wstunnel",
        "/websockify", "/tunnel", "/proxy", "/connect",
        "/ws-proxy", "/socket", "/web-socket",
    ]
    
    # Known tunnel subprotocols
    TUNNEL_SUBPROTOCOLS = [
        "binary", "tunnel", "proxy", "wstunnel",
        "websockify", "ws-tunnel",
    ]
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def detect_tunnel(self, target: str) -> WebSocketTunnelResult:
        """
        Run comprehensive WebSocket tunnel detection.
        
        Returns:
            WebSocketTunnelResult with detection results
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        endpoint_task = self._scan_tunnel_endpoints(target)
        frame_task = self._analyze_frame_patterns(target)
        timing_task = self._analyze_timing_correlation(target)
        size_task = self._analyze_size_distribution(target)
        behavior_task = self._analyze_tunnel_behavior(target)
        
        endpoint_result, frame_result, timing_result, size_result, behavior_result = await asyncio.gather(
            endpoint_task, frame_task, timing_task, size_task, behavior_task,
            return_exceptions=True
        )
        
        # Aggregate results
        tunnel_detected = False
        confidence = 0.0
        tunnel_type = ""
        
        # Process endpoint scan
        tunnel_endpoints = []
        if isinstance(endpoint_result, dict):
            tunnel_endpoints = endpoint_result.get("tunnel_endpoints", [])
            if tunnel_endpoints:
                tunnel_detected = True
                confidence += 0.3
        
        # Process frame analysis
        frame_analysis = {}
        if isinstance(frame_result, dict):
            frame_analysis = frame_result
            if frame_result.get("anomaly_detected", False):
                tunnel_detected = True
                confidence += 0.25
        
        # Process timing correlation
        timing_correlation = 0.0
        if isinstance(timing_result, dict):
            timing_correlation = timing_result.get("correlation_score", 0.0)
            if timing_correlation > 0.5:
                tunnel_detected = True
                confidence += 0.2
        
        # Process size distribution
        size_anomaly = False
        if isinstance(size_result, dict):
            size_anomaly = size_result.get("anomaly_detected", False)
            if size_anomaly:
                tunnel_detected = True
                confidence += 0.15
        
        # Process behavior analysis
        if isinstance(behavior_result, dict):
            detected_type = behavior_result.get("tunnel_type", "")
            if detected_type:
                tunnel_type = detected_type
                tunnel_detected = True
                confidence += 0.1
        
        # Determine tunnel type from endpoints
        if not tunnel_type and tunnel_endpoints:
            for ep in tunnel_endpoints:
                path = ep.get("path", "")
                if "wstunnel" in path:
                    tunnel_type = "wstunnel"
                elif "websockify" in path:
                    tunnel_type = "websockify"
                elif "ws-tunnel" in path:
                    tunnel_type = "ws-tunnel"
                elif "tunnel" in path:
                    tunnel_type = "generic-tunnel"
        
        # Normalize confidence
        confidence = min(1.0, confidence)
        
        # Determine severity
        if not tunnel_detected:
            severity = TunnelSeverity.NONE
        elif confidence < 0.3:
            severity = TunnelSeverity.LOW
        elif confidence < 0.6:
            severity = TunnelSeverity.MEDIUM
        elif confidence < 0.8:
            severity = TunnelSeverity.HIGH
        else:
            severity = TunnelSeverity.CRITICAL
        
        return WebSocketTunnelResult(
            timestamp=timestamp,
            target=target,
            tunnel_detected=tunnel_detected,
            confidence=confidence,
            tunnel_type=tunnel_type,
            frame_analysis=frame_analysis,
            timing_correlation=timing_correlation,
            size_distribution_anomaly=size_anomaly,
            severity=severity,
            details={
                "endpoint_scan": endpoint_result if isinstance(endpoint_result, dict) else {},
                "timing_analysis": timing_result if isinstance(timing_result, dict) else {},
                "size_analysis": size_result if isinstance(size_result, dict) else {},
                "behavior_analysis": behavior_result if isinstance(behavior_result, dict) else {},
            }
        )
    
    async def _scan_tunnel_endpoints(self, target: str) -> Dict[str, Any]:
        """
        Scan for WebSocket tunnel endpoints.
        
        Checks common paths for WebSocket tunnel services.
        """
        tunnel_endpoints = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for path in self.TUNNEL_PATHS:
                    try:
                        url = f"https://{target}{path}"
                        
                        # Try WebSocket upgrade
                        headers = {
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                            "Sec-WebSocket-Version": "13",
                        }
                        
                        async with session.get(
                            url,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            allow_redirects=False
                        ) as resp:
                            # 101 Switching Protocols = WebSocket endpoint found
                            if resp.status == 101:
                                tunnel_endpoints.append({
                                    "path": path,
                                    "url": url,
                                    "status": resp.status,
                                })
                    
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e), "tunnel_endpoints": []}
        
        return {
            "tunnel_endpoints": tunnel_endpoints,
            "paths_scanned": len(self.TUNNEL_PATHS),
        }
    
    async def _analyze_frame_patterns(self, target: str) -> Dict[str, Any]:
        """
        Analyze WebSocket frame patterns for tunnel indicators.
        
        Tunnel WebSocket frames differ from normal WebSocket:
        - Higher binary frame ratio
        - Larger average frame size
        - More consistent frame sizes (tunneled traffic)
        """
        anomaly_detected = False
        frame_stats = {
            "binary_frames": 0,
            "text_frames": 0,
            "total_frames": 0,
            "avg_frame_size": 0,
            "frame_size_variance": 0,
        }
        
        try:
            # Try to connect to WebSocket endpoint
            ws_url = f"wss://{target}/ws"
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.ws_connect(
                        ws_url,
                        timeout=self.timeout,
                        ssl=False
                    ) as ws:
                        # Collect frames
                        frame_sizes = []
                        
                        for _ in range(20):  # Collect 20 frames
                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                                
                                if msg.type == aiohttp.WSMsgType.BINARY:
                                    frame_stats["binary_frames"] += 1
                                    frame_sizes.append(len(msg.data))
                                elif msg.type == aiohttp.WSMsgType.TEXT:
                                    frame_stats["text_frames"] += 1
                                    frame_sizes.append(len(msg.data.encode()))
                                
                                frame_stats["total_frames"] += 1
                            
                            except asyncio.TimeoutError:
                                break
                        
                        # Analyze frame patterns
                        if frame_sizes:
                            frame_stats["avg_frame_size"] = sum(frame_sizes) / len(frame_sizes)
                            
                            # Calculate variance
                            mean = frame_stats["avg_frame_size"]
                            variance = sum((x - mean) ** 2 for x in frame_sizes) / len(frame_sizes)
                            frame_stats["frame_size_variance"] = variance
                            
                            # Tunnel frames typically have lower variance
                            # (tunneled traffic is more consistent than chat messages)
                            binary_ratio = frame_stats["binary_frames"] / max(frame_stats["total_frames"], 1)
                            
                            # Anomaly detection
                            if binary_ratio > 0.8 and variance < 1000:
                                anomaly_detected = True
                            
                            if frame_stats["avg_frame_size"] > 500:
                                anomaly_detected = True
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "anomaly_detected": False}
        
        return {
            "anomaly_detected": anomaly_detected,
            **frame_stats,
        }
    
    async def _analyze_timing_correlation(self, target: str) -> Dict[str, Any]:
        """
        Analyze timing correlation between WebSocket frames and proxied traffic.
        
        Tunnel WebSocket frames should correlate with proxied traffic patterns.
        """
        correlation_score = 0.0
        timing_samples = []
        
        try:
            ws_url = f"wss://{target}/ws"
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.ws_connect(
                        ws_url,
                        timeout=self.timeout,
                        ssl=False
                    ) as ws:
                        # Measure inter-frame timing
                        last_time = time.time()
                        
                        for _ in range(20):
                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                                current_time = time.time()
                                
                                interval = current_time - last_time
                                timing_samples.append(interval)
                                last_time = current_time
                            
                            except asyncio.TimeoutError:
                                break
                        
                        # Analyze timing patterns
                        if len(timing_samples) >= 5:
                            avg_interval = sum(timing_samples) / len(timing_samples)
                            variance = sum((x - avg_interval) ** 2 for x in timing_samples) / len(timing_samples)
                            
                            # Low variance in timing = tunnel behavior
                            # (proxied traffic has more consistent timing)
                            if variance < 0.1:
                                correlation_score = 0.7
                            elif variance < 0.5:
                                correlation_score = 0.4
                            else:
                                correlation_score = 0.1
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "correlation_score": 0.0}
        
        return {
            "correlation_score": correlation_score,
            "samples": len(timing_samples),
        }
    
    async def _analyze_size_distribution(self, target: str) -> Dict[str, Any]:
        """
        Analyze WebSocket frame size distribution.
        
        Tunnel frames have different size distribution than normal WebSocket.
        """
        anomaly_detected = False
        size_distribution = {}
        
        try:
            ws_url = f"wss://{target}/ws"
            
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.ws_connect(
                        ws_url,
                        timeout=self.timeout,
                        ssl=False
                    ) as ws:
                        frame_sizes = []
                        
                        for _ in range(30):
                            try:
                                msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                                
                                if msg.type in (aiohttp.WSMsgType.BINARY, aiohttp.WSMsgType.TEXT):
                                    size = len(msg.data) if msg.type == aiohttp.WSMsgType.BINARY else len(msg.data.encode())
                                    frame_sizes.append(size)
                            
                            except asyncio.TimeoutError:
                                break
                        
                        if frame_sizes:
                            # Create size distribution buckets
                            buckets = {"tiny": 0, "small": 0, "medium": 0, "large": 0, "huge": 0}
                            
                            for size in frame_sizes:
                                if size < 100:
                                    buckets["tiny"] += 1
                                elif size < 500:
                                    buckets["small"] += 1
                                elif size < 1000:
                                    buckets["medium"] += 1
                                elif size < 5000:
                                    buckets["large"] += 1
                                else:
                                    buckets["huge"] += 1
                            
                            size_distribution = buckets
                            
                            # Tunnel frames tend to be medium-large with low variance
                            total = len(frame_sizes)
                            medium_plus = buckets["medium"] + buckets["large"] + buckets["huge"]
                            
                            if medium_plus / total > 0.7:
                                anomaly_detected = True
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "anomaly_detected": False}
        
        return {
            "anomaly_detected": anomaly_detected,
            "size_distribution": size_distribution,
        }
    
    async def _analyze_tunnel_behavior(self, target: str) -> Dict[str, Any]:
        """
        Analyze WebSocket behavior for tunnel-specific patterns.
        
        Tunnel implementations have specific behaviors:
        - Specific subprotocol negotiation
        - Specific ping/pong handling
        - Specific error handling
        """
        tunnel_type = ""
        
        try:
            # Try different tunnel subprotocols
            for subprotocol in self.TUNNEL_SUBPROTOCOLS:
                ws_url = f"wss://{target}/ws"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.ws_connect(
                            ws_url,
                            protocols=[subprotocol],
                            timeout=self.timeout,
                            ssl=False
                        ) as ws:
                            # If connection succeeded with tunnel subprotocol
                            if ws.protocol == subprotocol:
                                tunnel_type = subprotocol
                                break
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "tunnel_type": ""}
        
        return {
            "tunnel_type": tunnel_type,
        }
