"""
Timing Side-Channel Detection — detect timing-based traffic analysis.

Advanced DPI and surveillance systems use timing analysis:
1. Inter-packet timing patterns — unique timing signatures per protocol
2. Request-response correlation — correlate requests with responses by timing
3. TCP timestamp analysis — TCP timestamps can leak info
4. Jitter fingerprinting — network jitter patterns are device-specific
5. Burst pattern detection — traffic burst patterns reveal application type

Detection methods:
- Inter-packet timing analysis — measure and analyze timing between packets
- Request-response correlation — detect timing correlation
- TCP timestamp analysis — analyze TCP timestamp options
- Jitter analysis — measure and fingerprint network jitter
- Burst pattern analysis — detect traffic burst patterns

Metrics:
- timing_sidechannel_detected: bool — whether timing analysis is possible
- inter_packet_timing_score: float — how distinctive inter-packet timing is
- correlation_score: float — request-response timing correlation
- tcp_timestamp_leak: bool — TCP timestamps leak info
- jitter_fingerprint: bool — jitter pattern is fingerprintable
- burst_pattern_detected: bool — distinctive burst patterns detected
"""

import asyncio
import socket
import time
import struct
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp
import numpy as np


class TimingSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TimingSidechannelResult:
    """Result of timing side-channel detection."""
    timestamp: str
    target: str
    timing_sidechannel_detected: bool
    inter_packet_timing_score: float = 0.0
    correlation_score: float = 0.0
    tcp_timestamp_leak: bool = False
    jitter_fingerprint: bool = False
    burst_pattern_detected: bool = False
    severity: TimingSeverity = TimingSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "timing_sidechannel_detected": self.timing_sidechannel_detected,
            "inter_packet_timing_score": self.inter_packet_timing_score,
            "correlation_score": self.correlation_score,
            "tcp_timestamp_leak": self.tcp_timestamp_leak,
            "jitter_fingerprint": self.jitter_fingerprint,
            "burst_pattern_detected": self.burst_pattern_detected,
            "severity": self.severity.value,
            "details": self.details,
        }


class TimingSidechannelDetector:
    """
    Detect timing side-channels in network traffic.
    
    Tests:
    1. Inter-packet timing analysis — measure timing between packets
    2. Request-response correlation — detect timing correlation
    3. TCP timestamp analysis — analyze TCP timestamp options
    4. Jitter analysis — measure network jitter patterns
    5. Burst pattern analysis — detect traffic burst patterns
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def detect_timing_sidechannel(self, target: str) -> TimingSidechannelResult:
        """
        Run comprehensive timing side-channel detection.
        
        Returns:
            TimingSidechannelResult with all detected timing leaks
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        ipt_task = self._analyze_inter_packet_timing(target)
        correlation_task = self._analyze_request_response_correlation(target)
        tcp_ts_task = self._analyze_tcp_timestamps(target)
        jitter_task = self._analyze_jitter(target)
        burst_task = self._analyze_burst_patterns(target)
        
        ipt_result, correlation_result, tcp_ts_result, jitter_result, burst_result = await asyncio.gather(
            ipt_task, correlation_task, tcp_ts_task, jitter_task, burst_task,
            return_exceptions=True
        )
        
        # Aggregate results
        timing_sidechannel_detected = False
        
        inter_packet_timing_score = 0.0
        if isinstance(ipt_result, dict):
            inter_packet_timing_score = ipt_result.get("distinctiveness_score", 0.0)
            if inter_packet_timing_score > 0.5:
                timing_sidechannel_detected = True
        
        correlation_score = 0.0
        if isinstance(correlation_result, dict):
            correlation_score = correlation_result.get("correlation_score", 0.0)
            if correlation_score > 0.5:
                timing_sidechannel_detected = True
        
        tcp_timestamp_leak = False
        if isinstance(tcp_ts_result, dict):
            tcp_timestamp_leak = tcp_ts_result.get("leak_detected", False)
            if tcp_timestamp_leak:
                timing_sidechannel_detected = True
        
        jitter_fingerprint = False
        if isinstance(jitter_result, dict):
            jitter_fingerprint = jitter_result.get("fingerprintable", False)
            if jitter_fingerprint:
                timing_sidechannel_detected = True
        
        burst_pattern_detected = False
        if isinstance(burst_result, dict):
            burst_pattern_detected = burst_result.get("burst_detected", False)
            if burst_pattern_detected:
                timing_sidechannel_detected = True
        
        # Determine severity
        if not timing_sidechannel_detected:
            severity = TimingSeverity.NONE
        elif inter_packet_timing_score < 0.3 and correlation_score < 0.3:
            severity = TimingSeverity.LOW
        elif inter_packet_timing_score < 0.6 or correlation_score < 0.6:
            severity = TimingSeverity.MEDIUM
        elif inter_packet_timing_score < 0.8 or correlation_score < 0.8:
            severity = TimingSeverity.HIGH
        else:
            severity = TimingSeverity.CRITICAL
        
        return TimingSidechannelResult(
            timestamp=timestamp,
            target=target,
            timing_sidechannel_detected=timing_sidechannel_detected,
            inter_packet_timing_score=inter_packet_timing_score,
            correlation_score=correlation_score,
            tcp_timestamp_leak=tcp_timestamp_leak,
            jitter_fingerprint=jitter_fingerprint,
            burst_pattern_detected=burst_pattern_detected,
            severity=severity,
            details={
                "inter_packet_timing": ipt_result if isinstance(ipt_result, dict) else {},
                "correlation": correlation_result if isinstance(correlation_result, dict) else {},
                "tcp_timestamps": tcp_ts_result if isinstance(tcp_ts_result, dict) else {},
                "jitter": jitter_result if isinstance(jitter_result, dict) else {},
                "burst_patterns": burst_result if isinstance(burst_result, dict) else {},
            }
        )
    
    async def _analyze_inter_packet_timing(self, target: str) -> Dict[str, Any]:
        """
        Analyze inter-packet timing patterns.
        
        Different protocols/applications have distinctive inter-packet timing.
        DPI can use this to identify traffic type.
        """
        timing_samples = []
        distinctiveness_score = 0.0
        
        try:
            # Measure inter-packet timing for multiple requests
            for _ in range(10):
                start_time = time.perf_counter()
                
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
                
                end_time = time.perf_counter()
                timing_samples.append(end_time - start_time)
            
            if len(timing_samples) >= 5:
                # Calculate statistics
                mean = sum(timing_samples) / len(timing_samples)
                variance = sum((x - mean) ** 2 for x in timing_samples) / len(timing_samples)
                std_dev = variance ** 0.5
                
                # Calculate coefficient of variation
                cv = std_dev / mean if mean > 0 else 0
                
                # Low CV = distinctive timing pattern (bad for privacy)
                if cv < 0.1:
                    distinctiveness_score = 0.8
                elif cv < 0.3:
                    distinctiveness_score = 0.5
                elif cv < 0.5:
                    distinctiveness_score = 0.3
                else:
                    distinctiveness_score = 0.1
        
        except Exception as e:
            return {"error": str(e), "distinctiveness_score": 0.0}
        
        return {
            "distinctiveness_score": distinctiveness_score,
            "samples": len(timing_samples),
            "mean": sum(timing_samples) / len(timing_samples) if timing_samples else 0.0,
            "std_dev": (sum((x - sum(timing_samples) / len(timing_samples)) ** 2 for x in timing_samples) / len(timing_samples)) ** 0.5 if timing_samples else 0.0,
        }
    
    async def _analyze_request_response_correlation(self, target: str) -> Dict[str, Any]:
        """
        Analyze request-response timing correlation.
        
        If request timing correlates with response timing, it's possible
        to correlate requests with responses (traffic analysis).
        """
        correlation_score = 0.0
        request_times = []
        response_times = []
        
        try:
            # Send multiple requests and measure timing
            for _ in range(10):
                request_time = time.perf_counter()
                request_times.append(request_time)
                
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
                
                response_time = time.perf_counter()
                response_times.append(response_time)
            
            if len(request_times) >= 5 and len(response_times) >= 5:
                # Calculate inter-request and inter-response intervals
                request_intervals = [request_times[i+1] - request_times[i] for i in range(len(request_times)-1)]
                response_intervals = [response_times[i+1] - response_times[i] for i in range(len(response_times)-1)]
                
                # Calculate correlation
                if len(request_intervals) == len(response_intervals):
                    correlation = np.corrcoef(request_intervals, response_intervals)[0, 1]
                    correlation_score = abs(correlation) if not np.isnan(correlation) else 0.0
        
        except Exception as e:
            return {"error": str(e), "correlation_score": 0.0}
        
        return {
            "correlation_score": correlation_score,
            "samples": len(request_times),
        }
    
    async def _analyze_tcp_timestamps(self, target: str) -> Dict[str, Any]:
        """
        Analyze TCP timestamp options for information leaks.
        
        TCP timestamps can leak:
        - System uptime
        - Clock rate
        - Host identity
        """
        leak_detected = False
        timestamp_info = {}
        
        try:
            # Connect and analyze TCP options
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            try:
                # Resolve target
                loop = asyncio.get_event_loop()
                infos = await loop.getaddrinfo(target, 443, type=socket.SOCK_STREAM)
                
                if infos:
                    sock.connect((infos[0][4][0], 443))
                    
                    # Get TCP_INFO (Linux-specific)
                    try:
                        tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 100)
                        
                        # Parse TCP_INFO structure
                        # tcpi_options contains TCP options including timestamps
                        if len(tcp_info) >= 40:
                            # Extract options field (simplified)
                            options = struct.unpack("B", tcp_info[1:2])[0]
                            
                            # Check if timestamps enabled
                            if options & 0x08:  # TCPI_OPT_TIMESTAMPS
                                leak_detected = True
                                timestamp_info["timestamps_enabled"] = True
                    
                    except Exception:
                        pass
            
            finally:
                sock.close()
        
        except Exception as e:
            return {"error": str(e), "leak_detected": False}
        
        return {
            "leak_detected": leak_detected,
            "timestamp_info": timestamp_info,
        }
    
    async def _analyze_jitter(self, target: str) -> Dict[str, Any]:
        """
        Analyze network jitter patterns.
        
        Network jitter (variation in packet delay) can fingerprint:
        - Network path
        - Device type
        - Geographic location
        """
        fingerprintable = False
        jitter_samples = []
        
        try:
            # Measure jitter for multiple requests
            for _ in range(20):
                start_time = time.perf_counter()
                
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
                
                end_time = time.perf_counter()
                jitter_samples.append(end_time - start_time)
            
            if len(jitter_samples) >= 10:
                # Calculate jitter statistics
                mean = sum(jitter_samples) / len(jitter_samples)
                variance = sum((x - mean) ** 2 for x in jitter_samples) / len(jitter_samples)
                
                # Low jitter variance = fingerprintable
                # (consistent network path)
                if variance < 0.001:
                    fingerprintable = True
                elif variance < 0.01:
                    fingerprintable = True
        
        except Exception as e:
            return {"error": str(e), "fingerprintable": False}
        
        return {
            "fingerprintable": fingerprintable,
            "samples": len(jitter_samples),
            "jitter_variance": variance if len(jitter_samples) >= 10 else 0.0,
        }
    
    async def _analyze_burst_patterns(self, target: str) -> Dict[str, Any]:
        """
        Analyze traffic burst patterns.
        
        Different applications have distinctive burst patterns:
        - Web browsing: request-response bursts
        - Video streaming: sustained high-rate bursts
        - VoIP: regular small-packet bursts
        """
        burst_detected = False
        burst_patterns = []
        
        try:
            # Measure traffic patterns
            packet_times = []
            
            for _ in range(30):
                start_time = time.perf_counter()
                
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
                
                end_time = time.perf_counter()
                packet_times.append(end_time)
            
            if len(packet_times) >= 10:
                # Calculate inter-packet intervals
                intervals = [packet_times[i+1] - packet_times[i] for i in range(len(packet_times)-1)]
                
                # Detect bursts (short intervals followed by longer gaps)
                burst_threshold = 0.05  # 50ms
                
                for i in range(len(intervals) - 1):
                    if intervals[i] < burst_threshold and intervals[i+1] > burst_threshold:
                        burst_patterns.append({
                            "burst_start": i,
                            "burst_duration": intervals[i],
                        })
                
                # If multiple bursts detected, pattern is distinctive
                if len(burst_patterns) >= 3:
                    burst_detected = True
        
        except Exception as e:
            return {"error": str(e), "burst_detected": False}
        
        return {
            "burst_detected": burst_detected,
            "burst_count": len(burst_patterns),
            "samples": len(packet_times),
        }
