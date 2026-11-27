"""
Traffic Pattern Analysis & Correlation — detect correlation-based traffic analysis.

ML-based DPI systems use traffic pattern analysis:
1. Packet size distribution — unique size patterns per application
2. Flow duration patterns — application-specific flow durations
3. Bidirectional traffic correlation — correlate upload/download patterns
4. Burst pattern detection — detect application-specific burst patterns
5. Entropy analysis — traffic entropy reveals encryption type

Detection methods:
- Size distribution analysis — analyze packet size distributions
- Flow pattern analysis — analyze flow duration and timing
- Bidirectional correlation — correlate upload/download patterns
- Burst analysis — detect and analyze traffic bursts
- Entropy analysis — measure traffic entropy

Metrics:
- pattern_detected: bool — whether distinctive patterns detected
- size_distribution_score: float — how distinctive size distribution is
- flow_pattern_score: float — how distinctive flow patterns are
- bidirectional_correlation: float — upload/download correlation
- burst_pattern_score: float — burst pattern distinctiveness
- entropy_score: float — traffic entropy (low = more predictable)
"""

import asyncio
import time
import math
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp
import numpy as np


class PatternSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TrafficPatternResult:
    """Result of traffic pattern analysis."""
    timestamp: str
    target: str
    pattern_detected: bool
    size_distribution_score: float = 0.0
    flow_pattern_score: float = 0.0
    bidirectional_correlation: float = 0.0
    burst_pattern_score: float = 0.0
    entropy_score: float = 0.0
    severity: PatternSeverity = PatternSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "pattern_detected": self.pattern_detected,
            "size_distribution_score": self.size_distribution_score,
            "flow_pattern_score": self.flow_pattern_score,
            "bidirectional_correlation": self.bidirectional_correlation,
            "burst_pattern_score": self.burst_pattern_score,
            "entropy_score": self.entropy_score,
            "severity": self.severity.value,
            "details": self.details,
        }


class TrafficPatternAnalyzer:
    """
    Analyze traffic patterns for correlation-based detection.
    
    Tests:
    1. Size distribution analysis — analyze packet size distributions
    2. Flow pattern analysis — analyze flow duration and timing
    3. Bidirectional correlation — correlate upload/download
    4. Burst analysis — detect traffic burst patterns
    5. Entropy analysis — measure traffic entropy
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def analyze_patterns(self, target: str) -> TrafficPatternResult:
        """
        Run comprehensive traffic pattern analysis.
        
        Returns:
            TrafficPatternResult with all detected patterns
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        size_task = self._analyze_size_distribution(target)
        flow_task = self._analyze_flow_patterns(target)
        bidir_task = self._analyze_bidirectional_correlation(target)
        burst_task = self._analyze_burst_patterns(target)
        entropy_task = self._analyze_entropy(target)
        
        size_result, flow_result, bidir_result, burst_result, entropy_result = await asyncio.gather(
            size_task, flow_task, bidir_task, burst_task, entropy_task,
            return_exceptions=True
        )
        
        # Aggregate results
        pattern_detected = False
        
        size_distribution_score = 0.0
        if isinstance(size_result, dict):
            size_distribution_score = size_result.get("distinctiveness_score", 0.0)
            if size_distribution_score > 0.5:
                pattern_detected = True
        
        flow_pattern_score = 0.0
        if isinstance(flow_result, dict):
            flow_pattern_score = flow_result.get("distinctiveness_score", 0.0)
            if flow_pattern_score > 0.5:
                pattern_detected = True
        
        bidirectional_correlation = 0.0
        if isinstance(bidir_result, dict):
            bidirectional_correlation = bidir_result.get("correlation_score", 0.0)
            if bidirectional_correlation > 0.5:
                pattern_detected = True
        
        burst_pattern_score = 0.0
        if isinstance(burst_result, dict):
            burst_pattern_score = burst_result.get("distinctiveness_score", 0.0)
            if burst_pattern_score > 0.5:
                pattern_detected = True
        
        entropy_score = 0.0
        if isinstance(entropy_result, dict):
            entropy_score = entropy_result.get("entropy_score", 0.0)
            if entropy_score < 0.3:  # Low entropy = predictable = bad
                pattern_detected = True
        
        # Determine severity
        if not pattern_detected:
            severity = PatternSeverity.NONE
        elif max(size_distribution_score, flow_pattern_score, burst_pattern_score) < 0.3:
            severity = PatternSeverity.LOW
        elif max(size_distribution_score, flow_pattern_score, burst_pattern_score) < 0.6:
            severity = PatternSeverity.MEDIUM
        elif max(size_distribution_score, flow_pattern_score, burst_pattern_score) < 0.8:
            severity = PatternSeverity.HIGH
        else:
            severity = PatternSeverity.CRITICAL
        
        return TrafficPatternResult(
            timestamp=timestamp,
            target=target,
            pattern_detected=pattern_detected,
            size_distribution_score=size_distribution_score,
            flow_pattern_score=flow_pattern_score,
            bidirectional_correlation=bidirectional_correlation,
            burst_pattern_score=burst_pattern_score,
            entropy_score=entropy_score,
            severity=severity,
            details={
                "size_analysis": size_result if isinstance(size_result, dict) else {},
                "flow_analysis": flow_result if isinstance(flow_result, dict) else {},
                "bidirectional_analysis": bidir_result if isinstance(bidir_result, dict) else {},
                "burst_analysis": burst_result if isinstance(burst_result, dict) else {},
                "entropy_analysis": entropy_result if isinstance(entropy_result, dict) else {},
            }
        )
    
    async def _analyze_size_distribution(self, target: str) -> Dict[str, Any]:
        """
        Analyze packet size distribution.
        
        Different applications have distinctive packet size distributions.
        """
        packet_sizes = []
        distinctiveness_score = 0.0
        
        try:
            # Simulate traffic and measure sizes
            for _ in range(20):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{target}/",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            data = await resp.read()
                            packet_sizes.append(len(data))
                except Exception:
                    pass
            
            if len(packet_sizes) >= 10:
                # Calculate distribution statistics
                mean = sum(packet_sizes) / len(packet_sizes)
                variance = sum((x - mean) ** 2 for x in packet_sizes) / len(packet_sizes)
                std_dev = math.sqrt(variance)
                
                # Calculate coefficient of variation
                cv = std_dev / mean if mean > 0 else 0
                
                # Low CV = distinctive pattern
                if cv < 0.2:
                    distinctiveness_score = 0.8
                elif cv < 0.5:
                    distinctiveness_score = 0.5
                else:
                    distinctiveness_score = 0.2
        
        except Exception as e:
            return {"error": str(e), "distinctiveness_score": 0.0}
        
        return {
            "distinctiveness_score": distinctiveness_score,
            "samples": len(packet_sizes),
            "mean_size": sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0.0,
        }
    
    async def _analyze_flow_patterns(self, target: str) -> Dict[str, Any]:
        """
        Analyze flow duration and timing patterns.
        
        Different applications have distinctive flow patterns.
        """
        flow_durations = []
        distinctiveness_score = 0.0
        
        try:
            # Measure flow durations
            for _ in range(15):
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
                flow_durations.append(end_time - start_time)
            
            if len(flow_durations) >= 10:
                mean = sum(flow_durations) / len(flow_durations)
                variance = sum((x - mean) ** 2 for x in flow_durations) / len(flow_durations)
                cv = math.sqrt(variance) / mean if mean > 0 else 0
                
                if cv < 0.2:
                    distinctiveness_score = 0.8
                elif cv < 0.5:
                    distinctiveness_score = 0.5
                else:
                    distinctiveness_score = 0.2
        
        except Exception as e:
            return {"error": str(e), "distinctiveness_score": 0.0}
        
        return {
            "distinctiveness_score": distinctiveness_score,
            "samples": len(flow_durations),
            "mean_duration": sum(flow_durations) / len(flow_durations) if flow_durations else 0.0,
        }
    
    async def _analyze_bidirectional_correlation(self, target: str) -> Dict[str, Any]:
        """
        Analyze bidirectional traffic correlation.
        
        Correlate upload (request) and download (response) patterns.
        """
        correlation_score = 0.0
        request_sizes = []
        response_sizes = []
        
        try:
            # Measure request and response sizes
            for _ in range(15):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{target}/",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            data = await resp.read()
                            response_sizes.append(len(data))
                            request_sizes.append(100)  # Approximate request size
                except Exception:
                    pass
            
            if len(request_sizes) >= 10 and len(response_sizes) >= 10:
                # Calculate correlation
                correlation = np.corrcoef(request_sizes, response_sizes)[0, 1]
                correlation_score = abs(correlation) if not np.isnan(correlation) else 0.0
        
        except Exception as e:
            return {"error": str(e), "correlation_score": 0.0}
        
        return {
            "correlation_score": correlation_score,
            "samples": len(request_sizes),
        }
    
    async def _analyze_burst_patterns(self, target: str) -> Dict[str, Any]:
        """
        Analyze traffic burst patterns.
        
        Detect and characterize traffic bursts.
        """
        burst_times = []
        distinctiveness_score = 0.0
        
        try:
            # Measure timing of multiple requests
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
                burst_times.append(end_time - start_time)
            
            if len(burst_times) >= 10:
                # Detect bursts (short durations)
                mean = sum(burst_times) / len(burst_times)
                burst_threshold = mean * 0.5
                
                bursts = [t for t in burst_times if t < burst_threshold]
                
                if len(bursts) >= 5:
                    # Bursts detected
                    burst_ratio = len(bursts) / len(burst_times)
                    distinctiveness_score = min(1.0, burst_ratio * 2)
        
        except Exception as e:
            return {"error": str(e), "distinctiveness_score": 0.0}
        
        return {
            "distinctiveness_score": distinctiveness_score,
            "samples": len(burst_times),
        }
    
    async def _analyze_entropy(self, target: str) -> Dict[str, Any]:
        """
        Analyze traffic entropy.
        
        Low entropy = predictable traffic = easier to fingerprint.
        """
        entropy_score = 1.0
        data_samples = []
        
        try:
            # Collect data samples
            for _ in range(10):
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{target}/",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            data = await resp.read()
                            data_samples.append(data[:1000])  # First 1000 bytes
                except Exception:
                    pass
            
            if data_samples:
                # Calculate entropy of each sample
                entropies = []
                
                for data in data_samples:
                    # Calculate byte frequency distribution
                    byte_counts = [0] * 256
                    for byte in data:
                        byte_counts[byte] += 1
                    
                    # Calculate entropy
                    entropy = 0.0
                    total = len(data)
                    for count in byte_counts:
                        if count > 0:
                            p = count / total
                            entropy -= p * math.log2(p)
                    
                    entropies.append(entropy)
                
                # Average entropy
                avg_entropy = sum(entropies) / len(entropies)
                
                # Normalize to 0-1 scale (max entropy for bytes is 8)
                entropy_score = avg_entropy / 8.0
        
        except Exception as e:
            return {"error": str(e), "entropy_score": 1.0}
        
        return {
            "entropy_score": entropy_score,
            "samples": len(data_samples),
        }
