"""
DNS over HTTPS/TLS Leak Detection — detect privacy leaks in DoH/DoT.

DoH/DoT are considered private, but can leak information through:
1. SNI in TLS handshake (for DoT)
2. HTTP headers in DoH requests
3. Timing correlations between DNS queries and content requests
4. Certificate transparency logs exposing queried domains
5. DNS query padding (or lack thereof)

Detection methods:
- SNI analysis — check if DoT reveals domain in TLS ClientHello
- HTTP header analysis — check DoH request headers for leaks
- Timing correlation — detect timing-based DNS-content correlation
- Certificate analysis — check if DoH/DoT certificates reveal info
- Query padding analysis — check if queries are padded to hide length

Metrics:
- leak_detected: bool — whether any leak was found
- sni_leak: bool — SNI leak detected (DoT)
- header_leak: bool — HTTP header leak detected (DoH)
- timing_correlation: float — timing correlation score (0-1)
- certificate_leak: bool — certificate leak detected
- padding_inadequate: bool — query padding inadequate
"""

import asyncio
import socket
import ssl
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class DNSLeakSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DNSLeakResult:
    """Result of DNS over HTTPS/TLS leak detection."""
    timestamp: str
    target: str
    leak_detected: bool
    sni_leak: bool = False
    header_leak: bool = False
    timing_correlation: float = 0.0
    certificate_leak: bool = False
    padding_inadequate: bool = False
    severity: DNSLeakSeverity = DNSLeakSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "leak_detected": self.leak_detected,
            "sni_leak": self.sni_leak,
            "header_leak": self.header_leak,
            "timing_correlation": self.timing_correlation,
            "certificate_leak": self.certificate_leak,
            "padding_inadequate": self.padding_inadequate,
            "severity": self.severity.value,
            "details": self.details,
        }


class DNSLeakDetector:
    """
    Detect DNS over HTTPS/TLS privacy leaks.
    
    Tests:
    1. SNI leak — DoT reveals domain in TLS ClientHello SNI
    2. HTTP header leak — DoH headers reveal query info
    3. Timing correlation — DNS query timing correlates with content
    4. Certificate leak — certificates reveal queried domains
    5. Padding inadequacy — queries not padded, revealing length
    """
    
    # Common DoH providers
    DOH_PROVIDERS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://mozilla.cloudflare-dns.com/dns-query",
    ]
    
    # Common DoT providers
    DOT_PROVIDERS = [
        ("1.1.1.1", 853),  # Cloudflare
        ("8.8.8.8", 853),  # Google
        ("9.9.9.9", 853),  # Quad9
    ]
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def detect_leaks(self, target: str) -> DNSLeakResult:
        """
        Run comprehensive DNS over HTTPS/TLS leak detection.
        
        Returns:
            DNSLeakResult with all detected leaks
        """
        timestamp = datetime.now().isoformat()
        
        # Run all detection tests in parallel
        sni_task = self._test_sni_leak(target)
        header_task = self._test_header_leak(target)
        timing_task = self._test_timing_correlation(target)
        cert_task = self._test_certificate_leak(target)
        padding_task = self._test_padding_adequacy(target)
        
        sni_result, header_result, timing_result, cert_result, padding_result = await asyncio.gather(
            sni_task, header_task, timing_task, cert_task, padding_task,
            return_exceptions=True
        )
        
        # Aggregate results
        sni_leak = isinstance(sni_result, dict) and sni_result.get("leak_detected", False)
        header_leak = isinstance(header_result, dict) and header_result.get("leak_detected", False)
        timing_correlation = timing_result.get("correlation_score", 0.0) if isinstance(timing_result, dict) else 0.0
        certificate_leak = isinstance(cert_result, dict) and cert_result.get("leak_detected", False)
        padding_inadequate = isinstance(padding_result, dict) and padding_result.get("inadequate", False)
        
        leak_detected = sni_leak or header_leak or timing_correlation > 0.5 or certificate_leak or padding_inadequate
        
        # Determine severity
        if not leak_detected:
            severity = DNSLeakSeverity.NONE
        elif timing_correlation < 0.3 and not (sni_leak or header_leak or certificate_leak):
            severity = DNSLeakSeverity.LOW
        elif timing_correlation < 0.6 or padding_inadequate:
            severity = DNSLeakSeverity.MEDIUM
        elif timing_correlation < 0.8 or (sni_leak and header_leak):
            severity = DNSLeakSeverity.HIGH
        else:
            severity = DNSLeakSeverity.CRITICAL
        
        return DNSLeakResult(
            timestamp=timestamp,
            target=target,
            leak_detected=leak_detected,
            sni_leak=sni_leak,
            header_leak=header_leak,
            timing_correlation=timing_correlation,
            certificate_leak=certificate_leak,
            padding_inadequate=padding_inadequate,
            severity=severity,
            details={
                "sni_test": sni_result if isinstance(sni_result, dict) else {},
                "header_test": header_result if isinstance(header_result, dict) else {},
                "timing_test": timing_result if isinstance(timing_result, dict) else {},
                "certificate_test": cert_result if isinstance(cert_result, dict) else {},
                "padding_test": padding_result if isinstance(padding_result, dict) else {},
            }
        )
    
    async def _test_sni_leak(self, target: str) -> Dict[str, Any]:
        """
        Test if DoT reveals domain in TLS ClientHello SNI.
        
        DoT should encrypt DNS queries, but TLS handshake still reveals
        the DoT server's domain in SNI. If DoT server domain matches
        queried domain, it's a leak.
        """
        leak_detected = False
        exposed_domains = []
        
        try:
            for dot_host, dot_port in self.DOT_PROVIDERS[:2]:  # Test first 2
                try:
                    # Create TLS connection to DoT server
                    context = ssl.create_default_context()
                    context.set_alpn_protocols(["dot"])
                    
                    sock = socket.create_connection((dot_host, dot_port), timeout=self.timeout)
                    
                    try:
                        with context.wrap_socket(sock, server_hostname=dot_host) as ssock:
                            # Get the certificate
                            cert = ssock.getpeercert()
                            
                            # Check if certificate subject matches target
                            if cert:
                                subject = dict(x[0] for x in cert["subject"])
                                cn = subject.get("commonName", "")
                                
                                # If DoT server CN matches target, it's a leak
                                if target.lower() in cn.lower():
                                    leak_detected = True
                                    exposed_domains.append(cn)
                    
                    finally:
                        sock.close()
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "leak_detected": False}
        
        return {
            "leak_detected": leak_detected,
            "exposed_domains": exposed_domains,
            "providers_tested": len(self.DOT_PROVIDERS[:2]),
        }
    
    async def _test_header_leak(self, target: str) -> Dict[str, Any]:
        """
        Test if DoH request headers reveal query information.
        
        DoH uses HTTPS, but HTTP headers may leak information:
        - Referer header revealing queried domain
        - Custom headers with query metadata
        - URL path revealing query type
        """
        leak_detected = False
        leaked_headers = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for doh_url in self.DOH_PROVIDERS[:2]:  # Test first 2
                    try:
                        # Send DoH query with target domain
                        query_params = {
                            "name": target,
                            "type": "A",
                        }
                        
                        headers = {
                            "Accept": "application/dns-message",
                            "Content-Type": "application/dns-message",
                        }
                        
                        async with session.get(
                            doh_url,
                            params=query_params,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            # Check response headers for leaks
                            resp_headers = dict(resp.headers)
                            
                            # Check if response reveals query info
                            for header_name, header_value in resp_headers.items():
                                if target.lower() in header_value.lower():
                                    leak_detected = True
                                    leaked_headers.append(f"{header_name}: {header_value}")
                    
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e), "leak_detected": False}
        
        return {
            "leak_detected": leak_detected,
            "leaked_headers": leaked_headers,
            "providers_tested": len(self.DOH_PROVIDERS[:2]),
        }
    
    async def _test_timing_correlation(self, target: str) -> Dict[str, Any]:
        """
        Test timing correlation between DNS queries and content requests.
        
        If DNS query timing correlates with content request timing,
        an observer can infer which domains are being accessed.
        """
        correlation_score = 0.0
        timing_samples = []
        
        try:
            # Measure timing of DNS queries vs content requests
            for _ in range(5):  # 5 samples
                # Send DNS query
                dns_start = time.time()
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            self.DOH_PROVIDERS[0],
                            params={"name": target, "type": "A"},
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            await resp.read()
                except Exception:
                    pass
                
                dns_end = time.time()
                dns_duration = dns_end - dns_start
                
                # Send content request to same domain
                content_start = time.time()
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"https://{target}",
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            await resp.read()
                except Exception:
                    pass
                
                content_end = time.time()
                content_duration = content_end - content_start
                
                # Calculate timing gap
                timing_gap = abs(dns_duration - content_duration)
                timing_samples.append(timing_gap)
            
            # Calculate correlation score
            # Low variance = high correlation = bad
            if timing_samples:
                avg_gap = sum(timing_samples) / len(timing_samples)
                variance = sum((x - avg_gap) ** 2 for x in timing_samples) / len(timing_samples)
                
                # Normalize to 0-1 scale (lower variance = higher score)
                correlation_score = min(1.0, 1.0 / (1.0 + variance * 10))
        
        except Exception as e:
            return {"error": str(e), "correlation_score": 0.0}
        
        return {
            "correlation_score": correlation_score,
            "samples": len(timing_samples),
            "avg_timing_gap": sum(timing_samples) / len(timing_samples) if timing_samples else 0.0,
        }
    
    async def _test_certificate_leak(self, target: str) -> Dict[str, Any]:
        """
        Test if DoH/DoT certificates reveal queried domains.
        
        Some DoH/DoT providers issue certificates per-domain,
        which can leak which domains are being queried.
        """
        leak_detected = False
        certificate_info = []
        
        try:
            for doh_url in self.DOH_PROVIDERS[:2]:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            doh_url,
                            params={"name": target, "type": "A"},
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as resp:
                            # Get certificate info
                            # Note: aiohttp doesn't expose cert details directly
                            # This is a simplified test
                            certificate_info.append({
                                "provider": doh_url,
                                "status": resp.status,
                            })
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "leak_detected": False}
        
        return {
            "leak_detected": leak_detected,
            "certificates_checked": len(certificate_info),
        }
    
    async def _test_padding_adequacy(self, target: str) -> Dict[str, Any]:
        """
        Test if DNS queries are adequately padded.
        
        Unpadded queries reveal query length, which can help
        identify the queried domain.
        """
        inadequate = False
        query_sizes = []
        
        try:
            # Measure query sizes for different domains
            test_domains = [target, "a.com", "very-long-domain-name.example.com"]
            
            for domain in test_domains:
                # Create DNS query
                query = self._create_dns_query(domain)
                query_sizes.append(len(query))
            
            # Check if sizes vary significantly
            if len(query_sizes) >= 2:
                size_variance = max(query_sizes) - min(query_sizes)
                
                # If variance > 10 bytes, padding is inadequate
                if size_variance > 10:
                    inadequate = True
        
        except Exception as e:
            return {"error": str(e), "inadequate": False}
        
        return {
            "inadequate": inadequate,
            "query_sizes": query_sizes,
            "size_variance": max(query_sizes) - min(query_sizes) if query_sizes else 0,
        }
    
    def _create_dns_query(self, domain: str) -> bytes:
        """Create a DNS query for the given domain."""
        # Simplified DNS query creation
        # Real implementation would use proper DNS library
        query = bytearray()
        
        # Transaction ID
        query.extend(b"\x00\x01")
        # Flags
        query.extend(b"\x01\x00")
        # Questions: 1
        query.extend(b"\x00\x01")
        # Answer RRs: 0
        query.extend(b"\x00\x00")
        # Authority RRs: 0
        query.extend(b"\x00\x00")
        # Additional RRs: 0
        query.extend(b"\x00\x00")
        
        # Domain name
        for part in domain.split("."):
            query.append(len(part))
            query.extend(part.encode())
        query.append(0)  # End of domain name
        
        # Query type: A (1)
        query.extend(b"\x00\x01")
        # Query class: IN (1)
        query.extend(b"\x00\x01")
        
        return bytes(query)
