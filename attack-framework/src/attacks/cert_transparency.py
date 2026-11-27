"""
Certificate Transparency Monitoring — monitor CT logs for domain blocking/changes.

Certificate Transparency (CT) logs are public logs of all issued TLS certificates.
They can be used to:
1. Detect domain blocking — if certificate is revoked or not renewed
2. Correlate certificate issuance patterns with blocking events
3. Enumerate subdomains from CT logs
4. Detect certificate changes that may indicate blocking
5. Monitor for new certificates issued for monitored domains

Detection methods:
- CT log monitoring — query CT logs for certificate changes
- Revocation detection — detect if certificates are revoked
- Issuance pattern analysis — detect unusual issuance patterns
- Subdomain enumeration — extract subdomains from CT logs
- Change detection — detect certificate changes over time

Metrics:
- certificates_found: int — number of certificates found in CT logs
- revoked_certificates: int — number of revoked certificates
- recent_issuance: int — certificates issued in last 24h
- subdomains_found: list — subdomains discovered from CT logs
- blocking_indicated: bool — whether CT data suggests blocking
- change_detected: bool — certificate changes detected
"""

import asyncio
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import aiohttp


class CTSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CTMonitoringResult:
    """Result of Certificate Transparency monitoring."""
    timestamp: str
    target: str
    certificates_found: int = 0
    revoked_certificates: int = 0
    recent_issuance: int = 0
    subdomains_found: List[str] = field(default_factory=list)
    blocking_indicated: bool = False
    change_detected: bool = False
    severity: CTSeverity = CTSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "certificates_found": self.certificates_found,
            "revoked_certificates": self.revoked_certificates,
            "recent_issuance": self.recent_issuance,
            "subdomains_found": self.subdomains_found,
            "blocking_indicated": self.blocking_indicated,
            "change_detected": self.change_detected,
            "severity": self.severity.value,
            "details": self.details,
        }


class CTMonitor:
    """
    Monitor Certificate Transparency logs for domain changes.
    
    Tests:
    1. CT log querying — fetch certificates from CT logs
    2. Revocation detection — check for revoked certificates
    3. Issuance pattern analysis — detect unusual patterns
    4. Subdomain enumeration — extract subdomains
    5. Change detection — detect changes over time
    """
    
    # CT log APIs
    CT_APIS = [
        "https://crt.sh/?q={}&output=json",
        "https://certspotter.com/api/v0/issuances?domain={}",
    ]
    
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
    
    async def monitor(self, target: str) -> CTMonitoringResult:
        """
        Run comprehensive CT log monitoring.
        
        Returns:
            CTMonitoringResult with monitoring results
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        crt_sh_task = self._query_crt_sh(target)
        certspotter_task = self._query_certspotter(target)
        
        crt_sh_result, certspotter_result = await asyncio.gather(
            crt_sh_task, certspotter_task,
            return_exceptions=True
        )
        
        # Aggregate results
        all_certs = []
        
        if isinstance(crt_sh_result, list):
            all_certs.extend(crt_sh_result)
        
        if isinstance(certspotter_result, list):
            all_certs.extend(certspotter_result)
        
        certificates_found = len(all_certs)
        
        # Analyze certificates
        revoked_count = 0
        recent_count = 0
        subdomains = set()
        
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        
        for cert in all_certs:
            # Check if revoked
            if cert.get("revoked", False):
                revoked_count += 1
            
            # Check if recent
            not_before = cert.get("not_before", "")
            if not_before:
                try:
                    cert_time = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                    if cert_time > day_ago:
                        recent_count += 1
                except Exception:
                    pass
            
            # Extract subdomains
            name = cert.get("name_value", "") or cert.get("common_name", "")
            if name:
                for subdomain in name.split("\n"):
                    subdomain = subdomain.strip()
                    if subdomain and target in subdomain:
                        subdomains.add(subdomain)
        
        # Detect blocking indicators
        blocking_indicated = False
        
        # If many certificates revoked, blocking might be happening
        if revoked_count > certificates_found * 0.3:
            blocking_indicated = True
        
        # If no recent issuances but target is active, might be blocked
        if recent_count == 0 and certificates_found > 5:
            # Check if last certificate is old
            if all_certs:
                last_cert = max(all_certs, key=lambda c: c.get("not_before", ""))
                last_time = last_cert.get("not_before", "")
                if last_time:
                    try:
                        cert_time = datetime.fromisoformat(last_time.replace("Z", "+00:00"))
                        if (now - cert_time).days > 30:
                            blocking_indicated = True
                    except Exception:
                        pass
        
        # Detect changes
        change_detected = recent_count > 0 or revoked_count > 0
        
        # Determine severity
        if not blocking_indicated and not change_detected:
            severity = CTSeverity.NONE
        elif not blocking_indicated and recent_count < 3:
            severity = CTSeverity.LOW
        elif not blocking_indicated:
            severity = CTSeverity.MEDIUM
        elif revoked_count < certificates_found * 0.5:
            severity = CTSeverity.HIGH
        else:
            severity = CTSeverity.CRITICAL
        
        return CTMonitoringResult(
            timestamp=timestamp,
            target=target,
            certificates_found=certificates_found,
            revoked_certificates=revoked_count,
            recent_issuance=recent_count,
            subdomains_found=list(subdomains)[:20],  # Limit to 20
            blocking_indicated=blocking_indicated,
            change_detected=change_detected,
            severity=severity,
            details={
                "crt_sh_count": len(crt_sh_result) if isinstance(crt_sh_result, list) else 0,
                "certspotter_count": len(certspotter_result) if isinstance(certspotter_result, list) else 0,
                "total_subdomains": len(subdomains),
            }
        )
    
    async def _query_crt_sh(self, target: str) -> List[Dict[str, Any]]:
        """
        Query crt.sh for certificates.
        
        crt.sh is a free CT log aggregator.
        """
        certificates = []
        
        try:
            url = f"https://crt.sh/?q={target}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        for entry in data:
                            certificates.append({
                                "id": entry.get("id"),
                                "name_value": entry.get("name_value", ""),
                                "common_name": entry.get("common_name", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                                "issuer_ca_id": entry.get("issuer_ca_id"),
                                "revoked": entry.get("entry_timestamp", "") == "",
                            })
        
        except Exception as e:
            return []
        
        return certificates
    
    async def _query_certspotter(self, target: str) -> List[Dict[str, Any]]:
        """
        Query Cert Spotter for certificates.
        
        Cert Spotter is another CT log aggregator.
        """
        certificates = []
        
        try:
            url = f"https://certspotter.com/api/v0/issuances?domain={target}&include_subdomains=true&expand=dns_names"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        
                        for entry in data:
                            certificates.append({
                                "id": entry.get("id"),
                                "name_value": "\n".join(entry.get("dns_names", [])),
                                "common_name": entry.get("dns_names", [""])[0] if entry.get("dns_names") else "",
                                "not_before": entry.get("time_not_before", ""),
                                "not_after": entry.get("time_not_after", ""),
                                "revoked": entry.get("revoked", False),
                            })
        
        except Exception as e:
            return []
        
        return certificates
