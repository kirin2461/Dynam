"""
Browser Extension Fingerprint — detect browser extension fingerprinting.

Browser extensions can be detected through:
1. Extension resource detection — detect extension-specific resources
2. Extension API detection — detect extension API calls
3. Extension behavior detection — detect extension-specific behaviors
4. Extension timing detection — detect extension timing patterns
5. Extension DOM detection — detect extension DOM modifications

Detection methods:
- Resource detection — check for extension-specific resources
- API detection — check for extension API usage
- Behavior detection — check for extension behaviors
- Timing detection — check for extension timing patterns
- DOM detection — check for extension DOM modifications

Metrics:
- extensions_detected: bool — whether extensions were detected
- extension_count: int — number of extensions detected
- extension_types: list — types of extensions detected
- fingerprintable: bool — whether extensions are fingerprintable
- privacy_risk: float — privacy risk score
"""

import asyncio
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class ExtensionSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExtensionFingerprintResult:
    """Result of browser extension fingerprinting."""
    timestamp: str
    target: str
    extensions_detected: bool = False
    extension_count: int = 0
    extension_types: List[str] = field(default_factory=list)
    fingerprintable: bool = False
    privacy_risk: float = 0.0
    severity: ExtensionSeverity = ExtensionSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "extensions_detected": self.extensions_detected,
            "extension_count": self.extension_count,
            "extension_types": self.extension_types,
            "fingerprintable": self.fingerprintable,
            "privacy_risk": self.privacy_risk,
            "severity": self.severity.value,
            "details": self.details,
        }


class BrowserExtensionDetector:
    """
    Detect browser extension fingerprinting.
    
    Tests:
    1. Resource detection — check for extension resources
    2. API detection — check for extension API usage
    3. Behavior detection — check for extension behaviors
    4. Timing detection — check for extension timing
    5. DOM detection — check for extension DOM modifications
    """
    
    # Known extension resource patterns
    EXTENSION_PATTERNS = {
        "adblock": [
            r"adblock",
            r"ublock",
            r"adblocker",
            r"\/adblock\/",
        ],
        "privacy": [
            r"privacy",
            r"ghostery",
            r"disconnect",
            r"privaxy",
        ],
        "password": [
            r"password",
            r"lastpass",
            r"1password",
            r"bitwarden",
            r"keepass",
        ],
        "vpn": [
            r"vpn",
            r"protonvpn",
            r"nordvpn",
            r"expressvpn",
        ],
        "developer": [
            r"react.*devtools",
            r"vue.*devtools",
            r"angular.*devtools",
            r"redux.*devtools",
        ],
    }
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def detect_extensions(self, target: str) -> ExtensionFingerprintResult:
        """
        Run comprehensive browser extension detection.
        
        Returns:
            ExtensionFingerprintResult with all detected extensions
        """
        timestamp = datetime.now().isoformat()
        
        # Run all tests in parallel
        resource_task = self._detect_extension_resources(target)
        api_task = self._detect_extension_apis(target)
        behavior_task = self._detect_extension_behaviors(target)
        timing_task = self._detect_extension_timing(target)
        dom_task = self._detect_extension_dom(target)
        
        resource_result, api_result, behavior_result, timing_result, dom_result = await asyncio.gather(
            resource_task, api_task, behavior_task, timing_task, dom_task,
            return_exceptions=True
        )
        
        # Aggregate results
        extension_types = set()
        extensions_detected = False
        
        if isinstance(resource_result, dict):
            extension_types.update(resource_result.get("extensions", []))
        
        if isinstance(api_result, dict):
            extension_types.update(api_result.get("extensions", []))
        
        if isinstance(behavior_result, dict):
            extension_types.update(behavior_result.get("extensions", []))
        
        if isinstance(timing_result, dict):
            extension_types.update(timing_result.get("extensions", []))
        
        if isinstance(dom_result, dict):
            extension_types.update(dom_result.get("extensions", []))
        
        extension_count = len(extension_types)
        extensions_detected = extension_count > 0
        
        # Calculate fingerprintability
        fingerprintable = extensions_detected
        
        # Calculate privacy risk
        privacy_risk = 0.0
        if extensions_detected:
            # More extensions = higher risk
            privacy_risk = min(1.0, extension_count / 5.0)
            
            # Certain extension types are higher risk
            if "vpn" in extension_types or "privacy" in extension_types:
                privacy_risk += 0.2
            
            privacy_risk = min(1.0, privacy_risk)
        
        # Determine severity
        if not extensions_detected:
            severity = ExtensionSeverity.NONE
        elif extension_count == 1:
            severity = ExtensionSeverity.LOW
        elif extension_count <= 3:
            severity = ExtensionSeverity.MEDIUM
        elif extension_count <= 5:
            severity = ExtensionSeverity.HIGH
        else:
            severity = ExtensionSeverity.CRITICAL
        
        return ExtensionFingerprintResult(
            timestamp=timestamp,
            target=target,
            extensions_detected=extensions_detected,
            extension_count=extension_count,
            extension_types=list(extension_types),
            fingerprintable=fingerprintable,
            privacy_risk=privacy_risk,
            severity=severity,
            details={
                "resource_test": resource_result if isinstance(resource_result, dict) else {},
                "api_test": api_result if isinstance(api_result, dict) else {},
                "behavior_test": behavior_result if isinstance(behavior_result, dict) else {},
                "timing_test": timing_result if isinstance(timing_result, dict) else {},
                "dom_test": dom_result if isinstance(dom_result, dict) else {},
            }
        )
    
    async def _detect_extension_resources(self, target: str) -> Dict[str, Any]:
        """
        Detect extension-specific resources.
        
        Check for extension-specific files, images, scripts.
        """
        extensions = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Fetch target page
                try:
                    async with session.get(
                        f"https://{target}",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            
                            # Check for extension patterns
                            for ext_type, patterns in self.EXTENSION_PATTERNS.items():
                                for pattern in patterns:
                                    if re.search(pattern, html, re.IGNORECASE):
                                        extensions.add(ext_type)
                                        break
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "extensions": []}
        
        return {
            "extensions": list(extensions),
        }
    
    async def _detect_extension_apis(self, target: str) -> Dict[str, Any]:
        """
        Detect extension API usage.
        
        Check for extension API calls in JavaScript.
        """
        extensions = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://{target}",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            
                            # Extract JavaScript
                            script_pattern = r'<script[^>]*>(.*?)</script>'
                            scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
                            
                            for script in scripts:
                                # Check for extension API patterns
                                if re.search(r'chrome\.runtime|browser\.runtime', script, re.IGNORECASE):
                                    extensions.add("chrome-extension")
                                
                                if re.search(r'chrome\.storage|browser\.storage', script, re.IGNORECASE):
                                    extensions.add("storage-extension")
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "extensions": []}
        
        return {
            "extensions": list(extensions),
        }
    
    async def _detect_extension_behaviors(self, target: str) -> Dict[str, Any]:
        """
        Detect extension-specific behaviors.
        
        Check for extension-specific network patterns.
        """
        extensions = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try to access extension resources
                extension_urls = [
                    f"https://{target}/extension",
                    f"https://{target}/chrome-extension",
                    f"https://{target}/moz-extension",
                ]
                
                for url in extension_urls:
                    try:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False,
                            allow_redirects=False
                        ) as resp:
                            if resp.status == 200:
                                extensions.add("extension-endpoint")
                    
                    except Exception:
                        pass
        
        except Exception as e:
            return {"error": str(e), "extensions": []}
        
        return {
            "extensions": list(extensions),
        }
    
    async def _detect_extension_timing(self, target: str) -> Dict[str, Any]:
        """
        Detect extension timing patterns.
        
        Extensions can affect page load timing.
        """
        extensions = set()
        
        try:
            # Measure page load timing
            timings = []
            
            for _ in range(5):
                start_time = asyncio.get_event_loop().time()
                
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
                
                end_time = asyncio.get_event_loop().time()
                timings.append(end_time - start_time)
            
            if len(timings) >= 3:
                # Check for timing anomalies
                mean = sum(timings) / len(timings)
                variance = sum((t - mean) ** 2 for t in timings) / len(timings)
                
                # High variance might indicate extension interference
                if variance > 0.5:
                    extensions.add("timing-anomaly")
        
        except Exception as e:
            return {"error": str(e), "extensions": []}
        
        return {
            "extensions": list(extensions),
        }
    
    async def _detect_extension_dom(self, target: str) -> Dict[str, Any]:
        """
        Detect extension DOM modifications.
        
        Extensions can modify the DOM.
        """
        extensions = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://{target}",
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as resp:
                        if resp.status == 200:
                            html = await resp.text()
                            
                            # Check for extension DOM patterns
                            if re.search(r'data-extension|data-addon|data-plugin', html, re.IGNORECASE):
                                extensions.add("dom-modification")
                            
                            # Check for extension-specific elements
                            if re.search(r'<.*extension.*>|<.*addon.*>|<.*plugin.*>', html, re.IGNORECASE):
                                extensions.add("extension-element")
                
                except Exception:
                    pass
        
        except Exception as e:
            return {"error": str(e), "extensions": []}
        
        return {
            "extensions": list(extensions),
        }
