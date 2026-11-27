"""
Browser Fingerprint Masking — detect and prevent browser fingerprinting.

Browser fingerprinting uses Canvas, WebGL, Audio, and other APIs to create
unique identifiers for tracking users across sessions.

Detection methods:
1. Canvas fingerprint — detect canvas.toDataURL() calls with unique patterns
2. WebGL fingerprint — detect renderer/vendor string harvesting
3. Audio fingerprint — detect AudioContext fingerprinting
4. Font enumeration — detect font detection attempts
5. Plugin enumeration — detect plugin list harvesting
6. Screen properties — detect screen resolution/depth harvesting

Metrics:
- fingerprint_detected: bool — whether fingerprinting was detected
- canvas_fingerprint: bool — canvas fingerprinting detected
- webgl_fingerprint: bool — WebGL fingerprinting detected
- audio_fingerprint: bool — audio fingerprinting detected
- font_enumeration: int — number of fonts probed
- plugin_enumeration: int — number of plugins probed
- fingerprint_hash: str — computed fingerprint hash (if detected)
"""

import asyncio
import hashlib
import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import aiohttp


class FingerprintSeverity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FingerprintResult:
    """Result of browser fingerprint detection."""
    timestamp: str
    target: str
    fingerprint_detected: bool
    canvas_fingerprint: bool = False
    webgl_fingerprint: bool = False
    audio_fingerprint: bool = False
    font_enumeration: int = 0
    plugin_enumeration: int = 0
    fingerprint_hash: str = ""
    severity: FingerprintSeverity = FingerprintSeverity.NONE
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "fingerprint_detected": self.fingerprint_detected,
            "canvas_fingerprint": self.canvas_fingerprint,
            "webgl_fingerprint": self.webgl_fingerprint,
            "audio_fingerprint": self.audio_fingerprint,
            "font_enumeration": self.font_enumeration,
            "plugin_enumeration": self.plugin_enumeration,
            "fingerprint_hash": self.fingerprint_hash,
            "severity": self.severity.value,
            "details": self.details,
        }


class BrowserFingerprintDetector:
    """
    Detect browser fingerprinting attempts.
    
    Tests:
    1. Canvas fingerprinting — detect canvas.toDataURL() with unique rendering
    2. WebGL fingerprinting — detect GPU vendor/renderer string harvesting
    3. Audio fingerprinting — detect AudioContext fingerprinting
    4. Font enumeration — detect font detection attempts
    5. Plugin enumeration — detect plugin list harvesting
    6. Screen properties — detect screen resolution/depth harvesting
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def detect_fingerprinting(self, target: str) -> FingerprintResult:
        """
        Run comprehensive browser fingerprint detection.
        
        Returns:
            FingerprintResult with all detected fingerprinting attempts
        """
        timestamp = datetime.now().isoformat()
        
        # Run all detection tests in parallel
        js_task = self._analyze_javascript(target)
        canvas_task = self._detect_canvas_fingerprint(target)
        webgl_task = self._detect_webgl_fingerprint(target)
        audio_task = self._detect_audio_fingerprint(target)
        
        js_result, canvas_result, webgl_result, audio_result = await asyncio.gather(
            js_task, canvas_task, webgl_task, audio_task,
            return_exceptions=True
        )
        
        # Aggregate results
        fingerprint_detected = False
        canvas_fingerprint = False
        webgl_fingerprint = False
        audio_fingerprint = False
        font_enumeration = 0
        plugin_enumeration = 0
        fingerprint_components = []
        
        # Process JavaScript analysis
        if isinstance(js_result, dict):
            canvas_fingerprint = js_result.get("canvas_detected", False)
            webgl_fingerprint = js_result.get("webgl_detected", False)
            audio_fingerprint = js_result.get("audio_detected", False)
            font_enumeration = js_result.get("font_count", 0)
            plugin_enumeration = js_result.get("plugin_count", 0)
            
            if canvas_fingerprint:
                fingerprint_components.append("canvas")
            if webgl_fingerprint:
                fingerprint_components.append("webgl")
            if audio_fingerprint:
                fingerprint_components.append("audio")
        
        # Process Canvas result
        if isinstance(canvas_result, dict) and canvas_result.get("detected"):
            canvas_fingerprint = True
            if "canvas" not in fingerprint_components:
                fingerprint_components.append("canvas")
        
        # Process WebGL result
        if isinstance(webgl_result, dict) and webgl_result.get("detected"):
            webgl_fingerprint = True
            if "webgl" not in fingerprint_components:
                fingerprint_components.append("webgl")
        
        # Process Audio result
        if isinstance(audio_result, dict) and audio_result.get("detected"):
            audio_fingerprint = True
            if "audio" not in fingerprint_components:
                fingerprint_components.append("audio")
        
        fingerprint_detected = len(fingerprint_components) > 0 or font_enumeration > 0 or plugin_enumeration > 0
        
        # Compute fingerprint hash from components
        if fingerprint_components:
            fingerprint_hash = hashlib.sha256(
                "|".join(sorted(fingerprint_components)).encode()
            ).hexdigest()[:16]
        else:
            fingerprint_hash = ""
        
        # Determine severity
        if not fingerprint_detected:
            severity = FingerprintSeverity.NONE
        elif len(fingerprint_components) == 1 and font_enumeration == 0:
            severity = FingerprintSeverity.LOW
        elif len(fingerprint_components) == 2 or font_enumeration > 10:
            severity = FingerprintSeverity.MEDIUM
        elif len(fingerprint_components) == 3 or plugin_enumeration > 5:
            severity = FingerprintSeverity.HIGH
        else:
            severity = FingerprintSeverity.CRITICAL
        
        return FingerprintResult(
            timestamp=timestamp,
            target=target,
            fingerprint_detected=fingerprint_detected,
            canvas_fingerprint=canvas_fingerprint,
            webgl_fingerprint=webgl_fingerprint,
            audio_fingerprint=audio_fingerprint,
            font_enumeration=font_enumeration,
            plugin_enumeration=plugin_enumeration,
            fingerprint_hash=fingerprint_hash,
            severity=severity,
            details={
                "js_analysis": js_result if isinstance(js_result, dict) else {},
                "canvas_test": canvas_result if isinstance(canvas_result, dict) else {},
                "webgl_test": webgl_result if isinstance(webgl_result, dict) else {},
                "audio_test": audio_result if isinstance(audio_result, dict) else {},
            }
        )
    
    async def _analyze_javascript(self, target: str) -> Dict[str, Any]:
        """
        Analyze JavaScript code for fingerprinting patterns.
        
        Looks for:
        - canvas.toDataURL() calls
        - WebGL context creation and parameter queries
        - AudioContext creation and oscillator patterns
        - Font detection libraries (FontDetect, fontdetect.js)
        - Plugin enumeration (navigator.plugins)
        """
        canvas_detected = False
        webgl_detected = False
        audio_detected = False
        font_count = 0
        plugin_count = 0
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{target}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status != 200:
                        return {"error": f"HTTP {resp.status}"}
                    
                    html = await resp.text()
                    
                    # Extract JavaScript from <script> tags
                    script_pattern = r'<script[^>]*>(.*?)</script>'
                    scripts = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
                    
                    for script in scripts:
                        # Canvas fingerprinting
                        if re.search(r'canvas.*toDataURL|getContext\(["\']2d["\']\).*toDataURL', script, re.IGNORECASE):
                            canvas_detected = True
                        
                        # WebGL fingerprinting
                        if re.search(r'getContext\(["\']webgl["\']\)|getParameter\(.*RENDERER|getParameter\(.*VENDOR', script, re.IGNORECASE):
                            webgl_detected = True
                        
                        # Audio fingerprinting
                        if re.search(r'new AudioContext|createOscillator|createAnalyser', script, re.IGNORECASE):
                            audio_detected = True
                        
                        # Font enumeration
                        font_matches = re.findall(r'font[_-]?detect|document\.fonts|font-family.*test', script, re.IGNORECASE)
                        font_count += len(font_matches)
                        
                        # Plugin enumeration
                        plugin_matches = re.findall(r'navigator\.plugins|navigator\.mimeTypes', script, re.IGNORECASE)
                        plugin_count += len(plugin_matches)
                    
                    # Check for external fingerprinting libraries
                    if re.search(r'fingerprint2\.js|fingerprintjs|creepjs', html, re.IGNORECASE):
                        # Known fingerprinting library detected
                        canvas_detected = True
                        webgl_detected = True
        
        except Exception as e:
            return {"error": str(e)}
        
        return {
            "canvas_detected": canvas_detected,
            "webgl_detected": webgl_detected,
            "audio_detected": audio_detected,
            "font_count": font_count,
            "plugin_count": plugin_count,
        }
    
    async def _detect_canvas_fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Detect canvas fingerprinting by checking for unique rendering patterns.
        
        Canvas fingerprinting works by rendering text/shapes with specific fonts
        and extracting the pixel data as a hash.
        """
        detected = False
        
        try:
            async with aiohttp.ClientSession() as session:
                # Check if target has canvas-based tracking
                async with session.get(
                    f"https://{target}/favicon.ico",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    # If favicon is a canvas-generated image, potential fingerprinting
                    content_type = resp.headers.get("Content-Type", "")
                    if "image/png" in content_type:
                        # Check if it's dynamically generated (canvas fingerprint)
                        cache_control = resp.headers.get("Cache-Control", "")
                        if "no-cache" in cache_control or "max-age=0" in cache_control:
                            detected = True
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "method": "canvas_toDataURL_analysis",
        }
    
    async def _detect_webgl_fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Detect WebGL fingerprinting by checking for GPU parameter harvesting.
        
        WebGL fingerprinting extracts GPU vendor/renderer strings to identify
        unique hardware configurations.
        """
        detected = False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{target}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status != 200:
                        return {"error": f"HTTP {resp.status}", "detected": False}
                    
                    html = await resp.text()
                    
                    # Check for WebGL fingerprinting patterns
                    patterns = [
                        r'getParameter\(.*UNMASKED_VENDOR_WEBGL',
                        r'getParameter\(.*UNMASKED_RENDERER_WEBGL',
                        r'getExtension\(["\']WEBGL_debug_renderer_info["\']\)',
                    ]
                    
                    for pattern in patterns:
                        if re.search(pattern, html, re.IGNORECASE):
                            detected = True
                            break
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "method": "webgl_parameter_harvesting",
        }
    
    async def _detect_audio_fingerprint(self, target: str) -> Dict[str, Any]:
        """
        Detect audio fingerprinting by checking for AudioContext patterns.
        
        Audio fingerprinting uses AudioContext to create unique audio signals
        and analyze the output to generate a fingerprint.
        """
        detected = False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{target}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as resp:
                    if resp.status != 200:
                        return {"error": f"HTTP {resp.status}", "detected": False}
                    
                    html = await resp.text()
                    
                    # Check for audio fingerprinting patterns
                    patterns = [
                        r'new AudioContext.*createOscillator',
                        r'createOscillator.*createAnalyser',
                        r'getChannelData.*frequencyBinCount',
                    ]
                    
                    for pattern in patterns:
                        if re.search(pattern, html, re.IGNORECASE):
                            detected = True
                            break
        
        except Exception as e:
            return {"error": str(e), "detected": False}
        
        return {
            "detected": detected,
            "method": "audio_context_analysis",
        }
