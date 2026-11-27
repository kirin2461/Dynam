"""
Advanced security detection routes — DNS leaks, ESNI/ECH, WebSocket tunnels, 
timing side-channels, certificate transparency, traffic patterns, HTTP/2 push,
MPTCP, IPv6 transition, proxy chains, browser extensions, protocol downgrade.

Endpoints:
  POST /api/detect/dns-leak          — DNS over HTTPS/TLS leak detection
  POST /api/detect/esni-ech          — ESNI/ECH testing
  POST /api/detect/websocket-tunnel  — WebSocket tunnel detection
  POST /api/detect/timing            — Timing side-channel detection
  POST /api/detect/ct                — Certificate transparency monitoring
  POST /api/detect/traffic-pattern   — Traffic pattern analysis
  POST /api/detect/http2-push        — HTTP/2 push abuse testing
  POST /api/detect/mptcp             — MPTCP testing
  POST /api/detect/ipv6              — IPv6 transition testing
  POST /api/detect/proxy-chain       — Proxy chain validation
  POST /api/detect/extension         — Browser extension fingerprinting
  POST /api/detect/downgrade         — Protocol downgrade testing
  
  GET variants for all endpoints
"""

from typing import Optional
from fastapi import FastAPI, Query

from ..attacks.dns_leak import DNSLeakDetector
from ..attacks.esni_ech import ECHTester
from ..attacks.websocket_tunnel import WebSocketTunnelDetector
from ..attacks.timing_sidechannel import TimingSidechannelDetector
from ..attacks.cert_transparency import CTMonitor
from ..attacks.traffic_pattern import TrafficPatternAnalyzer
from ..attacks.http2_push import HTTP2PushTester
from ..attacks.mptcp_test import MPTCPTester
from ..attacks.ipv6_transition import IPv6TransitionTester
from ..attacks.proxy_chain import ProxyChainValidator
from ..attacks.browser_extension import BrowserExtensionDetector
from ..attacks.protocol_downgrade import ProtocolDowngradeTester


def register_security_routes(app: FastAPI):
    """Register all advanced security detection routes."""
    
    # ─── DNS over HTTPS/TLS Leak Detection ────────────────────────────
    
    @app.post("/api/detect/dns-leak")
    async def detect_dns_leak(target: str = Query(...)):
        """Detect DNS over HTTPS/TLS leaks."""
        detector = DNSLeakDetector()
        result = await detector.detect_leaks(target)
        return result.to_dict()
    
    @app.get("/api/detect/dns-leak/{target}")
    async def detect_dns_leak_get(target: str):
        """Detect DNS over HTTPS/TLS leaks (GET)."""
        detector = DNSLeakDetector()
        result = await detector.detect_leaks(target)
        return result.to_dict()
    
    # ─── ESNI/ECH Testing ──────────────────────────────────────────────
    
    @app.post("/api/detect/esni-ech")
    async def test_esni_ech(target: str = Query(...)):
        """Test ESNI/ECH support and weaknesses."""
        tester = ECHTester()
        result = await tester.test_ech(target)
        return result.to_dict()
    
    @app.get("/api/detect/esni-ech/{target}")
    async def test_esni_ech_get(target: str):
        """Test ESNI/ECH (GET)."""
        tester = ECHTester()
        result = await tester.test_ech(target)
        return result.to_dict()
    
    # ─── WebSocket Tunnel Detection ────────────────────────────────────
    
    @app.post("/api/detect/websocket-tunnel")
    async def detect_websocket_tunnel(target: str = Query(...)):
        """Detect WebSocket-based tunneling."""
        detector = WebSocketTunnelDetector()
        result = await detector.detect_tunnel(target)
        return result.to_dict()
    
    @app.get("/api/detect/websocket-tunnel/{target}")
    async def detect_websocket_tunnel_get(target: str):
        """Detect WebSocket tunneling (GET)."""
        detector = WebSocketTunnelDetector()
        result = await detector.detect_tunnel(target)
        return result.to_dict()
    
    # ─── Timing Side-Channel Detection ─────────────────────────────────
    
    @app.post("/api/detect/timing")
    async def detect_timing_sidechannel(target: str = Query(...)):
        """Detect timing side-channels."""
        detector = TimingSidechannelDetector()
        result = await detector.detect_timing_sidechannel(target)
        return result.to_dict()
    
    @app.get("/api/detect/timing/{target}")
    async def detect_timing_sidechannel_get(target: str):
        """Detect timing side-channels (GET)."""
        detector = TimingSidechannelDetector()
        result = await detector.detect_timing_sidechannel(target)
        return result.to_dict()
    
    # ─── Certificate Transparency Monitoring ───────────────────────────
    
    @app.post("/api/detect/ct")
    async def monitor_cert_transparency(target: str = Query(...)):
        """Monitor certificate transparency logs."""
        monitor = CTMonitor()
        result = await monitor.monitor(target)
        return result.to_dict()
    
    @app.get("/api/detect/ct/{target}")
    async def monitor_cert_transparency_get(target: str):
        """Monitor CT logs (GET)."""
        monitor = CTMonitor()
        result = await monitor.monitor(target)
        return result.to_dict()
    
    # ─── Traffic Pattern Analysis ──────────────────────────────────────
    
    @app.post("/api/detect/traffic-pattern")
    async def analyze_traffic_pattern(target: str = Query(...)):
        """Analyze traffic patterns for correlation."""
        analyzer = TrafficPatternAnalyzer()
        result = await analyzer.analyze_patterns(target)
        return result.to_dict()
    
    @app.get("/api/detect/traffic-pattern/{target}")
    async def analyze_traffic_pattern_get(target: str):
        """Analyze traffic patterns (GET)."""
        analyzer = TrafficPatternAnalyzer()
        result = await analyzer.analyze_patterns(target)
        return result.to_dict()
    
    # ─── HTTP/2 Push Abuse Testing ─────────────────────────────────────
    
    @app.post("/api/detect/http2-push")
    async def test_http2_push(target: str = Query(...)):
        """Test HTTP/2 push for DPI bypass."""
        tester = HTTP2PushTester()
        result = await tester.test_push(target)
        return result.to_dict()
    
    @app.get("/api/detect/http2-push/{target}")
    async def test_http2_push_get(target: str):
        """Test HTTP/2 push (GET)."""
        tester = HTTP2PushTester()
        result = await tester.test_push(target)
        return result.to_dict()
    
    # ─── MPTCP Testing ─────────────────────────────────────────────────
    
    @app.post("/api/detect/mptcp")
    async def test_mptcp(target: str = Query(...)):
        """Test MPTCP support and DPI bypass potential."""
        tester = MPTCPTester()
        result = await tester.test_mptcp(target)
        return result.to_dict()
    
    @app.get("/api/detect/mptcp/{target}")
    async def test_mptcp_get(target: str):
        """Test MPTCP (GET)."""
        tester = MPTCPTester()
        result = await tester.test_mptcp(target)
        return result.to_dict()
    
    # ─── IPv6 Transition Testing ───────────────────────────────────────
    
    @app.post("/api/detect/ipv6")
    async def test_ipv6_transition(target: str = Query(...)):
        """Test IPv6 transition mechanisms."""
        tester = IPv6TransitionTester()
        result = await tester.test_ipv6_transition(target)
        return result.to_dict()
    
    @app.get("/api/detect/ipv6/{target}")
    async def test_ipv6_transition_get(target: str):
        """Test IPv6 transition (GET)."""
        tester = IPv6TransitionTester()
        result = await tester.test_ipv6_transition(target)
        return result.to_dict()
    
    # ─── Proxy Chain Validation ────────────────────────────────────────
    
    @app.post("/api/detect/proxy-chain")
    async def validate_proxy_chain(target: str = Query(...)):
        """Validate proxy chain for leaks."""
        validator = ProxyChainValidator()
        result = await validator.validate_chain(target)
        return result.to_dict()
    
    @app.get("/api/detect/proxy-chain/{target}")
    async def validate_proxy_chain_get(target: str):
        """Validate proxy chain (GET)."""
        validator = ProxyChainValidator()
        result = await validator.validate_chain(target)
        return result.to_dict()
    
    # ─── Browser Extension Fingerprinting ──────────────────────────────
    
    @app.post("/api/detect/extension")
    async def detect_browser_extension(target: str = Query(...)):
        """Detect browser extension fingerprinting."""
        detector = BrowserExtensionDetector()
        result = await detector.detect_extensions(target)
        return result.to_dict()
    
    @app.get("/api/detect/extension/{target}")
    async def detect_browser_extension_get(target: str):
        """Detect browser extensions (GET)."""
        detector = BrowserExtensionDetector()
        result = await detector.detect_extensions(target)
        return result.to_dict()
    
    # ─── Protocol Downgrade Testing ────────────────────────────────────
    
    @app.post("/api/detect/downgrade")
    async def test_protocol_downgrade(target: str = Query(...)):
        """Test protocol downgrade vulnerabilities."""
        tester = ProtocolDowngradeTester()
        result = await tester.test_downgrade(target)
        return result.to_dict()
    
    @app.get("/api/detect/downgrade/{target}")
    async def test_protocol_downgrade_get(target: str):
        """Test protocol downgrade (GET)."""
        tester = ProtocolDowngradeTester()
        result = await tester.test_downgrade(target)
        return result.to_dict()
