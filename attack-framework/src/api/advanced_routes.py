"""
Advanced modules routes — WebRTC, Browser Fingerprint, Adversarial Training, DPI Fingerprint.

Endpoints:
  POST /api/detect/webrtc        — WebRTC leak detection
  POST /api/detect/fingerprint   — Browser fingerprint detection
  POST /api/detect/dpi           — DPI system fingerprinting
  POST /api/training/retrain     — Retrain ONNX model with attack results
  
  GET  /api/detect/webrtc/{target}
  GET  /api/detect/fingerprint/{target}
  GET  /api/detect/dpi/{target}
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from ..attacks.webrtc_leak import WebRTCLeakDetector
from ..attacks.browser_fingerprint import BrowserFingerprintDetector
from ..attacks.dpi_fingerprint import DPIFingerprinter
from ..training.adversarial_training import AdversarialTrainingPipeline


# ─── Pydantic Models ────────────────────────────────────────────────────

class RetrainRequest(BaseModel):
    model_path: str
    attack_results: List[Dict[str, Any]]
    epochs: int = 5
    learning_rate: float = 0.001


# ─── Route Registration ─────────────────────────────────────────────────

def register_advanced_routes(app: FastAPI):
    """Register all advanced module routes."""
    
    # ─── WebRTC Leak Detection ─────────────────────────────────────────
    
    @app.post("/api/detect/webrtc")
    async def detect_webrtc_leaks(target: str):
        """Detect WebRTC IP/DNS leaks."""
        detector = WebRTCLeakDetector(timeout=10.0)
        result = await detector.detect_leaks(target)
        return result.to_dict()
    
    @app.get("/api/detect/webrtc/{target}")
    async def detect_webrtc_leaks_get(target: str):
        """Detect WebRTC leaks (GET method)."""
        detector = WebRTCLeakDetector(timeout=10.0)
        result = await detector.detect_leaks(target)
        return result.to_dict()
    
    # ─── Browser Fingerprint Detection ─────────────────────────────────
    
    @app.post("/api/detect/fingerprint")
    async def detect_browser_fingerprint(target: str):
        """Detect browser fingerprinting attempts."""
        detector = BrowserFingerprintDetector(timeout=10.0)
        result = await detector.detect_fingerprinting(target)
        return result.to_dict()
    
    @app.get("/api/detect/fingerprint/{target}")
    async def detect_browser_fingerprint_get(target: str):
        """Detect browser fingerprinting (GET method)."""
        detector = BrowserFingerprintDetector(timeout=10.0)
        result = await detector.detect_fingerprinting(target)
        return result.to_dict()
    
    # ─── DPI Fingerprinting ────────────────────────────────────────────
    
    @app.post("/api/detect/dpi")
    async def detect_dpi_system(target: str):
        """Identify DPI system and recommend bypass strategies."""
        fingerprinter = DPIFingerprinter(timeout=10.0)
        result = await fingerprinter.fingerprint(target)
        return result.to_dict()
    
    @app.get("/api/detect/dpi/{target}")
    async def detect_dpi_system_get(target: str):
        """Identify DPI system (GET method)."""
        fingerprinter = DPIFingerprinter(timeout=10.0)
        result = await fingerprinter.fingerprint(target)
        return result.to_dict()
    
    # ─── Adversarial Training ──────────────────────────────────────────
    
    @app.post("/api/training/retrain")
    async def retrain_model(request: RetrainRequest):
        """Retrain ONNX model with adversarial examples from attack results."""
        try:
            pipeline = AdversarialTrainingPipeline(
                base_model_path=request.model_path,
                output_dir="retrained_models"
            )
            
            result = await pipeline.retrain_from_attacks(
                attack_results=request.attack_results,
                epochs=request.epochs,
                learning_rate=request.learning_rate,
            )
            
            return result.to_dict()
        
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")
