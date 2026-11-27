"""
FastAPI server for the Attack Testing Framework.

Provides REST API + WebSocket for real-time progress updates.
"""

import asyncio
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from ..core.attack_manager import AttackManager, CampaignConfig, CampaignMode
from ..core.base_attack import AttackResult
from ..core.poller_engine import PollerEngine
from ..core.prometheus_export import PrometheusExporter
from ..attacks.implementations import ATTACK_REGISTRY
from ..reports.report_generator import ReportGenerator
from .poller_routes import register_poller_routes
from .advanced_routes import register_advanced_routes
from .security_routes import register_security_routes
from .math_routes import register_math_routes
from .distributed_routes import register_distributed_routes


# ─── Pydantic Models ────────────────────────────────────────────────────

class StartCampaignRequest(BaseModel):
    target: str
    mode: str = "single"  # single, campaign, auto, stress
    attacks: List[str] = Field(default_factory=lambda: list(ATTACK_REGISTRY.keys()))
    iterations: int = 100
    intensity: int = 5
    duration_seconds: int = 0
    concurrent: int = 1
    auto_stop_rate: float = 0.0
    adaptive: bool = False
    params: Dict[str, Any] = Field(default_factory=dict)


class CampaignResponse(BaseModel):
    campaign_id: str
    status: str
    progress_percent: float
    total_iterations: int
    completed_iterations: int
    current_attack: str
    success_rate: float
    avg_stealth: float
    detection_rate: float
    results_count: int


# ─── App Setup ───────────────────────────────────────────────────────────

app = FastAPI(
    title="Dynam Attack Framework API",
    version="1.0.0",
    description="Automated attack testing for resilience evaluation",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = AttackManager()
poller = PollerEngine(manager, reports_dir="reports")
prometheus = PrometheusExporter(manager, poller)
report_gen = ReportGenerator(output_dir="reports")

# Register poller & prometheus routes
register_poller_routes(app, poller, prometheus)

# Register advanced modules routes (WebRTC, Fingerprint, DPI, Training)
register_advanced_routes(app)

# Register security detection routes (DNS leak, ESNI/ECH, WebSocket, Timing, CT, etc.)
register_security_routes(app)

# Register mathematical core routes (Fractal, Chaotic, Ergodic, Topological, etc.)
register_math_routes(app)

# Register distributed coordination routes (Invitation, Campaigns, Federated, Mesh Math)
# Note: requires mesh_network instance, which will be initialized separately
# register_distributed_routes(app, node_id="dynam-node-001", mesh_network=None)

# WebSocket connections for real-time updates
ws_connections: Dict[str, List[WebSocket]] = {}


# ─── Progress Callback ──────────────────────────────────────────────────

async def broadcast_progress(progress):
    """Broadcast progress to all WebSocket clients."""
    campaign_id = progress.campaign_id
    connections = ws_connections.get(campaign_id, [])
    
    message = json.dumps(progress.to_dict())
    
    dead = []
    for ws in connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    
    for ws in dead:
        connections.remove(ws)


manager.on_progress(broadcast_progress)


# ─── REST Endpoints ─────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.get("/api/attacks")
async def list_attacks():
    """List all available attack types."""
    return {
        "attacks": [
            {
                "id": attack_id,
                "name": cls().name,
                "description": cls().description,
                "category": cls().category,
            }
            for attack_id, cls in ATTACK_REGISTRY.items()
        ]
    }


@app.post("/api/campaigns/start")
async def start_campaign(request: StartCampaignRequest):
    """Start a new attack campaign."""
    config = CampaignConfig(
        name=f"campaign-{datetime.now().strftime('%H%M%S')}",
        target=request.target,
        mode=CampaignMode(request.mode),
        attacks=request.attacks,
        iterations=request.iterations,
        intensity=request.intensity,
        duration_seconds=request.duration_seconds,
        concurrent=request.concurrent,
        auto_stop_on_detection_rate=request.auto_stop_rate,
        adaptive=request.adaptive,
        params=request.params,
    )
    
    campaign_id = await manager.start_campaign(config)
    return {"campaign_id": campaign_id, "status": "started"}


@app.post("/api/campaigns/{campaign_id}/stop")
async def stop_campaign(campaign_id: str):
    """Stop a running campaign."""
    await manager.stop_campaign(campaign_id)
    return {"status": "stopped"}


@app.get("/api/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get campaign progress."""
    progress = manager.get_campaign(campaign_id)
    if not progress:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return progress.to_dict()


@app.get("/api/campaigns")
async def list_campaigns():
    """List all campaigns."""
    return {
        "campaigns": [
            p.to_dict() for p in manager.get_all_campaigns().values()
        ]
    }


@app.get("/api/campaigns/{campaign_id}/summary")
async def get_summary(campaign_id: str):
    """Get campaign summary."""
    summary = manager.get_summary(campaign_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return summary.to_dict()


@app.get("/api/campaigns/{campaign_id}/report/json")
async def get_json_report(campaign_id: str):
    """Generate JSON report."""
    progress = manager.get_campaign(campaign_id)
    summary = manager.get_summary(campaign_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    filepath = report_gen.generate_json_report(summary, progress.results)
    return FileResponse(filepath, media_type="application/json")


@app.get("/api/campaigns/{campaign_id}/report/html")
async def get_html_report(campaign_id: str):
    """Generate HTML report."""
    progress = manager.get_campaign(campaign_id)
    summary = manager.get_summary(campaign_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    filepath = report_gen.generate_html_report(summary, progress.results)
    return FileResponse(filepath, media_type="text/html")


# ─── WebSocket ───────────────────────────────────────────────────────────

@app.websocket("/ws/{campaign_id}")
async def websocket_endpoint(websocket: WebSocket, campaign_id: str):
    """WebSocket for real-time campaign progress."""
    await websocket.accept()
    
    if campaign_id not in ws_connections:
        ws_connections[campaign_id] = []
    ws_connections[campaign_id].append(websocket)
    
    try:
        # Send initial status
        progress = manager.get_campaign(campaign_id)
        if progress:
            await websocket.send_text(json.dumps(progress.to_dict()))
        
        # Keep connection alive
        while True:
            data = await websocket.receive_text()
            # Client can send commands here if needed
    except WebSocketDisconnect:
        ws_connections[campaign_id].remove(websocket)
    except Exception:
        if websocket in ws_connections.get(campaign_id, []):
            ws_connections[campaign_id].remove(websocket)


# ─── Run ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
