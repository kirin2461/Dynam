"""
Poller & Prometheus routes — extends the main FastAPI app.

Endpoints:
  POST   /api/poller/targets              — add/update target
  GET    /api/poller/targets              — list all targets
  GET    /api/poller/targets/{name}       — get target
  DELETE /api/poller/targets/{name}       — delete target
  POST   /api/poller/targets/{name}/run   — trigger manual run
  GET    /api/poller/targets/{name}/history — get run history
  GET    /api/poller/targets/{name}/trend   — get trend analysis
  POST   /api/poller/start                — start engine
  POST   /api/poller/stop                 — stop engine
  GET    /api/poller/status               — engine status
  
  GET    /metrics                         — Prometheus metrics
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from ..core.poller_engine import PollerEngine, PollerTarget, PollerRunResult
from ..core.prometheus_export import PrometheusExporter


# ─── Pydantic Models ────────────────────────────────────────────────────

class PollerTargetRequest(BaseModel):
    name: str
    url: str
    schedule_seconds: int = 21600  # 6 hours
    attacks: List[str] = Field(default_factory=lambda: ["ecs", "fragment", "adversarial_padding"])
    mode: str = "auto"
    iterations: int = 200
    intensity: int = 5
    min_stealth: float = 0.5
    notify: List[str] = Field(default_factory=list)
    paused: bool = False


# ─── Route Registration ─────────────────────────────────────────────────

def register_poller_routes(app: FastAPI, poller: PollerEngine, prometheus: PrometheusExporter):
    """Register all poller and prometheus routes on the app."""
    
    # ─── Target CRUD ───────────────────────────────────────────────────
    
    @app.post("/api/poller/targets")
    async def add_target(request: PollerTargetRequest):
        target = PollerTarget(
            name=request.name,
            url=request.url,
            schedule_seconds=request.schedule_seconds,
            attacks=request.attacks,
            mode=request.mode,
            iterations=request.iterations,
            intensity=request.intensity,
            min_stealth=request.min_stealth,
            notify=request.notify,
            paused=request.paused,
        )
        poller.add_target(target)
        return {"status": "added", "name": request.name}
    
    @app.get("/api/poller/targets")
    async def list_targets():
        targets = poller.get_all_targets()
        return {
            "targets": [
                {
                    "name": t.name,
                    "url": t.url,
                    "schedule_seconds": t.schedule_seconds,
                    "mode": t.mode,
                    "attacks": t.attacks,
                    "iterations": t.iterations,
                    "intensity": t.intensity,
                    "min_stealth": t.min_stealth,
                    "paused": t.paused,
                    "last_run": t.last_run,
                    "last_stealth": t.last_stealth,
                    "total_runs": t.total_runs,
                    "successful_runs": t.successful_runs,
                }
                for t in targets
            ]
        }
    
    @app.get("/api/poller/targets/{name}")
    async def get_target(name: str):
        target = poller.get_target(name)
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        return {
            "name": target.name,
            "url": target.url,
            "schedule_seconds": target.schedule_seconds,
            "mode": target.mode,
            "attacks": target.attacks,
            "iterations": target.iterations,
            "intensity": target.intensity,
            "min_stealth": target.min_stealth,
            "notify": target.notify,
            "paused": target.paused,
            "last_run": target.last_run,
            "last_stealth": target.last_stealth,
            "total_runs": target.total_runs,
            "successful_runs": target.successful_runs,
            "created_at": target.created_at,
        }
    
    @app.delete("/api/poller/targets/{name}")
    async def delete_target(name: str):
        poller.remove_target(name)
        return {"status": "deleted", "name": name}
    
    # ─── Run & History ─────────────────────────────────────────────────
    
    @app.post("/api/poller/targets/{name}/run")
    async def trigger_run(name: str):
        result = await poller.run_now(name)
        if result is None:
            raise HTTPException(status_code=404, detail="Target not found")
        return {"status": "triggered", "target": name}
    
    @app.get("/api/poller/targets/{name}/history")
    async def get_history(name: str, limit: int = 100):
        results = poller.get_history(name, limit)
        return {
            "target": name,
            "count": len(results),
            "runs": [r.to_dict() for r in results],
        }
    
    @app.get("/api/poller/targets/{name}/trend")
    async def get_trend(name: str, days: int = 30):
        trend = poller.get_trend(name, days)
        return {"target": name, "days": days, **trend}
    
    # ─── Engine Control ────────────────────────────────────────────────
    
    @app.post("/api/poller/start")
    async def start_engine():
        await poller.start()
        return {"status": "started"}
    
    @app.post("/api/poller/stop")
    async def stop_engine():
        await poller.stop()
        return {"status": "stopped"}
    
    @app.get("/api/poller/status")
    async def engine_status():
        return {
            "running": poller._running,
            "active_runs": list(poller._active_runs.keys()),
            "targets_count": len(poller.get_all_targets()),
        }
    
    # ─── Prometheus Metrics ────────────────────────────────────────────
    
    @app.get("/metrics")
    async def prometheus_metrics():
        """Prometheus text exposition format."""
        return PlainTextResponse(
            prometheus.generate(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )
