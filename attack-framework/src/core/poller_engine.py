"""
Poller Engine — scheduled automated attack testing.

Continuous security assurance: run attack campaigns on schedule,
track trends, alert on degradation.

Targets:
- name: human-readable label
- url: target URL/domain
- schedule: cron-like interval (every 6h, daily, weekly)
- attacks: list of attack types to run
- mode: campaign mode (single/campaign/auto/stress)
- min_stealth: alert if stealth drops below this
- notify: list of notification channels

History:
- Each run produces a CampaignSummary
- Stored in SQLite for trend analysis
- Trend API: /api/poller/history/{target_name}
"""

import asyncio
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from pathlib import Path
from enum import Enum


class PollerStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class PollerTarget:
    """A scheduled attack testing target."""
    name: str
    url: str
    schedule_seconds: int = 21600          # default: every 6 hours
    attacks: List[str] = field(default_factory=lambda: ["ecs", "fragment", "adversarial_padding"])
    mode: str = "auto"
    iterations: int = 200
    intensity: int = 5
    min_stealth: float = 0.5              # alert threshold
    notify: List[str] = field(default_factory=list)  # ["telegram", "email", "webhook"]
    paused: bool = False
    last_run: Optional[str] = None        # ISO timestamp
    last_stealth: float = 0.0
    total_runs: int = 0
    successful_runs: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class PollerRunResult:
    """Result of a single poller run."""
    target_name: str
    campaign_id: str
    timestamp: str
    stealth_score: float
    success_rate: float
    detection_rate: float
    total_attacks: int
    duration_seconds: float
    status: str  # completed, failed, timeout
    alert_triggered: bool = False
    alert_reason: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PollerDatabase:
    """SQLite storage for poller targets and run history."""
    
    def __init__(self, db_path: str = "poller.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                name TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
        """)
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                data TEXT NOT NULL
            )
        """)
        
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_runs_target 
            ON runs(target_name, timestamp)
        """)
        
        conn.commit()
        conn.close()
    
    def save_target(self, target: PollerTarget):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO targets (name, data) VALUES (?, ?)",
            (target.name, json.dumps(asdict(target)))
        )
        conn.commit()
        conn.close()
    
    def get_target(self, name: str) -> Optional[PollerTarget]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT data FROM targets WHERE name = ?", (name,))
        row = c.fetchone()
        conn.close()
        if row:
            return PollerTarget(**json.loads(row[0]))
        return None
    
    def get_all_targets(self) -> List[PollerTarget]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT data FROM targets")
        targets = [PollerTarget(**json.loads(row[0])) for row in c.fetchall()]
        conn.close()
        return targets
    
    def delete_target(self, name: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM targets WHERE name = ?", (name,))
        c.execute("DELETE FROM runs WHERE target_name = ?", (name,))
        conn.commit()
        conn.close()
    
    def save_run(self, result: PollerRunResult):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT INTO runs (target_name, timestamp, data) VALUES (?, ?, ?)",
            (result.target_name, result.timestamp, json.dumps(result.to_dict()))
        )
        conn.commit()
        conn.close()
    
    def get_history(self, target_name: str, limit: int = 100) -> List[PollerRunResult]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT data FROM runs WHERE target_name = ? ORDER BY timestamp DESC LIMIT ?",
            (target_name, limit)
        )
        results = [PollerRunResult(**json.loads(row[0])) for row in c.fetchall()]
        conn.close()
        return results
    
    def get_trend(self, target_name: str, days: int = 30) -> Dict[str, Any]:
        """Compute trend analysis for the last N days."""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        since = (datetime.now() - timedelta(days=days)).isoformat()
        c.execute(
            "SELECT data FROM runs WHERE target_name = ? AND timestamp > ? ORDER BY timestamp",
            (target_name, since)
        )
        rows = c.fetchall()
        conn.close()
        
        if not rows:
            return {"trend": "no_data", "points": 0}
        
        stealths = []
        for row in rows:
            r = json.loads(row[0])
            stealths.append(r["stealth_score"])
        
        avg = sum(stealths) / len(stealths)
        
        # Simple linear trend
        if len(stealths) >= 2:
            first_half = sum(stealths[:len(stealths)//2]) / (len(stealths)//2)
            second_half = sum(stealths[len(stealths)//2:]) / (len(stealths) - len(stealths)//2)
            diff = second_half - first_half
            
            if diff > 0.05:
                trend = "improving"
            elif diff < -0.05:
                trend = "degrading"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "trend": trend,
            "points": len(stealths),
            "avg_stealth": avg,
            "min_stealth": min(stealths),
            "max_stealth": max(stealths),
            "first_stealth": stealths[0],
            "last_stealth": stealths[-1],
            "delta": stealths[-1] - stealths[0],
        }


class PollerEngine:
    """
    Orchestrates scheduled attack testing.
    
    Runs attack campaigns on schedule, stores results,
    detects degradation, triggers alerts.
    """
    
    def __init__(self, manager, reports_dir: str = "reports"):
        self.manager = manager
        self.reports_dir = reports_dir
        self.db = PollerDatabase("poller.db")
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._active_runs: Dict[str, str] = {}  # target_name -> campaign_id
        self._alert_callbacks: List = []
    
    def on_alert(self, callback):
        """Register alert callback: callback(target_name, reason, result)."""
        self._alert_callbacks.append(callback)
    
    async def _notify_alert(self, target_name: str, reason: str, result: PollerRunResult):
        for cb in self._alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(target_name, reason, result)
                else:
                    cb(target_name, reason, result)
            except Exception:
                pass
    
    def add_target(self, target: PollerTarget):
        """Add or update a polling target."""
        self.db.save_target(target)
    
    def remove_target(self, name: str):
        """Remove a polling target."""
        self.db.delete_target(name)
    
    def get_target(self, name: str) -> Optional[PollerTarget]:
        return self.db.get_target(name)
    
    def get_all_targets(self) -> List[PollerTarget]:
        return self.db.get_all_targets()
    
    def get_history(self, target_name: str, limit: int = 100) -> List[PollerRunResult]:
        return self.db.get_history(target_name, limit)
    
    def get_trend(self, target_name: str, days: int = 30) -> Dict[str, Any]:
        return self.db.get_trend(target_name, days)
    
    async def start(self):
        """Start the poller engine loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
    
    async def stop(self):
        """Stop the poller engine."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
    
    async def _poll_loop(self):
        """Main polling loop — checks targets every 60 seconds."""
        while self._running:
            try:
                targets = self.db.get_all_targets()
                now = datetime.now()
                
                for target in targets:
                    if target.paused:
                        continue
                    
                    # Check if it's time to run
                    if target.last_run:
                        last = datetime.fromisoformat(target.last_run)
                        next_run = last + timedelta(seconds=target.schedule_seconds)
                        if now < next_run:
                            continue
                    
                    # Check if already running
                    if target.name in self._active_runs:
                        continue
                    
                    # Run the campaign
                    asyncio.create_task(self._run_target(target))
                
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                await asyncio.sleep(60)
    
    async def _run_target(self, target: PollerTarget):
        """Execute an attack campaign for a target."""
        campaign_id = f"poller-{target.name}-{int(datetime.now().timestamp())}"
        self._active_runs[target.name] = campaign_id
        
        try:
            from .attack_manager import CampaignConfig, CampaignMode
            
            config = CampaignConfig(
                name=campaign_id,
                target=target.url,
                mode=CampaignMode(target.mode),
                attacks=target.attacks,
                iterations=target.iterations,
                intensity=target.intensity,
            )
            
            cid = await self.manager.start_campaign(config)
            
            # Wait for completion
            while True:
                progress = self.manager.get_campaign(cid)
                if progress and progress.status.value in ("completed", "stopped", "error"):
                    break
                await asyncio.sleep(1)
            
            summary = self.manager.get_summary(cid)
            progress = self.manager.get_campaign(cid)
            
            if summary:
                result = PollerRunResult(
                    target_name=target.name,
                    campaign_id=cid,
                    timestamp=datetime.now().isoformat(),
                    stealth_score=summary.avg_stealth,
                    success_rate=summary.success_rate,
                    detection_rate=1.0 - summary.success_rate,
                    total_attacks=summary.total_attacks,
                    duration_seconds=summary.duration_seconds,
                    status=summary.status,
                )
                
                # Check if alert needed
                if result.stealth_score < target.min_stealth:
                    result.alert_triggered = True
                    result.alert_reason = f"Stealth {result.stealth_score:.3f} < threshold {target.min_stealth}"
                    await self._notify_alert(target.name, result.alert_reason, result)
                
                # Save result
                self.db.save_run(result)
                
                # Update target stats
                target.last_run = result.timestamp
                target.last_stealth = result.stealth_score
                target.total_runs += 1
                if result.status == "completed":
                    target.successful_runs += 1
                self.db.save_target(target)
            
        except Exception as e:
            result = PollerRunResult(
                target_name=target.name,
                campaign_id=campaign_id,
                timestamp=datetime.now().isoformat(),
                stealth_score=0.0,
                success_rate=0.0,
                detection_rate=1.0,
                total_attacks=0,
                duration_seconds=0.0,
                status="error",
                alert_reason=str(e),
            )
            self.db.save_run(result)
        
        finally:
            self._active_runs.pop(target.name, None)
    
    async def run_now(self, target_name: str) -> Optional[str]:
        """Manually trigger a run for a specific target."""
        target = self.db.get_target(target_name)
        if not target:
            return None
        
        task = asyncio.create_task(self._run_target(target))
        return target.name
