"""
Prometheus Export — exposes attack framework metrics in Prometheus text format.

Endpoint: GET /metrics

Metrics:
  dynam_campaigns_total{status}          — total campaigns by status
  dynam_attacks_total{type,status}       — total attacks by type and result
  dynam_stealth_score{target}            — latest stealth score per target
  dynam_detection_rate{target}           — latest detection rate per target  
  dynam_attack_latency_ms{type}          — avg latency per attack type
  dynam_poller_targets                   — number of poller targets
  dynam_poller_next_run{name}            — seconds until next run
  dynam_onnx_inferences_total            — total ONNX inferences
  dynam_onnx_detections_total            — total ONNX detections
  dynam_onnx_confidence                  — latest ONNX confidence score
"""

from typing import Dict, List, Any
from datetime import datetime

from .attack_manager import AttackManager
from .poller_engine import PollerEngine


class PrometheusExporter:
    """Generate Prometheus-compatible metrics text."""
    
    def __init__(self, attack_manager: AttackManager, poller: PollerEngine):
        self.manager = attack_manager
        self.poller = poller
        self._counters: Dict[str, float] = {}
    
    def increment(self, name: str, labels: Dict[str, str] = None, value: float = 1.0):
        """Increment a counter."""
        key = self._make_key(name, labels)
        self._counters[key] = self._counters.get(key, 0) + value
    
    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f'{name}{{{label_str}}}'
    
    def generate(self) -> str:
        """Generate Prometheus text exposition format."""
        lines = []
        
        # ─── Campaign metrics ──────────────────────────────────────────
        campaigns = self.manager.get_all_campaigns()
        status_counts = {}
        for p in campaigns.values():
            s = p.status.value
            status_counts[s] = status_counts.get(s, 0) + 1
        
        lines.append("# HELP dynam_campaigns_total Total attack campaigns by status")
        lines.append("# TYPE dynam_campaigns_total counter")
        for status, count in status_counts.items():
            lines.append(f'dynam_campaigns_total{{status="{status}"}} {count}')
        
        # ─── Attack metrics ────────────────────────────────────────────
        attack_type_counts = {}
        attack_stealth = {}
        attack_latency = {}
        
        for progress in campaigns.values():
            for r in progress.results:
                at = r.attack_type
                status = r.status.value
                
                key = (at, status)
                attack_type_counts[key] = attack_type_counts.get(key, 0) + 1
                
                if at not in attack_stealth:
                    attack_stealth[at] = []
                attack_stealth[at].append(r.stealth_score)
                
                if at not in attack_latency:
                    attack_latency[at] = []
                attack_latency[at].append(r.latency_ms)
        
        lines.append("")
        lines.append("# HELP dynam_attacks_total Total attacks by type and status")
        lines.append("# TYPE dynam_attacks_total counter")
        for (at, status), count in attack_type_counts.items():
            lines.append(f'dynam_attacks_total{{type="{at}",status="{status}"}} {count}')
        
        # ─── Stealth scores ────────────────────────────────────────────
        lines.append("")
        lines.append("# HELP dynam_stealth_score Latest stealth score per target")
        lines.append("# TYPE dynam_stealth_score gauge")
        for progress in campaigns.values():
            if progress.results:
                target = progress.results[-1].target
                stealth = progress.avg_stealth
                lines.append(f'dynam_stealth_score{{target="{target}"}} {stealth:.4f}')
        
        # ─── Detection rate ────────────────────────────────────────────
        lines.append("")
        lines.append("# HELP dynam_detection_rate Latest detection rate per target")
        lines.append("# TYPE dynam_detection_rate gauge")
        for progress in campaigns.values():
            if progress.results:
                target = progress.results[-1].target
                rate = progress.detection_rate
                lines.append(f'dynam_detection_rate{{target="{target}"}} {rate:.4f}')
        
        # ─── Attack latency ────────────────────────────────────────────
        lines.append("")
        lines.append("# HELP dynam_attack_latency_ms Average attack latency by type")
        lines.append("# TYPE dynam_attack_latency_ms gauge")
        for at, latencies in attack_latency.items():
            avg = sum(latencies) / len(latencies)
            lines.append(f'dynam_attack_latency_ms{{type="{at}"}} {avg:.1f}')
        
        # ─── Poller metrics ────────────────────────────────────────────
        targets = self.poller.get_all_targets()
        
        lines.append("")
        lines.append("# HELP dynam_poller_targets Number of scheduled poller targets")
        lines.append("# TYPE dynam_poller_targets gauge")
        lines.append(f'dynam_poller_targets {len(targets)}')
        
        lines.append("")
        lines.append("# HELP dynam_poller_last_stealth Last stealth score per poller target")
        lines.append("# TYPE dynam_poller_last_stealth gauge")
        for t in targets:
            lines.append(f'dynam_poller_last_stealth{{name="{t.name}"}} {t.last_stealth:.4f}')
        
        lines.append("")
        lines.append("# HELP dynam_poller_total_runs Total runs per poller target")
        lines.append("# TYPE dynam_poller_total_runs counter")
        for t in targets:
            lines.append(f'dynam_poller_total_runs{{name="{t.name}"}} {t.total_runs}')
        
        # ─── Trend metrics ─────────────────────────────────────────────
        lines.append("")
        lines.append("# HELP dynam_poller_trend Trend direction per target (1=improving, 0=stable, -1=degrading)")
        lines.append("# TYPE dynam_poller_trend gauge")
        for t in targets:
            trend = self.poller.get_trend(t.name, days=7)
            trend_val = 1 if trend.get("trend") == "improving" else (-1 if trend.get("trend") == "degrading" else 0)
            lines.append(f'dynam_poller_trend{{name="{t.name}"}} {trend_val}')
        
        # ─── Internal counters ─────────────────────────────────────────
        lines.append("")
        lines.append("# HELP dynam_internal_counters Internal framework counters")
        lines.append("# TYPE dynam_internal_counters counter")
        for key, value in self._counters.items():
            lines.append(f'dynam_internal_{key} {value}')
        
        return "\n".join(lines) + "\n"
