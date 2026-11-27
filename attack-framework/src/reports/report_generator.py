"""
Report Generator — creates detailed reports from attack campaigns.

Report types:
- JSON: Machine-readable full report
- HTML: Visual report with charts
- PDF: Printable report (via HTML → PDF)
- Summary: Quick overview for executives
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..core.attack_manager import CampaignSummary, CampaignProgress
from ..core.base_attack import AttackResult, AttackStatus


class ReportGenerator:
    """Generates reports from campaign results."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_json_report(self, summary: CampaignSummary, 
                            results: List[AttackResult]) -> str:
        """Generate a full JSON report."""
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_version": "1.0",
                "generator": "Dynam Attack Framework",
            },
            "campaign_summary": summary.to_dict(),
            "detailed_results": [r.to_dict() for r in results],
            "attack_breakdown": self._compute_attack_breakdown(results),
            "timeline": self._compute_timeline(results),
            "recommendations": self._generate_recommendations(summary, results),
        }
        
        filename = f"report_{summary.campaign_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(filepath)
    
    def generate_html_report(self, summary: CampaignSummary,
                            results: List[AttackResult]) -> str:
        """Generate an HTML report with charts."""
        
        # Compute stats
        attack_stats = self._compute_attack_breakdown(results)
        timeline = self._compute_timeline(results)
        recommendations = self._generate_recommendations(summary, results)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Testing Report — {summary.campaign_id}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', system-ui, sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 1.8rem; color: #89b4fa; margin-bottom: 0.5rem; }}
        h2 {{ font-size: 1.3rem; color: #89b4fa; margin: 1.5rem 0 1rem; border-bottom: 1px solid #313244; padding-bottom: 0.5rem; }}
        .subtitle {{ color: #a6adc8; font-size: 0.9rem; margin-bottom: 2rem; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: #313244; border-radius: 8px; padding: 1.2rem; }}
        .card-label {{ font-size: 0.8rem; color: #a6adc8; margin-bottom: 0.3rem; }}
        .card-value {{ font-size: 1.8rem; font-weight: bold; font-family: 'JetBrains Mono', monospace; }}
        .green {{ color: #a6e3a1; }}
        .red {{ color: #f38ba8; }}
        .yellow {{ color: #f9e2af; }}
        .blue {{ color: #89b4fa; }}
        .orange {{ color: #fab387; }}
        .chart-container {{ background: #313244; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ text-align: left; padding: 0.8rem; background: #181825; color: #a6adc8; font-size: 0.8rem; text-transform: uppercase; }}
        td {{ padding: 0.8rem; border-bottom: 1px solid #313244; font-size: 0.9rem; font-family: monospace; }}
        .recommendation {{ background: #313244; border-left: 3px solid #89b4fa; padding: 1rem; margin-bottom: 0.8rem; border-radius: 0 8px 8px 0; }}
        .rec-title {{ font-weight: bold; color: #89b4fa; margin-bottom: 0.3rem; }}
        .rec-severity {{ font-size: 0.75rem; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-bottom: 0.3rem; }}
        .severity-high {{ background: #f38ba830; color: #f38ba8; }}
        .severity-medium {{ background: #f9e2af30; color: #f9e2af; }}
        .severity-low {{ background: #a6e3a130; color: #a6e3a1; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
        .badge-success {{ background: #a6e3a130; color: #a6e3a1; }}
        .badge-danger {{ background: #f38ba830; color: #f38ba8; }}
        .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #313244; color: #585b70; font-size: 0.8rem; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Attack Testing Report</h1>
        <p class="subtitle">Campaign: {summary.campaign_id} | Target: {summary.target} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <!-- Summary Cards -->
        <div class="grid">
            <div class="card">
                <div class="card-label">Total Attacks</div>
                <div class="card-value blue">{summary.total_attacks}</div>
            </div>
            <div class="card">
                <div class="card-label">Successful (Undetected)</div>
                <div class="card-value green">{summary.successful}</div>
            </div>
            <div class="card">
                <div class="card-label">Detected</div>
                <div class="card-value red">{summary.detected}</div>
            </div>
            <div class="card">
                <div class="card-label">Success Rate</div>
                <div class="card-value {'green' if summary.success_rate > 0.7 else 'yellow' if summary.success_rate > 0.4 else 'red'}">{summary.success_rate*100:.1f}%</div>
            </div>
            <div class="card">
                <div class="card-label">Avg Stealth Score</div>
                <div class="card-value yellow">{summary.avg_stealth:.3f}</div>
            </div>
            <div class="card">
                <div class="card-label">Duration</div>
                <div class="card-value blue">{summary.duration_seconds:.1f}s</div>
            </div>
        </div>
        
        <!-- Attack Breakdown Chart -->
        <div class="chart-container">
            <h2>Attack Type Breakdown</h2>
            <canvas id="attackChart" height="80"></canvas>
        </div>
        
        <!-- Timeline Chart -->
        <div class="chart-container">
            <h2>Stealth Score Timeline</h2>
            <canvas id="timelineChart" height="80"></canvas>
        </div>
        
        <!-- Results Table -->
        <h2>Detailed Results (Last 50)</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Attack</th>
                    <th>Stealth</th>
                    <th>Detected</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Add last 50 results
        for r in results[-50:]:
            stealth_color = "green" if r.stealth_score > 0.7 else "yellow" if r.stealth_score > 0.4 else "red"
            detected_badge = '<span class="badge badge-danger">Yes</span>' if r.status == AttackStatus.DETECTED else '<span class="badge badge-success">No</span>'
            html += f"""
                <tr>
                    <td>{r.timestamp.strftime('%H:%M:%S')}</td>
                    <td>{r.attack_type}</td>
                    <td class="{stealth_color}">{r.stealth_score:.3f}</td>
                    <td>{detected_badge}</td>
                    <td>{r.latency_ms:.0f}ms</td>
                </tr>"""
        
        html += """
            </tbody>
        </table>
        
        <!-- Recommendations -->
        <h2>Recommendations</h2>
"""
        
        for rec in recommendations:
            severity_class = f"severity-{rec['severity']}"
            html += f"""
        <div class="recommendation">
            <span class="rec-severity {severity_class}">{rec['severity'].upper()}</span>
            <div class="rec-title">{rec['title']}</div>
            <p>{rec['description']}</p>
        </div>"""
        
        html += f"""
        <div class="footer">
            Generated by Dynam Attack Framework v1.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    
    <script>
        // Attack Breakdown Chart
        new Chart(document.getElementById('attackChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps([a['type'] for a in attack_stats])},
                datasets: [{{
                    label: 'Success Rate',
                    data: {json.dumps([a['success_rate'] for a in attack_stats])},
                    backgroundColor: '#89b4fa',
                }}, {{
                    label: 'Avg Stealth',
                    data: {json.dumps([a['avg_stealth'] for a in attack_stats])},
                    backgroundColor: '#f9e2af',
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ beginAtZero: true, max: 1 }}
                }},
                plugins: {{
                    legend: {{ labels: {{ color: '#cdd6f4' }} }}
                }}
            }}
        }});
        
        // Timeline Chart
        new Chart(document.getElementById('timelineChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps([t['index'] for t in timeline[:100]])},
                datasets: [{{
                    label: 'Stealth Score',
                    data: {json.dumps([t['stealth'] for t in timeline[:100]])},
                    borderColor: '#89b4fa',
                    backgroundColor: '#89b4fa20',
                    fill: true,
                    tension: 0.3,
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{ beginAtZero: true, max: 1, ticks: {{ color: '#a6adc8' }} }},
                    x: {{ ticks: {{ color: '#a6adc8' }} }}
                }},
                plugins: {{
                    legend: {{ labels: {{ color: '#cdd6f4' }} }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
        
        filename = f"report_{summary.campaign_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        
        return str(filepath)
    
    def _compute_attack_breakdown(self, results: List[AttackResult]) -> List[Dict]:
        """Compute per-attack-type statistics."""
        by_type: Dict[str, List[AttackResult]] = {}
        for r in results:
            by_type.setdefault(r.attack_type, []).append(r)
        
        breakdown = []
        for attack_type, type_results in by_type.items():
            total = len(type_results)
            successful = sum(1 for r in type_results if r.status == AttackStatus.SUCCESS)
            stealths = [r.stealth_score for r in type_results]
            
            breakdown.append({
                "type": attack_type,
                "total": total,
                "successful": successful,
                "success_rate": successful / total if total > 0 else 0,
                "avg_stealth": sum(stealths) / len(stealths) if stealths else 0,
                "min_stealth": min(stealths) if stealths else 0,
                "max_stealth": max(stealths) if stealths else 0,
            })
        
        return sorted(breakdown, key=lambda x: x["success_rate"], reverse=True)
    
    def _compute_timeline(self, results: List[AttackResult]) -> List[Dict]:
        """Compute stealth score timeline."""
        return [
            {"index": i, "stealth": r.stealth_score, "attack": r.attack_type}
            for i, r in enumerate(results)
        ]
    
    def _generate_recommendations(self, summary: CampaignSummary,
                                  results: List[AttackResult]) -> List[Dict]:
        """Generate actionable recommendations based on results."""
        recommendations = []
        
        # Check overall success rate
        if summary.success_rate > 0.8:
            recommendations.append({
                "severity": "high",
                "title": "High Attack Success Rate",
                "description": f"Attacks succeed {summary.success_rate*100:.1f}% of the time. "
                    "Consider implementing stronger DPI detection or ML-based traffic analysis.",
            })
        elif summary.success_rate < 0.3:
            recommendations.append({
                "severity": "low",
                "title": "Good Defense Posture",
                "description": f"Only {summary.success_rate*100:.1f}% of attacks succeed. "
                    "Your current defenses are effective against tested attack types.",
            })
        
        # Check per-attack weaknesses
        breakdown = self._compute_attack_breakdown(results)
        for attack in breakdown:
            if attack["success_rate"] > 0.7:
                recommendations.append({
                    "severity": "high",
                    "title": f"Weak Against {attack['type']}",
                    "description": f"{attack['type']} attacks succeed {attack['success_rate']*100:.1f}% of the time. "
                        f"Consider adding specific countermeasures for this attack type.",
                })
            elif attack["success_rate"] < 0.2 and attack["total"] > 10:
                recommendations.append({
                    "severity": "low",
                    "title": f"Strong Against {attack['type']}",
                    "description": f"Only {attack['success_rate']*100:.1f}% of {attack['type']} attacks succeed. "
                        "This defense vector is working well.",
                })
        
        # Stealth score analysis
        if summary.avg_stealth < 0.4:
            recommendations.append({
                "severity": "medium",
                "title": "Low Average Stealth",
                "description": f"Average stealth score is {summary.avg_stealth:.3f}. "
                    "Traffic patterns are distinguishable from normal traffic. "
                    "Consider implementing traffic normalization or mimicry.",
            })
        
        # Latency analysis
        avg_latency = sum(r.latency_ms for r in results) / len(results) if results else 0
        if avg_latency > 1000:
            recommendations.append({
                "severity": "medium",
                "title": "High Attack Latency",
                "description": f"Average attack latency is {avg_latency:.0f}ms. "
                    "This may impact user experience. Consider optimizing attack speed.",
            })
        
        return recommendations
