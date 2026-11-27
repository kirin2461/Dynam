import { useState, useEffect, useRef } from 'react';
import { Target, Play, StopCircle, Settings, FileText, Activity, Zap, Radio, Download, BarChart3 } from 'lucide-react';

const ATTACK_TYPES = [
  { id: 'ecs', name: 'ECS (DNS Subnet)', category: 'dns', desc: 'Spoof client subnet in DNS queries' },
  { id: 'fragment', name: 'Fragmentation', category: 'network', desc: 'Fragment packets to evade inspection' },
  { id: 'ttl', name: 'TTL Manipulation', category: 'network', desc: 'Modify TTL for cache poisoning' },
  { id: 'http', name: 'HTTP Obfuscation', category: 'web', desc: 'Obfuscate headers and payload' },
  { id: 'tls_split', name: 'TLS Split', category: 'tls', desc: 'Split TLS handshake across segments' },
  { id: 'rotation', name: 'Protocol Rotation', category: 'network', desc: 'Rotate through protocols' },
  { id: 'adversarial_padding', name: 'Adversarial Padding', category: 'ml', desc: 'Defeat ML classifiers (ET-BERT)' },
];

const CAMPAIGN_MODES = [
  { id: 'single', name: 'Single Attack', desc: 'Run one attack type', icon: Target },
  { id: 'campaign', name: 'Campaign', desc: 'Sequential multi-attack', icon: Activity },
  { id: 'auto', name: 'Auto-Adaptive', desc: 'AI selects best attacks', icon: Zap },
  { id: 'stress', name: 'Stress Test', desc: 'High-intensity concurrent', icon: Radio },
];

export default function AutoAttackPage() {
  
  // Campaign config
  const [target, setTarget] = useState('');
  const [mode, setMode] = useState('auto');
  const [selectedAttacks, setSelectedAttacks] = useState<string[]>(ATTACK_TYPES.map(a => a.id));
  const [iterations, setIterations] = useState(200);
  const [intensity, setIntensity] = useState(5);
  const [concurrent, setConcurrent] = useState(4);
  const [autoStopRate, setAutoStopRate] = useState(0);
  const [adaptive, setAdaptive] = useState(true);

  // Campaign state
  const [campaignId, setCampaignId] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('Idle');
  const [results, setResults] = useState<any[]>([]);
  
  // Stats
  const [totalAttacks, setTotalAttacks] = useState(0);
  const [successful, setSuccessful] = useState(0);
  const [detected, setDetected] = useState(0);
  const [avgStealth, setAvgStealth] = useState(0);
  const [successRate, setSuccessRate] = useState(0);
  const stealthHistory = useRef<number[]>([]);

  // Real progress: poll Flask /api/adversary/status while running
  useEffect(() => {
    if (!running) return;
    let stopped = false;
    const tick = async () => {
      if (stopped) return;
      try {
        const token = (document.querySelector('meta[name="ncp-token"]') as HTMLMetaElement | null)?.content;
        const res = await fetch('/api/adversary/status', {
          headers: { ...(token ? { 'X-NCP-Token': token } : {}) },
        });
        if (!res.ok) return;
        const st = await res.json();
        if (stopped) return;
        setProgress(st.progress ?? 0);
        setStatus(st.status === 'running' ? `Running… ${st.progress ?? 0}%` : (st.status || ''));
        if (st.status === 'done' && st.results) {
          const r = st.results;
          setTotalAttacks(r.total_attacks ?? 0);
          setSuccessful(r.successful ?? 0);
          setDetected(Math.max(0, (r.total_attacks ?? 0) - (r.successful ?? 0)));
          setAvgStealth(r.avg_stealth ?? 0);
          setSuccessRate(r.success_rate ?? 0);
          setResults(prev => [{
            time: new Date().toLocaleTimeString(),
            attack: `campaign ${st.results?.campaign_id || ''}`.trim(),
            stealth: r.avg_stealth ?? 0,
            detected: (r.detection_rate ?? 0) > 0.5,
            latency: 0,
          }, ...prev].slice(0, 200));
          setRunning(false);
          setStatus('Completed (real campaign)');
        } else if (st.status === 'unavailable') {
          setRunning(false);
          setStatus('Backend unavailable');
        }
      } catch { /* transient */ }
    };
    tick();
    const interval = setInterval(tick, 1200);
    return () => { stopped = true; clearInterval(interval); };
  }, [running]);

  const startCampaign = async () => {
    if (!target) return;
    
    setRunning(true);
    setProgress(0);
    setResults([]);
    setTotalAttacks(0);
    setSuccessful(0);
    setDetected(0);
    setAvgStealth(0);
    setSuccessRate(0);
    stealthHistory.current = [];
    setStatus('Starting...');
    setCampaignId(null);
    
    // In real mode: POST to /api/campaigns/start
    try {
      const token = (document.querySelector('meta[name="ncp-token"]') as HTMLMetaElement | null)?.content;
      const response = await fetch('/api/adversary/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(token ? { 'X-NCP-Token': token } : {}) },
        body: JSON.stringify({
          attack_type: 'combined',
          target,
          mode,
          attacks: selectedAttacks,
          iterations,
          intensity,
          concurrent,
          auto_stop_rate: autoStopRate,
          adaptive,
        }),
      }).catch(() => null);

      if (response?.ok) {
        const data = await response.json();
        setCampaignId(data.campaign_id || null);
      }
    } catch {
      // Demo mode — continue with simulated data
    }
  };

  const stopCampaign = async () => {
    setRunning(false);
    setStatus('Stopped');
  };

  const toggleAttack = (id: string) => {
    setSelectedAttacks(prev => 
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    );
  };

  const downloadReport = async (format: 'json' | 'html') => {
    if (!campaignId) return;
    window.open(`/api/af/campaigns/${campaignId}/report/${format}`, '_blank');
  };

  const maxChartPoints = 100;
  const chartData = stealthHistory.current.slice(-maxChartPoints);
  const chartWidth = 600;
  const chartHeight = 120;
  const chartPath = chartData.length > 1 
    ? chartData.map((v, i) => {
        const x = (i / (maxChartPoints - 1)) * chartWidth;
        const y = chartHeight - v * chartHeight;
        return `${i === 0 ? 'M' : 'L'}${x},${y}`;
      }).join(' ')
    : '';

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-base-100">Automated Attack Testing</h1>
          <p className="text-sm text-base-500">
            Test network/site resilience against adversarial attacks & ML-based detection
          </p>
        </div>
        {campaignId && (
          <div className="flex gap-2">
            <button onClick={() => downloadReport('html')} className="btn btn-secondary flex items-center gap-2" disabled={running || totalAttacks === 0}>
              <FileText className="w-4 h-4" /> HTML Report
            </button>
            <button onClick={() => downloadReport('json')} className="btn btn-secondary flex items-center gap-2" disabled={running || totalAttacks === 0}>
              <Download className="w-4 h-4" /> JSON
            </button>
          </div>
        )}
      </div>

      {/* ─── Configuration ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Target & Mode */}
        <div className="card">
          <div className="card-header"><h2 className="card-title flex items-center gap-2"><Target className="w-4 h-4" /> Target & Mode</h2></div>
          <div className="card-content space-y-4">
            <div>
              <label className="block text-sm text-base-400 mb-2">Target URL / Domain</label>
              <input className="input w-full" placeholder="https://target.example.com" value={target} onChange={e => setTarget(e.target.value)} disabled={running} />
            </div>
            <div>
              <label className="block text-sm text-base-400 mb-2">Campaign Mode</label>
              <div className="grid grid-cols-2 gap-2">
                {CAMPAIGN_MODES.map(m => (
                  <button key={m.id} onClick={() => setMode(m.id)} disabled={running}
                    className={`p-3 rounded-lg border text-left transition-all ${mode === m.id ? 'border-accent-blue bg-accent-blue/10' : 'border-base-600 hover:border-base-500'}`}>
                    <div className="flex items-center gap-2">
                      <m.icon className="w-4 h-4 text-accent-blue" />
                      <span className="text-sm font-semibold text-base-200">{m.name}</span>
                    </div>
                    <div className="text-xs text-base-500 mt-1">{m.desc}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Parameters */}
        <div className="card">
          <div className="card-header"><h2 className="card-title flex items-center gap-2"><Settings className="w-4 h-4" /> Parameters</h2></div>
          <div className="card-content space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-base-400 mb-2">Iterations</label>
                <input type="number" className="input w-full" min={1} max={10000} value={iterations} onChange={e => setIterations(parseInt(e.target.value))} disabled={running} />
              </div>
              <div>
                <label className="block text-sm text-base-400 mb-2">Intensity (1-10)</label>
                <input type="number" className="input w-full" min={1} max={10} value={intensity} onChange={e => setIntensity(parseInt(e.target.value))} disabled={running} />
              </div>
              <div>
                <label className="block text-sm text-base-400 mb-2">Concurrent</label>
                <input type="number" className="input w-full" min={1} max={20} value={concurrent} onChange={e => setConcurrent(parseInt(e.target.value))} disabled={running} />
              </div>
              <div>
                <label className="block text-sm text-base-400 mb-2">Auto-stop at detection %</label>
                <input type="number" className="input w-full" min={0} max={100} value={autoStopRate * 100} onChange={e => setAutoStopRate(parseInt(e.target.value) / 100)} disabled={running} />
              </div>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={adaptive} onChange={e => setAdaptive(e.target.checked)} disabled={running} className="w-4 h-4" />
              <span className="text-sm text-base-200">Adaptive attack selection (learn from results)</span>
            </label>
          </div>
        </div>
      </div>

      {/* ─── Attack Selection ─── */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <h2 className="card-title">Attack Types</h2>
          <div className="flex gap-2">
            <button onClick={() => setSelectedAttacks(ATTACK_TYPES.map(a => a.id))} className="text-xs text-accent-blue hover:underline" disabled={running}>Select All</button>
            <button onClick={() => setSelectedAttacks([])} className="text-xs text-accent-red hover:underline" disabled={running}>Clear</button>
          </div>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
            {ATTACK_TYPES.map(at => (
              <button key={at.id} onClick={() => toggleAttack(at.id)} disabled={running}
                className={`p-3 rounded-lg border text-left transition-all ${
                  selectedAttacks.includes(at.id) ? 'border-accent-green bg-accent-green/10' : 'border-base-600 opacity-50'
                }`}>
                <div className="text-xs font-semibold text-base-200">{at.name}</div>
                <div className="text-[10px] text-base-500 mt-1">{at.desc}</div>
                <div className="text-[10px] text-accent-blue mt-1">{at.category}</div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ─── Controls ─── */}
      <div className="flex gap-3">
        {!running ? (
          <button onClick={startCampaign} disabled={!target || selectedAttacks.length === 0}
            className="btn btn-primary flex items-center gap-2 px-8">
            <Play className="w-5 h-5" /> Start Auto-Attack Campaign
          </button>
        ) : (
          <button onClick={stopCampaign} className="btn btn-danger flex items-center gap-2 px-8">
            <StopCircle className="w-5 h-5" /> Stop Campaign
          </button>
        )}
        <div className="flex-1 flex items-center gap-4">
          <div className="flex-1 bg-surface-1 rounded-full h-3">
            <div className={`h-3 rounded-full transition-all duration-300 ${
              running ? 'bg-accent-blue' : progress >= 100 ? 'bg-accent-green' : 'bg-base-600'
            }`} style={{ width: `${progress}%` }} />
          </div>
          <span className="font-mono text-sm text-base-200 w-12">{Math.round(progress)}%</span>
        </div>
        <span className="text-sm text-base-400">{status}</span>
      </div>

      {/* ─── Stats ─── */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="card p-4">
          <div className="text-xs text-base-500">Total Attacks</div>
          <div className="text-2xl font-bold font-mono text-accent-blue">{totalAttacks}</div>
        </div>
        <div className="card p-4 border-accent-green/30">
          <div className="text-xs text-base-500">Successful</div>
          <div className="text-2xl font-bold font-mono text-accent-green">{successful}</div>
        </div>
        <div className="card p-4 border-accent-red/30">
          <div className="text-xs text-base-500">Detected</div>
          <div className="text-2xl font-bold font-mono text-accent-red">{detected}</div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-base-500">Avg Stealth</div>
          <div className={`text-2xl font-bold font-mono ${avgStealth > 0.6 ? 'text-accent-green' : avgStealth > 0.3 ? 'text-accent-yellow' : 'text-accent-red'}`}>
            {avgStealth.toFixed(3)}
          </div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-base-500">Success Rate</div>
          <div className={`text-2xl font-bold font-mono ${successRate > 0.7 ? 'text-accent-green' : successRate > 0.4 ? 'text-accent-yellow' : 'text-accent-red'}`}>
            {(successRate * 100).toFixed(1)}%
          </div>
        </div>
      </div>

      {/* ─── Stealth Chart ─── */}
      {chartData.length > 1 && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title flex items-center gap-2"><BarChart3 className="w-4 h-4" /> Stealth Score Timeline</h2>
          </div>
          <div className="card-content">
            <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} className="w-full" style={{ height: 140 }}>
              {/* Detection threshold line */}
              <line x1="0" y1={chartHeight * 0.4} x2={chartWidth} y2={chartHeight * 0.4} stroke="#f38ba8" strokeWidth="1" strokeDasharray="4,4" opacity="0.5" />
              <text x={chartWidth - 60} y={chartHeight * 0.4 - 4} fill="#f38ba8" fontSize="10">Detection threshold</text>
              {/* Stealth line */}
              <path d={chartPath} fill="none" stroke="#89b4fa" strokeWidth="2" />
              <path d={chartPath + ` L${chartWidth},${chartHeight} L0,${chartHeight} Z`} fill="#89b4fa" opacity="0.1" />
            </svg>
          </div>
        </div>
      )}

      {/* ─── Results Table ─── */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title flex items-center gap-2"><Activity className="w-4 h-4" /> Attack Results</h2>
        </div>
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full">
            <thead className="bg-surface-1 border-b border-base-700 sticky top-0">
              <tr>
                <th className="text-left px-4 py-2 text-xs text-base-500">Time</th>
                <th className="text-left px-4 py-2 text-xs text-base-500">Attack</th>
                <th className="text-right px-4 py-2 text-xs text-base-500">Stealth</th>
                <th className="text-center px-4 py-2 text-xs text-base-500">Detected</th>
                <th className="text-right px-4 py-2 text-xs text-base-500">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {results.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-base-500">Start a campaign to see results</td></tr>
              ) : results.map((r, i) => (
                <tr key={i} className="hover:bg-surface-1 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs text-base-400">{r.time}</td>
                  <td className="px-4 py-2 text-sm text-base-200">{r.attack}</td>
                  <td className={`px-4 py-2 text-right font-mono text-sm font-bold ${
                    r.stealth > 0.7 ? 'text-accent-green' : r.stealth > 0.4 ? 'text-accent-yellow' : 'text-accent-red'
                  }`}>{r.stealth.toFixed(3)}</td>
                  <td className="px-4 py-2 text-center">
                    {r.detected ? <span className="badge badge-danger">Yes</span> : <span className="badge badge-success">No</span>}
                  </td>
                  <td className="px-4 py-2 text-right font-mono text-xs text-base-400">{r.latency?.toFixed(0)}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
