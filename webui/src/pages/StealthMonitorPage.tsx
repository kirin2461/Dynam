import { useState, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useWebSocket } from '@/hooks/useWebSocket';
import { Activity, Shield, ShieldAlert, Zap, Clock, BarChart3, Play } from 'lucide-react';

// ═══════ Types matching C++ HeuristicScores ═══════
interface HeuristicScores {
  entropy_score: number;        // 0-1, higher=better
  chi_squared_pvalue: number;   // >0.05 = passes, <0.01 = detected
  ks_distance: number;          // <0.1 = good, >0.3 = poor
  w1_distance: number;          // Wasserstein-1 in bytes
  size_variance_ratio: number;  // ~1.0 = good
  timing_cov: number;           // coefficient of variation
  burst_anomaly: number;        // 0-1, lower=better
  aggregate_stealth: number;    // weighted sum → 0-1
}

interface TestReport {
  timestamp: string;
  strategy: string;
  stealth: number;
  detected: boolean;
  entropy: number;
  chi2: number;
  learned_probability: number;
}

// ═══════ Metric Card ═══════
function MetricCard({ name, value, weight, good, threshold, unit }: {
  name: string;
  value: number;
  weight: number;
  good: boolean;
  threshold: string;
  unit?: string;
}) {
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 mb-2">
        <div className={`w-3 h-3 rounded-full ${good ? 'bg-accent-green' : 'bg-accent-red'}`} />
        <span className="text-xs text-base-500">{name}</span>
        <span className="ml-auto text-[10px] text-base-600 font-mono">w={weight}</span>
      </div>
      <div className="text-xl font-bold font-mono text-base-100">
        {value.toFixed(3)}{unit && <span className="text-xs text-base-500 ml-1">{unit}</span>}
      </div>
      <div className="text-[10px] text-base-600 mt-1">{threshold}</div>
    </div>
  );
}

// ═══════ Sparkline ═══════
function Sparkline({ data, height = 40 }: { data: number[]; height?: number }) {
  if (data.length < 2) return null;
  
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;
  
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * 100;
    const y = height - ((v - min) / range) * height;
    return `${x},${y}`;
  }).join(' ');

  const lastVal = data[data.length - 1];
  const color = lastVal > 0.7 ? '#a6e3a1' : lastVal > 0.5 ? '#f9e2af' : lastVal > 0.3 ? '#fab387' : '#f38ba8';

  return (
    <svg viewBox={`0 0 100 ${height}`} className="w-full" style={{ height }} preserveAspectRatio="none">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="2"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

// ═══════ Main Page ═══════
export default function StealthMonitorPage() {
  const { t } = useTranslation();
  const { connected } = useWebSocket();

  const [scores, setScores] = useState<HeuristicScores | null>(null);
  const [windowPackets, setWindowPackets] = useState({ collected: 0, total: 50 });
  const [learnedProb, setLearnedProb] = useState(-1);
  const [currentStrategy] = useState('Adaptive');
  const [history, setHistory] = useState<number[]>([]);
  const [reports, setReports] = useState<TestReport[]>([]);
  const [referenceProfile, setReferenceProfile] = useState('web_browsing');
  const [benchmarkRunning, setBenchmarkRunning] = useState(false);
  const [benchmarkResult, setBenchmarkResult] = useState<string | null>(null);

  // Stats
  const stats = useMemo(() => {
    if (history.length === 0) return { avg: 0, min: 1, max: 0, last: 0 };
    const sum = history.reduce((a, b) => a + b, 0);
    return {
      avg: sum / history.length,
      min: Math.min(...history),
      max: Math.max(...history),
      last: history[history.length - 1],
    };
  }, [history]);

  // Simulate incoming data (in real app, this comes from WebSocket)
  useEffect(() => {
    const interval = setInterval(() => {
      if (!connected) return;
      
      // Simulate metric updates
      const entropy = 0.7 + Math.random() * 0.25;
      const chi2 = 0.05 + Math.random() * 0.4;
      const ks = 0.05 + Math.random() * 0.15;
      const w1 = 20 + Math.random() * 60;
      const sizeVar = 0.8 + Math.random() * 0.4;
      const timing = 0.5 + Math.random() * 1.5;
      const burst = Math.random() * 0.5;
      
      // Compute aggregate (matching C++ weights)
      const e = entropy;
      const c = Math.min(1, chi2);
      const k = 1 - Math.min(1, ks);
      const w = 1 / (1 + Math.abs(w1) / 75);
      const s = 1 / (1 + Math.abs(sizeVar - 1));
      const tc = 1 / (1 + Math.abs(timing));
      const b = 1 - Math.min(1, burst);
      
      const stealth = 0.25*e + 0.25*c + 0.10*k + 0.05*w + 0.10*s + 0.15*tc + 0.10*b;
      const detected = stealth < 0.5;

      setScores({
        entropy_score: entropy,
        chi_squared_pvalue: chi2,
        ks_distance: ks,
        w1_distance: w1,
        size_variance_ratio: sizeVar,
        timing_cov: timing,
        burst_anomaly: burst,
        aggregate_stealth: stealth,
      });

      setWindowPackets(prev => {
        const next = prev.collected + Math.floor(Math.random() * 3) + 1;
        if (next >= prev.total) return { collected: 0, total: prev.total };
        return { collected: next, total: prev.total };
      });

      setLearnedProb(Math.random() * 0.6);
      
      setHistory(prev => [...prev.slice(-99), stealth]);
      
      if (Math.random() < 0.3) {
        setReports(prev => [
          {
            timestamp: new Date().toISOString(),
            strategy: currentStrategy,
            stealth,
            detected,
            entropy,
            chi2,
            learned_probability: Math.random() * 0.6,
          },
          ...prev.slice(0, 49),
        ]);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [connected, currentStrategy]);

  const stealth = scores?.aggregate_stealth ?? 0;
  const detected = stealth < 0.5;
  const stealthColor = stealth > 0.7 ? 'text-accent-green' : 
                       stealth > 0.5 ? 'text-accent-yellow' :
                       stealth > 0.3 ? 'text-accent-orange' : 'text-accent-red';

  const gaugeColor = stealth > 0.7 ? 'bg-accent-green' :
                     stealth > 0.5 ? 'bg-accent-yellow' :
                     stealth > 0.3 ? 'bg-accent-orange' : 'bg-accent-red';

  return (
    <div className="p-8 animate-fade-in space-y-6">
      {/* ═══ Header ═══ */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-base-100">
            {t('stealth.title', 'Shadow Classifier — Stealth Monitor')}
          </h1>
          <p className="text-sm text-base-500 mt-1">
            {t('stealth.subtitle', 'Real-time stealth evaluation of obfuscated traffic')}
          </p>
        </div>
        <div className="flex items-center gap-4">
          <select
            className="input"
            value={referenceProfile}
            onChange={e => setReferenceProfile(e.target.value)}
          >
            <option value="web_browsing">Web Browsing</option>
            <option value="video_stream">Video Stream</option>
            <option value="messenger">Messenger</option>
            <option value="gaming">Gaming</option>
            <option value="file_download">File Download</option>
          </select>
        </div>
      </div>

      {/* ═══ Row 1: Gauge + Status + Window ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Stealth Gauge */}
        <div className="card lg:col-span-1">
          <div className="card-content text-center">
            <div className="text-sm text-base-500 mb-2">
              {t('stealth.aggregate', 'Aggregate Stealth Score')}
            </div>
            <div className={`text-5xl font-bold font-mono ${stealthColor}`}>
              {stealth.toFixed(3)}
            </div>
            <div className="mt-4">
              <div className="w-full bg-surface-1 rounded-full h-3">
                <div
                  className={`${gaugeColor} h-3 rounded-full transition-all duration-500`}
                  style={{ width: `${stealth * 100}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-base-600 mt-1">
                <span>DETECTED</span>
                <span>UNDETECTED</span>
              </div>
            </div>
          </div>
        </div>

        {/* Detection Status */}
        <div className="card">
          <div className="card-content">
            <div className="text-sm text-base-500 mb-4">
              {t('stealth.detection', 'Detection Status')}
            </div>
            <div className="flex items-center gap-3 mb-4">
              {detected ? (
                <>
                  <ShieldAlert className="w-8 h-8 text-accent-red" />
                  <span className="text-2xl font-bold text-accent-red">
                    {t('stealth.detected', 'DETECTED')}
                  </span>
                </>
              ) : (
                <>
                  <Shield className="w-8 h-8 text-accent-green" />
                  <span className="text-2xl font-bold text-accent-green">
                    {t('stealth.undetected', 'UNDETECTED')}
                  </span>
                </>
              )}
            </div>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-base-500">SizeErrorLearner P(detected):</span>
                <span className={`font-mono font-bold ${learnedProb > 0.5 ? 'text-accent-red' : 'text-accent-green'}`}>
                  {learnedProb >= 0 ? (learnedProb * 100).toFixed(1) + '%' : '—'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-base-500">Threshold:</span>
                <span className="font-mono text-base-300">0.50</span>
              </div>
            </div>
          </div>
        </div>

        {/* Flow Window */}
        <div className="card">
          <div className="card-content">
            <div className="text-sm text-base-500 mb-4">
              {t('stealth.window', 'Flow Window')}
            </div>
            <div className="text-lg font-mono text-base-200 mb-2">
              {windowPackets.collected} / {windowPackets.total} packets
            </div>
            <div className="w-full bg-surface-1 rounded-full h-2 mb-4">
              <div
                className="bg-accent-blue h-2 rounded-full transition-all"
                style={{ width: `${(windowPackets.collected / windowPackets.total) * 100}%` }}
              />
            </div>
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-accent-blue" />
              <span className="text-sm font-bold text-accent-blue">
                Strategy: {currentStrategy}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ═══ Row 2: 7 Metric Cards ═══ */}
      <div>
        <h2 className="text-sm font-semibold text-base-400 mb-3">
          Heuristic Metrics (Weighted → Stealth)
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          {scores && (
            <>
              <MetricCard
                name="Entropy"
                value={scores.entropy_score}
                weight={0.25}
                good={scores.entropy_score > 0.7}
                threshold=">0.7 = random-like"
              />
              <MetricCard
                name="Chi² p-value"
                value={scores.chi_squared_pvalue}
                weight={0.25}
                good={scores.chi_squared_pvalue > 0.05}
                threshold=">0.05 = passes"
              />
              <MetricCard
                name="KS Distance"
                value={scores.ks_distance}
                weight={0.10}
                good={scores.ks_distance < 0.1}
                threshold="<0.1 = good mimicry"
              />
              <MetricCard
                name="Wasserstein-1"
                value={scores.w1_distance}
                weight={0.05}
                good={scores.w1_distance < 75}
                threshold="<75B displacement"
                unit="B"
              />
              <MetricCard
                name="Size Var Ratio"
                value={scores.size_variance_ratio}
                weight={0.10}
                good={Math.abs(scores.size_variance_ratio - 1) < 0.3}
                threshold="~1.0 = matches ref"
              />
              <MetricCard
                name="Timing CoV"
                value={scores.timing_cov}
                weight={0.15}
                good={scores.timing_cov < 1.0}
                threshold="close to ref"
              />
              <MetricCard
                name="Burst Anomaly"
                value={scores.burst_anomaly}
                weight={0.10}
                good={scores.burst_anomaly < 0.3}
                threshold="<0.3 = normal"
              />
            </>
          )}
        </div>
      </div>

      {/* ═══ Row 3: History + Benchmark ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Stealth History */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              {t('stealth.history', 'Stealth History')}
            </h3>
          </div>
          <div className="card-content">
            <div className="grid grid-cols-4 gap-4 mb-4">
              <div>
                <div className="text-xs text-base-500">Last</div>
                <div className={`font-mono font-bold ${stealthColor}`}>
                  {stats.last.toFixed(3)}
                </div>
              </div>
              <div>
                <div className="text-xs text-base-500">Average</div>
                <div className="font-mono font-bold text-base-200">
                  {stats.avg.toFixed(3)}
                </div>
              </div>
              <div>
                <div className="text-xs text-base-500">Min</div>
                <div className="font-mono font-bold text-accent-red">
                  {stats.min.toFixed(3)}
                </div>
              </div>
              <div>
                <div className="text-xs text-base-500">Max</div>
                <div className="font-mono font-bold text-accent-green">
                  {stats.max.toFixed(3)}
                </div>
              </div>
            </div>
            <Sparkline data={history} height={60} />
          </div>
        </div>

        {/* Strategy Benchmark */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title flex items-center gap-2">
              <Zap className="w-4 h-4" />
              {t('stealth.benchmark', 'Strategy Benchmark')}
            </h3>
          </div>
          <div className="card-content">
            <div className="flex gap-3 mb-4">
              <select className="input flex-1" disabled={benchmarkRunning}>
                <option value="random">Random (baseline ~60%)</option>
                <option value="http_mimic">HTTP Mimic</option>
                <option value="tls_mimic">TLS Mimic</option>
                <option value="quic_mimic">QUIC Mimic</option>
                <option value="dns_mimic">DNS Mimic</option>
                <option value="adaptive">Adaptive (best)</option>
              </select>
              <button
                className="btn btn-primary flex items-center gap-2"
                disabled={benchmarkRunning}
                onClick={() => {
                  setBenchmarkRunning(true);
                  setTimeout(() => {
                    setBenchmarkRunning(false);
                    setBenchmarkResult(
                      `200 samples → avg stealth: ${(0.65 + Math.random() * 0.25).toFixed(3)}, ` +
                      `detection: ${(Math.random() * 30).toFixed(1)}%`
                    );
                  }, 3000);
                }}
              >
                <Play className="w-4 h-4" />
                {benchmarkRunning ? '...' : 'Run (200 samples)'}
              </button>
            </div>
            {benchmarkResult && (
              <div className="text-sm font-mono text-accent-blue p-3 bg-accent-blue/10 rounded-lg">
                {benchmarkResult}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ═══ Row 4: TestReport Table ═══ */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title flex items-center gap-2">
            <Clock className="w-4 h-4" />
            {t('stealth.reports', 'Evaluation History (TestReports)')}
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-surface-1 border-b border-base-700">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-medium text-base-500">Time</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-base-500">Strategy</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-base-500">Stealth</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-base-500">Detected</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-base-500">Entropy</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-base-500">Chi²</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-base-500">P(learned)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-base-500">
                    No evaluations yet
                  </td>
                </tr>
              ) : (
                reports.map((r, i) => (
                  <tr key={i} className="hover:bg-surface-1 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-base-400">
                      {new Date(r.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className="badge badge-info text-xs">{r.strategy}</span>
                    </td>
                    <td className={`px-4 py-3 text-right font-mono text-sm font-bold ${
                      r.stealth > 0.7 ? 'text-accent-green' :
                      r.stealth > 0.5 ? 'text-accent-yellow' : 'text-accent-red'
                    }`}>
                      {r.stealth.toFixed(3)}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {r.detected ? (
                        <span className="badge badge-danger">✗ YES</span>
                      ) : (
                        <span className="badge badge-success">✓ NO</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-base-300">
                      {r.entropy.toFixed(3)}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-base-300">
                      {r.chi2.toFixed(4)}
                    </td>
                    <td className="px-4 py-3 text-right font-mono text-xs text-base-300">
                      {r.learned_probability >= 0
                        ? (r.learned_probability * 100).toFixed(1) + '%'
                        : '—'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
