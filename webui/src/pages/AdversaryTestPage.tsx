import { useState } from 'react';
import { adversaryApi } from '@/services/api';
import { Target, Play, StopCircle, TrendingUp, Shield, AlertTriangle } from 'lucide-react';

const ATTACK_TYPES = [
  { id: 'ecs', name: 'ECS (EDNS Client Subnet)', desc: 'Inject client subnet into DNS queries' },
  { id: 'fragment', name: 'Fragmentation Attack', desc: 'Fragment packets to evade inspection' },
  { id: 'ttl', name: 'TTL Manipulation', desc: 'Modify TTL to cause cache poisoning' },
  { id: 'http', name: 'HTTP Obfuscation', desc: 'Obfuscate HTTP headers and payload' },
  { id: 'tls_split', name: 'TLS Split Attack', desc: 'Split TLS handshake across packets' },
  { id: 'rotation', name: 'Protocol Rotation', desc: 'Rotate through multiple protocols' },
  { id: 'combined', name: 'Combined Attack', desc: 'Use multiple techniques simultaneously' },
  { id: 'all', name: 'All Attacks (Random)', desc: 'Random selection from all attack types' },
];

export default function AdversaryTestPage() {
  const [attackType, setAttackType] = useState('ecs');
  const [iterations, setIterations] = useState(100);
  const [intensity, setIntensity] = useState(5);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState('Ready');
  const [results, setResults] = useState<any[]>([]);
  
  // Summary stats
  const [totalAttacks, setTotalAttacks] = useState(0);
  const [successful, setSuccessful] = useState(0);
  const [detected, setDetected] = useState(0);
  const [stealthSum, setStealthSum] = useState(0);

  const avgStealth = totalAttacks > 0 ? (stealthSum / totalAttacks) : 0;
  const successRate = totalAttacks > 0 ? (successful / totalAttacks * 100) : 0;

  const startTest = async () => {
    setRunning(true);
    setProgress(0);
    setResults([]);
    setTotalAttacks(0);
    setSuccessful(0);
    setDetected(0);
    setStealthSum(0);
    setStatus('Starting campaign on backend…');
    try {
      await adversaryApi.run({ attack_type: attackType, iterations, intensity });
      setStatus('Running…');
      const timer = setInterval(async () => {
        try {
          const st = await adversaryApi.getStatus();
          setProgress(st.progress ?? 0);
          if (st.status === 'done' && st.results) {
            const r = st.results;
            clearInterval(timer);
            setRunning(false);
            setProgress(100);
            setTotalAttacks(r.total_attacks ?? 0);
            setSuccessful(r.successful ?? 0);
            setDetected(Math.max(0, (r.total_attacks ?? 0) - (r.successful ?? 0)));
            setStealthSum((r.avg_stealth ?? 0) * (r.total_attacks ?? 0));
            setResults([{
              time: new Date().toLocaleTimeString(),
              attack_type: (ATTACK_TYPES.find(a => a.id === attackType)?.name || attackType),
              intensity,
              stealth: r.avg_stealth ?? 0,
              detected: (r.detection_rate ?? 0) > 0.5,
              result: `done · det ${(r.detection_rate ?? 0).toFixed(2)} · ${r.successful ?? 0}/${r.total_attacks ?? 0} ok`,
            }]);
            setStatus('Test completed (real campaign)');
          } else if (st.status === 'running') {
            setStatus(`Running… ${st.progress ?? 0}%`);
          } else if (st.status === 'unavailable') {
            clearInterval(timer);
            setRunning(false);
            setStatus('Backend unavailable');
          }
        } catch (e) {
          clearInterval(timer);
          setRunning(false);
          setStatus('Poll failed');
        }
      }, 1000);
    } catch (e) {
      setRunning(false);
      setStatus('Failed to start');
    }
  };

  const stopTest = () => {
    setRunning(false);
    setStatus('Stopped locally (backend campaign keeps running)');
  };

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <div className="flex items-center gap-3">
        <Target className="w-8 h-8 text-accent-red" />
        <div>
          <h1 className="text-2xl font-bold text-base-100">Adversarial Attack Testing</h1>
          <p className="text-sm text-base-500">Test system resilience against various attack types</p>
        </div>
      </div>

      {/* Configuration */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Attack Configuration</h2>
        </div>
        <div className="card-content space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm text-base-400 mb-2">Attack Type</label>
              <select
                className="input w-full"
                value={attackType}
                onChange={e => setAttackType(e.target.value)}
                disabled={running}
              >
                {ATTACK_TYPES.map(at => (
                  <option key={at.id} value={at.id}>{at.name}</option>
                ))}
              </select>
              <p className="text-xs text-base-500 mt-1">
                {ATTACK_TYPES.find(a => a.id === attackType)?.desc}
              </p>
            </div>
            <div>
              <label className="block text-sm text-base-400 mb-2">Iterations</label>
              <input
                type="number"
                className="input w-full"
                min="1"
                max="10000"
                step="10"
                value={iterations}
                onChange={e => setIterations(parseInt(e.target.value))}
                disabled={running}
              />
            </div>
            <div>
              <label className="block text-sm text-base-400 mb-2">Intensity (1-10)</label>
              <input
                type="number"
                className="input w-full"
                min="1"
                max="10"
                value={intensity}
                onChange={e => setIntensity(parseInt(e.target.value))}
                disabled={running}
              />
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={startTest}
              disabled={running}
              className="btn btn-primary flex items-center gap-2"
            >
              <Play className="w-4 h-4" /> Start Test
            </button>
            <button
              onClick={stopTest}
              disabled={!running}
              className="btn btn-danger flex items-center gap-2"
            >
              <StopCircle className="w-4 h-4" /> Stop
            </button>
          </div>
        </div>
      </div>

      {/* Progress */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Progress</h2>
        </div>
        <div className="card-content">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-base-400">{status}</span>
            <span className="font-mono text-base-200">{progress}%</span>
          </div>
          <div className="w-full bg-surface-1 rounded-full h-3">
            <div
              className="bg-accent-blue h-3 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-4 h-4 text-accent-blue" />
            <span className="text-xs text-base-500">Total Attacks</span>
          </div>
          <div className="text-2xl font-bold font-mono text-accent-blue">{totalAttacks}</div>
        </div>
        <div className="card p-4 border-accent-green/30">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4 text-accent-green" />
            <span className="text-xs text-base-500">Successful</span>
          </div>
          <div className="text-2xl font-bold font-mono text-accent-green">{successful}</div>
        </div>
        <div className="card p-4 border-accent-red/30">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-4 h-4 text-accent-red" />
            <span className="text-xs text-base-500">Detected</span>
          </div>
          <div className="text-2xl font-bold font-mono text-accent-red">{detected}</div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-base-500 mb-2">Avg Stealth</div>
          <div className="text-2xl font-bold font-mono text-accent-yellow">{avgStealth.toFixed(3)}</div>
        </div>
        <div className="card p-4">
          <div className="text-xs text-base-500 mb-2">Success Rate</div>
          <div className="text-2xl font-bold font-mono text-accent-orange">{successRate.toFixed(1)}%</div>
        </div>
      </div>

      {/* Results Table */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Attack Results</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-surface-1 border-b border-base-700">
              <tr>
                <th className="text-left px-4 py-2 text-xs font-medium text-base-500">Time</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-base-500">Attack Type</th>
                <th className="text-right px-4 py-2 text-xs font-medium text-base-500">Intensity</th>
                <th className="text-right px-4 py-2 text-xs font-medium text-base-500">Stealth</th>
                <th className="text-center px-4 py-2 text-xs font-medium text-base-500">Detected</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-base-500">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {results.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-base-500">
                    No results yet. Start a test to see results.
                  </td>
                </tr>
              ) : (
                results.map((r, i) => (
                  <tr key={i} className="hover:bg-surface-1 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-base-400">{r.time}</td>
                    <td className="px-4 py-3 text-sm text-base-200">{r.attack_type}</td>
                    <td className="px-4 py-3 text-right font-mono text-sm text-base-200">{r.intensity}</td>
                    <td className={`px-4 py-3 text-right font-mono text-sm font-bold ${
                      r.stealth < 0.3 ? 'text-accent-red' :
                      r.stealth < 0.6 ? 'text-accent-yellow' : 'text-accent-green'
                    }`}>
                      {r.stealth.toFixed(3)}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {r.detected ? (
                        <span className="badge badge-danger">Yes</span>
                      ) : (
                        <span className="badge badge-success">No</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm text-base-200">{r.result}</td>
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
