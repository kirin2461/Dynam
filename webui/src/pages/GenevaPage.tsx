import { useState } from 'react';
import { genevaApi } from '@/services/api';
import { Dna, Play } from 'lucide-react';

const PRESETS = [
  { id: 'tspu_2026', name: 'TSPU 2026 (Russia)', desc: 'Bypass Russian TSPU deep inspection' },
  { id: 'gfw_2025', name: 'GFW 2025 (China)', desc: 'Bypass Great Firewall' },
  { id: 'iran_dpi', name: 'Iran DPI', desc: 'Bypass Iranian DPI filters' },
  { id: 'universal', name: 'Universal', desc: 'High overhead, maximum evasion' },
];

const ACTIONS = ['DUPLICATE', 'FRAGMENT', 'TAMPER_TTL', 'TAMPER_SEQ', 'TAMPER_FLAGS', 'TAMPER_CHECKSUM', 'DROP', 'DISORDER'];

export default function GenevaPage() {
  const [selectedPreset, setSelectedPreset] = useState('tspu_2026');
  const [genevaMsg, setGenevaMsg] = useState('');
  const applyStrategy = async () => {
    setGenevaMsg('Applying…');
    try {
      const r = await genevaApi.start({ preset: selectedPreset });
      setGenevaMsg(r?.ok === false ? `Failed: ${r.error || 'unknown'}` : 'Strategy applied ✓ engine running');
    } catch (e) {
      setGenevaMsg('Backend unavailable');
    }
  };

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <div className="flex items-center gap-3">
        <Dna className="w-8 h-8 text-accent-mauve" />
        <div>
          <h1 className="text-2xl font-bold text-base-100">Geneva Genetic Engine</h1>
          <p className="text-sm text-base-500">Packet-level manipulation strategies for evading stateful DPI</p>
        </div>
      </div>

      {/* Presets */}
      <div className="card">
        <div className="card-header"><h2 className="card-title">Preset Strategies</h2></div>
        <div className="card-content">
          <div className="grid grid-cols-2 gap-4">
            {PRESETS.map(p => (
              <button key={p.id} onClick={() => setSelectedPreset(p.id)}
                className={`p-4 rounded-lg border text-left transition-all ${selectedPreset === p.id ? 'border-accent-mauve bg-accent-mauve/10' : 'border-base-600 hover:border-base-500'}`}>
                <div className="font-semibold text-base-200">{p.name}</div>
                <div className="text-xs text-base-500 mt-1">{p.desc}</div>
              </button>
            ))}
          </div>
          <div className="mt-4 flex items-center gap-3">
            <button onClick={applyStrategy} className="btn btn-primary flex items-center gap-2"><Play className="w-4 h-4" /> Apply Strategy</button>
            {genevaMsg && <span className="text-sm text-base-300">{genevaMsg}</span>}
          </div>
        </div>
      </div>

      {/* Strategy Steps */}
      <div className="card">
        <div className="card-header"><h2 className="card-title">Strategy Steps</h2></div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-surface-1 border-b border-base-700">
              <tr>
                <th className="text-left px-4 py-2 text-xs text-base-500">#</th>
                <th className="text-left px-4 py-2 text-xs text-base-500">Action</th>
                <th className="text-left px-4 py-2 text-xs text-base-500">Target</th>
                <th className="text-left px-4 py-2 text-xs text-base-500">Parameter</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {ACTIONS.slice(0, 5).map((action, i) => (
                <tr key={i} className="hover:bg-surface-1">
                  <td className="px-4 py-3 font-mono text-xs text-base-400">{i + 1}</td>
                  <td className="px-4 py-3"><span className="badge badge-info text-xs">{action}</span></td>
                  <td className="px-4 py-3 font-mono text-xs text-base-300">packet[{i}]</td>
                  <td className="px-4 py-3 font-mono text-xs text-base-300">—</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: 'Processed', value: '0' },
          { label: 'Duplicated', value: '0' },
          { label: 'Fragmented', value: '0' },
          { label: 'Tampered', value: '0' },
          { label: 'Dropped', value: '0' },
          { label: 'Overhead', value: '0 B' },
        ].map((s, i) => (
          <div key={i} className="card p-4">
            <div className="text-xs text-base-500">{s.label}</div>
            <div className="text-xl font-bold font-mono text-base-200">{s.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
