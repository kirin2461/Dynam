import { useState } from 'react';
import { GitBranch, Activity, Radio } from 'lucide-react';

export default function TrafficShapingPage() {
  const [tab, setTab] = useState<'mimicry' | 'behavioral' | 'covert'>('mimicry');

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <h1 className="text-2xl font-bold text-base-100">Traffic Shaping & Covert Channels</h1>

      <div className="flex gap-2">
        {([
          { id: 'mimicry', label: 'Protocol Mimicry', icon: GitBranch },
          { id: 'behavioral', label: 'Behavioral Cloak', icon: Activity },
          { id: 'covert', label: 'Covert Channels', icon: Radio },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${tab === t.id ? 'bg-accent-blue text-white' : 'bg-surface-2 text-base-400 hover:bg-base-700'}`}>
            <t.icon className="w-4 h-4" /> {t.label}
          </button>
        ))}
      </div>

      {tab === 'mimicry' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header"><h2 className="card-title">Protocol Mimicry FSM</h2></div>
            <div className="card-content space-y-4">
              <div className="grid grid-cols-4 gap-4">
                {['BOOTSTRAP', 'HANDSHAKE', 'ESTABLISHED', 'DATA'].map((phase, i) => (
                  <div key={i} className={`p-4 rounded-lg border text-center ${i === 3 ? 'border-accent-blue bg-accent-blue/10' : 'border-base-600'}`}>
                    <div className="text-xs text-base-500">Phase {i + 1}</div>
                    <div className={`font-bold ${i === 3 ? 'text-accent-blue' : 'text-base-400'}`}>{phase}</div>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div><div className="text-xs text-base-500">Current State</div><div className="text-lg font-mono text-accent-blue">data_send</div></div>
                <div><div className="text-xs text-base-500">State Epoch</div><div className="text-lg font-mono text-base-200">42</div></div>
                <div><div className="text-xs text-base-500">Profile Epoch</div><div className="text-lg font-mono text-base-200">3</div></div>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-base-300 mb-2">Active Sessions</h3>
                <table className="w-full">
                  <thead className="bg-surface-1 border-b border-base-700">
                    <tr><th className="text-left px-3 py-2 text-xs text-base-500">Session</th><th className="text-left px-3 py-2 text-xs text-base-500">Profile</th><th className="text-left px-3 py-2 text-xs text-base-500">State</th><th className="text-left px-3 py-2 text-xs text-base-500">Dwell</th></tr>
                  </thead>
                  <tbody><tr className="border-b border-base-700"><td className="px-3 py-2 font-mono text-xs">—</td><td className="px-3 py-2 text-xs">—</td><td className="px-3 py-2 text-xs">—</td><td className="px-3 py-2 font-mono text-xs">—</td></tr></tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'behavioral' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">Behavioral Cloak — Browser-Pattern Mimicry</h2></div>
          <div className="card-content space-y-4">
            <div className="grid grid-cols-3 gap-4">
              {[
                { id: 'chrome_casual', name: 'Chrome Casual', desc: '5-30 pkt bursts, 2-8s idle', pattern: 'General browsing' },
                { id: 'chrome_streaming', name: 'Chrome Streaming', desc: '50-200 pkt bursts, 0.1-1s idle', pattern: 'Video playback' },
                { id: 'chrome_social', name: 'Chrome Social', desc: '3-10 pkt bursts, 5-30s idle', pattern: 'Social media scroll' },
              ].map(model => (
                <div key={model.id} className="bg-surface-1 p-4 rounded-lg">
                  <div className="font-semibold text-base-200">{model.name}</div>
                  <div className="text-xs text-base-500 mt-1">{model.desc}</div>
                  <div className="text-xs text-accent-blue mt-2">{model.pattern}</div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-4 gap-4">
              <div><div className="text-xs text-base-500">Upload Ratio</div><div className="text-lg font-mono text-base-200">15%</div></div>
              <div><div className="text-xs text-base-500">Small Packets</div><div className="text-lg font-mono text-base-200">30%</div></div>
              <div><div className="text-xs text-base-500">Medium Packets</div><div className="text-lg font-mono text-base-200">40%</div></div>
              <div><div className="text-xs text-base-500">Match Score</div><div className="text-lg font-mono text-accent-green">—</div></div>
            </div>
          </div>
        </div>
      )}

      {tab === 'covert' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">Covert Channels — Steganographic Communication</h2></div>
          <div className="card-content space-y-4">
            <div className="grid grid-cols-5 gap-3">
              {[
                { name: 'DNS Subdomain', desc: '<base32>.example.com', active: false },
                { name: 'DNS TXT', desc: 'TXT record queries', active: false },
                { name: 'HTTP Header', desc: 'Header ordering/values', active: false },
                { name: 'HTTP Cookie', desc: 'Cookie value encoding', active: false },
                { name: 'HTTPS Padding', desc: 'TLS record padding', active: false },
              ].map((ch, i) => (
                <div key={i} className={`p-3 rounded-lg border text-center ${ch.active ? 'border-accent-green bg-accent-green/10' : 'border-base-600'}`}>
                  <div className="text-xs font-semibold text-base-200">{ch.name}</div>
                  <div className="text-[10px] text-base-500 mt-1">{ch.desc}</div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div><div className="text-xs text-base-500">Bandwidth</div><div className="text-lg font-mono text-base-200">0 B/s</div></div>
              <div><div className="text-xs text-base-500">Messages Sent</div><div className="text-lg font-mono text-base-200">0</div></div>
              <div><div className="text-xs text-base-500">Cover Domain</div><div className="text-lg font-mono text-base-200 text-xs">cdn-static.example.com</div></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
