import { useState } from 'react';
import { Shield, Lock, Eye, Key } from 'lucide-react';

export default function ServerInvisibilityPage() {
  const [tab, setTab] = useState<'portknock' | 'spa' | 'reality' | 'stegodns'>('portknock');

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <h1 className="text-2xl font-bold text-base-100">Server Invisibility</h1>
      <p className="text-sm text-base-500">Make your server completely invisible to scanners</p>

      <div className="flex gap-2">
        {([
          { id: 'portknock', label: 'Port Knock', icon: Eye },
          { id: 'spa', label: 'SPA', icon: Key },
          { id: 'reality', label: 'Reality', icon: Shield },
          { id: 'stegodns', label: 'StegoDNS', icon: Lock },
        ] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${tab === t.id ? 'bg-accent-blue text-white' : 'bg-surface-2 text-base-400 hover:bg-base-700'}`}>
            <t.icon className="w-4 h-4" /> {t.label}
          </button>
        ))}
      </div>

      {tab === 'portknock' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">Port Knocking</h2></div>
          <div className="card-content space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-surface-1 p-4 rounded-lg">
                <h3 className="text-sm font-semibold text-base-300 mb-2">TOTP Sequence</h3>
                <p className="text-xs text-base-500">Time-based port sequence (changes every 30s)</p>
                <div className="mt-2 font-mono text-accent-green text-sm">Active</div>
              </div>
              <div className="bg-surface-1 p-4 rounded-lg">
                <h3 className="text-sm font-semibold text-base-300 mb-2">Static Sequence</h3>
                <p className="text-xs text-base-500">Fixed port list</p>
                <div className="mt-2 font-mono text-base-500">Inactive</div>
              </div>
              <div className="bg-surface-1 p-4 rounded-lg">
                <h3 className="text-sm font-semibold text-base-300 mb-2">SPA</h3>
                <p className="text-xs text-base-500">Single encrypted UDP packet</p>
                <div className="mt-2 font-mono text-base-500">Inactive</div>
              </div>
              <div className="bg-surface-1 p-4 rounded-lg">
                <h3 className="text-sm font-semibold text-base-300 mb-2">Covert TCP</h3>
                <p className="text-xs text-base-500">Encoded in TCP fields (window/IPID/TTL)</p>
                <div className="mt-2 font-mono text-base-500">Inactive</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === 'spa' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">Single Packet Authorization (SPA)</h2></div>
          <div className="card-content space-y-4">
            <p className="text-sm text-base-400">Ed25519 asymmetric — 256-byte UDP packet with signature</p>
            <div className="grid grid-cols-2 gap-4">
              <div><label className="text-xs text-base-500">Public Key</label><div className="input font-mono text-xs bg-surface-1">—</div></div>
              <div><label className="text-xs text-base-500">Key ID (BLAKE2b-64)</label><div className="input font-mono text-xs bg-surface-1">—</div></div>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div><div className="text-xs text-base-500">Auth Packets</div><div className="text-lg font-mono text-base-200">0</div></div>
              <div><div className="text-xs text-base-500">Authorized IPs</div><div className="text-lg font-mono text-base-200">0</div></div>
              <div><div className="text-xs text-base-500">Rejected</div><div className="text-lg font-mono text-accent-red">0</div></div>
            </div>
            <button className="btn btn-primary">Generate New Key</button>
          </div>
        </div>
      )}

      {tab === 'reality' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">Reality Protocol (XTLS-Reality-style)</h2></div>
          <div className="card-content space-y-4">
            <p className="text-sm text-base-400">Unauthorized clients see a real TLS session with fallback domain</p>
            <div className="grid grid-cols-2 gap-4">
              <div><label className="text-xs text-base-500">Gateway Domain</label><input className="input w-full" placeholder="gw.example.com" /></div>
              <div><label className="text-xs text-base-500">Fallback Domain</label><input className="input w-full" placeholder="www.microsoft.com" /></div>
            </div>
            <div className="grid grid-cols-3 gap-4">
              <div><div className="text-xs text-base-500">Authorized</div><div className="text-lg font-mono text-accent-green">0</div></div>
              <div><div className="text-xs text-base-500">Fallback</div><div className="text-lg font-mono text-accent-yellow">0</div></div>
              <div><div className="text-xs text-base-500">Dropped</div><div className="text-lg font-mono text-accent-red">0</div></div>
            </div>
          </div>
        </div>
      )}

      {tab === 'stegodns' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">StegoDNS — Zero-Knowledge DNS Records</h2></div>
          <div className="card-content space-y-4">
            <p className="text-sm text-base-400">Server params hidden in SPF-looking TXT records. XChaCha20-Poly1305 + Ed25519</p>
            <div><label className="text-xs text-base-500">Master Passphrase</label><input className="input w-full" type="password" /></div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-base-500">Node Parameters</label>
                <div className="grid grid-cols-2 gap-2">
                  <div><label className="text-[10px] text-base-600">IPv4</label><input className="input w-full" placeholder="1.2.3.4" /></div>
                  <div><label className="text-[10px] text-base-600">Port</label><input className="input w-full" type="number" placeholder="443" /></div>
                </div>
              </div>
              <div>
                <label className="text-xs text-base-500">Encoded SPF Record</label>
                <div className="input font-mono text-xs bg-surface-1 min-h-[60px] break-all">—</div>
              </div>
            </div>
            <button className="btn btn-primary">Encode</button>
          </div>
        </div>
      )}
    </div>
  );
}
