import { useState } from 'react';

export default function AnonymizationPage() {
  const [activeTab, setActiveTab] = useState<'i2p' | 'tor' | 'turn'>('i2p');

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <h1 className="text-2xl font-bold text-base-100">Anonymization Networks</h1>

      <div className="flex gap-2">
        {(['i2p', 'tor', 'turn'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === tab ? 'bg-accent-blue text-white' : 'bg-surface-2 text-base-400 hover:bg-base-700'}`}>
            {tab.toUpperCase()}
          </button>
        ))}
      </div>

      {activeTab === 'i2p' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header"><h2 className="card-title">I2P — Invisible Internet Project</h2></div>
            <div className="card-content space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div><div className="text-xs text-base-500">SAM Bridge</div><div className="text-lg font-mono text-accent-green">Connected</div></div>
                <div><div className="text-xs text-base-500">Tunnels</div><div className="text-lg font-mono text-base-200">0</div></div>
                <div><div className="text-xs text-base-500">Bandwidth</div><div className="text-lg font-mono text-base-200">0 KB/s</div></div>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-base-300 mb-2">Peer Filter</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div><label className="text-xs text-base-500">Allowlist (one per line)</label><textarea className="input w-full h-24 font-mono text-xs" placeholder="*.i2p" /></div>
                  <div><label className="text-xs text-base-500">Blocklist</label><textarea className="input w-full h-24 font-mono text-xs" placeholder="bad-dest.i2p" /></div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'tor' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">Tor Network</h2></div>
          <div className="card-content">
            <div className="grid grid-cols-3 gap-4">
              <div><div className="text-xs text-base-500">Status</div><div className="text-lg font-mono text-accent-green">Connected</div></div>
              <div><div className="text-xs text-base-500">Circuit Length</div><div className="text-lg font-mono text-base-200">3 hops</div></div>
              <div><div className="text-xs text-base-500">Exit Node</div><div className="text-lg font-mono text-base-200">—</div></div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'turn' && (
        <div className="card">
          <div className="card-header"><h2 className="card-title">TURN Relay</h2></div>
          <div className="card-content">
            <div className="grid grid-cols-2 gap-4">
              <div><label className="text-xs text-base-500">Server</label><input className="input w-full" placeholder="turn:relay.example.com:3478" /></div>
              <div><label className="text-xs text-base-500">Username</label><input className="input w-full" /></div>
            </div>
            <button className="btn btn-primary mt-4">Connect</button>
          </div>
        </div>
      )}
    </div>
  );
}
