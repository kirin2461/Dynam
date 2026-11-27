import { useState } from 'react';
import { Search, Shield } from 'lucide-react';

export default function DnsToolsPage() {
  const [hostname, setHostname] = useState('');
  const [recordType, setRecordType] = useState('A');

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <h1 className="text-2xl font-bold text-base-100">DNS Tools</h1>

      {/* DNS Lookup */}
      <div className="card">
        <div className="card-header"><h2 className="card-title">DNS Lookup — Side-by-Side Comparison</h2></div>
        <div className="card-content">
          <div className="flex gap-4 mb-6">
            <input className="input flex-1" placeholder="example.com" value={hostname} onChange={e => setHostname(e.target.value)} />
            <select className="input" value={recordType} onChange={e => setRecordType(e.target.value)}>
              <option>A</option><option>AAAA</option>
            </select>
            <button className="btn btn-primary flex items-center gap-2"><Search className="w-4 h-4" /> Look Up</button>
          </div>
          <div className="grid grid-cols-3 gap-4">
            {['System DNS', 'DoH · Cloudflare (1.1.1.1)', 'DoH · Google (8.8.8.8)'].map((resolver, i) => (
              <div key={i} className="bg-surface-1 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-base-300 mb-3">{resolver}</h3>
                <div className="font-mono text-xs text-base-400 min-h-[100px]">
                  {hostname ? 'Querying...' : 'Enter hostname'}
                </div>
              </div>
            ))}
          </div>
          <p className="text-xs text-base-500 mt-4">If System returns X but DoH returns Y → DNS leak or censorship intercept detected</p>
        </div>
      </div>

      {/* Leak Test */}
      <div className="card">
        <div className="card-header"><h2 className="card-title flex items-center gap-2"><Shield className="w-4 h-4" /> IP Leak Test</h2></div>
        <div className="card-content">
          <p className="text-sm text-base-400 mb-4">Compare direct IP vs IP through SOCKS5 proxy</p>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-surface-1 rounded-lg p-4">
              <h3 className="text-sm text-base-500 mb-2">Direct Connection</h3>
              <div className="text-xl font-mono text-base-200">—</div>
            </div>
            <div className="bg-surface-1 rounded-lg p-4">
              <h3 className="text-sm text-base-500 mb-2">Through SOCKS5 Proxy</h3>
              <div className="text-xl font-mono text-base-200">—</div>
            </div>
          </div>
          <button className="btn btn-primary mt-4">Run Leak Test</button>
        </div>
      </div>
    </div>
  );
}
