import { useState } from 'react';
import { Search, Globe, Lock, Shield, Server } from 'lucide-react';

export default function SiteReconPage() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null); void result;

  const scan = () => {
    setScanning(true);
    setTimeout(() => { setScanning(false); setResult({ demo: true }); }, 2000);
  };

  return (
    <div className="p-8 animate-fade-in space-y-6">
      <h1 className="text-2xl font-bold text-base-100">Site Reconnaissance</h1>
      
      {/* Input */}
      <div className="card">
        <div className="card-content flex gap-4">
          <input className="input flex-1" placeholder="https://example.com" value={url} onChange={e => setUrl(e.target.value)} />
          <button className="btn btn-primary flex items-center gap-2" onClick={scan} disabled={scanning}>
            <Search className="w-4 h-4" /> {scanning ? 'Scanning...' : 'Deep Scan'}
          </button>
        </div>
      </div>

      {/* 7 Probes */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { icon: Globe, name: 'HTTP Probe', desc: 'Status, headers, body' },
          { icon: Server, name: 'DNS Resolve', desc: 'A/AAAA records' },
          { icon: Lock, name: 'TLS Handshake', desc: 'Cipher, cert, SANs' },
          { icon: Shield, name: 'Security Headers', desc: 'HSTS, CSP, X-Frame' },
          { icon: Globe, name: 'robots.txt', desc: 'Crawl rules' },
          { icon: Globe, name: 'sitemap.xml', desc: 'URL inventory' },
          { icon: Globe, name: 'Favicon', desc: 'Existence + size' },
          { icon: Shield, name: 'Cookies', desc: 'Set by response' },
        ].map((probe, i) => (
          <div key={i} className="card p-4">
            <div className="flex items-center gap-2 mb-2">
              <probe.icon className="w-4 h-4 text-accent-blue" />
              <span className="text-sm font-semibold text-base-200">{probe.name}</span>
            </div>
            <p className="text-xs text-base-500">{probe.desc}</p>
          </div>
        ))}
      </div>

      {/* Bulk + Crawler tabs */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Bulk Scanner & Crawler</h2>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-semibold text-base-300 mb-2">Bulk Scan</h3>
              <p className="text-xs text-base-500 mb-3">Paste URLs (one per line), scan up to 6 concurrent</p>
              <textarea className="input w-full h-32 font-mono text-xs" placeholder="https://example.com&#10;https://github.com&#10;..." />
              <button className="btn btn-primary mt-2 w-full">Run Bulk Scan</button>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-base-300 mb-2">Site Crawler</h3>
              <p className="text-xs text-base-500 mb-3">BFS crawl with depth limit and page cap</p>
              <input className="input w-full mb-2" placeholder="Start URL" />
              <div className="grid grid-cols-2 gap-2 mb-2">
                <div><label className="text-xs text-base-500">Max Depth</label><input className="input w-full" type="number" defaultValue={2} /></div>
                <div><label className="text-xs text-base-500">Page Cap</label><input className="input w-full" type="number" defaultValue={30} /></div>
              </div>
              <button className="btn btn-primary w-full">Start Crawl</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
