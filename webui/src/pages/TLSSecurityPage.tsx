import { Lock, Shield } from 'lucide-react';

export default function TLSSecurityPage() {
  return (
    <div className="p-8 animate-fade-in space-y-6">
      <h1 className="text-2xl font-bold text-base-100">TLS Security</h1>

      {/* ECH */}
      <div className="card">
        <div className="card-header"><h2 className="card-title flex items-center gap-2"><Lock className="w-4 h-4" /> Encrypted Client Hello (ECH)</h2></div>
        <div className="card-content space-y-4">
          <p className="text-sm text-base-400">HPKE (RFC 9180) — encrypt SNI and other ClientHello extensions</p>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-base-500">KEM Algorithm</label>
              <select className="input w-full">
                <option>X25519-HKDF-SHA256 (0x0020)</option>
                <option>P-256-HKDF-SHA256 (0x0010)</option>
                <option>P-384-HKDF-SHA384 (0x0011)</option>
                <option>P-521-HKDF-SHA512 (0x0012)</option>
                <option>X448-HKDF-SHA512 (0x0021)</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-base-500">KDF</label>
              <select className="input w-full">
                <option>HKDF-SHA256</option>
                <option>HKDF-SHA384</option>
                <option>HKDF-SHA512</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-base-500">AEAD</label>
              <select className="input w-full">
                <option>AES-128-GCM</option>
                <option>AES-256-GCM</option>
                <option>ChaCha20-Poly1305</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div><div className="text-xs text-base-500">ECH Cache Entries</div><div className="text-lg font-mono text-base-200">0</div></div>
            <div><div className="text-xs text-base-500">ECH Retries</div><div className="text-lg font-mono text-base-200">0</div></div>
          </div>
        </div>
      </div>

      {/* TLS Fingerprint */}
      <div className="card">
        <div className="card-header"><h2 className="card-title flex items-center gap-2"><Shield className="w-4 h-4" /> TLS Fingerprint & Record Padding</h2></div>
        <div className="card-content space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h3 className="text-sm font-semibold text-base-300 mb-2">JA3/JA4 Fingerprint</h3>
              <div className="font-mono text-xs text-base-400 bg-surface-1 p-3 rounded">—</div>
            </div>
            <div>
              <h3 className="text-sm font-semibold text-base-300 mb-2">Record Padding Strategy</h3>
              <select className="input w-full">
                <option>Power-of-two alignment</option>
                <option>Random padding (16-256 bytes)</option>
                <option>Fixed size (512 bytes)</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
