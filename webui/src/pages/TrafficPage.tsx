import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { trafficApi } from '@/services/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { TrafficConnection } from '@/types';
import { RefreshCw } from 'lucide-react';

export default function TrafficPage() {
  const { t } = useTranslation();
  const { traffic: wsTraffic } = useWebSocket();
  
  const [connections, setConnections] = useState<TrafficConnection[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchTraffic();
  }, []);

  useEffect(() => {
    if (wsTraffic) {
      setConnections(wsTraffic.connections);
    }
  }, [wsTraffic]);

  const fetchTraffic = async () => {
    setLoading(true);
    try {
      const data = await trafficApi.get();
      setConnections(data.connections);
    } catch (error) {
      console.error('Failed to fetch traffic:', error);
    } finally {
      setLoading(false);
    }
  };

  const formatBytes = (bytes: number): string => {
    if (bytes > 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const getStealthColor = (score: number): string => {
    if (score > 0.8) return 'text-accent-red';
    if (score > 0.5) return 'text-accent-orange';
    if (score > 0.3) return 'text-accent-yellow';
    return 'text-accent-green';
  };

  return (
    <div className="p-8 animate-fade-in">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-base-100">{t('traffic.title')}</h1>
        <div className="flex items-center gap-4">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`btn ${autoRefresh ? 'btn-primary' : 'btn-secondary'}`}
          >
            {t('traffic.autoRefresh')}
          </button>
          <button onClick={fetchTraffic} className="btn btn-secondary" disabled={loading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            {t('traffic.refresh')}
          </button>
        </div>
      </div>

      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-surface-1 border-b border-base-700">
              <tr>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400">{t('traffic.source')}</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400">{t('traffic.destination')}</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400">{t('traffic.protocol')}</th>
                <th className="text-right px-6 py-3 text-sm font-medium text-base-400">{t('traffic.bytes')}</th>
                <th className="text-right px-6 py-3 text-sm font-medium text-base-400">{t('traffic.packets')}</th>
                <th className="text-right px-6 py-3 text-sm font-medium text-base-400">{t('traffic.stealth')}</th>
                <th className="text-center px-6 py-3 text-sm font-medium text-base-400">{t('traffic.onnx')}</th>
                <th className="text-right px-6 py-3 text-sm font-medium text-base-400">{t('traffic.probability')}</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400">{t('traffic.status')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {connections.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-6 py-12 text-center text-base-500">
                    {t('traffic.noConnections')}
                  </td>
                </tr>
              ) : (
                connections.map((conn, idx) => (
                  <tr key={idx} className="hover:bg-surface-1 transition-colors">
                    <td className="px-6 py-4 font-mono text-sm text-base-200">{conn.source}</td>
                    <td className="px-6 py-4 font-mono text-sm text-base-200">{conn.destination}</td>
                    <td className="px-6 py-4">
                      <span className="badge badge-info">{conn.protocol}</span>
                    </td>
                    <td className="px-6 py-4 text-right font-mono text-sm text-base-200">
                      {formatBytes(conn.bytes)}
                    </td>
                    <td className="px-6 py-4 text-right font-mono text-sm text-base-200">
                      {conn.packets.toLocaleString()}
                    </td>
                    <td className={`px-6 py-4 text-right font-mono text-sm font-medium ${getStealthColor(conn.stealth_score)}`}>
                      {conn.stealth_score.toFixed(3)}
                    </td>
                    <td className="px-6 py-4 text-center">
                      {conn.onnx_detected ? (
                        <span className="badge badge-danger">●</span>
                      ) : (
                        <span className="text-base-600">—</span>
                      )}
                    </td>
                    <td className="px-6 py-4 text-right font-mono text-sm text-base-200">
                      {conn.onnx_probability.toFixed(3)}
                    </td>
                    <td className="px-6 py-4">
                      <span className={`badge ${conn.status === 'active' ? 'badge-success' : 'badge-warning'}`}>
                        {conn.status}
                      </span>
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
