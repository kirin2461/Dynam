import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { trafficApi, statsApi } from '@/services/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { TrafficData, AppStats } from '@/types';
import { StatCard } from '@/components/StatCard';
import { BarChart3, Package, Network, Shield, Bot } from 'lucide-react';

export default function DashboardPage() {
  const { t } = useTranslation();
  const { traffic: wsTraffic, stats: wsStats } = useWebSocket();
  
  const [traffic, setTraffic] = useState<TrafficData | null>(null);
  const [stats, setStats] = useState<AppStats | null>(null);

  useEffect(() => {
    trafficApi.get().then(setTraffic).catch(console.error);
    statsApi.get().then(setStats).catch(console.error);
  }, []);

  // Update from WebSocket
  useEffect(() => {
    if (wsTraffic) setTraffic(wsTraffic);
  }, [wsTraffic]);

  useEffect(() => {
    if (wsStats) setStats(wsStats);
  }, [wsStats]);

  const formatBytes = (bytes: number): string => {
    if (bytes > 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes > 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const onnxDetected = traffic?.connections.filter(c => c.onnx_detected).length || 0;

  return (
    <div className="p-8 animate-fade-in">
      <h1 className="text-2xl font-bold text-base-100 mb-8">{t('dashboard.title')}</h1>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6 mb-8">
        <StatCard
          title={t('dashboard.totalBytes')}
          value={traffic ? formatBytes(traffic.total_bytes) : '—'}
          icon={<BarChart3 className="w-7 h-7" />}
        />
        <StatCard
          title={t('dashboard.totalPackets')}
          value={traffic?.total_packets.toLocaleString() || '—'}
          icon={<Package className="w-7 h-7" />}
        />
        <StatCard
          title={t('dashboard.connections')}
          value={traffic?.connections.length.toString() || '—'}
          icon={<Network className="w-7 h-7" />}
        />
        <StatCard
          title={t('dashboard.avgStealth')}
          value={stats?.avg_stealth.toFixed(3) || '—'}
          icon={<Shield className="w-7 h-7" />}
        />
        <StatCard
          title={t('dashboard.onnxDetected')}
          value={onnxDetected.toString()}
          icon={<Bot className="w-7 h-7" />}
          variant={onnxDetected > 0 ? 'danger' : 'default'}
        />
      </div>

      {/* Additional info */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Stealth Score Distribution</h2>
          </div>
          <div className="card-content">
            {stats ? (
              <div className="space-y-4">
                <div className="flex justify-between">
                  <span className="text-base-400">Min</span>
                  <span className="font-mono text-accent-green">{stats.min_stealth.toFixed(3)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-base-400">Median</span>
                  <span className="font-mono text-accent-yellow">{stats.median_stealth.toFixed(3)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-base-400">Max</span>
                  <span className="font-mono text-accent-red">{stats.max_stealth.toFixed(3)}</span>
                </div>
              </div>
            ) : (
              <p className="text-base-500">{t('common.loading')}</p>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">ONNX Model Performance</h2>
          </div>
          <div className="card-content">
            {stats ? (
              <div className="space-y-4">
                <div className="flex justify-between">
                  <span className="text-base-400">Inferences</span>
                  <span className="font-mono">{stats.onnx_inferences.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-base-400">Detections</span>
                  <span className="font-mono text-accent-red">{stats.onnx_detections}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-base-400">Detection Rate</span>
                  <span className="font-mono text-accent-orange">
                    {(stats.onnx_detection_rate * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-base-400">Avg Confidence</span>
                  <span className="font-mono text-accent-blue">
                    {stats.onnx_avg_confidence.toFixed(3)}
                  </span>
                </div>
              </div>
            ) : (
              <p className="text-base-500">{t('common.loading')}</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
