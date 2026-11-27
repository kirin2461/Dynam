import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { statsApi } from '@/services/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { AppStats } from '@/types';

export default function StatsPage() {
  const { t } = useTranslation();
  const { stats: wsStats } = useWebSocket();
  const [stats, setStats] = useState<AppStats | null>(null);

  useEffect(() => {
    statsApi.get().then(setStats).catch(console.error);
  }, []);

  useEffect(() => {
    if (wsStats) setStats(wsStats);
  }, [wsStats]);

  const formatBytes = (bytes: number): string => {
    if (bytes > 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    if (bytes > 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  if (!stats) return <div className="p-8">{t('common.loading')}</div>;

  return (
    <div className="p-8 animate-fade-in">
      <h1 className="text-2xl font-bold text-base-100 mb-8">{t('stats.title')}</h1>

      {/* Traffic Stats */}
      <div className="card mb-6">
        <div className="card-header">
          <h2 className="card-title">{t('stats.traffic')}</h2>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.totalBytes')}</div>
              <div className="text-2xl font-bold font-mono text-base-100">
                {formatBytes(stats.total_bytes)}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.totalPackets')}</div>
              <div className="text-2xl font-bold font-mono text-base-100">
                {stats.total_packets.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.connections')}</div>
              <div className="text-2xl font-bold font-mono text-base-100">
                {stats.total_connections.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.avgBandwidth')}</div>
              <div className="text-2xl font-bold font-mono text-base-100">
                {(stats.avg_bandwidth / 1024).toFixed(1)} KB/s
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Stealth Scores */}
      <div className="card mb-6">
        <div className="card-header">
          <h2 className="card-title">{t('stats.stealthScores')}</h2>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.average')}</div>
              <div className="text-2xl font-bold font-mono text-accent-yellow">
                {stats.avg_stealth.toFixed(3)}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.minimum')}</div>
              <div className="text-2xl font-bold font-mono text-accent-green">
                {stats.min_stealth.toFixed(3)}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.maximum')}</div>
              <div className="text-2xl font-bold font-mono text-accent-red">
                {stats.max_stealth.toFixed(3)}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.median')}</div>
              <div className="text-2xl font-bold font-mono text-accent-orange">
                {stats.median_stealth.toFixed(3)}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ONNX Model */}
      <div className="card mb-6">
        <div className="card-header">
          <h2 className="card-title">{t('stats.onnx')}</h2>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.inferences')}</div>
              <div className="text-2xl font-bold font-mono text-base-100">
                {stats.onnx_inferences.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.detections')}</div>
              <div className="text-2xl font-bold font-mono text-accent-red">
                {stats.onnx_detections.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.detectionRate')}</div>
              <div className="text-2xl font-bold font-mono text-accent-orange">
                {(stats.onnx_detection_rate * 100).toFixed(1)}%
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.avgConfidence')}</div>
              <div className="text-2xl font-bold font-mono text-accent-blue">
                {stats.onnx_avg_confidence.toFixed(3)}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Adversarial Tests */}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">{t('stats.attacks')}</h2>
        </div>
        <div className="card-content">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.totalAttacks')}</div>
              <div className="text-2xl font-bold font-mono text-base-100">
                {stats.total_attacks.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.successful')}</div>
              <div className="text-2xl font-bold font-mono text-accent-green">
                {stats.successful_attacks.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm text-base-400 mb-1">{t('stats.successRate')}</div>
              <div className="text-2xl font-bold font-mono text-accent-yellow">
                {(stats.attack_success_rate * 100).toFixed(1)}%
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
