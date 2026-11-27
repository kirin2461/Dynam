import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { configApi } from '@/services/api';
import type { AppConfig } from '@/types';

export default function ConfigPage() {
  const { t } = useTranslation();
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    configApi.get().then(setConfig).catch(console.error);
  }, []);

  const handleSave = async () => {
    if (!config) return;
    setLoading(true);
    try {
      await configApi.update(config);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (error) {
      console.error('Failed to save config:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    configApi.get().then(setConfig).catch(console.error);
  };

  if (!config) return <div className="p-8">{t('common.loading')}</div>;

  return (
    <div className="p-8 animate-fade-in">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-base-100">{t('config.title')}</h1>
        <div className="flex gap-4">
          <button onClick={handleReset} className="btn btn-secondary">
            {t('config.reset')}
          </button>
          <button onClick={handleSave} className="btn btn-primary" disabled={loading}>
            {loading ? t('common.loading') : t('config.save')}
          </button>
        </div>
      </div>

      {saved && (
        <div className="mb-6 p-4 bg-accent-green/10 border border-accent-green/30 rounded-lg text-accent-green">
          {t('config.saved')}
        </div>
      )}

      <div className="space-y-6">
        {/* ONNX Model */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">{t('config.onnx')}</h2>
          </div>
          <div className="card-content space-y-4">
            <div>
              <label className="block text-sm text-base-400 mb-2">{t('config.modelPath')}</label>
              <input
                type="text"
                className="input w-full"
                value={config.onnx_model_path}
                onChange={(e) => setConfig({ ...config, onnx_model_path: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-base-400 mb-2">{t('config.threshold')}</label>
                <input
                  type="number"
                  className="input w-full"
                  step="0.05"
                  min="0"
                  max="1"
                  value={config.onnx_threshold}
                  onChange={(e) => setConfig({ ...config, onnx_threshold: parseFloat(e.target.value) })}
                />
              </div>
              <div>
                <label className="block text-sm text-base-400 mb-2">{t('config.weight')}</label>
                <input
                  type="number"
                  className="input w-full"
                  step="0.1"
                  min="0"
                  max="1"
                  value={config.onnx_weight}
                  onChange={(e) => setConfig({ ...config, onnx_weight: parseFloat(e.target.value) })}
                />
              </div>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4"
                checked={config.onnx_enabled}
                onChange={(e) => setConfig({ ...config, onnx_enabled: e.target.checked })}
              />
              <span className="text-sm text-base-200">{t('config.enabled')}</span>
            </label>
          </div>
        </div>

        {/* DPI Bypass */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">{t('config.dpi')}</h2>
          </div>
          <div className="card-content space-y-4">
            <div>
              <label className="block text-sm text-base-400 mb-2">{t('config.strategy')}</label>
              <select
                className="input w-full"
                value={config.dpi_strategy}
                onChange={(e) => setConfig({ ...config, dpi_strategy: e.target.value })}
              >
                <option value="split">Split</option>
                <option value="fragment">Fragmentation</option>
                <option value="tls_split">TLS Split</option>
                <option value="http_obfuscate">HTTP Obfuscation</option>
                <option value="auto">Auto</option>
              </select>
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                className="w-4 h-4"
                checked={config.auto_rotate}
                onChange={(e) => setConfig({ ...config, auto_rotate: e.target.checked })}
              />
              <span className="text-sm text-base-200">{t('config.autoRotate')}</span>
            </label>
          </div>
        </div>

        {/* Proxy */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">{t('config.proxy')}</h2>
          </div>
          <div className="card-content space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-base-400 mb-2">{t('config.host')}</label>
                <input
                  type="text"
                  className="input w-full"
                  value={config.proxy_host}
                  onChange={(e) => setConfig({ ...config, proxy_host: e.target.value })}
                />
              </div>
              <div>
                <label className="block text-sm text-base-400 mb-2">{t('config.port')}</label>
                <input
                  type="number"
                  className="input w-full"
                  min="1"
                  max="65535"
                  value={config.proxy_port}
                  onChange={(e) => setConfig({ ...config, proxy_port: parseInt(e.target.value) })}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Logging */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">{t('config.logging')}</h2>
          </div>
          <div className="card-content space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-base-400 mb-2">{t('config.level')}</label>
                <select
                  className="input w-full"
                  value={config.log_level}
                  onChange={(e) => setConfig({ ...config, log_level: parseInt(e.target.value) })}
                >
                  <option value="0">Debug</option>
                  <option value="1">Info</option>
                  <option value="2">Warning</option>
                  <option value="3">Error</option>
                  <option value="4">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-base-400 mb-2">{t('config.retention')} ({t('config.days')})</label>
                <input
                  type="number"
                  className="input w-full"
                  min="1"
                  max="365"
                  value={config.log_retention_days}
                  onChange={(e) => setConfig({ ...config, log_retention_days: parseInt(e.target.value) })}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
