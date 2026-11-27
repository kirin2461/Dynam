import { useState, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { logsApi } from '@/services/api';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { LogEntry } from '@/types';
import { LogLevel } from '@/types';
import { Trash2 } from 'lucide-react';

export default function LogsPage() {
  const { t } = useTranslation();
  const { logs: wsLogs } = useWebSocket();
  
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [levelFilter, setLevelFilter] = useState<number>(-1);
  const [search, setSearch] = useState('');

  useEffect(() => {
    logsApi.get().then(data => setLogs(data.logs)).catch(console.error);
  }, []);

  const wsLenRef = useRef(0);
  useEffect(() => {
    if (wsLogs.length > wsLenRef.current) {
      const fresh = wsLogs.slice(wsLenRef.current);
      setLogs(prev => {
        const seen = new Set(prev.map(l => l.timestamp + '|' + l.message));
        const add = fresh.filter(l => !seen.has(l.timestamp + '|' + l.message));
        return add.length ? [...prev, ...add] : prev;
      });
    }
    wsLenRef.current = wsLogs.length;
  }, [wsLogs]);

  const handleClear = async () => {
    try {
      await logsApi.clear();
      setLogs([]);
    } catch (error) {
      console.error('Failed to clear logs:', error);
    }
  };

  const filteredLogs = logs.filter(log => {
    if (levelFilter >= 0 && log.level !== levelFilter) return false;
    if (search && !log.message.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const getLevelBadge = (level: number): string => {
    switch (level) {
      case LogLevel.Debug: return 'badge-info';
      case LogLevel.Info: return 'badge-success';
      case LogLevel.Warning: return 'badge-warning';
      case LogLevel.Error: return 'badge-danger';
      case LogLevel.Critical: return 'bg-accent-red text-white';
      default: return 'badge-info';
    }
  };

  const getLevelName = (level: number): string => {
    switch (level) {
      case LogLevel.Debug: return t('logs.debug');
      case LogLevel.Info: return t('logs.info');
      case LogLevel.Warning: return t('logs.warning');
      case LogLevel.Error: return t('logs.error');
      case LogLevel.Critical: return t('logs.critical');
      default: return 'Unknown';
    }
  };

  return (
    <div className="p-8 animate-fade-in">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-base-100">{t('logs.title')}</h1>
        <button onClick={handleClear} className="btn btn-danger">
          <Trash2 className="w-4 h-4 mr-2" />
          {t('logs.clear')}
        </button>
      </div>

      {/* Filters */}
      <div className="card mb-6">
        <div className="card-content">
          <div className="flex gap-4">
            <div className="flex-1">
              <label className="block text-sm text-base-400 mb-2">{t('logs.filter')}</label>
              <select
                className="input w-full"
                value={levelFilter}
                onChange={(e) => setLevelFilter(parseInt(e.target.value))}
              >
                <option value="-1">{t('logs.all')}</option>
                <option value="0">{t('logs.debug')}</option>
                <option value="1">{t('logs.info')}</option>
                <option value="2">{t('logs.warning')}</option>
                <option value="3">{t('logs.error')}</option>
                <option value="4">{t('logs.critical')}</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-sm text-base-400 mb-2">{t('logs.search')}</label>
              <input
                type="text"
                className="input w-full"
                placeholder={t('logs.search')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Logs table */}
      <div className="card">
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          <table className="w-full">
            <thead className="bg-surface-1 border-b border-base-700 sticky top-0">
              <tr>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400 w-48">{t('logs.time')}</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400 w-24">{t('logs.level')}</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400 w-32">{t('logs.source')}</th>
                <th className="text-left px-6 py-3 text-sm font-medium text-base-400">{t('logs.message')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-12 text-center text-base-500">
                    {t('logs.noLogs')}
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log, idx) => (
                  <tr key={idx} className="hover:bg-surface-1 transition-colors">
                    <td className="px-6 py-3 font-mono text-xs text-base-400">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`badge ${getLevelBadge(log.level)}`}>
                        {getLevelName(log.level)}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-base-200">{log.source}</td>
                    <td className="px-6 py-3 text-sm text-base-300 font-mono">{log.message}</td>
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
