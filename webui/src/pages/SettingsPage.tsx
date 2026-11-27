import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Moon, Sun, Save, Server } from 'lucide-react';
import { configApi } from '@/services/api';
import type { AppConfig } from '@/types';

export default function SettingsPage() {
  const { t, i18n } = useTranslation();
  const [language, setLanguage] = useState(i18n.language);
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('theme') as 'dark' | 'light') || 'dark';
  });

  // Engine configuration (real backend)
  const [cfg, setCfg] = useState<AppConfig | null>(null);
  const [cfgMsg, setCfgMsg] = useState('');
  const loadCfg = () => configApi.get().then(setCfg).catch(() => setCfgMsg('Failed to load config'));
  useEffect(() => { loadCfg(); }, []);
  const saveCfg = async () => {
    if (!cfg) return;
    try {
      await configApi.update(cfg);
      setCfgMsg('Configuration saved ✓');
    } catch {
      setCfgMsg('Save failed');
    }
  };

  useEffect(() => {
    // Apply theme
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  const handleLanguageChange = (lang: string) => {
    setLanguage(lang);
    i18n.changeLanguage(lang);
    localStorage.setItem('language', lang);
    document.documentElement.lang = lang;
  };

  const handleThemeChange = (newTheme: 'dark' | 'light') => {
    setTheme(newTheme);
  };

  return (
    <div className="p-8 animate-fade-in">
      <h1 className="text-2xl font-bold text-base-100 mb-8">{t('settings.title')}</h1>

      <div className="card max-w-2xl">
        <div className="card-header">
          <h2 className="card-title">{t('settings.appearance')}</h2>
        </div>
        <div className="card-content space-y-6">
          {/* Language */}
          <div>
            <label className="block text-sm text-base-400 mb-2">{t('settings.language')}</label>
            <select
              className="input w-full"
              value={language}
              onChange={(e) => handleLanguageChange(e.target.value)}
            >
              <option value="ru">Русский</option>
              <option value="en">English</option>
            </select>
          </div>

          {/* Theme */}
          <div>
            <label className="block text-sm text-base-400 mb-2">{t('settings.theme')}</label>
            <div className="flex gap-4">
              <button
                onClick={() => handleThemeChange('dark')}
                className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border-2 transition-colors ${
                  theme === 'dark'
                    ? 'border-accent-blue bg-accent-blue/10 text-accent-blue'
                    : 'border-base-600 text-base-400 hover:border-base-500'
                }`}
              >
                <Moon className="w-5 h-5" />
                {t('settings.dark')}
              </button>
              <button
                onClick={() => handleThemeChange('light')}
                className={`flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg border-2 transition-colors ${
                  theme === 'light'
                    ? 'border-accent-blue bg-accent-blue/10 text-accent-blue'
                    : 'border-base-600 text-base-400 hover:border-base-500'
                }`}
              >
                <Sun className="w-5 h-5" />
                {t('settings.light')}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Engine configuration */}
      <div className="card max-w-2xl mt-6">
        <div className="card-header flex items-center gap-2">
          <Server className="w-5 h-5 text-accent-blue" />
          <h2 className="card-title">Engine</h2>
        </div>
        <div className="card-content space-y-4">
          {!cfg ? (
            <div className="text-sm text-base-500">Loading…</div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-base-400 mb-2">DPI strategy</label>
                  <select className="input w-full" value={cfg.dpi_strategy}
                    onChange={e => setCfg({ ...cfg, dpi_strategy: e.target.value })}>
                    {['balanced','evasive','aggressive','fragile','stealth','paranoid'].map(x =>
                      <option key={x} value={x}>{x}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-base-400 mb-2">Log level (0-4)</label>
                  <input type="number" min={0} max={4} className="input w-full" value={cfg.log_level}
                    onChange={e => setCfg({ ...cfg, log_level: Number(e.target.value) })} />
                </div>
                <div>
                  <label className="block text-sm text-base-400 mb-2">Proxy host</label>
                  <input className="input w-full" placeholder="127.0.0.1" value={cfg.proxy_host}
                    onChange={e => setCfg({ ...cfg, proxy_host: e.target.value })} />
                </div>
                <div>
                  <label className="block text-sm text-base-400 mb-2">Proxy port</label>
                  <input type="number" className="input w-full" value={cfg.proxy_port}
                    onChange={e => setCfg({ ...cfg, proxy_port: Number(e.target.value) })} />
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm text-base-300">
                <input type="checkbox" checked={cfg.auto_rotate}
                  onChange={e => setCfg({ ...cfg, auto_rotate: e.target.checked })} />
                Auto-rotate strategy
              </label>
              <div className="flex items-center gap-3">
                <button onClick={saveCfg} className="btn btn-primary flex items-center gap-2">
                  <Save className="w-4 h-4" /> Save
                </button>
                {cfgMsg && <span className="text-sm text-accent-green">{cfgMsg}</span>}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}