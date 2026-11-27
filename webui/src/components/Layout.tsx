import { Outlet, NavLink } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { LayoutDashboard, Network, Shield, Settings, ScrollText, BarChart3, Cog, FlaskConical, Globe, Dna, Activity, Eye, Lock, Zap, Key, Radio, Target, Bot } from 'lucide-react';
import { useWebSocket } from '@/hooks/useWebSocket';

export default function Layout() {
  const { t } = useTranslation();
  const { connected } = useWebSocket();

  const navGroups = [
    {
      label: 'Core',
      items: [
        { to: '/dashboard', icon: LayoutDashboard, label: t('nav.dashboard') },
        { to: '/traffic', icon: Network, label: t('nav.traffic') },
        { to: '/stealth', icon: Shield, label: t('nav.stealth', 'Stealth Monitor') },
        { to: '/config', icon: Settings, label: t('nav.config') },
        { to: '/logs', icon: ScrollText, label: t('nav.logs') },
        { to: '/stats', icon: BarChart3, label: t('nav.stats') },
        { to: '/settings', icon: Cog, label: t('nav.settings') },
      ],
    },
    {
      label: 'Pentest & Recon',
      items: [
        { to: '/pentest', icon: FlaskConical, label: 'Pentest' },
        { to: '/auto-attack', icon: Bot, label: 'Auto-Attack' },
        { to: '/adversary-test', icon: Target, label: 'Attack Testing' },
        { to: '/recon', icon: Globe, label: 'Site Recon' },
        { to: '/dns', icon: Radio, label: 'DNS Tools' },
      ],
    },
    {
      label: 'Advanced',
      items: [
        { to: '/geneva', icon: Dna, label: 'Geneva Engine' },
        { to: '/shaping', icon: Activity, label: 'Traffic Shaping' },
        { to: '/anonymization', icon: Eye, label: 'Anonymization' },
        { to: '/tls', icon: Lock, label: 'TLS Security' },
        { to: '/invisibility', icon: Key, label: 'Server Invisibility' },
        { to: '/advanced', icon: Zap, label: 'Advanced Techniques' },
      ],
    },
  ];

  return (
    <div className="min-h-screen bg-surface flex">
      {/* Sidebar */}
      <aside className="w-64 bg-surface-2 border-r border-base-700 flex flex-col">
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-base-700">
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none" className="mr-3">
            <rect x="1" y="1" width="30" height="30" rx="6" stroke="#22d3ee" strokeWidth="1.5" />
            <circle cx="16" cy="16" r="7" stroke="#22d3ee" strokeWidth="1.5" />
            <circle cx="16" cy="16" r="2.5" fill="#22d3ee" />
            <line x1="16" y1="1" x2="16" y2="9" stroke="#22d3ee" strokeWidth="1.5" />
            <line x1="16" y1="23" x2="16" y2="31" stroke="#22d3ee" strokeWidth="1.5" />
            <line x1="1" y1="16" x2="9" y2="16" stroke="#22d3ee" strokeWidth="1.5" />
            <line x1="23" y1="16" x2="31" y2="16" stroke="#22d3ee" strokeWidth="1.5" />
          </svg>
          <div>
            <div className="font-bold text-base-100">{t('app.title')}</div>
            <div className="text-xs text-base-500">v2.0.0</div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 overflow-y-auto">
          {navGroups.map((group) => (
            <div key={group.label} className="mb-4">
              <div className="px-6 py-1 text-[10px] font-semibold uppercase text-base-600 tracking-wider">
                {group.label}
              </div>
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center px-6 py-2 text-sm transition-colors ${
                      isActive
                        ? 'bg-accent-blue/10 text-accent-blue border-r-2 border-accent-blue'
                        : 'text-base-400 hover:bg-surface-1 hover:text-base-200'
                    }`
                  }
                >
                  <item.icon className="w-4 h-4 mr-3" />
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* Connection status */}
        <div className="p-4 border-t border-base-700">
          <div className="flex items-center text-sm">
            <div className={`w-2 h-2 rounded-full mr-2 ${connected ? 'bg-accent-green' : 'bg-accent-red'}`} />
            <span className="text-base-400">
              {connected ? t('dashboard.connected') : t('dashboard.disconnected')}
            </span>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
