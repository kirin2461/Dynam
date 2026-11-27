import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/Layout';
import DashboardPage from './pages/DashboardPage';
import TrafficPage from './pages/TrafficPage';
import StealthMonitorPage from './pages/StealthMonitorPage';
import ConfigPage from './pages/ConfigPage';
import LogsPage from './pages/LogsPage';
import StatsPage from './pages/StatsPage';
import SettingsPage from './pages/SettingsPage';
// Pentest & Recon
import PentestPage from './pages/PentestPage';
import SiteReconPage from './pages/SiteReconPage';
import DnsToolsPage from './pages/DnsToolsPage';
// Advanced modules
import GenevaPage from './pages/GenevaPage';
import TrafficShapingPage from './pages/TrafficShapingPage';
import AnonymizationPage from './pages/AnonymizationPage';
import TLSSecurityPage from './pages/TLSSecurityPage';
import ServerInvisibilityPage from './pages/ServerInvisibilityPage';
import AdvancedPage from './pages/AdvancedPage';
import AdversaryTestPage from './pages/AdversaryTestPage';
import AutoAttackPage from './pages/AutoAttackPage';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          {/* Core */}
          <Route path="dashboard" element={<DashboardPage />} />
          <Route path="traffic" element={<TrafficPage />} />
          <Route path="stealth" element={<StealthMonitorPage />} />
          <Route path="config" element={<ConfigPage />} />
          <Route path="logs" element={<LogsPage />} />
          <Route path="stats" element={<StatsPage />} />
          <Route path="settings" element={<SettingsPage />} />
          {/* Pentest & Recon */}
          <Route path="pentest" element={<PentestPage />} />
          <Route path="recon" element={<SiteReconPage />} />
          <Route path="dns" element={<DnsToolsPage />} />
          {/* Advanced */}
          <Route path="geneva" element={<GenevaPage />} />
          <Route path="shaping" element={<TrafficShapingPage />} />
          <Route path="anonymization" element={<AnonymizationPage />} />
          <Route path="tls" element={<TLSSecurityPage />} />
          <Route path="invisibility" element={<ServerInvisibilityPage />} />
          <Route path="advanced" element={<AdvancedPage />} />
          <Route path="adversary-test" element={<AdversaryTestPage />} />
          <Route path="auto-attack" element={<AutoAttackPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
