#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <memory>

#include "ProxyController.hpp"
#include "DriverController.hpp"

namespace ncp {
    class Crypto;
    class License;
    class Database;
    namespace DPI {
        class IdentityRotation;
        class AdvancedDPIBypass;
    }
}

class StatusPanel;
class NetworkMonitor;
class DPIControl;
class TrafficAnalytics;
class SystemStats;
class ActivityLog;
class LicenseInfo;
class SettingsDialog;
class ModulesPanel;
class LeakTestPanel;
// PR #118 tool panels (header-only widgets)
class CryptoPanel;
class IdentityPanel;
class DPIMetricsPanel;
class DPIStrategyEditor;
class DnsLookupPanel;
class UrlProbePanel;
class SiteScraperPanel;
class PollerEngine;
class PollerPanel;
class EnterprisePanel;

namespace ncp::GUI {

/**
 * @brief Main application window for Network Control Protocol (Qt6).
 *
 * Native dashboard driving the external ncp.exe process via
 * ProxyController / DriverController:
 *  - Status panel with protection state + start/stop
 *  - DPI bypass strategy controls (proxy mode + driver mode)
 *  - Live network monitor + traffic chart
 *  - System stats, activity log, license panel
 *  - Modules panel + leak test
 *  - Managed Tor (obfs4/Snowflake bridges) via SettingsDialog
 *  - Interface menu: switch to Web UI (ncp-gui.exe) / reset launcher choice
 *
 * Merged with PR #118 (upstream Qt GUI): adds the advanced tool tabs
 * (DPI metrics/strategy, Identity rotation, DNS/URL/Site-Scraper tools,
 * Poller, Crypto), onboarding wizard, themes, profiles, diagnostics and
 * activity-log export. Those panels are backed by in-process core objects
 * (Crypto/Database/IdentityRotation/AdvancedDPIBypass) that are
 * instantiated for the panels but never start packet processing here —
 * the privacy-critical packet path stays in the external ncp.exe process.
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

public slots:
    void onConnectClicked();
    void onDisconnectClicked();
    void onQuickConnectClicked();
    void onBypassToggled(bool enabled);
    void onBypassTechniqueChanged(int index);
    void onSettingsClicked();
    void onUiSettingsClicked();
    void onThemeChanged(const QString& theme);
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onMinimizeToTray();
    void onLicenseActivate();
    void onLicenseDeactivate();
    void onCheckForUpdates();
    void onOpenWebUi();
    void onChooseUiNextTime();
    void onDriverStartClicked();
    void onDriverStopClicked();
    void onRunDiagnostics();
    void onExportLogs();

protected:
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;

private slots:
    void updateStats();
    void onStartFinished(bool ok, const QString& message);
    void appendLog(const QString& line);
    void onDriverLine(const QString& line);
    void onDriverModuleStatus(const QString& module, int state);
    void onDriverFailed(const QString& reason);
    void onDriverFinished(int exitCode);

private:
    void setupUI();
    void setupMenuBar();
    void setupToolBar();
    void setupStatusBar();
    void setupSystemTray();
    void setupConnections();
    void loadSettings();
    void saveSettings();
    void applyTheme(const QString& themeName);
    GuiProxyConfig collectConfig() const;
    void persistConfig(const GuiProxyConfig& cfg);
    /// Tray notification if the tray is visible, status-bar fallback otherwise.
    void notify(const QString& title, const QString& body);
    /// Best-effort refresh of the license panel from the core License object.
    void refreshLicenseStatus();

    // Core (license drives the license panel; best-effort)
    std::unique_ptr<ncp::License> license_;

    // PR #118: in-process core modules backing the advanced tool panels.
    // Instantiated for the panels only; never started for packet processing
    // in this process (that is the external ncp.exe's job).
    std::unique_ptr<ncp::Crypto> crypto_;
    std::unique_ptr<ncp::Database> database_;
    std::unique_ptr<ncp::DPI::IdentityRotation> identityRotation_;
    std::unique_ptr<ncp::DPI::AdvancedDPIBypass> advancedDpi_;

    ProxyController* controller_ = nullptr;   // child of this
    DriverController* driver_ = nullptr;      // ncp.exe run (driver mode)

    // UI Components (base app)
    StatusPanel* statusPanel_ = nullptr;
    NetworkMonitor* networkMonitor_ = nullptr;
    DPIControl* dpiControl_ = nullptr;
    TrafficAnalytics* trafficAnalytics_ = nullptr;
    SystemStats* systemStats_ = nullptr;
    ActivityLog* activityLog_ = nullptr;
    LicenseInfo* licenseInfo_ = nullptr;
    ModulesPanel* modulesPanel_ = nullptr;
    LeakTestPanel* leakTestPanel_ = nullptr;

    // UI Components (PR #118 tool tabs)
    CryptoPanel* cryptoPanel_ = nullptr;
    IdentityPanel* identityPanel_ = nullptr;
    DPIMetricsPanel* dpiMetricsPanel_ = nullptr;
    DPIStrategyEditor* dpiStrategyEditor_ = nullptr;
    DnsLookupPanel* dnsLookupPanel_ = nullptr;
    UrlProbePanel* urlProbePanel_ = nullptr;
    SiteScraperPanel* siteScraperPanel_ = nullptr;
    PollerPanel* pollerPanel_ = nullptr;
    std::unique_ptr<PollerEngine> pollerEngine_;
    // Enterprise tab: CLI enterprise modules (spa/reality/stegodns/porthop/
    // fog/xdp). Unconditional — needs only the external ncp CLI and the
    // linked ncp_core (in-process stegodns), no core runtime objects.
    EnterprisePanel* enterprisePanel_ = nullptr;

    // System tray (nullptr when tray unavailable — e.g. RDP session)
    QSystemTrayIcon* trayIcon_ = nullptr;
    QMenu* trayMenu_ = nullptr;

    // Timers
    QTimer* statsTimer_ = nullptr;

    // State
    bool isConnected_ = false;
    bool bypassEnabled_ = true;
    bool quitRequested_ = false;
    QString currentTheme_;
};

} // namespace ncp::GUI
