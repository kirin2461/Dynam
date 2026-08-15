#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <memory>

#include "ProxyController.hpp"
#include "DriverController.hpp"

namespace ncp { class License; }

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

namespace ncp::GUI {

/**
 * @brief Main application window for Network Control Protocol (Qt6).
 *
 * Native dashboard driving ncp_core in-process via ProxyController:
 *  - Status panel with protection state + start/stop
 *  - DPI bypass strategy controls
 *  - Live network monitor + traffic chart
 *  - System stats, activity log, license panel
 *  - Managed Tor (obfs4/Snowflake bridges) via SettingsDialog
 *  - Interface menu: switch to Web UI (ncp-gui.exe) / reset launcher choice
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

    // Core
    std::unique_ptr<ncp::License> license_;
    ProxyController* controller_ = nullptr;   // child of this
    DriverController* driver_ = nullptr;      // ncp.exe run (driver mode)

    // UI Components
    StatusPanel* statusPanel_ = nullptr;
    NetworkMonitor* networkMonitor_ = nullptr;
    DPIControl* dpiControl_ = nullptr;
    TrafficAnalytics* trafficAnalytics_ = nullptr;
    SystemStats* systemStats_ = nullptr;
    ActivityLog* activityLog_ = nullptr;
    LicenseInfo* licenseInfo_ = nullptr;
    ModulesPanel* modulesPanel_ = nullptr;
    LeakTestPanel* leakTestPanel_ = nullptr;

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
