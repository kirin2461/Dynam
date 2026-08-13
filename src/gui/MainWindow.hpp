#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <memory>

#include "ProxyController.hpp"

namespace ncp { class License; }

class StatusPanel;
class NetworkMonitor;
class DPIControl;
class TrafficAnalytics;
class SystemStats;
class ActivityLog;
class LicenseInfo;
class SettingsDialog;

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

protected:
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;

private slots:
    void updateStats();
    void onStartFinished(bool ok, const QString& message);
    void appendLog(const QString& line);

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
    ProxyController* controller_;   // child of this

    // UI Components
    StatusPanel* statusPanel_;
    NetworkMonitor* networkMonitor_;
    DPIControl* dpiControl_;
    TrafficAnalytics* trafficAnalytics_;
    SystemStats* systemStats_;
    ActivityLog* activityLog_;
    LicenseInfo* licenseInfo_;

    // System tray
    QSystemTrayIcon* trayIcon_;
    QMenu* trayMenu_;

    // Timers
    QTimer* statsTimer_;

    // State
    bool isConnected_ = false;
    bool bypassEnabled_ = true;
    bool quitRequested_ = false;
    QString currentTheme_;
};

} // namespace ncp::GUI
