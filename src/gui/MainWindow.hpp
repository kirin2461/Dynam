#pragma once

#include <QMainWindow>
#include <QStackedWidget>
#include <QSystemTrayIcon>
#include <QTimer>
#include <memory>

// Forward declarations
namespace ncp {
    class Crypto;
    class License;
    class Database;
    class Network;
}

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
 * @brief Main application window for Network Control Protocol
 * 
 * Implements a modern dark-themed dashboard with:
 * - Status panel with connection info
 * - Network flow monitoring
 * - DPI bypass controls
 * - Traffic analytics
 * - System statistics
 * - Activity logging
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

    // Prevent copying
    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

public slots:
    // Connection control
    void onConnectClicked();
    void onDisconnectClicked();
    void onQuickConnectClicked();
    
    // DPI Bypass control
    void onBypassToggled(bool enabled);
    void onBypassTechniqueChanged(int index);
    
    // Settings
    void onSettingsClicked();
    void onThemeChanged(const QString& theme);
    
    // System tray
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onMinimizeToTray();
    
    // License
    void onLicenseActivate();
    void onLicenseDeactivate();
    
    // Updates
    void onCheckForUpdates();

protected:
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;

private slots:
    void updateStats();
    void updateNetworkFlow();
    void updateActivityLog();
    void refreshLicenseStatus();

private:
    void setupUI();
    void setupMenuBar();
    void setupToolBar();
    void setupStatusBar();
    void setupCentralWidget();
    void setupSystemTray();
    void setupConnections();
    void loadSettings();
    void saveSettings();
    void applyTheme(const QString& themeName);
    QString loadStyleSheet(const QString& themeName);

    // Core modules
    std::unique_ptr<ncp::Crypto> crypto_;
    std::unique_ptr<ncp::License> license_;
    std::unique_ptr<ncp::Database> database_;
    std::unique_ptr<ncp::Network> network_;

    // UI Components
    QStackedWidget* stackedWidget_;
    StatusPanel* statusPanel_;
    NetworkMonitor* networkMonitor_;
    DPIControl* dpiControl_;
    TrafficAnalytics* trafficAnalytics_;
    SystemStats* systemStats_;
    ActivityLog* activityLog_;
    LicenseInfo* licenseInfo_;
    SettingsDialog* settingsDialog_;

    // System tray
    QSystemTrayIcon* trayIcon_;
    QMenu* trayMenu_;

    // Timers
    QTimer* statsTimer_;
    QTimer* networkTimer_;
    QTimer* logTimer_;

    // State
    bool isConnected_;
    bool bypassEnabled_;
    QString currentTheme_;
};

} // namespace ncp::GUI
