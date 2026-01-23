#include "MainWindow.hpp"
#include "widgets/StatusPanel.hpp"
#include "widgets/NetworkMonitor.hpp"
#include "widgets/DPIControl.hpp"
#include "widgets/TrafficAnalytics.hpp"
#include "widgets/SystemStats.hpp"
#include "widgets/ActivityLog.hpp"
#include "widgets/LicenseInfo.hpp"

#include "../core/include/ncp_crypto.hpp"
#include "../core/include/ncp_license.hpp"
#include "../core/include/ncp_db.hpp"
#include "../core/include/ncp_network.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QAction>
#include <QMenu>
#include <QMessageBox>
#include <QSettings>
#include <QFile>
#include <QCloseEvent>
#include <QApplication>

namespace NCP::GUI {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , isConnected_(false)
    , bypassEnabled_(false)
    , currentTheme_("dark_pro") {
    
    // Initialize core modules
    crypto_ = std::make_unique<NCP::Crypto>();
    license_ = std::make_unique<NCP::License>();
    database_ = std::make_unique<NCP::Database>();
    network_ = std::make_unique<NCP::Network>();
    
    // Setup UI
    setupUI();
    setupMenuBar();
    setupToolBar();
    setupStatusBar();
    setupSystemTray();
    setupConnections();
    
    // Load settings
    loadSettings();
    applyTheme(currentTheme_);
    
    // Setup timers
    statsTimer_ = new QTimer(this);
    connect(statsTimer_, &QTimer::timeout, this, &MainWindow::updateStats);
    statsTimer_->start(1000);  // Update every second
    
    networkTimer_ = new QTimer(this);
    connect(networkTimer_, &QTimer::timeout, this, &MainWindow::updateNetworkFlow);
    networkTimer_->start(500);  // Update every 500ms
    
    logTimer_ = new QTimer(this);
    connect(logTimer_, &QTimer::timeout, this, &MainWindow::updateActivityLog);
    logTimer_->start(2000);  // Update every 2 seconds
    
    setWindowTitle("NCP - Network Control Protocol v2.0");
    setMinimumSize(1200, 800);
    resize(1400, 900);
}

MainWindow::~MainWindow() {
    saveSettings();
}

void MainWindow::setupUI() {
    // Central widget with grid layout
    QWidget* central = new QWidget(this);
    setCentralWidget(central);
    
    QGridLayout* mainLayout = new QGridLayout(central);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(10, 10, 10, 10);
    
    // Row 0: Status Panel (full width)
    statusPanel_ = new StatusPanel(this);
    mainLayout->addWidget(statusPanel_, 0, 0, 1, 3);
    
    // Row 1: Network Monitor | DPI Control | Traffic Analytics
    networkMonitor_ = new NetworkMonitor(this);
    mainLayout->addWidget(networkMonitor_, 1, 0);
    
    dpiControl_ = new DPIControl(this);
    mainLayout->addWidget(dpiControl_, 1, 1);
    
    trafficAnalytics_ = new TrafficAnalytics(this);
    mainLayout->addWidget(trafficAnalytics_, 1, 2);
    
    // Row 2: System Stats | Activity Log | License Info
    systemStats_ = new SystemStats(this);
    mainLayout->addWidget(systemStats_, 2, 0);
    
    activityLog_ = new ActivityLog(this);
    mainLayout->addWidget(activityLog_, 2, 1);
    
    licenseInfo_ = new LicenseInfo(this);
    mainLayout->addWidget(licenseInfo_, 2, 2);
    
    // Set row/column stretch
    mainLayout->setRowStretch(0, 1);
    mainLayout->setRowStretch(1, 2);
    mainLayout->setRowStretch(2, 2);
    mainLayout->setColumnStretch(0, 1);
    mainLayout->setColumnStretch(1, 1);
    mainLayout->setColumnStretch(2, 1);
}

void MainWindow::setupMenuBar() {
    QMenuBar* menuBar = this->menuBar();
    
    // File menu
    QMenu* fileMenu = menuBar->addMenu(tr("&File"));
    fileMenu->addAction(tr("&Settings"), this, &MainWindow::onSettingsClicked);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("E&xit"), this, &QMainWindow::close);
    
    // Connection menu
    QMenu* connMenu = menuBar->addMenu(tr("&Connection"));
    connMenu->addAction(tr("&Connect"), this, &MainWindow::onConnectClicked);
    connMenu->addAction(tr("&Disconnect"), this, &MainWindow::onDisconnectClicked);
    connMenu->addAction(tr("&Quick Connect"), this, &MainWindow::onQuickConnectClicked);
    
    // Tools menu
    QMenu* toolsMenu = menuBar->addMenu(tr("&Tools"));
    QAction* bypassAction = toolsMenu->addAction(tr("&DPI Bypass"));
    bypassAction->setCheckable(true);
    connect(bypassAction, &QAction::toggled, this, &MainWindow::onBypassToggled);
    
    // Help menu
    QMenu* helpMenu = menuBar->addMenu(tr("&Help"));
    helpMenu->addAction(tr("Check for &Updates"), this, &MainWindow::onCheckForUpdates);
    helpMenu->addAction(tr("&About"), [this]() {
        QMessageBox::about(this, tr("About NCP"),
            tr("Network Control Protocol v2.0\n\n"
               "High-performance network management\n"
               "with DPI bypass capabilities."));
    });
}

void MainWindow::setupToolBar() {
    QToolBar* toolbar = addToolBar(tr("Main"));
    toolbar->setMovable(false);
    
    toolbar->addAction(tr("Connect"), this, &MainWindow::onConnectClicked);
    toolbar->addAction(tr("Disconnect"), this, &MainWindow::onDisconnectClicked);
    toolbar->addSeparator();
    toolbar->addAction(tr("Settings"), this, &MainWindow::onSettingsClicked);
}

void MainWindow::setupStatusBar() {
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::setupSystemTray() {
    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setToolTip("NCP - Network Control Protocol");
    
    trayMenu_ = new QMenu(this);
    trayMenu_->addAction(tr("Show"), this, &QMainWindow::show);
    trayMenu_->addAction(tr("Connect"), this, &MainWindow::onConnectClicked);
    trayMenu_->addAction(tr("Disconnect"), this, &MainWindow::onDisconnectClicked);
    trayMenu_->addSeparator();
    trayMenu_->addAction(tr("Exit"), this, &QMainWindow::close);
    
    trayIcon_->setContextMenu(trayMenu_);
    connect(trayIcon_, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayIconActivated);
    
    trayIcon_->show();
}

void MainWindow::setupConnections() {
    // Connect widget signals
    connect(dpiControl_, &DPIControl::bypassToggled,
            this, &MainWindow::onBypassToggled);
    connect(dpiControl_, &DPIControl::techniqueChanged,
            this, &MainWindow::onBypassTechniqueChanged);
    connect(licenseInfo_, &LicenseInfo::activateClicked,
            this, &MainWindow::onLicenseActivate);
}

void MainWindow::loadSettings() {
    QSettings settings("NCP", "NetworkControlProtocol");
    currentTheme_ = settings.value("theme", "dark_pro").toString();
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());
}

void MainWindow::saveSettings() {
    QSettings settings("NCP", "NetworkControlProtocol");
    settings.setValue("theme", currentTheme_);
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
}

void MainWindow::applyTheme(const QString& themeName) {
    QString stylesheet = loadStyleSheet(themeName);
    qApp->setStyleSheet(stylesheet);
    currentTheme_ = themeName;
}

QString MainWindow::loadStyleSheet(const QString& themeName) {
    QString path = QString(":/themes/%1.qss").arg(themeName);
    QFile file(path);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return QString::fromUtf8(file.readAll());
    }
    return QString();
}

// Slots implementation
void MainWindow::onConnectClicked() {
    if (!isConnected_) {
        isConnected_ = true;
        statusPanel_->setConnected(true);
        statusBar()->showMessage(tr("Connected"));
        database_->log_activity("connection", "Connected to network");
    }
}

void MainWindow::onDisconnectClicked() {
    if (isConnected_) {
        isConnected_ = false;
        statusPanel_->setConnected(false);
        statusBar()->showMessage(tr("Disconnected"));
        database_->log_activity("connection", "Disconnected from network");
    }
}

void MainWindow::onQuickConnectClicked() {
    onConnectClicked();
}

void MainWindow::onBypassToggled(bool enabled) {
    bypassEnabled_ = enabled;
    if (enabled) {
        network_->enable_bypass(NCP::Network::BypassTechnique::TCP_FRAGMENTATION);
        database_->log_activity("bypass", "DPI bypass enabled");
    } else {
        network_->disable_bypass();
        database_->log_activity("bypass", "DPI bypass disabled");
    }
    dpiControl_->setBypassEnabled(enabled);
}

void MainWindow::onBypassTechniqueChanged(int index) {
    auto technique = static_cast<NCP::Network::BypassTechnique>(index);
    network_->enable_bypass(technique);
}

void MainWindow::onSettingsClicked() {
    // Open settings dialog
}

void MainWindow::onThemeChanged(const QString& theme) {
    applyTheme(theme);
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onMinimizeToTray() {
    hide();
    trayIcon_->showMessage("NCP", tr("Application minimized to tray"));
}

void MainWindow::onLicenseActivate() {
    // Activate license
    QString hwid = QString::fromStdString(license_->get_hwid());
    licenseInfo_->setHWID(hwid);
}

void MainWindow::onLicenseDeactivate() {
    // Deactivate license
}

void MainWindow::onCheckForUpdates() {
    QMessageBox::information(this, tr("Updates"),
        tr("You are running the latest version."));
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (trayIcon_->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}

void MainWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::WindowStateChange) {
        if (isMinimized()) {
            onMinimizeToTray();
        }
    }
    QMainWindow::changeEvent(event);
}

void MainWindow::updateStats() {
    auto stats = network_->get_stats();
    systemStats_->updateStats(stats.bytes_sent, stats.bytes_received,
                               stats.packets_sent, stats.packets_received);
}

void MainWindow::updateNetworkFlow() {
    networkMonitor_->refresh();
}

void MainWindow::updateActivityLog() {
    auto logs = database_->get_recent_activity(50);
    activityLog_->setLogs(logs);
}

void MainWindow::refreshLicenseStatus() {
    auto info = license_->get_license_info("license.dat");
    licenseInfo_->updateInfo(info);
}

} // namespace NCP::GUI
