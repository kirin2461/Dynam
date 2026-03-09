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
#include <QTextBrowser>  // always available
#include <QUrl>
#include <QLabel>

#ifdef HAVE_QTWEBENGINE
#include <QWebEngineView>  // only when Qt WebEngine module is present
#endif

namespace ncp::GUI {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , isConnected_(false)
    , bypassEnabled_(false)
    , currentTheme_("dark_pro") {
    
    // Initialize core modules
    crypto_ = std::make_unique<ncp::Crypto>();
    license_ = std::make_unique<ncp::License>();
    database_ = std::make_unique<ncp::Database>();
    network_ = std::make_unique<ncp::Network>();
    
    // Setup UI
    setupUI();
    setupMenuBar();
    setupToolBar();
    setupStatusBar();
    setupCentralWidget();  // replaces native widgets with web UI wrapper
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

// ==================== setupCentralWidget ====================
//
// Replaces the native widget grid with a thin web-UI wrapper.
//
// The NCP web interface runs at http://localhost:8080 (started by the
// backend service).  The Qt window is deliberately kept minimal:
//   - With HAVE_QTWEBENGINE: QWebEngineView navigates to that URL.
//     The full Chromium-based engine renders the React/HTML UI.
//   - Without it: QTextBrowser shows a simple HTML status page with
//     a clickable hyperlink; QTextBrowser can open URLs via
//     QDesktopServices::openUrl (handled by its anchorClicked signal).
//
// Either path:
//   1. Creates a QWidget container with a QVBoxLayout.
//   2. Adds a small info label at the top (always visible).
//   3. Adds the web view / text browser below.
//   4. Calls setCentralWidget() to replace the setupUI() grid.
//
void MainWindow::setupCentralWidget() {
    static constexpr char WEB_UI_URL[] = "http://localhost:8080";

    QWidget* container = new QWidget(this);
    QVBoxLayout* layout = new QVBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);

    // Thin info bar at the top
    QLabel* infoLabel = new QLabel(
        tr("NCP Web Interface — <a href=\"%1\">%1</a>").arg(QLatin1String(WEB_UI_URL)),
        container
    );
    infoLabel->setTextFormat(Qt::RichText);
    infoLabel->setTextInteractionFlags(Qt::TextBrowserInteraction);
    infoLabel->setOpenExternalLinks(true);
    infoLabel->setContentsMargins(8, 4, 8, 4);
    layout->addWidget(infoLabel, 0 /* stretch=0: fixed height */);

#ifdef HAVE_QTWEBENGINE
    // ── QtWebEngine path ─────────────────────────────────────────────────────
    // QWebEngineView embeds a full Chromium engine; it loads the React-based
    // web UI served at localhost:8080 as if it were a regular browser tab.
    webView_ = new QWebEngineView(container);
    webView_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Show a loading placeholder until the backend is ready
    webView_->setHtml(
        QStringLiteral(
            "<html><body style='background:#1a1a2e;color:#e0e0e0;font-family:sans-serif;"
            "display:flex;align-items:center;justify-content:center;height:100vh;'>"
            "<div style='text-align:center'>"
            "<h2>NCP</h2>"
            "<p>Connecting to web interface…</p>"
            "<p style='font-size:12px;opacity:0.6'>"
            "Ensure the NCP backend service is running on port 8080."
            "</p></div></body></html>"
        )
    );

    // After a short delay, try to load the actual URL
    // (gives the backend service time to start up)
    QTimer::singleShot(1500 /* ms */, webView_, [this]() {
        webView_->load(QUrl(QLatin1String(WEB_UI_URL)));
    });

    layout->addWidget(webView_, 1 /* stretch=1: fills all remaining space */);

    // Reload shortcut: F5 reloads the web view
    auto* reloadAction = new QAction(tr("Reload Web UI"), this);
    reloadAction->setShortcut(QKeySequence::Refresh);
    connect(reloadAction, &QAction::triggered, webView_, &QWebEngineView::reload);
    addAction(reloadAction);

#else
    // ── QTextBrowser fallback path ───────────────────────────────────────────
    // QTextBrowser cannot render JavaScript, but it can display a rich-text
    // HTML landing page that opens the external URL in the system browser.
    textBrowser_ = new QTextBrowser(container);
    textBrowser_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    textBrowser_->setOpenExternalLinks(true);
    textBrowser_->setOpenLinks(true);

    // Build an informational HTML page
    const QString html = QStringLiteral(
        "<html>"
        "<head><style>"
        "body { background:#1a1a2e; color:#e0e0e0; font-family:sans-serif; margin:40px; }"
        "h1   { color:#7e57c2; }"
        "a    { color:#64b5f6; }"
        ".note { font-size:12px; opacity:0.7; margin-top:16px; }"
        "</style></head>"
        "<body>"
        "<h1>NCP Network Control Protocol</h1>"
        "<p>The web interface is served by the NCP backend at:</p>"
        "<p><a href=\"%1\">%1</a></p>"
        "<p>Click the link to open it in your default browser, or install "
        "the <b>Qt WebEngine</b> module and recompile with "
        "<code>-DHAVE_QTWEBENGINE</code> to embed it here.</p>"
        "<p class='note'>Build without HAVE_QTWEBENGINE — QTextBrowser fallback active.</p>"
        "</body></html>"
    ).arg(QLatin1String(WEB_UI_URL));

    textBrowser_->setHtml(html);
    layout->addWidget(textBrowser_, 1);

#endif // HAVE_QTWEBENGINE

    // Replace whatever setupUI() set as central widget
    setCentralWidget(container);
    statusBar()->showMessage(tr("Web UI: ") + QLatin1String(WEB_UI_URL));
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
        network_->enable_bypass(ncp::Network::BypassTechnique::TCP_FRAGMENTATION);
        database_->log_activity("bypass", "DPI bypass enabled");
    } else {
        network_->disable_bypass();
        database_->log_activity("bypass", "DPI bypass disabled");
    }
    dpiControl_->setBypassEnabled(enabled);
}

void MainWindow::onBypassTechniqueChanged(int index) {
    auto technique = static_cast<ncp::Network::BypassTechnique>(index);
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

} // namespace ncp::GUI
