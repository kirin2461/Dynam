#include "MainWindow.hpp"
#include "widgets/StatusPanel.hpp"
#include "widgets/NetworkMonitor.hpp"
#include "widgets/DPIControl.hpp"
#include "widgets/TrafficAnalytics.hpp"
#include "widgets/SystemStats.hpp"
#include "widgets/ActivityLog.hpp"
#include "widgets/LicenseInfo.hpp"
#include "widgets/SettingsDialog.hpp"
#include "widgets/CryptoPanel.hpp"
#include "widgets/LicenseActivationDialog.hpp"
#include "widgets/AboutDialog.hpp"
#include "widgets/IdentityPanel.hpp"
#include "widgets/DPIMetricsPanel.hpp"
#include "widgets/Themes.hpp"
#include "widgets/OnboardingWizard.hpp"
#include "widgets/StatusSummary.hpp"
#include "widgets/DiagnosticsDialog.hpp"
#include "widgets/DnsLookupPanel.hpp"
#include "widgets/UrlProbePanel.hpp"
#include "widgets/DPIStrategyEditor.hpp"
#include "widgets/Profiles.hpp"
#include "widgets/PollerEngine.hpp"
#include "widgets/PollerPanel.hpp"
#include <QTabWidget>
#include <QElapsedTimer>

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
#include <QDir>
#include <QProcess>
#include <QDesktopServices>
#include <QFileDialog>
#include <QTextStream>
#include <QDateTime>

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
    crypto_   = std::make_unique<ncp::Crypto>();
    license_  = std::make_unique<ncp::License>();
    database_ = std::make_unique<ncp::Database>();
    network_  = std::make_unique<ncp::Network>();

    // Identity rotation: seed an 8-identity pool so rotate-now has options.
    // generate_pool fills with random_device() entries; user can hit
    // Regenerate to refresh, Rotate now to step.
    identityRotation_ = std::make_unique<ncp::DPI::IdentityRotation>();
    identityRotation_->generate_pool(8);

    // Advanced DPI: instantiated but not started here. process_outgoing
    // wiring is a follow-up; right now the panel just shows live counters
    // (all zero until something pumps packets through it).
    advancedDpi_ = std::make_unique<ncp::DPI::AdvancedDPIBypass>();

    // Poller engine: independent of Connect state. It owns its own timers
    // and runs probes whenever they're due, even when bypass is off.
    // Persisted targets at ~/.dynam/poller.json reload here.
    pollerEngine_ = std::make_unique<PollerEngine>();
    
    // Setup UI
    setupUI();
    setupMenuBar();
    setupToolBar();
    setupStatusBar();
    // setupCentralWidget(): SKIPPED — it replaces the central widget set by
    // setupUI() above, which Qt-reparents (and then deletes) every panel widget.
    // The replacement was a wrapper for a localhost:8080 web UI that isn't
    // running in this build, so we keep the native panel grid.
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

    // First-launch onboarding. Deferred via singleShot so the main window
    // is fully visible before the modal wizard appears.
    if (OnboardingWizard::shouldRun()) {
        QTimer::singleShot(150, this, [this]{
            auto* wiz = new OnboardingWizard(this);
            wiz->setAttribute(Qt::WA_DeleteOnClose);
            connect(wiz, &QDialog::finished, this, [this](int){
                // Re-apply theme + maybe auto-connect now that the wizard
                // has persisted the user's choices.
                Themes::apply();
                if (QSettings().value("ui/auto_connect", false).toBool()) {
                    QTimer::singleShot(0, this, &MainWindow::onConnectClicked);
                }
            });
            wiz->show();
        });
    } else if (QSettings().value("ui/auto_connect", false).toBool()) {
        // No wizard, but auto-connect is set — fire after first paint.
        QTimer::singleShot(0, this, &MainWindow::onConnectClicked);
    }
}

MainWindow::~MainWindow() {
    // Stop timers first so queued timeouts don't fire on half-destroyed widgets.
    if (statsTimer_)   statsTimer_->stop();
    if (networkTimer_) networkTimer_->stop();
    if (logTimer_)     logTimer_->stop();
    saveSettings();
}

void MainWindow::setupUI() {
    // Five-tab layout. StatusPanel sits at the top as a always-visible
    // header; the QTabWidget lives below it. Widget creation order is
    // independent of the layout — every widget has `this` as parent so
    // it's owned by MainWindow, not by whichever tab page it ends up in.
    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* root = new QVBoxLayout(central);
    root->setSpacing(6);
    root->setContentsMargins(8, 8, 8, 8);

    statusPanel_ = new StatusPanel(this);
    root->addWidget(statusPanel_);

    auto* tabs = new QTabWidget(this);
    root->addWidget(tabs, 1);

    // ─── Overview ────────────────────────────────────────────────────────
    auto* overview = new QWidget(tabs);
    auto* overviewLayout = new QGridLayout(overview);
    systemStats_      = new SystemStats(this);
    trafficAnalytics_ = new TrafficAnalytics(this);
    overviewLayout->addWidget(systemStats_,      0, 0);
    overviewLayout->addWidget(trafficAnalytics_, 0, 1, 1, 2);
    overviewLayout->setColumnStretch(1, 1);
    overviewLayout->setColumnStretch(2, 1);
    tabs->addTab(overview, tr("Overview"));

    // ─── Network ─────────────────────────────────────────────────────────
    auto* networkTab = new QWidget(tabs);
    auto* networkLayout = new QVBoxLayout(networkTab);
    networkMonitor_ = new NetworkMonitor(this);
    networkLayout->addWidget(networkMonitor_);
    tabs->addTab(networkTab, tr("Network"));

    // ─── DPI ─────────────────────────────────────────────────────────────
    auto* dpiTab = new QWidget(tabs);
    auto* dpiLayout = new QVBoxLayout(dpiTab);
    dpiControl_       = new DPIControl(this);
    dpiMetricsPanel_  = new DPIMetricsPanel(advancedDpi_.get(), this);
    dpiStrategyEditor_= new DPIStrategyEditor(advancedDpi_.get(), this);
    auto* dpiInnerTabs = new QTabWidget(dpiTab);
    dpiInnerTabs->addTab(dpiMetricsPanel_,   tr("Metrics"));
    dpiInnerTabs->addTab(dpiStrategyEditor_, tr("Strategy"));
    dpiLayout->addWidget(dpiControl_);
    dpiLayout->addWidget(dpiInnerTabs, 1);
    tabs->addTab(dpiTab, tr("DPI"));

    // ─── Identity ────────────────────────────────────────────────────────
    identityPanel_ = new IdentityPanel(identityRotation_.get(), this);
    tabs->addTab(identityPanel_, tr("Identity"));

    // ─── Tools (DNS + URL probe) ─────────────────────────────────────────
    auto* toolsTab = new QWidget(tabs);
    auto* toolsLayout = new QVBoxLayout(toolsTab);
    auto* toolsInner = new QTabWidget(toolsTab);
    dnsLookupPanel_ = new DnsLookupPanel(this);
    urlProbePanel_  = new UrlProbePanel(this);
    toolsInner->addTab(dnsLookupPanel_, tr("DNS Lookup"));
    toolsInner->addTab(urlProbePanel_,  tr("URL Probe"));
    toolsLayout->addWidget(toolsInner);
    tabs->addTab(toolsTab, tr("Tools"));

    // ─── Poller ──────────────────────────────────────────────────────────
    pollerPanel_ = new PollerPanel(pollerEngine_.get(), this);
    tabs->addTab(pollerPanel_, tr("Poller"));

    // ─── Crypto ──────────────────────────────────────────────────────────
    cryptoPanel_ = new CryptoPanel(crypto_.get(), this);
    tabs->addTab(cryptoPanel_, tr("Crypto"));

    // ─── License ─────────────────────────────────────────────────────────
    auto* licenseTab = new QWidget(tabs);
    auto* licenseLayout = new QVBoxLayout(licenseTab);
    licenseInfo_ = new LicenseInfo(this);
    licenseLayout->addWidget(licenseInfo_);
    licenseLayout->addStretch(1);
    tabs->addTab(licenseTab, tr("License"));

    // ─── Logs ────────────────────────────────────────────────────────────
    auto* logsTab = new QWidget(tabs);
    auto* logsLayout = new QVBoxLayout(logsTab);
    activityLog_ = new ActivityLog(this);
    logsLayout->addWidget(activityLog_);
    tabs->addTab(logsTab, tr("Logs"));
}

void MainWindow::setupMenuBar() {
    QMenuBar* menuBar = this->menuBar();
    
    // File menu
    QMenu* fileMenu = menuBar->addMenu(tr("&File"));
    fileMenu->addAction(tr("&Settings"), this, &MainWindow::onSettingsClicked);
    fileMenu->addSeparator();
    fileMenu->addAction(tr("Save Profile…"), this, [this]{
        Profiles::saveAs(this);
        if (database_) database_->log_activity("profile", "Profile saved");
    });
    fileMenu->addAction(tr("Load Profile…"), this, [this]{
        if (Profiles::load(this)) {
            // Re-apply theme + reload any cached settings that the live
            // UI is showing. Auto-connect / bypass technique pick up on
            // the next Connect; no need to restart.
            Themes::apply();
            if (database_) database_->log_activity("profile", "Profile loaded");
        }
    });
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
    
    // Help menu — rebuilt with macOS-native conveniences. Show-in-Finder
    // uses `open -R` which highlights the file in its containing folder;
    // open without -R would just open the parent folder, which is less
    // useful when the user is hunting one specific file.
    QMenu* helpMenu = menuBar->addMenu(tr("&Help"));
    helpMenu->addAction(tr("Show Activity Log in Finder"), this, [this]{
        const QString p = QDir::homePath() + "/.dynam/activity.log";
        QProcess::startDetached("open", {"-R", p});
    });
    helpMenu->addAction(tr("Open Dynam Config Folder"), this, [this]{
        const QString p = QDir::homePath() + "/.dynam";
        QDir().mkpath(p);
        QProcess::startDetached("open", {p});
    });
    helpMenu->addAction(tr("View on GitHub"), this, [this]{
        QDesktopServices::openUrl(QUrl("https://github.com/kirin2461/Dynam"));
    });
    helpMenu->addAction(tr("Run Diagnostics…"), this, &MainWindow::onRunDiagnostics);
    helpMenu->addSeparator();
    helpMenu->addAction(tr("Check for &Updates"), this, &MainWindow::onCheckForUpdates);
    helpMenu->addAction(tr("&About Dynam"), this, &MainWindow::onCheckForUpdates);
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
    if (activityLog_) {
        connect(activityLog_, &ActivityLog::exportRequested,
                this, &MainWindow::onExportLogs);
    }
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
    // Persist the requested theme so Themes::apply() picks it up consistently
    // (apply() is also called from SettingsDialog when the user changes it
    // live, and from startup before MainWindow exists).
    if (!themeName.isEmpty()) {
        QSettings().setValue("ui/theme", themeName);
    }
    Themes::apply();
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
    if (isConnected_) return;
    isConnected_ = true;
    statusPanel_->setConnected(true);
    statusBar()->showMessage(tr("Connected"));
    if (database_) database_->log_activity("connection", "Connected to network");

    // Apply the persisted bypass technique on connect (Settings dialog
    // writes to network/bypass_technique; default is TCP_FRAGMENTATION).
    if (network_) {
        const int idx = QSettings().value("network/bypass_technique", 2).toInt();
        network_->enable_bypass(static_cast<ncp::BypassTechnique>(idx));
        bypassEnabled_ = true;
        if (dpiControl_) {
            const QSignalBlocker block(dpiControl_);
            dpiControl_->setBypassEnabled(true);
            dpiControl_->setTechniqueIndex(idx);
        }
    }

    // Start the AdvancedDPIBypass pipeline so its counters update during
    // the session. MODERATE preset is a safe default; users can revisit
    // via the DPI tab once we expose a preset selector.
    if (advancedDpi_) {
        ncp::DPI::AdvancedDPIConfig cfg;
        cfg.enable_tcp_keepalive_tricks = true;
        cfg.randomize_tcp_options       = true;
        cfg.randomize_ip_id             = true;
        cfg.tspu_bypass                 = true;
        if (advancedDpi_->initialize(cfg)) {
            advancedDpi_->apply_preset(
                ncp::DPI::AdvancedDPIBypass::BypassPreset::MODERATE);
            advancedDpi_->start();
        }
    }

    notify(tr("Connected"), tr("Dynam is protecting your traffic."));
}

void MainWindow::onDisconnectClicked() {
    if (!isConnected_) return;
    isConnected_ = false;
    statusPanel_->setConnected(false);
    statusBar()->showMessage(tr("Disconnected"));
    if (database_) database_->log_activity("connection", "Disconnected from network");
    if (network_) network_->disable_bypass();
    if (advancedDpi_ && advancedDpi_->is_running()) advancedDpi_->stop();
    bypassEnabled_ = false;
    if (dpiControl_) dpiControl_->setBypassEnabled(false);
    notify(tr("Disconnected"), tr("Network protection is off."));
}

void MainWindow::onQuickConnectClicked() {
    onConnectClicked();
}

void MainWindow::onBypassToggled(bool enabled) {
    bypassEnabled_ = enabled;
    if (enabled && network_) {
        // Read the user's currently-selected technique from the combo
        // rather than hard-coding TCP_FRAGMENTATION. Falls back to the
        // persisted Settings value if dpiControl_ isn't around yet.
        int idx = dpiControl_ ? dpiControl_->currentTechniqueIndex()
                              : QSettings().value("network/bypass_technique", 2).toInt();
        network_->enable_bypass(static_cast<ncp::BypassTechnique>(idx));
        if (database_) database_->log_activity("bypass", "DPI bypass enabled");
    } else if (network_) {
        network_->disable_bypass();
        if (database_) database_->log_activity("bypass", "DPI bypass disabled");
    }
    // setBypassEnabled would re-emit bypassToggled → infinite loop. Block
    // signals while we mirror the checkbox state.
    if (dpiControl_) {
        const QSignalBlocker block(dpiControl_);
        dpiControl_->setBypassEnabled(enabled);
    }
}

void MainWindow::onBypassTechniqueChanged(int index) {
    auto technique = static_cast<ncp::BypassTechnique>(index);
    network_->enable_bypass(technique);
}

void MainWindow::onSettingsClicked() {
    // SettingsDialog persists changes to QSettings on Accept, so we don't
    // need to block here — heap-allocate with WA_DeleteOnClose so it cleans
    // itself up when dismissed.
    auto* dlg = new SettingsDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->show();
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
    if (!license_) return;
    auto* dlg = new LicenseActivationDialog(license_.get(), this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    connect(dlg, &LicenseActivationDialog::activated, this, [this]{
        if (database_) database_->log_activity("license", "License activated");
        refreshLicenseStatus();
        notify(tr("License activated"), tr("Your license has been registered."));
    });
    // Refresh HWID into the panel either way — the dialog reads it but we
    // mirror it into LicenseInfo so the user sees what's bound on the device.
    if (licenseInfo_) {
        licenseInfo_->setHWID(QString::fromStdString(license_->get_hwid()));
    }
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->show();
}

void MainWindow::onLicenseDeactivate() {
    // Deactivate license
}

void MainWindow::onCheckForUpdates() {
    // Repurpose this slot as the "About" entry — the menubar action that
    // used to call it is now wired to a more useful About panel.
    auto* dlg = new AboutDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->show();
}

// Helper: show a tray notification if the tray icon is visible; otherwise
// fall back to a status-bar message. Centralises the "did something visible
// happen?" logic so each slot doesn't need to know about platform niceties.
void MainWindow::notify(const QString& title, const QString& body) {
    if (trayIcon_ && trayIcon_->isVisible()) {
        trayIcon_->showMessage(title, body, QSystemTrayIcon::Information, 3000);
    } else {
        statusBar()->showMessage(title + " — " + body, 4000);
    }
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

// Timer-driven slots: explicit null guards so a single torn-down or
// uninitialised collaborator can no-op instead of segfaulting the event loop.
void MainWindow::updateStats() {
    if (!network_ || !systemStats_) return;
    auto stats = network_->get_stats();
    systemStats_->updateStats(stats.bytes_sent, stats.bytes_received,
                               stats.packets_sent, stats.packets_received);
    if (trafficAnalytics_) {
        trafficAnalytics_->pushSample(stats.bytes_sent, stats.bytes_received);
    }
    if (dpiMetricsPanel_ && advancedDpi_) {
        dpiMetricsPanel_->update(advancedDpi_->get_stats());
    }
    if (identityPanel_) {
        identityPanel_->refresh();
    }

    // ─── Push the plain-English status sentence to StatusPanel ──────────
    // Compute per-second rate from a stored previous sample. summaryClock_
    // and last*_ live on MainWindow; first call seeds them, subsequent
    // calls produce a real delta.
    if (statusPanel_) {
        StatusSummaryInput in;
        in.connected      = isConnected_;
        in.techniqueIndex = dpiControl_ ? dpiControl_->currentTechniqueIndex()
                                        : 0;
        in.totalBytesSent = stats.bytes_sent;
        in.totalBytesRecv = stats.bytes_received;
        in.torEnabled     = QSettings().value("network/tor_enabled", false).toBool();
        if (identityRotation_) {
            in.rotationActive = identityRotation_->is_running();
            in.rotationsTotal = identityRotation_->get_stats().rotations_total;
        }
        if (summaryClock_.isValid()) {
            const qint64 ms = summaryClock_.restart();
            if (ms > 0) {
                const double s = ms / 1000.0;
                in.bytesSentPerSec = static_cast<uint64_t>(
                    (stats.bytes_sent     - lastSummaryBytesSent_) / s);
                in.bytesRecvPerSec = static_cast<uint64_t>(
                    (stats.bytes_received - lastSummaryBytesRecv_) / s);
            }
        } else {
            summaryClock_.start();
        }
        lastSummaryBytesSent_ = stats.bytes_sent;
        lastSummaryBytesRecv_ = stats.bytes_received;
        statusPanel_->setSummary(formatStatusSummary(in));
    }
}

void MainWindow::updateNetworkFlow() {
    if (!networkMonitor_) return;
    networkMonitor_->refresh();
}

void MainWindow::updateActivityLog() {
    if (!database_ || !activityLog_) return;
    auto logs = database_->get_recent_activity(50);
    activityLog_->setLogs(logs);
}

void MainWindow::onRunDiagnostics() {
    auto* dlg = new DiagnosticsDialog(
        crypto_.get(), license_.get(),
        advancedDpi_.get(), identityRotation_.get(), this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->show();
}

void MainWindow::onExportLogs() {
    if (!database_) return;
    const QString suggested = QDir::homePath()
        + "/Desktop/dynam-activity-"
        + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss")
        + ".log";
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Export activity log"), suggested,
        tr("Log files (*.log);;Text files (*.txt);;All files (*)"));
    if (path.isEmpty()) return;

    QFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(this, tr("Export failed"),
            tr("Could not open %1 for writing.").arg(path));
        return;
    }
    // Pull the FULL persisted log (up to kMaxEntries == 500), not just
    // whatever the in-memory QListWidget currently shows. The Database
    // returns them oldest-first which is the natural read order.
    QTextStream ts(&out);
    for (const auto& line : database_->get_recent_activity(500)) {
        ts << QString::fromStdString(line) << '\n';
    }
    statusBar()->showMessage(tr("Exported activity log to %1").arg(path), 4000);
    if (database_) database_->log_activity("export", "Activity log exported");
}

void MainWindow::refreshLicenseStatus() {
    if (!license_ || !licenseInfo_) return;
    auto info = license_->get_license_info("license.dat");
    licenseInfo_->updateInfo(info);
}

} // namespace ncp::GUI
