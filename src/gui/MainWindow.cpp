#include "MainWindow.hpp"
#include "SettingsDialog.hpp"
#include "Launcher.hpp"
#include "widgets/StatusPanel.hpp"
#include "widgets/NetworkMonitor.hpp"
#include "widgets/DPIControl.hpp"
#include "widgets/TrafficAnalytics.hpp"
#include "widgets/SystemStats.hpp"
#include "widgets/ActivityLog.hpp"
#include "widgets/LicenseInfo.hpp"
#include "widgets/ModulesPanel.hpp"
#include "widgets/LeakTestPanel.hpp"

// PR #118 (upstream Qt GUI) tool panels — header-only widgets.
#include "widgets/UiSettingsDialog.hpp"
#include "widgets/CryptoPanel.hpp"
#include "widgets/IdentityPanel.hpp"
#include "widgets/DPIMetricsPanel.hpp"
#include "widgets/DPIStrategyEditor.hpp"
#include "widgets/DnsLookupPanel.hpp"
#include "widgets/UrlProbePanel.hpp"
#include "widgets/SiteScraperPanel.hpp"
#include "widgets/PollerEngine.hpp"
#include "widgets/PollerPanel.hpp"
#include "widgets/Themes.hpp"
#include "widgets/OnboardingWizard.hpp"
#include "widgets/Profiles.hpp"
#include "widgets/DiagnosticsDialog.hpp"

#include "ncp_license.hpp"
#include "ncp_crypto.hpp"
#include "ncp_db.hpp"
#include "ncp_identity.hpp"
#include "ncp_dpi_advanced.hpp"

#include <QApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QGridLayout>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QSettings>
#include <QStatusBar>
#include <QTabWidget>
#include <QTextStream>
#include <QToolBar>
#include <QUrl>
#include <QVBoxLayout>

namespace ncp::GUI {

static const char* kAppVersion = "1.9.4";

static QIcon makeAppIcon() {
    QPixmap pm(64, 64);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(QColor("#4caf50"));
    p.setPen(Qt::NoPen);
    p.drawEllipse(8, 8, 48, 48);
    p.end();
    return QIcon(pm);
}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , currentTheme_(QStringLiteral("dark")) {
    // Core modules are best-effort: never let a core exception kill the UI.
    try {
        license_ = std::make_unique<ncp::License>();
    } catch (...) {
        license_.reset();
    }

    // PR #118: in-process core objects backing the advanced tool panels.
    // They are NOT started for packet processing — the privacy-critical
    // packet path stays in the external ncp.exe process (ProxyController /
    // DriverController), so nothing here touches the firewall.
    try { crypto_   = std::make_unique<ncp::Crypto>(); }   catch (...) { crypto_.reset(); }
    try { database_ = std::make_unique<ncp::Database>(); } catch (...) { database_.reset(); }
    try {
        identityRotation_ = std::make_unique<ncp::DPI::IdentityRotation>();
        // Seed an 8-identity pool so "rotate now" has options.
        identityRotation_->generate_pool(8);
    } catch (...) { identityRotation_.reset(); }
    try { advancedDpi_ = std::make_unique<ncp::DPI::AdvancedDPIBypass>(); }
    catch (...) { advancedDpi_.reset(); }

    // Poller engine: independent of Connect state. It owns its timers and
    // runs probes when due; persisted targets reload from ~/.dynam/poller.json.
    try { pollerEngine_ = std::make_unique<PollerEngine>(); }
    catch (...) { pollerEngine_.reset(); }

    controller_ = new ProxyController(this);
    driver_ = new DriverController(this);

    setupUI();
    setupMenuBar();
    setupToolBar();
    setupStatusBar();
    setupSystemTray();
    setupConnections();
    loadSettings();
    applyTheme(currentTheme_);

    statsTimer_ = new QTimer(this);
    connect(statsTimer_, &QTimer::timeout, this, &MainWindow::updateStats);
    statsTimer_->start(1000);

    setWindowTitle(QStringLiteral("NCP v%1 — Network Control Protocol (Qt6)")
                       .arg(QLatin1String(kAppVersion)));
    setWindowIcon(makeAppIcon());
    setMinimumSize(1100, 700);
    resize(1280, 820);

    // Show HWID in the license panel (best-effort)
    try {
        licenseInfo_->setHWID(license_
            ? QString::fromStdString(license_->get_hwid())
            : QStringLiteral("недоступен"));
    } catch (...) {
        licenseInfo_->setHWID(QStringLiteral("недоступен"));
    }

    // First-launch onboarding (PR #118). Deferred via singleShot so the main
    // window is fully visible before the modal wizard appears.
    if (OnboardingWizard::shouldRun()) {
        QTimer::singleShot(150, this, [this]{
            auto* wiz = new OnboardingWizard(this);
            wiz->setAttribute(Qt::WA_DeleteOnClose);
            connect(wiz, &QDialog::finished, this, [this](int){
                // Re-apply theme + maybe auto-connect now that the wizard
                // has persisted the user's choices.
                Themes::apply();
                if (QSettings().value("ui/auto_connect", true).toBool()) {
                    QTimer::singleShot(0, this, &MainWindow::onConnectClicked);
                }
            });
            wiz->show();
        });
    } else if (QSettings().value("ui/auto_connect", true).toBool()) {
        // No wizard, but auto-connect is set — fire after first paint.
        // Connect here starts the local SOCKS5 proxy (ncp.exe proxy,
        // --no-kill-switch) — it never touches the firewall.
        QTimer::singleShot(0, this, &MainWindow::onConnectClicked);
    }
}

MainWindow::~MainWindow() {
    if (driver_) driver_->stop();
    if (controller_) controller_->stop();
    saveSettings();
}

void MainWindow::setupUI() {
    // Tab layout (PR #118): StatusPanel sits on top as an always-visible
    // header; the QTabWidget below hosts the original dashboard grid
    // ("Обзор") plus the upstream tool tabs.
    QWidget* central = new QWidget(this);
    setCentralWidget(central);
    auto* root = new QVBoxLayout(central);
    root->setSpacing(6);
    root->setContentsMargins(8, 8, 8, 8);

    statusPanel_ = new StatusPanel(this);
    root->addWidget(statusPanel_);

    auto* tabs = new QTabWidget(this);
    root->addWidget(tabs, 1);

    // ─── Обзор: the original dashboard grid ─────────────────────────────
    auto* overview = new QWidget(tabs);
    QGridLayout* mainLayout = new QGridLayout(overview);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(4, 4, 4, 4);

    networkMonitor_ = new NetworkMonitor(this);
    mainLayout->addWidget(networkMonitor_, 0, 0);

    dpiControl_ = new DPIControl(this);
    mainLayout->addWidget(dpiControl_, 0, 1);

    trafficAnalytics_ = new TrafficAnalytics(this);
    mainLayout->addWidget(trafficAnalytics_, 0, 2);

    systemStats_ = new SystemStats(this);
    mainLayout->addWidget(systemStats_, 1, 0);

    activityLog_ = new ActivityLog(this);
    mainLayout->addWidget(activityLog_, 1, 1);

    licenseInfo_ = new LicenseInfo(this);
    mainLayout->addWidget(licenseInfo_, 1, 2);

    modulesPanel_ = new ModulesPanel(this);
    mainLayout->addWidget(modulesPanel_, 2, 0, 1, 2);

    leakTestPanel_ = new LeakTestPanel(this);
    mainLayout->addWidget(leakTestPanel_, 2, 2);

    mainLayout->setRowStretch(0, 2);
    mainLayout->setRowStretch(1, 2);
    mainLayout->setRowStretch(2, 2);
    mainLayout->setColumnStretch(0, 1);
    mainLayout->setColumnStretch(1, 1);
    mainLayout->setColumnStretch(2, 1);
    tabs->addTab(overview, tr("Обзор"));

    // ─── DPI (расшир.): live metrics + strategy editor (PR #118) ───────
    if (advancedDpi_) {
        auto* dpiTab = new QWidget(tabs);
        auto* dpiLayout = new QVBoxLayout(dpiTab);
        auto* dpiInnerTabs = new QTabWidget(dpiTab);
        dpiMetricsPanel_   = new DPIMetricsPanel(advancedDpi_.get(), this);
        dpiStrategyEditor_ = new DPIStrategyEditor(advancedDpi_.get(), this);
        dpiInnerTabs->addTab(dpiMetricsPanel_,   tr("Metrics"));
        dpiInnerTabs->addTab(dpiStrategyEditor_, tr("Strategy"));
        dpiLayout->addWidget(dpiInnerTabs, 1);
        tabs->addTab(dpiTab, tr("DPI (расшир.)"));
    }

    // ─── Идентичность: identity rotation (PR #118) ──────────────────────
    if (identityRotation_) {
        identityPanel_ = new IdentityPanel(identityRotation_.get(), this);
        tabs->addTab(identityPanel_, tr("Идентичность"));
    }

    // ─── Инструменты: DNS lookup + URL probe + site scraper (PR #118) ───
    {
        auto* toolsTab = new QWidget(tabs);
        auto* toolsLayout = new QVBoxLayout(toolsTab);
        auto* toolsInner = new QTabWidget(toolsTab);
        dnsLookupPanel_   = new DnsLookupPanel(this);
        urlProbePanel_    = new UrlProbePanel(this);
        siteScraperPanel_ = new SiteScraperPanel(pollerEngine_.get(), this);
        toolsInner->addTab(dnsLookupPanel_,   tr("DNS Lookup"));
        toolsInner->addTab(urlProbePanel_,    tr("URL Probe"));
        toolsInner->addTab(siteScraperPanel_, tr("Site Scraper"));
        toolsLayout->addWidget(toolsInner);
        tabs->addTab(toolsTab, tr("Инструменты"));
    }

    // ─── Поллер: scheduled probe engine (PR #118) ───────────────────────
    if (pollerEngine_) {
        pollerPanel_ = new PollerPanel(pollerEngine_.get(), this);
        tabs->addTab(pollerPanel_, tr("Поллер"));
    }

    // ─── Крипто: crypto self-tests / info (PR #118) ─────────────────────
    if (crypto_) {
        cryptoPanel_ = new CryptoPanel(crypto_.get(), this);
        tabs->addTab(cryptoPanel_, tr("Крипто"));
    }
}

void MainWindow::setupMenuBar() {
    QMenu* fileMenu = menuBar()->addMenu(tr("&Файл"));
    fileMenu->addAction(tr("&Настройки"), this, &MainWindow::onSettingsClicked);
    fileMenu->addAction(tr("Настройки &интерфейса…"), this, &MainWindow::onUiSettingsClicked);
    fileMenu->addSeparator();
    // Profiles (PR #118): snapshot/restore QSettings-backed preferences.
    fileMenu->addAction(tr("Сохранить профиль…"), this, [this]{
        Profiles::saveAs(this);
        if (database_) database_->log_activity("profile", "Profile saved");
    });
    fileMenu->addAction(tr("Загрузить профиль…"), this, [this]{
        if (Profiles::load(this)) {
            Themes::apply();
            if (database_) database_->log_activity("profile", "Profile loaded");
        }
    });
    fileMenu->addSeparator();
    fileMenu->addAction(tr("&Выход"), this, [this]() {
        quitRequested_ = true;
        close();
    });

    QMenu* connMenu = menuBar()->addMenu(tr("&Защита"));
    connMenu->addAction(tr("&Запустить прокси"), this, &MainWindow::onConnectClicked);
    connMenu->addAction(tr("&Остановить прокси"), this, &MainWindow::onDisconnectClicked);
    connMenu->addSeparator();
    connMenu->addAction(tr("Запустить &драйвер (ncp run)"),
                        this, &MainWindow::onDriverStartClicked);
    connMenu->addAction(tr("Остановить д&райвер"), this, &MainWindow::onDriverStopClicked);

    QMenu* uiMenu = menuBar()->addMenu(tr("&Интерфейс"));
    uiMenu->addAction(tr("Открыть &Web UI"), this, &MainWindow::onOpenWebUi);
    uiMenu->addAction(tr("Выбирать интерфейс при запуске…"),
                      this, &MainWindow::onChooseUiNextTime);

    QMenu* helpMenu = menuBar()->addMenu(tr("&Справка"));
    if (crypto_ && license_ && advancedDpi_ && identityRotation_) {
        helpMenu->addAction(tr("Диагностика…"), this, &MainWindow::onRunDiagnostics);
    }
    if (database_) {
        helpMenu->addAction(tr("Экспорт журнала…"), this, &MainWindow::onExportLogs);
    }
    helpMenu->addAction(tr("Мастер первой настройки"), this, [this]{
        // No first-launch gate when invoked explicitly — user can revisit anytime.
        auto* wiz = new OnboardingWizard(this);
        wiz->setAttribute(Qt::WA_DeleteOnClose);
        connect(wiz, &QDialog::finished, this, [](int){ Themes::apply(); });
        wiz->show();
    });
    helpMenu->addAction(tr("Проект на GitHub"), this, []{
        QDesktopServices::openUrl(QUrl("https://github.com/kirin2461/Dynam"));
    });
    helpMenu->addSeparator();
    helpMenu->addAction(tr("&О программе"), [this]() {
        QMessageBox::about(this, tr("О программе"),
            tr("NCP v%1 — Network Control Protocol (Qt6)\n\n"
               "Обход DPI, цепочки через Tor (мосты obfs4/Snowflake),\n"
               "скрытие IP и метаданных. Нативный интерфейс на Qt6.\n\n"
               "Режим драйвера (ncp run): пресеты операторов, zapret-профили,\n"
               "Geneva/Covert/stealth-модули, проверка утечек.")
               .arg(QLatin1String(kAppVersion)));
    });
}

void MainWindow::setupToolBar() {
    QToolBar* toolbar = addToolBar(tr("Main"));
    toolbar->setObjectName(QStringLiteral("mainToolBar"));  // for saveState()
    toolbar->setMovable(false);
    toolbar->addAction(tr("Запустить"), this, &MainWindow::onConnectClicked);
    toolbar->addAction(tr("Остановить"), this, &MainWindow::onDisconnectClicked);
    toolbar->addSeparator();
    toolbar->addAction(tr("Драйвер ▶"), this, &MainWindow::onDriverStartClicked);
    toolbar->addAction(tr("Драйвер ■"), this, &MainWindow::onDriverStopClicked);
    toolbar->addSeparator();
    toolbar->addAction(tr("Настройки"), this, &MainWindow::onSettingsClicked);
    toolbar->addSeparator();
    toolbar->addAction(tr("Web UI"), this, &MainWindow::onOpenWebUi);
}

void MainWindow::setupStatusBar() {
    statusBar()->showMessage(tr("Готов"));
}

void MainWindow::setupSystemTray() {
    if (qEnvironmentVariableIsSet("NCP_QT_NO_TRAY") || !QSystemTrayIcon::isSystemTrayAvailable())
        return;
    trayIcon_ = new QSystemTrayIcon(makeAppIcon(), this);
    trayIcon_->setToolTip("NCP — Network Control Protocol");

    trayMenu_ = new QMenu(this);
    trayMenu_->addAction(tr("Показать"), this, &QMainWindow::show);
    trayMenu_->addAction(tr("Запустить"), this, &MainWindow::onConnectClicked);
    trayMenu_->addAction(tr("Остановить"), this, &MainWindow::onDisconnectClicked);
    trayMenu_->addSeparator();
    trayMenu_->addAction(tr("Web UI"), this, &MainWindow::onOpenWebUi);
    trayMenu_->addSeparator();
    trayMenu_->addAction(tr("Выход"), this, [this]() {
        quitRequested_ = true;
        close();
    });

    trayIcon_->setContextMenu(trayMenu_);
    connect(trayIcon_, &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayIconActivated);
    trayIcon_->show();
}

void MainWindow::setupConnections() {
    connect(dpiControl_, &DPIControl::bypassToggled,
            this, &MainWindow::onBypassToggled);
    connect(dpiControl_, &DPIControl::techniqueChanged,
            this, &MainWindow::onBypassTechniqueChanged);
    connect(licenseInfo_, &LicenseInfo::activateClicked,
            this, &MainWindow::onLicenseActivate);

    connect(statusPanel_, &StatusPanel::startRequested,
            this, &MainWindow::onConnectClicked);
    connect(statusPanel_, &StatusPanel::stopRequested,
            this, &MainWindow::onDisconnectClicked);
    connect(statusPanel_, &StatusPanel::settingsRequested,
            this, &MainWindow::onSettingsClicked);

    connect(controller_, &ProxyController::startFinished,
            this, &MainWindow::onStartFinished);
    connect(controller_, &ProxyController::logLine,
            this, &MainWindow::appendLog);

    connect(driver_, &DriverController::lineReceived,
            this, &MainWindow::onDriverLine);
    connect(driver_, &DriverController::moduleStatus,
            this, &MainWindow::onDriverModuleStatus);
    connect(driver_, &DriverController::failedToStart,
            this, &MainWindow::onDriverFailed);
    connect(driver_, &DriverController::finished,
            this, &MainWindow::onDriverFinished);
    connect(driver_, &DriverController::startedOk, this, [this]() {
        modulesPanel_->setDriverState(QStringLiteral("запущен"), true);
        statusBar()->showMessage(tr("Драйвер запущен"));
    });
}

GuiProxyConfig MainWindow::collectConfig() const {
    GuiProxyConfig cfg;
    QSettings s("NCP", "ncp-qt");
    cfg.port = static_cast<uint16_t>(s.value("proxy_port", 1080).toInt());
    cfg.upstream = s.value("proxy_upstream").toString();
    cfg.tor_binary = s.value("tor_binary").toString();
    cfg.pt_obfs4 = s.value("pt_obfs4").toString();
    cfg.pt_snowflake = s.value("pt_snowflake").toString();
    cfg.bridges = s.value("tor_bridges").toStringList();

    cfg.doh = dpiControl_->dohEnabled();
    cfg.block_quic = dpiControl_->blockQuic();
    cfg.fake_quic = dpiControl_->fakeQuic();
    cfg.split_pos = dpiControl_->splitPos();
    cfg.split_sni = dpiControl_->splitSni();
    return cfg;
}

void MainWindow::persistConfig(const GuiProxyConfig& cfg) {
    QSettings s("NCP", "ncp-qt");
    s.setValue("proxy_port", cfg.port);
    s.setValue("proxy_upstream", cfg.upstream);
    s.setValue("tor_binary", cfg.tor_binary);
    s.setValue("pt_obfs4", cfg.pt_obfs4);
    s.setValue("pt_snowflake", cfg.pt_snowflake);
    s.setValue("tor_bridges", cfg.bridges);
}

void MainWindow::onConnectClicked() {
    if (controller_->running() || controller_->starting()) return;
    GuiProxyConfig cfg = collectConfig();
    persistConfig(cfg);
    statusPanel_->setBusy(true);
    statusBar()->showMessage(tr("Запуск защиты…"));
    appendLog(QStringLiteral("[ui] запуск: порт %1%2")
        .arg(cfg.port)
        .arg(cfg.tor_binary.isEmpty()
            ? (cfg.upstream.isEmpty() ? QStringLiteral(", напрямую")
                                      : QStringLiteral(", upstream %1").arg(cfg.upstream))
            : QStringLiteral(", управляемый Tor")));
    controller_->requestStart(cfg);
}

void MainWindow::onStartFinished(bool ok, const QString& message) {
    statusPanel_->setBusy(false);
    if (ok) {
        isConnected_ = true;
        statusPanel_->setConnected(true);
        statusPanel_->setAddress(QStringLiteral("127.0.0.1:%1").arg(controller_->boundPort()));
        statusPanel_->setChain(controller_->chainLabel());
        statusBar()->showMessage(tr("Защита активна"));
        if (database_) database_->log_activity("connection", "Proxy protection started");
        notify(tr("NCP"), tr("Защита активна — трафик идёт через прокси."));
    } else {
        isConnected_ = false;
        statusPanel_->setConnected(false);
        statusBar()->showMessage(tr("Ошибка запуска"));
        appendLog(QStringLiteral("[ui] ошибка запуска: %1").arg(message));
        QMessageBox::warning(this, tr("NCP"), message);
    }
}

void MainWindow::onDisconnectClicked() {
    if (!controller_->running()) return;
    controller_->stop();
    isConnected_ = false;
    statusPanel_->setConnected(false);
    statusPanel_->setChain(QString());
    statusBar()->showMessage(tr("Остановлено"));
    if (database_) database_->log_activity("connection", "Proxy protection stopped");
}

void MainWindow::onQuickConnectClicked() { onConnectClicked(); }

void MainWindow::onBypassToggled(bool enabled) {
    bypassEnabled_ = enabled;
    dpiControl_->setBypassEnabled(enabled);
    if (!enabled && controller_->running()) onDisconnectClicked();
}

void MainWindow::onBypassTechniqueChanged(int index) {
    Q_UNUSED(index);  // preset applied inside DPIControl; takes effect on next start
}

void MainWindow::onSettingsClicked() {
    SettingsDialog dlg(this);
    dlg.setConfig(collectConfig());
    if (dlg.exec() == QDialog::Accepted) {
        GuiProxyConfig cfg = collectConfig();
        GuiProxyConfig edited = dlg.config();
        // keep DPI toggles from the panel, take chain/tor from dialog
        edited.doh = cfg.doh;
        edited.block_quic = cfg.block_quic;
        edited.fake_quic = cfg.fake_quic;
        edited.split_pos = cfg.split_pos;
        edited.split_sni = cfg.split_sni;
        persistConfig(edited);
        statusPanel_->setAddress(QStringLiteral("127.0.0.1:%1").arg(edited.port));
        statusPanel_->setChain(edited.tor_binary.isEmpty() ? edited.upstream : QStringLiteral("управляемый Tor"));
        if (controller_->running()) {
            appendLog(QStringLiteral("[ui] настройки применятся после перезапуска"));
        }
    }
}

void MainWindow::onUiSettingsClicked() {
    // PR #118 UI settings (theme, auto-connect, Tor toggle, advanced tree).
    // The dialog persists to QSettings on Accept; heap-allocate with
    // WA_DeleteOnClose so it cleans itself up when dismissed.
    auto* dlg = new UiSettingsDialog(this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowModality(Qt::ApplicationModal);
    dlg->show();
}

void MainWindow::onThemeChanged(const QString& theme) { applyTheme(theme); }

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::DoubleClick) {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::onMinimizeToTray() {
    if (!trayIcon_) return;  // tray may be unavailable (RDP etc.)
    hide();
    trayIcon_->showMessage("NCP", tr("Приложение свёрнуто в трей"));
}

void MainWindow::onLicenseActivate() {
    appendLog(QStringLiteral("[ui] лицензия обновлена"));
    if (database_) database_->log_activity("license", "License updated via Qt GUI");
    refreshLicenseStatus();
}

void MainWindow::onLicenseDeactivate() {
    QSettings("NCP", "ncp-qt").remove("license_key");
}

void MainWindow::refreshLicenseStatus() {
    if (!license_ || !licenseInfo_) return;
    try {
        auto info = license_->get_license_info("license.dat");
        licenseInfo_->updateInfo(info);
    } catch (...) {
        // No license.dat or core failure — the panel's own offline verifier
        // (QSettings-backed) remains the source of truth in this build.
    }
}

void MainWindow::onCheckForUpdates() {
    QMessageBox::information(this, tr("Обновления"),
        tr("У вас последняя версия."));
}

void MainWindow::onOpenWebUi() {
    if (Launcher::launchWebUi(this))
        appendLog(QStringLiteral("[ui] запущен Web UI (ncp-gui.exe)"));
}

void MainWindow::onChooseUiNextTime() {
    Launcher::resetChoice();
    QMessageBox::information(this, tr("NCP"),
        tr("Выбор интерфейса будет предложен при следующем запуске."));
}

void MainWindow::onDriverStartClicked() {
    if (driver_->running()) return;
    DriverController::Options opt;
    opt.interface = dpiControl_->driverInterface();
    opt.preset = dpiControl_->driverPreset();
    opt.covert = dpiControl_->driverCovert();
    opt.zapretProfile = dpiControl_->driverZapretProfile();
    opt.zapretChains = dpiControl_->driverZapretChains();

    // persist driver options
    QSettings s("NCP", "ncp-qt");
    s.setValue("driver_iface", dpiControl_->driverInterface());
    s.setValue("driver_preset", opt.preset);
    s.setValue("driver_zapret", opt.zapretProfile);
    s.setValue("driver_chains", opt.zapretChains);
    s.setValue("driver_covert", opt.covert);

    modulesPanel_->resetStatuses();
    statusBar()->showMessage(tr("Запуск драйвера…"));
    driver_->start(opt);
}

void MainWindow::onDriverStopClicked() {
    if (!driver_->running()) return;
    driver_->stop();  // finished() handler updates panels
}

void MainWindow::onDriverLine(const QString& line) {
    appendLog(QStringLiteral("[driver] %1").arg(line));
}

void MainWindow::onDriverModuleStatus(const QString& module, int state) {
    modulesPanel_->setModuleStatus(module, state);
}

void MainWindow::onDriverFailed(const QString& reason) {
    modulesPanel_->setDriverState(QStringLiteral("ошибка запуска"), false);
    statusBar()->showMessage(tr("Драйвер: ошибка запуска"));
    appendLog(QStringLiteral("[driver] ошибка запуска: %1").arg(reason));
    QMessageBox::warning(this, tr("NCP — режим драйвера"), reason);
}

void MainWindow::onDriverFinished(int exitCode) {
    modulesPanel_->setDriverState(QStringLiteral("остановлен"), false);
    statusBar()->showMessage(tr("Драйвер остановлен (код %1)").arg(exitCode));
    appendLog(QStringLiteral("[driver] процесс завершён, код %1").arg(exitCode));
}

void MainWindow::onRunDiagnostics() {
    if (!crypto_ || !license_ || !advancedDpi_ || !identityRotation_) return;
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
        + "/ncp-activity-"
        + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss")
        + ".log";
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Экспорт журнала активности"), suggested,
        tr("Log files (*.log);;Text files (*.txt);;All files (*)"));
    if (path.isEmpty()) return;

    QFile out(path);
    if (!out.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        QMessageBox::warning(this, tr("Экспорт не удался"),
            tr("Не удалось открыть %1 для записи.").arg(path));
        return;
    }
    QTextStream ts(&out);
    for (const auto& line : database_->get_recent_activity(500)) {
        ts << QString::fromStdString(line) << '\n';
    }
    statusBar()->showMessage(tr("Журнал экспортирован в %1").arg(path), 4000);
    database_->log_activity("export", "Activity log exported");
}

// Helper: show a tray notification if the tray icon is visible; otherwise
// fall back to a status-bar message.
void MainWindow::notify(const QString& title, const QString& body) {
    if (trayIcon_ && trayIcon_->isVisible()) {
        trayIcon_->showMessage(title, body, QSystemTrayIcon::Information, 3000);
    } else {
        statusBar()->showMessage(title + " — " + body, 4000);
    }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (!quitRequested_ && trayIcon_ && trayIcon_->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}

void MainWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::WindowStateChange && isMinimized() &&
        !quitRequested_ && trayIcon_)
        onMinimizeToTray();
    QMainWindow::changeEvent(event);
}

void MainWindow::updateStats() {
    ncp::ProxyStats st = controller_->stats();
    networkMonitor_->setStats(st);
    trafficAnalytics_->addSample(st.connections_total);
    systemStats_->updateStats(st.bytes_client_to_server, st.bytes_server_to_client,
                              st.desync_splits_applied, st.quic_datagrams_blocked);

    // PR #118 panels: live counters (all zero until traffic flows through
    // the in-process pipeline — the panels are informational here).
    if (dpiMetricsPanel_ && advancedDpi_) {
        try { dpiMetricsPanel_->update(advancedDpi_->get_stats()); } catch (...) {}
    }
    if (identityPanel_) {
        try { identityPanel_->refresh(); } catch (...) {}
    }
}

void MainWindow::appendLog(const QString& line) {
    activityLog_->appendLine(line);
}

void MainWindow::loadSettings() {
    QSettings settings("NCP", "ncp-qt");
    currentTheme_ = settings.value("theme", "dark").toString();
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());
    statusPanel_->setAddress(QStringLiteral("127.0.0.1:%1")
        .arg(settings.value("proxy_port", 1080).toInt()));
    dpiControl_->setDriverOptions(
        settings.value("driver_iface").toString(),
        settings.value("driver_preset", "tspu").toString(),
        settings.value("driver_zapret").toString(),
        settings.value("driver_covert", false).toBool(),
        settings.value("driver_chains").toString());
    leakTestPanel_->setProxy(QStringLiteral("127.0.0.1"),
        static_cast<quint16>(settings.value("proxy_port", 1080).toInt()));
    // Enumerate interfaces asynchronously for the driver-mode dropdown.
    DriverController::listInterfaces(this, [this](const QStringList& ifaces) {
        if (!ifaces.isEmpty()) dpiControl_->setInterfaces(ifaces);
    });
}

void MainWindow::saveSettings() {
    QSettings settings("NCP", "ncp-qt");
    settings.setValue("theme", currentTheme_);
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
}

void MainWindow::applyTheme(const QString& themeName) {
    // Themes (PR #118) knows "system"/"dark"/"light". The historical id
    // "dark_pro" maps to "dark". Persist under ui/theme so Themes::apply()
    // picks it up consistently (it is also called from UiSettingsDialog and
    // the onboarding wizard).
    QString t = themeName;
    if (t == QLatin1String("dark_pro")) t = QStringLiteral("dark");
    if (t.isEmpty()) t = QStringLiteral("dark");
    QSettings().setValue("ui/theme", t);
    Themes::apply();
    currentTheme_ = t;
}

} // namespace ncp::GUI
