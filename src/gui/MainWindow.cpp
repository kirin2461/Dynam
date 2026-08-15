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

#include "ncp_license.hpp"

#include <QApplication>
#include <QCloseEvent>
#include <QGridLayout>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QPixmap>
#include <QSettings>
#include <QStatusBar>
#include <QToolBar>

namespace ncp::GUI {

static const char* kAppVersion = "1.9.2";

static const char* kDarkQss = R"(
QMainWindow, QWidget { background:#16161e; color:#d8d8e0; font-family:'Segoe UI',sans-serif; }
QMenuBar { background:#101018; border-bottom:1px solid #2a2a3a; }
QMenuBar::item:selected, QMenu::item:selected { background:#2a2a4a; }
QMenu { background:#101018; border:1px solid #2a2a3a; }
QToolBar { background:#101018; border:none; spacing:6px; padding:4px; }
QToolButton { background:#22222e; color:#d8d8e0; border-radius:4px; padding:5px 10px; }
QToolButton:hover { background:#2e2e44; }
QPushButton { background:#22222e; border:1px solid #34344a; border-radius:4px; padding:5px 12px; }
QPushButton:hover { background:#2e2e44; }
QPushButton:disabled { color:#666; background:#1b1b24; }
QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {
    background:#101018; border:1px solid #2a2a3a; border-radius:3px; padding:4px; }
QStatusBar { background:#101018; border-top:1px solid #2a2a3a; }
QToolTip { background:#22222e; color:#d8d8e0; border:1px solid #34344a; }
QCheckBox { spacing:6px; }
QDialog { background:#16161e; }
)";

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
    , currentTheme_("dark_pro") {
    // License is best-effort: never let a core exception kill the UI.
    try {
        license_ = std::make_unique<ncp::License>();
    } catch (...) {
        license_.reset();
    }
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
}

MainWindow::~MainWindow() {
    if (driver_) driver_->stop();
    if (controller_) controller_->stop();
    saveSettings();
}

void MainWindow::setupUI() {
    QWidget* central = new QWidget(this);
    setCentralWidget(central);

    QGridLayout* mainLayout = new QGridLayout(central);
    mainLayout->setSpacing(10);
    mainLayout->setContentsMargins(10, 10, 10, 10);

    statusPanel_ = new StatusPanel(this);
    mainLayout->addWidget(statusPanel_, 0, 0, 1, 3);

    networkMonitor_ = new NetworkMonitor(this);
    mainLayout->addWidget(networkMonitor_, 1, 0);

    dpiControl_ = new DPIControl(this);
    mainLayout->addWidget(dpiControl_, 1, 1);

    trafficAnalytics_ = new TrafficAnalytics(this);
    mainLayout->addWidget(trafficAnalytics_, 1, 2);

    systemStats_ = new SystemStats(this);
    mainLayout->addWidget(systemStats_, 2, 0);

    activityLog_ = new ActivityLog(this);
    mainLayout->addWidget(activityLog_, 2, 1);

    licenseInfo_ = new LicenseInfo(this);
    mainLayout->addWidget(licenseInfo_, 2, 2);

    modulesPanel_ = new ModulesPanel(this);
    mainLayout->addWidget(modulesPanel_, 3, 0, 1, 2);

    leakTestPanel_ = new LeakTestPanel(this);
    mainLayout->addWidget(leakTestPanel_, 3, 2);

    mainLayout->setRowStretch(0, 0);
    mainLayout->setRowStretch(1, 2);
    mainLayout->setRowStretch(2, 2);
    mainLayout->setRowStretch(3, 2);
    mainLayout->setColumnStretch(0, 1);
    mainLayout->setColumnStretch(1, 1);
    mainLayout->setColumnStretch(2, 1);
}

void MainWindow::setupMenuBar() {
    QMenu* fileMenu = menuBar()->addMenu(tr("&Файл"));
    fileMenu->addAction(tr("&Настройки"), this, &MainWindow::onSettingsClicked);
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
}

void MainWindow::onLicenseDeactivate() {
    QSettings("NCP", "ncp-qt").remove("license_key");
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
}

void MainWindow::appendLog(const QString& line) {
    activityLog_->appendLine(line);
}

void MainWindow::loadSettings() {
    QSettings settings("NCP", "ncp-qt");
    currentTheme_ = settings.value("theme", "dark_pro").toString();
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
    Q_UNUSED(themeName);
    qApp->setStyleSheet(QString::fromUtf8(kDarkQss));
}

} // namespace ncp::GUI
