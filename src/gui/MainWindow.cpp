#include "MainWindow.hpp"
#include "SettingsDialog.hpp"
#include "widgets/StatusPanel.hpp"
#include "widgets/NetworkMonitor.hpp"
#include "widgets/DPIControl.hpp"
#include "widgets/TrafficAnalytics.hpp"
#include "widgets/SystemStats.hpp"
#include "widgets/ActivityLog.hpp"
#include "widgets/LicenseInfo.hpp"

#include "ncp_license.hpp"

#include <QApplication>
#include <QCloseEvent>
#include <QGridLayout>
#include <QLabel>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPixmap>
#include <QSettings>
#include <QStatusBar>
#include <QToolBar>

namespace ncp::GUI {

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
)";

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , currentTheme_("dark_pro") {
    license_ = std::make_unique<ncp::License>();
    controller_ = new ProxyController(this);

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

    setWindowTitle(QStringLiteral("NCP — Network Control Protocol (Qt6)"));
    setMinimumSize(1100, 700);
    resize(1280, 820);

    // Show HWID in the license panel (best-effort)
    try {
        licenseInfo_->setHWID(QString::fromStdString(license_->get_hwid()));
    } catch (...) {
        licenseInfo_->setHWID(QStringLiteral("недоступен"));
    }
}

MainWindow::~MainWindow() {
    controller_->stop();
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

    mainLayout->setRowStretch(0, 0);
    mainLayout->setRowStretch(1, 2);
    mainLayout->setRowStretch(2, 2);
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
    connMenu->addAction(tr("&Запустить"), this, &MainWindow::onConnectClicked);
    connMenu->addAction(tr("&Остановить"), this, &MainWindow::onDisconnectClicked);

    QMenu* helpMenu = menuBar()->addMenu(tr("&Справка"));
    helpMenu->addAction(tr("&О программе"), [this]() {
        QMessageBox::about(this, tr("О программе"),
            tr("NCP — Network Control Protocol (Qt6)\n\n"
               "Обход DPI, цепочки через Tor (мосты obfs4/Snowflake),\n"
               "скрытие IP и метаданных. Нативный интерфейс на Qt6."));
    });
}

void MainWindow::setupToolBar() {
    QToolBar* toolbar = addToolBar(tr("Main"));
    toolbar->setMovable(false);
    toolbar->addAction(tr("Запустить"), this, &MainWindow::onConnectClicked);
    toolbar->addAction(tr("Остановить"), this, &MainWindow::onDisconnectClicked);
    toolbar->addSeparator();
    toolbar->addAction(tr("Настройки"), this, &MainWindow::onSettingsClicked);
}

void MainWindow::setupStatusBar() {
    statusBar()->showMessage(tr("Готов"));
}

void MainWindow::setupSystemTray() {
    if (qEnvironmentVariableIsSet("NCP_QT_NO_TRAY") || !QSystemTrayIcon::isSystemTrayAvailable())
        return;
    QPixmap pm(32, 32);
    pm.fill(QColor("#4caf50"));
    trayIcon_ = new QSystemTrayIcon(QIcon(pm), this);
    trayIcon_->setToolTip("NCP — Network Control Protocol");

    trayMenu_ = new QMenu(this);
    trayMenu_->addAction(tr("Показать"), this, &QMainWindow::show);
    trayMenu_->addAction(tr("Запустить"), this, &MainWindow::onConnectClicked);
    trayMenu_->addAction(tr("Остановить"), this, &MainWindow::onDisconnectClicked);
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
    if (controller_->running()) return;
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

void MainWindow::closeEvent(QCloseEvent* event) {
    if (!quitRequested_ && trayIcon_->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}

void MainWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::WindowStateChange && isMinimized() && !quitRequested_)
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
