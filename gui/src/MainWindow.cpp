#include "MainWindow.hpp"

#include <QVBoxLayout>
#include <QJsonArray>
#include <QApplication>

#include "core/I18nManager.hpp"
#include "core/ThemeManager.hpp"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle(tr("Dynam — Network Control Protocol"));
    resize(1200, 800);
    
    // Create models
    m_configModel = new models::ConfigModel(this);
    
    // Create backend clients
    m_restClient = new core::RestClient(this);
    m_wsClient = new core::WebSocketClient(this);
    
    setupUi();
    setupConnections();
    
    // Connect to WebSocket
    m_wsClient->connectToServer(m_restClient->baseUrl());
}

MainWindow::~MainWindow() = default;

void MainWindow::setServerUrl(const QString& url)
{
    m_restClient->setBaseUrl(url);
    m_wsClient->connectToServer(url);
}

void MainWindow::setupUi()
{
    // ─── Tab widget ────────────────────────────────────────────────────
    m_tabWidget = new QTabWidget();
    m_tabWidget->setTabPosition(QTabWidget::North);
    m_tabWidget->setDocumentMode(true);
    
    // ─── Traffic Monitor Tab ───────────────────────────────────────────
    m_trafficWidget = new widgets::TrafficMonitorWidget();
    m_tabWidget->addTab(m_trafficWidget, tr("Traffic Monitor"));
    
    // ─── Configuration Tab ─────────────────────────────────────────────
    m_configWidget = new widgets::ConfigWidget();
    m_tabWidget->addTab(m_configWidget, tr("Configuration"));
    
    // ─── Activity Log Tab ──────────────────────────────────────────────
    m_logWidget = new widgets::LogWidget();
    m_tabWidget->addTab(m_logWidget, tr("Activity Log"));
    
    // ─── Stealth Monitor Tab ──────────────────────────────────────────
    m_stealthWidget = new widgets::StealthMonitorWidget();
    m_tabWidget->addTab(m_stealthWidget, tr("Stealth Monitor"));
    
    // ─── Statistics Tab ────────────────────────────────────────────────
    m_statsWidget = new widgets::StatsWidget();
    m_tabWidget->addTab(m_statsWidget, tr("Statistics"));
    
    // ─── Settings Tab ──────────────────────────────────────────────────
    m_settingsWidget = new widgets::SettingsWidget();
    m_tabWidget->addTab(m_settingsWidget, tr("Settings"));
    
    setCentralWidget(m_tabWidget);
    
    // ─── Status bar ────────────────────────────────────────────────────
    m_connectionStatusLabel = new QLabel(tr("Disconnected"));
    m_connectionStatusLabel->setStyleSheet("color: #f38ba8;");
    statusBar()->addPermanentWidget(m_connectionStatusLabel);
    
    statusBar()->showMessage(tr("Ready"));
}

void MainWindow::setupConnections()
{
    // Tab selection
    connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](int index) {
        if (index == 0) onTrafficTabSelected();
        else if (index == 1) onConfigTabSelected();
        else if (index == 2) onLogsTabSelected();
        else if (index == 4) onStatsTabSelected();
    });
    
    // Widget signals
    connect(m_trafficWidget, &widgets::TrafficMonitorWidget::refreshRequested,
            this, &MainWindow::onTrafficRefreshRequested);
    connect(m_configWidget, &widgets::ConfigWidget::configSaved,
            this, &MainWindow::onConfigSaved);
    connect(m_logWidget, &widgets::LogWidget::clearRequested,
            this, &MainWindow::onLogsClearRequested);
    connect(m_stealthWidget, &widgets::StealthMonitorWidget::benchmarkRequested,
            this, &MainWindow::onStealthBenchmarkRequested);
    
    // Settings
    connect(m_settingsWidget, &widgets::SettingsWidget::languageChanged,
            this, &MainWindow::onLanguageChanged);
    connect(m_settingsWidget, &widgets::SettingsWidget::themeChanged,
            this, &MainWindow::onThemeChanged);
    
    // WebSocket
    connect(m_wsClient, &core::WebSocketClient::connected,
            this, &MainWindow::onWebSocketConnected);
    connect(m_wsClient, &core::WebSocketClient::disconnected,
            this, &MainWindow::onWebSocketDisconnected);
    connect(m_wsClient, &core::WebSocketClient::trafficUpdate,
            this, &MainWindow::onTrafficUpdate);
    connect(m_wsClient, &core::WebSocketClient::logEntry,
            this, &MainWindow::onLogEntry);
    connect(m_wsClient, &core::WebSocketClient::statsUpdate,
            this, &MainWindow::onStatsUpdate);
    connect(m_wsClient, &core::WebSocketClient::stealthUpdate,
            this, &MainWindow::onStealthUpdate);
}

void MainWindow::onTrafficTabSelected()
{
    // Fetch traffic data via REST
    m_restClient->getTraffic([this](const QJsonObject& data, bool ok) {
        if (ok) {
            m_trafficWidget->updateTraffic(data);
        }
    });
}

void MainWindow::onConfigTabSelected()
{
    // Fetch config via REST
    m_restClient->getConfig([this](const QJsonObject& data, bool ok) {
        if (ok) {
            m_configModel->loadFromJson(data);
            m_configWidget->loadFromModel(m_configModel);
        }
    });
}

void MainWindow::onLogsTabSelected()
{
    // Fetch logs via REST
    m_restClient->getLogs(1000, [this](const QJsonObject& data, bool ok) {
        if (ok) {
            QJsonArray logs = data.value("logs").toArray();
            for (const auto& log : logs) {
                m_logWidget->addEntry(log.toObject());
            }
        }
    });
}

void MainWindow::onStatsTabSelected()
{
    // Fetch stats via REST
    m_restClient->getStats([this](const QJsonObject& data, bool ok) {
        if (ok) {
            m_statsWidget->updateStats(data);
        }
    });
}

void MainWindow::onTrafficRefreshRequested()
{
    m_restClient->getTraffic([this](const QJsonObject& data, bool ok) {
        if (ok) {
            m_trafficWidget->updateTraffic(data);
        }
    });
}

void MainWindow::onConfigSaved()
{
    QJsonObject config = m_configModel->toJson();
    m_restClient->updateConfig(config, [this](bool ok) {
        if (ok) {
            statusBar()->showMessage(tr("Configuration saved"), 3000);
        } else {
            statusBar()->showMessage(tr("Failed to save configuration"), 3000);
        }
    });
}

void MainWindow::onLogsClearRequested()
{
    m_restClient->clearLogs([this](bool ok) {
        if (ok) {
            statusBar()->showMessage(tr("Logs cleared"), 3000);
        }
    });
}

void MainWindow::onStealthBenchmarkRequested(const QString& strategy)
{
    QJsonObject params;
    params["strategy"] = strategy;
    params["samples"] = 200;
    params["runs"] = 8;

    m_stealthWidget->onTestStarted();

    m_restClient->runStealthBenchmark(params, [this](const QJsonObject& data, bool ok) {
        if (ok) {
            m_stealthWidget->updateResults(data);
            m_stealthWidget->onTestFinished();
        } else {
            m_stealthWidget->onTestFinished();
        }
    });
}

void MainWindow::onLanguageChanged(const QString& lang)
{
    core::I18nManager::instance().setLanguage(lang);
    // Re-translate UI
    m_tabWidget->setTabText(0, tr("Traffic Monitor"));
    m_tabWidget->setTabText(1, tr("Configuration"));
    m_tabWidget->setTabText(2, tr("Activity Log"));
    m_tabWidget->setTabText(3, tr("Stealth Monitor"));
    m_tabWidget->setTabText(4, tr("Statistics"));
    m_tabWidget->setTabText(5, tr("Settings"));
}

void MainWindow::onThemeChanged(const QString& theme)
{
    core::ThemeManager::instance().setTheme(theme);
}

void MainWindow::onWebSocketConnected()
{
    updateConnectionStatus(true);
    statusBar()->showMessage(tr("Connected to backend"), 3000);
}

void MainWindow::onWebSocketDisconnected()
{
    updateConnectionStatus(false);
    statusBar()->showMessage(tr("Disconnected from backend"), 3000);
}

void MainWindow::onTrafficUpdate(const QJsonObject& data)
{
    // Only update if traffic tab is active
    if (m_tabWidget->currentIndex() == 0) {
        m_trafficWidget->updateTraffic(data);
    }
}

void MainWindow::onLogEntry(const QJsonObject& entry)
{
    m_logWidget->addEntry(entry);
}

void MainWindow::onStatsUpdate(const QJsonObject& data)
{
    if (m_tabWidget->currentIndex() == 4) {
        m_statsWidget->updateStats(data);
    }
}

void MainWindow::onStealthUpdate(const QJsonObject& data)
{
    int progress = data.value("progress").toInt();
    QString status = data.value("status").toString();
    m_stealthWidget->updateProgress(progress, status);
    
    if (progress >= 100) {
        m_stealthWidget->updateResults(data);
        m_stealthWidget->onTestFinished();
    }
}

void MainWindow::updateConnectionStatus(bool connected)
{
    if (connected) {
        m_connectionStatusLabel->setText(tr("● Connected"));
        m_connectionStatusLabel->setStyleSheet("color: #a6e3a1;");
    } else {
        m_connectionStatusLabel->setText(tr("● Disconnected"));
        m_connectionStatusLabel->setStyleSheet("color: #f38ba8;");
    }
}
