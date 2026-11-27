#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QStatusBar>
#include <QLabel>
#include <QJsonObject>

#include "core/RestClient.hpp"
#include "core/WebSocketClient.hpp"
#include "models/ConfigModel.hpp"
#include "widgets/TrafficMonitorWidget.hpp"
#include "widgets/ConfigWidget.hpp"
#include "widgets/LogWidget.hpp"
#include "widgets/StealthMonitorWidget.hpp"
#include "widgets/StatsWidget.hpp"
#include "widgets/SettingsWidget.hpp"

/**
 * @brief Main application window with tabbed interface.
 * 
 * Tabs:
 * 1. Traffic Monitor — real-time connection tracking
 * 2. Configuration — ONNX, DPI bypass, proxy settings
 * 3. Activity Log — filterable log viewer
 * 4. Adversary Tester — attack simulation
 * 5. Statistics — aggregate metrics dashboard
 * 6. Settings — language, theme
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;
    
    /// Set backend server URL
    void setServerUrl(const QString& url);

private slots:
    void onTrafficTabSelected();
    void onConfigTabSelected();
    void onLogsTabSelected();
    void onStatsTabSelected();
    
    void onTrafficRefreshRequested();
    void onConfigSaved();
    void onLogsClearRequested();
    void onStealthBenchmarkRequested(const QString& strategy);
    
    void onLanguageChanged(const QString& lang);
    void onThemeChanged(const QString& theme);
    
    void onWebSocketConnected();
    void onWebSocketDisconnected();
    void onTrafficUpdate(const QJsonObject& data);
    void onLogEntry(const QJsonObject& entry);
    void onStatsUpdate(const QJsonObject& data);
    void onStealthUpdate(const QJsonObject& data);

private:
    void setupUi();
    void setupConnections();
    void updateConnectionStatus(bool connected);
    
    // Tab widget
    QTabWidget* m_tabWidget;
    
    // Widgets
    widgets::TrafficMonitorWidget* m_trafficWidget;
    widgets::ConfigWidget* m_configWidget;
    widgets::LogWidget* m_logWidget;
    widgets::StealthMonitorWidget* m_stealthWidget;
    widgets::StatsWidget* m_statsWidget;
    widgets::SettingsWidget* m_settingsWidget;
    
    // Models
    models::ConfigModel* m_configModel;
    
    // Backend communication
    core::RestClient* m_restClient;
    core::WebSocketClient* m_wsClient;
    
    // Status bar
    QLabel* m_connectionStatusLabel;
};
