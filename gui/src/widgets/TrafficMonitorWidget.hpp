#pragma once

#include <QWidget>
#include <QTableView>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QTimer>

#include "models/TrafficModel.hpp"

namespace widgets {

/**
 * @brief Traffic monitoring widget with real-time connection table.
 * 
 * Displays:
 * - Active connections with source, destination, protocol, bytes, packets
 * - Stealth scores (heuristic + ONNX combined)
 * - ONNX detection results
 * - Aggregate statistics (total bytes, packets, connections)
 * - Auto-refresh toggle
 */
class TrafficMonitorWidget : public QWidget {
    Q_OBJECT

public:
    explicit TrafficMonitorWidget(QWidget* parent = nullptr);
    
    /// Update traffic data from JSON
    void updateTraffic(const QJsonObject& data);
    
    /// Get the traffic model
    models::TrafficModel* model() { return m_model; }

signals:
    void refreshRequested();

private slots:
    void onToggleAutoRefresh(bool checked);
    void onRefreshClicked();

private:
    void setupUi();
    void updateStats();
    
    models::TrafficModel* m_model;
    QTableView* m_table;
    
    // Stats labels
    QLabel* m_totalBytesLabel;
    QLabel* m_totalPacketsLabel;
    QLabel* m_totalConnectionsLabel;
    QLabel* m_avgStealthLabel;
    QLabel* m_detectedLabel;
    
    // Controls
    QPushButton* m_refreshButton;
    QPushButton* m_autoRefreshButton;
    QTimer* m_autoRefreshTimer;
    bool m_autoRefresh = true;
};

} // namespace widgets
