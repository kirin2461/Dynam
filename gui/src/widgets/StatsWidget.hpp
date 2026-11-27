#pragma once

#include <QWidget>
#include <QLabel>
#include <QJsonObject>

namespace widgets {

/**
 * @brief Statistics dashboard widget.
 * 
 * Displays aggregate statistics:
 * - Total traffic (bytes, packets, connections)
 * - Stealth score distribution
 * - ONNX detection statistics
 * - Attack success rates
 */
class StatsWidget : public QWidget {
    Q_OBJECT

public:
    explicit StatsWidget(QWidget* parent = nullptr);
    
    /// Update statistics from JSON
    void updateStats(const QJsonObject& stats);

private:
    void setupUi();
    
    // Traffic stats
    QLabel* m_totalBytesLabel;
    QLabel* m_totalPacketsLabel;
    QLabel* m_totalConnectionsLabel;
    QLabel* m_avgBandwidthLabel;
    
    // Stealth stats
    QLabel* m_avgStealthLabel;
    QLabel* m_minStealthLabel;
    QLabel* m_maxStealthLabel;
    QLabel* m_medianStealthLabel;
    
    // ONNX stats
    QLabel* m_onnxInferencesLabel;
    QLabel* m_onnxDetectionsLabel;
    QLabel* m_onnxDetectionRateLabel;
    QLabel* m_onnxAvgConfidenceLabel;
    
    // Attack stats
    QLabel* m_totalAttacksLabel;
    QLabel* m_successfulAttacksLabel;
    QLabel* m_attackSuccessRateLabel;
};

} // namespace widgets
