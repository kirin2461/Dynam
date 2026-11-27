#pragma once

#include <QWidget>
#include <QComboBox>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QJsonObject>

namespace widgets {

/**
 * @brief Geneva Genetic Engine widget — preset strategies + visualization.
 * 
 * Shows:
 * - Preset strategies (TSPU 2026 Russia, GFW 2025 China, Iran DPI, Universal)
 * - Strategy steps (DUPLICATE, FRAGMENT, TAMPER_TTL/SEQ/FLAGS, DROP, DISORDER)
 * - Statistics (packets processed, duplicated, fragmented, tampered, dropped)
 * - Overhead tracking
 */
class GenevaWidget : public QWidget {
    Q_OBJECT

public:
    explicit GenevaWidget(QWidget* parent = nullptr);

signals:
    void strategySelected(const QString& strategy);

public slots:
    void updateStats(const QJsonObject& stats);
    void showStrategy(const QJsonObject& strategy);

private slots:
    void onStrategyChanged(int index);

private:
    void setupUi();

    QComboBox* m_strategyCombo;
    QPushButton* m_applyButton;
    QTableWidget* m_stepsTable;
    
    // Stats labels
    QLabel* m_packetsProcessed;
    QLabel* m_packetsDuplicated;
    QLabel* m_packetsFragmented;
    QLabel* m_packetsTampered;
    QLabel* m_packetsDropped;
    QLabel* m_overheadBytes;
};

} // namespace widgets
