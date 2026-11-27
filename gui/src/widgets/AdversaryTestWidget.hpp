#pragma once

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QComboBox>
#include <QSpinBox>
#include <QProgressBar>
#include <QTableWidget>
#include <QGroupBox>
#include <QJsonObject>
#include <QJsonArray>
#include <QTimer>

namespace widgets {

/**
 * @brief Adversarial Attack Testing module.
 * 
 * Tests system resilience against various attack types:
 * - ECS (EDNS Client Subnet) attacks
 * - Fragmentation attacks
 * - TTL manipulation
 * - HTTP obfuscation
 * - TLS split attacks
 * - Protocol rotation
 * - Combined attacks
 * 
 * For each attack:
 * - Run N iterations with configurable intensity
 * - Measure success rate, stealth score, detection rate
 * - Show detailed results per attack type
 */
class AdversaryTestWidget : public QWidget {
    Q_OBJECT

public:
    explicit AdversaryTestWidget(QWidget* parent = nullptr);

signals:
    void testRequested(const QJsonObject& params);
    void stopRequested();

public slots:
    void updateProgress(int percent, const QString& status);
    void addResult(const QJsonObject& result);
    void onTestFinished(const QJsonObject& summary);
    void onTestStarted();

private slots:
    void onRunTest();
    void onStopTest();

private:
    void setupUi();
    void updateSummary();

    // Controls
    QComboBox* m_attackTypeCombo;
    QSpinBox* m_iterationsSpin;
    QSpinBox* m_intensitySpin;
    QPushButton* m_runButton;
    QPushButton* m_stopButton;
    
    // Progress
    QProgressBar* m_progressBar;
    QLabel* m_statusLabel;
    
    // Summary
    QLabel* m_totalAttacksLabel;
    QLabel* m_successfulLabel;
    QLabel* m_detectedLabel;
    QLabel* m_avgStealthLabel;
    QLabel* m_successRateLabel;
    
    // Results table
    QTableWidget* m_resultsTable;
    
    // State
    bool m_running = false;
    int m_totalAttacks = 0;
    int m_successful = 0;
    int m_detected = 0;
    double m_stealthSum = 0.0;
};

} // namespace widgets
