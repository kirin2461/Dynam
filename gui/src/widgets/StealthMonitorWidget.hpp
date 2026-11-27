#pragma once

#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QComboBox>
#include <QTableWidget>
#include <QTimer>
#include <QPushButton>
#include <QJsonObject>
#include <QJsonArray>
#include <QVector>

namespace widgets {

/**
 * @brief Shadow Classifier monitor — visualizes the AdversaryTester pipeline.
 *
 * NOT an "attack tester" — this is a real-time stealth evaluation dashboard.
 * The actual AdversaryTester:
 *   - Records outgoing packets via record_packet()
 *   - Evaluates stealth every N packets (window) using 7 statistical metrics
 *   - Computes aggregate_stealth() weighted score [0, 1]
 *   - Sends DetectionFeedback to AdversarialPadding when stealth < threshold
 *   - Has SizeErrorLearner for online P(detected) estimation
 *
 * UI shows:
 *   1. Main stealth gauge (big, color-coded)
 *   2. 7 individual metric cards with weights
 *   3. Window progress (packets collected / window_packets)
 *   4. Detection status + SizeErrorLearner probability
 *   5. Reference profile selector (web/video/messenger/gaming)
 *   6. Stealth history sparkline
 *   7. Strategy benchmark runner
 *   8. TestReport log table
 */
class StealthMonitorWidget : public QWidget {
    Q_OBJECT

public:
    explicit StealthMonitorWidget(QWidget* parent = nullptr);

    /// Update from WebSocket/backend JSON
    void updateFromJson(const QJsonObject& data);
    
    /// Update window status (packets collected)
    void updateWindowStatus(int collected, int total);
    
    /// Update the 7 heuristic metrics
    void updateMetrics(const QJsonObject& metrics);
    
    /// Update stealth score
    void updateStealthScore(double score, bool detected);
    
    /// Update SizeErrorLearner probability
    void updateLearnedProbability(double prob);
    
    /// Add a TestReport to history
    void addTestReport(const QJsonObject& report);
    
    /// Update history sparkline data
    void updateHistory(const QJsonArray& scores);

    // ─── Benchmark lifecycle (driven by MainWindow's REST calls) ───
    /// Benchmark started: disable the run button, show "running" state.
    void onTestStarted();
    /// Benchmark finished (success or failure): re-enable the run button.
    void onTestFinished();
    /// Progress/status line while a (streamed) benchmark runs.
    void updateProgress(int progress, const QString& status);
    /// Final benchmark payload:
    /// {strategies:[{strategy,avg,min,max,detection_rate,…}],
    ///  best_strategy, best_stealth}
    void updateResults(const QJsonObject& data);

signals:
    void referenceProfileChanged(const QString& profile);
    void benchmarkRequested(const QString& strategy);
    void feedbackToggleChanged(bool enabled);
    void thresholdChanged(double value);

private slots:
    void onProfileChanged(int index);
    void onRunBenchmark();

private:
    void setupUi();
    void updateGaugeColor(double score);
    QString getMetricColor(double value, double goodThreshold, bool inverse = false) const;

    // ─── Main gauge ────────────────────────────────────────────────────
    QLabel* m_stealthValue;
    QProgressBar* m_stealthGauge;
    QLabel* m_detectionStatus;
    QLabel* m_learnedProb;

    // ─── 7 metric cards ────────────────────────────────────────────────
    struct MetricCard {
        QLabel* name;
        QLabel* value;
        QLabel* weight;
        QWidget* indicator; // colored dot
    };
    MetricCard m_entropy;
    MetricCard m_chi2;
    MetricCard m_ks;
    MetricCard m_wasserstein;
    MetricCard m_sizeVar;
    MetricCard m_timingCov;
    MetricCard m_burst;

    // ─── Window status ─────────────────────────────────────────────────
    QLabel* m_windowLabel;
    QProgressBar* m_windowProgress;
    QLabel* m_strategyLabel;

    // ─── Reference profile ─────────────────────────────────────────────
    QComboBox* m_profileCombo;

    // ─── History ───────────────────────────────────────────────────────
    QLabel* m_historyAvg;
    QLabel* m_historyMin;
    QLabel* m_historyMax;
    QLabel* m_historyLast;
    QVector<double> m_scoreHistory;

    // ─── Benchmark ─────────────────────────────────────────────────────
    QComboBox* m_benchmarkStrategy;
    QPushButton* m_benchmarkButton;
    QLabel* m_benchmarkResult;

    // ─── TestReport table ──────────────────────────────────────────────
    QTableWidget* m_reportTable;

    // ─── Threshold ─────────────────────────────────────────────────────
    QLabel* m_thresholdLabel;
};

} // namespace widgets
