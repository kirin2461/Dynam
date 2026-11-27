#include "StealthMonitorWidget.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QPushButton>
#include <QHeaderView>
#include <QFont>
#include <QDateTime>

namespace widgets {

StealthMonitorWidget::StealthMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void StealthMonitorWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    // ═══════ Row 1: Title + Reference Profile ═══════
    auto* titleRow = new QHBoxLayout();
    auto* titleLabel = new QLabel(tr("Shadow Classifier — Stealth Monitor"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    titleRow->addWidget(titleLabel);
    titleRow->addStretch();

    auto* profileLabel = new QLabel(tr("Reference:"));
    titleRow->addWidget(profileLabel);
    m_profileCombo = new QComboBox();
    m_profileCombo->addItem(tr("Web Browsing"), "web_browsing");
    m_profileCombo->addItem(tr("Video Stream"), "video_stream");
    m_profileCombo->addItem(tr("Messenger"), "messenger");
    m_profileCombo->addItem(tr("Gaming"), "gaming");
    m_profileCombo->addItem(tr("File Download"), "file_download");
    connect(m_profileCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &StealthMonitorWidget::onProfileChanged);
    titleRow->addWidget(m_profileCombo);
    mainLayout->addLayout(titleRow);

    // ═══════ Row 2: Main stealth gauge + Detection status ═══════
    auto* gaugeRow = new QHBoxLayout();
    gaugeRow->setSpacing(16);

    // Stealth gauge
    auto* gaugeBox = new QGroupBox(tr("Aggregate Stealth Score"));
    auto* gaugeLayout = new QVBoxLayout(gaugeBox);

    m_stealthValue = new QLabel("0.000");
    QFont gaugeFont = m_stealthValue->font();
    gaugeFont.setPointSize(36);
    gaugeFont.setBold(true);
    m_stealthValue->setFont(gaugeFont);
    m_stealthValue->setAlignment(Qt::AlignCenter);
    m_stealthValue->setStyleSheet("color: #6c7086;");
    gaugeLayout->addWidget(m_stealthValue);

    m_stealthGauge = new QProgressBar();
    m_stealthGauge->setRange(0, 1000);
    m_stealthGauge->setValue(0);
    m_stealthGauge->setTextVisible(false);
    m_stealthGauge->setFixedHeight(12);
    gaugeLayout->addWidget(m_stealthGauge);

    auto* gaugeLabels = new QHBoxLayout();
    auto* detLabel = new QLabel(tr("DETECTED"));
    detLabel->setStyleSheet("color: #f38ba8;");
    gaugeLabels->addWidget(detLabel);
    gaugeLabels->addStretch();
    auto* safeLabel = new QLabel(tr("UNDETECTED"));
    safeLabel->setStyleSheet("color: #a6e3a1;");
    safeLabels:
    gaugeLabels->addWidget(safeLabel);
    gaugeLayout->addLayout(gaugeLabels);

    gaugeRow->addWidget(gaugeBox, 2);

    // Detection status panel
    auto* statusBox = new QGroupBox(tr("Detection Status"));
    auto* statusLayout = new QVBoxLayout(statusBox);

    m_detectionStatus = new QLabel(tr("Evaluating..."));
    QFont statusFont = m_detectionStatus->font();
    statusFont.setPointSize(16);
    statusFont.setBold(true);
    m_detectionStatus->setFont(statusFont);
    m_detectionStatus->setAlignment(Qt::AlignCenter);
    statusLayout->addWidget(m_detectionStatus);

    statusLayout->addSpacing(8);

    auto* learnedRow = new QHBoxLayout();
    learnedRow->addWidget(new QLabel(tr("SizeErrorLearner P(detected):")));
    m_learnedProb = new QLabel("—");
    m_learnedProb->setFont(statusFont);
    learnedRow->addWidget(m_learnedProb);
    statusLayout->addLayout(learnedRow);

    auto* thresholdRow = new QHBoxLayout();
    thresholdRow->addWidget(new QLabel(tr("Threshold:")));
    m_thresholdLabel = new QLabel("0.50");
    thresholdRow->addWidget(m_thresholdLabel);
    statusLayout->addLayout(thresholdRow);

    statusLayout->addStretch();

    gaugeRow->addWidget(statusBox, 1);

    // Window + Strategy
    auto* windowBox = new QGroupBox(tr("Flow Window"));
    auto* windowLayout = new QVBoxLayout(windowBox);

    m_windowLabel = new QLabel("0 / 50 packets");
    QFont windowFont = m_windowLabel->font();
    windowFont.setPointSize(14);
    m_windowLabel->setFont(windowFont);
    windowLayout->addWidget(m_windowLabel);

    m_windowProgress = new QProgressBar();
    m_windowProgress->setRange(0, 50);
    m_windowProgress->setValue(0);
    m_windowProgress->setTextVisible(false);
    m_windowProgress->setFixedHeight(8);
    windowLayout->addWidget(m_windowProgress);

    windowLayout->addSpacing(8);

    m_strategyLabel = new QLabel(tr("Strategy: Adaptive"));
    m_strategyLabel->setStyleSheet("color: #89b4fa; font-weight: bold;");
    windowLayout->addWidget(m_strategyLabel);

    windowLayout->addStretch();

    gaugeRow->addWidget(windowBox, 1);

    mainLayout->addLayout(gaugeRow);

    // ═══════ Row 3: 7 Metric Cards ═══════
    auto* metricsBox = new QGroupBox(tr("Heuristic Metrics (Weighted → Stealth)"));
    auto* metricsGrid = new QGridLayout(metricsBox);
    metricsGrid->setSpacing(8);

    auto createMetricCard = [](const QString& name, const QString& weight, MetricCard& card) {
        auto* container = new QWidget();
        auto* layout = new QVBoxLayout(container);
        layout->setContentsMargins(8, 6, 8, 6);

        auto* topRow = new QHBoxLayout();
        card.indicator = new QWidget();
        card.indicator->setFixedSize(10, 10);
        card.indicator->setStyleSheet("background: #6c7086; border-radius: 5px;");
        topRow->addWidget(card.indicator);
        card.name = new QLabel(name);
        card.name->setStyleSheet("font-size: 9pt; color: #a6adc8;");
        topRow->addWidget(card.name);
        topRow->addStretch();
        card.weight = new QLabel(weight);
        card.weight->setStyleSheet("font-size: 8pt; color: #585b70;");
        topRow->addWidget(card.weight);
        layout->addLayout(topRow);

        card.value = new QLabel("—");
        QFont valueFont = card.value->font();
        valueFont.setPointSize(14);
        valueFont.setBold(true);
        card.value->setFont(valueFont);
        layout->addWidget(card.value);

        return container;
    };

    metricsGrid->addWidget(createMetricCard(tr("Entropy"), "w=0.25", m_entropy), 0, 0);
    metricsGrid->addWidget(createMetricCard(tr("Chi² p-value"), "w=0.25", m_chi2), 0, 1);
    metricsGrid->addWidget(createMetricCard(tr("KS Distance"), "w=0.10", m_ks), 0, 2);
    metricsGrid->addWidget(createMetricCard(tr("Wasserstein-1"), "w=0.05", m_wasserstein), 0, 3);
    metricsGrid->addWidget(createMetricCard(tr("Size Variance"), "w=0.10", m_sizeVar), 0, 4);
    metricsGrid->addWidget(createMetricCard(tr("Timing CoV"), "w=0.15", m_timingCov), 0, 5);
    metricsGrid->addWidget(createMetricCard(tr("Burst Anomaly"), "w=0.10", m_burst), 0, 6);

    mainLayout->addWidget(metricsBox);

    // ═══════ Row 4: History + Benchmark ═══════
    auto* bottomRow = new QHBoxLayout();
    bottomRow->setSpacing(16);

    // History stats
    auto* historyBox = new QGroupBox(tr("Stealth History"));
    auto* historyLayout = new QVBoxLayout(historyBox);

    auto* historyStats = new QHBoxLayout();
    
    auto addStat = [&](const QString& label, QLabel*& target) {
        auto* w = new QWidget();
        auto* l = new QVBoxLayout(w);
        l->setContentsMargins(4, 2, 4, 2);
        auto* name = new QLabel(label);
        name->setStyleSheet("font-size: 8pt; color: #585b70;");
        l->addWidget(name);
        target = new QLabel("—");
        QFont f = target->font();
        f.setBold(true);
        target->setFont(f);
        l->addWidget(target);
        historyStats->addWidget(w);
    };

    addStat(tr("Last"), m_historyLast);
    addStat(tr("Avg"), m_historyAvg);
    addStat(tr("Min"), m_historyMin);
    addStat(tr("Max"), m_historyMax);
    historyStats->addStretch();
    historyLayout->addLayout(historyStats);

    // Simple text-based sparkline
    auto* sparkline = new QLabel("▁▂▃▅▇▅▃▂▁▂▃▅▇▅▃");
    sparkline->setStyleSheet("font-family: monospace; font-size: 18pt; color: #89b4fa;");
    sparkline->setAlignment(Qt::AlignCenter);
    historyLayout->addWidget(sparkline);

    bottomRow->addWidget(historyBox, 1);

    // Benchmark
    auto* benchBox = new QGroupBox(tr("Strategy Benchmark"));
    auto* benchLayout = new QVBoxLayout(benchBox);

    m_benchmarkStrategy = new QComboBox();
    m_benchmarkStrategy->addItem(tr("Random"), "random");
    m_benchmarkStrategy->addItem(tr("HTTP Mimic"), "http_mimic");
    m_benchmarkStrategy->addItem(tr("TLS Mimic"), "tls_mimic");
    m_benchmarkStrategy->addItem(tr("QUIC Mimic"), "quic_mimic");
    m_benchmarkStrategy->addItem(tr("DNS Mimic"), "dns_mimic");
    m_benchmarkStrategy->addItem(tr("Adaptive"), "adaptive");
    benchLayout->addWidget(m_benchmarkStrategy);

    m_benchmarkButton = new QPushButton(tr("Run Benchmark (200 samples)"));
    connect(m_benchmarkButton, &QPushButton::clicked, this, &StealthMonitorWidget::onRunBenchmark);
    benchLayout->addWidget(m_benchmarkButton);

    m_benchmarkResult = new QLabel(tr("No benchmark run yet"));
    m_benchmarkResult->setWordWrap(true);
    m_benchmarkResult->setStyleSheet("font-size: 9pt; color: #a6adc8;");
    benchLayout->addWidget(m_benchmarkResult);

    bottomRow->addWidget(benchBox, 1);

    mainLayout->addLayout(bottomRow);

    // ═══════ Row 5: TestReport Table ═══════
    auto* reportBox = new QGroupBox(tr("Evaluation History (TestReports)"));
    auto* reportLayout = new QVBoxLayout(reportBox);

    m_reportTable = new QTableWidget();
    m_reportTable->setColumnCount(7);
    m_reportTable->setHorizontalHeaderLabels({
        tr("Time"), tr("Strategy"), tr("Stealth"), tr("Detected"),
        tr("Entropy"), tr("Chi²"), tr("P(learned)")
    });
    m_reportTable->horizontalHeader()->setStretchLastSection(true);
    m_reportTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_reportTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_reportTable->verticalHeader()->setVisible(false);
    m_reportTable->setAlternatingRowColors(true);
    reportLayout->addWidget(m_reportTable);

    mainLayout->addWidget(reportBox);
}

void StealthMonitorWidget::updateFromJson(const QJsonObject& data)
{
    if (data.contains("stealth_score")) {
        double score = data.value("stealth_score").toDouble();
        bool detected = data.value("detected").toBool();
        updateStealthScore(score, detected);
    }
    if (data.contains("metrics")) {
        updateMetrics(data.value("metrics").toObject());
    }
    if (data.contains("learned_probability")) {
        updateLearnedProbability(data.value("learned_probability").toDouble());
    }
    if (data.contains("strategy")) {
        m_strategyLabel->setText(tr("Strategy: %1").arg(data.value("strategy").toString()));
    }
}

void StealthMonitorWidget::updateWindowStatus(int collected, int total)
{
    m_windowLabel->setText(tr("%1 / %2 packets").arg(collected).arg(total));
    m_windowProgress->setRange(0, total);
    m_windowProgress->setValue(collected);
}

void StealthMonitorWidget::updateMetrics(const QJsonObject& metrics)
{
    auto setMetric = [](MetricCard& card, double value, const QString& text,
                       double goodThreshold, bool inverse = false) {
        card.value->setText(text);
        bool good = inverse ? (value < goodThreshold) : (value > goodThreshold);
        card.indicator->setStyleSheet(
            good ? "background: #a6e3a1; border-radius: 5px;"
                 : "background: #f38ba8; border-radius: 5px;"
        );
    };

    if (metrics.contains("entropy")) {
        double v = metrics.value("entropy").toDouble();
        setMetric(m_entropy, v, QString::number(v, 'f', 3), 0.7);
    }
    if (metrics.contains("chi2_pvalue")) {
        double v = metrics.value("chi2_pvalue").toDouble();
        setMetric(m_chi2, v, QString::number(v, 'f', 4), 0.05, false);
        m_chi2.indicator->setStyleSheet(
            v > 0.05 ? "background: #a6e3a1; border-radius: 5px;"
                     : "background: #f38ba8; border-radius: 5px;"
        );
    }
    if (metrics.contains("ks_distance")) {
        double v = metrics.value("ks_distance").toDouble();
        setMetric(m_ks, v, QString::number(v, 'f', 3), 0.1, true);
    }
    if (metrics.contains("wasserstein")) {
        double v = metrics.value("wasserstein").toDouble();
        m_wasserstein.value->setText(QString::number(v, 'f', 1) + " B");
        m_wasserstein.indicator->setStyleSheet(
            v < 75.0 ? "background: #a6e3a1; border-radius: 5px;"
                     : "background: #f38ba8; border-radius: 5px;"
        );
    }
    if (metrics.contains("size_variance_ratio")) {
        double v = metrics.value("size_variance_ratio").toDouble();
        setMetric(m_sizeVar, v, QString::number(v, 'f', 3), 0.5, false);
        double diff = std::abs(v - 1.0);
        m_sizeVar.indicator->setStyleSheet(
            diff < 0.3 ? "background: #a6e3a1; border-radius: 5px;"
                       : "background: #f38ba8; border-radius: 5px;"
        );
    }
    if (metrics.contains("timing_cov")) {
        double v = metrics.value("timing_cov").toDouble();
        m_timingCov.value->setText(QString::number(v, 'f', 3));
        m_timingCov.indicator->setStyleSheet("background: #f9e2af; border-radius: 5px;");
    }
    if (metrics.contains("burst_anomaly")) {
        double v = metrics.value("burst_anomaly").toDouble();
        setMetric(m_burst, v, QString::number(v, 'f', 3), 0.3, true);
    }
}

void StealthMonitorWidget::updateStealthScore(double score, bool detected)
{
    m_stealthValue->setText(QString::number(score, 'f', 3));
    m_stealthGauge->setValue(static_cast<int>(score * 1000));
    updateGaugeColor(score);

    if (detected) {
        m_detectionStatus->setText(tr("✗ DETECTED"));
        m_detectionStatus->setStyleSheet("color: #f38ba8;");
    } else {
        m_detectionStatus->setText(tr("✓ UNDETECTED"));
        m_detectionStatus->setStyleSheet("color: #a6e3a1;");
    }

    // Update history last
    m_historyLast->setText(QString::number(score, 'f', 3));
    m_scoreHistory.append(score);
    if (m_scoreHistory.size() > 100) m_scoreHistory.removeFirst();

    // Recalculate stats
    if (!m_scoreHistory.isEmpty()) {
        double sum = 0, mn = 1.0, mx = 0.0;
        for (double s : m_scoreHistory) {
            sum += s;
            mn = std::min(mn, s);
            mx = std::max(mx, s);
        }
        m_historyAvg->setText(QString::number(sum / m_scoreHistory.size(), 'f', 3));
        m_historyMin->setText(QString::number(mn, 'f', 3));
        m_historyMax->setText(QString::number(mx, 'f', 3));
    }
}

void StealthMonitorWidget::updateLearnedProbability(double prob)
{
    if (prob < 0) {
        m_learnedProb->setText("—");
    } else {
        m_learnedProb->setText(QString::number(prob, 'f', 3));
        m_learnedProb->setStyleSheet(
            prob > 0.5 ? "color: #f38ba8; font-size: 16pt; font-weight: bold;"
                       : "color: #a6e3a1; font-size: 16pt; font-weight: bold;"
        );
    }
}

void StealthMonitorWidget::addTestReport(const QJsonObject& report)
{
    int row = m_reportTable->rowCount();
    m_reportTable->insertRow(row);

    auto time = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString strategy = report.value("strategy").toString();
    double stealth = report.value("stealth").toDouble();
    bool detected = report.value("detected").toBool();
    double entropy = report.value("entropy").toDouble();
    double chi2 = report.value("chi2_pvalue").toDouble();
    double learned = report.value("learned_probability").toDouble(-1.0);

    m_reportTable->setItem(row, 0, new QTableWidgetItem(time));
    m_reportTable->setItem(row, 1, new QTableWidgetItem(strategy));
    m_reportTable->setItem(row, 2, new QTableWidgetItem(QString::number(stealth, 'f', 3)));
    m_reportTable->setItem(row, 3, new QTableWidgetItem(detected ? tr("✗ YES") : tr("✓ NO")));
    m_reportTable->setItem(row, 4, new QTableWidgetItem(QString::number(entropy, 'f', 3)));
    m_reportTable->setItem(row, 5, new QTableWidgetItem(QString::number(chi2, 'f', 4)));
    m_reportTable->setItem(row, 6, new QTableWidgetItem(
        learned >= 0 ? QString::number(learned, 'f', 3) : "—"));

    // Keep last 50 rows
    while (m_reportTable->rowCount() > 50) {
        m_reportTable->removeRow(0);
    }
}

void StealthMonitorWidget::updateHistory(const QJsonArray& scores)
{
    m_scoreHistory.clear();
    for (const auto& s : scores) {
        m_scoreHistory.append(s.toDouble());
    }
}

void StealthMonitorWidget::updateGaugeColor(double score)
{
    QString color;
    if (score > 0.7) color = "#a6e3a1";       // green
    else if (score > 0.5) color = "#f9e2af";   // yellow
    else if (score > 0.3) color = "#fab387";   // orange
    else color = "#f38ba8";                     // red

    m_stealthValue->setStyleSheet(QString("color: %1;").arg(color));

    QString barStyle = QString(
        "QProgressBar::chunk { background: %1; border-radius: 6px; }"
        "QProgressBar { background: #313244; border-radius: 6px; border: none; }"
    ).arg(color);
    m_stealthGauge->setStyleSheet(barStyle);
}

void StealthMonitorWidget::onProfileChanged(int index)
{
    QString profile = m_profileCombo->itemData(index).toString();
    emit referenceProfileChanged(profile);
}

void StealthMonitorWidget::onRunBenchmark()
{
    QString strategy = m_benchmarkStrategy->currentData().toString();
    m_benchmarkButton->setEnabled(false);
    m_benchmarkButton->setText(tr("Running..."));
    emit benchmarkRequested(strategy);
}

// ─── Benchmark lifecycle (MainWindow drives these via REST) ────────

void StealthMonitorWidget::onTestStarted()
{
    if (m_benchmarkButton) {
        m_benchmarkButton->setEnabled(false);
        m_benchmarkButton->setText(tr("Running..."));
    }
    if (m_benchmarkResult) {
        m_benchmarkResult->setText(tr("Benchmark running…"));
    }
}

void StealthMonitorWidget::onTestFinished()
{
    if (m_benchmarkButton) {
        m_benchmarkButton->setEnabled(true);
        m_benchmarkButton->setText(tr("Run Benchmark (200 samples)"));
    }
}

void StealthMonitorWidget::updateProgress(int progress, const QString& status)
{
    if (m_benchmarkResult) {
        m_benchmarkResult->setText(
            QStringLiteral("%1 — %2%").arg(status).arg(progress));
    }
}

void StealthMonitorWidget::updateResults(const QJsonObject& data)
{
    const QJsonArray strategies = data.value("strategies").toArray();
    if (strategies.isEmpty()) {
        if (m_benchmarkResult) {
            m_benchmarkResult->setText(tr("No benchmark results"));
        }
        return;
    }

    double gsum = 0.0;
    double gmin = 1.0;
    double gmax = 0.0;
    double best = -1.0;
    QString bestName;

    for (const QJsonValue& v : strategies) {
        const QJsonObject s = v.toObject();
        const double avg = s.value("avg_stealth").toDouble();
        const double mn = s.value("min_stealth").toDouble();
        const double mx = s.value("max_stealth").toDouble();
        const double det = s.value("detection_rate").toDouble();
        const QString name = s.value("strategy").toString();

        gsum += avg;
        gmin = qMin(gmin, mn);
        gmax = qMax(gmax, mx);
        if (avg > best) {
            best = avg;
            bestName = name;
        }

        const int row = m_reportTable->rowCount();
        m_reportTable->insertRow(row);
        auto setCell = [this, row](int col, const QString& text) {
            m_reportTable->setItem(row, col, new QTableWidgetItem(text));
        };
        setCell(0, QDateTime::currentDateTime().toString("HH:mm:ss"));
        setCell(1, name);
        setCell(2, QString::number(avg, 'f', 3));
        setCell(3, QStringLiteral("%1%").arg(det * 100.0, 0, 'f', 0));
        setCell(4, QStringLiteral("—"));
        setCell(5, QStringLiteral("—"));
        setCell(6, QStringLiteral("—"));
    }
    m_reportTable->scrollToBottom();

    const double gavg = gsum / static_cast<double>(strategies.size());
    updateStealthScore(gavg, gavg < 0.5);
    if (m_historyAvg) m_historyAvg->setText(QString::number(gavg, 'f', 3));
    if (m_historyMin) m_historyMin->setText(QString::number(gmin, 'f', 3));
    if (m_historyMax) m_historyMax->setText(QString::number(gmax, 'f', 3));
    if (m_historyLast) m_historyLast->setText(QString::number(gavg, 'f', 3));
    m_scoreHistory.append(gavg);
    if (m_scoreHistory.size() > 100) m_scoreHistory.removeFirst();

    if (m_benchmarkResult) {
        m_benchmarkResult->setText(
            tr("Best: %1 (%2) — avg %3")
                .arg(bestName)
                .arg(QString::number(best, 'f', 3))
                .arg(QString::number(gavg, 'f', 3)));
    }
}

} // namespace widgets
