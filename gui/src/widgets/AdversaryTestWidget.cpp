#include "AdversaryTestWidget.hpp"
#include <QHeaderView>
#include <QFont>
#include <QDateTime>

namespace widgets {

AdversaryTestWidget::AdversaryTestWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void AdversaryTestWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(12);

    // ─── Title ─────────────────────────────────────────────────────────
    auto* titleLabel = new QLabel(tr("Adversarial Attack Testing"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(14);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);

    auto* subtitleLabel = new QLabel(tr("Test system resilience against various attack types"));
    subtitleLabel->setStyleSheet("color: #a6adc8; font-size: 9pt;");
    mainLayout->addWidget(subtitleLabel);

    // ─── Configuration ─────────────────────────────────────────────────
    auto* configBox = new QGroupBox(tr("Attack Configuration"));
    auto* configLayout = new QGridLayout(configBox);

    configLayout->addWidget(new QLabel(tr("Attack Type:")), 0, 0);
    m_attackTypeCombo = new QComboBox();
    m_attackTypeCombo->addItem(tr("ECS (EDNS Client Subnet)"), "ecs");
    m_attackTypeCombo->addItem(tr("Fragmentation Attack"), "fragment");
    m_attackTypeCombo->addItem(tr("TTL Manipulation"), "ttl");
    m_attackTypeCombo->addItem(tr("HTTP Obfuscation"), "http");
    m_attackTypeCombo->addItem(tr("TLS Split Attack"), "tls_split");
    m_attackTypeCombo->addItem(tr("Protocol Rotation"), "rotation");
    m_attackTypeCombo->addItem(tr("Combined Attack"), "combined");
    m_attackTypeCombo->addItem(tr("All Attacks (Random)"), "all");
    configLayout->addWidget(m_attackTypeCombo, 0, 1);

    configLayout->addWidget(new QLabel(tr("Iterations:")), 1, 0);
    m_iterationsSpin = new QSpinBox();
    m_iterationsSpin->setRange(1, 10000);
    m_iterationsSpin->setValue(100);
    m_iterationsSpin->setSingleStep(10);
    configLayout->addWidget(m_iterationsSpin, 1, 1);

    configLayout->addWidget(new QLabel(tr("Intensity:")), 2, 0);
    m_intensitySpin = new QSpinBox();
    m_intensitySpin->setRange(1, 10);
    m_intensitySpin->setValue(5);
    configLayout->addWidget(m_intensitySpin, 2, 1);

    auto* buttonLayout = new QHBoxLayout();
    m_runButton = new QPushButton(tr("Start Test"));
    m_runButton->setStyleSheet("background: #89b4fa; color: #1e1e2e; font-weight: bold; padding: 10px 20px;");
    connect(m_runButton, &QPushButton::clicked, this, &AdversaryTestWidget::onRunTest);
    buttonLayout->addWidget(m_runButton);

    m_stopButton = new QPushButton(tr("Stop"));
    m_stopButton->setEnabled(false);
    m_stopButton->setStyleSheet("background: #f38ba8; color: #1e1e2e; font-weight: bold; padding: 10px 20px;");
    connect(m_stopButton, &QPushButton::clicked, this, &AdversaryTestWidget::onStopTest);
    buttonLayout->addWidget(m_stopButton);
    buttonLayout->addStretch();

    configLayout->addLayout(buttonLayout, 3, 0, 1, 2);
    mainLayout->addWidget(configBox);

    // ─── Progress ──────────────────────────────────────────────────────
    auto* progressBox = new QGroupBox(tr("Progress"));
    auto* progressLayout = new QVBoxLayout(progressBox);

    m_statusLabel = new QLabel(tr("Ready"));
    progressLayout->addWidget(m_statusLabel);

    m_progressBar = new QProgressBar();
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    progressLayout->addWidget(m_progressBar);

    mainLayout->addWidget(progressBox);

    // ─── Summary Cards ─────────────────────────────────────────────────
    auto* summaryLayout = new QHBoxLayout();

    auto createCard = [](const QString& title, QLabel*& valueLabel, const QString& color) {
        auto* card = new QWidget();
        auto* layout = new QVBoxLayout(card);
        layout->setContentsMargins(12, 8, 12, 8);

        auto* titleLabel = new QLabel(title);
        titleLabel->setStyleSheet("color: #a6adc8; font-size: 9pt;");
        layout->addWidget(titleLabel);

        valueLabel = new QLabel("0");
        QFont valueFont = valueLabel->font();
        valueFont.setPointSize(20);
        valueFont.setBold(true);
        valueLabel->setFont(valueFont);
        valueLabel->setStyleSheet(QString("color: %1;").arg(color));
        layout->addWidget(valueLabel);

        return card;
    };

    summaryLayout->addWidget(createCard(tr("Total Attacks"), m_totalAttacksLabel, "#89b4fa"));
    summaryLayout->addWidget(createCard(tr("Successful"), m_successfulLabel, "#a6e3a1"));
    summaryLayout->addWidget(createCard(tr("Detected"), m_detectedLabel, "#f38ba8"));
    summaryLayout->addWidget(createCard(tr("Avg Stealth"), m_avgStealthLabel, "#f9e2af"));
    summaryLayout->addWidget(createCard(tr("Success Rate"), m_successRateLabel, "#fab387"));
    summaryLayout->addStretch();

    mainLayout->addLayout(summaryLayout);

    // ─── Results Table ─────────────────────────────────────────────────
    auto* tableBox = new QGroupBox(tr("Attack Results"));
    auto* tableLayout = new QVBoxLayout(tableBox);

    m_resultsTable = new QTableWidget();
    m_resultsTable->setColumnCount(6);
    m_resultsTable->setHorizontalHeaderLabels({
        tr("Time"), tr("Attack Type"), tr("Intensity"), tr("Stealth"), tr("Detected"), tr("Result")
    });
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_resultsTable->verticalHeader()->setVisible(false);
    m_resultsTable->setAlternatingRowColors(true);

    m_resultsTable->setColumnWidth(0, 100);
    m_resultsTable->setColumnWidth(1, 150);
    m_resultsTable->setColumnWidth(2, 80);
    m_resultsTable->setColumnWidth(3, 80);
    m_resultsTable->setColumnWidth(4, 80);

    tableLayout->addWidget(m_resultsTable);
    mainLayout->addWidget(tableBox);
}

void AdversaryTestWidget::onRunTest()
{
    m_running = true;
    m_runButton->setEnabled(false);
    m_stopButton->setEnabled(true);
    m_attackTypeCombo->setEnabled(false);
    m_iterationsSpin->setEnabled(false);
    m_intensitySpin->setEnabled(false);

    m_totalAttacks = 0;
    m_successful = 0;
    m_detected = 0;
    m_stealthSum = 0.0;

    m_resultsTable->setRowCount(0);
    updateSummary();

    QJsonObject params;
    params["attack_type"] = m_attackTypeCombo->currentData().toString();
    params["iterations"] = m_iterationsSpin->value();
    params["intensity"] = m_intensitySpin->value();

    emit testRequested(params);
}

void AdversaryTestWidget::onStopTest()
{
    m_running = false;
    emit stopRequested();
}

void AdversaryTestWidget::updateProgress(int percent, const QString& status)
{
    m_progressBar->setValue(percent);
    m_statusLabel->setText(status);
}

void AdversaryTestWidget::addResult(const QJsonObject& result)
{
    int row = m_resultsTable->rowCount();
    m_resultsTable->insertRow(row);

    QString time = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString attackType = result.value("attack_type").toString();
    int intensity = result.value("intensity").toInt();
    double stealth = result.value("stealth").toDouble();
    bool detected = result.value("detected").toBool();
    QString resultText = result.value("result").toString();

    m_resultsTable->setItem(row, 0, new QTableWidgetItem(time));
    m_resultsTable->setItem(row, 1, new QTableWidgetItem(attackType));
    m_resultsTable->setItem(row, 2, new QTableWidgetItem(QString::number(intensity)));
    
    auto* stealthItem = new QTableWidgetItem(QString::number(stealth, 'f', 3));
    if (stealth < 0.3) stealthItem->setForeground(QColor("#f38ba8"));
    else if (stealth < 0.6) stealthItem->setForeground(QColor("#f9e2af"));
    else stealthItem->setForeground(QColor("#a6e3a1"));
    m_resultsTable->setItem(row, 3, stealthItem);
    
    auto* detectedItem = new QTableWidgetItem(detected ? tr("Yes") : tr("No"));
    detectedItem->setForeground(detected ? QColor("#f38ba8") : QColor("#a6e3a1"));
    m_resultsTable->setItem(row, 4, detectedItem);
    
    m_resultsTable->setItem(row, 5, new QTableWidgetItem(resultText));

    // Update counters
    m_totalAttacks++;
    if (!detected) m_successful++;
    if (detected) m_detected++;
    m_stealthSum += stealth;

    updateSummary();
}

void AdversaryTestWidget::updateSummary()
{
    m_totalAttacksLabel->setText(QString::number(m_totalAttacks));
    m_successfulLabel->setText(QString::number(m_successful));
    m_detectedLabel->setText(QString::number(m_detected));
    
    double avgStealth = m_totalAttacks > 0 ? m_stealthSum / m_totalAttacks : 0.0;
    m_avgStealthLabel->setText(QString::number(avgStealth, 'f', 3));
    
    double successRate = m_totalAttacks > 0 ? (double)m_successful / m_totalAttacks * 100.0 : 0.0;
    m_successRateLabel->setText(QString::number(successRate, 'f', 1) + "%");
}

void AdversaryTestWidget::onTestFinished(const QJsonObject& summary)
{
    m_running = false;
    m_runButton->setEnabled(true);
    m_stopButton->setEnabled(false);
    m_attackTypeCombo->setEnabled(true);
    m_iterationsSpin->setEnabled(true);
    m_intensitySpin->setEnabled(true);

    m_progressBar->setValue(100);
    m_statusLabel->setText(tr("Test completed"));

    // Update from summary if provided
    if (summary.contains("total_attacks")) {
        m_totalAttacks = summary.value("total_attacks").toInt();
        m_successful = summary.value("successful").toInt();
        m_detected = summary.value("detected").toInt();
        m_stealthSum = summary.value("stealth_sum").toDouble();
        updateSummary();
    }
}

void AdversaryTestWidget::onTestStarted()
{
    m_statusLabel->setText(tr("Running attacks..."));
    m_progressBar->setValue(0);
}

} // namespace widgets
