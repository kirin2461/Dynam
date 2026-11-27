#include "StatsWidget.hpp"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFont>

namespace widgets {

StatsWidget::StatsWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void StatsWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(16);
    
    // ─── Title ─────────────────────────────────────────────────────────
    auto* titleLabel = new QLabel(tr("Statistics"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);
    
    // ─── Traffic Stats ─────────────────────────────────────────────────
    auto* trafficGroup = new QGroupBox(tr("Traffic"));
    auto* trafficLayout = new QHBoxLayout(trafficGroup);
    trafficLayout->setSpacing(24);
    
    auto createStatBox = [](const QString& name, QLabel*& valueLabel) {
        auto* box = new QWidget();
        auto* boxLayout = new QVBoxLayout(box);
        boxLayout->setContentsMargins(12, 8, 12, 8);
        
        auto* nameLabel = new QLabel(name);
        nameLabel->setStyleSheet("color: #a6adc8; font-size: 9pt;");
        boxLayout->addWidget(nameLabel);
        
        valueLabel = new QLabel("0");
        QFont valueFont = valueLabel->font();
        valueFont.setPointSize(14);
        valueFont.setBold(true);
        valueLabel->setFont(valueFont);
        boxLayout->addWidget(valueLabel);
        
        return box;
    };
    
    trafficLayout->addWidget(createStatBox(tr("Total Bytes"), m_totalBytesLabel));
    trafficLayout->addWidget(createStatBox(tr("Total Packets"), m_totalPacketsLabel));
    trafficLayout->addWidget(createStatBox(tr("Connections"), m_totalConnectionsLabel));
    trafficLayout->addWidget(createStatBox(tr("Avg Bandwidth"), m_avgBandwidthLabel));
    trafficLayout->addStretch();
    
    mainLayout->addWidget(trafficGroup);
    
    // ─── Stealth Stats ─────────────────────────────────────────────────
    auto* stealthGroup = new QGroupBox(tr("Stealth Scores"));
    auto* stealthLayout = new QHBoxLayout(stealthGroup);
    stealthLayout->setSpacing(24);
    
    stealthLayout->addWidget(createStatBox(tr("Average"), m_avgStealthLabel));
    stealthLayout->addWidget(createStatBox(tr("Minimum"), m_minStealthLabel));
    stealthLayout->addWidget(createStatBox(tr("Maximum"), m_maxStealthLabel));
    stealthLayout->addWidget(createStatBox(tr("Median"), m_medianStealthLabel));
    stealthLayout->addStretch();
    
    mainLayout->addWidget(stealthGroup);
    
    // ─── ONNX Stats ────────────────────────────────────────────────────
    auto* onnxGroup = new QGroupBox(tr("ONNX Model"));
    auto* onnxLayout = new QHBoxLayout(onnxGroup);
    onnxLayout->setSpacing(24);
    
    onnxLayout->addWidget(createStatBox(tr("Inferences"), m_onnxInferencesLabel));
    onnxLayout->addWidget(createStatBox(tr("Detections"), m_onnxDetectionsLabel));
    onnxLayout->addWidget(createStatBox(tr("Detection Rate"), m_onnxDetectionRateLabel));
    onnxLayout->addWidget(createStatBox(tr("Avg Confidence"), m_onnxAvgConfidenceLabel));
    onnxLayout->addStretch();
    
    mainLayout->addWidget(onnxGroup);
    
    // ─── Attack Stats ──────────────────────────────────────────────────
    auto* attackGroup = new QGroupBox(tr("Adversarial Tests"));
    auto* attackLayout = new QHBoxLayout(attackGroup);
    attackLayout->setSpacing(24);
    
    attackLayout->addWidget(createStatBox(tr("Total Attacks"), m_totalAttacksLabel));
    attackLayout->addWidget(createStatBox(tr("Successful"), m_successfulAttacksLabel));
    attackLayout->addWidget(createStatBox(tr("Success Rate"), m_attackSuccessRateLabel));
    attackLayout->addStretch();
    
    mainLayout->addWidget(attackGroup);
    
    mainLayout->addStretch();
}

void StatsWidget::updateStats(const QJsonObject& stats)
{
    // Traffic
    quint64 bytes = stats.value("total_bytes").toVariant().toULongLong();
    if (bytes > 1024 * 1024 * 1024) {
        m_totalBytesLabel->setText(QString("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2));
    } else if (bytes > 1024 * 1024) {
        m_totalBytesLabel->setText(QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 2));
    } else if (bytes > 1024) {
        m_totalBytesLabel->setText(QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1));
    } else {
        m_totalBytesLabel->setText(QString("%1 B").arg(bytes));
    }
    
    m_totalPacketsLabel->setText(QString::number(stats.value("total_packets").toVariant().toULongLong()));
    m_totalConnectionsLabel->setText(QString::number(stats.value("total_connections").toInt()));
    m_avgBandwidthLabel->setText(QString("%1 KB/s").arg(stats.value("avg_bandwidth").toDouble() / 1024.0, 0, 'f', 1));
    
    // Stealth
    m_avgStealthLabel->setText(QString::number(stats.value("avg_stealth").toDouble(), 'f', 3));
    m_minStealthLabel->setText(QString::number(stats.value("min_stealth").toDouble(), 'f', 3));
    m_maxStealthLabel->setText(QString::number(stats.value("max_stealth").toDouble(), 'f', 3));
    m_medianStealthLabel->setText(QString::number(stats.value("median_stealth").toDouble(), 'f', 3));
    
    // ONNX
    m_onnxInferencesLabel->setText(QString::number(stats.value("onnx_inferences").toInt()));
    m_onnxDetectionsLabel->setText(QString::number(stats.value("onnx_detections").toInt()));
    m_onnxDetectionRateLabel->setText(QString::number(stats.value("onnx_detection_rate").toDouble() * 100, 'f', 1) + "%");
    m_onnxAvgConfidenceLabel->setText(QString::number(stats.value("onnx_avg_confidence").toDouble(), 'f', 3));
    
    // Attacks
    m_totalAttacksLabel->setText(QString::number(stats.value("total_attacks").toInt()));
    m_successfulAttacksLabel->setText(QString::number(stats.value("successful_attacks").toInt()));
    m_attackSuccessRateLabel->setText(QString::number(stats.value("attack_success_rate").toDouble() * 100, 'f', 1) + "%");
}

} // namespace widgets
