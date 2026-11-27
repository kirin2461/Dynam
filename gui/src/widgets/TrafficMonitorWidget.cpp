#include "TrafficMonitorWidget.hpp"

#include <QHeaderView>
#include <QFont>

namespace widgets {

TrafficMonitorWidget::TrafficMonitorWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
    
    // Auto-refresh timer (2 seconds)
    m_autoRefreshTimer = new QTimer(this);
    m_autoRefreshTimer->setInterval(2000);
    connect(m_autoRefreshTimer, &QTimer::timeout, this, &TrafficMonitorWidget::onRefreshClicked);
    
    if (m_autoRefresh) {
        m_autoRefreshTimer->start();
    }
}

void TrafficMonitorWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(16);
    
    // ─── Title ─────────────────────────────────────────────────────────
    auto* titleLabel = new QLabel(tr("Traffic Monitor"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);
    
    // ─── Stats row ─────────────────────────────────────────────────────
    auto* statsLayout = new QHBoxLayout();
    statsLayout->setSpacing(24);
    
    auto createStatBox = [this](const QString& label, QLabel*& valueLabel) {
        auto* box = new QWidget();
        auto* boxLayout = new QVBoxLayout(box);
        boxLayout->setContentsMargins(12, 8, 12, 8);
        boxLayout->setSpacing(4);
        
        auto* name = new QLabel(label);
        name->setStyleSheet("color: #a6adc8; font-size: 9pt;");
        boxLayout->addWidget(name);
        
        valueLabel = new QLabel("0");
        QFont valueFont = valueLabel->font();
        valueFont.setPointSize(14);
        valueFont.setBold(true);
        valueLabel->setFont(valueFont);
        boxLayout->addWidget(valueLabel);
        
        return box;
    };
    
    statsLayout->addWidget(createStatBox(tr("Total Bytes"), m_totalBytesLabel));
    statsLayout->addWidget(createStatBox(tr("Total Packets"), m_totalPacketsLabel));
    statsLayout->addWidget(createStatBox(tr("Connections"), m_totalConnectionsLabel));
    statsLayout->addWidget(createStatBox(tr("Avg Stealth"), m_avgStealthLabel));
    statsLayout->addWidget(createStatBox(tr("ONNX Detected"), m_detectedLabel));
    statsLayout->addStretch();
    
    mainLayout->addLayout(statsLayout);
    
    // ─── Controls ──────────────────────────────────────────────────────
    auto* controlsLayout = new QHBoxLayout();
    controlsLayout->setSpacing(8);
    
    m_refreshButton = new QPushButton(tr("Refresh"));
    connect(m_refreshButton, &QPushButton::clicked, this, &TrafficMonitorWidget::onRefreshClicked);
    controlsLayout->addWidget(m_refreshButton);
    
    m_autoRefreshButton = new QPushButton(tr("Auto-refresh"));
    m_autoRefreshButton->setCheckable(true);
    m_autoRefreshButton->setChecked(m_autoRefresh);
    connect(m_autoRefreshButton, &QPushButton::toggled, this, &TrafficMonitorWidget::onToggleAutoRefresh);
    controlsLayout->addWidget(m_autoRefreshButton);
    
    controlsLayout->addStretch();
    
    mainLayout->addLayout(controlsLayout);
    
    // ─── Table ─────────────────────────────────────────────────────────
    m_model = new models::TrafficModel(this);
    
    m_table = new QTableView();
    m_table->setModel(m_model);
    m_table->setAlternatingRowColors(true);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSortingEnabled(true);
    
    // Set column widths
    m_table->setColumnWidth(models::TrafficModel::ColSource, 140);
    m_table->setColumnWidth(models::TrafficModel::ColDest, 140);
    m_table->setColumnWidth(models::TrafficModel::ColProtocol, 80);
    m_table->setColumnWidth(models::TrafficModel::ColBytes, 100);
    m_table->setColumnWidth(models::TrafficModel::ColPackets, 80);
    m_table->setColumnWidth(models::TrafficModel::ColStealthScore, 80);
    m_table->setColumnWidth(models::TrafficModel::ColOnnxDetected, 60);
    m_table->setColumnWidth(models::TrafficModel::ColONNX_Prob, 80);
    m_table->setColumnWidth(models::TrafficModel::ColStatus, 100);
    
    mainLayout->addWidget(m_table, 1);
    
    // Connect model signals
    connect(m_model, &models::TrafficModel::dataUpdated, this, &TrafficMonitorWidget::updateStats);
}

void TrafficMonitorWidget::updateTraffic(const QJsonObject& data)
{
    m_model->updateFromJson(data);
}

void TrafficMonitorWidget::onToggleAutoRefresh(bool checked)
{
    m_autoRefresh = checked;
    if (checked) {
        m_autoRefreshTimer->start();
    } else {
        m_autoRefreshTimer->stop();
    }
}

void TrafficMonitorWidget::onRefreshClicked()
{
    emit refreshRequested();
}

void TrafficMonitorWidget::updateStats()
{
    quint64 bytes = m_model->totalBytes();
    if (bytes > 1024 * 1024 * 1024) {
        m_totalBytesLabel->setText(QString("%1 GB").arg(bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2));
    } else if (bytes > 1024 * 1024) {
        m_totalBytesLabel->setText(QString("%1 MB").arg(bytes / (1024.0 * 1024.0), 0, 'f', 2));
    } else if (bytes > 1024) {
        m_totalBytesLabel->setText(QString("%1 KB").arg(bytes / 1024.0, 0, 'f', 1));
    } else {
        m_totalBytesLabel->setText(QString("%1 B").arg(bytes));
    }
    
    m_totalPacketsLabel->setText(QString::number(m_model->totalPackets()));
    m_totalConnectionsLabel->setText(QString::number(m_model->totalConnections()));
    m_avgStealthLabel->setText(QString::number(m_model->averageStealthScore(), 'f', 2));
    m_detectedLabel->setText(QString::number(m_model->detectedConnections()));
}

} // namespace widgets
