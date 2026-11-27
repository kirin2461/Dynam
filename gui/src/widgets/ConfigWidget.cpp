#include "ConfigWidget.hpp"

#include <QGroupBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QFont>

namespace widgets {

ConfigWidget::ConfigWidget(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void ConfigWidget::setupUi()
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(16, 16, 16, 16);
    mainLayout->setSpacing(16);
    
    // ─── Title ─────────────────────────────────────────────────────────
    auto* titleLabel = new QLabel(tr("Configuration"));
    QFont titleFont = titleLabel->font();
    titleFont.setPointSize(16);
    titleFont.setBold(true);
    titleLabel->setFont(titleFont);
    mainLayout->addWidget(titleLabel);
    
    // ─── ONNX Model Settings ───────────────────────────────────────────
    auto* onnxGroup = new QGroupBox(tr("ONNX Model"));
    auto* onnxLayout = new QFormLayout(onnxGroup);
    onnxLayout->setSpacing(12);
    
    auto* pathLayout = new QHBoxLayout();
    m_onnxModelPathEdit = new QLineEdit();
    m_onnxModelPathEdit->setPlaceholderText(tr("Path to ONNX model file..."));
    pathLayout->addWidget(m_onnxModelPathEdit);
    
    m_browseButton = new QPushButton(tr("Browse..."));
    connect(m_browseButton, &QPushButton::clicked, this, &ConfigWidget::onBrowseModelPath);
    pathLayout->addWidget(m_browseButton);
    
    onnxLayout->addRow(tr("Model path:"), pathLayout);
    
    m_onnxThresholdSpin = new QDoubleSpinBox();
    m_onnxThresholdSpin->setRange(0.0, 1.0);
    m_onnxThresholdSpin->setSingleStep(0.05);
    m_onnxThresholdSpin->setDecimals(2);
    m_onnxThresholdSpin->setValue(0.5);
    onnxLayout->addRow(tr("Detection threshold:"), m_onnxThresholdSpin);
    
    m_onnxWeightSpin = new QDoubleSpinBox();
    m_onnxWeightSpin->setRange(0.0, 1.0);
    m_onnxWeightSpin->setSingleStep(0.1);
    m_onnxWeightSpin->setDecimals(2);
    m_onnxWeightSpin->setValue(0.6);
    onnxLayout->addRow(tr("Weight (combine with heuristic):"), m_onnxWeightSpin);
    
    m_onnxEnabledCheck = new QCheckBox(tr("Enable ONNX detection"));
    m_onnxEnabledCheck->setChecked(true);
    onnxLayout->addRow("", m_onnxEnabledCheck);
    
    mainLayout->addWidget(onnxGroup);
    
    // ─── DPI Bypass Settings ───────────────────────────────────────────
    auto* dpiGroup = new QGroupBox(tr("DPI Bypass"));
    auto* dpiLayout = new QFormLayout(dpiGroup);
    dpiLayout->setSpacing(12);
    
    m_strategyCombo = new QComboBox();
    m_strategyCombo->addItem("Split", "split");
    m_strategyCombo->addItem("Fragmentation", "fragment");
    m_strategyCombo->addItem("TLS Split", "tls_split");
    m_strategyCombo->addItem("HTTP Obfuscation", "http_obfuscate");
    m_strategyCombo->addItem("Auto", "auto");
    dpiLayout->addRow(tr("Strategy:"), m_strategyCombo);
    
    m_autoRotateCheck = new QCheckBox(tr("Auto-rotate strategies"));
    dpiLayout->addRow("", m_autoRotateCheck);
    
    mainLayout->addWidget(dpiGroup);
    
    // ─── Proxy Settings ────────────────────────────────────────────────
    auto* proxyGroup = new QGroupBox(tr("Proxy"));
    auto* proxyLayout = new QFormLayout(proxyGroup);
    proxyLayout->setSpacing(12);
    
    m_proxyHostEdit = new QLineEdit();
    m_proxyHostEdit->setText("127.0.0.1");
    proxyLayout->addRow(tr("Host:"), m_proxyHostEdit);
    
    m_proxyPortSpin = new QSpinBox();
    m_proxyPortSpin->setRange(1, 65535);
    m_proxyPortSpin->setValue(1080);
    proxyLayout->addRow(tr("Port:"), m_proxyPortSpin);
    
    mainLayout->addWidget(proxyGroup);
    
    // ─── Logging Settings ──────────────────────────────────────────────
    auto* logGroup = new QGroupBox(tr("Logging"));
    auto* logLayout = new QFormLayout(logGroup);
    logLayout->setSpacing(12);
    
    m_logLevelCombo = new QComboBox();
    m_logLevelCombo->addItem("Debug", 0);
    m_logLevelCombo->addItem("Info", 1);
    m_logLevelCombo->addItem("Warning", 2);
    m_logLevelCombo->addItem("Error", 3);
    m_logLevelCombo->addItem("Critical", 4);
    m_logLevelCombo->setCurrentIndex(2); // Warning
    logLayout->addRow(tr("Log level:"), m_logLevelCombo);
    
    m_logRetentionSpin = new QSpinBox();
    m_logRetentionSpin->setRange(1, 365);
    m_logRetentionSpin->setValue(7);
    m_logRetentionSpin->setSuffix(tr(" days"));
    logLayout->addRow(tr("Retention:"), m_logRetentionSpin);
    
    mainLayout->addWidget(logGroup);
    
    // ─── Buttons ───────────────────────────────────────────────────────
    mainLayout->addStretch();
    
    auto* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    m_resetButton = new QPushButton(tr("Reset"));
    connect(m_resetButton, &QPushButton::clicked, this, &ConfigWidget::onResetClicked);
    buttonLayout->addWidget(m_resetButton);
    
    m_saveButton = new QPushButton(tr("Save"));
    connect(m_saveButton, &QPushButton::clicked, this, &ConfigWidget::onSaveClicked);
    buttonLayout->addWidget(m_saveButton);
    
    mainLayout->addLayout(buttonLayout);
}

void ConfigWidget::loadFromModel(models::ConfigModel* model)
{
    m_model = model;
    
    m_onnxModelPathEdit->setText(model->onnxModelPath());
    m_onnxThresholdSpin->setValue(model->onnxThreshold());
    m_onnxWeightSpin->setValue(model->onnxWeight());
    m_onnxEnabledCheck->setChecked(model->onnxEnabled());
    
    // Find strategy in combo
    QString strategy = model->currentStrategy();
    for (int i = 0; i < m_strategyCombo->count(); ++i) {
        if (m_strategyCombo->itemData(i).toString() == strategy) {
            m_strategyCombo->setCurrentIndex(i);
            break;
        }
    }
    m_autoRotateCheck->setChecked(model->autoRotate());
    
    m_proxyHostEdit->setText(model->proxyHost());
    m_proxyPortSpin->setValue(model->proxyPort());
    
    // Find log level in combo
    int level = model->logLevel();
    for (int i = 0; i < m_logLevelCombo->count(); ++i) {
        if (m_logLevelCombo->itemData(i).toInt() == level) {
            m_logLevelCombo->setCurrentIndex(i);
            break;
        }
    }
    m_logRetentionSpin->setValue(model->logRetentionDays());
}

void ConfigWidget::saveToModel(models::ConfigModel* model)
{
    model->setOnnxModelPath(m_onnxModelPathEdit->text());
    model->setOnnxThreshold(m_onnxThresholdSpin->value());
    model->setOnnxWeight(m_onnxWeightSpin->value());
    model->setOnnxEnabled(m_onnxEnabledCheck->isChecked());
    
    model->setCurrentStrategy(m_strategyCombo->currentData().toString());
    model->setAutoRotate(m_autoRotateCheck->isChecked());
    
    model->setProxyHost(m_proxyHostEdit->text());
    model->setProxyPort(m_proxyPortSpin->value());
    
    model->setLogLevel(m_logLevelCombo->currentData().toInt());
    model->setLogRetentionDays(m_logRetentionSpin->value());
}

void ConfigWidget::onBrowseModelPath()
{
    QString path = QFileDialog::getOpenFileName(
        this,
        tr("Select ONNX Model"),
        QString(),
        tr("ONNX Models (*.onnx);;All Files (*)")
    );
    
    if (!path.isEmpty()) {
        m_onnxModelPathEdit->setText(path);
    }
}

void ConfigWidget::onSaveClicked()
{
    if (m_model) {
        saveToModel(m_model);
        emit configSaved();
        
        QMessageBox::information(this, tr("Saved"), tr("Configuration saved successfully."));
    }
}

void ConfigWidget::onResetClicked()
{
    if (m_model) {
        loadFromModel(m_model);
    }
}

} // namespace widgets
