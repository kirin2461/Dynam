#pragma once

#include <QWidget>
#include <QLineEdit>
#include <QDoubleSpinBox>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>

#include "models/ConfigModel.hpp"

namespace widgets {

/**
 * @brief Configuration widget for application settings.
 * 
 * Provides UI for configuring:
 * - ONNX model (path, threshold, weight, enable/disable)
 * - DPI bypass strategies (selection, auto-rotation)
 * - Proxy settings (host, port)
 * - Logging (level, retention)
 */
class ConfigWidget : public QWidget {
    Q_OBJECT

public:
    explicit ConfigWidget(QWidget* parent = nullptr);
    
    /// Load config from model
    void loadFromModel(models::ConfigModel* model);
    
    /// Save config to model
    void saveToModel(models::ConfigModel* model);

signals:
    void configSaved();

private slots:
    void onBrowseModelPath();
    void onSaveClicked();
    void onResetClicked();

private:
    void setupUi();
    
    // ONNX settings
    QLineEdit* m_onnxModelPathEdit;
    QPushButton* m_browseButton;
    QDoubleSpinBox* m_onnxThresholdSpin;
    QDoubleSpinBox* m_onnxWeightSpin;
    QCheckBox* m_onnxEnabledCheck;
    
    // DPI bypass
    QComboBox* m_strategyCombo;
    QCheckBox* m_autoRotateCheck;
    
    // Proxy
    QLineEdit* m_proxyHostEdit;
    QSpinBox* m_proxyPortSpin;
    
    // Logging
    QComboBox* m_logLevelCombo;
    QSpinBox* m_logRetentionSpin;
    
    // Buttons
    QPushButton* m_saveButton;
    QPushButton* m_resetButton;
    
    models::ConfigModel* m_model = nullptr;
};

} // namespace widgets
