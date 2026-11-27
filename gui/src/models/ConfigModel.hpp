#pragma once

#include <QObject>
#include <QJsonObject>
#include <QString>

namespace models {

/**
 * @brief Data model for application configuration.
 * 
 * Stores and manages configuration settings:
 * - ONNX model settings (path, threshold, weight)
 * - DPI bypass strategies
 * - Proxy settings
 * - Logging settings
 */
class ConfigModel : public QObject {
    Q_OBJECT

public:
    explicit ConfigModel(QObject* parent = nullptr);
    
    // ─── Load/Save ─────────────────────────────────────────────────────
    void loadFromJson(const QJsonObject& json);
    QJsonObject toJson() const;
    
    // ─── ONNX Settings ─────────────────────────────────────────────────
    QString onnxModelPath() const { return m_onnxModelPath; }
    void setOnnxModelPath(const QString& path);
    
    double onnxThreshold() const { return m_onnxThreshold; }
    void setOnnxThreshold(double threshold);
    
    double onnxWeight() const { return m_onnxWeight; }
    void setOnnxWeight(double weight);
    
    bool onnxEnabled() const { return m_onnxEnabled; }
    void setOnnxEnabled(bool enabled);
    
    // ─── DPI Bypass Settings ───────────────────────────────────────────
    QString currentStrategy() const { return m_currentStrategy; }
    void setCurrentStrategy(const QString& strategy);
    
    bool autoRotate() const { return m_autoRotate; }
    void setAutoRotate(bool rotate);
    
    // ─── Proxy Settings ────────────────────────────────────────────────
    QString proxyHost() const { return m_proxyHost; }
    void setProxyHost(const QString& host);
    
    int proxyPort() const { return m_proxyPort; }
    void setProxyPort(int port);
    
    // ─── Logging ───────────────────────────────────────────────────────
    int logLevel() const { return m_logLevel; }
    void setLogLevel(int level);
    
    int logRetentionDays() const { return m_logRetentionDays; }
    void setLogRetentionDays(int days);

signals:
    void configChanged();
    void onnxSettingsChanged();

private:
    // ONNX
    QString m_onnxModelPath;
    double m_onnxThreshold = 0.5;
    double m_onnxWeight = 0.6;
    bool m_onnxEnabled = true;
    
    // DPI Bypass
    QString m_currentStrategy = "split";
    bool m_autoRotate = false;
    
    // Proxy
    QString m_proxyHost = "127.0.0.1";
    int m_proxyPort = 1080;
    
    // Logging
    int m_logLevel = 2; // Info
    int m_logRetentionDays = 7;
};

} // namespace models
