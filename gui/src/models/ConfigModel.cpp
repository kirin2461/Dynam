#include "ConfigModel.hpp"

namespace models {

ConfigModel::ConfigModel(QObject* parent)
    : QObject(parent)
{
}

void ConfigModel::loadFromJson(const QJsonObject& json)
{
    // ONNX
    m_onnxModelPath = json.value("onnx_model_path").toString();
    m_onnxThreshold = json.value("onnx_threshold").toDouble(0.5);
    m_onnxWeight = json.value("onnx_weight").toDouble(0.6);
    m_onnxEnabled = json.value("onnx_enabled").toBool(true);
    
    // DPI Bypass
    m_currentStrategy = json.value("dpi_strategy").toString("split");
    m_autoRotate = json.value("auto_rotate").toBool(false);
    
    // Proxy
    m_proxyHost = json.value("proxy_host").toString("127.0.0.1");
    m_proxyPort = json.value("proxy_port").toInt(1080);
    
    // Logging
    m_logLevel = json.value("log_level").toInt(2);
    m_logRetentionDays = json.value("log_retention_days").toInt(7);
    
    emit configChanged();
}

QJsonObject ConfigModel::toJson() const
{
    QJsonObject json;
    
    // ONNX
    json["onnx_model_path"] = m_onnxModelPath;
    json["onnx_threshold"] = m_onnxThreshold;
    json["onnx_weight"] = m_onnxWeight;
    json["onnx_enabled"] = m_onnxEnabled;
    
    // DPI Bypass
    json["dpi_strategy"] = m_currentStrategy;
    json["auto_rotate"] = m_autoRotate;
    
    // Proxy
    json["proxy_host"] = m_proxyHost;
    json["proxy_port"] = m_proxyPort;
    
    // Logging
    json["log_level"] = m_logLevel;
    json["log_retention_days"] = m_logRetentionDays;
    
    return json;
}

void ConfigModel::setOnnxModelPath(const QString& path)
{
    if (m_onnxModelPath != path) {
        m_onnxModelPath = path;
        emit onnxSettingsChanged();
        emit configChanged();
    }
}

void ConfigModel::setOnnxThreshold(double threshold)
{
    if (m_onnxThreshold != threshold) {
        m_onnxThreshold = threshold;
        emit onnxSettingsChanged();
        emit configChanged();
    }
}

void ConfigModel::setOnnxWeight(double weight)
{
    if (m_onnxWeight != weight) {
        m_onnxWeight = weight;
        emit onnxSettingsChanged();
        emit configChanged();
    }
}

void ConfigModel::setOnnxEnabled(bool enabled)
{
    if (m_onnxEnabled != enabled) {
        m_onnxEnabled = enabled;
        emit onnxSettingsChanged();
        emit configChanged();
    }
}

void ConfigModel::setCurrentStrategy(const QString& strategy)
{
    if (m_currentStrategy != strategy) {
        m_currentStrategy = strategy;
        emit configChanged();
    }
}

void ConfigModel::setAutoRotate(bool rotate)
{
    if (m_autoRotate != rotate) {
        m_autoRotate = rotate;
        emit configChanged();
    }
}

void ConfigModel::setProxyHost(const QString& host)
{
    if (m_proxyHost != host) {
        m_proxyHost = host;
        emit configChanged();
    }
}

void ConfigModel::setProxyPort(int port)
{
    if (m_proxyPort != port) {
        m_proxyPort = port;
        emit configChanged();
    }
}

void ConfigModel::setLogLevel(int level)
{
    if (m_logLevel != level) {
        m_logLevel = level;
        emit configChanged();
    }
}

void ConfigModel::setLogRetentionDays(int days)
{
    if (m_logRetentionDays != days) {
        m_logRetentionDays = days;
        emit configChanged();
    }
}

} // namespace models
