#include "TrafficModel.hpp"

#include <QMutexLocker>
#include <QColor>

namespace models {

TrafficModel::TrafficModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int TrafficModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent)
    QMutexLocker lock(&m_mutex);
    return m_connections.size();
}

int TrafficModel::columnCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent)
    return ColCount;
}

QVariant TrafficModel::data(const QModelIndex& index, int role) const
{
    QMutexLocker lock(&m_mutex);
    
    if (!index.isValid() || index.row() >= m_connections.size()) {
        return QVariant();
    }
    
    const Connection& conn = m_connections[index.row()];
    
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case ColSource: return conn.source;
            case ColDest: return conn.destination;
            case ColProtocol: return conn.protocol;
            case ColBytes: {
                if (conn.bytes > 1024 * 1024) {
                    return QString("%1 MB").arg(conn.bytes / (1024.0 * 1024.0), 0, 'f', 2);
                } else if (conn.bytes > 1024) {
                    return QString("%1 KB").arg(conn.bytes / 1024.0, 0, 'f', 1);
                }
                return QString("%1 B").arg(conn.bytes);
            }
            case ColPackets: return conn.packets;
            case ColStealthScore: return QString::number(conn.stealthScore, 'f', 2);
            case ColOnnxDetected: return conn.onnxDetected ? "✓" : "—";
            case ColONNX_Prob: return QString::number(conn.onnxProbability, 'f', 3);
            case ColStatus: return conn.status;
        }
    } else if (role == Qt::ForegroundRole) {
        // Color stealth score
        if (index.column() == ColStealthScore) {
            if (conn.stealthScore > 0.8) return QColor("#f38ba8"); // red
            if (conn.stealthScore > 0.5) return QColor("#fab387"); // orange
            if (conn.stealthScore > 0.3) return QColor("#f9e2af"); // yellow
            return QColor("#a6e3a1"); // green
        }
        // Color ONNX detection
        if (index.column() == ColOnnxDetected && conn.onnxDetected) {
            return QColor("#f38ba8"); // red for detected
        }
    } else if (role == Qt::ToolTipRole) {
        if (index.column() == ColStealthScore) {
            return tr("Combined stealth score (heuristic + ONNX)");
        }
        if (index.column() == ColOnnxDetected) {
            return tr("ONNX model detection of NCP-obfuscated traffic");
        }
    }
    
    return QVariant();
}

QVariant TrafficModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }
    
    switch (section) {
        case ColSource: return tr("Source");
        case ColDest: return tr("Destination");
        case ColProtocol: return tr("Protocol");
        case ColBytes: return tr("Bytes");
        case ColPackets: return tr("Packets");
        case ColStealthScore: return tr("Stealth");
        case ColOnnxDetected: return tr("ONNX");
        case ColONNX_Prob: return tr("P(NCP)");
        case ColStatus: return tr("Status");
    }
    
    return QVariant();
}

void TrafficModel::updateFromJson(const QJsonObject& data)
{
    QMutexLocker lock(&m_mutex);
    
    beginResetModel();
    m_connections.clear();
    
    QJsonArray connections = data.value("connections").toArray();
    for (const auto& connVal : connections) {
        QJsonObject connObj = connVal.toObject();
        
        Connection conn;
        conn.source = connObj.value("source").toString();
        conn.destination = connObj.value("destination").toString();
        conn.protocol = connObj.value("protocol").toString();
        conn.bytes = connObj.value("bytes").toVariant().toULongLong();
        conn.packets = connObj.value("packets").toVariant().toULongLong();
        conn.stealthScore = connObj.value("stealth_score").toDouble();
        conn.onnxDetected = connObj.value("onnx_detected").toBool();
        conn.onnxProbability = connObj.value("onnx_probability").toDouble();
        conn.status = connObj.value("status").toString();
        
        m_connections.append(conn);
    }
    
    m_totalBytes = data.value("total_bytes").toVariant().toULongLong();
    m_totalPackets = data.value("total_packets").toVariant().toULongLong();
    
    endResetModel();
    
    emit dataUpdated();
}

void TrafficModel::clear()
{
    QMutexLocker lock(&m_mutex);
    
    beginResetModel();
    m_connections.clear();
    m_totalBytes = 0;
    m_totalPackets = 0;
    endResetModel();
    
    emit dataUpdated();
}

double TrafficModel::averageStealthScore() const
{
    QMutexLocker lock(&m_mutex);
    
    if (m_connections.isEmpty()) return 0.0;
    
    double sum = 0.0;
    for (const auto& conn : m_connections) {
        sum += conn.stealthScore;
    }
    return sum / m_connections.size();
}

int TrafficModel::detectedConnections() const
{
    QMutexLocker lock(&m_mutex);
    
    int count = 0;
    for (const auto& conn : m_connections) {
        if (conn.onnxDetected) count++;
    }
    return count;
}

} // namespace models
