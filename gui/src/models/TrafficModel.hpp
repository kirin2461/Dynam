#pragma once

#include <QObject>
#include <QJsonObject>
#include <QJsonArray>
#include <QAbstractTableModel>
#include <QVector>
#include <QMutex>

namespace models {

/**
 * @brief Data model for traffic monitoring.
 * 
 * Stores real-time traffic data from the backend:
 * - Active connections (source, dest, protocol, bytes, stealth score)
 * - Aggregate statistics (total bytes, packets, connections)
 * - Per-connection ONNX detection results
 */
class TrafficModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ColSource = 0,
        ColDest,
        ColProtocol,
        ColBytes,
        ColPackets,
        ColStealthScore,
        ColOnnxDetected,
        ColONNX_Prob,
        ColStatus,
        ColCount
    };
    
    explicit TrafficModel(QObject* parent = nullptr);
    
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    
    /// Update from JSON data (from REST or WebSocket)
    void updateFromJson(const QJsonObject& data);
    
    /// Clear all data
    void clear();
    
    /// Get total stats
    quint64 totalBytes() const { return m_totalBytes; }
    quint64 totalPackets() const { return m_totalPackets; }
    int totalConnections() const { return m_connections.size(); }
    double averageStealthScore() const;
    int detectedConnections() const;

signals:
    void dataUpdated();

private:
    struct Connection {
        QString source;
        QString destination;
        QString protocol;
        quint64 bytes = 0;
        quint64 packets = 0;
        double stealthScore = 0.0;
        bool onnxDetected = false;
        double onnxProbability = 0.0;
        QString status;
    };
    
    QVector<Connection> m_connections;
    quint64 m_totalBytes = 0;
    quint64 m_totalPackets = 0;
    mutable QMutex m_mutex;
};

} // namespace models
