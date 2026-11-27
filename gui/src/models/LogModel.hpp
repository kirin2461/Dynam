#pragma once

#include <QObject>
#include <QAbstractTableModel>
#include <QVector>
#include <QMutex>
#include <QDateTime>

namespace models {

/**
 * @brief Data model for application logs.
 * 
 * Stores log entries with timestamps, levels, sources, and messages.
 * Supports filtering by level and source.
 */
class LogModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        ColTimestamp = 0,
        ColLevel,
        ColSource,
        ColMessage,
        ColCount
    };
    
    enum LogLevel {
        Debug = 0,
        Info = 1,
        Warning = 2,
        Error = 3,
        Critical = 4
    };
    
    explicit LogModel(QObject* parent = nullptr);
    
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
    
    /// Add a log entry
    void addEntry(const QDateTime& timestamp, int level, const QString& source, const QString& message);
    
    /// Add entry from JSON
    void addFromJson(const QJsonObject& entry);
    
    /// Clear all logs
    void clear();
    
    /// Set maximum number of entries (circular buffer)
    void setMaxEntries(int max);
    
    /// Filter by minimum level
    void setMinLevel(int level);
    
    /// Filter by source
    void setSourceFilter(const QString& source);

private:
    struct LogEntry {
        QDateTime timestamp;
        int level;
        QString source;
        QString message;
    };
    
    QVector<LogEntry> m_entries;
    int m_maxEntries = 10000;
    int m_minLevel = Debug;
    QString m_sourceFilter;
    mutable QMutex m_mutex;
    
    bool matchesFilter(const LogEntry& entry) const;
};

} // namespace models
