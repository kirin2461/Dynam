#include "LogModel.hpp"

#include <QMutexLocker>
#include <QColor>
#include <QJsonObject>
#include <QJsonDocument>

namespace models {

LogModel::LogModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int LogModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent)
    QMutexLocker lock(&m_mutex);
    return m_entries.size();
}

int LogModel::columnCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent)
    return ColCount;
}

QVariant LogModel::data(const QModelIndex& index, int role) const
{
    QMutexLocker lock(&m_mutex);
    
    if (!index.isValid() || index.row() >= m_entries.size()) {
        return QVariant();
    }
    
    const LogEntry& entry = m_entries[index.row()];
    
    if (role == Qt::DisplayRole) {
        switch (index.column()) {
            case ColTimestamp:
                return entry.timestamp.toString("yyyy-MM-dd HH:mm:ss.zzz");
            case ColLevel:
                switch (entry.level) {
                    case Debug: return "DEBUG";
                    case Info: return "INFO";
                    case Warning: return "WARN";
                    case Error: return "ERROR";
                    case Critical: return "CRIT";
                }
                break;
            case ColSource: return entry.source;
            case ColMessage: return entry.message;
        }
    } else if (role == Qt::ForegroundRole) {
        if (index.column() == ColLevel) {
            switch (entry.level) {
                case Debug: return QColor("#6c7086"); // gray
                case Info: return QColor("#89b4fa"); // blue
                case Warning: return QColor("#f9e2af"); // yellow
                case Error: return QColor("#fab387"); // orange
                case Critical: return QColor("#f38ba8"); // red
            }
        }
    }
    
    return QVariant();
}

QVariant LogModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }
    
    switch (section) {
        case ColTimestamp: return tr("Time");
        case ColLevel: return tr("Level");
        case ColSource: return tr("Source");
        case ColMessage: return tr("Message");
    }
    
    return QVariant();
}

void LogModel::addEntry(const QDateTime& timestamp, int level, const QString& source, const QString& message)
{
    LogEntry entry{timestamp, level, source, message};
    
    if (!matchesFilter(entry)) return;
    
    QMutexLocker lock(&m_mutex);
    
    // Circular buffer
    if (m_entries.size() >= m_maxEntries) {
        beginRemoveRows(QModelIndex(), 0, 0);
        m_entries.removeFirst();
        endRemoveRows();
    }
    
    beginInsertRows(QModelIndex(), m_entries.size(), m_entries.size());
    m_entries.append(entry);
    endInsertRows();
}

void LogModel::addFromJson(const QJsonObject& entry)
{
    QDateTime timestamp = QDateTime::fromString(
        entry.value("timestamp").toString(), 
        Qt::ISODateWithMs
    );
    if (!timestamp.isValid()) {
        timestamp = QDateTime::currentDateTime();
    }
    
    int level = entry.value("level").toInt(Info);
    QString source = entry.value("source").toString();
    QString message = entry.value("message").toString();
    
    addEntry(timestamp, level, source, message);
}

void LogModel::clear()
{
    QMutexLocker lock(&m_mutex);
    
    beginResetModel();
    m_entries.clear();
    endResetModel();
}

void LogModel::setMaxEntries(int max)
{
    m_maxEntries = max;
}

void LogModel::setMinLevel(int level)
{
    m_minLevel = level;
}

void LogModel::setSourceFilter(const QString& source)
{
    m_sourceFilter = source;
}

bool LogModel::matchesFilter(const LogEntry& entry) const
{
    if (entry.level < m_minLevel) return false;
    if (!m_sourceFilter.isEmpty() && entry.source != m_sourceFilter) return false;
    return true;
}

} // namespace models
