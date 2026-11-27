#pragma once
#include <QWidget>
#include <QLabel>
#include <QTableWidget>

namespace widgets {
class RealityWidget : public QWidget {
    Q_OBJECT
public:
    explicit RealityWidget(QWidget* parent = nullptr);
public slots:
    void updateStats(const QJsonObject& stats);
    void updateConnections(const QJsonArray& conns);
private:
    void setupUi();
    QLabel* m_authorizedCount;
    QLabel* m_fallbackCount;
    QLabel* m_droppedCount;
    QTableWidget* m_connectionsTable;
};
} // namespace widgets
