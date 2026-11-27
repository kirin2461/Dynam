#pragma once
#include <QWidget>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QTableWidget>

namespace widgets {
class I2PWidget : public QWidget {
    Q_OBJECT
public:
    explicit I2PWidget(QWidget* parent = nullptr);
public slots:
    void updateStatus(const QJsonObject& status);
    void updatePeers(const QJsonArray& peers);
private:
    void setupUi();
    QLabel* m_samStatus;
    QLabel* m_tunnelCount;
    QLabel* m_bandwidth;
    QTableWidget* m_peersTable;
};
} // namespace widgets
