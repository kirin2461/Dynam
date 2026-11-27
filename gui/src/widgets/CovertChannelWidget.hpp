#pragma once
#include <QWidget>
#include <QLabel>
#include <QComboBox>
#include <QTableWidget>

namespace widgets {
class CovertChannelWidget : public QWidget {
    Q_OBJECT
public:
    explicit CovertChannelWidget(QWidget* parent = nullptr);
public slots:
    void updateChannel(const QJsonObject& channel);
    void addMessage(const QJsonObject& msg);
private:
    void setupUi();
    QComboBox* m_channelType;
    QLabel* m_bandwidth;
    QLabel* m_messagesSent;
    QTableWidget* m_messagesTable;
};
} // namespace widgets
