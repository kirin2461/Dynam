#pragma once
#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>

namespace widgets {
class SPAWidget : public QWidget {
    Q_OBJECT
public:
    explicit SPAWidget(QWidget* parent = nullptr);
signals:
    void generateKey();
    void sendAuth();
public slots:
    void updateStatus(const QJsonObject& status);
    void updateKeys(const QJsonArray& keys);
private:
    void setupUi();
    QLabel* m_keyId;
    QLabel* m_authCount;
    QPushButton* m_generateBtn;
    QPushButton* m_sendBtn;
    QTableWidget* m_keysTable;
};
} // namespace widgets
