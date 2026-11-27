#pragma once
#include <QWidget>
#include <QLabel>
#include <QComboBox>
#include <QTableWidget>

namespace widgets {
class ECHWidget : public QWidget {
    Q_OBJECT
public:
    explicit ECHWidget(QWidget* parent = nullptr);
public slots:
    void updateConfig(const QJsonObject& config);
    void updateCache(const QJsonArray& entries);
private:
    void setupUi();
    QComboBox* m_kemAlgo;
    QComboBox* m_kdfAlgo;
    QComboBox* m_aeadAlgo;
    QLabel* m_cacheSize;
    QTableWidget* m_cacheTable;
};
} // namespace widgets
