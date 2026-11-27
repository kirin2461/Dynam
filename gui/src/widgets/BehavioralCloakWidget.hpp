#pragma once
#include <QWidget>
#include <QLabel>
#include <QComboBox>

namespace widgets {
class BehavioralCloakWidget : public QWidget {
    Q_OBJECT
public:
    explicit BehavioralCloakWidget(QWidget* parent = nullptr);
public slots:
    void updateModel(const QJsonObject& model);
    void updateStats(const QJsonObject& stats);
private:
    void setupUi();
    QComboBox* m_modelCombo;
    QLabel* m_burstPackets;
    QLabel* m_idleTime;
    QLabel* m_uploadRatio;
    QLabel* m_matchScore;
};
} // namespace widgets
