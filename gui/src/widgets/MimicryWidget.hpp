#pragma once
#include <QWidget>
#include <QLabel>
#include <QComboBox>
#include <QTableWidget>

namespace widgets {
class MimicryWidget : public QWidget {
    Q_OBJECT
public:
    explicit MimicryWidget(QWidget* parent = nullptr);
public slots:
    void updateSession(const QJsonObject& session);
    void updateFSM(const QJsonObject& fsm);
private:
    void setupUi();
    QComboBox* m_profileCombo;
    QLabel* m_currentState;
    QLabel* m_currentPhase;
    QLabel* m_epoch;
    QTableWidget* m_transitionsTable;
};
} // namespace widgets
