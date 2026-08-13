#pragma once

#include <QWidget>

class QLabel;
class QPushButton;

// Top dashboard panel: protection state, listen address, chain info,
// start/stop buttons.
class StatusPanel : public QWidget {
    Q_OBJECT
public:
    explicit StatusPanel(QWidget* parent = nullptr);

    void setConnected(bool connected);
    void setAddress(const QString& addr);
    void setChain(const QString& chain);     // "" = direct
    void setBusy(bool busy);                 // starting (managed Tor bootstrap)

signals:
    void startRequested();
    void stopRequested();
    void settingsRequested();

private:
    QLabel* dotLabel_;
    QLabel* stateLabel_;
    QLabel* addressLabel_;
    QLabel* chainLabel_;
    QPushButton* startBtn_;
    QPushButton* stopBtn_;
    QPushButton* settingsBtn_;
};
