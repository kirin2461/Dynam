#pragma once
#include <QWidget>
#include <QLabel>
#include <QHBoxLayout>
#include <QFrame>
#include <QTimer>
#include <QDateTime>

// A coloured dot — solid filled circle drawn via QSS border-radius.
// Green when connected, red when not.
class StatusDot : public QFrame {
    Q_OBJECT
public:
    explicit StatusDot(QWidget* parent = nullptr) : QFrame(parent) {
        setFixedSize(12, 12);
        setConnected(false);
    }
    void setConnected(bool on) {
        const char* color = on ? "#2ecc71" : "#e74c3c";  // green / red
        setStyleSheet(QString("background:%1; border-radius:6px;").arg(color));
    }
};

class StatusPanel : public QWidget {
    Q_OBJECT
public:
    explicit StatusPanel(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QHBoxLayout(this);
        layout->setContentsMargins(4, 4, 4, 4);

        dot_         = new StatusDot(this);
        statusLabel_ = new QLabel("Disconnected", this);
        uptimeLabel_ = new QLabel("", this);

        QFont bold = statusLabel_->font();
        bold.setBold(true);
        statusLabel_->setFont(bold);

        layout->addWidget(dot_);
        layout->addWidget(statusLabel_);
        layout->addStretch(1);
        layout->addWidget(uptimeLabel_);

        // Tick once a second to refresh the uptime string; cheap.
        uptimeTimer_ = new QTimer(this);
        connect(uptimeTimer_, &QTimer::timeout, this, &StatusPanel::tickUptime);
        uptimeTimer_->start(1000);
    }

    void setConnected(bool connected) {
        if (connected_ == connected) return;
        connected_ = connected;
        dot_->setConnected(connected);
        statusLabel_->setText(connected ? "Connected" : "Disconnected");
        if (connected) {
            connectedAt_ = QDateTime::currentDateTime();
        } else {
            connectedAt_ = QDateTime();
            uptimeLabel_->clear();
        }
    }

private slots:
    void tickUptime() {
        if (!connected_ || !connectedAt_.isValid()) return;
        const qint64 secs = connectedAt_.secsTo(QDateTime::currentDateTime());
        const qint64 h = secs / 3600;
        const qint64 m = (secs / 60) % 60;
        const qint64 s = secs % 60;
        uptimeLabel_->setText(QString("uptime %1:%2:%3")
                                   .arg(h, 2, 10, QChar('0'))
                                   .arg(m, 2, 10, QChar('0'))
                                   .arg(s, 2, 10, QChar('0')));
    }

private:
    StatusDot* dot_;
    QLabel*    statusLabel_;
    QLabel*    uptimeLabel_;
    QTimer*    uptimeTimer_;
    QDateTime  connectedAt_;
    bool       connected_ = false;
};
