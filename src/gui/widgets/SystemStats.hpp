#pragma once
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <cstdint>

class SystemStats : public QWidget {
    Q_OBJECT
public:
    explicit SystemStats(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        label_ = new QLabel("0 ↑ / 0 ↓ bytes — 0 ↑ / 0 ↓ pkts", this);
        layout->addWidget(label_);
    }
    void updateStats(uint64_t bytes_sent, uint64_t bytes_received,
                     uint64_t packets_sent, uint64_t packets_received) {
        label_->setText(QString("%1 ↑ / %2 ↓ bytes — %3 ↑ / %4 ↓ pkts")
                            .arg(bytes_sent).arg(bytes_received)
                            .arg(packets_sent).arg(packets_received));
    }
private:
    QLabel* label_;
};
