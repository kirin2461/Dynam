#pragma once
// Minimal scaffolding widget — real implementation pending.
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>

class StatusPanel : public QWidget {
    Q_OBJECT
public:
    explicit StatusPanel(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        label_ = new QLabel("Status: Disconnected", this);
        layout->addWidget(label_);
    }
    void setConnected(bool connected) {
        label_->setText(connected ? "Status: Connected" : "Status: Disconnected");
    }
private:
    QLabel* label_;
};
