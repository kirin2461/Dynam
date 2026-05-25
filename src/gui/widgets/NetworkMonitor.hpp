#pragma once
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>

class NetworkMonitor : public QWidget {
    Q_OBJECT
public:
    explicit NetworkMonitor(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("Network Monitor (stub)", this));
    }
    void refresh() {}
};
