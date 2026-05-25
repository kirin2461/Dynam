#pragma once
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>

class TrafficAnalytics : public QWidget {
    Q_OBJECT
public:
    explicit TrafficAnalytics(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("Traffic Analytics (stub)", this));
    }
};
