#pragma once

#include <QWidget>
#include <QChart>
#include <QChartView>
#include <QLineSeries>
#include <QValueAxis>

// Connections-per-interval chart (Qt Charts).
class TrafficAnalytics : public QWidget {
    Q_OBJECT
public:
    explicit TrafficAnalytics(QWidget* parent = nullptr);

    // Feed cumulative connections_total; delta per sample is plotted.
    void addSample(uint64_t connectionsTotal);

private:
    QChart* chart_;
    QChartView* view_;
    QLineSeries* series_;
    QValueAxis* axisX_;
    QValueAxis* axisY_;
    uint64_t lastTotal_ = 0;
    int tick_ = 0;
    double maxY_ = 10.0;
};
