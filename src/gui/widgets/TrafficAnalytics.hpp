#pragma once
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QtCharts/QChart>
#include <QtCharts/QChartView>
#include <QtCharts/QLineSeries>
#include <QtCharts/QValueAxis>
#include <QElapsedTimer>
#include <QPainter>
#include <cstdint>
#include <algorithm>

class TrafficAnalytics : public QWidget {
    Q_OBJECT
public:
    explicit TrafficAnalytics(QWidget* parent = nullptr) : QWidget(parent) {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->addWidget(new QLabel("<b>Traffic (B/s, last 60s)</b>", this));

        sentSeries_ = new QLineSeries(this);
        sentSeries_->setName("Sent");
        recvSeries_ = new QLineSeries(this);
        recvSeries_->setName("Recv");

        chart_ = new QChart();
        chart_->addSeries(sentSeries_);
        chart_->addSeries(recvSeries_);
        chart_->legend()->setAlignment(Qt::AlignBottom);
        chart_->setBackgroundRoundness(4);
        chart_->setMargins(QMargins(4, 4, 4, 4));

        axisX_ = new QValueAxis(chart_);
        axisX_->setRange(0, kWindowSeconds);
        axisX_->setLabelFormat("%ds");
        axisX_->setTickCount(7);
        chart_->addAxis(axisX_, Qt::AlignBottom);
        sentSeries_->attachAxis(axisX_);
        recvSeries_->attachAxis(axisX_);

        axisY_ = new QValueAxis(chart_);
        axisY_->setRange(0, 1024);  // bootstrap; rescales as data arrives
        axisY_->setLabelFormat("%.0f");
        chart_->addAxis(axisY_, Qt::AlignLeft);
        sentSeries_->attachAxis(axisY_);
        recvSeries_->attachAxis(axisY_);

        view_ = new QChartView(chart_, this);
        view_->setRenderHint(QPainter::Antialiasing);
        layout->addWidget(view_, 1);
    }

    // Feed a cumulative (sent, recv) pair; we derive per-second deltas.
    void pushSample(uint64_t bytes_sent, uint64_t bytes_received) {
        if (!clock_.isValid()) {
            clock_.start();
            lastSent_ = bytes_sent;
            lastRecv_ = bytes_received;
            return;
        }
        const qint64 elapsed_ms = clock_.restart();
        if (elapsed_ms <= 0) return;
        const double secs = elapsed_ms / 1000.0;
        const double sentRate = (bytes_sent      - lastSent_) / secs;
        const double recvRate = (bytes_received - lastRecv_) / secs;
        lastSent_ = bytes_sent;
        lastRecv_ = bytes_received;

        appendShift(sentSeries_, sentRate);
        appendShift(recvSeries_, recvRate);
        rescaleY();
    }

private:
    static constexpr int kWindowSeconds = 60;

    // Append at the right edge and drop the oldest point; relabel x-axis
    // so the chart looks like a strip-chart moving right-to-left.
    void appendShift(QLineSeries* series, double value) {
        for (int i = 0; i < series->count(); ++i) {
            const auto p = series->at(i);
            series->replace(i, p.x() - 1, p.y());
        }
        series->append(kWindowSeconds, value);
        while (series->count() > 0 && series->at(0).x() < 0) {
            series->remove(0);
        }
    }

    void rescaleY() {
        double peak = 0;
        for (auto* s : {sentSeries_, recvSeries_}) {
            for (int i = 0; i < s->count(); ++i) peak = std::max(peak, s->at(i).y());
        }
        axisY_->setRange(0, std::max(peak * 1.2, 1024.0));
    }

    QChart*       chart_;
    QChartView*   view_;
    QLineSeries*  sentSeries_;
    QLineSeries*  recvSeries_;
    QValueAxis*   axisX_;
    QValueAxis*   axisY_;
    QElapsedTimer clock_;
    uint64_t      lastSent_ = 0;
    uint64_t      lastRecv_ = 0;
};
