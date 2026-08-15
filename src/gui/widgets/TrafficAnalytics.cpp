#include "TrafficAnalytics.hpp"

#include <QVBoxLayout>
#include <QLabel>


TrafficAnalytics::TrafficAnalytics(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(QStringLiteral("<b>Соединения (за интервал)</b>"), this));

    series_ = new QLineSeries();
    chart_ = new QChart();
    chart_->addSeries(series_);
    chart_->setBackgroundVisible(false);
    chart_->legend()->hide();
    chart_->setMargins(QMargins(4, 4, 4, 4));

    axisX_ = new QValueAxis();
    axisX_->setRange(0, 60);
    axisX_->setLabelFormat("%d");
    axisX_->setLabelsColor(QColor("#aaa"));
    axisY_ = new QValueAxis();
    axisY_->setRange(0, maxY_);
    axisY_->setLabelFormat("%d");
    axisY_->setLabelsColor(QColor("#aaa"));
    chart_->addAxis(axisX_, Qt::AlignBottom);
    chart_->addAxis(axisY_, Qt::AlignLeft);
    series_->attachAxis(axisX_);
    series_->attachAxis(axisY_);
    series_->setColor(QColor("#4caf50"));

    view_ = new QChartView(chart_, this);
    view_->setRenderHint(QPainter::Antialiasing);
    view_->setStyleSheet("background: transparent;");
    lay->addWidget(view_, 1);
}

void TrafficAnalytics::addSample(uint64_t connectionsTotal) {
    double delta = (tick_ == 0 || connectionsTotal < lastTotal_)
        ? 0.0
        : static_cast<double>(connectionsTotal - lastTotal_);
    lastTotal_ = connectionsTotal;
    series_->append(tick_++, delta);
    if (tick_ > 60) {
        series_->removePoints(0, 1);
        axisX_->setRange(tick_ - 60, tick_);
    }
    if (delta > maxY_) {
        maxY_ = delta * 1.2;
        axisY_->setRange(0, maxY_);
    }
}
