#pragma once
#include <QWidget>
#include <QPainter>
#include <QPaintEvent>
#include <QVector>
#include <QColor>

// SparklineWidget — paints a horizontal sequence of pass/fail bars.
// Designed to live inside a QTableWidget cell at ~120×24 px. Each bool
// becomes one bar; green = pass, red = fail. Newest result is rightmost.
// Empty history → blank widget.
//
// Repaint is cheap (one paint per row per refresh) and we don't cache
// pixmaps — the table re-renders maybe 1×/sec, well below where any
// optimization matters.
class SparklineWidget : public QWidget {
    Q_OBJECT
public:
    explicit SparklineWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumSize(120, 22);
        // Tooltip is set externally with the success-rate text so the
        // user can hover for context.
    }

    void setHistory(const QVector<bool>& h) {
        history_ = h;
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, false);

        const QColor passClr("#2ecc71");
        const QColor failClr("#e74c3c");
        const QColor bgClr  ("#2a2a3a");  // subtle background bar for empty slots

        const int n = history_.size();
        const int totalSlots = SparklineCapacity;  // always draw a fixed window
        const int w = width();
        const int h = height();
        const int gap = 1;
        const int barW = std::max(2, (w - gap * (totalSlots - 1)) / totalSlots);
        const int actualW = barW * totalSlots + gap * (totalSlots - 1);
        const int xOff = (w - actualW) / 2;

        for (int i = 0; i < totalSlots; ++i) {
            const int x = xOff + i * (barW + gap);
            const int idx = i - (totalSlots - n);   // align newest to the right
            QColor c = bgClr;
            if (idx >= 0 && idx < n) {
                c = history_[idx] ? passClr : failClr;
            }
            p.fillRect(x, 0, barW, h, c);
        }
    }

private:
    static constexpr int SparklineCapacity = 60;  // must match PollerTarget::kHistoryDepth
    QVector<bool> history_;
};
