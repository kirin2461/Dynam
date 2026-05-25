#pragma once
#include <QWidget>
#include <QLabel>
#include <QGridLayout>
#include <QElapsedTimer>
#include <QFont>
#include <cstdint>

class SystemStats : public QWidget {
    Q_OBJECT
public:
    explicit SystemStats(QWidget* parent = nullptr) : QWidget(parent) {
        auto* grid = new QGridLayout(this);
        grid->setHorizontalSpacing(16);
        grid->setVerticalSpacing(4);

        auto monoBold = [](const QString& text, QWidget* p) {
            auto* lbl = new QLabel(text, p);
            QFont f = lbl->font();
            f.setStyleHint(QFont::Monospace);
            f.setFamily("Menlo");
            lbl->setFont(f);
            return lbl;
        };

        grid->addWidget(new QLabel("<b>System Stats</b>", this), 0, 0, 1, 3);

        grid->addWidget(new QLabel("Sent",     this), 1, 0);
        grid->addWidget(new QLabel("Recv",     this), 2, 0);
        grid->addWidget(new QLabel("Packets",  this), 3, 0);

        sentTotal_  = monoBold("—", this); grid->addWidget(sentTotal_,  1, 1);
        recvTotal_  = monoBold("—", this); grid->addWidget(recvTotal_,  2, 1);
        pktsTotal_  = monoBold("—", this); grid->addWidget(pktsTotal_,  3, 1);

        sentRate_   = monoBold("0 B/s", this); grid->addWidget(sentRate_, 1, 2);
        recvRate_   = monoBold("0 B/s", this); grid->addWidget(recvRate_, 2, 2);
        pktsRate_   = monoBold("0/s",   this); grid->addWidget(pktsRate_, 3, 2);

        grid->setColumnStretch(0, 0);
        grid->setColumnStretch(1, 1);
        grid->setColumnStretch(2, 1);
    }

    void updateStats(uint64_t bytes_sent, uint64_t bytes_received,
                     uint64_t packets_sent, uint64_t packets_received) {
        const uint64_t pkts_total = packets_sent + packets_received;

        // Compute delta-rate. clock_.invalidated() returns true on the very
        // first call; that sample seeds the baseline so we don't divide by
        // zero or report a fake spike.
        if (!clock_.isValid()) {
            clock_.start();
            lastSent_ = bytes_sent;
            lastRecv_ = bytes_received;
            lastPkts_ = pkts_total;
        } else {
            const qint64 elapsed_ms = clock_.restart();
            if (elapsed_ms > 0) {
                const double secs = elapsed_ms / 1000.0;
                sentRate_->setText(formatBytes(static_cast<uint64_t>(
                    (bytes_sent - lastSent_) / secs)) + "/s");
                recvRate_->setText(formatBytes(static_cast<uint64_t>(
                    (bytes_received - lastRecv_) / secs)) + "/s");
                pktsRate_->setText(QString::number(static_cast<uint64_t>(
                    (pkts_total - lastPkts_) / secs)) + "/s");
                lastSent_ = bytes_sent;
                lastRecv_ = bytes_received;
                lastPkts_ = pkts_total;
            }
        }

        sentTotal_->setText(formatBytes(bytes_sent));
        recvTotal_->setText(formatBytes(bytes_received));
        pktsTotal_->setText(QString("%1 ↑ / %2 ↓")
                                .arg(packets_sent).arg(packets_received));
    }

private:
    static QString formatBytes(uint64_t bytes) {
        constexpr double K = 1024.0;
        if (bytes < 1024)                return QString("%1 B").arg(bytes);
        if (bytes < 1024ULL * 1024)      return QString::asprintf("%.1f KB", bytes / K);
        if (bytes < 1024ULL * 1024 * 1024) return QString::asprintf("%.2f MB", bytes / (K*K));
        return QString::asprintf("%.2f GB", bytes / (K*K*K));
    }

    QLabel* sentTotal_;
    QLabel* recvTotal_;
    QLabel* pktsTotal_;
    QLabel* sentRate_;
    QLabel* recvRate_;
    QLabel* pktsRate_;

    QElapsedTimer clock_;
    uint64_t lastSent_ = 0;
    uint64_t lastRecv_ = 0;
    uint64_t lastPkts_ = 0;
};
