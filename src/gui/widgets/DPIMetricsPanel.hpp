#pragma once
#include <QWidget>
#include <QGroupBox>
#include <QGridLayout>
#include <QLabel>
#include <QFont>
#include "../../core/include/ncp_dpi_advanced.hpp"

// Live counter readout for AdvancedDPIBypass. Pull-model: MainWindow's
// stats timer calls update() each second with the latest snapshot, this
// widget just renders. Lifetime: AdvancedDPIBypass is owned by MainWindow.
class DPIMetricsPanel : public QWidget {
    Q_OBJECT
public:
    explicit DPIMetricsPanel(QWidget* parent = nullptr) : QWidget(parent) {
        auto* box = new QGroupBox(tr("Live DPI counters"), this);
        auto* grid = new QGridLayout(box);
        grid->setHorizontalSpacing(20);

        auto addRow = [&](int row, const QString& label, QLabel*& out) {
            grid->addWidget(new QLabel(label, box), row, 0);
            out = new QLabel("0", box);
            out->setFont(mono());
            grid->addWidget(out, row, 1);
        };

        addRow(0, tr("TCP segments split:"),      tcpSplit_);
        addRow(1, tr("TCP overlaps sent:"),       tcpOverlap_);
        addRow(2, tr("TCP OOB sent:"),            tcpOob_);
        addRow(3, tr("TLS records split:"),       tlsSplit_);
        addRow(4, tr("GREASE injected:"),         grease_);
        addRow(5, tr("Packets padded:"),          padded_);
        addRow(6, tr("Padding bytes:"),           padBytes_);
        addRow(7, tr("Timing delays applied:"),   delays_);
        addRow(8, tr("Fake packets injected:"),   fakes_);
        addRow(9, tr("Signatures evaded:"),       evaded_);
        addRow(10, tr("ECH applied:"),            ech_);

        auto* outer = new QGridLayout(this);
        outer->addWidget(box, 0, 0);
        outer->setContentsMargins(0, 0, 0, 0);
    }

    void update(const ncp::DPI::AdvancedDPIStats& s) {
        tcpSplit_  ->setText(QString::number(s.tcp_segments_split.load()));
        tcpOverlap_->setText(QString::number(s.tcp_overlaps_sent.load()));
        tcpOob_    ->setText(QString::number(s.tcp_oob_sent.load()));
        tlsSplit_  ->setText(QString::number(s.tls_records_split.load()));
        grease_    ->setText(QString::number(s.grease_injected.load()));
        padded_    ->setText(QString::number(s.packets_padded.load()));
        padBytes_  ->setText(QString::number(s.bytes_padding.load()));
        delays_    ->setText(QString::number(s.timing_delays_applied.load()));
        fakes_     ->setText(QString::number(s.fake_packets_injected.load()));
        evaded_    ->setText(QString::number(s.dpi_signatures_evaded.load()));
        ech_       ->setText(QString::number(s.ech_applied.load()));
    }

private:
    static QFont mono() {
        QFont f; f.setStyleHint(QFont::Monospace); f.setFamily("Menlo");
        return f;
    }
    QLabel *tcpSplit_, *tcpOverlap_, *tcpOob_, *tlsSplit_, *grease_;
    QLabel *padded_, *padBytes_, *delays_, *fakes_, *evaded_, *ech_;
};
