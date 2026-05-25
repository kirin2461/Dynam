#pragma once
#include <QWidget>
#include <QGroupBox>
#include <QGridLayout>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QFont>
#include <QPushButton>
#include <QSpinBox>
#include <QThread>
#include <atomic>
#include <vector>
#include <random>
#include "../../core/include/ncp_dpi_advanced.hpp"

// Worker thread for the benchmark — pumps synthetic packets through
// AdvancedDPIBypass::process_outgoing on a tight loop so the counters
// move visibly without us having to wait for real network traffic. The
// engine pointer is borrowed from MainWindow and outlives the worker.
class DPIBenchmarkWorker : public QObject {
    Q_OBJECT
public:
    DPIBenchmarkWorker(ncp::DPI::AdvancedDPIBypass* engine, int packetSize, int durationSec)
        : engine_(engine), packetSize_(packetSize), durationSec_(durationSec) {}

public slots:
    void run() {
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, 255);
        std::vector<uint8_t> buf(packetSize_);
        const auto deadline = std::chrono::steady_clock::now()
                              + std::chrono::seconds(durationSec_);
        uint64_t pumped = 0;
        while (!stop_.load() && std::chrono::steady_clock::now() < deadline) {
            for (auto& b : buf) b = static_cast<uint8_t>(dist(rng));
            (void)engine_->process_outgoing(buf.data(), buf.size());
            ++pumped;
            if ((pumped & 0xFFF) == 0) QThread::usleep(100);  // yield occasionally
        }
        emit finished(pumped);
    }
    void requestStop() { stop_.store(true); }

signals:
    void finished(quint64 packetsPumped);

private:
    ncp::DPI::AdvancedDPIBypass* engine_;
    int packetSize_;
    int durationSec_;
    std::atomic<bool> stop_{false};
};

// Live counter readout for AdvancedDPIBypass. Pull-model: MainWindow's
// stats timer calls update() each second with the latest snapshot, this
// widget just renders. Lifetime: AdvancedDPIBypass is owned by MainWindow.
class DPIMetricsPanel : public QWidget {
    Q_OBJECT
public:
    explicit DPIMetricsPanel(ncp::DPI::AdvancedDPIBypass* engine = nullptr,
                              QWidget* parent = nullptr)
        : QWidget(parent), engine_(engine) {
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

        // Benchmark row: lets the user generate synthetic load so the
        // counters above visibly increment. Useful sanity check that the
        // pipeline is wired even when no real traffic is flowing.
        auto* benchBox = new QGroupBox(tr("Benchmark"), this);
        auto* benchLayout = new QHBoxLayout(benchBox);
        sizeSpin_ = new QSpinBox(benchBox);
        sizeSpin_->setRange(64, 65535);
        sizeSpin_->setSingleStep(64);
        sizeSpin_->setValue(1500);
        sizeSpin_->setSuffix(" B");
        durSpin_ = new QSpinBox(benchBox);
        durSpin_->setRange(1, 120);
        durSpin_->setValue(5);
        durSpin_->setSuffix(" s");
        runBtn_  = new QPushButton(tr("Run benchmark"), benchBox);
        stopBtn_ = new QPushButton(tr("Stop"), benchBox);
        stopBtn_->setEnabled(false);
        benchStatus_ = new QLabel(tr("idle"), benchBox);
        benchLayout->addWidget(new QLabel(tr("Packet size:"), benchBox));
        benchLayout->addWidget(sizeSpin_);
        benchLayout->addWidget(new QLabel(tr("Duration:"), benchBox));
        benchLayout->addWidget(durSpin_);
        benchLayout->addWidget(runBtn_);
        benchLayout->addWidget(stopBtn_);
        benchLayout->addStretch(1);
        benchLayout->addWidget(benchStatus_);

        connect(runBtn_,  &QPushButton::clicked, this, &DPIMetricsPanel::startBenchmark);
        connect(stopBtn_, &QPushButton::clicked, this, &DPIMetricsPanel::stopBenchmark);

        auto* outer = new QVBoxLayout(this);
        outer->setContentsMargins(0, 0, 0, 0);
        outer->addWidget(box);
        outer->addWidget(benchBox);
        outer->addStretch(1);
    }

private slots:
    void startBenchmark() {
        if (!engine_) {
            benchStatus_->setText(tr("no engine"));
            return;
        }
        if (worker_) return;  // already running

        worker_ = new DPIBenchmarkWorker(engine_, sizeSpin_->value(), durSpin_->value());
        thread_ = new QThread(this);
        worker_->moveToThread(thread_);
        connect(thread_, &QThread::started,  worker_, &DPIBenchmarkWorker::run);
        connect(worker_, &DPIBenchmarkWorker::finished, this,
                &DPIMetricsPanel::onBenchmarkDone, Qt::QueuedConnection);

        runBtn_->setEnabled(false);
        stopBtn_->setEnabled(true);
        benchStatus_->setText(tr("running…"));
        thread_->start();
    }

    void stopBenchmark() {
        if (worker_) worker_->requestStop();
    }

    void onBenchmarkDone(quint64 pumped) {
        thread_->quit();
        thread_->wait();
        worker_->deleteLater();
        thread_->deleteLater();
        worker_ = nullptr;
        thread_ = nullptr;
        runBtn_->setEnabled(true);
        stopBtn_->setEnabled(false);
        benchStatus_->setText(tr("done — %1 packets pumped").arg(pumped));
    }

public:
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

    ncp::DPI::AdvancedDPIBypass* engine_;  // not owned
    QSpinBox*    sizeSpin_;
    QSpinBox*    durSpin_;
    QPushButton* runBtn_;
    QPushButton* stopBtn_;
    QLabel*      benchStatus_;
    DPIBenchmarkWorker* worker_ = nullptr;
    QThread*           thread_  = nullptr;
};
