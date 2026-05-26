#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QLabel>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QSplitter>
#include <QProgressBar>
#include <QFileDialog>
#include <QMessageBox>
#include <QFont>
#include <QBrush>
#include <QColor>
#include <QQueue>
#include <QHash>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include "ScanCommon.hpp"

// Bulk scanner — paste URLs (one per line), Run, watch the leaderboard
// fill in real time as ScanProbe instances finish. Concurrency capped at
// 6 in-flight requests so we don't hammer the user's network (or the
// targets); the queue drains as slots free up.
class BulkScanDialog : public QDialog {
    Q_OBJECT
public:
    explicit BulkScanDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle(tr("Dynam — Bulk Site Scan"));
        setModal(false);
        resize(960, 640);
        net_ = new QNetworkAccessManager(this);

        auto* root = new QVBoxLayout(this);

        auto* split = new QSplitter(Qt::Horizontal, this);

        // ─── Left: URL input + controls ─────────────────────────────
        auto* leftWidget = new QWidget(split);
        auto* leftLayout = new QVBoxLayout(leftWidget);
        leftLayout->addWidget(new QLabel(tr("URLs (one per line)"), leftWidget));
        urlInput_ = new QPlainTextEdit(leftWidget);
        QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
        urlInput_->setFont(mono);
        urlInput_->setPlaceholderText(
            "https://example.com\nhttps://github.com\ncloudflare.com\n…");
        leftLayout->addWidget(urlInput_, 1);

        auto* btnRow = new QHBoxLayout;
        runBtn_    = new QPushButton(tr("Run scan"), leftWidget);
        cancelBtn_ = new QPushButton(tr("Cancel"), leftWidget);
        cancelBtn_->setEnabled(false);
        exportBtn_ = new QPushButton(tr("Export JSON…"), leftWidget);
        exportBtn_->setEnabled(false);
        btnRow->addWidget(runBtn_);
        btnRow->addWidget(cancelBtn_);
        btnRow->addStretch(1);
        btnRow->addWidget(exportBtn_);
        leftLayout->addLayout(btnRow);

        progress_ = new QProgressBar(leftWidget);
        progress_->setVisible(false);
        leftLayout->addWidget(progress_);

        // ─── Right: leaderboard table ───────────────────────────────
        auto* rightWidget = new QWidget(split);
        auto* rightLayout = new QVBoxLayout(rightWidget);
        rightLayout->addWidget(new QLabel(tr("Results (sort by clicking a header)"), rightWidget));

        table_ = new QTableWidget(rightWidget);
        table_->setColumnCount(8);
        table_->setHorizontalHeaderLabels({
            tr("URL"), tr("Status"), tr("Grade"), tr("Score"),
            tr("TLS"), tr("Server"), tr("Title"), tr("Tech"),
        });
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setAlternatingRowColors(true);
        table_->setSortingEnabled(true);
        table_->horizontalHeader()->setStretchLastSection(true);
        table_->verticalHeader()->setVisible(false);
        rightLayout->addWidget(table_, 1);

        split->addWidget(leftWidget);
        split->addWidget(rightWidget);
        split->setStretchFactor(0, 1);
        split->setStretchFactor(1, 3);
        root->addWidget(split, 1);

        connect(runBtn_,    &QPushButton::clicked, this, &BulkScanDialog::startRun);
        connect(cancelBtn_, &QPushButton::clicked, this, &BulkScanDialog::cancelRun);
        connect(exportBtn_, &QPushButton::clicked, this, &BulkScanDialog::exportJson);
    }

private slots:
    void startRun() {
        const QString raw = urlInput_->toPlainText();
        queue_.clear();
        for (const auto& line : raw.split('\n')) {
            const QString t = line.trimmed();
            if (t.isEmpty() || t.startsWith('#')) continue;
            queue_.enqueue(t);
        }
        if (queue_.isEmpty()) {
            QMessageBox::information(this, tr("Bulk scan"),
                tr("Add some URLs (one per line) first."));
            return;
        }
        total_       = queue_.size();
        completed_   = 0;
        results_.clear();
        table_->setRowCount(0);
        // Sorting must be off while we mutate rows; turn back on after.
        table_->setSortingEnabled(false);
        progress_->setVisible(true);
        progress_->setRange(0, total_);
        progress_->setValue(0);
        runBtn_->setEnabled(false);
        cancelBtn_->setEnabled(true);
        exportBtn_->setEnabled(false);
        cancelled_ = false;
        pumpQueue();
    }

    void cancelRun() {
        cancelled_ = true;
        queue_.clear();
        cancelBtn_->setEnabled(false);
    }

    void exportJson() {
        const QString path = QFileDialog::getSaveFileName(
            this, tr("Export bulk scan"),
            QDir::homePath() + "/Desktop/dynam-bulk-"
                + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") + ".json",
            tr("JSON (*.json);;All files (*)"));
        if (path.isEmpty()) return;
        QJsonArray arr;
        for (const auto& r : results_) arr.append(r.toJson());
        QJsonDocument doc(arr);
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::warning(this, tr("Export failed"), f.errorString());
            return;
        }
        f.write(doc.toJson(QJsonDocument::Indented));
    }

private:
    static constexpr int kMaxConcurrent = 6;

    void pumpQueue() {
        while (inFlight_ < kMaxConcurrent && !queue_.isEmpty() && !cancelled_) {
            const QString urlStr = queue_.dequeue();
            QUrl url(urlStr);
            if (url.scheme().isEmpty()) url.setScheme("https");
            ++inFlight_;
            auto* probe = new ScanProbe(net_, url, this);
            connect(probe, &ScanProbe::done, this, [this, probe](const ScanReport& r){
                addResultRow(r);
                results_.append(r);
                probe->deleteLater();
                --inFlight_;
                ++completed_;
                progress_->setValue(completed_);
                if (queue_.isEmpty() && inFlight_ == 0) finalize();
                else pumpQueue();
            });
            probe->run();
        }
    }

    void addResultRow(const ScanReport& r) {
        const int row = table_->rowCount();
        table_->insertRow(row);

        auto* urlItem  = new QTableWidgetItem(r.requestUrl.toString());
        auto* statItem = new QTableWidgetItem(r.httpStatus
                                                ? QString::number(r.httpStatus)
                                                : "—");
        auto* gradeItem = new QTableWidgetItem(r.secGrade);
        // Color the grade cell so the eye finds outliers fast.
        const QColor c = (r.secGrade == "A" ? QColor("#2ecc71") :
                          r.secGrade == "B" ? QColor("#3498db") :
                          r.secGrade == "C" ? QColor("#f39c12") :
                          r.secGrade == "D" ? QColor("#e67e22") :
                                              QColor("#e74c3c"));
        gradeItem->setForeground(QBrush(c));
        QFont gradeFont = gradeItem->font();
        gradeFont.setBold(true);
        gradeItem->setFont(gradeFont);

        auto* scoreItem = new QTableWidgetItem(
            QString("%1/%2").arg(r.secScore).arg(r.secMax));
        // Numeric sort: stash the percent as Qt::UserRole
        scoreItem->setData(Qt::UserRole,
                            r.secMax ? (100.0 * r.secScore / r.secMax) : 0.0);

        auto* tlsItem = new QTableWidgetItem(r.tlsProtocol.isEmpty()
                                              ? "—"
                                              : QString("%1 · %2-bit")
                                                  .arg(r.tlsProtocol).arg(r.tlsBits));
        auto* serverItem = new QTableWidgetItem(r.server.isEmpty() ? "—" : r.server);
        auto* titleItem  = new QTableWidgetItem(r.title.left(60));
        auto* techItem   = new QTableWidgetItem(r.techDetected.join(", "));

        table_->setItem(row, 0, urlItem);
        table_->setItem(row, 1, statItem);
        table_->setItem(row, 2, gradeItem);
        table_->setItem(row, 3, scoreItem);
        table_->setItem(row, 4, tlsItem);
        table_->setItem(row, 5, serverItem);
        table_->setItem(row, 6, titleItem);
        table_->setItem(row, 7, techItem);
    }

    void finalize() {
        progress_->setVisible(false);
        runBtn_->setEnabled(true);
        cancelBtn_->setEnabled(false);
        exportBtn_->setEnabled(!results_.isEmpty());
        // Re-enable sorting; sort by grade descending (A first) by default
        table_->setSortingEnabled(true);
        for (int c = 0; c < 6; ++c) table_->resizeColumnToContents(c);
    }

    QNetworkAccessManager* net_;
    QPlainTextEdit*  urlInput_;
    QPushButton*     runBtn_;
    QPushButton*     cancelBtn_;
    QPushButton*     exportBtn_;
    QProgressBar*    progress_;
    QTableWidget*    table_;

    QQueue<QString>  queue_;
    QList<ScanReport> results_;
    int              total_     = 0;
    int              completed_ = 0;
    int              inFlight_  = 0;
    bool             cancelled_ = false;
};
