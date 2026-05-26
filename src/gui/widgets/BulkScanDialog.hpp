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
#include <QInputDialog>
#include <QMenu>
#include "ScanCommon.hpp"
#include "PollerEngine.hpp"
#include "BulkDiffDialog.hpp"

// Bulk scanner — paste URLs (one per line), Run, watch the leaderboard
// fill in real time as ScanProbe instances finish. Concurrency capped at
// 6 in-flight requests so we don't hammer the user's network (or the
// targets); the queue drains as slots free up.
class BulkScanDialog : public QDialog {
    Q_OBJECT
public:
    explicit BulkScanDialog(PollerEngine* poller = nullptr,
                              QWidget* parent = nullptr)
        : QDialog(parent), poller_(poller) {
        setWindowTitle(tr("Dynam — Bulk Site Scan"));
        setModal(false);
        resize(1000, 660);
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
        runBtn_      = new QPushButton(tr("Run scan"), leftWidget);
        cancelBtn_   = new QPushButton(tr("Cancel"), leftWidget);
        cancelBtn_->setEnabled(false);
        historyBtn_  = new QPushButton(tr("History…"), leftWidget);
        btnRow->addWidget(runBtn_);
        btnRow->addWidget(cancelBtn_);
        btnRow->addStretch(1);
        btnRow->addWidget(historyBtn_);
        diffBtn_ = new QPushButton(tr("Diff…"), leftWidget);
        btnRow->addWidget(diffBtn_);
        leftLayout->addLayout(btnRow);

        auto* btnRow2 = new QHBoxLayout;
        exportJsonBtn_ = new QPushButton(tr("Export JSON…"), leftWidget);
        exportHtmlBtn_ = new QPushButton(tr("Export HTML…"), leftWidget);
        scheduleBtn_   = new QPushButton(tr("Schedule re-scans…"), leftWidget);
        exportJsonBtn_->setEnabled(false);
        exportHtmlBtn_->setEnabled(false);
        scheduleBtn_->setEnabled(false);
        scheduleBtn_->setToolTip(poller_
            ? tr("Create a Poller target for every URL so they're checked on a schedule")
            : tr("Poller engine not available; schedule disabled"));
        scheduleBtn_->setVisible(poller_ != nullptr);
        btnRow2->addWidget(exportJsonBtn_);
        btnRow2->addWidget(exportHtmlBtn_);
        btnRow2->addStretch(1);
        btnRow2->addWidget(scheduleBtn_);
        leftLayout->addLayout(btnRow2);

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

        connect(runBtn_,        &QPushButton::clicked, this, &BulkScanDialog::startRun);
        connect(cancelBtn_,     &QPushButton::clicked, this, &BulkScanDialog::cancelRun);
        connect(exportJsonBtn_, &QPushButton::clicked, this, &BulkScanDialog::exportJson);
        connect(exportHtmlBtn_, &QPushButton::clicked, this, &BulkScanDialog::exportHtml);
        connect(scheduleBtn_,   &QPushButton::clicked, this, &BulkScanDialog::scheduleRescans);
        connect(historyBtn_,    &QPushButton::clicked, this, &BulkScanDialog::openHistory);
        connect(diffBtn_,       &QPushButton::clicked, this, &BulkScanDialog::openDiff);
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
        exportJsonBtn_->setEnabled(false);
        exportHtmlBtn_->setEnabled(false);
        scheduleBtn_->setEnabled(false);
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

    void exportHtml() {
        const QString path = QFileDialog::getSaveFileName(
            this, tr("Export HTML report"),
            QDir::homePath() + "/Desktop/dynam-bulk-"
                + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") + ".html",
            tr("HTML (*.html);;All files (*)"));
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::warning(this, tr("Export failed"), f.errorString());
            return;
        }
        f.write(renderHtmlReport().toUtf8());
    }

    void scheduleRescans() {
        if (!poller_ || results_.isEmpty()) return;
        bool ok = false;
        const int interval = QInputDialog::getInt(this,
            tr("Schedule re-scans"),
            tr("Re-check every N seconds:"),
            300 /*default*/, 30, 86400, 30, &ok);
        if (!ok) return;
        int created = 0;
        for (const auto& r : results_) {
            PollerTarget t;
            t.name        = r.title.isEmpty() ? r.requestUrl.host() : r.title;
            t.kind        = PollerKind::HttpsUrl;
            t.target      = r.requestUrl.toString();
            t.intervalSec = interval;
            poller_->addTarget(t);
            ++created;
        }
        QMessageBox::information(this, tr("Scheduled"),
            tr("Created %1 Poller target%2 with a %3-second interval. "
               "Open the Poller tab in the main window to see them live.")
                .arg(created).arg(created == 1 ? "" : "s").arg(interval));
    }

    void openHistory() {
        const auto entries = ScanHistory::list("bulk");
        if (entries.isEmpty()) {
            QMessageBox::information(this, tr("History"),
                tr("No previous bulk runs found in ~/.dynam/scans/."));
            return;
        }
        QStringList labels;
        for (const auto& e : entries) labels << e.second;
        bool ok = false;
        const QString choice = QInputDialog::getItem(this,
            tr("Load bulk history"),
            tr("Pick a previous run to display:"),
            labels, 0, false, &ok);
        if (!ok) return;
        const int idx = labels.indexOf(choice);
        if (idx < 0) return;
        loadFromFile(entries[idx].first);
    }

    void openDiff() {
        auto* dlg = new BulkDiffDialog(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }

    void loadFromFile(const QString& path) {
        const auto doc = ScanHistory::load(path);
        if (!doc.isArray()) return;
        results_.clear();
        table_->setSortingEnabled(false);
        table_->setRowCount(0);
        for (const QJsonValue& v : doc.array()) {
            // Minimal round-trip: only fill the fields the table renders.
            // Full ScanReport::fromJson would be richer but isn't worth
            // implementing for the leaderboard view.
            ScanReport r;
            const auto o = v.toObject();
            r.requestUrl    = QUrl(o.value("request_url").toString());
            r.finalUrl      = QUrl(o.value("final_url").toString());
            r.httpStatus    = o.value("http_status").toInt();
            r.title         = o.value("title").toString();
            r.server        = o.value("server").toString();
            const auto sec  = o.value("security").toObject();
            r.secScore      = sec.value("score").toInt();
            r.secMax        = sec.value("max").toInt();
            r.secGrade      = sec.value("grade").toString();
            const auto tls  = o.value("tls").toObject();
            r.tlsProtocol   = tls.value("protocol").toString();
            r.tlsBits       = tls.value("bits").toInt();
            for (const QJsonValue& t : o.value("tech").toArray())
                r.techDetected.append(t.toString());
            addResultRow(r);
            results_.append(r);
        }
        table_->setSortingEnabled(true);
        exportJsonBtn_->setEnabled(true);
        exportHtmlBtn_->setEnabled(true);
        scheduleBtn_->setEnabled(poller_ != nullptr);
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
        const bool any = !results_.isEmpty();
        exportJsonBtn_->setEnabled(any);
        exportHtmlBtn_->setEnabled(any);
        scheduleBtn_->setEnabled(any && poller_ != nullptr);
        // Re-enable sorting; sort by grade descending (A first) by default
        table_->setSortingEnabled(true);
        for (int c = 0; c < 6; ++c) table_->resizeColumnToContents(c);

        // Persist a snapshot so the user can revisit via History…
        // (kept under ~/.dynam/scans/, auto-pruned to kMaxHistory).
        if (any && !cancelled_) {
            QJsonArray arr;
            for (const auto& r : results_) arr.append(r.toJson());
            ScanHistory::save("bulk", arr);
        }
    }

    // Standalone HTML report — inline CSS, no JS, works offline. Uses
    // simple coloured bars for the grade-distribution chart instead of
    // dragging in a chart library.
    QString renderHtmlReport() const {
        QHash<QString, int> gradeCount;
        for (const auto& r : results_) gradeCount[r.secGrade.isEmpty() ? "?" : r.secGrade]++;
        const QStringList gradeOrder = {"A", "B", "C", "D", "F", "?"};
        const QHash<QString, QString> gradeColor = {
            {"A", "#2ecc71"}, {"B", "#3498db"}, {"C", "#f39c12"},
            {"D", "#e67e22"}, {"F", "#e74c3c"}, {"?", "#7f8c8d"},
        };
        const int total = results_.size();

        QString html;
        html += "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n";
        html += "<title>Dynam bulk scan — " + QDateTime::currentDateTime().toString(Qt::ISODate) + "</title>\n";
        html += "<style>\n"
                "  body { font-family: -apple-system, sans-serif; max-width: 1100px; "
                "         margin: 32px auto; padding: 0 24px; color: #222; }\n"
                "  h1   { border-bottom: 2px solid #eee; padding-bottom: 8px; }\n"
                "  .meta { color: #888; font-size: 13px; }\n"
                "  .chart { display: flex; gap: 4px; height: 36px; margin: 16px 0; }\n"
                "  .chart .bar { color: white; padding: 8px; font-weight: bold; min-width: 24px; "
                "                text-align: center; border-radius: 3px; }\n"
                "  .card { border: 1px solid #ddd; border-radius: 6px; padding: 16px; "
                "          margin: 12px 0; background: #fafafa; }\n"
                "  .grade { display: inline-block; padding: 2px 10px; border-radius: 4px; "
                "           color: white; font-weight: bold; }\n"
                "  .url   { font-family: Menlo, monospace; color: #555; word-break: break-all; }\n"
                "  table { border-collapse: collapse; width: 100%; font-size: 13px; }\n"
                "  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; }\n"
                "  th { background: #f5f5f5; }\n"
                "  .tech { color: #555; font-size: 12px; }\n"
                "</style>\n</head>\n<body>\n";

        html += QString("<h1>Bulk site scan</h1>\n"
                        "<p class=\"meta\">Generated %1 · %2 target%3</p>\n")
                    .arg(QDateTime::currentDateTime().toString(Qt::ISODate))
                    .arg(total).arg(total == 1 ? "" : "s");

        // Chart bar
        html += "<h2>Grade distribution</h2>\n<div class=\"chart\">\n";
        for (const QString& g : gradeOrder) {
            const int n = gradeCount.value(g);
            if (n == 0) continue;
            const int pct = total ? (100 * n / total) : 0;
            html += QString("  <div class=\"bar\" style=\"background:%1; flex:%2;\">%3 · %4</div>\n")
                        .arg(gradeColor.value(g)).arg(n).arg(g).arg(n);
        }
        html += "</div>\n";

        // Summary table
        html += "<h2>Leaderboard</h2>\n<table>\n";
        html += "<tr><th>URL</th><th>Status</th><th>Grade</th><th>Score</th>"
                "<th>TLS</th><th>Server</th><th>Tech</th></tr>\n";
        for (const auto& r : results_) {
            const QString g = r.secGrade.isEmpty() ? "?" : r.secGrade;
            html += "<tr>"
                    "<td class=\"url\">" + r.requestUrl.toString().toHtmlEscaped() + "</td>"
                    "<td>" + QString::number(r.httpStatus) + "</td>"
                    "<td><span class=\"grade\" style=\"background:" + gradeColor.value(g) + "\">"
                          + g + "</span></td>"
                    "<td>" + QString("%1/%2").arg(r.secScore).arg(r.secMax) + "</td>"
                    "<td>" + (r.tlsProtocol.isEmpty() ? "—" : r.tlsProtocol) + "</td>"
                    "<td>" + r.server.toHtmlEscaped() + "</td>"
                    "<td class=\"tech\">" + r.techDetected.join(", ").toHtmlEscaped() + "</td>"
                    "</tr>\n";
        }
        html += "</table>\n";

        // Per-target detail cards
        html += "<h2>Per-target detail</h2>\n";
        for (const auto& r : results_) {
            const QString g = r.secGrade.isEmpty() ? "?" : r.secGrade;
            html += "<div class=\"card\">\n";
            html += "<h3>" + r.requestUrl.toString().toHtmlEscaped() + " · "
                    "<span class=\"grade\" style=\"background:" + gradeColor.value(g) + "\">"
                    + g + " · " + QString::number(r.secScore) + "/" + QString::number(r.secMax)
                    + "</span></h3>\n";
            html += "<p class=\"url\">→ " + r.finalUrl.toString().toHtmlEscaped() + "</p>\n";
            if (!r.title.isEmpty())
                html += "<p><b>" + r.title.toHtmlEscaped() + "</b></p>\n";
            html += "<p>HTTP " + QString::number(r.httpStatus)
                    + " · " + QString::number(r.timingMs) + " ms"
                    + (r.server.isEmpty() ? "" : " · " + r.server.toHtmlEscaped()) + "</p>\n";
            if (!r.tlsProtocol.isEmpty())
                html += "<p>TLS: " + r.tlsProtocol + " · " + r.tlsCipher
                        + " (" + QString::number(r.tlsBits) + "-bit)</p>\n";
            if (!r.techDetected.isEmpty())
                html += "<p class=\"tech\">Tech: " + r.techDetected.join(", ").toHtmlEscaped() + "</p>\n";
            html += "</div>\n";
        }

        html += "<p class=\"meta\">Report generated by Dynam Site Scraper</p>\n";
        html += "</body></html>\n";
        return html;
    }

    QNetworkAccessManager* net_;
    PollerEngine*    poller_;
    QPlainTextEdit*  urlInput_;
    QPushButton*     runBtn_;
    QPushButton*     cancelBtn_;
    QPushButton*     historyBtn_;
    QPushButton*     diffBtn_;
    QPushButton*     exportJsonBtn_;
    QPushButton*     exportHtmlBtn_;
    QPushButton*     scheduleBtn_;
    QProgressBar*    progress_;
    QTableWidget*    table_;

    QQueue<QString>  queue_;
    QList<ScanReport> results_;
    int              total_     = 0;
    int              completed_ = 0;
    int              inFlight_  = 0;
    bool             cancelled_ = false;
};
