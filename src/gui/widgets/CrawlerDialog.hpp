#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QSpinBox>
#include <QLabel>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QProgressBar>
#include <QFont>
#include <QQueue>
#include <QSet>
#include <QRegularExpression>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QJsonArray>
#include <QInputDialog>
#include <QMessageBox>
#include "ScanCommon.hpp"

// Depth-limited BFS crawler. Starts from the input URL, fetches each
// page, extracts internal links from <a href>, queues new ones up to
// depth N or page cap M. Polite about it: cap concurrency and stop at
// the page limit no matter the depth.
class CrawlerDialog : public QDialog {
    Q_OBJECT
public:
    explicit CrawlerDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle(tr("Dynam — Site Crawler"));
        setModal(false);
        resize(900, 600);
        net_ = new QNetworkAccessManager(this);

        auto* root = new QVBoxLayout(this);

        // ─── Controls ───────────────────────────────────────────────
        auto* form = new QFormLayout;
        urlEdit_ = new QLineEdit(this);
        urlEdit_->setPlaceholderText("https://example.com");

        depthSpin_ = new QSpinBox(this);
        depthSpin_->setRange(1, 5);
        depthSpin_->setValue(2);
        depthSpin_->setSuffix(tr(" hops"));

        capSpin_ = new QSpinBox(this);
        capSpin_->setRange(5, 500);
        capSpin_->setValue(30);
        capSpin_->setSingleStep(5);
        capSpin_->setSuffix(tr(" pages"));

        form->addRow(tr("Start URL:"), urlEdit_);
        form->addRow(tr("Max depth:"), depthSpin_);
        form->addRow(tr("Page cap:"),  capSpin_);
        root->addLayout(form);

        auto* btnRow = new QHBoxLayout;
        startBtn_  = new QPushButton(tr("Start crawl"), this);
        stopBtn_   = new QPushButton(tr("Stop"), this);
        historyBtn_ = new QPushButton(tr("History…"), this);
        stopBtn_->setEnabled(false);
        btnRow->addWidget(startBtn_);
        btnRow->addWidget(stopBtn_);
        btnRow->addWidget(historyBtn_);
        btnRow->addStretch(1);
        statusLabel_ = new QLabel(tr("idle"), this);
        statusLabel_->setStyleSheet("color:#888;");
        btnRow->addWidget(statusLabel_);
        root->addLayout(btnRow);

        progress_ = new QProgressBar(this);
        progress_->setVisible(false);
        root->addWidget(progress_);

        table_ = new QTableWidget(this);
        table_->setColumnCount(6);
        table_->setHorizontalHeaderLabels({
            tr("Depth"), tr("Status"), tr("URL"), tr("Type"),
            tr("Bytes"), tr("Title"),
        });
        table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table_->setAlternatingRowColors(true);
        table_->setSortingEnabled(true);
        table_->horizontalHeader()->setStretchLastSection(true);
        table_->verticalHeader()->setVisible(false);
        root->addWidget(table_, 1);

        connect(startBtn_,   &QPushButton::clicked,     this, &CrawlerDialog::start);
        connect(stopBtn_,    &QPushButton::clicked,     this, &CrawlerDialog::stop);
        connect(urlEdit_,    &QLineEdit::returnPressed, this, &CrawlerDialog::start);
        connect(historyBtn_, &QPushButton::clicked,     this, &CrawlerDialog::openHistory);
    }

private slots:
    void start() {
        QString text = urlEdit_->text().trimmed();
        if (text.isEmpty()) return;
        if (!text.contains("://")) text = "https://" + text;
        QUrl seed(text);
        if (!seed.isValid() || seed.host().isEmpty()) {
            statusLabel_->setText(tr("invalid URL"));
            return;
        }

        seedHost_   = seed.host();
        maxDepth_   = depthSpin_->value();
        pageCap_    = capSpin_->value();
        cancelled_  = false;
        visited_.clear();
        queue_.clear();
        capturedRows_.clear();
        table_->setRowCount(0);
        table_->setSortingEnabled(false);

        queue_.enqueue({seed, 0});
        visited_.insert(seed.toString(QUrl::RemoveFragment));
        startBtn_->setEnabled(false);
        stopBtn_->setEnabled(true);
        progress_->setVisible(true);
        progress_->setRange(0, pageCap_);
        progress_->setValue(0);
        statusLabel_->setText(tr("crawling %1 (depth %2, cap %3)")
                                .arg(seedHost_).arg(maxDepth_).arg(pageCap_));
        pumpQueue();
    }

    void stop() {
        cancelled_ = true;
        queue_.clear();
        stopBtn_->setEnabled(false);
        statusLabel_->setText(tr("cancelling…"));
    }

private:
    struct Pending { QUrl url; int depth; };
    static constexpr int kMaxConcurrent = 4;

    void pumpQueue() {
        while (inFlight_ < kMaxConcurrent && !queue_.isEmpty()
               && fetched_ < pageCap_ && !cancelled_) {
            const Pending p = queue_.dequeue();
            ++inFlight_;
            fetchOne(p);
        }
        if (inFlight_ == 0) finalize();
    }

    void fetchOne(const Pending& p) {
        QNetworkRequest req(p.url);
        req.setHeader(QNetworkRequest::UserAgentHeader,
                      "Mozilla/5.0 (compatible; Dynam-Crawler/1.2)");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* timer = new QElapsedTimer; timer->start();
        QNetworkReply* reply = net_->get(req);
        connect(reply, &QNetworkReply::finished, this,
                [this, reply, p, timer]{
            const qint64 /*ms*/ _ = timer->elapsed(); (void)_;
            delete timer;
            const QByteArray body = reply->readAll();
            const int status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QString ctype = reply->header(QNetworkRequest::ContentTypeHeader).toString();

            // Title (only useful for HTML responses)
            QString title;
            if (ctype.contains("html", Qt::CaseInsensitive)) {
                QRegularExpression titleRe("<title[^>]*>([^<]*)</title>",
                    QRegularExpression::CaseInsensitiveOption);
                const auto tm = titleRe.match(QString::fromUtf8(body.left(64 * 1024)));
                if (tm.hasMatch()) title = tm.captured(1).trimmed();
            }

            addRow(p.depth, status, p.url.toString(), ctype, body.size(), title);
            ++fetched_;
            progress_->setValue(fetched_);

            // Extract internal links and enqueue (up to depth+1 < maxDepth)
            if (ctype.contains("html", Qt::CaseInsensitive) && p.depth + 1 <= maxDepth_) {
                QRegularExpression linkRe("<a\\s[^>]*href=[\"']([^\"']+)[\"']",
                    QRegularExpression::CaseInsensitiveOption);
                auto it = linkRe.globalMatch(QString::fromUtf8(body));
                while (it.hasNext()) {
                    const QString href = it.next().captured(1);
                    if (href.startsWith('#') || href.startsWith("mailto:")
                        || href.startsWith("tel:") || href.startsWith("javascript:"))
                        continue;
                    QUrl child = p.url.resolved(QUrl(href)).adjusted(
                        QUrl::RemoveFragment | QUrl::StripTrailingSlash);
                    // Only internal links
                    if (child.host() != seedHost_) continue;
                    const QString key = child.toString();
                    if (visited_.contains(key)) continue;
                    visited_.insert(key);
                    queue_.enqueue({child, p.depth + 1});
                }
            }

            reply->deleteLater();
            --inFlight_;
            pumpQueue();
        });
    }

    // In-memory record of every row, used for save-on-finalize + history reload.
    struct Row {
        int depth = 0; int status = 0; QString url, type, title; qint64 bytes = 0;
        QJsonObject toJson() const {
            QJsonObject o;
            o["depth"]=depth; o["status"]=status; o["url"]=url;
            o["type"]=type; o["bytes"]=static_cast<qint64>(bytes); o["title"]=title;
            return o;
        }
    };
    QList<Row> capturedRows_;

    void addRow(int depth, int status, const QString& url,
                  const QString& type, qint64 bytes, const QString& title) {
        capturedRows_.append({depth, status, url, type, title, bytes});
        const int row = table_->rowCount();
        table_->insertRow(row);

        auto* depthItem = new QTableWidgetItem(QString::number(depth));
        depthItem->setData(Qt::UserRole, depth);  // numeric sort

        auto* statItem = new QTableWidgetItem(status ? QString::number(status) : "—");
        if (status >= 200 && status < 300) statItem->setForeground(QBrush(QColor("#2ecc71")));
        else if (status >= 300 && status < 400) statItem->setForeground(QBrush(QColor("#3498db")));
        else if (status >= 400) statItem->setForeground(QBrush(QColor("#e74c3c")));

        auto* urlItem = new QTableWidgetItem(url);
        QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
        urlItem->setFont(mono);

        auto* typeItem  = new QTableWidgetItem(type.section(';', 0, 0));
        auto* bytesItem = new QTableWidgetItem(QString::number(bytes));
        bytesItem->setData(Qt::UserRole, static_cast<qlonglong>(bytes));
        auto* titleItem = new QTableWidgetItem(title.left(80));

        table_->setItem(row, 0, depthItem);
        table_->setItem(row, 1, statItem);
        table_->setItem(row, 2, urlItem);
        table_->setItem(row, 3, typeItem);
        table_->setItem(row, 4, bytesItem);
        table_->setItem(row, 5, titleItem);
    }

    void finalize() {
        progress_->setVisible(false);
        startBtn_->setEnabled(true);
        stopBtn_->setEnabled(false);
        table_->setSortingEnabled(true);
        for (int c = 0; c < 5; ++c) table_->resizeColumnToContents(c);
        statusLabel_->setText(cancelled_
            ? tr("cancelled — %1 pages fetched").arg(fetched_)
            : tr("done — %1 pages, %2 queued unvisited")
                .arg(fetched_).arg(queue_.size() + visited_.size() - fetched_));

        // Persist a snapshot so the user can revisit via History….
        if (!capturedRows_.isEmpty() && !cancelled_) {
            QJsonObject doc;
            doc["seed"]      = seedHost_;
            doc["max_depth"] = maxDepth_;
            doc["page_cap"]  = pageCap_;
            doc["timestamp"] = QDateTime::currentDateTime().toString(Qt::ISODate);
            QJsonArray rows;
            for (const auto& r : capturedRows_) rows.append(r.toJson());
            doc["rows"] = rows;
            ScanHistory::save("crawl", doc);
        }
        fetched_   = 0;
        inFlight_  = 0;
    }

    void openHistory() {
        const auto entries = ScanHistory::list("crawl");
        if (entries.isEmpty()) {
            QMessageBox::information(this, tr("History"),
                tr("No previous crawl runs found in ~/.dynam/scans/."));
            return;
        }
        QStringList labels;
        for (const auto& e : entries) labels << e.second;
        bool ok = false;
        const QString choice = QInputDialog::getItem(this,
            tr("Load crawl history"),
            tr("Pick a previous crawl to display:"),
            labels, 0, false, &ok);
        if (!ok) return;
        const int idx = labels.indexOf(choice);
        if (idx < 0) return;
        const auto doc = ScanHistory::load(entries[idx].first);
        if (!doc.isObject()) return;
        const auto obj = doc.object();
        seedHost_ = obj.value("seed").toString();
        urlEdit_->setText("https://" + seedHost_);
        depthSpin_->setValue(obj.value("max_depth").toInt(2));
        capSpin_->setValue(obj.value("page_cap").toInt(30));
        table_->setSortingEnabled(false);
        table_->setRowCount(0);
        capturedRows_.clear();
        for (const QJsonValue& v : obj.value("rows").toArray()) {
            const auto r = v.toObject();
            addRow(r.value("depth").toInt(),
                   r.value("status").toInt(),
                   r.value("url").toString(),
                   r.value("type").toString(),
                   r.value("bytes").toVariant().toLongLong(),
                   r.value("title").toString());
        }
        table_->setSortingEnabled(true);
        statusLabel_->setText(tr("loaded %1 rows from %2")
                                .arg(capturedRows_.size()).arg(entries[idx].second));
    }

    QNetworkAccessManager* net_;
    QLineEdit*    urlEdit_;
    QSpinBox*     depthSpin_;
    QSpinBox*     capSpin_;
    QPushButton*  startBtn_;
    QPushButton*  stopBtn_;
    QPushButton*  historyBtn_;
    QProgressBar* progress_;
    QLabel*       statusLabel_;
    QTableWidget* table_;

    QString          seedHost_;
    int              maxDepth_ = 2;
    int              pageCap_  = 30;
    int              fetched_  = 0;
    int              inFlight_ = 0;
    bool             cancelled_ = false;
    QQueue<Pending>  queue_;
    QSet<QString>    visited_;
};
