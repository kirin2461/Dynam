#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QPlainTextEdit>
#include <QScrollArea>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QHostInfo>
#include <QSslSocket>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QNetworkCookieJar>
#include <QNetworkCookie>
#include <QRegularExpression>
#include <QUrl>
#include <QUrlQuery>
#include <QHostAddress>
#include <QElapsedTimer>
#include <QApplication>
#include <QClipboard>
#include <QFont>
#include <QSet>
#include <QFileDialog>
#include <QJsonDocument>
#include <QMessageBox>
#include "ScanCommon.hpp"
#include "BulkScanDialog.hpp"
#include "CrawlerDialog.hpp"

// SiteScraperPanel — one-click reconnaissance of a URL. Fires off ~7
// independent probes in parallel and renders results as they arrive:
//   1. Main GET request (status, headers, body for HTML parsing)
//   2. DNS resolve (A records)
//   3. TLS handshake (cipher, cert chain, expiry, SANs)
//   4. /robots.txt
//   5. /sitemap.xml
//   6. /favicon.ico (existence + size)
//   7. Cookies set by main response
//
// HTML body is regex-extracted for:
//   - <title>
//   - <meta name="…" content="…">  + <meta property="og:…">
//   - <a href="…">  (link inventory)
//   - <img src=…>, <script src=…>, <link href=…>
//   - <form action=…>
//
// Each section is its own QGroupBox in a scroll area; a section renders
// the moment its probe finishes.
class SiteScraperPanel : public QWidget {
    Q_OBJECT
public:
    explicit SiteScraperPanel(QWidget* parent = nullptr) : QWidget(parent) {
        net_ = new QNetworkAccessManager(this);

        auto* root = new QVBoxLayout(this);

        // ─── URL input bar ──────────────────────────────────────────
        auto* inputBox = new QGroupBox(tr("Inspect a website"), this);
        auto* inputLayout = new QHBoxLayout(inputBox);
        urlEdit_ = new QLineEdit(inputBox);
        urlEdit_->setPlaceholderText("example.com  (or full https://… URL)");
        QFont big = urlEdit_->font(); big.setPointSize(big.pointSize() + 2);
        urlEdit_->setFont(big);
        scanBtn_ = new QPushButton(tr("Scan"), inputBox);
        scanBtn_->setDefault(true);
        scanBtn_->setMinimumWidth(80);
        exportMdBtn_ = new QPushButton(tr("Export MD"), inputBox);
        exportJsonBtn_ = new QPushButton(tr("Export JSON"), inputBox);
        exportMdBtn_->setEnabled(false);
        exportJsonBtn_->setEnabled(false);
        bulkBtn_  = new QPushButton(tr("Bulk…"), inputBox);
        crawlBtn_ = new QPushButton(tr("Crawl…"), inputBox);
        inputLayout->addWidget(urlEdit_, 1);
        inputLayout->addWidget(scanBtn_);
        inputLayout->addWidget(exportMdBtn_);
        inputLayout->addWidget(exportJsonBtn_);
        inputLayout->addSpacing(8);
        inputLayout->addWidget(bulkBtn_);
        inputLayout->addWidget(crawlBtn_);
        connect(scanBtn_,       &QPushButton::clicked,     this, &SiteScraperPanel::startScan);
        connect(urlEdit_,       &QLineEdit::returnPressed, this, &SiteScraperPanel::startScan);
        connect(exportMdBtn_,   &QPushButton::clicked,     this, &SiteScraperPanel::exportMd);
        connect(exportJsonBtn_, &QPushButton::clicked,     this, &SiteScraperPanel::exportJson);
        connect(bulkBtn_,       &QPushButton::clicked,     this, &SiteScraperPanel::openBulkDialog);
        connect(crawlBtn_,      &QPushButton::clicked,     this, &SiteScraperPanel::openCrawlerDialog);

        root->addWidget(inputBox);

        // ─── Scroll area of result sections ─────────────────────────
        auto* scroll = new QScrollArea(this);
        scroll->setWidgetResizable(true);
        auto* sectionHost = new QWidget;
        sectionsLayout_ = new QVBoxLayout(sectionHost);
        sectionsLayout_->setSpacing(8);
        sectionsLayout_->addStretch(1);
        scroll->setWidget(sectionHost);
        root->addWidget(scroll, 1);

        statusBar_ = new QLabel(tr("Enter a URL and press Scan."), this);
        statusBar_->setStyleSheet("color:#888; padding:4px;");
        root->addWidget(statusBar_);
    }

private slots:
    void startScan() {
        QString text = urlEdit_->text().trimmed();
        if (text.isEmpty()) return;
        if (!text.contains("://")) text = "https://" + text;
        const QUrl url(text);
        if (!url.isValid() || url.host().isEmpty()) {
            statusBar_->setText(tr("invalid URL: %1").arg(url.errorString()));
            return;
        }

        clearSections();
        currentHost_ = url.host();
        pendingProbes_ = 0;
        scanBtn_->setEnabled(false);
        exportMdBtn_->setEnabled(false);
        exportJsonBtn_->setEnabled(false);
        report_ = {};                       // fresh report for this run
        report_.requestUrl = url;
        statusBar_->setText(tr("Scanning %1 …").arg(currentHost_));

        fetchMain(url);
        resolveDns(url.host());
        fetchTlsInfo(url.host(), url.port(443));
        fetchAuxiliary(url, "/robots.txt",  &SiteScraperPanel::renderRobots);
        fetchAuxiliary(url, "/sitemap.xml", &SiteScraperPanel::renderSitemap);
        fetchFavicon(url);
    }

private:
    // ─── Section helpers ────────────────────────────────────────────
    void clearSections() {
        // Tear down every section but keep the trailing stretch
        while (sectionsLayout_->count() > 1) {
            auto* item = sectionsLayout_->takeAt(0);
            if (item->widget()) item->widget()->deleteLater();
            delete item;
        }
    }

    QGroupBox* addSection(const QString& title) {
        auto* box = new QGroupBox(title);
        box->setCheckable(true);
        box->setChecked(true);
        // Insert before the trailing stretch
        sectionsLayout_->insertWidget(sectionsLayout_->count() - 1, box);
        return box;
    }

    QPlainTextEdit* monoTextIn(QGroupBox* box) {
        auto* layout = new QVBoxLayout(box);
        auto* edit = new QPlainTextEdit(box);
        edit->setReadOnly(true);
        QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
        edit->setFont(mono);
        edit->setMaximumHeight(300);
        layout->addWidget(edit);
        return edit;
    }

    void probeDone() {
        if (--pendingProbes_ <= 0) {
            scanBtn_->setEnabled(true);
            exportMdBtn_->setEnabled(true);
            exportJsonBtn_->setEnabled(true);
            // Tech detection runs once all probes are in so it has access
            // to both the main body and the full header set.
            if (!report_.responseHeaders.isEmpty() && !rawBody_.isEmpty()) {
                detectTech(report_.responseHeaders, rawBody_, report_);
                if (!report_.techDetected.isEmpty()) {
                    auto* box = addSection(tr("🧰 Technology — %1 detected")
                                              .arg(report_.techDetected.size()));
                    auto* out = monoTextIn(box);
                    out->setPlainText(report_.techDetected.join('\n'));
                }
            }
            statusBar_->setText(tr("Scan complete for %1 · grade %2 · %3 tech")
                                  .arg(currentHost_)
                                  .arg(report_.secGrade.isEmpty() ? "—" : report_.secGrade)
                                  .arg(report_.techDetected.size()));
        }
    }
    void probeStart() { ++pendingProbes_; }

    // ─── Export ─────────────────────────────────────────────────────
    void exportMd() {
        const QString path = QFileDialog::getSaveFileName(this,
            tr("Export scan as Markdown"),
            QDir::homePath() + "/Desktop/dynam-scan-"
                + currentHost_ + "-"
                + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") + ".md",
            tr("Markdown (*.md);;All files (*)"));
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::warning(this, tr("Export failed"), f.errorString());
            return;
        }
        f.write(report_.toMarkdown().toUtf8());
        statusBar_->setText(tr("Exported %1").arg(path));
    }

    void exportJson() {
        const QString path = QFileDialog::getSaveFileName(this,
            tr("Export scan as JSON"),
            QDir::homePath() + "/Desktop/dynam-scan-"
                + currentHost_ + "-"
                + QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss") + ".json",
            tr("JSON (*.json);;All files (*)"));
        if (path.isEmpty()) return;
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            QMessageBox::warning(this, tr("Export failed"), f.errorString());
            return;
        }
        QJsonDocument doc(report_.toJson());
        f.write(doc.toJson(QJsonDocument::Indented));
        statusBar_->setText(tr("Exported %1").arg(path));
    }

    void openBulkDialog() {
        auto* dlg = new BulkScanDialog(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }

    void openCrawlerDialog() {
        auto* dlg = new CrawlerDialog(this);
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }

    // ─── Probe 1: main GET ──────────────────────────────────────────
    void fetchMain(const QUrl& url) {
        probeStart();
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::UserAgentHeader,
                      "Mozilla/5.0 (compatible; Dynam-SiteScraper/1.2)");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* timer = new QElapsedTimer; timer->start();
        QNetworkReply* reply = net_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, timer, url]{
            const qint64 ms = timer->elapsed();
            delete timer;
            // Capture into ScanReport for export + tech-detection.
            report_.finalUrl    = reply->url();
            report_.httpStatus  = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            report_.timingMs    = ms;
            report_.server      = reply->header(QNetworkRequest::ServerHeader).toString();
            report_.contentType = reply->header(QNetworkRequest::ContentTypeHeader).toString();
            for (const auto& p : reply->rawHeaderPairs()) {
                report_.responseHeaders.insert(
                    QString::fromUtf8(p.first).toLower(),
                    QString::fromUtf8(p.second));
            }
            scoreSecurity(reply, report_);
            report_.cookies = reply->header(QNetworkRequest::SetCookieHeader)
                                .value<QList<QNetworkCookie>>();

            renderSummary(url, reply, ms);
            renderHeaders(reply);
            renderSecurityHeaders(reply);
            renderCookies(reply);
            const QByteArray body = reply->readAll();
            report_.bodyBytes = body.size();
            rawBody_ = body;          // saved so tech-detect can run in probeDone()
            renderMeta(body);
            renderResources(body, url);
            renderLinks(body, url);
            renderForms(body, url);
            reply->deleteLater();
            probeDone();
        });
    }

    // ─── Probe 2: DNS ────────────────────────────────────────────────
    void resolveDns(const QString& host) {
        probeStart();
        QHostInfo::lookupHost(host, this, [this, host](const QHostInfo& info){
            auto* box = addSection(tr("🌐 DNS — %1").arg(host));
            auto* out = monoTextIn(box);
            if (info.error() != QHostInfo::NoError) {
                out->setPlainText(tr("error: %1").arg(info.errorString()));
            } else if (info.addresses().isEmpty()) {
                out->setPlainText(tr("(no records)"));
            } else {
                QStringList lines;
                for (const QHostAddress& a : info.addresses()) {
                    const QString rec = QString("%1   %2")
                                            .arg(a.protocol() == QAbstractSocket::IPv6Protocol ? "AAAA" : "A",
                                                 -5)
                                            .arg(a.toString());
                    lines << rec;
                    report_.dnsRecords.append(rec.simplified());
                }
                out->setPlainText(lines.join('\n'));
            }
            probeDone();
        });
    }

    // ─── Probe 3: TLS handshake ─────────────────────────────────────
    void fetchTlsInfo(const QString& host, quint16 port) {
        probeStart();
        auto* sock = new QSslSocket(this);
        QTimer::singleShot(10000, sock, [sock]{ if (sock) sock->abort(); });
        connect(sock, &QSslSocket::encrypted, this, [this, sock, host]{
            auto* box = addSection(tr("🔒 TLS — %1").arg(host));
            auto* out = monoTextIn(box);
            const auto cfg = sock->sslConfiguration();
            const auto cipher = cfg.sessionCipher();
            const auto chain = sock->peerCertificateChain();
            // Capture into report
            report_.tlsProtocol = cipher.protocolString();
            report_.tlsCipher   = cipher.name();
            report_.tlsBits     = cipher.usedBits();
            if (!chain.isEmpty()) {
                const auto& leaf = chain.first();
                report_.certSubject   = leaf.subjectInfo(QSslCertificate::CommonName).join(',');
                report_.certIssuer    = leaf.issuerInfo(QSslCertificate::CommonName).join(',');
                report_.certValidFrom = leaf.effectiveDate();
                report_.certValidTo   = leaf.expiryDate();
                report_.certSans      = leaf.subjectAlternativeNames().values();
            }
            QString text;
            text += QString("Protocol:    %1\n").arg(cipher.protocolString());
            text += QString("Cipher:      %1 (%2-bit)\n")
                        .arg(cipher.name()).arg(cipher.usedBits());
            if (!chain.isEmpty()) {
                const auto& leaf = chain.first();
                text += "\n── Leaf certificate ─────────────────\n";
                text += "Subject CN:  " + leaf.subjectInfo(QSslCertificate::CommonName).join(',') + "\n";
                text += "Issuer:      " + leaf.issuerInfo(QSslCertificate::CommonName).join(',') + "\n";
                text += "Valid from:  " + leaf.effectiveDate().toString(Qt::ISODate) + "\n";
                text += "Valid to:    " + leaf.expiryDate().toString(Qt::ISODate);
                const qint64 days = QDateTime::currentDateTime().secsTo(leaf.expiryDate()) / 86400;
                text += QString(" (%1 days remaining)\n").arg(days);
                const auto sans = leaf.subjectAlternativeNames().values();
                if (!sans.isEmpty()) {
                    text += "SANs:        " + sans.join(", ");
                }
                if (chain.size() > 1) {
                    text += QString("\n\n+ %1 intermediate certificate(s) in chain")
                                .arg(chain.size() - 1);
                }
            } else {
                text += "(no peer certificate chain)";
            }
            out->setPlainText(text);
            sock->disconnectFromHost();
            sock->deleteLater();
            probeDone();
        });
        connect(sock, &QSslSocket::errorOccurred, this,
                [this, sock, host](QAbstractSocket::SocketError) {
            auto* box = addSection(tr("🔒 TLS — %1").arg(host));
            auto* out = monoTextIn(box);
            out->setPlainText(tr("TLS error: %1").arg(sock->errorString()));
            sock->deleteLater();
            probeDone();
        });
        sock->connectToHostEncrypted(host, port);
    }

    // ─── Generic auxiliary GET (robots.txt, sitemap.xml) ────────────
    using AuxRenderer = void (SiteScraperPanel::*)(const QString& path, QNetworkReply*);
    void fetchAuxiliary(const QUrl& base, const QString& path, AuxRenderer render) {
        probeStart();
        QUrl url(base);
        url.setPath(path);
        url.setQuery(QString{});
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::UserAgentHeader,
                      "Mozilla/5.0 (compatible; Dynam-SiteScraper/1.2)");
        QNetworkReply* reply = net_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, path, render]{
            (this->*render)(path, reply);
            reply->deleteLater();
            probeDone();
        });
    }

    void renderRobots(const QString& path, QNetworkReply* reply) {
        auto* box = addSection(tr("🤖 %1").arg(path));
        auto* out = monoTextIn(box);
        const int status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status == 200) {
            const QString body = QString::fromUtf8(reply->readAll());
            out->setPlainText(body);
            report_.robotsTxt = body;
        } else if (status == 0) {
            out->setPlainText(tr("error: %1").arg(reply->errorString()));
        } else {
            out->setPlainText(tr("HTTP %1 — no robots.txt at this host").arg(status));
        }
    }

    void renderSitemap(const QString& path, QNetworkReply* reply) {
        auto* box = addSection(tr("🗺  %1").arg(path));
        auto* out = monoTextIn(box);
        const int status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status == 200) {
            const QByteArray body = reply->readAll();
            // Count <loc> tags so the user gets a "size of map" hint
            // without having to read all of it.
            int locs = 0;
            QRegularExpression re("<loc>");
            auto it = re.globalMatch(QString::fromUtf8(body));
            while (it.hasNext()) { it.next(); ++locs; }
            report_.sitemapXml      = QString::fromUtf8(body.left(2048));
            report_.sitemapLocCount = locs;
            out->setPlainText(tr("(%1 <loc> entries, %2 bytes)\n\n").arg(locs).arg(body.size())
                              + QString::fromUtf8(body.left(2048)));
        } else {
            out->setPlainText(tr("HTTP %1 — no sitemap.xml at this host").arg(status));
        }
    }

    void fetchFavicon(const QUrl& base) {
        probeStart();
        QUrl url(base);
        url.setPath("/favicon.ico");
        url.setQuery(QString{});
        QNetworkRequest req(url);
        QNetworkReply* reply = net_->head(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply]{
            auto* box = addSection(tr("🖼  /favicon.ico"));
            auto* out = monoTextIn(box);
            const int status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const auto sizeHdr = reply->header(QNetworkRequest::ContentLengthHeader);
            if (status == 200) {
                report_.faviconFound = true;
                report_.faviconBytes = sizeHdr.toLongLong();
                out->setPlainText(tr("found · %1 bytes · %2")
                                      .arg(sizeHdr.toLongLong())
                                      .arg(reply->header(QNetworkRequest::ContentTypeHeader).toString()));
            } else {
                out->setPlainText(tr("HTTP %1 (no favicon)").arg(status));
            }
            reply->deleteLater();
            probeDone();
        });
    }

    // ─── Renderers for main-response sub-sections ───────────────────
    void renderSummary(const QUrl& url, QNetworkReply* reply, qint64 ms) {
        auto* box = addSection(tr("📋 Summary"));
        auto* form = new QFormLayout(box);
        auto add = [&](const QString& l, const QString& v){
            auto* val = new QLabel(v, box);
            val->setTextInteractionFlags(Qt::TextSelectableByMouse);
            val->setWordWrap(true);
            QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
            val->setFont(mono);
            form->addRow(l, val);
        };
        const int status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QString reason = reply->attribute(
            QNetworkRequest::HttpReasonPhraseAttribute).toString();
        add(tr("Request URL:"), url.toString());
        add(tr("Final URL:"),   reply->url().toString());
        add(tr("HTTP status:"), QString("%1 %2").arg(status).arg(reason));
        add(tr("Round trip:"),  QString("%1 ms").arg(ms));
        add(tr("Server:"),      reply->header(QNetworkRequest::ServerHeader).toString().toUtf8().isEmpty()
                                  ? QStringLiteral("(not advertised)")
                                  : reply->header(QNetworkRequest::ServerHeader).toString());
    }

    void renderHeaders(QNetworkReply* reply) {
        auto* box = addSection(tr("📨 HTTP response headers"));
        auto* out = monoTextIn(box);
        QString text;
        for (const auto& p : reply->rawHeaderPairs()) {
            text += QString::fromUtf8(p.first) + ": "
                  + QString::fromUtf8(p.second) + "\n";
        }
        out->setPlainText(text);
    }

    // Security score = sum of weighted "this important header is present"
    // checks. Tweak the weights to match your threat model.
    void renderSecurityHeaders(QNetworkReply* reply) {
        struct Check { const char* header; int weight; const char* hint; };
        // Weights are deliberately opinionated; revisit them in
        // `formatSecurityHeaders` below if you want a different stance.
        static const std::initializer_list<Check> kChecks = {
            {"strict-transport-security", 20, "force HTTPS for future visits"},
            {"content-security-policy",   25, "blocks unexpected scripts/iframes"},
            {"x-content-type-options",     8, "stops MIME sniffing"},
            {"x-frame-options",            8, "blocks clickjacking via iframes"},
            {"referrer-policy",            6, "limits Referer leakage"},
            {"permissions-policy",         8, "controls camera/mic/geoloc"},
            {"x-xss-protection",           2, "legacy, mostly historical"},
            {"cross-origin-opener-policy", 8, "isolates browsing context"},
            {"cross-origin-embedder-policy", 8, "enables high-resolution timers safely"},
            {"cross-origin-resource-policy", 7, "limits embedding by other origins"},
        };
        QString text;
        int score = 0, max = 0;
        for (const auto& c : kChecks) {
            max += c.weight;
            const bool present = reply->hasRawHeader(c.header);
            if (present) score += c.weight;
            text += QString("%1 %2  (%3, +%4)  %5\n")
                        .arg(present ? "✓" : "✗")
                        .arg(QString(c.header), -32)
                        .arg(c.hint)
                        .arg(c.weight)
                        .arg(present
                                ? QString::fromUtf8(reply->rawHeader(c.header)).left(80)
                                : QString());
        }
        const int pct = max > 0 ? (100 * score / max) : 0;
        const QString label = pct >= 80 ? "A" : pct >= 60 ? "B" : pct >= 40 ? "C" : pct >= 20 ? "D" : "F";
        auto* box = addSection(tr("🛡️  Security headers — score %1/%2 (%3%, grade %4)")
                                  .arg(score).arg(max).arg(pct).arg(label));
        monoTextIn(box)->setPlainText(text);
    }

    void renderCookies(QNetworkReply* reply) {
        const auto cookies = reply->header(QNetworkRequest::SetCookieHeader)
                                  .value<QList<QNetworkCookie>>();
        if (cookies.isEmpty()) return;  // skip the section entirely if none
        auto* box = addSection(tr("🍪 Cookies set (%1)").arg(cookies.size()));
        auto* out = monoTextIn(box);
        QString text;
        for (const auto& c : cookies) {
            text += QString("%1 = %2\n")
                        .arg(QString::fromUtf8(c.name()),
                             QString::fromUtf8(c.value()).left(80));
            text += QString("    domain=%1; path=%2; secure=%3; httpOnly=%4; expires=%5\n\n")
                        .arg(c.domain(), c.path(),
                             c.isSecure() ? "yes" : "no",
                             c.isHttpOnly() ? "yes" : "no",
                             c.expirationDate().isValid()
                                ? c.expirationDate().toString(Qt::ISODate)
                                : "(session)");
        }
        out->setPlainText(text);
    }

    void renderMeta(const QByteArray& body) {
        // Slice off the head so we don't regex-walk megabytes of body.
        const QString head = QString::fromUtf8(body.left(64 * 1024));
        QString text;

        QRegularExpression titleRe("<title[^>]*>([^<]*)</title>",
                                    QRegularExpression::CaseInsensitiveOption);
        const auto titleMatch = titleRe.match(head);
        if (titleMatch.hasMatch()) {
            const QString t = titleMatch.captured(1).trimmed();
            text += "<title>: " + t + "\n\n";
            report_.title = t;
        }

        // <meta name="…" content="…">  and  <meta property="og:…">
        QRegularExpression metaRe(
            "<meta\\s+(?:name|property|http-equiv)=[\"']([^\"']+)[\"']\\s+content=[\"']([^\"']*)[\"']",
            QRegularExpression::CaseInsensitiveOption);
        auto it = metaRe.globalMatch(head);
        while (it.hasNext()) {
            const auto m = it.next();
            text += QString("  %1 = %2\n")
                        .arg(m.captured(1).leftJustified(28))
                        .arg(m.captured(2).left(120));
            report_.meta.insert(m.captured(1), m.captured(2));
        }

        if (!text.isEmpty()) {
            auto* box = addSection(tr("📄 Meta / SEO"));
            monoTextIn(box)->setPlainText(text);
        }
    }

    void renderResources(const QByteArray& body, const QUrl& base) {
        const QString head = QString::fromUtf8(body);  // resources can be anywhere

        auto pull = [&](const QString& name, const QString& pattern) -> QStringList {
            QStringList out;
            QRegularExpression re(pattern, QRegularExpression::CaseInsensitiveOption);
            auto it = re.globalMatch(head);
            while (it.hasNext()) {
                out << base.resolved(QUrl(it.next().captured(1))).toString();
            }
            // dedupe but preserve order
            QSet<QString> seen; QStringList dedup;
            for (const auto& u : out) {
                if (!seen.contains(u)) { dedup << u; seen.insert(u); }
            }
            return dedup;
        };

        const auto scripts = pull("script", "<script[^>]*src=[\"']([^\"']+)[\"']");
        const auto styles  = pull("link",   "<link[^>]*rel=[\"']stylesheet[\"'][^>]*href=[\"']([^\"']+)[\"']");
        const auto images  = pull("img",    "<img[^>]*src=[\"']([^\"']+)[\"']");

        report_.scripts = scripts;
        report_.styles  = styles;
        report_.images  = images;

        if (scripts.isEmpty() && styles.isEmpty() && images.isEmpty()) return;

        auto* box = addSection(tr("📦 Resources — %1 scripts · %2 stylesheets · %3 images")
                                  .arg(scripts.size()).arg(styles.size()).arg(images.size()));
        auto* out = monoTextIn(box);
        QString text;
        if (!scripts.isEmpty()) { text += "── scripts ──\n"; for (const auto& u : scripts) text += "  " + u + "\n"; text += "\n"; }
        if (!styles.isEmpty())  { text += "── stylesheets ──\n"; for (const auto& u : styles)  text += "  " + u + "\n"; text += "\n"; }
        if (!images.isEmpty())  { text += "── images (first 30) ──\n"; for (int i = 0; i < std::min<int>(images.size(), 30); ++i) text += "  " + images[i] + "\n"; }
        out->setPlainText(text);
    }

    void renderLinks(const QByteArray& body, const QUrl& base) {
        QRegularExpression re("<a\\s[^>]*href=[\"']([^\"']+)[\"']",
                               QRegularExpression::CaseInsensitiveOption);
        QStringList internal, external, mailto, tel, fragment;
        QSet<QString> seen;
        auto it = re.globalMatch(QString::fromUtf8(body));
        while (it.hasNext()) {
            const QString raw = it.next().captured(1);
            if (raw.startsWith("#"))       { fragment << raw; continue; }
            if (raw.startsWith("mailto:")) { mailto   << raw; continue; }
            if (raw.startsWith("tel:"))    { tel      << raw; continue; }
            const QString abs = base.resolved(QUrl(raw)).toString();
            if (seen.contains(abs)) continue;
            seen.insert(abs);
            if (QUrl(abs).host() == base.host()) internal << abs;
            else                                   external << abs;
        }
        report_.linksInternal = internal;
        report_.linksExternal = external;
        report_.linksMailto   = mailto;
        report_.linksTel      = tel;

        if (internal.isEmpty() && external.isEmpty()
            && mailto.isEmpty() && tel.isEmpty()) return;

        auto* box = addSection(tr("🔗 Links — %1 internal · %2 external · %3 mailto · %4 tel")
                                  .arg(internal.size()).arg(external.size())
                                  .arg(mailto.size()).arg(tel.size()));
        auto* out = monoTextIn(box);
        QString text;
        auto dump = [&](const QString& head, const QStringList& xs) {
            if (xs.isEmpty()) return;
            text += "── " + head + " ──\n";
            for (int i = 0; i < std::min<int>(xs.size(), 50); ++i) text += "  " + xs[i] + "\n";
            if (xs.size() > 50) text += QString("  … and %1 more\n").arg(xs.size() - 50);
            text += "\n";
        };
        dump("internal", internal);
        dump("external", external);
        dump("mailto",   mailto);
        dump("tel",      tel);
        out->setPlainText(text);
    }

    void renderForms(const QByteArray& body, const QUrl& base) {
        QRegularExpression formRe(
            "<form[^>]*?(?:action=[\"']([^\"']*)[\"'])?[^>]*?(?:method=[\"']([^\"']*)[\"'])?[^>]*>",
            QRegularExpression::CaseInsensitiveOption);
        QString text;
        int count = 0;
        auto it = formRe.globalMatch(QString::fromUtf8(body));
        while (it.hasNext()) {
            const auto m = it.next();
            ++count;
            const QString action = m.captured(1).isEmpty()
                                       ? base.toString()
                                       : base.resolved(QUrl(m.captured(1))).toString();
            const QString method = m.captured(2).isEmpty() ? "GET" : m.captured(2).toUpper();
            text += QString("%1   %2\n").arg(method, -6).arg(action);
            report_.forms.append({method, action});
        }
        if (count == 0) return;
        auto* box = addSection(tr("📝 Forms (%1)").arg(count));
        monoTextIn(box)->setPlainText(text);
    }

    QLineEdit*             urlEdit_;
    QPushButton*           scanBtn_;
    QPushButton*           exportMdBtn_;
    QPushButton*           exportJsonBtn_;
    QPushButton*           bulkBtn_;
    QPushButton*           crawlBtn_;
    QVBoxLayout*           sectionsLayout_;
    QLabel*                statusBar_;
    QNetworkAccessManager* net_;
    QString                currentHost_;
    int                    pendingProbes_ = 0;
    ScanReport             report_;        // accumulated during scan
    QByteArray             rawBody_;       // kept for tech detection in probeDone()
};
