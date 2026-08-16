#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QGroupBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QUrl>
#include <QUrlQuery>
#include <QFont>

// DNS lookup tool — side-by-side comparison of system DNS vs DoH (Cloudflare
// and Google). The value isn't lookup-per-se (dig does that), it's catching
// DNS leaks: if system resolver returns X but DoH returns Y, you've found
// either a leak or a censorship intercept. We use Cloudflare/Google's JSON
// DoH endpoints (RFC 8484 wire format would also work but JSON is much
// easier to render).
class DnsLookupPanel : public QWidget {
    Q_OBJECT
public:
    explicit DnsLookupPanel(QWidget* parent = nullptr) : QWidget(parent) {
        net_ = new QNetworkAccessManager(this);

        auto* root = new QVBoxLayout(this);

        // ─── Input row ──────────────────────────────────────────────
        auto* inputBox = new QGroupBox(tr("Lookup"), this);
        auto* form = new QFormLayout(inputBox);
        hostnameEdit_ = new QLineEdit(inputBox);
        hostnameEdit_->setPlaceholderText("example.com");
        recordType_ = new QComboBox(inputBox);
        recordType_->addItems({"A", "AAAA"});
        auto* lookupBtn = new QPushButton(tr("Look up"), inputBox);
        auto* btnRow = new QHBoxLayout;
        btnRow->addWidget(lookupBtn);
        btnRow->addStretch(1);
        form->addRow(tr("Hostname:"),    hostnameEdit_);
        form->addRow(tr("Record type:"), recordType_);
        form->addRow("", btnRow);
        connect(lookupBtn,     &QPushButton::clicked,  this, &DnsLookupPanel::startLookup);
        connect(hostnameEdit_, &QLineEdit::returnPressed, this, &DnsLookupPanel::startLookup);

        // ─── Side-by-side resolver columns ──────────────────────────
        auto* resultsRow = new QHBoxLayout;
        resultsRow->addWidget(makeColumn("System", systemOutput_));
        resultsRow->addWidget(makeColumn("DoH · Cloudflare (1.1.1.1)", cloudflareOutput_));
        resultsRow->addWidget(makeColumn("DoH · Google (8.8.8.8)", googleOutput_));

        verdictLabel_ = new QLabel(tr("Run a lookup to compare resolvers."), this);
        verdictLabel_->setWordWrap(true);
        verdictLabel_->setStyleSheet("color:#888; padding:4px;");

        root->addWidget(inputBox);
        root->addLayout(resultsRow, 1);
        root->addWidget(verdictLabel_);
    }

private slots:
    void startLookup() {
        const QString host = hostnameEdit_->text().trimmed();
        if (host.isEmpty()) return;
        clearAll();
        verdictLabel_->setText(tr("Querying all three resolvers…"));

        // Each query is independent; we record results into a small struct
        // and run the verdict once all three have reported.
        results_ = {};
        results_.host = host;

        // 1. System resolver via getaddrinfo (Qt wraps as QHostInfo::lookupHost)
        QHostInfo::lookupHost(host, this, &DnsLookupPanel::onSystemResolved);

        // 2 + 3. DoH JSON endpoints
        fetchDoH("https://cloudflare-dns.com/dns-query", host, &results_.cloudflareReady,
                 cloudflareOutput_);
        fetchDoH("https://dns.google/resolve",           host, &results_.googleReady,
                 googleOutput_);
    }

    void onSystemResolved(const QHostInfo& info) {
        const QString want = recordType_->currentText();
        QStringList ips;
        for (const QHostAddress& a : info.addresses()) {
            const bool isV6 = a.protocol() == QAbstractSocket::IPv6Protocol;
            if ((want == "A" && !isV6) || (want == "AAAA" && isV6)) {
                ips << a.toString();
            }
        }
        if (info.error() != QHostInfo::NoError) {
            systemOutput_->setPlainText("error: " + info.errorString());
        } else if (ips.isEmpty()) {
            systemOutput_->setPlainText("(no records)");
        } else {
            systemOutput_->setPlainText(ips.join('\n'));
        }
        results_.systemReady = true;
        results_.systemIps   = ips;
        maybeVerdict();
    }

private:
    struct Results {
        QString     host;
        bool        systemReady     = false;
        bool        cloudflareReady = false;
        bool        googleReady     = false;
        QStringList systemIps;
        QStringList cloudflareIps;
        QStringList googleIps;
    } results_;

    QGroupBox* makeColumn(const QString& title, QPlainTextEdit*& out) {
        auto* box = new QGroupBox(title, this);
        auto* l = new QVBoxLayout(box);
        out = new QPlainTextEdit(box);
        out->setReadOnly(true);
        QFont mono; mono.setStyleHint(QFont::Monospace); mono.setFamily("Menlo");
        out->setFont(mono);
        l->addWidget(out);
        return box;
    }

    void clearAll() {
        systemOutput_->clear();
        cloudflareOutput_->clear();
        googleOutput_->clear();
    }

    void fetchDoH(const QString& baseUrl, const QString& host,
                   bool* readyFlag, QPlainTextEdit* out) {
        QUrl u(baseUrl);
        QUrlQuery q;
        q.addQueryItem("name", host);
        q.addQueryItem("type", recordType_->currentText());
        u.setQuery(q);

        QNetworkRequest req(u);
        // application/dns-json — both Cloudflare and Google return the same
        // JSON shape with an "Answer" array.
        req.setRawHeader("accept", "application/dns-json");
        req.setHeader(QNetworkRequest::UserAgentHeader, "Dynam/1.2 (DnsLookupPanel)");

        auto* timer = new QElapsedTimer;
        timer->start();
        auto* reply = net_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, out, readyFlag, timer]{
            const qint64 ms = timer->elapsed();
            delete timer;
            QStringList ips;
            if (reply->error() != QNetworkReply::NoError) {
                out->setPlainText(QString("error: %1").arg(reply->errorString()));
            } else {
                const auto doc = QJsonDocument::fromJson(reply->readAll());
                for (const QJsonValue& v : doc.object().value("Answer").toArray()) {
                    const QString data = v.toObject().value("data").toString();
                    if (!data.isEmpty()) ips << data;
                }
                if (ips.isEmpty()) {
                    out->setPlainText(QString("(no records, %1 ms)").arg(ms));
                } else {
                    out->setPlainText(ips.join('\n') + QString("\n\n— %1 ms").arg(ms));
                }
            }
            *readyFlag = true;
            // store into Results via pointer arithmetic… or just check which:
            if (out == cloudflareOutput_) results_.cloudflareIps = ips;
            if (out == googleOutput_)     results_.googleIps     = ips;
            reply->deleteLater();
            maybeVerdict();
        });
    }

    void maybeVerdict() {
        if (!(results_.systemReady && results_.cloudflareReady && results_.googleReady))
            return;
        // Compare. If all three agree, we're clean. If system disagrees
        // with both DoH resolvers but they agree with each other, that's
        // a strong DNS leak/intercept signal.
        const auto norm = [](QStringList l){ l.sort(); l.removeDuplicates(); return l; };
        const QStringList sys = norm(results_.systemIps);
        const QStringList cf  = norm(results_.cloudflareIps);
        const QStringList go  = norm(results_.googleIps);

        if (sys.isEmpty() && cf.isEmpty() && go.isEmpty()) {
            verdictLabel_->setText(tr("⚠ No records returned by any resolver — hostname may not exist."));
            verdictLabel_->setStyleSheet("color:#f39c12;");
        } else if (sys == cf && cf == go) {
            verdictLabel_->setText(tr("✓ All three resolvers agree — no leak detected."));
            verdictLabel_->setStyleSheet("color:#2ecc71;");
        } else if (cf == go && sys != cf) {
            verdictLabel_->setText(tr(
                "⚠ Both DoH resolvers agree, but your system resolver disagrees. "
                "Possible DNS interception or upstream censorship."));
            verdictLabel_->setStyleSheet("color:#e74c3c;");
        } else {
            verdictLabel_->setText(tr(
                "↻ Resolvers returned different answers — could be CDN geo-routing or staged rollout."));
            verdictLabel_->setStyleSheet("color:#3498db;");
        }
    }

    QLineEdit*             hostnameEdit_;
    QComboBox*             recordType_;
    QPlainTextEdit*        systemOutput_;
    QPlainTextEdit*        cloudflareOutput_;
    QPlainTextEdit*        googleOutput_;
    QLabel*                verdictLabel_;
    QNetworkAccessManager* net_;
};
