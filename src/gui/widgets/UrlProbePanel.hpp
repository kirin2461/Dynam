#pragma once
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QGroupBox>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QElapsedTimer>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QSslCipher>
#include <QFont>

// URL probe — fetches an arbitrary URL and shows status, headers, body size,
// TLS info, and timing. Two purposes:
//   1. Confirm "the bypass works" — try a censored URL, see if it loads
//   2. Inspect the TLS handshake characteristics (cipher, protocol)
class UrlProbePanel : public QWidget {
    Q_OBJECT
public:
    explicit UrlProbePanel(QWidget* parent = nullptr) : QWidget(parent) {
        net_ = new QNetworkAccessManager(this);

        auto* root = new QVBoxLayout(this);

        auto* inputBox = new QGroupBox(tr("Probe"), this);
        auto* form = new QFormLayout(inputBox);
        urlEdit_ = new QLineEdit(inputBox);
        urlEdit_->setPlaceholderText("https://example.com");
        method_ = new QComboBox(inputBox);
        method_->addItems({"GET", "HEAD"});
        auto* go = new QPushButton(tr("Fetch"), inputBox);
        auto* row = new QHBoxLayout;
        row->addWidget(go);
        row->addStretch(1);
        form->addRow(tr("URL:"),    urlEdit_);
        form->addRow(tr("Method:"), method_);
        form->addRow("", row);
        connect(go,       &QPushButton::clicked,     this, &UrlProbePanel::fetch);
        connect(urlEdit_, &QLineEdit::returnPressed, this, &UrlProbePanel::fetch);

        // ─── Two-column result: summary + raw headers ───────────────
        auto* resultRow = new QHBoxLayout;

        auto* summaryBox = new QGroupBox(tr("Summary"), this);
        auto* summaryForm = new QFormLayout(summaryBox);
        statusLabel_   = mono(new QLabel("—", summaryBox));
        finalUrlLabel_ = mono(new QLabel("—", summaryBox));
        finalUrlLabel_->setWordWrap(true);
        sizeLabel_     = mono(new QLabel("—", summaryBox));
        timingLabel_   = mono(new QLabel("—", summaryBox));
        tlsLabel_      = mono(new QLabel("—", summaryBox));
        tlsLabel_->setWordWrap(true);
        summaryForm->addRow(tr("Status:"),    statusLabel_);
        summaryForm->addRow(tr("Final URL:"), finalUrlLabel_);
        summaryForm->addRow(tr("Body size:"), sizeLabel_);
        summaryForm->addRow(tr("Time:"),      timingLabel_);
        summaryForm->addRow(tr("TLS:"),       tlsLabel_);

        auto* headersBox = new QGroupBox(tr("Response headers"), this);
        auto* headersLayout = new QVBoxLayout(headersBox);
        headersOutput_ = new QPlainTextEdit(headersBox);
        headersOutput_->setReadOnly(true);
        QFont mono2; mono2.setStyleHint(QFont::Monospace); mono2.setFamily("Menlo");
        headersOutput_->setFont(mono2);
        headersLayout->addWidget(headersOutput_);

        resultRow->addWidget(summaryBox);
        resultRow->addWidget(headersBox, 1);

        root->addWidget(inputBox);
        root->addLayout(resultRow, 1);
    }

private slots:
    void fetch() {
        const QString u = urlEdit_->text().trimmed();
        if (u.isEmpty()) return;
        QUrl url(u);
        if (!url.isValid()) {
            statusLabel_->setText(QString("invalid URL: %1").arg(url.errorString()));
            return;
        }
        if (url.scheme().isEmpty()) url.setScheme("https");

        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::UserAgentHeader, "Dynam/1.2 (UrlProbePanel)");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);

        statusLabel_->setText("…");
        finalUrlLabel_->setText("…");
        sizeLabel_->setText("…");
        timingLabel_->setText("…");
        tlsLabel_->setText("…");
        headersOutput_->clear();

        auto* timer = new QElapsedTimer;
        timer->start();
        QNetworkReply* reply = (method_->currentText() == "HEAD")
                                   ? net_->head(req)
                                   : net_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, timer]{
            const qint64 ms = timer->elapsed();
            delete timer;
            onFinished(reply, ms);
            reply->deleteLater();
        });
    }

private:
    QLabel* mono(QLabel* l) {
        QFont f; f.setStyleHint(QFont::Monospace); f.setFamily("Menlo");
        l->setFont(f);
        return l;
    }

    void onFinished(QNetworkReply* reply, qint64 ms) {
        if (reply->error() != QNetworkReply::NoError) {
            statusLabel_->setText(QString("error: %1").arg(reply->errorString()));
            return;
        }
        const int status = reply->attribute(
            QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const QString reason = reply->attribute(
            QNetworkRequest::HttpReasonPhraseAttribute).toString();
        statusLabel_->setText(QString("%1 %2").arg(status).arg(reason));
        finalUrlLabel_->setText(reply->url().toString());
        const QByteArray body = reply->readAll();
        sizeLabel_->setText(QString("%1 bytes").arg(body.size()));
        timingLabel_->setText(QString("%1 ms").arg(ms));

        // TLS handshake details (only present if the request actually used TLS)
        const QSslConfiguration ssl = reply->sslConfiguration();
        const QSslCipher c = ssl.sessionCipher();
        if (c.isNull()) {
            tlsLabel_->setText("(no TLS — plain HTTP?)");
        } else {
            tlsLabel_->setText(QString("%1 · %2 · %3-bit")
                                   .arg(c.protocolString())
                                   .arg(c.name())
                                   .arg(c.usedBits()));
        }

        QString hdrs;
        for (const auto& p : reply->rawHeaderPairs()) {
            hdrs += QString::fromUtf8(p.first) + ": "
                  + QString::fromUtf8(p.second) + "\n";
        }
        headersOutput_->setPlainText(hdrs);
    }

    QLineEdit*             urlEdit_;
    QComboBox*             method_;
    QLabel*                statusLabel_;
    QLabel*                finalUrlLabel_;
    QLabel*                sizeLabel_;
    QLabel*                timingLabel_;
    QLabel*                tlsLabel_;
    QPlainTextEdit*        headersOutput_;
    QNetworkAccessManager* net_;
};
