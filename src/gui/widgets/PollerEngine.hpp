#pragma once
#include <QObject>
#include <QTimer>
#include <QString>
#include <QDateTime>
#include <QHash>
#include <QUuid>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonValue>
#include <QFile>
#include <QDir>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTcpSocket>
#include <QSslSocket>
#include <QSslCertificate>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QRegularExpression>
#include <memory>

// ─── Data types ─────────────────────────────────────────────────────────────
// PollerTarget is a value type — no Qt parent-child ownership, JSON-roundtrippable.
// It carries both *configuration* (name, kind, target, interval, paused) and
// *running stats* (total_runs, successful_runs, last_status, last_latency_ms,
// last_run_at). Splitting those would be cleaner but adds two structs and a
// lookup; for our purposes one value type per row reads better.

enum class PollerKind {
    HttpsUrl,        // HEAD; 2xx/3xx = ok
    DnsLookup,       // resolve; any record = ok
    TcpConnect,      // connect host:port; reachable = ok
    ApiJson,         // GET; parse JSON; criteria like "data.status==ok"
    TlsCertExpiry,   // open TLS to host:port; criteria = minimum days remaining
    HttpBodyMatch,   // GET; criteria = substring (or /regex/) the body must contain
};

inline QString pollerKindName(PollerKind k) {
    switch (k) {
        case PollerKind::HttpsUrl:       return "HTTPS";
        case PollerKind::DnsLookup:      return "DNS";
        case PollerKind::TcpConnect:     return "TCP";
        case PollerKind::ApiJson:        return "API";
        case PollerKind::TlsCertExpiry:  return "TLS-Cert";
        case PollerKind::HttpBodyMatch:  return "Body";
    }
    return "?";
}

// Hint string shown next to the Criteria field for each kind.
inline QString criteriaHint(PollerKind k) {
    switch (k) {
        case PollerKind::HttpsUrl:       return "(none — HTTP status is the criterion)";
        case PollerKind::DnsLookup:      return "(none — any record = ok)";
        case PollerKind::TcpConnect:     return "(none — connect = ok)";
        case PollerKind::ApiJson:        return "JSON key == value, e.g. data.status==ok";
        case PollerKind::TlsCertExpiry:  return "minimum days remaining, e.g. 30";
        case PollerKind::HttpBodyMatch:  return "substring, or /regex/ to use a regex";
    }
    return "";
}

struct PollerTarget {
    QString    id;                  // UUID
    QString    name;
    PollerKind kind = PollerKind::HttpsUrl;
    QString    target;              // URL / hostname / host:port
    int        intervalSec = 60;
    bool       paused = false;
    QString    criteria;            // kind-specific validation string; see criteriaHint()

    // Stats (mutated by the engine)
    quint64    totalRuns      = 0;
    quint64    successfulRuns = 0;
    QString    lastStatus;          // human-readable e.g. "200 OK" / "DNS ok (2 records)" / "timeout"
    bool       lastOk         = false;
    qint64     lastLatencyMs  = -1;
    QDateTime  lastRunAt;

    QJsonObject toJson() const {
        return QJsonObject{
            {"id",          id},
            {"name",        name},
            {"kind",        static_cast<int>(kind)},
            {"target",      target},
            {"intervalSec", intervalSec},
            {"paused",      paused},
            {"criteria",    criteria},
        };
    }
    static PollerTarget fromJson(const QJsonObject& o) {
        PollerTarget t;
        t.id          = o.value("id").toString(QUuid::createUuid().toString(QUuid::WithoutBraces));
        t.name        = o.value("name").toString();
        t.kind        = static_cast<PollerKind>(o.value("kind").toInt(0));
        t.target      = o.value("target").toString();
        t.intervalSec = o.value("intervalSec").toInt(60);
        t.paused      = o.value("paused").toBool(false);
        t.criteria    = o.value("criteria").toString();
        return t;
    }

    double successRate() const {
        if (totalRuns == 0) return -1.0;
        return 100.0 * static_cast<double>(successfulRuns) / static_cast<double>(totalRuns);
    }
};

// ─── Engine ──────────────────────────────────────────────────────────────────
// Owns one QTimer per target. Each tick dispatches a kind-appropriate probe
// (QNetworkAccessManager::head for HTTPS, QHostInfo for DNS, QTcpSocket for
// TCP). On completion, updates the target's stats and emits targetUpdated.

class PollerEngine : public QObject {
    Q_OBJECT
public:
    explicit PollerEngine(QObject* parent = nullptr)
        : QObject(parent), net_(new QNetworkAccessManager(this)) {
        const QString dir = QDir::homePath() + "/.dynam";
        QDir().mkpath(dir);
        storePath_ = dir + "/poller.json";
        load();
    }

    // Snapshot of all targets (in insertion order)
    QList<PollerTarget> targets() const {
        QList<PollerTarget> out;
        for (const auto& id : order_) out.append(targets_.value(id));
        return out;
    }

    PollerTarget target(const QString& id) const { return targets_.value(id); }

    QString addTarget(PollerTarget t) {
        if (t.id.isEmpty()) t.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
        targets_.insert(t.id, t);
        order_.append(t.id);
        startTimerFor(t.id);
        save();
        emit targetAdded(t.id);
        return t.id;
    }

    void updateTarget(const QString& id, const PollerTarget& t) {
        if (!targets_.contains(id)) return;
        const bool intervalChanged = targets_[id].intervalSec != t.intervalSec;
        const bool pausedChanged   = targets_[id].paused      != t.paused;
        // Preserve stats from old; copy config from new
        auto merged = targets_[id];
        merged.name        = t.name;
        merged.kind        = t.kind;
        merged.target      = t.target;
        merged.intervalSec = t.intervalSec;
        merged.paused      = t.paused;
        merged.criteria    = t.criteria;
        targets_[id]       = merged;
        if (intervalChanged || pausedChanged) {
            stopTimerFor(id);
            if (!merged.paused) startTimerFor(id);
        }
        save();
        emit targetUpdated(id);
    }

    void removeTarget(const QString& id) {
        stopTimerFor(id);
        targets_.remove(id);
        order_.removeAll(id);
        save();
        emit targetRemoved(id);
    }

    void runNow(const QString& id) { probe(id); }

signals:
    void targetAdded(const QString& id);
    void targetUpdated(const QString& id);
    void targetRemoved(const QString& id);

private:
    void startTimerFor(const QString& id) {
        if (timers_.contains(id)) return;
        auto* t = new QTimer(this);
        const int ivMs = std::max(1, targets_[id].intervalSec) * 1000;
        t->setInterval(ivMs);
        connect(t, &QTimer::timeout, this, [this, id]{ probe(id); });
        timers_.insert(id, t);
        t->start();
        // Also probe once immediately so the user sees something within
        // a second of adding a target.
        QTimer::singleShot(50, this, [this, id]{ probe(id); });
    }

    void stopTimerFor(const QString& id) {
        if (auto* t = timers_.take(id)) {
            t->stop();
            t->deleteLater();
        }
    }

    void probe(const QString& id) {
        if (!targets_.contains(id)) return;
        PollerTarget t = targets_[id];
        if (t.paused) return;
        switch (t.kind) {
            case PollerKind::HttpsUrl:       probeHttps(id);    break;
            case PollerKind::DnsLookup:      probeDns(id);      break;
            case PollerKind::TcpConnect:     probeTcp(id);      break;
            case PollerKind::ApiJson:        probeApiJson(id);  break;
            case PollerKind::TlsCertExpiry:  probeTlsCert(id);  break;
            case PollerKind::HttpBodyMatch:  probeHttpBody(id); break;
        }
    }

    void probeHttps(const QString& id) {
        const PollerTarget t = targets_[id];
        QUrl url(t.target);
        if (url.scheme().isEmpty()) url.setScheme("https");
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::UserAgentHeader, "Dynam-Poller/1.2");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* timer = new QElapsedTimer; timer->start();
        QNetworkReply* reply = net_->head(req);
        connect(reply, &QNetworkReply::finished, this, [this, id, reply, timer]{
            const qint64 ms = timer->elapsed();
            delete timer;
            const int status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QString reason = reply->attribute(
                QNetworkRequest::HttpReasonPhraseAttribute).toString();
            const bool ok = (reply->error() == QNetworkReply::NoError &&
                              status >= 200 && status < 400);
            const QString detail = (reply->error() == QNetworkReply::NoError)
                ? QString("%1 %2").arg(status).arg(reason)
                : QString("error: %1").arg(reply->errorString());
            recordResult(id, ok, ms, detail);
            reply->deleteLater();
        });
    }

    void probeDns(const QString& id) {
        const PollerTarget t = targets_[id];
        auto* timer = new QElapsedTimer; timer->start();
        // QHostInfo::lookupHost takes a callback bound to a QObject; capture
        // id and timer for the response.
        QHostInfo::lookupHost(t.target, this, [this, id, timer](const QHostInfo& info){
            const qint64 ms = timer->elapsed();
            delete timer;
            const bool ok = (info.error() == QHostInfo::NoError &&
                              !info.addresses().isEmpty());
            const QString detail = ok
                ? QString("ok (%1 records)").arg(info.addresses().size())
                : QString("error: %1").arg(info.errorString());
            recordResult(id, ok, ms, detail);
        });
    }

    void probeTcp(const QString& id) {
        const PollerTarget t = targets_[id];
        const QStringList parts = t.target.split(':');
        if (parts.size() != 2) {
            recordResult(id, false, 0, "expected host:port");
            return;
        }
        const QString host = parts[0];
        const quint16 port = parts[1].toUShort();
        auto* sock = new QTcpSocket(this);
        auto* timer = new QElapsedTimer; timer->start();
        // 5-second connect timeout — anything longer is a "down" call.
        QTimer::singleShot(5000, sock, [sock]{ if (sock) sock->abort(); });
        connect(sock, &QTcpSocket::connected, this, [this, id, sock, timer]{
            const qint64 ms = timer->elapsed();
            delete timer;
            recordResult(id, true, ms, "connected");
            sock->disconnectFromHost();
            sock->deleteLater();
        });
        connect(sock, &QTcpSocket::errorOccurred, this,
                [this, id, sock, timer](QAbstractSocket::SocketError) {
            const qint64 ms = timer->elapsed();
            delete timer;
            recordResult(id, false, ms, QString("error: %1").arg(sock->errorString()));
            sock->deleteLater();
        });
        sock->connectToHost(host, port);
    }

    // GET URL, parse JSON, evaluate criteria like "data.status==ok".
    // Empty criteria → only HTTP status matters. Dotted path → walk nested
    // QJsonObject; bare key → top-level field.
    void probeApiJson(const QString& id) {
        const PollerTarget t = targets_[id];
        QUrl url(t.target);
        if (url.scheme().isEmpty()) url.setScheme("https");
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::UserAgentHeader, "Dynam-Poller/1.2");
        req.setRawHeader("accept", "application/json");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* timer = new QElapsedTimer; timer->start();
        auto* reply = net_->get(req);
        const QString criteria = t.criteria;
        connect(reply, &QNetworkReply::finished, this,
                [this, id, reply, timer, criteria]{
            const qint64 ms = timer->elapsed();
            delete timer;
            const int status = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            if (reply->error() != QNetworkReply::NoError) {
                recordResult(id, false, ms,
                             QString("error: %1").arg(reply->errorString()));
                reply->deleteLater();
                return;
            }
            if (status < 200 || status >= 400) {
                recordResult(id, false, ms,
                             QString("HTTP %1 (not 2xx/3xx)").arg(status));
                reply->deleteLater();
                return;
            }
            const QByteArray body = reply->readAll();

            // If the user didn't supply a criterion, they're just using the
            // API kind for labelling — don't force the body to be JSON. The
            // HTTP status above already passed, so we're done.
            if (criteria.isEmpty()) {
                recordResult(id, true, ms,
                             QString("HTTP %1 · %2 B body (no criterion)")
                                 .arg(status).arg(body.size()));
                reply->deleteLater();
                return;
            }

            QJsonParseError perr;
            const auto doc = QJsonDocument::fromJson(body, &perr);
            if (perr.error != QJsonParseError::NoError) {
                recordResult(id, false, ms,
                             formatJsonParseError(body, perr));
                reply->deleteLater();
                return;
            }
            QString detail = QString("HTTP %1 · JSON ok").arg(status);
            bool ok = evaluateJsonCriterion(doc, criteria, detail);
            recordResult(id, ok, ms, detail);
            reply->deleteLater();
        });
    }

    // Build a diagnostic like "invalid JSON @ byte 142: illegal number
    // near `…99.5, "size":0123, "up…`". The window shrinks at start/end
    // of body so we never read out of bounds.
    static QString formatJsonParseError(const QByteArray& body,
                                          const QJsonParseError& perr) {
        const int n      = body.size();
        const int center = std::clamp(perr.offset, 0, n);
        const int from   = std::max(0, center - 20);
        const int to     = std::min(n, center + 20);
        const QByteArray snippet = body.mid(from, to - from);
        // Make the snippet single-line and safely printable.
        QString clean = QString::fromUtf8(snippet)
                            .replace('\n', QChar(0x21B5))   // ↵
                            .replace('\r', "")
                            .replace('\t', " ");
        // Insert a marker at the error position within the snippet.
        const int markerAt = center - from;
        if (markerAt >= 0 && markerAt <= clean.size()) {
            clean.insert(markerAt, "›");  // hint at the bad byte
        }
        return QString("invalid JSON @ byte %1: %2 near `%3`")
                   .arg(perr.offset)
                   .arg(perr.errorString())
                   .arg(clean);
    }

    // Open a TLS connection, grab the peer cert, check days remaining.
    // criteria = minimum required days (default 30). No HTTP request is sent.
    void probeTlsCert(const QString& id) {
        const PollerTarget t = targets_[id];
        QString host = t.target;
        quint16 port = 443;
        if (t.target.contains(':')) {
            const auto parts = t.target.split(':');
            host = parts[0];
            port = parts[1].toUShort();
        }
        const int minDays = t.criteria.isEmpty() ? 30 : t.criteria.toInt();
        auto* sock = new QSslSocket(this);
        auto* timer = new QElapsedTimer; timer->start();
        QTimer::singleShot(10000, sock, [sock]{ if (sock) sock->abort(); });

        connect(sock, &QSslSocket::encrypted, this,
                [this, id, sock, timer, minDays]{
            const qint64 ms = timer->elapsed();
            delete timer;
            const auto chain = sock->peerCertificateChain();
            if (chain.isEmpty()) {
                recordResult(id, false, ms, "no peer certificate");
            } else {
                const QSslCertificate cert = chain.first();
                const QDateTime expiry = cert.expiryDate();
                const qint64 days =
                    QDateTime::currentDateTime().secsTo(expiry) / 86400;
                const bool ok = days >= minDays;
                recordResult(id, ok, ms,
                             QString("%1 days remaining (min %2) · CN=%3")
                                 .arg(days).arg(minDays)
                                 .arg(cert.subjectInfo(QSslCertificate::CommonName).join(',')));
            }
            sock->disconnectFromHost();
            sock->deleteLater();
        });
        connect(sock, &QSslSocket::errorOccurred, this,
                [this, id, sock, timer](QAbstractSocket::SocketError) {
            const qint64 ms = timer->elapsed();
            delete timer;
            recordResult(id, false, ms,
                         QString("error: %1").arg(sock->errorString()));
            sock->deleteLater();
        });
        sock->connectToHostEncrypted(host, port);
    }

    // GET URL, check that response body contains criteria. Criteria wrapped
    // in /…/ is treated as a regex; otherwise plain substring.
    void probeHttpBody(const QString& id) {
        const PollerTarget t = targets_[id];
        QUrl url(t.target);
        if (url.scheme().isEmpty()) url.setScheme("https");
        QNetworkRequest req(url);
        req.setHeader(QNetworkRequest::UserAgentHeader, "Dynam-Poller/1.2");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
        auto* timer = new QElapsedTimer; timer->start();
        auto* reply = net_->get(req);
        const QString criteria = t.criteria;
        connect(reply, &QNetworkReply::finished, this,
                [this, id, reply, timer, criteria]{
            const qint64 ms = timer->elapsed();
            delete timer;
            if (reply->error() != QNetworkReply::NoError) {
                recordResult(id, false, ms,
                             QString("error: %1").arg(reply->errorString()));
                reply->deleteLater();
                return;
            }
            const QString body = QString::fromUtf8(reply->readAll());
            if (criteria.isEmpty()) {
                recordResult(id, true, ms,
                             QString("body OK (%1 bytes, no criterion)").arg(body.size()));
            } else if (criteria.size() >= 2 && criteria.startsWith('/') && criteria.endsWith('/')) {
                QRegularExpression re(criteria.mid(1, criteria.size() - 2));
                const bool ok = re.match(body).hasMatch();
                recordResult(id, ok, ms,
                             ok ? QString("regex matched") : QString("regex did not match"));
            } else {
                const bool ok = body.contains(criteria);
                recordResult(id, ok, ms,
                             ok ? QString("substring matched") : QString("substring not found"));
            }
            reply->deleteLater();
        });
    }

    // Walk a dotted JSON path against the parsed document, then compare to
    // the right-hand value. Comparison is string-equality after JSON value
    // serialization — good enough for "status==ok" / "healthy==true" / "errors==0".
    static bool evaluateJsonCriterion(const QJsonDocument& doc,
                                       const QString& criterion,
                                       QString& detailOut) {
        const int eq = criterion.indexOf("==");
        if (eq < 0) {
            detailOut = QString("invalid criterion (need key==value): %1").arg(criterion);
            return false;
        }
        const QString key   = criterion.left(eq).trimmed();
        const QString want  = criterion.mid(eq + 2).trimmed();
        QJsonValue cur = doc.isObject() ? QJsonValue(doc.object())
                                         : QJsonValue(doc.array());
        for (const QString& part : key.split('.')) {
            if (cur.isObject()) cur = cur.toObject().value(part);
            else { detailOut = QString("path '%1' not navigable").arg(key); return false; }
        }
        QString actual;
        if      (cur.isString()) actual = cur.toString();
        else if (cur.isBool())   actual = cur.toBool() ? "true" : "false";
        else if (cur.isDouble()) actual = QString::number(cur.toDouble(), 'g', 15);
        else if (cur.isNull())   actual = "null";
        else                      actual = QJsonDocument(cur.toObject()).toJson(QJsonDocument::Compact);
        const bool ok = (actual == want);
        detailOut = QString("%1 = '%2' (want '%3')").arg(key, actual, want);
        return ok;
    }

    void recordResult(const QString& id, bool ok, qint64 ms, const QString& detail) {
        if (!targets_.contains(id)) return;
        PollerTarget& t = targets_[id];
        ++t.totalRuns;
        if (ok) ++t.successfulRuns;
        t.lastOk        = ok;
        t.lastLatencyMs = ms;
        t.lastStatus    = detail;
        t.lastRunAt     = QDateTime::currentDateTime();
        emit targetUpdated(id);
    }

    void save() {
        QJsonArray arr;
        for (const QString& id : order_) arr.append(targets_[id].toJson());
        QJsonDocument doc(arr);
        QFile f(storePath_);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write(doc.toJson(QJsonDocument::Indented));
        }
    }

    void load() {
        QFile f(storePath_);
        if (!f.open(QIODevice::ReadOnly)) return;
        const QJsonArray arr = QJsonDocument::fromJson(f.readAll()).array();
        for (const QJsonValue& v : arr) {
            PollerTarget t = PollerTarget::fromJson(v.toObject());
            if (t.id.isEmpty()) continue;
            targets_.insert(t.id, t);
            order_.append(t.id);
            if (!t.paused) startTimerFor(t.id);
        }
    }

    QHash<QString, PollerTarget> targets_;
    QStringList                   order_;          // insertion order
    QHash<QString, QTimer*>       timers_;
    QNetworkAccessManager*        net_;
    QString                       storePath_;
};
