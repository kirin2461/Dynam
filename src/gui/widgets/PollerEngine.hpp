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
#include <QFile>
#include <QDir>
#include <QHostInfo>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTcpSocket>
#include <QElapsedTimer>
#include <QHostAddress>
#include <memory>

// ─── Data types ─────────────────────────────────────────────────────────────
// PollerTarget is a value type — no Qt parent-child ownership, JSON-roundtrippable.
// It carries both *configuration* (name, kind, target, interval, paused) and
// *running stats* (total_runs, successful_runs, last_status, last_latency_ms,
// last_run_at). Splitting those would be cleaner but adds two structs and a
// lookup; for our purposes one value type per row reads better.

enum class PollerKind {
    HttpsUrl,
    DnsLookup,
    TcpConnect,
};

inline QString pollerKindName(PollerKind k) {
    switch (k) {
        case PollerKind::HttpsUrl:    return "HTTPS";
        case PollerKind::DnsLookup:   return "DNS";
        case PollerKind::TcpConnect:  return "TCP";
    }
    return "?";
}

struct PollerTarget {
    QString    id;                  // UUID
    QString    name;
    PollerKind kind = PollerKind::HttpsUrl;
    QString    target;              // URL / hostname / host:port
    int        intervalSec = 60;
    bool       paused = false;

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
            case PollerKind::HttpsUrl:   probeHttps(id);  break;
            case PollerKind::DnsLookup:  probeDns(id);    break;
            case PollerKind::TcpConnect: probeTcp(id);    break;
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
