#include "RestClient.hpp"

#include <QJsonArray>
#include <QTimer>
#include <QRegularExpression>

namespace core {

RestClient::RestClient(QObject* parent)
    : QObject(parent)
{
    m_baseUrl.setScheme("http");
    m_baseUrl.setHost("127.0.0.1");
    m_baseUrl.setPort(8085);
    fetchToken();
}

void RestClient::setBaseUrl(const QString& url)
{
    m_baseUrl = QUrl(url);
    if (!m_baseUrl.isValid()) {
        m_baseUrl.setScheme("http");
        m_baseUrl.setHost("127.0.0.1");
        m_baseUrl.setPort(8085);
    }
    m_token.clear();
    fetchToken();
}

void RestClient::fetchToken()
{
    // The backend injects a per-start API token into the index page as
    // <meta name="ncp-token" content="…">. Scrape it once per base URL;
    // every /api request then carries X-NCP-Token.
    QUrl url = m_baseUrl;
    QString path = url.path();
    if (path.endsWith('/')) path.chop(1);
    url.setPath(path + "/");
    QNetworkRequest request(url);
    if (!m_token.isEmpty()) {
        request.setRawHeader("X-NCP-Token", m_token.toUtf8());
    }
    QNetworkReply* reply = m_manager.get(request);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) return;
        const QString html = QString::fromUtf8(reply->readAll());
        static const QRegularExpression re(
            QStringLiteral(R"_(name="ncp-token\s+content="([^"]+)")_"));
        const auto m = re.match(html);
        if (m.hasMatch()) m_token = m.captured(1);
    });
}

// ─── Private helpers ───────────────────────────────────────────────────────

static QUrl makeUrl(const QUrl& base, const QString& endpoint)
{
    QUrl url = base;
    QString path = url.path();
    if (path.endsWith('/')) path.chop(1);
    url.setPath(path + endpoint);
    return url;
}

void RestClient::get(const QString& endpoint, JsonCallback callback)
{
    QUrl url = makeUrl(m_baseUrl, endpoint);
    QNetworkRequest request(url);
    if (!m_token.isEmpty()) {
        request.setRawHeader("X-NCP-Token", m_token.toUtf8());
    }
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    QNetworkReply* reply = m_manager.get(request);
    
    QObject::connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        
        if (reply->error() != QNetworkReply::NoError) {
            if (callback) callback({}, false);
            return;
        }
        
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (callback) callback(doc.object(), true);
    });
}

void RestClient::put(const QString& endpoint, const QJsonObject& data, JsonCallback callback)
{
    QUrl url = makeUrl(m_baseUrl, endpoint);
    QNetworkRequest request(url);
    if (!m_token.isEmpty()) {
        request.setRawHeader("X-NCP-Token", m_token.toUtf8());
    }
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    QNetworkReply* reply = m_manager.put(request, QJsonDocument(data).toJson());
    
    QObject::connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        
        if (reply->error() != QNetworkReply::NoError) {
            if (callback) callback({}, false);
            return;
        }
        
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (callback) callback(doc.object(), true);
    });
}

void RestClient::post(const QString& endpoint, const QJsonObject& data, JsonCallback callback)
{
    QUrl url = makeUrl(m_baseUrl, endpoint);
    QNetworkRequest request(url);
    if (!m_token.isEmpty()) {
        request.setRawHeader("X-NCP-Token", m_token.toUtf8());
    }
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    
    QNetworkReply* reply = m_manager.post(request, QJsonDocument(data).toJson());
    
    QObject::connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        
        if (reply->error() != QNetworkReply::NoError) {
            if (callback) callback({}, false);
            return;
        }
        
        QByteArray data = reply->readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);
        if (callback) callback(doc.object(), true);
    });
}

void RestClient::del(const QString& endpoint, VoidCallback callback)
{
    QUrl url = makeUrl(m_baseUrl, endpoint);
    QNetworkRequest request(url);
    if (!m_token.isEmpty()) {
        request.setRawHeader("X-NCP-Token", m_token.toUtf8());
    }
    
    QNetworkReply* reply = m_manager.deleteResource(request);
    
    QObject::connect(reply, &QNetworkReply::finished, this, [reply, callback]() {
        reply->deleteLater();
        if (callback) callback(reply->error() == QNetworkReply::NoError);
    });
}

// ─── Public API ────────────────────────────────────────────────────────────

void RestClient::getTraffic(JsonCallback callback)
{
    get("/api/traffic", callback);
}

void RestClient::getConfig(JsonCallback callback)
{
    get("/api/config", callback);
}

void RestClient::updateConfig(const QJsonObject& config, VoidCallback callback)
{
    put("/api/config", config, [callback](const QJsonObject&, bool ok) {
        if (callback) callback(ok);
    });
}

void RestClient::runAdversaryTest(const QJsonObject& params, JsonCallback callback)
{
    post("/api/adversary/run", params, callback);
}

void RestClient::getAdversaryStatus(JsonCallback callback)
{
    get("/api/adversary/status", callback);
}

void RestClient::getLogs(int limit, JsonCallback callback)
{
    get(QString("/api/logs?limit=%1").arg(limit), callback);
}

void RestClient::clearLogs(VoidCallback callback)
{
    del("/api/logs", callback);
}

void RestClient::runStealthBenchmark(const QJsonObject& params, JsonCallback callback)
{
    post("/api/stealth/benchmark", params, callback);
}

void RestClient::getStats(JsonCallback callback)
{
    get("/api/stats", callback);
}

void RestClient::ping(VoidCallback callback)
{
    get("/api/health", [callback](const QJsonObject&, bool ok) {
        if (callback) callback(ok);
    });
}

} // namespace core
