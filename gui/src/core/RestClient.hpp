#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <QUrl>
#include <QString>
#include <functional>

namespace core {

/**
 * @brief REST client for communicating with the Dynam backend API.
 * 
 * Provides methods for all API endpoints:
 * - Traffic monitoring (GET /api/traffic)
 * - Configuration (GET/PUT /api/config)
 * - AdversaryTester (POST /api/adversary/run)
 * - Logs (GET /api/logs)
 * - Stats (GET /api/stats)
 */
class RestClient : public QObject {
    Q_OBJECT

public:
    using JsonCallback = std::function<void(const QJsonObject&, bool)>;
    using VoidCallback = std::function<void(bool)>;

    explicit RestClient(QObject* parent = nullptr);
    
    /// Set base URL for the backend (e.g., "http://127.0.0.1:8085")
    void setBaseUrl(const QString& url);
    QString baseUrl() const { return m_baseUrl.toString(); }
    
    // ─── Traffic API ───────────────────────────────────────────────────
    void getTraffic(JsonCallback callback);
    
    // ─── Config API ────────────────────────────────────────────────────
    void getConfig(JsonCallback callback);
    void updateConfig(const QJsonObject& config, VoidCallback callback);
    
    // ─── AdversaryTester API ───────────────────────────────────────────
    void runAdversaryTest(const QJsonObject& params, JsonCallback callback);
    void getAdversaryStatus(JsonCallback callback);

    // ─── Stealth benchmark (ncp-adversary-bench) ────────────────────
    /// POST /api/stealth/benchmark — runs AdversaryTester strategy
    /// benchmarks server-side and returns {strategies:[…], best_*}.
    void runStealthBenchmark(const QJsonObject& params, JsonCallback callback);

    // ─── Logs API ──────────────────────────────────────────────────────
    void getLogs(int limit, JsonCallback callback);
    void clearLogs(VoidCallback callback);
    
    // ─── Stats API ─────────────────────────────────────────────────────
    void getStats(JsonCallback callback);
    
    // ─── Health ────────────────────────────────────────────────────────
    void ping(VoidCallback callback);

signals:
    void connectionError(const QString& error);

private:
    void fetchToken();
    void get(const QString& endpoint, JsonCallback callback);
    void put(const QString& endpoint, const QJsonObject& data, JsonCallback callback);
    void post(const QString& endpoint, const QJsonObject& data, JsonCallback callback);
    void del(const QString& endpoint, VoidCallback callback);

    QNetworkAccessManager m_manager;
    QUrl m_baseUrl;
    QString m_token;  // per-start API token scraped from the index page
};

} // namespace core
