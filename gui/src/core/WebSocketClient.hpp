#pragma once

#include <QObject>
#include <QWebSocket>
#include <QNetworkAccessManager>
#include <QTimer>
#include <QJsonObject>
#include <QJsonValue>
#include <QUrl>

namespace core {

/**
 * @brief Socket.IO (Engine.IO v4) client for real-time backend data.
 *
 * Two transports, picked automatically:
 *   1. WebSocket  — ws://host/socket.io/?EIO=4&transport=websocket
 *   2. HTTP long-polling — fallback when the WSGI server cannot upgrade
 *      (waitress has no WS support): GET/POST /socket.io/?EIO=4&transport=polling
 *
 * Namespace: "/ws" (flask-socketio). Events mapped to signals:
 *   traffic -> trafficUpdate, log -> logEntry, status -> statusUpdate,
 *   adversary -> adversaryUpdate, stats -> statsUpdate, stealth -> stealthUpdate
 */
class WebSocketClient : public QObject {
    Q_OBJECT

public:
    explicit WebSocketClient(QObject* parent = nullptr);
    ~WebSocketClient() override;

    /// Connect to the backend Socket.IO endpoint (base URL, http(s)://…)
    void connectToServer(const QString& url);

    /// Disconnect both transports
    void disconnect();

    /// True once the /ws namespace handshake completed
    bool isConnected() const { return m_nsConnected; }

    /// Send a {type, data} message to the backend as a socket.io event
    void sendMessage(const QJsonObject& message);

signals:
    void connected();
    void disconnected();
    void error(const QString& error);

    // ─── Real-time data signals ────────────────────────────────────
    void trafficUpdate(const QJsonObject& data);
    void logEntry(const QJsonObject& entry);
    void statusUpdate(const QJsonObject& status);
    void adversaryUpdate(const QJsonObject& data);
    void statsUpdate(const QJsonObject& data);
    void stealthUpdate(const QJsonObject& data);

private slots:
    void onConnected();
    void onDisconnected();
    void onError(QAbstractSocket::SocketError socketError);
    void onTextMessageReceived(const QString& message);
    void onReconnectTimer();

private:
    // ─── shared ────────────────────────────────────────────────────
    void attemptReconnect();
    void handleEnginePacket(const QString& packet);
    void handleSocketEvent(const QString& event, const QJsonValue& data);
    void sendPacket(const QString& packet);
    QString buildWsUrl() const;
    QString buildPollUrl(bool withSid) const;

    // ─── websocket transport ───────────────────────────────────────
    // (m_socket slots above)

    // ─── http long-polling transport ───────────────────────────────
    void startPolling();
    void pollingGet();
    void pollingPost(const QString& packet);
    void onPollingFinished();

    QWebSocket m_socket;
    QNetworkAccessManager m_nam;
    QTimer m_reconnectTimer;
    int m_reconnectAttempts = 0;
    int m_maxReconnectAttempts = 10;
    int m_baseReconnectDelayMs = 1000;
    QString m_serverUrl;
    bool m_autoReconnect = true;

    bool m_nsConnected = false;
    bool m_connectSent = false;

    bool m_usePolling = false;     // WS failed → polling for this session
    bool m_pollActive = false;
    bool m_pollInFlight = false;
    QString m_sid;                 // engine.io session id
};

} // namespace core
