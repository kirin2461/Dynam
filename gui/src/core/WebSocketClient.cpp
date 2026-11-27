#include "WebSocketClient.hpp"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrlQuery>
#include <QtMath>

namespace core {

static const QChar kRecordSep(0x1e);  // engine.io v4 packet separator

WebSocketClient::WebSocketClient(QObject* parent)
    : QObject(parent)
{
    connect(&m_socket, &QWebSocket::connected, this, &WebSocketClient::onConnected);
    connect(&m_socket, &QWebSocket::disconnected, this, &WebSocketClient::onDisconnected);
    connect(&m_socket, &QWebSocket::errorOccurred, this, &WebSocketClient::onError);
    connect(&m_socket, &QWebSocket::textMessageReceived, this,
            &WebSocketClient::onTextMessageReceived);

    m_reconnectTimer.setSingleShot(true);
    connect(&m_reconnectTimer, &QTimer::timeout, this, &WebSocketClient::onReconnectTimer);
}

WebSocketClient::~WebSocketClient()
{
    m_autoReconnect = false;
    m_reconnectTimer.stop();
    m_pollActive = false;
    m_socket.close();
}

// ─── URL helpers ───────────────────────────────────────────────────

QString WebSocketClient::buildWsUrl() const
{
    QString wsUrl = m_serverUrl;
    if (wsUrl.startsWith("http://")) {
        wsUrl.replace(0, 7, "ws://");
    } else if (wsUrl.startsWith("https://")) {
        wsUrl.replace(0, 8, "wss://");
    }
    QUrl url(wsUrl);
    url.setPath("/socket.io/");
    QUrlQuery q;
    q.addQueryItem("EIO", "4");
    q.addQueryItem("transport", "websocket");
    url.setQuery(q);
    return url.toString();
}

QString WebSocketClient::buildPollUrl(bool withSid) const
{
    QUrl url(m_serverUrl);
    url.setPath("/socket.io/");
    QUrlQuery q;
    q.addQueryItem("EIO", "4");
    q.addQueryItem("transport", "polling");
    if (withSid && !m_sid.isEmpty()) q.addQueryItem("sid", m_sid);
    url.setQuery(q);
    return url.toString();
}

// ─── public API ────────────────────────────────────────────────────

void WebSocketClient::connectToServer(const QString& url)
{
    m_serverUrl = url;
    m_reconnectAttempts = 0;
    m_nsConnected = false;
    m_connectSent = false;
    m_sid.clear();
    m_pollActive = false;
    m_usePolling = false;
    m_socket.open(QUrl(buildWsUrl()));
}

void WebSocketClient::disconnect()
{
    m_autoReconnect = false;
    m_reconnectTimer.stop();
    m_nsConnected = false;
    m_connectSent = false;
    m_pollActive = false;
    m_socket.close();
}

void WebSocketClient::sendMessage(const QJsonObject& message)
{
    if (!isConnected()) return;
    QString type = message.value("type").toString();
    if (type.isEmpty()) return;
    QJsonArray frame;
    frame.append(type);
    frame.append(message.value("data"));
    const QString json = QJsonDocument(frame).toJson(QJsonDocument::Compact);
    sendPacket(QStringLiteral("42/ws,") + json);
}

// ─── packet dispatch (both transports) ─────────────────────────────

void WebSocketClient::sendPacket(const QString& packet)
{
    if (m_usePolling) {
        pollingPost(packet);
    } else if (m_socket.state() == QAbstractSocket::ConnectedState) {
        m_socket.sendTextMessage(packet);
    }
}

void WebSocketClient::onConnected()
{
    m_reconnectAttempts = 0;
    // Wait for the engine.io "open" packet before joining the /ws namespace.
}

void WebSocketClient::onDisconnected()
{
    const bool wasConnected = m_nsConnected;
    m_nsConnected = false;
    m_connectSent = false;
    if (wasConnected) emit disconnected();
    if (!m_usePolling) attemptReconnect();
}

void WebSocketClient::onError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError)
    if (!m_usePolling && !m_nsConnected) {
        // The WSGI server refused the WS upgrade (e.g. waitress) —
        // fall back to HTTP long-polling for this session.
        m_usePolling = true;
        m_socket.abort();
        startPolling();
        return;
    }
    emit error(m_socket.errorString());
}

void WebSocketClient::onTextMessageReceived(const QString& message)
{
    if (message.isEmpty()) return;
    // WebSocket frames are single packets; polling batches with 0x1e.
    if (message.contains(kRecordSep)) {
        for (const QString& p : message.split(kRecordSep)) {
            if (!p.isEmpty()) handleEnginePacket(p);
        }
    } else {
        handleEnginePacket(message);
    }
}

void WebSocketClient::handleEnginePacket(const QString& packet)
{
    if (packet.isEmpty()) return;
    const QChar type = packet.at(0);
    if (type == '0') {
        // engine.io OPEN — capture sid (polling) and join /ws.
        if (m_sid.isEmpty() && packet.size() > 1) {
            QJsonDocument doc = QJsonDocument::fromJson(packet.mid(1).toUtf8());
            m_sid = doc.object().value("sid").toString();
        }
        if (!m_connectSent) {
            m_connectSent = true;
            sendPacket(QStringLiteral("40/ws,"));
        }
    } else if (type == '2') {
        sendPacket(QStringLiteral("3"));  // PING → PONG
    } else if (type == '3' || type == '1') {
        // PONG / CLOSE — nothing to do
    } else if (type == '4') {
        if (packet.size() < 2) return;
        const QChar subtype = packet.at(1);
        QString rest = packet.mid(2);
        if (rest.startsWith('/')) {
            const int comma = rest.indexOf(',');
            if (comma < 0) return;
            rest = rest.mid(comma + 1);
        }
        if (subtype == '0') {
            if (!m_nsConnected) {
                m_nsConnected = true;
                emit connected();
            }
        } else if (subtype == '2') {
            QJsonDocument doc = QJsonDocument::fromJson(rest.toUtf8());
            if (!doc.isArray()) return;
            const QJsonArray arr = doc.array();
            if (arr.isEmpty()) return;
            handleSocketEvent(arr.at(0).toString(),
                              arr.size() > 1 ? arr.at(1) : QJsonValue());
        } else if (subtype == '4') {
            emit error(rest);
        }
    }
}

void WebSocketClient::handleSocketEvent(const QString& event, const QJsonValue& data)
{
    const QJsonObject obj = data.toObject();
    if (event == "traffic") {
        emit trafficUpdate(obj);
    } else if (event == "log") {
        emit logEntry(obj);
    } else if (event == "status") {
        emit statusUpdate(obj);
    } else if (event == "adversary") {
        emit adversaryUpdate(obj);
    } else if (event == "stats") {
        emit statsUpdate(obj);
    } else if (event == "stealth") {
        emit stealthUpdate(obj);
    }
}

// ─── reconnect ─────────────────────────────────────────────────────

void WebSocketClient::attemptReconnect()
{
    if (!m_autoReconnect) return;
    if (m_reconnectAttempts >= m_maxReconnectAttempts) {
        emit error(tr("Max reconnect attempts reached"));
        return;
    }
    const int delay = qMin(
        static_cast<int>(m_baseReconnectDelayMs * qPow(2, m_reconnectAttempts)),
        30000);
    m_reconnectTimer.start(delay);
    m_reconnectAttempts++;
}

void WebSocketClient::onReconnectTimer()
{
    if (!m_autoReconnect) return;
    if (m_usePolling) {
        startPolling();
    } else {
        m_nsConnected = false;
        m_connectSent = false;
        m_socket.open(QUrl(buildWsUrl()));
    }
}

// ─── HTTP long-polling transport ───────────────────────────────────

void WebSocketClient::startPolling()
{
    m_pollActive = true;
    m_nsConnected = false;
    m_connectSent = false;
    m_sid.clear();
    pollingGet();  // first GET: engine.io open packet carries the sid
}

void WebSocketClient::pollingGet()
{
    if (!m_pollActive || m_pollInFlight) return;
    m_pollInFlight = true;

    QNetworkRequest req(QUrl(buildPollUrl(!m_sid.isEmpty())));
    req.setTransferTimeout(60000);  // > pingInterval+pingTimeout
    QNetworkReply* reply = m_nam.get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        m_pollInFlight = false;
        if (!m_pollActive) return;

        if (reply->error() != QNetworkReply::NoError) {
            // Transport-level failure — drop to reconnect logic.
            m_nsConnected = false;
            if (m_autoReconnect) {
                attemptReconnect();
            } else {
                emit error(reply->errorString());
            }
            return;
        }

        const QByteArray body = reply->readAll();
        const QString text = QString::fromUtf8(body);
        if (text.contains(kRecordSep)) {
            for (const QString& p : text.split(kRecordSep)) {
                if (!p.isEmpty()) handleEnginePacket(p);
            }
        } else if (!text.isEmpty()) {
            handleEnginePacket(text);
        }
        // Keep the long-poll loop running.
        pollingGet();
    });
}

void WebSocketClient::pollingPost(const QString& packet)
{
    if (!m_pollActive) return;
    QNetworkRequest req(QUrl(buildPollUrl(true)));
    req.setHeader(QNetworkRequest::ContentTypeHeader,
                  "text/plain;charset=UTF-8");
    QNetworkReply* reply = m_nam.post(req, packet.toUtf8());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            emit error(reply->errorString());
            return;
        }
        // POST ack body is "ok" — the actual packets arrive via GET.
        const QString text = QString::fromUtf8(reply->readAll());
        if (!text.isEmpty() && text != "ok") {
            // Some engines answer inside the POST body.
            if (text.contains(kRecordSep)) {
                for (const QString& p : text.split(kRecordSep)) {
                    if (!p.isEmpty()) handleEnginePacket(p);
                }
            } else {
                handleEnginePacket(text);
            }
        }
    });
}

} // namespace core
