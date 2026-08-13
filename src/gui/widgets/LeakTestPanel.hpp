#pragma once

#include <QWidget>

class QLabel;
class QLineEdit;
class QPushButton;
class QTcpSocket;
class QTimer;

/**
 * @brief Leak-test panel (v1.9.2).
 *
 * Compares the externally visible IP address of a direct connection with
 * one routed through the local NCP SOCKS5 proxy — the same check the Web UI
 * offers. A SOCKS5 client handshake is implemented directly on QTcpSocket
 * (no extra dependencies). DNS resolution of the test host is shown as
 * additional information.
 */
class LeakTestPanel : public QWidget {
    Q_OBJECT
public:
    explicit LeakTestPanel(QWidget* parent = nullptr);

    /// SOCKS5 endpoint of the running local proxy (default 127.0.0.1:1080).
    void setProxy(const QString& host, quint16 port);

private slots:
    void runTest();

private:
    enum class Leg { Direct, Proxied };
    void startLeg(Leg leg);
    void finishLeg(Leg leg, bool ok, const QString& ipOrError);
    void evaluate();

    QLineEdit* hostEdit_ = nullptr;
    QPushButton* runBtn_ = nullptr;
    QLabel* directLabel_ = nullptr;
    QLabel* proxiedLabel_ = nullptr;
    QLabel* verdictLabel_ = nullptr;
    QLabel* dnsLabel_ = nullptr;

    QString proxyHost_ = QStringLiteral("127.0.0.1");
    quint16 proxyPort_ = 1080;

    QTcpSocket* sock_ = nullptr;
    QTimer* timeout_ = nullptr;
    Leg leg_ = Leg::Direct;
    int socksPhase_ = 0;   // 0 = greeting, 1 = connect reply, 2 = http
    QByteArray buf_;
    QString directIp_, proxiedIp_;
    bool directDone_ = false, proxiedDone_ = false;
};
