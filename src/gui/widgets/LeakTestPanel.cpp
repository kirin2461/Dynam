#include "LeakTestPanel.hpp"

#include <QHBoxLayout>
#include <QHostInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTcpSocket>
#include <QTimer>
#include <QVBoxLayout>

LeakTestPanel::LeakTestPanel(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(QStringLiteral("<b>Проверка утечек</b>"), this));

    auto* row = new QHBoxLayout();
    row->addWidget(new QLabel(QStringLiteral("Сервис:"), this));
    hostEdit_ = new QLineEdit(QStringLiteral("ifconfig.me/ip"), this);
    hostEdit_->setToolTip(tr("HTTP-сервис, возвращающий внешний IP (host/path)"));
    row->addWidget(hostEdit_, 1);
    runBtn_ = new QPushButton(QStringLiteral("Проверить"), this);
    row->addWidget(runBtn_);
    lay->addLayout(row);

    directLabel_ = new QLabel(QStringLiteral("Напрямую: —"), this);
    proxiedLabel_ = new QLabel(QStringLiteral("Через прокси: —"), this);
    verdictLabel_ = new QLabel(QString(), this);
    dnsLabel_ = new QLabel(QString(), this);
    dnsLabel_->setWordWrap(true);
    lay->addWidget(directLabel_);
    lay->addWidget(proxiedLabel_);
    lay->addWidget(verdictLabel_);
    lay->addWidget(dnsLabel_);
    lay->addStretch(1);

    timeout_ = new QTimer(this);
    timeout_->setSingleShot(true);
    connect(timeout_, &QTimer::timeout, this, [this]() {
        if (sock_) { sock_->abort(); }
        finishLeg(leg_, false, tr("таймаут"));
    });
    connect(runBtn_, &QPushButton::clicked, this, &LeakTestPanel::runTest);
}

void LeakTestPanel::setProxy(const QString& host, quint16 port) {
    proxyHost_ = host;
    proxyPort_ = port;
}

void LeakTestPanel::runTest() {
    if (sock_) return;  // test in flight
    directDone_ = proxiedDone_ = false;
    directIp_.clear();
    proxiedIp_.clear();
    verdictLabel_->clear();
    dnsLabel_->clear();
    runBtn_->setEnabled(false);

    // Informational: how the test host resolves via system DNS.
    const QString host = hostEdit_->text().section(QLatin1Char('/'), 0, 0);
    QHostInfo::lookupHost(host, this, [this](const QHostInfo& info) {
        QStringList addrs;
        for (const auto& a : info.addresses()) addrs << a.toString();
        dnsLabel_->setText(addrs.isEmpty()
            ? tr("DNS: не удалось резолвить (%1)").arg(info.errorString())
            : tr("DNS: %1").arg(addrs.join(QStringLiteral(", "))));
    });

    startLeg(Leg::Direct);
}

void LeakTestPanel::startLeg(Leg leg) {
    leg_ = leg;
    buf_.clear();
    socksPhase_ = (leg == Leg::Proxied) ? 0 : 2;

    const QString hostPort = hostEdit_->text().trimmed();
    const QString host = hostPort.section(QLatin1Char('/'), 0, 0);
    const QString path = QStringLiteral("/") +
        hostPort.section(QLatin1Char('/'), 1, -1, QString::SectionSkipEmpty);

    sock_ = new QTcpSocket(this);
    connect(sock_, &QTcpSocket::readyRead, this, [this, host, path]() {
        buf_ += sock_->readAll();
        if (leg_ == Leg::Proxied && socksPhase_ == 0) {
            if (buf_.size() < 2) return;
            if (static_cast<quint8>(buf_[1]) != 0x00) {
                finishLeg(leg_, false, tr("SOCKS5: метод отклонён"));
                return;
            }
            // CONNECT to domain:port 80
            QByteArray req;
            req.append('\x05').append('\x01').append('\x00').append('\x03');
            const QByteArray h = host.toLatin1();
            req.append(static_cast<char>(h.size()));
            req.append(h);
            req.append('\x00').append('\x50');
            sock_->write(req);
            buf_.clear();
            socksPhase_ = 1;
        } else if (leg_ == Leg::Proxied && socksPhase_ == 1) {
            if (buf_.size() < 4) return;
            if (static_cast<quint8>(buf_[1]) != 0x00) {
                finishLeg(leg_, false,
                    tr("SOCKS5: connect отклонён (0x%1)")
                        .arg(static_cast<quint8>(buf_[1]), 2, 16, QLatin1Char('0')));
                return;
            }
            socksPhase_ = 2;
            buf_.clear();
            sock_->write(QStringLiteral("GET %1 HTTP/1.0\r\nHost: %2\r\n\r\n")
                             .arg(path, host).toLatin1());
        } else {
            // HTTP: wait for connection close or a complete body.
            const int split = buf_.indexOf("\r\n\r\n");
            if (split < 0) return;
            const QByteArray body = buf_.mid(split + 4).trimmed();
            if (body.isEmpty()) return;
            finishLeg(leg_, true, QString::fromLatin1(body.left(64)));
        }
    });
    connect(sock_, &QTcpSocket::disconnected, this, [this]() {
        if (!sock_) return;
        const int split = buf_.indexOf("\r\n\r\n");
        if (split >= 0) {
            const QByteArray body = buf_.mid(split + 4).trimmed();
            if (!body.isEmpty()) {
                finishLeg(leg_, true, QString::fromLatin1(body.left(64)));
                return;
            }
        }
        if (socksPhase_ == 2)
            finishLeg(leg_, false, tr("пустой ответ"));
    });
    connect(sock_, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred),
            this, [this](QAbstractSocket::SocketError) {
        if (sock_)
            finishLeg(leg_, false, sock_->errorString());
    });

    if (leg == Leg::Proxied) {
        sock_->connectToHost(proxyHost_, proxyPort_);
        // SOCKS5 greeting: version 5, one method, no-auth
        connect(sock_, &QTcpSocket::connected, this, [this]() {
            if (sock_ && socksPhase_ == 0)
                sock_->write(QByteArray("\x05\x01\x00", 3));
        });
    } else {
        sock_->connectToHost(host, 80);
    }
    timeout_->start(9000);
}

void LeakTestPanel::finishLeg(Leg leg, bool ok, const QString& ipOrError) {
    if (sock_) {
        sock_->disconnect(this);
        sock_->deleteLater();
        sock_ = nullptr;
    }
    timeout_->stop();

    const QString text = ok
        ? QStringLiteral("<span style='color:#4caf50'>%1</span>").arg(ipOrError)
        : QStringLiteral("<span style='color:#e05252'>%1</span>").arg(ipOrError);

    if (leg == Leg::Direct) {
        directDone_ = true;
        directIp_ = ok ? ipOrError : QString();
        directLabel_->setText(tr("Напрямую: %1").arg(text));
        startLeg(Leg::Proxied);
    } else {
        proxiedDone_ = true;
        proxiedIp_ = ok ? ipOrError : QString();
        proxiedLabel_->setText(tr("Через прокси: %1").arg(text));
        runBtn_->setEnabled(true);
        evaluate();
    }
}

void LeakTestPanel::evaluate() {
    if (directIp_.isEmpty() || proxiedIp_.isEmpty()) {
        verdictLabel_->setText(QStringLiteral(
            "<span style='color:#e0a040'>Вердикт: сравнить не удалось "
            "(одна из проверок не прошла)</span>"));
    } else if (directIp_ == proxiedIp_) {
        verdictLabel_->setText(QStringLiteral(
            "<span style='color:#e0a040'>Вердикт: IP совпадает — трафик не "
            "идёт через прокси или прокси не меняет выход</span>"));
    } else {
        verdictLabel_->setText(QStringLiteral(
            "<span style='color:#4caf50'>Вердикт: IP различается — утечки IP "
            "через прокси нет</span>"));
    }
}
