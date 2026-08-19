#pragma once

/**
 * @file EnterprisePanel.hpp
 * @brief «Enterprise» tab: Qt front-end for the CLI enterprise modules that
 *        had no GUI coverage — spa, reality, stegodns, porthop, fog, xdp.
 *
 * Mapping to the CLI (src/cli/main.cpp):
 *  - SPA:      keygen / knock are one-shot `ncp spa ...` invocations via
 *              DriverController::runNcpCommand(); serve is a long-running
 *              daemon held as a QProcess member (started/stopped here).
 *  - Reality:  serve start/stop as a daemon QProcess; «dry-run» validates
 *              the configuration via `ncp reality serve --dry-run`.
 *  - StegoDNS: encode/decode run in-process through ncp::StegoDnsEncoder /
 *              ncp::StegoDnsDecoder (ncp_core is linked into the GUI), so no
 *              subprocess is needed and passphrases never hit a command line.
 *  - PortHop:  serve is a daemon QProcess; client send is one-shot.
 *  - Fog:      node is a daemon QProcess.
 *  - XDP:      probe / stats / drop set+clear are one-shot (compile/attach/
 *              detach are intentionally NOT exposed — they require root and
 *              kernel toolchain access; use the CLI). Linux-only.
 *
 * Secrets (passphrases, shared secrets, key-file paths) are never written
 * to the panel log; logged command lines are redacted by redactArgs().
 *
 * Style follows the other header-only tool panels (CryptoPanel.hpp) and is
 * kept compatible with Qt 6.4.
 */

#include <QApplication>
#include <QAbstractSocket>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFont>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QScrollArea>
#include <QVBoxLayout>
#include <QWidget>

#include <array>
#include <cstdint>
#include <vector>

#include "../DriverController.hpp"
#include "../../core/include/ncp_spa.hpp"
#include "../../core/include/ncp_stegodns.hpp"

class EnterprisePanel : public QWidget {
    Q_OBJECT
public:
    explicit EnterprisePanel(QWidget* parent = nullptr) : QWidget(parent) {
        auto* root = new QVBoxLayout(this);

        auto* scroll = new QScrollArea(this);
        scroll->setWidgetResizable(true);
        auto* inner = new QWidget;
        auto* v = new QVBoxLayout(inner);
        v->setSpacing(10);

        v->addWidget(buildSpaGroup(inner));
        v->addWidget(buildRealityGroup(inner));
        v->addWidget(buildStegoGroup(inner));
        v->addWidget(buildPortHopGroup(inner));
        v->addWidget(buildFogGroup(inner));
        v->addWidget(buildXdpGroup(inner));
        v->addStretch(1);

        scroll->setWidget(inner);
        root->addWidget(scroll, 1);

        auto* logBox = new QGroupBox(tr("Журнал"), this);
        auto* logLayout = new QVBoxLayout(logBox);
        log_ = new QPlainTextEdit(logBox);
        log_->setReadOnly(true);
        log_->setFont(mono());
        log_->setMaximumBlockCount(2000);
        log_->setMinimumHeight(110);
        logLayout->addWidget(log_);
        root->addWidget(logBox);
    }

    ~EnterprisePanel() override {
        // Terminate the daemons before our children (log, labels) die.
        stopDaemon(&spaProc_,     nullptr, QStringLiteral("SPA"));
        stopDaemon(&realityProc_, nullptr, QStringLiteral("Reality"));
        stopDaemon(&phProc_,      nullptr, QStringLiteral("PortHop"));
        stopDaemon(&fogProc_,     nullptr, QStringLiteral("Fog"));
    }

private:
    // ────────────────────────────────────────────────────────────────────────
    //  SPA (ncp spa keygen | knock | serve)
    // ────────────────────────────────────────────────────────────────────────
    QGroupBox* buildSpaGroup(QWidget* parent) {
        auto* box = new QGroupBox(tr("SPA — Single Packet Authorization"), parent);
        auto* v = new QVBoxLayout(box);

        // ── keygen ──
        auto* kgBox = new QGroupBox(tr("Генерация ключей (spa keygen)"), box);
        auto* kgForm = new QFormLayout(kgBox);
        spaKeygenPrefix_ = new QLineEdit(QStringLiteral("spa"), kgBox);
        auto* kgBtn = new QPushButton(tr("Сгенерировать ключ"), kgBox);
        kgForm->addRow(tr("Префикс файла:"), spaKeygenPrefix_);
        kgForm->addRow(QString(), kgBtn);
        connect(kgBtn, &QPushButton::clicked, this, [this] {
            const QString prefix = spaKeygenPrefix_->text().trimmed();
            if (prefix.isEmpty()) { warn(tr("Укажите префикс файла ключа.")); return; }
            runOnce({QStringLiteral("spa"), QStringLiteral("keygen"),
                     QStringLiteral("--out"), prefix});
        });

        // ── knock ──
        auto* knBox = new QGroupBox(tr("Отправка knock (spa knock)"), box);
        auto* knForm = new QFormLayout(knBox);
        spaKnockHost_ = new QLineEdit(knBox);
        spaKnockHost_->setPlaceholderText(tr("host (IP или DNS-имя)"));
        spaKnockPort_ = new QLineEdit(QString::number(ncp::SPA_DEFAULT_PORT), knBox);
        spaKnockAllowPort_ = new QLineEdit(knBox);
        spaKnockAllowPort_->setPlaceholderText(tr("порт, который открыть (1-65535)"));
        spaKnockProto_ = new QComboBox(knBox);
        spaKnockProto_->addItems({QStringLiteral("tcp"), QStringLiteral("udp")});
        spaKnockTtl_ = new QLineEdit(QStringLiteral("300"), knBox);
        spaKnockKey_ = new QLineEdit(knBox);
        spaKnockKey_->setPlaceholderText(tr("файл .key из spa keygen"));
        auto* knKeyRow = new QHBoxLayout;
        knKeyRow->addWidget(spaKnockKey_, 1);
        auto* knBrowse = new QPushButton(tr("Обзор…"), knBox);
        knKeyRow->addWidget(knBrowse);
        connect(knBrowse, &QPushButton::clicked, this, [this] { browseFile(spaKnockKey_); });
        spaKnockTwice_ = new QCheckBox(tr("Отправить дважды (replay self-test)"), knBox);
        auto* knBtn = new QPushButton(tr("Отправить knock"), knBox);
        knForm->addRow(tr("Хост:"), spaKnockHost_);
        knForm->addRow(tr("UDP-порт SPA:"), spaKnockPort_);
        knForm->addRow(tr("Открыть порт:"), spaKnockAllowPort_);
        knForm->addRow(tr("Протокол:"), spaKnockProto_);
        knForm->addRow(tr("TTL (с):"), spaKnockTtl_);
        knForm->addRow(tr("Файл ключа:"), knKeyRow);
        knForm->addRow(QString(), spaKnockTwice_);
        knForm->addRow(QString(), knBtn);
        connect(knBtn, &QPushButton::clicked, this, [this] {
            const QString host = spaKnockHost_->text().trimmed();
            int udpPort = 0, allowPort = 0;
            if (host.isEmpty()) { warn(tr("Укажите хост для knock.")); return; }
            if (!parsePort(spaKnockPort_->text(), udpPort)) {
                warn(tr("UDP-порт SPA должен быть числом 1-65535.")); return;
            }
            if (!parsePort(spaKnockAllowPort_->text(), allowPort)) {
                warn(tr("Открываемый порт должен быть числом 1-65535.")); return;
            }
            bool ok = false;
            const int ttl = spaKnockTtl_->text().trimmed().toInt(&ok);
            if (!ok || ttl < 0 || ttl > 86400) {
                warn(tr("TTL должен быть числом 0-86400 (0 = умолчание сервера).")); return;
            }
            const QString keyPath = spaKnockKey_->text().trimmed();
            if (keyPath.isEmpty() || !QFile::exists(keyPath)) {
                warn(tr("Укажите существующий файл ключа (.key).")); return;
            }
            QStringList args{QStringLiteral("spa"), QStringLiteral("knock"), host,
                             QStringLiteral("--key"), keyPath,
                             QStringLiteral("--allow-port"), QString::number(allowPort),
                             QStringLiteral("--port"), QString::number(udpPort),
                             QStringLiteral("--proto"), spaKnockProto_->currentText(),
                             QStringLiteral("--ttl"), QString::number(ttl)};
            if (spaKnockTwice_->isChecked())
                args << QStringLiteral("--send-twice");
            runOnce(args);
        });

        // ── serve (daemon) ──
        auto* svBox = new QGroupBox(tr("Сервер (spa serve)"), box);
        auto* svForm = new QFormLayout(svBox);
        spaServeKeys_ = new QLineEdit(svBox);
        spaServeKeys_->setPlaceholderText(tr("файл authorized_keys (base64 pubkey на строку)"));
        auto* svKeyRow = new QHBoxLayout;
        svKeyRow->addWidget(spaServeKeys_, 1);
        auto* svBrowse = new QPushButton(tr("Обзор…"), svBox);
        svKeyRow->addWidget(svBrowse);
        connect(svBrowse, &QPushButton::clicked, this, [this] { browseFile(spaServeKeys_); });
        spaServePort_ = new QLineEdit(QString::number(ncp::SPA_DEFAULT_PORT), svBox);
        spaServeBind_ = new QLineEdit(QStringLiteral("0.0.0.0"), svBox);
        spaServeDry_ = new QCheckBox(tr("dry-run (ipset-команды только логируются)"), svBox);
        spaServeStatus_ = new QLabel(tr("не запущен"), svBox);
        auto* svBtns = new QHBoxLayout;
        auto* svStart = new QPushButton(tr("Старт"), svBox);
        auto* svStop  = new QPushButton(tr("Стоп"), svBox);
        svBtns->addWidget(svStart);
        svBtns->addWidget(svStop);
        svBtns->addStretch(1);
        svBtns->addWidget(new QLabel(tr("Статус:"), svBox));
        svBtns->addWidget(spaServeStatus_);
        svForm->addRow(tr("Authorized keys:"), svKeyRow);
        svForm->addRow(tr("UDP-порт:"), spaServePort_);
        svForm->addRow(tr("Bind-адрес:"), spaServeBind_);
        svForm->addRow(QString(), spaServeDry_);
        svForm->addRow(QString(), svBtns);
        connect(svStart, &QPushButton::clicked, this, [this] {
            const QString keys = spaServeKeys_->text().trimmed();
            int port = 0;
            if (keys.isEmpty() || !QFile::exists(keys)) {
                warn(tr("Укажите существующий файл authorized_keys.")); return;
            }
            if (!parsePort(spaServePort_->text(), port)) {
                warn(tr("UDP-порт должен быть числом 1-65535.")); return;
            }
            const QString bind = spaServeBind_->text().trimmed();
            if (bind.isEmpty()) { warn(tr("Укажите bind-адрес.")); return; }
            QStringList args{QStringLiteral("spa"), QStringLiteral("serve"),
                             QStringLiteral("--authorized-keys"), keys,
                             QStringLiteral("--port"), QString::number(port),
                             QStringLiteral("--bind"), bind};
            if (spaServeDry_->isChecked())
                args << QStringLiteral("--dry-run");
            startDaemon(&spaProc_, spaServeStatus_, QStringLiteral("SPA"), args);
        });
        connect(svStop, &QPushButton::clicked, this, [this] {
            stopDaemon(&spaProc_, spaServeStatus_, QStringLiteral("SPA"));
        });

        v->addWidget(kgBox);
        v->addWidget(knBox);
        v->addWidget(svBox);
        return box;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Reality (ncp reality serve [--dry-run])
    // ────────────────────────────────────────────────────────────────────────
    QGroupBox* buildRealityGroup(QWidget* parent) {
        auto* box = new QGroupBox(tr("Reality — fallback-сервер (XTLS-Reality-style)"), parent);
        auto* form = new QFormLayout(box);

        rlListen_   = new QLineEdit(QStringLiteral("443"), box);
        rlFallback_ = new QLineEdit(box);
        rlFallback_->setPlaceholderText(tr("example.com:443"));
        rlInternal_ = new QLineEdit(QStringLiteral("127.0.0.1:8080"), box);
        rlKeyFile_  = new QLineEdit(box);
        rlKeyFile_->setPlaceholderText(tr("файл ключей клиентов (key_id + base64 secret)"));
        auto* keyRow = new QHBoxLayout;
        keyRow->addWidget(rlKeyFile_, 1);
        auto* browse = new QPushButton(tr("Обзор…"), box);
        keyRow->addWidget(browse);
        connect(browse, &QPushButton::clicked, this, [this] { browseFile(rlKeyFile_); });

        rlStatus_ = new QLabel(tr("не запущен"), box);
        auto* btns = new QHBoxLayout;
        auto* dryBtn   = new QPushButton(tr("Проверить (dry-run)"), box);
        auto* startBtn = new QPushButton(tr("Старт"), box);
        auto* stopBtn  = new QPushButton(tr("Стоп"), box);
        btns->addWidget(dryBtn);
        btns->addWidget(startBtn);
        btns->addWidget(stopBtn);
        btns->addStretch(1);
        btns->addWidget(new QLabel(tr("Статус:"), box));
        btns->addWidget(rlStatus_);

        form->addRow(tr("Listen-порт:"), rlListen_);
        form->addRow(tr("Fallback (host:port):"), rlFallback_);
        form->addRow(tr("Internal (host:port):"), rlInternal_);
        form->addRow(tr("Файл ключей:"), keyRow);
        form->addRow(QString(), btns);

        auto collectArgs = [this](bool dryRun, QStringList& out) -> bool {
            int listen = 0;
            if (!parsePort(rlListen_->text(), listen)) {
                warn(tr("Listen-порт должен быть числом 1-65535.")); return false;
            }
            QString fh, ih;
            int fp = 0, ip = 0;
            if (!splitHostPort(rlFallback_->text(), fh, fp)) {
                warn(tr("Fallback должен быть в форме host:port.")); return false;
            }
            if (!splitHostPort(rlInternal_->text(), ih, ip)) {
                warn(tr("Internal должен быть в форме host:port.")); return false;
            }
            const QString keyFile = rlKeyFile_->text().trimmed();
            if (keyFile.isEmpty() || !QFile::exists(keyFile)) {
                warn(tr("Укажите существующий файл ключей.")); return false;
            }
            out = {QStringLiteral("reality"), QStringLiteral("serve"),
                   QStringLiteral("--listen"), QString::number(listen),
                   QStringLiteral("--fallback"), rlFallback_->text().trimmed(),
                   QStringLiteral("--internal"), rlInternal_->text().trimmed(),
                   QStringLiteral("--key-file"), keyFile};
            if (dryRun) out << QStringLiteral("--dry-run");
            return true;
        };

        connect(dryBtn, &QPushButton::clicked, this, [this, collectArgs] {
            QStringList args;
            if (collectArgs(true, args)) runOnce(args);
        });
        connect(startBtn, &QPushButton::clicked, this, [this, collectArgs] {
            QStringList args;
            if (collectArgs(false, args))
                startDaemon(&realityProc_, rlStatus_, QStringLiteral("Reality"), args);
        });
        connect(stopBtn, &QPushButton::clicked, this, [this] {
            stopDaemon(&realityProc_, rlStatus_, QStringLiteral("Reality"));
        });
        return box;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Stego-DNS (in-process: ncp::StegoDnsEncoder / Decoder)
    // ────────────────────────────────────────────────────────────────────────
    QGroupBox* buildStegoGroup(QWidget* parent) {
        auto* box = new QGroupBox(tr("Stego-DNS — скрытые TXT-записи (in-process)"), parent);
        auto* v = new QVBoxLayout(box);

        // ── encode ──
        auto* encBox = new QGroupBox(tr("Публикация (encode)"), box);
        auto* ef = new QFormLayout(encBox);
        seIp_ = new QLineEdit(encBox);
        seIp_->setPlaceholderText(tr("a.b.c.d"));
        sePort_ = new QLineEdit(encBox);
        seSpaPub_ = new QLineEdit(encBox);
        seSpaPub_->setPlaceholderText(tr("base64, 32-байтный SPA pubkey сервера"));
        sePass_ = new QLineEdit(encBox);
        sePass_->setEchoMode(QLineEdit::Password);
        sePass_->setPlaceholderText(tr("мастер-пароль расшифровки"));
        seSignKey_ = new QLineEdit(encBox);
        seSignKey_->setPlaceholderText(tr("64-байтный Ed25519 secret или .key из spa keygen"));
        auto* skRow = new QHBoxLayout;
        skRow->addWidget(seSignKey_, 1);
        auto* skBrowse = new QPushButton(tr("Обзор…"), encBox);
        skRow->addWidget(skBrowse);
        connect(skBrowse, &QPushButton::clicked, this, [this] { browseFile(seSignKey_); });
        seDomain_ = new QLineEdit(encBox);
        seDomain_->setPlaceholderText(tr("example.com"));
        seExpires_ = new QLineEdit(QStringLiteral("0"), encBox);
        seExpires_->setPlaceholderText(tr("unix time, 0 = без срока"));
        auto* encBtn = new QPushButton(tr("Создать TXT-запись"), encBox);
        seOut_ = new QPlainTextEdit(encBox);
        seOut_->setReadOnly(true);
        seOut_->setFont(mono());
        seOut_->setMaximumHeight(64);
        seOut_->setPlaceholderText(tr("v=spf1 ip4:… include:…._ncp.<domain> ~all"));
        seVerifyKey_ = new QLineEdit(encBox);
        seVerifyKey_->setReadOnly(true);
        seVerifyKey_->setFont(mono());
        seVerifyKey_->setPlaceholderText(tr("verify-pubkey (base64) для декодирования"));
        auto* copyBtn = new QPushButton(tr("Копировать TXT"), encBox);
        ef->addRow(tr("IP сервера:"), seIp_);
        ef->addRow(tr("Порт:"), sePort_);
        ef->addRow(tr("SPA pubkey:"), seSpaPub_);
        ef->addRow(tr("Пароль:"), sePass_);
        ef->addRow(tr("Ключ подписи:"), skRow);
        ef->addRow(tr("Домен:"), seDomain_);
        ef->addRow(tr("Истекает (unix):"), seExpires_);
        ef->addRow(QString(), encBtn);
        ef->addRow(tr("TXT:"), seOut_);
        ef->addRow(QString(), copyBtn);
        ef->addRow(tr("Verify-pubkey:"), seVerifyKey_);
        connect(encBtn, &QPushButton::clicked, this, [this] { stegoEncode(); });
        connect(copyBtn, &QPushButton::clicked, this, [this] {
            QApplication::clipboard()->setText(seOut_->toPlainText());
        });

        // ── decode ──
        auto* decBox = new QGroupBox(tr("Чтение (decode)"), box);
        auto* df = new QFormLayout(decBox);
        sdTxt_ = new QPlainTextEdit(decBox);
        sdTxt_->setFont(mono());
        sdTxt_->setMaximumHeight(64);
        sdTxt_->setPlaceholderText(tr("TXT-запись целиком: v=spf1 ip4:… include:… ~all"));
        sdPass_ = new QLineEdit(decBox);
        sdPass_->setEchoMode(QLineEdit::Password);
        sdVerifyPub_ = new QLineEdit(decBox);
        sdVerifyPub_->setPlaceholderText(tr("base64, 32-байтный verify-pubkey"));
        auto* decBtn = new QPushButton(tr("Декодировать"), decBox);
        sdOut_ = new QPlainTextEdit(decBox);
        sdOut_->setReadOnly(true);
        sdOut_->setFont(mono());
        sdOut_->setMaximumHeight(90);
        df->addRow(tr("TXT-запись:"), sdTxt_);
        df->addRow(tr("Пароль:"), sdPass_);
        df->addRow(tr("Verify-pubkey:"), sdVerifyPub_);
        df->addRow(QString(), decBtn);
        df->addRow(tr("NodeParams:"), sdOut_);
        connect(decBtn, &QPushButton::clicked, this, [this] { stegoDecode(); });

        v->addWidget(encBox);
        v->addWidget(decBox);
        return box;
    }

    void stegoEncode() {
        ncp::NodeParams params;

        QHostAddress addr;
        if (!addr.setAddress(seIp_->text().trimmed()) ||
            addr.protocol() != QAbstractSocket::IPv4Protocol) {
            warn(tr("Укажите корректный IPv4-адрес.")); return;
        }
        const quint32 v4 = addr.toIPv4Address();
        params.ipv4 = {static_cast<uint8_t>(v4 >> 24), static_cast<uint8_t>(v4 >> 16),
                       static_cast<uint8_t>(v4 >> 8),  static_cast<uint8_t>(v4)};

        int port = 0;
        if (!parsePort(sePort_->text(), port)) {
            warn(tr("Порт должен быть числом 1-65535.")); return;
        }
        params.port = static_cast<uint16_t>(port);

        bool ok = false;
        const qulonglong exp = seExpires_->text().trimmed().toULongLong(&ok);
        if (!ok || exp > 0xFFFFFFFFULL) {
            warn(tr("«Истекает» — unix time (0 = без срока).")); return;
        }
        params.expires_unix = static_cast<uint32_t>(exp);

        std::vector<uint8_t> spaPk;
        if (!ncp::spa_base64_decode(seSpaPub_->text().trimmed().toStdString(), spaPk) ||
            spaPk.size() != 32) {
            warn(tr("SPA pubkey должен быть base64 32-байтного ключа.")); return;
        }
        std::copy(spaPk.begin(), spaPk.end(), params.spa_pubkey.begin());

        const std::string pass = sePass_->text().toStdString();
        if (pass.empty()) { warn(tr("Укажите мастер-пароль.")); return; }

        std::array<uint8_t, 64> sk{};
        if (!loadSigningKey(seSignKey_->text().trimmed(), sk)) {
            warn(tr("Не удалось прочитать ключ подписи (64 байта raw/base64 "
                    "или 96-байтный .key из spa keygen).")); return;
        }

        const std::string domain = seDomain_->text().trimmed().toStdString();
        if (domain.empty()) { warn(tr("Укажите домен.")); return; }

        ncp::StegoDnsEncoder encoder(pass, sk);
        seOut_->setPlainText(QString::fromStdString(encoder.encode_txt(params, domain)));
        // The verify key is the second half of the libsodium secret (sk || pk).
        seVerifyKey_->setText(QString::fromStdString(
            ncp::spa_base64_encode(sk.data() + 32, 32)));
        appendLog(tr("[stegodns] TXT-запись создана для домена %1")
                      .arg(QString::fromStdString(domain)));
    }

    void stegoDecode() {
        const std::string txt  = sdTxt_->toPlainText().trimmed().toStdString();
        const std::string pass = sdPass_->text().toStdString();
        if (txt.empty() || pass.empty()) {
            warn(tr("Укажите TXT-запись и пароль.")); return;
        }
        std::vector<uint8_t> vpk;
        if (!ncp::spa_base64_decode(sdVerifyPub_->text().trimmed().toStdString(), vpk) ||
            vpk.size() != 32) {
            warn(tr("Verify-pubkey должен быть base64 32-байтного ключа.")); return;
        }
        std::array<uint8_t, 32> pk{};
        std::copy(vpk.begin(), vpk.end(), pk.begin());

        ncp::StegoDnsDecoder decoder(pass, pk);
        const uint64_t now = static_cast<uint64_t>(QDateTime::currentSecsSinceEpoch());
        const auto params = decoder.decode_txt(txt, now);
        if (!params) {
            sdOut_->setPlainText(tr("Ошибка декодирования: неверная запись, подпись, "
                                    "пароль или запись истекла."));
            return;
        }
        sdOut_->setPlainText(
            tr("ip:          %1.%2.%3.%4\n"
               "port:        %5\n"
               "spa_pubkey:  %6\n"
               "expires:     %7")
                .arg(params->ipv4[0]).arg(params->ipv4[1])
                .arg(params->ipv4[2]).arg(params->ipv4[3])
                .arg(params->port)
                .arg(QString::fromStdString(
                    ncp::spa_base64_encode(params->spa_pubkey.data(), 32)))
                .arg(params->expires_unix == 0
                         ? tr("никогда")
                         : QDateTime::fromSecsSinceEpoch(params->expires_unix)
                               .toString(Qt::ISODate)));
        appendLog(tr("[stegodns] запись декодирована: %1:%2")
                      .arg(QStringLiteral("%1.%2.%3.%4")
                               .arg(params->ipv4[0]).arg(params->ipv4[1])
                               .arg(params->ipv4[2]).arg(params->ipv4[3]))
                      .arg(params->port));
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Port-Hopping (ncp porthop serve | client)
    // ────────────────────────────────────────────────────────────────────────
    QGroupBox* buildPortHopGroup(QWidget* parent) {
        auto* box = new QGroupBox(tr("Port-Hopping — UDP-транспорт со сменой портов"), parent);
        auto* v = new QVBoxLayout(box);

        // Shared HopSchedule parameters (used by both serve and client).
        auto* schedBox = new QGroupBox(tr("Расписание портов (общее для serve/client)"), box);
        auto* sf = new QFormLayout(schedBox);
        phBasePort_ = new QLineEdit(QStringLiteral("40000"), schedBox);
        phRange_    = new QLineEdit(QStringLiteral("16"), schedBox);
        phSecret_   = new QLineEdit(schedBox);
        phSecret_->setEchoMode(QLineEdit::Password);
        phSecret_->setPlaceholderText(tr("общий секрет расписания"));
        phInterval_ = new QLineEdit(QStringLiteral("60"), schedBox);
        sf->addRow(tr("Базовый порт:"), phBasePort_);
        sf->addRow(tr("Диапазон:"), phRange_);
        sf->addRow(tr("Секрет:"), phSecret_);
        sf->addRow(tr("Интервал смены (с):"), phInterval_);

        // ── serve (daemon) ──
        auto* svBox = new QGroupBox(tr("Сервер (porthop serve)"), box);
        auto* svf = new QFormLayout(svBox);
        phSessions_ = new QLineEdit(svBox);
        phSessions_->setPlaceholderText(
            tr("session-id через запятую; пусто = демо 0x1122334455667788"));
        phStatus_ = new QLabel(tr("не запущен"), svBox);
        auto* svBtns = new QHBoxLayout;
        auto* svStart = new QPushButton(tr("Старт"), svBox);
        auto* svStop  = new QPushButton(tr("Стоп"), svBox);
        svBtns->addWidget(svStart);
        svBtns->addWidget(svStop);
        svBtns->addStretch(1);
        svBtns->addWidget(new QLabel(tr("Статус:"), svBox));
        svBtns->addWidget(phStatus_);
        svf->addRow(tr("Session-id:"), phSessions_);
        svf->addRow(QString(), svBtns);

        // ── client (one-shot) ──
        auto* clBox = new QGroupBox(tr("Клиент (porthop client)"), box);
        auto* cf = new QFormLayout(clBox);
        phClientHost_ = new QLineEdit(clBox);
        phClientHost_->setPlaceholderText(tr("IP сервера"));
        phClientMsg_ = new QLineEdit(clBox);
        phClientMsg_->setPlaceholderText(tr("сообщение для echo"));
        phClientSid_ = new QLineEdit(clBox);
        phClientSid_->setPlaceholderText(tr("пусто = демо 0x1122334455667788"));
        auto* sendBtn = new QPushButton(tr("Отправить"), clBox);
        cf->addRow(tr("Хост:"), phClientHost_);
        cf->addRow(tr("Сообщение:"), phClientMsg_);
        cf->addRow(tr("Session-id:"), phClientSid_);
        cf->addRow(QString(), sendBtn);

        // Shared schedule validation; fills args with --base-port/--range/
        // --secret/--hop-interval. Returns false after warning on bad input.
        auto appendSchedule = [this](QStringList& args) -> bool {
            int base = 0, range = 0;
            bool ok = false;
            if (!parsePort(phBasePort_->text(), base)) {
                warn(tr("Базовый порт должен быть числом 1-65535.")); return false;
            }
            const int r = phRange_->text().trimmed().toInt(&ok);
            if (!ok || r <= 0 || r > 65535 || base + r > 65536) {
                warn(tr("Диапазон портов некорректен (base+range > 65536).")); return false;
            }
            range = r;
            if (phSecret_->text().isEmpty()) {
                warn(tr("Укажите общий секрет расписания.")); return false;
            }
            const int interval = phInterval_->text().trimmed().toInt(&ok);
            if (!ok || interval <= 0) {
                warn(tr("Интервал смены должен быть положительным числом секунд.")); return false;
            }
            args << QStringLiteral("--base-port") << QString::number(base)
                 << QStringLiteral("--range") << QString::number(range)
                 << QStringLiteral("--secret") << phSecret_->text()
                 << QStringLiteral("--hop-interval") << QString::number(interval);
            return true;
        };

        connect(svStart, &QPushButton::clicked, this, [this, appendSchedule] {
            QStringList args{QStringLiteral("porthop"), QStringLiteral("serve")};
            if (!appendSchedule(args)) return;
            const QString sessions = phSessions_->text().trimmed();
            if (!sessions.isEmpty()) {
                const auto parts = sessions.split(QLatin1Char(','), Qt::SkipEmptyParts);
                for (const QString& raw : parts) {
                    const QString sid = raw.trimmed();
                    bool ok = false;
                    sid.toULongLong(&ok, 0);
                    if (!ok) {
                        warn(tr("Некорректный session-id: %1").arg(sid)); return;
                    }
                    args << QStringLiteral("--session-id") << sid;
                }
            }
            startDaemon(&phProc_, phStatus_, QStringLiteral("PortHop"), args);
        });
        connect(svStop, &QPushButton::clicked, this, [this] {
            stopDaemon(&phProc_, phStatus_, QStringLiteral("PortHop"));
        });
        connect(sendBtn, &QPushButton::clicked, this, [this, appendSchedule] {
            const QString host = phClientHost_->text().trimmed();
            const QString msg  = phClientMsg_->text();
            if (host.isEmpty() || msg.isEmpty()) {
                warn(tr("Укажите хост и сообщение.")); return;
            }
            QStringList args{QStringLiteral("porthop"), QStringLiteral("client")};
            if (!appendSchedule(args)) return;
            args << QStringLiteral("--host") << host
                 << QStringLiteral("--message") << msg;
            const QString sid = phClientSid_->text().trimmed();
            if (!sid.isEmpty()) {
                bool ok = false;
                sid.toULongLong(&ok, 0);
                if (!ok) { warn(tr("Некорректный session-id: %1").arg(sid)); return; }
                args << QStringLiteral("--session-id") << sid;
            }
            runOnce(args);
        });

        v->addWidget(schedBox);
        v->addWidget(svBox);
        v->addWidget(clBox);
        return box;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Fog (ncp fog node)
    // ────────────────────────────────────────────────────────────────────────
    QGroupBox* buildFogGroup(QWidget* parent) {
        auto* box = new QGroupBox(tr("Fog — кооперативный mesh-узел"), parent);
        auto* form = new QFormLayout(box);

        fogId_ = new QLineEdit(box);
        fogId_->setPlaceholderText(tr("32 hex-символа (16 байт id узла)"));
        fogId_->setFont(mono());
        fogPort_ = new QLineEdit(box);
        fogPort_->setPlaceholderText(tr("UDP-порт"));
        fogPeers_ = new QLineEdit(box);
        fogPeers_->setPlaceholderText(tr("ip:port через запятую (необязательно)"));
        fogStatus_ = new QLabel(tr("не запущен"), box);

        auto* btns = new QHBoxLayout;
        auto* startBtn = new QPushButton(tr("Старт"), box);
        auto* stopBtn  = new QPushButton(tr("Стоп"), box);
        btns->addWidget(startBtn);
        btns->addWidget(stopBtn);
        btns->addStretch(1);
        btns->addWidget(new QLabel(tr("Статус:"), box));
        btns->addWidget(fogStatus_);

        form->addRow(tr("ID узла:"), fogId_);
        form->addRow(tr("UDP-порт:"), fogPort_);
        form->addRow(tr("Peers:"), fogPeers_);
        form->addRow(QString(), btns);

        connect(startBtn, &QPushButton::clicked, this, [this] {
            const QString id = fogId_->text().trimmed();
            int port = 0;
            if (!isHex32(id)) {
                warn(tr("ID узла должен быть ровно 32 hex-символа (16 байт).")); return;
            }
            if (!parsePort(fogPort_->text(), port)) {
                warn(tr("UDP-порт должен быть числом 1-65535.")); return;
            }
            QStringList args{QStringLiteral("fog"), QStringLiteral("node"),
                             QStringLiteral("--id"), id,
                             QStringLiteral("--port"), QString::number(port)};
            const QString peers = fogPeers_->text().trimmed();
            if (!peers.isEmpty()) {
                const auto parts = peers.split(QLatin1Char(','), Qt::SkipEmptyParts);
                for (const QString& raw : parts) {
                    const QString peer = raw.trimmed();
                    QString ph;
                    int pp = 0;
                    if (!splitHostPort(peer, ph, pp)) {
                        warn(tr("Peer должен быть в форме ip:port: %1").arg(peer)); return;
                    }
                    args << QStringLiteral("--peer") << peer;
                }
            }
            startDaemon(&fogProc_, fogStatus_, QStringLiteral("Fog"), args);
        });
        connect(stopBtn, &QPushButton::clicked, this, [this] {
            stopDaemon(&fogProc_, fogStatus_, QStringLiteral("Fog"));
        });
        return box;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  XDP (ncp xdp probe | stats | drop) — Linux only
    // ────────────────────────────────────────────────────────────────────────
    QGroupBox* buildXdpGroup(QWidget* parent) {
        auto* box = new QGroupBox(tr("XDP (eBPF) — обработка пакетов в ядре"), parent);
        auto* form = new QFormLayout(box);

        auto* note = new QLabel(tr("Доступно только на Linux. compile/attach/detach "
                                   "требуют root и намеренно доступны только в CLI."), box);
        note->setWordWrap(true);
        form->addRow(note);

        auto* probeBtn = new QPushButton(tr("Probe — проверить поддержку BPF"), box);
        form->addRow(QString(), probeBtn);
        connect(probeBtn, &QPushButton::clicked, this, [this] {
            runOnce({QStringLiteral("xdp"), QStringLiteral("probe")});
        });

        xdpStatsPort_ = new QLineEdit(box);
        xdpStatsPort_->setPlaceholderText(tr("dport"));
        auto* statsRow = new QHBoxLayout;
        statsRow->addWidget(xdpStatsPort_, 1);
        auto* statsBtn = new QPushButton(tr("Статистика UDP"), box);
        statsRow->addWidget(statsBtn);
        form->addRow(tr("Stats порт:"), statsRow);
        connect(statsBtn, &QPushButton::clicked, this, [this] {
            int port = 0;
            if (!parsePortAllowZero(xdpStatsPort_->text(), port)) {
                warn(tr("Порт должен быть числом 0-65535.")); return;
            }
            runOnce({QStringLiteral("xdp"), QStringLiteral("stats"),
                     QString::number(port)});
        });

        xdpDropPort_ = new QLineEdit(box);
        xdpDropPort_->setPlaceholderText(tr("dport"));
        auto* dropRow = new QHBoxLayout;
        dropRow->addWidget(xdpDropPort_, 1);
        auto* dropSetBtn   = new QPushButton(tr("Drop: задать"), box);
        auto* dropClearBtn = new QPushButton(tr("Drop: снять"), box);
        dropRow->addWidget(dropSetBtn);
        dropRow->addWidget(dropClearBtn);
        form->addRow(tr("Drop порт:"), dropRow);
        connect(dropSetBtn, &QPushButton::clicked, this, [this] {
            int port = 0;
            if (!parsePort(xdpDropPort_->text(), port)) {
                warn(tr("Порт должен быть числом 1-65535.")); return;
            }
            runOnce({QStringLiteral("xdp"), QStringLiteral("drop"),
                     QString::number(port)});
        });
        connect(dropClearBtn, &QPushButton::clicked, this, [this] {
            runOnce({QStringLiteral("xdp"), QStringLiteral("drop"),
                     QStringLiteral("0")});
        });

#ifndef Q_OS_LINUX
        box->setEnabled(false);
        box->setTitle(tr("XDP (eBPF) — только Linux"));
#endif
        return box;
    }

    // ────────────────────────────────────────────────────────────────────────
    //  Process plumbing + helpers
    // ────────────────────────────────────────────────────────────────────────

    /// One-shot command: run through DriverController, log redacted cmdline
    /// and full output.
    void runOnce(const QStringList& args) {
        appendLog(tr("[ui] ncp %1").arg(redactArgs(args).join(QLatin1Char(' '))));
        ncp::GUI::DriverController::runNcpCommand(
            this, args, [this](int code, const QString& out) {
                const QString text = out.trimmed();
                if (!text.isEmpty())
                    appendLog(text);
                appendLog(tr("[*] команда завершена, код %1").arg(code));
            });
    }

    /// Long-running daemon. slot points at the owning QProcess* member; on
    /// spontaneous exit the slot is nulled and the status label reset.
    void startDaemon(QProcess** slot, QLabel* status, const QString& title,
                     const QStringList& args) {
        QProcess*& proc = *slot;
        if (proc && proc->state() != QProcess::NotRunning) {
            appendLog(tr("[!] %1 уже запущен").arg(title));
            return;
        }
        const QString exe = ncp::GUI::DriverController::findNcpExe();
        if (exe.isEmpty()) {
            appendLog(tr("[!] %1: ncp CLI не найден рядом с приложением.").arg(title));
            return;
        }
        if (proc) {  // stale, already-finished process (e.g. failed start)
            proc->disconnect(this);
            delete proc;
            proc = nullptr;
        }
        proc = new QProcess(this);
        proc->setProcessChannelMode(QProcess::MergedChannels);
        QProcess* p = proc;
        connect(proc, &QProcess::readyRead, this, [this, p, title] {
            const QString chunk = QString::fromLocal8Bit(p->readAll());
            const auto lines = chunk.split(QLatin1Char('\n'));
            for (const QString& raw : lines) {
                const QString line = raw.trimmed();
                if (!line.isEmpty())
                    appendLog(QStringLiteral("[%1] %2").arg(title, line));
            }
        });
        connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, [this, p, slot, status, title](int code, QProcess::ExitStatus) {
            appendLog(tr("[*] %1 завершён (код %2)").arg(title).arg(code));
            if (*slot == p) *slot = nullptr;
            if (status) status->setText(tr("не запущен"));
            p->deleteLater();
        });
        connect(proc, &QProcess::errorOccurred, this, [this, title](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart)
                appendLog(tr("[!] %1: не удалось запустить (возможно, нужны "
                             "права администратора).").arg(title));
        });
        appendLog(tr("[ui] %1: ncp %2").arg(title, redactArgs(args).join(QLatin1Char(' '))));
        proc->start(exe, args);
        if (proc->waitForStarted(5000)) {
            if (status) status->setText(tr("работает"));
        } else {
            if (status) status->setText(tr("не запущен"));
        }
    }

    void stopDaemon(QProcess** slot, QLabel* status, const QString& title) {
        QProcess*& proc = *slot;
        if (!proc) return;
        proc->disconnect(this);  // no more callbacks into this panel
        if (proc->state() != QProcess::NotRunning) {
            proc->terminate();
            if (!proc->waitForFinished(3000)) {
                proc->kill();
                proc->waitForFinished(2000);
            }
            appendLog(tr("[*] %1: остановлено").arg(title));
        }
        delete proc;
        proc = nullptr;
        if (status) status->setText(tr("не запущен"));
    }

    void appendLog(const QString& line) {
        if (log_)
            log_->appendPlainText(line);
    }

    void browseFile(QLineEdit* edit) {
        const QString path = QFileDialog::getOpenFileName(this, tr("Выбор файла"));
        if (!path.isEmpty())
            edit->setText(path);
    }

    void warn(const QString& msg) {
        QMessageBox::warning(this, tr("Проверка полей"), msg);
    }

    // ── validation / parsing helpers ──

    static bool parsePort(const QString& s, int& port) {
        bool ok = false;
        port = s.trimmed().toInt(&ok);
        return ok && port > 0 && port <= 65535;
    }

    static bool parsePortAllowZero(const QString& s, int& port) {
        bool ok = false;
        port = s.trimmed().toInt(&ok);
        return ok && port >= 0 && port <= 65535;
    }

    static bool splitHostPort(const QString& s, QString& host, int& port) {
        const QString t = s.trimmed();
        const int idx = t.lastIndexOf(QLatin1Char(':'));
        if (idx <= 0 || idx >= t.size() - 1)
            return false;
        host = t.left(idx);
        return parsePort(t.mid(idx + 1), port);
    }

    static bool isHex32(const QString& s) {
        if (s.size() != 32)
            return false;
        for (const QChar c : s) {
            const bool hex = (c >= QLatin1Char('0') && c <= QLatin1Char('9')) ||
                             (c >= QLatin1Char('a') && c <= QLatin1Char('f')) ||
                             (c >= QLatin1Char('A') && c <= QLatin1Char('F'));
            if (!hex)
                return false;
        }
        return true;
    }

    /// Replace values of secret-bearing options with "***" before logging.
    static QStringList redactArgs(const QStringList& args) {
        static const QStringList secretOpts{
            QStringLiteral("--secret"),       QStringLiteral("--passphrase"),
            QStringLiteral("--key"),          QStringLiteral("--key-file"),
            QStringLiteral("--signing-key"),  QStringLiteral("--authorized-keys"),
        };
        QStringList out = args;
        for (int i = 1; i < out.size(); ++i)
            if (secretOpts.contains(out.at(i - 1)))
                out[i] = QStringLiteral("***");
        return out;
    }

    /// Signing key for stegodns encode: raw 64-byte Ed25519 secret, a
    /// 96-byte `ncp spa keygen` keyfile (sk || pk — trimmed to 64) or base64
    /// of either. Mirrors stegodns_load_signing_key() in src/cli/main.cpp.
    static bool loadSigningKey(const QString& path, std::array<uint8_t, 64>& sk) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly))
            return false;
        QByteArray raw = f.readAll();
        while (!raw.isEmpty() &&
               (raw.endsWith('\n') || raw.endsWith('\r') ||
                raw.endsWith(' ') || raw.endsWith('\t')))
            raw.chop(1);
        std::vector<uint8_t> bytes(raw.begin(), raw.end());
        if (bytes.size() != 64 && bytes.size() != 96) {
            std::vector<uint8_t> dec;
            if (ncp::spa_base64_decode(QString::fromUtf8(raw).toStdString(), dec))
                bytes = std::move(dec);
        }
        if (bytes.size() == 96)
            bytes.resize(64);
        if (bytes.size() != 64)
            return false;
        std::copy(bytes.begin(), bytes.end(), sk.begin());
        return true;
    }

    static QFont mono() {
        QFont f;
        f.setStyleHint(QFont::Monospace);
        f.setFamily(QStringLiteral("Menlo"));
        return f;
    }

    // ── daemon processes ──
    QProcess* spaProc_     = nullptr;
    QProcess* realityProc_ = nullptr;
    QProcess* phProc_      = nullptr;
    QProcess* fogProc_     = nullptr;

    // ── shared log ──
    QPlainTextEdit* log_ = nullptr;

    // ── SPA widgets ──
    QLineEdit* spaKeygenPrefix_ = nullptr;
    QLineEdit* spaKnockHost_ = nullptr;
    QLineEdit* spaKnockPort_ = nullptr;
    QLineEdit* spaKnockAllowPort_ = nullptr;
    QComboBox* spaKnockProto_ = nullptr;
    QLineEdit* spaKnockTtl_ = nullptr;
    QLineEdit* spaKnockKey_ = nullptr;
    QCheckBox* spaKnockTwice_ = nullptr;
    QLineEdit* spaServeKeys_ = nullptr;
    QLineEdit* spaServePort_ = nullptr;
    QLineEdit* spaServeBind_ = nullptr;
    QCheckBox* spaServeDry_ = nullptr;
    QLabel*    spaServeStatus_ = nullptr;

    // ── Reality widgets ──
    QLineEdit* rlListen_ = nullptr;
    QLineEdit* rlFallback_ = nullptr;
    QLineEdit* rlInternal_ = nullptr;
    QLineEdit* rlKeyFile_ = nullptr;
    QLabel*    rlStatus_ = nullptr;

    // ── Stego-DNS widgets ──
    QLineEdit* seIp_ = nullptr;
    QLineEdit* sePort_ = nullptr;
    QLineEdit* seSpaPub_ = nullptr;
    QLineEdit* sePass_ = nullptr;
    QLineEdit* seSignKey_ = nullptr;
    QLineEdit* seDomain_ = nullptr;
    QLineEdit* seExpires_ = nullptr;
    QPlainTextEdit* seOut_ = nullptr;
    QLineEdit* seVerifyKey_ = nullptr;
    QPlainTextEdit* sdTxt_ = nullptr;
    QLineEdit* sdPass_ = nullptr;
    QLineEdit* sdVerifyPub_ = nullptr;
    QPlainTextEdit* sdOut_ = nullptr;

    // ── Port-Hopping widgets ──
    QLineEdit* phBasePort_ = nullptr;
    QLineEdit* phRange_ = nullptr;
    QLineEdit* phSecret_ = nullptr;
    QLineEdit* phInterval_ = nullptr;
    QLineEdit* phSessions_ = nullptr;
    QLabel*    phStatus_ = nullptr;
    QLineEdit* phClientHost_ = nullptr;
    QLineEdit* phClientMsg_ = nullptr;
    QLineEdit* phClientSid_ = nullptr;

    // ── Fog widgets ──
    QLineEdit* fogId_ = nullptr;
    QLineEdit* fogPort_ = nullptr;
    QLineEdit* fogPeers_ = nullptr;
    QLabel*    fogStatus_ = nullptr;

    // ── XDP widgets ──
    QLineEdit* xdpStatsPort_ = nullptr;
    QLineEdit* xdpDropPort_ = nullptr;
};
