#include "ProxyController.hpp"

#include <QMetaObject>

namespace ncp::GUI {

ProxyController::ProxyController(QObject* parent) : QObject(parent) {}

ProxyController::~ProxyController() { stop(); }

void ProxyController::pushLog(const std::string& line) {
    {
        std::lock_guard<std::mutex> lk(log_mtx_);
        logs_.push_back(QString::fromStdString(line));
        while (logs_.size() > 2000) logs_.pop_front();
    }
    // queued delivery to the GUI thread
    QString q = QString::fromStdString(line);
    QMetaObject::invokeMethod(this, [this, q]() { emit logLine(q); },
                              Qt::QueuedConnection);
}

std::deque<QString> ProxyController::drainLogs() {
    std::lock_guard<std::mutex> lk(log_mtx_);
    std::deque<QString> out;
    out.swap(logs_);
    return out;
}

void ProxyController::requestStart(const GuiProxyConfig& cfg) {
    if (running_.load() || worker_.joinable()) return;
    cfg_ = cfg;
    worker_ = std::thread([this, cfg]() {
        QString err;
        bool ok = startInternal(cfg, &err);
        QMetaObject::invokeMethod(this, [this, ok, err]() {
            emit startFinished(ok, ok ? QString() : err);
        }, Qt::QueuedConnection);
    });
}

uint16_t ProxyController::boundPort() const {
    return proxy_ ? proxy_->bound_port() : 0;
}

ncp::ProxyStats ProxyController::stats() const {
    return proxy_ ? proxy_->stats() : ncp::ProxyStats{};
}

QString ProxyController::chainLabel() const { return chain_label_; }

bool ProxyController::startInternal(const GuiProxyConfig& cfg, QString* err) {
    stop();

    ncp::DesyncProxy::Config pc;
    pc.port = cfg.port;
    pc.listen_host = "127.0.0.1";
    pc.use_doh = cfg.doh;
    pc.block_quic = cfg.block_quic;
    pc.fake_quic_repeats = cfg.fake_quic;
    pc.base.enable_tcp_split = true;
    pc.base.split_position = cfg.split_pos;
    pc.base.split_at_sni = cfg.split_sni;
    pc.base.enable_noise = false;
    pc.base.enable_fake_packet = false;
    pc.base.enable_disorder = false;
    pc.log_cb = [this](const std::string& m) { pushLog(m); };

    chain_label_.clear();

    // Managed Tor (bridges hide Tor usage itself)
    if (!cfg.tor_binary.trimmed().isEmpty()) {
        tor_ = std::make_unique<ncp::TorManager>();
        ncp::TorLaunchConfig tc;
        tc.tor_binary = cfg.tor_binary.toStdString();
        tc.obfs4_binary = cfg.pt_obfs4.toStdString();
        tc.snowflake_binary = cfg.pt_snowflake.toStdString();
        for (const auto& b : cfg.bridges)
            if (!b.trimmed().isEmpty())
                tc.bridges.push_back(b.trimmed().toStdString());
        pushLog("[tor] запуск управляемого Tor (" +
                std::to_string(tc.bridges.size()) + " мостов)...");
        std::string terr;
        if (!tor_->start(tc, &terr)) {
            if (err) *err = QStringLiteral("Управляемый Tor не запустился: %1")
                                .arg(QString::fromStdString(terr));
            tor_.reset();
            return false;
        }
        pc.upstream_type = "socks5";
        pc.upstream_host = "127.0.0.1";
        pc.upstream_port = tor_->socks_port();
        chain_label_ = QStringLiteral("управляемый Tor + мосты (Tor скрыт), SOCKS5 127.0.0.1:%1")
                           .arg(tor_->socks_port());
        pushLog("[tor] Bootstrapped 100% — цепочка активна");
    } else if (!cfg.upstream.trimmed().isEmpty()) {
        // socks5://host:port | http://host:port
        QString u = cfg.upstream.trimmed();
        int scheme = u.indexOf("://");
        QString type = (scheme >= 0) ? u.left(scheme) : QStringLiteral("socks5");
        QString rest = (scheme >= 0) ? u.mid(scheme + 3) : u;
        if (type == "socks") type = "socks5";
        int colon = rest.lastIndexOf(':');
        bool portOk = false;
        int pnum = (colon >= 0) ? rest.mid(colon + 1).toInt(&portOk) : 0;
        if (colon < 0 || !portOk || pnum <= 0 || pnum > 65535 ||
            (type != "socks5" && type != "http")) {
            if (err) *err = QStringLiteral("Неверный upstream: %1 (нужно socks5://host:port)").arg(u);
            return false;
        }
        pc.upstream_type = type.toStdString();
        pc.upstream_host = rest.left(colon).toStdString();
        pc.upstream_port = static_cast<uint16_t>(pnum);
        chain_label_ = QStringLiteral("%1 — IP назначения скрыт от провайдера").arg(u);
    }

    proxy_ = std::make_unique<ncp::DesyncProxy>();
    if (!proxy_->start(pc)) {
        if (err) *err = QStringLiteral("Не удалось запустить прокси на 127.0.0.1:%1").arg(cfg.port);
        proxy_.reset();
        if (tor_) { tor_->stop(); tor_.reset(); }
        return false;
    }
    running_.store(true);
    pushLog("[proxy] запущен на 127.0.0.1:" + std::to_string(proxy_->bound_port()));
    return true;
}

void ProxyController::stop() {
    if (worker_.joinable()) worker_.join();
    running_.store(false);
    if (proxy_) {
        proxy_->stop();
        proxy_.reset();
        pushLog("[proxy] остановлен");
    }
    if (tor_) {
        tor_->stop();
        tor_.reset();
        pushLog("[tor] остановлен");
    }
    chain_label_.clear();
}

} // namespace ncp::GUI
