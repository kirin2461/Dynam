#pragma once

// In-process controller: owns DesyncProxy (+ optional managed Tor) and
// exposes it to Qt via queued signals. No subprocess, no web backend —
// the Qt6 GUI drives ncp_core directly.
//
// Threading contract (v1.9.1 hardening):
//  - requestStart() spawns a worker thread; startInternal() runs ONLY there.
//  - startInternal() never calls stop() (a thread must never join itself).
//  - proxy_/tor_/chain_label_ are guarded by state_mtx_; readers from the
//    GUI thread (stats(), boundPort(), chainLabel()) take the same lock.
//  - stop() may be called from any thread EXCEPT the worker itself.

#include <QObject>
#include <QString>
#include <QStringList>
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

#include "ncp_proxy.hpp"
#include "ncp_tor_manager.hpp"

namespace ncp::GUI {

struct GuiProxyConfig {
    uint16_t port = 1080;
    bool doh = true;
    bool block_quic = false;
    int fake_quic = 0;
    int split_pos = 2;
    bool split_sni = true;
    QString upstream;        // "socks5://host:port" | "http://host:port" | ""
    QString tor_binary;      // managed Tor (empty = off)
    QString pt_obfs4;
    QString pt_snowflake;
    QStringList bridges;
    QString license_key;     // reserved (gate handled by LicenseInfo)
};

class ProxyController : public QObject {
    Q_OBJECT
public:
    explicit ProxyController(QObject* parent = nullptr);
    ~ProxyController() override;

    // Non-blocking: heavy work (managed-Tor bootstrap) runs on a worker
    // thread; result arrives via startFinished(bool, QString).
    void requestStart(const GuiProxyConfig& cfg);
    void stop();

    bool running() const { return running_.load(); }
    bool starting() const { return starting_.load(); }
    uint16_t boundPort() const;
    ncp::ProxyStats stats() const;
    QString chainLabel() const;
    GuiProxyConfig config() const { return cfg_; }

    std::deque<QString> drainLogs();

signals:
    void startFinished(bool ok, const QString& message);
    void logLine(const QString& line);

private:
    bool startInternal(const GuiProxyConfig& cfg, QString* err);
    // Joins the worker if it is joinable and we are NOT the worker thread.
    // A thread joining itself throws std::system_error -> terminate (was the
    // v1.9.0 crash-on-start bug).
    void joinWorker();

    // Guarded by state_mtx_ (GUI thread reads stats while worker commits).
    mutable std::mutex state_mtx_;
    std::unique_ptr<ncp::DesyncProxy> proxy_;
    std::unique_ptr<ncp::TorManager> tor_;
    QString chain_label_;

    GuiProxyConfig cfg_;
    std::atomic<bool> running_{false};
    std::atomic<bool> starting_{false};
    std::thread worker_;

    mutable std::mutex log_mtx_;
    std::deque<QString> logs_;
    void pushLog(const std::string& line);
};

} // namespace ncp::GUI
