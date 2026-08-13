#pragma once

#include <QWidget>
#include "ncp_proxy.hpp"

class QLabel;

// Live counters from DesyncProxy::stats().
class NetworkMonitor : public QWidget {
    Q_OBJECT
public:
    explicit NetworkMonitor(QWidget* parent = nullptr);

    void setStats(const ncp::ProxyStats& s);
    void refresh();  // API compat with the original skeleton

private:
    QLabel* connTotal_;
    QLabel* connActive_;
    QLabel* bytesUp_;
    QLabel* bytesDown_;
    QLabel* splits_;
    QLabel* quicBlocked_;

    static QString humanBytes(uint64_t b);
};
