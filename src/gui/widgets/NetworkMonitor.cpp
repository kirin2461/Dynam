#include "NetworkMonitor.hpp"

#include <QFormLayout>
#include <QLabel>
#include <QVBoxLayout>

NetworkMonitor::NetworkMonitor(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(QStringLiteral("<b>Сетевой монитор</b>"), this));

    auto* form = new QFormLayout();
    connTotal_ = new QLabel("0", this);
    connActive_ = new QLabel("0", this);
    bytesUp_ = new QLabel("0 Б", this);
    bytesDown_ = new QLabel("0 Б", this);
    splits_ = new QLabel("0", this);
    quicBlocked_ = new QLabel("0", this);

    form->addRow(QStringLiteral("Соединений всего:"), connTotal_);
    form->addRow(QStringLiteral("Активных:"), connActive_);
    form->addRow(QStringLiteral("Отправлено:"), bytesUp_);
    form->addRow(QStringLiteral("Получено:"), bytesDown_);
    form->addRow(QStringLiteral("Desync-сплитов:"), splits_);
    form->addRow(QStringLiteral("QUIC заблокировано:"), quicBlocked_);
    lay->addLayout(form);
    lay->addStretch(1);
}

QString NetworkMonitor::humanBytes(uint64_t b) {
    const char* units[] = {"Б", "КБ", "МБ", "ГБ"};
    double v = static_cast<double>(b);
    int u = 0;
    while (v >= 1024.0 && u < 3) { v /= 1024.0; ++u; }
    return QStringLiteral("%1 %2").arg(v, 0, 'f', u ? 1 : 0).arg(units[u]);
}

void NetworkMonitor::setStats(const ncp::ProxyStats& s) {
    connTotal_->setText(QString::number(s.connections_total));
    connActive_->setText(QString::number(s.connections_active));
    bytesUp_->setText(humanBytes(s.bytes_client_to_server));
    bytesDown_->setText(humanBytes(s.bytes_server_to_client));
    splits_->setText(QString::number(s.desync_splits_applied));
    quicBlocked_->setText(QString::number(s.quic_datagrams_blocked));
}

void NetworkMonitor::refresh() { /* stats pushed via setStats() */ }
