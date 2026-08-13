#include "ModulesPanel.hpp"

#include <QGridLayout>
#include <QLabel>

namespace {
QString dotFor(int state) {
    switch (state) {
        case 1:  return QStringLiteral("<span style='color:#4caf50'>&#9679;</span> активен");
        case 2:  return QStringLiteral("<span style='color:#e05252'>&#9679;</span> ошибка");
        default: return QStringLiteral("<span style='color:#777'>&#9679;</span> ожидание");
    }
}
} // namespace

ModulesPanel::ModulesPanel(QWidget* parent) : QWidget(parent) {
    // Modules reported by `ncp.exe run` (see web GUI debug log) in
    // approximately the order they initialise.
    order_ = {
        QStringLiteral("Спуфинг (DNS/IP)"),
        QStringLiteral("DPI пресет"),
        QStringLiteral("TLS Fingerprint"),
        QStringLiteral("Advanced DPI bypass"),
        QStringLiteral("Paranoid Mode"),
        QStringLiteral("DNS Leak Prevention"),
        QStringLiteral("L3 Stealth"),
        QStringLiteral("RTT Equalizer"),
        QStringLiteral("Volume Normalizer"),
        QStringLiteral("WF Defense (Tamaraw)"),
        QStringLiteral("Behavioral Cloak"),
        QStringLiteral("Time Correlation Breaker"),
        QStringLiteral("Self-Test Monitor"),
        QStringLiteral("Session Fragmenter"),
        QStringLiteral("Cross-Layer Correlator"),
        QStringLiteral("Geneva Engine"),
        QStringLiteral("Covert Channel"),
        QStringLiteral("Protocol Rotation"),
        QStringLiteral("AS-Aware Router"),
        QStringLiteral("Geo Obfuscator"),
        QStringLiteral("Zapret профиль"),
    };

    auto* lay = new QGridLayout(this);
    lay->setContentsMargins(6, 6, 6, 6);
    lay->setHorizontalSpacing(14);

    auto* title = new QLabel(QStringLiteral("<b>Модули защиты</b>"), this);
    lay->addWidget(title, 0, 0, 1, 2);

    driverStateLabel_ = new QLabel(
        QStringLiteral("драйвер: <span style='color:#777'>остановлен</span>"), this);
    lay->addWidget(driverStateLabel_, 0, 2, 1, 2);

    const int cols = 2;  // two name+status pairs per row
    for (int i = 0; i < order_.size(); ++i) {
        const int row = 1 + i / cols;
        const int col = (i % cols) * 2;
        auto* name = new QLabel(order_[i], this);
        auto* status = new QLabel(dotFor(0), this);
        status->setTextFormat(Qt::RichText);
        lay->addWidget(name, row, col);
        lay->addWidget(status, row, col + 1);
        statusLabels_.insert(order_[i], status);
    }
}

void ModulesPanel::setModuleStatus(const QString& module, int state) {
    QLabel* lbl = statusLabels_.value(module, nullptr);
    if (!lbl) return;  // unknown module — ignore (kept strict to avoid drift)
    lbl->setText(dotFor(state));
}

void ModulesPanel::resetStatuses() {
    for (auto* lbl : statusLabels_)
        lbl->setText(dotFor(0));
}

void ModulesPanel::setDriverState(const QString& text, bool active) {
    driverStateLabel_->setText(QStringLiteral("драйвер: <span style='color:%1'>%2</span>")
        .arg(active ? QStringLiteral("#4caf50") : QStringLiteral("#777"), text));
}
