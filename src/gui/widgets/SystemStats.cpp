#include "SystemStats.hpp"

#include <QFormLayout>
#include <QLabel>
#include <QVBoxLayout>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <psapi.h>
#else
#  include <sys/resource.h>
#endif

SystemStats::SystemStats(QWidget* parent) : QWidget(parent) {
    started_.start();
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(QStringLiteral("<b>Система</b>"), this));

    auto* form = new QFormLayout();
    uptime_ = new QLabel("0:00:00", this);
    memory_ = new QLabel("—", this);
    packets_ = new QLabel("0 / 0", this);
    form->addRow(QStringLiteral("Аптайм:"), uptime_);
    form->addRow(QStringLiteral("Память процесса:"), memory_);
    form->addRow(QStringLiteral("Пакеты (tx/rx):"), packets_);
    lay->addLayout(form);
    lay->addStretch(1);
}

void SystemStats::updateStats(uint64_t bytesSent, uint64_t bytesRecv,
                              uint64_t packetsSent, uint64_t packetsRecv) {
    Q_UNUSED(bytesSent);
    Q_UNUSED(bytesRecv);
    qint64 secs = started_.elapsed() / 1000;
    uptime_->setText(QStringLiteral("%1:%2:%3")
        .arg(secs / 3600)
        .arg((secs / 60) % 60, 2, 10, QLatin1Char('0'))
        .arg(secs % 60, 2, 10, QLatin1Char('0')));
    packets_->setText(QStringLiteral("%1 / %2").arg(packetsSent).arg(packetsRecv));

#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        memory_->setText(QStringLiteral("%1 МБ")
            .arg(pmc.WorkingSetSize / (1024.0 * 1024.0), 0, 'f', 1));
#else
    struct rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        memory_->setText(QStringLiteral("%1 МБ").arg(ru.ru_maxrss / 1024.0, 0, 'f', 1));
#endif
}
