#pragma once

#include <QWidget>
#include <QElapsedTimer>

class QLabel;

// Process uptime / memory / packet counters.
class SystemStats : public QWidget {
    Q_OBJECT
public:
    explicit SystemStats(QWidget* parent = nullptr);

    // API-compatible with the original skeleton call:
    // updateStats(bytes_sent, bytes_received, packets_sent, packets_received)
    void updateStats(uint64_t bytesSent, uint64_t bytesRecv,
                     uint64_t packetsSent, uint64_t packetsRecv);

private:
    QLabel* uptime_;
    QLabel* memory_;
    QLabel* packets_;
    QElapsedTimer started_;
};
