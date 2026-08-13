#pragma once

#include <QHash>
#include <QString>
#include <QStringList>
#include <QWidget>

class QLabel;

/**
 * @brief Module status grid (v1.9.2).
 *
 * Shows the state of every protection module that `ncp.exe run` reports
 * (Geneva Engine, Covert Channel, DNS Leak Prevention, zapret chains, ...).
 * States: ожидание (grey) / активен (green) / ошибка (red).
 * This mirrors the module visibility the Web UI provides, which was missing
 * from the Qt GUI.
 */
class ModulesPanel : public QWidget {
    Q_OBJECT
public:
    explicit ModulesPanel(QWidget* parent = nullptr);

    /// state: 0 = unknown/waiting, 1 = active, 2 = failed.
    void setModuleStatus(const QString& module, int state);
    /// Back to all-grey (driver stopped).
    void resetStatuses();
    /// Header note, e.g. "драйвер: запущен" / "драйвер: остановлен".
    void setDriverState(const QString& text, bool active);

private:
    QLabel* driverStateLabel_ = nullptr;
    QHash<QString, QLabel*> statusLabels_;
    QStringList order_;
};
