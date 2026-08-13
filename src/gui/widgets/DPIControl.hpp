#pragma once

#include <QWidget>

class QCheckBox;
class QSpinBox;
class QComboBox;
class QLineEdit;

// DPI bypass strategy controls: proxy-mode (in-process) + driver-mode
// (`ncp.exe run` — Geneva/Covert/zapret, parity with the Web UI).
class DPIControl : public QWidget {
    Q_OBJECT
public:
    explicit DPIControl(QWidget* parent = nullptr);

    // --- proxy mode (in-process SOCKS5) ---
    int splitPos() const;
    bool splitSni() const;
    int fakeQuic() const;
    bool blockQuic() const;
    bool dohEnabled() const;
    void setBypassEnabled(bool enabled);

    // --- driver mode (`ncp.exe run`) ---
    QString driverInterface() const;
    QString driverPreset() const;
    QString driverZapretProfile() const;   // "" = off
    QString driverZapretChains() const;    // "" = none (custom csv chains)
    bool driverCovert() const;
    void setDriverOptions(const QString& iface, const QString& preset,
                          const QString& zapret, bool covert,
                          const QString& chains = QString());
    /// Fill the interface dropdown (from `ncp network interfaces`).
    void setInterfaces(const QStringList& ifaces);

signals:
    void bypassToggled(bool enabled);
    void techniqueChanged(int index);

private:
    QCheckBox* enableBox_;
    QComboBox* presetCombo_;
    QSpinBox* splitPosSpin_;
    QCheckBox* sniBox_;
    QSpinBox* fakeQuicSpin_;
    QCheckBox* blockQuicBox_;
    QCheckBox* dohBox_;

    // driver mode
    QComboBox* ifaceCombo_;
    QComboBox* driverPresetCombo_;
    QComboBox* zapretCombo_;
    QLineEdit* chainsEdit_;
    QCheckBox* covertBox_;
};
