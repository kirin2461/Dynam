#pragma once

#include <QWidget>

class QCheckBox;
class QSpinBox;
class QComboBox;

// DPI bypass strategy controls.
class DPIControl : public QWidget {
    Q_OBJECT
public:
    explicit DPIControl(QWidget* parent = nullptr);

    int splitPos() const;
    bool splitSni() const;
    int fakeQuic() const;
    bool blockQuic() const;
    bool dohEnabled() const;
    void setBypassEnabled(bool enabled);

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
};
