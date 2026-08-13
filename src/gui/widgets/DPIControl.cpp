#include "DPIControl.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QSpinBox>
#include <QVBoxLayout>

DPIControl::DPIControl(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    auto* title = new QLabel(QStringLiteral("<b>Обход DPI</b>"), this);
    lay->addWidget(title);

    enableBox_ = new QCheckBox(QStringLiteral("Включить обход при запуске"), this);
    enableBox_->setChecked(true);
    lay->addWidget(enableBox_);

    auto* form = new QFormLayout();
    presetCombo_ = new QComboBox(this);
    presetCombo_->addItem(QStringLiteral("split-2 + SNI (по умолчанию)"));
    presetCombo_->addItem(QStringLiteral("split-1 (агрессивный)"));
    presetCombo_->addItem(QStringLiteral("split-4 + SNI"));
    presetCombo_->addItem(QStringLiteral("только SNI"));
    form->addRow(QStringLiteral("Пресет:"), presetCombo_);

    splitPosSpin_ = new QSpinBox(this);
    splitPosSpin_->setRange(1, 16);
    splitPosSpin_->setValue(2);
    form->addRow(QStringLiteral("Позиция сплита:"), splitPosSpin_);

    sniBox_ = new QCheckBox(QStringLiteral("Сплит на SNI/Host"), this);
    sniBox_->setChecked(true);
    form->addRow(QString(), sniBox_);

    fakeQuicSpin_ = new QSpinBox(this);
    fakeQuicSpin_->setRange(0, 10);
    form->addRow(QStringLiteral("Фейковые QUIC Initial:"), fakeQuicSpin_);

    blockQuicBox_ = new QCheckBox(QStringLiteral("Блокировать QUIC (принудительно TCP)"), this);
    form->addRow(QString(), blockQuicBox_);

    dohBox_ = new QCheckBox(QStringLiteral("DoH-резолв (обход DNS-блокировок)"), this);
    dohBox_->setChecked(true);
    form->addRow(QString(), dohBox_);

    lay->addLayout(form);
    lay->addStretch(1);

    connect(enableBox_, &QCheckBox::toggled, this, &DPIControl::bypassToggled);
    connect(presetCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this](int idx) {
        switch (idx) {
            case 0: splitPosSpin_->setValue(2); sniBox_->setChecked(true); break;
            case 1: splitPosSpin_->setValue(1); sniBox_->setChecked(false); break;
            case 2: splitPosSpin_->setValue(4); sniBox_->setChecked(true); break;
            case 3: sniBox_->setChecked(true); break;
        }
        emit techniqueChanged(idx);
    });
}

int DPIControl::splitPos() const { return splitPosSpin_->value(); }
bool DPIControl::splitSni() const { return sniBox_->isChecked(); }
int DPIControl::fakeQuic() const { return fakeQuicSpin_->value(); }
bool DPIControl::blockQuic() const { return blockQuicBox_->isChecked(); }
bool DPIControl::dohEnabled() const { return dohBox_->isChecked(); }
void DPIControl::setBypassEnabled(bool enabled) { enableBox_->setChecked(enabled); }
