#include "DPIControl.hpp"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
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

    // ---- Driver mode (`ncp.exe run`), parity with the Web UI ----
    auto* drvGroup = new QGroupBox(QStringLiteral("Режим драйвера (ncp run)"), this);
    auto* drvForm = new QFormLayout(drvGroup);

    ifaceCombo_ = new QComboBox(drvGroup);
    ifaceCombo_->setEditable(true);
    ifaceCombo_->addItem(QStringLiteral("авто"), QString());
    ifaceCombo_->lineEdit()->setPlaceholderText(
        QStringLiteral("имя интерфейса, напр. «Беспроводная сеть 2»"));
    drvForm->addRow(QStringLiteral("Интерфейс:"), ifaceCombo_);

    driverPresetCombo_ = new QComboBox(drvGroup);
    // Valid values per src/cli/main.cpp
    for (const char* p : {"tspu", "beeline", "mts", "megafon", "tele2", "mobile", "auto"})
        driverPresetCombo_->addItem(QStringLiteral("operator: %1").arg(QLatin1String(p)),
                                    QString::fromLatin1(p));
    drvForm->addRow(QStringLiteral("Пресет оператора:"), driverPresetCombo_);

    zapretCombo_ = new QComboBox(drvGroup);
    zapretCombo_->addItem(QStringLiteral("выкл"), QString());
    // list_zapret_profiles() in ncp_dpi_zapret.cpp
    for (const char* z : {"zapret_full", "zapret_general", "zapret_discord",
                          "zapret_google", "zapret_quic", "zapret_tcp",
                          "zapret_youtube", "zapret_rublock"})
        zapretCombo_->addItem(QString::fromLatin1(z), QString::fromLatin1(z));
    drvForm->addRow(QStringLiteral("Zapret-профиль:"), zapretCombo_);

    chainsEdit_ = new QLineEdit(drvGroup);
    chainsEdit_->setPlaceholderText(
        QStringLiteral("свои цепочки через запятую, напр. quic_general,youtube_tls"));
    drvForm->addRow(QStringLiteral("Zapret-цепочки:"), chainsEdit_);

    covertBox_ = new QCheckBox(
        QStringLiteral("Covert channel (маскировка под легитимный трафик)"), drvGroup);
    drvForm->addRow(QString(), covertBox_);

    lay->addWidget(drvGroup);
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

QString DPIControl::driverInterface() const {
    // editable combo: currentData() is "" for the "авто" entry; typed text
    // may carry " (ip)" suffix when picked from the enumerated list
    QString t = ifaceCombo_->currentText().trimmed();
    const int paren = t.indexOf(QStringLiteral(" ("));
    if (paren > 0) t = t.left(paren);
    return (t == QStringLiteral("авто")) ? QString() : t;
}
QString DPIControl::driverPreset() const { return driverPresetCombo_->currentData().toString(); }
QString DPIControl::driverZapretProfile() const { return zapretCombo_->currentData().toString(); }
QString DPIControl::driverZapretChains() const { return chainsEdit_->text().trimmed(); }
bool DPIControl::driverCovert() const { return covertBox_->isChecked(); }

void DPIControl::setDriverOptions(const QString& iface, const QString& preset,
                                  const QString& zapret, bool covert,
                                  const QString& chains) {
    ifaceCombo_->setCurrentText(iface.isEmpty() ? QStringLiteral("авто") : iface);
    int idx = driverPresetCombo_->findData(preset);
    if (idx >= 0) driverPresetCombo_->setCurrentIndex(idx);
    idx = zapretCombo_->findData(zapret);
    zapretCombo_->setCurrentIndex(idx >= 0 ? idx : 0);
    chainsEdit_->setText(chains);
    covertBox_->setChecked(covert);
}

void DPIControl::setInterfaces(const QStringList& ifaces) {
    const QString current = ifaceCombo_->currentText();
    ifaceCombo_->clear();
    ifaceCombo_->addItem(QStringLiteral("авто"), QString());
    for (const QString& i : ifaces)
        ifaceCombo_->addItem(i, i);
    if (!current.isEmpty()) {
        const int idx = ifaceCombo_->findText(current);
        if (idx >= 0) ifaceCombo_->setCurrentIndex(idx);
        else ifaceCombo_->setCurrentText(current);
    }
}
