#include "LicenseInfo.hpp"
#include "../LicenseVerifier.hpp"

#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>

LicenseInfo::LicenseInfo(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->addWidget(new QLabel(QStringLiteral("<b>Лицензия</b>"), this));

    auto* form = new QFormLayout();
    planLabel_ = new QLabel(QStringLiteral("—"), this);
    statusLabel_ = new QLabel(QStringLiteral("нет ключа"), this);
    hwidLabel_ = new QLabel(QStringLiteral("—"), this);
    hwidLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    hwidLabel_->setStyleSheet("color:#888;font-size:10px;");
    form->addRow(QStringLiteral("План:"), planLabel_);
    form->addRow(QStringLiteral("Статус:"), statusLabel_);
    form->addRow(QStringLiteral("HWID:"), hwidLabel_);
    lay->addLayout(form);

    keyEdit_ = new QLineEdit(this);
    keyEdit_->setPlaceholderText(QStringLiteral("NCP-XXXXX-XXXXX-…"));
    lay->addWidget(keyEdit_);

    applyBtn_ = new QPushButton(QStringLiteral("Проверить и сохранить"), this);
    lay->addWidget(applyBtn_);

    verdictLabel_ = new QLabel(QString(), this);
    verdictLabel_->setWordWrap(true);
    lay->addWidget(verdictLabel_);
    lay->addStretch(1);

    connect(applyBtn_, &QPushButton::clicked, this, [this]() {
        QString key = keyEdit_->text().trimmed();
        auto chk = ncp::GUI::verifyLicenseKey(key);
        if (chk.valid) {
            QSettings("NCP", "ncp-qt").setValue("license_key", key);
            verdictLabel_->setStyleSheet("color:#4caf50;");
            QString days = (chk.days == 0) ? QStringLiteral("бессрочная")
                                           : QStringLiteral("%1 дн.").arg(chk.days);
            verdictLabel_->setText(QStringLiteral("✓ Ключ действителен: %1, %2, модулей: %3")
                .arg(chk.plan, days).arg(chk.modules.size()));
            reloadFromSettings();
            emit activateClicked();
        } else {
            verdictLabel_->setStyleSheet("color:#ef5350;");
            verdictLabel_->setText(QStringLiteral("✗ %1").arg(chk.error));
        }
    });

    reloadFromSettings();
}

void LicenseInfo::reloadFromSettings() {
    QString key = QSettings("NCP", "ncp-qt").value("license_key").toString();
    if (key.isEmpty()) {
        planLabel_->setText(QStringLiteral("—"));
        statusLabel_->setText(QStringLiteral("нет ключа"));
        statusLabel_->setStyleSheet("color:#888;");
        return;
    }
    auto chk = ncp::GUI::verifyLicenseKey(key);
    if (chk.valid) {
        planLabel_->setText(chk.plan);
        QString days = (chk.days == 0) ? QStringLiteral("бессрочная")
                                       : QStringLiteral("%1 дн.").arg(chk.days);
        statusLabel_->setText(QStringLiteral("активна (%1)").arg(days));
        statusLabel_->setStyleSheet("color:#4caf50;");
    } else {
        planLabel_->setText(QStringLiteral("—"));
        statusLabel_->setText(chk.error);
        statusLabel_->setStyleSheet("color:#ef5350;");
    }
}

void LicenseInfo::setHWID(const QString& hwid) { hwidLabel_->setText(hwid); }
void LicenseInfo::updateInfo(const ncp::License::LicenseInfo& info) {
    planLabel_->setText(QString::fromStdString(info.plan));
    statusLabel_->setText(info.is_valid ? QStringLiteral("активна")
                                        : QStringLiteral("недействительна"));
}
QString LicenseInfo::currentKey() const {
    return QSettings("NCP", "ncp-qt").value("license_key").toString();
}
