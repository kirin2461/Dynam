#include "SettingsDialog.hpp"

#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace ncp::GUI {

static QHBoxLayout* fileRow(QLineEdit* edit, QWidget* parent, const QString& filter) {
    auto* row = new QHBoxLayout();
    auto* btn = new QPushButton(QStringLiteral("…"), parent);
    btn->setFixedWidth(30);
    QObject::connect(btn, &QPushButton::clicked, parent, [edit, parent, filter]() {
        QString f = QFileDialog::getOpenFileName(parent, QString(), QString(), filter);
        if (!f.isEmpty()) edit->setText(f);
    });
    row->addWidget(edit, 1);
    row->addWidget(btn);
    return row;
}

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle(QStringLiteral("Настройки прокси и цепочки"));
    setMinimumWidth(520);
    auto* lay = new QVBoxLayout(this);
    auto* form = new QFormLayout();

    portSpin_ = new QSpinBox(this);
    portSpin_->setRange(1, 65535);
    portSpin_->setValue(1080);
    form->addRow(QStringLiteral("Порт прокси:"), portSpin_);

    upstreamEdit_ = new QLineEdit(this);
    upstreamEdit_->setPlaceholderText(
        QStringLiteral("socks5://127.0.0.1:9050 (Tor) — пусто = напрямую"));
    form->addRow(QStringLiteral("Upstream-цепочка:"), upstreamEdit_);

    lay->addLayout(form);

    auto* torTitle = new QLabel(
        QStringLiteral("<b>Управляемый Tor</b> — скрывает сам факт Tor (мосты obfs4/Snowflake).<br>"
                       "<span style='color:#888'>Если указан tor.exe, upstream выше игнорируется.</span>"), this);
    torTitle->setWordWrap(true);
    lay->addWidget(torTitle);

    auto* torForm = new QFormLayout();
    torBinaryEdit_ = new QLineEdit(this);
    torBinaryEdit_->setPlaceholderText(QStringLiteral("Путь к tor.exe (пусто = выкл)"));
    torForm->addRow(QStringLiteral("tor.exe:"),
                    fileRow(torBinaryEdit_, this, QStringLiteral("tor (tor*.exe);;Все файлы (*)")));

    ptObfs4Edit_ = new QLineEdit(this);
    ptObfs4Edit_->setPlaceholderText(QStringLiteral("lyrebird.exe (для obfs4-мостов)"));
    torForm->addRow(QStringLiteral("obfs4 plugin:"),
                    fileRow(ptObfs4Edit_, this, QStringLiteral("lyrebird/obfs4proxy (*obfs4* *lyrebird*);;Все файлы (*)")));

    ptSnowflakeEdit_ = new QLineEdit(this);
    ptSnowflakeEdit_->setPlaceholderText(QStringLiteral("snowflake-client.exe (опционально)"));
    torForm->addRow(QStringLiteral("snowflake plugin:"),
                    fileRow(ptSnowflakeEdit_, this, QStringLiteral("snowflake (*snowflake*);;Все файлы (*)")));
    lay->addLayout(torForm);

    lay->addWidget(new QLabel(QStringLiteral("Мосты (каждый с новой строки):"), this));
    bridgesEdit_ = new QPlainTextEdit(this);
    bridgesEdit_->setPlaceholderText(
        QStringLiteral("obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0"));
    bridgesEdit_->setMaximumHeight(90);
    lay->addWidget(bridgesEdit_);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    lay->addWidget(buttons);
}

void SettingsDialog::setConfig(const GuiProxyConfig& cfg) {
    portSpin_->setValue(cfg.port);
    upstreamEdit_->setText(cfg.upstream);
    torBinaryEdit_->setText(cfg.tor_binary);
    ptObfs4Edit_->setText(cfg.pt_obfs4);
    ptSnowflakeEdit_->setText(cfg.pt_snowflake);
    bridgesEdit_->setPlainText(cfg.bridges.join('\n'));
}

GuiProxyConfig SettingsDialog::config() const {
    GuiProxyConfig cfg;
    cfg.port = static_cast<uint16_t>(portSpin_->value());
    cfg.upstream = upstreamEdit_->text().trimmed();
    cfg.tor_binary = torBinaryEdit_->text().trimmed();
    cfg.pt_obfs4 = ptObfs4Edit_->text().trimmed();
    cfg.pt_snowflake = ptSnowflakeEdit_->text().trimmed();
    for (const auto& line : bridgesEdit_->toPlainText().split('\n'))
        if (!line.trimmed().isEmpty() && !line.trimmed().startsWith('#'))
            cfg.bridges << line.trimmed();
    return cfg;
}

} // namespace ncp::GUI
