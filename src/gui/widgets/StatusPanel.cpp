#include "StatusPanel.hpp"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

StatusPanel::StatusPanel(QWidget* parent) : QWidget(parent) {
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(12, 10, 12, 10);

    auto* top = new QHBoxLayout();
    dotLabel_ = new QLabel(QStringLiteral("●"), this);
    dotLabel_->setStyleSheet("font-size:28px; color:#888;");
    stateLabel_ = new QLabel(QStringLiteral("Защита остановлена"), this);
    stateLabel_->setStyleSheet("font-size:18px; font-weight:bold;");
    top->addWidget(dotLabel_);
    top->addWidget(stateLabel_);
    top->addStretch(1);

    startBtn_ = new QPushButton(QStringLiteral("Запустить защиту"), this);
    stopBtn_ = new QPushButton(QStringLiteral("Остановить"), this);
    settingsBtn_ = new QPushButton(QStringLiteral("Настройки"), this);
    stopBtn_->setEnabled(false);
    startBtn_->setStyleSheet(
        "QPushButton{background:#2e7d32;color:#fff;padding:6px 14px;border-radius:4px;}"
        "QPushButton:disabled{background:#444;color:#888;}");
    stopBtn_->setStyleSheet(
        "QPushButton{background:#c62828;color:#fff;padding:6px 14px;border-radius:4px;}"
        "QPushButton:disabled{background:#444;color:#888;}");
    top->addWidget(settingsBtn_);
    top->addWidget(startBtn_);
    top->addWidget(stopBtn_);
    lay->addLayout(top);

    addressLabel_ = new QLabel(QStringLiteral("Прокси: 127.0.0.1:1080 (SOCKS5 + HTTP)"), this);
    chainLabel_ = new QLabel(QStringLiteral("Цепочка: прямое подключение"), this);
    addressLabel_->setStyleSheet("color:#aaa;");
    chainLabel_->setStyleSheet("color:#aaa;");
    lay->addWidget(addressLabel_);
    lay->addWidget(chainLabel_);

    connect(startBtn_, &QPushButton::clicked, this, &StatusPanel::startRequested);
    connect(stopBtn_, &QPushButton::clicked, this, &StatusPanel::stopRequested);
    connect(settingsBtn_, &QPushButton::clicked, this, &StatusPanel::settingsRequested);
}

void StatusPanel::setConnected(bool connected) {
    dotLabel_->setStyleSheet(connected ? "font-size:28px; color:#4caf50;"
                                       : "font-size:28px; color:#888;");
    stateLabel_->setText(connected ? QStringLiteral("Защита активна")
                                   : QStringLiteral("Защита остановлена"));
    startBtn_->setEnabled(!connected);
    stopBtn_->setEnabled(connected);
}

void StatusPanel::setBusy(bool busy) {
    if (busy) {
        dotLabel_->setStyleSheet("font-size:28px; color:#ffb300;");
        stateLabel_->setText(QStringLiteral("Запуск (Tor bootstrap)…"));
        startBtn_->setEnabled(false);
        stopBtn_->setEnabled(false);
    }
}

void StatusPanel::setAddress(const QString& addr) {
    addressLabel_->setText(QStringLiteral("Прокси: %1 (SOCKS5 + HTTP)").arg(addr));
}

void StatusPanel::setChain(const QString& chain) {
    chainLabel_->setText(chain.isEmpty()
        ? QStringLiteral("Цепочка: прямое подключение")
        : QStringLiteral("Цепочка: %1").arg(chain));
}
