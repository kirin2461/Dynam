#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QMessageBox>
#include <QSettings>
#include "../../core/include/ncp_license.hpp"

class LicenseActivationDialog : public QDialog {
    Q_OBJECT
public:
    explicit LicenseActivationDialog(ncp::License* license, QWidget* parent = nullptr)
        : QDialog(parent), license_(license) {
        setWindowTitle(tr("Activate license"));
        setModal(true);
        resize(440, 220);

        auto* root = new QVBoxLayout(this);

        auto* hwidLabel = new QLabel(tr("Hardware ID (HWID):"), this);
        hwidValue_ = new QLineEdit(this);
        hwidValue_->setReadOnly(true);
        if (license_) {
            hwidValue_->setText(QString::fromStdString(license_->get_hwid()));
        }

        auto* form = new QFormLayout;
        keyEdit_ = new QLineEdit(this);
        keyEdit_->setPlaceholderText(tr("XXXX-XXXX-XXXX-XXXX"));
        serverEdit_ = new QLineEdit(this);
        serverEdit_->setText(QSettings().value("license/server_url",
            "https://license.ncp-project.org").toString());

        form->addRow(tr("License key:"),    keyEdit_);
        form->addRow(tr("Activation server:"), serverEdit_);

        statusLabel_ = new QLabel(this);
        statusLabel_->setWordWrap(true);
        statusLabel_->setStyleSheet("color:#888;");

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
        activateBtn_ = buttons->addButton(tr("Activate"), QDialogButtonBox::AcceptRole);
        connect(activateBtn_, &QPushButton::clicked, this, &LicenseActivationDialog::doActivate);
        connect(buttons,      &QDialogButtonBox::rejected, this, &QDialog::reject);

        root->addWidget(hwidLabel);
        root->addWidget(hwidValue_);
        root->addSpacing(6);
        root->addLayout(form);
        root->addWidget(statusLabel_);
        root->addStretch(1);
        root->addWidget(buttons);
    }

signals:
    void activated();

private slots:
    void doActivate() {
        if (!license_) return;
        const QString key    = keyEdit_->text().trimmed();
        const QString server = serverEdit_->text().trimmed();
        if (key.isEmpty()) {
            statusLabel_->setStyleSheet("color:#e74c3c;");
            statusLabel_->setText(tr("License key required."));
            return;
        }
        activateBtn_->setEnabled(false);
        statusLabel_->setStyleSheet("color:#888;");
        statusLabel_->setText(tr("Contacting %1 …").arg(server));
        QApplication::processEvents();

        // activate_license is a synchronous network call; reasonable to run
        // on the UI thread for a one-shot click. If it blocks the UI on a
        // slow connection, move to QtConcurrent::run later.
        const bool ok = license_->activate_license(
            key.toStdString(), server.toStdString());

        if (ok) {
            QSettings().setValue("license/server_url", server);
            statusLabel_->setStyleSheet("color:#2ecc71;");
            statusLabel_->setText(tr("Activated successfully."));
            emit activated();
            accept();
        } else {
            statusLabel_->setStyleSheet("color:#e74c3c;");
            statusLabel_->setText(tr("Activation failed. Check key + connectivity."));
            activateBtn_->setEnabled(true);
        }
    }

private:
    ncp::License* license_;  // not owned
    QLineEdit*    hwidValue_;
    QLineEdit*    keyEdit_;
    QLineEdit*    serverEdit_;
    QLabel*       statusLabel_;
    QPushButton*  activateBtn_;
};
