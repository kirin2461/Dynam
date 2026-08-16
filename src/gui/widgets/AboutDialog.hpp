#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QApplication>
#include <QClipboard>
#include <QStyle>
#include <QFont>

class AboutDialog : public QDialog {
    Q_OBJECT
public:
    explicit AboutDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle(tr("About Dynam"));
        setModal(true);
        resize(440, 360);

        auto* root = new QVBoxLayout(this);

        auto* title = new QLabel("<h2>Dynam</h2>", this);
        title->setAlignment(Qt::AlignCenter);

        auto* subtitle = new QLabel(tr("Network Control Protocol"), this);
        subtitle->setAlignment(Qt::AlignCenter);
        subtitle->setStyleSheet("color:#888;");

        auto* versionRow = new QHBoxLayout;
        auto* versionLabel = new QLabel(this);
        versionLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
        QFont mono;
        mono.setStyleHint(QFont::Monospace);
        mono.setFamily("Menlo");
        versionLabel->setFont(mono);
        versionLabel->setText(
            QString("Version %1\nQt %2\n%3")
                .arg(QCoreApplication::applicationVersion().isEmpty()
                        ? "1.2.0"
                        : QCoreApplication::applicationVersion())
                .arg(qVersion())
                .arg(__DATE__ " " __TIME__));
        versionRow->addStretch(1);
        versionRow->addWidget(versionLabel);
        versionRow->addStretch(1);

        auto* description = new QLabel(this);
        description->setWordWrap(true);
        description->setTextInteractionFlags(Qt::TextBrowserInteraction);
        description->setOpenExternalLinks(true);
        description->setText(tr(
            "<p>Multi-layered network anonymisation and privacy platform with "
            "DPI bypass, traffic spoofing, paranoid mode, and post-quantum "
            "cryptography.</p>"
            "<p>Licensed under the GNU Affero General Public License v3.0.</p>"
            "<p><a href=\"https://github.com/kirin2461/Dynam\">Project page</a> · "
            "<a href=\"https://github.com/kirin2461/Dynam/issues\">Report an issue</a></p>"));

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
        auto* copyBtn = buttons->addButton(tr("Copy version"), QDialogButtonBox::ActionRole);
        connect(copyBtn, &QPushButton::clicked, this, [versionLabel]{
            QApplication::clipboard()->setText(versionLabel->text());
        });
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);

        root->addWidget(title);
        root->addWidget(subtitle);
        root->addSpacing(12);
        root->addLayout(versionRow);
        root->addSpacing(12);
        root->addWidget(description);
        root->addStretch(1);
        root->addWidget(buttons);
    }
};
