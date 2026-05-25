#pragma once
#include <QDialog>
#include <QFormLayout>
#include <QComboBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QSettings>
#include <QVBoxLayout>
#include <QLabel>

// Persists to QSettings under the org / app key set by QApplication
// (see Application::Application). Read-back happens in MainWindow whenever
// it wants to apply settings — for now we just persist; wiring the values
// back into ncp::Network is a follow-up.
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle(tr("Dynam — Settings"));
        setModal(true);
        resize(420, 240);

        auto* root = new QVBoxLayout(this);
        auto* form = new QFormLayout;

        // The order here mirrors ncp::BypassTechnique in
        // src/core/include/ncp_network.hpp — keep them in sync.
        bypassCombo_ = new QComboBox(this);
        bypassCombo_->addItems({
            "None",
            "TTL modification",
            "TCP fragmentation",
            "SNI spoofing",
            "Fake packet",
            "Disorder",
            "Obfuscation",
            "HTTP mimicry",
            "TLS mimicry",
        });

        tunnelEndpoint_ = new QLineEdit(this);
        tunnelEndpoint_->setPlaceholderText("host:port (e.g. tunnel.example.com:443)");

        autoConnect_ = new QCheckBox(tr("Auto-connect on launch"), this);

        logRetention_ = new QSpinBox(this);
        logRetention_->setRange(50, 5000);
        logRetention_->setSingleStep(50);
        logRetention_->setSuffix(tr(" entries"));

        form->addRow(tr("Default bypass technique"), bypassCombo_);
        form->addRow(tr("Tunnel endpoint"),          tunnelEndpoint_);
        form->addRow(tr("Activity log retention"),   logRetention_);
        form->addRow(autoConnect_);

        root->addLayout(form);
        root->addStretch(1);

        auto* note = new QLabel(
            tr("Settings persist via QSettings; bypass technique and tunnel "
               "endpoint take effect on the next Connect."), this);
        note->setWordWrap(true);
        note->setStyleSheet("color:#888; font-size:11px;");
        root->addWidget(note);

        auto* buttons = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::onAccept);
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        root->addWidget(buttons);

        load();
    }

private slots:
    void onAccept() {
        save();
        accept();
    }

private:
    void load() {
        QSettings s;
        bypassCombo_->setCurrentIndex(s.value("network/bypass_technique", 2).toInt()); // TCP_FRAG
        tunnelEndpoint_->setText(s.value("network/tunnel_endpoint").toString());
        autoConnect_->setChecked(s.value("ui/auto_connect", false).toBool());
        logRetention_->setValue(s.value("ui/log_retention", 500).toInt());
    }

    void save() {
        QSettings s;
        s.setValue("network/bypass_technique", bypassCombo_->currentIndex());
        s.setValue("network/tunnel_endpoint",  tunnelEndpoint_->text().trimmed());
        s.setValue("ui/auto_connect",          autoConnect_->isChecked());
        s.setValue("ui/log_retention",         logRetention_->value());
    }

    QComboBox* bypassCombo_;
    QLineEdit* tunnelEndpoint_;
    QCheckBox* autoConnect_;
    QSpinBox*  logRetention_;
};
