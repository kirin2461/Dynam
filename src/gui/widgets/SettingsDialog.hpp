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
#include <QStandardPaths>
#include <QTabWidget>
#include "Themes.hpp"
#include "AdvancedSettingsPanel.hpp"

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
        resize(640, 480);

        auto* root = new QVBoxLayout(this);
        auto* tabs = new QTabWidget(this);
        root->addWidget(tabs, 1);

        // ─── Basic tab: the existing form ───────────────────────────
        auto* basicTab = new QWidget(tabs);
        auto* basicLayout = new QVBoxLayout(basicTab);
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

        themeCombo_ = new QComboBox(this);
        themeCombo_->addItem(tr("System"), "system");
        themeCombo_->addItem(tr("Dark"),   "dark");
        themeCombo_->addItem(tr("Light"),  "light");

        // Tor proxy toggle — always toggleable. If no `tor` binary is on
        // PATH the tooltip says so but the user can still set the
        // preference; useful for "I'm installing Tor in another terminal"
        // or "I'll set this and grab the binary later".
        torEnabled_ = new QCheckBox(tr("Route traffic through Tor"), this);
        const QString torPath = QStandardPaths::findExecutable("tor");
        torEnabled_->setToolTip(torPath.isEmpty()
            ? tr("No `tor` binary detected on PATH yet — your preference "
                  "is still saved; install Tor with `brew install tor` when ready.")
            : tr("Tor binary found at %1").arg(torPath));

        form->addRow(tr("Theme"),                    themeCombo_);
        form->addRow(tr("Default bypass technique"), bypassCombo_);
        form->addRow(tr("Tunnel endpoint"),          tunnelEndpoint_);
        form->addRow(tr("Activity log retention"),   logRetention_);
        form->addRow(autoConnect_);
        form->addRow(torEnabled_);

        basicLayout->addLayout(form);
        basicLayout->addStretch(1);

        auto* note = new QLabel(
            tr("Settings persist via QSettings; bypass technique and tunnel "
               "endpoint take effect on the next Connect."), basicTab);
        note->setWordWrap(true);
        note->setStyleSheet("color:#888; font-size:11px;");
        basicLayout->addWidget(note);

        tabs->addTab(basicTab, tr("Basic"));

        // ─── Advanced tab: raw QSettings editor ─────────────────────
        advancedPanel_ = new AdvancedSettingsPanel(tabs);
        tabs->addTab(advancedPanel_, tr("Advanced"));

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
        autoConnect_->setChecked(s.value("ui/auto_connect", true).toBool());
        logRetention_->setValue(s.value("ui/log_retention", 500).toInt());

        const QString currentTheme = s.value("ui/theme", "system").toString();
        const int themeIdx = themeCombo_->findData(currentTheme);
        themeCombo_->setCurrentIndex(themeIdx >= 0 ? themeIdx : 0);
        torEnabled_->setChecked(s.value("network/tor_enabled", false).toBool());
    }

    void save() {
        QSettings s;
        s.setValue("network/bypass_technique", bypassCombo_->currentIndex());
        s.setValue("network/tunnel_endpoint",  tunnelEndpoint_->text().trimmed());
        s.setValue("ui/auto_connect",          autoConnect_->isChecked());
        s.setValue("ui/log_retention",         logRetention_->value());
        s.setValue("ui/theme",                 themeCombo_->currentData().toString());
        s.setValue("network/tor_enabled",      torEnabled_->isChecked());
        Themes::apply();  // takes effect immediately for any open windows
    }

    QComboBox* bypassCombo_;
    QLineEdit* tunnelEndpoint_;
    QCheckBox* autoConnect_;
    QSpinBox*  logRetention_;
    QComboBox* themeCombo_;
    QCheckBox* torEnabled_;
    AdvancedSettingsPanel* advancedPanel_ = nullptr;
};
