#pragma once
#include <QWizard>
#include <QWizardPage>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QCheckBox>
#include <QComboBox>
#include <QSettings>
#include <QPixmap>
#include <QApplication>

// First-launch wizard. Shown once (per QSettings ui/onboarded) and
// lets the user pick a theme + opt into auto-connect before they see
// the main window. Skip-able by closing the dialog — the ui/onboarded
// flag is still set, so it won't re-appear next launch.
class OnboardingWizard : public QWizard {
    Q_OBJECT
public:
    explicit OnboardingWizard(QWidget* parent = nullptr) : QWizard(parent) {
        setWindowTitle(tr("Welcome to Dynam"));
        setWizardStyle(QWizard::ModernStyle);
        setOption(QWizard::NoBackButtonOnStartPage, true);
        resize(560, 420);

        addPage(makeWelcomePage());
        addPage(makeTourPage());
        addPage(makePreferencesPage());
        addPage(makeDonePage());

        connect(this, &QWizard::accepted, this, &OnboardingWizard::commit);
        connect(this, &QDialog::rejected, this, &OnboardingWizard::markSeen);
    }

    // Static helper: returns true if the wizard hasn't run yet.
    static bool shouldRun() {
        return !QSettings().value("ui/onboarded", false).toBool();
    }

private:
    QWizardPage* makeWelcomePage() {
        auto* page = new QWizardPage;
        page->setTitle(tr("Welcome"));
        page->setSubTitle(tr("Multi-layered network anonymisation and privacy platform."));
        auto* layout = new QVBoxLayout(page);
        auto* msg = new QLabel(tr(
            "<p>Dynam combines DPI-bypass, traffic spoofing, paranoid-mode "
            "isolation, and post-quantum cryptography into a single app.</p>"
            "<p>This short setup will help you pick a theme and decide whether "
            "Dynam should connect automatically when you launch it.</p>"
            "<p>You can revisit any of these choices later from the "
            "<b>Settings</b> menu.</p>"), page);
        msg->setWordWrap(true);
        layout->addWidget(msg);
        layout->addStretch(1);
        return page;
    }

    QWizardPage* makeTourPage() {
        auto* page = new QWizardPage;
        page->setTitle(tr("The six tabs"));
        page->setSubTitle(tr("Each tab gives you control over one layer of the stack."));
        auto* layout = new QVBoxLayout(page);
        layout->addWidget(makeTourRow(
            "🏠", tr("Overview"),
            tr("Live throughput, packet counters, and a 60-second traffic chart.")));
        layout->addWidget(makeTourRow(
            "🌐", tr("Network"),
            tr("Local interface enumeration and IPv4 addresses.")));
        layout->addWidget(makeTourRow(
            "🛡️", tr("DPI"),
            tr("Toggle bypass, pick a technique, and watch the live evasion counters move.")));
        layout->addWidget(makeTourRow(
            "🆔", tr("Identity"),
            tr("Rotate MAC + hostname through a randomised pool to defeat tracking.")));
        layout->addWidget(makeTourRow(
            "🔐", tr("Crypto"),
            tr("Real ChaCha20-Poly1305 encrypt/decrypt, hashing, and key generation.")));
        layout->addWidget(makeTourRow(
            "📜", tr("Logs"),
            tr("Activity history persisted across restarts.")));
        layout->addStretch(1);
        return page;
    }

    QWizardPage* makePreferencesPage() {
        auto* page = new QWizardPage;
        page->setTitle(tr("Your defaults"));
        page->setSubTitle(tr("Pick a theme and decide whether to auto-connect."));
        auto* layout = new QVBoxLayout(page);

        themeCombo_ = new QComboBox(page);
        themeCombo_->addItem(tr("System (follow macOS appearance)"), "system");
        themeCombo_->addItem(tr("Dark"),  "dark");
        themeCombo_->addItem(tr("Light"), "light");
        const QString current = QSettings().value("ui/theme", "system").toString();
        themeCombo_->setCurrentIndex(themeCombo_->findData(current));

        autoConnect_ = new QCheckBox(tr("Connect automatically on launch"), page);
        autoConnect_->setChecked(QSettings().value("ui/auto_connect", true).toBool());

        auto* themeRow = new QHBoxLayout;
        themeRow->addWidget(new QLabel(tr("Theme:"), page));
        themeRow->addWidget(themeCombo_, 1);
        layout->addLayout(themeRow);
        layout->addWidget(autoConnect_);
        layout->addStretch(1);
        // We read the values directly in commit() rather than going through
        // QWizard's field registration; registerField is protected and only
        // callable from QWizardPage subclasses.
        return page;
    }

    QWizardPage* makeDonePage() {
        auto* page = new QWizardPage;
        page->setTitle(tr("You're ready"));
        page->setSubTitle(tr("Press Finish to open the main window."));
        auto* layout = new QVBoxLayout(page);
        auto* msg = new QLabel(tr(
            "<p>Settings are saved to <code>QSettings</code> and persist between launches.</p>"
            "<p>If you ever need to re-run this wizard, delete the "
            "<code>ui/onboarded</code> key:<br>"
            "<code>defaults delete com.NCP.NetworkControlProtocol ui.onboarded</code></p>"), page);
        msg->setWordWrap(true);
        msg->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(msg);
        layout->addStretch(1);
        return page;
    }

    QWidget* makeTourRow(const QString& icon, const QString& title, const QString& body) {
        auto* row = new QWidget;
        auto* l = new QHBoxLayout(row);
        l->setContentsMargins(0, 0, 0, 0);
        auto* iconLabel = new QLabel(icon);
        iconLabel->setStyleSheet("font-size:20px;");
        l->addWidget(iconLabel);
        auto* text = new QLabel(QString("<b>%1</b> — %2").arg(title, body));
        text->setWordWrap(true);
        l->addWidget(text, 1);
        return row;
    }

private slots:
    void commit() {
        QSettings s;
        s.setValue("ui/theme",        themeCombo_->currentData().toString());
        s.setValue("ui/auto_connect", autoConnect_->isChecked());
        markSeen();
    }
    void markSeen() {
        QSettings().setValue("ui/onboarded", true);
    }

private:
    QComboBox* themeCombo_ = nullptr;
    QCheckBox* autoConnect_ = nullptr;
};
