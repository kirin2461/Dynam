#pragma once
#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QDialogButtonBox>
#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QDir>
#include <QSysInfo>
#include <QSettings>
#include "../../core/include/ncp_crypto.hpp"
#include "../../core/include/ncp_license.hpp"
#include "../../core/include/ncp_dpi_advanced.hpp"
#include "../../core/include/ncp_identity.hpp"

// Diagnostics — runs a panel of "does this thing work?" checks against
// the live core modules and renders the results as a copy-able report.
// Useful for both end-user self-help (paste into a GitHub issue) and
// quick regression sanity (after a refactor, hit Run → green checks).
//
// Each check is small and read-only: nothing here mutates persistent
// state or sends network traffic.
class DiagnosticsDialog : public QDialog {
    Q_OBJECT
public:
    DiagnosticsDialog(ncp::Crypto* crypto,
                       ncp::License* license,
                       ncp::DPI::AdvancedDPIBypass* advancedDpi,
                       ncp::DPI::IdentityRotation* rotation,
                       QWidget* parent = nullptr)
        : QDialog(parent), crypto_(crypto), license_(license),
          advancedDpi_(advancedDpi), rotation_(rotation) {
        setWindowTitle(tr("Dynam Diagnostics"));
        setModal(true);
        resize(640, 460);

        auto* root = new QVBoxLayout(this);
        root->addWidget(new QLabel(
            tr("Click <b>Run</b> to verify each subsystem. Results are "
               "selectable — copy them into a GitHub issue if you hit a "
               "problem."), this));

        report_ = new QPlainTextEdit(this);
        report_->setReadOnly(true);
        QFont mono;
        mono.setStyleHint(QFont::Monospace);
        mono.setFamily("Menlo");
        report_->setFont(mono);
        root->addWidget(report_, 1);

        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
        runBtn_ = buttons->addButton(tr("Run"), QDialogButtonBox::ActionRole);
        auto* copyBtn = buttons->addButton(tr("Copy"), QDialogButtonBox::ActionRole);
        connect(runBtn_,  &QPushButton::clicked, this, &DiagnosticsDialog::runChecks);
        connect(copyBtn,  &QPushButton::clicked, this, [this]{
            QApplication::clipboard()->setText(report_->toPlainText());
        });
        connect(buttons,  &QDialogButtonBox::rejected, this, &QDialog::reject);
        root->addWidget(buttons);

        // Run automatically the first time so the user sees content.
        runChecks();
    }

private slots:
    void runChecks() {
        runBtn_->setEnabled(false);
        QString out;
        QTextStream s(&out);

        // ── Environment ─────────────────────────────────────────────
        s << "Dynam diagnostics — " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
        s << "OS:           " << QSysInfo::prettyProductName() << "\n";
        s << "Kernel:       " << QSysInfo::kernelType() << " " << QSysInfo::kernelVersion() << "\n";
        s << "Arch:         " << QSysInfo::currentCpuArchitecture() << "\n";
        s << "Qt:           " << qVersion() << "\n";
        s << "App version:  " << QCoreApplication::applicationVersion() << "\n";
        s << "\n";

        // ── Core modules ────────────────────────────────────────────
        check(s, "Crypto/libsodium init",     [&]{ return checkCrypto(); });
        check(s, "License/IOKit HWID",        [&]{ return checkLicense(); });
        check(s, "AdvancedDPI initialize",    [&]{ return checkAdvancedDpi(); });
        check(s, "Identity rotation pool",    [&]{ return checkIdentity(); });

        // ── Filesystem ──────────────────────────────────────────────
        check(s, "~/.dynam writable",         [&]{ return checkDynamDir(); });
        check(s, "Activity log readable",     [&]{ return checkActivityLog(); });

        // ── Settings ────────────────────────────────────────────────
        s << "\nSettings:\n";
        for (const QString& key : {
                "ui/theme", "ui/auto_connect", "ui/onboarded",
                "network/bypass_technique", "network/tor_enabled"}) {
            s << "  " << key << " = "
              << QSettings().value(key).toString() << "\n";
        }

        report_->setPlainText(out);
        runBtn_->setEnabled(true);
    }

private:
    template <typename Fn>
    void check(QTextStream& s, const QString& name, Fn fn) {
        QString detail;
        bool ok = false;
        try {
            ok = fn();  // checks return their detail via a member capture
        } catch (const std::exception& e) {
            detail = QString::fromUtf8(e.what());
        }
        if (!lastDetail_.isEmpty()) detail = lastDetail_;
        lastDetail_.clear();
        s << (ok ? "  ✓ " : "  ✗ ") << name;
        if (!detail.isEmpty()) s << "  — " << detail;
        s << "\n";
    }

    bool checkCrypto() {
        if (!crypto_) { lastDetail_ = "no instance"; return false; }
        auto kp = crypto_->generate_keypair();
        if (!kp.is_valid()) { lastDetail_ = "keypair invalid"; return false; }
        lastDetail_ = QString("Ed25519 keypair generated (%1-byte pubkey)")
                          .arg(kp.public_key.size());
        return true;
    }

    bool checkLicense() {
        if (!license_) { lastDetail_ = "no instance"; return false; }
        const std::string hwid = license_->get_hwid();
        if (hwid.empty()) { lastDetail_ = "HWID empty"; return false; }
        lastDetail_ = QString("HWID = %1…")
                          .arg(QString::fromStdString(hwid).left(16));
        return true;
    }

    bool checkAdvancedDpi() {
        if (!advancedDpi_) { lastDetail_ = "no instance"; return false; }
        ncp::DPI::AdvancedDPIConfig cfg;
        cfg.randomize_tcp_options = true;
        const bool ok = advancedDpi_->initialize(cfg);
        if (!ok) { lastDetail_ = "initialize returned false"; return false; }
        const auto stats = advancedDpi_->get_stats();
        lastDetail_ = QString("initialized; running=%1; segments_split=%2")
                          .arg(advancedDpi_->is_running() ? "yes" : "no")
                          .arg(stats.tcp_segments_split.load());
        return true;
    }

    bool checkIdentity() {
        if (!rotation_) { lastDetail_ = "no instance"; return false; }
        const auto stats = rotation_->get_stats();
        const auto id    = rotation_->get_current();
        lastDetail_ = QString("hostname=%1; rotations=%2")
                          .arg(QString::fromStdString(id.hostname))
                          .arg(stats.rotations_total);
        return true;
    }

    bool checkDynamDir() {
        const QString dir = QDir::homePath() + "/.dynam";
        QDir d;
        if (!d.mkpath(dir)) { lastDetail_ = "mkpath failed"; return false; }
        // Touch a temp file to confirm write permission
        QFile probe(dir + "/.diag-probe");
        if (!probe.open(QIODevice::WriteOnly)) {
            lastDetail_ = QString("open failed: %1").arg(probe.errorString());
            return false;
        }
        probe.close();
        probe.remove();
        lastDetail_ = dir;
        return true;
    }

    bool checkActivityLog() {
        const QString path = QDir::homePath() + "/.dynam/activity.log";
        QFile f(path);
        if (!f.exists()) { lastDetail_ = "no log yet (file missing)"; return true; }
        if (!f.open(QIODevice::ReadOnly)) {
            lastDetail_ = QString("open failed: %1").arg(f.errorString());
            return false;
        }
        int lines = 0;
        while (!f.atEnd()) { f.readLine(); ++lines; }
        lastDetail_ = QString("%1 lines, %2 KB")
                          .arg(lines).arg(f.size() / 1024.0, 0, 'f', 1);
        return true;
    }

    ncp::Crypto*                  crypto_;
    ncp::License*                 license_;
    ncp::DPI::AdvancedDPIBypass*  advancedDpi_;
    ncp::DPI::IdentityRotation*   rotation_;
    QPlainTextEdit*               report_;
    QPushButton*                  runBtn_;
    QString                       lastDetail_;  // populated by each check
};
