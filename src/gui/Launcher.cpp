#include "Launcher.hpp"

#include <QCheckBox>
#include <QCoreApplication>
#include <QDialog>
#include <QFile>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>

namespace ncp::GUI {
namespace Launcher {

static const char* kSettingsKey = "ui_mode";

QString modeName(Mode m) {
    switch (m) {
    case Mode::Qt:  return QStringLiteral("Qt GUI");
    case Mode::Web: return QStringLiteral("Web UI");
    default:        return QStringLiteral("спросить");
    }
}

Mode resolveMode() {
    // 1) CLI override: --ui=qt | --ui=web | --choose-ui
    const QStringList args = QCoreApplication::arguments();
    for (const QString& a : args) {
        if (a == QLatin1String("--choose-ui"))
            return Mode::Ask;
        if (a.startsWith(QLatin1String("--ui="))) {
            const QString v = a.mid(5).toLower();
            if (v == QLatin1String("qt"))  return Mode::Qt;
            if (v == QLatin1String("web")) return Mode::Web;
        }
    }
    // 2) saved choice
    const QString saved = QSettings("NCP", "ncp-qt")
                              .value(QLatin1String(kSettingsKey))
                              .toString().toLower();
    if (saved == QLatin1String("qt"))  return Mode::Qt;
    if (saved == QLatin1String("web")) return Mode::Web;
    return Mode::Ask;
}

Mode promptMode(QWidget* parent) {
    QDialog dlg(parent);
    dlg.setWindowTitle(QStringLiteral("NCP — выбор интерфейса"));
    dlg.setModal(true);
    dlg.setMinimumWidth(420);

    auto* lay = new QVBoxLayout(&dlg);
    auto* title = new QLabel(QStringLiteral("<b>Какой интерфейс запустить?</b>"), &dlg);
    title->setStyleSheet("font-size:15px;");
    lay->addWidget(title);
    lay->addWidget(new QLabel(
        QStringLiteral("Qt GUI — нативная панель (быстрая, работает без браузера).\n"
                       "Web UI — привычный браузерный интерфейс (ncp-gui.exe)."), &dlg));

    Mode chosen = Mode::Qt;
    auto* btnQt = new QPushButton(QStringLiteral("Qt GUI (нативный)"), &dlg);
    auto* btnWeb = new QPushButton(QStringLiteral("Web UI (браузерный)"), &dlg);
    btnQt->setStyleSheet("QPushButton{background:#2e7d32;color:#fff;padding:10px;border-radius:5px;font-size:14px;}"
                         "QPushButton:hover{background:#388e3c;}");
    btnWeb->setStyleSheet("QPushButton{background:#1565c0;color:#fff;padding:10px;border-radius:5px;font-size:14px;}"
                          "QPushButton:hover{background:#1e88e5;}");
    lay->addWidget(btnQt);
    lay->addWidget(btnWeb);

    auto* remember = new QCheckBox(QStringLiteral("Запомнить выбор"), &dlg);
    remember->setChecked(true);
    lay->addWidget(remember);

    QObject::connect(btnQt, &QPushButton::clicked, &dlg, [&]() {
        chosen = Mode::Qt;
        if (remember->isChecked())
            QSettings("NCP", "ncp-qt").setValue(QLatin1String(kSettingsKey), "qt");
        dlg.accept();
    });
    QObject::connect(btnWeb, &QPushButton::clicked, &dlg, [&]() {
        chosen = Mode::Web;
        if (remember->isChecked())
            QSettings("NCP", "ncp-qt").setValue(QLatin1String(kSettingsKey), "web");
        dlg.accept();
    });

    if (dlg.exec() != QDialog::Accepted)
        return Mode::Qt;  // dialog closed — safe default
    return chosen;
}

bool launchWebUi(QWidget* parent) {
    const QString exe = QCoreApplication::applicationDirPath() + "/ncp-gui.exe";
    if (!QFile::exists(exe)) {
        QMessageBox::warning(parent, QStringLiteral("NCP — Web UI"),
            QStringLiteral("Не найден %1.\n\n"
                           "Положите ncp-gui.exe (веб-интерфейс) рядом с ncp-qt.exe "
                           "или запустите веб-версию отдельно.").arg(exe));
        return false;
    }
    if (!QProcess::startDetached(exe, QStringList())) {
        QMessageBox::warning(parent, QStringLiteral("NCP — Web UI"),
            QStringLiteral("Не удалось запустить %1").arg(exe));
        return false;
    }
    return true;
}

void resetChoice() {
    QSettings("NCP", "ncp-qt").remove(QLatin1String(kSettingsKey));
}

} // namespace Launcher
} // namespace ncp::GUI
