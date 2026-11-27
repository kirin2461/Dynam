/**
 * @file main.cpp
 * @brief Entry point for Dynam GUI application.
 */

#include <QApplication>
#include <QCommandLineParser>
#include <QTranslator>
#include <QLocale>
#include <QDir>
#include <QSettings>

#include "core/I18nManager.hpp"
#include "core/ThemeManager.hpp"
#include "MainWindow.hpp"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Dynam");
    app.setApplicationVersion("2.0.0");
    app.setOrganizationName("Dynam");
    app.setOrganizationDomain("dynam.app");

    // ─── Command line ────────────────────────────────────────────────
    QCommandLineParser parser;
    parser.setApplicationDescription("Dynam GUI — Network Control Protocol Dashboard");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption langOption(
        {"l", "lang"},
        "Override language (ru, en)",
        "lang", "");
    parser.addOption(langOption);

    QCommandLineOption serverOption(
        {"s", "server"},
        "Backend server URL",
        "url", "http://127.0.0.1:8085");
    parser.addOption(serverOption);

    parser.process(app);

    // ─── Initialize i18n ─────────────────────────────────────────────
    auto& i18n = core::I18nManager::instance();
    QString lang = parser.value(langOption);
    if (!lang.isEmpty()) {
        i18n.setLanguage(lang);
    } else {
        QSettings settings;
        i18n.setLanguage(settings.value("language", QLocale::system().name().left(2)).toString());
    }

    // ─── Initialize theme ────────────────────────────────────────────
    auto& themeMgr = core::ThemeManager::instance();
    {
        QSettings settings;
        themeMgr.setTheme(settings.value("theme", "dark").toString());
    }

    // ─── Main window ─────────────────────────────────────────────────
    MainWindow window;
    QString serverUrl = parser.value(serverOption);
    window.setServerUrl(serverUrl);
    window.show();

    return app.exec();
}
