// NCP Qt6 GUI entry point.
//   ncp-qt                 — launcher: pick Qt GUI / Web UI (remembers choice)
//   ncp-qt --ui=qt         — force native Qt GUI
//   ncp-qt --ui=web        — launch Web UI (ncp-gui.exe) and exit
//   ncp-qt --choose-ui     — show the chooser dialog even if a choice is saved
//   ncp-qt --smoke         — headless CI: construct UI, run 5s, quit
//   ncp-qt --smoke-start   — headless CI: also start protection at t=1s
//                            (exercises the worker-thread start path)

#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sodium.h>

#ifndef _WIN32
#include <unistd.h>  // _exit() in the smoke watchdog (POSIX; MSVC has it via <stdlib.h>)
#endif

#include "MainWindow.hpp"
#include "Launcher.hpp"

static QFile* g_smokeLog = nullptr;

static void smokeMessageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) {
    Q_UNUSED(ctx);
    const QString line = QDateTime::currentDateTime().toString("HH:mm:ss.zzz") + " [" +
                         QString::number((int)type) + "] " + msg;
    if (g_smokeLog) {
        QTextStream ts(g_smokeLog);
        ts << line << "\n";
        ts.flush();
        g_smokeLog->flush();
    }
    // Also mirror to stderr (visible when console is attached).
    fprintf(stderr, "%s\n", qPrintable(line));
    fflush(stderr);
}

static bool hasArg(int argc, char* argv[], const char* arg) {
    for (int i = 1; i < argc; ++i)
        if (strcmp(argv[i], arg) == 0) return true;
    return false;
}

int main(int argc, char* argv[]) {
    const bool smokeMode = hasArg(argc, argv, "--smoke") || hasArg(argc, argv, "--smoke-start");
    const bool smokeStart = hasArg(argc, argv, "--smoke-start");

    if (smokeMode) {
        // GUI-subsystem apps have no console under wine/Windows — log to a file
        // so CI can verify the result.
        g_smokeLog = new QFile("ncp-qt-smoke.log");
        if (g_smokeLog->open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            qInstallMessageHandler(smokeMessageHandler);
        } else {
            delete g_smokeLog;
            g_smokeLog = nullptr;
        }
        // Headless environments (CI, wine without X): no system tray.
        qputenv("NCP_QT_NO_TRAY", "1");
    }

    if (sodium_init() < 0) {
        qFatal("libsodium init failed");
    }
    QApplication app(argc, argv);
    app.setApplicationName("NCP");
    app.setApplicationDisplayName("NCP — Network Control Protocol");
    app.setOrganizationName("NCP");

    QCommandLineParser parser;
    parser.addHelpOption();
    QCommandLineOption smokeOpt("smoke", "Construct UI and exit (smoke test)");
    QCommandLineOption smokeStartOpt("smoke-start", "Smoke test incl. protection start");
    QCommandLineOption uiOpt("ui", "Force UI mode: qt | web", "mode");
    QCommandLineOption chooseUiOpt("choose-ui", "Show UI chooser even if a choice is saved");
    parser.addOption(smokeOpt);
    parser.addOption(smokeStartOpt);
    parser.addOption(uiOpt);
    parser.addOption(chooseUiOpt);
    parser.process(app);

    if (smokeMode) {
        // CI path: never ask anything, always the native UI.
        ncp::GUI::MainWindow w;
        // Hard watchdog: never hang CI even if the event loop stalls.
        QTimer::singleShot(12000, &app, []() {
            qWarning("SMOKE-TIMEOUT: UI did not settle in time");
            _exit(3);
        });
        if (smokeStart) {
            // Exercise the worker-thread start path (the v1.9.0 self-join
            // crash lived here) and let stats timers fire several times.
            QTimer::singleShot(1000, &w, [&w]() {
                qInfo("SMOKE: requesting protection start");
                w.onConnectClicked();
            });
            QTimer::singleShot(4000, &app, [&w]() {
                qInfo("SMOKE: stats still flowing, stopping protection");
                w.onDisconnectClicked();
            });
        }
        QTimer::singleShot(5500, &app, [&app]() {
            qInfo("SMOKE-OK: MainWindow + timers exercised, quitting");
            app.quit();
        });
        return app.exec();
    }

    // Launcher: pick the interface.
    using ncp::GUI::Launcher::Mode;
    Mode mode = ncp::GUI::Launcher::resolveMode();
    if (mode == Mode::Ask)
        mode = ncp::GUI::Launcher::promptMode(nullptr);

    if (mode == Mode::Web) {
        // Start the web interface and exit — no Qt window needed.
        return ncp::GUI::Launcher::launchWebUi(nullptr) ? 0 : 2;
    }

    ncp::GUI::MainWindow w;
    w.show();
    return app.exec();
}
