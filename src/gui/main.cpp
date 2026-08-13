// NCP Qt6 GUI entry point.
//   ncp-qt           — normal start
//   ncp-qt --smoke   — construct MainWindow and quit (CI/wine smoke test)

#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QDateTime>
#include <cstdio>
#include <cstdlib>
#include <sodium.h>

#include "MainWindow.hpp"

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
    const bool smokeMode = hasArg(argc, argv, "--smoke");

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
    parser.addOption(smokeOpt);
    parser.process(app);

    ncp::GUI::MainWindow w;

    if (smokeMode) {
        // Hard watchdog: never hang CI even if the event loop stalls.
        QTimer::singleShot(10000, &app, []() {
            qWarning("SMOKE-TIMEOUT: UI did not settle in time");
            _exit(3);
        });
        QTimer::singleShot(1500, &app, [&app]() {
            qInfo("SMOKE-OK: MainWindow constructed, quitting");
            app.quit();
        });
    } else {
        w.show();
    }
    return app.exec();
}
