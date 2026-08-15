#include "DriverController.hpp"

#include <QCoreApplication>
#include <QFile>
#include <QProcess>

namespace ncp::GUI {

DriverController::DriverController(QObject* parent) : QObject(parent) {}

DriverController::~DriverController() { stop(); }

bool DriverController::running() const {
    return proc_ && proc_->state() != QProcess::NotRunning;
}

QString DriverController::findNcpExe() {
    const QString path =
        QCoreApplication::applicationDirPath() + QStringLiteral("/ncp.exe");
    return QFile::exists(path) ? path : QString();
}

QStringList DriverController::availablePresets() {
    // src/cli/main.cpp: "Valid: tspu, beeline, mts, megafon, tele2, mobile, auto"
    return {QStringLiteral("tspu"),    QStringLiteral("beeline"),
            QStringLiteral("mts"),     QStringLiteral("megafon"),
            QStringLiteral("tele2"),   QStringLiteral("mobile"),
            QStringLiteral("auto")};
}

QStringList DriverController::availableZapretProfiles() {
    // list_zapret_profiles() in src/core/src/ncp_dpi_zapret.cpp
    return {QStringLiteral("zapret_full"),    QStringLiteral("zapret_general"),
            QStringLiteral("zapret_discord"), QStringLiteral("zapret_google"),
            QStringLiteral("zapret_quic"),    QStringLiteral("zapret_tcp"),
            QStringLiteral("zapret_youtube"), QStringLiteral("zapret_rublock")};
}

void DriverController::start(const Options& opt) {
    if (running()) return;

    const QString exe = findNcpExe();
    if (exe.isEmpty()) {
        emit failedToStart(tr("ncp.exe не найден рядом с ncp-qt.exe.\n"
                              "Режим драйвера требует ncp.exe, WinDivert.dll "
                              "и WinDivert64.sys в каталоге программы."));
        return;
    }

    QStringList args{QStringLiteral("run"),
                     QStringLiteral("--no-license-check"),
                     // NEVER enable the kill switch from the UI.
                     QStringLiteral("--no-kill-switch")};
    if (!opt.interface.trimmed().isEmpty())
        args << QStringLiteral("--interface") << opt.interface.trimmed();
    if (!opt.preset.isEmpty())
        args << QStringLiteral("--preset") << opt.preset;
    if (opt.covert)
        args << QStringLiteral("--covert");
    if (!opt.zapretProfile.isEmpty())
        args << QStringLiteral("--zapret-profile") << opt.zapretProfile;
    if (!opt.zapretChains.isEmpty())
        args << QStringLiteral("--zapret-chains") << opt.zapretChains;

    proc_ = new QProcess(this);
    proc_->setProcessChannelMode(QProcess::MergedChannels);
    connect(proc_, &QProcess::readyRead, this, &DriverController::onReadyRead);
    connect(proc_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [this](int code, QProcess::ExitStatus) {
        if (proc_) { proc_->deleteLater(); proc_ = nullptr; }
        emit finished(code);
    });
    connect(proc_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
        if (e == QProcess::FailedToStart) {
            emit failedToStart(tr("Не удалось запустить ncp.exe "
                                  "(нужны права администратора и установленный Npcap)."));
        }
    });

    emit lineReceived(QStringLiteral("[ui] запуск драйвера: ncp.exe %1")
                          .arg(args.join(QLatin1Char(' '))));
    proc_->start(exe, args);
    if (proc_->waitForStarted(5000))
        emit startedOk();
}

void DriverController::listInterfaces(QObject* ctx,
                                      std::function<void(const QStringList&)> cb) {
    const QString exe = findNcpExe();
    if (exe.isEmpty()) { cb({}); return; }
    auto* proc = new QProcess(ctx);
    QObject::connect(proc, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
        ctx, [proc, cb](int, QProcess::ExitStatus) {
            QStringList out;
            const QString text = QString::fromLocal8Bit(proc->readAll());
            for (QString line : text.split(QLatin1Char('\n'))) {
                line = line.trimmed();
                // "  <name> (<ip>) [UP]"
                if (line.isEmpty() || line.startsWith(QStringLiteral("Available")))
                    continue;
                out << line;
            }
            cb(out);
            proc->deleteLater();
        });
    proc->start(exe, {QStringLiteral("network"), QStringLiteral("interfaces")});
}

void DriverController::stop() {
    if (!proc_) return;
    if (proc_->state() != QProcess::NotRunning) {
        proc_->terminate();
        if (!proc_->waitForFinished(4000))
            proc_->kill();
    }
    proc_->deleteLater();
    proc_ = nullptr;
}

void DriverController::onReadyRead() {
    if (!proc_) return;
    partial_ += QString::fromLocal8Bit(proc_->readAll());
    int idx;
    while ((idx = partial_.indexOf(QLatin1Char('\n'))) >= 0) {
        QString line = partial_.left(idx).trimmed();
        partial_.remove(0, idx + 1);
        if (line.isEmpty()) continue;
        emit lineReceived(line);
        parseLine(line);
    }
}

void DriverController::parseLine(const QString& line) {
    // Map ncp.exe startup output to module names shown in ModulesPanel.
    // Log lines look like: "[+] Geneva Engine active", "[!] X failed",
    // "ERROR: DNSLeakPrevention: WFP unavailable ...", "WF Defense (Tamaraw) ..."
    struct Map { const char* needle; const char* module; };
    static const Map kMap[] = {
        {"Spoofing",              "Спуфинг (DNS/IP)"},
        {"DPI preset",            "DPI пресет"},
        {"TLS fingerprint",       "TLS Fingerprint"},
        {"Advanced DPI",          "Advanced DPI bypass"},
        {"Paranoid",              "Paranoid Mode"},
        {"DNSLeakPrevention",     "DNS Leak Prevention"},
        {"DNS leak",              "DNS Leak Prevention"},
        {"L3 Stealth",            "L3 Stealth"},
        {"RTT Equalizer",         "RTT Equalizer"},
        {"Volume Normalizer",     "Volume Normalizer"},
        {"WF Defense",            "WF Defense (Tamaraw)"},
        {"Tamaraw",               "WF Defense (Tamaraw)"},
        {"Behavioral Cloak",      "Behavioral Cloak"},
        {"Time Correlation",      "Time Correlation Breaker"},
        {"Self-Test",             "Self-Test Monitor"},
        {"SessionFragmenter",     "Session Fragmenter"},
        {"Session Fragmenter",    "Session Fragmenter"},
        {"CrossLayerCorrelator",  "Cross-Layer Correlator"},
        {"Cross-Layer",           "Cross-Layer Correlator"},
        {"Geneva",                "Geneva Engine"},
        {"Covert Channel",        "Covert Channel"},
        {"ProtocolRotation",      "Protocol Rotation"},
        {"Protocol Rotation",     "Protocol Rotation"},
        {"ASAware",               "AS-Aware Router"},
        {"AS-Aware",              "AS-Aware Router"},
        {"GeoObfuscator",         "Geo Obfuscator"},
        {"zapret",                "Zapret профиль"},
        {"Zapret",                "Zapret профиль"},
    };

    const bool good = line.contains(QStringLiteral("[+]")) ||
                      line.contains(QStringLiteral("active"), Qt::CaseInsensitive) ||
                      line.contains(QStringLiteral("enabled"), Qt::CaseInsensitive) ||
                      line.contains(QStringLiteral("initialized"), Qt::CaseInsensitive) ||
                      line.contains(QStringLiteral("started"), Qt::CaseInsensitive);
    const bool bad = line.contains(QStringLiteral("[!]")) ||
                     line.contains(QStringLiteral("failed"), Qt::CaseInsensitive) ||
                     line.contains(QStringLiteral("ERROR"), Qt::CaseSensitive) ||
                     line.contains(QStringLiteral("unavailable"), Qt::CaseInsensitive) ||
                     line.contains(QStringLiteral("disabled"), Qt::CaseInsensitive);
    if (!good && !bad) return;

    for (const auto& m : kMap) {
        if (line.contains(QLatin1String(m.needle))) {
            emit moduleStatus(QString::fromLatin1(m.module), bad ? 2 : 1);
            return;
        }
    }
}

} // namespace ncp::GUI
