#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <functional>

class QProcess;

namespace ncp::GUI {

/**
 * @brief Driver mode controller (v1.9.2).
 *
 * Spawns `ncp.exe run` (WinDivert driver mode with Geneva/Covert/stealth
 * modules) as a child process and streams its stdout/stderr back into the
 * GUI. This brings the Qt interface to feature parity with the Web UI,
 * which already exposed driver mode, presets, zapret profiles and module
 * status.
 *
 * Requirements at runtime (same as Web UI driver mode):
 *  - ncp.exe located next to ncp-qt.exe
 *  - WinDivert.dll / WinDivert64.sys next to ncp.exe
 *  - Npcap driver installed (ncp.exe hard-depends on wpcap.dll)
 *  - administrator rights
 *
 * The GUI always passes --no-kill-switch: the kill switch must never be
 * enabled from the UI (a previous incident locked the server out entirely).
 */
class DriverController : public QObject {
    Q_OBJECT
public:
    struct Options {
        QString interface;      ///< --interface ("" = let ncp auto-select)
        QString preset;         ///< --preset tspu|beeline|mts|megafon|tele2|mobile|auto
        bool covert = false;    ///< --covert (CovertChannelManager)
        QString zapretProfile;  ///< --zapret-profile ("" = off)
        QString zapretChains;   ///< --zapret-chains csv ("" = none, custom chains)
    };

    explicit DriverController(QObject* parent = nullptr);
    ~DriverController() override;

    bool running() const;

    /// Path to the CLI: ncp.exe next to ncp-qt.exe (Windows), ncp next to
    /// the binary (Linux), or Contents/Resources/bin/ncp inside the .app
    /// bundle (macOS). Returns "" when not found.
    static QString findNcpExe();
    /// Operator presets accepted by `ncp run --preset` (see src/cli/main.cpp).
    static QStringList availablePresets();
    /// Zapret profiles from list_zapret_profiles() (ncp_dpi_zapret.cpp).
    static QStringList availableZapretProfiles();

    void start(const Options& opt);
    void stop();

    /// Query `ncp.exe network interfaces` asynchronously; cb gets display
    /// strings like "Беспроводная сеть 2 (192.168.1.10)" (possibly empty).
    static void listInterfaces(QObject* ctx,
                               std::function<void(const QStringList&)> cb);

    /// Run an arbitrary one-shot `ncp <args...>` command asynchronously;
    /// cb gets (exit code, merged stdout+stderr). Used by the Enterprise
    /// panel for subcommands that terminate on their own (spa keygen/knock,
    /// stegodns, porthop client, xdp probe/stats/drop, --dry-run checks).
    /// Long-running daemons must be managed with a dedicated QProcess
    /// instead. cb is invoked exactly once with code -1 on start failure.
    static void runNcpCommand(QObject* ctx, const QStringList& args,
                              std::function<void(int, const QString&)> cb);

signals:
    /// Raw output line from ncp.exe (stdout+stderr merged, trimmed).
    void lineReceived(const QString& line);
    /// Parsed module status: state 0 = unknown, 1 = active, 2 = failed.
    void moduleStatus(const QString& module, int state);
    void startedOk();
    void failedToStart(const QString& reason);
    void finished(int exitCode);

private slots:
    void onReadyRead();

private:
    void parseLine(const QString& line);

    QProcess* proc_ = nullptr;
    QString partial_;
};

} // namespace ncp::GUI
