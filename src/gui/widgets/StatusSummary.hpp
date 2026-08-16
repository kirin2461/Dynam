#pragma once
// Computes the plain-English status sentence shown under the StatusPanel
// header. The struct captures everything the formatter could possibly
// want; the formatter is a pure function so it's trivial to unit-test
// and swap out per locale or tone.
//
// MainWindow fills the struct in updateStats() and calls
// statusPanel_->setSummary(formatStatusSummary(in)).

#include <QString>
#include <QStringList>
#include <cstdint>

struct StatusSummaryInput {
    bool        connected           = false;
    int         techniqueIndex      = 0;     ///< Index into BypassTechnique enum
    uint64_t    bytesSentPerSec     = 0;
    uint64_t    bytesRecvPerSec     = 0;
    uint64_t    totalBytesSent      = 0;
    uint64_t    totalBytesRecv      = 0;
    bool        torEnabled          = false;
    bool        rotationActive      = false;
    uint64_t    rotationsTotal      = 0;
};

// Names that line up 1:1 with ncp::BypassTechnique. Used by the default
// formatter; if you write your own, feel free to pick prettier strings.
inline QStringList kTechniqueNames() {
    return {
        "no bypass",
        "TTL modification",
        "TCP fragmentation",
        "SNI spoofing",
        "fake packet",
        "disorder",
        "obfuscation",
        "HTTP mimicry",
        "TLS mimicry",
    };
}

// Helper: turn a byte count into "1.2 MB", "850 KB", etc.
inline QString formatBytesShort(uint64_t bytes) {
    constexpr double K = 1024.0;
    if (bytes < 1024) return QString("%1 B").arg(bytes);
    if (bytes < 1024ULL * 1024)        return QString::asprintf("%.1f KB", bytes / K);
    if (bytes < 1024ULL * 1024 * 1024) return QString::asprintf("%.2f MB", bytes / (K*K));
    return QString::asprintf("%.2f GB", bytes / (K*K*K));
}

// ─── TODO(you): customise the status sentence ───────────────────────────────
// This is the one piece where your taste shapes how the app feels.
// Trade-offs to weigh:
//   * Terse vs. verbose — "TLS mimicry · 1.2 MB/s ↑" reads at a glance,
//     "Protecting traffic with TLS mimicry — sending 1.2 MB/s, receiving
//     850 KB/s" sets expectations.
//   * Diagnostic vs. reassuring — operators want numbers, end-users want
//     to know they're safe.
//   * What to show when idle (in.connected == false) — empty? a hint to
//     click Connect? a privacy reminder?
//   * Whether Tor / rotation status is worth a parenthetical or
//     deserves its own line.
//
// The default below is a starting point — swap it for whatever you'd
// rather see in the StatusPanel. ~5–10 lines is plenty.
inline QString formatStatusSummary(const StatusSummaryInput& in) {
    if (!in.connected) {
        return QString();  // empty when idle — feel free to add a hint here
    }
    const QStringList names = kTechniqueNames();
    const QString tech = (in.techniqueIndex >= 0 && in.techniqueIndex < names.size())
                            ? names[in.techniqueIndex]
                            : QString("unknown");
    QString s = QString("Bypass: %1 · ↑%2/s · ↓%3/s")
                    .arg(tech)
                    .arg(formatBytesShort(in.bytesSentPerSec))
                    .arg(formatBytesShort(in.bytesRecvPerSec));
    if (in.torEnabled)     s += QStringLiteral(" · via Tor");
    if (in.rotationActive) s += QString(" · %1 rotations").arg(in.rotationsTotal);
    return s;
}
