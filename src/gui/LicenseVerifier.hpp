#pragma once

// Offline NCP license key verification (same scheme as the web GUI):
// key = "NCP-" + base32(payload_json + ed25519_signature).
// Verified with libsodium (already linked into ncp_core).

#include <QString>
#include <QStringList>

namespace ncp::GUI {

struct LicenseCheck {
    bool valid = false;
    bool expired = false;
    QString plan;
    QStringList modules;
    int days = -1;        // 0 = lifetime
    QString created;
    QString error;        // human-readable reason when !valid
};

// Public key is embedded (same as web/server.py NCP_LICENSE_PUBLIC_KEY_B64).
LicenseCheck verifyLicenseKey(const QString& keyString);

} // namespace ncp::GUI
