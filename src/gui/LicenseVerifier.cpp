#include "LicenseVerifier.hpp"

#include <QByteArray>
#include <QDate>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include <sodium.h>

namespace ncp::GUI {

// Same key as web/server.py NCP_LICENSE_PUBLIC_KEY_B64.
static const char* kPublicKeyB64 = "FT2FWdlm6rGldWix5fDJBuZmrHIR+73CuRpWszs/Hog=";

// RFC4648 base32 (uppercase, no padding required on input).
static QByteArray base32Decode(const QByteArray& in) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int lookup[256];
    for (int& i : lookup) i = -1;
    for (int i = 0; i < 32; ++i) lookup[static_cast<unsigned char>(alphabet[i])] = i;

    QByteArray out;
    int buffer = 0, bits = 0;
    for (char ch : in) {
        int v = lookup[static_cast<unsigned char>(ch)];
        if (v < 0) continue;  // skip '=' and separators
        buffer = (buffer << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.append(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

LicenseCheck verifyLicenseKey(const QString& keyString) {
    LicenseCheck res;
    QString s = keyString.trimmed();
    if (s.toUpper().startsWith("NCP-")) s = s.mid(4);
    s.remove('-');
    s = s.toUpper();
    if (s.isEmpty()) {
        res.error = QStringLiteral("пустой ключ");
        return res;
    }

    QByteArray raw = base32Decode(s.toLatin1());
    if (raw.size() <= crypto_sign_BYTES) {
        res.error = QStringLiteral("неверный формат ключа");
        return res;
    }
    QByteArray payload = raw.left(raw.size() - crypto_sign_BYTES);
    QByteArray sig = raw.right(crypto_sign_BYTES);
    QByteArray pub = QByteArray::fromBase64(kPublicKeyB64);
    if (pub.size() != crypto_sign_PUBLICKEYBYTES) {
        res.error = QStringLiteral("внутренняя ошибка ключа");
        return res;
    }
    if (crypto_sign_verify_detached(
            reinterpret_cast<const unsigned char*>(sig.constData()),
            reinterpret_cast<const unsigned char*>(payload.constData()),
            payload.size(),
            reinterpret_cast<const unsigned char*>(pub.constData())) != 0) {
        res.error = QStringLiteral("подпись недействительна");
        return res;
    }

    QJsonParseError perr{};
    QJsonDocument doc = QJsonDocument::fromJson(payload, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        res.error = QStringLiteral("повреждённые данные ключа");
        return res;
    }
    QJsonObject o = doc.object();
    res.plan = o.value("plan").toString();
    for (const auto& m : o.value("modules").toArray())
        res.modules << m.toString();
    res.days = o.value("days").toInt(-1);
    res.created = o.value("created").toString();

    // days == 0 means lifetime; otherwise created + days is the deadline.
    if (res.days > 0 && !res.created.isEmpty()) {
        QDate from = QDate::fromString(res.created, Qt::ISODate);
        if (from.isValid() && from.addDays(res.days) < QDate::currentDate()) {
            res.expired = true;
            res.error = QStringLiteral("срок действия истёк");
            return res;
        }
    }
    res.valid = true;
    return res;
}

} // namespace ncp::GUI
