#pragma once
// Shared data + probe helpers used by SiteScraperPanel (single URL,
// detailed view), BulkScanDialog (many URLs, leaderboard), and
// CrawlerDialog (recursive crawl). The deep-render panel uses ScanReport
// to feed export; bulk/crawler use it as the single result shape across
// dozens of concurrent runs.

#include <QObject>
#include <QString>
#include <QStringList>
#include <QList>
#include <QHash>
#include <QPair>
#include <QDateTime>
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkCookie>
#include <QSslSocket>
#include <QSslCertificate>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QHostInfo>
#include <QHostAddress>
#include <QRegularExpression>
#include <QTimer>
#include <QElapsedTimer>
#include <QSet>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QDir>
#include <QFile>
#include <QDateTime>

// ─── ScanReport: everything we learned about one URL ────────────────────────
struct ScanReport {
    QUrl       requestUrl;
    QUrl       finalUrl;          // after redirects
    int        httpStatus = 0;
    qint64     timingMs   = -1;
    QString    server;
    QString    contentType;
    qint64     bodyBytes  = -1;

    QStringList dnsRecords;

    // TLS
    QString    tlsProtocol;
    QString    tlsCipher;
    int        tlsBits = 0;
    QString    certSubject;
    QString    certIssuer;
    QDateTime  certValidFrom;
    QDateTime  certValidTo;
    QStringList certSans;

    // Security headers
    int        secScore = 0;
    int        secMax   = 0;
    QString    secGrade;
    QHash<QString, bool>     secPresent;   // header → present

    // HTML-derived
    QString    title;
    QHash<QString, QString>  meta;
    QStringList linksInternal, linksExternal, linksMailto, linksTel;
    QStringList scripts, styles, images;
    QList<QPair<QString,QString>> forms;     // (method, action)
    QList<QNetworkCookie>    cookies;

    // Detected tech signatures (e.g. "React", "Cloudflare", "WordPress")
    QStringList techDetected;

    // Auxiliary fetches
    QString    robotsTxt;
    QString    sitemapXml;
    int        sitemapLocCount = -1;
    bool       faviconFound    = false;
    qint64     faviconBytes    = -1;

    QHash<QString, QString>  responseHeaders;  // header name → value

    // Serialisation
    QJsonObject toJson() const;
    QString     toMarkdown() const;
};

// ─── Security header weights (single source of truth) ──────────────────────
struct SecurityCheck { const char* header; int weight; const char* hint; };
inline const QList<SecurityCheck>& securityChecks() {
    static const QList<SecurityCheck> kChecks = {
        {"strict-transport-security", 20, "force HTTPS for future visits"},
        {"content-security-policy",   25, "blocks unexpected scripts/iframes"},
        {"x-content-type-options",     8, "stops MIME sniffing"},
        {"x-frame-options",            8, "blocks clickjacking via iframes"},
        {"referrer-policy",            6, "limits Referer leakage"},
        {"permissions-policy",         8, "controls camera/mic/geoloc"},
        {"x-xss-protection",           2, "legacy, mostly historical"},
        {"cross-origin-opener-policy", 8, "isolates browsing context"},
        {"cross-origin-embedder-policy", 8, "enables high-resolution timers safely"},
        {"cross-origin-resource-policy", 7, "limits embedding by other origins"},
    };
    return kChecks;
}
inline QString gradeForPercent(int pct) {
    if (pct >= 80) return "A";
    if (pct >= 60) return "B";
    if (pct >= 40) return "C";
    if (pct >= 20) return "D";
    return "F";
}

// ─── Tech signatures ────────────────────────────────────────────────────────
// Each signature pattern-matches on headers + body. ~15 high-confidence
// signatures covering the most common stacks. Easy to extend — add an
// entry to the list. Inspired by Wappalyzer but vastly simpler.
struct TechSignature {
    QString name;
    QString headerName;    // case-insensitive match; "" = any header
    QString headerNeedle;  // substring required in that header value
    QString bodyNeedle;    // substring required in body (case-sensitive)
    QString bodyRegex;     // OR a regex (used when bodyNeedle empty)
};
inline const QList<TechSignature>& techSignatures() {
    static const QList<TechSignature> sigs = {
        // CDN / edge
        {"Cloudflare",        "server",       "cloudflare", "",            ""},
        {"Cloudflare",        "cf-ray",       "",           "",            ""},
        {"AWS CloudFront",    "via",          "CloudFront", "",            ""},
        {"AWS CloudFront",    "x-amz-cf-id",  "",           "",            ""},
        {"Fastly",            "x-served-by",  "cache-",     "",            ""},
        {"Akamai",            "x-akamai-transformed", "",   "",            ""},
        {"Vercel",            "server",       "Vercel",     "",            ""},
        {"Netlify",           "server",       "Netlify",    "",            ""},

        // Web servers
        {"nginx",             "server",       "nginx",      "",            ""},
        {"Apache",            "server",       "Apache",     "",            ""},
        {"Microsoft IIS",     "server",       "Microsoft-IIS","",          ""},
        {"LiteSpeed",         "server",       "LiteSpeed",  "",            ""},

        // Frameworks / runtimes
        {"Next.js",           "x-powered-by", "Next.js",    "",            ""},
        {"Next.js",           "",             "",           "__NEXT_DATA__","" },
        {"Nuxt",              "",             "",           "",            "id=\"__nuxt\""},
        {"React",             "",             "",           "",            "data-reactroot|data-reactid|/_next/static/chunks/main"},
        {"Vue.js",            "",             "",           "",            "data-server-rendered|__vue__"},
        {"Angular",           "",             "",           "ng-version=\"",""},
        {"Svelte",            "",             "",           "",            "svelte-[0-9a-z]+"},
        {"Astro",             "",             "",           "",            "astro-island|/_astro/"},
        {"Express",           "x-powered-by", "Express",    "",            ""},
        {"PHP",               "x-powered-by", "PHP",        "",            ""},
        {"ASP.NET",           "x-powered-by", "ASP.NET",    "",            ""},
        {"Rails",             "server",       "Phusion Passenger","",      ""},

        // CMS
        {"WordPress",         "",             "",           "wp-content",  ""},
        {"WordPress",         "",             "",           "wp-includes", ""},
        {"Drupal",            "",             "",           "",            "<meta name=\"Generator\" content=\"Drupal"},
        {"Joomla",            "",             "",           "",            "<meta name=\"generator\" content=\"Joomla"},
        {"Ghost",             "",             "",           "",            "<meta name=\"generator\" content=\"Ghost"},
        {"Shopify",           "x-shopify-stage", "",        "",            ""},
        {"Squarespace",       "",             "",           "static.squarespace.com",""},
        {"Webflow",           "",             "",           "webflow.com", ""},
        {"Wix",               "",             "",           "wix.com",     ""},

        // Analytics / tag mgmt
        {"Google Analytics",  "",             "",           "googletagmanager.com/gtag",""},
        {"Google Tag Manager","",             "",           "googletagmanager.com/gtm",""},
        {"HubSpot",           "",             "",           "hs-scripts.com",""},
        {"Segment",           "",             "",           "cdn.segment.com",""},
        {"Plausible",         "",             "",           "plausible.io/js",""},
        {"Fathom",            "",             "",           "cdn.usefathom.com",""},

        // Common JS libs
        {"jQuery",            "",             "",           "",            "jquery[.-][0-9]"},
        {"Tailwind CSS",      "",             "",           "",            "tailwindcss|tw-[a-z]+-[0-9]+"},
        {"Bootstrap",         "",             "",           "",            "bootstrap[.-][0-9]"},

        // Auth / payments
        {"Stripe",            "",             "",           "js.stripe.com",""},
        {"Auth0",             "",             "",           "auth0.com",   ""},
        {"Firebase",          "",             "",           "firebaseio.com",""},
        {"Intercom",          "",             "",           "widget.intercom.io",""},
    };
    return sigs;
}

// ─── Score / grade helpers used by every renderer ──────────────────────────
inline void scoreSecurity(QNetworkReply* reply, ScanReport& report) {
    int score = 0, max = 0;
    for (const auto& c : securityChecks()) {
        max += c.weight;
        const bool present = reply->hasRawHeader(c.header);
        if (present) score += c.weight;
        report.secPresent.insert(QString(c.header), present);
    }
    report.secScore = score;
    report.secMax   = max;
    report.secGrade = gradeForPercent(max ? (100 * score / max) : 0);
}

// Match every tech signature against the response. Order-preserving,
// deduped — same name from multiple matches lists once.
inline void detectTech(const QHash<QString, QString>& headers,
                        const QByteArray& body,
                        ScanReport& report) {
    const QString bodyStr = QString::fromUtf8(body);
    QSet<QString> seen;
    for (const auto& sig : techSignatures()) {
        bool match = true;
        if (!sig.headerName.isEmpty()) {
            const QString val = headers.value(sig.headerName.toLower());
            if (val.isEmpty()) { match = false; }
            else if (!sig.headerNeedle.isEmpty() &&
                     !val.contains(sig.headerNeedle, Qt::CaseInsensitive)) {
                match = false;
            }
        }
        if (match && !sig.bodyNeedle.isEmpty()) {
            if (!bodyStr.contains(sig.bodyNeedle)) match = false;
        }
        if (match && !sig.bodyRegex.isEmpty()) {
            const QRegularExpression re(sig.bodyRegex,
                QRegularExpression::CaseInsensitiveOption);
            if (!re.match(bodyStr).hasMatch()) match = false;
        }
        // Must have at least one positive condition (avoid matching everything)
        if (sig.headerName.isEmpty() && sig.bodyNeedle.isEmpty() && sig.bodyRegex.isEmpty()) continue;
        if (match && !seen.contains(sig.name)) {
            seen.insert(sig.name);
            report.techDetected.append(sig.name);
        }
    }
}

// ─── ScanReport serialisation ───────────────────────────────────────────────
inline QJsonObject ScanReport::toJson() const {
    QJsonObject o;
    o["request_url"] = requestUrl.toString();
    o["final_url"]   = finalUrl.toString();
    o["http_status"] = httpStatus;
    o["timing_ms"]   = static_cast<qint64>(timingMs);
    o["server"]      = server;
    o["content_type"]= contentType;
    o["body_bytes"]  = bodyBytes;
    o["title"]       = title;

    QJsonArray dns;
    for (const auto& r : dnsRecords) dns.append(r);
    o["dns"] = dns;

    QJsonObject tls;
    tls["protocol"]     = tlsProtocol;
    tls["cipher"]       = tlsCipher;
    tls["bits"]         = tlsBits;
    tls["cert_subject"] = certSubject;
    tls["cert_issuer"]  = certIssuer;
    if (certValidFrom.isValid()) tls["cert_valid_from"] = certValidFrom.toString(Qt::ISODate);
    if (certValidTo.isValid())   tls["cert_valid_to"]   = certValidTo.toString(Qt::ISODate);
    QJsonArray sans; for (const auto& s : certSans) sans.append(s);
    tls["sans"] = sans;
    o["tls"] = tls;

    QJsonObject sec;
    sec["score"] = secScore;
    sec["max"]   = secMax;
    sec["grade"] = secGrade;
    QJsonObject secs;
    for (auto it = secPresent.constBegin(); it != secPresent.constEnd(); ++it)
        secs[it.key()] = it.value();
    sec["headers_present"] = secs;
    o["security"] = sec;

    QJsonObject metaJ;
    for (auto it = meta.constBegin(); it != meta.constEnd(); ++it)
        metaJ[it.key()] = it.value();
    o["meta"] = metaJ;

    auto stringsToArray = [](const QStringList& l){
        QJsonArray a; for (const auto& s : l) a.append(s); return a;
    };
    o["links_internal"] = stringsToArray(linksInternal);
    o["links_external"] = stringsToArray(linksExternal);
    o["scripts"]        = stringsToArray(scripts);
    o["stylesheets"]    = stringsToArray(styles);
    o["images"]         = stringsToArray(images);
    o["tech"]           = stringsToArray(techDetected);

    QJsonArray formsJ;
    for (const auto& f : forms) {
        QJsonObject fo;
        fo["method"] = f.first;
        fo["action"] = f.second;
        formsJ.append(fo);
    }
    o["forms"] = formsJ;

    QJsonObject hdrs;
    for (auto it = responseHeaders.constBegin(); it != responseHeaders.constEnd(); ++it)
        hdrs[it.key()] = it.value();
    o["response_headers"] = hdrs;

    o["robots_txt"]    = robotsTxt;
    o["sitemap_locs"]  = sitemapLocCount;
    o["favicon_found"] = faviconFound;
    o["favicon_bytes"] = faviconBytes;

    return o;
}

inline QString ScanReport::toMarkdown() const {
    QString md;
    md += QString("# Dynam Site Scan — %1\n\n").arg(requestUrl.toString());
    md += QString("- **Final URL:** %1\n").arg(finalUrl.toString());
    md += QString("- **HTTP status:** %1\n").arg(httpStatus);
    md += QString("- **Round-trip:** %1 ms\n").arg(timingMs);
    md += QString("- **Server:** %1\n").arg(server.isEmpty() ? "—" : server);
    md += QString("- **Title:** %1\n").arg(title.isEmpty() ? "—" : title);
    md += "\n";

    md += "## Security headers — ";
    md += QString("score %1/%2 (grade %3)\n\n").arg(secScore).arg(secMax).arg(secGrade);
    md += "| header | present | weight |\n|---|---|---|\n";
    for (const auto& c : securityChecks()) {
        md += QString("| `%1` | %2 | %3 |\n").arg(c.header)
                .arg(secPresent.value(c.header) ? "✓" : "✗")
                .arg(c.weight);
    }
    md += "\n";

    if (!techDetected.isEmpty()) {
        md += "## Detected technology\n\n";
        for (const auto& t : techDetected) md += QString("- %1\n").arg(t);
        md += "\n";
    }

    if (!tlsProtocol.isEmpty()) {
        md += "## TLS\n\n";
        md += QString("- **Protocol:** %1\n").arg(tlsProtocol);
        md += QString("- **Cipher:** %1 (%2-bit)\n").arg(tlsCipher).arg(tlsBits);
        md += QString("- **Subject:** %1\n").arg(certSubject);
        md += QString("- **Issuer:** %1\n").arg(certIssuer);
        if (certValidTo.isValid()) {
            const qint64 days = QDateTime::currentDateTime().secsTo(certValidTo) / 86400;
            md += QString("- **Expires:** %1 (%2 days)\n").arg(
                certValidTo.toString(Qt::ISODate)).arg(days);
        }
        if (!certSans.isEmpty()) {
            md += QString("- **SANs:** %1\n").arg(certSans.join(", "));
        }
        md += "\n";
    }

    if (!dnsRecords.isEmpty()) {
        md += "## DNS\n\n";
        for (const auto& r : dnsRecords) md += QString("- `%1`\n").arg(r);
        md += "\n";
    }

    md += QString("## Links — %1 internal · %2 external\n\n")
            .arg(linksInternal.size()).arg(linksExternal.size());
    md += QString("## Resources — %1 scripts · %2 stylesheets · %3 images\n\n")
            .arg(scripts.size()).arg(styles.size()).arg(images.size());
    md += QString("## Forms — %1\n\n").arg(forms.size());
    if (!cookies.isEmpty()) {
        md += QString("## Cookies set — %1\n\n").arg(cookies.size());
        for (const auto& c : cookies) {
            md += QString("- `%1` (domain=%2; secure=%3; httpOnly=%4)\n")
                    .arg(QString::fromUtf8(c.name()))
                    .arg(c.domain())
                    .arg(c.isSecure() ? "yes" : "no")
                    .arg(c.isHttpOnly() ? "yes" : "no");
        }
        md += "\n";
    }

    md += QString("---\n_Generated by Dynam Site Scraper · %1_\n")
            .arg(QDateTime::currentDateTime().toString(Qt::ISODate));
    return md;
}

// ─── ScanProbe: reusable single-URL probe used by bulk + crawler ───────────
// Fires one request + TLS handshake + DNS lookup in parallel, fills a
// ScanReport, then emits done(). Single-shot: build, connect to done(),
// run(), let it destroy itself via deleteLater() in the handler.
class ScanProbe : public QObject {
    Q_OBJECT
public:
    explicit ScanProbe(QNetworkAccessManager* net, const QUrl& url,
                        QObject* parent = nullptr)
        : QObject(parent), net_(net), url_(url) {
        if (url_.scheme().isEmpty()) url_.setScheme("https");
        report_.requestUrl = url_;
    }

    void run() {
        pending_ = 0;
        startMain();
        startDns();
        startTls();
    }

    const ScanReport& report() const { return report_; }

signals:
    void done(const ScanReport& report);

private:
    void startMain() {
        ++pending_;
        QNetworkRequest req(url_);
        req.setHeader(QNetworkRequest::UserAgentHeader,
                      "Mozilla/5.0 (compatible; Dynam-Scanner/1.2)");
        req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::NoLessSafeRedirectPolicy);
        timer_.start();
        QNetworkReply* reply = net_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply]{
            report_.timingMs    = timer_.elapsed();
            report_.finalUrl    = reply->url();
            report_.httpStatus  = reply->attribute(
                QNetworkRequest::HttpStatusCodeAttribute).toInt();
            report_.server      = reply->header(QNetworkRequest::ServerHeader).toString();
            report_.contentType = reply->header(QNetworkRequest::ContentTypeHeader).toString();
            const QByteArray body = reply->readAll();
            report_.bodyBytes = body.size();
            for (const auto& p : reply->rawHeaderPairs()) {
                report_.responseHeaders.insert(
                    QString::fromUtf8(p.first).toLower(),
                    QString::fromUtf8(p.second));
            }
            scoreSecurity(reply, report_);
            detectTech(report_.responseHeaders, body, report_);
            report_.cookies = reply->header(QNetworkRequest::SetCookieHeader)
                                .value<QList<QNetworkCookie>>();

            // Quick HTML extraction — only the bits bulk/crawler care about
            QRegularExpression titleRe("<title[^>]*>([^<]*)</title>",
                QRegularExpression::CaseInsensitiveOption);
            const auto tm = titleRe.match(QString::fromUtf8(body.left(64 * 1024)));
            if (tm.hasMatch()) report_.title = tm.captured(1).trimmed();

            reply->deleteLater();
            maybeDone();
        });
    }

    void startDns() {
        ++pending_;
        QHostInfo::lookupHost(url_.host(), this,
            [this](const QHostInfo& info){
                for (const auto& a : info.addresses()) {
                    report_.dnsRecords.append(
                        (a.protocol() == QAbstractSocket::IPv6Protocol ? "AAAA " : "A ")
                        + a.toString());
                }
                maybeDone();
            });
    }

    void startTls() {
        ++pending_;
        auto* sock = new QSslSocket(this);
        QTimer::singleShot(10000, sock, [sock]{ if (sock) sock->abort(); });
        connect(sock, &QSslSocket::encrypted, this, [this, sock]{
            const auto cipher = sock->sslConfiguration().sessionCipher();
            report_.tlsProtocol = cipher.protocolString();
            report_.tlsCipher   = cipher.name();
            report_.tlsBits     = cipher.usedBits();
            const auto chain = sock->peerCertificateChain();
            if (!chain.isEmpty()) {
                const auto& leaf = chain.first();
                report_.certSubject   = leaf.subjectInfo(QSslCertificate::CommonName).join(',');
                report_.certIssuer    = leaf.issuerInfo(QSslCertificate::CommonName).join(',');
                report_.certValidFrom = leaf.effectiveDate();
                report_.certValidTo   = leaf.expiryDate();
                report_.certSans      = leaf.subjectAlternativeNames().values();
            }
            sock->disconnectFromHost();
            sock->deleteLater();
            maybeDone();
        });
        connect(sock, &QSslSocket::errorOccurred, this,
                [this, sock](QAbstractSocket::SocketError){
            sock->deleteLater();
            maybeDone();
        });
        sock->connectToHostEncrypted(url_.host(), url_.port(443));
    }

    void maybeDone() {
        if (--pending_ <= 0) {
            emit done(report_);
        }
    }

    QNetworkAccessManager* net_;
    QUrl                   url_;
    int                    pending_ = 0;
    ScanReport             report_;
    QElapsedTimer          timer_;
};

// ─── ScanHistory: persistence under ~/.dynam/scans/ ────────────────────────
// Two file kinds:
//   ~/.dynam/scans/bulk-YYYYMMDD-HHMMSS.json   ← array of ScanReport
//   ~/.dynam/scans/crawl-YYYYMMDD-HHMMSS.json  ← {seed, depth, cap, rows:[…]}
// Auto-prune to last kMaxHistory of each kind so the directory doesn't grow
// unbounded.
namespace ScanHistory {

inline QString dirPath() {
    const QString dir = QDir::homePath() + "/.dynam/scans";
    QDir().mkpath(dir);
    return dir;
}

inline QString stamp() {
    return QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss");
}

constexpr int kMaxHistory = 50;

inline void pruneOld(const QString& kind);  // fwd-decl for save() below

// Generic kind-keyed save / list / load. `kind` is "bulk" or "crawl".
inline QString save(const QString& kind, const QJsonValue& payload) {
    const QString path = QString("%1/%2-%3.json")
                            .arg(dirPath(), kind, stamp());
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return {};
    QJsonDocument doc(payload.isObject() ? QJsonDocument(payload.toObject())
                                          : QJsonDocument(payload.toArray()));
    f.write(doc.toJson(QJsonDocument::Indented));
    pruneOld(kind);
    return path;
}

// Return list of (path, ISO timestamp) tuples, newest first.
inline QList<QPair<QString, QString>> list(const QString& kind) {
    QList<QPair<QString, QString>> out;
    QDir d(dirPath());
    const auto files = d.entryList({kind + "-*.json"}, QDir::Files,
                                    QDir::Name | QDir::Reversed);
    for (const QString& name : files) {
        const QString stem = name.section('.', 0, 0);          // bulk-20260525-153012
        const QString ts   = stem.section('-', 1);             // 20260525-153012
        QDateTime when = QDateTime::fromString(ts, "yyyyMMdd-HHmmss");
        out.append({d.absoluteFilePath(name),
                    when.isValid() ? when.toString("yyyy-MM-dd HH:mm:ss") : ts});
    }
    return out;
}

inline QJsonDocument load(const QString& path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return {};
    return QJsonDocument::fromJson(f.readAll());
}

inline void pruneOld(const QString& kind) {
    QDir d(dirPath());
    const auto files = d.entryList({kind + "-*.json"}, QDir::Files,
                                    QDir::Name | QDir::Reversed);
    for (int i = kMaxHistory; i < files.size(); ++i) {
        d.remove(files[i]);
    }
}

}  // namespace ScanHistory
