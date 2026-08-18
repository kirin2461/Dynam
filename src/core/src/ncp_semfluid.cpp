/**
 * @file ncp_semfluid.cpp
 * @brief Semantic Fluid Transport (M8) — implementation.
 *
 * The carrier is a realistic HTTP/1.1 request. Payload chunks are
 * embedded as 64-char base62 cookie values with per-chunk BLAKE2b-4
 * checksums. Chunk order is the fixed appearance order of cookie
 * pairs inside the Cookie header(s).
 */

#include "ncp_semfluid.hpp"

#include <cstring>
#include <cctype>
#include <algorithm>

#include <sodium.h>

namespace ncp {

namespace {

// ===== Templates =====

struct TemplateDef {
    const char* name;
    const char* method;
    std::vector<const char*> paths;
    std::vector<const char*> hosts;
    std::vector<const char*> user_agents;
    std::vector<const char*> accepts;
    std::vector<const char*> accept_languages;
    std::vector<const char*> referers;      // empty => header omitted
    const char* content_type;               // nullptr => no body
};

const TemplateDef kTemplates[] = {
    { // 0: Windows telemetry POST
        "win_telemetry", "POST",
        {"/v1/track", "/telemetry/events", "/OneCollector/1.0"},
        {"settings-win.data.microsoft.com", "v10.events.data.microsoft.com",
         "telecommand.telemetry.microsoft.com"},
        {"Microsoft-Windows-Telemetry/10.0 (Windows NT 10.0; Win64; x64)",
         "Microsoft-CryptoAPI/10.0"},
        {"*/*"},
        {"en-US,en;q=0.9", "en-US"},
        {},
        "application/json",
    },
    { // 1: Chrome component update GET
        "chrome_update", "GET",
        {"/service/update2", "/update2/crx", "/component/update"},
        {"update.googleapis.com", "edge.microsoft.com",
         "redirector.gvt1.com"},
        {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"},
        {"*/*", "application/json"},
        {"en-US,en;q=0.9", "en-GB,en;q=0.8"},
        {},
        nullptr,
    },
    { // 2: CDN image GET
        "cdn_image", "GET",
        {"/static/img/logo-header.png", "/assets/i/banner-2x.webp",
         "/media/cache/sprite.png"},
        {"cdn.static.example-cdn.net", "images.cdn-assets.io",
         "statics.content-delivery.net"},
        {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
         "(KHTML, like Gecko) Version/17.2 Safari/605.1.15"},
        {"image/avif,image/webp,image/apng,image/*,*/*;q=0.8"},
        {"en-US,en;q=0.9", "ru-RU,ru;q=0.9,en;q=0.8"},
        {"https://www.example.com/", "https://news.example.org/article"},
        nullptr,
    },
    { // 3: OAuth-ish token refresh POST
        "oauth_post", "POST",
        {"/oauth2/token", "/connect/token", "/auth/realms/master/protocol/openid-connect/token"},
        {"login.example-idp.com", "oauth2.accounts.example.net",
         "auth.sso-provider.io"},
        {"okhttp/4.12.0", "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8)",
         "PostmanRuntime/7.36.0"},
        {"application/json", "application/json, text/plain, */*"},
        {"en-US,en;q=0.9"},
        {},
        "application/x-www-form-urlencoded",
    },
    { // 4: Video manifest GET
        "video_manifest", "GET",
        {"/v/9aKq2/manifest.mpd", "/hls/master.m3u8",
         "/dash/stream-441/manifest.mpd"},
        {"video-cdn.streaming-example.net", "manifest.vod-platform.tv",
         "edge-01.media-delivery.example.com"},
        {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
         "Gecko/20100101 Firefox/121.0",
         "VLC/3.0.20 LibVLC/3.0.20"},
        {"*/*"},
        {"en-US,en;q=0.5", "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3"},
        {"https://player.streaming-example.net/watch?v=9aKq2"},
        nullptr,
    },
};

// Cookie names cycled in fixed order (chunk map is the appearance order).
const char* kCookieNames[] = {
    "MSFPC", "_uetsid", "_uetvid", "MUID", "MUIDB",
    "ANON", "AADSSO", "_clck", "_ga", "sessionid",
};
constexpr size_t kCookieNameCount = sizeof(kCookieNames) / sizeof(kCookieNames[0]);

const char kBase62Alphabet[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

int base62_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
    if (c >= 'a' && c <= 'z') return c - 'a' + 36;
    return -1;
}

bool is_base62_str(const std::string& s) {
    for (char c : s) if (base62_value(c) < 0) return false;
    return !s.empty();
}

// One decorative (non-chunk) cookie for realism on some templates.
// Its value is deliberately NOT 64 base62 chars, so unwrap() skips it.
const char* kDecoCookieName  = "SRCHHPGUSR";
const char* kDecoCookieValue = "SRCHLANG=en";

} // namespace

// ===== HttpRequest =====

std::optional<std::string> HttpRequest::header(const std::string& name) const {
    for (const auto& h : headers) {
        if (h.first.size() == name.size()) {
            bool eq = true;
            for (size_t i = 0; i < name.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(h.first[i])) !=
                    std::tolower(static_cast<unsigned char>(name[i]))) { eq = false; break; }
            }
            if (eq) return h.second;
        }
    }
    return std::nullopt;
}

std::string HttpRequest::serialize() const {
    std::string out;
    out += method;
    out += ' ';
    out += path;
    out += " HTTP/1.1\r\n";
    for (const auto& h : headers) {
        out += h.first;
        out += ": ";
        out += h.second;
        out += "\r\n";
    }
    out += "\r\n";
    out.append(reinterpret_cast<const char*>(body.data()), body.size());
    return out;
}

// ===== base62 big-integer codec =====

std::string SemanticWrapper::base62_encode_block(const uint8_t* data, size_t len,
                                                 size_t width) {
    // Big-number base conversion: repeatedly divide the big-endian byte
    // array by 62, collecting remainders (most significant digit last).
    std::vector<uint8_t> num(data, data + len);
    std::string digits;
    digits.reserve(width);
    bool nonzero = true;
    while (nonzero) {
        uint32_t rem = 0;
        nonzero = false;
        for (size_t i = 0; i < num.size(); ++i) {
            uint32_t cur = (rem << 8) | num[i];
            num[i] = static_cast<uint8_t>(cur / 62);
            rem = cur % 62;
            if (num[i] != 0) nonzero = true;
        }
        digits.push_back(kBase62Alphabet[rem]);
    }
    // Left-pad with '0' to fixed width.
    while (digits.size() < width) digits.push_back('0');
    std::reverse(digits.begin(), digits.end());
    if (digits.size() > width) digits.resize(width); // unreachable for len<=47
    return digits;
}

bool SemanticWrapper::base62_decode_block(const std::string& s,
                                          uint8_t* out, size_t out_len) {
    if (s.empty() || !out) return false;
    std::vector<uint8_t> num(out_len, 0);
    for (char c : s) {
        int v = base62_value(c);
        if (v < 0) return false;
        uint32_t carry = static_cast<uint32_t>(v);
        for (size_t i = out_len; i-- > 0;) {
            uint32_t cur = num[i] * 62u + carry;
            num[i] = static_cast<uint8_t>(cur & 0xFF);
            carry = cur >> 8;
        }
        if (carry != 0) return false; // value does not fit out_len bytes
    }
    std::memcpy(out, num.data(), out_len);
    return true;
}

const char* SemanticWrapper::template_name(int template_id) {
    if (template_id < 0 || template_id >= kTemplateCount) return "unknown";
    return kTemplates[template_id].name;
}

// ===== wrap =====

HttpRequest SemanticWrapper::wrap(const std::vector<uint8_t>& payload,
                                  std::optional<int> template_id,
                                  std::mt19937_64& rng) {
    if (sodium_init() < 0) {
        // Extremely unlikely; fall through, hashing is still functional.
    }
    int tid = template_id ? (*template_id % kTemplateCount + kTemplateCount) % kTemplateCount
                          : static_cast<int>(rng() % kTemplateCount);
    const TemplateDef& t = kTemplates[tid];

    auto pick = [&rng](const std::vector<const char*>& pool) -> const char* {
        return pool[rng() % pool.size()];
    };

    // ---- chunk the payload ----
    // blob = len(4,BE) || payload ; chunk = 43B data || BLAKE2b-4(data)
    std::vector<uint8_t> blob;
    blob.reserve(payload.size() + 4);
    uint32_t len32 = static_cast<uint32_t>(payload.size());
    for (int i = 3; i >= 0; --i)
        blob.push_back(static_cast<uint8_t>((len32 >> (i * 8)) & 0xFF));
    blob.insert(blob.end(), payload.begin(), payload.end());

    size_t nchunks = (blob.size() + kChunkDataBytes - 1) / kChunkDataBytes;
    if (nchunks == 0) nchunks = 1;
    std::vector<std::string> chunk_fields;
    chunk_fields.reserve(nchunks);
    for (size_t c = 0; c < nchunks; ++c) {
        uint8_t block[kChunkDataBytes + 4];
        std::memset(block, 0, sizeof(block));
        size_t off = c * kChunkDataBytes;
        size_t take = std::min(kChunkDataBytes, blob.size() - off);
        std::memcpy(block, blob.data() + off, take);
        crypto_generichash(block + kChunkDataBytes, 4,
                           block, kChunkDataBytes, nullptr, 0);
        chunk_fields.push_back(base62_encode_block(block, sizeof(block),
                                                   kChunkFieldChars));
    }

    // ---- build the request ----
    HttpRequest req;
    req.method = t.method;
    req.path = pick(t.paths);

    // Fixed header order; values sampled from per-template pools.
    req.headers.emplace_back("Host", pick(t.hosts));
    req.headers.emplace_back("User-Agent", pick(t.user_agents));
    req.headers.emplace_back("Accept", pick(t.accepts));
    req.headers.emplace_back("Accept-Language", pick(t.accept_languages));
    if (!t.referers.empty()) {
        req.headers.emplace_back("Referer", pick(t.referers));
    }
    req.headers.emplace_back("Accept-Encoding", "gzip, deflate, br");
    req.headers.emplace_back("Connection", "keep-alive");

    // Cookie chunks, in fixed order, spread across Cookie headers.
    // One Cookie header per ~4 pairs keeps header lines plausible.
    std::string cookie_line;
    size_t in_line = 0;
    auto flush_cookie = [&]() {
        if (!cookie_line.empty()) {
            req.headers.emplace_back("Cookie", cookie_line);
            cookie_line.clear();
            in_line = 0;
        }
    };
    // Optional decorative cookie first on some templates (not a chunk).
    if (tid == 2 || tid == 4) {
        cookie_line = std::string(kDecoCookieName) + "=" + kDecoCookieValue;
        in_line = 1;
    }
    for (size_t i = 0; i < chunk_fields.size(); ++i) {
        if (!cookie_line.empty()) cookie_line += "; ";
        cookie_line += kCookieNames[i % kCookieNameCount];
        cookie_line += '=';
        cookie_line += chunk_fields[i];
        if (++in_line >= 4) flush_cookie();
    }
    flush_cookie();

    // Plausible body for POST templates.
    if (t.content_type) {
        req.headers.emplace_back("Content-Type", t.content_type);
        char body_buf[192];
        if (tid == 0) {
            // Telemetry-ish JSON with rng-derived fields.
            std::snprintf(body_buf, sizeof(body_buf),
                          "{\"ver\":\"4.0\",\"name\":\"Microsoft.Device."
                          "Heartbeat\",\"time\":\"2024-01-%02lluT%02llu:%02llu:"
                          "%02lluZ\",\"iKey\":\"o:%08llx\",\"data\":{\"baseType"
                          "\":\"EventData\"}}",
                          static_cast<unsigned long long>(rng() % 28 + 1),
                          static_cast<unsigned long long>(rng() % 24),
                          static_cast<unsigned long long>(rng() % 60),
                          static_cast<unsigned long long>(rng() % 60),
                          static_cast<unsigned long long>(rng() & 0xFFFFFFFFULL));
        } else {
            std::snprintf(body_buf, sizeof(body_buf),
                          "grant_type=refresh_token&client_id=%016llx"
                          "&scope=openid%%20profile",
                          static_cast<unsigned long long>(rng()));
        }
        req.body.assign(body_buf, body_buf + std::strlen(body_buf));
        req.headers.emplace_back("Content-Length",
                                 std::to_string(req.body.size()));
    }

    return req;
}

// ===== unwrap =====

std::optional<std::vector<uint8_t>> SemanticWrapper::unwrap(
        const HttpRequest& req) {
    // Collect chunk candidates in the fixed order: Cookie header(s),
    // appearance order; a value that is exactly 64 base62 chars is a chunk.
    std::vector<std::string> chunk_fields;
    for (const auto& h : req.headers) {
        std::string name_lower = h.first;
        for (auto& c : name_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (name_lower != "cookie") continue;
        size_t pos = 0;
        while (pos < h.second.size()) {
            size_t end = h.second.find(';', pos);
            std::string pair = h.second.substr(
                pos, end == std::string::npos ? std::string::npos : end - pos);
            pos = (end == std::string::npos) ? h.second.size() : end + 1;
            // Trim whitespace.
            size_t b = pair.find_first_not_of(" \t");
            size_t e = pair.find_last_not_of(" \t");
            if (b == std::string::npos) continue;
            pair = pair.substr(b, e - b + 1);
            size_t eq = pair.find('=');
            if (eq == std::string::npos) continue;
            std::string value = pair.substr(eq + 1);
            if (value.size() == kChunkFieldChars && is_base62_str(value)) {
                chunk_fields.push_back(std::move(value));
            }
        }
    }
    if (chunk_fields.empty()) return std::nullopt;

    // Decode + verify each chunk, concatenating data parts.
    std::vector<uint8_t> blob;
    blob.reserve(chunk_fields.size() * kChunkDataBytes);
    for (const std::string& f : chunk_fields) {
        uint8_t block[kChunkDataBytes + 4];
        if (!base62_decode_block(f, block, sizeof(block))) return std::nullopt;
        uint8_t check[4];
        crypto_generichash(check, sizeof(check), block, kChunkDataBytes,
                           nullptr, 0);
        if (std::memcmp(check, block + kChunkDataBytes, 4) != 0) {
            return std::nullopt;
        }
        blob.insert(blob.end(), block, block + kChunkDataBytes);
    }

    if (blob.size() < 4) return std::nullopt;
    uint32_t len32 = (uint32_t(blob[0]) << 24) | (uint32_t(blob[1]) << 16) |
                     (uint32_t(blob[2]) << 8)  |  uint32_t(blob[3]);
    if (len32 > kMaxPayload) return std::nullopt;
    size_t needed = 4 + static_cast<size_t>(len32);
    if (blob.size() < needed) return std::nullopt;
    // Chunk count must match exactly — no trailing junk, nothing missing.
    size_t expected_chunks = (needed + kChunkDataBytes - 1) / kChunkDataBytes;
    if (chunk_fields.size() != expected_chunks) return std::nullopt;

    return std::vector<uint8_t>(blob.begin() + 4, blob.begin() + 4 + len32);
}

// ===== parse_request =====

std::optional<HttpRequest> SemanticWrapper::parse_request(const uint8_t* bytes,
                                                          size_t len) {
    if (!bytes || len == 0) return std::nullopt;
    std::string s(reinterpret_cast<const char*>(bytes), len);
    return parse_request(s);
}

std::optional<HttpRequest> SemanticWrapper::parse_request(const std::string& s) {
    HttpRequest req;
    size_t pos = 0;

    // Request line: METHOD SP PATH SP HTTP/1.1 CRLF
    size_t eol = s.find("\r\n", pos);
    if (eol == std::string::npos) return std::nullopt;
    std::string line = s.substr(0, eol);
    size_t sp1 = line.find(' ');
    size_t sp2 = line.rfind(' ');
    if (sp1 == std::string::npos || sp2 == sp1) return std::nullopt;
    req.method = line.substr(0, sp1);
    req.path   = line.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string version = line.substr(sp2 + 1);
    if (version.rfind("HTTP/1.", 0) != 0) return std::nullopt;
    if (req.method.empty() || req.path.empty()) return std::nullopt;
    pos = eol + 2;

    // Headers until the empty line.
    while (true) {
        eol = s.find("\r\n", pos);
        if (eol == std::string::npos) return std::nullopt;
        if (eol == pos) { pos = eol + 2; break; } // end of headers
        std::string hline = s.substr(pos, eol - pos);
        size_t colon = hline.find(':');
        if (colon == std::string::npos || colon == 0) return std::nullopt;
        std::string name = hline.substr(0, colon);
        std::string value = hline.substr(colon + 1);
        size_t b = value.find_first_not_of(" \t");
        size_t e = value.find_last_not_of(" \t");
        value = (b == std::string::npos) ? std::string()
                                         : value.substr(b, e - b + 1);
        req.headers.emplace_back(std::move(name), std::move(value));
        pos = eol + 2;
    }

    // Body per Content-Length (if any).
    auto cl = req.header("Content-Length");
    if (cl) {
        // Strict, non-negative decimal parse.
        if (cl->empty()) return std::nullopt;
        size_t n = 0;
        for (char c : *cl) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
            n = n * 10 + static_cast<size_t>(c - '0');
            if (n > (4u << 20)) return std::nullopt; // sanity cap
        }
        if (s.size() - pos < n) return std::nullopt;
        req.body.assign(s.begin() + pos, s.begin() + pos + n);
    }
    return req;
}

} // namespace ncp
