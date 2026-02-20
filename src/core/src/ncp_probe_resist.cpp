#include "ncp_probe_resist.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>

// FIX #21 + #22: Use libsodium for HMAC-SHA256 fallback and CSPRNG.
// sodium is already linked project-wide (used in ncp_paranoid.cpp, i2p.cpp, etc.)
#include <sodium.h>

// Use OpenSSL HMAC if available (primary path)
#ifdef HAVE_OPENSSL
#  include <openssl/hmac.h>
#  include <openssl/sha.h>
#  include <openssl/evp.h>
#endif

namespace ncp {
namespace DPI {

// ===== String conversions =====

const char* cover_mode_to_string(CoverMode m) noexcept {
    switch (m) {
        case CoverMode::REDIRECT:    return "REDIRECT";
        case CoverMode::MIRROR:      return "MIRROR";
        case CoverMode::RESET:       return "RESET";
        case CoverMode::DROP:        return "DROP";
        case CoverMode::TARPIT:      return "TARPIT";
        case CoverMode::ECHO_NGINX:  return "ECHO_NGINX";
        case CoverMode::ECHO_IIS:    return "ECHO_IIS";
        case CoverMode::ECHO_APACHE: return "ECHO_APACHE";
        default: return "UNKNOWN";
    }
}

CoverMode cover_mode_from_string(const std::string& name) noexcept {
    if (name == "REDIRECT")    return CoverMode::REDIRECT;
    if (name == "MIRROR")      return CoverMode::MIRROR;
    if (name == "RESET")       return CoverMode::RESET;
    if (name == "DROP")        return CoverMode::DROP;
    if (name == "TARPIT")      return CoverMode::TARPIT;
    if (name == "ECHO_NGINX")  return CoverMode::ECHO_NGINX;
    if (name == "ECHO_IIS")    return CoverMode::ECHO_IIS;
    if (name == "ECHO_APACHE") return CoverMode::ECHO_APACHE;
    return CoverMode::ECHO_NGINX;
}

const char* auth_result_to_string(AuthResult r) noexcept {
    switch (r) {
        case AuthResult::AUTHENTICATED:       return "AUTHENTICATED";
        case AuthResult::REPLAY_DETECTED:     return "REPLAY_DETECTED";
        case AuthResult::INVALID_HMAC:        return "INVALID_HMAC";
        case AuthResult::NO_AUTH_DATA:        return "NO_AUTH_DATA";
        case AuthResult::RATE_LIMITED:        return "RATE_LIMITED";
        case AuthResult::IP_BANNED:           return "IP_BANNED";
        case AuthResult::BAD_TLS_FINGERPRINT: return "BAD_TLS_FINGERPRINT";
        case AuthResult::PROBE_PATTERN:       return "PROBE_PATTERN";
        default: return "UNKNOWN";
    }
}

// ===== CSPRNG =====

// FIX #22: Replace raw /dev/urandom read with randombytes_buf() from libsodium.
static void csprng_fill(uint8_t* buf, size_t len) {
    randombytes_buf(buf, len);
}

static std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

// ===== Config Presets =====

ProbeResistConfig ProbeResistConfig::strict() {
    ProbeResistConfig c;
    c.enable_auth = true;
    c.cover_mode = CoverMode::DROP;
    c.enable_replay_protection = true;
    c.enable_pattern_detection = true;
    c.burst_threshold = 3;
    c.burst_window_sec = 10;
    c.enable_ip_reputation = true;
    c.ban_threshold = -5;
    c.auth_fail_penalty = -5;
    c.replay_penalty = -10;
    c.temp_ban_duration_sec = 7200;
    c.enable_ja3_filter = true;
    c.enable_rate_limit = true;
    c.rate_limit_per_ip = 5;
    c.rate_limit_window_sec = 60;
    return c;
}

ProbeResistConfig ProbeResistConfig::balanced() {
    ProbeResistConfig c;
    c.enable_auth = true;
    c.cover_mode = CoverMode::ECHO_NGINX;
    c.enable_replay_protection = true;
    c.enable_pattern_detection = true;
    c.burst_threshold = 5;
    c.burst_window_sec = 10;
    c.enable_ip_reputation = true;
    c.ban_threshold = -10;
    c.auth_fail_penalty = -3;
    c.replay_penalty = -5;
    c.temp_ban_duration_sec = 3600;
    c.enable_ja3_filter = false;
    c.enable_rate_limit = true;
    c.rate_limit_per_ip = 10;
    c.rate_limit_window_sec = 60;
    return c;
}

ProbeResistConfig ProbeResistConfig::permissive() {
    ProbeResistConfig c;
    c.enable_auth = true;
    c.cover_mode = CoverMode::ECHO_NGINX;
    c.enable_replay_protection = true;
    c.enable_pattern_detection = false;
    c.enable_ip_reputation = true;
    c.ban_threshold = -20;
    c.auth_fail_penalty = -2;
    c.replay_penalty = -3;
    c.temp_ban_duration_sec = 1800;
    c.enable_ja3_filter = false;
    c.enable_rate_limit = true;
    c.rate_limit_per_ip = 30;
    c.rate_limit_window_sec = 60;
    return c;
}

// ===== Constructor / Destructor =====

ProbeResist::ProbeResist()
    : ProbeResist(ProbeResistConfig::balanced()) {}

ProbeResist::ProbeResist(const ProbeResistConfig& config)
    : config_(config) {
    // Populate scanner JA3 set
    for (const auto& ja3 : config_.known_scanner_ja3) {
        ja3_scanner_set_.insert(ja3);
    }
    for (const auto& ja3 : config_.ja3_allowlist) {
        ja3_allowlist_.insert(ja3);
    }
}

ProbeResist::~ProbeResist() = default;

// ===== Core: process_connection =====

// FIX #26: Snapshot config_ under shared_lock once at entry, then use
// the local copy for the entire call — zero contention on the hot path.
AuthResult ProbeResist::process_connection(
    const std::string& source_ip,
    uint16_t source_port,
    const uint8_t* data,
    size_t data_len,
    const std::string& ja3_fingerprint) {

    // Snapshot config under shared_lock (readers don't block each other)
    ProbeResistConfig cfg;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        cfg = config_;
    }

    stats_.total_connections.fetch_add(1);

    ProbeEvent event;
    event.source_ip = source_ip;
    event.source_port = source_port;
    event.ja3_fingerprint = ja3_fingerprint;
    event.payload_size = data_len;
    event.timestamp = std::chrono::system_clock::now();

    // L5: Check IP ban first (fastest)
    if (cfg.enable_ip_reputation && is_ip_banned(source_ip)) {
        stats_.rejected_ip_ban.fetch_add(1);
        event.result = AuthResult::IP_BANNED;
        event.details = "IP is banned";
        emit_event(event);
        return AuthResult::IP_BANNED;
    }

    // L7: Rate limiting
    if (cfg.enable_rate_limit && is_rate_limited(source_ip)) {
        stats_.rejected_rate_limit.fetch_add(1);
        if (cfg.enable_ip_reputation) {
            update_reputation(source_ip, -1);
        }
        event.result = AuthResult::RATE_LIMITED;
        event.details = "Rate limit exceeded";
        emit_event(event);
        return AuthResult::RATE_LIMITED;
    }

    // L6: JA3 filter
    if (cfg.enable_ja3_filter && !ja3_fingerprint.empty()) {
        if (!is_ja3_allowed(ja3_fingerprint)) {
            stats_.rejected_ja3.fetch_add(1);
            if (cfg.enable_ip_reputation) {
                update_reputation(source_ip, cfg.auth_fail_penalty);
            }
            event.result = AuthResult::BAD_TLS_FINGERPRINT;
            event.details = "JA3 not in allowlist: " + ja3_fingerprint;
            emit_event(event);
            return AuthResult::BAD_TLS_FINGERPRINT;
        }
    }

    // L4: Probe pattern detection
    if (cfg.enable_pattern_detection) {
        if (!ja3_fingerprint.empty() && is_known_scanner(ja3_fingerprint)) {
            stats_.rejected_probe_pattern.fetch_add(1);
            if (cfg.enable_ip_reputation) {
                update_reputation(source_ip, cfg.auth_fail_penalty * 2);
            }
            event.result = AuthResult::PROBE_PATTERN;
            event.details = "Known scanner JA3: " + ja3_fingerprint;
            emit_event(event);
            return AuthResult::PROBE_PATTERN;
        }

        if (is_probe_pattern(source_ip)) {
            stats_.rejected_probe_pattern.fetch_add(1);
            if (cfg.enable_ip_reputation) {
                update_reputation(source_ip, cfg.auth_fail_penalty);
            }
            event.result = AuthResult::PROBE_PATTERN;
            event.details = "Burst connection pattern detected";
            emit_event(event);
            return AuthResult::PROBE_PATTERN;
        }
    }

    // L1: Authentication
    if (cfg.enable_auth) {
        size_t required_len = cfg.auth_offset + cfg.nonce_length + 4 + cfg.auth_length;
        if (data_len < required_len) {
            stats_.rejected_no_auth.fetch_add(1);
            if (cfg.enable_ip_reputation) {
                update_reputation(source_ip, cfg.auth_fail_penalty);
            }
            event.result = AuthResult::NO_AUTH_DATA;
            event.details = "Packet too short for auth data";
            emit_event(event);
            return AuthResult::NO_AUTH_DATA;
        }

        const uint8_t* auth_start = data + cfg.auth_offset;
        const uint8_t* nonce = auth_start;
        const uint8_t* timestamp_bytes = nonce + cfg.nonce_length;
        const uint8_t* hmac_received = timestamp_bytes + 4;

        // Verify timestamp
        uint32_t pkt_timestamp = (static_cast<uint32_t>(timestamp_bytes[0]) << 24) |
                                 (static_cast<uint32_t>(timestamp_bytes[1]) << 16) |
                                 (static_cast<uint32_t>(timestamp_bytes[2]) << 8) |
                                  static_cast<uint32_t>(timestamp_bytes[3]);
        uint32_t now_ts = static_cast<uint32_t>(std::time(nullptr));
        uint32_t diff = (pkt_timestamp > now_ts) ? (pkt_timestamp - now_ts) : (now_ts - pkt_timestamp);

        if (diff > cfg.timestamp_tolerance_sec) {
            stats_.rejected_bad_hmac.fetch_add(1);
            if (cfg.enable_ip_reputation) {
                update_reputation(source_ip, cfg.auth_fail_penalty);
            }
            event.result = AuthResult::INVALID_HMAC;
            event.details = "Timestamp out of tolerance: delta=" + std::to_string(diff) + "s";
            emit_event(event);
            return AuthResult::INVALID_HMAC;
        }

        // Compute expected HMAC over [nonce | timestamp]
        size_t msg_len = cfg.nonce_length + 4;
        auto expected_hmac = compute_hmac(
            auth_start, msg_len,
            cfg.shared_secret.data(), cfg.shared_secret.size());

        // FIX #23: sodium_memcmp for constant-time comparison
        size_t cmp_len = (std::min)(size_t(32), cfg.auth_length);
        bool hmac_valid = (sodium_memcmp(hmac_received, expected_hmac.data(), cmp_len) == 0);

        if (!hmac_valid) {
            stats_.rejected_bad_hmac.fetch_add(1);
            if (cfg.enable_ip_reputation) {
                update_reputation(source_ip, cfg.auth_fail_penalty);
            }
            event.result = AuthResult::INVALID_HMAC;
            event.details = "HMAC mismatch";
            emit_event(event);
            return AuthResult::INVALID_HMAC;
        }

        // L3: Replay protection
        if (cfg.enable_replay_protection) {
            if (!check_and_record_nonce(nonce, cfg.nonce_length)) {
                stats_.rejected_replay.fetch_add(1);
                stats_.replays_caught.fetch_add(1);
                if (cfg.enable_ip_reputation) {
                    update_reputation(source_ip, cfg.replay_penalty);
                }
                event.result = AuthResult::REPLAY_DETECTED;
                event.details = "Nonce replay detected";
                emit_event(event);
                return AuthResult::REPLAY_DETECTED;
            }
        }

        // All checks passed
        stats_.authenticated.fetch_add(1);
        if (cfg.enable_ip_reputation) {
            update_reputation(source_ip, cfg.auth_success_reward);
        }
        event.result = AuthResult::AUTHENTICATED;
        event.details = "OK";
        emit_event(event);
        return AuthResult::AUTHENTICATED;
    }

    // Auth disabled — let through
    stats_.authenticated.fetch_add(1);
    event.result = AuthResult::AUTHENTICATED;
    emit_event(event);
    return AuthResult::AUTHENTICATED;
}

// ===== L1: generate_client_auth =====

// FIX #26: snapshot config_ under shared_lock
std::vector<uint8_t> ProbeResist::generate_client_auth() {
    ProbeResistConfig cfg;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        cfg = config_;
    }

    std::vector<uint8_t> token;
    token.resize(cfg.nonce_length + 4);

    csprng_fill(token.data(), cfg.nonce_length);

    uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
    token[cfg.nonce_length + 0] = (ts >> 24) & 0xFF;
    token[cfg.nonce_length + 1] = (ts >> 16) & 0xFF;
    token[cfg.nonce_length + 2] = (ts >> 8) & 0xFF;
    token[cfg.nonce_length + 3] = ts & 0xFF;

    auto hmac = compute_hmac(
        token.data(), token.size(),
        cfg.shared_secret.data(), cfg.shared_secret.size());

    token.insert(token.end(), hmac.begin(), hmac.end());
    return token;
}

// FIX #26: snapshot config_ under shared_lock
bool ProbeResist::verify_auth(const uint8_t* data, size_t data_len) {
    ProbeResistConfig cfg;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        cfg = config_;
    }

    size_t required = cfg.nonce_length + 4 + cfg.auth_length;
    if (data_len < required) return false;

    const uint8_t* hmac_received = data + cfg.nonce_length + 4;

    size_t msg_len = cfg.nonce_length + 4;
    auto expected = compute_hmac(data, msg_len,
        cfg.shared_secret.data(), cfg.shared_secret.size());

    return (sodium_memcmp(hmac_received, expected.data(), 32) == 0);
}

// FIX #21: compute_hmac — fallback uses crypto_auth_hmacsha256 from libsodium
std::array<uint8_t, 32> ProbeResist::compute_hmac(
    const uint8_t* data, size_t data_len,
    const uint8_t* key, size_t key_len) {

    std::array<uint8_t, 32> result{};

#ifdef HAVE_OPENSSL
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, static_cast<int>(key_len),
         data, data_len, result.data(), &out_len);
#else
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, data, data_len);
    crypto_auth_hmacsha256_final(&state, result.data());
    sodium_memzero(&state, sizeof(state));
#endif

    return result;
}

// ===== L2: Cover Responses =====

// FIX #26: snapshot config_ under shared_lock
std::vector<uint8_t> ProbeResist::generate_cover_response(
    const uint8_t* request_data, size_t request_len) {

    stats_.cover_responses_sent.fetch_add(1);
    (void)request_data;
    (void)request_len;

    ProbeResistConfig cfg;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        cfg = config_;
    }

    switch (cfg.cover_mode) {
        case CoverMode::REDIRECT:
            return generate_redirect(cfg.cover_site_url);
        case CoverMode::ECHO_NGINX:
            return generate_nginx_default();
        case CoverMode::ECHO_IIS:
            return generate_iis_default();
        case CoverMode::ECHO_APACHE:
            return generate_apache_default();
        case CoverMode::RESET:
        case CoverMode::DROP:
        case CoverMode::TARPIT:
            return {};
        case CoverMode::MIRROR:
            return {};
        default:
            return generate_nginx_default();
    }
}

std::vector<uint8_t> ProbeResist::generate_nginx_default() {
    std::string html =
        "<html>\r\n"
        "<head><title>Welcome to nginx!</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>Welcome to nginx!</h1></center>\r\n"
        "<hr><center>nginx/1.24.0</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char date_buf[64];
    struct tm gmt;
#ifdef _WIN32
    gmtime_s(&gmt, &t);
#else
    gmtime_r(&t, &gmt);
#endif
    strftime(date_buf, sizeof(date_buf), "%a, %d %b %Y %H:%M:%S GMT", &gmt);

    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n";
    resp << "Server: nginx/1.24.0\r\n";
    resp << "Date: " << date_buf << "\r\n";
    resp << "Content-Type: text/html\r\n";
    resp << "Content-Length: " << html.size() << "\r\n";
    resp << "Connection: close\r\n";
    resp << "Accept-Ranges: bytes\r\n";
    resp << "\r\n";
    resp << html;

    std::string s = resp.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> ProbeResist::generate_iis_default() {
    std::string html =
        "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
        "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n"
        "<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n"
        "<head><title>IIS Windows Server</title></head>\r\n"
        "<body><img src=\"iisstart.png\" alt=\"IIS\" /></body>\r\n"
        "</html>\r\n";

    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n";
    resp << "Content-Type: text/html\r\n";
    resp << "Server: Microsoft-IIS/10.0\r\n";
    resp << "Content-Length: " << html.size() << "\r\n";
    resp << "Connection: close\r\n";
    resp << "\r\n";
    resp << html;

    std::string s = resp.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> ProbeResist::generate_apache_default() {
    std::string html =
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" "
        "\"http://www.w3.org/TR/html4/strict.dtd\">\r\n"
        "<html><head><title>Apache2 Default Page: It works</title></head>\r\n"
        "<body><h1>It works!</h1></body></html>\r\n";

    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n";
    resp << "Server: Apache/2.4.57\r\n";
    resp << "Content-Type: text/html; charset=UTF-8\r\n";
    resp << "Content-Length: " << html.size() << "\r\n";
    resp << "Connection: close\r\n";
    resp << "\r\n";
    resp << html;

    std::string s = resp.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> ProbeResist::generate_redirect(const std::string& url) {
    std::string html = "<html><body>Moved</body></html>";

    std::ostringstream resp;
    resp << "HTTP/1.1 301 Moved Permanently\r\n";
    resp << "Location: " << url << "\r\n";
    resp << "Server: nginx/1.24.0\r\n";
    resp << "Content-Type: text/html\r\n";
    resp << "Content-Length: " << html.size() << "\r\n";
    resp << "Connection: close\r\n";
    resp << "\r\n";
    resp << html;

    std::string s = resp.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

// ===== L3: Replay Protection =====

// FIX #25: hex_str pre-computed in NonceEntry.
// FIX #26: snapshot config_ for nonce_window_size / nonce_expiry_sec.
bool ProbeResist::check_and_record_nonce(const uint8_t* nonce, size_t nonce_len) {
    std::string hex = bytes_to_hex(nonce, nonce_len);

    // Snapshot config values we need
    size_t window_size;
    uint32_t expiry_sec;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        window_size = config_.nonce_window_size;
        expiry_sec = config_.nonce_expiry_sec;
    }

    std::lock_guard<std::mutex> lock(nonce_mutex_);

    if (nonce_set_.count(hex) > 0) {
        return false;  // replay!
    }

    auto now = std::chrono::steady_clock::now();
    while (!nonce_window_.empty() && nonce_window_.front().expiry < now) {
        nonce_set_.erase(nonce_window_.front().hex_str);
        nonce_window_.pop_front();
    }

    while (nonce_window_.size() >= window_size) {
        nonce_set_.erase(nonce_window_.front().hex_str);
        nonce_window_.pop_front();
    }

    NonceEntry entry;
    std::memset(entry.hash.data(), 0, 32);
    std::memcpy(entry.hash.data(), nonce, (std::min)(nonce_len, size_t(32)));
    entry.hex_str = hex;
    entry.expiry = now + std::chrono::seconds(expiry_sec);

    nonce_window_.push_back(std::move(entry));
    nonce_set_.insert(hex);

    return true;
}

void ProbeResist::evict_expired_nonces() {
    std::lock_guard<std::mutex> lock(nonce_mutex_);
    auto now = std::chrono::steady_clock::now();
    while (!nonce_window_.empty() && nonce_window_.front().expiry < now) {
        nonce_set_.erase(nonce_window_.front().hex_str);
        nonce_window_.pop_front();
    }
}

// ===== L4: Probe Pattern Detection =====

// FIX #26: snapshot config_ for burst params
bool ProbeResist::is_probe_pattern(const std::string& source_ip) {
    uint32_t burst_window;
    uint32_t burst_threshold;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        burst_window = config_.burst_window_sec;
        burst_threshold = config_.burst_threshold;
    }

    std::lock_guard<std::mutex> lock(conn_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto& history = conn_history_[source_ip];

    history.push_back({now});

    auto cutoff = now - std::chrono::seconds(burst_window);
    while (!history.empty() && history.front().time < cutoff) {
        history.pop_front();
    }

    return history.size() >= burst_threshold;
}

bool ProbeResist::is_known_scanner(const std::string& ja3) const {
    std::lock_guard<std::mutex> lock(ja3_mutex_);
    return ja3_scanner_set_.count(ja3) > 0;
}

// ===== L5: IP Reputation =====

IPReputation ProbeResist::get_ip_reputation(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto it = ip_reputation_.find(ip);
    if (it != ip_reputation_.end()) {
        return it->second;
    }
    IPReputation rep;
    rep.ip = ip;
    return rep;
}

// FIX #26: snapshot config_ for reputation params
// FIX #27: O(log n) eviction via ip_eviction_index_ instead of O(n) full scan
void ProbeResist::update_reputation(const std::string& ip, int32_t delta) {
    // Snapshot config values we need
    int32_t ban_threshold;
    uint32_t temp_ban_sec;
    size_t max_tracked;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        ban_threshold = config_.ban_threshold;
        temp_ban_sec = config_.temp_ban_duration_sec;
        max_tracked = config_.max_tracked_ips;
    }

    std::lock_guard<std::mutex> lock(ip_mutex_);

    auto& rep = ip_reputation_[ip];
    auto now = std::chrono::system_clock::now();

    // Remove old eviction index entry before updating last_seen
    if (!rep.ip.empty()) {
        ip_eviction_index_.erase({rep.last_seen, ip});
    } else {
        rep.ip = ip;
        rep.first_seen = now;
    }

    rep.last_seen = now;
    rep.total_connections++;
    rep.score += delta;

    if (delta < 0) {
        rep.failed_auths++;
    } else if (delta > 0) {
        rep.successful_auths++;
    }

    // Insert updated eviction index entry
    ip_eviction_index_.insert({rep.last_seen, ip});

    // Auto-ban check
    if (rep.score <= ban_threshold && !rep.is_banned) {
        rep.is_banned = true;
        if (temp_ban_sec > 0) {
            rep.ban_until = now + std::chrono::seconds(temp_ban_sec);
        }
        stats_.ips_banned.fetch_add(1);
    }

    // FIX #27: Memory limit — O(log n) eviction via sorted index
    // Pop the oldest entry with positive score from the front of the index.
    while (ip_reputation_.size() > max_tracked) {
        bool evicted = false;
        auto it = ip_eviction_index_.begin();
        while (it != ip_eviction_index_.end()) {
            auto map_it = ip_reputation_.find(it->second);
            if (map_it != ip_reputation_.end() && map_it->second.score >= 0) {
                ip_reputation_.erase(map_it);
                it = ip_eviction_index_.erase(it);
                evicted = true;
                break;
            }
            ++it;
        }
        if (!evicted) break;  // only negative-score IPs left, can't evict
    }
}

bool ProbeResist::is_ip_banned(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto it = ip_reputation_.find(ip);
    if (it == ip_reputation_.end()) return false;
    if (!it->second.is_banned) return false;

    auto ban_until = it->second.ban_until;
    if (ban_until != std::chrono::system_clock::time_point{} &&
        std::chrono::system_clock::now() > ban_until) {
        return false;
    }
    return true;
}

// FIX #27: maintain eviction index
void ProbeResist::ban_ip(const std::string& ip, uint32_t duration_sec) {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto& rep = ip_reputation_[ip];

    // Remove stale index entry if exists
    if (!rep.ip.empty()) {
        ip_eviction_index_.erase({rep.last_seen, ip});
    }

    rep.ip = ip;
    rep.is_banned = true;
    auto now = std::chrono::system_clock::now();
    if (rep.last_seen == std::chrono::system_clock::time_point{}) {
        rep.last_seen = now;
        rep.first_seen = now;
    }
    if (duration_sec > 0) {
        rep.ban_until = now + std::chrono::seconds(duration_sec);
    } else {
        rep.ban_until = {};
    }

    ip_eviction_index_.insert({rep.last_seen, ip});
    stats_.ips_banned.fetch_add(1);
}

// FIX #27: maintain eviction index
void ProbeResist::unban_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto it = ip_reputation_.find(ip);
    if (it != ip_reputation_.end()) {
        it->second.is_banned = false;
        it->second.score = 0;
        // No index change needed — last_seen unchanged
    }
}

std::vector<std::string> ProbeResist::get_banned_ips() const {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    std::vector<std::string> result;
    for (const auto& pair : ip_reputation_) {
        if (pair.second.is_banned) {
            result.push_back(pair.first);
        }
    }
    return result;
}

// ===== L6: JA3 Filter =====

bool ProbeResist::is_ja3_allowed(const std::string& ja3) const {
    std::lock_guard<std::mutex> lock(ja3_mutex_);
    if (ja3_allowlist_.empty()) return true;
    return ja3_allowlist_.count(ja3) > 0;
}

void ProbeResist::add_ja3_allowlist(const std::string& ja3) {
    std::lock_guard<std::mutex> lock(ja3_mutex_);
    ja3_allowlist_.insert(ja3);
}

void ProbeResist::remove_ja3_allowlist(const std::string& ja3) {
    std::lock_guard<std::mutex> lock(ja3_mutex_);
    ja3_allowlist_.erase(ja3);
}

// ===== L7: Rate Limiting =====

// FIX #26: snapshot config_ for rate limit params
bool ProbeResist::is_rate_limited(const std::string& ip) {
    uint32_t window_sec;
    uint32_t limit_per_ip;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        window_sec = config_.rate_limit_window_sec;
        limit_per_ip = config_.rate_limit_per_ip;
    }

    std::lock_guard<std::mutex> lock(rate_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto& entry = rate_limits_[ip];

    auto window = std::chrono::seconds(window_sec);
    if (now - entry.window_start > window) {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count++;
    return entry.count > limit_per_ip;
}

// ===== Events & Config =====

void ProbeResist::set_event_callback(ProbeEventCallback callback) {
    event_callback_ = callback;
}

void ProbeResist::emit_event(const ProbeEvent& event) {
    if (event_callback_) {
        event_callback_(event);
    }
}

// FIX #26: unique_lock on config_mutex_ — exclusive write
void ProbeResist::set_config(const ProbeResistConfig& config) {
    {
        std::unique_lock<std::shared_mutex> lk(config_mutex_);
        config_ = config;
    }
    // FIX #24: Lock ja3_mutex_ when rebuilding JA3 sets from config
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        std::lock_guard<std::mutex> lock(ja3_mutex_);
        ja3_scanner_set_.clear();
        for (const auto& ja3 : config_.known_scanner_ja3) {
            ja3_scanner_set_.insert(ja3);
        }
        ja3_allowlist_.clear();
        for (const auto& ja3 : config_.ja3_allowlist) {
            ja3_allowlist_.insert(ja3);
        }
    }
}

// FIX #26: shared_lock on config_mutex_ — concurrent reads OK
ProbeResistConfig ProbeResist::get_config() const {
    std::shared_lock<std::shared_mutex> lk(config_mutex_);
    return config_;
}

ProbeResistStats ProbeResist::get_stats() const {
    return ProbeResistStats(stats_);
}

void ProbeResist::reset_stats() {
    stats_.reset();
}

// FIX #26: snapshot config_ for cleanup params
// FIX #27: maintain eviction index during cleanup
void ProbeResist::cleanup_stale_data() {
    // Snapshot config values needed for cleanup
    int32_t ban_threshold;
    uint32_t rate_window_sec;
    uint32_t burst_window_sec;
    {
        std::shared_lock<std::shared_mutex> lk(config_mutex_);
        ban_threshold = config_.ban_threshold;
        rate_window_sec = config_.rate_limit_window_sec;
        burst_window_sec = config_.burst_window_sec;
    }

    // Unban expired IPs
    {
        std::lock_guard<std::mutex> lock(ip_mutex_);
        auto now = std::chrono::system_clock::now();
        for (auto& pair : ip_reputation_) {
            if (pair.second.is_banned &&
                pair.second.ban_until != std::chrono::system_clock::time_point{} &&
                now > pair.second.ban_until) {
                pair.second.is_banned = false;
                pair.second.score = ban_threshold / 2;
                // score changed but last_seen unchanged — no index update needed
            }
        }
    }

    // Clean old rate limit entries
    {
        std::lock_guard<std::mutex> lock(rate_mutex_);
        auto now = std::chrono::steady_clock::now();
        auto window = std::chrono::seconds(rate_window_sec * 2);
        for (auto it = rate_limits_.begin(); it != rate_limits_.end();) {
            if (now - it->second.window_start > window) {
                it = rate_limits_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean old connection history
    {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        auto now = std::chrono::steady_clock::now();
        auto cutoff = now - std::chrono::seconds(burst_window_sec * 3);
        for (auto it = conn_history_.begin(); it != conn_history_.end();) {
            while (!it->second.empty() && it->second.front().time < cutoff) {
                it->second.pop_front();
            }
            if (it->second.empty()) {
                it = conn_history_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Evict expired nonces
    evict_expired_nonces();
}

} // namespace DPI
} // namespace ncp
