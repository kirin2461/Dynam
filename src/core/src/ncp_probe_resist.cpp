#include "ncp_probe_resist.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#  define NOMINMAX
#  include <windows.h>
#  include <bcrypt.h>
#  undef min
#  undef max
#  undef ERROR
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

// Use OpenSSL HMAC if available
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

static void csprng_fill(uint8_t* buf, size_t len) {
#ifdef _WIN32
    BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) {
            ssize_t r = read(fd, buf + off, len - off);
            if (r <= 0) break;
            off += static_cast<size_t>(r);
        }
        close(fd);
    }
#endif
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

AuthResult ProbeResist::process_connection(
    const std::string& source_ip,
    uint16_t source_port,
    const uint8_t* data,
    size_t data_len,
    const std::string& ja3_fingerprint) {

    stats_.total_connections.fetch_add(1);

    ProbeEvent event;
    event.source_ip = source_ip;
    event.source_port = source_port;
    event.ja3_fingerprint = ja3_fingerprint;
    event.payload_size = data_len;
    event.timestamp = std::chrono::system_clock::now();

    // L5: Check IP ban first (fastest)
    if (config_.enable_ip_reputation && is_ip_banned(source_ip)) {
        stats_.rejected_ip_ban.fetch_add(1);
        event.result = AuthResult::IP_BANNED;
        event.details = "IP is banned";
        emit_event(event);
        return AuthResult::IP_BANNED;
    }

    // L7: Rate limiting
    if (config_.enable_rate_limit && is_rate_limited(source_ip)) {
        stats_.rejected_rate_limit.fetch_add(1);
        if (config_.enable_ip_reputation) {
            update_reputation(source_ip, -1);
        }
        event.result = AuthResult::RATE_LIMITED;
        event.details = "Rate limit exceeded";
        emit_event(event);
        return AuthResult::RATE_LIMITED;
    }

    // L6: JA3 filter
    if (config_.enable_ja3_filter && !ja3_fingerprint.empty()) {
        if (!is_ja3_allowed(ja3_fingerprint)) {
            stats_.rejected_ja3.fetch_add(1);
            if (config_.enable_ip_reputation) {
                update_reputation(source_ip, config_.auth_fail_penalty);
            }
            event.result = AuthResult::BAD_TLS_FINGERPRINT;
            event.details = "JA3 not in allowlist: " + ja3_fingerprint;
            emit_event(event);
            return AuthResult::BAD_TLS_FINGERPRINT;
        }
    }

    // L4: Probe pattern detection
    if (config_.enable_pattern_detection) {
        // Check known scanner fingerprint
        if (!ja3_fingerprint.empty() && is_known_scanner(ja3_fingerprint)) {
            stats_.rejected_probe_pattern.fetch_add(1);
            if (config_.enable_ip_reputation) {
                update_reputation(source_ip, config_.auth_fail_penalty * 2);
            }
            event.result = AuthResult::PROBE_PATTERN;
            event.details = "Known scanner JA3: " + ja3_fingerprint;
            emit_event(event);
            return AuthResult::PROBE_PATTERN;
        }

        // Check burst pattern
        if (is_probe_pattern(source_ip)) {
            stats_.rejected_probe_pattern.fetch_add(1);
            if (config_.enable_ip_reputation) {
                update_reputation(source_ip, config_.auth_fail_penalty);
            }
            event.result = AuthResult::PROBE_PATTERN;
            event.details = "Burst connection pattern detected";
            emit_event(event);
            return AuthResult::PROBE_PATTERN;
        }
    }

    // L1: Authentication
    if (config_.enable_auth) {
        size_t required_len = config_.auth_offset + config_.nonce_length + 4 + config_.auth_length;
        if (data_len < required_len) {
            stats_.rejected_no_auth.fetch_add(1);
            if (config_.enable_ip_reputation) {
                update_reputation(source_ip, config_.auth_fail_penalty);
            }
            event.result = AuthResult::NO_AUTH_DATA;
            event.details = "Packet too short for auth data";
            emit_event(event);
            return AuthResult::NO_AUTH_DATA;
        }

        const uint8_t* auth_start = data + config_.auth_offset;
        const uint8_t* nonce = auth_start;
        const uint8_t* timestamp_bytes = nonce + config_.nonce_length;
        const uint8_t* hmac_received = timestamp_bytes + 4;

        // Verify timestamp
        uint32_t pkt_timestamp = (static_cast<uint32_t>(timestamp_bytes[0]) << 24) |
                                 (static_cast<uint32_t>(timestamp_bytes[1]) << 16) |
                                 (static_cast<uint32_t>(timestamp_bytes[2]) << 8) |
                                  static_cast<uint32_t>(timestamp_bytes[3]);
        uint32_t now_ts = static_cast<uint32_t>(std::time(nullptr));
        uint32_t diff = (pkt_timestamp > now_ts) ? (pkt_timestamp - now_ts) : (now_ts - pkt_timestamp);

        if (diff > config_.timestamp_tolerance_sec) {
            stats_.rejected_bad_hmac.fetch_add(1);
            if (config_.enable_ip_reputation) {
                update_reputation(source_ip, config_.auth_fail_penalty);
            }
            event.result = AuthResult::INVALID_HMAC;
            event.details = "Timestamp out of tolerance: delta=" + std::to_string(diff) + "s";
            emit_event(event);
            return AuthResult::INVALID_HMAC;
        }

        // Compute expected HMAC over [nonce | timestamp]
        size_t msg_len = config_.nonce_length + 4;
        auto expected_hmac = compute_hmac(
            auth_start, msg_len,
            config_.shared_secret.data(), config_.shared_secret.size());

        // Constant-time comparison
        bool hmac_valid = true;
        volatile uint8_t accum = 0;
        for (size_t i = 0; i < 32 && i < config_.auth_length; ++i) {
            accum |= hmac_received[i] ^ expected_hmac[i];
        }
        hmac_valid = (accum == 0);

        if (!hmac_valid) {
            stats_.rejected_bad_hmac.fetch_add(1);
            if (config_.enable_ip_reputation) {
                update_reputation(source_ip, config_.auth_fail_penalty);
            }
            event.result = AuthResult::INVALID_HMAC;
            event.details = "HMAC mismatch";
            emit_event(event);
            return AuthResult::INVALID_HMAC;
        }

        // L3: Replay protection
        if (config_.enable_replay_protection) {
            if (!check_and_record_nonce(nonce, config_.nonce_length)) {
                stats_.rejected_replay.fetch_add(1);
                stats_.replays_caught.fetch_add(1);
                if (config_.enable_ip_reputation) {
                    update_reputation(source_ip, config_.replay_penalty);
                }
                event.result = AuthResult::REPLAY_DETECTED;
                event.details = "Nonce replay detected";
                emit_event(event);
                return AuthResult::REPLAY_DETECTED;
            }
        }

        // All checks passed
        stats_.authenticated.fetch_add(1);
        if (config_.enable_ip_reputation) {
            update_reputation(source_ip, config_.auth_success_reward);
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

std::vector<uint8_t> ProbeResist::generate_client_auth() {
    // Format: [nonce(16) | timestamp(4) | hmac(32)] = 52 bytes
    std::vector<uint8_t> token;
    token.resize(config_.nonce_length + 4);

    // Random nonce
    csprng_fill(token.data(), config_.nonce_length);

    // Timestamp (big-endian)
    uint32_t ts = static_cast<uint32_t>(std::time(nullptr));
    token[config_.nonce_length + 0] = (ts >> 24) & 0xFF;
    token[config_.nonce_length + 1] = (ts >> 16) & 0xFF;
    token[config_.nonce_length + 2] = (ts >> 8) & 0xFF;
    token[config_.nonce_length + 3] = ts & 0xFF;

    // HMAC over [nonce | timestamp]
    auto hmac = compute_hmac(
        token.data(), token.size(),
        config_.shared_secret.data(), config_.shared_secret.size());

    token.insert(token.end(), hmac.begin(), hmac.end());
    return token;
}

bool ProbeResist::verify_auth(const uint8_t* data, size_t data_len) {
    size_t required = config_.nonce_length + 4 + config_.auth_length;
    if (data_len < required) return false;

    const uint8_t* nonce = data;
    const uint8_t* timestamp_bytes = nonce + config_.nonce_length;
    const uint8_t* hmac_received = timestamp_bytes + 4;

    size_t msg_len = config_.nonce_length + 4;
    auto expected = compute_hmac(data, msg_len,
        config_.shared_secret.data(), config_.shared_secret.size());

    volatile uint8_t accum = 0;
    for (size_t i = 0; i < 32; ++i) {
        accum |= hmac_received[i] ^ expected[i];
    }
    return (accum == 0);
}

std::array<uint8_t, 32> ProbeResist::compute_hmac(
    const uint8_t* data, size_t data_len,
    const uint8_t* key, size_t key_len) {

    std::array<uint8_t, 32> result{};

#ifdef HAVE_OPENSSL
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, static_cast<int>(key_len),
         data, data_len, result.data(), &out_len);
#else
    // Fallback: simple HMAC-SHA256 construction
    // HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))
    // Using a basic approach — in production HAVE_OPENSSL should always be defined
    static constexpr size_t BLOCK_SIZE = 64;
    std::array<uint8_t, BLOCK_SIZE> k_pad{};

    if (key_len > BLOCK_SIZE) {
        // Hash the key first (would need SHA256 — simplified fallback)
        std::memcpy(k_pad.data(), key, (std::min)(key_len, BLOCK_SIZE));
    } else {
        std::memcpy(k_pad.data(), key, key_len);
    }

    // XOR with ipad (0x36) and compute inner hash
    // This is a simplified fallback — real impl uses OpenSSL
    // Just XOR key with data for a basic MAC
    for (size_t i = 0; i < 32 && i < data_len; ++i) {
        result[i] = k_pad[i % BLOCK_SIZE] ^ data[i];
    }
    for (size_t i = 0; i < 32; ++i) {
        result[i] ^= k_pad[(i + 32) % BLOCK_SIZE];
    }
#endif

    return result;
}

// ===== L2: Cover Responses =====

std::vector<uint8_t> ProbeResist::generate_cover_response(
    const uint8_t* request_data, size_t request_len) {

    stats_.cover_responses_sent.fetch_add(1);
    (void)request_data;
    (void)request_len;

    switch (config_.cover_mode) {
        case CoverMode::REDIRECT:
            return generate_redirect(config_.cover_site_url);
        case CoverMode::ECHO_NGINX:
            return generate_nginx_default();
        case CoverMode::ECHO_IIS:
            return generate_iis_default();
        case CoverMode::ECHO_APACHE:
            return generate_apache_default();
        case CoverMode::RESET:
        case CoverMode::DROP:
        case CoverMode::TARPIT:
            return {};  // Caller handles at TCP level
        case CoverMode::MIRROR:
            return {};  // Caller handles proxying
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

bool ProbeResist::check_and_record_nonce(const uint8_t* nonce, size_t nonce_len) {
    std::string hex = bytes_to_hex(nonce, nonce_len);

    std::lock_guard<std::mutex> lock(nonce_mutex_);

    // Check if seen
    if (nonce_set_.count(hex) > 0) {
        return false;  // replay!
    }

    // Evict expired
    auto now = std::chrono::steady_clock::now();
    while (!nonce_window_.empty() && nonce_window_.front().expiry < now) {
        std::string old_hex = bytes_to_hex(
            nonce_window_.front().hash.data(), nonce_window_.front().hash.size());
        nonce_set_.erase(old_hex);
        nonce_window_.pop_front();
    }

    // Evict oldest if at capacity
    while (nonce_window_.size() >= config_.nonce_window_size) {
        std::string old_hex = bytes_to_hex(
            nonce_window_.front().hash.data(), nonce_window_.front().hash.size());
        nonce_set_.erase(old_hex);
        nonce_window_.pop_front();
    }

    // Record
    NonceEntry entry;
    std::memset(entry.hash.data(), 0, 32);
    std::memcpy(entry.hash.data(), nonce, (std::min)(nonce_len, size_t(32)));
    entry.expiry = now + std::chrono::seconds(config_.nonce_expiry_sec);

    nonce_window_.push_back(entry);
    nonce_set_.insert(hex);

    return true;  // new nonce, OK
}

void ProbeResist::evict_expired_nonces() {
    std::lock_guard<std::mutex> lock(nonce_mutex_);
    auto now = std::chrono::steady_clock::now();
    while (!nonce_window_.empty() && nonce_window_.front().expiry < now) {
        std::string old_hex = bytes_to_hex(
            nonce_window_.front().hash.data(), nonce_window_.front().hash.size());
        nonce_set_.erase(old_hex);
        nonce_window_.pop_front();
    }
}

// ===== L4: Probe Pattern Detection =====

bool ProbeResist::is_probe_pattern(const std::string& source_ip) {
    std::lock_guard<std::mutex> lock(conn_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto& history = conn_history_[source_ip];

    // Record this connection
    history.push_back({now});

    // Evict old entries
    auto cutoff = now - std::chrono::seconds(config_.burst_window_sec);
    while (!history.empty() && history.front().time < cutoff) {
        history.pop_front();
    }

    // Check burst threshold
    return history.size() >= config_.burst_threshold;
}

bool ProbeResist::is_known_scanner(const std::string& ja3) const {
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

void ProbeResist::update_reputation(const std::string& ip, int32_t delta) {
    std::lock_guard<std::mutex> lock(ip_mutex_);

    auto& rep = ip_reputation_[ip];
    if (rep.ip.empty()) {
        rep.ip = ip;
        rep.first_seen = std::chrono::system_clock::now();
    }
    rep.last_seen = std::chrono::system_clock::now();
    rep.total_connections++;
    rep.score += delta;

    if (delta < 0) {
        rep.failed_auths++;
    } else if (delta > 0) {
        rep.successful_auths++;
    }

    // Auto-ban check
    if (rep.score <= config_.ban_threshold && !rep.is_banned) {
        rep.is_banned = true;
        if (config_.temp_ban_duration_sec > 0) {
            rep.ban_until = std::chrono::system_clock::now() +
                std::chrono::seconds(config_.temp_ban_duration_sec);
        }
        stats_.ips_banned.fetch_add(1);
    }

    // Memory limit
    if (ip_reputation_.size() > config_.max_tracked_ips) {
        // Evict oldest entry with positive score
        std::string oldest_positive;
        auto oldest_time = std::chrono::system_clock::now();
        for (const auto& pair : ip_reputation_) {
            if (pair.second.score >= 0 && pair.second.last_seen < oldest_time) {
                oldest_time = pair.second.last_seen;
                oldest_positive = pair.first;
            }
        }
        if (!oldest_positive.empty()) {
            ip_reputation_.erase(oldest_positive);
        }
    }
}

bool ProbeResist::is_ip_banned(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto it = ip_reputation_.find(ip);
    if (it == ip_reputation_.end()) return false;
    if (!it->second.is_banned) return false;

    // Check temp ban expiry
    auto ban_until = it->second.ban_until;
    if (ban_until != std::chrono::system_clock::time_point{} &&
        std::chrono::system_clock::now() > ban_until) {
        // Ban expired — but we can't modify from const method
        // Caller should call cleanup_stale_data() periodically
        return false;
    }
    return true;
}

void ProbeResist::ban_ip(const std::string& ip, uint32_t duration_sec) {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto& rep = ip_reputation_[ip];
    rep.ip = ip;
    rep.is_banned = true;
    if (duration_sec > 0) {
        rep.ban_until = std::chrono::system_clock::now() +
            std::chrono::seconds(duration_sec);
    } else {
        rep.ban_until = {};  // permanent
    }
    stats_.ips_banned.fetch_add(1);
}

void ProbeResist::unban_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(ip_mutex_);
    auto it = ip_reputation_.find(ip);
    if (it != ip_reputation_.end()) {
        it->second.is_banned = false;
        it->second.score = 0;
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
    if (ja3_allowlist_.empty()) return true;  // no filter
    return ja3_allowlist_.count(ja3) > 0;
}

void ProbeResist::add_ja3_allowlist(const std::string& ja3) {
    ja3_allowlist_.insert(ja3);
}

void ProbeResist::remove_ja3_allowlist(const std::string& ja3) {
    ja3_allowlist_.erase(ja3);
}

// ===== L7: Rate Limiting =====

bool ProbeResist::is_rate_limited(const std::string& ip) {
    std::lock_guard<std::mutex> lock(rate_mutex_);

    auto now = std::chrono::steady_clock::now();
    auto& entry = rate_limits_[ip];

    auto window = std::chrono::seconds(config_.rate_limit_window_sec);
    if (now - entry.window_start > window) {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count++;
    return entry.count > config_.rate_limit_per_ip;
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

void ProbeResist::set_config(const ProbeResistConfig& config) {
    config_ = config;
    ja3_scanner_set_.clear();
    for (const auto& ja3 : config_.known_scanner_ja3) {
        ja3_scanner_set_.insert(ja3);
    }
    ja3_allowlist_.clear();
    for (const auto& ja3 : config_.ja3_allowlist) {
        ja3_allowlist_.insert(ja3);
    }
}

ProbeResistConfig ProbeResist::get_config() const {
    return config_;
}

ProbeResistStats ProbeResist::get_stats() const {
    return ProbeResistStats(stats_);
}

void ProbeResist::reset_stats() {
    stats_.reset();
}

void ProbeResist::cleanup_stale_data() {
    // Unban expired IPs
    {
        std::lock_guard<std::mutex> lock(ip_mutex_);
        auto now = std::chrono::system_clock::now();
        for (auto& pair : ip_reputation_) {
            if (pair.second.is_banned &&
                pair.second.ban_until != std::chrono::system_clock::time_point{} &&
                now > pair.second.ban_until) {
                pair.second.is_banned = false;
                pair.second.score = config_.ban_threshold / 2; // partial rehabilitation
            }
        }
    }

    // Clean old rate limit entries
    {
        std::lock_guard<std::mutex> lock(rate_mutex_);
        auto now = std::chrono::steady_clock::now();
        auto window = std::chrono::seconds(config_.rate_limit_window_sec * 2);
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
        auto cutoff = now - std::chrono::seconds(config_.burst_window_sec * 3);
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
