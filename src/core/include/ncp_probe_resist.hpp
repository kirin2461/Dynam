#pragma once

/**
 * @file ncp_probe_resist.hpp
 * @brief Active Probing Resistance (APR) — Phase 3 Anti-ML-TSPU
 *
 * TSPU/GFW active probing workflow:
 *   1. DPI flags suspicious traffic (encrypted, unknown protocol)
 *   2. Prober connects to the server IP:port
 *   3. Prober replays captured ClientHello or sends crafted handshake
 *   4. If server responds with non-standard protocol → confirmed proxy → block
 *
 * APR defense layers:
 *   L1: Client authentication via HMAC-SHA256 within first flight
 *   L2: Unauthenticated → redirect/mirror to cover site (VLESS+Reality)
 *   L3: Replay detection via nonce window
 *   L4: Probe pattern recognition (scanner fingerprints, burst timing)
 *   L5: IP reputation scoring with auto-ban
 *   L6: TLS fingerprint allowlist (JA3/JA4)
 *   L7: Rate limiting per source IP
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <array>
#include <deque>

namespace ncp {
namespace DPI {

// ===== Cover Server Mode =====

enum class CoverMode {
    REDIRECT,   // 301/302 redirect to cover site
    MIRROR,     // Proxy the cover site content back
    RESET,      // TCP RST — looks like closed port
    DROP,       // Silently drop — looks like filtered port
    TARPIT,     // Slow-read: accept but never respond (waste prober time)
    ECHO_NGINX, // Respond with generic nginx default page
    ECHO_IIS,   // Respond with generic IIS default page
    ECHO_APACHE // Respond with generic Apache default page
};

const char* cover_mode_to_string(CoverMode m) noexcept;
CoverMode cover_mode_from_string(const std::string& name) noexcept;

// ===== Authentication Result =====

enum class AuthResult {
    AUTHENTICATED,      // Valid client with correct HMAC
    REPLAY_DETECTED,    // Valid HMAC but nonce already seen
    INVALID_HMAC,       // Wrong HMAC — likely probe
    NO_AUTH_DATA,       // No authentication field in handshake
    RATE_LIMITED,       // Too many attempts from this IP
    IP_BANNED,          // IP is in ban list
    BAD_TLS_FINGERPRINT,// JA3 not in allowlist
    PROBE_PATTERN       // Matches known scanner behavior
};

const char* auth_result_to_string(AuthResult r) noexcept;

// ===== Probe Event (for logging/callbacks) =====

struct ProbeEvent {
    std::string source_ip;
    uint16_t source_port = 0;
    AuthResult result = AuthResult::NO_AUTH_DATA;
    std::string ja3_fingerprint;
    std::string details;
    std::chrono::system_clock::time_point timestamp;
    size_t payload_size = 0;
};

using ProbeEventCallback = std::function<void(const ProbeEvent&)>;

// ===== IP Reputation =====

struct IPReputation {
    std::string ip;
    int32_t score = 0;           // negative = suspicious, positive = trusted
    uint32_t total_connections = 0;
    uint32_t failed_auths = 0;
    uint32_t successful_auths = 0;
    uint32_t replay_attempts = 0;
    bool is_banned = false;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    std::chrono::system_clock::time_point ban_until;  // temp ban expiry
};

// ===== Rate Limiter Entry =====

struct RateLimitEntry {
    uint32_t count = 0;
    std::chrono::steady_clock::time_point window_start;
};

// ===== Configuration =====

struct ProbeResistConfig {
    bool enabled = true;

    // === L1: Authentication ===
    bool enable_auth = true;
    std::vector<uint8_t> shared_secret;   // HMAC key (32 bytes recommended)
    size_t auth_offset = 0;               // offset in first packet where HMAC starts
    size_t auth_length = 32;              // HMAC-SHA256 = 32 bytes
    size_t nonce_length = 16;             // random nonce prepended to HMAC
    uint32_t timestamp_tolerance_sec = 30; // clock skew tolerance

    // === L2: Cover Server ===
    CoverMode cover_mode = CoverMode::ECHO_NGINX;
    std::string cover_site_url = "https://www.yandex.ru";
    std::string cover_site_host = "www.yandex.ru";
    uint16_t cover_site_port = 443;

    // === L3: Replay Protection ===
    bool enable_replay_protection = true;
    size_t nonce_window_size = 65536;     // max nonces to remember
    uint32_t nonce_expiry_sec = 300;      // nonces expire after 5 min

    // === L4: Probe Pattern Detection ===
    bool enable_pattern_detection = true;
    uint32_t burst_threshold = 5;         // N connections in burst_window = suspicious
    uint32_t burst_window_sec = 10;       // burst detection window
    std::vector<std::string> known_scanner_ja3;  // known prober JA3 fingerprints

    // === L5: IP Reputation ===
    bool enable_ip_reputation = true;
    int32_t ban_threshold = -10;          // score below this = auto-ban
    int32_t auth_fail_penalty = -3;       // per failed auth
    int32_t replay_penalty = -5;          // per replay attempt
    int32_t auth_success_reward = 1;      // per successful auth
    uint32_t temp_ban_duration_sec = 3600; // 1 hour temp ban
    size_t max_tracked_ips = 100000;      // memory limit

    // === L6: TLS Fingerprint ===
    bool enable_ja3_filter = false;       // disabled by default — too strict
    std::vector<std::string> ja3_allowlist;  // allowed JA3 hashes

    // === L7: Rate Limiting ===
    bool enable_rate_limit = true;
    uint32_t rate_limit_per_ip = 10;      // max connections per window
    uint32_t rate_limit_window_sec = 60;  // 1 minute window

    // Presets
    static ProbeResistConfig strict();
    static ProbeResistConfig balanced();
    static ProbeResistConfig permissive();
};

// ===== Statistics =====

struct ProbeResistStats {
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> authenticated{0};
    std::atomic<uint64_t> rejected_bad_hmac{0};
    std::atomic<uint64_t> rejected_replay{0};
    std::atomic<uint64_t> rejected_no_auth{0};
    std::atomic<uint64_t> rejected_rate_limit{0};
    std::atomic<uint64_t> rejected_ip_ban{0};
    std::atomic<uint64_t> rejected_ja3{0};
    std::atomic<uint64_t> rejected_probe_pattern{0};
    std::atomic<uint64_t> cover_responses_sent{0};
    std::atomic<uint64_t> ips_banned{0};
    std::atomic<uint64_t> replays_caught{0};

    void reset() {
        total_connections.store(0); authenticated.store(0);
        rejected_bad_hmac.store(0); rejected_replay.store(0);
        rejected_no_auth.store(0); rejected_rate_limit.store(0);
        rejected_ip_ban.store(0); rejected_ja3.store(0);
        rejected_probe_pattern.store(0); cover_responses_sent.store(0);
        ips_banned.store(0); replays_caught.store(0);
    }

    ProbeResistStats() = default;
    ProbeResistStats(const ProbeResistStats& o)
        : total_connections(o.total_connections.load()),
          authenticated(o.authenticated.load()),
          rejected_bad_hmac(o.rejected_bad_hmac.load()),
          rejected_replay(o.rejected_replay.load()),
          rejected_no_auth(o.rejected_no_auth.load()),
          rejected_rate_limit(o.rejected_rate_limit.load()),
          rejected_ip_ban(o.rejected_ip_ban.load()),
          rejected_ja3(o.rejected_ja3.load()),
          rejected_probe_pattern(o.rejected_probe_pattern.load()),
          cover_responses_sent(o.cover_responses_sent.load()),
          ips_banned(o.ips_banned.load()),
          replays_caught(o.replays_caught.load()) {}
};

// ===== Main Class =====

class ProbeResist {
public:
    ProbeResist();
    explicit ProbeResist(const ProbeResistConfig& config);
    ~ProbeResist();

    ProbeResist(const ProbeResist&) = delete;
    ProbeResist& operator=(const ProbeResist&) = delete;

    // ===== Core: Process Incoming Connection =====

    /// Process the first packet from a new connection.
    /// Returns AuthResult indicating whether to allow or cover.
    AuthResult process_connection(
        const std::string& source_ip,
        uint16_t source_port,
        const uint8_t* data,
        size_t data_len,
        const std::string& ja3_fingerprint = "");

    // ===== L1: Authentication =====

    /// Generate auth token for client to embed in first packet.
    /// Returns: [nonce(16) | timestamp(4) | hmac(32)] = 52 bytes
    std::vector<uint8_t> generate_client_auth();

    /// Verify auth token from first packet.
    bool verify_auth(const uint8_t* data, size_t data_len);

    /// Compute HMAC-SHA256.
    std::array<uint8_t, 32> compute_hmac(
        const uint8_t* data, size_t data_len,
        const uint8_t* key, size_t key_len);

    // ===== L2: Cover Responses =====

    /// Generate cover response based on configured mode.
    std::vector<uint8_t> generate_cover_response(
        const uint8_t* request_data = nullptr,
        size_t request_len = 0);

    /// Generate specific cover page HTML.
    static std::vector<uint8_t> generate_nginx_default();
    static std::vector<uint8_t> generate_iis_default();
    static std::vector<uint8_t> generate_apache_default();
    static std::vector<uint8_t> generate_redirect(const std::string& url);

    // ===== L3: Replay Protection =====

    /// Check if nonce has been seen before. If not, record it.
    bool check_and_record_nonce(const uint8_t* nonce, size_t nonce_len);

    /// Evict expired nonces.
    void evict_expired_nonces();

    // ===== L4: Probe Pattern Detection =====

    /// Check if connection pattern matches known probe behavior.
    bool is_probe_pattern(const std::string& source_ip);

    /// Check JA3 against known scanner fingerprints.
    bool is_known_scanner(const std::string& ja3) const;

    // ===== L5: IP Reputation =====

    /// Get reputation for an IP.
    IPReputation get_ip_reputation(const std::string& ip) const;

    /// Update reputation score.
    void update_reputation(const std::string& ip, int32_t delta);

    /// Check if IP is banned.
    bool is_ip_banned(const std::string& ip) const;

    /// Manually ban/unban IP.
    void ban_ip(const std::string& ip, uint32_t duration_sec = 0);
    void unban_ip(const std::string& ip);

    /// Get all banned IPs.
    std::vector<std::string> get_banned_ips() const;

    // ===== L6: JA3 Filter =====

    /// Check if JA3 fingerprint is in allowlist.
    bool is_ja3_allowed(const std::string& ja3) const;

    /// Add/remove JA3 to allowlist.
    void add_ja3_allowlist(const std::string& ja3);
    void remove_ja3_allowlist(const std::string& ja3);

    // ===== L7: Rate Limiting =====

    /// Check if IP is rate-limited.
    bool is_rate_limited(const std::string& ip);

    // ===== Events & Config =====

    void set_event_callback(ProbeEventCallback callback);
    void set_config(const ProbeResistConfig& config);
    ProbeResistConfig get_config() const;

    ProbeResistStats get_stats() const;
    void reset_stats();

private:
    void emit_event(const ProbeEvent& event);
    void cleanup_stale_data();

    ProbeResistConfig config_;
    ProbeResistStats stats_;
    ProbeEventCallback event_callback_;

    // Nonce window: hash → expiry time
    struct NonceEntry {
        std::array<uint8_t, 32> hash;  // SHA256 of nonce
        std::chrono::steady_clock::time_point expiry;
    };
    std::deque<NonceEntry> nonce_window_;
    std::unordered_set<std::string> nonce_set_;  // fast lookup by hex
    mutable std::mutex nonce_mutex_;

    // IP reputation store
    std::unordered_map<std::string, IPReputation> ip_reputation_;
    mutable std::mutex ip_mutex_;

    // Rate limiter
    std::unordered_map<std::string, RateLimitEntry> rate_limits_;
    mutable std::mutex rate_mutex_;

    // Connection timing (for burst detection)
    struct ConnectionRecord {
        std::chrono::steady_clock::time_point time;
    };
    std::unordered_map<std::string, std::deque<ConnectionRecord>> conn_history_;
    mutable std::mutex conn_mutex_;

    // JA3 sets
    std::unordered_set<std::string> ja3_allowlist_;
    std::unordered_set<std::string> ja3_scanner_set_;
};

} // namespace DPI
} // namespace ncp
