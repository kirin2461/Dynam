#pragma once

/**
 * @file ncp_port_knock.hpp
 * @brief Port Knocking — Phase 5 (server invisibility layer)
 *
 * Makes the NCP server completely invisible to scanners.
 * The real service port stays DROP/RESET until the client
 * sends the correct knock sequence.
 *
 * Modes:
 *   1. TOTP Sequence  — ports derived from shared secret + time (changes every 30s)
 *   2. Static Sequence — fixed port list (simple but less secure)
 *   3. SPA (Single Packet Authorization) — one encrypted UDP packet
 *   4. Covert Knock    — sequence encoded in TCP fields (window/IPID/TTL)
 *
 * Integration with ProbeResist:
 *   - Knock opens the "gate" for source IP
 *   - Once gate is open, ProbeResist takes over for L1-L7 checks
 *   - If knock fails, server doesn't even respond (not even cover page)
 *
 * Security notes:
 *   - HMAC uses libsodium crypto_auth (HMAC-SHA-512-256), no OpenSSL required
 *   - config_ is protected by shared_mutex for thread-safe read/write
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace ncp {
namespace DPI {

// ===== Knock Mode =====

enum class KnockMode {
    TOTP_SEQUENCE,   // Time-based port sequence (recommended)
    STATIC_SEQUENCE, // Fixed port sequence
    SPA,             // Single Packet Authorization
    COVERT_TCP       // Encoded in TCP header fields
};

const char* knock_mode_to_string(KnockMode m) noexcept;

// ===== Knock Result =====

enum class KnockResult {
    GATE_OPENED,       // Correct sequence — gate opened for this IP
    SEQUENCE_PROGRESS, // Partial sequence — waiting for more knocks
    WRONG_SEQUENCE,    // Incorrect port in sequence
    REPLAY,            // Sequence already used
    RATE_LIMITED,      // Too many knock attempts
    GATE_ALREADY_OPEN, // IP already has an open gate
    EXPIRED,           // Took too long between knocks
    SPA_AUTHENTICATED, // SPA packet verified
    SPA_INVALID        // SPA packet failed verification
};

const char* knock_result_to_string(KnockResult r) noexcept;

// ===== Knock Event =====

struct KnockEvent {
    std::string source_ip;
    uint16_t knocked_port = 0;
    KnockResult result = KnockResult::WRONG_SEQUENCE;
    int sequence_progress = 0;   // how many correct knocks so far
    int sequence_total = 0;      // total knocks needed
    std::string details;
    std::chrono::system_clock::time_point timestamp;
};

using KnockEventCallback = std::function<void(const KnockEvent&)>;

// ===== Gate Entry (per-IP open gate) =====

struct GateEntry {
    std::string ip;
    std::chrono::steady_clock::time_point opened_at;
    std::chrono::steady_clock::time_point expires_at;
    bool is_open = false;
};

// ===== Knock Progress (partial sequence tracker) =====

struct KnockProgress {
    std::string ip;
    std::vector<uint16_t> received_ports;
    std::chrono::steady_clock::time_point first_knock;
    std::chrono::steady_clock::time_point last_knock;
};

// ===== Configuration =====

struct PortKnockConfig {
    bool enabled = true;
    KnockMode mode = KnockMode::TOTP_SEQUENCE;

    // === Shared Secret (for TOTP + SPA) ===
    std::vector<uint8_t> shared_secret;  // 32 bytes recommended

    // === TOTP Sequence ===
    uint32_t totp_interval_sec = 30;     // new sequence every 30s
    uint32_t totp_tolerance = 1;         // accept ±1 time window
    size_t sequence_length = 4;          // knock 4 ports
    uint16_t port_range_min = 1024;      // generated ports in this range
    uint16_t port_range_max = 65535;

    // === Static Sequence ===
    std::vector<uint16_t> static_sequence;  // e.g., {7000, 8123, 9456, 3311}

    // === SPA ===
    uint16_t spa_listen_port = 0;        // 0 = random high port
    size_t spa_packet_size = 256;        // encrypted packet size

    // === Covert TCP ===
    // Encode knock in: TCP window size (low 16 bits) or IP ID field
    uint16_t covert_target_port = 80;    // port to send covert SYN to
    bool covert_use_window = true;       // encode in TCP window size
    bool covert_use_ipid = false;        // encode in IP ID field

    // === Timing ===
    uint32_t knock_timeout_sec = 10;     // max time to complete full sequence
    uint32_t gate_duration_sec = 30;     // how long gate stays open after knock
    uint32_t gate_max_connections = 3;   // max connections through open gate

    // === Rate Limiting ===
    uint32_t max_attempts_per_ip = 5;    // per window
    uint32_t attempt_window_sec = 60;

    // === Anti-Replay ===
    size_t replay_window_size = 1024;    // remember N completed sequences
    uint32_t replay_expiry_sec = 300;

    // === Memory ===
    size_t max_tracked_ips = 10000;
    size_t max_active_gates = 1000;

    // Presets
    static PortKnockConfig paranoid();
    static PortKnockConfig balanced();
    static PortKnockConfig spa_only();
};

// ===== Statistics =====

struct PortKnockStats {
    std::atomic<uint64_t> total_knocks{0};
    std::atomic<uint64_t> gates_opened{0};
    std::atomic<uint64_t> wrong_sequences{0};
    std::atomic<uint64_t> replays_blocked{0};
    std::atomic<uint64_t> rate_limited{0};
    std::atomic<uint64_t> expired_sequences{0};
    std::atomic<uint64_t> spa_authenticated{0};
    std::atomic<uint64_t> spa_rejected{0};
    std::atomic<uint64_t> active_gates{0};

    void reset() {
        total_knocks.store(0); gates_opened.store(0);
        wrong_sequences.store(0); replays_blocked.store(0);
        rate_limited.store(0); expired_sequences.store(0);
        spa_authenticated.store(0); spa_rejected.store(0);
        active_gates.store(0);
    }

    PortKnockStats() = default;
    PortKnockStats(const PortKnockStats& o)
        : total_knocks(o.total_knocks.load()),
          gates_opened(o.gates_opened.load()),
          wrong_sequences(o.wrong_sequences.load()),
          replays_blocked(o.replays_blocked.load()),
          rate_limited(o.rate_limited.load()),
          expired_sequences(o.expired_sequences.load()),
          spa_authenticated(o.spa_authenticated.load()),
          spa_rejected(o.spa_rejected.load()),
          active_gates(o.active_gates.load()) {}
};

// ===== Main Class =====

class PortKnock {
public:
    PortKnock();
    explicit PortKnock(const PortKnockConfig& config);
    ~PortKnock();

    PortKnock(const PortKnock&) = delete;
    PortKnock& operator=(const PortKnock&) = delete;

    // ===== Core: Process Incoming Knock =====

    /// Process a SYN packet to a port (sequence knock mode).
    KnockResult process_knock(
        const std::string& source_ip,
        uint16_t knocked_port);

    /// Process a SPA packet (Single Packet Authorization).
    KnockResult process_spa(
        const std::string& source_ip,
        const uint8_t* data,
        size_t data_len);

    /// Process a covert TCP knock (encoded in header fields).
    KnockResult process_covert_knock(
        const std::string& source_ip,
        uint16_t tcp_window,
        uint16_t ip_id,
        uint8_t ttl);

    // ===== Gate Management =====

    /// Check if IP has an open gate.
    bool is_gate_open(const std::string& ip) const;

    /// Manually open/close gate for an IP.
    void open_gate(const std::string& ip, uint32_t duration_sec = 0);
    void close_gate(const std::string& ip);

    /// Get all IPs with open gates.
    std::vector<std::string> get_open_gates() const;

    /// Evict expired gates.
    void cleanup_expired_gates();

    // ===== Client-Side: Generate Knock Sequence =====

    /// Generate the current TOTP port sequence for client to knock.
    std::vector<uint16_t> generate_totp_sequence(int64_t time_offset = 0) const;

    /// Generate SPA packet for client to send.
    std::vector<uint8_t> generate_spa_packet() const;

    /// Generate covert knock values (window_size, ip_id, ttl).
    struct CovertKnockValues {
        uint16_t tcp_window;
        uint16_t ip_id;
        uint8_t ttl;
    };
    std::vector<CovertKnockValues> generate_covert_sequence() const;

    // ===== Config & Stats =====

    void set_event_callback(KnockEventCallback callback);
    void set_config(const PortKnockConfig& config);
    PortKnockConfig get_config() const;

    PortKnockStats get_stats() const;
    void reset_stats();

private:
    void emit_event(const KnockEvent& event);
    bool check_rate_limit(const std::string& ip);
    bool is_replay(const std::vector<uint16_t>& sequence);
    void record_completed_sequence(const std::vector<uint16_t>& sequence);
    std::string sequence_to_key(const std::vector<uint16_t>& seq) const;

    /// Derive port from HMAC(secret, counter) in [port_min, port_max].
    uint16_t derive_port(uint64_t counter, size_t index) const;

    /// Compute HMAC via libsodium crypto_auth (HMAC-SHA-512-256).
    std::array<uint8_t, 32> compute_hmac(
        const uint8_t* data, size_t data_len) const;

    PortKnockConfig config_;
    mutable std::shared_mutex config_mutex_;  // protects config_ reads/writes
    PortKnockStats stats_;
    KnockEventCallback event_callback_;

    // Gate tracking
    std::unordered_map<std::string, GateEntry> gates_;
    mutable std::mutex gate_mutex_;

    // Knock progress (partial sequences)
    std::unordered_map<std::string, KnockProgress> progress_;
    mutable std::mutex progress_mutex_;

    // Rate limiting
    struct RateEntry {
        uint32_t count = 0;
        std::chrono::steady_clock::time_point window_start;
    };
    std::unordered_map<std::string, RateEntry> rate_limits_;
    mutable std::mutex rate_mutex_;

    // Replay protection
    struct ReplayEntry {
        std::string sequence_key;
        std::chrono::steady_clock::time_point expiry;
    };
    std::deque<ReplayEntry> replay_window_;
    std::unordered_set<std::string> replay_set_;
    mutable std::mutex replay_mutex_;
};

} // namespace DPI
} // namespace ncp
