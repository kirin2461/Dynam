#include "ncp_port_knock.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <numeric>
#include <sodium.h>

#ifdef _WIN32
#  include <windows.h>
#  include <bcrypt.h>
#  undef min
#  undef max
#  undef ERROR
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace ncp {
namespace DPI {

// ===== String conversions =====

const char* knock_mode_to_string(KnockMode m) noexcept {
    switch (m) {
        case KnockMode::TOTP_SEQUENCE:   return "TOTP_SEQUENCE";
        case KnockMode::STATIC_SEQUENCE: return "STATIC_SEQUENCE";
        case KnockMode::SPA:             return "SPA";
        case KnockMode::COVERT_TCP:      return "COVERT_TCP";
        default: return "UNKNOWN";
    }
}

const char* knock_result_to_string(KnockResult r) noexcept {
    switch (r) {
        case KnockResult::GATE_OPENED:       return "GATE_OPENED";
        case KnockResult::SEQUENCE_PROGRESS: return "SEQUENCE_PROGRESS";
        case KnockResult::WRONG_SEQUENCE:    return "WRONG_SEQUENCE";
        case KnockResult::REPLAY:            return "REPLAY";
        case KnockResult::RATE_LIMITED:      return "RATE_LIMITED";
        case KnockResult::GATE_ALREADY_OPEN: return "GATE_ALREADY_OPEN";
        case KnockResult::EXPIRED:           return "EXPIRED";
        case KnockResult::SPA_AUTHENTICATED: return "SPA_AUTHENTICATED";
        case KnockResult::SPA_INVALID:       return "SPA_INVALID";
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

// ===== Config Presets =====

PortKnockConfig PortKnockConfig::paranoid() {
    PortKnockConfig c;
    c.mode = KnockMode::TOTP_SEQUENCE;
    c.totp_interval_sec = 15;         // faster rotation
    c.totp_tolerance = 0;             // exact time only
    c.sequence_length = 6;            // 6 ports to knock
    c.knock_timeout_sec = 8;          // tight timing
    c.gate_duration_sec = 15;         // short gate
    c.gate_max_connections = 1;       // single connection
    c.max_attempts_per_ip = 3;
    c.attempt_window_sec = 300;
    return c;
}

PortKnockConfig PortKnockConfig::balanced() {
    PortKnockConfig c;
    c.mode = KnockMode::TOTP_SEQUENCE;
    c.totp_interval_sec = 30;
    c.totp_tolerance = 1;
    c.sequence_length = 4;
    c.knock_timeout_sec = 10;
    c.gate_duration_sec = 30;
    c.gate_max_connections = 3;
    c.max_attempts_per_ip = 5;
    c.attempt_window_sec = 60;
    return c;
}

PortKnockConfig PortKnockConfig::spa_only() {
    PortKnockConfig c;
    c.mode = KnockMode::SPA;
    c.spa_packet_size = 256;
    c.gate_duration_sec = 30;
    c.gate_max_connections = 3;
    c.max_attempts_per_ip = 10;
    c.attempt_window_sec = 60;
    return c;
}

// ===== Constructor / Destructor =====

PortKnock::PortKnock()
    : PortKnock(PortKnockConfig::balanced()) {}

PortKnock::PortKnock(const PortKnockConfig& config)
    : config_(config) {}

PortKnock::~PortKnock() = default;

// ===== HMAC =====
// FIX: Replaced XOR-based MAC fallback with libsodium crypto_auth().
// The old fallback was trivially forgeable (XOR of first 32 bytes).
// libsodium is already a project dependency — no new deps required.
//
// crypto_auth() uses HMAC-SHA-512-256 (keyed MAC, 32-byte output,
// 32-byte key). If shared_secret is not exactly crypto_auth_KEYBYTES,
// we derive a proper key via crypto_generichash (BLAKE2b).

std::array<uint8_t, 32> PortKnock::compute_hmac(
    const uint8_t* data, size_t data_len) const {

    std::array<uint8_t, 32> result{};

    // Read config under shared lock
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    const auto& secret = config_.shared_secret;

    // Derive a crypto_auth key from shared_secret (handles any secret length)
    uint8_t key[crypto_auth_KEYBYTES];
    if (secret.size() == crypto_auth_KEYBYTES) {
        std::memcpy(key, secret.data(), crypto_auth_KEYBYTES);
    } else {
        // Hash the secret into exactly crypto_auth_KEYBYTES bytes
        crypto_generichash(key, crypto_auth_KEYBYTES,
                           secret.data(), secret.size(),
                           nullptr, 0);
    }
    lock.unlock();

    // Compute HMAC-SHA-512-256 (crypto_auth)
    crypto_auth(result.data(), data, data_len, key);

    // Wipe derived key
    sodium_memzero(key, sizeof(key));

    return result;
}

// ===== Port derivation from TOTP =====

uint16_t PortKnock::derive_port(uint64_t counter, size_t index) const {
    // HMAC(secret, counter || index) → port in [min, max]
    uint8_t msg[12];
    msg[0] = (counter >> 56) & 0xFF;
    msg[1] = (counter >> 48) & 0xFF;
    msg[2] = (counter >> 40) & 0xFF;
    msg[3] = (counter >> 32) & 0xFF;
    msg[4] = (counter >> 24) & 0xFF;
    msg[5] = (counter >> 16) & 0xFF;
    msg[6] = (counter >> 8)  & 0xFF;
    msg[7] =  counter        & 0xFF;
    msg[8]  = (index >> 24) & 0xFF;
    msg[9]  = (index >> 16) & 0xFF;
    msg[10] = (index >> 8)  & 0xFF;
    msg[11] =  index        & 0xFF;

    auto hmac = compute_hmac(msg, sizeof(msg));

    // Dynamic truncation (RFC 4226 style)
    uint8_t offset = hmac[31] & 0x0F;
    uint32_t code = (static_cast<uint32_t>(hmac[offset] & 0x7F) << 24) |
                    (static_cast<uint32_t>(hmac[offset + 1]) << 16) |
                    (static_cast<uint32_t>(hmac[offset + 2]) << 8) |
                     static_cast<uint32_t>(hmac[offset + 3]);

    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    uint16_t range = config_.port_range_max - config_.port_range_min + 1;
    return config_.port_range_min + static_cast<uint16_t>(code % range);
}

// ===== Generate TOTP Sequence =====

std::vector<uint16_t> PortKnock::generate_totp_sequence(int64_t time_offset) const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    uint64_t counter = (now / config_.totp_interval_sec) + time_offset;
    size_t seq_len = config_.sequence_length;
    lock.unlock();

    std::vector<uint16_t> sequence;
    sequence.reserve(seq_len);

    for (size_t i = 0; i < seq_len; ++i) {
        sequence.push_back(derive_port(counter, i));
    }

    return sequence;
}

// ===== Generate SPA Packet =====

std::vector<uint8_t> PortKnock::generate_spa_packet() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    size_t pkt_size = config_.spa_packet_size;
    lock.unlock();

    // SPA format: [random_nonce(16) | timestamp(8) | hmac(32) | padding]
    std::vector<uint8_t> packet(pkt_size, 0);

    // Random nonce
    csprng_fill(packet.data(), 16);

    // Timestamp (big-endian 64-bit)
    uint64_t ts = static_cast<uint64_t>(std::time(nullptr));
    packet[16] = (ts >> 56) & 0xFF;
    packet[17] = (ts >> 48) & 0xFF;
    packet[18] = (ts >> 40) & 0xFF;
    packet[19] = (ts >> 32) & 0xFF;
    packet[20] = (ts >> 24) & 0xFF;
    packet[21] = (ts >> 16) & 0xFF;
    packet[22] = (ts >> 8)  & 0xFF;
    packet[23] =  ts        & 0xFF;

    // HMAC over [nonce(16) | timestamp(8)]
    auto hmac = compute_hmac(packet.data(), 24);
    std::memcpy(packet.data() + 24, hmac.data(), 32);

    // Random padding for rest
    if (packet.size() > 56) {
        csprng_fill(packet.data() + 56, packet.size() - 56);
    }

    return packet;
}

// ===== Generate Covert Knock Values =====

std::vector<PortKnock::CovertKnockValues> PortKnock::generate_covert_sequence() const {
    auto ports = generate_totp_sequence();
    std::vector<CovertKnockValues> result;
    result.reserve(ports.size());

    for (auto port : ports) {
        CovertKnockValues cv;
        cv.tcp_window = port;             // encode port in TCP window
        cv.ip_id = port ^ 0xA5A5;        // XOR obfuscation for IP ID
        cv.ttl = 64 + (port & 0x0F);     // slight TTL variation
        result.push_back(cv);
    }

    return result;
}

// ===== Core: process_knock (sequence mode) =====

KnockResult PortKnock::process_knock(
    const std::string& source_ip,
    uint16_t knocked_port) {

    stats_.total_knocks.fetch_add(1);

    KnockEvent event;
    event.source_ip = source_ip;
    event.knocked_port = knocked_port;
    event.timestamp = std::chrono::system_clock::now();

    // Already open?
    if (is_gate_open(source_ip)) {
        event.result = KnockResult::GATE_ALREADY_OPEN;
        emit_event(event);
        return KnockResult::GATE_ALREADY_OPEN;
    }

    // Rate limit
    if (!check_rate_limit(source_ip)) {
        stats_.rate_limited.fetch_add(1);
        event.result = KnockResult::RATE_LIMITED;
        emit_event(event);
        return KnockResult::RATE_LIMITED;
    }

    // Snapshot config under shared lock
    KnockMode mode;
    uint32_t totp_tolerance;
    uint32_t knock_timeout_sec;
    uint32_t gate_duration_sec;
    std::vector<uint16_t> static_sequence;
    {
        std::shared_lock<std::shared_mutex> lock(config_mutex_);
        mode = config_.mode;
        totp_tolerance = config_.totp_tolerance;
        knock_timeout_sec = config_.knock_timeout_sec;
        gate_duration_sec = config_.gate_duration_sec;
        static_sequence = config_.static_sequence;
    }

    // Get expected sequence(s) — check current and ±tolerance windows
    std::vector<std::vector<uint16_t>> valid_sequences;
    if (mode == KnockMode::TOTP_SEQUENCE) {
        for (int64_t offset = -static_cast<int64_t>(totp_tolerance);
             offset <= static_cast<int64_t>(totp_tolerance); ++offset) {
            valid_sequences.push_back(generate_totp_sequence(offset));
        }
    } else if (mode == KnockMode::STATIC_SEQUENCE) {
        valid_sequences.push_back(static_sequence);
    } else if (mode == KnockMode::COVERT_TCP) {
        // Covert mode uses process_covert_knock instead
        for (int64_t offset = -static_cast<int64_t>(totp_tolerance);
             offset <= static_cast<int64_t>(totp_tolerance); ++offset) {
            valid_sequences.push_back(generate_totp_sequence(offset));
        }
    }

    // Get or create progress
    std::lock_guard<std::mutex> lock(progress_mutex_);
    auto& prog = progress_[source_ip];
    if (prog.ip.empty()) {
        prog.ip = source_ip;
        prog.first_knock = std::chrono::steady_clock::now();
    }

    // Check timeout
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - prog.first_knock).count();

    if (!prog.received_ports.empty() &&
        elapsed > static_cast<int64_t>(knock_timeout_sec)) {
        // Sequence expired — reset
        stats_.expired_sequences.fetch_add(1);
        prog.received_ports.clear();
        prog.first_knock = now;
        event.result = KnockResult::EXPIRED;
        event.details = "Sequence timed out after " + std::to_string(elapsed) + "s";
        emit_event(event);
        return KnockResult::EXPIRED;
    }

    prog.received_ports.push_back(knocked_port);
    prog.last_knock = now;

    // Check against all valid sequences
    for (const auto& expected : valid_sequences) {
        if (expected.empty()) continue;

        size_t progress_idx = prog.received_ports.size() - 1;

        // Check if current knock matches expected at this position
        if (progress_idx < expected.size() &&
            prog.received_ports.back() == expected[progress_idx]) {

            // Verify all previous knocks also match
            bool all_match = true;
            for (size_t i = 0; i < prog.received_ports.size() && i < expected.size(); ++i) {
                if (prog.received_ports[i] != expected[i]) {
                    all_match = false;
                    break;
                }
            }

            if (all_match) {
                event.sequence_progress = static_cast<int>(prog.received_ports.size());
                event.sequence_total = static_cast<int>(expected.size());

                if (prog.received_ports.size() >= expected.size()) {
                    // Full sequence matched!
                    // Anti-replay check
                    if (is_replay(prog.received_ports)) {
                        stats_.replays_blocked.fetch_add(1);
                        prog.received_ports.clear();
                        event.result = KnockResult::REPLAY;
                        event.details = "Sequence replay detected";
                        emit_event(event);
                        return KnockResult::REPLAY;
                    }

                    record_completed_sequence(prog.received_ports);
                    prog.received_ports.clear();

                    // Open gate!
                    open_gate(source_ip, gate_duration_sec);
                    stats_.gates_opened.fetch_add(1);

                    event.result = KnockResult::GATE_OPENED;
                    event.details = "Sequence complete — gate opened for " +
                        std::to_string(gate_duration_sec) + "s";
                    emit_event(event);
                    return KnockResult::GATE_OPENED;
                }

                // Partial match — waiting for more knocks
                event.result = KnockResult::SEQUENCE_PROGRESS;
                event.details = std::to_string(prog.received_ports.size()) +
                    "/" + std::to_string(expected.size());
                emit_event(event);
                return KnockResult::SEQUENCE_PROGRESS;
            }
        }
    }

    // No match — wrong knock, reset progress
    stats_.wrong_sequences.fetch_add(1);
    prog.received_ports.clear();
    prog.first_knock = now;

    event.result = KnockResult::WRONG_SEQUENCE;
    event.details = "Port " + std::to_string(knocked_port) + " not in expected sequence";
    emit_event(event);
    return KnockResult::WRONG_SEQUENCE;
}

// ===== Core: process_spa =====

KnockResult PortKnock::process_spa(
    const std::string& source_ip,
    const uint8_t* data,
    size_t data_len) {

    stats_.total_knocks.fetch_add(1);

    KnockEvent event;
    event.source_ip = source_ip;
    event.timestamp = std::chrono::system_clock::now();

    if (is_gate_open(source_ip)) {
        event.result = KnockResult::GATE_ALREADY_OPEN;
        emit_event(event);
        return KnockResult::GATE_ALREADY_OPEN;
    }

    if (!check_rate_limit(source_ip)) {
        stats_.rate_limited.fetch_add(1);
        event.result = KnockResult::RATE_LIMITED;
        emit_event(event);
        return KnockResult::RATE_LIMITED;
    }

    // Minimum size: nonce(16) + timestamp(8) + hmac(32) = 56
    if (data_len < 56) {
        stats_.spa_rejected.fetch_add(1);
        event.result = KnockResult::SPA_INVALID;
        event.details = "Packet too short";
        emit_event(event);
        return KnockResult::SPA_INVALID;
    }

    // Snapshot config for timestamp validation
    uint32_t totp_interval;
    uint32_t totp_tol;
    uint32_t gate_dur;
    {
        std::shared_lock<std::shared_mutex> lock(config_mutex_);
        totp_interval = config_.totp_interval_sec;
        totp_tol = config_.totp_tolerance;
        gate_dur = config_.gate_duration_sec;
    }

    // Verify timestamp
    uint64_t pkt_ts = 0;
    for (int i = 0; i < 8; ++i) {
        pkt_ts = (pkt_ts << 8) | data[16 + i];
    }
    uint64_t now_ts = static_cast<uint64_t>(std::time(nullptr));
    uint64_t diff = (pkt_ts > now_ts) ? (pkt_ts - now_ts) : (now_ts - pkt_ts);

    if (diff > totp_interval * (totp_tol + 1)) {
        stats_.spa_rejected.fetch_add(1);
        event.result = KnockResult::SPA_INVALID;
        event.details = "Timestamp out of range: delta=" + std::to_string(diff) + "s";
        emit_event(event);
        return KnockResult::SPA_INVALID;
    }

    // Verify HMAC over [nonce(16) | timestamp(8)]
    auto expected_hmac = compute_hmac(data, 24);

    // Constant-time comparison (sodium_memcmp returns 0 on match)
    if (sodium_memcmp(data + 24, expected_hmac.data(), 32) != 0) {
        stats_.spa_rejected.fetch_add(1);
        event.result = KnockResult::SPA_INVALID;
        event.details = "HMAC mismatch";
        emit_event(event);
        return KnockResult::SPA_INVALID;
    }

    // Anti-replay: use nonce as key
    std::vector<uint16_t> nonce_as_ports;
    for (int i = 0; i < 8; ++i) {
        uint16_t p = (static_cast<uint16_t>(data[i * 2]) << 8) | data[i * 2 + 1];
        nonce_as_ports.push_back(p);
    }
    if (is_replay(nonce_as_ports)) {
        stats_.replays_blocked.fetch_add(1);
        event.result = KnockResult::REPLAY;
        event.details = "SPA nonce replay";
        emit_event(event);
        return KnockResult::REPLAY;
    }
    record_completed_sequence(nonce_as_ports);

    // Authenticated!
    open_gate(source_ip, gate_dur);
    stats_.spa_authenticated.fetch_add(1);
    stats_.gates_opened.fetch_add(1);

    event.result = KnockResult::SPA_AUTHENTICATED;
    event.details = "SPA verified — gate opened for " +
        std::to_string(gate_dur) + "s";
    emit_event(event);
    return KnockResult::SPA_AUTHENTICATED;
}

// ===== Core: process_covert_knock =====

KnockResult PortKnock::process_covert_knock(
    const std::string& source_ip,
    uint16_t tcp_window,
    uint16_t ip_id,
    uint8_t ttl) {

    // Decode the knock value from TCP header fields
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    bool use_window = config_.covert_use_window;
    bool use_ipid = config_.covert_use_ipid;
    lock.unlock();

    uint16_t decoded_port = 0;
    if (use_window) {
        decoded_port = tcp_window;
    } else if (use_ipid) {
        decoded_port = ip_id ^ 0xA5A5;  // reverse XOR obfuscation
    }
    (void)ttl; // TTL used as secondary validation in future

    return process_knock(source_ip, decoded_port);
}

// ===== Gate Management =====

bool PortKnock::is_gate_open(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(gate_mutex_);
    auto it = gates_.find(ip);
    if (it == gates_.end()) return false;
    if (!it->second.is_open) return false;

    // Check expiry
    if (std::chrono::steady_clock::now() > it->second.expires_at) {
        return false;  // expired, but can't modify from const
    }
    return true;
}

void PortKnock::open_gate(const std::string& ip, uint32_t duration_sec) {
    std::lock_guard<std::mutex> lock(gate_mutex_);

    if (duration_sec == 0) {
        std::shared_lock<std::shared_mutex> cfg_lock(config_mutex_);
        duration_sec = config_.gate_duration_sec;
    }

    auto now = std::chrono::steady_clock::now();
    GateEntry& gate = gates_[ip];
    gate.ip = ip;
    gate.opened_at = now;
    gate.expires_at = now + std::chrono::seconds(duration_sec);
    gate.is_open = true;

    stats_.active_gates.store(gates_.size());

    // Evict if too many
    std::shared_lock<std::shared_mutex> cfg_lock(config_mutex_);
    size_t max_gates = config_.max_active_gates;
    cfg_lock.unlock();

    if (gates_.size() > max_gates) {
        // Remove oldest expired
        for (auto it = gates_.begin(); it != gates_.end();) {
            if (!it->second.is_open || now > it->second.expires_at) {
                it = gates_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void PortKnock::close_gate(const std::string& ip) {
    std::lock_guard<std::mutex> lock(gate_mutex_);
    auto it = gates_.find(ip);
    if (it != gates_.end()) {
        it->second.is_open = false;
    }
    stats_.active_gates.store(gates_.size());
}

std::vector<std::string> PortKnock::get_open_gates() const {
    std::lock_guard<std::mutex> lock(gate_mutex_);
    std::vector<std::string> result;
    auto now = std::chrono::steady_clock::now();
    for (const auto& pair : gates_) {
        if (pair.second.is_open && now <= pair.second.expires_at) {
            result.push_back(pair.first);
        }
    }
    return result;
}

void PortKnock::cleanup_expired_gates() {
    std::lock_guard<std::mutex> lock(gate_mutex_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = gates_.begin(); it != gates_.end();) {
        if (now > it->second.expires_at) {
            it = gates_.erase(it);
        } else {
            ++it;
        }
    }
    stats_.active_gates.store(gates_.size());

    // Snapshot config values for cleanup thresholds
    uint32_t knock_timeout;
    uint32_t attempt_window;
    {
        std::shared_lock<std::shared_mutex> cfg_lock(config_mutex_);
        knock_timeout = config_.knock_timeout_sec;
        attempt_window = config_.attempt_window_sec;
    }

    // Also clean progress
    {
        std::lock_guard<std::mutex> plock(progress_mutex_);
        auto cutoff = now - std::chrono::seconds(knock_timeout * 3);
        for (auto it = progress_.begin(); it != progress_.end();) {
            if (it->second.last_knock < cutoff || it->second.received_ports.empty()) {
                it = progress_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean rate limits
    {
        std::lock_guard<std::mutex> rlock(rate_mutex_);
        auto window = std::chrono::seconds(attempt_window * 2);
        for (auto it = rate_limits_.begin(); it != rate_limits_.end();) {
            if (now - it->second.window_start > window) {
                it = rate_limits_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Clean replay window
    {
        std::lock_guard<std::mutex> rplock(replay_mutex_);
        while (!replay_window_.empty() && replay_window_.front().expiry < now) {
            replay_set_.erase(replay_window_.front().sequence_key);
            replay_window_.pop_front();
        }
    }
}

// ===== Rate Limiting =====

bool PortKnock::check_rate_limit(const std::string& ip) {
    std::lock_guard<std::mutex> lock(rate_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto& entry = rate_limits_[ip];

    std::shared_lock<std::shared_mutex> cfg_lock(config_mutex_);
    auto window = std::chrono::seconds(config_.attempt_window_sec);
    uint32_t max_attempts = config_.max_attempts_per_ip;
    cfg_lock.unlock();

    if (now - entry.window_start > window) {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count++;
    return entry.count <= max_attempts;
}

// ===== Replay Protection =====

std::string PortKnock::sequence_to_key(const std::vector<uint16_t>& seq) const {
    std::ostringstream oss;
    for (size_t i = 0; i < seq.size(); ++i) {
        if (i > 0) oss << ':';
        oss << seq[i];
    }
    return oss.str();
}

bool PortKnock::is_replay(const std::vector<uint16_t>& sequence) {
    std::lock_guard<std::mutex> lock(replay_mutex_);
    return replay_set_.count(sequence_to_key(sequence)) > 0;
}

void PortKnock::record_completed_sequence(const std::vector<uint16_t>& sequence) {
    std::lock_guard<std::mutex> lock(replay_mutex_);
    auto key = sequence_to_key(sequence);

    if (replay_set_.count(key) > 0) return;

    auto now = std::chrono::steady_clock::now();

    // Evict expired
    while (!replay_window_.empty() && replay_window_.front().expiry < now) {
        replay_set_.erase(replay_window_.front().sequence_key);
        replay_window_.pop_front();
    }

    // Snapshot config for replay limits
    size_t replay_win_size;
    uint32_t replay_expiry;
    {
        std::shared_lock<std::shared_mutex> cfg_lock(config_mutex_);
        replay_win_size = config_.replay_window_size;
        replay_expiry = config_.replay_expiry_sec;
    }

    // Evict oldest if at capacity
    while (replay_window_.size() >= replay_win_size) {
        replay_set_.erase(replay_window_.front().sequence_key);
        replay_window_.pop_front();
    }

    ReplayEntry entry;
    entry.sequence_key = key;
    entry.expiry = now + std::chrono::seconds(replay_expiry);
    replay_window_.push_back(entry);
    replay_set_.insert(key);
}

// ===== Events & Config =====

void PortKnock::emit_event(const KnockEvent& event) {
    if (event_callback_) {
        event_callback_(event);
    }
}

void PortKnock::set_event_callback(KnockEventCallback callback) {
    event_callback_ = callback;
}

void PortKnock::set_config(const PortKnockConfig& config) {
    std::unique_lock<std::shared_mutex> lock(config_mutex_);
    config_ = config;
}

PortKnockConfig PortKnock::get_config() const {
    std::shared_lock<std::shared_mutex> lock(config_mutex_);
    return config_;
}

PortKnockStats PortKnock::get_stats() const {
    return PortKnockStats(stats_);
}

void PortKnock::reset_stats() {
    stats_.reset();
}

} // namespace DPI
} // namespace ncp
