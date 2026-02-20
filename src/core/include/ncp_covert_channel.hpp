#pragma once

/**
 * @file ncp_covert_channel.hpp
 * @brief Covert Channel base interface — unified API for all steganographic transports
 *
 * All covert channels (DNS, TLS Padding, HTTP Header Steg, HLS Video Steg)
 * implement ICovertChannel, enabling the CovertChannelManager to multiplex
 * and failover transparently.
 *
 * ARCHITECTURE:
 *   - Channels are THIN transports: send(bytes) → embed → wire
 *   - Encryption is NOT inside channels — CovertChannelManager handles it
 *     centrally via ncp::Crypto::encrypt_aead() / decrypt_aead()
 *   - Channel selection, failover, and key management are Manager's job
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>

namespace ncp {

// Forward declarations for Manager dependencies
class Crypto;
class TrafficMimicry;
class INetworkBackend;

namespace covert {

// ===== Channel Statistics =====

struct ChannelStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    double estimated_bps = 0.0;        // current throughput estimate
    double stealthiness_score = 0.0;   // 0.0 (exposed) - 1.0 (perfect stealth)
    uint64_t errors = 0;
    uint64_t retries = 0;
    std::chrono::steady_clock::time_point last_activity;
};

// ===== Channel State =====

enum class ChannelState {
    CLOSED,
    OPENING,
    OPEN,
    DEGRADED,    // operational but with reduced capacity/stealth
    CLOSING,
    ERROR
};

const char* channel_state_to_string(ChannelState s) noexcept;

// ===== Detection Event =====

struct CovertDetectionEvent {
    enum class Type {
        NONE,
        STATISTICAL_ANOMALY,     // traffic pattern anomaly detected
        TIMING_ANOMALY,          // inter-packet timing deviation
        VOLUME_ANOMALY,          // unusual query volume
        CONTENT_FINGERPRINT,     // payload fingerprinted by DPI
        ACTIVE_PROBE,            // active probing attempt detected
        BLOCK_DETECTED           // channel appears blocked
    };
    Type type = Type::NONE;
    double confidence = 0.0;     // 0.0 - 1.0
    std::string details;
    std::chrono::system_clock::time_point timestamp;
};

using DetectionCallback = std::function<void(const CovertDetectionEvent&)>;

// ===== Base Interface =====

/**
 * @brief Thin transport interface for covert channels.
 *
 * Channels do NOT encrypt — they only embed and transport raw bytes.
 * CovertChannelManager wraps send/receive with encrypt_aead/decrypt_aead.
 */
class ICovertChannel {
public:
    virtual ~ICovertChannel() = default;

    // Lifecycle
    virtual bool open() = 0;
    virtual void close() = 0;
    virtual bool is_open() const = 0;
    virtual ChannelState state() const = 0;

    // Data transfer (raw bytes — no encryption here)
    virtual size_t send(const uint8_t* data, size_t len) = 0;
    virtual size_t receive(uint8_t* buf, size_t max_len) = 0;

    // Convenience wrappers
    size_t send(const std::vector<uint8_t>& data) {
        return send(data.data(), data.size());
    }
    std::vector<uint8_t> receive(size_t max_len = 65536) {
        std::vector<uint8_t> buf(max_len);
        size_t n = receive(buf.data(), max_len);
        buf.resize(n);
        return buf;
    }

    // Metadata
    virtual ChannelStats get_stats() const = 0;
    virtual std::string channel_type() const = 0;
    virtual double max_capacity_bps() const = 0;

    // Detection awareness
    virtual void set_detection_callback(DetectionCallback cb) = 0;
    virtual void on_detection(const CovertDetectionEvent& event) = 0;
};

// ===== Channel Manager =====

/**
 * @brief Multiplexes data across multiple covert channels with automatic failover.
 *
 * ENCRYPTION LAYER:
 *   Manager wraps all channel I/O with ncp::Crypto:
 *     send(pt) → encrypt_aead(pt, session_key, channel_id_as_aad) → channel.send(ct)
 *     channel.receive() → ct → decrypt_aead(ct, session_key, channel_id_as_aad) → pt
 *
 *   This ensures:
 *   - Channels stay thin (embed + transport only)
 *   - No crypto duplication across channels (DRY)
 *   - ProtocolOrchestrator manages keys centrally (HKDF from shared_secret)
 *   - channel_id as AAD authenticates which channel produced the ciphertext
 *
 * Integrates with ncp_orchestrator.hpp — when a channel reports detection,
 * manager shifts traffic to surviving channels and notifies the orchestrator.
 */
class CovertChannelManager {
public:
    struct Config {
        bool enable_redundancy = false;       // send via multiple channels for reliability
        bool enable_failover = true;          // auto-switch on detection
        int health_check_interval_ms = 5000;
        double detection_threshold = 0.7;     // stealth score below this triggers failover
        size_t max_chunk_size = 512;          // max payload per channel message
    };

    CovertChannelManager();
    explicit CovertChannelManager(const Config& config);
    CovertChannelManager(const Config& config, std::shared_ptr<ncp::Crypto> crypto);
    ~CovertChannelManager();

    // Channel registration
    void add_channel(std::shared_ptr<ICovertChannel> channel);
    void remove_channel(const std::string& channel_type);
    std::vector<std::string> active_channels() const;

    // Unified send/receive (auto-selects best channel + encrypts/decrypts)
    // send: encrypt_aead(data, session_key_, channel_id_aad) → channel.send(ct)
    // receive: channel.receive() → decrypt_aead(ct, session_key_, channel_id_aad)
    size_t send(const uint8_t* data, size_t len);
    size_t receive(uint8_t* buf, size_t max_len);

    // Session key management (called by ProtocolOrchestrator)
    void set_session_key(const std::vector<uint8_t>& key);
    bool has_session_key() const;

    // Lifecycle
    void start();
    void stop();
    bool is_running() const;

    // Aggregate stats
    ChannelStats aggregate_stats() const;

    // Detection handling
    void set_escalation_callback(std::function<void(const std::string& channel, const CovertDetectionEvent&)> cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace covert
} // namespace ncp
