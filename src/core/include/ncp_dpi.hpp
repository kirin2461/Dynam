#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <optional>

namespace ncp {
namespace DPI {

enum class DPIMode {
    DRIVER,
    PROXY,
    PASSIVE
};

enum class DPIPreset {
    NONE,
    RUNET_SOFT,
    RUNET_STRONG
};

    enum class ValidationError {
    NONE = 0,
    INVALID_FRAGMENT_SIZE,
    INVALID_FRAGMENT_OFFSET,
    INVALID_SPLIT_POSITION,
    INVALID_NOISE_SIZE,
    INVALID_FAKE_TTL,
    INVALID_DISORDER_DELAY,
    INVALID_LISTEN_PORT,
    INVALID_NFQUEUE_NUM,
    PROXY_MISSING_HOST
};

struct DPIConfig {
    DPIMode mode = DPIMode::DRIVER;

    bool enable_tcp_split = true;
    int split_position = 2;
    bool split_at_sni = true;

    bool enable_noise = true;
    int noise_size = 64;
    bool enable_host_case = true;
    std::string fake_host;

    bool enable_fake_packet = true;
    int fake_ttl = 1;

    bool enable_disorder = true;
    bool enable_oob_data = false;
    int disorder_delay_ms = 15;

    uint16_t listen_port = 8080;
    std::string target_host;
    uint16_t target_port = 443;

    int nfqueue_num = 0;

    int fragment_size = 2;
    int fragment_offset = 2;
    
    // Advanced DPI bypass techniques
    bool randomize_split_position = false;  // Randomize split position on each packet
    int split_position_min = 1;
    int split_position_max = 10;
    
    bool enable_pattern_obfuscation = true;  // Obfuscate TLS/HTTP patterns
    bool randomize_fake_ttl = false;  // Randomize fake packet TTL (1-8)
    bool enable_tcp_options_randomization = false;  // Randomize TCP options
    
    bool enable_timing_jitter = false;  // Add timing jitter to packets
    int timing_jitter_min_us = 0;  // Min jitter in microseconds
    int timing_jitter_max_us = 1000;  // Max jitter in microseconds
    
    bool enable_multi_layer_split = false;  // Split at multiple positions
    std::vector<int> split_positions;  // Multiple split positions
    
    bool enable_decoy_sni = false;  // Send decoy SNI packets
    std::vector<std::string> decoy_sni_domains;  // Decoy SNI domains
    
    bool enable_adaptive_fragmentation = true;  // Adapt fragmentation based on detection
    int max_fragment_retries = 3;  // Max retries before changing strategy

    ValidationError validate() const noexcept {
        if (fragment_size < 1 || fragment_size > 1460) return ValidationError::INVALID_FRAGMENT_SIZE;
        if (fragment_offset < 0) return ValidationError::INVALID_FRAGMENT_OFFSET;
        if (split_position < 0) return ValidationError::INVALID_SPLIT_POSITION;
        if (noise_size < 0 || noise_size > 65535) return ValidationError::INVALID_NOISE_SIZE;
        if (fake_ttl < 1 || fake_ttl > 255) return ValidationError::INVALID_FAKE_TTL;
        if (disorder_delay_ms < 0 || disorder_delay_ms > 10000) return ValidationError::INVALID_DISORDER_DELAY;
        if (listen_port == 0) return ValidationError::INVALID_LISTEN_PORT;
        if (nfqueue_num < 0 || nfqueue_num > 65535) return ValidationError::INVALID_NFQUEUE_NUM;
        if (mode == DPIMode::PROXY && target_host.empty()) return ValidationError::PROXY_MISSING_HOST;
        return ValidationError::NONE;
    }

    bool is_valid() const noexcept {
        return validate() == ValidationError::NONE;
    }

    void reset() noexcept {
        *this = DPIConfig{};
    }

    bool operator==(const DPIConfig& other) const noexcept {
        return mode == other.mode &&
               enable_tcp_split == other.enable_tcp_split &&
               split_position == other.split_position &&
               split_at_sni == other.split_at_sni &&
               enable_noise == other.enable_noise &&
               noise_size == other.noise_size &&
               enable_host_case == other.enable_host_case &&
               fake_host == other.fake_host &&
               enable_fake_packet == other.enable_fake_packet &&
               fake_ttl == other.fake_ttl &&
               enable_disorder == other.enable_disorder &&
               enable_oob_data == other.enable_oob_data &&
               disorder_delay_ms == other.disorder_delay_ms &&
               listen_port == other.listen_port &&
               target_host == other.target_host &&
               target_port == other.target_port &&
               nfqueue_num == other.nfqueue_num &&
               fragment_size == other.fragment_size &&
                                    fragment_offset == other.fragment_offset &&
                // Advanced DPI bypass fields
                randomize_split_position == other.randomize_split_position &&
                split_position_min == other.split_position_min &&
                split_position_max == other.split_position_max &&
                enable_pattern_obfuscation == other.enable_pattern_obfuscation &&
                randomize_fake_ttl == other.randomize_fake_ttl &&
                enable_tcp_options_randomization == other.enable_tcp_options_randomization &&
                enable_timing_jitter == other.enable_timing_jitter &&
                timing_jitter_min_us == other.timing_jitter_min_us &&
                timing_jitter_max_us == other.timing_jitter_max_us &&
                enable_multi_layer_split == other.enable_multi_layer_split &&
                split_positions == other.split_positions &&
                enable_decoy_sni == other.enable_decoy_sni &&
                decoy_sni_domains == other.decoy_sni_domains &&
                enable_adaptive_fragmentation == other.enable_adaptive_fragmentation &&
                max_fragment_retries == other.max_fragment_retries;
        return !(*this == other);
    }

    std::string to_string() const {
        std::ostringstream oss;
        oss << "DPIConfig {\n"
            << "  mode: " << static_cast<int>(mode) << ",\n"
            << "  enable_tcp_split: " << enable_tcp_split << ",\n"
            << "  split_position: " << split_position << ",\n"
            << "  split_at_sni: " << split_at_sni << ",\n"
            << "  enable_noise: " << enable_noise << ",\n"
            << "  noise_size: " << noise_size << ",\n"
            << "  enable_host_case: " << enable_host_case << ",\n"
            << "  fake_host: \"" << fake_host << "\",\n"
            << "  enable_fake_packet: " << enable_fake_packet << ",\n"
            << "  fake_ttl: " << fake_ttl << ",\n"
            << "  enable_disorder: " << enable_disorder << ",\n"
            << "  enable_oob_data: " << enable_oob_data << ",\n"
            << "  disorder_delay_ms: " << disorder_delay_ms << ",\n"
            << "  listen_port: " << listen_port << ",\n"
            << "  target_host: \"" << target_host << "\",\n"
            << "  target_port: " << target_port << ",\n"
            << "  nfqueue_num: " << nfqueue_num << ",\n"
            << "  fragment_size: " << fragment_size << ",\n"
            << "  fragment_offset: " << fragment_offset << "\n"
                        << "  // Advanced DPI bypass fields\n"
            << "  randomize_split_position: " << randomize_split_position << ",\n"
            << "  split_position_min: " << split_position_min << ",\n"
            << "  split_position_max: " << split_position_max << ",\n"
            << "  enable_pattern_obfuscation: " << enable_pattern_obfuscation << ",\n"
            << "  randomize_fake_ttl: " << randomize_fake_ttl << ",\n"
            << "  enable_tcp_options_randomization: " << enable_tcp_options_randomization << ",\n"
            << "  enable_timing_jitter: " << enable_timing_jitter << ",\n"
            << "  timing_jitter_min_us: " << timing_jitter_min_us << ",\n"
            << "  timing_jitter_max_us: " << timing_jitter_max_us << ",\n"
            << "  enable_multi_layer_split: " << enable_multi_layer_split << ",\n"
            << "  enable_decoy_sni: " << enable_decoy_sni << ",\n"
            << "  enable_adaptive_fragmentation: " << enable_adaptive_fragmentation << ",\n"
            << "  max_fragment_retries: " << max_fragment_retries << "\n"
            << "}";
        return oss.str();
    }

    std::string serialize() const {
        std::ostringstream oss;
        oss << static_cast<int>(mode) << "|"
            << enable_tcp_split << "|" << split_position << "|" << split_at_sni << "|"
            << enable_noise << "|" << noise_size << "|" << enable_host_case << "|"
            << fake_host << "|" << enable_fake_packet << "|" << fake_ttl << "|"
            << enable_disorder << "|" << enable_oob_data << "|" << disorder_delay_ms << "|"
            << listen_port << "|" << target_host << "|" << target_port << "|"
                            << nfqueue_num << "|" << fragment_size << "|" << fragment_offset
                // Advanced fields
                << "|" << randomize_split_position << "|" << split_position_min << "|" << split_position_max
                << "|" << enable_pattern_obfuscation << "|" << randomize_fake_ttl
                << "|" << enable_tcp_options_randomization
                << "|" << enable_timing_jitter << "|" << timing_jitter_min_us << "|" << timing_jitter_max_us
                << "|" << enable_multi_layer_split
                << "|" << enable_decoy_sni
                << "|" << enable_adaptive_fragmentation << "|" << max_fragment_retries;
        return oss.str();
    }

    static std::optional<DPIConfig> deserialize(const std::string& data) {
        DPIConfig cfg;
        std::istringstream iss(data);
        std::string token;
        int mode_int;
        try {
            if (!std::getline(iss, token, '|')) return std::nullopt;
            mode_int = std::stoi(token);
            cfg.mode = static_cast<DPIMode>(mode_int);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.enable_tcp_split = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.split_position = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.split_at_sni = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.enable_noise = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.noise_size = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.enable_host_case = std::stoi(token);
            if (!std::getline(iss, cfg.fake_host, '|')) return std::nullopt;
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.enable_fake_packet = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.fake_ttl = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.enable_disorder = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.enable_oob_data = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.disorder_delay_ms = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.listen_port = static_cast<uint16_t>(std::stoi(token));
            if (!std::getline(iss, cfg.target_host, '|')) return std::nullopt;
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.target_port = static_cast<uint16_t>(std::stoi(token));
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.nfqueue_num = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.fragment_size = std::stoi(token);
            if (!std::getline(iss, token, '|')) return std::nullopt;
            cfg.fragment_offset = std::stoi(token);
            // Advanced fields (optional - backward compatible)
            if (std::getline(iss, token, '|')) {
                cfg.randomize_split_position = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg; // return partial
                cfg.split_position_min = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.split_position_max = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.enable_pattern_obfuscation = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.randomize_fake_ttl = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.enable_tcp_options_randomization = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.enable_timing_jitter = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.timing_jitter_min_us = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.timing_jitter_max_us = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.enable_multi_layer_split = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.enable_decoy_sni = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.enable_adaptive_fragmentation = std::stoi(token);
                if (!std::getline(iss, token, '|')) return cfg;
                cfg.max_fragment_retries = std::stoi(token);
            }
                    } catch (...) {
            return std::nullopt;
        }
        if (!cfg.is_valid()) return std::nullopt;
        return cfg;
    }
};

const char* validation_error_to_string(ValidationError err);

void apply_preset(DPIPreset preset, DPIConfig& config);
DPIPreset preset_from_string(const std::string& name);
const char* preset_to_string(DPIPreset preset);

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERR
};

using LogCallback = std::function<void(LogLevel, const std::string&)>;
using ConfigChangeCallback = std::function<void(const DPIConfig&, const DPIConfig&)>;

/**
 * @brief Callback for advanced DPI transform pipeline integration.
 *
 * When set, the proxy send path delegates packet transformation to the
 * callback instead of using the built-in send_with_fragmentation logic.
 *
 * Parameters:
 *   - data:            raw packet bytes
 *   - len:             byte count
 *   - is_client_hello: true when the packet is a TLS ClientHello
 *
 * Returns: ordered list of segments to send over the wire.
 *          Each segment is transmitted as a separate send() call,
 *          with optional timing jitter applied between them.
 */
using TransformCallback = std::function<
    std::vector<std::vector<uint8_t>>(const uint8_t* data, size_t len, bool is_client_hello)
>;

struct DPIStats {
    std::atomic<uint64_t> packets_total{0};
    std::atomic<uint64_t> packets_modified{0};
    std::atomic<uint64_t> packets_fragmented{0};
    std::atomic<uint64_t> fake_packets_sent{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> connections_handled{0};

        DPIStats() = default;
    DPIStats(const DPIStats& other)
        : packets_total(other.packets_total.load()),
          packets_modified(other.packets_modified.load()),
          packets_fragmented(other.packets_fragmented.load()),
          fake_packets_sent(other.fake_packets_sent.load()),
          bytes_sent(other.bytes_sent.load()),
          bytes_received(other.bytes_received.load()),
          connections_handled(other.connections_handled.load()) {}
    DPIStats& operator=(const DPIStats& other) {
        if (this != &other) {
            packets_total.store(other.packets_total.load());
            packets_modified.store(other.packets_modified.load());
            packets_fragmented.store(other.packets_fragmented.load());
            fake_packets_sent.store(other.fake_packets_sent.load());
            bytes_sent.store(other.bytes_sent.load());
            bytes_received.store(other.bytes_received.load());
            connections_handled.store(other.connections_handled.load());
        }
        return *this;
    }

    void reset() noexcept {
        packets_total.store(0);
        packets_modified.store(0);
        packets_fragmented.store(0);
        fake_packets_sent.store(0);
        bytes_sent.store(0);
        bytes_received.store(0);
        connections_handled.store(0);
    }

    DPIStats snapshot() const noexcept {
        DPIStats s;
        s.packets_total.store(packets_total.load());
        s.packets_modified.store(packets_modified.load());
        s.packets_fragmented.store(packets_fragmented.load());
        s.fake_packets_sent.store(fake_packets_sent.load());
        s.bytes_sent.store(bytes_sent.load());
        s.bytes_received.store(bytes_received.load());
        s.connections_handled.store(connections_handled.load());
        return s;
    }
};

class DPIBypass {
public:
    DPIBypass();
    ~DPIBypass();

    DPIBypass(const DPIBypass&) = delete;
    DPIBypass& operator=(const DPIBypass&) = delete;

    bool initialize(const DPIConfig& config);
    bool start();
    void stop();
    void shutdown();
    bool is_running() const;

    DPIConfig get_config() const;
    bool update_config(const DPIConfig& config);

    DPIStats get_stats() const;
    void reset_stats();

    void set_log_callback(LogCallback callback);
    void set_config_change_callback(ConfigChangeCallback callback);

    /**
     * @brief Register an advanced transform pipeline for outgoing packets.
     *
     * When a non-null callback is installed the proxy send path will call it
     * instead of the built-in send_with_fragmentation routine, allowing
     * AdvancedDPIBypass::process_outgoing (or any external transform chain)
     * to control segmentation, obfuscation and timing of each connection.
     *
     * Pass nullptr to revert to the default built-in fragmentation logic.
     *
     * Thread-safe: the callback is guarded by an internal mutex and may be
     * changed while the proxy is running.
     */
    void set_transform_callback(TransformCallback callback);

private:
    void log(LogLevel level, const std::string& message);
    void notify_config_change(const DPIConfig& old_cfg, const DPIConfig& new_cfg);

    class Impl;
    std::unique_ptr<Impl> impl_;

    mutable std::shared_mutex config_mutex_;
    DPIConfig config_;

    mutable std::mutex log_mutex_;
    LogCallback log_callback_;

    mutable std::mutex config_cb_mutex_;
    ConfigChangeCallback config_change_callback_;

    mutable std::mutex transform_cb_mutex_;
    TransformCallback transform_callback_;

    DPIStats stats_;
};

} // namespace DPI
} // namespace ncp
