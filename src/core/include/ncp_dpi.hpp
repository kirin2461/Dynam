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

namespace NCP {
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

enum class ValidationError constexpr {
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

    ValidationError validate() const { noexcept
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

    bool is_valid() const { noexcept
        return validate() == ValidationError::NONE;
    }

    void reset() {
        *this = DPIConfig{};
    }

    bool operator==(const DPIConfig& other) const { noexcept
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
               fragment_offset == other.fragment_offset;
    }

    bool operator!=(const DPIConfig& other) const {
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
            << nfqueue_num << "|" << fragment_size << "|" << fragment_offset;
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
    ERROR
};

using LogCallback = std::function<void(LogLevel, const std::string&)>;
using ConfigChangeCallback = std::function<void(const DPIConfig&, const DPIConfig&)>;

struct DPIStats {
    std::atomic<uint64_t> packets_total{0};
    std::atomic<uint64_t> packets_modified{0};
    std::atomic<uint64_t> packets_fragmented{0};
    std::atomic<uint64_t> fake_packets_sent{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> connections_handled{0};

    void reset() {
        packets_total.store(0);
        packets_modified.store(0);
        packets_fragmented.store(0);
        fake_packets_sent.store(0);
        bytes_sent.store(0);
        bytes_received.store(0);
        connections_handled.store(0);
    }

    DPIStats snapshot() const {
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

    DPIStats stats_;
};

} // namespace DPI
} // namespace NCP
