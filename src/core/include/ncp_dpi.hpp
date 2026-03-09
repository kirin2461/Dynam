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

// Forward declare from ncp_dpi_zapret.hpp
struct ZapretChain;

enum class DPIMode {
    DRIVER,
    PROXY,
    PASSIVE,
    WS_TUNNEL   // WebSocket tunnel mode (requires HAVE_LIBWEBSOCKETS)
};

enum class DPIPreset {
    NONE,
    RUNET_SOFT,
    RUNET_STRONG,
    RUNET_TSPU,        // Advanced TSPU bypass: fake+disorder+multisplit (home ISPs)
    // Mobile operator presets (higher TTL, adapted fooling)
    BEELINE_MOBILE,    // Beeline: reverse-frag + higher TTL + DNS fix
    MTS_MOBILE,        // MTS: fake+disorder, auto-ttl range 4-8
    MEGAFON_MOBILE,    // Megafon: split+fake+OOB, ttl=6
    TELE2_MOBILE,      // Tele2/t2: similar to MTS with minor tweaks
    MOBILE_UNIVERSAL,  // Universal mobile: conservative multi-method
    AUTOPROBE          // Auto-detect: tries strategies sequentially
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
    PROXY_MISSING_HOST,
    // FIX: New validation errors for advanced fields
    INVALID_SPLIT_RANGE,         // split_position_min > split_position_max
    INVALID_JITTER_RANGE,        // timing_jitter_min_us > timing_jitter_max_us
    WS_TUNNEL_MISSING_URL        // ws_server_url empty when mode == WS_TUNNEL
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

    // Fooling methods for fake packets (bitflags)
    // 1=badsum (wrong TCP checksum), 2=badseq (wrong TCP SeqNum),
    // 4=md5sig (TCP MD5 option), 8=datanoack (set ACK=0 on data pkt)
    int fake_fooling = 0;
    int fake_repeats = 1;         // send each fake N times
    // Multi-split positions (used when enable_multi_layer_split=true)
    // e.g. {1, <sni_offset>} for pos 1 + midsld
    // (split_positions vector from advanced section is reused)

    uint16_t listen_port = 8881;
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
    bool enable_tcp_options_randomization = false;  // Randomize TCP options (delegated to AdvancedDPIBypass)
    
    bool enable_timing_jitter = false;  // Add timing jitter to packets
    int timing_jitter_min_us = 0;  // Min jitter in microseconds
    int timing_jitter_max_us = 1000;  // Max jitter in microseconds
    
    bool enable_multi_layer_split = false;  // Split at multiple positions
    std::vector<int> split_positions;  // Multiple split positions
    
    bool enable_decoy_sni = false;  // Send decoy SNI packets
    std::vector<std::string> decoy_sni_domains;  // Decoy SNI domains
    
    bool enable_adaptive_fragmentation = true;  // Adapt fragmentation based on detection
    int max_fragment_retries = 3;  // Max retries before changing strategy

    // Reverse fragment order (send second fragment first, then first)
    // Mimics GoodbyeDPI --reverse-frag; effective on Beeline and some TSPU
    bool enable_reverse_frag = false;

    // Auto-TTL: automatically determine fake TTL based on incoming packets
    // Uses incoming TTL to estimate hop count: fake_ttl = path_hops + autottl_delta
    //
    // R7-DPI-01 LIMITATION: In DRIVER mode (WinDivert on Windows), auto-TTL is
    // ineffective because WinDivert intercepts OUTBOUND packets before routing,
    // so the observed TTL is the local OS default (128), not the path TTL.
    // Auto-TTL requires observing INCOMING SYN-ACK packets to estimate hop count.
    // Workaround: Use PROXY mode where incoming packets are observable, or set
    // fake_ttl manually. See AUDIT.md #R7-DPI-01 for details.
    bool enable_autottl = false;
    int autottl_delta = 1;       // delta added to estimated path hops (can be negative)
    int autottl_min = 3;         // minimum auto-detected TTL
    int autottl_max = 20;        // maximum auto-detected TTL

    // Auto-probe: sequentially try preset strategies until one works
    bool enable_autoprobe = false;
    int autoprobe_timeout_sec = 8;     // seconds to test each strategy
    int autoprobe_max_strategies = 10; // max strategies to try

    // WebSocket tunnel settings (used when mode == WS_TUNNEL)
    std::string ws_server_url;        // wss://relay.example.com/tunnel
    std::string ws_sni_override;      // domain fronting SNI
    uint16_t ws_local_port = 8081;    // local proxy port for WS tunnel
    int ws_ping_interval_sec = 30;
    int ws_reconnect_delay_ms = 1000;
    int ws_max_reconnect_attempts = 10;

    // R11-M01: Helper to normalize ranges (min <= max). Called from parse() only.
    // This is NOT part of validate() to keep validation const and side-effect-free.
    static void normalize_ranges(DPIConfig& cfg) noexcept {
        if (cfg.randomize_split_position && cfg.split_position_min > cfg.split_position_max) {
            std::swap(cfg.split_position_min, cfg.split_position_max);
        }
        if (cfg.enable_timing_jitter && cfg.timing_jitter_min_us > cfg.timing_jitter_max_us) {
            std::swap(cfg.timing_jitter_min_us, cfg.timing_jitter_max_us);
        }
        if (cfg.autottl_min > cfg.autottl_max) {
            std::swap(cfg.autottl_min, cfg.autottl_max);
        }
    }

    // FIX: Extended validation covering advanced fields
    // R11-M01: Validation is now const and side-effect-free (no auto-correction)
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
        // R11-M01: Only check ranges, don't auto-correct (that's done in parse() via normalize_ranges)
        if (mode == DPIMode::WS_TUNNEL && ws_server_url.empty())
            return ValidationError::WS_TUNNEL_MISSING_URL;
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
                max_fragment_retries == other.max_fragment_retries &&
                enable_reverse_frag == other.enable_reverse_frag &&
                enable_autottl == other.enable_autottl &&
                autottl_delta == other.autottl_delta &&
                autottl_min == other.autottl_min &&
                autottl_max == other.autottl_max &&
                enable_autoprobe == other.enable_autoprobe &&
                autoprobe_timeout_sec == other.autoprobe_timeout_sec &&
                autoprobe_max_strategies == other.autoprobe_max_strategies &&
                // WS tunnel fields
                ws_server_url == other.ws_server_url &&
                ws_sni_override == other.ws_sni_override &&
                ws_local_port == other.ws_local_port &&
                ws_ping_interval_sec == other.ws_ping_interval_sec &&
                ws_reconnect_delay_ms == other.ws_reconnect_delay_ms &&
                ws_max_reconnect_attempts == other.ws_max_reconnect_attempts;
    }

    bool operator!=(const DPIConfig& other) const noexcept {
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
            << "  max_fragment_retries: " << max_fragment_retries << ",\n"
            << "  enable_reverse_frag: " << enable_reverse_frag << ",\n"
            << "  enable_autottl: " << enable_autottl << ",\n"
            << "  autottl_delta: " << autottl_delta << ",\n"
            << "  autottl_min: " << autottl_min << ",\n"
            << "  autottl_max: " << autottl_max << ",\n"
            << "  enable_autoprobe: " << enable_autoprobe << ",\n"
            << "  autoprobe_timeout_sec: " << autoprobe_timeout_sec << ",\n"
            << "  autoprobe_max_strategies: " << autoprobe_max_strategies << ",\n"
            << "  // WS tunnel fields\n"
            << "  ws_server_url: \"" << ws_server_url << "\",\n"
            << "  ws_sni_override: \"" << ws_sni_override << "\",\n"
            << "  ws_local_port: " << ws_local_port << ",\n"
            << "  ws_ping_interval_sec: " << ws_ping_interval_sec << ",\n"
            << "  ws_reconnect_delay_ms: " << ws_reconnect_delay_ms << ",\n"
            << "  ws_max_reconnect_attempts: " << ws_max_reconnect_attempts << "\n"
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
                << "|" << enable_adaptive_fragmentation << "|" << max_fragment_retries
                << "|" << enable_reverse_frag
                << "|" << enable_autottl << "|" << autottl_delta
                << "|" << autottl_min << "|" << autottl_max
                << "|" << enable_autoprobe << "|" << autoprobe_timeout_sec
                << "|" << autoprobe_max_strategies
                // WS tunnel fields
                << "|" << ws_server_url << "|" << ws_sni_override
                << "|" << ws_local_port << "|" << ws_ping_interval_sec
                << "|" << ws_reconnect_delay_ms << "|" << ws_max_reconnect_attempts;
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
                // New adaptive/autoprobe fields (optional - backward compatible)
                if (std::getline(iss, token, '|')) {
                    cfg.enable_reverse_frag = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.enable_autottl = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.autottl_delta = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.autottl_min = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.autottl_max = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.enable_autoprobe = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.autoprobe_timeout_sec = std::stoi(token);
                    if (std::getline(iss, token, '|')) cfg.autoprobe_max_strategies = std::stoi(token);
                }
                // WS tunnel fields (optional - backward compatible)
                if (std::getline(iss, cfg.ws_server_url, '|')) {
                    if (!std::getline(iss, cfg.ws_sni_override, '|')) return cfg;
                    if (!std::getline(iss, token, '|')) return cfg;
                    cfg.ws_local_port = static_cast<uint16_t>(std::stoi(token));
                    if (!std::getline(iss, token, '|')) return cfg;
                    cfg.ws_ping_interval_sec = std::stoi(token);
                    if (!std::getline(iss, token, '|')) return cfg;
                    cfg.ws_reconnect_delay_ms = std::stoi(token);
                    if (!std::getline(iss, token, '|')) return cfg;
                    cfg.ws_max_reconnect_attempts = std::stoi(token);
                }
                // R11-M01: Normalize all ranges in one place after parsing
                normalize_ranges(cfg);
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

enum class DPILogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERR
};

using LogCallback = std::function<void(DPILogLevel, const std::string&)>;
using ConfigChangeCallback = std::function<void(const DPIConfig&, const DPIConfig&)>;

/**
 * @brief Transform callback invoked on outgoing payload BEFORE fragmentation.
 *
 * Receives raw payload bytes, returns transformed bytes that will then be
 * fragmented/split by the DPIBypass send pipeline.  If the callback returns
 * an empty vector the original payload is used unchanged.
 *
 * Thread-safety: the callback may be invoked from any connection-handling
 * thread.  Implementations must be re-entrant.
 */
using TransformCallback = std::function<std::vector<uint8_t>(
    const std::vector<uint8_t>& payload)>;

struct DPIStats {
    std::atomic<uint64_t> packets_total{0};
    std::atomic<uint64_t> packets_modified{0};
    std::atomic<uint64_t> packets_fragmented{0};
    std::atomic<uint64_t> fake_packets_sent{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> connections_handled{0};
    // CRIT-1: count WinDivertSend failures
    std::atomic<uint64_t> send_errors{0};

        DPIStats() = default;
    DPIStats(const DPIStats& other)
        : packets_total(other.packets_total.load()),
          packets_modified(other.packets_modified.load()),
          packets_fragmented(other.packets_fragmented.load()),
          fake_packets_sent(other.fake_packets_sent.load()),
          bytes_sent(other.bytes_sent.load()),
          bytes_received(other.bytes_received.load()),
          connections_handled(other.connections_handled.load()),
          send_errors(other.send_errors.load()) {}
    DPIStats& operator=(const DPIStats& other) {
        if (this != &other) {
            packets_total.store(other.packets_total.load());
            packets_modified.store(other.packets_modified.load());
            packets_fragmented.store(other.packets_fragmented.load());
            fake_packets_sent.store(other.fake_packets_sent.load());
            bytes_sent.store(other.bytes_sent.load());
            bytes_received.store(other.bytes_received.load());
            connections_handled.store(other.connections_handled.load());
            send_errors.store(other.send_errors.load());
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
        send_errors.store(0);
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
        s.send_errors.store(send_errors.load());
        return s;
    }
};

// Module hook callbacks - set by external code (e.g. main.cpp) to integrate
// additional processing modules into the WinDivert packet pipeline.
// All fields are optional: check before calling.
struct ModuleHooks {
    // Called for every intercepted outbound packet BEFORE DPI processing.
    // Receives raw packet buffer and length (length may be modified in-place).
    // Return false to DROP the packet (skip sending).
    std::function<bool(uint8_t* packet, uint32_t& packet_len)> pre_process;

    // Called for every intercepted outbound packet AFTER DPI processing.
    // For stats/monitoring only - packet is already sent.
    std::function<void(const uint8_t* packet, uint32_t packet_len)> post_process;

    // Called to get delay in microseconds before sending a real segment.
    // Return value <= 0 means no delay. Sanity cap is applied in the loop.
    std::function<int64_t(const uint8_t* packet, uint32_t packet_len)> get_send_delay_us;
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

    /// Mark this instance as a base-only layer (no AdvancedDPIBypass child).
    /// Used internally by AdvancedDPIBypass to break infinite recursion.
    void set_base_only(bool v);

    /**
     * @brief Register a transform callback for the outgoing send pipeline.
     *
     * The callback is invoked on every outgoing payload BEFORE TCP
     * fragmentation / advanced DPI processing.  This allows the
     * ProtocolOrchestrator (or any external layer) to inject adversarial
     * padding, mimicry wrapping, etc. into the DPIBypass send path.
     *
     * Pass nullptr / empty std::function to clear the callback.
     *
     * Thread-safe: may be called while the bypass is running.
     */
    void set_transform_callback(TransformCallback callback);

    /// Register module hooks to be called in the WinDivert packet pipeline.
    /// Thread-safe: may be called before or after start().
    void set_module_hooks(const ModuleHooks& hooks);

    /// Set zapret chains for chain-based DPI desync.
    /// When non-empty, windivert_loop uses per-chain parameters.
    void set_zapret_chains(std::vector<ZapretChain> chains);

private:
    void log(DPILogLevel level, const std::string& message);
    void notify_config_change(const DPIConfig& old_cfg, const DPIConfig& new_cfg);

    class Impl;
    std::unique_ptr<Impl> impl_;

    // FIX: Removed dead outer config_ / config_mutex_ -- all config lives in Impl

    mutable std::mutex log_mutex_;
    LogCallback log_callback_;

    mutable std::mutex config_cb_mutex_;
    ConfigChangeCallback config_change_callback_;

    DPIStats stats_;
};

} // namespace DPI
} // namespace ncp
