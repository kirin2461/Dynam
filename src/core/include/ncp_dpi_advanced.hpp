#ifndef NCP_DPI_ADVANCED_HPP
#define NCP_DPI_ADVANCED_HPP

#include "ncp_dpi.hpp"
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <chrono>
#include <random>
#include <cstdint>

namespace NCP {
namespace DPI {

/**
 * @brief Advanced DPI evasion techniques
 */
enum class EvasionTechnique {
    // TCP-level techniques
    TCP_SEGMENTATION,       // Split TCP segments
    TCP_DISORDER,           // Out-of-order packet delivery
    TCP_OVERLAP,            // Overlapping TCP segments
    TCP_OOB_DATA,           // Out-of-band urgent data
    TCP_WINDOW_SIZE,        // TCP window size manipulation
    TCP_TIMESTAMP_EDIT,     // TCP timestamp option editing
    TCP_RST_CONFUSION,      // RST packet injection for DPI confusion
    
    // TLS-level techniques
    TLS_RECORD_SPLIT,       // Split TLS records
    TLS_PADDING,            // TLS record padding
    TLS_FAKE_EXTENSION,     // Inject fake TLS extensions
    TLS_VERSION_CONFUSION,  // TLS version field manipulation
    TLS_GREASE,             // GREASE values for extension randomization
    
    // HTTP/HTTPS techniques
    HTTP_HEADER_SPLIT,      // Split HTTP headers
    HTTP_SPACE_TRICK,       // Space before colon in headers
    HTTP_CASE_VARIATION,    // Mixed case in method/headers
    HTTP_HOST_CONFUSION,    // Host header obfuscation
    
    // IP-level techniques
    IP_FRAGMENTATION,       // IP-level fragmentation
    IP_TTL_TRICKS,          // TTL manipulation (fake packets)
    IP_ID_RANDOMIZATION,    // IP ID field randomization
    IP_OPTIONS_PADDING,     // IP options for length confusion
    
    // Timing techniques  
    TIMING_JITTER,          // Random timing between packets
    TIMING_THROTTLE,        // Slow packet sending
    TIMING_BURST,           // Burst then pause patterns
};

/**
 * @brief Protocol obfuscation modes
 */
enum class ObfuscationMode {
    NONE,                   // No obfuscation
    XOR_SIMPLE,             // Simple XOR cipher (weak, for testing)
    XOR_ROLLING,            // Rolling XOR with changing key
    AES_STREAM,             // AES-CTR stream cipher
    CHACHA20,               // ChaCha20 stream cipher
    SHADOWSOCKS,            // Shadowsocks-compatible
    OBFS4,                  // obfs4 compatible
    WEBSOCKET_TUNNEL,       // WebSocket encapsulation
    HTTP_CAMOUFLAGE,        // Make traffic look like HTTP
    DNS_TUNNEL,             // DNS tunneling
};

/**
 * @brief Traffic padding configuration
 */
struct PaddingConfig {
    bool enabled = false;
    size_t min_padding = 0;         // Minimum padding bytes
    size_t max_padding = 256;       // Maximum padding bytes
    bool random_padding = true;     // Randomize padding size
    uint8_t padding_byte = 0x00;    // Padding byte value (0x00 or random)
};

/**
 * @brief Traffic shaping configuration
 */
struct TrafficShapingConfig {
    bool enabled = false;
    
    // Bandwidth limiting
    uint64_t max_bandwidth_bps = 0; // 0 = unlimited
    
    // Timing patterns
    uint32_t min_delay_ms = 0;      // Minimum inter-packet delay
    uint32_t max_delay_ms = 100;    // Maximum inter-packet delay
    bool random_timing = true;      // Randomize delays
    
    // Burst patterns
    bool burst_mode = false;        // Enable burst sending
    uint32_t burst_size = 10;       // Packets per burst
    uint32_t burst_delay_ms = 50;   // Delay between bursts
};

/**
 * @brief Protocol mimicry configuration
 */
struct MimicryConfig {
    bool enabled = false;
    std::string protocol = "https";  // Protocol to mimic
    std::string fake_host = "";      // Fake Host header
    std::string fake_sni = "";       // Fake SNI (innocent domain)
    bool add_http_headers = false;   // Add innocent HTTP headers
    std::vector<std::pair<std::string, std::string>> custom_headers;
};

/**
 * @brief Advanced DPI configuration
 */
struct AdvancedDPIConfig {
    // Inherit from basic config
    DPIConfig base_config;
    
    // Enabled evasion techniques
    std::vector<EvasionTechnique> techniques;
    
    // Obfuscation settings
    ObfuscationMode obfuscation = ObfuscationMode::NONE;
    std::vector<uint8_t> obfuscation_key;  // Key for encryption-based obfuscation
    
    // Padding and shaping
    PaddingConfig padding;
    TrafficShapingConfig shaping;
    
    // Protocol mimicry
    MimicryConfig mimicry;
    
    // TCP-level settings
    bool enable_tcp_keepalive_tricks = false;
    bool enable_nagle_manipulation = true;
    int tcp_window_scale = -1;      // -1 = auto
    
    // Fingerprint randomization
    bool randomize_tcp_options = true;
    bool randomize_ip_id = true;
    bool randomize_ttl = false;     // Can break connectivity
    int ttl_range_min = 64;
    int ttl_range_max = 128;
    
    // Multi-path settings
    bool enable_multipath = false;   // Use multiple routes if available
    
    // Russian DPI specific
    bool tspu_bypass = true;        // TSPU (Russian DPI) specific bypass
    bool china_gfw_bypass = false;  // China GFW specific techniques
};

/**
 * @brief Advanced DPI evasion statistics
 */
struct AdvancedDPIStats {
    DPIStats base_stats;
    
    // Technique-specific counters
    uint64_t tcp_segments_split = 0;
    uint64_t tcp_overlaps_sent = 0;
    uint64_t tcp_oob_sent = 0;
    uint64_t tls_records_split = 0;
    uint64_t packets_padded = 0;
    uint64_t bytes_padding = 0;
    uint64_t timing_delays_applied = 0;
    uint64_t fake_packets_injected = 0;
    
    // Obfuscation stats
    uint64_t bytes_obfuscated = 0;
    uint64_t bytes_deobfuscated = 0;
    
    // Detection evasion
    uint64_t dpi_signatures_evaded = 0;  // Estimated
};

/**
 * @brief Packet transformer interface
 */
class PacketTransformer {
public:
    virtual ~PacketTransformer() = default;
    
    // Transform outgoing packet
    virtual std::vector<std::vector<uint8_t>> transform(
        const uint8_t* data,
        size_t len,
        bool is_client_hello
    ) = 0;
    
    // Reverse transform for incoming packets (if applicable)
    virtual std::vector<uint8_t> reverse_transform(
        const uint8_t* data,
        size_t len
    ) = 0;
};

/**
 * @brief TCP segment manipulator for DPI evasion
 */
class TCPManipulator {
public:
    TCPManipulator();
    ~TCPManipulator();
    
    // Split data at specific positions
    std::vector<std::vector<uint8_t>> split_segments(
        const uint8_t* data,
        size_t len,
        const std::vector<size_t>& split_points
    );
    
    // Create overlapping segments
    std::vector<std::vector<uint8_t>> create_overlap(
        const uint8_t* data,
        size_t len,
        size_t overlap_size
    );
    
    // Add TCP out-of-band data
    std::vector<uint8_t> add_oob_marker(
        const uint8_t* data,
        size_t len,
        size_t urgent_position
    );
    
    // Reorder segments for disorder effect
    void shuffle_segments(
        std::vector<std::vector<uint8_t>>& segments,
        std::mt19937& rng
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief TLS record manipulator
 */
class TLSManipulator {
public:
    TLSManipulator();
    ~TLSManipulator();
    
    // Find SNI in ClientHello and return split points
    std::vector<size_t> find_sni_split_points(
        const uint8_t* data,
        size_t len
    );
    
    // Split TLS record into multiple records
    std::vector<std::vector<uint8_t>> split_tls_record(
        const uint8_t* data,
        size_t len,
        size_t max_fragment_size
    );
    
    // Add padding to TLS record
    std::vector<uint8_t> add_tls_padding(
        const uint8_t* data,
        size_t len,
        size_t padding_size
    );
    
    // Inject GREASE values
    std::vector<uint8_t> inject_grease(
        const uint8_t* data,
        size_t len
    );
    
    // Create fake ClientHello with innocent SNI
    std::vector<uint8_t> create_fake_client_hello(
        const std::string& fake_sni
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Traffic obfuscator
 */
class TrafficObfuscator {
public:
    TrafficObfuscator(ObfuscationMode mode, const std::vector<uint8_t>& key = {});
    ~TrafficObfuscator();
    
    // Obfuscate data
    std::vector<uint8_t> obfuscate(
        const uint8_t* data,
        size_t len
    );
    
    // De-obfuscate data
    std::vector<uint8_t> deobfuscate(
        const uint8_t* data,
        size_t len
    );
    
    // Get current mode
    ObfuscationMode get_mode() const;
    
    // Rotate key (for modes that support it)
    void rotate_key();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Advanced DPI Bypass with enhanced evasion
 */
class AdvancedDPIBypass {
public:
    AdvancedDPIBypass();
    ~AdvancedDPIBypass();
    
    // Non-copyable
    AdvancedDPIBypass(const AdvancedDPIBypass&) = delete;
    AdvancedDPIBypass& operator=(const AdvancedDPIBypass&) = delete;
    
    /**
     * @brief Initialize with advanced configuration
     */
    bool initialize(const AdvancedDPIConfig& config);
    
    /**
     * @brief Start bypass
     */
    bool start();
    
    /**
     * @brief Stop bypass
     */
    void stop();
    
    /**
     * @brief Check if running
     */
    bool is_running() const;
    
    /**
     * @brief Get statistics
     */
    AdvancedDPIStats get_stats() const;
    
    /**
     * @brief Process and transform data for evasion
     */
    std::vector<std::vector<uint8_t>> process_outgoing(
        const uint8_t* data,
        size_t len
    );
    
    /**
     * @brief Process incoming data (reverse transform)
     */
    std::vector<uint8_t> process_incoming(
        const uint8_t* data,
        size_t len
    );
    
    /**
     * @brief Set log callback
     */
    void set_log_callback(std::function<void(const std::string&)> callback);
    
    /**
     * @brief Enable/disable specific technique at runtime
     */
    void set_technique_enabled(EvasionTechnique technique, bool enabled);
    
    /**
     * @brief Get currently active techniques
     */
    std::vector<EvasionTechnique> get_active_techniques() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Preset configurations for different DPI systems
 */
namespace Presets {
    // Russian TSPU (ТСПУ) bypass preset
    AdvancedDPIConfig create_tspu_preset();
    
    // China GFW bypass preset  
    AdvancedDPIConfig create_gfw_preset();
    
    // Iran DPI bypass preset
    AdvancedDPIConfig create_iran_preset();
    
    // Generic aggressive preset
    AdvancedDPIConfig create_aggressive_preset();
    
    // Minimal footprint preset (less detectable)
    AdvancedDPIConfig create_stealth_preset();
    
    // Maximum compatibility preset
    AdvancedDPIConfig create_compatible_preset();
}

}  // namespace DPI
}  // namespace NCP

#endif  // NCP_DPI_ADVANCED_HPP
