#ifndef NCP_DPI_ADVANCED_HPP
#define NCP_DPI_ADVANCED_HPP

#include "ncp_dpi.hpp"
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <chrono>
#include <cstdint>

// Forward declaration to avoid circular include
namespace ncp {
    class TLSFingerprint;
}

namespace ncp {
namespace DPI {

/**
 * @brief Advanced DPI evasion techniques
 */
enum class EvasionTechnique {
    // TCP-level techniques
    TCP_SEGMENTATION,
    TCP_DISORDER,
    TCP_OVERLAP,
    TCP_OOB_DATA,
    TCP_WINDOW_SIZE,
    TCP_TIMESTAMP_EDIT,
    TCP_RST_CONFUSION,
    
    // TLS-level techniques
    TLS_RECORD_SPLIT,
    TLS_PADDING,
    TLS_FAKE_EXTENSION,
    TLS_VERSION_CONFUSION,
    TLS_GREASE,
    
    // HTTP/HTTPS techniques
    HTTP_HEADER_SPLIT,
    HTTP_SPACE_TRICK,
    SNI_SPLIT,
    GREASE_INJECTION,
    FAKE_SNI,
    HTTP_CASE_VARIATION,
    HTTP_HOST_CONFUSION,
    
    // IP-level techniques
    IP_FRAGMENTATION,
    IP_TTL_TRICKS,
    IP_ID_RANDOMIZATION,
    IP_OPTIONS_PADDING,
    
    // Timing techniques  
    TIMING_JITTER,
    TIMING_THROTTLE,
    TIMING_BURST,
};

/**
 * @brief Protocol obfuscation modes
 */
enum class ObfuscationMode {
    NONE,
    XOR_SIMPLE,
    XOR_ROLLING,
    AES_STREAM,
    CHACHA20,
    SHADOWSOCKS,
    OBFS4,
    WEBSOCKET_TUNNEL,
    HTTP_CAMOUFLAGE,
    DNS_TUNNEL,
};

struct PaddingConfig {
    bool enabled = false;
    size_t min_padding = 0;
    size_t max_padding = 256;
    bool random_padding = true;
    uint8_t padding_byte = 0x00;
};

struct TrafficShapingConfig {
    bool enabled = false;
    uint64_t max_bandwidth_bps = 0;
    uint32_t min_delay_ms = 0;
    uint32_t max_delay_ms = 100;
    bool random_timing = true;
    bool burst_mode = false;
    uint32_t burst_size = 10;
    uint32_t burst_delay_ms = 50;
};

struct MimicryConfig {
    bool enabled = false;
    std::string protocol = "https";
    std::string fake_host = "";
    std::string fake_sni = "";
    bool add_http_headers = false;
    std::vector<std::pair<std::string, std::string>> custom_headers;
};

struct AdvancedDPIConfig {
    DPIConfig base_config;
    std::vector<EvasionTechnique> techniques;
    ObfuscationMode obfuscation = ObfuscationMode::NONE;
    std::vector<uint8_t> obfuscation_key;
    PaddingConfig padding;
    TrafficShapingConfig shaping;
    MimicryConfig mimicry;
    bool enable_tcp_keepalive_tricks = false;
    bool enable_nagle_manipulation = true;
    int tcp_window_scale = -1;
    bool randomize_tcp_options = true;
    bool randomize_ip_id = true;
    bool randomize_ttl = false;
    int ttl_range_min = 64;
    int ttl_range_max = 128;
    bool enable_multipath = false;
    bool tspu_bypass = true;
    bool china_gfw_bypass = false;

    // === Phase 3D: ECH (Encrypted Client Hello) support ===
    bool enable_ech = false;
    std::vector<uint8_t> ech_config_list;  // Serialized ECHConfig (from DNS or manual)
};

struct AdvancedDPIStats {
    DPIStats base_stats;
    uint64_t tcp_segments_split = 0;
    uint64_t tcp_overlaps_sent = 0;
    uint64_t tcp_oob_sent = 0;
    uint64_t tls_records_split = 0;
    uint64_t grease_injected = 0;
    uint64_t packets_padded = 0;
    uint64_t bytes_padding = 0;
    uint64_t timing_delays_applied = 0;
    uint64_t fake_packets_injected = 0;
    uint64_t bytes_obfuscated = 0;
    uint64_t bytes_deobfuscated = 0;
    uint64_t dpi_signatures_evaded = 0;
    uint64_t ech_applied = 0;  // Phase 3D: Count successful ECH applications
};

class PacketTransformer {
public:
    virtual ~PacketTransformer() = default;
    virtual std::vector<std::vector<uint8_t>> transform(
        const uint8_t* data, size_t len, bool is_client_hello) = 0;
    virtual std::vector<uint8_t> reverse_transform(
        const uint8_t* data, size_t len) = 0;
};

class TCPManipulator {
public:
    TCPManipulator();
    ~TCPManipulator();
    
    std::vector<std::vector<uint8_t>> split_segments(
        const uint8_t* data, size_t len,
        const std::vector<size_t>& split_points);
    
    std::vector<std::vector<uint8_t>> create_overlap(
        const uint8_t* data, size_t len, size_t overlap_size);
    
    std::vector<uint8_t> add_oob_marker(
        const uint8_t* data, size_t len, size_t urgent_position);
    
    void shuffle_segments(
        std::vector<std::vector<uint8_t>>& segments,
        void* unused_param = nullptr);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class TLSManipulator {
public:
    TLSManipulator();
    ~TLSManipulator();
    
    std::vector<size_t> find_sni_split_points(
        const uint8_t* data, size_t len);
    
    std::vector<std::vector<uint8_t>> split_tls_record(
        const uint8_t* data, size_t len, size_t max_fragment_size);
    
    std::vector<uint8_t> add_tls_padding(
        const uint8_t* data, size_t len, size_t padding_size);
    
    std::vector<uint8_t> inject_grease(
        const uint8_t* data, size_t len);
    
    std::vector<uint8_t> create_fake_client_hello(
        const std::string& fake_sni);

    /**
     * @brief Set TLS fingerprint for realistic ClientHello generation.
     * @param fp Pointer to TLSFingerprint (not owned, caller must keep alive).
     */
    void set_tls_fingerprint(ncp::TLSFingerprint* fp);

    /**
     * @brief Create a ClientHello using the currently set TLS fingerprint.
     *        Falls back to create_fake_client_hello() if no fingerprint set.
     * @param sni  Server Name Indication hostname.
     * @return Complete TLS record containing a fingerprinted ClientHello.
     */
    std::vector<uint8_t> create_fingerprinted_client_hello(
        const std::string& sni);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class TrafficObfuscator {
public:
    TrafficObfuscator(ObfuscationMode mode, const std::vector<uint8_t>& key = {});
    ~TrafficObfuscator();
    
    std::vector<uint8_t> obfuscate(const uint8_t* data, size_t len);
    std::vector<uint8_t> deobfuscate(const uint8_t* data, size_t len);
    ObfuscationMode get_mode() const;
    void rotate_key();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class AdvancedDPIBypass {
public:
    AdvancedDPIBypass();
    ~AdvancedDPIBypass();
    
    AdvancedDPIBypass(const AdvancedDPIBypass&) = delete;
    AdvancedDPIBypass& operator=(const AdvancedDPIBypass&) = delete;
    
    bool initialize(const AdvancedDPIConfig& config);
    bool start();
    void stop();
    bool is_running() const;
    AdvancedDPIStats get_stats() const;
    
    std::vector<std::vector<uint8_t>> process_outgoing(
        const uint8_t* data, size_t len);
    
    std::vector<uint8_t> process_incoming(
        const uint8_t* data, size_t len);
    
    void set_log_callback(std::function<void(const std::string&)> callback);
    void set_technique_enabled(EvasionTechnique technique, bool enabled);
    std::vector<EvasionTechnique> get_active_techniques() const;

    enum class BypassPreset {
        MINIMAL,
        MODERATE,
        AGGRESSIVE,
        STEALTH
    };

    void apply_preset(BypassPreset preset);

    /**
     * @brief Set TLS fingerprint for the advanced bypass pipeline.
     *        The fingerprint is forwarded to internal TLSManipulator
     *        so that fake/real ClientHello use realistic browser profiles.
     * @param fp Pointer to TLSFingerprint (not owned, caller keeps alive).
     */
    void set_tls_fingerprint(ncp::TLSFingerprint* fp);

    /**
     * @brief Set ECH config for ClientHello encryption (Phase 3D).
     *        When enable_ech is true and this is set, process_outgoing()
     *        will apply ECH to ClientHello before splitting/obfuscation.
     * @param config_list Serialized ECHConfigList (from DNS HTTPS record or manual config).
     */
    void set_ech_config(const std::vector<uint8_t>& config_list);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class DPIEvasion {
public:
    static std::vector<uint8_t> apply_ech(
        const std::vector<uint8_t>& client_hello,
        const std::vector<uint8_t>& ech_config);

    static std::vector<uint8_t> apply_domain_fronting(
        const std::vector<uint8_t>& data,
        const std::string& front_domain,
        const std::string& real_domain);
};

namespace Presets {
    AdvancedDPIConfig create_tspu_preset();
    AdvancedDPIConfig create_gfw_preset();
    AdvancedDPIConfig create_iran_preset();
    AdvancedDPIConfig create_aggressive_preset();
    AdvancedDPIConfig create_stealth_preset();
    AdvancedDPIConfig create_compatible_preset();
}

}  // namespace DPI
} // namespace ncp

#endif  // NCP_DPI_ADVANCED_HPP
