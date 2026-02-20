#ifndef NCP_TRAFFIC_MIMICRY_HPP
#define NCP_TRAFFIC_MIMICRY_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <chrono>
#include <map>
#include <functional>
#include <atomic>
#include <mutex>
#include "ncp_csprng.hpp"

namespace ncp {

/**
 * @brief Advanced Traffic Mimicry with realistic protocol emulation
 * Disguises specialized traffic as common protocols with proper timing and behavior
 */
class TrafficMimicry {
public:
    enum class MimicProfile {
        HTTP_GET,            // HTTP/1.1 GET request
        HTTP_POST,           // HTTP/1.1 POST request
        HTTPS_CLIENT_HELLO,  // TLS ClientHello
        HTTPS_APPLICATION,   // TLS Application Data
        DNS_QUERY,           // DNS Query
        DNS_RESPONSE,        // DNS Response
        QUIC_INITIAL,        // QUIC Initial packet
        WEBSOCKET,           // WebSocket frame
        BITTORRENT,          // BitTorrent protocol
        SKYPE,               // Skype-like traffic
        ZOOM,                // Zoom-like video conference
        GENERIC_TCP,         // Generic TCP stream
        GENERIC_UDP          // Generic UDP datagram
    };
    
    struct MimicConfig {
        MimicProfile profile = MimicProfile::HTTPS_APPLICATION;
        bool enable_timing_mimicry = true;   // Mimic real protocol timing
        bool enable_size_mimicry = true;     // Mimic real packet sizes
        bool enable_pattern_mimicry = true;  // Mimic protocol patterns
        bool randomize_fields = true;        // Randomize non-critical fields
        
        // Timing parameters (milliseconds)
        int min_inter_packet_delay = 10;
        int max_inter_packet_delay = 500;
        
        // Size parameters
        int min_padding = 0;
        int max_padding = 512;
        
        // Protocol-specific options
        std::string http_user_agent;         // Custom User-Agent
        std::string http_host;               // Custom Host header
        std::vector<std::string> http_headers;  // Additional headers
        std::string tls_sni;                 // SNI for TLS
        std::vector<uint16_t> tls_cipher_suites;  // TLS cipher suites
    };
    
    struct MimicStats {
        std::atomic<uint64_t> packets_wrapped{0};
        std::atomic<uint64_t> packets_unwrapped{0};
        std::atomic<uint64_t> bytes_original{0};
        std::atomic<uint64_t> bytes_mimicked{0};
        // average_overhead_percent requires mutex (non-atomic double)
        double average_overhead_percent = 0.0;

        MimicStats() = default;
        MimicStats(const MimicStats& o)
            : packets_wrapped(o.packets_wrapped.load()),
              packets_unwrapped(o.packets_unwrapped.load()),
              bytes_original(o.bytes_original.load()),
              bytes_mimicked(o.bytes_mimicked.load()),
              average_overhead_percent(o.average_overhead_percent) {}
        MimicStats& operator=(const MimicStats& o) {
            if (this != &o) {
                packets_wrapped.store(o.packets_wrapped.load());
                packets_unwrapped.store(o.packets_unwrapped.load());
                bytes_original.store(o.bytes_original.load());
                bytes_mimicked.store(o.bytes_mimicked.load());
                average_overhead_percent = o.average_overhead_percent;
            }
            return *this;
        }
    };

    // Maximum payload size for DNS tunnel (fits in valid DNS QNAME)
    static constexpr size_t MAX_DNS_PAYLOAD = 100;
    
    TrafficMimicry();
    explicit TrafficMimicry(const MimicConfig& config);
    ~TrafficMimicry();
    
    // Transform data to look like a specific protocol
    std::vector<uint8_t> wrap_payload(
        const std::vector<uint8_t>& payload,
        MimicProfile profile
    );
    
    std::vector<uint8_t> wrap_payload(
        const std::vector<uint8_t>& payload
    );
    
    // Extract original data from a mimicked packet
    std::vector<uint8_t> unwrap_payload(
        const std::vector<uint8_t>& mimicked_data,
        MimicProfile profile
    );
    
    std::vector<uint8_t> unwrap_payload(
        const std::vector<uint8_t>& mimicked_data
    );
    
    // Configuration
    void set_config(const MimicConfig& config);
    MimicConfig get_config() const;
    
    // Statistics
    MimicStats get_stats() const;
    void reset_stats();
    
    // Protocol detection (for unwrapping)
    MimicProfile detect_profile(const std::vector<uint8_t>& data);
    
    // Timing simulation
    std::chrono::milliseconds get_next_packet_delay();

    /// Set the symmetric key used for TLS ClientHello AEAD encryption.
    /// Both sides of the tunnel must share the same key for wrap/unwrap to work.
    /// Key must be exactly crypto_aead_xchacha20poly1305_ietf_KEYBYTES (32) bytes.
    void set_tls_session_key(const std::vector<uint8_t>& key);

    /// Get the current TLS session key (e.g. to transmit to the peer during handshake).
    std::vector<uint8_t> get_tls_session_key() const;
    
private:
    // HTTP mimicry
    std::vector<uint8_t> create_http_get_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_http_post_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_http_payload(const std::vector<uint8_t>& data);
    
    // HTTPS/TLS mimicry
    std::vector<uint8_t> create_https_client_hello_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_https_application_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_tls_payload(const std::vector<uint8_t>& data);
    
    // DNS mimicry
    std::vector<uint8_t> create_dns_query_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_dns_response_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_dns_payload(const std::vector<uint8_t>& data);
    
    // QUIC mimicry
    std::vector<uint8_t> create_quic_initial_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_quic_payload(const std::vector<uint8_t>& data);
    
    // WebSocket mimicry
    std::vector<uint8_t> create_websocket_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_websocket_payload(const std::vector<uint8_t>& data);
    
    // Application-specific mimicry
    std::vector<uint8_t> create_bittorrent_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_skype_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_zoom_wrapper(const std::vector<uint8_t>& payload);
    
    // Generic wrappers
    std::vector<uint8_t> create_generic_tcp_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_generic_udp_wrapper(const std::vector<uint8_t>& payload);
    
    // Utilities
    std::string generate_random_http_path();
    std::string generate_random_user_agent();
    std::string generate_random_hostname();
    uint16_t generate_random_port();
    std::vector<uint8_t> generate_random_padding(size_t min_size, size_t max_size);
    
    // Timing utilities
    std::chrono::milliseconds calculate_realistic_delay(MimicProfile profile, size_t packet_size);
    
    MimicConfig config_;
    MimicStats stats_;
    mutable std::mutex stats_overhead_mutex_;  // Protects average_overhead_percent
    std::chrono::steady_clock::time_point last_packet_time_;
    
    // Protocol-specific state — separate counters per protocol
    uint32_t tls_seq_;
    uint32_t skype_seq_;
    uint32_t zoom_seq_;
    uint16_t dns_transaction_id_;
    int      dns_last_domain_idx_;  // Track query domain for response matching
    uint64_t quic_packet_number_;

    /// Symmetric key for XChaCha20-Poly1305 encryption in TLS ClientHello wrapper.
    /// Generated randomly in constructor; must be shared with peer for unwrap.
    std::vector<uint8_t> tls_session_key_;
};

} // namespace ncp

#endif // NCP_TRAFFIC_MIMICRY_HPP
