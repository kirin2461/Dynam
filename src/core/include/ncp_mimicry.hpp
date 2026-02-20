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
 * @brief TLS session phase — tracks the state machine so that
 *        Mimicry never emits Application Data (0x17) before a
 *        complete handshake sequence (0x16) has been sent.
 *
 * Issue #57: Orchestrator was sending 0x17 without prior 0x16,
 * which is an instant DPI anomaly signal.
 */
enum class TlsSessionPhase {
    IDLE,                   // No TLS records sent yet
    CLIENT_HELLO_SENT,      // ClientHello (0x16) emitted
    HANDSHAKE_COMPLETE,     // Fake ServerHello+Finished emitted
    APPLICATION_DATA        // Ready for Application Data (0x17)
};

/**
 * @brief Advanced Traffic Mimicry with realistic protocol emulation
 * Disguises specialized traffic as common protocols with proper timing and behavior
 */
class TrafficMimicry {
public:
    /**
     * @brief Wire format version for mimicry protocols.
     *
     * Both peers MUST use the same MIMICRY_WIRE_VERSION for wrap/unwrap
     * to succeed.  Embedded in TLS ClientHello (Random[24]),
     * QUIC Initial (plaintext[0]), and BitTorrent (reserved[4]).
     *
     * Increment on ANY breaking wire-format change.
     *
     * History:
     *   v1 — legacy (XOR ClientHello, no ct_len in QUIC, payload-leak BT)
     *   v2 — AEAD-only ClientHello, QUIC ct_len field, safe BT info_hash
     */
    static constexpr uint8_t MIMICRY_WIRE_VERSION = 2;

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

    static constexpr size_t MAX_DNS_PAYLOAD = 100;
    
    TrafficMimicry();
    explicit TrafficMimicry(const MimicConfig& config);
    ~TrafficMimicry();
    
    std::vector<uint8_t> wrap_payload(
        const std::vector<uint8_t>& payload,
        MimicProfile profile
    );
    
    std::vector<uint8_t> wrap_payload(
        const std::vector<uint8_t>& payload
    );

    std::vector<uint8_t> wrap_tls_session_aware(
        const std::vector<uint8_t>& payload,
        std::vector<std::vector<uint8_t>>& handshake_preamble
    );

    std::vector<std::vector<uint8_t>> generate_tls_handshake_sequence();
    void reset_tls_session();
    TlsSessionPhase get_tls_session_phase() const;
    bool is_tls_managed() const;
    
    std::vector<uint8_t> unwrap_payload(
        const std::vector<uint8_t>& mimicked_data,
        MimicProfile profile
    );
    
    std::vector<uint8_t> unwrap_payload(
        const std::vector<uint8_t>& mimicked_data
    );
    
    void set_config(const MimicConfig& config);
    MimicConfig get_config() const;
    
    MimicStats get_stats() const;
    void reset_stats();
    
    MimicProfile detect_profile(const std::vector<uint8_t>& data);
    std::chrono::milliseconds get_next_packet_delay();

    void set_tls_session_key(const std::vector<uint8_t>& key);
    std::vector<uint8_t> get_tls_session_key() const;
    
private:
    std::vector<uint8_t> create_http_get_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_http_post_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_http_payload(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> create_https_client_hello_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_https_application_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_tls_payload(const std::vector<uint8_t>& data);

    std::vector<uint8_t> create_fake_server_hello();
    std::vector<uint8_t> create_fake_change_cipher_spec();
    std::vector<uint8_t> create_fake_finished();
    
    std::vector<uint8_t> create_dns_query_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_dns_response_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_dns_payload(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> create_quic_initial_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_quic_payload(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> create_websocket_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_websocket_payload(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> create_bittorrent_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_bittorrent_payload(const std::vector<uint8_t>& data);
    std::vector<uint8_t> create_skype_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_zoom_wrapper(const std::vector<uint8_t>& payload);
    
    std::vector<uint8_t> create_generic_tcp_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_generic_udp_wrapper(const std::vector<uint8_t>& payload);
    
    std::string generate_random_http_path();
    std::string generate_random_user_agent();
    std::string generate_random_hostname();
    uint16_t generate_random_port();
    std::vector<uint8_t> generate_random_padding(size_t min_size, size_t max_size);
    std::chrono::milliseconds calculate_realistic_delay(MimicProfile profile, size_t packet_size);
    
    MimicConfig config_;
    MimicStats stats_;
    mutable std::mutex stats_overhead_mutex_;
    std::chrono::steady_clock::time_point last_packet_time_;
    
    uint32_t tls_seq_;
    uint32_t skype_seq_;
    uint32_t zoom_seq_;
    uint16_t dns_transaction_id_;
    int      dns_last_domain_idx_;
    uint64_t quic_packet_number_;

    TlsSessionPhase tls_session_phase_ = TlsSessionPhase::IDLE;
    std::vector<uint8_t> tls_session_key_;
};

} // namespace ncp

#endif // NCP_TRAFFIC_MIMICRY_HPP
