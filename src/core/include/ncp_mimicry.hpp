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
#include <array>
#include "ncp_csprng.hpp"

namespace ncp {

/**
 * @brief TLS session phase - tracks the state machine so that
 *        Mimicry never emits Application Data (0x17) before a
 *        complete handshake sequence (0x16) has been sent.
 *
 * Issue #57: Orchestrator was sending 0x17 without prior 0x16,
 * which is an instant DPI anomaly signal.
 */
enum class TlsSessionPhase {
    IDLE,               // No TLS records sent yet
    CLIENT_HELLO_SENT,  // ClientHello (0x16) emitted
    HANDSHAKE_COMPLETE, // Fake ServerHello+Finished emitted
    APPLICATION_DATA    // Ready for Application Data (0x17)
};

/**
 * @brief Advanced Traffic Mimicry with realistic protocol emulation
 * Disguises specialized traffic as common protocols with proper timing and behavior
 */
class TrafficMimicry {
public:
    enum class MimicProfile {
        HTTP_GET,           // HTTP/1.1 GET request
        HTTP_POST,          // HTTP/1.1 POST request
        HTTPS_CLIENT_HELLO, // TLS ClientHello
        HTTPS_APPLICATION,  // TLS Application Data
        DNS_QUERY,          // DNS Query
        DNS_RESPONSE,       // DNS Response
        QUIC_INITIAL,       // QUIC Initial packet
        WEBSOCKET,          // WebSocket frame
        BITTORRENT,         // BitTorrent protocol
        SKYPE,              // Skype-like traffic
        ZOOM,               // Zoom-like video conference
        GENERIC_TCP,        // Generic TCP stream
        GENERIC_UDP,        // Generic UDP datagram
        // --- Transition protocol v2 stateful masks (appended; existing
        // numeric values are frozen). Session-bound: these masks are
        // keyed by MimicConfig::session_mask_key and fail closed on
        // unwrap for the wrong session / key / DCID. ---
        QUIC_SHORT_HEADER,  // QUIC 1-RTT-like short header, session-stable DCID
        STUN_MESSAGE        // RFC 5389-shaped Binding msg + MESSAGE-INTEGRITY
    };

    struct MimicConfig {
        MimicProfile profile = MimicProfile::HTTPS_APPLICATION;
        bool enable_timing_mimicry = true;   // Mimic real protocol timing
        bool enable_size_mimicry   = true;   // Mimic real packet sizes
        bool enable_pattern_mimicry = true;  // Mimic protocol patterns
        bool randomize_fields = true;        // Randomize non-critical fields

        // Timing parameters (milliseconds)
        int min_inter_packet_delay = 10;
        int max_inter_packet_delay = 500;

        // Size parameters
        int min_padding = 0;
        int max_padding = 512;

        // Protocol-specific options
        std::string http_user_agent;                // Custom User-Agent
        std::string http_host;                      // Custom Host header
        std::vector<std::string> http_headers;      // Additional headers
        std::string tls_sni;                        // SNI for TLS
        std::vector<uint16_t> tls_cipher_suites;    // TLS cipher suites

        // R9-H06: Configurable regional whitelist (override hardcoded Russian domains)
        std::vector<std::string> regional_whitelist_hosts;  // Custom whitelist hosts
        std::vector<std::string> regional_whitelist_paths;  // Custom whitelist paths
        bool use_regional_whitelist = false;                // Enable custom whitelist

        /**
         * @brief Wire format version.
         * 0 = generate random value (1-255) at object construction.
         * Non-zero = use exactly this value.
         * Both peers must agree on the same value.
         * History:
         *   v1 - legacy (XOR ClientHello, no ct_len in QUIC, payload-leak BT)
         *   v2 - AEAD-only ClientHello, QUIC ct_len field, safe BT info_hash
         *   v3 - XChaCha20-Poly1305 for Application Data, atomic state
         */
        uint8_t wire_version = 0;

        /**
         * @brief TLS session key rotation threshold (packets).
         * 0 = disabled (key never rotated automatically).
         * After this many wrap calls the key is regenerated.
         */
        uint64_t tls_key_rotation_packets = 0;

        /**
         * @brief Minimum QUIC Initial packet size in bytes.
         * Default 1200 (RFC 9000 minimum). Can be reduced to save bandwidth.
         */
        uint16_t quic_min_packet_size = 1200;

        /**
         * @brief Per-session mask binding key (transition protocol v2).
         *
         * All-zero = legacy/unbound behavior (the v2 stateful masks then
         * operate with a zero key — deterministic, but NOT authenticated
         * per session). The session adapter derives this once per
         * established E2E session
         * (HKDF(shared secret, "ncp-mimicry-session/mask-v1")) so both
         * endpoints hold identical key material. Only the stateful v2 masks
         * (QUIC_SHORT_HEADER, STUN_MESSAGE) consume it: QUIC_SHORT_HEADER
         * derives its session-stable DCID and per-packet AEAD key from it
         * and rejects datagrams carrying a foreign DCID; STUN_MESSAGE
         * derives its transaction ids and MESSAGE-INTEGRITY HMAC from it
         * and rejects forgery/tampering at the mask layer. Generic and all
         * pre-existing masks ignore this field completely (wire-identical).
         *
         * WARNING (standalone use): with an all-zero session_mask_key the
         * QUIC_SHORT_HEADER DCID and the STUN transaction-id stream are
         * CONSTANT across all standalone instances — a deployment-wide
         * fingerprint any observer can match on. Use these masks through
         * the session adapter (which installs a per-session key derived
         * from the E2E shared secret) or provision a unique key per
         * session yourself.
         */
        std::array<uint8_t, 32> session_mask_key{};

        /**
         * @brief Endpoint role byte mixed into the STUN_MESSAGE
         * transaction-id stream (transition protocol v2).
         *
         * 0 = unspecified (standalone use): the transaction id keeps the
         * legacy form HMAC-SHA256(session_mask_key, counter), so pre-role
         * streams are byte-identical. 1 = client, 2 = server: the stream
         * becomes HMAC-SHA256(session_mask_key, role || counter), making
         * the two endpoints' transaction-id sequences direction-distinct
         * instead of identical. The session adapter sets this from its
         * Role; the value never affects unwrap (transaction ids are not
         * authenticated — MESSAGE-INTEGRITY is).
         */
        uint8_t endpoint_role = 0;
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
    ~TrafficMimicry() noexcept;

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

    /**
     * @brief Rotate the TLS session key immediately.
     * Generates a new random 32-byte key and securely wipes the old one.
     * Resets the packet counter for automatic rotation.
     */
    void rotate_tls_session_key();

private:
    std::vector<uint8_t> create_http_get_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_http_post_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_http_payload(const std::vector<uint8_t>& data);

    std::vector<uint8_t> create_https_client_hello_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> create_fragmented_tls_records(const std::vector<uint8_t>& payload, const std::string& sni);
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

    // --- Transition protocol v2 stateful masks (session-bound) ---
    std::vector<uint8_t> create_quic_short_header_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_quic_short_header_payload(const std::vector<uint8_t>& data);
    std::vector<uint8_t> create_stun_message_wrapper(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> extract_stun_message_payload(const std::vector<uint8_t>& data);

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
    uint16_t    generate_random_port();
    std::vector<uint8_t> generate_random_padding(size_t min_size, size_t max_size);
    std::chrono::milliseconds calculate_realistic_delay(const MimicConfig& cfg, TrafficMimicry::MimicProfile profile, size_t packet_size);

    MimicConfig config_;
    mutable std::mutex config_mutex_;  // guards config_ (R6-11/R6-07 snapshots)
    MimicStats  stats_;
    mutable std::mutex stats_overhead_mutex_;
    // R6-13: Use atomic for thread-safe last_packet_time access
    std::atomic<uint64_t> last_packet_time_epoch_{0};  // nanoseconds since epoch

    // ---- Thread-safe state counters (Task #2: atomics) ----
    std::atomic<uint64_t> tls_seq_{0};
    std::atomic<uint32_t> skype_seq_{0};
    std::atomic<uint32_t> zoom_seq_{0};
    std::atomic<uint16_t> dns_transaction_id_{0};
    std::atomic<int>      dns_last_domain_idx_{0};
    std::atomic<uint64_t> quic_packet_number_{0};
    // STUN_MESSAGE transaction counter (v2 mask): drives the request/response
    // type alternation and the per-message transaction id derivation.
    std::atomic<uint64_t> stun_counter_{0};
    // TlsSessionPhase stored as int for std::atomic compatibility
    std::atomic<int>      tls_session_phase_{static_cast<int>(TlsSessionPhase::IDLE)};

    // ---- TLS session key (Task #1, #3) ----
    std::vector<uint8_t>  tls_session_key_;
    mutable std::mutex    tls_key_mutex_;

    /// Counts wrap calls since last key rotation (Task #3)
    std::atomic<uint64_t> tls_packets_since_key_rotation_{0};

    // ---- Wire version (Task #4) ----
    /// Effective wire version byte used in all protocol fields.
    /// Derived from config_.wire_version at construction:
    ///   0  -> random byte 1-255
    ///   N  -> exactly N
    uint8_t wire_version_ = 2;
};

} // namespace ncp

#endif // NCP_TRAFFIC_MIMICRY_HPP
