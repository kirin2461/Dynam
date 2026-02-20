#pragma once

/**
 * @file ncp_dns_covert.hpp
 * @brief DNS Covert Channel — steganographic data transport via DNS queries/responses
 *
 * Encodes covert data in:
 *   - Upstream:   subdomain labels (base32-encoded chunks as <data>.zone.example.com)
 *   - Downstream: TXT records (base64 payload), CNAME chains (label encoding),
 *                 A/AAAA records (IP-encoded data)
 *
 * Integrates with existing NCP infrastructure:
 *   - ncp_doh.hpp:        DoHClient for encrypted upstream queries
 *   - ncp_ech.hpp:        ECH hides destination server from DPI
 *   - ncp_flow_shaper.hpp: jitter injection + mimicry of normal DNS patterns
 *   - ncp_doh.hpp:        SecureDNSCache for covert response caching
 *
 * Capacity: ~15-50 Kbps depending on query rate, MTU, and encoding.
 * Stealth:  DNS queries travel via DoH/DoH3 (encrypted), ECH hides SNI.
 *           Flow shaper adds jitter matching real browser DNS behavior.
 *
 * Does NOT require root — operates at application layer over DoH.
 */

#include "ncp_covert_channel.hpp"
#include "ncp_doh.hpp"
#include "ncp_flow_shaper.hpp"

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <functional>
#include <chrono>

namespace ncp {
namespace covert {

// ===== DNS Encoding Schemes =====

enum class DNSEncodingScheme {
    BASE32_SUBDOMAIN,      // <base32_chunk>.data.zone -> upstream via subdomain labels
    BASE64_TXT,            // TXT record responses carry base64 payload (downstream)
    CNAME_CHAIN,           // CNAME chain labels encode data bytes
    IP_ENCODING_A,         // A record: 4 bytes per record in IPv4 address
    IP_ENCODING_AAAA,      // AAAA record: 16 bytes per record in IPv6 address
    HYBRID                 // auto-select best per direction
};

// ===== DNS Covert Channel Configuration =====

struct DNSCovertConfig {
    // === Zone & Server ===
    std::string authoritative_zone;     // e.g. "data.yourdomain.com"
    std::string authoritative_ns;       // NS IP for direct queries (optional)
    uint16_t authoritative_port = 53;

    // === Encoding ===
    DNSEncodingScheme upstream_encoding = DNSEncodingScheme::BASE32_SUBDOMAIN;
    DNSEncodingScheme downstream_encoding = DNSEncodingScheme::BASE64_TXT;
    size_t max_label_length = 63;       // DNS label limit
    size_t max_subdomain_labels = 4;    // max encoded labels per query
    size_t max_query_name_length = 253; // RFC 1035 limit

    // === Transport (reuses DoH) ===
    DoHClient::Config doh_config;       // DoH transport configuration
    bool use_doh3 = false;              // prefer DoH3 (QUIC) when available
    bool use_ech = true;                // encrypt SNI via ECH

    // === Flow Shaping (stealth) ===
    bool enable_flow_shaping = true;
    double min_query_interval_ms = 50;   // minimum inter-query delay
    double max_query_interval_ms = 2000; // maximum inter-query delay
    double jitter_factor = 0.3;          // +/-30% timing jitter
    bool mimic_browser_dns = true;       // match real browser DNS patterns

    // === Reliability ===
    int max_retries = 3;
    int retry_backoff_ms = 500;
    int query_timeout_ms = 5000;
    size_t tx_queue_max = 1024;          // max pending outbound chunks
    size_t rx_buffer_max = 65536;        // max reassembly buffer

    // === Crypto ===
    std::vector<uint8_t> channel_key;    // symmetric key for payload encryption
    bool encrypt_payload = true;         // encrypt before encoding
    bool enable_padding = true;          // pad to fixed chunk sizes

    // === Detection Evasion ===
    bool randomize_case = true;          // DNS 0x20 bit encoding
    bool mix_legitimate_queries = true;  // interleave with real DNS lookups
    std::vector<std::string> cover_domains; // legitimate domains for cover traffic
    double cover_traffic_ratio = 0.3;    // 30% cover queries
};

// ===== DNS Covert Channel Statistics =====

struct DNSCovertStats {
    uint64_t queries_sent = 0;
    uint64_t queries_received = 0;
    uint64_t cover_queries_sent = 0;
    uint64_t payload_bytes_upstream = 0;
    uint64_t payload_bytes_downstream = 0;
    uint64_t encoding_overhead_bytes = 0;
    uint64_t retries = 0;
    uint64_t timeouts = 0;
    uint64_t decode_errors = 0;
    double avg_query_latency_ms = 0.0;
    double current_throughput_bps = 0.0;
    double stealth_score = 0.0;          // 0.0 - 1.0
};

// ===== DNS Chunk Protocol =====

/**
 * Wire format for a single covert DNS chunk:
 *
 *   [1B flags][2B seq_num][2B total_chunks][2B payload_len][NB payload][4B crc32]
 *
 * Flags:
 *   bit 0: is_last_chunk
 *   bit 1: is_encrypted
 *   bit 2: is_compressed
 *   bit 3: requires_ack
 *   bits 4-7: reserved
 */
struct DNSChunkHeader {
    uint8_t flags = 0;
    uint16_t sequence_number = 0;
    uint16_t total_chunks = 0;
    uint16_t payload_length = 0;

    static constexpr uint8_t FLAG_LAST_CHUNK  = 0x01;
    static constexpr uint8_t FLAG_ENCRYPTED   = 0x02;
    static constexpr uint8_t FLAG_COMPRESSED  = 0x04;
    static constexpr uint8_t FLAG_REQUIRES_ACK = 0x08;

    static constexpr size_t HEADER_SIZE = 7;  // 1+2+2+2
    static constexpr size_t CRC_SIZE = 4;
    static constexpr size_t OVERHEAD = HEADER_SIZE + CRC_SIZE; // 11 bytes

    std::vector<uint8_t> serialize() const;
    static DNSChunkHeader deserialize(const uint8_t* data, size_t len);
    bool is_last() const { return flags & FLAG_LAST_CHUNK; }
    bool is_encrypted() const { return flags & FLAG_ENCRYPTED; }
};

// ===== Subdomain Encoder =====

/**
 * Encodes raw binary data into DNS-safe subdomain labels.
 *
 * IMPORTANT: This is a PURE encoder — it does NOT add chunk headers or CRC.
 * Framing (header + CRC) is done exclusively in DNSCovertChannel::send_chunk().
 *
 * encode_upstream_raw():  raw bytes → base32hex labels → FQDN query names
 * decode_upstream_raw():  FQDN query name → strip zone/seq → base32hex decode → raw bytes
 *
 * Example: encode_upstream_raw({0xDE, 0xAD}) → ["36wq.s0000.data.yourdomain.com"]
 */
class SubdomainEncoder {
public:
    explicit SubdomainEncoder(const DNSCovertConfig& config);

    // Pure encoding: raw bytes → DNS query names (NO framing added)
    std::vector<std::string> encode_upstream_raw(
        const uint8_t* data, size_t len, uint16_t sequence_base);

    // Pure decoding: DNS query name → raw bytes (NO framing stripped)
    std::vector<uint8_t> decode_upstream_raw(const std::string& query_name);

    // Encode payload into DNS response records (TXT/CNAME/A/AAAA)
    std::vector<std::vector<uint8_t>> encode_downstream(
        const uint8_t* data, size_t len, DNSEncodingScheme scheme);

    // Decode DNS response records back to payload
    std::vector<uint8_t> decode_downstream(
        const std::vector<std::string>& records, DNSEncodingScheme scheme);

    // Capacity: max raw bytes that fit in one DNS query name
    size_t max_payload_per_query() const;
    size_t max_payload_per_response(DNSEncodingScheme scheme) const;

private:
    DNSCovertConfig config_;

    std::string base32hex_encode(const uint8_t* data, size_t len) const;
    std::vector<uint8_t> base32hex_decode(const std::string& encoded) const;
    std::string base64url_encode(const uint8_t* data, size_t len) const;
    std::vector<uint8_t> base64url_decode(const std::string& encoded) const;

    std::vector<std::string> split_into_labels(const std::string& data) const;
    std::string randomize_case(const std::string& name) const;
};

// ===== Reassembly Buffer =====

class ChunkReassembler {
public:
    explicit ChunkReassembler(size_t max_buffer_size = 65536);

    // Add a received chunk. Returns false on error (OOM cap, bad seq, etc.)
    bool add_chunk(const DNSChunkHeader& header, const uint8_t* payload, size_t len);

    bool is_complete() const;
    std::vector<uint8_t> extract();
    void reset();

    size_t chunks_received() const;
    size_t chunks_expected() const;
    size_t bytes_buffered() const;

    // Max total_chunks we accept from wire (OOM protection)
    static constexpr uint16_t MAX_TOTAL_CHUNKS = 1024;

private:
    struct ChunkSlot {
        bool received = false;
        std::vector<uint8_t> data;
    };
    std::vector<ChunkSlot> slots_;
    size_t max_buffer_;
    size_t received_count_ = 0;
    uint16_t total_expected_ = 0;
    bool header_seen_ = false;
};

// ===== DNS Covert Channel =====

class DNSCovertChannel : public ICovertChannel {
public:
    DNSCovertChannel();
    explicit DNSCovertChannel(const DNSCovertConfig& config);
    ~DNSCovertChannel() override;

    DNSCovertChannel(const DNSCovertChannel&) = delete;
    DNSCovertChannel& operator=(const DNSCovertChannel&) = delete;

    // === ICovertChannel interface ===
    bool open() override;
    void close() override;
    bool is_open() const override;
    ChannelState state() const override;

    size_t send(const uint8_t* data, size_t len) override;
    size_t receive(uint8_t* buf, size_t max_len) override;

    ChannelStats get_stats() const override;
    std::string channel_type() const override { return "dns_covert"; }
    double max_capacity_bps() const override;

    void set_detection_callback(DetectionCallback cb) override;
    void on_detection(const CovertDetectionEvent& event) override;

    // === DNS-specific API ===

    // Reconfigure channel. MUST be CLOSED — returns false if open.
    bool set_config(const DNSCovertConfig& config);
    DNSCovertConfig get_config() const;
    DNSCovertStats get_dns_stats() const;

    void send_cover_query();

    void set_server_mode(bool enabled);
    bool is_server_mode() const;

    uint16_t session_id() const;
    void rotate_session();

private:
    void tx_worker_func();
    void rx_worker_func();
    void cover_traffic_func();

    // THE SINGLE framing point: [hdr][payload][crc32] → encode → DNS queries
    bool send_chunk(const DNSChunkHeader& header, const uint8_t* payload, size_t len);

    bool process_response(const DoHClient::DNSResult& result);

    std::vector<uint8_t> encrypt_payload(const uint8_t* data, size_t len) const;
    std::vector<uint8_t> decrypt_payload(const uint8_t* data, size_t len) const;

    void update_stealth_score();
    double calculate_query_entropy() const;
    std::chrono::milliseconds next_query_delay() const;

    // Config & state
    DNSCovertConfig config_;
    std::atomic<ChannelState> state_{ChannelState::CLOSED};
    uint16_t session_id_ = 0;
    bool server_mode_ = false;

    // Components
    std::unique_ptr<DoHClient> doh_client_;
    std::unique_ptr<SubdomainEncoder> encoder_;
    std::unique_ptr<ChunkReassembler> reassembler_;

    // TX queue
    struct TxItem {
        DNSChunkHeader header;
        std::vector<uint8_t> payload;  // raw payload, NO framing
    };
    std::queue<TxItem> tx_queue_;
    mutable std::mutex tx_mutex_;
    std::condition_variable tx_cv_;

    // RX buffer
    std::vector<uint8_t> rx_buffer_;
    mutable std::mutex rx_mutex_;
    std::condition_variable rx_cv_;

    // Worker threads
    std::thread tx_thread_;
    std::thread rx_thread_;
    std::thread cover_thread_;
    std::atomic<bool> running_{false};

    // Stats — LOCK ORDER: tx_mutex_ first, then stats_mutex_ (never reverse)
    mutable std::mutex stats_mutex_;
    DNSCovertStats dns_stats_;
    ChannelStats base_stats_;
    uint64_t stealth_update_counter_ = 0; // update_stealth_score every N queries

    // Detection
    DetectionCallback detection_cb_;
    std::mutex detection_mutex_;

    // Timing
    std::chrono::steady_clock::time_point last_query_time_;
    std::vector<double> recent_intervals_;
};

} // namespace covert
} // namespace ncp
