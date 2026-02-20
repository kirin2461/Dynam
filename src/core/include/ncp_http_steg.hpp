#pragma once

/**
 * @file ncp_http_steg.hpp
 * @brief HTTP Header Steganography — covert data in HTTP header order & values
 *
 * ARCHITECTURE (per review):
 *   - Transport: uses INetworkBackend* → send_tcp_packet()
 *   - HTTP scaffold: uses TrafficMimicry* → create_http_get_wrapper()
 *   - Steg layer: ONLY embeds data in specific headers
 *   - NO internal encryption — Manager handles crypto centrally
 *
 * Pipeline:
 *   ICovertChannel::send(raw_bytes)
 *     → fragment into per-request chunks
 *     → embed in HTTP headers (permutation + value coding)
 *     → TrafficMimicry::create_http_get_wrapper() for realistic scaffold
 *     → INetworkBackend::send_tcp_packet() for wire transport
 *
 * Encoding:
 *   - Permutation coding: order of N carrier headers encodes ⌊log₂(N!)⌋ bits
 *   - Value encoding: Cookie, Accept-Language, X-Request-ID, If-None-Match
 *     carry payload bytes via lookup tables with browser-realistic values
 *
 * Capacity: ~40-80 bits (permutation) + ~128 bits (values) per request
 * No root required (if backend is PROXY_ONLY) ✅
 */

#include "ncp_covert_channel.hpp"

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <functional>

namespace ncp {

// Forward declarations — no include needed, channel takes pointers
class TrafficMimicry;
class INetworkBackend;

namespace covert {

// ===== Browser Profile for Steg Value Tables =====

enum class StegBrowserType {
    CHROME_WIN,
    CHROME_MAC,
    FIREFOX_WIN,
    FIREFOX_LINUX,
    SAFARI_MAC,
    EDGE_WIN
};

// ===== HTTP Header Steg Configuration =====

struct HTTPStegConfig {
    // === Target ===
    std::string target_host;            // Host header value / IP
    uint16_t target_port = 443;
    std::string target_path = "/";      // GET path

    // === Dependencies (injected, not owned) ===
    // TrafficMimicry* — for HTTP scaffold (create_http_get_wrapper etc.)
    // INetworkBackend* — for wire transport (send_tcp_packet)
    // Both set via constructor or set_transport()

    // === Browser mimicry ===
    StegBrowserType browser_type = StegBrowserType::CHROME_WIN;
    bool rotate_browser = false;        // rotate profile per session

    // === Carrier headers (permutation coding) ===
    // These headers' ORDER encodes data bits.
    // Default set chosen for maximum permutation entropy with
    // plausible reordering across browser versions.
    std::vector<std::string> permutation_headers = {
        "Accept", "Accept-Language", "Accept-Encoding",
        "Cache-Control", "Connection", "Upgrade-Insecure-Requests"
    };

    // === Value-encoding headers ===
    struct ValueCarrier {
        std::string header_name;
        size_t capacity_bits;           // max bits per header value
    };
    std::vector<ValueCarrier> value_carriers = {
        {"Cookie",           64},       // session-like cookie value
        {"Accept-Language",  24},       // language tag permutation
        {"X-Request-ID",     128},      // UUID-like, full payload
        {"If-None-Match",    64}        // ETag-like value
    };

    // === Timing ===
    double min_request_interval_ms = 200;
    double max_request_interval_ms = 5000;
    double jitter_factor = 0.3;

    // === Reliability ===
    int max_retries = 3;
    int request_timeout_ms = 10000;
    size_t tx_queue_max = 512;
    size_t rx_buffer_max = 65536;

    // === Cover traffic ===
    bool enable_cover_requests = true;
    double cover_traffic_ratio = 0.4;   // 40% cover
    std::vector<std::string> cover_paths;// legitimate paths to intersperse
};

// ===== HTTP Steg Statistics =====

struct HTTPStegStats {
    uint64_t requests_sent = 0;
    uint64_t responses_received = 0;
    uint64_t cover_requests_sent = 0;
    uint64_t payload_bits_sent = 0;
    uint64_t payload_bits_received = 0;
    uint64_t permutation_bits = 0;      // bits encoded via header order
    uint64_t value_bits = 0;            // bits encoded via header values
    uint64_t errors = 0;
    double avg_request_latency_ms = 0.0;
    double stealth_score = 0.0;
};

// ===== Permutation Codec =====

/**
 * Encodes/decodes integer values via permutation ordering (Lehmer code).
 *
 * N items → N! arrangements → ⌊log₂(N!)⌋ bits per request.
 * 6 headers: 720 perms → 9 bits.  8 headers: 40320 → 15 bits.
 */
class PermutationCodec {
public:
    explicit PermutationCodec(size_t n_items);

    size_t capacity_bits() const;
    std::vector<size_t> encode(uint64_t value) const;
    uint64_t decode(const std::vector<size_t>& permutation) const;
    uint64_t max_value() const;

private:
    size_t n_;
    uint64_t factorial_;
};

// ===== Header Value Encoder =====

/**
 * Maps payload bytes ↔ realistic HTTP header values.
 *
 * X-Request-ID: UUID v4 format → 128 bits (version/variant bits masked)
 * Cookie:       _ga=GA1.2.<hex> → 64 bits
 * Accept-Language: lang order + q-values → 24 bits
 * If-None-Match:   W/"<hex>" → 64 bits
 */
class HeaderValueEncoder {
public:
    explicit HeaderValueEncoder(StegBrowserType browser_type);

    std::string encode_value(const std::string& header_name,
                             const uint8_t* data, size_t bits);
    std::vector<uint8_t> decode_value(const std::string& header_name,
                                      const std::string& value,
                                      size_t expected_bits);
    size_t capacity_bits(const std::string& header_name) const;

private:
    StegBrowserType browser_type_;

    std::string encode_cookie(const uint8_t* data, size_t bits);
    std::string encode_accept_language(const uint8_t* data, size_t bits);
    std::string encode_request_id(const uint8_t* data, size_t bits);
    std::string encode_etag(const uint8_t* data, size_t bits);

    std::vector<uint8_t> decode_cookie(const std::string& value, size_t bits);
    std::vector<uint8_t> decode_accept_language(const std::string& value, size_t bits);
    std::vector<uint8_t> decode_request_id(const std::string& value, size_t bits);
    std::vector<uint8_t> decode_etag(const std::string& value, size_t bits);

    static const std::vector<std::string>& get_language_pool(StegBrowserType type);
};

// ===== Steg HTTP Request (internal) =====

struct StegHTTPRequest {
    std::string method = "GET";
    std::string path = "/";
    std::vector<std::pair<std::string, std::string>> headers; // ordered!
    size_t covert_bits_permutation = 0;
    size_t covert_bits_values = 0;
};

// ===== HTTP Header Steg Channel =====

class HTTPStegChannel : public ICovertChannel {
public:
    /**
     * @param backend  Network transport (send_tcp_packet). NOT owned.
     * @param mimicry  HTTP scaffold generator. NOT owned.
     * @param config   Channel configuration.
     */
    HTTPStegChannel(ncp::INetworkBackend* backend,
                    ncp::TrafficMimicry* mimicry,
                    const HTTPStegConfig& config = {});
    ~HTTPStegChannel() override;

    HTTPStegChannel(const HTTPStegChannel&) = delete;
    HTTPStegChannel& operator=(const HTTPStegChannel&) = delete;

    // === ICovertChannel interface ===
    bool open() override;
    void close() override;
    bool is_open() const override;
    ChannelState state() const override;

    size_t send(const uint8_t* data, size_t len) override;
    size_t receive(uint8_t* buf, size_t max_len) override;

    ChannelStats get_stats() const override;
    std::string channel_type() const override { return "http_header_steg"; }
    double max_capacity_bps() const override;

    void set_detection_callback(DetectionCallback cb) override;
    void on_detection(const CovertDetectionEvent& event) override;

    // === HTTP Steg specific ===
    bool set_config(const HTTPStegConfig& config);
    HTTPStegConfig get_config() const;
    HTTPStegStats get_steg_stats() const;
    size_t bits_per_request() const;

private:
    // Build steg headers for one chunk → returns ordered header pairs
    std::vector<std::pair<std::string, std::string>>
        build_steg_headers(const uint8_t* data, size_t bits,
                           size_t& out_perm_bits, size_t& out_val_bits);

    // Full pipeline: steg headers → mimicry wrap → backend send
    bool send_steg_request(const uint8_t* data, size_t bits);
    void send_cover_request();

    // Workers
    void tx_worker_func();
    void cover_traffic_func();

    void update_stealth_score();
    std::chrono::milliseconds next_request_delay() const;

    // Dependencies (not owned)
    ncp::INetworkBackend* backend_;
    ncp::TrafficMimicry* mimicry_;

    // Config & State
    HTTPStegConfig config_;
    std::atomic<ChannelState> state_{ChannelState::CLOSED};

    // Components
    std::unique_ptr<PermutationCodec> perm_codec_;
    std::unique_ptr<HeaderValueEncoder> value_encoder_;

    // TX queue
    struct TxItem {
        std::vector<uint8_t> payload;
        size_t bit_count = 0;
    };
    std::queue<TxItem> tx_queue_;
    mutable std::mutex tx_mutex_;
    std::condition_variable tx_cv_;

    // RX buffer
    std::vector<uint8_t> rx_buffer_;
    mutable std::mutex rx_mutex_;
    std::condition_variable rx_cv_;

    // Workers
    std::thread tx_thread_;
    std::thread cover_thread_;
    std::atomic<bool> running_{false};

    // Stats — lock order: tx_mutex_ → stats_mutex_ (never reverse)
    mutable std::mutex stats_mutex_;
    HTTPStegStats steg_stats_;
    ChannelStats base_stats_;
    uint64_t stealth_update_counter_ = 0;

    // Detection
    DetectionCallback detection_cb_;
    std::mutex detection_mutex_;
};

} // namespace covert
} // namespace ncp
