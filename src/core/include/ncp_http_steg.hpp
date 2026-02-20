#pragma once

/**
 * @file ncp_http_steg.hpp
 * @brief HTTP Header Steganography — covert data in HTTP header order & values
 *
 * Encoding:
 *   - Permutation coding: order of N carrier headers encodes ⌊log₂(N!)⌋ bits
 *   - Value encoding: Cookie, Accept-Language, X-Request-ID, ETag carry
 *     payload bytes via lookup tables with browser-realistic values
 *
 * Reuses BrowserProfile from ncp_mimicry.hpp for realistic header fingerprints.
 * All traffic travels inside HTTPS — DPI sees only encrypted TLS.
 *
 * Capacity: ~40-80 bits (permutation) + ~128 bits (values) per request
 * No root required ✅
 */

#include "ncp_covert_channel.hpp"
#include "ncp_mimicry.hpp"

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
namespace covert {

// ===== Browser Profile for Steg =====

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
    std::string target_url;             // HTTPS endpoint for cover requests
    std::string target_host;            // Host header value
    uint16_t target_port = 443;

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
    // These headers' VALUES carry payload bytes via lookup tables.
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

    // === Crypto ===
    std::vector<uint8_t> channel_key;   // symmetric key for payload encryption
    bool encrypt_payload = true;

    // === Cover traffic ===
    bool enable_cover_requests = true;
    double cover_traffic_ratio = 0.4;   // 40% cover
    std::vector<std::string> cover_urls;// legitimate URLs to intersperse
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
 * Encodes/decodes integer values via permutation ordering.
 *
 * N items can be arranged in N! ways. Given a set of N carrier headers,
 * their ordering encodes an integer in [0, N!), which represents
 * ⌊log₂(N!)⌋ bits of data.
 *
 * For 6 headers: 6! = 720, ⌊log₂(720)⌋ = 9 bits per request.
 * For 8 headers: 8! = 40320, ⌊log₂(40320)⌋ = 15 bits per request.
 *
 * Uses Lehmer code (factoradic) for O(N²) encode/decode.
 */
class PermutationCodec {
public:
    explicit PermutationCodec(size_t n_items);

    // Max bits encodable in one permutation
    size_t capacity_bits() const;

    // Encode: integer → permutation of [0..N-1]
    std::vector<size_t> encode(uint64_t value) const;

    // Decode: permutation → integer
    uint64_t decode(const std::vector<size_t>& permutation) const;

    // Max encodable value (N! - 1)
    uint64_t max_value() const;

private:
    size_t n_;
    uint64_t factorial_;
};

// ===== Header Value Encoder =====

/**
 * Encodes payload bytes into realistic HTTP header values.
 *
 * Each carrier header has a value generator that maps data bits
 * to plausible header values using the browser profile.
 *
 * Example: X-Request-ID = UUID format, 128 bits of payload
 *   encode(0xDEADBEEF...) → "550e8400-e29b-41d4-a716-446655440000"
 *   (UUID is derived from payload, not random)
 *
 * Example: Accept-Language = language tag permutation, 24 bits
 *   encode(0x42) → "en-US,en;q=0.9,fr;q=0.8"
 *   (language order/q-values encode data)
 */
class HeaderValueEncoder {
public:
    explicit HeaderValueEncoder(StegBrowserType browser_type);

    // Encode bits into a header value
    std::string encode_value(const std::string& header_name,
                             const uint8_t* data, size_t bits);

    // Decode bits from a header value
    std::vector<uint8_t> decode_value(const std::string& header_name,
                                      const std::string& value,
                                      size_t expected_bits);

    // Get capacity for a specific header
    size_t capacity_bits(const std::string& header_name) const;

private:
    StegBrowserType browser_type_;

    // Per-header encoding strategies
    std::string encode_cookie(const uint8_t* data, size_t bits);
    std::string encode_accept_language(const uint8_t* data, size_t bits);
    std::string encode_request_id(const uint8_t* data, size_t bits);
    std::string encode_etag(const uint8_t* data, size_t bits);

    std::vector<uint8_t> decode_cookie(const std::string& value, size_t bits);
    std::vector<uint8_t> decode_accept_language(const std::string& value, size_t bits);
    std::vector<uint8_t> decode_request_id(const std::string& value, size_t bits);
    std::vector<uint8_t> decode_etag(const std::string& value, size_t bits);

    // Language tag tables per browser
    static const std::vector<std::string>& get_language_pool(StegBrowserType type);
};

// ===== HTTP Steg Request Builder =====

struct StegHTTPRequest {
    std::string method = "GET";
    std::string path = "/";
    std::vector<std::pair<std::string, std::string>> headers; // ordered!
    std::string body;                   // for POST requests

    // How many covert bits are in this request
    size_t covert_bits_permutation = 0;
    size_t covert_bits_values = 0;
};

struct StegHTTPResponse {
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    bool has_covert_data = false;
};

// ===== HTTP Header Steg Channel =====

class HTTPStegChannel : public ICovertChannel {
public:
    HTTPStegChannel();
    explicit HTTPStegChannel(const HTTPStegConfig& config);
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

    // Calculate total bits per request for current config
    size_t bits_per_request() const;

private:
    // Build a steg HTTP request encoding the given bits
    StegHTTPRequest build_steg_request(const uint8_t* data, size_t bits);

    // Extract covert bits from an HTTP response
    std::vector<uint8_t> extract_from_response(const StegHTTPResponse& response);

    // Send an HTTP request and get response
    StegHTTPResponse send_http_request(const StegHTTPRequest& request);

    // Workers
    void tx_worker_func();
    void cover_traffic_func();

    // Encryption (reuses same pattern as DNS channel)
    std::vector<uint8_t> encrypt_payload(const uint8_t* data, size_t len) const;
    std::vector<uint8_t> decrypt_payload(const uint8_t* data, size_t len) const;

    void update_stealth_score();
    std::chrono::milliseconds next_request_delay() const;

    // State
    HTTPStegConfig config_;
    std::atomic<ChannelState> state_{ChannelState::CLOSED};

    // Components
    std::unique_ptr<PermutationCodec> perm_codec_;
    std::unique_ptr<HeaderValueEncoder> value_encoder_;

    // TX queue
    struct TxItem {
        std::vector<uint8_t> payload;   // raw bits to encode
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
