/**
 * @file ncp_http_steg.cpp
 * @brief HTTP Header Steganography — implementation
 *
 * Follows patterns from DNS covert channel (review-hardened):
 *   - randombytes_uniform() for unbiased selection
 *   - /4294967296.0 for [0,1) range
 *   - Consistent lock order: tx_mutex_ → stats_mutex_
 *   - set_config() requires CLOSED state
 */

#include "include/ncp_covert_channel.hpp"
#include "include/ncp_http_steg.hpp"
#include "include/ncp_logger.hpp"

#include <sodium.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <sstream>

namespace ncp {
namespace covert {

// ==================== PermutationCodec ====================

static uint64_t factorial(size_t n) {
    uint64_t result = 1;
    for (size_t i = 2; i <= n && result < UINT64_MAX / (i + 1); ++i) {
        result *= i;
    }
    return result;
}

PermutationCodec::PermutationCodec(size_t n_items)
    : n_(n_items), factorial_(factorial(n_items)) {}

size_t PermutationCodec::capacity_bits() const {
    if (factorial_ <= 1) return 0;
    return static_cast<size_t>(std::floor(std::log2(static_cast<double>(factorial_))));
}

uint64_t PermutationCodec::max_value() const {
    return factorial_ - 1;
}

// Encode integer → permutation using Lehmer code (factoradic number system)
std::vector<size_t> PermutationCodec::encode(uint64_t value) const {
    value = value % factorial_; // clamp to valid range

    std::vector<size_t> available(n_);
    std::iota(available.begin(), available.end(), 0);

    std::vector<size_t> permutation;
    permutation.reserve(n_);

    uint64_t remaining = value;
    for (size_t i = n_; i > 0; --i) {
        uint64_t fact_i_minus_1 = factorial(i - 1);
        size_t index = 0;
        if (fact_i_minus_1 > 0) {
            index = static_cast<size_t>(remaining / fact_i_minus_1);
            remaining = remaining % fact_i_minus_1;
        }
        if (index >= available.size()) index = available.size() - 1;

        permutation.push_back(available[index]);
        available.erase(available.begin() + index);
    }

    return permutation;
}

// Decode permutation → integer using Lehmer code
uint64_t PermutationCodec::decode(const std::vector<size_t>& permutation) const {
    if (permutation.size() != n_) return 0;

    std::vector<size_t> available(n_);
    std::iota(available.begin(), available.end(), 0);

    uint64_t value = 0;
    for (size_t i = 0; i < n_; ++i) {
        // Find position of permutation[i] in available
        auto it = std::find(available.begin(), available.end(), permutation[i]);
        if (it == available.end()) return 0; // invalid permutation

        size_t index = static_cast<size_t>(std::distance(available.begin(), it));
        value += index * factorial(n_ - 1 - i);
        available.erase(it);
    }

    return value;
}

// ==================== HeaderValueEncoder ====================

HeaderValueEncoder::HeaderValueEncoder(StegBrowserType browser_type)
    : browser_type_(browser_type) {}

// Language pools per browser type (realistic distribution)
static const std::vector<std::string> CHROME_LANGUAGES = {
    "en-US", "en", "en-GB", "fr", "de", "es", "pt-BR", "ja",
    "ko", "zh-CN", "zh-TW", "ru", "ar", "hi", "it", "nl"
};
static const std::vector<std::string> FIREFOX_LANGUAGES = {
    "en-US", "en", "fr", "de", "es-ES", "pt-PT", "ja",
    "ru", "zh-CN", "ko", "it", "pl", "nl", "sv", "da", "fi"
};
static const std::vector<std::string> SAFARI_LANGUAGES = {
    "en-US", "en", "en-AU", "fr-FR", "de-DE", "ja", "zh-Hans",
    "zh-Hant", "ko", "es", "pt-BR", "it", "nl", "sv", "nb", "da"
};

const std::vector<std::string>& HeaderValueEncoder::get_language_pool(StegBrowserType type) {
    switch (type) {
        case StegBrowserType::FIREFOX_WIN:
        case StegBrowserType::FIREFOX_LINUX:
            return FIREFOX_LANGUAGES;
        case StegBrowserType::SAFARI_MAC:
            return SAFARI_LANGUAGES;
        default:
            return CHROME_LANGUAGES;
    }
}

size_t HeaderValueEncoder::capacity_bits(const std::string& header_name) const {
    if (header_name == "X-Request-ID") return 128;  // full UUID
    if (header_name == "Cookie") return 64;          // session cookie
    if (header_name == "Accept-Language") return 24;  // language permutation
    if (header_name == "If-None-Match") return 64;   // ETag
    return 0;
}

std::string HeaderValueEncoder::encode_value(const std::string& header_name,
                                              const uint8_t* data, size_t bits) {
    size_t bytes = (bits + 7) / 8;
    if (header_name == "X-Request-ID") return encode_request_id(data, bits);
    if (header_name == "Cookie") return encode_cookie(data, bits);
    if (header_name == "Accept-Language") return encode_accept_language(data, bits);
    if (header_name == "If-None-Match") return encode_etag(data, bits);
    return "";
}

std::vector<uint8_t> HeaderValueEncoder::decode_value(const std::string& header_name,
                                                       const std::string& value,
                                                       size_t expected_bits) {
    if (header_name == "X-Request-ID") return decode_request_id(value, expected_bits);
    if (header_name == "Cookie") return decode_cookie(value, expected_bits);
    if (header_name == "Accept-Language") return decode_accept_language(value, expected_bits);
    if (header_name == "If-None-Match") return decode_etag(value, expected_bits);
    return {};
}

// X-Request-ID: UUID v4 format, payload bytes as hex in UUID positions
std::string HeaderValueEncoder::encode_request_id(const uint8_t* data, size_t bits) {
    // UUID format: 8-4-4-4-12 hex chars = 32 hex = 16 bytes
    uint8_t uuid_bytes[16] = {0};
    size_t bytes = std::min((bits + 7) / 8, size_t(16));
    std::memcpy(uuid_bytes, data, bytes);

    // Set version 4 bits (byte 6, high nibble = 0100)
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
    // Set variant bits (byte 8, high 2 bits = 10)
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;

    char buf[37];
    snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
        uuid_bytes[4], uuid_bytes[5], uuid_bytes[6], uuid_bytes[7],
        uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
        uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]);
    return std::string(buf);
}

std::vector<uint8_t> HeaderValueEncoder::decode_request_id(const std::string& value, size_t bits) {
    std::vector<uint8_t> result;
    std::string hex;
    for (char c : value) {
        if (c != '-') hex += c;
    }
    for (size_t i = 0; i + 1 < hex.size() && result.size() < 16; i += 2) {
        auto byte = static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    // Unmask version/variant bits
    if (result.size() > 6) result[6] = result[6] & 0x0F;
    if (result.size() > 8) result[8] = result[8] & 0x3F;
    return result;
}

// Cookie: _ga=GA1.2.<hex_encoded_payload>; _gid=GA1.2.<random>
std::string HeaderValueEncoder::encode_cookie(const uint8_t* data, size_t bits) {
    size_t bytes = std::min((bits + 7) / 8, size_t(8));
    std::ostringstream oss;
    oss << "_ga=GA1.2.";
    for (size_t i = 0; i < bytes; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", data[i]);
        oss << hex;
    }
    // Add realistic-looking secondary cookie
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    oss << "; _gid=GA1.2." << (r % 2000000000);
    return oss.str();
}

std::vector<uint8_t> HeaderValueEncoder::decode_cookie(const std::string& value, size_t bits) {
    // Extract hex after "_ga=GA1.2."
    auto pos = value.find("_ga=GA1.2.");
    if (pos == std::string::npos) return {};
    pos += 10; // skip "_ga=GA1.2."
    auto end = value.find(';', pos);
    std::string hex = value.substr(pos, end == std::string::npos ? std::string::npos : end - pos);

    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        result.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

// Accept-Language: encode via permutation of language tags + q-values
std::string HeaderValueEncoder::encode_accept_language(const uint8_t* data, size_t bits) {
    const auto& pool = get_language_pool(browser_type_);
    size_t bytes = std::min((bits + 7) / 8, size_t(3));

    uint32_t value = 0;
    for (size_t i = 0; i < bytes; ++i) {
        value = (value << 8) | data[i];
    }

    // Use value to select and order 3-5 languages from pool
    size_t n_langs = 3 + (value % 3); // 3-5 languages
    value /= 3;

    std::ostringstream oss;
    std::vector<bool> used(pool.size(), false);
    for (size_t i = 0; i < n_langs && i < pool.size(); ++i) {
        uint32_t idx = value % static_cast<uint32_t>(pool.size());
        value /= static_cast<uint32_t>(pool.size());
        // Find next unused
        for (size_t j = 0; j < pool.size(); ++j) {
            size_t actual = (idx + j) % pool.size();
            if (!used[actual]) {
                used[actual] = true;
                if (i > 0) oss << ",";
                oss << pool[actual];
                if (i > 0) {
                    // q-value decreasing
                    double q = 0.9 - i * 0.1;
                    if (q < 0.1) q = 0.1;
                    char qbuf[8];
                    snprintf(qbuf, sizeof(qbuf), ";q=%.1f", q);
                    oss << qbuf;
                }
                break;
            }
        }
    }
    return oss.str();
}

std::vector<uint8_t> HeaderValueEncoder::decode_accept_language(const std::string& value, size_t bits) {
    // Reverse mapping: parse language order, map back to value
    // Simplified: extract first 3 bytes from language indices
    const auto& pool = get_language_pool(browser_type_);
    std::vector<uint8_t> result;

    // Parse languages from Accept-Language header
    std::vector<std::string> langs;
    std::string token;
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == ',' || value[i] == ';') {
            if (!token.empty()) {
                langs.push_back(token);
                token.clear();
            }
            if (value[i] == ';') {
                while (i < value.size() && value[i] != ',') ++i;
            }
        } else if (value[i] != ' ') {
            token += value[i];
        }
    }
    if (!token.empty()) langs.push_back(token);

    // Reconstruct value from language indices
    uint32_t decoded = 0;
    uint32_t multiplier = 1;
    for (size_t i = langs.size(); i > 0; --i) {
        auto it = std::find(pool.begin(), pool.end(), langs[i-1]);
        if (it != pool.end()) {
            decoded += static_cast<uint32_t>(std::distance(pool.begin(), it)) * multiplier;
            multiplier *= static_cast<uint32_t>(pool.size());
        }
    }
    decoded = decoded * 3 + static_cast<uint32_t>(langs.size() - 3);

    size_t bytes = std::min((bits + 7) / 8, size_t(3));
    for (size_t i = bytes; i > 0; --i) {
        result.push_back(static_cast<uint8_t>((decoded >> ((i-1) * 8)) & 0xFF));
    }
    return result;
}

// If-None-Match (ETag): W/"<hex_payload>" or "<hex_payload>"
std::string HeaderValueEncoder::encode_etag(const uint8_t* data, size_t bits) {
    size_t bytes = std::min((bits + 7) / 8, size_t(8));
    std::ostringstream oss;
    oss << "W/\"";
    for (size_t i = 0; i < bytes; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", data[i]);
        oss << hex;
    }
    oss << "\"";
    return oss.str();
}

std::vector<uint8_t> HeaderValueEncoder::decode_etag(const std::string& value, size_t bits) {
    // Extract hex between quotes
    auto start = value.find('"');
    auto end = value.rfind('"');
    if (start == std::string::npos || start == end) return {};
    std::string hex = value.substr(start + 1, end - start - 1);

    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        result.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

// ==================== HTTPStegChannel ====================

HTTPStegChannel::HTTPStegChannel()
    : HTTPStegChannel(HTTPStegConfig{}) {}

HTTPStegChannel::HTTPStegChannel(const HTTPStegConfig& config)
    : config_(config) {
    perm_codec_ = std::make_unique<PermutationCodec>(config_.permutation_headers.size());
    value_encoder_ = std::make_unique<HeaderValueEncoder>(config_.browser_type);
}

HTTPStegChannel::~HTTPStegChannel() {
    close();
}

bool HTTPStegChannel::open() {
    if (state_.load() == ChannelState::OPEN) return true;
    state_.store(ChannelState::OPENING);

    if (config_.target_url.empty() && config_.target_host.empty()) {
        NCP_LOG_ERROR("HTTP steg channel: no target configured");
        state_.store(ChannelState::ERROR);
        return false;
    }

    running_.store(true);
    tx_thread_ = std::thread([this] { tx_worker_func(); });

    if (config_.enable_cover_requests && !config_.cover_urls.empty()) {
        cover_thread_ = std::thread([this] { cover_traffic_func(); });
    }

    state_.store(ChannelState::OPEN);
    NCP_LOG_INFO("HTTP steg channel opened (target: " + config_.target_host + ")");
    return true;
}

void HTTPStegChannel::close() {
    if (state_.load() == ChannelState::CLOSED) return;
    state_.store(ChannelState::CLOSING);
    running_.store(false);

    tx_cv_.notify_all();
    rx_cv_.notify_all();

    if (tx_thread_.joinable()) tx_thread_.join();
    if (cover_thread_.joinable()) cover_thread_.join();

    state_.store(ChannelState::CLOSED);
    NCP_LOG_INFO("HTTP steg channel closed");
}

bool HTTPStegChannel::is_open() const {
    auto s = state_.load();
    return s == ChannelState::OPEN || s == ChannelState::DEGRADED;
}

ChannelState HTTPStegChannel::state() const {
    return state_.load();
}

size_t HTTPStegChannel::bits_per_request() const {
    size_t perm_bits = perm_codec_->capacity_bits();
    size_t val_bits = 0;
    for (const auto& vc : config_.value_carriers) {
        val_bits += vc.capacity_bits;
    }
    return perm_bits + val_bits;
}

size_t HTTPStegChannel::send(const uint8_t* data, size_t len) {
    if (!is_open() || len == 0) return 0;

    std::vector<uint8_t> payload;
    if (config_.encrypt_payload && !config_.channel_key.empty()) {
        payload = encrypt_payload(data, len);
    } else {
        payload.assign(data, data + len);
    }

    size_t bits_total = payload.size() * 8;
    size_t bpr = bits_per_request();
    if (bpr == 0) return 0;

    // Fragment into per-request chunks
    {
        std::lock_guard<std::mutex> lock(tx_mutex_);
        size_t offset_bits = 0;
        while (offset_bits < bits_total) {
            size_t chunk_bits = std::min(bpr, bits_total - offset_bits);
            size_t byte_start = offset_bits / 8;
            size_t byte_count = (chunk_bits + 7) / 8;

            TxItem item;
            item.payload.assign(payload.begin() + byte_start,
                               payload.begin() + byte_start + byte_count);
            item.bit_count = chunk_bits;
            if (tx_queue_.size() >= config_.tx_queue_max) {
                NCP_LOG_WARN("HTTP steg channel: TX queue full");
                break;
            }
            tx_queue_.push(std::move(item));
            offset_bits += chunk_bits;
        }
    }
    tx_cv_.notify_one();

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        base_stats_.bytes_sent += len;
        base_stats_.messages_sent++;
    }

    return len;
}

size_t HTTPStegChannel::receive(uint8_t* buf, size_t max_len) {
    std::unique_lock<std::mutex> lock(rx_mutex_);
    rx_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
        return !rx_buffer_.empty() || !running_.load();
    });

    if (rx_buffer_.empty()) return 0;
    size_t to_copy = std::min(max_len, rx_buffer_.size());
    std::memcpy(buf, rx_buffer_.data(), to_copy);
    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + to_copy);

    {
        std::lock_guard<std::mutex> slock(stats_mutex_);
        base_stats_.bytes_received += to_copy;
        base_stats_.messages_received++;
    }
    return to_copy;
}

ChannelStats HTTPStegChannel::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return base_stats_;
}

double HTTPStegChannel::max_capacity_bps() const {
    double bpr = static_cast<double>(bits_per_request());
    double interval_sec = config_.min_request_interval_ms / 1000.0;
    if (interval_sec <= 0) interval_sec = 0.2;
    return bpr / interval_sec;
}

HTTPStegStats HTTPStegChannel::get_steg_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return steg_stats_;
}

void HTTPStegChannel::set_detection_callback(DetectionCallback cb) {
    std::lock_guard<std::mutex> lock(detection_mutex_);
    detection_cb_ = std::move(cb);
}

void HTTPStegChannel::on_detection(const CovertDetectionEvent& event) {
    if (event.confidence > 0.7) {
        NCP_LOG_WARN("HTTP steg channel: detection event (confidence: " +
                     std::to_string(event.confidence) + ")");
        if (event.confidence > 0.9) {
            state_.store(ChannelState::DEGRADED);
        }
    }
    std::lock_guard<std::mutex> lock(detection_mutex_);
    if (detection_cb_) detection_cb_(event);
}

bool HTTPStegChannel::set_config(const HTTPStegConfig& config) {
    if (state_.load() != ChannelState::CLOSED) {
        NCP_LOG_ERROR("HTTP steg channel: set_config() requires CLOSED state");
        return false;
    }
    config_ = config;
    perm_codec_ = std::make_unique<PermutationCodec>(config_.permutation_headers.size());
    value_encoder_ = std::make_unique<HeaderValueEncoder>(config_.browser_type);
    return true;
}

HTTPStegConfig HTTPStegChannel::get_config() const {
    return config_;
}

StegHTTPRequest HTTPStegChannel::build_steg_request(const uint8_t* data, size_t bits) {
    StegHTTPRequest req;
    req.method = "GET";
    req.path = config_.target_url.empty() ? "/" : config_.target_url;

    size_t offset_bits = 0;

    // 1) Permutation coding: encode bits in header ORDER
    size_t perm_bits = perm_codec_->capacity_bits();
    uint64_t perm_value = 0;
    size_t perm_bytes = std::min((perm_bits + 7) / 8, (bits - offset_bits + 7) / 8);
    for (size_t i = 0; i < perm_bytes && offset_bits / 8 + i < (bits + 7) / 8; ++i) {
        perm_value = (perm_value << 8) | data[offset_bits / 8 + i];
    }
    // Mask to actual perm bits
    if (perm_bits < 64) perm_value &= ((1ULL << perm_bits) - 1);

    auto perm = perm_codec_->encode(perm_value);

    // Build headers in permutation order
    for (size_t idx : perm) {
        if (idx < config_.permutation_headers.size()) {
            // Use browser-appropriate default values for these headers
            std::string hdr_name = config_.permutation_headers[idx];
            std::string hdr_value;
            if (hdr_name == "Accept")
                hdr_value = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            else if (hdr_name == "Accept-Encoding")
                hdr_value = "gzip, deflate, br";
            else if (hdr_name == "Cache-Control")
                hdr_value = "no-cache";
            else if (hdr_name == "Connection")
                hdr_value = "keep-alive";
            else if (hdr_name == "Upgrade-Insecure-Requests")
                hdr_value = "1";
            else
                hdr_value = "";
            req.headers.push_back({hdr_name, hdr_value});
        }
    }
    offset_bits += perm_bits;
    req.covert_bits_permutation = perm_bits;

    // 2) Value encoding: encode bits in header VALUES
    for (const auto& vc : config_.value_carriers) {
        if (offset_bits >= bits) break;
        size_t val_bits = std::min(vc.capacity_bits, bits - offset_bits);
        size_t byte_offset = offset_bits / 8;

        std::string encoded_value = value_encoder_->encode_value(
            vc.header_name, data + byte_offset, val_bits);

        if (!encoded_value.empty()) {
            req.headers.push_back({vc.header_name, encoded_value});
            offset_bits += val_bits;
            req.covert_bits_values += val_bits;
        }
    }

    // 3) Add Host header (required)
    req.headers.push_back({"Host", config_.target_host});

    return req;
}

std::vector<uint8_t> HTTPStegChannel::extract_from_response(const StegHTTPResponse& response) {
    // Server encodes response data in the same way — extract from response headers
    std::vector<uint8_t> result;
    for (const auto& vc : config_.value_carriers) {
        for (const auto& hdr : response.headers) {
            if (hdr.first == vc.header_name) {
                auto decoded = value_encoder_->decode_value(
                    vc.header_name, hdr.second, vc.capacity_bits);
                result.insert(result.end(), decoded.begin(), decoded.end());
            }
        }
    }
    return result;
}

StegHTTPResponse HTTPStegChannel::send_http_request(const StegHTTPRequest& request) {
    // TODO: actual HTTPS request via TLS socket
    // For now: construct and log the request, return empty response
    StegHTTPResponse response;
    response.status_code = 200;
    // In production: use libcurl or custom TLS client
    return response;
}

void HTTPStegChannel::tx_worker_func() {
    while (running_.load()) {
        TxItem item;
        {
            std::unique_lock<std::mutex> lock(tx_mutex_);
            tx_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
                return !tx_queue_.empty() || !running_.load();
            });
            if (!running_.load() && tx_queue_.empty()) break;
            if (tx_queue_.empty()) continue;
            item = std::move(tx_queue_.front());
            tx_queue_.pop();
        }

        auto delay = next_request_delay();
        if (delay.count() > 0) std::this_thread::sleep_for(delay);

        auto request = build_steg_request(item.payload.data(), item.bit_count);
        auto response = send_http_request(request);

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            steg_stats_.requests_sent++;
            steg_stats_.payload_bits_sent += item.bit_count;
            steg_stats_.permutation_bits += request.covert_bits_permutation;
            steg_stats_.value_bits += request.covert_bits_values;
            stealth_update_counter_++;
        }

        // Extract any response data
        if (response.status_code == 200 && response.has_covert_data) {
            auto decoded = extract_from_response(response);
            if (!decoded.empty()) {
                std::lock_guard<std::mutex> lock(rx_mutex_);
                rx_buffer_.insert(rx_buffer_.end(), decoded.begin(), decoded.end());
                rx_cv_.notify_one();
            }
        }

        if (stealth_update_counter_ % 10 == 0) {
            update_stealth_score();
        }
    }
}

void HTTPStegChannel::cover_traffic_func() {
    while (running_.load()) {
        auto delay = next_request_delay();
        double ratio = config_.cover_traffic_ratio;
        if (ratio <= 0.0) ratio = 1.0;
        double cover_delay_ms = delay.count() / ratio;
        std::this_thread::sleep_for(std::chrono::milliseconds(
            static_cast<int64_t>(cover_delay_ms)));

        if (!running_.load()) break;

        // Send legitimate cover request
        if (!config_.cover_urls.empty()) {
            uint32_t idx = randombytes_uniform(
                static_cast<uint32_t>(config_.cover_urls.size()));
            StegHTTPRequest cover_req;
            cover_req.method = "GET";
            cover_req.path = config_.cover_urls[idx];
            cover_req.headers.push_back({"Host", config_.target_host});
            send_http_request(cover_req);

            std::lock_guard<std::mutex> lock(stats_mutex_);
            steg_stats_.cover_requests_sent++;
        }
    }
}

std::vector<uint8_t> HTTPStegChannel::encrypt_payload(
    const uint8_t* data, size_t len) const {
    if (config_.channel_key.size() < crypto_secretbox_KEYBYTES)
        return {data, data + len};
    std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<uint8_t> ct(crypto_secretbox_MACBYTES + len);
    crypto_secretbox_easy(ct.data(), data, len, nonce.data(), config_.channel_key.data());
    std::vector<uint8_t> result;
    result.reserve(nonce.size() + ct.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ct.begin(), ct.end());
    return result;
}

std::vector<uint8_t> HTTPStegChannel::decrypt_payload(
    const uint8_t* data, size_t len) const {
    if (config_.channel_key.size() < crypto_secretbox_KEYBYTES)
        return {data, data + len};
    if (len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)
        return {};
    const uint8_t* nonce = data;
    const uint8_t* ct = data + crypto_secretbox_NONCEBYTES;
    size_t ct_len = len - crypto_secretbox_NONCEBYTES;
    std::vector<uint8_t> pt(ct_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(pt.data(), ct, ct_len, nonce, config_.channel_key.data()) != 0)
        return {};
    return pt;
}

void HTTPStegChannel::update_stealth_score() {
    double score = 1.0;
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t total = steg_stats_.requests_sent + steg_stats_.cover_requests_sent;
    if (total > 0) {
        double cover_ratio = static_cast<double>(steg_stats_.cover_requests_sent) / total;
        if (cover_ratio < 0.2) score -= 0.3;
    }
    if (steg_stats_.errors > 0 && steg_stats_.requests_sent > 0) {
        double err_rate = static_cast<double>(steg_stats_.errors) / steg_stats_.requests_sent;
        if (err_rate > 0.1) score -= 0.2;
    }
    steg_stats_.stealth_score = std::max(0.0, std::min(1.0, score));
    base_stats_.stealthiness_score = steg_stats_.stealth_score;
}

std::chrono::milliseconds HTTPStegChannel::next_request_delay() const {
    double base = config_.min_request_interval_ms +
        (config_.max_request_interval_ms - config_.min_request_interval_ms) * 0.3;
    double jitter_range = base * config_.jitter_factor;
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    double jitter = (static_cast<double>(r) / 4294967296.0 - 0.5) * 2.0 * jitter_range;
    double delay = std::max(config_.min_request_interval_ms, base + jitter);
    return std::chrono::milliseconds(static_cast<int64_t>(delay));
}

} // namespace covert
} // namespace ncp
