/**
 * @file ncp_http_steg.cpp
 * @brief HTTP Header Steganography — implementation
 *
 * REFACTORED per architecture review:
 *   - NO internal crypto (Manager handles encrypt_aead/decrypt_aead)
 *   - Uses INetworkBackend* for transport
 *   - Uses TrafficMimicry* for HTTP scaffold
 *   - Steg layer only embeds data in headers
 *
 * Pipeline:
 *   send(raw_bytes)
 *     → fragment into per-request chunks
 *     → build_steg_headers() — permutation + value encoding
 *     → mimicry_->wrap_payload(steg_bytes, HTTP_GET) — adds realistic scaffold
 *     → backend_->send_tcp_packet() — wire transport
 *
 * Patterns from DNS covert channel (review-hardened):
 *   - randombytes_uniform() for unbiased selection
 *   - /4294967296.0 for [0,1) range
 *   - Consistent lock order: tx_mutex_ → stats_mutex_
 *   - set_config() requires CLOSED state
 */

#include "include/ncp_covert_channel.hpp"
#include "include/ncp_http_steg.hpp"
#include "include/ncp_mimicry.hpp"
#include "include/ncp_network_backend.hpp"
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

// Encode integer → permutation using Lehmer code (factoradic)
std::vector<size_t> PermutationCodec::encode(uint64_t value) const {
    value = value % factorial_;

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

// Decode permutation → integer
uint64_t PermutationCodec::decode(const std::vector<size_t>& permutation) const {
    if (permutation.size() != n_) return 0;

    std::vector<size_t> available(n_);
    std::iota(available.begin(), available.end(), 0);

    uint64_t value = 0;
    for (size_t i = 0; i < n_; ++i) {
        auto it = std::find(available.begin(), available.end(), permutation[i]);
        if (it == available.end()) return 0;

        size_t index = static_cast<size_t>(std::distance(available.begin(), it));
        value += index * factorial(n_ - 1 - i);
        available.erase(it);
    }

    return value;
}

// ==================== HeaderValueEncoder ====================

HeaderValueEncoder::HeaderValueEncoder(StegBrowserType browser_type)
    : browser_type_(browser_type) {}

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
    if (header_name == "X-Request-ID") return 128;
    if (header_name == "Cookie") return 64;
    if (header_name == "Accept-Language") return 24;
    if (header_name == "If-None-Match") return 64;
    return 0;
}

std::string HeaderValueEncoder::encode_value(const std::string& header_name,
                                              const uint8_t* data, size_t bits) {
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
    uint8_t uuid_bytes[16] = {0};
    size_t bytes = std::min((bits + 7) / 8, size_t(16));
    std::memcpy(uuid_bytes, data, bytes);

    // Set version 4 bits + variant bits for valid UUID v4
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
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
    if (result.size() > 6) result[6] = result[6] & 0x0F;
    if (result.size() > 8) result[8] = result[8] & 0x3F;
    return result;
}

// Cookie: _ga=GA1.2.<hex_payload>; _gid=GA1.2.<random>
std::string HeaderValueEncoder::encode_cookie(const uint8_t* data, size_t bits) {
    size_t bytes = std::min((bits + 7) / 8, size_t(8));
    std::ostringstream oss;
    oss << "_ga=GA1.2.";
    for (size_t i = 0; i < bytes; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", data[i]);
        oss << hex;
    }
    uint32_t r = randombytes_uniform(2000000000);
    oss << "; _gid=GA1.2." << r;
    return oss.str();
}

std::vector<uint8_t> HeaderValueEncoder::decode_cookie(const std::string& value, size_t bits) {
    auto pos = value.find("_ga=GA1.2.");
    if (pos == std::string::npos) return {};
    pos += 10;
    auto end = value.find(';', pos);
    std::string hex = value.substr(pos, end == std::string::npos ? std::string::npos : end - pos);

    std::vector<uint8_t> result;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        result.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return result;
}

// Accept-Language: encode via language tag permutation + q-values
std::string HeaderValueEncoder::encode_accept_language(const uint8_t* data, size_t bits) {
    const auto& pool = get_language_pool(browser_type_);
    size_t bytes = std::min((bits + 7) / 8, size_t(3));

    uint32_t value = 0;
    for (size_t i = 0; i < bytes; ++i) {
        value = (value << 8) | data[i];
    }

    size_t n_langs = 3 + (value % 3);
    value /= 3;

    std::ostringstream oss;
    std::vector<bool> used(pool.size(), false);
    for (size_t i = 0; i < n_langs && i < pool.size(); ++i) {
        uint32_t idx = value % static_cast<uint32_t>(pool.size());
        value /= static_cast<uint32_t>(pool.size());
        for (size_t j = 0; j < pool.size(); ++j) {
            size_t actual = (idx + j) % pool.size();
            if (!used[actual]) {
                used[actual] = true;
                if (i > 0) oss << ",";
                oss << pool[actual];
                if (i > 0) {
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
    const auto& pool = get_language_pool(browser_type_);
    std::vector<uint8_t> result;

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

// If-None-Match: W/"<hex_payload>"
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

HTTPStegChannel::HTTPStegChannel(ncp::INetworkBackend* backend,
                                 ncp::TrafficMimicry* mimicry,
                                 const HTTPStegConfig& config)
    : backend_(backend),
      mimicry_(mimicry),
      config_(config) {
    perm_codec_ = std::make_unique<PermutationCodec>(config_.permutation_headers.size());
    value_encoder_ = std::make_unique<HeaderValueEncoder>(config_.browser_type);
}

HTTPStegChannel::~HTTPStegChannel() {
    close();
}

bool HTTPStegChannel::open() {
    if (state_.load() == ChannelState::OPEN) return true;
    state_.store(ChannelState::OPENING);

    if (!backend_ || !mimicry_) {
        NCP_LOG_ERROR("HTTP steg: backend or mimicry not set");
        state_.store(ChannelState::ERROR);
        return false;
    }
    if (config_.target_host.empty()) {
        NCP_LOG_ERROR("HTTP steg: no target_host configured");
        state_.store(ChannelState::ERROR);
        return false;
    }

    running_.store(true);
    tx_thread_ = std::thread([this] { tx_worker_func(); });

    if (config_.enable_cover_requests && !config_.cover_paths.empty()) {
        cover_thread_ = std::thread([this] { cover_traffic_func(); });
    }

    state_.store(ChannelState::OPEN);
    NCP_LOG_INFO("HTTP steg channel opened (" + config_.target_host + ")");
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

    // NO encryption here — Manager handles it.
    // Just fragment raw bytes into per-request chunks.
    size_t bits_total = len * 8;
    size_t bpr = bits_per_request();
    if (bpr == 0) return 0;

    {
        std::lock_guard<std::mutex> lock(tx_mutex_);
        size_t offset_bits = 0;
        while (offset_bits < bits_total) {
            size_t chunk_bits = std::min(bpr, bits_total - offset_bits);
            size_t byte_start = offset_bits / 8;
            size_t byte_count = (chunk_bits + 7) / 8;

            TxItem item;
            item.payload.assign(data + byte_start, data + byte_start + byte_count);
            item.bit_count = chunk_bits;
            if (tx_queue_.size() >= config_.tx_queue_max) {
                NCP_LOG_WARN("HTTP steg: TX queue full");
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
        NCP_LOG_WARN("HTTP steg: detection (confidence: " +
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
        NCP_LOG_ERROR("HTTP steg: set_config() requires CLOSED state");
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

std::vector<std::pair<std::string, std::string>>
HTTPStegChannel::build_steg_headers(const uint8_t* data, size_t bits,
                                     size_t& out_perm_bits, size_t& out_val_bits) {
    std::vector<std::pair<std::string, std::string>> headers;
    size_t offset_bits = 0;

    // 1) Permutation coding: header ORDER encodes bits
    size_t perm_bits = perm_codec_->capacity_bits();
    uint64_t perm_value = 0;
    size_t perm_bytes = std::min((perm_bits + 7) / 8, (bits + 7) / 8);
    for (size_t i = 0; i < perm_bytes; ++i) {
        perm_value = (perm_value << 8) | data[i];
    }
    if (perm_bits < 64) perm_value &= ((1ULL << perm_bits) - 1);

    auto perm = perm_codec_->encode(perm_value);

    // Default header values (browser-appropriate)
    static const std::map<std::string, std::string> default_values = {
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        {"Accept-Encoding", "gzip, deflate, br"},
        {"Cache-Control", "no-cache"},
        {"Connection", "keep-alive"},
        {"Upgrade-Insecure-Requests", "1"}
    };

    for (size_t idx : perm) {
        if (idx < config_.permutation_headers.size()) {
            const auto& name = config_.permutation_headers[idx];
            auto it = default_values.find(name);
            headers.push_back({name, it != default_values.end() ? it->second : ""});
        }
    }
    offset_bits += perm_bits;
    out_perm_bits = perm_bits;

    // 2) Value encoding: header VALUES carry payload
    out_val_bits = 0;
    for (const auto& vc : config_.value_carriers) {
        if (offset_bits >= bits) break;
        size_t val_bits = std::min(vc.capacity_bits, bits - offset_bits);
        size_t byte_offset = offset_bits / 8;

        std::string encoded = value_encoder_->encode_value(
            vc.header_name, data + byte_offset, val_bits);

        if (!encoded.empty()) {
            headers.push_back({vc.header_name, encoded});
            offset_bits += val_bits;
            out_val_bits += val_bits;
        }
    }

    // Host header (required)
    headers.push_back({"Host", config_.target_host});

    return headers;
}

bool HTTPStegChannel::send_steg_request(const uint8_t* data, size_t bits) {
    size_t perm_b = 0, val_b = 0;
    auto steg_headers = build_steg_headers(data, bits, perm_b, val_b);

    // Serialize steg headers into a byte vector for mimicry wrapping.
    // TrafficMimicry::create_http_get_wrapper() builds full HTTP request
    // including User-Agent, Host, realistic paths, etc.
    // We inject our steg headers into the mimicry config before wrapping.

    // Build raw HTTP request line + steg headers
    std::ostringstream raw;
    raw << "GET " << config_.target_path << " HTTP/1.1\r\n";
    for (const auto& [name, value] : steg_headers) {
        raw << name << ": " << value << "\r\n";
    }
    raw << "\r\n";
    std::string request_str = raw.str();
    std::vector<uint8_t> request_bytes(request_str.begin(), request_str.end());

    // Wrap with TrafficMimicry for TLS layer (HTTPS_APPLICATION)
    auto wrapped = mimicry_->wrap_payload(request_bytes,
                                           ncp::TrafficMimicry::MimicProfile::HTTPS_APPLICATION);

    // Send via INetworkBackend
    bool ok = backend_->send_tcp_packet(
        "",                         // src_ip: auto
        config_.target_host,        // dst_ip
        0,                          // src_port: auto
        config_.target_port,        // dst_port
        wrapped,                    // payload
        0x18,                       // TCP flags: PSH+ACK
        64                          // TTL
    );

    if (!ok) {
        NCP_LOG_WARN("HTTP steg: send_tcp_packet failed");
    }
    return ok;
}

void HTTPStegChannel::send_cover_request() {
    if (config_.cover_paths.empty()) return;

    uint32_t idx = randombytes_uniform(
        static_cast<uint32_t>(config_.cover_paths.size()));

    std::ostringstream raw;
    raw << "GET " << config_.cover_paths[idx] << " HTTP/1.1\r\n";
    raw << "Host: " << config_.target_host << "\r\n";
    raw << "Accept: text/html,*/*\r\n";
    raw << "Connection: keep-alive\r\n";
    raw << "\r\n";
    std::string request_str = raw.str();
    std::vector<uint8_t> request_bytes(request_str.begin(), request_str.end());

    auto wrapped = mimicry_->wrap_payload(request_bytes,
                                           ncp::TrafficMimicry::MimicProfile::HTTPS_APPLICATION);

    backend_->send_tcp_packet(
        "", config_.target_host, 0, config_.target_port,
        wrapped, 0x18, 64);
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

        bool ok = send_steg_request(item.payload.data(), item.bit_count);

        // Stats update — lock order: tx_mutex_ already released, safe to take stats_mutex_
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            steg_stats_.requests_sent++;
            steg_stats_.payload_bits_sent += item.bit_count;
            if (!ok) steg_stats_.errors++;
            stealth_update_counter_++;
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

        send_cover_request();

        std::lock_guard<std::mutex> lock(stats_mutex_);
        steg_stats_.cover_requests_sent++;
    }
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
