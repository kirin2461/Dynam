/**
 * @file ncp_dns_covert.cpp
 * @brief DNS Covert Channel — implementation
 *
 * Fix log (review v1):
 *   🔴 #1: Double encoding removed — encode_upstream_raw() is pure encoder,
 *          send_chunk() is the SINGLE framing point
 *   🔴 #2: set_config() requires CLOSED state (thread-safe)
 *   🟡 #3: ABBA deadlock fixed — lock order: tx_mutex_ → stats_mutex_
 *   🟡 #4: Modulo bias fixed — randombytes_uniform() + /4294967296.0
 *   🟡 #5: Division by zero in cover_traffic_func() guarded
 *   🟡 #6: ChunkReassembler OOM cap — MAX_TOTAL_CHUNKS = 1024
 *   🟢 #7: update_stealth_score() called every 10 queries
 */

#include "include/ncp_covert_channel.hpp"
#include "include/ncp_dns_covert.hpp"
#include "include/ncp_csprng.hpp"
#include "include/ncp_logger.hpp"

#include <sodium.h>
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <numeric>
#include <random>
#include <sstream>

namespace ncp {
namespace covert {

// ==================== ChannelState string ====================

const char* channel_state_to_string(ChannelState s) noexcept {
    switch (s) {
        case ChannelState::CLOSED:   return "CLOSED";
        case ChannelState::OPENING:  return "OPENING";
        case ChannelState::OPEN:     return "OPEN";
        case ChannelState::DEGRADED: return "DEGRADED";
        case ChannelState::CLOSING:  return "CLOSING";
        case ChannelState::ERROR:    return "ERROR";
    }
    return "UNKNOWN";
}

// ==================== DNSChunkHeader ====================

std::vector<uint8_t> DNSChunkHeader::serialize() const {
    std::vector<uint8_t> out(HEADER_SIZE);
    out[0] = flags;
    out[1] = static_cast<uint8_t>(sequence_number >> 8);
    out[2] = static_cast<uint8_t>(sequence_number & 0xFF);
    out[3] = static_cast<uint8_t>(total_chunks >> 8);
    out[4] = static_cast<uint8_t>(total_chunks & 0xFF);
    out[5] = static_cast<uint8_t>(payload_length >> 8);
    out[6] = static_cast<uint8_t>(payload_length & 0xFF);
    return out;
}

DNSChunkHeader DNSChunkHeader::deserialize(const uint8_t* data, size_t len) {
    DNSChunkHeader h;
    if (len < HEADER_SIZE) return h;
    h.flags = data[0];
    h.sequence_number = (static_cast<uint16_t>(data[1]) << 8) | data[2];
    h.total_chunks    = (static_cast<uint16_t>(data[3]) << 8) | data[4];
    h.payload_length  = (static_cast<uint16_t>(data[5]) << 8) | data[6];
    return h;
}

// ==================== CRC32 ====================

static uint32_t crc32_compute(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return crc ^ 0xFFFFFFFF;
}

// ==================== Base32hex encode/decode ====================

static const char BASE32HEX_CHARS[] = "0123456789abcdefghijklmnopqrstuv";

std::string SubdomainEncoder::base32hex_encode(const uint8_t* data, size_t len) const {
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    uint64_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += BASE32HEX_CHARS[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out += BASE32HEX_CHARS[(buffer << (5 - bits)) & 0x1F];
    }
    return out;
}

std::vector<uint8_t> SubdomainEncoder::base32hex_decode(const std::string& encoded) const {
    std::vector<uint8_t> out;
    out.reserve(encoded.size() * 5 / 8);
    uint64_t buffer = 0;
    int bits = 0;
    for (char c : encoded) {
        int val = -1;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'v') val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'V') val = c - 'A' + 10;
        if (val < 0) continue;
        buffer = (buffer << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

// ==================== Base64url encode/decode ====================

static const char BASE64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string SubdomainEncoder::base64url_encode(const uint8_t* data, size_t len) const {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= data[i + 2];
        out += BASE64URL_CHARS[(n >> 18) & 0x3F];
        out += BASE64URL_CHARS[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? BASE64URL_CHARS[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? BASE64URL_CHARS[n & 0x3F] : '=';
    }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

std::vector<uint8_t> SubdomainEncoder::base64url_decode(const std::string& encoded) const {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(encoded.size() * 3 / 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : encoded) {
        int v = val(c);
        if (v < 0) continue;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

// ==================== SubdomainEncoder ====================

SubdomainEncoder::SubdomainEncoder(const DNSCovertConfig& config)
    : config_(config) {}

std::vector<std::string> SubdomainEncoder::split_into_labels(const std::string& data) const {
    std::vector<std::string> labels;
    for (size_t i = 0; i < data.size(); i += config_.max_label_length) {
        labels.push_back(data.substr(i, config_.max_label_length));
    }
    return labels;
}

std::string SubdomainEncoder::randomize_case(const std::string& name) const {
    if (!config_.randomize_case) return name;
    std::string result = name;
    for (auto& c : result) {
        if (c >= 'a' && c <= 'z') {
            uint8_t r;
            randombytes_buf(&r, 1);
            if (r & 1) c = static_cast<char>(c - 32);
        }
    }
    return result;
}

size_t SubdomainEncoder::max_payload_per_query() const {
    size_t zone_len = config_.authoritative_zone.size() + 1;
    size_t seq_label = 6; // "s0000."
    size_t available = config_.max_query_name_length - zone_len - seq_label;
    size_t usable_chars = available - (available / (config_.max_label_length + 1));
    return (usable_chars * 5) / 8;
}

size_t SubdomainEncoder::max_payload_per_response(DNSEncodingScheme scheme) const {
    switch (scheme) {
        case DNSEncodingScheme::BASE64_TXT:      return 189;
        case DNSEncodingScheme::CNAME_CHAIN:     return 180;
        case DNSEncodingScheme::IP_ENCODING_A:   return 40;
        case DNSEncodingScheme::IP_ENCODING_AAAA: return 160;
        default: return 189;
    }
}

// FIX #1: Pure encoder — takes raw bytes, returns DNS query names.
// Does NOT add chunk headers or CRC. Framing is done in send_chunk().
std::vector<std::string> SubdomainEncoder::encode_upstream_raw(
    const uint8_t* data, size_t len, uint16_t sequence_base) {

    std::vector<std::string> queries;
    size_t capacity = max_payload_per_query();
    if (capacity == 0) return queries;

    size_t offset = 0;
    uint16_t seq = sequence_base;

    while (offset < len) {
        size_t chunk_len = std::min(capacity, len - offset);

        // base32hex encode this chunk of raw bytes
        std::string encoded = base32hex_encode(data + offset, chunk_len);
        auto labels = split_into_labels(encoded);

        // Build FQDN: <label1>.<label2>.s<seq>.<zone>
        std::ostringstream oss;
        for (const auto& lbl : labels) {
            oss << lbl << ".";
        }
        char seq_label[8];
        snprintf(seq_label, sizeof(seq_label), "s%04x", seq);
        oss << seq_label << "." << config_.authoritative_zone;

        queries.push_back(randomize_case(oss.str()));

        offset += chunk_len;
        ++seq;
    }

    return queries;
}

// FIX #1: Pure decoder — returns raw bytes from query name.
std::vector<uint8_t> SubdomainEncoder::decode_upstream_raw(const std::string& query_name) {
    auto zone_pos = query_name.find(config_.authoritative_zone);
    if (zone_pos == std::string::npos) return {};

    std::string prefix = query_name.substr(0, zone_pos);
    if (!prefix.empty() && prefix.back() == '.') prefix.pop_back();

    // Remove sequence label (last label before zone)
    auto last_dot = prefix.rfind('.');
    if (last_dot != std::string::npos && prefix[last_dot + 1] == 's') {
        prefix = prefix.substr(0, last_dot);
    } else if (prefix.size() > 5 && prefix[prefix.size() - 5] == 's') {
        prefix = prefix.substr(0, prefix.size() - 5);
        if (!prefix.empty() && prefix.back() == '.') prefix.pop_back();
    }

    // Remove dots, lowercase
    std::string encoded;
    for (char c : prefix) {
        if (c != '.') encoded += static_cast<char>(std::tolower(c));
    }

    return base32hex_decode(encoded);
}

std::vector<std::vector<uint8_t>> SubdomainEncoder::encode_downstream(
    const uint8_t* data, size_t len, DNSEncodingScheme scheme) {
    std::vector<std::vector<uint8_t>> records;

    switch (scheme) {
        case DNSEncodingScheme::BASE64_TXT: {
            std::string encoded = base64url_encode(data, len);
            for (size_t i = 0; i < encoded.size(); i += 250) {
                std::string chunk = encoded.substr(i, 250);
                records.push_back({chunk.begin(), chunk.end()});
            }
            break;
        }
        case DNSEncodingScheme::IP_ENCODING_A: {
            for (size_t i = 0; i < len; i += 4) {
                std::vector<uint8_t> rec(4, 0);
                for (size_t j = 0; j < 4 && (i + j) < len; ++j)
                    rec[j] = data[i + j];
                records.push_back(rec);
            }
            break;
        }
        case DNSEncodingScheme::IP_ENCODING_AAAA: {
            for (size_t i = 0; i < len; i += 16) {
                std::vector<uint8_t> rec(16, 0);
                for (size_t j = 0; j < 16 && (i + j) < len; ++j)
                    rec[j] = data[i + j];
                records.push_back(rec);
            }
            break;
        }
        default: {
            std::string encoded = base64url_encode(data, len);
            records.push_back({encoded.begin(), encoded.end()});
            break;
        }
    }
    return records;
}

std::vector<uint8_t> SubdomainEncoder::decode_downstream(
    const std::vector<std::string>& records, DNSEncodingScheme scheme) {
    std::vector<uint8_t> result;

    switch (scheme) {
        case DNSEncodingScheme::BASE64_TXT: {
            std::string combined;
            for (const auto& r : records) combined += r;
            result = base64url_decode(combined);
            break;
        }
        case DNSEncodingScheme::IP_ENCODING_A:
        case DNSEncodingScheme::IP_ENCODING_AAAA: {
            for (const auto& r : records)
                result.insert(result.end(), r.begin(), r.end());
            break;
        }
        default: {
            std::string combined;
            for (const auto& r : records) combined += r;
            result = base64url_decode(combined);
            break;
        }
    }
    return result;
}

// ==================== ChunkReassembler ====================
// FIX #6: MAX_TOTAL_CHUNKS cap to prevent OOM on malicious headers

ChunkReassembler::ChunkReassembler(size_t max_buffer_size)
    : max_buffer_(max_buffer_size) {}

bool ChunkReassembler::add_chunk(const DNSChunkHeader& header,
                                  const uint8_t* payload, size_t len) {
    if (!header_seen_) {
        // FIX #6: Reject unreasonable total_chunks to prevent OOM
        if (header.total_chunks > MAX_TOTAL_CHUNKS || header.total_chunks == 0) {
            return false;
        }
        total_expected_ = header.total_chunks;
        slots_.resize(total_expected_);
        header_seen_ = true;
    }

    if (header.sequence_number >= slots_.size()) return false;
    if (slots_[header.sequence_number].received) return true; // duplicate

    size_t current_size = bytes_buffered();
    if (current_size + len > max_buffer_) return false;

    slots_[header.sequence_number].data.assign(payload, payload + len);
    slots_[header.sequence_number].received = true;
    ++received_count_;
    return true;
}

bool ChunkReassembler::is_complete() const {
    return header_seen_ && received_count_ == total_expected_;
}

std::vector<uint8_t> ChunkReassembler::extract() {
    if (!is_complete()) return {};
    std::vector<uint8_t> result;
    for (const auto& slot : slots_) {
        result.insert(result.end(), slot.data.begin(), slot.data.end());
    }
    reset();
    return result;
}

void ChunkReassembler::reset() {
    slots_.clear();
    received_count_ = 0;
    total_expected_ = 0;
    header_seen_ = false;
}

size_t ChunkReassembler::chunks_received() const { return received_count_; }
size_t ChunkReassembler::chunks_expected() const { return total_expected_; }

size_t ChunkReassembler::bytes_buffered() const {
    size_t total = 0;
    for (const auto& slot : slots_) {
        if (slot.received) total += slot.data.size();
    }
    return total;
}

// ==================== DNSCovertChannel ====================

DNSCovertChannel::DNSCovertChannel()
    : DNSCovertChannel(DNSCovertConfig{}) {}

DNSCovertChannel::DNSCovertChannel(const DNSCovertConfig& config)
    : config_(config) {
    doh_client_ = std::make_unique<DoHClient>(config_.doh_config);
    encoder_ = std::make_unique<SubdomainEncoder>(config_);
    reassembler_ = std::make_unique<ChunkReassembler>(config_.rx_buffer_max);
    randombytes_buf(&session_id_, sizeof(session_id_));
}

DNSCovertChannel::~DNSCovertChannel() {
    close();
}

bool DNSCovertChannel::open() {
    if (state_.load() == ChannelState::OPEN) return true;
    state_.store(ChannelState::OPENING);

    try {
        if (config_.authoritative_zone.empty()) {
            NCP_LOG_ERROR("DNS covert channel: authoritative_zone not configured");
            state_.store(ChannelState::ERROR);
            return false;
        }

        auto test = doh_client_->resolve("cloudflare.com", DoHClient::RecordType::A);
        if (test.addresses.empty() && !test.error_message.empty()) {
            NCP_LOG_WARN("DNS covert channel: DoH test query failed: " + test.error_message);
        }

        running_.store(true);
        tx_thread_ = std::thread([this] { tx_worker_func(); });

        if (config_.mix_legitimate_queries && !config_.cover_domains.empty()) {
            cover_thread_ = std::thread([this] { cover_traffic_func(); });
        }

        state_.store(ChannelState::OPEN);
        NCP_LOG_INFO("DNS covert channel opened (zone: " + config_.authoritative_zone + ")");
        return true;
    } catch (const std::exception& e) {
        NCP_LOG_ERROR("DNS covert channel open failed: " + std::string(e.what()));
        state_.store(ChannelState::ERROR);
        return false;
    }
}

void DNSCovertChannel::close() {
    if (state_.load() == ChannelState::CLOSED) return;
    state_.store(ChannelState::CLOSING);
    running_.store(false);

    tx_cv_.notify_all();
    rx_cv_.notify_all();

    if (tx_thread_.joinable()) tx_thread_.join();
    if (rx_thread_.joinable()) rx_thread_.join();
    if (cover_thread_.joinable()) cover_thread_.join();

    state_.store(ChannelState::CLOSED);
    NCP_LOG_INFO("DNS covert channel closed");
}

bool DNSCovertChannel::is_open() const {
    auto s = state_.load();
    return s == ChannelState::OPEN || s == ChannelState::DEGRADED;
}

ChannelState DNSCovertChannel::state() const {
    return state_.load();
}

// FIX #1: send() only fragments into TxItems with raw payload + metadata.
// No framing here — framing happens exclusively in send_chunk().
size_t DNSCovertChannel::send(const uint8_t* data, size_t len) {
    if (!is_open() || len == 0) return 0;

    // Optionally encrypt
    std::vector<uint8_t> payload;
    if (config_.encrypt_payload && !config_.channel_key.empty()) {
        payload = encrypt_payload(data, len);
    } else {
        payload.assign(data, data + len);
    }

    // Calculate usable payload per chunk (minus framing overhead)
    size_t raw_capacity = encoder_->max_payload_per_query();
    if (raw_capacity <= DNSChunkHeader::OVERHEAD) return 0;
    size_t usable = raw_capacity - DNSChunkHeader::OVERHEAD;

    uint16_t total = static_cast<uint16_t>((payload.size() + usable - 1) / usable);

    // Queue raw payload chunks — lock tx_mutex_ only
    {
        std::lock_guard<std::mutex> lock(tx_mutex_);
        if (tx_queue_.size() + total > config_.tx_queue_max) {
            NCP_LOG_WARN("DNS covert channel: TX queue full");
            return 0;
        }

        for (uint16_t seq = 0; seq < total; ++seq) {
            size_t offset = seq * usable;
            size_t chunk_len = std::min(usable, payload.size() - offset);

            TxItem item;
            item.header.sequence_number = seq;
            item.header.total_chunks = total;
            item.header.payload_length = static_cast<uint16_t>(chunk_len);
            if (seq == total - 1) item.header.flags |= DNSChunkHeader::FLAG_LAST_CHUNK;
            if (config_.encrypt_payload) item.header.flags |= DNSChunkHeader::FLAG_ENCRYPTED;

            item.payload.assign(payload.begin() + offset,
                               payload.begin() + offset + chunk_len);
            tx_queue_.push(std::move(item));
        }
    }
    tx_cv_.notify_one();

    // Update stats — lock stats_mutex_ only (not nested in tx_mutex_)
    // FIX #3: Consistent lock order — never nest stats inside tx
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        dns_stats_.payload_bytes_upstream += len;
        base_stats_.bytes_sent += len;
        base_stats_.messages_sent++;
    }

    return len;
}

size_t DNSCovertChannel::receive(uint8_t* buf, size_t max_len) {
    std::unique_lock<std::mutex> lock(rx_mutex_);
    rx_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
        return !rx_buffer_.empty() || !running_.load();
    });

    if (rx_buffer_.empty()) return 0;

    size_t to_copy = std::min(max_len, rx_buffer_.size());
    std::memcpy(buf, rx_buffer_.data(), to_copy);
    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + to_copy);

    // stats_mutex_ only (rx_mutex_ released above? no, still held — but
    // rx_mutex_ is never locked inside tx_mutex_ or stats_mutex_, so OK)
    {
        std::lock_guard<std::mutex> slock(stats_mutex_);
        base_stats_.bytes_received += to_copy;
        base_stats_.messages_received++;
    }

    return to_copy;
}

ChannelStats DNSCovertChannel::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return base_stats_;
}

double DNSCovertChannel::max_capacity_bps() const {
    double payload = static_cast<double>(encoder_->max_payload_per_query());
    double interval_sec = config_.min_query_interval_ms / 1000.0;
    if (interval_sec <= 0) interval_sec = 0.05;
    return (payload * 8.0) / interval_sec;
}

DNSCovertStats DNSCovertChannel::get_dns_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return dns_stats_;
}

void DNSCovertChannel::set_detection_callback(DetectionCallback cb) {
    std::lock_guard<std::mutex> lock(detection_mutex_);
    detection_cb_ = std::move(cb);
}

void DNSCovertChannel::on_detection(const CovertDetectionEvent& event) {
    if (event.confidence > 0.7) {
        NCP_LOG_WARN("DNS covert channel: detection event (confidence: " +
                     std::to_string(event.confidence) + "): " + event.details);
        if (event.confidence > 0.9) {
            state_.store(ChannelState::DEGRADED);
        }
    }
    std::lock_guard<std::mutex> lock(detection_mutex_);
    if (detection_cb_) {
        detection_cb_(event);
    }
}

// FIX #2: set_config() requires CLOSED state. Thread-safe: no race
// with tx_worker because workers only run when state is OPEN.
bool DNSCovertChannel::set_config(const DNSCovertConfig& config) {
    if (state_.load() != ChannelState::CLOSED) {
        NCP_LOG_ERROR("DNS covert channel: set_config() requires CLOSED state "
                      "(current: " + std::string(channel_state_to_string(state_.load())) + ")");
        return false;
    }
    config_ = config;
    encoder_ = std::make_unique<SubdomainEncoder>(config_);
    doh_client_ = std::make_unique<DoHClient>(config_.doh_config);
    reassembler_ = std::make_unique<ChunkReassembler>(config_.rx_buffer_max);
    return true;
}

DNSCovertConfig DNSCovertChannel::get_config() const {
    return config_;
}

void DNSCovertChannel::send_cover_query() {
    if (config_.cover_domains.empty()) return;

    // FIX #4: Use randombytes_uniform() — no modulo bias
    uint32_t idx = randombytes_uniform(static_cast<uint32_t>(config_.cover_domains.size()));

    auto result = doh_client_->resolve(config_.cover_domains[idx], DoHClient::RecordType::A);
    (void)result;

    std::lock_guard<std::mutex> lock(stats_mutex_);
    dns_stats_.cover_queries_sent++;
}

void DNSCovertChannel::set_server_mode(bool enabled) {
    server_mode_ = enabled;
}

bool DNSCovertChannel::is_server_mode() const {
    return server_mode_;
}

uint16_t DNSCovertChannel::session_id() const {
    return session_id_;
}

void DNSCovertChannel::rotate_session() {
    randombytes_buf(&session_id_, sizeof(session_id_));
    reassembler_->reset();
}

// ==================== Worker Threads ====================

// FIX #3: Lock order fixed — tx_mutex_ THEN stats_mutex_, never reversed.
void DNSCovertChannel::tx_worker_func() {
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
        // tx_mutex_ released here

        auto delay = next_query_delay();
        if (delay.count() > 0) {
            std::this_thread::sleep_for(delay);
        }

        if (!send_chunk(item.header, item.payload.data(), item.payload.size())) {
            // FIX #3: Lock tx_mutex_ FIRST, then stats_mutex_ — correct order
            {
                std::lock_guard<std::mutex> tlock(tx_mutex_);
                if (tx_queue_.size() < config_.tx_queue_max) {
                    tx_queue_.push(std::move(item));
                }
            }
            {
                std::lock_guard<std::mutex> slock(stats_mutex_);
                dns_stats_.retries++;
                base_stats_.errors++;
            }
        }

        // FIX #7: Update stealth score every 10 queries
        {
            std::lock_guard<std::mutex> slock(stats_mutex_);
            stealth_update_counter_++;
        }
        // Check outside lock (read of counter is approximate, OK for heuristic)
        if (stealth_update_counter_ % 10 == 0) {
            update_stealth_score();
        }
    }
}

void DNSCovertChannel::rx_worker_func() {
    // Placeholder — downstream data arrives in-band via process_response().
    // This thread is NOT started in open(), so no resource waste.
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// FIX #5: Guard against division by zero in cover_traffic_ratio
void DNSCovertChannel::cover_traffic_func() {
    while (running_.load()) {
        auto delay = next_query_delay();
        double ratio = config_.cover_traffic_ratio;
        if (ratio <= 0.0) ratio = 1.0; // FIX #5: prevent div/0
        double cover_delay_ms = delay.count() / ratio;
        std::this_thread::sleep_for(std::chrono::milliseconds(
            static_cast<int64_t>(cover_delay_ms)));

        if (!running_.load()) break;
        send_cover_query();
    }
}

// FIX #1: send_chunk() is the SINGLE framing point.
// Builds [header][payload][crc32], then passes raw frame bytes
// to encode_upstream_raw() which is a PURE base32hex encoder.
bool DNSCovertChannel::send_chunk(const DNSChunkHeader& header,
                                   const uint8_t* payload, size_t len) {
    // Build frame: [7B header][NB payload][4B CRC32]
    auto hdr_bytes = header.serialize();
    std::vector<uint8_t> frame;
    frame.reserve(DNSChunkHeader::HEADER_SIZE + len + DNSChunkHeader::CRC_SIZE);
    frame.insert(frame.end(), hdr_bytes.begin(), hdr_bytes.end());
    frame.insert(frame.end(), payload, payload + len);
    uint32_t crc = crc32_compute(frame.data(), frame.size());
    frame.push_back(static_cast<uint8_t>(crc >> 24));
    frame.push_back(static_cast<uint8_t>(crc >> 16));
    frame.push_back(static_cast<uint8_t>(crc >> 8));
    frame.push_back(static_cast<uint8_t>(crc & 0xFF));

    // FIX #1: encode_upstream_raw() is a PURE encoder — just base32hex + labels
    auto queries = encoder_->encode_upstream_raw(frame.data(), frame.size(),
                                                  header.sequence_number);
    if (queries.empty()) return false;

    bool success = true;
    for (const auto& qname : queries) {
        auto result = doh_client_->resolve(qname, DoHClient::RecordType::TXT);

        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            dns_stats_.queries_sent++;
            dns_stats_.encoding_overhead_bytes += qname.size();
        }

        if (!result.error_message.empty()) {
            success = false;
            std::lock_guard<std::mutex> lock(stats_mutex_);
            dns_stats_.timeouts++;
        }

        if (!result.addresses.empty() || !result.cnames.empty()) {
            process_response(result);
        }

        // Track timing for stealth scoring
        auto now = std::chrono::steady_clock::now();
        if (last_query_time_ != std::chrono::steady_clock::time_point{}) {
            double interval_ms = std::chrono::duration<double, std::milli>(
                now - last_query_time_).count();
            recent_intervals_.push_back(interval_ms);
            if (recent_intervals_.size() > 100) {
                recent_intervals_.erase(recent_intervals_.begin());
            }
        }
        last_query_time_ = now;
    }

    return success;
}

bool DNSCovertChannel::process_response(const DoHClient::DNSResult& result) {
    if (result.addresses.empty() && result.cnames.empty()) return false;

    std::vector<std::string> txt_records;
    for (const auto& addr : result.addresses) {
        txt_records.push_back(addr);
    }

    if (txt_records.empty()) return false;

    auto decoded = encoder_->decode_downstream(txt_records, config_.downstream_encoding);
    if (decoded.empty()) return false;

    if (config_.encrypt_payload && !config_.channel_key.empty()) {
        decoded = decrypt_payload(decoded.data(), decoded.size());
        if (decoded.empty()) return false;
    }

    {
        std::lock_guard<std::mutex> lock(rx_mutex_);
        rx_buffer_.insert(rx_buffer_.end(), decoded.begin(), decoded.end());
    }
    rx_cv_.notify_one();

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        dns_stats_.payload_bytes_downstream += decoded.size();
        dns_stats_.queries_received++;
    }

    return true;
}

// ==================== Crypto ====================

std::vector<uint8_t> DNSCovertChannel::encrypt_payload(
    const uint8_t* data, size_t len) const {

    if (config_.channel_key.size() < crypto_secretbox_KEYBYTES) {
        return {data, data + len};
    }

    std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<uint8_t> ciphertext(crypto_secretbox_MACBYTES + len);
    crypto_secretbox_easy(ciphertext.data(), data, len,
                          nonce.data(), config_.channel_key.data());

    std::vector<uint8_t> result;
    result.reserve(nonce.size() + ciphertext.size());
    result.insert(result.end(), nonce.begin(), nonce.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

std::vector<uint8_t> DNSCovertChannel::decrypt_payload(
    const uint8_t* data, size_t len) const {

    if (config_.channel_key.size() < crypto_secretbox_KEYBYTES) {
        return {data, data + len};
    }
    if (len < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return {};
    }

    const uint8_t* nonce = data;
    const uint8_t* ciphertext = data + crypto_secretbox_NONCEBYTES;
    size_t ciphertext_len = len - crypto_secretbox_NONCEBYTES;

    std::vector<uint8_t> plaintext(ciphertext_len - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plaintext.data(), ciphertext, ciphertext_len,
                                    nonce, config_.channel_key.data()) != 0) {
        return {};
    }
    return plaintext;
}

// ==================== Stealth ====================

// FIX #7: Now actually called every 10 queries from tx_worker_func()
void DNSCovertChannel::update_stealth_score() {
    double score = 1.0;

    // Factor 1: Query frequency
    if (!recent_intervals_.empty()) {
        double avg_interval = std::accumulate(recent_intervals_.begin(),
                                               recent_intervals_.end(), 0.0) /
                              recent_intervals_.size();
        if (avg_interval < 100.0) score -= 0.3;
    }

    // Factor 2: Cover traffic ratio
    std::lock_guard<std::mutex> lock(stats_mutex_);
    uint64_t total = dns_stats_.queries_sent + dns_stats_.cover_queries_sent;
    if (total > 0) {
        double cover_ratio = static_cast<double>(dns_stats_.cover_queries_sent) / total;
        if (cover_ratio < 0.1) score -= 0.2;
    }

    // Factor 3: Error rate
    if (dns_stats_.queries_sent > 0) {
        double err_rate = static_cast<double>(dns_stats_.timeouts) / dns_stats_.queries_sent;
        if (err_rate > 0.1) score -= 0.2;
    }

    dns_stats_.stealth_score = std::max(0.0, std::min(1.0, score));
    base_stats_.stealthiness_score = dns_stats_.stealth_score;
}

// FIX #4: Use 4294967296.0 (2^32) instead of UINT32_MAX for correct [0, 1) range
std::chrono::milliseconds DNSCovertChannel::next_query_delay() const {
    double base = config_.min_query_interval_ms +
        (config_.max_query_interval_ms - config_.min_query_interval_ms) * 0.3;

    double jitter_range = base * config_.jitter_factor;
    uint32_t r;
    randombytes_buf(&r, sizeof(r));
    double jitter = (static_cast<double>(r) / 4294967296.0 - 0.5) * 2.0 * jitter_range;

    double delay = std::max(config_.min_query_interval_ms, base + jitter);
    return std::chrono::milliseconds(static_cast<int64_t>(delay));
}

// ==================== CovertChannelManager ====================

struct CovertChannelManager::Impl {
    Config config;
    std::vector<std::shared_ptr<ICovertChannel>> channels;
    mutable std::mutex channels_mutex;
    std::atomic<bool> running{false};
    std::function<void(const std::string&, const CovertDetectionEvent&)> escalation_cb;
    std::thread health_thread;

    void health_check() {
        while (running.load()) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config.health_check_interval_ms));
            if (!running.load()) break;

            std::lock_guard<std::mutex> lock(channels_mutex);
            for (auto& ch : channels) {
                auto stats = ch->get_stats();
                if (stats.stealthiness_score < config.detection_threshold) {
                    CovertDetectionEvent event;
                    event.type = CovertDetectionEvent::Type::STATISTICAL_ANOMALY;
                    event.confidence = 1.0 - stats.stealthiness_score;
                    event.details = ch->channel_type() + " stealth below threshold";
                    event.timestamp = std::chrono::system_clock::now();
                    ch->on_detection(event);
                    if (escalation_cb) {
                        escalation_cb(ch->channel_type(), event);
                    }
                }
            }
        }
    }
};

CovertChannelManager::CovertChannelManager()
    : CovertChannelManager(Config{}) {}

CovertChannelManager::CovertChannelManager(const Config& config)
    : impl_(std::make_unique<Impl>()) {
    impl_->config = config;
}

CovertChannelManager::~CovertChannelManager() {
    stop();
}

void CovertChannelManager::add_channel(std::shared_ptr<ICovertChannel> channel) {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    impl_->channels.push_back(std::move(channel));
}

void CovertChannelManager::remove_channel(const std::string& channel_type) {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    impl_->channels.erase(
        std::remove_if(impl_->channels.begin(), impl_->channels.end(),
            [&](const auto& ch) { return ch->channel_type() == channel_type; }),
        impl_->channels.end());
}

std::vector<std::string> CovertChannelManager::active_channels() const {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    std::vector<std::string> result;
    for (const auto& ch : impl_->channels) {
        if (ch->is_open()) result.push_back(ch->channel_type());
    }
    return result;
}

size_t CovertChannelManager::send(const uint8_t* data, size_t len) {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);

    std::shared_ptr<ICovertChannel> best;
    double best_score = -1.0;
    for (auto& ch : impl_->channels) {
        if (!ch->is_open()) continue;
        auto stats = ch->get_stats();
        if (stats.stealthiness_score > best_score) {
            best_score = stats.stealthiness_score;
            best = ch;
        }
    }

    if (!best) return 0;
    return best->send(data, len);
}

size_t CovertChannelManager::receive(uint8_t* buf, size_t max_len) {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    for (auto& ch : impl_->channels) {
        if (!ch->is_open()) continue;
        size_t n = ch->receive(buf, max_len);
        if (n > 0) return n;
    }
    return 0;
}

void CovertChannelManager::start() {
    impl_->running.store(true);
    impl_->health_thread = std::thread([this] { impl_->health_check(); });
}

void CovertChannelManager::stop() {
    impl_->running.store(false);
    if (impl_->health_thread.joinable()) impl_->health_thread.join();
}

bool CovertChannelManager::is_running() const {
    return impl_->running.load();
}

ChannelStats CovertChannelManager::aggregate_stats() const {
    std::lock_guard<std::mutex> lock(impl_->channels_mutex);
    ChannelStats total;
    for (const auto& ch : impl_->channels) {
        auto s = ch->get_stats();
        total.bytes_sent += s.bytes_sent;
        total.bytes_received += s.bytes_received;
        total.messages_sent += s.messages_sent;
        total.messages_received += s.messages_received;
        total.errors += s.errors;
        total.estimated_bps += s.estimated_bps;
    }
    if (!impl_->channels.empty()) {
        total.stealthiness_score = 0;
        for (const auto& ch : impl_->channels) {
            total.stealthiness_score += ch->get_stats().stealthiness_score;
        }
        total.stealthiness_score /= impl_->channels.size();
    }
    return total;
}

void CovertChannelManager::set_escalation_callback(
    std::function<void(const std::string&, const CovertDetectionEvent&)> cb) {
    impl_->escalation_cb = std::move(cb);
}

} // namespace covert
} // namespace ncp
