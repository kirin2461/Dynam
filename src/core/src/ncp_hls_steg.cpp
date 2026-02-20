/**
 * @file ncp_hls_steg.cpp
 * @brief HLS Video Steganography — implementation
 *
 * MPEG-TS adaptation field stuffing + NULL packet covert channel.
 * Follows review-hardened patterns from DNS covert channel.
 */

#include "include/ncp_covert_channel.hpp"
#include "include/ncp_hls_steg.hpp"
#include "include/ncp_logger.hpp"

#include <sodium.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <fstream>

namespace ncp {
namespace covert {

// ==================== TSPacketBuilder ====================

TSPacketBuilder::TSPacketBuilder() {}

size_t TSPacketBuilder::max_covert_in_af(size_t total_af_length) {
    // AF: [1B length][1B flags][stuffing...]
    // Covert frame inside stuffing: [1B marker][2B length][data]
    if (total_af_length <= TS_AF_MIN_SIZE + COVERT_FRAME_OVERHEAD) return 0;
    return total_af_length - TS_AF_MIN_SIZE - COVERT_FRAME_OVERHEAD;
}

std::vector<uint8_t> TSPacketBuilder::build_af_stuffing_packet(
    uint16_t pid,
    uint8_t continuity_counter,
    const uint8_t* real_payload, size_t payload_len,
    const uint8_t* covert_data, size_t covert_len) {

    std::vector<uint8_t> packet(TS_PACKET_SIZE, 0xFF);

    // === TS header (4 bytes) ===
    packet[0] = TS_SYNC_BYTE;  // sync
    packet[1] = static_cast<uint8_t>((pid >> 8) & 0x1F); // TEI=0, PUSI=0, TP=0, PID hi
    packet[2] = static_cast<uint8_t>(pid & 0xFF);         // PID lo
    // AFC=11 (both AF and payload), CC
    packet[3] = 0x30 | (continuity_counter & 0x0F);

    // === Adaptation field ===
    // AF length = stuffing + 1 (flags) = total_packet - header - real_payload
    size_t af_total = TS_PACKET_SIZE - TS_HEADER_SIZE - payload_len;
    if (af_total < 2) af_total = 2;
    packet[4] = static_cast<uint8_t>(af_total - 1); // AF length (excludes length byte itself)
    packet[5] = 0x00; // AF flags: no indicators

    // Stuffing region starts at offset 6
    size_t stuffing_start = TS_HEADER_SIZE + 2; // 4 (header) + 1 (af_len) + 1 (flags)
    size_t stuffing_len = af_total - 2;

    // Embed covert data in stuffing
    if (covert_len > 0 && covert_len + COVERT_FRAME_OVERHEAD <= stuffing_len) {
        packet[stuffing_start] = COVERT_MARKER;
        packet[stuffing_start + 1] = static_cast<uint8_t>((covert_len >> 8) & 0xFF);
        packet[stuffing_start + 2] = static_cast<uint8_t>(covert_len & 0xFF);
        std::memcpy(&packet[stuffing_start + COVERT_FRAME_OVERHEAD],
                    covert_data, covert_len);
        // Rest of stuffing stays 0xFF
    }
    // else: all stuffing is 0xFF (legitimate padding)

    // === Payload ===
    if (payload_len > 0 && real_payload) {
        size_t payload_start = TS_HEADER_SIZE + af_total;
        std::memcpy(&packet[payload_start], real_payload,
                    std::min(payload_len, TS_PACKET_SIZE - payload_start));
    }

    return packet;
}

std::vector<uint8_t> TSPacketBuilder::build_null_packet(
    const uint8_t* covert_data, size_t covert_len,
    uint8_t continuity_counter) {

    std::vector<uint8_t> packet(TS_PACKET_SIZE, 0xFF);

    // NULL packet header
    packet[0] = TS_SYNC_BYTE;
    packet[1] = 0x1F; // PID 0x1FFF high
    packet[2] = 0xFF; // PID 0x1FFF low
    packet[3] = 0x10 | (continuity_counter & 0x0F); // AFC=01 (payload only), CC

    // Payload area: embed covert data with framing
    if (covert_len > 0 && covert_len + COVERT_FRAME_OVERHEAD <= TS_MAX_PAYLOAD) {
        packet[TS_HEADER_SIZE] = COVERT_MARKER;
        packet[TS_HEADER_SIZE + 1] = static_cast<uint8_t>((covert_len >> 8) & 0xFF);
        packet[TS_HEADER_SIZE + 2] = static_cast<uint8_t>(covert_len & 0xFF);
        std::memcpy(&packet[TS_HEADER_SIZE + COVERT_FRAME_OVERHEAD],
                    covert_data, covert_len);
    }

    return packet;
}

TSPacketBuilder::ParsedPacket TSPacketBuilder::parse_packet(const uint8_t* pkt) {
    ParsedPacket result;

    if (pkt[0] != TS_SYNC_BYTE) return result;

    result.pid = (static_cast<uint16_t>(pkt[1] & 0x1F) << 8) | pkt[2];
    uint8_t afc = (pkt[3] >> 4) & 0x03;
    result.continuity_counter = pkt[3] & 0x0F;
    result.has_adaptation_field = (afc & 0x02) != 0;
    result.has_payload = (afc & 0x01) != 0;
    result.is_null_packet = (result.pid == TS_NULL_PID);

    size_t offset = TS_HEADER_SIZE;

    if (result.has_adaptation_field && offset < TS_PACKET_SIZE) {
        uint8_t af_len = pkt[offset];
        offset++; // skip length byte

        if (af_len > 0 && offset < TS_PACKET_SIZE) {
            offset++; // skip flags byte
            size_t stuffing_start = offset;
            size_t stuffing_end = TS_HEADER_SIZE + 1 + af_len;
            result.stuffing_bytes = (stuffing_end > stuffing_start)
                                    ? stuffing_end - stuffing_start : 0;

            // Check for covert marker in stuffing
            if (result.stuffing_bytes >= COVERT_FRAME_OVERHEAD &&
                pkt[stuffing_start] == COVERT_MARKER) {
                uint16_t data_len =
                    (static_cast<uint16_t>(pkt[stuffing_start + 1]) << 8) |
                    pkt[stuffing_start + 2];
                if (data_len > 0 &&
                    stuffing_start + COVERT_FRAME_OVERHEAD + data_len <= stuffing_end) {
                    result.covert_data.assign(
                        pkt + stuffing_start + COVERT_FRAME_OVERHEAD,
                        pkt + stuffing_start + COVERT_FRAME_OVERHEAD + data_len);
                }
            }

            offset = stuffing_end;
        }
    }

    // For NULL packets, check payload for covert data
    if (result.is_null_packet && result.has_payload) {
        size_t payload_start = offset;
        if (payload_start + COVERT_FRAME_OVERHEAD < TS_PACKET_SIZE &&
            pkt[payload_start] == COVERT_MARKER) {
            uint16_t data_len =
                (static_cast<uint16_t>(pkt[payload_start + 1]) << 8) |
                pkt[payload_start + 2];
            if (data_len > 0 &&
                payload_start + COVERT_FRAME_OVERHEAD + data_len <= TS_PACKET_SIZE) {
                result.covert_data.assign(
                    pkt + payload_start + COVERT_FRAME_OVERHEAD,
                    pkt + payload_start + COVERT_FRAME_OVERHEAD + data_len);
            }
        }
    }

    // Extract real payload
    if (result.has_payload && !result.is_null_packet && offset < TS_PACKET_SIZE) {
        result.real_payload.assign(pkt + offset, pkt + TS_PACKET_SIZE);
    }

    return result;
}

// ==================== HLSSegmentCodec ====================

HLSSegmentCodec::HLSSegmentCodec(const HLSStegConfig& config)
    : config_(config),
      builder_(std::make_unique<TSPacketBuilder>()) {
    init_chacha_key();
}

void HLSSegmentCodec::init_chacha_key() {
    if (config_.channel_key.size() < crypto_stream_chacha20_KEYBYTES) {
        config_.channel_key.resize(crypto_stream_chacha20_KEYBYTES, 0);
    }
    if (config_.channel_nonce.size() < crypto_stream_chacha20_NONCEBYTES) {
        config_.channel_nonce.resize(crypto_stream_chacha20_NONCEBYTES, 0);
    }
}

std::vector<uint8_t> HLSSegmentCodec::derive_packet_nonce(uint64_t packet_index) const {
    std::vector<uint8_t> nonce(crypto_stream_chacha20_NONCEBYTES, 0);
    // XOR base nonce with packet index for per-packet uniqueness
    for (size_t i = 0; i < sizeof(packet_index) && i < nonce.size(); ++i) {
        nonce[i] = config_.channel_nonce[i] ^
                   static_cast<uint8_t>((packet_index >> (i * 8)) & 0xFF);
    }
    return nonce;
}

void HLSSegmentCodec::encrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index) {
    if (!config_.encrypt_stuffing || config_.channel_key.empty()) return;
    auto nonce = derive_packet_nonce(packet_index);
    // XOR with ChaCha20 keystream
    std::vector<uint8_t> keystream(len);
    crypto_stream_chacha20(keystream.data(), len,
                            nonce.data(), config_.channel_key.data());
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= keystream[i];
    }
}

void HLSSegmentCodec::decrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index) {
    // ChaCha20 is symmetric — encrypt = decrypt
    encrypt_stuffing(data, len, packet_index);
}

size_t HLSSegmentCodec::estimate_capacity(size_t segment_size) const {
    size_t n_packets = segment_size / TS_PACKET_SIZE;
    size_t capacity = 0;

    // AF stuffing capacity
    size_t stuffing_packets = static_cast<size_t>(
        n_packets * config_.max_stuffing_ratio);
    size_t avg_stuffing = (config_.min_stuffing_bytes + config_.max_stuffing_bytes) / 2;
    if (config_.carrier_mode != HLSStegConfig::CarrierMode::NULL_PACKETS_ONLY) {
        capacity += stuffing_packets * (avg_stuffing - TSPacketBuilder::COVERT_FRAME_OVERHEAD);
    }

    // NULL packet capacity
    if (config_.carrier_mode != HLSStegConfig::CarrierMode::AF_STUFFING_ONLY) {
        size_t null_packets = n_packets / config_.null_packet_interval;
        capacity += null_packets * (TS_MAX_PAYLOAD - TSPacketBuilder::COVERT_FRAME_OVERHEAD);
    }

    return capacity;
}

std::vector<uint8_t> HLSSegmentCodec::encode_segment(
    const std::vector<uint8_t>& input_segment,
    const uint8_t* covert_data, size_t covert_len) {

    std::vector<uint8_t> output;
    output.reserve(input_segment.size() + input_segment.size() / 10); // ~10% overhead

    size_t n_packets = input_segment.size() / TS_PACKET_SIZE;
    size_t covert_offset = 0;
    uint64_t pkt_index = 0;
    uint8_t null_cc = 0;

    for (size_t i = 0; i < n_packets; ++i) {
        const uint8_t* src = &input_segment[i * TS_PACKET_SIZE];
        auto parsed = builder_->parse_packet(src);

        bool inject_stuffing =
            (config_.carrier_mode != HLSStegConfig::CarrierMode::NULL_PACKETS_ONLY) &&
            covert_offset < covert_len &&
            (i % static_cast<size_t>(1.0 / config_.max_stuffing_ratio)) == 0;

        if (inject_stuffing && parsed.has_payload) {
            // Calculate stuffing size
            size_t stuff_avail = config_.max_stuffing_bytes;
            if (stuff_avail > TS_MAX_STUFFING) stuff_avail = TS_MAX_STUFFING;
            size_t max_covert = TSPacketBuilder::max_covert_in_af(stuff_avail + TS_AF_MIN_SIZE);
            size_t to_embed = std::min(max_covert, covert_len - covert_offset);

            if (to_embed > 0) {
                // Build modified packet with AF stuffing
                auto new_pkt = builder_->build_af_stuffing_packet(
                    parsed.pid,
                    parsed.continuity_counter,
                    parsed.real_payload.data(), parsed.real_payload.size(),
                    covert_data + covert_offset, to_embed);

                // Encrypt the covert portion of stuffing
                if (config_.encrypt_stuffing) {
                    size_t covert_start = TS_HEADER_SIZE + 2 + TSPacketBuilder::COVERT_FRAME_OVERHEAD;
                    if (covert_start + to_embed <= new_pkt.size()) {
                        encrypt_stuffing(&new_pkt[covert_start], to_embed, pkt_index);
                    }
                }

                output.insert(output.end(), new_pkt.begin(), new_pkt.end());
                covert_offset += to_embed;
                pkt_index++;
                continue; // skip normal copy
            }
        }

        // Copy original packet as-is
        output.insert(output.end(), src, src + TS_PACKET_SIZE);
        pkt_index++;

        // Insert NULL packet for additional capacity
        bool inject_null =
            (config_.carrier_mode != HLSStegConfig::CarrierMode::AF_STUFFING_ONLY) &&
            covert_offset < covert_len &&
            (i % config_.null_packet_interval) == 0;

        if (inject_null) {
            size_t to_embed = std::min(
                TSPacketBuilder::max_covert_in_null() - TSPacketBuilder::COVERT_FRAME_OVERHEAD,
                covert_len - covert_offset);

            auto null_pkt = builder_->build_null_packet(
                covert_data + covert_offset, to_embed, null_cc++);

            // Encrypt NULL packet covert data
            if (config_.encrypt_stuffing && to_embed > 0) {
                size_t covert_start = TS_HEADER_SIZE + TSPacketBuilder::COVERT_FRAME_OVERHEAD;
                if (covert_start + to_embed <= null_pkt.size()) {
                    encrypt_stuffing(&null_pkt[covert_start], to_embed, pkt_index);
                }
            }

            output.insert(output.end(), null_pkt.begin(), null_pkt.end());
            covert_offset += to_embed;
            pkt_index++;
        }
    }

    return output;
}

std::vector<uint8_t> HLSSegmentCodec::decode_segment(
    const std::vector<uint8_t>& modified_segment) {

    std::vector<uint8_t> extracted;
    size_t n_packets = modified_segment.size() / TS_PACKET_SIZE;
    uint64_t pkt_index = 0;

    for (size_t i = 0; i < n_packets; ++i) {
        const uint8_t* pkt = &modified_segment[i * TS_PACKET_SIZE];
        auto parsed = builder_->parse_packet(pkt);

        if (!parsed.covert_data.empty()) {
            // Decrypt if needed
            if (config_.encrypt_stuffing) {
                decrypt_stuffing(parsed.covert_data.data(),
                                parsed.covert_data.size(), pkt_index);
            }
            extracted.insert(extracted.end(),
                           parsed.covert_data.begin(),
                           parsed.covert_data.end());
        }
        pkt_index++;
    }

    return extracted;
}

// ==================== HLSStegChannel ====================

HLSStegChannel::HLSStegChannel()
    : HLSStegChannel(HLSStegConfig{}) {}

HLSStegChannel::HLSStegChannel(const HLSStegConfig& config)
    : config_(config) {
    codec_ = std::make_unique<HLSSegmentCodec>(config_);
}

HLSStegChannel::~HLSStegChannel() {
    close();
}

bool HLSStegChannel::open() {
    if (state_.load() == ChannelState::OPEN) return true;
    state_.store(ChannelState::OPENING);

    running_.store(true);
    state_.store(ChannelState::OPEN);
    NCP_LOG_INFO("HLS steg channel opened");
    return true;
}

void HLSStegChannel::close() {
    if (state_.load() == ChannelState::CLOSED) return;
    state_.store(ChannelState::CLOSING);
    running_.store(false);

    tx_cv_.notify_all();
    rx_cv_.notify_all();

    if (encoder_thread_.joinable()) encoder_thread_.join();

    state_.store(ChannelState::CLOSED);
    NCP_LOG_INFO("HLS steg channel closed");
}

bool HLSStegChannel::is_open() const {
    auto s = state_.load();
    return s == ChannelState::OPEN || s == ChannelState::DEGRADED;
}

ChannelState HLSStegChannel::state() const {
    return state_.load();
}

size_t HLSStegChannel::send(const uint8_t* data, size_t len) {
    if (!is_open() || len == 0) return 0;

    std::vector<uint8_t> payload;
    if (!config_.channel_key.empty()) {
        payload = encrypt_payload(data, len);
    } else {
        payload.assign(data, data + len);
    }

    {
        std::lock_guard<std::mutex> lock(tx_mutex_);
        if (tx_queue_.size() >= config_.tx_queue_max) {
            NCP_LOG_WARN("HLS steg channel: TX queue full");
            return 0;
        }
        tx_queue_.push(std::move(payload));
    }
    tx_cv_.notify_one();

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        base_stats_.bytes_sent += len;
        base_stats_.messages_sent++;
        hls_stats_.payload_bytes_hidden += len;
    }

    return len;
}

size_t HLSStegChannel::receive(uint8_t* buf, size_t max_len) {
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
        hls_stats_.payload_bytes_extracted += to_copy;
    }
    return to_copy;
}

ChannelStats HLSStegChannel::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return base_stats_;
}

double HLSStegChannel::max_capacity_bps() const {
    // Theoretical: stuffing_ratio * bitrate
    return config_.target_bitrate_bps * config_.max_stuffing_ratio;
}

HLSStegStats HLSStegChannel::get_hls_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return hls_stats_;
}

void HLSStegChannel::set_detection_callback(DetectionCallback cb) {
    std::lock_guard<std::mutex> lock(detection_mutex_);
    detection_cb_ = std::move(cb);
}

void HLSStegChannel::on_detection(const CovertDetectionEvent& event) {
    if (event.confidence > 0.7) {
        NCP_LOG_WARN("HLS steg channel: detection event (confidence: " +
                     std::to_string(event.confidence) + ")");
        if (event.confidence > 0.9) {
            state_.store(ChannelState::DEGRADED);
        }
    }
    std::lock_guard<std::mutex> lock(detection_mutex_);
    if (detection_cb_) detection_cb_(event);
}

bool HLSStegChannel::set_config(const HLSStegConfig& config) {
    if (state_.load() != ChannelState::CLOSED) {
        NCP_LOG_ERROR("HLS steg channel: set_config() requires CLOSED state");
        return false;
    }
    config_ = config;
    codec_ = std::make_unique<HLSSegmentCodec>(config_);
    return true;
}

HLSStegConfig HLSStegChannel::get_config() const {
    return config_;
}

void HLSStegChannel::feed_segment(const std::vector<uint8_t>& segment_data) {
    auto extracted = codec_->decode_segment(segment_data);
    if (extracted.empty()) return;

    // Decrypt if encrypted
    if (!config_.channel_key.empty()) {
        extracted = decrypt_payload(extracted.data(), extracted.size());
        if (extracted.empty()) return;
    }

    {
        std::lock_guard<std::mutex> lock(rx_mutex_);
        rx_buffer_.insert(rx_buffer_.end(), extracted.begin(), extracted.end());
    }
    rx_cv_.notify_one();

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        hls_stats_.segments_parsed++;
        hls_stats_.payload_bytes_extracted += extracted.size();
        stealth_update_counter_++;
    }
    if (stealth_update_counter_ % 5 == 0) {
        update_stealth_score();
    }
}

std::vector<uint8_t> HLSStegChannel::get_encoded_segment(
    const std::vector<uint8_t>& input_segment) {

    // Get pending covert data from TX queue
    std::vector<uint8_t> covert_data;
    {
        std::lock_guard<std::mutex> lock(tx_mutex_);
        if (!tx_queue_.empty()) {
            covert_data = std::move(tx_queue_.front());
            tx_queue_.pop();
        }
    }

    if (covert_data.empty()) {
        return input_segment; // pass-through if nothing to embed
    }

    auto encoded = codec_->encode_segment(input_segment,
                                           covert_data.data(),
                                           covert_data.size());

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        hls_stats_.segments_created++;
        hls_stats_.ts_packets_written += encoded.size() / TS_PACKET_SIZE;
    }

    return encoded;
}

void HLSStegChannel::encoder_worker_func() {
    // In production: reads input TS segments from a source,
    // embeds pending covert data, writes to output directory.
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void HLSStegChannel::update_stealth_score() {
    double score = 1.0;

    std::lock_guard<std::mutex> lock(stats_mutex_);

    // Factor: stuffing ratio should not exceed configured max
    if (hls_stats_.ts_packets_written > 0) {
        double actual_ratio = static_cast<double>(
            hls_stats_.af_stuffing_packets + hls_stats_.null_packets_injected) /
            hls_stats_.ts_packets_written;
        if (actual_ratio > config_.max_stuffing_ratio * 1.2) {
            score -= 0.3; // exceeding expected ratio
        }
        hls_stats_.stuffing_ratio = actual_ratio;
    }

    // Factor: encrypted stuffing should look random (always true if encrypt_stuffing=true)
    if (!config_.encrypt_stuffing) {
        score -= 0.4; // unencrypted stuffing is detectable
    }

    hls_stats_.stealth_score = std::max(0.0, std::min(1.0, score));
    base_stats_.stealthiness_score = hls_stats_.stealth_score;
}

std::vector<uint8_t> HLSStegChannel::encrypt_payload(
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

std::vector<uint8_t> HLSStegChannel::decrypt_payload(
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

} // namespace covert
} // namespace ncp
