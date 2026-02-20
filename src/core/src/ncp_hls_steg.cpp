/**
 * @file ncp_hls_steg.cpp
 * @brief HLS Video Steganography — fake .m3u8 + .ts generator
 *
 * REFACTORED per architecture review:
 *   - Generates FAKE HLS stream (not MITM proxy)
 *   - NO internal payload encryption (Manager handles encrypt_aead/decrypt_aead)
 *   - Stuffing encryption is separate: ChaCha20 on stuffing bytes for stealth
 *     (makes stuffing statistically indistinguishable from random padding)
 *   - M3U8PlaylistGenerator produces valid playlists
 *   - TSPacketBuilder builds valid MPEG-TS packets from scratch
 */

#include "include/ncp_covert_channel.hpp"
#include "include/ncp_hls_steg.hpp"
#include "include/ncp_mimicry.hpp"
#include "include/ncp_logger.hpp"

#include <sodium.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <numeric>
#include <sstream>
#include <iomanip>

namespace ncp {
namespace covert {

// ==================== M3U8PlaylistGenerator ====================

M3U8PlaylistGenerator::M3U8PlaylistGenerator(double segment_duration)
    : segment_duration_(segment_duration) {}

std::string M3U8PlaylistGenerator::generate_playlist(
    size_t segment_count, size_t media_sequence) const {

    std::ostringstream oss;
    oss << "#EXTM3U\n";
    oss << "#EXT-X-VERSION:3\n";
    oss << "#EXT-X-TARGETDURATION:" << static_cast<int>(std::ceil(segment_duration_)) << "\n";
    oss << "#EXT-X-MEDIA-SEQUENCE:" << media_sequence << "\n";

    for (size_t i = 0; i < segment_count; ++i) {
        oss << "#EXTINF:" << std::fixed << std::setprecision(1)
            << segment_duration_ << ",\n";
        oss << segment_filename(media_sequence + i) << "\n";
    }

    return oss.str();
}

std::string M3U8PlaylistGenerator::segment_filename(size_t index) {
    std::ostringstream oss;
    oss << "segment_" << std::setw(6) << std::setfill('0') << index << ".ts";
    return oss.str();
}

// ==================== TSPacketBuilder ====================

TSPacketBuilder::TSPacketBuilder() {}

size_t TSPacketBuilder::max_covert_in_af(size_t total_af_length) {
    if (total_af_length <= TS_AF_MIN_SIZE + COVERT_FRAME_OVERHEAD) return 0;
    return total_af_length - TS_AF_MIN_SIZE - COVERT_FRAME_OVERHEAD;
}

std::vector<uint8_t> TSPacketBuilder::build_af_stuffing_packet(
    uint16_t pid,
    uint8_t continuity_counter,
    const uint8_t* real_payload, size_t payload_len,
    const uint8_t* covert_data, size_t covert_len) {

    std::vector<uint8_t> packet(TS_PACKET_SIZE, 0xFF);

    packet[0] = TS_SYNC_BYTE;
    packet[1] = static_cast<uint8_t>((pid >> 8) & 0x1F);
    packet[2] = static_cast<uint8_t>(pid & 0xFF);
    packet[3] = 0x30 | (continuity_counter & 0x0F); // AFC=11

    size_t af_total = TS_PACKET_SIZE - TS_HEADER_SIZE - payload_len;
    if (af_total < 2) af_total = 2;
    packet[4] = static_cast<uint8_t>(af_total - 1);
    packet[5] = 0x00; // AF flags

    size_t stuffing_start = TS_HEADER_SIZE + 2;
    size_t stuffing_len = af_total - 2;

    if (covert_len > 0 && covert_len + COVERT_FRAME_OVERHEAD <= stuffing_len) {
        packet[stuffing_start] = COVERT_MARKER;
        packet[stuffing_start + 1] = static_cast<uint8_t>((covert_len >> 8) & 0xFF);
        packet[stuffing_start + 2] = static_cast<uint8_t>(covert_len & 0xFF);
        std::memcpy(&packet[stuffing_start + COVERT_FRAME_OVERHEAD],
                    covert_data, covert_len);
    }

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

    packet[0] = TS_SYNC_BYTE;
    packet[1] = 0x1F;
    packet[2] = 0xFF;
    packet[3] = 0x10 | (continuity_counter & 0x0F);

    if (covert_len > 0 && covert_len + COVERT_FRAME_OVERHEAD <= TS_MAX_PAYLOAD) {
        packet[TS_HEADER_SIZE] = COVERT_MARKER;
        packet[TS_HEADER_SIZE + 1] = static_cast<uint8_t>((covert_len >> 8) & 0xFF);
        packet[TS_HEADER_SIZE + 2] = static_cast<uint8_t>(covert_len & 0xFF);
        std::memcpy(&packet[TS_HEADER_SIZE + COVERT_FRAME_OVERHEAD],
                    covert_data, covert_len);
    }

    return packet;
}

std::vector<uint8_t> TSPacketBuilder::build_fake_video_packet(
    uint16_t pid, uint8_t cc) {
    // Minimal valid PES packet inside TS
    std::vector<uint8_t> packet(TS_PACKET_SIZE, 0xFF);

    packet[0] = TS_SYNC_BYTE;
    packet[1] = 0x40 | static_cast<uint8_t>((pid >> 8) & 0x1F); // PUSI=1
    packet[2] = static_cast<uint8_t>(pid & 0xFF);
    packet[3] = 0x10 | (cc & 0x0F); // AFC=01 (payload only)

    // PES header: 00 00 01 E0 (video stream)
    packet[4] = 0x00;
    packet[5] = 0x00;
    packet[6] = 0x01;
    packet[7] = 0xE0; // stream_id = video
    // PES packet length (0 = unspecified for video)
    packet[8] = 0x00;
    packet[9] = 0x00;
    // Rest is fill data (looks like video elementary stream)
    // Fill with pseudo-random to avoid entropy anomaly
    randombytes_buf(&packet[10], TS_PACKET_SIZE - 10);

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
        offset++;

        if (af_len > 0 && offset < TS_PACKET_SIZE) {
            offset++; // skip flags
            size_t stuffing_start = offset;
            size_t stuffing_end = TS_HEADER_SIZE + 1 + af_len;
            result.stuffing_bytes = (stuffing_end > stuffing_start)
                                    ? stuffing_end - stuffing_start : 0;

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
    if (config_.stuffing_key.size() < crypto_stream_chacha20_KEYBYTES) {
        config_.stuffing_key.resize(crypto_stream_chacha20_KEYBYTES, 0);
    }
    if (config_.stuffing_nonce.size() < crypto_stream_chacha20_NONCEBYTES) {
        config_.stuffing_nonce.resize(crypto_stream_chacha20_NONCEBYTES, 0);
    }
}

std::vector<uint8_t> HLSSegmentCodec::derive_packet_nonce(uint64_t packet_index) const {
    std::vector<uint8_t> nonce(crypto_stream_chacha20_NONCEBYTES, 0);
    for (size_t i = 0; i < sizeof(packet_index) && i < nonce.size(); ++i) {
        nonce[i] = config_.stuffing_nonce[i] ^
                   static_cast<uint8_t>((packet_index >> (i * 8)) & 0xFF);
    }
    return nonce;
}

void HLSSegmentCodec::encrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index) {
    if (!config_.encrypt_stuffing || config_.stuffing_key.empty()) return;
    auto nonce = derive_packet_nonce(packet_index);
    std::vector<uint8_t> keystream(len);
    crypto_stream_chacha20(keystream.data(), len,
                            nonce.data(), config_.stuffing_key.data());
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= keystream[i];
    }
}

void HLSSegmentCodec::decrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index) {
    encrypt_stuffing(data, len, packet_index); // XOR is symmetric
}

size_t HLSSegmentCodec::estimate_capacity(size_t segment_size) const {
    size_t n_packets = segment_size / TS_PACKET_SIZE;
    size_t capacity = 0;

    size_t stuffing_packets = static_cast<size_t>(
        n_packets * config_.max_stuffing_ratio);
    size_t avg_stuffing = (config_.min_stuffing_bytes + config_.max_stuffing_bytes) / 2;
    if (config_.carrier_mode != HLSStegConfig::CarrierMode::NULL_PACKETS_ONLY) {
        capacity += stuffing_packets * (avg_stuffing - TSPacketBuilder::COVERT_FRAME_OVERHEAD);
    }

    if (config_.carrier_mode != HLSStegConfig::CarrierMode::AF_STUFFING_ONLY) {
        size_t null_packets = n_packets / config_.null_packet_interval;
        capacity += null_packets * (TS_MAX_PAYLOAD - TSPacketBuilder::COVERT_FRAME_OVERHEAD);
    }

    return capacity;
}

std::vector<uint8_t> HLSSegmentCodec::generate_segment(
    const uint8_t* covert_data, size_t covert_len,
    size_t target_segment_size) {

    // Calculate segment size based on bitrate and duration
    if (target_segment_size == 0) {
        double bytes_per_sec = config_.target_bitrate_bps / 8.0;
        target_segment_size = static_cast<size_t>(bytes_per_sec * config_.segment_duration_sec);
        // Round up to TS_PACKET_SIZE boundary
        target_segment_size = ((target_segment_size + TS_PACKET_SIZE - 1) / TS_PACKET_SIZE)
                              * TS_PACKET_SIZE;
    }

    size_t n_packets = target_segment_size / TS_PACKET_SIZE;
    std::vector<uint8_t> segment;
    segment.reserve(target_segment_size + target_segment_size / 10);

    size_t covert_offset = 0;
    uint64_t pkt_index = 0;
    uint8_t video_cc = 0;
    uint8_t null_cc = 0;

    for (size_t i = 0; i < n_packets; ++i) {
        // Decide packet type
        bool inject_null =
            (config_.carrier_mode != HLSStegConfig::CarrierMode::AF_STUFFING_ONLY) &&
            covert_offset < covert_len &&
            (i % config_.null_packet_interval) == 0 &&
            i > 0; // don't start with NULL

        bool inject_stuffing =
            (config_.carrier_mode != HLSStegConfig::CarrierMode::NULL_PACKETS_ONLY) &&
            covert_offset < covert_len &&
            !inject_null &&
            (i % static_cast<size_t>(1.0 / config_.max_stuffing_ratio)) == 0;

        if (inject_null) {
            size_t max_covert = TSPacketBuilder::max_covert_in_null()
                                - TSPacketBuilder::COVERT_FRAME_OVERHEAD;
            size_t to_embed = std::min(max_covert, covert_len - covert_offset);

            auto pkt = builder_->build_null_packet(
                covert_data + covert_offset, to_embed, null_cc++);

            if (config_.encrypt_stuffing && to_embed > 0) {
                size_t cs = TS_HEADER_SIZE + TSPacketBuilder::COVERT_FRAME_OVERHEAD;
                if (cs + to_embed <= pkt.size()) {
                    encrypt_stuffing(&pkt[cs], to_embed, pkt_index);
                }
            }

            segment.insert(segment.end(), pkt.begin(), pkt.end());
            covert_offset += to_embed;

        } else if (inject_stuffing) {
            // Fake video packet with AF stuffing carrying covert data
            size_t stuff_avail = config_.max_stuffing_bytes;
            if (stuff_avail > TS_MAX_STUFFING) stuff_avail = TS_MAX_STUFFING;
            size_t max_covert = TSPacketBuilder::max_covert_in_af(stuff_avail + TS_AF_MIN_SIZE);
            size_t to_embed = std::min(max_covert, covert_len - covert_offset);

            // Minimal real payload (PES start code)
            uint8_t pes_start[4] = {0x00, 0x00, 0x01, 0xE0};
            size_t payload_len = std::min(size_t(4),
                TS_MAX_PAYLOAD - stuff_avail - TS_AF_MIN_SIZE);

            auto pkt = builder_->build_af_stuffing_packet(
                config_.video_pid, video_cc++,
                pes_start, payload_len,
                covert_data + covert_offset, to_embed);

            if (config_.encrypt_stuffing && to_embed > 0) {
                size_t cs = TS_HEADER_SIZE + 2 + TSPacketBuilder::COVERT_FRAME_OVERHEAD;
                if (cs + to_embed <= pkt.size()) {
                    encrypt_stuffing(&pkt[cs], to_embed, pkt_index);
                }
            }

            segment.insert(segment.end(), pkt.begin(), pkt.end());
            covert_offset += to_embed;

        } else {
            // Normal fake video packet (no covert data)
            auto pkt = builder_->build_fake_video_packet(config_.video_pid, video_cc++);
            segment.insert(segment.end(), pkt.begin(), pkt.end());
        }

        pkt_index++;
    }

    return segment;
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

HLSStegChannel::HLSStegChannel(ncp::TrafficMimicry* mimicry,
                                 const HLSStegConfig& config)
    : mimicry_(mimicry),
      config_(config) {
    codec_ = std::make_unique<HLSSegmentCodec>(config_);
    playlist_gen_ = std::make_unique<M3U8PlaylistGenerator>(config_.segment_duration_sec);
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

    // NO encryption here — Manager handles it.
    std::vector<uint8_t> payload(data, data + len);

    {
        std::lock_guard<std::mutex> lock(tx_mutex_);
        if (tx_queue_.size() >= config_.tx_queue_max) {
            NCP_LOG_WARN("HLS steg: TX queue full");
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
        NCP_LOG_WARN("HLS steg: detection (confidence: " +
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
        NCP_LOG_ERROR("HLS steg: set_config() requires CLOSED state");
        return false;
    }
    config_ = config;
    codec_ = std::make_unique<HLSSegmentCodec>(config_);
    playlist_gen_ = std::make_unique<M3U8PlaylistGenerator>(config_.segment_duration_sec);
    return true;
}

HLSStegConfig HLSStegChannel::get_config() const {
    return config_;
}

void HLSStegChannel::feed_segment(const std::vector<uint8_t>& segment_data) {
    // NO decryption here — Manager wraps receive() with decrypt_aead.
    // We only extract from TS structure.
    auto extracted = codec_->decode_segment(segment_data);
    if (extracted.empty()) return;

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

std::vector<uint8_t> HLSStegChannel::get_encoded_segment() {
    std::vector<uint8_t> covert_data;
    {
        std::unique_lock<std::mutex> lock(tx_mutex_);
        tx_cv_.wait_for(lock, std::chrono::milliseconds(
            static_cast<int64_t>(config_.segment_duration_sec * 1000)), [this] {
            return !tx_queue_.empty() || !running_.load();
        });

        if (!tx_queue_.empty()) {
            covert_data = std::move(tx_queue_.front());
            tx_queue_.pop();
        }
    }

    // Generate fake segment (with or without covert data)
    auto segment = codec_->generate_segment(
        covert_data.empty() ? nullptr : covert_data.data(),
        covert_data.size());

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        hls_stats_.segments_created++;
        hls_stats_.ts_packets_written += segment.size() / TS_PACKET_SIZE;
        segment_counter_++;
    }

    return segment;
}

std::string HLSStegChannel::get_playlist() const {
    return playlist_gen_->generate_playlist(5, segment_counter_);
}

void HLSStegChannel::update_stealth_score() {
    double score = 1.0;
    std::lock_guard<std::mutex> lock(stats_mutex_);

    if (hls_stats_.ts_packets_written > 0) {
        double actual_ratio = static_cast<double>(
            hls_stats_.af_stuffing_packets + hls_stats_.null_packets_injected) /
            hls_stats_.ts_packets_written;
        if (actual_ratio > config_.max_stuffing_ratio * 1.2) {
            score -= 0.3;
        }
        hls_stats_.stuffing_ratio = actual_ratio;
    }

    if (!config_.encrypt_stuffing) {
        score -= 0.4; // unencrypted stuffing is detectable
    }

    hls_stats_.stealth_score = std::max(0.0, std::min(1.0, score));
    base_stats_.stealthiness_score = hls_stats_.stealth_score;
}

} // namespace covert
} // namespace ncp
