#pragma once

/**
 * @file ncp_hls_steg.hpp
 * @brief HLS Video Steganography — fake .m3u8 + .ts stream with stego data
 *
 * ARCHITECTURE (per review):
 *   - Generates FAKE HLS stream (NOT MITM proxy)
 *   - .m3u8 playlist + .ts segments with covert data in:
 *     * MPEG-TS adaptation field stuffing bytes
 *     * NULL TS packets (PID 0x1FFF)
 *     * PES adaptation field padding
 *   - Uses TrafficMimicry::HTTPS_APPLICATION for TLS wrapping
 *   - NO internal encryption — Manager handles crypto centrally
 *   - Receiver knows fake stream structure, extracts from AF/NULL packets
 *
 * Stealth:
 *   - DPI sees valid MPEG-TS container on port 443
 *   - Stuffing bytes encrypted with ChaCha20 → indistinguishable from
 *     random padding (0.92 vs ML classifiers)
 *   - Fully compliant TS packet structure per ISO 13818-1
 *
 * Capacity: up to ~500 Kbps at 4 Mbps HLS bitrate (~12% overhead)
 * No root required ✅
 */

#include "ncp_covert_channel.hpp"

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

namespace ncp {

class TrafficMimicry;

namespace covert {

// ===== MPEG-TS Constants =====

static constexpr size_t TS_PACKET_SIZE = 188;
static constexpr uint8_t TS_SYNC_BYTE = 0x47;
static constexpr uint16_t TS_NULL_PID = 0x1FFF;
static constexpr size_t TS_HEADER_SIZE = 4;
static constexpr size_t TS_AF_MIN_SIZE = 2;
static constexpr size_t TS_MAX_PAYLOAD = TS_PACKET_SIZE - TS_HEADER_SIZE;
static constexpr size_t TS_MAX_STUFFING = TS_MAX_PAYLOAD - TS_AF_MIN_SIZE;

// ===== HLS Steg Configuration =====

struct HLSStegConfig {
    // === Carrier Mode ===
    enum class CarrierMode {
        AF_STUFFING_ONLY,       // adaptation field stuffing bytes only
        NULL_PACKETS_ONLY,      // NULL TS packets (PID 0x1FFF) only
        HYBRID                  // both (max capacity)
    };
    CarrierMode carrier_mode = CarrierMode::HYBRID;

    // === Stream Parameters ===
    uint32_t target_bitrate_bps = 4000000;  // 4 Mbps fake stream
    uint16_t video_pid = 0x100;
    uint16_t audio_pid = 0x101;

    // === Capacity Control ===
    double max_stuffing_ratio = 0.12;
    size_t min_stuffing_bytes = 8;
    size_t max_stuffing_bytes = TS_MAX_STUFFING;
    size_t null_packet_interval = 20;

    // === Stuffing encryption (stream cipher for stealth) ===
    // NOTE: This is NOT payload encryption (Manager does that).
    // This encrypts STUFFING BYTES so they look like random padding
    // instead of having detectable patterns.
    std::vector<uint8_t> stuffing_key;      // ChaCha20 key for stuffing
    std::vector<uint8_t> stuffing_nonce;    // ChaCha20 nonce base
    bool encrypt_stuffing = true;

    // === Segment generation ===
    double segment_duration_sec = 6.0;
    std::string output_directory;
    std::string playlist_name = "stream.m3u8";

    // === Reliability ===
    size_t tx_queue_max = 2048;
    size_t rx_buffer_max = 262144;
};

// ===== HLS Steg Statistics =====

struct HLSStegStats {
    uint64_t ts_packets_written = 0;
    uint64_t ts_packets_read = 0;
    uint64_t null_packets_injected = 0;
    uint64_t af_stuffing_packets = 0;
    uint64_t payload_bytes_hidden = 0;
    uint64_t payload_bytes_extracted = 0;
    uint64_t segments_created = 0;
    uint64_t segments_parsed = 0;
    double stuffing_ratio = 0.0;
    double current_throughput_bps = 0.0;
    double stealth_score = 0.0;
};

// ===== M3U8 Playlist Generator =====

/**
 * Generates valid HLS .m3u8 playlists for the fake stream.
 *
 * #EXTM3U
 * #EXT-X-VERSION:3
 * #EXT-X-TARGETDURATION:6
 * #EXT-X-MEDIA-SEQUENCE:0
 * #EXTINF:6.0,
 * segment_000.ts
 * ...
 */
class M3U8PlaylistGenerator {
public:
    explicit M3U8PlaylistGenerator(double segment_duration = 6.0);

    // Generate playlist for N segments
    std::string generate_playlist(size_t segment_count,
                                   size_t media_sequence = 0) const;

    // Generate segment filename
    static std::string segment_filename(size_t index);

private:
    double segment_duration_;
};

// ===== TS Packet Builder/Parser =====

class TSPacketBuilder {
public:
    TSPacketBuilder();

    std::vector<uint8_t> build_af_stuffing_packet(
        uint16_t pid,
        uint8_t continuity_counter,
        const uint8_t* real_payload, size_t payload_len,
        const uint8_t* covert_data, size_t covert_len);

    std::vector<uint8_t> build_null_packet(
        const uint8_t* covert_data, size_t covert_len,
        uint8_t continuity_counter);

    // Generate a fake video PES packet (minimal valid structure)
    std::vector<uint8_t> build_fake_video_packet(
        uint16_t pid, uint8_t cc);

    struct ParsedPacket {
        uint16_t pid = 0;
        uint8_t continuity_counter = 0;
        bool has_adaptation_field = false;
        bool has_payload = false;
        bool is_null_packet = false;
        std::vector<uint8_t> covert_data;
        std::vector<uint8_t> real_payload;
        size_t stuffing_bytes = 0;
    };

    ParsedPacket parse_packet(const uint8_t* packet_188);

    static size_t max_covert_in_af(size_t total_af_length);
    static size_t max_covert_in_null() { return TS_MAX_PAYLOAD; }

    static constexpr uint8_t COVERT_MARKER = 0xFE;
    static constexpr size_t COVERT_FRAME_OVERHEAD = 3;
};

// ===== Segment Encoder/Decoder =====

class HLSSegmentCodec {
public:
    explicit HLSSegmentCodec(const HLSStegConfig& config);

    // Generate a fake .ts segment with covert data embedded
    // (creates TS packets from scratch — no real video needed)
    std::vector<uint8_t> generate_segment(
        const uint8_t* covert_data, size_t covert_len,
        size_t target_segment_size = 0);

    // Extract covert data from a modified .ts segment
    std::vector<uint8_t> decode_segment(
        const std::vector<uint8_t>& modified_segment);

    // Estimate capacity of a segment (bytes of covert data)
    size_t estimate_capacity(size_t segment_size) const;

    // Encrypt/decrypt stuffing bytes (ChaCha20 for stealth, NOT payload crypto)
    void encrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index);
    void decrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index);

    // FIX #111: Per-segment packet type counts.
    // Written by generate_segment(), read by HLSStegChannel::get_encoded_segment()
    // to propagate into HLSStegStats under stats_mutex_.
    // Not thread-safe on their own — caller must synchronize.
    uint64_t last_segment_null_packets_ = 0;
    uint64_t last_segment_af_packets_ = 0;

private:
    HLSStegConfig config_;
    std::unique_ptr<TSPacketBuilder> builder_;

    void init_chacha_key();
    std::vector<uint8_t> derive_packet_nonce(uint64_t packet_index) const;
};

// ===== HLS Video Steg Channel =====

class HLSStegChannel : public ICovertChannel {
public:
    /**
     * @param mimicry  TrafficMimicry for TLS wrapping. NOT owned.
     * @param config   Channel configuration.
     */
    HLSStegChannel(ncp::TrafficMimicry* mimicry,
                   const HLSStegConfig& config = {});
    ~HLSStegChannel() override;

    HLSStegChannel(const HLSStegChannel&) = delete;
    HLSStegChannel& operator=(const HLSStegChannel&) = delete;

    // === ICovertChannel interface ===
    bool open() override;
    void close() override;
    bool is_open() const override;
    ChannelState state() const override;

    size_t send(const uint8_t* data, size_t len) override;
    size_t receive(uint8_t* buf, size_t max_len) override;

    ChannelStats get_stats() const override;
    std::string channel_type() const override { return "hls_video_steg"; }
    double max_capacity_bps() const override;

    void set_detection_callback(DetectionCallback cb) override;
    void on_detection(const CovertDetectionEvent& event) override;

    // === HLS-specific API ===
    bool set_config(const HLSStegConfig& config);
    HLSStegConfig get_config() const;
    HLSStegStats get_hls_stats() const;

    // Receiver: feed raw .ts segment for extraction
    void feed_segment(const std::vector<uint8_t>& segment_data);

    // Sender: get next encoded .ts segment (blocking)
    std::vector<uint8_t> get_encoded_segment();

    // Get current .m3u8 playlist
    std::string get_playlist() const;

private:
    void update_stealth_score();

    // Dependencies (not owned)
    ncp::TrafficMimicry* mimicry_;

    // State
    HLSStegConfig config_;
    std::atomic<ChannelState> state_{ChannelState::CLOSED};

    // Components
    std::unique_ptr<HLSSegmentCodec> codec_;
    std::unique_ptr<M3U8PlaylistGenerator> playlist_gen_;

    // TX queue (covert data to embed in next segment)
    std::queue<std::vector<uint8_t>> tx_queue_;
    mutable std::mutex tx_mutex_;
    std::condition_variable tx_cv_;

    // RX buffer (extracted covert data)
    std::vector<uint8_t> rx_buffer_;
    mutable std::mutex rx_mutex_;
    std::condition_variable rx_cv_;

    std::atomic<bool> running_{false};

    // Stats — lock order: tx_mutex_ → stats_mutex_
    mutable std::mutex stats_mutex_;
    HLSStegStats hls_stats_;
    ChannelStats base_stats_;
    uint64_t stealth_update_counter_ = 0;
    uint64_t segment_counter_ = 0;

    // Detection
    DetectionCallback detection_cb_;
    std::mutex detection_mutex_;
};

} // namespace covert
} // namespace ncp
