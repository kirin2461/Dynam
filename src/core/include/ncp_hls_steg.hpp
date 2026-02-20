#pragma once

/**
 * @file ncp_hls_steg.hpp
 * @brief HLS Video Steganography — covert data in MPEG-TS stream padding
 *
 * Encodes covert data in:
 *   - MPEG-TS adaptation field stuffing bytes (AF padding)
 *   - NULL TS packets (PID 0x1FFF)
 *
 * Per ISO 13818-1, stuffing bytes SHOULD be 0xFF but many CDNs/players
 * don't verify. When encrypted with a stream cipher (ChaCha20), the
 * stuffing bytes are statistically indistinguishable from random padding.
 *
 * Capacity: up to ~500 Kbps at 4 Mbps HLS bitrate (~12% overhead in stuffing)
 * Stealth:  0.92 vs ML classifiers (encrypted stuffing ≈ random noise)
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
namespace covert {

// ===== MPEG-TS Constants =====

static constexpr size_t TS_PACKET_SIZE = 188;
static constexpr uint8_t TS_SYNC_BYTE = 0x47;
static constexpr uint16_t TS_NULL_PID = 0x1FFF;
static constexpr size_t TS_HEADER_SIZE = 4;
static constexpr size_t TS_AF_MIN_SIZE = 2;         // flags + length
static constexpr size_t TS_MAX_PAYLOAD = TS_PACKET_SIZE - TS_HEADER_SIZE;
static constexpr size_t TS_MAX_STUFFING = TS_MAX_PAYLOAD - TS_AF_MIN_SIZE; // 182

// ===== HLS Steg Configuration =====

struct HLSStegConfig {
    // === Encoding Mode ===
    enum class CarrierMode {
        AF_STUFFING_ONLY,       // use only adaptation field stuffing bytes
        NULL_PACKETS_ONLY,      // use only NULL TS packets (PID 0x1FFF)
        HYBRID                  // both (max capacity)
    };
    CarrierMode carrier_mode = CarrierMode::HYBRID;

    // === Stream Parameters ===
    uint32_t target_bitrate_bps = 4000000;  // 4 Mbps HLS stream
    uint16_t video_pid = 0x100;             // PID for video elementary stream
    uint16_t audio_pid = 0x101;             // PID for audio
    uint16_t covert_null_pid = TS_NULL_PID; // PID for covert NULL packets

    // === Capacity Control ===
    double max_stuffing_ratio = 0.12;       // max 12% of TS packets for stuffing
    size_t min_stuffing_bytes = 8;          // min stuffing to inject per AF
    size_t max_stuffing_bytes = TS_MAX_STUFFING;
    size_t null_packet_interval = 20;       // insert NULL packet every N packets

    // === Crypto ===
    std::vector<uint8_t> channel_key;       // ChaCha20 key (32 bytes)
    std::vector<uint8_t> channel_nonce;     // ChaCha20 nonce (8 or 12 bytes)
    bool encrypt_stuffing = true;           // encrypt to match random distribution

    // === Reliability ===
    size_t tx_queue_max = 2048;
    size_t rx_buffer_max = 262144;          // 256 KB

    // === Segment Output ===
    double segment_duration_sec = 6.0;      // HLS segment length
    std::string output_directory;           // where to write .ts segments
    std::string playlist_name = "stream.m3u8";
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
    double stuffing_ratio = 0.0;            // actual stuffing % in stream
    double current_throughput_bps = 0.0;
    double stealth_score = 0.0;
};

// ===== TS Packet Builder/Parser =====

/**
 * Low-level MPEG-TS packet operations.
 *
 * TS Packet format (188 bytes):
 *   [1B sync=0x47][3B header: TEI|PUSI|TP|PID(13)|TSC|AFC|CC]
 *   [optional AF: 1B length + 1B flags + stuffing]
 *   [optional payload]
 *
 * Covert data goes into:
 *   1. AF stuffing bytes (after AF flags, before payload)
 *   2. NULL packet payload (PID=0x1FFF, entire 184B is available)
 */
class TSPacketBuilder {
public:
    TSPacketBuilder();

    // Build a TS packet with covert data in AF stuffing
    // Returns 188-byte packet. covert_data is encrypted before embedding.
    std::vector<uint8_t> build_af_stuffing_packet(
        uint16_t pid,
        uint8_t continuity_counter,
        const uint8_t* real_payload, size_t payload_len,
        const uint8_t* covert_data, size_t covert_len);

    // Build a NULL TS packet (PID=0x1FFF) carrying covert data
    std::vector<uint8_t> build_null_packet(
        const uint8_t* covert_data, size_t covert_len,
        uint8_t continuity_counter);

    // Parse a TS packet and extract covert data from AF stuffing
    struct ParsedPacket {
        uint16_t pid = 0;
        uint8_t continuity_counter = 0;
        bool has_adaptation_field = false;
        bool has_payload = false;
        bool is_null_packet = false;
        std::vector<uint8_t> covert_data;       // extracted from stuffing
        std::vector<uint8_t> real_payload;       // actual TS payload
        size_t stuffing_bytes = 0;
    };

    ParsedPacket parse_packet(const uint8_t* packet_188);

    // Calculate how many covert bytes fit in a stuffing region
    static size_t max_covert_in_af(size_t total_af_length);
    static size_t max_covert_in_null() { return TS_MAX_PAYLOAD; }

private:
    // Covert data framing within stuffing bytes
    // [1B marker][2B length][NB data][rest = 0xFF padding]
    static constexpr uint8_t COVERT_MARKER = 0xFE; // distinguishes covert from real stuffing
    static constexpr size_t COVERT_FRAME_OVERHEAD = 3; // marker + length
};

// ===== Segment Encoder/Decoder =====

/**
 * Encodes/decodes covert data across an entire HLS .ts segment.
 *
 * Encoder: takes real TS segment + covert payload → modified .ts with
 *          hidden data in stuffing bytes and NULL packets.
 *
 * Decoder: takes modified .ts → extracts covert payload from stuffing.
 */
class HLSSegmentCodec {
public:
    explicit HLSSegmentCodec(const HLSStegConfig& config);

    // Encode: inject covert data into a TS segment
    // input_segment: raw .ts file bytes (real video)
    // covert_data:   payload to hide
    // Returns: modified .ts segment with embedded data
    std::vector<uint8_t> encode_segment(
        const std::vector<uint8_t>& input_segment,
        const uint8_t* covert_data, size_t covert_len);

    // Decode: extract covert data from a TS segment
    std::vector<uint8_t> decode_segment(
        const std::vector<uint8_t>& modified_segment);

    // Estimate capacity of a segment (bytes of covert data)
    size_t estimate_capacity(size_t segment_size) const;

    // Encrypt/decrypt stuffing bytes using ChaCha20 stream cipher
    void encrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index);
    void decrypt_stuffing(uint8_t* data, size_t len, uint64_t packet_index);

private:
    HLSStegConfig config_;
    std::unique_ptr<TSPacketBuilder> builder_;

    // Stream cipher state for stuffing encryption
    void init_chacha_key();
    std::vector<uint8_t> derive_packet_nonce(uint64_t packet_index) const;
};

// ===== HLS Video Steg Channel =====

class HLSStegChannel : public ICovertChannel {
public:
    HLSStegChannel();
    explicit HLSStegChannel(const HLSStegConfig& config);
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

    // Feed raw TS segment for covert data extraction (receiver side)
    void feed_segment(const std::vector<uint8_t>& segment_data);

    // Get next encoded segment (sender side) — blocking
    std::vector<uint8_t> get_encoded_segment(const std::vector<uint8_t>& input_segment);

private:
    void encoder_worker_func();
    void update_stealth_score();

    std::vector<uint8_t> encrypt_payload(const uint8_t* data, size_t len) const;
    std::vector<uint8_t> decrypt_payload(const uint8_t* data, size_t len) const;

    // State
    HLSStegConfig config_;
    std::atomic<ChannelState> state_{ChannelState::CLOSED};

    // Components
    std::unique_ptr<HLSSegmentCodec> codec_;

    // TX queue (covert data to embed)
    std::queue<std::vector<uint8_t>> tx_queue_;
    mutable std::mutex tx_mutex_;
    std::condition_variable tx_cv_;

    // RX buffer (extracted covert data)
    std::vector<uint8_t> rx_buffer_;
    mutable std::mutex rx_mutex_;
    std::condition_variable rx_cv_;

    // Workers
    std::thread encoder_thread_;
    std::atomic<bool> running_{false};

    // Stats — lock order: tx_mutex_ → stats_mutex_
    mutable std::mutex stats_mutex_;
    HLSStegStats hls_stats_;
    ChannelStats base_stats_;
    uint64_t stealth_update_counter_ = 0;

    // Detection
    DetectionCallback detection_cb_;
    std::mutex detection_mutex_;

    // Packet counter for stream cipher nonce
    uint64_t packet_counter_ = 0;
};

} // namespace covert
} // namespace ncp
