#pragma once
/**
 * @file ncp_flow_shaper.hpp
 * @brief FlowShaper — Phase 2 Anti-ML-TSPU (flow-level traffic shaping)
 *
 * ML classifiers (ET-BERT, FlowPic, AppNet) analyze entire flows, not single packets.
 * They look at:
 * 1. Packet size distribution (histogram of sizes per flow)
 * 2. Inter-arrival time distribution
 * 3. Upload/download byte ratio
 * 4. Burst patterns (packets/second over time)
 * 5. Flow duration and idle periods
 *
 * FlowShaper makes any NCP flow look like a chosen "cover" application
 * by reshaping all five dimensions to match a target profile.
 */
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <atomic>
#include <string>
#include <functional>
#include <chrono>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <memory>
#include "ncp_csprng.hpp"

namespace ncp {
namespace DPI {

// ===== Flow Profile =====
enum class FlowProfile {
    WEB_BROWSING,   // burst(10-30 pkts) → pause(2-8s) → burst
    VIDEO_STREAM,   // constant downstream ~5Mbps, small ACK upstream
    MESSENGER,      // rare small packets, periodic typing indicators
    GAMING,         // small packets 50-100B at constant 20-60Hz
    FILE_DOWNLOAD,  // large downstream, minimal upstream
    CUSTOM          // user-defined profile parameters
};

const char* flow_profile_to_string(FlowProfile p) noexcept;
FlowProfile flow_profile_from_string(const std::string& name) noexcept;

// ===== Size Distribution Model =====
struct SizeDistribution {
    struct Bucket {
        size_t size;
        double weight;
    };
    std::vector<Bucket> buckets;

    static SizeDistribution web_browsing();
    static SizeDistribution video_stream();
    static SizeDistribution messenger();
    static SizeDistribution gaming();
    static SizeDistribution file_download();
};

// ===== Burst Model =====
struct BurstModel {
    int burst_packets_min = 5;
    int burst_packets_max = 30;
    double burst_inter_ms_min = 1.0;
    double burst_inter_ms_max = 20.0;

    double pause_ms_min = 500.0;
    double pause_ms_max = 8000.0;

    enum class Distribution { GAUSSIAN, PARETO, EXPONENTIAL };
    Distribution timing_distribution = Distribution::PARETO;
    double pareto_alpha = 1.5;

    static BurstModel web_browsing();
    static BurstModel video_stream();
    static BurstModel messenger();
    static BurstModel gaming();
    static BurstModel file_download();
};

// ===== Flow Shaper Configuration =====
struct FlowShaperConfig {
    bool enabled = true;
    FlowProfile profile = FlowProfile::WEB_BROWSING;

    bool enable_size_shaping = true;
    SizeDistribution size_dist;

    bool enable_timing_shaping = true;
    BurstModel burst_model;

    bool enable_ratio_shaping = true;
    double target_upload_ratio = 0.15;
    double ratio_tolerance = 0.05;

    bool enable_idle_keepalive = true;
    double keepalive_interval_ms = 5000.0;
    size_t keepalive_size = 52;

    bool enable_flow_dummy = true;
    double dummy_ratio = 0.05;

    static FlowShaperConfig web_browsing();
    static FlowShaperConfig video_stream();
    static FlowShaperConfig messenger();
    static FlowShaperConfig gaming();
    static FlowShaperConfig file_download();
};

// ===== Flow Statistics =====
struct FlowShaperStats {
    std::atomic<uint64_t> packets_shaped{0};
    std::atomic<uint64_t> packets_original{0};
    std::atomic<uint64_t> bytes_original{0};
    std::atomic<uint64_t> bytes_shaped{0};
    std::atomic<uint64_t> dummy_packets{0};
    std::atomic<uint64_t> keepalives_sent{0};
    std::atomic<uint64_t> packets_split{0};
    std::atomic<uint64_t> packets_merged{0};
    std::atomic<uint64_t> bursts_generated{0};
    std::atomic<uint64_t> pauses_injected{0};

    double current_upload_ratio = 0.0;
    double overhead_percent = 0.0;

    void reset() {
        packets_shaped.store(0);
        packets_original.store(0);
        bytes_original.store(0);
        bytes_shaped.store(0);
        dummy_packets.store(0);
        keepalives_sent.store(0);
        packets_split.store(0);
        packets_merged.store(0);
        bursts_generated.store(0);
        pauses_injected.store(0);
        current_upload_ratio = 0.0;
        overhead_percent = 0.0;
    }

    FlowShaperStats() = default;
    FlowShaperStats(const FlowShaperStats& o)
        : packets_shaped(o.packets_shaped.load())
        , packets_original(o.packets_original.load())
        , bytes_original(o.bytes_original.load())
        , bytes_shaped(o.bytes_shaped.load())
        , dummy_packets(o.dummy_packets.load())
        , keepalives_sent(o.keepalives_sent.load())
        , packets_split(o.packets_split.load())
        , packets_merged(o.packets_merged.load())
        , bursts_generated(o.bursts_generated.load())
        , pauses_injected(o.pauses_injected.load())
        , current_upload_ratio(o.current_upload_ratio)
        , overhead_percent(o.overhead_percent) {}
};

// ===== Shaped Packet =====
struct ShapedPacket {
    std::vector<uint8_t> data;
    std::chrono::microseconds delay_before_send{0};
    bool is_dummy = false;
    bool is_keepalive = false;
    bool is_upload = true;
};

using FlowSendCallback = std::function<void(const ShapedPacket&)>;

static constexpr size_t CHUNK_HEADER_SIZE = 8;

// ===== Main Class =====
class FlowShaper {
public:
    FlowShaper();
    ~FlowShaper();

    FlowShaper(const FlowShaper&) = delete;
    FlowShaper& operator=(const FlowShaper&) = delete;
    FlowShaper(FlowShaper&&) noexcept;
    FlowShaper& operator=(FlowShaper&&) noexcept;

    // ===== Lifecycle =====
    void start(FlowSendCallback callback);
    void stop();
    bool is_running() const;

    // ===== Core Operations =====
    void enqueue(const std::vector<uint8_t>& packet, bool is_upload = true);
    void enqueue_batch(const std::vector<std::vector<uint8_t>>& packets, bool is_upload = true);
    std::vector<ShapedPacket> shape_sync(const std::vector<uint8_t>& packet, bool is_upload = true);

    // ===== Size Shaping =====
    std::vector<std::vector<uint8_t>> reshape_size(const std::vector<uint8_t>& packet);
    size_t select_target_size();

    // ===== Timing =====
    std::chrono::microseconds next_delay();
    bool should_burst() const;

    // ===== Dummy / Keepalive =====
    ShapedPacket generate_dummy();
    ShapedPacket generate_keepalive();

    /// Check if packet is a flow shaper dummy.
    bool is_flow_dummy(const uint8_t* data, size_t len) const;

    // ===== Ratio Shaping =====
    double current_ratio() const;
    bool needs_ratio_balance() const;

    // ===== Config / Stats =====
    void update_config(const FlowShaperConfig& cfg);
    FlowShaperConfig get_config() const;
    FlowShaperStats get_stats() const;
    void reset_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace DPI
} // namespace ncp
