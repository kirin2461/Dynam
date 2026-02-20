#pragma once

/**
 * @file ncp_flow_shaper.hpp
 * @brief FlowShaper — Phase 2 Anti-ML-TSPU (flow-level traffic shaping)
 *
 * ML classifiers (ET-BERT, FlowPic, AppNet) analyze entire flows, not single packets.
 * They look at:
 *   1. Packet size distribution (histogram of sizes per flow)
 *   2. Inter-arrival time distribution
 *   3. Upload/download byte ratio
 *   4. Burst patterns (packets/second over time)
 *   5. Flow duration and idle periods
 *
 * FlowShaper makes any NCP flow look like a chosen "cover" application
 * by reshaping all five dimensions to match a target profile.
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <atomic>
#include <string>
#include <functional>
#include <chrono>
#include <queue>
#include <mutex>
#include <thread>
#include <memory>
#include "ncp_csprng.hpp"

namespace ncp {
namespace DPI {

// ===== Flow Profile =====

enum class FlowProfile {
    WEB_BROWSING,    // burst(10-30 pkts) → pause(2-8s) → burst
    VIDEO_STREAM,    // constant downstream ~5Mbps, small ACK upstream
    MESSENGER,       // rare small packets, periodic typing indicators
    GAMING,          // small packets 50-100B at constant 20-60Hz
    FILE_DOWNLOAD,   // large downstream, minimal upstream
    CUSTOM           // user-defined profile parameters
};

const char* flow_profile_to_string(FlowProfile p) noexcept;
FlowProfile flow_profile_from_string(const std::string& name) noexcept;

// ===== Size Distribution Model =====

/// Describes the target packet size distribution for a profile.
/// ML classifiers build histograms of packet sizes — we must match them.
struct SizeDistribution {
    /// Weighted buckets: each pair is (size, weight).
    /// Packets will be padded/split to match this distribution.
    struct Bucket {
        size_t size;      // target packet size
        double weight;    // relative frequency (0.0 - 1.0)
    };
    std::vector<Bucket> buckets;

    /// Pre-built distributions for known profiles
    static SizeDistribution web_browsing();
    static SizeDistribution video_stream();
    static SizeDistribution messenger();
    static SizeDistribution gaming();
    static SizeDistribution file_download();
};

// ===== Burst Model =====

/// Describes burst/pause timing patterns.
struct BurstModel {
    // Burst phase
    int burst_packets_min = 5;       // min packets in a burst
    int burst_packets_max = 30;      // max packets in a burst
    double burst_inter_ms_min = 1.0; // min delay between packets in burst
    double burst_inter_ms_max = 20.0;// max delay between packets in burst

    // Pause phase (between bursts)
    double pause_ms_min = 500.0;     // min pause after burst
    double pause_ms_max = 8000.0;    // max pause after burst

    // Distribution type for inter-arrival times
    enum class Distribution {
        UNIFORM,    // flat random
        GAUSSIAN,   // normal
        PARETO,     // heavy tail — most realistic for web traffic
        EXPONENTIAL // memoryless
    };
    Distribution timing_distribution = Distribution::PARETO;
    double pareto_alpha = 1.5;  // shape parameter for Pareto

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

    // Size shaping
    bool enable_size_shaping = true;
    SizeDistribution size_dist;         // auto-set from profile if empty

    // Timing shaping
    bool enable_timing_shaping = true;
    BurstModel burst_model;             // auto-set from profile if empty

    // Upload/Download ratio enforcement
    bool enable_ratio_shaping = true;
    double target_upload_ratio = 0.15;  // target: 15% upload, 85% download
    double ratio_tolerance = 0.05;      // ±5% tolerance

    // Idle period injection
    bool enable_idle_keepalive = true;
    double keepalive_interval_ms = 5000.0;  // send keepalive every 5s during idle
    size_t keepalive_size = 52;             // TCP ACK size

    // Dummy traffic injection (flow-level)
    bool enable_flow_dummy = true;
    double dummy_ratio = 0.05;           // 5% of flow packets are dummy

    // Performance
    double max_overhead_percent = 8.0;
    size_t max_queue_depth = 1024;

    // Presets
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
        : packets_shaped(o.packets_shaped.load()),
          packets_original(o.packets_original.load()),
          bytes_original(o.bytes_original.load()),
          bytes_shaped(o.bytes_shaped.load()),
          dummy_packets(o.dummy_packets.load()),
          keepalives_sent(o.keepalives_sent.load()),
          packets_split(o.packets_split.load()),
          packets_merged(o.packets_merged.load()),
          bursts_generated(o.bursts_generated.load()),
          pauses_injected(o.pauses_injected.load()),
          current_upload_ratio(o.current_upload_ratio),
          overhead_percent(o.overhead_percent) {}
};

// ===== Shaped Packet =====

/// A single packet output from the shaper with associated delay.
struct ShapedPacket {
    std::vector<uint8_t> data;
    std::chrono::microseconds delay_before_send{0}; // wait this long before sending
    bool is_dummy = false;        // receiver should discard
    bool is_keepalive = false;    // idle keepalive
    bool is_upload = true;        // direction
};

// ===== Packet Send Callback =====

using FlowSendCallback = std::function<void(const ShapedPacket&)>;

// ===== Main Class =====

class FlowShaper {
public:
    FlowShaper();
    explicit FlowShaper(const FlowShaperConfig& config);
    ~FlowShaper();

    FlowShaper(const FlowShaper&) = delete;
    FlowShaper& operator=(const FlowShaper&) = delete;
    FlowShaper(FlowShaper&&) noexcept;
    FlowShaper& operator=(FlowShaper&&) noexcept;

    // ===== Lifecycle =====

    /// Start the flow shaper background thread.
    /// Callback is invoked when a shaped packet is ready to send.
    void start(FlowSendCallback callback);

    /// Stop the flow shaper, flush remaining packets.
    void stop();

    bool is_running() const;

    // ===== Core Operations =====

    /// Enqueue an outgoing packet for shaping.
    /// The shaper will buffer it and release shaped versions via callback.
    void enqueue(const std::vector<uint8_t>& packet, bool is_upload = true);

    /// Enqueue multiple packets.
    void enqueue_batch(const std::vector<std::vector<uint8_t>>& packets, bool is_upload = true);

    /// Shape a single packet synchronously (no background thread).
    /// Returns one or more shaped packets (may split or merge).
    std::vector<ShapedPacket> shape_sync(const std::vector<uint8_t>& packet, bool is_upload = true);

    // ===== Size Shaping =====

    /// Reshape packet to match target size distribution.
    /// May split large packets or pad small ones.
    std::vector<std::vector<uint8_t>> reshape_size(const std::vector<uint8_t>& packet);

    /// Select target size from distribution using weighted random.
    size_t select_target_size();

    // ===== Timing =====

    /// Calculate next inter-packet delay based on burst model.
    std::chrono::microseconds next_delay();

    /// Check if we should start a new burst or continue pause.
    bool should_burst() const;

    // ===== Dummy / Keepalive =====

    /// Generate a flow-level dummy packet matching current profile.
    ShapedPacket generate_dummy();

    /// Generate an idle keepalive packet.
    ShapedPacket generate_keepalive();

    /// Check if packet is a flow shaper dummy (for receiver discard).
    static bool is_flow_dummy(const uint8_t* data, size_t len);

    // ===== Ratio Shaping =====

    /// Get current upload/download ratio.
    double current_ratio() const;

    /// Check if ratio is within target range; may inject balancing traffic.
    bool needs_ratio_balance() const;

    // ===== Config & Stats =====

    void set_config(const FlowShaperConfig& config);
    FlowShaperConfig get_config() const;
    void set_profile(FlowProfile profile);

    FlowShaperStats get_stats() const;
    void reset_stats();

private:
    void worker_thread_func();
    void apply_profile_defaults();

    // Size shaping internals
    std::vector<uint8_t> pad_to_size(const std::vector<uint8_t>& data, size_t target);
    std::vector<std::vector<uint8_t>> split_packet(const std::vector<uint8_t>& data, size_t max_size);

    // Timing internals
    double sample_pareto(double alpha, double xm);
    double sample_exponential(double lambda);
    std::chrono::microseconds sample_delay();
    void advance_burst_state();

    // Ratio tracking
    void track_bytes(size_t bytes, bool is_upload);
    ShapedPacket generate_ratio_balance_packet();

    // Dummy magic
    static constexpr uint8_t FLOW_DUMMY_MAGIC_0 = 0xF1;
    static constexpr uint8_t FLOW_DUMMY_MAGIC_1 = 0x0A;
    static constexpr uint8_t FLOW_DUMMY_MAGIC_2 = 0xD5;
    static constexpr uint8_t FLOW_DUMMY_MAGIC_3 = 0xEE;

    FlowShaperConfig config_;
    FlowShaperStats stats_;

    // Phase 0: mt19937 rng_ REMOVED — all randomness via ncp::csprng_*

    // Burst state machine
    enum class BurstState { BURSTING, PAUSING, IDLE };
    BurstState burst_state_ = BurstState::IDLE;
    int packets_in_current_burst_ = 0;
    int current_burst_target_ = 0;
    std::chrono::steady_clock::time_point last_packet_time_;
    std::chrono::steady_clock::time_point pause_end_time_;

    // Ratio tracking
    uint64_t upload_bytes_ = 0;
    uint64_t download_bytes_ = 0;

    // Background thread
    struct QueueEntry {
        std::vector<uint8_t> data;
        bool is_upload;
    };
    std::queue<QueueEntry> packet_queue_;
    std::mutex queue_mutex_;
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
    FlowSendCallback send_callback_;

    // Size distribution cumulative weights (precomputed)
    std::vector<double> cumulative_weights_;
    void precompute_weights();
};

} // namespace DPI
} // namespace ncp
