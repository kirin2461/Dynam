#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ncp {
namespace DPI {

enum class RotationLayer : uint8_t {
    L2_IDENTITY = 0,
    L7_TLS,
    L7_TIMING,
    L7_DUMMY,
    L7_GENEVA,
    COUNT_
};

static constexpr size_t ROTATION_LAYER_COUNT = static_cast<size_t>(RotationLayer::COUNT_);

struct LayerRotationConfig {
    uint32_t base_interval_sec = 1800;
    double   jitter_factor     = 0.3;
    uint32_t min_interval_sec  = 300;
    bool     enabled           = true;
};

struct RotationCoordinatorConfig {
    std::array<LayerRotationConfig, ROTATION_LAYER_COUNT> layers;
    double   correlation_threshold = 0.7;
    uint32_t correlation_window    = 10;
    uint32_t decorrelation_max_delay_sec = 120;
    bool coordinate_tls_with_l2     = true;
    bool coordinate_timing_with_l2  = true;
    bool coordinate_dummy_with_l2   = true;
    bool coordinate_geneva_with_l2  = true;
    uint32_t stagger_min_ms = 50;
    uint32_t stagger_max_ms = 2000;

    RotationCoordinatorConfig() {
        layers[0] = {1800, 0.30, 600, true};
        layers[1] = {1800, 0.30, 300, true};
        layers[2] = {2400, 0.35, 300, true};
        layers[3] = {2100, 0.25, 300, true};
        layers[4] = {3600, 0.40, 600, true};
    }
};

struct RotationEvent {
    RotationLayer layer;
    std::chrono::steady_clock::time_point timestamp;
    uint32_t actual_interval_ms;  // FIX: was _sec (truncated), now ms
};

struct CorrelationResult {
    RotationLayer layer_a;
    RotationLayer layer_b;
    double pearson_r;
    bool is_correlated;
    uint32_t injected_delay_ms;
};

struct RotationStats {
    std::array<uint64_t, ROTATION_LAYER_COUNT> rotation_counts{};
    uint64_t correlation_detections = 0;
    uint64_t total_decorrelation_delay_ms = 0;
    uint64_t coordinated_rotations = 0;
};

using RotationCallback = std::function<void(RotationLayer layer)>;
using CorrelationCallback = std::function<void(const CorrelationResult&)>;

class RotationCoordinator {
public:
    RotationCoordinator();
    ~RotationCoordinator();
    RotationCoordinator(const RotationCoordinator&) = delete;
    RotationCoordinator& operator=(const RotationCoordinator&) = delete;
    RotationCoordinator(RotationCoordinator&&) noexcept;
    RotationCoordinator& operator=(RotationCoordinator&&) noexcept;

    void set_config(const RotationCoordinatorConfig& config);
    RotationCoordinatorConfig get_config() const;
    void set_rotation_callback(RotationCallback cb);
    void set_correlation_callback(CorrelationCallback cb);
    void start();
    void stop();
    bool is_running() const;
    void rotate_now(RotationLayer layer);

    /// Rotate all layers with stagger. Use for emergency/init only —
    /// creates near-simultaneous events that anti-correlation may flag.
    void rotate_all();

    std::chrono::milliseconds time_until_next(RotationLayer layer) const;
    std::vector<RotationEvent> get_recent_events(size_t max_count = 50) const;
    std::vector<CorrelationResult> get_correlation_results() const;
    RotationStats get_stats() const;
    void reset_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace DPI
} // namespace ncp
