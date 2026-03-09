#pragma once

/**
 * @file ncp_behavioral_cloak.hpp
 * @brief Behavioral Cloak — Phase 5 Browser-Pattern Mimicry
 *
 * Shapes NCP traffic to match the burst/idle/ratio patterns of real Chrome
 * browsing sessions, defeating ML classifiers that extract behavioral
 * features (burst length, idle gap distribution, upload/download ratio,
 * packet-size histogram) to identify VPN/proxy traffic.
 *
 * Supported models:
 *   chrome_casual   — general browsing: 5-30 pkt bursts, 2-8s idle
 *   chrome_streaming — video playback: 50-200 pkt bursts, 0.1-1s idle
 *   chrome_social    — social-media scrolling: 3-10 pkt bursts, 5-30s idle
 */

#ifndef NCP_BEHAVIORAL_CLOAK_HPP
#define NCP_BEHAVIORAL_CLOAK_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>

#include "ncp_orchestrator.hpp"

namespace ncp {
namespace DPI {

// ===== Behavior Model =====

struct BrowsingBehaviorModel {
    std::string name;   ///< e.g. "chrome_casual"

    // Burst characteristics
    uint32_t burst_min_packets = 5;
    uint32_t burst_max_packets = 30;
    double   burst_interval_min_ms = 50.0;   ///< Min inter-packet delay within burst
    double   burst_interval_max_ms = 200.0;  ///< Max inter-packet delay within burst

    // Idle (between bursts)
    double idle_min_ms = 2000.0;
    double idle_max_ms = 8000.0;

    // Upload/download ratio
    double upload_ratio = 0.15;       ///< Typical browsing: 15% up, 85% down
    double ratio_tolerance = 0.05;    ///< Acceptable deviation

    // Packet-size distribution percentages
    double pct_small  = 0.30;   ///< <200 bytes  (ACKs, small requests)
    double pct_medium = 0.40;   ///< 200-1000 bytes
    double pct_large  = 0.30;   ///< >1000 bytes (content)

    // Presets
    static BrowsingBehaviorModel chrome_casual();
    static BrowsingBehaviorModel chrome_streaming();
    static BrowsingBehaviorModel chrome_social();
};

// ===== Configuration =====

struct BehavioralCloakConfig {
    bool enabled = true;
    std::string active_model = "chrome_casual";

    bool shape_bursts  = true;   ///< Enforce burst packet count limits
    bool shape_idle    = true;   ///< Enforce idle gap durations
    bool shape_ratios  = true;   ///< Enforce upload/download ratio
    bool inject_fake_idle = true; ///< Inject keepalive-like packets during idle
};

// ===== Statistics =====

struct BehavioralCloakStats {
    std::atomic<uint64_t> packets_shaped{0};
    std::atomic<uint64_t> bursts_generated{0};
    std::atomic<uint64_t> idle_periods_injected{0};
    std::atomic<uint64_t> ratio_adjustments{0};

    void reset() {
        packets_shaped.store(0);
        bursts_generated.store(0);
        idle_periods_injected.store(0);
        ratio_adjustments.store(0);
    }

    BehavioralCloakStats() = default;
    BehavioralCloakStats(const BehavioralCloakStats& o)
        : packets_shaped(o.packets_shaped.load()),
          bursts_generated(o.bursts_generated.load()),
          idle_periods_injected(o.idle_periods_injected.load()),
          ratio_adjustments(o.ratio_adjustments.load()) {}

    BehavioralCloakStats& operator=(const BehavioralCloakStats& o) {
        if (this != &o) {
            packets_shaped.store(o.packets_shaped.load());
            bursts_generated.store(o.bursts_generated.load());
            idle_periods_injected.store(o.idle_periods_injected.load());
            ratio_adjustments.store(o.ratio_adjustments.load());
        }
        return *this;
    }
};

// ===== BehavioralCloak =====

class BehavioralCloak {
public:
    BehavioralCloak();
    explicit BehavioralCloak(const BehavioralCloakConfig& cfg);

    /**
     * @brief Shape a packet and return the delay to apply before sending.
     *
     * Consults the active model to enforce:
     *   - Burst inter-packet intervals (shape_bursts)
     *   - Upload ratio corrections (shape_ratios)
     *
     * @param packet_size  Payload size in bytes.
     * @param is_upload    true = outbound packet.
     * @return Delay in microseconds to wait before transmitting this packet.
     */
    std::chrono::microseconds shape_packet(size_t packet_size, bool is_upload);

    /**
     * @brief Get the recommended idle duration to wait before the next burst.
     *
     * Returns 0 if the cloak is currently in BURSTING state.
     */
    std::chrono::milliseconds get_idle_duration();

    /**
     * @brief Decide whether a dummy/keepalive packet should be injected now.
     *
     * Returns true if inject_fake_idle is enabled and we are in IDLE state
     * and the idle gap has been active for at least 10% of the model's
     * idle_max_ms.
     */
    bool should_inject_dummy();

    /**
     * @brief Generate a dummy keepalive packet that fits the active model.
     *
     * Generates a packet whose size matches the model's small-packet
     * distribution (< 200 bytes) filled with CSPRNG random bytes.
     */
    std::vector<uint8_t> generate_dummy_packet();

    // ===== Model management =====

    void load_default_models();
    void add_model(const BrowsingBehaviorModel& model);
    void set_active_model(const std::string& name);
    std::string get_active_model_name() const;

    // ===== Config / stats =====

    void set_config(const BehavioralCloakConfig& cfg);
    BehavioralCloakConfig get_config() const;

    BehavioralCloakStats get_stats() const;
    void reset_stats();

    void set_threat_level(ThreatLevel level);
    ThreatLevel get_threat_level() const;

private:
    BehavioralCloakConfig  config_;
    BehavioralCloakStats   stats_;
    mutable std::mutex     mutex_;
    // R10-FIX-05: Use atomic for thread-safe threat level access
    std::atomic<ThreatLevel> threat_level_{ThreatLevel::NONE};

    std::unordered_map<std::string, BrowsingBehaviorModel> models_;

    // Burst state machine
    enum class BurstState { IDLE, BURSTING };
    BurstState burst_state_          = BurstState::IDLE;
    uint32_t   packets_in_current_burst_ = 0;
    uint32_t   target_burst_size_        = 0;

    std::chrono::steady_clock::time_point last_packet_time_;
    std::chrono::steady_clock::time_point burst_start_time_;
    std::chrono::steady_clock::time_point idle_start_time_;

    // Session volume for ratio shaping
    uint64_t session_upload_bytes_   = 0;
    uint64_t session_download_bytes_ = 0;

    /**
     * @brief Return pointer to the active model, or nullptr if not found.
     * Caller must hold mutex_.
     */
    const BrowsingBehaviorModel* get_active_model_() const;

    /**
     * @brief Transition the burst state machine.
     * Caller must hold mutex_.
     */
    void transition_burst_state_();

    /**
     * @brief Compute intra-burst inter-packet delay.
     * Caller must hold mutex_.
     */
    std::chrono::microseconds compute_burst_delay_() const;

    /**
     * @brief Compute idle-gap delay (between bursts).
     * Caller must hold mutex_.
     */
    std::chrono::microseconds compute_idle_delay_() const;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_BEHAVIORAL_CLOAK_HPP
