/**
 * @file ncp_behavioral_cloak.cpp
 * @brief Behavioral Cloak implementation — Phase 5
 *
 * Shapes packet timing, burst patterns, idle gaps, and upload/download
 * ratios to match real Chrome browsing sessions, defeating ML-based
 * behavioral classifiers.
 */

#include "ncp_behavioral_cloak.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>
// <cmath> already included above for std::isfinite

namespace ncp {
namespace DPI {

// ===== BrowsingBehaviorModel presets =====

BrowsingBehaviorModel BrowsingBehaviorModel::chrome_casual() {
    BrowsingBehaviorModel m;
    m.name                   = "chrome_casual";
    m.burst_min_packets      = 5;
    m.burst_max_packets      = 30;
    m.burst_interval_min_ms  = 50.0;
    m.burst_interval_max_ms  = 200.0;
    m.idle_min_ms            = 2000.0;
    m.idle_max_ms            = 8000.0;
    m.upload_ratio           = 0.15;
    m.ratio_tolerance        = 0.05;
    m.pct_small              = 0.30;
    m.pct_medium             = 0.40;
    m.pct_large              = 0.30;
    return m;
}

BrowsingBehaviorModel BrowsingBehaviorModel::chrome_streaming() {
    BrowsingBehaviorModel m;
    m.name                   = "chrome_streaming";
    m.burst_min_packets      = 50;
    m.burst_max_packets      = 200;
    m.burst_interval_min_ms  = 2.0;
    m.burst_interval_max_ms  = 20.0;
    m.idle_min_ms            = 100.0;
    m.idle_max_ms            = 1000.0;
    m.upload_ratio           = 0.05;   // mostly download
    m.ratio_tolerance        = 0.03;
    m.pct_small              = 0.10;
    m.pct_medium             = 0.20;
    m.pct_large              = 0.70;   // large chunks
    return m;
}

BrowsingBehaviorModel BrowsingBehaviorModel::chrome_social() {
    BrowsingBehaviorModel m;
    m.name                   = "chrome_social";
    m.burst_min_packets      = 3;
    m.burst_max_packets      = 10;
    m.burst_interval_min_ms  = 80.0;
    m.burst_interval_max_ms  = 300.0;
    m.idle_min_ms            = 5000.0;
    m.idle_max_ms            = 30000.0;
    m.upload_ratio           = 0.20;   // more uploads (posts, likes)
    m.ratio_tolerance        = 0.08;
    m.pct_small              = 0.40;
    m.pct_medium             = 0.40;
    m.pct_large              = 0.20;
    return m;
}

// ===== Constructors =====

BehavioralCloak::BehavioralCloak() {
    load_default_models();
    last_packet_time_ = std::chrono::steady_clock::now();
    NCP_LOG_DEBUG("[BehavioralCloak] Initialized with default config");
}

BehavioralCloak::BehavioralCloak(const BehavioralCloakConfig& cfg)
    : config_(cfg)
{
    load_default_models();
    last_packet_time_ = std::chrono::steady_clock::now();
    NCP_LOG_DEBUG("[BehavioralCloak] Initialized with model: " + cfg.active_model);
}

// ===== Public API =====

std::chrono::microseconds BehavioralCloak::shape_packet(size_t packet_size, bool is_upload) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return std::chrono::microseconds(0);
    }

    const BrowsingBehaviorModel* model = get_active_model_();
    if (!model) {
        return std::chrono::microseconds(0);
    }

    // Update session volume for ratio shaping
    if (is_upload) {
        session_upload_bytes_ += packet_size;
    } else {
        session_download_bytes_ += packet_size;
    }

    // Ratio adjustment: if upload fraction deviates significantly, add a
    // hint delay for uploads when we are already over the target ratio.
    std::chrono::microseconds extra_ratio_delay(0);
    if (config_.shape_ratios) {
        uint64_t total = session_upload_bytes_ + session_download_bytes_;
        if (total > 0 && is_upload) {
            double actual_ratio = static_cast<double>(session_upload_bytes_)
                                  / static_cast<double>(total);
            double target_ratio = model->upload_ratio;
            if (actual_ratio > target_ratio + model->ratio_tolerance) {
                // Too many uploads: delay uploads slightly to let downloads catch up
                double excess = actual_ratio - (target_ratio + model->ratio_tolerance);
                // R10-FIX-07: Bounds check to prevent integer overflow from invalid float values
                if (std::isfinite(excess) && excess >= 0.0 && excess <= 1.0) {
                    int64_t penalty_us = static_cast<int64_t>(excess * 50000.0);  // up to ~50ms
                    // Cap at 100ms to prevent excessive delays
                    if (penalty_us > 100000) penalty_us = 100000;
                    if (penalty_us < 0) penalty_us = 0;
                    extra_ratio_delay = std::chrono::microseconds(penalty_us);
                    stats_.ratio_adjustments.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    }

    // Manage burst state machine
    transition_burst_state_();

    std::chrono::microseconds base_delay(0);
    if (burst_state_ == BurstState::BURSTING) {
        base_delay = compute_burst_delay_();
        ++packets_in_current_burst_;
    } else {
        // We are in IDLE — the caller should honour get_idle_duration().
        // Return a minimal delay.
        base_delay = compute_idle_delay_();
    }

    last_packet_time_ = std::chrono::steady_clock::now();
    stats_.packets_shaped.fetch_add(1, std::memory_order_relaxed);

    // At HIGH+ threat: add extra random delay to break any residual pattern
    if (threat_level_ >= ThreatLevel::HIGH) {
        int64_t noise_us = static_cast<int64_t>(
            csprng_double_range(0.0, static_cast<double>(model->burst_interval_max_ms) * 500.0)
        );
        base_delay += std::chrono::microseconds(noise_us);
    }

    return base_delay + extra_ratio_delay;
}

std::chrono::milliseconds BehavioralCloak::get_idle_duration() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled || !config_.shape_idle) {
        return std::chrono::milliseconds(0);
    }

    if (burst_state_ == BurstState::BURSTING) {
        return std::chrono::milliseconds(0);
    }

    const BrowsingBehaviorModel* model = get_active_model_();
    if (!model) {
        return std::chrono::milliseconds(0);
    }

    double idle_ms = csprng_double_range(model->idle_min_ms, model->idle_max_ms);

    // At HIGH threat: shorten idle to look more "normal user" active
    if (threat_level_ >= ThreatLevel::HIGH) {
        idle_ms *= 0.6;
    }

    return std::chrono::milliseconds(static_cast<int64_t>(idle_ms));
}

bool BehavioralCloak::should_inject_dummy() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled || !config_.inject_fake_idle) {
        return false;
    }
    if (burst_state_ != BurstState::IDLE) {
        return false;
    }

    const BrowsingBehaviorModel* model = get_active_model_();
    if (!model) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(
        now - idle_start_time_).count();

    // Inject after at least 10% of the model's max idle time
    double threshold_ms = model->idle_max_ms * 0.10;
    if (elapsed_ms < threshold_ms) return false;

    // Randomly decide (probability ~20% per check) to inject
    return csprng_coin(0.20);
}

std::vector<uint8_t> BehavioralCloak::generate_dummy_packet() {
    std::lock_guard<std::mutex> lock(mutex_);

    const BrowsingBehaviorModel* model = get_active_model_();

    // Target a "small" packet (<200 bytes) to mimic keepalive / ACK / OPTIONS
    size_t max_small = 200;
    size_t min_small = 40;
    size_t size;
    if (model) {
        double r = csprng_double();
        if (r < model->pct_small) {
            size = static_cast<size_t>(csprng_double_range(
                static_cast<double>(min_small), static_cast<double>(max_small)));
        } else {
            size = static_cast<size_t>(csprng_double_range(40.0, 80.0));
        }
    } else {
        size = static_cast<size_t>(csprng_double_range(40.0, 120.0));
    }

    std::vector<uint8_t> pkt(size);
    csprng_fill(pkt);

    stats_.idle_periods_injected.fetch_add(1, std::memory_order_relaxed);
    return pkt;
}

// ===== Model management =====

void BehavioralCloak::load_default_models() {
    std::lock_guard<std::mutex> lock(mutex_);
    models_.clear();
    auto casual    = BrowsingBehaviorModel::chrome_casual();
    auto streaming = BrowsingBehaviorModel::chrome_streaming();
    auto social    = BrowsingBehaviorModel::chrome_social();
    models_[casual.name]    = casual;
    models_[streaming.name] = streaming;
    models_[social.name]    = social;
    NCP_LOG_DEBUG("[BehavioralCloak] Default models loaded (casual/streaming/social)");
}

void BehavioralCloak::add_model(const BrowsingBehaviorModel& model) {
    std::lock_guard<std::mutex> lock(mutex_);
    models_[model.name] = model;
    NCP_LOG_INFO("[BehavioralCloak] Model added: " + model.name);
}

void BehavioralCloak::set_active_model(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (models_.find(name) == models_.end()) {
        NCP_LOG_ERROR("[BehavioralCloak] Unknown model: " + name);
        return;
    }
    config_.active_model = name;
    // Reset burst state on model change
    burst_state_              = BurstState::IDLE;
    packets_in_current_burst_ = 0;
    target_burst_size_        = 0;
    idle_start_time_          = std::chrono::steady_clock::now();
    NCP_LOG_INFO("[BehavioralCloak] Active model set to: " + name);
}

std::string BehavioralCloak::get_active_model_name() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.active_model;
}

// ===== Config / stats =====

void BehavioralCloak::set_config(const BehavioralCloakConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[BehavioralCloak] Config updated");
}

BehavioralCloakConfig BehavioralCloak::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

BehavioralCloakStats BehavioralCloak::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void BehavioralCloak::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    NCP_LOG_DEBUG("[BehavioralCloak] Stats reset");
}

void BehavioralCloak::set_threat_level(ThreatLevel level) {
    // R10-FIX-05: Atomic compare-and-swap to avoid unnecessary locking
    ThreatLevel expected = threat_level_.load(std::memory_order_relaxed);
    if (expected != level) {
        threat_level_.store(level, std::memory_order_relaxed);
        NCP_LOG_INFO("[BehavioralCloak] Threat level → "
                     + std::to_string(static_cast<int>(level)));
    }
}

ThreatLevel BehavioralCloak::get_threat_level() const {
    // R10-FIX-05: Atomic load for thread-safe access without locking
    return threat_level_.load(std::memory_order_relaxed);
}

// ===== Private helpers =====

const BrowsingBehaviorModel* BehavioralCloak::get_active_model_() const {
    // Caller must hold mutex_.
    auto it = models_.find(config_.active_model);
    if (it == models_.end()) return nullptr;
    return &it->second;
}

void BehavioralCloak::transition_burst_state_() {
    // Caller must hold mutex_.
    const BrowsingBehaviorModel* model = get_active_model_();
    if (!model) return;

    if (burst_state_ == BurstState::IDLE) {
        // Decide to start a new burst
        target_burst_size_ = static_cast<uint32_t>(
            csprng_range(static_cast<int>(model->burst_min_packets),
                         static_cast<int>(model->burst_max_packets)));
        packets_in_current_burst_ = 0;
        burst_state_              = BurstState::BURSTING;
        burst_start_time_         = std::chrono::steady_clock::now();
        stats_.bursts_generated.fetch_add(1, std::memory_order_relaxed);
    } else if (burst_state_ == BurstState::BURSTING) {
        if (packets_in_current_burst_ >= target_burst_size_) {
            burst_state_     = BurstState::IDLE;
            idle_start_time_ = std::chrono::steady_clock::now();
        }
    }
}

std::chrono::microseconds BehavioralCloak::compute_burst_delay_() const {
    // Caller must hold mutex_.
    const BrowsingBehaviorModel* model = get_active_model_();
    if (!model) return std::chrono::microseconds(0);

    double delay_ms = csprng_double_range(model->burst_interval_min_ms,
                                          model->burst_interval_max_ms);
    return std::chrono::microseconds(static_cast<int64_t>(delay_ms * 1000.0));
}

std::chrono::microseconds BehavioralCloak::compute_idle_delay_() const {
    // Caller must hold mutex_.
    const BrowsingBehaviorModel* model = get_active_model_();
    if (!model || !config_.shape_idle) {
        return std::chrono::microseconds(0);
    }
    double delay_ms = csprng_double_range(model->idle_min_ms, model->idle_max_ms);
    return std::chrono::microseconds(static_cast<int64_t>(delay_ms * 1000.0));
}

} // namespace DPI
} // namespace ncp
