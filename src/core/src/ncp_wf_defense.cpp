/**
 * @file ncp_wf_defense.cpp
 * @brief WFDefense — Website Fingerprinting Defense implementation
 */

#include "ncp_wf_defense.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <sstream>
#include <cmath>

namespace ncp {
namespace DPI {

// =====================================================================
// WFDefenseStats
// =====================================================================

void WFDefenseStats::reset() noexcept {
    pages_defended.store(0);
    dummy_packets_sent.store(0);
    dummy_bytes_sent.store(0);
    real_packets_processed.store(0);
    overhead_bytes.store(0);
}

// =====================================================================
// Construction
// =====================================================================

WFDefense::WFDefense() {
    config_.enabled = Config::instance().getBool("wf_defense.enabled", true);
    config_.tamaraw_mode = Config::instance().getBool("wf_defense.tamaraw_mode", true);
    config_.target_total_packets = static_cast<size_t>(
        Config::instance().getInt("wf_defense.target_total_packets", 500));
    config_.target_total_bytes = static_cast<size_t>(
        Config::instance().getInt("wf_defense.target_total_bytes", 500000));
    config_.packet_size = static_cast<size_t>(
        Config::instance().getInt("wf_defense.packet_size", 1000));

    NCP_LOG_DEBUG("WFDefense: initialized (default config)");
}

WFDefense::WFDefense(const WFDefenseConfig& cfg)
    : config_(cfg)
{
    NCP_LOG_DEBUG("WFDefense: initialized (custom config)");
}

// =====================================================================
// Accessors
// =====================================================================

void WFDefense::set_config(const WFDefenseConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
}

WFDefenseConfig WFDefense::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

WFDefenseStats WFDefense::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void WFDefense::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
}

void WFDefense::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    threat_level_ = level;
    // At HIGH threat, force constant rate mode for maximum protection
    if (level >= ThreatLevel::HIGH) {
        config_.constant_rate_mode = true;
        NCP_LOG_INFO("WFDefense: HIGH threat detected — constant rate mode enabled");
    }
    NCP_LOG_DEBUG("WFDefense: threat level set to " +
        std::to_string(static_cast<int>(level)));
}

// =====================================================================
// Session lifecycle
// =====================================================================

void WFDefense::begin_page_load() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!config_.enabled) return;

    active_session_      = true;
    real_outgoing_count_ = 0;
    real_incoming_count_ = 0;
    real_bytes_          = 0;

    auto now = std::chrono::steady_clock::now();
    session_start_       = now;
    last_outgoing_time_  = now;
    last_incoming_time_  = now;

    NCP_LOG_DEBUG("WFDefense: page load session started");
}

void WFDefense::record_real_packet(size_t size, bool is_outgoing) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_session_) return;

    if (is_outgoing) {
        ++real_outgoing_count_;
        last_outgoing_time_ = std::chrono::steady_clock::now();
    } else {
        ++real_incoming_count_;
        last_incoming_time_ = std::chrono::steady_clock::now();
    }
    real_bytes_ += size;
    stats_.real_packets_processed.fetch_add(1);
}

// =====================================================================
// compute_pad_target_ — round real_count up to next multiple
// =====================================================================

size_t WFDefense::compute_pad_target_(size_t real_count) const {
    // Called under lock
    size_t m = config_.tamaraw_pad_multiple;
    if (m == 0) m = 1;
    size_t target = ((real_count + m - 1) / m) * m;
    // Enforce at least target_total_packets when in basic mode
    if (!config_.tamaraw_mode) {
        target = std::max(target, config_.target_total_packets);
    }
    return target;
}

// =====================================================================
// end_page_load
// =====================================================================

PaddingPlan WFDefense::end_page_load() {
    std::lock_guard<std::mutex> lock(mutex_);

    PaddingPlan plan{};
    plan.dummy_packet_size = config_.packet_size;

    if (!active_session_) {
        NCP_LOG_WARN("WFDefense: end_page_load called outside session");
        return plan;
    }

    active_session_ = false;
    stats_.pages_defended.fetch_add(1);

    if (!config_.enabled) {
        NCP_LOG_DEBUG("WFDefense: disabled, no padding injected");
        return plan;
    }

    if (config_.tamaraw_mode) {
        // Tamaraw: pad each direction independently to next multiple
        size_t out_target = compute_pad_target_(real_outgoing_count_);
        size_t in_target  = compute_pad_target_(real_incoming_count_);

        plan.dummy_outgoing_packets =
            (out_target > real_outgoing_count_) ?
            (out_target - real_outgoing_count_) : 0;
        plan.dummy_incoming_packets =
            (in_target > real_incoming_count_) ?
            (in_target - real_incoming_count_) : 0;

        // Schedule interval: use outgoing rate for the send_interval field
        plan.send_interval = std::chrono::microseconds(
            static_cast<long long>(config_.tamaraw_outgoing_rate_ms * 1000.0));

        NCP_LOG_INFO(
            "WFDefense: Tamaraw plan — out_real=" +
            std::to_string(real_outgoing_count_) +
            " out_dummy=" + std::to_string(plan.dummy_outgoing_packets) +
            " in_real=" + std::to_string(real_incoming_count_) +
            " in_dummy=" + std::to_string(plan.dummy_incoming_packets));
    } else if (config_.constant_rate_mode) {
        // Constant-rate mode: compute total duration and fill with packets
        auto session_duration = std::chrono::steady_clock::now() - session_start_;
        double duration_s = std::chrono::duration<double>(session_duration).count();
        size_t expected_total = static_cast<size_t>(
            duration_s * config_.constant_rate_pps);

        size_t real_total = real_outgoing_count_ + real_incoming_count_;
        size_t dummy_total = (expected_total > real_total) ?
                              (expected_total - real_total) : 0;

        // Apply max overhead cap
        if (real_total > 0) {
            double overhead_ratio =
                static_cast<double>(dummy_total) / static_cast<double>(real_total);
            if (overhead_ratio > config_.max_overhead_ratio) {
                dummy_total = static_cast<size_t>(
                    real_total * config_.max_overhead_ratio);
            }
        }

        plan.dummy_outgoing_packets = dummy_total / 2;
        plan.dummy_incoming_packets = dummy_total - plan.dummy_outgoing_packets;
        plan.send_interval = std::chrono::microseconds(
            static_cast<long long>(1e6 / config_.constant_rate_pps));

        NCP_LOG_INFO("WFDefense: constant-rate plan — dummy=" +
            std::to_string(dummy_total));
    } else {
        // Target-based normalization
        size_t real_total   = real_outgoing_count_ + real_incoming_count_;
        size_t target_total = config_.target_total_packets;
        size_t dummy_total  = (target_total > real_total) ?
                               (target_total - real_total) : 0;

        // Apply overhead cap
        if (real_total > 0) {
            double overhead_ratio =
                static_cast<double>(dummy_total) / static_cast<double>(real_total);
            if (overhead_ratio > config_.max_overhead_ratio) {
                dummy_total = static_cast<size_t>(
                    real_total * config_.max_overhead_ratio);
            }
        }

        plan.dummy_outgoing_packets = dummy_total / 2;
        plan.dummy_incoming_packets = dummy_total - plan.dummy_outgoing_packets;
        plan.send_interval = std::chrono::microseconds(10000); // 10ms default

        NCP_LOG_INFO("WFDefense: target-based plan — real=" +
            std::to_string(real_total) +
            " dummy=" + std::to_string(dummy_total));
    }

    // Track stats
    size_t total_dummy = plan.dummy_outgoing_packets + plan.dummy_incoming_packets;
    stats_.dummy_packets_sent.fetch_add(total_dummy);
    stats_.dummy_bytes_sent.fetch_add(total_dummy * plan.dummy_packet_size);
    stats_.overhead_bytes.fetch_add(total_dummy * plan.dummy_packet_size);

    return plan;
}

// =====================================================================
// generate_dummy_packet
// =====================================================================

std::vector<uint8_t> WFDefense::generate_dummy_packet(bool /*is_outgoing*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t sz = config_.packet_size;
    return csprng_bytes(sz);
}

// =====================================================================
// get_next_send_time (Tamaraw scheduling)
// =====================================================================

std::chrono::microseconds WFDefense::get_next_send_time(bool is_outgoing) {
    std::lock_guard<std::mutex> lock(mutex_);

    double rate_ms = is_outgoing
        ? config_.tamaraw_outgoing_rate_ms
        : config_.tamaraw_incoming_rate_ms;

    auto interval = std::chrono::microseconds(
        static_cast<long long>(rate_ms * 1000.0));

    auto now = std::chrono::steady_clock::now();
    auto& last = is_outgoing ? last_outgoing_time_ : last_incoming_time_;

    auto next_abs = last + interval;
    if (next_abs <= now) {
        // Already overdue — schedule immediately
        last = now;
        return std::chrono::microseconds(0);
    }

    auto wait = std::chrono::duration_cast<std::chrono::microseconds>(next_abs - now);
    last = next_abs;
    return wait;
}

// =====================================================================
// is_active
// =====================================================================

bool WFDefense::is_active() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_session_;
}

} // namespace DPI
} // namespace ncp
