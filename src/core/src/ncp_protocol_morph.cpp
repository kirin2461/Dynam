#include "../include/ncp_protocol_morph.hpp"
#include <sodium.h>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <numeric>

namespace ncp {

// ==================== Impl ====================

class ProtocolMorph::Impl {
public:
    Config config_;
    Stats stats_;
    mutable std::mutex mutex_;
    LogCallback log_cb_;

    // PRNG state for deterministic peer-synchronized selection
    uint8_t prng_key_[32] = {};
    uint64_t prng_counter_ = 0;
    bool deterministic_mode_ = false;

    // Mutation state
    uint64_t connection_count_ = 0;
    uint64_t mutation_epoch_ = 0;

    // Current mutation state
    BrowserType current_browser_ = BrowserType::CHROME;
    size_t browser_pool_idx_ = 0;

    void initialize(const Config& cfg) {
        config_ = cfg;

        if (!cfg.shared_seed.empty() && cfg.shared_seed.size() >= 32) {
            std::memcpy(prng_key_, cfg.shared_seed.data(), 32);
            deterministic_mode_ = true;
        } else {
            randombytes_buf(prng_key_, sizeof(prng_key_));
            deterministic_mode_ = false;
        }

        prng_counter_ = 0;
        connection_count_ = 0;
        mutation_epoch_ = 0;
        browser_pool_idx_ = 0;

        if (!cfg.mutation.browser_pool.empty()) {
            current_browser_ = cfg.mutation.browser_pool[0];
        }
    }

    // Deterministic PRNG: derive uint32 from key + counter
    uint32_t next_random() {
        // Use crypto_stream_xchacha20 to derive deterministic bytes
        uint8_t nonce[24] = {};
        // Encode counter into nonce
        uint64_t ctr = prng_counter_++;
        std::memcpy(nonce, &ctr, sizeof(ctr));

        uint8_t out[4];
        crypto_stream_xchacha20(out, sizeof(out), nonce, prng_key_);

        return (static_cast<uint32_t>(out[0]) << 24) |
               (static_cast<uint32_t>(out[1]) << 16) |
               (static_cast<uint32_t>(out[2]) << 8) |
                static_cast<uint32_t>(out[3]);
    }

    // Get current local hour (0-23) accounting for UTC offset
    uint8_t get_local_hour() const {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        struct tm utc_tm;
#ifdef _WIN32
        gmtime_s(&utc_tm, &time_t_now);
#else
        gmtime_r(&time_t_now, &utc_tm);
#endif
        int hour = utc_tm.tm_hour;
        int offset_hours = config_.schedule.utc_offset_minutes / 60;
        hour = (hour + offset_hours + 24) % 24;
        return static_cast<uint8_t>(hour);
    }

    // Check if hour falls within a slot (handles midnight wraparound)
    static bool hour_in_slot(uint8_t hour, uint8_t start, uint8_t end) {
        if (start < end) {
            return hour >= start && hour < end;
        } else {
            // Wraps midnight: e.g. 23:00 - 06:00
            return hour >= start || hour < end;
        }
    }

    // Build effective weights: base weights + schedule boosts
    std::vector<std::pair<TrafficMimicry::MimicProfile, uint32_t>> build_effective_weights() {
        std::vector<std::pair<TrafficMimicry::MimicProfile, uint32_t>> weights;

        for (const auto& pw : config_.profile_weights) {
            if (pw.weight > 0) {
                weights.push_back({pw.profile, pw.weight});
            }
        }

        // Apply schedule boosts
        if (config_.schedule.enabled) {
            uint8_t hour = get_local_hour();

            for (const auto& slot : config_.schedule.slots) {
                if (hour_in_slot(hour, slot.hour_start, slot.hour_end)) {
                    // Find or add this profile
                    bool found = false;
                    for (auto& w : weights) {
                        if (w.first == slot.profile) {
                            w.second += slot.weight_boost;
                            found = true;
                            break;
                        }
                    }
                    if (!found && slot.weight_boost > 0) {
                        weights.push_back({slot.profile, slot.weight_boost});
                    }
                    stats_.schedule_overrides++;
                }
            }
        }

        return weights;
    }

    // Weighted random selection from effective weights
    TrafficMimicry::MimicProfile select_weighted(
        const std::vector<std::pair<TrafficMimicry::MimicProfile, uint32_t>>& weights
    ) {
        if (weights.empty()) {
            return TrafficMimicry::MimicProfile::HTTPS_APPLICATION;
        }

        uint32_t total = 0;
        for (const auto& w : weights) {
            total += w.second;
        }
        if (total == 0) {
            return weights[0].first;
        }

        uint32_t roll = next_random() % total;
        uint32_t cumulative = 0;
        for (const auto& w : weights) {
            cumulative += w.second;
            if (roll < cumulative) {
                return w.first;
            }
        }

        return weights.back().first;
    }

    // Perform wire format mutation
    void perform_mutation(ConnectionProfile& cp) {
        mutation_epoch_++;
        stats_.mutations_performed++;

        // Rotate browser profile
        if (config_.mutation.rotate_browser_profile && !config_.mutation.browser_pool.empty()) {
            browser_pool_idx_ = (browser_pool_idx_ + 1) % config_.mutation.browser_pool.size();
            current_browser_ = config_.mutation.browser_pool[browser_pool_idx_];
        }

        // Generate new cipher suite order
        if (config_.mutation.rotate_cipher_priority) {
            // Start with common TLS 1.3 + 1.2 suites, shuffle order
            cp.tls_cipher_suites = {
                0x1301, 0x1302, 0x1303,  // TLS 1.3
                0xC02F, 0xC030, 0xCCA8,  // ECDHE-RSA
                0xC02B, 0xC02C           // ECDHE-ECDSA
            };
            // Fisher-Yates shuffle using our PRNG
            for (size_t i = cp.tls_cipher_suites.size() - 1; i > 0; --i) {
                size_t j = next_random() % (i + 1);
                std::swap(cp.tls_cipher_suites[i], cp.tls_cipher_suites[j]);
            }
        }

        // Shuffle TLS extension order
        if (config_.mutation.shuffle_extension_order) {
            cp.tls_extensions = {
                0,   // server_name
                10,  // supported_groups
                11,  // ec_point_formats
                13,  // signature_algorithms
                16,  // ALPN
                23,  // extended_master_secret
                35,  // session_ticket
                43,  // supported_versions
                45,  // psk_key_exchange_modes
                51   // key_share
            };
            for (size_t i = cp.tls_extensions.size() - 1; i > 0; --i) {
                size_t j = next_random() % (i + 1);
                std::swap(cp.tls_extensions[i], cp.tls_extensions[j]);
            }
        }

        // Mutate ALPN protocols
        if (config_.mutation.mutate_alpn) {
            // Common ALPN variations seen in the wild
            static const std::vector<std::vector<std::string>> alpn_sets = {
                {"h2", "http/1.1"},
                {"h2"},
                {"http/1.1"},
                {"h2", "http/1.1", "http/1.0"},
                {"h3", "h2", "http/1.1"},
            };
            size_t idx = next_random() % alpn_sets.size();
            cp.alpn_protocols = alpn_sets[idx];
        }

        cp.browser_profile = current_browser_;
        cp.mutation_epoch = mutation_epoch_;

        log("[ProtocolMorph] Wire mutation #" + std::to_string(mutation_epoch_) +
            " \u2014 browser=" + browser_name(current_browser_));
    }

    static std::string browser_name(BrowserType bt) {
        switch (bt) {
            case BrowserType::CHROME: return "Chrome";
            case BrowserType::FIREFOX: return "Firefox";
            case BrowserType::SAFARI: return "Safari";
            case BrowserType::EDGE: return "Edge";
            case BrowserType::ANDROID_CHROME: return "Android-Chrome";
            case BrowserType::IOS_SAFARI: return "iOS-Safari";
            default: return "Unknown";
        }
    }

    static std::string profile_name(TrafficMimicry::MimicProfile p) {
        switch (p) {
            case TrafficMimicry::MimicProfile::HTTP_GET: return "HTTP_GET";
            case TrafficMimicry::MimicProfile::HTTP_POST: return "HTTP_POST";
            case TrafficMimicry::MimicProfile::HTTPS_CLIENT_HELLO: return "TLS_CH";
            case TrafficMimicry::MimicProfile::HTTPS_APPLICATION: return "TLS_APP";
            case TrafficMimicry::MimicProfile::DNS_QUERY: return "DNS_Q";
            case TrafficMimicry::MimicProfile::DNS_RESPONSE: return "DNS_R";
            case TrafficMimicry::MimicProfile::QUIC_INITIAL: return "QUIC";
            case TrafficMimicry::MimicProfile::WEBSOCKET: return "WS";
            case TrafficMimicry::MimicProfile::BITTORRENT: return "BT";
            case TrafficMimicry::MimicProfile::SKYPE: return "Skype";
            case TrafficMimicry::MimicProfile::ZOOM: return "Zoom";
            case TrafficMimicry::MimicProfile::GENERIC_TCP: return "TCP";
            case TrafficMimicry::MimicProfile::GENERIC_UDP: return "UDP";
            default: return "?";
        }
    }

    void log(const std::string& msg) {
        if (log_cb_) {
            log_cb_(msg);
        }
    }
};

// ==================== ProtocolMorph lifecycle ====================

ProtocolMorph::ProtocolMorph() : impl_(std::make_unique<Impl>()) {
    impl_->initialize(Config{});
}

ProtocolMorph::ProtocolMorph(const Config& config) : impl_(std::make_unique<Impl>()) {
    impl_->initialize(config);
}

ProtocolMorph::~ProtocolMorph() = default;

void ProtocolMorph::set_config(const Config& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialize(config);
}

ProtocolMorph::Config ProtocolMorph::get_config() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->config_;
}

// ==================== Core API ====================

ProtocolMorph::ConnectionProfile ProtocolMorph::select_profile_for_connection() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    ConnectionProfile cp;
    cp.connection_id = impl_->connection_count_;
    cp.mutation_epoch = impl_->mutation_epoch_;

    // 1. Build effective weights (base + schedule boosts)
    auto weights = impl_->build_effective_weights();

    // 2. Weighted random selection
    cp.mimic_profile = impl_->select_weighted(weights);

    // 3. Apply wire mutation if threshold reached
    bool should_mutate = (impl_->connection_count_ > 0) &&
        (impl_->connection_count_ % impl_->config_.mutation.connections_per_mutation == 0);

    if (should_mutate) {
        impl_->perform_mutation(cp);
    } else {
        // Use current mutation state
        cp.browser_profile = impl_->current_browser_;
        cp.mutation_epoch = impl_->mutation_epoch_;
    }

    // 4. Build MimicConfig from selected profile
    cp.mimic_config.profile = cp.mimic_profile;
    cp.mimic_config.enable_timing_mimicry = true;
    cp.mimic_config.enable_size_mimicry = true;
    cp.mimic_config.enable_pattern_mimicry = true;
    cp.mimic_config.randomize_fields = true;

    // If TLS-based, apply cipher suites to config
    if (!cp.tls_cipher_suites.empty()) {
        cp.mimic_config.tls_cipher_suites = cp.tls_cipher_suites;
    }

    // Track usage
    impl_->stats_.profile_usage[cp.mimic_profile]++;

    impl_->log("[ProtocolMorph] Connection #" + std::to_string(cp.connection_id) +
               " \u2192 " + Impl::profile_name(cp.mimic_profile) +
               " (epoch " + std::to_string(cp.mutation_epoch) + ")");

    return cp;
}

void ProtocolMorph::on_connection_opened() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->connection_count_++;
    impl_->stats_.connections_total++;
}

TrafficMimicry::MimicProfile ProtocolMorph::get_scheduled_profile() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);

    if (!impl_->config_.schedule.enabled || impl_->config_.schedule.slots.empty()) {
        return TrafficMimicry::MimicProfile::HTTPS_APPLICATION;
    }

    uint8_t hour = impl_->get_local_hour();

    for (const auto& slot : impl_->config_.schedule.slots) {
        if (Impl::hour_in_slot(hour, slot.hour_start, slot.hour_end)) {
            return slot.profile;
        }
    }

    return TrafficMimicry::MimicProfile::HTTPS_APPLICATION;
}

void ProtocolMorph::force_mutation() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    ConnectionProfile cp;
    impl_->perform_mutation(cp);
}

uint64_t ProtocolMorph::get_mutation_epoch() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->mutation_epoch_;
}

// ==================== Stats ====================

ProtocolMorph::Stats ProtocolMorph::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->stats_;
}

void ProtocolMorph::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->stats_.connections_total = 0;
    impl_->stats_.mutations_performed = 0;
    impl_->stats_.schedule_overrides = 0;
    impl_->stats_.profile_usage.clear();
}

// ==================== Logging ====================

void ProtocolMorph::set_log_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->log_cb_ = cb;
}

} // namespace ncp
