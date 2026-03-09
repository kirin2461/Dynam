/**
 * @file ncp_transport_manager.cpp
 * @brief Implementations for ProtocolRotationSchedule, ASAwareRouter, GeoObfuscator
 *
 * See ncp_transport_manager.hpp for full documentation.
 *
 * C++17 / MSVC-compatible.
 */

#include "ncp_transport_manager.hpp"

#include <algorithm>
#include <ctime>
#include <numeric>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#  include <windows.h>   // SYSTEMTIME used by current_hour_utc_()
#endif

namespace ncp {

// ============================================================
// ============================================================
//   ProtocolRotationSchedule
// ============================================================
// ============================================================

// ---- helpers ------------------------------------------------

static const char* protocol_name(TransportProtocol p) {
    switch (p) {
        case TransportProtocol::OBFS4:             return "OBFS4";
        case TransportProtocol::WEBSOCKET_TLS:     return "WEBSOCKET_TLS";
        case TransportProtocol::QUIC_LIKE:         return "QUIC_LIKE";
        case TransportProtocol::RAW_TLS_1_3:       return "RAW_TLS_1_3";
        case TransportProtocol::MEEK_FRONTING:     return "MEEK_FRONTING";
        case TransportProtocol::SHADOWSOCKS_AEAD:  return "SHADOWSOCKS_AEAD";
        default:                                    return "UNKNOWN";
    }
}

// ---- constructors -------------------------------------------

ProtocolRotationSchedule::ProtocolRotationSchedule()
    : last_rotation_time_(std::chrono::steady_clock::now())
{
    // Read config overrides
    const auto& cfg = Config::instance();
    config_.enabled               = cfg.getBool("protocol_rotation.enabled", true);
    config_.min_protocol_duration = std::chrono::minutes(
        cfg.getInt("protocol_rotation.min_duration_minutes", 30));
    config_.max_protocol_duration = std::chrono::minutes(
        cfg.getInt("protocol_rotation.max_duration_minutes", 120));
    config_.randomize_within_slot = cfg.getBool("protocol_rotation.randomize", true);

    load_default_schedule();
    NCP_LOG_INFO("[ProtocolRotationSchedule] Initialized with default schedule");
}

ProtocolRotationSchedule::ProtocolRotationSchedule(const ProtocolRotationConfig& cfg)
    : config_(cfg),
      last_rotation_time_(std::chrono::steady_clock::now())
{
    NCP_LOG_INFO("[ProtocolRotationSchedule] Initialized with custom config");
}

// ---- default schedule ---------------------------------------

void ProtocolRotationSchedule::load_default_schedule() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.schedule.clear();

    // 06:00 – 18:00 UTC: business hours — blend with HTTPS
    TimeSlot day;
    day.start_hour = 6;
    day.end_hour   = 18;
    day.allowed_protocols = {
        TransportProtocol::WEBSOCKET_TLS,
        TransportProtocol::QUIC_LIKE
    };
    day.preferred = TransportProtocol::WEBSOCKET_TLS;
    config_.schedule.push_back(std::move(day));

    // 18:00 – 00:00 UTC: evening — diverse traffic mix
    TimeSlot evening;
    evening.start_hour = 18;
    evening.end_hour   = 0;   // wraps midnight
    evening.allowed_protocols = {
        TransportProtocol::OBFS4,
        TransportProtocol::SHADOWSOCKS_AEAD,
        TransportProtocol::WEBSOCKET_TLS
    };
    evening.preferred = TransportProtocol::OBFS4;
    config_.schedule.push_back(std::move(evening));

    // 00:00 – 06:00 UTC: night — low traffic, use stealthy protocols
    TimeSlot night;
    night.start_hour = 0;
    night.end_hour   = 6;
    night.allowed_protocols = {
        TransportProtocol::RAW_TLS_1_3,
        TransportProtocol::MEEK_FRONTING
    };
    night.preferred = TransportProtocol::RAW_TLS_1_3;
    config_.schedule.push_back(std::move(night));

    NCP_LOG_DEBUG("[ProtocolRotationSchedule] Default schedule loaded "
                  "(day=WEBSOCKET/QUIC, evening=OBFS4/SS, night=RAW_TLS/MEEK)");
}

// ---- private helpers ----------------------------------------

uint8_t ProtocolRotationSchedule::current_hour_utc_() const {
#ifdef _WIN32
    SYSTEMTIME st;
    GetSystemTime(&st);
    return static_cast<uint8_t>(st.wHour);
#else
    std::time_t t = std::time(nullptr);
    // R10-FIX-08: Validate time result and check gmtime_r return value
    if (t == static_cast<std::time_t>(-1)) {
        return 0;  // Fallback to hour 0 on error
    }
    std::tm utc_tm{};
    if (!gmtime_r(&t, &utc_tm)) {
        return 0;  // Fallback to hour 0 on conversion error
    }
    return static_cast<uint8_t>(utc_tm.tm_hour);
#endif
}

const TimeSlot* ProtocolRotationSchedule::find_current_slot_() const {
    // Assumes mutex already held by caller
    uint8_t hour = current_hour_utc_();
    for (const auto& slot : config_.schedule) {
        if (slot.start_hour < slot.end_hour) {
            // Normal window (e.g. 6–18)
            if (hour >= slot.start_hour && hour < slot.end_hour) {
                return &slot;
            }
        } else {
            // Wraps midnight (e.g. 18–0 means 18–23 + 0)
            if (hour >= slot.start_hour || hour < slot.end_hour) {
                return &slot;
            }
        }
    }
    return nullptr;
}

// ---- public API ---------------------------------------------

TransportProtocol ProtocolRotationSchedule::get_current_protocol() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return current_protocol_;
    }

    const TimeSlot* slot = find_current_slot_();
    if (!slot) {
        // No matching slot; keep current
        return current_protocol_;
    }

    // At HIGH/CRITICAL threat, prefer more obfuscated protocols
    if (threat_level_ >= ThreatLevel::HIGH) {
        // Prefer OBFS4 or SHADOWSOCKS at high threat
        for (const auto& proto : slot->allowed_protocols) {
            if (proto == TransportProtocol::OBFS4 ||
                proto == TransportProtocol::SHADOWSOCKS_AEAD ||
                proto == TransportProtocol::MEEK_FRONTING) {
                return proto;
            }
        }
    }

    return slot->preferred;
}

bool ProtocolRotationSchedule::should_rotate() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) return false;

    auto now     = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
                       now - last_rotation_time_);

    // Forced rotation when max duration exceeded
    if (elapsed >= config_.max_protocol_duration) {
        NCP_LOG_DEBUG("[ProtocolRotationSchedule] Max protocol duration reached, rotation due");
        return true;
    }

    // Check if current protocol is still in the current slot's allowed list
    if (elapsed >= config_.min_protocol_duration) {
        const TimeSlot* slot = find_current_slot_();
        if (slot) {
            bool still_valid = false;
            for (const auto& p : slot->allowed_protocols) {
                if (p == current_protocol_) { still_valid = true; break; }
            }
            if (!still_valid) {
                NCP_LOG_DEBUG("[ProtocolRotationSchedule] Current protocol not in slot, rotation due");
                return true;
            }
        }
    }

    return false;
}

TransportProtocol ProtocolRotationSchedule::rotate() {
    std::lock_guard<std::mutex> lock(mutex_);

    const TimeSlot* slot = find_current_slot_();
    TransportProtocol next = current_protocol_;

    if (slot && !slot->allowed_protocols.empty()) {
        if (config_.randomize_within_slot && slot->allowed_protocols.size() > 1) {
            // Pick randomly from the allowed list, avoiding the current one if possible
            std::vector<TransportProtocol> candidates;
            for (const auto& p : slot->allowed_protocols) {
                if (p != current_protocol_) candidates.push_back(p);
            }
            if (candidates.empty()) candidates = slot->allowed_protocols;

            uint32_t idx = csprng_uniform(static_cast<uint32_t>(candidates.size()));
            next = candidates[idx];
        } else {
            next = slot->preferred;
        }
    } else {
        // No slot — cycle through all protocol enum values (6 total)
        int cur = static_cast<int>(current_protocol_);
        cur = (cur + 1) % 6;
        next = static_cast<TransportProtocol>(cur);
    }

    bool was_forced = std::chrono::duration_cast<std::chrono::minutes>(
        std::chrono::steady_clock::now() - last_rotation_time_)
        >= config_.max_protocol_duration;

    std::ostringstream oss;
    oss << "[ProtocolRotationSchedule] Rotate: "
        << protocol_name(current_protocol_) << " -> " << protocol_name(next)
        << (was_forced ? " (forced)" : "");
    NCP_LOG_INFO(oss.str());

    current_protocol_  = next;
    last_rotation_time_ = std::chrono::steady_clock::now();
    stats_.rotations.fetch_add(1);
    if (was_forced) stats_.forced_rotations.fetch_add(1);

    return current_protocol_;
}

std::vector<TransportProtocol> ProtocolRotationSchedule::get_allowed_protocols() const {
    std::lock_guard<std::mutex> lock(mutex_);
    const TimeSlot* slot = find_current_slot_();
    if (slot) return slot->allowed_protocols;
    // Return all protocols when no slot matches
    return {
        TransportProtocol::OBFS4,
        TransportProtocol::WEBSOCKET_TLS,
        TransportProtocol::QUIC_LIKE,
        TransportProtocol::RAW_TLS_1_3,
        TransportProtocol::MEEK_FRONTING,
        TransportProtocol::SHADOWSOCKS_AEAD
    };
}

// ---- config / stats -----------------------------------------

void ProtocolRotationSchedule::set_config(const ProtocolRotationConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[ProtocolRotationSchedule] Config updated");
}

ProtocolRotationConfig ProtocolRotationSchedule::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

ProtocolRotationStats ProtocolRotationSchedule::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void ProtocolRotationSchedule::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    NCP_LOG_DEBUG("[ProtocolRotationSchedule] Stats reset");
}

void ProtocolRotationSchedule::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (level != threat_level_) {
        std::ostringstream oss;
        oss << "[ProtocolRotationSchedule] Threat level changed to "
            << static_cast<int>(level);
        NCP_LOG_INFO(oss.str());
        threat_level_ = level;
        // At CRITICAL, force an immediate rotation
        if (level == ThreatLevel::CRITICAL) {
            last_rotation_time_ = std::chrono::steady_clock::now() -
                                   config_.max_protocol_duration;
        }
    }
}


// ============================================================
// ============================================================
//   ASAwareRouter
// ============================================================
// ============================================================

ASAwareRouter::ASAwareRouter()
    : last_rebalance_(std::chrono::steady_clock::now())
{
    const auto& cfg = Config::instance();
    config_.enabled               = cfg.getBool("as_router.enabled", true);
    config_.max_connections_per_as = static_cast<size_t>(
        cfg.getInt("as_router.max_connections_per_as", 3));
    config_.prefer_cdn            = cfg.getBool("as_router.prefer_cdn", true);
    config_.balance_ratio         = 0.3;
    config_.rebalance_interval    = std::chrono::minutes(
        cfg.getInt("as_router.rebalance_interval_minutes", 10));

    load_default_entries();
    NCP_LOG_INFO("[ASAwareRouter] Initialized with default AS entries");
}

ASAwareRouter::ASAwareRouter(const ASAwareRouterConfig& cfg)
    : config_(cfg),
      last_rebalance_(std::chrono::steady_clock::now())
{
    NCP_LOG_INFO("[ASAwareRouter] Initialized with custom config");
}

// ---- default entries ----------------------------------------

void ASAwareRouter::load_default_entries() {
    std::lock_guard<std::mutex> lock(mutex_);
    as_entries_.clear();

    // Five well-known CDN/cloud ASes used for fronting
    ASEntry cf;
    cf.asn    = 13335; cf.name = "Cloudflare";
    cf.ip_range = "104.16.0.0/12"; cf.weight = 1.5; cf.is_cdn = true;
    as_entries_.push_back(cf);

    ASEntry ak;
    ak.asn    = 20940; ak.name = "Akamai";
    ak.ip_range = "23.32.0.0/11";  ak.weight = 1.2; ak.is_cdn = true;
    as_entries_.push_back(ak);

    ASEntry fa;
    fa.asn    = 54113; fa.name = "Fastly";
    fa.ip_range = "151.101.0.0/16"; fa.weight = 1.0; fa.is_cdn = true;
    as_entries_.push_back(fa);

    ASEntry aws;
    aws.asn   = 16509; aws.name = "AWS CloudFront";
    aws.ip_range = "13.32.0.0/15"; aws.weight = 1.0; aws.is_cdn = true;
    as_entries_.push_back(aws);

    ASEntry gcp;
    gcp.asn   = 15169; gcp.name = "Google Cloud CDN";
    gcp.ip_range = "34.64.0.0/10"; gcp.weight = 0.9; gcp.is_cdn = true;
    as_entries_.push_back(gcp);

    NCP_LOG_DEBUG("[ASAwareRouter] Loaded 5 default AS entries "
                  "(Cloudflare/Akamai/Fastly/AWS/GCP)");
}

// ---- private helpers ----------------------------------------

double ASAwareRouter::compute_max_fraction_() const {
    // Assumes mutex held by caller
    uint64_t total = 0;
    for (const auto& e : as_entries_) total += e.bytes_sent;
    if (total == 0) return 0.0;

    uint64_t max_bytes = 0;
    for (const auto& e : as_entries_) {
        if (e.bytes_sent > max_bytes) max_bytes = e.bytes_sent;
    }
    return static_cast<double>(max_bytes) / static_cast<double>(total);
}

// ---- public API ---------------------------------------------

void ASAwareRouter::add_as_entry(const ASEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    as_entries_.push_back(entry);
    std::ostringstream oss;
    oss << "[ASAwareRouter] Added AS" << entry.asn << " (" << entry.name << ")";
    NCP_LOG_DEBUG(oss.str());
}

const ASEntry* ASAwareRouter::select_next_as() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled || as_entries_.empty()) return nullptr;

    // Auto-rebalance if interval expired
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(
        std::chrono::steady_clock::now() - last_rebalance_);
    if (elapsed >= config_.rebalance_interval) {
        // Rebalance inline (does not recurse because we hold the lock)
        for (auto& e : as_entries_) {
            e.active_connections = 0;
            e.bytes_sent         = 0;
        }
        last_rebalance_ = std::chrono::steady_clock::now();
        stats_.rebalances.fetch_add(1);
        NCP_LOG_DEBUG("[ASAwareRouter] Auto-rebalance triggered");
    }

    // Build candidate list
    std::vector<ASEntry*> candidates;
    for (auto& e : as_entries_) {
        if (e.active_connections >= config_.max_connections_per_as) continue;
        candidates.push_back(&e);
    }
    if (candidates.empty()) {
        NCP_LOG_WARN("[ASAwareRouter] All AS entries at max connections");
        return nullptr;
    }

    // Compute selection weight for each candidate
    // Weight = AS weight
    //        + CDN bonus (if prefer_cdn)
    //        - overload penalty (active_connections / max_connections_per_as)
    // At HIGH/CRITICAL threat: increase diversity (reduce weight of most-used)
    std::vector<double> weights;
    weights.reserve(candidates.size());
    for (const auto* e : candidates) {
        double w = e->weight;
        if (config_.prefer_cdn && e->is_cdn) w *= 1.4;
        double load_factor = (config_.max_connections_per_as > 0)
            ? static_cast<double>(e->active_connections) /
              static_cast<double>(config_.max_connections_per_as)
            : 0.0;
        w *= (1.0 - 0.5 * load_factor); // penalise loaded ASes
        if (threat_level_ >= ThreatLevel::HIGH) {
            // Reduce weight of heavily trafficked AS for diversity
            uint64_t total_bytes = 0;
            for (const auto& ae : as_entries_) total_bytes += ae.bytes_sent;
            if (total_bytes > 0) {
                double share = static_cast<double>(e->bytes_sent) /
                               static_cast<double>(total_bytes);
                w *= (1.0 - share);
            }
        }
        weights.push_back(w > 0.0 ? w : 0.01);
    }

    // Weighted random selection
    double total_w = 0.0;
    for (double ww : weights) total_w += ww;
    double r = csprng_double() * total_w;
    double acc = 0.0;
    ASEntry* chosen = candidates.back();
    for (size_t i = 0; i < candidates.size(); ++i) {
        acc += weights[i];
        if (r <= acc) { chosen = candidates[i]; break; }
    }

    chosen->active_connections++;
    stats_.connections_routed.fetch_add(1);
    if (chosen->is_cdn) stats_.cdn_connections.fetch_add(1);

    std::ostringstream oss;
    oss << "[ASAwareRouter] Routed to AS" << chosen->asn
        << " (" << chosen->name << ") active=" << chosen->active_connections;
    NCP_LOG_DEBUG(oss.str());

    return chosen;
}

void ASAwareRouter::record_traffic(uint32_t asn, size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& e : as_entries_) {
        if (e.asn == asn) {
            e.bytes_sent += bytes;
            return;
        }
    }
    NCP_LOG_DEBUG("[ASAwareRouter] record_traffic: unknown ASN " +
                  std::to_string(asn));
}

void ASAwareRouter::release_connection(uint32_t asn) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& e : as_entries_) {
        if (e.asn == asn) {
            if (e.active_connections > 0) --e.active_connections;
            return;
        }
    }
}

bool ASAwareRouter::is_balanced() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return compute_max_fraction_() <= config_.balance_ratio;
}

void ASAwareRouter::rebalance() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& e : as_entries_) {
        e.active_connections = 0;
        e.bytes_sent         = 0;
    }
    last_rebalance_ = std::chrono::steady_clock::now();
    stats_.rebalances.fetch_add(1);
    NCP_LOG_INFO("[ASAwareRouter] Manual rebalance complete");
}

// ---- config / stats -----------------------------------------

void ASAwareRouter::set_config(const ASAwareRouterConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[ASAwareRouter] Config updated");
}

ASAwareRouterConfig ASAwareRouter::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

ASAwareRouterStats ASAwareRouter::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void ASAwareRouter::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    NCP_LOG_DEBUG("[ASAwareRouter] Stats reset");
}

void ASAwareRouter::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (level != threat_level_) {
        std::ostringstream oss;
        oss << "[ASAwareRouter] Threat level changed to "
            << static_cast<int>(level);
        NCP_LOG_INFO(oss.str());
        threat_level_ = level;
        // At CRITICAL, reset bytes_sent to re-randomise distribution
        if (level == ThreatLevel::CRITICAL) {
            for (auto& e : as_entries_) e.bytes_sent = 0;
        }
    }
}


// ============================================================
// ============================================================
//   GeoObfuscator
// ============================================================
// ============================================================

GeoObfuscator::GeoObfuscator() {
    const auto& cfg = Config::instance();
    config_.enabled               = cfg.getBool("geo_obfuscator.enabled", true);
    config_.home_region           = cfg.get("geo_obfuscator.home_region", "RU");
    config_.max_rtt_penalty_ms    = 100.0;
    config_.auto_select_region    = cfg.getBool("geo_obfuscator.auto_select", true);
    config_.health_check_interval = std::chrono::minutes(
        cfg.getInt("geo_obfuscator.health_check_minutes", 5));
    config_.preferred_exit_regions = {"DE", "NL", "FI", "SE"};

    load_default_nodes();
    NCP_LOG_INFO("[GeoObfuscator] Initialized (home=" + config_.home_region + ")");
}

GeoObfuscator::GeoObfuscator(const GeoObfuscatorConfig& cfg)
    : config_(cfg)
{
    NCP_LOG_INFO("[GeoObfuscator] Initialized with custom config (home=" +
                 config_.home_region + ")");
}

// ---- default nodes ------------------------------------------

void GeoObfuscator::load_default_nodes() {
    std::lock_guard<std::mutex> lock(mutex_);
    exit_nodes_.clear();

    auto now = std::chrono::steady_clock::now();

    // Helper lambda to push two nodes per region
    auto push = [&](const char* code, const char* name,
                    double lat, double lon, double rtt,
                    const char* addr1, uint16_t port1,
                    const char* addr2, uint16_t port2)
    {
        GeoRegion region{code, name, lat, lon, rtt, 1.0};

        GeoExitNode n1;
        n1.address  = addr1; n1.port = port1;
        n1.region   = region; n1.measured_rtt_ms = rtt;
        n1.is_alive = true;   n1.last_check = now;
        exit_nodes_.push_back(n1);

        GeoExitNode n2;
        n2.address  = addr2; n2.port = port2;
        n2.region   = region; n2.measured_rtt_ms = rtt + 5.0;
        n2.is_alive = true;   n2.last_check = now;
        exit_nodes_.push_back(n2);
    };

    // Germany — Frankfurt
    push("DE", "Germany",    50.1109,  8.6821, 45.0,
         "de-exit-01.example.ncp", 4443,
         "de-exit-02.example.ncp", 4443);

    // Netherlands — Amsterdam
    push("NL", "Netherlands", 52.3676,  4.9041, 50.0,
         "nl-exit-01.example.ncp", 4443,
         "nl-exit-02.example.ncp", 4443);

    // Finland — Helsinki
    push("FI", "Finland",     60.1699, 24.9384, 35.0,
         "fi-exit-01.example.ncp", 4443,
         "fi-exit-02.example.ncp", 4443);

    // Sweden — Stockholm
    push("SE", "Sweden",      59.3293, 18.0686, 38.0,
         "se-exit-01.example.ncp", 4443,
         "se-exit-02.example.ncp", 4443);

    NCP_LOG_DEBUG("[GeoObfuscator] Loaded 8 default exit nodes (DE/NL/FI/SE, 2 each)");
}

// ---- private helpers ----------------------------------------

double GeoObfuscator::compute_node_score_(const GeoExitNode& node) const {
    // Assumes mutex held by caller
    if (!node.is_alive) return -1.0;

    // Base score: inverse RTT (lower RTT => higher score)
    double rtt_ref = node.region.expected_rtt_ms > 0.0
                     ? node.region.expected_rtt_ms : 50.0;
    double rtt_score = rtt_ref / (node.measured_rtt_ms > 0.0
                                   ? node.measured_rtt_ms : rtt_ref);

    // Region weight from GeoRegion
    double score = rtt_score * node.region.weight;

    // Penalty if measured RTT exceeds expected + max penalty
    double rtt_excess = node.measured_rtt_ms - node.region.expected_rtt_ms;
    if (rtt_excess > config_.max_rtt_penalty_ms) {
        score *= 0.5; // significant penalty
    }

    // Small cryptographic random factor (up to 10%) to break ties
    score += csprng_double() * 0.1;

    return score;
}

std::vector<GeoExitNode*>
GeoObfuscator::get_alive_nodes_in_region_(const std::string& region) {
    // Assumes mutex held by caller
    std::vector<GeoExitNode*> result;
    for (auto& n : exit_nodes_) {
        if (n.is_alive && n.region.code == region) {
            result.push_back(&n);
        }
    }
    return result;
}

// ---- public API ---------------------------------------------

void GeoObfuscator::add_exit_node(const GeoExitNode& node) {
    std::lock_guard<std::mutex> lock(mutex_);
    exit_nodes_.push_back(node);
    NCP_LOG_DEBUG("[GeoObfuscator] Added exit node " + node.address +
                  " (" + node.region.code + ")");
}

const GeoExitNode* GeoObfuscator::select_exit_node() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) return nullptr;

    // Determine candidate region list
    std::vector<std::string> regions;
    if (threat_level_ >= ThreatLevel::HIGH) {
        // High threat: use ALL available regions for diversity
        for (const auto& n : exit_nodes_) {
            if (!n.is_alive) continue;
            bool found = false;
            for (const auto& r : regions) {
                if (r == n.region.code) { found = true; break; }
            }
            if (!found) regions.push_back(n.region.code);
        }
        NCP_LOG_DEBUG("[GeoObfuscator] High threat: using all available regions");
    } else {
        regions = config_.preferred_exit_regions;
    }

    // Score all alive nodes across candidate regions
    const GeoExitNode* best = nullptr;
    double best_score = -1.0;

    for (const auto& region : regions) {
        for (const auto& n : exit_nodes_) {
            if (!n.is_alive || n.region.code != region) continue;
            double s = compute_node_score_(n);
            if (s > best_score) {
                best_score = s;
                best       = &n;
            }
        }
    }

    if (!best) {
        NCP_LOG_WARN("[GeoObfuscator] No alive exit node found");
        return nullptr;
    }

    // Track region switch
    if (best->region.code != current_region_) {
        stats_.region_switches.fetch_add(1);
        std::ostringstream oss;
        oss << "[GeoObfuscator] Region switch: "
            << current_region_ << " -> " << best->region.code;
        NCP_LOG_INFO(oss.str());
        current_region_ = best->region.code;
    }

    stats_.connections_routed.fetch_add(1);
    NCP_LOG_DEBUG("[GeoObfuscator] Selected exit node " + best->address +
                  " (" + best->region.code + ", score=" +
                  std::to_string(best_score) + ")");
    return best;
}

const GeoExitNode* GeoObfuscator::select_exit_in_region(const std::string& region_code) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) return nullptr;

    const GeoExitNode* best = nullptr;
    double best_score = -1.0;

    for (const auto& n : exit_nodes_) {
        if (!n.is_alive || n.region.code != region_code) continue;
        double s = compute_node_score_(n);
        if (s > best_score) {
            best_score = s;
            best       = &n;
        }
    }

    if (!best) {
        NCP_LOG_WARN("[GeoObfuscator] No alive exit node in region " + region_code);
        return nullptr;
    }

    stats_.connections_routed.fetch_add(1);
    NCP_LOG_DEBUG("[GeoObfuscator] Region-specific select: " + best->address +
                  " (" + region_code + ")");
    return best;
}

void GeoObfuscator::record_node_rtt(const std::string& address, double rtt_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& n : exit_nodes_) {
        if (n.address == address) {
            n.measured_rtt_ms = rtt_ms;
            NCP_LOG_DEBUG("[GeoObfuscator] RTT update: " + address +
                          " = " + std::to_string(rtt_ms) + " ms");
            return;
        }
    }
    NCP_LOG_DEBUG("[GeoObfuscator] record_node_rtt: unknown node " + address);
}

void GeoObfuscator::set_node_status(const std::string& address, bool alive) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& n : exit_nodes_) {
        if (n.address == address) {
            if (n.is_alive && !alive) {
                stats_.dead_nodes_detected.fetch_add(1);
                NCP_LOG_WARN("[GeoObfuscator] Node dead: " + address);
            } else if (!n.is_alive && alive) {
                NCP_LOG_INFO("[GeoObfuscator] Node recovered: " + address);
            }
            n.is_alive  = alive;
            n.last_check = std::chrono::steady_clock::now();
            return;
        }
    }
    NCP_LOG_DEBUG("[GeoObfuscator] set_node_status: unknown node " + address);
}

std::vector<std::string> GeoObfuscator::get_available_regions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> regions;
    for (const auto& n : exit_nodes_) {
        if (!n.is_alive) continue;
        bool found = false;
        for (const auto& r : regions) {
            if (r == n.region.code) { found = true; break; }
        }
        if (!found) regions.push_back(n.region.code);
    }
    return regions;
}

void GeoObfuscator::run_health_checks() {
    stats_.health_checks.fetch_add(1);
    std::lock_guard<std::mutex> lock(mutex_);

    // Placeholder: in a real implementation, this would spawn async probes
    // to each exit node and call set_node_status() with the result.
    std::ostringstream oss;
    oss << "[GeoObfuscator] Health-check pass #" << stats_.health_checks.load()
        << " — checking " << exit_nodes_.size() << " node(s) "
        "(async probes not yet wired)";
    NCP_LOG_INFO(oss.str());

    // Reset last_check timestamps so callers know a check was attempted
    auto now = std::chrono::steady_clock::now();
    for (auto& n : exit_nodes_) n.last_check = now;
}

// ---- config / stats -----------------------------------------

void GeoObfuscator::set_config(const GeoObfuscatorConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[GeoObfuscator] Config updated");
}

GeoObfuscatorConfig GeoObfuscator::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

GeoObfuscatorStats GeoObfuscator::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void GeoObfuscator::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    NCP_LOG_DEBUG("[GeoObfuscator] Stats reset");
}

void GeoObfuscator::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (level != threat_level_) {
        std::ostringstream oss;
        oss << "[GeoObfuscator] Threat level changed to "
            << static_cast<int>(level);
        NCP_LOG_INFO(oss.str());
        threat_level_ = level;
    }
}


} // namespace ncp
