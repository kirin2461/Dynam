/**
 * @file ncp_session_fragmenter.cpp
 * @brief SessionFragmenter implementation
 *
 * Defeats TSPU statistical VPN analysis by capping TCP session lifetimes
 * at a randomized value in [min_session_lifetime, max_session_lifetime] and
 * reopening connections through a freshly-generated ephemeral source port.
 *
 * C++17 / MSVC-compatible. libsodium CSPRNG used throughout — no mt19937.
 */

#include "../include/ncp_session_fragmenter.hpp"

#include <sstream>
#include <algorithm>
#include <cassert>

// ---------------------------------------------------------------------------
// Platform helpers (not strictly required here but kept for parity with
// other ncp modules that use socket APIs)
// ---------------------------------------------------------------------------
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#elif defined(__linux__)
#  include <arpa/inet.h>
#endif

namespace ncp {

// ---------------------------------------------------------------------------
// Anonymous-namespace utilities
// ---------------------------------------------------------------------------
namespace {

/// Build the canonical flow key string "srcIP:srcPort-dstIP:dstPort".
inline std::string make_flow_key(const std::string& src_ip, uint16_t src_port,
                                  const std::string& dst_ip, uint16_t dst_port)
{
    std::ostringstream oss;
    oss << src_ip << ':' << src_port << '-' << dst_ip << ':' << dst_port;
    return oss.str();
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

SessionFragmenter::SessionFragmenter()
{
    // Read config overrides from ncp_config (optional — sane defaults apply)
    bool   en  = Config::instance().getBool("session_fragmenter.enabled",    true);
    int    mx  = Config::instance().getInt ("session_fragmenter.max_lifetime", 120);
    int    mn  = Config::instance().getInt ("session_fragmenter.min_lifetime",  60);
    int    ps  = Config::instance().getInt ("session_fragmenter.port_start",  49152);
    int    pe  = Config::instance().getInt ("session_fragmenter.port_end",    65535);
    size_t ms  = static_cast<size_t>(
                     Config::instance().getInt("session_fragmenter.max_sessions", 10000));
    bool   rnd = Config::instance().getBool("session_fragmenter.randomize",  true);

    config_.enabled               = en;
    config_.max_session_lifetime  = std::chrono::seconds{mx};
    config_.min_session_lifetime  = std::chrono::seconds{mn};
    config_.port_range_start      = static_cast<uint16_t>(ps);
    config_.port_range_end        = static_cast<uint16_t>(pe);
    config_.max_tracked_sessions  = ms;
    config_.randomize_lifetime    = rnd;

    NCP_LOG_INFO("[SessionFragmenter] Initialized"
                 " max_lifetime=" + std::to_string(mx) + "s"
                 " min_lifetime=" + std::to_string(mn) + "s"
                 " port_range=[" + std::to_string(ps) + "," + std::to_string(pe) + "]");
}

SessionFragmenter::SessionFragmenter(const SessionFragmenterConfig& cfg)
    : config_(cfg)
{
    NCP_LOG_INFO("[SessionFragmenter] Initialized with custom config"
                 " max_lifetime=" + std::to_string(cfg.max_session_lifetime.count()) + "s"
                 " min_lifetime=" + std::to_string(cfg.min_session_lifetime.count()) + "s");
}

SessionFragmenter::~SessionFragmenter()
{
    stop_monitor();
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

std::chrono::seconds SessionFragmenter::compute_lifetime_()
{
    // Under HIGH/CRITICAL threat the effective ceiling drops to 60 s to
    // make sessions harder for TSPU to fingerprint over time.
    auto effective_max = config_.max_session_lifetime;
    if (threat_level_ >= DPI::ThreatLevel::HIGH) {
        effective_max = std::chrono::seconds{60};
    }

    if (!config_.randomize_lifetime) {
        return effective_max;
    }

    // Clamp min < max
    auto lo = config_.min_session_lifetime.count();
    auto hi = effective_max.count();
    if (lo >= hi) {
        return effective_max;
    }

    auto secs = csprng_range(static_cast<int>(lo), static_cast<int>(hi));
    return std::chrono::seconds{secs};
}

void SessionFragmenter::cleanup_old_sessions_()
{
    // Evict ~10 % of capacity, favouring sessions with the oldest
    // last_activity timestamp.
    size_t evict_count = std::max<size_t>(1, config_.max_tracked_sessions / 10);

    // Collect (last_activity, flow_key) pairs
    std::vector<std::pair<std::chrono::steady_clock::time_point, std::string>> candidates;
    candidates.reserve(sessions_.size());
    for (auto& kv : sessions_) {
        candidates.emplace_back(kv.second.last_activity, kv.first);
    }

    // Sort ascending by last_activity — oldest first
    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b){ return a.first < b.first; });

    size_t removed = 0;
    for (auto& [tp, key] : candidates) {
        if (removed >= evict_count) break;
        sessions_.erase(key);
        ++removed;
    }

    NCP_LOG_DEBUG("[SessionFragmenter] cleanup evicted " + std::to_string(removed)
                  + " idle sessions (capacity=" + std::to_string(config_.max_tracked_sessions) + ")");
}

// ---------------------------------------------------------------------------
// Core packet processing
// ---------------------------------------------------------------------------

bool SessionFragmenter::process_packet(const std::string& src_ip, uint16_t src_port,
                                        const std::string& dst_ip, uint16_t dst_port,
                                        size_t packet_size)
{
    if (!config_.enabled) return true;

    const std::string key = make_flow_key(src_ip, src_port, dst_ip, dst_port);
    auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        // Enforce capacity
        if (sessions_.size() >= config_.max_tracked_sessions) {
            cleanup_old_sessions_();
        }

        // Create new session record
        TrackedSession ts;
        ts.flow_key         = key;
        ts.src_port         = src_port;
        ts.dst_port         = dst_port;
        ts.dst_ip           = dst_ip;
        ts.start_time       = now;
        ts.last_activity    = now;
        ts.assigned_lifetime = compute_lifetime_();
        ts.bytes_sent       = packet_size;
        ts.bytes_received   = 0;
        ts.marked_for_reset = false;

        sessions_.emplace(key, std::move(ts));
        stats_.sessions_tracked.fetch_add(1);

        NCP_LOG_DEBUG("[SessionFragmenter] New session " + key
                      + " lifetime=" + std::to_string(sessions_.at(key).assigned_lifetime.count()) + "s");
        return true;
    }

    // Update existing session
    TrackedSession& ts = it->second;
    ts.bytes_sent    += packet_size;
    ts.last_activity  = now;

    if (ts.marked_for_reset) {
        // Already flagged — tell caller to hold/drop until reset completes
        return false;
    }

    // Check whether lifetime has elapsed
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - ts.start_time);
    if (elapsed >= ts.assigned_lifetime) {
        ts.marked_for_reset = true;
        stats_.sessions_reset.fetch_add(1);
        stats_.total_resets.fetch_add(1);

        NCP_LOG_INFO("[SessionFragmenter] Session expired " + key
                     + " elapsed=" + std::to_string(elapsed.count()) + "s"
                     + " limit="   + std::to_string(ts.assigned_lifetime.count()) + "s");
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Expired-session scan
// ---------------------------------------------------------------------------

std::vector<std::string> SessionFragmenter::check_expired_sessions()
{
    std::vector<std::string> expired;
    auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [key, ts] : sessions_) {
        if (ts.marked_for_reset) {
            expired.push_back(key);
            continue;
        }
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - ts.start_time);
        if (elapsed >= ts.assigned_lifetime) {
            ts.marked_for_reset = true;
            stats_.sessions_reset.fetch_add(1);
            stats_.total_resets.fetch_add(1);
            expired.push_back(key);

            NCP_LOG_INFO("[SessionFragmenter] Periodic check — session expired " + key
                         + " elapsed=" + std::to_string(elapsed.count()) + "s");
        }
    }
    return expired;
}

// ---------------------------------------------------------------------------
// Port generation
// ---------------------------------------------------------------------------

uint16_t SessionFragmenter::generate_new_port()
{
    constexpr size_t MAX_RECENTLY_USED = 256;
    constexpr int    MAX_ATTEMPTS      = 1024;

    const int lo = static_cast<int>(config_.port_range_start);
    const int hi = static_cast<int>(config_.port_range_end);

    std::lock_guard<std::mutex> lock(mutex_);

    uint16_t chosen = 0;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        uint16_t candidate = static_cast<uint16_t>(csprng_range(lo, hi));

        bool recently_used = (std::find(recently_used_ports_.begin(),
                                         recently_used_ports_.end(),
                                         candidate) != recently_used_ports_.end());
        if (!recently_used) {
            chosen = candidate;
            break;
        }
    }

    // Fall back: if all candidates happened to be in the recent list (extremely
    // unlikely), just pick any random port.
    if (chosen == 0) {
        chosen = static_cast<uint16_t>(csprng_range(lo, hi));
    }

    // Record usage; keep the ring buffer at MAX_RECENTLY_USED entries
    recently_used_ports_.push_back(chosen);
    if (recently_used_ports_.size() > MAX_RECENTLY_USED) {
        recently_used_ports_.erase(recently_used_ports_.begin());
    }

    stats_.sessions_reopened.fetch_add(1);

    NCP_LOG_DEBUG("[SessionFragmenter] Generated new ephemeral port " + std::to_string(chosen));
    return chosen;
}

// ---------------------------------------------------------------------------
// Session removal
// ---------------------------------------------------------------------------

void SessionFragmenter::remove_session(const std::string& flow_key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto erased = sessions_.erase(flow_key);
    if (erased > 0) {
        NCP_LOG_DEBUG("[SessionFragmenter] Removed session " + flow_key);
    }
}

// ---------------------------------------------------------------------------
// Background monitor thread
// ---------------------------------------------------------------------------

void SessionFragmenter::start_monitor(
    std::function<void(const std::string& flow_key)> on_expire)
{
    if (running_.load()) {
        NCP_LOG_WARN("[SessionFragmenter] Monitor already running");
        return;
    }

    running_.store(true);
    monitor_thread_ = std::thread([this, on_expire = std::move(on_expire)]() {
        NCP_LOG_INFO("[SessionFragmenter] Monitor thread started");

        while (running_.load()) {
            // Sleep 5 seconds, checking running_ every 250 ms for responsive shutdown
            for (int i = 0; i < 20 && running_.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
            if (!running_.load()) break;

            auto expired = check_expired_sessions();
            for (const auto& key : expired) {
                NCP_LOG_INFO("[SessionFragmenter] Monitor triggering reset for " + key);
                try {
                    on_expire(key);
                } catch (const std::exception& ex) {
                    NCP_LOG_ERROR("[SessionFragmenter] on_expire threw: " + std::string(ex.what()));
                }
            }
        }

        NCP_LOG_INFO("[SessionFragmenter] Monitor thread stopped");
    });
}

void SessionFragmenter::stop_monitor()
{
    running_.store(false);
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

// ---------------------------------------------------------------------------
// Configuration & stats accessors
// ---------------------------------------------------------------------------

void SessionFragmenter::set_config(const SessionFragmenterConfig& cfg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[SessionFragmenter] Config updated"
                 " max_lifetime=" + std::to_string(cfg.max_session_lifetime.count()) + "s");
}

SessionFragmenterConfig SessionFragmenter::get_config() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

SessionFragmenterStats SessionFragmenter::get_stats() const
{
    // Copy constructor loads each atomic individually for a consistent snapshot.
    return stats_;
}

void SessionFragmenter::reset_stats()
{
    stats_.reset();
    NCP_LOG_DEBUG("[SessionFragmenter] Stats reset");
}

void SessionFragmenter::set_threat_level(DPI::ThreatLevel level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    threat_level_ = level;
    NCP_LOG_INFO("[SessionFragmenter] Threat level set to "
                 + std::to_string(static_cast<int>(level)));
}

} // namespace ncp
