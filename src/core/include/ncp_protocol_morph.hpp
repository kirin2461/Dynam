#ifndef NCP_PROTOCOL_MORPH_HPP
#define NCP_PROTOCOL_MORPH_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include <atomic>
#include <functional>
#include <map>
#include "ncp_mimicry.hpp"
#include "ncp_tls_fingerprint.hpp"

namespace ncp {

/**
 * @brief Protocol Morphing Engine — Shapeshifter-inspired optimizer
 *
 * Sits above TrafficMimicry and TLSFingerprint, orchestrating:
 *   1. Per-connection protocol selection (weighted random)
 *   2. Wire format mutation (JA3, extension order, ALPN) every N connections
 *   3. Time-of-day protocol schedule (circadian pattern mimicry)
 *
 * Integration:
 *   - Caller creates ProtocolMorph, calls select_profile_for_connection()
 *     before each new tunnel, receives a configured MimicConfig + TLS fingerprint.
 *   - Wire mutation happens automatically after N connections via on_connection_opened().
 *   - Schedule is evaluated via get_scheduled_profile() which respects local time.
 *
 * Both peers must agree on the same protocol for a given connection.
 * The selector is seeded from a shared secret so both sides derive the same sequence.
 */
class ProtocolMorph {
public:
    // ==================== Protocol Selector ====================

    /**
     * @brief Weight for each mimicry profile in the random selector.
     *
     * Weights are relative — a profile with weight 3 is 3x more likely
     * than a profile with weight 1. Weight 0 disables the profile.
     */
    struct ProfileWeight {
        TrafficMimicry::MimicProfile profile;
        uint32_t weight;    // 0 = disabled
    };

    /**
     * @brief Per-connection selection result.
     *
     * Contains everything needed to configure TrafficMimicry + TLSFingerprint
     * for a single connection.
     */
    struct ConnectionProfile {
        TrafficMimicry::MimicProfile mimic_profile;
        TrafficMimicry::MimicConfig  mimic_config;

        // TLS fingerprint mutations (only relevant for TLS-based profiles)
        std::vector<uint16_t>  tls_cipher_suites;   // Shuffled cipher suite order
        std::vector<uint16_t>  tls_extensions;       // Shuffled extension order
        std::vector<std::string> alpn_protocols;     // Mutated ALPN values
        BrowserType            browser_profile;      // Emulated browser

        uint64_t connection_id;                      // Monotonic connection counter
        uint64_t mutation_epoch;                     // Current wire mutation epoch
    };

    // ==================== Wire Format Mutator ====================

    struct MutationConfig {
        uint32_t connections_per_mutation = 50;      // Mutate JA3 every N connections
        bool shuffle_extension_order = true;         // Randomize TLS extension ordering
        bool rotate_cipher_priority = true;          // Rotate cipher suite preference order
        bool mutate_alpn = true;                     // Vary ALPN protocol list
        bool rotate_browser_profile = true;          // Cycle through browser JA3 profiles

        /// Browser profiles to cycle through
        std::vector<BrowserType> browser_pool = {
            BrowserType::CHROME,
            BrowserType::FIREFOX,
            BrowserType::SAFARI,
            BrowserType::EDGE
        };
    };

    // ==================== Protocol Schedule ====================

    /**
     * @brief Time-of-day protocol assignment.
     *
     * Defines which mimicry profile to prefer during a given hour range.
     * Mimics real-world usage: HTTP/2 during work hours, WebSocket for
     * real-time apps in the evening, raw TLS at night (background syncs).
     */
    struct ScheduleSlot {
        uint8_t hour_start;     // 0-23 (local time)
        uint8_t hour_end;       // 0-23 (exclusive, wraps at midnight)
        TrafficMimicry::MimicProfile profile;
        uint32_t weight_boost;  // Added to the profile's base weight during this slot
    };

    struct ScheduleConfig {
        bool enabled = false;
        std::vector<ScheduleSlot> slots;
        int utc_offset_minutes = 0;  // Local timezone offset from UTC

        /**
         * @brief Default schedule mimicking Moscow-timezone usage.
         *
         *   06:00-12:00  HTTP GET/POST  (browsing, work start)
         *   12:00-18:00  WebSocket      (real-time apps, meetings)
         *   18:00-23:00  QUIC           (streaming, downloads)
         *   23:00-06:00  HTTPS App Data (background sync, updates)
         */
        static ScheduleConfig default_moscow() {
            ScheduleConfig cfg;
            cfg.enabled = true;
            cfg.utc_offset_minutes = 180; // MSK = UTC+3
            cfg.slots = {
                {6,  12, TrafficMimicry::MimicProfile::HTTP_GET,             10},
                {12, 18, TrafficMimicry::MimicProfile::WEBSOCKET,            10},
                {18, 23, TrafficMimicry::MimicProfile::QUIC_INITIAL,         10},
                {23,  6, TrafficMimicry::MimicProfile::HTTPS_APPLICATION,    10},
            };
            return cfg;
        }

        static ScheduleConfig default_utc() {
            ScheduleConfig cfg;
            cfg.enabled = true;
            cfg.utc_offset_minutes = 0;
            cfg.slots = {
                {7,  12, TrafficMimicry::MimicProfile::HTTP_GET,             10},
                {12, 18, TrafficMimicry::MimicProfile::WEBSOCKET,            10},
                {18, 22, TrafficMimicry::MimicProfile::QUIC_INITIAL,         10},
                {22,  7, TrafficMimicry::MimicProfile::HTTPS_APPLICATION,    10},
            };
            return cfg;
        }
    };

    // ==================== Master Config ====================

    struct Config {
        // Protocol selector
        std::vector<ProfileWeight> profile_weights = {
            {TrafficMimicry::MimicProfile::HTTPS_APPLICATION,  5},
            {TrafficMimicry::MimicProfile::HTTP_GET,           3},
            {TrafficMimicry::MimicProfile::HTTP_POST,          2},
            {TrafficMimicry::MimicProfile::WEBSOCKET,          4},
            {TrafficMimicry::MimicProfile::QUIC_INITIAL,       3},
            {TrafficMimicry::MimicProfile::DNS_QUERY,          1},
            {TrafficMimicry::MimicProfile::BITTORRENT,         1},
        };

        MutationConfig mutation;
        ScheduleConfig schedule;

        /// Shared secret for deterministic peer-synchronized selection.
        /// Both sides derive the same PRNG sequence from this seed.
        /// If empty, uses local CSPRNG (non-synchronized mode).
        std::vector<uint8_t> shared_seed;
    };

    // ==================== Statistics ====================

    struct Stats {
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> mutations_performed{0};
        std::atomic<uint64_t> schedule_overrides{0};
        std::map<TrafficMimicry::MimicProfile, uint64_t> profile_usage;

        Stats() = default;
        Stats(const Stats& o)
            : connections_total(o.connections_total.load())
            , mutations_performed(o.mutations_performed.load())
            , schedule_overrides(o.schedule_overrides.load())
            , profile_usage(o.profile_usage) {}
    };

    // ==================== Lifecycle ====================

    ProtocolMorph();
    explicit ProtocolMorph(const Config& config);
    ~ProtocolMorph();

    ProtocolMorph(const ProtocolMorph&) = delete;
    ProtocolMorph& operator=(const ProtocolMorph&) = delete;

    void set_config(const Config& config);
    Config get_config() const;

    // ==================== Core API ====================

    /**
     * @brief Select protocol profile for a new connection.
     *
     * Algorithm:
     *   1. Evaluate schedule → get time-based weight boosts
     *   2. Build weighted distribution from base weights + schedule boosts
     *   3. Draw from PRNG (shared_seed-derived or CSPRNG)
     *   4. Apply wire format mutations if connection_count % N == 0
     *   5. Return fully configured ConnectionProfile
     *
     * Thread-safe. Caller applies the result to TrafficMimicry + TLSFingerprint.
     */
    ConnectionProfile select_profile_for_connection();

    /**
     * @brief Notify that a connection was opened (increments counters).
     *
     * Triggers wire format mutation if connections_per_mutation threshold reached.
     */
    void on_connection_opened();

    /**
     * @brief Get the currently scheduled profile based on local time.
     *
     * Returns the MimicProfile that the schedule prefers right now,
     * or HTTPS_APPLICATION as fallback if no schedule slot matches.
     */
    TrafficMimicry::MimicProfile get_scheduled_profile() const;

    /**
     * @brief Force a wire format mutation now (resets the counter).
     */
    void force_mutation();

    /**
     * @brief Get current mutation epoch (incremented on each mutation).
     */
    uint64_t get_mutation_epoch() const;

    // ==================== Stats ====================

    Stats get_stats() const;
    void reset_stats();

    // ==================== Logging ====================
    using LogCallback = std::function<void(const std::string&)>;
    void set_log_callback(LogCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ncp

#endif // NCP_PROTOCOL_MORPH_HPP
