#pragma once

/**
 * @file ncp_burst_morpher.hpp
 * @brief AdvTraffic-style Burst Perturbation Engine — Phase 5 ML-Guided Anti-Classification
 *
 * Replaces random/template adversarial padding with RL-cached optimal byte
 * sequences that make traffic burst patterns indistinguishable from
 * YouTube/Netflix/Zoom for transformer-based classifiers (ET-BERT, NetMamba).
 *
 * Research basis:
 *   AdvTraffic (2025): 16-32 bytes of RL-optimized pre-padding drops
 *   ET-BERT accuracy from 99% to 25.68% with only 3.4% overhead.
 *   Random pre-padding of the same size only reaches 89%.
 *
 * Architecture:
 *   BurstMorpher does NOT run inference at runtime. Instead:
 *   1. Offline Python RL agent trains byte-level perturbation policy
 *   2. Policy is distilled into a lookup table (PerturbationCache)
 *   3. Runtime: hash(burst_profile) → cache lookup → padding bytes
 *   4. Cache miss → fallback to rule-based TLS_MIMIC padding
 *
 * Integration with existing pipeline:
 *   ProtocolOrchestrator::prepare_payload()
 *     → burst_morpher_.select_perturbation(payload, burst_stats)
 *     → adversarial_.pad(data)  // with ML_GUIDED strategy using returned bytes
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <deque>
#include <optional>

namespace ncp {
namespace DPI {

// ===== Burst Profile =====

/// Direction of a packet in a burst
enum class PacketDirection : uint8_t {
    OUTBOUND = 0,
    INBOUND  = 1
};

/// Single packet observation within a burst
struct PacketObservation {
    size_t size = 0;                              // payload size in bytes
    PacketDirection direction = PacketDirection::OUTBOUND;
    std::chrono::steady_clock::time_point timestamp;
};

/// Statistical profile of a traffic burst.
/// A "burst" is a sequence of packets with IAT < burst_gap_threshold.
/// This is the input to the perturbation cache lookup.
struct BurstProfile {
    // Packet size statistics
    size_t packet_count = 0;
    size_t total_bytes = 0;
    size_t min_size = 0;
    size_t max_size = 0;
    double mean_size = 0.0;
    double stddev_size = 0.0;

    // Inter-arrival time statistics (microseconds)
    double mean_iat_us = 0.0;
    double stddev_iat_us = 0.0;
    double min_iat_us = 0.0;
    double max_iat_us = 0.0;

    // Directional statistics
    size_t outbound_count = 0;
    size_t inbound_count = 0;
    double outbound_ratio = 0.0;  // outbound / total

    // First N packet sizes (feature window for classifier)
    static constexpr size_t FEATURE_WINDOW = 16;
    std::array<uint16_t, FEATURE_WINDOW> first_sizes{};  // first N packet sizes
    size_t first_sizes_count = 0;

    /// Compute a 64-bit hash suitable for cache key.
    /// Quantizes continuous values into discrete buckets to allow
    /// approximate matching (e.g., mean_size rounded to nearest 32).
    uint64_t compute_hash() const;

    /// Compute cosine similarity between this profile and another.
    /// Used for finding nearest target profile.
    double similarity(const BurstProfile& other) const;
};

// ===== Target Traffic Profiles =====

/// Known traffic types to mimic
enum class TargetTrafficType : uint8_t {
    YOUTUBE_STREAM = 0,
    NETFLIX_STREAM = 1,
    ZOOM_VIDEO     = 2,
    HTTP_BROWSING  = 3,
    QUIC_WEB       = 4,
    CUSTOM         = 255
};

const char* target_type_to_string(TargetTrafficType t) noexcept;

/// Pre-captured statistical profile of a target traffic type.
/// Used as the "goal" for perturbation — make NCP traffic look like this.
struct TargetProfile {
    TargetTrafficType type = TargetTrafficType::YOUTUBE_STREAM;
    std::string name;

    // Target burst statistics (what we want to look like)
    BurstProfile reference_burst;

    // Byte distribution targets
    double target_entropy = 7.2;              // bits/byte (Netflix HTTPS ≈ 7.2)
    double target_bit_density = 0.48;         // near-random (encrypted content)

    // Packet size distribution (histogram: bucket → probability)
    // Buckets: 0-63, 64-127, 128-255, 256-511, 512-1023, 1024-1460
    static constexpr size_t SIZE_BUCKETS = 6;
    std::array<double, SIZE_BUCKETS> size_distribution{};

    // IAT distribution targets (microseconds)
    double target_mean_iat_us = 0.0;
    double target_stddev_iat_us = 0.0;

    // Pre-built profiles
    static TargetProfile youtube();
    static TargetProfile netflix();
    static TargetProfile zoom();
    static TargetProfile http_browsing();
    static TargetProfile quic_web();
};

/// Database of target profiles. Thread-safe.
class TargetProfileDB {
public:
    TargetProfileDB();

    /// Load built-in profiles (YouTube, Netflix, Zoom, HTTP, QUIC)
    void load_defaults();

    /// Add/replace a custom profile
    void add_profile(const TargetProfile& profile);

    /// Get profile by type
    const TargetProfile* get(TargetTrafficType type) const;

    /// Find the closest target profile to the given burst.
    /// Returns nullptr if DB is empty.
    const TargetProfile* find_nearest(const BurstProfile& burst) const;

    /// Get all loaded profiles
    std::vector<const TargetProfile*> all() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<uint8_t, TargetProfile> profiles_;
};

// ===== Perturbation Cache =====

/// A single perturbation entry: pre-computed padding bytes for a
/// specific (burst_hash, target_type) combination.
struct PerturbationEntry {
    std::vector<uint8_t> pre_padding;    // bytes to prepend (16-32 bytes typically)
    std::vector<uint8_t> post_padding;   // bytes to append (optional, 0-16 bytes)
    size_t target_total_size = 0;        // target packet size after padding
    double evasion_score = 0.0;          // estimated evasion probability [0, 1]
    TargetTrafficType target_type = TargetTrafficType::YOUTUBE_STREAM;
    std::chrono::steady_clock::time_point created;
};

/// LRU cache mapping (burst_hash, target_type) → perturbation entry.
/// Populated offline by RL policy sidecar.
class PerturbationCache {
public:
    explicit PerturbationCache(size_t max_entries = 10000);

    /// Look up perturbation for a burst profile + target.
    /// Returns nullptr on cache miss.
    const PerturbationEntry* lookup(
        uint64_t burst_hash,
        TargetTrafficType target
    ) const;

    /// Insert/replace a perturbation entry.
    void insert(
        uint64_t burst_hash,
        TargetTrafficType target,
        PerturbationEntry entry
    );

    /// Bulk load from serialized format.
    /// Format: [count:4][entries...] where each entry is:
    ///   [burst_hash:8][target:1][pre_len:2][pre_bytes...][post_len:2][post_bytes...]
    ///   [target_size:4][evasion_score_x1000:2]
    bool load_from_buffer(const uint8_t* data, size_t len);

    /// Serialize cache to buffer for persistence.
    std::vector<uint8_t> serialize() const;

    /// Load from file path
    bool load_from_file(const std::string& path);

    /// Save to file path
    bool save_to_file(const std::string& path) const;

    /// Clear all entries
    void clear();

    /// Number of entries
    size_t size() const;

    /// Cache hit/miss statistics
    struct CacheStats {
        std::atomic<uint64_t> hits{0};
        std::atomic<uint64_t> misses{0};
        std::atomic<uint64_t> evictions{0};

        double hit_rate() const {
            uint64_t total = hits.load() + misses.load();
            return total > 0 ? static_cast<double>(hits.load()) / total : 0.0;
        }
    };
    CacheStats get_stats() const;
    void reset_stats();

private:
    /// Cache key: combined burst_hash + target_type
    struct CacheKey {
        uint64_t burst_hash;
        TargetTrafficType target;

        bool operator==(const CacheKey& o) const {
            return burst_hash == o.burst_hash && target == o.target;
        }
    };

    struct CacheKeyHash {
        size_t operator()(const CacheKey& k) const {
            return std::hash<uint64_t>()(k.burst_hash) ^
                   (std::hash<uint8_t>()(static_cast<uint8_t>(k.target)) << 32);
        }
    };

    void evict_lru_();  // caller must hold mutex_

    mutable std::mutex mutex_;
    size_t max_entries_;
    std::unordered_map<CacheKey, PerturbationEntry, CacheKeyHash> entries_;
    mutable std::deque<CacheKey> lru_order_;  // front = most recent
    mutable CacheStats stats_;
};

// ===== Burst Tracker =====

/// Tracks ongoing burst by observing packet timestamps.
/// Splits bursts when IAT exceeds gap_threshold.
class BurstTracker {
public:
    /// @param gap_threshold_us  Max IAT before a new burst starts (default: 100ms)
    explicit BurstTracker(double gap_threshold_us = 100000.0);

    /// Observe a new packet. May trigger burst completion.
    /// @return completed BurstProfile if a burst just ended, nullopt otherwise
    std::optional<BurstProfile> observe_packet(
        size_t size,
        PacketDirection direction
    );

    /// Force-complete current burst (e.g., on connection close)
    std::optional<BurstProfile> flush();

    /// Get current (incomplete) burst stats
    BurstProfile current_burst() const;

    void set_gap_threshold(double us);
    double get_gap_threshold() const;

private:
    BurstProfile finalize_burst_() const;  // caller must hold mutex_

    mutable std::mutex mutex_;
    double gap_threshold_us_;
    std::vector<PacketObservation> current_observations_;
};

// ===== BurstMorpher Configuration =====

struct BurstMorpherConfig {
    bool enabled = true;

    // Target selection
    TargetTrafficType default_target = TargetTrafficType::YOUTUBE_STREAM;
    bool auto_select_target = true;   // pick closest target per-burst

    // Perturbation limits
    size_t max_pre_padding = 48;       // max pre-padding bytes (AdvTraffic: 16-32)
    size_t max_post_padding = 16;      // max post-padding bytes
    size_t min_pre_padding = 16;       // min pre-padding (below this = ineffective)
    double max_overhead_percent = 5.0; // max bandwidth overhead from morphing

    // Cache
    size_t cache_max_entries = 10000;
    std::string cache_file_path;       // path to persist cache (empty = in-memory only)

    // Burst detection
    double burst_gap_threshold_us = 100000.0;  // 100ms gap = new burst

    // Fallback behavior on cache miss
    bool fallback_to_rule_based = true;  // degrade to TLS_MIMIC padding
    bool generate_random_on_miss = false; // generate random padding matching target stats

    // Sidecar update
    bool enable_sidecar_updates = false;  // listen for cache updates from Python sidecar
    uint16_t sidecar_port = 0;            // UDP port for cache update datagrams
};

// ===== BurstMorpher Statistics =====

struct BurstMorpherStats {
    std::atomic<uint64_t> bursts_observed{0};
    std::atomic<uint64_t> perturbations_applied{0};
    std::atomic<uint64_t> cache_hits{0};
    std::atomic<uint64_t> cache_misses{0};
    std::atomic<uint64_t> fallbacks{0};          // fell back to rule-based
    std::atomic<uint64_t> bytes_overhead{0};     // total bytes added by morphing
    std::atomic<uint64_t> bytes_original{0};     // total original bytes processed

    double overhead_percent() const {
        uint64_t orig = bytes_original.load();
        return orig > 0 ? (static_cast<double>(bytes_overhead.load()) / orig) * 100.0 : 0.0;
    }

    void reset() {
        bursts_observed.store(0);
        perturbations_applied.store(0);
        cache_hits.store(0);
        cache_misses.store(0);
        fallbacks.store(0);
        bytes_overhead.store(0);
        bytes_original.store(0);
    }

    BurstMorpherStats() = default;
    BurstMorpherStats(const BurstMorpherStats& o)
        : bursts_observed(o.bursts_observed.load()),
          perturbations_applied(o.perturbations_applied.load()),
          cache_hits(o.cache_hits.load()),
          cache_misses(o.cache_misses.load()),
          fallbacks(o.fallbacks.load()),
          bytes_overhead(o.bytes_overhead.load()),
          bytes_original(o.bytes_original.load()) {}
};

// ===== BurstMorpher — Main Class =====

/// Selects optimal adversarial perturbation bytes based on burst profile
/// and target traffic type. Core of Phase 5 ML-guided anti-classification.
///
/// Usage in orchestrator:
///   auto [pre, post] = burst_morpher_.select_perturbation(payload.size(), burst_stats);
///   // feed pre/post to AdversarialPadding as ML_GUIDED override
///
class BurstMorpher {
public:
    BurstMorpher();
    explicit BurstMorpher(const BurstMorpherConfig& config);
    ~BurstMorpher();

    BurstMorpher(const BurstMorpher&) = delete;
    BurstMorpher& operator=(const BurstMorpher&) = delete;
    BurstMorpher(BurstMorpher&&) noexcept;
    BurstMorpher& operator=(BurstMorpher&&) noexcept;

    // ===== Core API =====

    /// Result of perturbation selection
    struct PerturbationResult {
        std::vector<uint8_t> pre_padding;    // bytes to prepend before payload
        std::vector<uint8_t> post_padding;   // bytes to append after payload
        size_t target_total_size = 0;        // recommended padded size
        double evasion_score = 0.0;          // estimated evasion probability
        TargetTrafficType target_used = TargetTrafficType::YOUTUBE_STREAM;
        bool from_cache = false;             // true if cache hit
        bool is_fallback = false;            // true if fell back to rule-based
    };

    /// Select optimal perturbation for the given payload size and burst stats.
    ///
    /// This is the main entry point called from the orchestrator pipeline.
    /// Steps:
    ///   1. Hash burst_profile → cache key
    ///   2. Lookup in PerturbationCache
    ///   3. Cache hit → return pre-computed bytes
    ///   4. Cache miss → generate fallback padding matching target stats
    ///
    /// @param payload_size   Size of the payload to be padded
    /// @param burst          Current burst statistics
    /// @param target         Override target type (nullopt = auto-select)
    /// @return Perturbation result with pre/post padding bytes
    PerturbationResult select_perturbation(
        size_t payload_size,
        const BurstProfile& burst,
        std::optional<TargetTrafficType> target = std::nullopt
    );

    /// Observe a packet for burst tracking. Call on every send/receive.
    /// Internally updates BurstTracker and triggers burst completion events.
    void observe_packet(size_t size, PacketDirection direction);

    /// Get the latest completed burst profile (or current incomplete burst).
    BurstProfile get_latest_burst() const;

    // ===== Cache Management =====

    /// Get the perturbation cache (for loading/saving)
    PerturbationCache& cache();
    const PerturbationCache& cache() const;

    /// Get the target profile database
    TargetProfileDB& target_db();
    const TargetProfileDB& target_db() const;

    // ===== Configuration =====

    void set_config(const BurstMorpherConfig& config);
    BurstMorpherConfig get_config() const;

    // ===== Statistics =====

    BurstMorpherStats get_stats() const;
    void reset_stats();

private:
    /// Generate fallback perturbation when cache misses.
    /// Creates padding that statistically matches target profile:
    ///   - Size sampled from target's size distribution
    ///   - Bytes generated to match target entropy/bit-density
    ///   - Prefix matches target protocol signature (if applicable)
    PerturbationResult generate_fallback_(
        size_t payload_size,
        const TargetProfile& target
    );

    /// Generate padding bytes matching target byte distribution.
    /// Uses rejection sampling to hit target entropy.
    std::vector<uint8_t> generate_target_bytes_(
        size_t len,
        double target_entropy,
        double target_bit_density
    );

    /// Select target packet size from target's size distribution.
    size_t sample_target_size_(
        size_t payload_size,
        const TargetProfile& target
    );

    BurstMorpherConfig config_;
    BurstMorpherStats stats_;

    PerturbationCache cache_;
    TargetProfileDB target_db_;
    BurstTracker burst_tracker_;

    // Latest completed burst (for select_perturbation when caller
    // doesn't track bursts themselves)
    mutable std::mutex burst_mutex_;
    BurstProfile latest_burst_;
    bool has_completed_burst_ = false;
};

} // namespace DPI
} // namespace ncp
