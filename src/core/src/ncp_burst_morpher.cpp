#include "ncp_burst_morpher.hpp"
#include "ncp_csprng.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <numeric>

namespace ncp {
namespace DPI {

// ===== String conversion =====

const char* target_type_to_string(TargetTrafficType t) noexcept {
    switch (t) {
        case TargetTrafficType::YOUTUBE_STREAM: return "YOUTUBE_STREAM";
        case TargetTrafficType::NETFLIX_STREAM: return "NETFLIX_STREAM";
        case TargetTrafficType::ZOOM_VIDEO:     return "ZOOM_VIDEO";
        case TargetTrafficType::HTTP_BROWSING:  return "HTTP_BROWSING";
        case TargetTrafficType::QUIC_WEB:       return "QUIC_WEB";
        case TargetTrafficType::CUSTOM:         return "CUSTOM";
        default: return "UNKNOWN";
    }
}

// ===== BurstProfile =====

uint64_t BurstProfile::compute_hash() const {
    // Quantize continuous values into discrete buckets for approximate matching.
    // This allows cache hits when burst stats are "close enough".
    uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a offset basis
    auto mix = [&h](uint64_t val) {
        h ^= val;
        h *= 0x100000001b3ULL;  // FNV prime
    };

    // Quantize: packet_count to nearest 4, sizes to nearest 32
    mix((packet_count + 2) / 4);
    mix((static_cast<uint64_t>(mean_size) + 16) / 32);
    mix((static_cast<uint64_t>(stddev_size) + 8) / 16);
    mix(static_cast<uint64_t>(mean_iat_us / 1000.0));  // quantize to ms
    mix(static_cast<uint64_t>(outbound_ratio * 10));     // 10 buckets

    // Include first 4 packet sizes (most important for classifier)
    for (size_t i = 0; i < (std::min)(first_sizes_count, static_cast<size_t>(4)); ++i) {
        mix((first_sizes[i] + 32) / 64);  // quantize to 64-byte buckets
    }

    return h;
}

double BurstProfile::similarity(const BurstProfile& other) const {
    // Cosine similarity on a feature vector:
    // [mean_size, stddev_size, mean_iat, outbound_ratio, pkt_count, first_sizes...]
    auto norm = [](const std::vector<double>& v) {
        double sum = 0;
        for (double x : v) sum += x * x;
        return std::sqrt(sum);
    };

    auto make_features = [](const BurstProfile& p) -> std::vector<double> {
        std::vector<double> f;
        f.push_back(p.mean_size / 1460.0);       // normalize to MTU
        f.push_back(p.stddev_size / 500.0);
        f.push_back(p.mean_iat_us / 100000.0);   // normalize to 100ms
        f.push_back(p.outbound_ratio);
        f.push_back(static_cast<double>(p.packet_count) / 100.0);
        for (size_t i = 0; i < FEATURE_WINDOW; ++i) {
            f.push_back(i < p.first_sizes_count
                        ? static_cast<double>(p.first_sizes[i]) / 1460.0
                        : 0.0);
        }
        return f;
    };

    auto fa = make_features(*this);
    auto fb = make_features(other);

    double dot = 0;
    for (size_t i = 0; i < fa.size(); ++i) dot += fa[i] * fb[i];

    double na = norm(fa);
    double nb = norm(fb);
    if (na < 1e-9 || nb < 1e-9) return 0.0;

    return dot / (na * nb);
}

// ===== TargetProfile Presets =====

TargetProfile TargetProfile::youtube() {
    TargetProfile p;
    p.type = TargetTrafficType::YOUTUBE_STREAM;
    p.name = "YouTube HTTPS Stream";

    // YouTube ABR streaming: large chunks + small control packets
    p.reference_burst.packet_count = 40;
    p.reference_burst.mean_size = 1100.0;
    p.reference_burst.stddev_size = 450.0;
    p.reference_burst.mean_iat_us = 2500.0;      // ~2.5ms between packets
    p.reference_burst.stddev_iat_us = 1500.0;
    p.reference_burst.outbound_ratio = 0.15;      // mostly inbound (download)

    p.target_entropy = 7.85;          // encrypted MPEG-DASH ≈ near-random
    p.target_bit_density = 0.498;     // very close to 0.5 (encrypted)

    // Size distribution: mostly large packets with some small ACKs
    p.size_distribution = {0.08, 0.05, 0.07, 0.10, 0.15, 0.55};

    p.target_mean_iat_us = 2500.0;
    p.target_stddev_iat_us = 1500.0;

    return p;
}

TargetProfile TargetProfile::netflix() {
    TargetProfile p;
    p.type = TargetTrafficType::NETFLIX_STREAM;
    p.name = "Netflix HTTPS Stream";

    p.reference_burst.packet_count = 50;
    p.reference_burst.mean_size = 1300.0;
    p.reference_burst.stddev_size = 350.0;
    p.reference_burst.mean_iat_us = 1800.0;
    p.reference_burst.stddev_iat_us = 1000.0;
    p.reference_burst.outbound_ratio = 0.10;

    p.target_entropy = 7.90;
    p.target_bit_density = 0.499;

    // Netflix: more concentrated at large sizes (chunked transfer)
    p.size_distribution = {0.06, 0.04, 0.05, 0.08, 0.12, 0.65};

    p.target_mean_iat_us = 1800.0;
    p.target_stddev_iat_us = 1000.0;

    return p;
}

TargetProfile TargetProfile::zoom() {
    TargetProfile p;
    p.type = TargetTrafficType::ZOOM_VIDEO;
    p.name = "Zoom Video Call";

    p.reference_burst.packet_count = 30;
    p.reference_burst.mean_size = 800.0;
    p.reference_burst.stddev_size = 350.0;
    p.reference_burst.mean_iat_us = 20000.0;     // ~20ms (50fps video)
    p.reference_burst.stddev_iat_us = 5000.0;
    p.reference_burst.outbound_ratio = 0.45;      // bidirectional

    p.target_entropy = 7.70;
    p.target_bit_density = 0.495;

    // Zoom: bimodal — small audio + medium video
    p.size_distribution = {0.15, 0.20, 0.15, 0.20, 0.20, 0.10};

    p.target_mean_iat_us = 20000.0;
    p.target_stddev_iat_us = 5000.0;

    return p;
}

TargetProfile TargetProfile::http_browsing() {
    TargetProfile p;
    p.type = TargetTrafficType::HTTP_BROWSING;
    p.name = "HTTPS Web Browsing";

    p.reference_burst.packet_count = 15;
    p.reference_burst.mean_size = 600.0;
    p.reference_burst.stddev_size = 500.0;
    p.reference_burst.mean_iat_us = 5000.0;
    p.reference_burst.stddev_iat_us = 10000.0;
    p.reference_burst.outbound_ratio = 0.35;

    p.target_entropy = 7.50;
    p.target_bit_density = 0.490;

    // HTTP: very variable sizes
    p.size_distribution = {0.20, 0.15, 0.15, 0.15, 0.15, 0.20};

    p.target_mean_iat_us = 5000.0;
    p.target_stddev_iat_us = 10000.0;

    return p;
}

TargetProfile TargetProfile::quic_web() {
    TargetProfile p;
    p.type = TargetTrafficType::QUIC_WEB;
    p.name = "QUIC Web Browsing";

    p.reference_burst.packet_count = 20;
    p.reference_burst.mean_size = 1000.0;
    p.reference_burst.stddev_size = 400.0;
    p.reference_burst.mean_iat_us = 3000.0;
    p.reference_burst.stddev_iat_us = 4000.0;
    p.reference_burst.outbound_ratio = 0.30;

    p.target_entropy = 7.80;
    p.target_bit_density = 0.497;

    // QUIC: medium-large with multiplexed streams
    p.size_distribution = {0.10, 0.10, 0.15, 0.20, 0.25, 0.20};

    p.target_mean_iat_us = 3000.0;
    p.target_stddev_iat_us = 4000.0;

    return p;
}

// ===== TargetProfileDB =====

TargetProfileDB::TargetProfileDB() {
    load_defaults();
}

void TargetProfileDB::load_defaults() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto add = [this](TargetProfile p) {
        profiles_[static_cast<uint8_t>(p.type)] = std::move(p);
    };
    add(TargetProfile::youtube());
    add(TargetProfile::netflix());
    add(TargetProfile::zoom());
    add(TargetProfile::http_browsing());
    add(TargetProfile::quic_web());
}

void TargetProfileDB::add_profile(const TargetProfile& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    profiles_[static_cast<uint8_t>(profile.type)] = profile;
}

const TargetProfile* TargetProfileDB::get(TargetTrafficType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = profiles_.find(static_cast<uint8_t>(type));
    return it != profiles_.end() ? &it->second : nullptr;
}

const TargetProfile* TargetProfileDB::find_nearest(
    const BurstProfile& burst) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const TargetProfile* best = nullptr;
    double best_sim = -1.0;

    for (auto& [_, profile] : profiles_) {
        double sim = burst.similarity(profile.reference_burst);
        if (sim > best_sim) {
            best_sim = sim;
            best = &profile;
        }
    }
    return best;
}

std::vector<const TargetProfile*> TargetProfileDB::all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<const TargetProfile*> result;
    for (auto& [_, p] : profiles_) result.push_back(&p);
    return result;
}

// ===== PerturbationCache =====

PerturbationCache::PerturbationCache(size_t max_entries)
    : max_entries_(max_entries) {}

const PerturbationEntry* PerturbationCache::lookup(
    uint64_t burst_hash,
    TargetTrafficType target) const {

    std::lock_guard<std::mutex> lock(mutex_);
    CacheKey key{burst_hash, target};
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        stats_.misses.fetch_add(1);
        return nullptr;
    }

    stats_.hits.fetch_add(1);

    // Move to front of LRU
    auto lru_it = std::find(lru_order_.begin(), lru_order_.end(), key);
    if (lru_it != lru_order_.end()) {
        lru_order_.erase(lru_it);
    }
    lru_order_.push_front(key);

    return &it->second;
}

void PerturbationCache::insert(
    uint64_t burst_hash,
    TargetTrafficType target,
    PerturbationEntry entry) {

    std::lock_guard<std::mutex> lock(mutex_);
    CacheKey key{burst_hash, target};

    // Remove old LRU entry if replacing
    auto lru_it = std::find(lru_order_.begin(), lru_order_.end(), key);
    if (lru_it != lru_order_.end()) {
        lru_order_.erase(lru_it);
    }

    // Evict if at capacity
    while (entries_.size() >= max_entries_ && !lru_order_.empty()) {
        evict_lru_();
    }

    entry.created = std::chrono::steady_clock::now();
    entries_[key] = std::move(entry);
    lru_order_.push_front(key);
}

void PerturbationCache::evict_lru_() {
    if (lru_order_.empty()) return;
    auto oldest = lru_order_.back();
    lru_order_.pop_back();
    entries_.erase(oldest);
    stats_.evictions.fetch_add(1);
}

bool PerturbationCache::load_from_buffer(const uint8_t* data, size_t len) {
    if (!data || len < 4) return false;

    size_t offset = 0;
    auto read_u8 = [&]() -> uint8_t {
        if (offset >= len) return 0;
        return data[offset++];
    };
    auto read_u16 = [&]() -> uint16_t {
        if (offset + 2 > len) return 0;
        uint16_t v = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        offset += 2;
        return v;
    };
    auto read_u32 = [&]() -> uint32_t {
        if (offset + 4 > len) return 0;
        uint32_t v = (static_cast<uint32_t>(data[offset]) << 24) |
                     (static_cast<uint32_t>(data[offset+1]) << 16) |
                     (static_cast<uint32_t>(data[offset+2]) << 8) |
                      data[offset+3];
        offset += 4;
        return v;
    };
    auto read_u64 = [&]() -> uint64_t {
        uint64_t hi = read_u32();
        uint64_t lo = read_u32();
        return (hi << 32) | lo;
    };

    uint32_t count = read_u32();
    if (count > 100000) return false;  // sanity limit

    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    lru_order_.clear();

    for (uint32_t i = 0; i < count && offset < len; ++i) {
        uint64_t burst_hash = read_u64();
        auto target = static_cast<TargetTrafficType>(read_u8());

        PerturbationEntry entry;
        uint16_t pre_len = read_u16();
        if (offset + pre_len > len) return false;
        entry.pre_padding.assign(data + offset, data + offset + pre_len);
        offset += pre_len;

        uint16_t post_len = read_u16();
        if (offset + post_len > len) return false;
        entry.post_padding.assign(data + offset, data + offset + post_len);
        offset += post_len;

        entry.target_total_size = read_u32();
        entry.evasion_score = static_cast<double>(read_u16()) / 1000.0;
        entry.target_type = target;
        entry.created = std::chrono::steady_clock::now();

        CacheKey key{burst_hash, target};
        entries_[key] = std::move(entry);
        lru_order_.push_back(key);
    }

    return true;
}

std::vector<uint8_t> PerturbationCache::serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<uint8_t> buf;
    auto write_u8 = [&](uint8_t v) { buf.push_back(v); };
    auto write_u16 = [&](uint16_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto write_u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto write_u64 = [&](uint64_t v) {
        write_u32(static_cast<uint32_t>((v >> 32) & 0xFFFFFFFF));
        write_u32(static_cast<uint32_t>(v & 0xFFFFFFFF));
    };

    write_u32(static_cast<uint32_t>(entries_.size()));

    for (auto& [key, entry] : entries_) {
        write_u64(key.burst_hash);
        write_u8(static_cast<uint8_t>(key.target));

        write_u16(static_cast<uint16_t>(entry.pre_padding.size()));
        buf.insert(buf.end(), entry.pre_padding.begin(), entry.pre_padding.end());

        write_u16(static_cast<uint16_t>(entry.post_padding.size()));
        buf.insert(buf.end(), entry.post_padding.begin(), entry.post_padding.end());

        write_u32(static_cast<uint32_t>(entry.target_total_size));
        write_u16(static_cast<uint16_t>(entry.evasion_score * 1000.0));
    }

    return buf;
}

bool PerturbationCache::load_from_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    return load_from_buffer(data.data(), data.size());
}

bool PerturbationCache::save_to_file(const std::string& path) const {
    auto data = serialize();
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
    return f.good();
}

void PerturbationCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    lru_order_.clear();
}

size_t PerturbationCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

PerturbationCache::CacheStats PerturbationCache::get_stats() const {
    return CacheStats{stats_.hits.load(), stats_.misses.load(), stats_.evictions.load()};
}

void PerturbationCache::reset_stats() {
    stats_.hits.store(0);
    stats_.misses.store(0);
    stats_.evictions.store(0);
}

// ===== BurstTracker =====

BurstTracker::BurstTracker(double gap_threshold_us)
    : gap_threshold_us_(gap_threshold_us) {}

std::optional<BurstProfile> BurstTracker::observe_packet(
    size_t size,
    PacketDirection direction) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    std::optional<BurstProfile> completed;

    // Check if this packet starts a new burst
    if (!current_observations_.empty()) {
        auto last_ts = current_observations_.back().timestamp;
        double iat_us = std::chrono::duration_cast<std::chrono::microseconds>(
            now - last_ts).count();

        if (iat_us > gap_threshold_us_) {
            // Gap detected — finalize current burst
            completed = finalize_burst_();
            current_observations_.clear();
        }
    }

    current_observations_.push_back({size, direction, now});
    return completed;
}

std::optional<BurstProfile> BurstTracker::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (current_observations_.empty()) return std::nullopt;
    auto result = finalize_burst_();
    current_observations_.clear();
    return result;
}

BurstProfile BurstTracker::current_burst() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return finalize_burst_();
}

BurstProfile BurstTracker::finalize_burst_() const {
    BurstProfile bp;
    if (current_observations_.empty()) return bp;

    bp.packet_count = current_observations_.size();

    // Size stats
    std::vector<double> sizes;
    for (auto& obs : current_observations_) {
        sizes.push_back(static_cast<double>(obs.size));
        bp.total_bytes += obs.size;
        if (obs.direction == PacketDirection::OUTBOUND) bp.outbound_count++;
        else bp.inbound_count++;
    }

    bp.min_size = static_cast<size_t>(*std::min_element(sizes.begin(), sizes.end()));
    bp.max_size = static_cast<size_t>(*std::max_element(sizes.begin(), sizes.end()));
    bp.mean_size = std::accumulate(sizes.begin(), sizes.end(), 0.0) / sizes.size();

    double var = 0;
    for (double s : sizes) var += (s - bp.mean_size) * (s - bp.mean_size);
    bp.stddev_size = sizes.size() > 1 ? std::sqrt(var / (sizes.size() - 1)) : 0.0;

    bp.outbound_ratio = bp.packet_count > 0
        ? static_cast<double>(bp.outbound_count) / bp.packet_count : 0.0;

    // IAT stats
    if (current_observations_.size() >= 2) {
        std::vector<double> iats;
        for (size_t i = 1; i < current_observations_.size(); ++i) {
            double iat = std::chrono::duration_cast<std::chrono::microseconds>(
                current_observations_[i].timestamp -
                current_observations_[i-1].timestamp).count();
            iats.push_back(iat);
        }

        bp.mean_iat_us = std::accumulate(iats.begin(), iats.end(), 0.0) / iats.size();
        bp.min_iat_us = *std::min_element(iats.begin(), iats.end());
        bp.max_iat_us = *std::max_element(iats.begin(), iats.end());

        double iat_var = 0;
        for (double iat : iats) iat_var += (iat - bp.mean_iat_us) * (iat - bp.mean_iat_us);
        bp.stddev_iat_us = iats.size() > 1 ? std::sqrt(iat_var / (iats.size() - 1)) : 0.0;
    }

    // First N sizes
    bp.first_sizes_count = (std::min)(current_observations_.size(),
                                       BurstProfile::FEATURE_WINDOW);
    for (size_t i = 0; i < bp.first_sizes_count; ++i) {
        bp.first_sizes[i] = static_cast<uint16_t>(
            (std::min)(current_observations_[i].size, static_cast<size_t>(65535)));
    }

    return bp;
}

void BurstTracker::set_gap_threshold(double us) {
    std::lock_guard<std::mutex> lock(mutex_);
    gap_threshold_us_ = us;
}

double BurstTracker::get_gap_threshold() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return gap_threshold_us_;
}

// ===== BurstMorpher =====

BurstMorpher::BurstMorpher()
    : BurstMorpher(BurstMorpherConfig{}) {}

BurstMorpher::BurstMorpher(const BurstMorpherConfig& config)
    : config_(config),
      cache_(config.cache_max_entries),
      burst_tracker_(config.burst_gap_threshold_us) {

    // Load persisted cache if path is set
    if (!config_.cache_file_path.empty()) {
        cache_.load_from_file(config_.cache_file_path);
    }
}

BurstMorpher::~BurstMorpher() {
    // Persist cache on shutdown
    if (!config_.cache_file_path.empty()) {
        cache_.save_to_file(config_.cache_file_path);
    }
}

BurstMorpher::BurstMorpher(BurstMorpher&&) noexcept = default;
BurstMorpher& BurstMorpher::operator=(BurstMorpher&&) noexcept = default;

// ===== Core: select_perturbation =====

BurstMorpher::PerturbationResult BurstMorpher::select_perturbation(
    size_t payload_size,
    const BurstProfile& burst,
    std::optional<TargetTrafficType> target_override) {

    if (!config_.enabled || payload_size == 0) {
        return {};  // no-op
    }

    stats_.bytes_original.fetch_add(payload_size);

    // 1. Select target profile
    TargetTrafficType target_type = config_.default_target;
    const TargetProfile* target_prof = nullptr;

    if (target_override.has_value()) {
        target_type = target_override.value();
        target_prof = target_db_.get(target_type);
    } else if (config_.auto_select_target) {
        target_prof = target_db_.find_nearest(burst);
        if (target_prof) target_type = target_prof->type;
    }

    if (!target_prof) {
        target_prof = target_db_.get(config_.default_target);
    }
    if (!target_prof) {
        stats_.fallbacks.fetch_add(1);
        return {};  // no target profiles loaded
    }

    // 2. Cache lookup
    uint64_t burst_hash = burst.compute_hash();
    const PerturbationEntry* cached = cache_.lookup(burst_hash, target_type);

    if (cached) {
        // Cache hit: use pre-computed optimal bytes
        stats_.cache_hits.fetch_add(1);
        stats_.perturbations_applied.fetch_add(1);

        PerturbationResult result;
        result.pre_padding = cached->pre_padding;
        result.post_padding = cached->post_padding;
        result.target_total_size = cached->target_total_size;
        result.evasion_score = cached->evasion_score;
        result.target_used = target_type;
        result.from_cache = true;
        result.is_fallback = false;

        size_t overhead = result.pre_padding.size() + result.post_padding.size();
        stats_.bytes_overhead.fetch_add(overhead);

        return result;
    }

    // 3. Cache miss: generate fallback
    stats_.cache_misses.fetch_add(1);

    if (config_.fallback_to_rule_based || config_.generate_random_on_miss) {
        stats_.fallbacks.fetch_add(1);
        return generate_fallback_(payload_size, *target_prof);
    }

    return {};  // no padding if fallback disabled
}

void BurstMorpher::observe_packet(size_t size, PacketDirection direction) {
    auto completed = burst_tracker_.observe_packet(size, direction);
    if (completed.has_value()) {
        stats_.bursts_observed.fetch_add(1);
        std::lock_guard<std::mutex> lock(burst_mutex_);
        latest_burst_ = completed.value();
        has_completed_burst_ = true;
    }
}

BurstProfile BurstMorpher::get_latest_burst() const {
    std::lock_guard<std::mutex> lock(burst_mutex_);
    return has_completed_burst_ ? latest_burst_ : burst_tracker_.current_burst();
}

// ===== Fallback Generation =====

BurstMorpher::PerturbationResult BurstMorpher::generate_fallback_(
    size_t payload_size,
    const TargetProfile& target) {

    PerturbationResult result;
    result.target_used = target.type;
    result.from_cache = false;
    result.is_fallback = true;

    // Sample target size from distribution
    size_t target_size = sample_target_size_(payload_size, target);

    // Calculate pre-padding needed
    size_t pre_len = 0;
    if (target_size > payload_size) {
        pre_len = target_size - payload_size;
    } else {
        // Target smaller than payload — use minimum effective padding
        pre_len = config_.min_pre_padding;
    }

    // Clamp to limits
    pre_len = (std::max)(pre_len, config_.min_pre_padding);
    pre_len = (std::min)(pre_len, config_.max_pre_padding);

    // Check overhead limit
    uint64_t total_orig = stats_.bytes_original.load();
    uint64_t total_overhead = stats_.bytes_overhead.load();
    if (total_orig > 0) {
        double current_overhead_pct =
            (static_cast<double>(total_overhead + pre_len) / total_orig) * 100.0;
        if (current_overhead_pct > config_.max_overhead_percent) {
            pre_len = config_.min_pre_padding;  // use minimum
        }
    }

    // Generate padding bytes matching target byte distribution
    result.pre_padding = generate_target_bytes_(
        pre_len, target.target_entropy, target.target_bit_density);

    result.target_total_size = payload_size + pre_len;
    result.evasion_score = 0.5;  // unknown for fallback

    stats_.perturbations_applied.fetch_add(1);
    stats_.bytes_overhead.fetch_add(pre_len);

    return result;
}

std::vector<uint8_t> BurstMorpher::generate_target_bytes_(
    size_t len,
    double target_entropy,
    double target_bit_density) {

    if (len == 0) return {};

    std::vector<uint8_t> result(len);

    if (target_entropy > 7.5) {
        // High entropy target (encrypted video): near-random bytes
        ncp::csprng_fill(result.data(), len);
    } else if (target_entropy > 6.0) {
        // Medium entropy: mix random + structured
        ncp::csprng_fill(result.data(), len);
        // Inject some ASCII-range bytes to lower entropy slightly
        size_t ascii_count = static_cast<size_t>(len * (1.0 - target_entropy / 8.0));
        for (size_t i = 0; i < ascii_count && i < len; ++i) {
            size_t pos = ncp::csprng_range_size(0, len - 1);
            result[pos] = static_cast<uint8_t>(ncp::csprng_range(0x20, 0x7E));
        }
    } else {
        // Low entropy: mostly structured (text-like)
        for (size_t i = 0; i < len; ++i) {
            result[i] = static_cast<uint8_t>(ncp::csprng_range(0x20, 0x7E));
        }
    }

    return result;
}

size_t BurstMorpher::sample_target_size_(
    size_t payload_size,
    const TargetProfile& target) {

    // Sample from target's size distribution
    static const size_t bucket_maxes[TargetProfile::SIZE_BUCKETS] =
        {63, 127, 255, 511, 1023, 1460};
    static const size_t bucket_mins[TargetProfile::SIZE_BUCKETS] =
        {0, 64, 128, 256, 512, 1024};

    // Weighted random selection of bucket
    double r = static_cast<double>(ncp::csprng_uniform(1000)) / 1000.0;
    double cumulative = 0.0;
    size_t selected_bucket = TargetProfile::SIZE_BUCKETS - 1;

    for (size_t i = 0; i < TargetProfile::SIZE_BUCKETS; ++i) {
        cumulative += target.size_distribution[i];
        if (r <= cumulative) {
            selected_bucket = i;
            break;
        }
    }

    // Sample uniformly within selected bucket
    size_t min_s = bucket_mins[selected_bucket];
    size_t max_s = bucket_maxes[selected_bucket];

    // Ensure target >= payload (we can only add padding, not shrink)
    if (max_s < payload_size) max_s = payload_size + config_.min_pre_padding;
    if (min_s < payload_size) min_s = payload_size;

    if (min_s >= max_s) return min_s;
    return ncp::csprng_range_size(min_s, max_s);
}

// ===== Cache/DB Access =====

PerturbationCache& BurstMorpher::cache() { return cache_; }
const PerturbationCache& BurstMorpher::cache() const { return cache_; }
TargetProfileDB& BurstMorpher::target_db() { return target_db_; }
const TargetProfileDB& BurstMorpher::target_db() const { return target_db_; }

// ===== Config & Stats =====

void BurstMorpher::set_config(const BurstMorpherConfig& config) {
    config_ = config;
    burst_tracker_.set_gap_threshold(config.burst_gap_threshold_us);
}

BurstMorpherConfig BurstMorpher::get_config() const {
    return config_;
}

BurstMorpherStats BurstMorpher::get_stats() const {
    return BurstMorpherStats(stats_);
}

void BurstMorpher::reset_stats() {
    stats_.reset();
    cache_.reset_stats();
}

} // namespace DPI
} // namespace ncp
