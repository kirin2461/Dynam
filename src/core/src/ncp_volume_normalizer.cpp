/**
 * @file ncp_volume_normalizer.cpp
 * @brief Traffic Volume Normalizer implementation — Phase 5
 *
 * Pads packets to discrete web-browsing bucket sizes and injects cover
 * traffic so that volume-based ML classifiers cannot distinguish VPN
 * traffic from ordinary HTTPS browsing.
 */

#include "ncp_volume_normalizer.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace ncp {
namespace DPI {

// ===== Default bucket definitions =====

static const VolumeBucket kDefaultBuckets[] = {
    { "tiny_page",        1024UL,        10UL * 1024,        0.30 },
    { "medium_page",      10UL * 1024,   100UL * 1024,       0.40 },
    { "large_page",       100UL * 1024,  500UL * 1024,       0.20 },
    { "streaming_chunk",  500UL * 1024,  2UL * 1024 * 1024,  0.10 },
};

// ===== Constructors =====

VolumeNormalizer::VolumeNormalizer() {
    load_default_buckets();
    NCP_LOG_DEBUG("[VolumeNormalizer] Initialized with default config");
}

VolumeNormalizer::VolumeNormalizer(const VolumeNormalizerConfig& cfg)
    : config_(cfg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_buckets_loaded_();
    NCP_LOG_DEBUG("[VolumeNormalizer] Initialized with custom config");
}

// ===== Public API =====

std::vector<uint8_t> VolumeNormalizer::normalize(const std::vector<uint8_t>& data,
                                                   bool /*is_request*/) {
    if (data.empty()) return data;

    std::lock_guard<std::mutex> lock(mutex_);

    if (!config_.enabled) {
        return data;
    }

    ensure_buckets_loaded_();

    const size_t original_size  = data.size();
    const size_t max_allowed    = original_size
        + static_cast<size_t>(original_size * config_.max_overhead_ratio);

    // Find target size respecting overhead cap
    const VolumeBucket& bucket = select_bucket(original_size);
    size_t target = round_to_block_(original_size);

    // Clamp to bucket max and overhead cap
    target = std::min(target, bucket.max_bytes);
    target = std::min(target, max_allowed);

    // At HIGH+ threat: reduce padding to avoid detection of the normalization
    // pattern itself (some analysers detect padding uniformity)
    if (threat_level_ >= ThreatLevel::HIGH) {
        // Add a random small offset so the padded size is not exactly a
        // multiple of padding_block_size every time.
        size_t noise = static_cast<size_t>(
            csprng_double_range(0.0, static_cast<double>(config_.padding_block_size) * 0.5)
        );
        target = std::min(target + noise, max_allowed);
    }

    if (target <= original_size) {
        // No padding can be added without exceeding overhead cap
        stats_.bytes_original.fetch_add(original_size, std::memory_order_relaxed);
        stats_.bytes_padded.fetch_add(original_size, std::memory_order_relaxed);
        stats_.requests_normalized.fetch_add(1, std::memory_order_relaxed);
        return data;
    }

    size_t pad_bytes = target - original_size;

    std::vector<uint8_t> result;
    result.reserve(target);
    result.insert(result.end(), data.begin(), data.end());

    // Fill padding with CSPRNG random bytes to maintain entropy
    std::vector<uint8_t> padding(pad_bytes);
    csprng_fill(padding);
    result.insert(result.end(), padding.begin(), padding.end());

    stats_.bytes_original.fetch_add(original_size, std::memory_order_relaxed);
    stats_.bytes_padded.fetch_add(result.size(), std::memory_order_relaxed);
    stats_.requests_normalized.fetch_add(1, std::memory_order_relaxed);

    std::ostringstream oss;
    oss << "[VolumeNormalizer] Normalized: " << original_size
        << " → " << result.size() << " bytes (bucket: " << bucket.name << ")";
    NCP_LOG_DEBUG(oss.str());

    return result;
}

size_t VolumeNormalizer::compute_target_size(size_t original_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensure_buckets_loaded_();

    const VolumeBucket& bucket = select_bucket(original_size);
    size_t target = round_to_block_(original_size);
    target = std::min(target, bucket.max_bytes);

    size_t max_allowed = original_size
        + static_cast<size_t>(original_size * config_.max_overhead_ratio);
    target = std::min(target, max_allowed);

    return (target > original_size) ? target : original_size;
}

std::vector<uint8_t> VolumeNormalizer::generate_cover_traffic() {
    // Build a minimal but plausible HTTP/1.1 GET request
    static const char* const kPaths[] = {
        "/favicon.ico",
        "/static/main.js",
        "/api/ping",
        "/images/logo.png",
        "/fonts/roboto.woff2",
        "/static/style.css",
        "/",
        "/search?q=news",
    };
    static const size_t kNumPaths = sizeof(kPaths) / sizeof(kPaths[0]);

    const char* path = kPaths[csprng_uniform(static_cast<uint32_t>(kNumPaths))];

    static const char* const kHosts[] = {
        "www.google.com",
        "www.youtube.com",
        "cdn.jsdelivr.net",
        "fonts.googleapis.com",
        "static.cloudflare.com",
    };
    static const size_t kNumHosts = sizeof(kHosts) / sizeof(kHosts[0]);
    const char* host = kHosts[csprng_uniform(static_cast<uint32_t>(kNumHosts))];

    std::ostringstream oss;
    oss << "GET " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
           "AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/122.0.0.0 Safari/537.36\r\n"
        << "Accept: */*\r\n"
        << "Accept-Encoding: gzip, deflate, br\r\n"
        << "Connection: keep-alive\r\n"
        << "\r\n";

    std::string req = oss.str();
    std::vector<uint8_t> result(req.begin(), req.end());

    // Pad to tiny_page bucket boundary
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ensure_buckets_loaded_();
        size_t target = round_to_block_(result.size());
        if (target > result.size()) {
            size_t pad = target - result.size();
            std::vector<uint8_t> padding(pad);
            csprng_fill(padding);
            result.insert(result.end(), padding.begin(), padding.end());
        }
        stats_.cover_bytes_sent.fetch_add(result.size(), std::memory_order_relaxed);
    }

    NCP_LOG_DEBUG("[VolumeNormalizer] Cover traffic generated: "
                  + std::to_string(result.size()) + " bytes");
    return result;
}

void VolumeNormalizer::record_transfer(size_t bytes, bool is_upload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (is_upload) {
        session_upload_bytes_ += bytes;
    } else {
        session_download_bytes_ += bytes;
    }
}

size_t VolumeNormalizer::get_session_volume() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_upload_bytes_ + session_download_bytes_;
}

const VolumeBucket& VolumeNormalizer::select_bucket(size_t data_size) const {
    // Must be called with mutex_ held (or externally safe).
    // Find the first bucket whose range covers data_size.
    for (const auto& b : config_.buckets) {
        if (data_size >= b.min_bytes && data_size <= b.max_bytes) {
            return b;
        }
    }
    // Fallback: return the last (largest) bucket
    return config_.buckets.back();
}

void VolumeNormalizer::load_default_buckets() {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.buckets.clear();
    for (const auto& b : kDefaultBuckets) {
        config_.buckets.push_back(b);
    }
    NCP_LOG_DEBUG("[VolumeNormalizer] Default buckets loaded");
}

// ===== Config / stats =====

void VolumeNormalizer::set_config(const VolumeNormalizerConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    ensure_buckets_loaded_();
    NCP_LOG_INFO("[VolumeNormalizer] Config updated");
}

VolumeNormalizerConfig VolumeNormalizer::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

VolumeNormalizerStats VolumeNormalizer::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void VolumeNormalizer::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
    NCP_LOG_DEBUG("[VolumeNormalizer] Stats reset");
}

void VolumeNormalizer::set_threat_level(ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (threat_level_ != level) {
        threat_level_ = level;
        NCP_LOG_INFO("[VolumeNormalizer] Threat level → "
                     + std::to_string(static_cast<int>(level)));
    }
}

ThreatLevel VolumeNormalizer::get_threat_level() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return threat_level_;
}

// ===== Private helpers =====

void VolumeNormalizer::ensure_buckets_loaded_() {
    // Must be called with mutex_ held.
    if (config_.buckets.empty()) {
        config_.buckets.clear();
        for (const auto& b : kDefaultBuckets) {
            config_.buckets.push_back(b);
        }
    }
}

size_t VolumeNormalizer::round_to_block_(size_t size) const {
    // Must be called with mutex_ held.
    size_t block = config_.padding_block_size;
    if (block == 0) return size;
    return ((size + block - 1) / block) * block;
}

} // namespace DPI
} // namespace ncp
