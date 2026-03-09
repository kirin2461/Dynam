#pragma once

/**
 * @file ncp_volume_normalizer.hpp
 * @brief Traffic Volume Normalizer — Phase 5 ML-Classification Defense
 *
 * Normalizes request/response sizes to standard web-browsing bucket boundaries
 * (e.g. tiny_page, medium_page, large_page, streaming_chunk) to prevent
 * volume-based ML classifiers from identifying VPN/tunnel traffic.
 *
 * Additional cover traffic injection injects dummy HTTP-like requests
 * during idle periods to match typical user browsing patterns.
 *
 * Research basis:
 *   Traffic volume / size distributions are one of the strongest signals
 *   used by deep-learning DPI engines (e.g. nDPI, ET-BERT).  Normalising
 *   to discrete buckets removes this signal entirely.
 */

#ifndef NCP_VOLUME_NORMALIZER_HPP
#define NCP_VOLUME_NORMALIZER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>

#include "ncp_orchestrator.hpp"

namespace ncp {
namespace DPI {

// ===== Volume Bucket =====

struct VolumeBucket {
    std::string name;      ///< e.g. "tiny_page", "medium_page", …
    size_t min_bytes;      ///< Inclusive lower bound
    size_t max_bytes;      ///< Inclusive upper bound
    double probability;    ///< Relative frequency in normal browsing (for selection)
};

// ===== Configuration =====

struct VolumeNormalizerConfig {
    bool enabled = true;

    /// Bucket definitions. Populated with defaults if empty on construction.
    std::vector<VolumeBucket> buckets;

    /// Pad payload to multiples of this block size (within the chosen bucket).
    size_t padding_block_size = 128;

    /// Maximum extra bytes added as a fraction of the original size.
    double max_overhead_ratio = 0.30;   ///< 30% overhead cap

    /// Inject dummy HTTP-like requests during idle periods.
    bool add_cover_traffic = true;

    /// Minimum interval between cover-traffic injections.
    std::chrono::seconds cover_interval{5};
};

// ===== Statistics =====

struct VolumeNormalizerStats {
    std::atomic<uint64_t> bytes_original{0};
    std::atomic<uint64_t> bytes_padded{0};
    std::atomic<uint64_t> cover_bytes_sent{0};
    std::atomic<uint64_t> requests_normalized{0};

    void reset() {
        bytes_original.store(0);
        bytes_padded.store(0);
        cover_bytes_sent.store(0);
        requests_normalized.store(0);
    }

    VolumeNormalizerStats() = default;
    VolumeNormalizerStats(const VolumeNormalizerStats& o)
        : bytes_original(o.bytes_original.load()),
          bytes_padded(o.bytes_padded.load()),
          cover_bytes_sent(o.cover_bytes_sent.load()),
          requests_normalized(o.requests_normalized.load()) {}

    VolumeNormalizerStats& operator=(const VolumeNormalizerStats& o) {
        if (this != &o) {
            bytes_original.store(o.bytes_original.load());
            bytes_padded.store(o.bytes_padded.load());
            cover_bytes_sent.store(o.cover_bytes_sent.load());
            requests_normalized.store(o.requests_normalized.load());
        }
        return *this;
    }
};

// ===== VolumeNormalizer =====

class VolumeNormalizer {
public:
    VolumeNormalizer();
    explicit VolumeNormalizer(const VolumeNormalizerConfig& cfg);

    /**
     * @brief Pad data to a bucket boundary.
     *
     * Selects the appropriate bucket for the given data size, then pads
     * the data with random bytes (CSPRNG) to the nearest block boundary
     * within that bucket.  Honours max_overhead_ratio.
     *
     * @param data        Original payload bytes.
     * @param is_request  true = upload (request), false = download (response).
     * @return Padded payload.  May equal the input if overhead cap is reached.
     */
    std::vector<uint8_t> normalize(const std::vector<uint8_t>& data, bool is_request);

    /**
     * @brief Compute the target padded size for original_size bytes.
     *
     * Selects a bucket, then rounds up to the next block boundary within
     * that bucket while respecting max_overhead_ratio.
     */
    size_t compute_target_size(size_t original_size);

    /**
     * @brief Generate a cover-traffic payload mimicking a small HTTP GET.
     *
     * Returns a realistic HTTP/1.1 request for a random common path,
     * padded to a tiny_page bucket boundary.
     */
    std::vector<uint8_t> generate_cover_traffic();

    /**
     * @brief Record bytes transferred in this session.
     * @param bytes      Number of bytes.
     * @param is_upload  true = upload, false = download.
     */
    void record_transfer(size_t bytes, bool is_upload);

    /**
     * @brief Total bytes transferred this session (upload + download).
     */
    size_t get_session_volume() const;

    /**
     * @brief Select the bucket that best fits data_size.
     *
     * If data_size falls within a bucket's [min, max] range, that bucket is
     * returned directly.  Otherwise the largest bucket is returned.
     */
    const VolumeBucket& select_bucket(size_t data_size) const;

    /**
     * @brief Populate config_.buckets with built-in defaults:
     *   tiny_page     (1 KB – 10 KB,   p=0.30)
     *   medium_page   (10 KB – 100 KB, p=0.40)
     *   large_page    (100 KB – 500 KB, p=0.20)
     *   streaming_chunk (500 KB – 2 MB, p=0.10)
     */
    void load_default_buckets();

    // ===== Config / stats =====

    void set_config(const VolumeNormalizerConfig& cfg);
    VolumeNormalizerConfig get_config() const;

    VolumeNormalizerStats get_stats() const;
    void reset_stats();

    void set_threat_level(ThreatLevel level);
    ThreatLevel get_threat_level() const;

private:
    VolumeNormalizerConfig config_;
    VolumeNormalizerStats  stats_;
    mutable std::mutex     mutex_;
    ThreatLevel            threat_level_ = ThreatLevel::NONE;

    size_t session_upload_bytes_   = 0;
    size_t session_download_bytes_ = 0;

    /// Ensure buckets are loaded (call load_default_buckets if empty).
    /// Caller must hold mutex_.
    void ensure_buckets_loaded_();

    /// Round size up to the nearest multiple of padding_block_size.
    size_t round_to_block_(size_t size) const;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_VOLUME_NORMALIZER_HPP
