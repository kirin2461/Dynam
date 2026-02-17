#ifndef NCP_ECH_CACHE_HPP
#define NCP_ECH_CACHE_HPP

/**
 * @file ncp_ech_cache.hpp
 * @brief Thread-safe LRU cache for ECHConfigs with TTL
 */

#include "ncp_ech.hpp"
#include <string>
#include <memory>
#include <optional>
#include <chrono>

namespace ncp {
namespace DPI {
namespace ECH {

/**
 * @brief Cache entry metadata
 */
struct CacheEntry {
    ECHConfig config;
    std::chrono::steady_clock::time_point timestamp;
    std::chrono::seconds ttl;
    uint32_t hit_count = 0;
    bool from_disk = false;
};

/**
 * @brief Cache configuration
 */
struct CacheConfig {
    size_t max_entries = 100;
    std::chrono::seconds default_ttl = std::chrono::seconds(3600);  // 1 hour
    bool enable_disk_cache = false;
    std::string disk_cache_path = "./ech_cache.dat";
    bool auto_refresh = true;  // Auto-refresh before expiry
    std::chrono::seconds refresh_threshold = std::chrono::seconds(300);  // 5 min before expiry
};

/**
 * @brief Cache statistics
 */
struct CacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t evictions = 0;
    uint64_t expirations = 0;
    uint64_t disk_loads = 0;
    uint64_t disk_saves = 0;
    size_t current_size = 0;
    
    double hit_rate() const {
        uint64_t total = hits + misses;
        return total > 0 ? static_cast<double>(hits) / total : 0.0;
    }
};

/**
 * @brief Thread-safe LRU cache for ECHConfigs
 */
class ECHConfigCache {
public:
    ECHConfigCache();
    explicit ECHConfigCache(const CacheConfig& config);
    ~ECHConfigCache();

    /**
     * @brief Get ECHConfig from cache
     * @param domain Domain name
     * @return ECHConfig if found and not expired
     */
    std::optional<ECHConfig> get(const std::string& domain);

    /**
     * @brief Put ECHConfig into cache
     * @param domain Domain name
     * @param config ECHConfig to cache
     * @param ttl Time-to-live (optional, uses default if not specified)
     */
    void put(const std::string& domain, const ECHConfig& config,
             std::optional<std::chrono::seconds> ttl = std::nullopt);

    /**
     * @brief Invalidate entry
     * @param domain Domain name
     */
    void invalidate(const std::string& domain);

    /**
     * @brief Clear all entries
     */
    void clear();

    /**
     * @brief Get cache statistics
     */
    CacheStats get_stats() const;

    /**
     * @brief Reset statistics
     */
    void reset_stats();

    /**
     * @brief Save cache to disk
     * @return true on success
     */
    bool save_to_disk();

    /**
     * @brief Load cache from disk
     * @return Number of entries loaded
     */
    size_t load_from_disk();

    /**
     * @brief Remove expired entries
     * @return Number of entries removed
     */
    size_t cleanup_expired();

    /**
     * @brief Check if domain needs refresh
     * @param domain Domain name
     * @return true if entry exists but close to expiry
     */
    bool needs_refresh(const std::string& domain) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Global singleton cache instance
 */
class GlobalECHCache {
public:
    static ECHConfigCache& instance();
    static void configure(const CacheConfig& config);
};

} // namespace ECH
} // namespace DPI
} // namespace ncp

#endif // NCP_ECH_CACHE_HPP
