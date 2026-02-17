/**
 * @file ncp_ech_cache.cpp
 * @brief ECHConfig cache implementation
 */

#include "../include/ncp_ech_cache.hpp"
#include <mutex>
#include <unordered_map>
#include <list>
#include <fstream>
#include <algorithm>

namespace ncp {
namespace DPI {
namespace ECH {

// LRU cache implementation using hash map + doubly-linked list
struct ECHConfigCache::Impl {
    CacheConfig config;
    CacheStats stats;
    mutable std::mutex mutex;

    // LRU structure: domain -> (iterator to list, entry)
    using ListItem = std::pair<std::string, CacheEntry>;
    std::list<ListItem> lru_list;
    std::unordered_map<std::string, typename std::list<ListItem>::iterator> cache_map;

    Impl() {
        config = CacheConfig();
    }

    explicit Impl(const CacheConfig& cfg) : config(cfg) {
        if (config.enable_disk_cache) {
            load_from_disk_internal();
        }
    }

    ~Impl() {
        if (config.enable_disk_cache) {
            save_to_disk_internal();
        }
    }

    bool is_expired(const CacheEntry& entry) const {
        auto now = std::chrono::steady_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.timestamp);
        return age >= entry.ttl;
    }

    bool is_near_expiry(const CacheEntry& entry) const {
        auto now = std::chrono::steady_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - entry.timestamp);
        auto remaining = entry.ttl - age;
        return remaining <= config.refresh_threshold;
    }

    void evict_lru() {
        if (lru_list.empty()) return;

        auto& victim = lru_list.back();
        cache_map.erase(victim.first);
        lru_list.pop_back();
        stats.evictions++;
    }

    void move_to_front(typename std::list<ListItem>::iterator it) {
        lru_list.splice(lru_list.begin(), lru_list, it);
    }

    size_t cleanup_expired_internal() {
        size_t removed = 0;
        auto it = lru_list.begin();
        while (it != lru_list.end()) {
            if (is_expired(it->second)) {
                cache_map.erase(it->first);
                it = lru_list.erase(it);
                stats.expirations++;
                removed++;
            } else {
                ++it;
            }
        }
        return removed;
    }

    bool save_to_disk_internal() {
        if (!config.enable_disk_cache) return false;

        try {
            std::ofstream ofs(config.disk_cache_path, std::ios::binary);
            if (!ofs) return false;

            // Write header: version + entry count
            uint32_t version = 1;
            uint32_t count = static_cast<uint32_t>(lru_list.size());
            ofs.write(reinterpret_cast<const char*>(&version), sizeof(version));
            ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));

            // Write entries
            for (const auto& item : lru_list) {
                const auto& domain = item.first;
                const auto& entry = item.second;

                // Skip expired entries
                if (is_expired(entry)) continue;

                // Domain length + domain
                uint32_t domain_len = static_cast<uint32_t>(domain.size());
                ofs.write(reinterpret_cast<const char*>(&domain_len), sizeof(domain_len));
                ofs.write(domain.data(), domain_len);

                // TTL (as seconds)
                uint64_t ttl_secs = entry.ttl.count();
                ofs.write(reinterpret_cast<const char*>(&ttl_secs), sizeof(ttl_secs));

                // ECHConfig serialization (simplified)
                uint32_t pk_len = static_cast<uint32_t>(entry.config.public_key.size());
                ofs.write(reinterpret_cast<const char*>(&pk_len), sizeof(pk_len));
                ofs.write(reinterpret_cast<const char*>(entry.config.public_key.data()), pk_len);

                uint32_t pn_len = static_cast<uint32_t>(entry.config.public_name.size());
                ofs.write(reinterpret_cast<const char*>(&pn_len), sizeof(pn_len));
                ofs.write(entry.config.public_name.data(), pn_len);

                ofs.write(reinterpret_cast<const char*>(&entry.config.config_id), sizeof(entry.config.config_id));
            }

            stats.disk_saves++;
            return true;

        } catch (...) {
            return false;
        }
    }

    size_t load_from_disk_internal() {
        if (!config.enable_disk_cache) return 0;

        try {
            std::ifstream ifs(config.disk_cache_path, std::ios::binary);
            if (!ifs) return 0;

            // Read header
            uint32_t version, count;
            ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
            ifs.read(reinterpret_cast<char*>(&count), sizeof(count));

            if (version != 1) return 0;

            size_t loaded = 0;
            for (uint32_t i = 0; i < count; ++i) {
                // Read domain
                uint32_t domain_len;
                ifs.read(reinterpret_cast<char*>(&domain_len), sizeof(domain_len));
                std::string domain(domain_len, '\0');
                ifs.read(&domain[0], domain_len);

                // Read TTL
                uint64_t ttl_secs;
                ifs.read(reinterpret_cast<char*>(&ttl_secs), sizeof(ttl_secs));

                // Read ECHConfig
                ECHConfig config;
                uint32_t pk_len;
                ifs.read(reinterpret_cast<char*>(&pk_len), sizeof(pk_len));
                config.public_key.resize(pk_len);
                ifs.read(reinterpret_cast<char*>(config.public_key.data()), pk_len);

                uint32_t pn_len;
                ifs.read(reinterpret_cast<char*>(&pn_len), sizeof(pn_len));
                config.public_name.resize(pn_len);
                ifs.read(&config.public_name[0], pn_len);

                ifs.read(reinterpret_cast<char*>(&config.config_id), sizeof(config.config_id));

                // Create entry
                CacheEntry entry;
                entry.config = config;
                entry.timestamp = std::chrono::steady_clock::now();
                entry.ttl = std::chrono::seconds(ttl_secs);
                entry.from_disk = true;

                // Add to cache
                lru_list.emplace_front(domain, entry);
                cache_map[domain] = lru_list.begin();
                loaded++;
            }

            stats.disk_loads++;
            return loaded;

        } catch (...) {
            return 0;
        }
    }
};

ECHConfigCache::ECHConfigCache() : impl_(std::make_unique<Impl>()) {}
ECHConfigCache::ECHConfigCache(const CacheConfig& config)
    : impl_(std::make_unique<Impl>(config)) {}
ECHConfigCache::~ECHConfigCache() = default;

std::optional<ECHConfig> ECHConfigCache::get(const std::string& domain) {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto it = impl_->cache_map.find(domain);
    if (it == impl_->cache_map.end()) {
        impl_->stats.misses++;
        return std::nullopt;
    }

    auto& entry = it->second->second;

    // Check expiration
    if (impl_->is_expired(entry)) {
        impl_->cache_map.erase(it);
        impl_->lru_list.erase(it->second);
        impl_->stats.expirations++;
        impl_->stats.misses++;
        return std::nullopt;
    }

    // Move to front (most recently used)
    impl_->move_to_front(it->second);
    entry.hit_count++;
    impl_->stats.hits++;

    return entry.config;
}

void ECHConfigCache::put(const std::string& domain, const ECHConfig& config,
                         std::optional<std::chrono::seconds> ttl) {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    // Check if already exists
    auto it = impl_->cache_map.find(domain);
    if (it != impl_->cache_map.end()) {
        // Update existing entry
        auto& entry = it->second->second;
        entry.config = config;
        entry.timestamp = std::chrono::steady_clock::now();
        entry.ttl = ttl.value_or(impl_->config.default_ttl);
        impl_->move_to_front(it->second);
        return;
    }

    // Evict if at capacity
    if (impl_->lru_list.size() >= impl_->config.max_entries) {
        impl_->evict_lru();
    }

    // Create new entry
    CacheEntry entry;
    entry.config = config;
    entry.timestamp = std::chrono::steady_clock::now();
    entry.ttl = ttl.value_or(impl_->config.default_ttl);

    impl_->lru_list.emplace_front(domain, entry);
    impl_->cache_map[domain] = impl_->lru_list.begin();
    impl_->stats.current_size = impl_->lru_list.size();
}

void ECHConfigCache::invalidate(const std::string& domain) {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto it = impl_->cache_map.find(domain);
    if (it != impl_->cache_map.end()) {
        impl_->lru_list.erase(it->second);
        impl_->cache_map.erase(it);
        impl_->stats.current_size = impl_->lru_list.size();
    }
}

void ECHConfigCache::clear() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->lru_list.clear();
    impl_->cache_map.clear();
    impl_->stats.current_size = 0;
}

CacheStats ECHConfigCache::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->stats.current_size = impl_->lru_list.size();
    return impl_->stats;
}

void ECHConfigCache::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->stats = CacheStats();
    impl_->stats.current_size = impl_->lru_list.size();
}

bool ECHConfigCache::save_to_disk() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->save_to_disk_internal();
}

size_t ECHConfigCache::load_from_disk() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->load_from_disk_internal();
}

size_t ECHConfigCache::cleanup_expired() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->cleanup_expired_internal();
}

bool ECHConfigCache::needs_refresh(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto it = impl_->cache_map.find(domain);
    if (it == impl_->cache_map.end()) {
        return false;
    }

    return impl_->config.auto_refresh && impl_->is_near_expiry(it->second->second);
}

// Global singleton
ECHConfigCache& GlobalECHCache::instance() {
    static ECHConfigCache cache;
    return cache;
}

void GlobalECHCache::configure(const CacheConfig& config) {
    // Recreate cache with new config
    instance() = ECHConfigCache(config);
}

} // namespace ECH
} // namespace DPI
} // namespace ncp
