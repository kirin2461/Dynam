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

namespace {

// Disk cache format version 2 (little-endian, all ECHConfig fields).
// v1 lost cipher_suites/raw_config, making restored configs unusable.
constexpr uint32_t kDiskCacheVersion = 2;

// Sanity caps for untrusted on-disk sizes (prevent OOM from corrupt files)
constexpr uint32_t kMaxDomainLen     = 253;      // DNS name limit
constexpr uint32_t kMaxPublicNameLen = 253;
constexpr uint32_t kMaxPublicKeyLen  = 4096;     // generous for HPKE keys
constexpr uint32_t kMaxCipherSuites  = 16;
constexpr uint32_t kMaxRawConfigLen  = 65535;
constexpr uint32_t kMaxEntryCount    = 100000;
constexpr uint64_t kMaxTtlSecs       = 30ULL * 24 * 3600;  // 30 days

void write_u8(std::ofstream& o, uint8_t v) {
    o.write(reinterpret_cast<const char*>(&v), 1);
}
void write_u16(std::ofstream& o, uint16_t v) {
    char b[2] = {static_cast<char>(v & 0xFF), static_cast<char>((v >> 8) & 0xFF)};
    o.write(b, 2);
}
void write_u32(std::ofstream& o, uint32_t v) {
    char b[4] = {static_cast<char>(v & 0xFF), static_cast<char>((v >> 8) & 0xFF),
                 static_cast<char>((v >> 16) & 0xFF), static_cast<char>((v >> 24) & 0xFF)};
    o.write(b, 4);
}
void write_u64(std::ofstream& o, uint64_t v) {
    char b[8];
    for (int i = 0; i < 8; i++) b[i] = static_cast<char>((v >> (8 * i)) & 0xFF);
    o.write(b, 8);
}

bool read_u8(std::ifstream& i, uint8_t& v) {
    i.read(reinterpret_cast<char*>(&v), 1);
    return i.good();
}
bool read_u16(std::ifstream& i, uint16_t& v) {
    char b[2];
    i.read(b, 2);
    if (!i.good()) return false;
    v = static_cast<uint16_t>(static_cast<uint8_t>(b[0]) |
        (static_cast<uint16_t>(static_cast<uint8_t>(b[1])) << 8));
    return true;
}
bool read_u32(std::ifstream& i, uint32_t& v) {
    char b[4];
    i.read(b, 4);
    if (!i.good()) return false;
    v = static_cast<uint32_t>(static_cast<uint8_t>(b[0])) |
        (static_cast<uint32_t>(static_cast<uint8_t>(b[1])) << 8) |
        (static_cast<uint32_t>(static_cast<uint8_t>(b[2])) << 16) |
        (static_cast<uint32_t>(static_cast<uint8_t>(b[3])) << 24);
    return true;
}
bool read_u64(std::ifstream& i, uint64_t& v) {
    char b[8];
    i.read(b, 8);
    if (!i.good()) return false;
    v = 0;
    for (int k = 0; k < 8; k++)
        v |= static_cast<uint64_t>(static_cast<uint8_t>(b[k])) << (8 * k);
    return true;
}

void write_bytes(std::ofstream& o, const uint8_t* data, uint32_t len) {
    write_u32(o, len);
    if (len) o.write(reinterpret_cast<const char*>(data), len);
}

// Read a length-prefixed byte blob with a hard cap. Returns false on
// malformed input (bad read or length above cap) — never allocates
// attacker-controlled sizes.
bool read_bytes(std::ifstream& i, std::vector<uint8_t>& out, uint32_t cap) {
    uint32_t len;
    if (!read_u32(i, len) || len > cap) return false;
    out.resize(len);
    if (len) {
        i.read(reinterpret_cast<char*>(out.data()), len);
        if (!i.good()) return false;
    }
    return true;
}

bool read_string(std::ifstream& i, std::string& out, uint32_t cap) {
    uint32_t len;
    if (!read_u32(i, len) || len > cap) return false;
    out.assign(len, '\0');
    if (len) {
        i.read(&out[0], len);
        if (!i.good()) return false;
    }
    return true;
}

void write_ech_config(std::ofstream& o, const ECHConfig& c) {
    write_u16(o, c.version);
    write_u8(o, c.config_id);
    write_u16(o, c.maximum_name_length);
    write_bytes(o, c.public_key.data(), static_cast<uint32_t>(c.public_key.size()));
    write_u32(o, static_cast<uint32_t>(c.public_name.size()));
    if (!c.public_name.empty()) o.write(c.public_name.data(), c.public_name.size());
    write_u32(o, static_cast<uint32_t>(c.cipher_suites.size()));
    for (const auto& cs : c.cipher_suites) {
        write_u16(o, static_cast<uint16_t>(cs.kem_id));
        write_u16(o, static_cast<uint16_t>(cs.kdf_id));
        write_u16(o, static_cast<uint16_t>(cs.aead_id));
    }
    write_bytes(o, c.raw_config.data(), static_cast<uint32_t>(c.raw_config.size()));
}

bool read_ech_config(std::ifstream& i, ECHConfig& c) {
    if (!read_u16(i, c.version)) return false;
    if (!read_u8(i, c.config_id)) return false;
    if (!read_u16(i, c.maximum_name_length)) return false;
    if (!read_bytes(i, c.public_key, kMaxPublicKeyLen)) return false;
    if (!read_string(i, c.public_name, kMaxPublicNameLen)) return false;
    uint32_t suite_count;
    if (!read_u32(i, suite_count) || suite_count > kMaxCipherSuites) return false;
    c.cipher_suites.clear();
    c.cipher_suites.reserve(suite_count);
    for (uint32_t s = 0; s < suite_count; s++) {
        uint16_t kem, kdf, aead;
        if (!read_u16(i, kem) || !read_u16(i, kdf) || !read_u16(i, aead)) return false;
        c.cipher_suites.emplace_back(static_cast<HPKEKem>(kem),
                                     static_cast<HPKEKDF>(kdf),
                                     static_cast<HPKEAEAD>(aead));
    }
    if (!read_bytes(i, c.raw_config, kMaxRawConfigLen)) return false;
    return true;
}

}  // namespace

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

            // Write header: version + entry count (only non-expired entries)
            uint32_t live = 0;
            for (const auto& item : lru_list)
                if (!is_expired(item.second)) live++;
            write_u32(ofs, kDiskCacheVersion);
            write_u32(ofs, live);

            // Write entries
            for (const auto& item : lru_list) {
                const auto& domain = item.first;
                const auto& entry = item.second;

                // Skip expired entries
                if (is_expired(entry)) continue;

                // Domain length + domain
                write_u32(ofs, static_cast<uint32_t>(domain.size()));
                ofs.write(domain.data(), domain.size());

                // TTL (as seconds)
                write_u64(ofs, static_cast<uint64_t>(entry.ttl.count()));

                // Full ECHConfig serialization (v2: includes cipher_suites and
                // raw_config so restored configs are usable by ECHClientContext)
                write_ech_config(ofs, entry.config);
            }

            if (!ofs.good()) return false;
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
            if (!read_u32(ifs, version) || !read_u32(ifs, count)) return 0;
            if (version != kDiskCacheVersion) return 0;  // v1 was lossy — discard
            if (count > kMaxEntryCount) return 0;        // corrupt header

            size_t loaded = 0;
            for (uint32_t i = 0; i < count; ++i) {
                std::string domain;
                if (!read_string(ifs, domain, kMaxDomainLen)) break;
                if (domain.empty()) break;

                uint64_t ttl_secs;
                if (!read_u64(ifs, ttl_secs) || ttl_secs > kMaxTtlSecs) break;

                ECHConfig cfg;
                if (!read_ech_config(ifs, cfg)) break;   // malformed — stop

                // Create entry
                CacheEntry entry;
                entry.config = std::move(cfg);
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
        // FIX: Save list iterator BEFORE erasing from map,
        // because `it` is invalidated by cache_map.erase().
        auto list_it = it->second;
        impl_->cache_map.erase(it);
        impl_->lru_list.erase(list_it);
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
