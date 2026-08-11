#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP Hostlist — domain list matching for per-host DPI strategies
//
// Supports zapret-style hostlist files (one domain per line, '#' comments,
// optional leading "*." wildcards) with suffix matching:
//   pattern "example.com" matches "example.com" and any "*.example.com".
//
// Also implements auto-hostlist: automatically appending hosts for which
// a block was detected (RST injection / timeout), with dedup + persistence.
// ═══════════════════════════════════════════════════════════════════════════

#include <string>
#include <vector>
#include <unordered_set>
#include <shared_mutex>
#include <cstdint>

namespace ncp {

class HostlistMatcher {
public:
    HostlistMatcher() = default;

    // Load entries from file (replaces current contents).
    // Returns number of entries loaded; -1 on I/O error.
    int load(const std::string& path);

    // Save entries to file (one per line, sorted). Returns false on I/O error.
    bool save(const std::string& path) const;

    // Add single host/pattern (normalized). Returns true if newly inserted.
    bool add(const std::string& host);

    // Remove exact entry. Returns true if it existed.
    bool remove(const std::string& host);

    // True if host equals an entry or is a subdomain of one.
    bool contains(const std::string& host) const;

    bool empty() const;
    size_t size() const;
    std::vector<std::string> entries() const;  // sorted snapshot
    void clear();

    // Normalize: lowercase, strip trailing dot, strip leading "*." and ".".
    static std::string normalize(const std::string& host);

    // Match hostname against one pattern (suffix rule, see class comment).
    static bool matches_pattern(const std::string& host, const std::string& pattern);

    // Validate that a string looks like a DNS hostname (sane chars/length).
    static bool is_valid_hostname(const std::string& host);

private:
    // All entries stored normalized. Suffix semantics: entry "example.com"
    // covers "example.com" and "a.b.example.com".
    std::unordered_set<std::string> entries_;
    mutable std::shared_mutex mu_;
};

// ───────────────────────────────────────────────────────────────────────────
// AutoHostlist — observes block events and accumulates blocked hosts on disk.
// Thread-safe. Deduplicates. Caps size (new entries beyond the cap are not
// stored).
// ───────────────────────────────────────────────────────────────────────────
class AutoHostlist {
public:
    explicit AutoHostlist(std::string path = {}, size_t max_entries = 100000);

    void set_path(const std::string& path);
    std::string path() const;

    // Load existing file (if any).
    bool load();

    // Record a blocked host. Returns true if it was newly added.
    // Persists to disk immediately (append) when newly added.
    bool record_blocked(const std::string& host);

    bool contains(const std::string& host) const;
    size_t size() const;
    std::vector<std::string> entries() const;
    bool clear();  // also truncates the file

    HostlistMatcher& matcher() { return matcher_; }

private:
    bool append_to_file(const std::string& host);

    HostlistMatcher matcher_;
    std::string path_;
    size_t max_entries_;
    mutable std::shared_mutex mu_;
};

} // namespace ncp
