#include "ncp_hostlist.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <mutex>

namespace ncp {

// ─────────────────────────────────────────────────────────────────────────────
// HostlistMatcher
// ─────────────────────────────────────────────────────────────────────────────

std::string HostlistMatcher::normalize(const std::string& host) {
    std::string h;
    h.reserve(host.size());
    for (char c : host) {
        h.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    // strip whitespace
    size_t b = h.find_first_not_of(" \t\r\n");
    size_t e = h.find_last_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    h = h.substr(b, e - b + 1);
    // strip leading "*." wildcard and stray dots
    while (h.size() >= 2 && h.compare(0, 2, "*.") == 0) h.erase(0, 2);
    while (!h.empty() && h.front() == '.') h.erase(h.begin());
    // strip trailing dot (FQDN form)
    while (!h.empty() && h.back() == '.') h.pop_back();
    return h;
}

bool HostlistMatcher::is_valid_hostname(const std::string& host) {
    if (host.empty() || host.size() > 253) return false;
    for (char c : host) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '-' || c == '.')) return false;
    }
    return true;
}

bool HostlistMatcher::matches_pattern(const std::string& host_in, const std::string& pattern_in) {
    const std::string host = normalize(host_in);
    const std::string pat = normalize(pattern_in);
    if (host.empty() || pat.empty()) return false;
    if (host == pat) return true;
    // suffix rule: host ends with "." + pat
    if (host.size() > pat.size() &&
        host.compare(host.size() - pat.size(), pat.size(), pat) == 0 &&
        host[host.size() - pat.size() - 1] == '.') {
        return true;
    }
    return false;
}

int HostlistMatcher::load(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return -1;
    std::unordered_set<std::string> fresh;
    std::string line;
    while (std::getline(f, line)) {
        // strip comments
        const size_t hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        std::string h = normalize(line);
        if (h.empty() || !is_valid_hostname(h)) continue;
        fresh.insert(std::move(h));
    }
    {
        std::unique_lock<std::shared_mutex> lk(mu_);
        entries_.swap(fresh);
    }
    std::shared_lock<std::shared_mutex> lk(mu_);
    return static_cast<int>(entries_.size());
}

bool HostlistMatcher::save(const std::string& path) const {
    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return false;
    for (const auto& e : entries()) f << e << '\n';
    return f.good();
}

bool HostlistMatcher::add(const std::string& host) {
    std::string h = normalize(host);
    if (h.empty() || !is_valid_hostname(h)) return false;
    std::unique_lock<std::shared_mutex> lk(mu_);
    return entries_.insert(std::move(h)).second;
}

bool HostlistMatcher::remove(const std::string& host) {
    std::string h = normalize(host);
    std::unique_lock<std::shared_mutex> lk(mu_);
    return entries_.erase(h) > 0;
}

bool HostlistMatcher::contains(const std::string& host_in) const {
    const std::string host = normalize(host_in);
    if (host.empty()) return false;
    std::shared_lock<std::shared_mutex> lk(mu_);
    // check host, then each parent suffix: a.b.c -> a.b.c, b.c, c... (skip TLD-only)
    std::string cur = host;
    for (;;) {
        if (entries_.find(cur) != entries_.end()) return true;
        const size_t dot = cur.find('.');
        if (dot == std::string::npos || dot + 1 >= cur.size()) break;
        cur.erase(0, dot + 1);
        // don't let a bare-TLD entry (e.g. "com") match every .com host:
        // suffix candidates must still contain a dot
        if (cur.find('.') == std::string::npos) break;
    }
    return false;
}

bool HostlistMatcher::empty() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return entries_.empty();
}

size_t HostlistMatcher::size() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return entries_.size();
}

std::vector<std::string> HostlistMatcher::entries() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    std::vector<std::string> out(entries_.begin(), entries_.end());
    lk.unlock();
    std::sort(out.begin(), out.end());
    return out;
}

void HostlistMatcher::clear() {
    std::unique_lock<std::shared_mutex> lk(mu_);
    entries_.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// AutoHostlist
// ─────────────────────────────────────────────────────────────────────────────

AutoHostlist::AutoHostlist(std::string path, size_t max_entries)
    : path_(std::move(path)), max_entries_(max_entries) {}

void AutoHostlist::set_path(const std::string& path) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    path_ = path;
}

std::string AutoHostlist::path() const {
    std::shared_lock<std::shared_mutex> lk(mu_);
    return path_;
}

bool AutoHostlist::load() {
    std::shared_lock<std::shared_mutex> lk(mu_);
    if (path_.empty()) return false;
    return matcher_.load(path_) >= 0;
}

bool AutoHostlist::record_blocked(const std::string& host) {
    const std::string h = HostlistMatcher::normalize(host);
    if (h.empty() || !HostlistMatcher::is_valid_hostname(h)) return false;
    {
        std::shared_lock<std::shared_mutex> lk(mu_);
        if (matcher_.size() >= max_entries_) return false;
        if (matcher_.contains(h)) return false;
    }
    const bool added = matcher_.add(h);
    if (added) append_to_file(h);
    return added;
}

bool AutoHostlist::contains(const std::string& host) const {
    return matcher_.contains(host);
}

size_t AutoHostlist::size() const {
    return matcher_.size();
}

std::vector<std::string> AutoHostlist::entries() const {
    return matcher_.entries();
}

bool AutoHostlist::clear() {
    matcher_.clear();
    std::shared_lock<std::shared_mutex> lk(mu_);
    if (path_.empty()) return true;
    std::ofstream f(path_, std::ios::trunc);
    return f.good();
}

bool AutoHostlist::append_to_file(const std::string& host) {
    std::shared_lock<std::shared_mutex> lk(mu_);
    if (path_.empty()) return false;
    std::ofstream f(path_, std::ios::app);
    if (!f.is_open()) return false;
    f << host << '\n';
    return f.good();
}

} // namespace ncp
