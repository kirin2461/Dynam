#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP AutoPilot — adaptive, self-learning DPI-bypass strategy engine.
//
// AutoPilot remembers which desync strategy actually works for each host
// (learned via live blockcheck-style probing through temporary localhost
// SOCKS5 proxies — no admin, no firewall changes), applies the learned
// strategy inside DesyncProxy, watches live traffic for degradation
// (RST-after-hello / timeouts) and automatically re-learns in the background.
//
// Design invariants (hard-won lessons, do not break):
//   - ABI-STABLE: no members behind build-flag #ifdefs in this header.
//   - Threading: single mutex + private *_locked helpers; public methods
//     never call each other while holding the lock; probing never happens
//     under the lock.
//   - Safety: probing is TCP/443 TLS ClientHello only; no TUN, no firewall,
//     no VPN. Feature is opt-in (enabled=false by default).
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_dpi_zapret.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ncp {

// A learned socket-level strategy for one host.
struct AutoPilotStrategy {
    std::string name;                      // blockcheck strategy name; "direct" = passthrough
    std::vector<DPI::ZSplitPos> positions; // empty = passthrough (no split)
    bool host_case = false;                // randomize Host header case (HTTP)
};

struct AutoPilotRecord {
    std::string host;                      // key, normalized lowercase
    AutoPilotStrategy strategy;
    uint64_t successes = 0;
    uint64_t failures = 0;
    uint32_t consec_failures = 0;
    double ewma_latency_ms = 0.0;
    int64_t last_learned = 0;              // unix time
    int64_t last_outcome = 0;              // unix time of last report_*
    double relearn_cooldown_sec = 120.0;   // exponential backoff (x2 on failed learn, cap 3600)
    bool degraded = false;
};

class AutoPilot {
public:
    struct Config {
        std::string db_path;               // empty → default_db_path()
        uint32_t degrade_threshold = 3;    // consecutive failures → degraded
        double ewma_alpha = 0.3;
        int probe_timeout_ms = 5000;
        size_t max_records = 512;          // LRU eviction by last_outcome
        bool background_relearn = true;    // janitor thread re-learns degraded hosts
        // Resolve probe targets via DoH during learn (networks with poisoned
        // DNS). Should mirror the proxy's --doh setting.
        bool use_doh = false;
    };

    AutoPilot();
    ~AutoPilot();

    AutoPilot(const AutoPilot&) = delete;
    AutoPilot& operator=(const AutoPilot&) = delete;

    // Load DB from disk. Missing/corrupt file = empty DB (not an error).
    bool load(const Config& cfg);
    // Atomic save (tmp file + rename).
    bool save() const;

    // Look up the learned strategy for host (longest-suffix match:
    // a record for "youtube.com" serves "www.youtube.com").
    // Degraded records are skipped (caller falls back to chains/base).
    // Returns false when no usable record exists.
    bool lookup(const std::string& host, AutoPilotStrategy* out) const;

    // Live-traffic feedback (called from DesyncProxy relay loop).
    // report_success on an unknown host is a no-op (keeps the DB clean).
    // report_failure on an unknown host accumulates into a pending counter;
    // at the degrade threshold a degraded placeholder record is created so
    // the background janitor learns the host.
    void report_success(const std::string& host, double latency_ms);
    void report_failure(const std::string& host, const std::string& reason);

    // Synchronous learn: probe all default blockcheck strategies against
    // host:443 and persist the winner (including "direct").
    // Returns true when a working strategy was found.
    // Never holds the internal mutex while probing.
    bool learn(const std::string& host, std::string* learned_name = nullptr);

    void reset(const std::string& host);   // empty host = wipe all records
    std::vector<AutoPilotRecord> records() const;
    std::string to_json() const;           // full DB as JSON (for CLI/GUI)

    void set_enabled(bool en);             // persisted in DB
    bool enabled() const;

    // Background janitor: every few seconds picks ONE degraded host with
    // recent traffic (last_outcome within 10 min) whose relearn cooldown has
    // expired and re-learns it. At most one learn runs at a time.
    void start();
    void stop();
    bool running() const;

    // Normalize host: lowercase, strip trailing dot, strip brackets.
    static std::string normalize_host(const std::string& host);
    // ~/.ncp/autopilot.json (Linux) or %APPDATA%\ncp\autopilot.json (Windows).
    static std::string default_db_path();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ncp
