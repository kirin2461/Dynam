#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP DPI detector — detects blocking/DPI events from connection outcomes.
//
// Fed by the desync proxy (and, where available, packet-level backends):
//   - RST right after ClientHello, before any application data  → RST injection
//   - repeated connect/probe timeouts for a host                 → timeout block
//   - successful handshake clears the host's pending state
//
// Events are kept in a bounded ring buffer and can be appended to a JSONL
// file for consumption by the web GUI.
// ═══════════════════════════════════════════════════════════════════════════

#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <chrono>
#include <functional>

namespace ncp {

class DpiDetector {
public:
    enum class EventKind : uint8_t {
        RST_INJECTION = 0,   // connection reset right after ClientHello
        TIMEOUT_BLOCK = 1,   // repeated timeouts reaching the host
        TCP_RESET_PRE = 2,   // reset before any data was sent (connect-level)
        BLOCK_CLEARED = 3    // host reachable again after detected block
    };

    struct Event {
        EventKind kind;
        std::string host;
        std::string detail;
        uint64_t ts_unix = 0;
    };

    using EventCallback = std::function<void(const Event&)>;

    // timeout_threshold: consecutive timeouts required before TIMEOUT_BLOCK.
    explicit DpiDetector(size_t ring_capacity = 512, int timeout_threshold = 2);

    void set_event_callback(EventCallback cb);

    // Enable JSONL persistence (append). Empty path disables.
    void set_log_file(const std::string& path);

    // ── Feed API ──
    void on_connect_reset(const std::string& host);    // RST during/just after connect
    void on_reset_after_hello(const std::string& host);// RST after CH, before data
    void on_timeout(const std::string& host);          // probe/connect timeout
    void on_success(const std::string& host);          // data received — host OK

    // ── Query API ──
    std::vector<Event> recent_events(size_t max_count) const;
    size_t total_events() const;
    size_t events_of_kind(EventKind k) const;
    // hosts currently considered blocked (rst or timeout)
    std::vector<std::string> blocked_hosts() const;

    // ── Per-host report (Task 3) ──
    struct HostReport {
        std::string host;
        bool blocked = false;
        int consecutive_timeouts = 0;
        uint64_t events = 0;
    };
    /// Snapshot of every host seen so far, sorted by host name.
    std::vector<HostReport> host_reports() const;

    /// Expire a block automatically after `ttl` with no re-confirmation.
    /// Zero (the default) keeps the previous "until success" behaviour.
    void set_block_ttl(std::chrono::milliseconds ttl);

    /// Drop all hosts, counters and buffered events (not the log file).
    void reset_all();

    static const char* kind_to_string(EventKind k);
    static std::string event_to_json(const Event& e);

private:
    void emit(Event&& e);

    struct HostState {
        int consecutive_timeouts = 0;
        bool blocked = false;
        uint64_t events = 0;
        std::chrono::steady_clock::time_point blocked_at{};
    };

    // Clear `st` if its block has outlived block_ttl_. Caller holds mu_.
    bool expire_locked(HostState& st, std::chrono::steady_clock::time_point now) const;

    mutable std::mutex mu_;
    std::deque<Event> ring_;
    size_t capacity_;
    int timeout_threshold_;
    std::chrono::milliseconds block_ttl_{0};
    // Mutable: lazy block expiry updates HostState inside const queries.
    mutable std::unordered_map<std::string, HostState> hosts_;
    std::unordered_map<int, size_t> kind_counts_;
    size_t total_ = 0;
    std::string log_path_;
    EventCallback cb_;
};

} // namespace ncp
