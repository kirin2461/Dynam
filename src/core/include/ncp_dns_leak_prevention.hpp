#pragma once
/**
 * @file ncp_dns_leak_prevention.hpp
 * @brief DNS Leak Prevention — Dynam/NCP Anti-TSPU
 *
 * Blocks plaintext DNS (UDP/TCP port 53) that would reveal queries to TSPU
 * in cleartext, bypassing DoH. Also blocks WebRTC STUN ports that can leak
 * the real IP and raw IPv6 when not going through the tunnel.
 *
 * Platform support:
 *   Windows: Windows Filtering Platform (WFP) — fwpuclnt.lib already linked.
 *            Creates a WFP sublayer with callout filters.
 *   Linux:   iptables / ip6tables via system() calls.
 *            Rules are tagged with a comment so they can be removed cleanly.
 *
 * Leak detection:
 *   check_for_leaks() attempts a DNS resolution via getaddrinfo() and
 *   inspects the resolved address against the known DoH endpoint set.
 *   If a non-DoH address appears in the system resolver response it fires
 *   the on_leak_detected callback.
 *
 * Thread-safety: all public methods are guarded by mutex_ except stats
 *   accessors which use atomics directly.
 */

#include <string>
#include <vector>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <functional>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <fwpmu.h>
#  include <fwptypes.h>
#  pragma comment(lib, "fwpuclnt.lib")
#  pragma comment(lib, "Ws2_32.lib")
#else
#  include <sys/socket.h>
#  include <netdb.h>
#  include <arpa/inet.h>
#endif

namespace ncp {

// ============================================================
// DNSLeakConfig
// ============================================================

struct DNSLeakConfig {
    bool enabled           = true;
    bool block_udp53       = true;   ///< Block UDP port 53 (except whitelisted servers)
    bool block_tcp53       = true;   ///< Block TCP port 53 (except whitelisted servers)
    bool block_webrtc_stun = true;   ///< Block UDP STUN ports 3478 / 5349 / 19302
    bool block_raw_ipv6    = false;  ///< Block raw IPv6 traffic (enable when not tunneled)

    // Whitelisted DNS servers — traffic to these on port 53 is allowed.
    // Localhost is always implicitly whitelisted.
    std::vector<std::string> allowed_dns_servers = {
        "127.0.0.1", "::1"
    };

    // DoH endpoints: HTTPS traffic to these IPs is explicitly permitted.
    // Used by check_for_leaks() to validate that resolution goes through DoH.
    std::vector<std::string> doh_endpoints = {
        "1.1.1.1",          "1.0.0.1",           // Cloudflare
        "8.8.8.8",          "8.8.4.4",           // Google
        "9.9.9.9",          "149.112.112.112",   // Quad9
        "94.140.14.14",     "94.140.15.15"       // AdGuard
    };

    // WebRTC STUN ports to block (UDP)
    std::vector<uint16_t> stun_ports = {3478, 5349, 19302};

    // Monitoring
    bool enable_leak_detection          = true;
    int  detection_check_interval_sec  = 30;

    /// Callback fired when a DNS leak is detected.
    /// @param leaked_query  The hostname that was resolved outside DoH.
    /// @param dst_ip        Destination IP of the leaking DNS packet.
    using LeakCallback = std::function<void(const std::string& leaked_query,
                                             const std::string& dst_ip)>;
    LeakCallback on_leak_detected;
};

// ============================================================
// DNSLeakStats
// ============================================================

struct DNSLeakStats {
    std::atomic<uint64_t> dns_queries_blocked{0};
    std::atomic<uint64_t> stun_packets_blocked{0};
    std::atomic<uint64_t> ipv6_packets_blocked{0};
    std::atomic<uint64_t> leaks_detected{0};
    std::atomic<uint64_t> rules_installed{0};

    void reset();

    DNSLeakStats() = default;
    DNSLeakStats(const DNSLeakStats& o);
    DNSLeakStats& operator=(const DNSLeakStats& o);
};

// ============================================================
// DNSLeakPrevention
// ============================================================

class DNSLeakPrevention {
public:
    DNSLeakPrevention();
    explicit DNSLeakPrevention(const DNSLeakConfig& config);
    ~DNSLeakPrevention();

    DNSLeakPrevention(const DNSLeakPrevention&)            = delete;
    DNSLeakPrevention& operator=(const DNSLeakPrevention&) = delete;

    // ----- Lifecycle -----

    /// Install firewall rules. Idempotent — safe to call when already active.
    /// @return true on success; false if platform-level API failed.
    bool activate();

    /// Remove all installed firewall rules.
    /// @return true on success (or if already inactive).
    bool deactivate();

    /// @return true if rules are currently installed.
    bool is_active() const;

    // ----- Whitelist management -----

    /// Add an IP address to the allowed DNS server list.
    /// If already active, the rule set is NOT automatically updated —
    /// call deactivate() + activate() to apply the change.
    void add_allowed_server(const std::string& ip);

    /// Remove an IP address from the allowed DNS server list.
    void remove_allowed_server(const std::string& ip);

    // ----- Query-level check -----

    /// Test whether a connection to dst_ip:dst_port would be blocked.
    /// Does NOT modify firewall state — useful for policy validation.
    bool would_block(const std::string& dst_ip, uint16_t dst_port, bool is_udp) const;

    // ----- Leak detection -----

    /// Perform an active leak check:
    ///   1. Resolve a canary hostname via the system resolver.
    ///   2. Compare the resulting server IPs against the DoH endpoint list.
    ///   3. If a non-DoH server was used, fire on_leak_detected callback
    ///      and increment leaks_detected counter.
    /// @return true if no leak was detected, false if a leak was found.
    bool check_for_leaks();

    // ----- Configuration -----

    void           set_config(const DNSLeakConfig& config);
    DNSLeakConfig  get_config() const;

    // ----- Stats -----

    DNSLeakStats get_stats()  const;
    void         reset_stats();

private:
    // ----- Internal helpers -----

    bool is_allowed_dns_server(const std::string& ip) const;
    bool is_stun_port(uint16_t port) const;

    // Utility: run a system() command, log result
    bool run_command_(const std::string& cmd);

    // ----- Platform-specific -----

#ifdef _WIN32
    /// Open WFP engine and install sublayer + filters.
    bool install_wfp_filters_();
    /// Remove all filters registered in filter_ids_, then remove sublayer.
    bool remove_wfp_filters_();

    /// Add a single WFP block filter.
    /// @return filter ID on success, 0 on failure.
    uint64_t add_wfp_filter_(
        HANDLE      engine,
        const GUID& layer_key,
        const char* filter_name,
        uint16_t    port,           ///< 0 = match all ports
        bool        is_udp,
        const std::string& except_ip ///< empty = block everything on port
    );

    HANDLE                engine_handle_ = nullptr;   ///< WFP engine handle
    GUID                  sublayer_key_  = {};         ///< Our WFP sublayer GUID
    std::vector<uint64_t> filter_ids_;                ///< All installed filter IDs

#else
    /// Install iptables/ip6tables rules.
    bool install_iptables_rules_();
    /// Remove iptables/ip6tables rules we previously installed.
    bool remove_iptables_rules_();

    /// Unique comment tag so we can surgically delete only our rules.
    static constexpr const char* RULE_COMMENT = "ncp_dns_leak";

    /// Human-readable list of rules for logging
    std::vector<std::string> installed_rules_;
#endif

    // ----- State -----

    DNSLeakConfig         config_;
    DNSLeakStats          stats_;
    std::atomic<bool>     active_{false};
    mutable std::mutex    mutex_;
};

} // namespace ncp
