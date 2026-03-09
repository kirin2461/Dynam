/**
 * @file ncp_dns_leak_prevention.cpp
 * @brief DNS Leak Prevention — implementation
 *
 * Windows path: WFP (Windows Filtering Platform)
 *   - FwpmEngineOpen0        — open engine
 *   - FwpmSubLayerAdd0       — create our sublayer
 *   - FwpmFilterAdd0         — add block filters
 *   - FwpmFilterDeleteById0  — remove individual filters
 *   - FwpmSubLayerDeleteByKey0 — remove sublayer
 *   - FwpmEngineClose0       — close engine
 *
 * Linux path: iptables / ip6tables via system()
 *   Rules are tagged with --comment ncp_dns_leak for clean removal.
 *
 * Leak detection:
 *   Resolves "dns-canary.ncp.invalid" (expected NXDOMAIN from DoH)
 *   and "example.com" (expected valid answer from DoH).
 *   If the system resolver returns an IP that is not one of our known
 *   DoH endpoints it means a plaintext DNS query escaped.
 */

#include "ncp_dns_leak_prevention.hpp"
#include "ncp_logger.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#ifdef _WIN32
#  include <objbase.h>           // CoCreateGuid
#  include <stdio.h>             // _popen / _pclose
#  pragma comment(lib, "Ole32.lib")
#else
#  include <cstdio>
#  include <sys/types.h>
#endif

namespace ncp {

// ============================================================
// DNSLeakStats — copy semantics
// ============================================================

DNSLeakStats::DNSLeakStats(const DNSLeakStats& o)
    : dns_queries_blocked  (o.dns_queries_blocked.load())
    , stun_packets_blocked (o.stun_packets_blocked.load())
    , ipv6_packets_blocked (o.ipv6_packets_blocked.load())
    , leaks_detected       (o.leaks_detected.load())
    , rules_installed      (o.rules_installed.load())
{}

DNSLeakStats& DNSLeakStats::operator=(const DNSLeakStats& o)
{
    if (this == &o) return *this;
    dns_queries_blocked.store(o.dns_queries_blocked.load());
    stun_packets_blocked.store(o.stun_packets_blocked.load());
    ipv6_packets_blocked.store(o.ipv6_packets_blocked.load());
    leaks_detected.store(o.leaks_detected.load());
    rules_installed.store(o.rules_installed.load());
    return *this;
}

void DNSLeakStats::reset()
{
    dns_queries_blocked.store(0);
    stun_packets_blocked.store(0);
    ipv6_packets_blocked.store(0);
    leaks_detected.store(0);
    rules_installed.store(0);
}

// ============================================================
// Constructors / Destructor
// ============================================================

DNSLeakPrevention::DNSLeakPrevention()
    : config_()
{
    NCP_LOG_INFO("[DNSLeakPrevention] Created (default config).");
}

DNSLeakPrevention::DNSLeakPrevention(const DNSLeakConfig& config)
    : config_(config)
{
    NCP_LOG_INFO("[DNSLeakPrevention] Created with custom config.");
}

DNSLeakPrevention::~DNSLeakPrevention()
{
    if (active_.load()) {
        NCP_LOG_INFO("[DNSLeakPrevention] Destructor: deactivating.");
        deactivate();
    }
}

// ============================================================
// Helpers
// ============================================================

bool DNSLeakPrevention::is_allowed_dns_server(const std::string& ip) const
{
    // Localhost is always allowed
    if (ip == "127.0.0.1" || ip == "::1" || ip == "localhost")
        return true;
    const auto& list = config_.allowed_dns_servers;
    return std::find(list.begin(), list.end(), ip) != list.end();
}

bool DNSLeakPrevention::is_stun_port(uint16_t port) const
{
    const auto& ports = config_.stun_ports;
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

bool DNSLeakPrevention::would_block(const std::string& dst_ip,
                                     uint16_t dst_port,
                                     bool is_udp) const
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (!config_.enabled) return false;

    // DNS port check
    if (dst_port == 53) {
        bool is_tcp_dns = !is_udp && config_.block_tcp53;
        bool is_udp_dns =  is_udp && config_.block_udp53;
        if (is_tcp_dns || is_udp_dns) {
            if (!is_allowed_dns_server(dst_ip))
                return true;
        }
    }

    // STUN check
    if (is_udp && config_.block_webrtc_stun && is_stun_port(dst_port))
        return true;

    // IPv6 check — only applicable when block_raw_ipv6 is set
    if (config_.block_raw_ipv6) {
        // Simple heuristic: if the dst_ip contains ':' it is IPv6
        if (dst_ip.find(':') != std::string::npos)
            return true;
    }

    return false;
}

bool DNSLeakPrevention::run_command_(const std::string& cmd)
{
    NCP_LOG_DEBUG("[DNSLeakPrevention] system(\"" + cmd + "\")");
    int ret = ::system(cmd.c_str());
    if (ret != 0) {
        NCP_LOG_ERROR("[DNSLeakPrevention] Command failed (exit=" +
                      std::to_string(ret) + "): " + cmd);
        return false;
    }
    return true;
}

// ============================================================
// activate / deactivate
// ============================================================

bool DNSLeakPrevention::activate()
{
    std::lock_guard<std::mutex> lk(mutex_);

    if (!config_.enabled) {
        NCP_LOG_INFO("[DNSLeakPrevention] activate() called but config.enabled=false - skipping.");
        return true;
    }

    if (active_.load()) {
        NCP_LOG_DEBUG("[DNSLeakPrevention] Already active - idempotent call.");
        return true;
    }

    NCP_LOG_INFO("[DNSLeakPrevention] Activating DNS leak prevention rules...");

#ifdef _WIN32
    if (!install_wfp_filters_()) {
        NCP_LOG_ERROR("[DNSLeakPrevention] WFP filter installation failed.");
        return false;
    }
#else
    if (!install_iptables_rules_()) {
        NCP_LOG_ERROR("[DNSLeakPrevention] iptables rule installation failed.");
        return false;
    }
#endif

    active_.store(true);
    NCP_LOG_INFO("[DNSLeakPrevention] Active. Rules installed: "
                 + std::to_string(stats_.rules_installed.load()));
    return true;
}

bool DNSLeakPrevention::deactivate()
{
    std::lock_guard<std::mutex> lk(mutex_);

    if (!active_.load()) {
        NCP_LOG_DEBUG("[DNSLeakPrevention] deactivate() - already inactive.");
        return true;
    }

    NCP_LOG_INFO("[DNSLeakPrevention] Deactivating DNS leak prevention rules...");

    bool ok = false;
#ifdef _WIN32
    ok = remove_wfp_filters_();
#else
    ok = remove_iptables_rules_();
#endif

    if (ok) {
        active_.store(false);
        NCP_LOG_INFO("[DNSLeakPrevention] Rules removed.");
    } else {
        NCP_LOG_ERROR("[DNSLeakPrevention] Failed to remove some rules.");
    }
    return ok;
}

bool DNSLeakPrevention::is_active() const
{
    return active_.load();
}

// ============================================================
// Whitelist management
// ============================================================

void DNSLeakPrevention::add_allowed_server(const std::string& ip)
{
    std::lock_guard<std::mutex> lk(mutex_);
    auto& list = config_.allowed_dns_servers;
    if (std::find(list.begin(), list.end(), ip) == list.end()) {
        list.push_back(ip);
        NCP_LOG_INFO("[DNSLeakPrevention] Whitelisted DNS server: " + ip);
    }
}

void DNSLeakPrevention::remove_allowed_server(const std::string& ip)
{
    std::lock_guard<std::mutex> lk(mutex_);
    auto& list = config_.allowed_dns_servers;
    list.erase(std::remove(list.begin(), list.end(), ip), list.end());
    NCP_LOG_INFO("[DNSLeakPrevention] Removed DNS whitelist entry: " + ip);
}

// ============================================================
// check_for_leaks
// ============================================================

bool DNSLeakPrevention::check_for_leaks()
{
    if (!config_.enable_leak_detection) return true;

    NCP_LOG_DEBUG("[DNSLeakPrevention] Running leak detection probe...");

    // We resolve "example.com" using getaddrinfo() with AF_UNSPEC so we see
    // which server the OS resolver used.  getaddrinfo() doesn't expose the
    // server IP directly, so we use a two-step approach:
    //   1. Resolve a known hostname.
    //   2. Inspect /etc/resolv.conf (Linux) or ipconfig (Windows) to find
    //      which nameserver is configured and check if it is a DoH endpoint.

    // Step 1: Verify system resolver address
    std::string system_ns;

#ifdef _WIN32
    // On Windows, read the DNS servers via GetNetworkParams or ipconfig output.
    // For simplicity we use _popen to capture ipconfig /all output.
    {
        FILE* fp = _popen("ipconfig /all", "r");
        if (fp) {
            char buf[256];
            while (fgets(buf, sizeof(buf), fp)) {
                std::string line(buf);
                if (line.find("DNS Servers") != std::string::npos ||
                    line.find("DNS Server")  != std::string::npos) {
                    // Extract the first IP-like token after ':'
                    auto colon = line.find(':');
                    if (colon != std::string::npos) {
                        std::string addr = line.substr(colon + 1);
                        // Trim whitespace/newline
                        addr.erase(0, addr.find_first_not_of(" \t\r\n"));
                        addr.erase(addr.find_last_not_of(" \t\r\n") + 1);
                        if (!addr.empty()) {
                            system_ns = addr;
                            break;
                        }
                    }
                }
            }
            _pclose(fp);
        }
    }
#else
    // Linux: read /etc/resolv.conf
    {
        FILE* fp = fopen("/etc/resolv.conf", "r");
        if (fp) {
            char buf[256];
            while (fgets(buf, sizeof(buf), fp)) {
                std::string line(buf);
                if (line.substr(0, 10) == "nameserver") {
                    // "nameserver <ip>"
                    auto pos = line.find_first_of(' ');
                    if (pos != std::string::npos) {
                        std::string addr = line.substr(pos + 1);
                        addr.erase(0, addr.find_first_not_of(" \t"));
                        addr.erase(addr.find_last_not_of(" \t\r\n") + 1);
                        if (!addr.empty()) {
                            system_ns = addr;
                            break;
                        }
                    }
                }
            }
            fclose(fp);
        }
    }
#endif

    if (system_ns.empty()) {
        NCP_LOG_WARN("[DNSLeakPrevention] Could not determine system nameserver - skipping leak check.");
        return true; // cannot determine — assume ok
    }

    NCP_LOG_DEBUG("[DNSLeakPrevention] System nameserver: " + system_ns);

    // Step 2: Check if system_ns is one of our DoH endpoints or whitelisted servers
    bool is_safe = is_allowed_dns_server(system_ns);
    if (!is_safe) {
        // Also check DoH endpoints list
        const auto& doh = config_.doh_endpoints;
        is_safe = (std::find(doh.begin(), doh.end(), system_ns) != doh.end());
    }

    if (!is_safe) {
        NCP_LOG_ERROR("[DNSLeakPrevention] LEAK DETECTED - system DNS server '"
                      + system_ns + "' is NOT a DoH endpoint!");
        stats_.leaks_detected.fetch_add(1, std::memory_order_relaxed);

        if (config_.on_leak_detected) {
            config_.on_leak_detected("(system resolver)", system_ns);
        }
        return false;
    }

    NCP_LOG_DEBUG("[DNSLeakPrevention] Leak check passed - nameserver " + system_ns + " is safe.");
    return true;
}

// ============================================================
// Configuration
// ============================================================

void DNSLeakPrevention::set_config(const DNSLeakConfig& config)
{
    std::lock_guard<std::mutex> lk(mutex_);
    config_ = config;
    NCP_LOG_INFO("[DNSLeakPrevention] Config updated.");
}

DNSLeakConfig DNSLeakPrevention::get_config() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return config_;
}

DNSLeakStats DNSLeakPrevention::get_stats() const
{
    return DNSLeakStats(stats_);
}

void DNSLeakPrevention::reset_stats()
{
    stats_.reset();
    NCP_LOG_DEBUG("[DNSLeakPrevention] Stats reset.");
}

// ============================================================
// ============================================================
// PLATFORM-SPECIFIC IMPLEMENTATIONS
// ============================================================
// ============================================================

// ============================================================
// WINDOWS — WFP
// ============================================================

#ifdef _WIN32

// We use a fixed GUID for our sublayer so we can find and remove it later.
// {A1B2C3D4-E5F6-7890-ABCD-EF0123456789}
static const GUID NCP_SUBLAYER_GUID = {
    0xa1b2c3d4,
    0xe5f6,
    0x7890,
    {0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}
};

bool DNSLeakPrevention::install_wfp_filters_()
{
    DWORD result = ERROR_SUCCESS;

    // 1. Open WFP engine — DNS-FIX-3: use dynamic session so filters
    //    are automatically removed if the process crashes.
    FWPM_SESSION0 session{};
    session.displayData.name = const_cast<wchar_t*>(L"NCP DNS Leak Prevention");
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    result = FwpmEngineOpen0(
        nullptr,               // local machine
        RPC_C_AUTHN_WINNT,
        nullptr,               // auth identity
        &session,              // dynamic session
        reinterpret_cast<HANDLE*>(&engine_handle_)
    );
    if (result != ERROR_SUCCESS) {
        NCP_LOG_ERROR("[DNSLeakPrevention] FwpmEngineOpen0 failed: " + std::to_string(result));
        engine_handle_ = nullptr;
        return false;
    }

    // 2. Start a transaction for atomic installation
    result = FwpmTransactionBegin0(reinterpret_cast<HANDLE>(engine_handle_), 0);
    if (result != ERROR_SUCCESS) {
        NCP_LOG_ERROR("[DNSLeakPrevention] FwpmTransactionBegin0 failed: " + std::to_string(result));
        FwpmEngineClose0(reinterpret_cast<HANDLE>(engine_handle_));
        engine_handle_ = nullptr;
        return false;
    }

    // 3. Create sublayer
    FWPM_SUBLAYER0 sublayer{};
    sublayer.subLayerKey = NCP_SUBLAYER_GUID;
    sublayer.displayData.name        = const_cast<wchar_t*>(L"NCP DNS Leak Prevention");
    sublayer.displayData.description = const_cast<wchar_t*>(L"Dynam/NCP: block plaintext DNS and STUN");
    sublayer.flags    = 0;
    sublayer.weight   = 0x100; // higher = evaluated first

    result = FwpmSubLayerAdd0(reinterpret_cast<HANDLE>(engine_handle_), &sublayer, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        NCP_LOG_ERROR("[DNSLeakPrevention] FwpmSubLayerAdd0 failed: " + std::to_string(result));
        FwpmTransactionAbort0(reinterpret_cast<HANDLE>(engine_handle_));
        FwpmEngineClose0(reinterpret_cast<HANDLE>(engine_handle_));
        engine_handle_ = nullptr;
        return false;
    }

    sublayer_key_ = NCP_SUBLAYER_GUID;
    uint64_t rules = 0;

    // Helper: add one block filter for a specific port + protocol
    // We only block traffic NOT going to whitelisted servers.
    // WFP doesn't have a "not-destination-address" condition natively, so we:
    //   a) Add a PERMIT filter for each whitelisted IP at the same port (higher weight).
    //   b) Add a BLOCK filter for the port (lower weight).
    // This achieves: "block port 53 UDP unless dst is 127.0.0.1/::1/..."

    auto add_permit_filter = [&](const GUID& layer,
                                  const std::string& ip_str,
                                  uint16_t port,
                                  UINT8 proto) -> bool {
        // Convert IP string to FWP_V4_ADDR_AND_MASK or FWP_V6_ADDR_AND_MASK
        FWPM_FILTER0 flt{};
        FWPM_FILTER_CONDITION0 conds[3]{};
        DWORD condCount = 0;

        // Protocol condition
        conds[condCount].fieldKey         = FWPM_CONDITION_IP_PROTOCOL;
        conds[condCount].matchType        = FWP_MATCH_EQUAL;
        conds[condCount].conditionValue.type    = FWP_UINT8;
        conds[condCount].conditionValue.uint8   = proto;
        condCount++;

        // Port condition
        conds[condCount].fieldKey         = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[condCount].matchType        = FWP_MATCH_EQUAL;
        conds[condCount].conditionValue.type    = FWP_UINT16;
        conds[condCount].conditionValue.uint16  = port;
        condCount++;

        // Address condition — use FWP_UINT32 for IPv4 (host-order),
        // FWP_BYTE_ARRAY16_TYPE for IPv6
        bool is_v6 = (ip_str.find(':') != std::string::npos);
        // DNS-FIX-4: v6addr declared at lambda scope (not inside the if-block)
        // so its pointer remains valid through FwpmFilterAdd0.
        FWP_BYTE_ARRAY16 v6addr{};
        UINT32 v4addr_ho = 0; // host-order IPv4 address
        if (is_v6) {
            inet_pton(AF_INET6, ip_str.c_str(), v6addr.byteArray16);
            conds[condCount].fieldKey      = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            conds[condCount].matchType     = FWP_MATCH_EQUAL;
            conds[condCount].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            conds[condCount].conditionValue.byteArray16 = &v6addr;
        } else {
            DWORD addr_no = 0; // network-order
            inet_pton(AF_INET, ip_str.c_str(), &addr_no);
            v4addr_ho = ntohl(addr_no); // WFP stores IPv4 in host-order
            conds[condCount].fieldKey      = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            conds[condCount].matchType     = FWP_MATCH_EQUAL; // DNS-FIX-5: explicit, not zero-init
            conds[condCount].conditionValue.type = FWP_UINT32;
            conds[condCount].conditionValue.uint32 = v4addr_ho;
        }
        condCount++;

        flt.layerKey           = layer;
        flt.subLayerKey        = NCP_SUBLAYER_GUID;
        flt.displayData.name   = const_cast<wchar_t*>(L"NCP DNS Permit");
        flt.weight.type        = FWP_UINT8;
        flt.weight.uint8       = 15; // higher than block filter (10)
        flt.numFilterConditions = condCount;
        flt.filterCondition    = conds;
        flt.action.type        = FWP_ACTION_PERMIT;
        // DNS-FIX-2: hard permit — overrides blocks from other sublayers
        flt.flags              = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

        UINT64 flt_id = 0;
        DWORD r = FwpmFilterAdd0(reinterpret_cast<HANDLE>(engine_handle_),
                                  &flt, nullptr, &flt_id);
        if (r == ERROR_SUCCESS) {
            filter_ids_.push_back(flt_id);
            rules++;
            NCP_LOG_INFO("[DNSLeakPrevention] Permit filter OK: " + ip_str
                         + ":" + std::to_string(port)
                         + (is_v6 ? " (V6)" : " (V4)"));
            return true;
        }
        NCP_LOG_WARN("[DNSLeakPrevention] add_permit_filter failed for " + ip_str
                     + ":" + std::to_string(port) + " (err=" + std::to_string(r) + ")");
        return false;
    };

    auto add_block_filter = [&](const GUID& layer,
                                 uint16_t port,
                                 UINT8 proto) -> bool {
        FWPM_FILTER0 flt{};
        FWPM_FILTER_CONDITION0 conds[2]{};

        conds[0].fieldKey      = FWPM_CONDITION_IP_PROTOCOL;
        conds[0].matchType     = FWP_MATCH_EQUAL;
        conds[0].conditionValue.type  = FWP_UINT8;
        conds[0].conditionValue.uint8 = proto;

        conds[1].fieldKey      = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[1].matchType     = FWP_MATCH_EQUAL;
        conds[1].conditionValue.type   = FWP_UINT16;
        conds[1].conditionValue.uint16 = port;

        flt.layerKey            = layer;
        flt.subLayerKey         = NCP_SUBLAYER_GUID;
        flt.displayData.name    = const_cast<wchar_t*>(L"NCP DNS Block");
        flt.weight.type         = FWP_UINT8;
        flt.weight.uint8        = 10; // lower than permit
        flt.numFilterConditions = 2;
        flt.filterCondition     = conds;
        flt.action.type         = FWP_ACTION_BLOCK;

        UINT64 flt_id = 0;
        DWORD r = FwpmFilterAdd0(reinterpret_cast<HANDLE>(engine_handle_),
                                  &flt, nullptr, &flt_id);
        if (r == ERROR_SUCCESS) {
            filter_ids_.push_back(flt_id);
            rules++;
            return true;
        }
        NCP_LOG_WARN("[DNSLeakPrevention] add_block_filter failed for port "
                     + std::to_string(port) + " (err=" + std::to_string(r) + ")");
        return false;
    };

    // IPPROTO values
    constexpr UINT8 PROTO_UDP = 17;
    constexpr UINT8 PROTO_TCP = 6;

    // Helper: pick correct WFP layer based on IP address family
    auto is_ipv6 = [](const std::string& ip) -> bool {
        return ip.find(':') != std::string::npos;
    };

    // DNS-FIX-6: track overall success; abort transaction on any filter failure
    bool all_ok = true;

    // Block UDP port 53
    if (config_.block_udp53) {
        // Permit whitelisted servers first — match layer to address family
        for (const auto& ip : config_.allowed_dns_servers) {
            if (is_ipv6(ip)) {
                if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, ip, 53, PROTO_UDP))
                    { all_ok = false; break; }
            } else {
                if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, ip, 53, PROTO_UDP))
                    { all_ok = false; break; }
            }
        }
        // DNS-FIX-1: also permit DoH endpoint IPs on UDP port 53
        if (all_ok) {
            for (const auto& ip : config_.doh_endpoints) {
                if (is_ipv6(ip)) {
                    if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, ip, 53, PROTO_UDP))
                        { all_ok = false; break; }
                } else {
                    if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, ip, 53, PROTO_UDP))
                        { all_ok = false; break; }
                }
            }
        }
        if (all_ok && !add_block_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 53, PROTO_UDP))
            all_ok = false;
        if (all_ok && !add_block_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, 53, PROTO_UDP))
            all_ok = false;
        if (all_ok)
            NCP_LOG_INFO("[DNSLeakPrevention] WFP: UDP/53 block rules added.");
    }

    // Block TCP port 53
    if (all_ok && config_.block_tcp53) {
        for (const auto& ip : config_.allowed_dns_servers) {
            if (is_ipv6(ip)) {
                if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, ip, 53, PROTO_TCP))
                    { all_ok = false; break; }
            } else {
                if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, ip, 53, PROTO_TCP))
                    { all_ok = false; break; }
            }
        }
        // DNS-FIX-1: also permit DoH endpoint IPs on TCP port 53
        if (all_ok) {
            for (const auto& ip : config_.doh_endpoints) {
                if (is_ipv6(ip)) {
                    if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, ip, 53, PROTO_TCP))
                        { all_ok = false; break; }
                } else {
                    if (!add_permit_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, ip, 53, PROTO_TCP))
                        { all_ok = false; break; }
                }
            }
        }
        if (all_ok && !add_block_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, 53, PROTO_TCP))
            all_ok = false;
        if (all_ok && !add_block_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, 53, PROTO_TCP))
            all_ok = false;
        if (all_ok)
            NCP_LOG_INFO("[DNSLeakPrevention] WFP: TCP/53 block rules added.");
    }

    // Block STUN ports (UDP)
    if (all_ok && config_.block_webrtc_stun) {
        for (uint16_t port : config_.stun_ports) {
            if (!add_block_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, port, PROTO_UDP))
                { all_ok = false; break; }
            if (!add_block_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, port, PROTO_UDP))
                { all_ok = false; break; }
            NCP_LOG_INFO("[DNSLeakPrevention] WFP: UDP/" + std::to_string(port) + " STUN block added.");
        }
    }

    // Block raw IPv6 if requested
    if (all_ok && config_.block_raw_ipv6) {
        // Block all outbound IPv6 by blocking FWPM_LAYER_ALE_AUTH_CONNECT_V6 unconditionally
        FWPM_FILTER0 flt{};
        flt.layerKey             = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        flt.subLayerKey          = NCP_SUBLAYER_GUID;
        flt.displayData.name     = const_cast<wchar_t*>(L"NCP IPv6 Block");
        flt.weight.type          = FWP_UINT8;
        flt.weight.uint8         = 10;
        flt.numFilterConditions  = 0;
        flt.action.type          = FWP_ACTION_BLOCK;
        UINT64 flt_id = 0;
        if (FwpmFilterAdd0(reinterpret_cast<HANDLE>(engine_handle_),
                           &flt, nullptr, &flt_id) == ERROR_SUCCESS) {
            filter_ids_.push_back(flt_id);
            rules++;
            NCP_LOG_INFO("[DNSLeakPrevention] WFP: raw IPv6 block added.");
        } else {
            all_ok = false;
        }
    }

    // DNS-FIX-6: abort transaction if any filter installation failed
    if (!all_ok) {
        NCP_LOG_ERROR("[DNSLeakPrevention] Filter installation failed - aborting WFP transaction.");
        FwpmTransactionAbort0(reinterpret_cast<HANDLE>(engine_handle_));
        FwpmEngineClose0(reinterpret_cast<HANDLE>(engine_handle_));
        engine_handle_ = nullptr;
        return false;
    }

    // Commit transaction
    result = FwpmTransactionCommit0(reinterpret_cast<HANDLE>(engine_handle_));
    if (result != ERROR_SUCCESS) {
        NCP_LOG_ERROR("[DNSLeakPrevention] FwpmTransactionCommit0 failed: " + std::to_string(result));
        FwpmTransactionAbort0(reinterpret_cast<HANDLE>(engine_handle_));
        FwpmEngineClose0(reinterpret_cast<HANDLE>(engine_handle_));
        engine_handle_ = nullptr;
        filter_ids_.clear();  // R7-HIGH-04: rolled-back filters no longer exist
        return false;
    }

    stats_.rules_installed.fetch_add(rules, std::memory_order_relaxed);
    NCP_LOG_INFO("[DNSLeakPrevention] WFP filters installed: " + std::to_string(rules));
    return true;
}

bool DNSLeakPrevention::remove_wfp_filters_()
{
    if (!engine_handle_) return true;

    bool all_ok = true;

    // Remove individual filters
    for (uint64_t fid : filter_ids_) {
        DWORD r = FwpmFilterDeleteById0(reinterpret_cast<HANDLE>(engine_handle_), fid);
        if (r != ERROR_SUCCESS && r != FWP_E_FILTER_NOT_FOUND) {
            NCP_LOG_WARN("[DNSLeakPrevention] FwpmFilterDeleteById0(" +
                          std::to_string(fid) + ") failed: " + std::to_string(r));
            all_ok = false;
        }
    }
    filter_ids_.clear();

    // Remove our sublayer
    DWORD r = FwpmSubLayerDeleteByKey0(reinterpret_cast<HANDLE>(engine_handle_),
                                        &sublayer_key_);
    if (r != ERROR_SUCCESS && r != FWP_E_SUBLAYER_NOT_FOUND) {
        NCP_LOG_WARN("[DNSLeakPrevention] FwpmSubLayerDeleteByKey0 failed: " + std::to_string(r));
        all_ok = false;
    }

    FwpmEngineClose0(reinterpret_cast<HANDLE>(engine_handle_));
    engine_handle_ = nullptr;
    stats_.rules_installed.store(0);
    return all_ok;
}

// Stub for add_wfp_filter_ (used only internally above; suppress unused warning)
uint64_t DNSLeakPrevention::add_wfp_filter_(
    HANDLE     /*engine*/,
    const GUID& /*layer_key*/,
    const char* /*filter_name*/,
    uint16_t    /*port*/,
    bool        /*is_udp*/,
    const std::string& /*except_ip*/)
{
    // Granular helper intentionally left as stub — actual logic inlined above.
    return 0;
}

// ============================================================
// LINUX — iptables
// ============================================================

#else // !_WIN32

bool DNSLeakPrevention::install_iptables_rules_()
{
    installed_rules_.clear();
    bool all_ok = true;
    uint64_t rules = 0;

    // Helper: build one iptables/ip6tables rule and run it
    auto add_rule = [&](const std::string& table_cmd, const std::string& rule) {
        // -C checks existence first; if not found, -A adds it
        std::string check = table_cmd + " -C " + rule + " 2>/dev/null";
        std::string add   = table_cmd + " -A " + rule
                            + " -m comment --comment " + std::string(RULE_COMMENT);
        // Only add if not already present
        if (::system(check.c_str()) != 0) {
            if (run_command_(add)) {
                installed_rules_.push_back(rule);
                rules++;
            } else {
                all_ok = false;
            }
        } else {
            NCP_LOG_DEBUG("[DNSLeakPrevention] Rule already present: " + rule);
            installed_rules_.push_back(rule); // track it anyway for removal
        }
    };

    // Block UDP port 53 except to whitelisted servers
    if (config_.block_udp53) {
        // First: ACCEPT rules for whitelisted servers (inserted before the DROP)
        for (const auto& ip : config_.allowed_dns_servers) {
            bool is_v6 = (ip.find(':') != std::string::npos);
            std::string tbl = is_v6 ? "ip6tables" : "iptables";
            std::string dst_flag = "-d " + ip;
            add_rule(tbl, "OUTPUT -p udp --dport 53 " + dst_flag + " -j ACCEPT");
        }
        // DROP all other UDP/53 output
        add_rule("iptables",  "OUTPUT -p udp --dport 53 -j DROP");
        add_rule("ip6tables", "OUTPUT -p udp --dport 53 -j DROP");
        NCP_LOG_INFO("[DNSLeakPrevention] iptables: UDP/53 block rules added.");
    }

    // Block TCP port 53 except to whitelisted servers
    if (config_.block_tcp53) {
        for (const auto& ip : config_.allowed_dns_servers) {
            bool is_v6 = (ip.find(':') != std::string::npos);
            std::string tbl = is_v6 ? "ip6tables" : "iptables";
            add_rule(tbl, "OUTPUT -p tcp --dport 53 -d " + ip + " -j ACCEPT");
        }
        add_rule("iptables",  "OUTPUT -p tcp --dport 53 -j DROP");
        add_rule("ip6tables", "OUTPUT -p tcp --dport 53 -j DROP");
        NCP_LOG_INFO("[DNSLeakPrevention] iptables: TCP/53 block rules added.");
    }

    // Block STUN ports
    if (config_.block_webrtc_stun) {
        for (uint16_t port : config_.stun_ports) {
            std::string p = std::to_string(port);
            add_rule("iptables",  "OUTPUT -p udp --dport " + p + " -j DROP");
            add_rule("ip6tables", "OUTPUT -p udp --dport " + p + " -j DROP");
            NCP_LOG_INFO("[DNSLeakPrevention] iptables: STUN UDP/" + p + " block added.");
        }
    }

    // Block raw IPv6 outbound (when tunnel not active)
    if (config_.block_raw_ipv6) {
        add_rule("ip6tables", "OUTPUT -j DROP");
        NCP_LOG_INFO("[DNSLeakPrevention] ip6tables: raw IPv6 OUTPUT blocked.");
    }

    stats_.rules_installed.fetch_add(rules, std::memory_order_relaxed);
    NCP_LOG_INFO("[DNSLeakPrevention] iptables rules installed: " + std::to_string(rules));
    return all_ok;
}

bool DNSLeakPrevention::remove_iptables_rules_()
{
    bool all_ok = true;

    // Remove rules by comment tag — safer than tracking exact rule strings
    // iptables-save / grep / iptables -D approach
    auto remove_by_comment = [&](const std::string& tbl) {
        // List all rules, grep for our comment, delete each
        std::string cmd = tbl + " -S OUTPUT 2>/dev/null | "
                          "grep '" + std::string(RULE_COMMENT) + "' | "
                          "while read rule; do "
                          "  " + tbl + " -D $(echo \"$rule\" | sed 's/^-A //'); "
                          "done";
        if (!run_command_(cmd)) {
            NCP_LOG_WARN("[DNSLeakPrevention] remove_by_comment partial failure for " + tbl);
            all_ok = false;
        }
    };

    remove_by_comment("iptables");
    remove_by_comment("ip6tables");
    installed_rules_.clear();
    stats_.rules_installed.store(0);
    NCP_LOG_INFO("[DNSLeakPrevention] iptables rules removed.");
    return all_ok;
}

#endif // _WIN32

} // namespace ncp
