/**
 * @file ncp_cross_layer_correlator.cpp
 * @brief CrossLayerCorrelator implementation
 *
 * Validates coherence across network layers (L2 MAC / L3 TTL+MSS /
 * L4 TCP window / L7 TLS+hostname) to detect OS fingerprint mismatches
 * that TSPU deep-inspection can exploit.
 *
 * C++17 / MSVC-compatible.  Uses <regex> for hostname pattern matching.
 */

#include "../include/ncp_cross_layer_correlator.hpp"

#include <algorithm>
#include <sstream>
#include <cmath>
#include <cassert>
#include <cctype>

namespace ncp {

// ---------------------------------------------------------------------------
// Anonymous-namespace helpers
// ---------------------------------------------------------------------------
namespace {

/// Convert ASCII string to lower-case in-place.
inline std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

/// Extract the OUI prefix (first 3 colon-separated octets) from a MAC address.
/// Returns empty string on malformed input.
inline std::string extract_oui(const std::string& mac) {
    // Expected formats: "aa:bb:cc:dd:ee:ff"  or  "aa-bb-cc-dd-ee-ff"
    if (mac.size() < 8) return {};

    // Normalise separator to ':'
    std::string m = mac;
    std::replace(m.begin(), m.end(), '-', ':');

    auto p1 = m.find(':');
    if (p1 == std::string::npos) return {};
    auto p2 = m.find(':', p1 + 1);
    if (p2 == std::string::npos) return {};

    return to_lower(m.substr(0, p2));  // "aa:bb:cc"
}

/// Name for a CorrelationCheck (for log messages).
inline const char* check_name(CorrelationCheck c) {
    switch (c) {
        case CorrelationCheck::MAC_VS_TTL:             return "MAC_VS_TTL";
        case CorrelationCheck::TTL_VS_OS_PROFILE:      return "TTL_VS_OS_PROFILE";
        case CorrelationCheck::TCP_WINDOW_VS_PROFILE:  return "TCP_WINDOW_VS_PROFILE";
        case CorrelationCheck::TLS_VS_HOSTNAME:        return "TLS_VS_HOSTNAME";
        case CorrelationCheck::TLS_VS_USER_AGENT:      return "TLS_VS_USER_AGENT";
        case CorrelationCheck::MSS_VS_MTU:             return "MSS_VS_MTU";
        case CorrelationCheck::IPV6_VS_PROFILE:        return "IPV6_VS_PROFILE";
    }
    return "UNKNOWN";
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

CrossLayerCorrelator::CrossLayerCorrelator()
{
    config_.enabled            = Config::instance().getBool("cross_layer.enabled",    true);
    config_.active_profile     = Config::instance().get   ("cross_layer.profile",     "Windows10-Chrome");
    config_.auto_fix           = Config::instance().getBool("cross_layer.auto_fix",   true);
    config_.log_mismatches     = Config::instance().getBool("cross_layer.log_mismatches", true);
    config_.mismatch_threshold = static_cast<float>(
        Config::instance().getInt("cross_layer.mismatch_threshold_pct", 70)) / 100.0f;

    load_default_profiles();

    NCP_LOG_INFO("[CrossLayerCorrelator] Initialized"
                 " profile=" + config_.active_profile
                 + " auto_fix=" + (config_.auto_fix ? "true" : "false"));
}

CrossLayerCorrelator::CrossLayerCorrelator(const CrossLayerCorrelatorConfig& cfg)
    : config_(cfg)
{
    load_default_profiles();
    NCP_LOG_INFO("[CrossLayerCorrelator] Initialized with custom config"
                 " profile=" + cfg.active_profile);
}

// ---------------------------------------------------------------------------
// Built-in profiles
// ---------------------------------------------------------------------------

void CrossLayerCorrelator::load_default_profiles()
{
    std::lock_guard<std::mutex> lock(mutex_);
    profiles_.clear();

    // -------------------------------------------------------------------
    // Windows 10 / Chrome
    // -------------------------------------------------------------------
    {
        CrossLayerProfile p;
        p.name             = "Windows10-Chrome";
        p.expected_ttl     = 128;
        p.ttl_tolerance    = 5;
        p.expected_mss     = 1460;
        p.supports_ipv6    = true;
        p.tcp_window_size  = 65535;
        p.tcp_window_scale = 8;
        p.tcp_options_order = { 2, 4, 8, 1, 3 }; // MSS, SACK-OK, TS, NOP, WS
        // Intel and Realtek are dominant Windows NICs
        p.mac_oui_prefixes = {
            "00:50:56",  // VMware (common in test/lab Windows VMs)
            "00:0c:29",  // VMware Workstation
            "00:1c:42",  // Parallels
            "8c:8d:28",  // Intel Wi-Fi 6
            "d4:81:d7",  // Intel
            "a4:c3:f0",  // Intel NUC / laptops
            "00:e0:4c",  // Realtek
            "52:54:00",  // QEMU/KVM
        };
        p.tls_ja3_prefix           = "771,";
        p.expected_hostname_pattern = "^DESKTOP-[A-Z0-9]{7}$|^LAPTOP-[A-Z0-9]{7}$";
        p.expected_user_agent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

        profiles_[p.name] = std::move(p);
    }

    // -------------------------------------------------------------------
    // Windows 11 / Edge
    // -------------------------------------------------------------------
    {
        CrossLayerProfile p;
        p.name             = "Windows11-Edge";
        p.expected_ttl     = 128;
        p.ttl_tolerance    = 5;
        p.expected_mss     = 1460;
        p.supports_ipv6    = true;
        p.tcp_window_size  = 65535;
        p.tcp_window_scale = 8;
        p.tcp_options_order = { 2, 4, 8, 1, 3 };
        p.mac_oui_prefixes = {
            "00:50:56",
            "00:0c:29",
            "8c:8d:28",
            "a4:c3:f0",
            "00:e0:4c",
            "6c:02:e0",  // Intel AX201
            "fc:77:74",  // Intel Killer
        };
        p.tls_ja3_prefix           = "771,";
        p.expected_hostname_pattern = "^DESKTOP-[A-Z0-9]{7}$|^[A-Za-z][A-Za-z0-9\\-]{0,14}$";
        p.expected_user_agent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        profiles_[p.name] = std::move(p);
    }

    // -------------------------------------------------------------------
    // macOS / Safari
    // -------------------------------------------------------------------
    {
        CrossLayerProfile p;
        p.name             = "macOS-Safari";
        p.expected_ttl     = 64;
        p.ttl_tolerance    = 3;
        p.expected_mss     = 1460;
        p.supports_ipv6    = true;
        p.tcp_window_size  = 65535;
        p.tcp_window_scale = 6;
        p.tcp_options_order = { 2, 4, 8, 1, 3 };
        // Apple OUI prefixes (Broadcom Wi-Fi, Apple Ethernet, T2 etc.)
        p.mac_oui_prefixes = {
            "a4:83:e7",  // Apple
            "f0:18:98",  // Apple
            "3c:06:30",  // Apple
            "8c:85:90",  // Apple
            "00:17:f2",  // Apple
            "00:3e:e1",  // Apple
            "ac:de:48",  // Apple
            "f4:5c:89",  // Apple (M1/M2 Mac)
            "7c:d1:c3",  // Apple
        };
        p.tls_ja3_prefix           = "771,4865-4866-4867-";
        p.expected_hostname_pattern = "^[A-Za-z][A-Za-z0-9\\-]{0,14}\\.local$|^MacBook";
        p.expected_user_agent      = "Mozilla/5.0 (Macintosh; Intel Mac OS X";

        profiles_[p.name] = std::move(p);
    }

    // -------------------------------------------------------------------
    // Linux / Firefox
    // -------------------------------------------------------------------
    {
        CrossLayerProfile p;
        p.name             = "Linux-Firefox";
        p.expected_ttl     = 64;
        p.ttl_tolerance    = 5;
        p.expected_mss     = 1460;
        p.supports_ipv6    = true;
        p.tcp_window_size  = 64240;
        p.tcp_window_scale = 7;
        p.tcp_options_order = { 2, 4, 8, 1, 3 };
        // Generic Linux / server OUI prefixes
        p.mac_oui_prefixes = {
            "00:50:56",  // VMware
            "00:0c:29",  // VMware Workstation
            "52:54:00",  // QEMU/KVM
            "02:42:",    // Docker (virtual prefix)
            "00:16:3e",  // Xen
            "08:00:27",  // VirtualBox
        };
        p.tls_ja3_prefix           = "771,4865-4867-4866-";
        p.expected_hostname_pattern = "^[a-z][a-z0-9\\-]{0,62}$";
        p.expected_user_agent      = "Mozilla/5.0 (X11; Linux x86_64)";

        profiles_[p.name] = std::move(p);
    }

    stats_.profiles_loaded.store(static_cast<uint64_t>(profiles_.size()));
    NCP_LOG_INFO("[CrossLayerCorrelator] Loaded " + std::to_string(profiles_.size())
                 + " default profiles");
}

// ---------------------------------------------------------------------------
// Profile management
// ---------------------------------------------------------------------------

void CrossLayerCorrelator::add_profile(const CrossLayerProfile& profile)
{
    std::lock_guard<std::mutex> lock(mutex_);
    profiles_[profile.name] = profile;
    stats_.profiles_loaded.fetch_add(1);
    NCP_LOG_INFO("[CrossLayerCorrelator] Added profile: " + profile.name);
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

const CrossLayerProfile* CrossLayerCorrelator::get_active_profile_() const
{
    auto it = profiles_.find(config_.active_profile);
    if (it == profiles_.end()) {
        NCP_LOG_ERROR("[CrossLayerCorrelator] Active profile '"
                      + config_.active_profile + "' not found");
        return nullptr;
    }
    return &it->second;
}

bool CrossLayerCorrelator::mac_matches_oui_(const std::string& mac,
                                             const std::vector<std::string>& ouis)
{
    const std::string oui = to_lower(extract_oui(mac));
    if (oui.empty()) return false;

    for (const auto& entry : ouis) {
        std::string e = to_lower(entry);
        // Allow prefix matching: entry might be "02:42:" (Docker) — only 5 chars
        if (oui.rfind(e, 0) == 0 || e.rfind(oui, 0) == 0) {
            return true;
        }
    }
    return false;
}

float CrossLayerCorrelator::compute_ttl_confidence_(uint8_t observed,
                                                      uint8_t expected,
                                                      uint8_t tolerance)
{
    int diff = static_cast<int>(observed) - static_cast<int>(expected);
    if (diff < 0) diff = -diff;

    if (diff <= static_cast<int>(tolerance)) {
        return 0.0f;  // within tolerance — fully coherent
    }

    // Scale linearly: at diff = tolerance we start at 0; at diff = 64 we hit 1.
    constexpr float max_diff = 64.0f;
    float normalized = static_cast<float>(diff - tolerance) / max_diff;
    return std::min(1.0f, normalized);
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

CorrelationResult CrossLayerCorrelator::check_mac_vs_ttl(const std::string& mac,
                                                           uint8_t ttl)
{
    CorrelationResult r;
    r.check = CorrelationCheck::MAC_VS_TTL;
    r.coherent   = true;
    r.confidence = 0.0f;

    std::lock_guard<std::mutex> lock(mutex_);
    const CrossLayerProfile* profile = get_active_profile_();
    if (!profile) {
        r.detail = "No active profile";
        return r;
    }

    stats_.checks_performed.fetch_add(1);

    bool oui_match = mac_matches_oui_(mac, profile->mac_oui_prefixes);
    float ttl_conf = compute_ttl_confidence_(ttl, profile->expected_ttl,
                                              profile->ttl_tolerance);

    // Mismatch: OUI does NOT match AND TTL deviates significantly
    if (!oui_match && ttl_conf > config_.mismatch_threshold) {
        r.coherent   = false;
        r.confidence = ttl_conf;
        r.detail     = "OUI " + extract_oui(mac)
                        + " not in profile '" + profile->name + "'"
                        + "; TTL " + std::to_string(ttl)
                        + " expected " + std::to_string(profile->expected_ttl);
        stats_.mismatches_detected.fetch_add(1);
        if (config_.log_mismatches) {
            NCP_LOG_WARN("[CrossLayerCorrelator] MAC_VS_TTL mismatch: " + r.detail);
        }
    } else if (!oui_match) {
        // OUI unknown but TTL is plausible — low-confidence notice
        r.coherent   = true;   // not critical
        r.confidence = 0.3f;
        r.detail     = "OUI " + extract_oui(mac)
                        + " not in profile (TTL within tolerance)";
    } else {
        r.detail = "OUI matches profile; TTL within tolerance";
    }

    return r;
}

CorrelationResult CrossLayerCorrelator::check_tcp_window_vs_profile(uint32_t window,
                                                                      uint16_t scale)
{
    CorrelationResult r;
    r.check = CorrelationCheck::TCP_WINDOW_VS_PROFILE;
    r.coherent   = true;
    r.confidence = 0.0f;

    std::lock_guard<std::mutex> lock(mutex_);
    const CrossLayerProfile* profile = get_active_profile_();
    if (!profile) {
        r.detail = "No active profile";
        return r;
    }

    stats_.checks_performed.fetch_add(1);

    float win_diff  = (profile->tcp_window_size > 0)
                      ? std::fabs(static_cast<float>(window)
                                  - static_cast<float>(profile->tcp_window_size))
                        / static_cast<float>(profile->tcp_window_size)
                      : 0.0f;

    float scale_diff = (profile->tcp_window_scale > 0)
                       ? std::fabs(static_cast<float>(scale)
                                   - static_cast<float>(profile->tcp_window_scale))
                         / static_cast<float>(profile->tcp_window_scale)
                       : 0.0f;

    // Combined confidence: larger of the two ratios, capped at 1.0
    float conf = std::min(1.0f, std::max(win_diff, scale_diff));

    if (conf > config_.mismatch_threshold) {
        r.coherent   = false;
        r.confidence = conf;
        r.detail     = "TCP window " + std::to_string(window)
                        + " (expected " + std::to_string(profile->tcp_window_size) + ")"
                        + " scale " + std::to_string(scale)
                        + " (expected " + std::to_string(profile->tcp_window_scale) + ")";
        stats_.mismatches_detected.fetch_add(1);
        if (config_.log_mismatches) {
            NCP_LOG_WARN("[CrossLayerCorrelator] TCP_WINDOW_VS_PROFILE mismatch: " + r.detail);
        }
    } else {
        r.confidence = conf;
        r.detail     = "TCP window coherent with profile";
    }

    return r;
}

CorrelationResult CrossLayerCorrelator::check_tls_vs_hostname(const std::string& ja3,
                                                               const std::string& hostname)
{
    CorrelationResult r;
    r.check      = CorrelationCheck::TLS_VS_HOSTNAME;
    r.coherent   = true;
    r.confidence = 0.0f;

    std::lock_guard<std::mutex> lock(mutex_);
    const CrossLayerProfile* profile = get_active_profile_();
    if (!profile) {
        r.detail = "No active profile";
        return r;
    }

    stats_.checks_performed.fetch_add(1);

    bool ja3_ok      = true;
    bool hostname_ok = true;
    float conf       = 0.0f;

    // --- JA3 prefix check ---
    if (!ja3.empty() && !profile->tls_ja3_prefix.empty()) {
        ja3_ok = (ja3.rfind(profile->tls_ja3_prefix, 0) == 0);
        if (!ja3_ok) conf += 0.5f;
    }

    // --- Hostname regex check ---
    if (!hostname.empty() && !profile->expected_hostname_pattern.empty()) {
        try {
            std::regex re(profile->expected_hostname_pattern,
                          std::regex_constants::ECMAScript
                          | std::regex_constants::icase);
            hostname_ok = std::regex_search(hostname, re);
        } catch (const std::regex_error& ex) {
            NCP_LOG_ERROR("[CrossLayerCorrelator] Regex error for profile '"
                          + profile->name + "': " + ex.what());
            hostname_ok = true;  // treat as OK if pattern is broken
        }
        if (!hostname_ok) conf += 0.5f;
    }

    conf = std::min(1.0f, conf);

    if (conf > config_.mismatch_threshold) {
        r.coherent   = false;
        r.confidence = conf;
        r.detail     = "JA3 prefix mismatch=" + std::string(ja3_ok ? "no" : "yes")
                        + " hostname mismatch=" + std::string(hostname_ok ? "no" : "yes")
                        + " (profile=" + profile->name + ")";
        stats_.mismatches_detected.fetch_add(1);
        if (config_.log_mismatches) {
            NCP_LOG_WARN("[CrossLayerCorrelator] TLS_VS_HOSTNAME mismatch: " + r.detail);
        }
    } else {
        r.confidence = conf;
        r.detail     = "TLS/hostname coherent with profile";
    }

    return r;
}

// ---------------------------------------------------------------------------
// Full coherence validation
// ---------------------------------------------------------------------------

std::vector<CorrelationResult> CrossLayerCorrelator::validate_coherence(
    const std::string& mac_address,
    uint8_t            observed_ttl,
    uint16_t           observed_mss,
    uint32_t           tcp_window,
    uint16_t           tcp_window_scale,
    const std::string& tls_ja3,
    const std::string& dhcp_hostname)
{
    if (!config_.enabled) return {};

    std::vector<CorrelationResult> results;
    results.reserve(7);

    // At HIGH/CRITICAL threat: lower the mismatch threshold to 0.5
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (threat_level_ >= DPI::ThreatLevel::HIGH) {
            if (config_.mismatch_threshold > 0.5f) {
                config_.mismatch_threshold = 0.5f;
                NCP_LOG_INFO("[CrossLayerCorrelator] HIGH threat: threshold lowered to 0.5");
            }
        }
    }

    // --- MAC vs TTL ---
    if (!mac_address.empty()) {
        results.push_back(check_mac_vs_ttl(mac_address, observed_ttl));
    }

    // --- TTL vs OS Profile (standalone TTL check without MAC) ---
    {
        CorrelationResult r;
        r.check = CorrelationCheck::TTL_VS_OS_PROFILE;
        r.coherent   = true;
        r.confidence = 0.0f;

        std::lock_guard<std::mutex> lock(mutex_);
        const CrossLayerProfile* profile = get_active_profile_();
        if (profile) {
            stats_.checks_performed.fetch_add(1);
            float conf = compute_ttl_confidence_(observed_ttl,
                                                  profile->expected_ttl,
                                                  profile->ttl_tolerance);
            r.confidence = conf;
            if (conf > config_.mismatch_threshold) {
                r.coherent = false;
                r.detail   = "TTL " + std::to_string(observed_ttl)
                              + " expected ~" + std::to_string(profile->expected_ttl)
                              + " (profile=" + profile->name + ")";
                stats_.mismatches_detected.fetch_add(1);
                if (config_.log_mismatches) {
                    NCP_LOG_WARN("[CrossLayerCorrelator] TTL_VS_OS_PROFILE: " + r.detail);
                }
            } else {
                r.detail = "TTL within expected range for " + profile->name;
            }
        }
        results.push_back(r);
    }

    // --- TCP window ---
    results.push_back(check_tcp_window_vs_profile(tcp_window, tcp_window_scale));

    // --- TLS vs hostname ---
    if (!tls_ja3.empty() || !dhcp_hostname.empty()) {
        results.push_back(check_tls_vs_hostname(tls_ja3, dhcp_hostname));
    }

    // --- MSS vs MTU (simple sanity: MSS <= 1460 for standard Ethernet) ---
    {
        CorrelationResult r;
        r.check = CorrelationCheck::MSS_VS_MTU;
        r.coherent   = true;
        r.confidence = 0.0f;

        std::lock_guard<std::mutex> lock(mutex_);
        const CrossLayerProfile* profile = get_active_profile_();
        if (profile) {
            stats_.checks_performed.fetch_add(1);
            if (observed_mss > 0) {
                float diff_ratio = std::fabs(static_cast<float>(observed_mss)
                                             - static_cast<float>(profile->expected_mss))
                                   / static_cast<float>(profile->expected_mss);
                r.confidence = std::min(1.0f, diff_ratio);
                if (diff_ratio > config_.mismatch_threshold) {
                    r.coherent = false;
                    r.detail   = "MSS " + std::to_string(observed_mss)
                                  + " expected " + std::to_string(profile->expected_mss);
                    stats_.mismatches_detected.fetch_add(1);
                    if (config_.log_mismatches) {
                        NCP_LOG_WARN("[CrossLayerCorrelator] MSS_VS_MTU: " + r.detail);
                    }
                } else {
                    r.detail = "MSS within expected range";
                }
            }
        }
        results.push_back(r);
    }

    // --- IPv6 support vs profile ---
    {
        CorrelationResult r;
        r.check      = CorrelationCheck::IPV6_VS_PROFILE;
        r.coherent   = true;
        r.confidence = 0.0f;
        r.detail     = "IPv6 check skipped (no observed IPv6 flag)";
        // This check requires external context (whether IPv6 is actually being used).
        // When integrated with the pipeline, call validate_coherence with a dedicated
        // overload that accepts a bool has_ipv6.  For now we mark it as coherent.
        results.push_back(r);
    }

    // Apply auto-fix counter
    if (config_.auto_fix) {
        uint64_t fix_count = 0;
        for (auto& res : results) {
            if (!res.coherent) {
                ++fix_count;
            }
        }
        if (fix_count > 0) {
            stats_.auto_fixes_applied.fetch_add(fix_count);
            NCP_LOG_INFO("[CrossLayerCorrelator] Auto-fix triggered for "
                         + std::to_string(fix_count) + " mismatch(es)");
        }
    }

    return results;
}

// ---------------------------------------------------------------------------
// Fix recommendations
// ---------------------------------------------------------------------------

std::vector<CrossLayerCorrelator::FixRecommendation>
CrossLayerCorrelator::get_fix_recommendations(const std::vector<CorrelationResult>& results)
{
    std::vector<FixRecommendation> fixes;

    std::lock_guard<std::mutex> lock(mutex_);
    const CrossLayerProfile* profile = get_active_profile_();
    if (!profile) return fixes;

    for (const auto& r : results) {
        if (r.coherent) continue;

        switch (r.check) {
            case CorrelationCheck::MAC_VS_TTL:
            case CorrelationCheck::TTL_VS_OS_PROFILE: {
                FixRecommendation f;
                f.check             = r.check;
                f.field_to_fix      = "ip_ttl";
                f.recommended_value = std::to_string(profile->expected_ttl);
                fixes.push_back(f);
                break;
            }
            case CorrelationCheck::TCP_WINDOW_VS_PROFILE: {
                {
                    FixRecommendation f1;
                    f1.check             = r.check;
                    f1.field_to_fix      = "tcp_window_size";
                    f1.recommended_value = std::to_string(profile->tcp_window_size);
                    fixes.push_back(f1);
                }
                {
                    FixRecommendation f2;
                    f2.check             = r.check;
                    f2.field_to_fix      = "tcp_window_scale";
                    f2.recommended_value = std::to_string(profile->tcp_window_scale);
                    fixes.push_back(f2);
                }
                break;
            }
            case CorrelationCheck::TLS_VS_HOSTNAME: {
                {
                    FixRecommendation f1;
                    f1.check             = r.check;
                    f1.field_to_fix      = "tls_ja3_prefix";
                    f1.recommended_value = profile->tls_ja3_prefix;
                    fixes.push_back(f1);
                }
                {
                    FixRecommendation f2;
                    f2.check             = r.check;
                    f2.field_to_fix      = "dhcp_hostname_pattern";
                    f2.recommended_value = profile->expected_hostname_pattern;
                    fixes.push_back(f2);
                }
                break;
            }
            case CorrelationCheck::TLS_VS_USER_AGENT: {
                FixRecommendation f;
                f.check             = r.check;
                f.field_to_fix      = "http_user_agent";
                f.recommended_value = profile->expected_user_agent;
                fixes.push_back(f);
                break;
            }
            case CorrelationCheck::MSS_VS_MTU: {
                FixRecommendation f;
                f.check             = r.check;
                f.field_to_fix      = "tcp_mss";
                f.recommended_value = std::to_string(profile->expected_mss);
                fixes.push_back(f);
                break;
            }
            case CorrelationCheck::IPV6_VS_PROFILE: {
                FixRecommendation f;
                f.check             = r.check;
                f.field_to_fix      = "ipv6_enabled";
                f.recommended_value = profile->supports_ipv6 ? "true" : "false";
                fixes.push_back(f);
                break;
            }
        }
    }

    NCP_LOG_DEBUG("[CrossLayerCorrelator] Generated " + std::to_string(fixes.size())
                  + " fix recommendation(s)");
    return fixes;
}

// ---------------------------------------------------------------------------
// Configuration & stats
// ---------------------------------------------------------------------------

void CrossLayerCorrelator::set_active_profile(const std::string& profile_name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (profiles_.find(profile_name) == profiles_.end()) {
        NCP_LOG_ERROR("[CrossLayerCorrelator] set_active_profile: unknown profile '"
                      + profile_name + "'");
        return;
    }
    config_.active_profile = profile_name;
    NCP_LOG_INFO("[CrossLayerCorrelator] Active profile switched to: " + profile_name);
}

std::string CrossLayerCorrelator::get_active_profile() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.active_profile;
}

void CrossLayerCorrelator::set_config(const CrossLayerCorrelatorConfig& cfg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    NCP_LOG_INFO("[CrossLayerCorrelator] Config updated"
                 " profile=" + cfg.active_profile
                 + " threshold=" + std::to_string(cfg.mismatch_threshold));
}

CrossLayerCorrelatorConfig CrossLayerCorrelator::get_config() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

CrossLayerCorrelatorStats CrossLayerCorrelator::get_stats() const
{
    // Copy constructor loads each atomic individually for a consistent snapshot.
    return stats_;
}

void CrossLayerCorrelator::reset_stats()
{
    stats_.reset();
    NCP_LOG_DEBUG("[CrossLayerCorrelator] Stats reset");
}

void CrossLayerCorrelator::set_threat_level(DPI::ThreatLevel level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    threat_level_ = level;
    if (level >= DPI::ThreatLevel::HIGH && config_.mismatch_threshold > 0.5f) {
        config_.mismatch_threshold = 0.5f;
        NCP_LOG_INFO("[CrossLayerCorrelator] HIGH/CRITICAL threat:"
                     " mismatch_threshold lowered to 0.5");
    }
    NCP_LOG_INFO("[CrossLayerCorrelator] Threat level set to "
                 + std::to_string(static_cast<int>(level)));
}

} // namespace ncp
