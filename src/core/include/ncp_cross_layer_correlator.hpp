#pragma once
#ifndef NCP_CROSS_LAYER_CORRELATOR_HPP
#define NCP_CROSS_LAYER_CORRELATOR_HPP

/**
 * @file ncp_cross_layer_correlator.hpp
 * @brief CrossLayerCorrelator — multi-layer coherence validation for anti-TSPU
 *
 * TSPU detectors can flag traffic by finding contradictions across network
 * layers: a MAC OUI that belongs to Apple hardware but a TTL of 64 (Linux),
 * a Windows-sized TCP window scale combined with a Linux JA3 fingerprint, etc.
 *
 * This module:
 *   • Maintains named OS/browser "profiles" describing expected L2-L7 values.
 *   • Runs a battery of CorrelationChecks against live packet metadata.
 *   • Produces per-check CorrelationResult objects with confidence scores.
 *   • Recommends specific field corrections so other modules (L3Stealth,
 *     TLSFingerprint) can autocorrect mismatches.
 *
 * Architecture: ncp namespace, C++17, MSVC-compatible, thread-safe.
 */

#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"
#include "ncp_orchestrator.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <regex>

namespace ncp {

// ---------------------------------------------------------------------------
// OS/Browser profile — describes expected per-layer values
// ---------------------------------------------------------------------------

struct CrossLayerProfile {
    std::string name;  ///< e.g. "Windows10-Chrome", "macOS-Safari"

    // --- L2 hints ---
    std::vector<std::string> mac_oui_prefixes;  ///< first 3 octets, e.g. "00:50:56"

    // --- L3 hints ---
    uint8_t  expected_ttl        = 128;  ///< Windows default
    uint8_t  ttl_tolerance       = 5;
    uint16_t expected_mss        = 1460;
    bool     supports_ipv6       = true;

    // --- L4 hints ---
    uint32_t tcp_window_size     = 65535;
    uint16_t tcp_window_scale    = 8;
    std::vector<uint8_t> tcp_options_order;  ///< standard TCP option kinds in order

    // --- L7 hints ---
    std::string tls_ja3_prefix;            ///< expected JA3 fingerprint pattern
    std::string expected_hostname_pattern; ///< regex for DHCP hostname
    std::string expected_user_agent;
};

// ---------------------------------------------------------------------------
// Enumeration of individual correlation checks
// ---------------------------------------------------------------------------

enum class CorrelationCheck {
    MAC_VS_TTL,
    TTL_VS_OS_PROFILE,
    TCP_WINDOW_VS_PROFILE,
    TLS_VS_HOSTNAME,
    TLS_VS_USER_AGENT,
    MSS_VS_MTU,
    IPV6_VS_PROFILE
};

// ---------------------------------------------------------------------------
// Result of a single check
// ---------------------------------------------------------------------------

struct CorrelationResult {
    CorrelationCheck check;
    bool             coherent    = true;
    std::string      detail;
    float            confidence  = 1.0f;  ///< 0..1; higher = more certain about the mismatch
};

// ---------------------------------------------------------------------------
// Module configuration
// ---------------------------------------------------------------------------

struct CrossLayerCorrelatorConfig {
    bool        enabled             = true;
    std::string active_profile      = "Windows10-Chrome";
    bool        auto_fix            = true;   ///< automatically fix detected mismatches
    bool        log_mismatches      = true;
    float       mismatch_threshold  = 0.7f;   ///< report if confidence > threshold
};

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct CrossLayerCorrelatorStats {
    std::atomic<uint64_t> checks_performed{0};
    std::atomic<uint64_t> mismatches_detected{0};
    std::atomic<uint64_t> auto_fixes_applied{0};
    std::atomic<uint64_t> profiles_loaded{0};

    CrossLayerCorrelatorStats() = default;

    /// Custom copy constructor: atomics are not copyable, load each value.
    CrossLayerCorrelatorStats(const CrossLayerCorrelatorStats& o)
        : checks_performed  (o.checks_performed.load())
        , mismatches_detected(o.mismatches_detected.load())
        , auto_fixes_applied(o.auto_fixes_applied.load())
        , profiles_loaded   (o.profiles_loaded.load())
    {}

    CrossLayerCorrelatorStats& operator=(const CrossLayerCorrelatorStats& o) {
        if (this != &o) {
            checks_performed.store  (o.checks_performed.load());
            mismatches_detected.store(o.mismatches_detected.load());
            auto_fixes_applied.store(o.auto_fixes_applied.load());
            profiles_loaded.store   (o.profiles_loaded.load());
        }
        return *this;
    }

    void reset() {
        checks_performed.store(0);
        mismatches_detected.store(0);
        auto_fixes_applied.store(0);
        profiles_loaded.store(0);
    }
};

// ---------------------------------------------------------------------------
// CrossLayerCorrelator
// ---------------------------------------------------------------------------

class CrossLayerCorrelator {
public:
    CrossLayerCorrelator();
    explicit CrossLayerCorrelator(const CrossLayerCorrelatorConfig& cfg);

    // Non-copyable
    CrossLayerCorrelator(const CrossLayerCorrelator&)            = delete;
    CrossLayerCorrelator& operator=(const CrossLayerCorrelator&) = delete;
    CrossLayerCorrelator(CrossLayerCorrelator&&)                 = default;
    CrossLayerCorrelator& operator=(CrossLayerCorrelator&&)      = default;

    // -----------------------------------------------------------------------
    // Profile management
    // -----------------------------------------------------------------------

    /** @brief Load the four built-in profiles (Windows10-Chrome, Windows11-Edge,
     *         macOS-Safari, Linux-Firefox). */
    void load_default_profiles();

    /** @brief Register a custom profile. */
    void add_profile(const CrossLayerProfile& profile);

    // -----------------------------------------------------------------------
    // Correlation API
    // -----------------------------------------------------------------------

    /**
     * @brief Run all correlation checks against the active profile.
     *
     * Any empty string parameter is treated as "not observed / not available"
     * and the corresponding checks are skipped with coherent=true.
     *
     * @param mac_address    Source MAC ("aa:bb:cc:dd:ee:ff")
     * @param observed_ttl   IP TTL value from the packet
     * @param observed_mss   TCP MSS option value
     * @param tcp_window     TCP window size
     * @param tcp_window_scale  TCP window scale option value
     * @param tls_ja3        JA3 fingerprint string (hex or hash)
     * @param dhcp_hostname  Hostname field from DHCP OPTION 12
     * @return               One CorrelationResult per check executed
     */
    std::vector<CorrelationResult> validate_coherence(
        const std::string& mac_address,
        uint8_t            observed_ttl,
        uint16_t           observed_mss,
        uint32_t           tcp_window,
        uint16_t           tcp_window_scale,
        const std::string& tls_ja3,
        const std::string& dhcp_hostname
    );

    // -----------------------------------------------------------------------
    // Individual checks (public for targeted use)
    // -----------------------------------------------------------------------

    CorrelationResult check_mac_vs_ttl          (const std::string& mac, uint8_t ttl);
    CorrelationResult check_tcp_window_vs_profile(uint32_t window, uint16_t scale);
    CorrelationResult check_tls_vs_hostname      (const std::string& ja3,
                                                  const std::string& hostname);

    // -----------------------------------------------------------------------
    // Fix recommendations
    // -----------------------------------------------------------------------

    /** Maps each failing CorrelationResult to a concrete field + value fix. */
    struct FixRecommendation {
        CorrelationCheck check;
        std::string      field_to_fix;
        std::string      recommended_value;
    };

    std::vector<FixRecommendation> get_fix_recommendations(
        const std::vector<CorrelationResult>& results);

    // -----------------------------------------------------------------------
    // Configuration & stats
    // -----------------------------------------------------------------------

    void                          set_active_profile(const std::string& profile_name);
    std::string                   get_active_profile() const;

    void                          set_config(const CrossLayerCorrelatorConfig& cfg);
    CrossLayerCorrelatorConfig    get_config() const;
    CrossLayerCorrelatorStats     get_stats()  const;
    void                          reset_stats();
    void                          set_threat_level(DPI::ThreatLevel level);

private:
    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * @brief Return pointer to the currently active profile, or nullptr if
     *        the profile name is not registered.  Caller must hold mutex_.
     */
    const CrossLayerProfile* get_active_profile_() const;

    /**
     * @brief Check whether @p mac's OUI (first 3 octets) matches any entry
     *        in @p ouis.  Case-insensitive, colon-separated.
     */
    bool mac_matches_oui_(const std::string& mac,
                           const std::vector<std::string>& ouis);

    /**
     * @brief Compute a confidence score in [0,1] for how well @p observed
     *        matches @p expected given a @p tolerance band.
     *
     * Returns 0.0 when the hop-count difference is within tolerance (fully
     * coherent), 1.0 when the difference is extreme.
     */
    float compute_ttl_confidence_(uint8_t observed, uint8_t expected,
                                   uint8_t tolerance);

    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------

    CrossLayerCorrelatorConfig  config_;
    CrossLayerCorrelatorStats   stats_;
    DPI::ThreatLevel            threat_level_ = DPI::ThreatLevel::NONE;

    mutable std::mutex          mutex_;

    std::unordered_map<std::string, CrossLayerProfile> profiles_;
};

} // namespace ncp

#endif // NCP_CROSS_LAYER_CORRELATOR_HPP
