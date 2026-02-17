#ifndef NCP_ECH_FETCH_HPP
#define NCP_ECH_FETCH_HPP

/**
 * @file ncp_ech_fetch.hpp
 * @brief ECHConfig fetching via DNS-over-HTTPS (DoH)
 */

#include "ncp_ech.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace ncp {
namespace DPI {
namespace ECH {

/**
 * @brief DoH resolver configuration
 */
struct DoHConfig {
    std::string server_url = "https://1.1.1.1/dns-query";  // Cloudflare DoH
    uint32_t timeout_ms = 5000;
    bool verify_ssl = true;
};

/**
 * @brief ECH configuration fetcher via DNS-over-HTTPS
 */
class ECHConfigFetcher {
public:
    ECHConfigFetcher();
    ~ECHConfigFetcher();

    /**
     * @brief Set DoH resolver configuration
     */
    void set_doh_config(const DoHConfig& config);

    /**
     * @brief Fetch ECHConfig for a domain via DoH
     * @param domain Target domain (e.g., "cloudflare.com")
     * @param config Output: Parsed ECHConfig
     * @return true on success
     */
    bool fetch_ech_config(const std::string& domain, ECHConfig& config);

    /**
     * @brief Fetch ECHConfigs from HTTPS resource record
     * @param domain Target domain
     * @return Vector of ECHConfigs (may be empty)
     */
    std::vector<ECHConfig> fetch_all_configs(const std::string& domain);

    /**
     * @brief Get last error message
     */
    std::string get_last_error() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Convenience function: Fetch ECHConfig using default DoH
 * @param domain Target domain
 * @return ECHConfig or std::nullopt on failure
 */
std::optional<ECHConfig> fetch_ech_config_simple(const std::string& domain);

} // namespace ECH
} // namespace DPI
} // namespace ncp

#endif // NCP_ECH_FETCH_HPP
