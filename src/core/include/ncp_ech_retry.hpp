#ifndef NCP_ECH_RETRY_HPP
#define NCP_ECH_RETRY_HPP

/**
 * @file ncp_ech_retry.hpp
 * @brief ECH retry mechanism with retry_configs support
 */

#include "ncp_ech.hpp"
#include "ncp_ech_fetch.hpp"
#include "ncp_ech_cache.hpp"
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <functional>

namespace ncp {
namespace DPI {
namespace ECH {

/**
 * @brief ECH connection result
 */
enum class ECHResult {
    SUCCESS,              // ECH accepted
    RETRY_REQUIRED,       // Server sent retry_configs
    GREASE_ACCEPTED,      // GREASE succeeded (ECH not supported)
    FALLBACK_PLAINTEXT,   // Fallback to plaintext
    NETWORK_ERROR,        // Network failure
    CONFIG_INVALID,       // Invalid ECHConfig
};

/**
 * @brief ECH connection attempt details
 */
struct ECHAttempt {
    ECHResult result;
    std::string domain;
    ECHConfig config_used;
    std::vector<ECHConfig> retry_configs;  // Server-provided retry configs
    std::string error_message;
    std::chrono::milliseconds latency;
    bool used_cache = false;
};

/**
 * @brief Retry policy configuration
 */
struct RetryPolicy {
    uint32_t max_retries = 3;
    std::chrono::milliseconds initial_delay = std::chrono::milliseconds(100);
    std::chrono::milliseconds max_delay = std::chrono::milliseconds(5000);
    double backoff_multiplier = 2.0;
    bool enable_grease = true;         // Send GREASE on first attempt
    bool fallback_to_plaintext = true; // Allow plaintext fallback
};

/**
 * @brief Callback for connection attempts
 */
using ECHAttemptCallback = std::function<void(const ECHAttempt&)>;

/**
 * @brief ECH connection manager with retry logic
 */
class ECHConnectionManager {
public:
    ECHConnectionManager();
    explicit ECHConnectionManager(const RetryPolicy& policy);
    ~ECHConnectionManager();

    /**
     * @brief Connect with ECH and retry on failure
     * @param domain Target domain
     * @param client_hello Original ClientHello
     * @param encrypted_hello Output: ECH-encrypted ClientHello
     * @return ECHResult indicating outcome
     */
    ECHResult connect_with_ech(
        const std::string& domain,
        const std::vector<uint8_t>& client_hello,
        std::vector<uint8_t>& encrypted_hello
    );

    /**
     * @brief Handle retry_configs from server
     * @param domain Domain name
     * @param retry_configs Server-provided ECHConfigs
     */
    void handle_retry_configs(
        const std::string& domain,
        const std::vector<ECHConfig>& retry_configs
    );

    /**
     * @brief Set attempt callback for monitoring
     */
    void set_attempt_callback(ECHAttemptCallback callback);

    /**
     * @brief Get last attempt details
     */
    std::optional<ECHAttempt> get_last_attempt() const;

    /**
     * @brief Get all attempt history for domain
     */
    std::vector<ECHAttempt> get_attempt_history(const std::string& domain) const;

    /**
     * @brief Clear attempt history
     */
    void clear_history();

    /**
     * @brief Enable/disable cache usage
     */
    void set_cache_enabled(bool enabled);

    /**
     * @brief Set cache instance (default uses global cache)
     */
    void set_cache(std::shared_ptr<ECHConfigCache> cache);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Convenience function: Connect with automatic retry
 * @param domain Target domain
 * @param client_hello Original ClientHello
 * @return Encrypted ClientHello or original on failure
 */
std::vector<uint8_t> connect_with_retry(
    const std::string& domain,
    const std::vector<uint8_t>& client_hello
);

} // namespace ECH
} // namespace DPI
} // namespace ncp

#endif // NCP_ECH_RETRY_HPP
