/**
 * @file ncp_ech_retry.cpp
 * @brief ECH retry mechanism implementation
 */

#include "../include/ncp_ech_retry.hpp"
#include <thread>
#include <mutex>
#include <unordered_map>
#include <math>

namespace ncp {
namespace DPI {
namespace ECH {

struct ECHConnectionManager::Impl {
    RetryPolicy policy;
    ECHAttemptCallback callback;
    std::shared_ptr<ECHConfigCache> cache;
    bool cache_enabled = true;

    mutable std::mutex mutex;
    std::optional<ECHAttempt> last_attempt;
    std::unordered_map<std::string, std::vector<ECHAttempt>> history;

    Impl() {
        policy = RetryPolicy();
        cache = std::make_shared<ECHConfigCache>();
    }

    explicit Impl(const RetryPolicy& pol) : policy(pol) {
        cache = std::make_shared<ECHConfigCache>();
    }

    ECHResult attempt_connection(
        const std::string& domain,
        const std::vector<uint8_t>& client_hello,
        const ECHConfig& config,
        std::vector<uint8_t>& encrypted_hello,
        ECHAttempt& attempt
    ) {
        auto start = std::chrono::steady_clock::now();

        attempt.domain = domain;
        attempt.config_used = config;

        // Apply ECH encryption
        encrypted_hello = apply_ech(client_hello, config);

        // Check if encryption succeeded
        if (encrypted_hello.size() <= client_hello.size()) {
            // ECH failed (returned unmodified)
            attempt.result = ECHResult::CONFIG_INVALID;
            attempt.error_message = "ECH encryption failed";
        } else {
            // ECH applied successfully
            attempt.result = ECHResult::SUCCESS;
        }

        auto end = std::chrono::steady_clock::now();
        attempt.latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        return attempt.result;
    }

    void store_attempt(const ECHAttempt& attempt) {
        std::lock_guard<std::mutex> lock(mutex);
        last_attempt = attempt;
        history[attempt.domain].push_back(attempt);

        // Limit history size per domain
        if (history[attempt.domain].size() > 10) {
            history[attempt.domain].erase(history[attempt.domain].begin());
        }

        if (callback) {
            callback(attempt);
        }
    }
};

ECHConnectionManager::ECHConnectionManager() : impl_(std::make_unique<Impl>()) {}
ECHConnectionManager::ECHConnectionManager(const RetryPolicy& policy)
    : impl_(std::make_unique<Impl>(policy)) {}
ECHConnectionManager::~ECHConnectionManager() = default;

ECHResult ECHConnectionManager::connect_with_ech(
    const std::string& domain,
    const std::vector<uint8_t>& client_hello,
    std::vector<uint8_t>& encrypted_hello
) {
    ECHConfig config;
    bool config_found = false;

    // Try 1: Check cache
    if (impl_->cache_enabled && impl_->cache) {
        auto cached = impl_->cache->get(domain);
        if (cached.has_value()) {
            config = cached.value();
            config_found = true;

            ECHAttempt attempt;
            attempt.used_cache = true;
            auto result = impl_->attempt_connection(domain, client_hello, config, encrypted_hello, attempt);
            impl_->store_attempt(attempt);

            if (result == ECHResult::SUCCESS) {
                return ECHResult::SUCCESS;
            }

            // Cache entry invalid - invalidate and continue
            impl_->cache->invalidate(domain);
        }
    }

    // Try 2: Fetch from DoH
    ECHConfigFetcher fetcher;
    if (fetcher.fetch_ech_config(domain, config)) {
        config_found = true;

        ECHAttempt attempt;
        auto result = impl_->attempt_connection(domain, client_hello, config, encrypted_hello, attempt);
        impl_->store_attempt(attempt);

        if (result == ECHResult::SUCCESS) {
            // Cache successful config
            if (impl_->cache_enabled && impl_->cache) {
                impl_->cache->put(domain, config);
            }
            return ECHResult::SUCCESS;
        }
    }

    // Try 3: Retry with backoff
    for (uint32_t retry = 0; retry < impl_->policy.max_retries; ++retry) {
        // Calculate delay
        
        // Calculate delay with explicit duration_cast to resolve std::min ambiguity
        auto delay_raw = impl_->policy.initial_delay * static_cast<double>(std::pow(impl_->policy.backoff_multiplier, retry));
        auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(delay_raw);
        delay = std::min(delay, impl_->policy.max_delay);

        delay = std::min(delay, impl_->policy.max_delay);

        std::this_thread::sleep_for(delay);

        // Retry fetch
        if (fetcher.fetch_ech_config(domain, config)) {
            ECHAttempt attempt;
            auto result = impl_->attempt_connection(domain, client_hello, config, encrypted_hello, attempt);
            impl_->store_attempt(attempt);

            if (result == ECHResult::SUCCESS) {
                if (impl_->cache_enabled && impl_->cache) {
                    impl_->cache->put(domain, config);
                }
                return ECHResult::SUCCESS;
            }
        }
    }

    // Try 4: GREASE (if enabled)
    if (impl_->policy.enable_grease) {
        // Send GREASE ECH extension (random values)
        // This helps with ecosystem deployment
        ECHAttempt attempt;
        attempt.domain = domain;
        attempt.result = ECHResult::GREASE_ACCEPTED;
        attempt.error_message = "No ECHConfig available, sent GREASE";
        impl_->store_attempt(attempt);

        // Return unmodified for GREASE
        encrypted_hello = client_hello;
        return ECHResult::GREASE_ACCEPTED;
    }

    // Try 5: Plaintext fallback
    if (impl_->policy.fallback_to_plaintext) {
        ECHAttempt attempt;
        attempt.domain = domain;
        attempt.result = ECHResult::FALLBACK_PLAINTEXT;
        attempt.error_message = "ECH unavailable, using plaintext";
        impl_->store_attempt(attempt);

        encrypted_hello = client_hello;
        return ECHResult::FALLBACK_PLAINTEXT;
    }

    // All attempts failed
    ECHAttempt attempt;
    attempt.domain = domain;
    attempt.result = ECHResult::NETWORK_ERROR;
    attempt.error_message = "All ECH attempts failed";
    impl_->store_attempt(attempt);

    return ECHResult::NETWORK_ERROR;
}

void ECHConnectionManager::handle_retry_configs(
    const std::string& domain,
    const std::vector<ECHConfig>& retry_configs
) {
    if (retry_configs.empty() || !impl_->cache_enabled || !impl_->cache) {
        return;
    }

    // Invalidate old config
    impl_->cache->invalidate(domain);

    // Cache new configs (use first one)
    impl_->cache->put(domain, retry_configs[0]);

    ECHAttempt attempt;
    attempt.domain = domain;
    attempt.result = ECHResult::RETRY_REQUIRED;
    attempt.retry_configs = retry_configs;
    attempt.error_message = "Server provided retry_configs";
    impl_->store_attempt(attempt);
}

void ECHConnectionManager::set_attempt_callback(ECHAttemptCallback callback) {
    impl_->callback = std::move(callback);
}

std::optional<ECHAttempt> ECHConnectionManager::get_last_attempt() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->last_attempt;
}

std::vector<ECHAttempt> ECHConnectionManager::get_attempt_history(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto it = impl_->history.find(domain);
    if (it != impl_->history.end()) {
        return it->second;
    }
    return {};
}

void ECHConnectionManager::clear_history() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->history.clear();
    impl_->last_attempt = std::nullopt;
}

void ECHConnectionManager::set_cache_enabled(bool enabled) {
    impl_->cache_enabled = enabled;
}

void ECHConnectionManager::set_cache(std::shared_ptr<ECHConfigCache> cache) {
    impl_->cache = cache;
}

// Convenience function
std::vector<uint8_t> connect_with_retry(
    const std::string& domain,
    const std::vector<uint8_t>& client_hello
) {
    ECHConnectionManager manager;
    std::vector<uint8_t> result;
    manager.connect_with_ech(domain, client_hello, result);
    return result;
}

} // namespace ECH
} // namespace DPI
} // namespace ncp
