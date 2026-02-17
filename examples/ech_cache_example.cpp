/**
 * @file ech_cache_example.cpp
 * @brief Example: Using ECH cache and retry mechanism
 */

#include <iostream>
#include <iomanip>
#include "../src/core/include/ncp_ech.hpp"
#include "../src/core/include/ncp_ech_cache.hpp"
#include "../src/core/include/ncp_ech_retry.hpp"

using namespace ncp::DPI::ECH;

int main() {
    std::cout << "=== ECH Cache & Retry Example ===\n\n";

    // Configure cache
    CacheConfig cache_config;
    cache_config.max_entries = 50;
    cache_config.default_ttl = std::chrono::seconds(3600);
    cache_config.enable_disk_cache = true;
    cache_config.disk_cache_path = "./ech_cache.dat";
    cache_config.auto_refresh = true;

    GlobalECHCache::configure(cache_config);
    auto& cache = GlobalECHCache::instance();

    std::cout << "1. Cache configured\n";
    std::cout << "   - Max entries: " << cache_config.max_entries << "\n";
    std::cout << "   - TTL: " << cache_config.default_ttl.count() << "s\n";
    std::cout << "   - Disk cache: " << (cache_config.enable_disk_cache ? "enabled" : "disabled") << "\n\n";

    // Configure retry policy
    RetryPolicy retry_policy;
    retry_policy.max_retries = 3;
    retry_policy.initial_delay = std::chrono::milliseconds(100);
    retry_policy.enable_grease = true;
    retry_policy.fallback_to_plaintext = true;

    ECHConnectionManager manager(retry_policy);

    std::cout << "2. Retry policy configured\n";
    std::cout << "   - Max retries: " << retry_policy.max_retries << "\n";
    std::cout << "   - Initial delay: " << retry_policy.initial_delay.count() << "ms\n";
    std::cout << "   - GREASE enabled: " << (retry_policy.enable_grease ? "yes" : "no") << "\n\n";

    // Set monitoring callback
    manager.set_attempt_callback([](const ECHAttempt& attempt) {
        std::cout << "   [Attempt] " << attempt.domain;
        std::cout << " - Result: ";
        switch (attempt.result) {
            case ECHResult::SUCCESS:
                std::cout << "SUCCESS";
                break;
            case ECHResult::RETRY_REQUIRED:
                std::cout << "RETRY_REQUIRED";
                break;
            case ECHResult::GREASE_ACCEPTED:
                std::cout << "GREASE_ACCEPTED";
                break;
            case ECHResult::FALLBACK_PLAINTEXT:
                std::cout << "FALLBACK_PLAINTEXT";
                break;
            case ECHResult::CONFIG_INVALID:
                std::cout << "CONFIG_INVALID";
                break;
            case ECHResult::NETWORK_ERROR:
                std::cout << "NETWORK_ERROR";
                break;
        }
        std::cout << " (" << attempt.latency.count() << "ms)";
        if (attempt.used_cache) {
            std::cout << " [CACHED]";
        }
        std::cout << "\n";
    });

    // Test domains
    std::vector<std::string> domains = {
        "cloudflare.com",
        "crypto.cloudflare.com",
        "defo.ie",
        "example.com"
    };

    std::cout << "3. Testing ECH connections with retry...\n\n";

    std::vector<uint8_t> client_hello(64, 0x01);  // Dummy ClientHello

    for (const auto& domain : domains) {
        std::cout << "   Connecting to " << domain << "...\n";

        std::vector<uint8_t> encrypted;
        auto result = manager.connect_with_ech(domain, client_hello, encrypted);

        if (result == ECHResult::SUCCESS) {
            std::cout << "   ✓ ECH encryption successful\n";
        } else if (result == ECHResult::GREASE_ACCEPTED) {
            std::cout << "   ~ GREASE sent (ECH not supported)\n";
        } else if (result == ECHResult::FALLBACK_PLAINTEXT) {
            std::cout << "   ! Fallback to plaintext\n";
        }
        std::cout << "\n";
    }

    // Display cache statistics
    auto stats = cache.get_stats();
    std::cout << "4. Cache Statistics:\n";
    std::cout << "   - Total hits: " << stats.hits << "\n";
    std::cout << "   - Total misses: " << stats.misses << "\n";
    std::cout << "   - Hit rate: " << std::fixed << std::setprecision(2)
              << (stats.hit_rate() * 100) << "%\n";
    std::cout << "   - Evictions: " << stats.evictions << "\n";
    std::cout << "   - Expirations: " << stats.expirations << "\n";
    std::cout << "   - Current size: " << stats.current_size << "\n\n";

    // Save cache to disk
    if (cache.save_to_disk()) {
        std::cout << "5. Cache saved to disk\n\n";
    }

    // Cleanup expired entries
    size_t cleaned = cache.cleanup_expired();
    std::cout << "6. Cleaned up " << cleaned << " expired entries\n\n";

    std::cout << "=== Example Complete ===\n";
    return 0;
}
