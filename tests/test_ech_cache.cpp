/**
 * @file test_ech_cache.cpp
 * @brief Unit tests for ECH cache and retry mechanism
 */

#include <gtest/gtest.h>
#include "../src/core/include/ncp_ech_cache.hpp"
#include "../src/core/include/ncp_ech_retry.hpp"
#include <atomic>
#include <thread>
#include <chrono>

using namespace ncp::DPI::ECH;

class ECHCacheTest : public ::testing::Test {
protected:
    ECHConfigCache cache;

    ECHConfig create_test_config(const std::string& domain) {
        ECHConfig config;
        config.public_name = domain;
        config.config_id = 1;
        config.public_key = {0x01, 0x02, 0x03, 0x04};
        return config;
    }
};

// Test 1: Basic put and get
TEST_F(ECHCacheTest, BasicPutGet) {
    auto config = create_test_config("example.com");
    cache.put("example.com", config);

    auto retrieved = cache.get("example.com");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->public_name, "example.com");
    EXPECT_EQ(retrieved->config_id, 1);
}

// Test 2: Cache miss
TEST_F(ECHCacheTest, CacheMiss) {
    auto result = cache.get("nonexistent.com");
    EXPECT_FALSE(result.has_value());
}

// Test 3: TTL expiration
TEST_F(ECHCacheTest, TTLExpiration) {
    auto config = create_test_config("expiring.com");
    cache.put("expiring.com", config, std::chrono::seconds(1));

    // Should be available immediately
    auto result1 = cache.get("expiring.com");
    EXPECT_TRUE(result1.has_value());

    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Should be expired
    auto result2 = cache.get("expiring.com");
    EXPECT_FALSE(result2.has_value());
}

// Test 4: LRU eviction
TEST_F(ECHCacheTest, LRUEviction) {
    CacheConfig config;
    config.max_entries = 3;
    ECHConfigCache small_cache(config);

    small_cache.put("domain1.com", create_test_config("domain1.com"));
    small_cache.put("domain2.com", create_test_config("domain2.com"));
    small_cache.put("domain3.com", create_test_config("domain3.com"));

    // All should be present
    EXPECT_TRUE(small_cache.get("domain1.com").has_value());
    EXPECT_TRUE(small_cache.get("domain2.com").has_value());
    EXPECT_TRUE(small_cache.get("domain3.com").has_value());

    // Add 4th entry - should evict LRU (domain1)
    small_cache.put("domain4.com", create_test_config("domain4.com"));

    EXPECT_FALSE(small_cache.get("domain1.com").has_value());
    EXPECT_TRUE(small_cache.get("domain4.com").has_value());
}

// Test 5: Cache statistics
TEST_F(ECHCacheTest, CacheStatistics) {
    cache.put("test.com", create_test_config("test.com"));

    cache.get("test.com");  // Hit
    cache.get("test.com");  // Hit
    cache.get("missing.com");  // Miss

    auto stats = cache.get_stats();
    EXPECT_EQ(stats.hits, 2);
    EXPECT_EQ(stats.misses, 1);
    EXPECT_NEAR(stats.hit_rate(), 0.666, 0.01);
}

// Test 6: Invalidation
TEST_F(ECHCacheTest, Invalidation) {
    cache.put("remove.com", create_test_config("remove.com"));
    EXPECT_TRUE(cache.get("remove.com").has_value());

    cache.invalidate("remove.com");
    EXPECT_FALSE(cache.get("remove.com").has_value());
}

// Test 7: Clear cache
TEST_F(ECHCacheTest, ClearCache) {
    cache.put("domain1.com", create_test_config("domain1.com"));
    cache.put("domain2.com", create_test_config("domain2.com"));

    cache.clear();

    EXPECT_FALSE(cache.get("domain1.com").has_value());
    EXPECT_FALSE(cache.get("domain2.com").has_value());
    EXPECT_EQ(cache.get_stats().current_size, 0);
}

// Test 8: Needs refresh
TEST_F(ECHCacheTest, NeedsRefresh) {
    CacheConfig config;
    config.auto_refresh = true;
    config.default_ttl = std::chrono::seconds(10);
    config.refresh_threshold = std::chrono::seconds(8);
    ECHConfigCache refresh_cache(config);

    refresh_cache.put("refresh.com", create_test_config("refresh.com"));

    // Should not need refresh immediately
    EXPECT_FALSE(refresh_cache.needs_refresh("refresh.com"));

    // Wait until close to expiry
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Should need refresh now
    EXPECT_TRUE(refresh_cache.needs_refresh("refresh.com"));
}

// Test 9: Disk persistence
TEST_F(ECHCacheTest, DiskPersistence) {
    CacheConfig config;
    config.enable_disk_cache = true;
    config.disk_cache_path = "./test_ech_cache.dat";

    {
        ECHConfigCache disk_cache(config);
        disk_cache.put("persistent.com", create_test_config("persistent.com"));
        disk_cache.save_to_disk();
    }

    // Load in new cache instance
    {
        ECHConfigCache disk_cache(config);
        size_t loaded = disk_cache.load_from_disk();
        EXPECT_GT(loaded, 0);

        auto result = disk_cache.get("persistent.com");
        EXPECT_TRUE(result.has_value());
    }

    // Cleanup
    std::remove("./test_ech_cache.dat");
}

// Test 10: ECH retry mechanism (deterministic, no network)
//
// Previously this test called connect_with_ech() on a real domain, which
// performs live DoH lookups (HTTPS RR + TXT fallback) on a cache miss.
// Those lookups can stall for minutes on network-restricted runners, so
// the test wrapped the call in a watchdog thread that was DETACHED on
// stall — the detached worker then kept running past the end of the
// process, touching torn-down statics (observed: std::bad_alloc abort;
// the CMake ordering note "keep the ECH files last" only papered over
// it). It also wrote to stack locals of the already-exited test body.
//
// The fetch path is now injected via set_config_fetch_override(), so the
// retry/backoff/fallback logic is exercised with zero network access,
// no watchdog, and no detached thread.
TEST_F(ECHCacheTest, ECHRetryMechanism) {
    RetryPolicy policy;
    policy.max_retries = 1;  // bound the backoff loop
    policy.initial_delay = std::chrono::milliseconds(1);
    policy.max_delay = std::chrono::milliseconds(10);
    ECHConnectionManager manager(policy);

    // Fetch override that always fails fast — no DoH, no sockets.
    int fetch_calls = 0;
    manager.set_config_fetch_override(
        [&fetch_calls](const std::string&, ECHConfig&) -> bool {
            ++fetch_calls;
            return false;
        });

    const std::string domain = "nonexistent.invalid";
    std::vector<uint8_t> client_hello = {0x16, 0x03, 0x03, 0x00, 0x10};
    std::vector<uint8_t> encrypted;

    ECHResult result = manager.connect_with_ech(domain, client_hello, encrypted);

    // With GREASE enabled (default policy) the manager must fall back to
    // GREASE once the initial fetch and the bounded retry both fail.
    EXPECT_EQ(result, ECHResult::GREASE_ACCEPTED);
    // Initial fetch + max_retries retry fetches.
    EXPECT_EQ(fetch_calls, 1 + static_cast<int>(policy.max_retries));

    // Check history
    auto last = manager.get_last_attempt();
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ(last->result, ECHResult::GREASE_ACCEPTED);
    EXPECT_EQ(last->domain, domain);
}

// Test 11: retry loop actually retries and succeeds (deterministic)
TEST_F(ECHCacheTest, ECHRetrySucceedsAfterTransientFetchFailure) {
    RetryPolicy policy;
    policy.max_retries = 3;
    policy.initial_delay = std::chrono::milliseconds(1);
    policy.max_delay = std::chrono::milliseconds(10);
    ECHConnectionManager manager(policy);

    // Fail the first two fetches, succeed on the third (the 2nd retry)
    // with a fully valid config so attempt_connection() applies ECH.
    int fetch_calls = 0;
    manager.set_config_fetch_override(
        [&fetch_calls](const std::string& domain, ECHConfig& cfg) -> bool {
            ++fetch_calls;
            if (fetch_calls < 3) return false;
            std::vector<uint8_t> private_key;
            cfg = create_test_ech_config(domain, HPKECipherSuite(), private_key);
            return true;
        });

    const std::string domain = "retry-success.example";
    // Minimal well-formed ClientHello: record header + handshake header +
    // version + random + empty session id + cipher suites + compression +
    // empty extensions block (required by apply_ech()'s parser).
    std::vector<uint8_t> client_hello = {
        0x16, 0x03, 0x03, 0x00, 0x40,  // TLS record header
        0x01, 0x00, 0x00, 0x3c,        // Handshake: ClientHello
        0x03, 0x03,                    // Version
    };
    for (int i = 0; i < 32; i++)
        client_hello.push_back(static_cast<uint8_t>(i));  // random
    client_hello.push_back(0x00);        // session id length
    client_hello.push_back(0x00);        // cipher suites length (2)
    client_hello.push_back(0x02);
    client_hello.push_back(0x13);        // TLS_AES_128_GCM_SHA256
    client_hello.push_back(0x01);
    client_hello.push_back(0x01);        // compression methods length
    client_hello.push_back(0x00);        // null compression
    client_hello.push_back(0x00);        // extensions length (0)
    client_hello.push_back(0x00);
    std::vector<uint8_t> encrypted;

    ECHResult result = manager.connect_with_ech(domain, client_hello, encrypted);

    EXPECT_EQ(result, ECHResult::SUCCESS);
    EXPECT_EQ(fetch_calls, 3);
    EXPECT_GT(encrypted.size(), client_hello.size());
    // Successful config is cached for subsequent connections.
    ASSERT_TRUE(manager.get_last_attempt().has_value());
    EXPECT_EQ(manager.get_last_attempt()->result, ECHResult::SUCCESS);
}

// main() is provided by gtest_main via the ncp_tests target.
