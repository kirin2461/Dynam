/**
 * @file test_ech_cache.cpp
 * @brief Unit tests for ECH cache and retry mechanism
 */

#include <gtest/gtest.h>
#include "../src/core/include/ncp_ech_cache.hpp"
#include "../src/core/include/ncp_ech_retry.hpp"
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

// Test 10: ECH retry mechanism
TEST_F(ECHCacheTest, ECHRetryMechanism) {
    ECHConnectionManager manager;

    std::vector<uint8_t> client_hello = {0x16, 0x03, 0x03, 0x00, 0x10};
    std::vector<uint8_t> encrypted;

    // This will likely fail (no real ECHConfig), but should not crash
    auto result = manager.connect_with_ech("nonexistent.test", client_hello, encrypted);

    // Should fallback or return error
    EXPECT_TRUE(
        result == ECHResult::FALLBACK_PLAINTEXT ||
        result == ECHResult::GREASE_ACCEPTED ||
        result == ECHResult::NETWORK_ERROR
    );

    // Check history
    auto last = manager.get_last_attempt();
    EXPECT_TRUE(last.has_value());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
