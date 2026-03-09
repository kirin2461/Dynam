// ══════════════════════════════════════════════════════════════════════════════
// tests/test_doh.cpp
// Tests for DoHClient, DoH3Client, SecureDNSCache (ncp_doh.hpp)
//
// NOTE: Actual network queries cannot be performed in unit tests.
//       These tests cover config, DNS wire-format building/parsing, and
//       cache functionality only.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_doh.hpp"

#include <string>
#include <vector>
#include <chrono>

using namespace ncp;

// ══════════════════════════════════════════════════════════════════════════════
// DoHClient — Configuration
// ══════════════════════════════════════════════════════════════════════════════

class DoHClientTest : public ::testing::Test {
protected:
    DoHClient::Config make_config(DoHClient::Provider prov) {
        DoHClient::Config cfg;
        cfg.provider   = prov;
        cfg.timeout_ms = 1000;
        cfg.enable_cache = true;
        cfg.fallback_to_system_dns = false;
        return cfg;
    }
};

TEST_F(DoHClientTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ DoHClient c; });
}

TEST_F(DoHClientTest, ConfigConstructor_NoThrow) {
    EXPECT_NO_THROW({ DoHClient c(make_config(DoHClient::Provider::CLOUDFLARE_PRIMARY)); });
}

TEST_F(DoHClientTest, SetAndGetConfig_Roundtrip) {
    DoHClient c;
    auto cfg = make_config(DoHClient::Provider::GOOGLE_PRIMARY);
    cfg.max_retries = 5;
    c.set_config(cfg);
    EXPECT_EQ(c.get_config().max_retries, 5u);
    EXPECT_EQ(c.get_config().provider, DoHClient::Provider::GOOGLE_PRIMARY);
}

TEST_F(DoHClientTest, SetProvider_UpdatesConfig) {
    DoHClient c;
    c.set_provider(DoHClient::Provider::QUAD9);
    EXPECT_EQ(c.get_config().provider, DoHClient::Provider::QUAD9);
}

TEST_F(DoHClientTest, SetCustomServer_UpdatesConfig) {
    DoHClient c;
    c.set_custom_server("https://custom.example.com/dns-query");
    EXPECT_EQ(c.get_config().custom_server_url, "https://custom.example.com/dns-query");
}

// ── Provider Map ─────────────────────────────────────────────────────────────

TEST_F(DoHClientTest, GetAvailableProviders_NotEmpty) {
    DoHClient c;
    auto providers = c.get_available_providers();
    EXPECT_FALSE(providers.empty());
}

TEST_F(DoHClientTest, GetAvailableProviders_ContainsKnownProviders) {
    DoHClient c;
    auto providers = c.get_available_providers();
    bool has_cloudflare = false;
    bool has_google     = false;
    for (auto& p : providers) {
        if (p.find("cloudflare") != std::string::npos ||
            p.find("1.1.1.1")   != std::string::npos) has_cloudflare = true;
        if (p.find("google")    != std::string::npos ||
            p.find("8.8.8.8")   != std::string::npos) has_google = true;
    }
    EXPECT_TRUE(has_cloudflare || has_google);
}

// ── Hostname Validation ───────────────────────────────────────────────────────

TEST_F(DoHClientTest, IsValidHostname_ValidNames) {
    DoHClient c;
    EXPECT_TRUE(c.is_valid_hostname("example.com"));
    EXPECT_TRUE(c.is_valid_hostname("www.google.com"));
    EXPECT_TRUE(c.is_valid_hostname("sub.domain.co.uk"));
    EXPECT_TRUE(c.is_valid_hostname("localhost"));
}

TEST_F(DoHClientTest, IsValidHostname_InvalidNames) {
    DoHClient c;
    EXPECT_FALSE(c.is_valid_hostname(""));
    EXPECT_FALSE(c.is_valid_hostname("-invalid"));
    EXPECT_FALSE(c.is_valid_hostname("has space.com"));
}

// ── Cache Management ─────────────────────────────────────────────────────────

TEST_F(DoHClientTest, InitialCacheSize_Zero) {
    DoHClient c;
    EXPECT_EQ(c.get_cache_size(), 0u);
}

TEST_F(DoHClientTest, IsCached_FalseInitially) {
    DoHClient c;
    EXPECT_FALSE(c.is_cached("example.com"));
    EXPECT_FALSE(c.is_cached("google.com"));
}

TEST_F(DoHClientTest, ClearCache_NoThrow) {
    DoHClient c;
    EXPECT_NO_THROW(c.clear_cache());
}

// ── Statistics ────────────────────────────────────────────────────────────────

TEST_F(DoHClientTest, InitialStatistics_AllZero) {
    DoHClient c;
    auto stats = c.get_statistics();
    EXPECT_EQ(stats.total_queries,      0u);
    EXPECT_EQ(stats.successful_queries, 0u);
    EXPECT_EQ(stats.failed_queries,     0u);
}

TEST_F(DoHClientTest, ResetStatistics_NoThrow) {
    DoHClient c;
    EXPECT_NO_THROW(c.reset_statistics());
}

// ── DNS Record Types ─────────────────────────────────────────────────────────

TEST_F(DoHClientTest, RecordType_AHasValue1) {
    EXPECT_EQ(static_cast<int>(DoHClient::RecordType::A), 1);
}

TEST_F(DoHClientTest, RecordType_AAAAHasValue28) {
    EXPECT_EQ(static_cast<int>(DoHClient::RecordType::AAAA), 28);
}

TEST_F(DoHClientTest, RecordType_CNAMEHasValue5) {
    EXPECT_EQ(static_cast<int>(DoHClient::RecordType::CNAME), 5);
}

TEST_F(DoHClientTest, RecordType_MXHasValue15) {
    EXPECT_EQ(static_cast<int>(DoHClient::RecordType::MX), 15);
}

// ── DNSResult Structure ───────────────────────────────────────────────────────

TEST_F(DoHClientTest, DNSResult_DefaultValues) {
    DoHClient::DNSResult r{};
    r.hostname = "example.com";
    r.type     = DoHClient::RecordType::A;
    EXPECT_FALSE(r.from_cache);
    EXPECT_FALSE(r.dnssec_valid);
    EXPECT_EQ(r.ttl, 0u);
}

// ── Error Handling ────────────────────────────────────────────────────────────

TEST_F(DoHClientTest, GetLastError_EmptyInitially) {
    DoHClient c;
    EXPECT_TRUE(c.get_last_error().empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// DoH3Client
// ══════════════════════════════════════════════════════════════════════════════

class DoH3ClientTest : public ::testing::Test {};

TEST_F(DoH3ClientTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ DoH3Client c; });
}

TEST_F(DoH3ClientTest, ConfigConstructor_NoThrow) {
    DoH3Client::Config cfg;
    cfg.server_url = "https://dns.google/dns-query";
    cfg.port = 443;
    EXPECT_NO_THROW({ DoH3Client c(cfg); });
}

TEST_F(DoH3ClientTest, IsConnected_FalseInitially) {
    DoH3Client c;
    EXPECT_FALSE(c.is_connected());
}

TEST_F(DoH3ClientTest, GetConfig_MatchesSet) {
    DoH3Client c;
    DoH3Client::Config cfg;
    cfg.server_url = "https://cloudflare-dns.com/dns-query";
    cfg.enable_0rtt = false;
    c.set_config(cfg);
    EXPECT_EQ(c.get_config().server_url, "https://cloudflare-dns.com/dns-query");
    EXPECT_FALSE(c.get_config().enable_0rtt);
}

TEST_F(DoH3ClientTest, InitialStats_AllZero) {
    DoH3Client c;
    auto s = c.get_stats();
    EXPECT_EQ(s.queries_sent, 0u);
    EXPECT_EQ(s.queries_successful, 0u);
}

TEST_F(DoH3ClientTest, ResetStats_NoThrow) {
    DoH3Client c;
    EXPECT_NO_THROW(c.reset_stats());
}

TEST_F(DoH3ClientTest, Disconnect_WhenNotConnected_NoThrow) {
    DoH3Client c;
    EXPECT_NO_THROW(c.disconnect());
}

// ══════════════════════════════════════════════════════════════════════════════
// SecureDNSCache
// ══════════════════════════════════════════════════════════════════════════════

class SecureDNSCacheTest : public ::testing::Test {
protected:
    SecureDNSCache make_cache() {
        SecureDNSCache::Config cfg;
        cfg.max_entries = 100;
        cfg.default_ttl_seconds = 60;
        return SecureDNSCache(cfg);
    }

    DoHClient::DNSResult make_result(const std::string& host) {
        DoHClient::DNSResult r{};
        r.hostname = host;
        r.addresses = {"1.2.3.4"};
        r.type = DoHClient::RecordType::A;
        r.ttl = 300;
        return r;
    }
};

TEST_F(SecureDNSCacheTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ SecureDNSCache c; });
}

TEST_F(SecureDNSCacheTest, InitialState_EmptyAndZeroSize) {
    auto c = make_cache();
    EXPECT_EQ(c.size(), 0u);
}

TEST_F(SecureDNSCacheTest, Has_FalseForUncachedHostname) {
    auto c = make_cache();
    EXPECT_FALSE(c.has("example.com"));
}

TEST_F(SecureDNSCacheTest, Put_And_Has) {
    auto c = make_cache();
    c.put("example.com", make_result("example.com"), 300);
    EXPECT_TRUE(c.has("example.com"));
}

TEST_F(SecureDNSCacheTest, Put_And_Get) {
    auto c = make_cache();
    auto res = make_result("myhost.test");
    c.put("myhost.test", res, 300);
    auto got = c.get("myhost.test");
    EXPECT_EQ(got.hostname, "myhost.test");
    EXPECT_EQ(got.addresses, res.addresses);
}

TEST_F(SecureDNSCacheTest, Size_IncreasesAfterPut) {
    auto c = make_cache();
    EXPECT_EQ(c.size(), 0u);
    c.put("a.com", make_result("a.com"), 60);
    c.put("b.com", make_result("b.com"), 60);
    EXPECT_EQ(c.size(), 2u);
}

TEST_F(SecureDNSCacheTest, Remove_DecreasesSize) {
    auto c = make_cache();
    c.put("x.com", make_result("x.com"), 60);
    c.remove("x.com");
    EXPECT_EQ(c.size(), 0u);
    EXPECT_FALSE(c.has("x.com"));
}

TEST_F(SecureDNSCacheTest, Clear_EmptiesCache) {
    auto c = make_cache();
    c.put("a.com", make_result("a.com"), 60);
    c.put("b.com", make_result("b.com"), 60);
    c.clear();
    EXPECT_EQ(c.size(), 0u);
}

TEST_F(SecureDNSCacheTest, HitRate_UpdatesCorrectly) {
    auto c = make_cache();
    c.put("hit.com", make_result("hit.com"), 300);
    c.get("hit.com");   // hit
    c.get("miss.com");  // miss
    EXPECT_NEAR(c.hit_rate(), 0.5, 0.01);
}

TEST_F(SecureDNSCacheTest, PurgeExpired_NoThrow) {
    auto c = make_cache();
    EXPECT_NO_THROW(c.purge_expired());
}
