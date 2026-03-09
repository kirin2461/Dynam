// ══════════════════════════════════════════════════════════════════════════════
// tests/test_security_classes.cpp
// Tests for security classes (ncp_security.hpp):
//   CertificatePinner, LatencyMonitor, TrafficPadder, ForensicLogger,
//   CanaryTokens, MonitoringDetector, SecurityManager
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_security.hpp"

#include <string>
#include <vector>
#include <chrono>
#include <thread>

using namespace ncp;

// ══════════════════════════════════════════════════════════════════════════════
// CertificatePinner
// ══════════════════════════════════════════════════════════════════════════════

class CertificatePinnerTest : public ::testing::Test {
protected:
    CertificatePinner pinner;
};

TEST_F(CertificatePinnerTest, AddPin_And_Verify_Match) {
    pinner.add_pin("example.com", "abc123hash");
    EXPECT_TRUE(pinner.verify_certificate("example.com", "abc123hash"));
}

TEST_F(CertificatePinnerTest, Verify_Mismatch_ReturnsFalse) {
    pinner.add_pin("example.com", "correct_hash");
    EXPECT_FALSE(pinner.verify_certificate("example.com", "wrong_hash"));
}

TEST_F(CertificatePinnerTest, Verify_NoPins_ReturnsFalse) {
    EXPECT_FALSE(pinner.verify_certificate("unknown.com", "any_hash"));
}

TEST_F(CertificatePinnerTest, AddPin_BackupPin) {
    pinner.add_pin("example.com", "primary_hash", false);
    pinner.add_pin("example.com", "backup_hash",  true);
    EXPECT_TRUE(pinner.verify_certificate("example.com", "primary_hash"));
    EXPECT_TRUE(pinner.verify_certificate("example.com", "backup_hash"));
    EXPECT_FALSE(pinner.verify_certificate("example.com", "wrong_hash"));
}

TEST_F(CertificatePinnerTest, AddPins_BulkAdd) {
    std::vector<CertificatePinner::PinnedCert> pins;
    CertificatePinner::PinnedCert p;
    p.hostname    = "bulk.com";
    p.sha256_hash = "bulk_hash_1";
    p.is_backup   = false;
    pins.push_back(p);
    pinner.add_pins(pins);
    EXPECT_TRUE(pinner.verify_certificate("bulk.com", "bulk_hash_1"));
}

TEST_F(CertificatePinnerTest, TrustOnFirstUse_AddsPin) {
    bool added = pinner.trust_on_first_use("new.com", "hash_abc");
    EXPECT_TRUE(added);
    EXPECT_TRUE(pinner.verify_certificate("new.com", "hash_abc"));
}

TEST_F(CertificatePinnerTest, TrustOnFirstUse_SecondCallReturnsFalse) {
    pinner.trust_on_first_use("tofu.com", "h1");
    bool second = pinner.trust_on_first_use("tofu.com", "h2");
    EXPECT_FALSE(second); // pin already exists
}

TEST_F(CertificatePinnerTest, GetPins_ReturnsPinsForHostname) {
    pinner.add_pin("a.com", "hash_a");
    auto pins = pinner.get_pins("a.com");
    EXPECT_EQ(pins.size(), 1u);
    EXPECT_EQ(pins[0].sha256_hash, "hash_a");
}

TEST_F(CertificatePinnerTest, ClearPins_RemovesAll) {
    pinner.add_pin("b.com", "hash_b");
    pinner.clear_pins();
    EXPECT_FALSE(pinner.verify_certificate("b.com", "hash_b"));
}

TEST_F(CertificatePinnerTest, LoadDefaultPins_NoThrow) {
    EXPECT_NO_THROW(pinner.load_default_pins());
}

TEST_F(CertificatePinnerTest, MismatchCallback_Invoked) {
    bool called = false;
    pinner.set_mismatch_callback([&](const CertificatePinner::PinMismatchReport& r) {
        called = true;
        EXPECT_EQ(r.hostname, "cb.com");
    });
    pinner.add_pin("cb.com", "correct");
    pinner.verify_certificate("cb.com", "wrong"); // triggers mismatch
    EXPECT_TRUE(called);
}

// ══════════════════════════════════════════════════════════════════════════════
// LatencyMonitor
// ══════════════════════════════════════════════════════════════════════════════

class LatencyMonitorTest : public ::testing::Test {
protected:
    LatencyMonitor monitor{500}; // 500ms threshold
};

TEST_F(LatencyMonitorTest, RecordLatency_NoThrow) {
    EXPECT_NO_THROW(monitor.record_latency("cloudflare", 30));
}

TEST_F(LatencyMonitorTest, GetStats_AfterRecording) {
    monitor.record_latency("cloudflare", 10);
    monitor.record_latency("cloudflare", 20);
    monitor.record_latency("cloudflare", 30);
    auto stats = monitor.get_latency_stats("cloudflare");
    EXPECT_EQ(stats.min_ms, 10u);
    EXPECT_EQ(stats.max_ms, 30u);
    EXPECT_GE(stats.sample_count, 3u);
}

TEST_F(LatencyMonitorTest, GetThreshold) {
    EXPECT_EQ(monitor.get_threshold(), 500u);
}

TEST_F(LatencyMonitorTest, SetThreshold) {
    monitor.set_threshold(1000);
    EXPECT_EQ(monitor.get_threshold(), 1000u);
}

TEST_F(LatencyMonitorTest, IsAnomalous_HighLatency) {
    monitor.set_threshold(100);
    EXPECT_TRUE(monitor.is_anomalous("test", 500));
}

TEST_F(LatencyMonitorTest, IsAnomalous_LowLatency) {
    monitor.set_threshold(100);
    EXPECT_FALSE(monitor.is_anomalous("test", 50));
}

TEST_F(LatencyMonitorTest, AlertCallback_InvokedOnHighLatency) {
    bool called = false;
    monitor.set_alert_callback([&](const LatencyMonitor::LatencyAlert& a) {
        called = true;
        EXPECT_GT(a.latency_ms, a.threshold_ms);
    });
    monitor.record_latency("prov", 9999); // far above 500ms threshold
    EXPECT_TRUE(called);
}

TEST_F(LatencyMonitorTest, GetMonitoredProviders_AfterRecording) {
    monitor.record_latency("cloudflare", 10);
    monitor.record_latency("google",     20);
    auto providers = monitor.get_monitored_providers();
    EXPECT_GE(providers.size(), 2u);
}

TEST_F(LatencyMonitorTest, ClearHistory_NoThrow) {
    monitor.record_latency("p", 100);
    EXPECT_NO_THROW(monitor.clear_history());
}

// ══════════════════════════════════════════════════════════════════════════════
// TrafficPadder
// ══════════════════════════════════════════════════════════════════════════════

class TrafficPadderTest : public ::testing::Test {
protected:
    TrafficPadder padder{64, 256};
};

TEST_F(TrafficPadderTest, AddPadding_OutputLargerOrEqualToInput) {
    std::vector<uint8_t> data(50, 0xAA);
    auto padded = padder.add_padding(data);
    EXPECT_GE(padded.size(), 64u);
}

TEST_F(TrafficPadderTest, RemovePadding_RestoresOriginal) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto padded   = padder.add_padding(data);
    auto restored = padder.remove_padding(padded);
    EXPECT_EQ(restored, data);
}

TEST_F(TrafficPadderTest, Roundtrip_LargeData) {
    std::vector<uint8_t> data(512, 0xFF);
    auto padded   = padder.add_padding(data);
    auto restored = padder.remove_padding(padded);
    EXPECT_EQ(restored, data);
}

TEST_F(TrafficPadderTest, PaddedSize_WithinConfiguredRange) {
    std::vector<uint8_t> data(10, 0x01);
    auto padded = padder.add_padding(data);
    EXPECT_GE(padded.size(), 64u);  // min_size
}

TEST_F(TrafficPadderTest, GetMinMax) {
    EXPECT_EQ(padder.get_min_size(), 64u);
    EXPECT_EQ(padder.get_max_size(), 256u);
}

TEST_F(TrafficPadderTest, SetPaddingRange) {
    padder.set_padding_range(128, 512);
    EXPECT_EQ(padder.get_min_size(), 128u);
    EXPECT_EQ(padder.get_max_size(), 512u);
}

// ══════════════════════════════════════════════════════════════════════════════
// ForensicLogger
// ══════════════════════════════════════════════════════════════════════════════

class ForensicLoggerTest : public ::testing::Test {
protected:
    ForensicLogger logger;
};

TEST_F(ForensicLoggerTest, DefaultEnabled) {
    EXPECT_TRUE(logger.is_enabled());
}

TEST_F(ForensicLoggerTest, SetEnabled_Disable) {
    logger.set_enabled(false);
    EXPECT_FALSE(logger.is_enabled());
}

TEST_F(ForensicLoggerTest, Log_NoThrow) {
    EXPECT_NO_THROW(logger.log(
        ForensicLogger::EventType::INFO, "test", "test message"));
}

TEST_F(ForensicLoggerTest, LogDnsQuery_NoThrow) {
    EXPECT_NO_THROW(logger.log_dns_query("example.com", "cloudflare"));
}

TEST_F(ForensicLoggerTest, LogDnsResponse_NoThrow) {
    EXPECT_NO_THROW(logger.log_dns_response("example.com", 30, true));
}

TEST_F(ForensicLoggerTest, LogCertVerification_NoThrow) {
    EXPECT_NO_THROW(logger.log_cert_verification("example.com", true));
}

TEST_F(ForensicLoggerTest, LogError_NoThrow) {
    EXPECT_NO_THROW(logger.log_error("source", "some error"));
}

TEST_F(ForensicLoggerTest, GetRecentEntries_AfterLog) {
    logger.log(ForensicLogger::EventType::INFO, "src", "msg1");
    logger.log(ForensicLogger::EventType::WARNING, "src", "msg2");
    auto entries = logger.get_recent_entries(10);
    EXPECT_GE(entries.size(), 2u);
}

TEST_F(ForensicLoggerTest, GetRecentEntries_LimitHonored) {
    for (int i = 0; i < 20; ++i) {
        logger.log(ForensicLogger::EventType::INFO, "s", "msg");
    }
    auto entries = logger.get_recent_entries(5);
    EXPECT_LE(entries.size(), 5u);
}

TEST_F(ForensicLoggerTest, Flush_NoThrow) {
    EXPECT_NO_THROW(logger.flush());
}

// ══════════════════════════════════════════════════════════════════════════════
// CanaryTokens
// ══════════════════════════════════════════════════════════════════════════════

class CanaryTokensTest : public ::testing::Test {
protected:
    CanaryTokens canary;
};

TEST_F(CanaryTokensTest, AddCanary_And_GetDomains) {
    canary.add_canary("canary1.example.com", "expected_ip");
    auto domains = canary.get_canary_domains();
    EXPECT_EQ(domains.size(), 1u);
    EXPECT_EQ(domains[0], "canary1.example.com");
}

TEST_F(CanaryTokensTest, RemoveCanary) {
    canary.add_canary("c.example.com", "resp");
    canary.remove_canary("c.example.com");
    EXPECT_TRUE(canary.get_canary_domains().empty());
}

TEST_F(CanaryTokensTest, CheckCanary_NotTriggered) {
    canary.add_canary("safe.example.com", "expected");
    auto result = canary.check_canary("safe.example.com", "expected");
    EXPECT_FALSE(result.triggered);
}

TEST_F(CanaryTokensTest, CheckCanary_Triggered) {
    canary.add_canary("intercepted.example.com", "expected");
    auto result = canary.check_canary("intercepted.example.com", "different");
    EXPECT_TRUE(result.triggered);
}

TEST_F(CanaryTokensTest, TriggerCallback_Invoked) {
    bool called = false;
    canary.set_trigger_callback([&](const CanaryTokens::CanaryResult&) {
        called = true;
    });
    canary.add_canary("trigger.example.com", "expected");
    canary.check_canary("trigger.example.com", "wrong_response");
    EXPECT_TRUE(called);
}

TEST_F(CanaryTokensTest, ClearCanaries) {
    canary.add_canary("a.com", "r");
    canary.add_canary("b.com", "r");
    canary.clear_canaries();
    EXPECT_TRUE(canary.get_canary_domains().empty());
}

// ══════════════════════════════════════════════════════════════════════════════
// MonitoringDetector
// ══════════════════════════════════════════════════════════════════════════════

class MonitoringDetectorTest : public ::testing::Test {
protected:
    MonitoringDetector detector;
};

TEST_F(MonitoringDetectorTest, IsNetworkMonitored_ReturnsBool) {
    bool result = detector.is_network_monitored();
    (void)result; // may be false in test env
}

TEST_F(MonitoringDetectorTest, IsDebuggerPresent_ReturnsBool) {
    bool result = detector.is_debugger_present();
    (void)result;
}

TEST_F(MonitoringDetectorTest, IsRunningInVM_ReturnsBool) {
    bool result = detector.is_running_in_vm();
    (void)result;
}

TEST_F(MonitoringDetectorTest, ScanThreats_NoThrow) {
    EXPECT_NO_THROW(detector.scan_threats());
}

TEST_F(MonitoringDetectorTest, ScanThreats_StructHasFields) {
    auto info = detector.scan_threats();
    // In normal test env, should not detect debugger/sandbox
    (void)info.debugger_detected;
    (void)info.vm_detected;
    (void)info.sandbox_detected;
}

// ══════════════════════════════════════════════════════════════════════════════
// SecurityManager
// ══════════════════════════════════════════════════════════════════════════════

class SecurityManagerTest : public ::testing::Test {};

TEST_F(SecurityManagerTest, DefaultConstructor_NoThrow) {
    EXPECT_NO_THROW({ SecurityManager sm; });
}

TEST_F(SecurityManagerTest, ConfigConstructor_NoThrow) {
    SecurityManager::Config cfg;
    cfg.enable_certificate_pinning = true;
    cfg.enable_latency_monitoring  = true;
    cfg.enable_traffic_padding     = true;
    EXPECT_NO_THROW({ SecurityManager sm(cfg); });
}

TEST_F(SecurityManagerTest, Configure_NoThrow) {
    SecurityManager sm;
    SecurityManager::Config cfg;
    cfg.latency_threshold_ms = 1000;
    EXPECT_NO_THROW(sm.configure(cfg));
}

TEST_F(SecurityManagerTest, GetConfig_ReturnsSet) {
    SecurityManager sm;
    SecurityManager::Config cfg;
    cfg.latency_threshold_ms = 750;
    sm.configure(cfg);
    EXPECT_EQ(sm.get_config().latency_threshold_ms, 750u);
}

TEST_F(SecurityManagerTest, CertPinner_AccessorWorks) {
    SecurityManager sm;
    auto& pinner = sm.certificate_pinner();
    pinner.add_pin("sm.com", "hash");
    EXPECT_TRUE(sm.certificate_pinner().verify_certificate("sm.com", "hash"));
}

TEST_F(SecurityManagerTest, LatencyMonitor_AccessorWorks) {
    SecurityManager sm;
    EXPECT_NO_THROW(sm.latency_monitor().record_latency("test", 50));
}

TEST_F(SecurityManagerTest, TrafficPadder_AccessorRoundtrip) {
    SecurityManager sm;
    std::vector<uint8_t> data = {10, 20, 30};
    auto padded   = sm.traffic_padder().add_padding(data);
    auto restored = sm.traffic_padder().remove_padding(padded);
    EXPECT_EQ(restored, data);
}

TEST_F(SecurityManagerTest, ForensicLogger_AccessorWorks) {
    SecurityManager sm;
    EXPECT_NO_THROW(sm.forensic_logger().log_info("sm", "test"));
}

TEST_F(SecurityManagerTest, CanaryTokens_AccessorWorks) {
    SecurityManager sm;
    sm.canary_tokens().add_canary("test.com", "expected");
    EXPECT_EQ(sm.canary_tokens().get_canary_domains().size(), 1u);
}
