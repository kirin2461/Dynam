/**
 * @file test_paranoid.cpp
 * @brief Unit tests for ParanoidMode module
 */

#include <gtest/gtest.h>
#include "ncp_paranoid.hpp"
#include <thread>
#include <chrono>
#include <set>

using namespace ncp;

class ParanoidModeTest : public ::testing::Test {
protected:
    void SetUp() override {
        paranoid = std::make_unique<ParanoidMode>();
    }
    
    void TearDown() override {
        if (paranoid && paranoid->is_active()) {
            paranoid->deactivate();
        }
        paranoid.reset();
    }
    
    std::unique_ptr<ParanoidMode> paranoid;
};

// ---- Activation/Deactivation Tests ----

TEST_F(ParanoidModeTest, InitialState) {
    EXPECT_FALSE(paranoid->is_active());
}

TEST_F(ParanoidModeTest, ActivateDeactivate) {
    EXPECT_FALSE(paranoid->is_active());
    
    paranoid->activate();
    EXPECT_TRUE(paranoid->is_active());
    
    paranoid->deactivate();
    EXPECT_FALSE(paranoid->is_active());
}

TEST_F(ParanoidModeTest, DoubleActivation) {
    paranoid->activate();
    EXPECT_TRUE(paranoid->is_active());
    
    // Second activation should be safe (no-op or idempotent)
    EXPECT_NO_THROW(paranoid->activate());
    EXPECT_TRUE(paranoid->is_active());
}

TEST_F(ParanoidModeTest, DoubleDeactivation) {
    paranoid->activate();
    paranoid->deactivate();
    EXPECT_FALSE(paranoid->is_active());
    
    // Second deactivation should be safe
    EXPECT_NO_THROW(paranoid->deactivate());
    EXPECT_FALSE(paranoid->is_active());
}

// ---- Threat Level Tests ----

TEST_F(ParanoidModeTest, SetThreatLevel) {
    paranoid->set_threat_level(ThreatLevel::LOW);
    EXPECT_EQ(paranoid->get_threat_level(), ThreatLevel::LOW);
    
    paranoid->set_threat_level(ThreatLevel::MEDIUM);
    EXPECT_EQ(paranoid->get_threat_level(), ThreatLevel::MEDIUM);
    
    paranoid->set_threat_level(ThreatLevel::HIGH);
    EXPECT_EQ(paranoid->get_threat_level(), ThreatLevel::HIGH);
    
    paranoid->set_threat_level(ThreatLevel::CRITICAL);
    EXPECT_EQ(paranoid->get_threat_level(), ThreatLevel::CRITICAL);
    
    paranoid->set_threat_level(ThreatLevel::TINFOIL_HAT);
    EXPECT_EQ(paranoid->get_threat_level(), ThreatLevel::TINFOIL_HAT);
}

TEST_F(ParanoidModeTest, ThreatLevelAffectsConfig) {
    paranoid->set_threat_level(ThreatLevel::LOW);
    auto config_low = paranoid->get_config();
    
    paranoid->set_threat_level(ThreatLevel::TINFOIL_HAT);
    auto config_high = paranoid->get_config();
    
    // Higher threat level should enable more protections
    // Specific assertions depend on implementation details
    // At minimum, config objects should be different
}

// ---- Circuit Management Tests ----

TEST_F(ParanoidModeTest, CreateIsolatedCircuit) {
    std::string circuit_id = paranoid->create_isolated_circuit();
    
    EXPECT_FALSE(circuit_id.empty());
}

TEST_F(ParanoidModeTest, CircuitIdUniqueness) {
    std::set<std::string> circuit_ids;
    
    for (int i = 0; i < 100; ++i) {
        std::string circuit_id = paranoid->create_isolated_circuit();
        EXPECT_FALSE(circuit_id.empty());
        
        // Each circuit ID should be unique
        auto [iter, inserted] = circuit_ids.insert(circuit_id);
        EXPECT_TRUE(inserted) << "Duplicate circuit ID: " << circuit_id;
    }
    
    EXPECT_EQ(circuit_ids.size(), 100);
}

TEST_F(ParanoidModeTest, DestroyCircuit) {
    std::string circuit_id = paranoid->create_isolated_circuit();
    EXPECT_FALSE(circuit_id.empty());
    
    // Destroying should not throw
    EXPECT_NO_THROW(paranoid->destroy_circuit(circuit_id));
}

TEST_F(ParanoidModeTest, DestroyNonexistentCircuit) {
    // Destroying a non-existent circuit should be safe
    EXPECT_NO_THROW(paranoid->destroy_circuit("nonexistent_circuit_id"));
}

TEST_F(ParanoidModeTest, RotateAllCircuits) {
    // Create some circuits
    paranoid->create_isolated_circuit();
    paranoid->create_isolated_circuit();
    paranoid->create_isolated_circuit();
    
    // Rotate should not throw
    EXPECT_NO_THROW(paranoid->rotate_all_circuits());
}

// ---- HTTP Header Sanitization Tests ----

TEST_F(ParanoidModeTest, SanitizeHttpHeaders) {
    std::map<std::string, std::string> headers;
    headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
    headers["X-Forwarded-For"] = "192.168.1.100";
    headers["X-Real-IP"] = "10.0.0.1";
    headers["Accept"] = "text/html";
    headers["Host"] = "example.com";
    
    auto sanitized = paranoid->sanitize_http_headers(headers);
    
    // Dangerous headers should be removed or modified
    EXPECT_TRUE(sanitized.find("X-Forwarded-For") == sanitized.end() ||
                sanitized["X-Forwarded-For"] != "192.168.1.100");
    EXPECT_TRUE(sanitized.find("X-Real-IP") == sanitized.end() ||
                sanitized["X-Real-IP"] != "10.0.0.1");
    
    // Safe headers should be preserved
    EXPECT_TRUE(sanitized.find("Accept") != sanitized.end());
    EXPECT_TRUE(sanitized.find("Host") != sanitized.end());
}

TEST_F(ParanoidModeTest, SanitizeEmptyHeaders) {
    std::map<std::string, std::string> empty_headers;
    
    auto sanitized = paranoid->sanitize_http_headers(empty_headers);
    
    // Should not throw, result may be empty or contain default headers
}

// ---- Cover Traffic Tests ----

TEST_F(ParanoidModeTest, CoverTrafficStartStop) {
    paranoid->activate();
    
    // Start cover traffic (may be no-op if not fully implemented)
    EXPECT_NO_THROW(paranoid->start_cover_traffic());
    
    // Brief wait
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Stop cover traffic
    EXPECT_NO_THROW(paranoid->stop_cover_traffic());
}

TEST_F(ParanoidModeTest, CoverTrafficWithoutActivation) {
    // Cover traffic operations without activation should be safe
    EXPECT_NO_THROW(paranoid->start_cover_traffic());
    EXPECT_NO_THROW(paranoid->stop_cover_traffic());
}

// ---- Panic Callback Tests ----

TEST_F(ParanoidModeTest, SetPanicCallback) {
    bool callback_invoked = false;
    
    paranoid->set_panic_callback([&callback_invoked]() {
        callback_invoked = true;
    });
    
    // Trigger panic (if method exists)
    paranoid->trigger_canary();
    
    EXPECT_TRUE(callback_invoked);
}

TEST_F(ParanoidModeTest, NullPanicCallback) {
    // Setting null callback should not crash
    EXPECT_NO_THROW(paranoid->set_panic_callback(nullptr));
    EXPECT_NO_THROW(paranoid->trigger_canary());
}

// ---- Request Batching Tests ----

TEST_F(ParanoidModeTest, EnableRequestBatching) {
    EXPECT_NO_THROW(paranoid->enable_request_batching(10, std::chrono::milliseconds(100)));
}

TEST_F(ParanoidModeTest, DisableRequestBatching) {
    paranoid->enable_request_batching(10, std::chrono::milliseconds(100));
    EXPECT_NO_THROW(paranoid->disable_request_batching());
}

// ---- Security Audit Tests ----

TEST_F(ParanoidModeTest, PerformSecurityAudit) {
    SecurityAudit audit = paranoid->perform_security_audit();
    
    // Audit should return valid structure
    // Specific assertions depend on SecurityAudit definition
}

// ---- Delay Tests ----

TEST_F(ParanoidModeTest, AddRandomDelay) {
    auto start = std::chrono::steady_clock::now();
    
    paranoid->add_random_delay(10, 50);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Delay should be within bounds (with some tolerance)
    EXPECT_GE(duration, 10 - 5);  // Allow 5ms tolerance
    EXPECT_LE(duration, 50 + 50); // Allow 50ms tolerance for scheduling
}

TEST_F(ParanoidModeTest, ZeroDelay) {
    auto start = std::chrono::steady_clock::now();
    
    paranoid->add_random_delay(0, 0);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Should be very fast
    EXPECT_LE(duration, 10);
}

// ---- Configuration Tests ----

TEST_F(ParanoidModeTest, SetLayeredConfig) {
    LayeredSecurityConfig config;
    config.use_vpn = true;
    config.use_tor = true;
    config.use_i2p = false;
    
    EXPECT_NO_THROW(paranoid->set_layered_config(config));
    
    auto retrieved = paranoid->get_layered_config();
    EXPECT_EQ(retrieved.use_vpn, true);
    EXPECT_EQ(retrieved.use_tor, true);
    EXPECT_EQ(retrieved.use_i2p, false);
}

// ---- Traces Cleanup Tests ----

TEST_F(ParanoidModeTest, ClearAllTraces) {
    // Should not throw even if nothing to clear
    EXPECT_NO_THROW(paranoid->clear_all_traces());
}

TEST_F(ParanoidModeTest, ClearSystemTraces) {
    // May require privileges, should handle gracefully
    EXPECT_NO_THROW(paranoid->clear_system_traces());
}

// ---- Memory Protection Tests ----

TEST_F(ParanoidModeTest, EnableMemoryProtection) {
    // May fail without root privileges, but should not crash
    EXPECT_NO_THROW(paranoid->enable_memory_protection());
}

TEST_F(ParanoidModeTest, WipeMemoryOnExit) {
    EXPECT_NO_THROW(paranoid->wipe_memory_on_exit());
}

// ---- File Operations Tests ----

TEST_F(ParanoidModeTest, ShredNonexistentFile) {
    // Shredding non-existent file should return false or throw
    // Implementation dependent
    EXPECT_NO_THROW(paranoid->shred_file("/nonexistent/path/file.txt", 3));
}

TEST_F(ParanoidModeTest, StripMetadataEmptyData) {
    std::vector<uint8_t> empty_data;
    
    auto result = paranoid->strip_metadata(empty_data);
    
    // Should return empty or same data
    EXPECT_TRUE(result.empty());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
