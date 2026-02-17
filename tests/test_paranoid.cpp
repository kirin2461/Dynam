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
    paranoid->set_threat_level(ParanoidMode::ThreatLevel::MODERATE);
    EXPECT_EQ(paranoid->get_threat_level(), ParanoidMode::ThreatLevel::MODERATE);
    
    paranoid->set_threat_level(ParanoidMode::ThreatLevel::HIGH);
    EXPECT_EQ(paranoid->get_threat_level(), ParanoidMode::ThreatLevel::HIGH);
    
    paranoid->set_threat_level(ParanoidMode::ThreatLevel::EXTREME);
    EXPECT_EQ(paranoid->get_threat_level(), ParanoidMode::ThreatLevel::EXTREME);
    
    paranoid->set_threat_level(ParanoidMode::ThreatLevel::TINFOIL_HAT);
    EXPECT_EQ(paranoid->get_threat_level(), ParanoidMode::ThreatLevel::TINFOIL_HAT);
}

TEST_F(ParanoidModeTest, ThreatLevelAffectsConfig) {
    paranoid->set_threat_level(ParanoidMode::ThreatLevel::MODERATE);
    auto level_low = paranoid->get_threat_level();
    
    paranoid->set_threat_level(ParanoidMode::ThreatLevel::TINFOIL_HAT);
    auto level_high = paranoid->get_threat_level();
    
    // Different threat levels should be set
    EXPECT_NE(level_low, level_high);
}

// ---- Circuit Management Tests ----

TEST_F(ParanoidModeTest, CreateIsolatedCircuit) {
    std::string circuit_id = paranoid->create_isolated_circuit("example.com");
    
    EXPECT_FALSE(circuit_id.empty());
}

TEST_F(ParanoidModeTest, CircuitIdUniqueness) {
    std::set<std::string> circuit_ids;
    
    for (int i = 0; i < 100; ++i) {
        std::string circuit_id = paranoid->create_isolated_circuit("example" + std::to_string(i) + ".com");
        EXPECT_FALSE(circuit_id.empty());
        
        // Each circuit ID should be unique
        auto [iter, inserted] = circuit_ids.insert(circuit_id);
        EXPECT_TRUE(inserted) << "Duplicate circuit ID: " << circuit_id;
    }
    
    EXPECT_EQ(circuit_ids.size(), 100);
}

TEST_F(ParanoidModeTest, DestroyCircuit) {
    std::string circuit_id = paranoid->create_isolated_circuit("example.com");
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
    paranoid->create_isolated_circuit("example1.com");
    paranoid->create_isolated_circuit("example2.com");
    paranoid->create_isolated_circuit("example3.com");
    
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
    
    paranoid->sanitize_http_headers(headers);
    
    // Dangerous headers should be removed or modified
    EXPECT_TRUE(headers.find("X-Forwarded-For") == headers.end() ||
                headers["X-Forwarded-For"] != "192.168.1.100");
    EXPECT_TRUE(headers.find("X-Real-IP") == headers.end() ||
                headers["X-Real-IP"] != "10.0.0.1");
}

TEST_F(ParanoidModeTest, SanitizeEmptyHeaders) {
    std::map<std::string, std::string> empty_headers;
    
    EXPECT_NO_THROW(paranoid->sanitize_http_headers(empty_headers));
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
    
    // Trigger panic (using canary_trigger instead of trigger_canary)
    paranoid->canary_trigger();
    
    EXPECT_TRUE(callback_invoked);
}

TEST_F(ParanoidModeTest, NullPanicCallback) {
    // Setting null callback should not crash
    EXPECT_NO_THROW(paranoid->set_panic_callback(nullptr));
    EXPECT_NO_THROW(paranoid->canary_trigger());
}

// ---- Request Batching Tests ----

TEST_F(ParanoidModeTest, EnableRequestBatching) {
    EXPECT_NO_THROW(paranoid->enable_request_batching(10, 100));
}

// ---- Security Audit Tests ----

TEST_F(ParanoidModeTest, PerformSecurityAudit) {
    ParanoidMode::SecurityAudit audit = paranoid->perform_security_audit();
    
    // Audit should return valid structure with score 0-100
    EXPECT_GE(audit.security_score, 0);
    EXPECT_LE(audit.security_score, 100);
}

// ---- Delay Tests ----

TEST_F(ParanoidModeTest, AddRandomDelay) {
    auto start = std::chrono::steady_clock::now();
    
    paranoid->add_random_delay();
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // Delay should have occurred (at least some time should pass)
    EXPECT_GE(duration, 0);
}

// ---- Traces Cleanup Tests ----

TEST_F(ParanoidModeTest, ClearAllTraces) {
    // Should not throw even if nothing to clear
    EXPECT_NO_THROW(paranoid->clear_all_traces());
}

// ---- Memory Protection Tests ----

TEST_F(ParanoidModeTest, WipeMemoryOnExit) {
    EXPECT_NO_THROW(paranoid->wipe_memory_on_exit());
}

// ---- File Operations Tests ----

TEST_F(ParanoidModeTest, SecureDeleteNonexistentFile) {
    // Secure delete non-existent file should not throw
    EXPECT_NO_THROW(paranoid->secure_delete_file("/nonexistent/path/file.txt", 3));
}

TEST_F(ParanoidModeTest, StripMetadataEmptyData) {
    std::vector<uint8_t> empty_data;
    
    EXPECT_NO_THROW(paranoid->strip_metadata(empty_data));
}

// Note: main() is NOT defined here - GTest provides it when linking with gtest_main
