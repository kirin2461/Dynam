// Integration tests for DPI bypass fixes (Issues #2, #3, #4)
// File: tests/integration/test_dpi_fixes.cpp

#include "ncp_dpi.hpp"
#include "ncp_dpi_advanced.hpp"
#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>

using namespace ncp::DPI;
using namespace std::chrono_literals;

// ==================== Test #2: Config Race Condition ====================

TEST(DPIBypassIntegration, ConfigRaceCondition_NoDataRace) {
    DPIBypass dpi;
    DPIConfig config;
    config.mode = DPIMode::PROXY;
    config.listen_port = 18080;
    config.target_host = "127.0.0.1";
    config.target_port = 443;
    config.enable_tcp_split = true;
    
    ASSERT_TRUE(dpi.initialize(config));
    ASSERT_TRUE(dpi.start());
    
    std::atomic<bool> stop_test{false};
    std::atomic<int> updates_completed{0};
    
    // Thread 1: Continuously update config
    std::thread updater([&]() {
        DPIConfig new_config = config;
        while (!stop_test) {
            new_config.fragment_size = (new_config.fragment_size % 100) + 1;
            new_config.split_position = (new_config.split_position % 50) + 1;
            dpi.update_config(new_config);
            updates_completed++;
            std::this_thread::sleep_for(1ms);
        }
    });
    
    // Thread 2: Simulate multiple connections reading config
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) {
        workers.emplace_back([&]() {
            while (!stop_test) {
                auto cfg = dpi.get_config();
                // Simulate work with config
                volatile int dummy = cfg.fragment_size + cfg.split_position;
                (void)dummy;
                std::this_thread::sleep_for(500us);
            }
        });
    }
    
    // Run for 2 seconds
    std::this_thread::sleep_for(2s);
    stop_test = true;
    
    updater.join();
    for (auto& w : workers) w.join();
    
    dpi.stop();
    
    EXPECT_GT(updates_completed.load(), 100) << "Should complete 100+ config updates";
    std::cout << "✓ Config race test: " << updates_completed 
              << " updates completed without data race\n";
}

// ==================== Test #3: Responsive Shutdown ====================

TEST(DPIBypassIntegration, ResponsiveShutdown_Under500ms) {
    DPIBypass dpi;
    DPIConfig config;
    config.mode = DPIMode::PROXY;
    config.listen_port = 18081;
    config.target_host = "127.0.0.1";
    config.target_port = 443;
    
    ASSERT_TRUE(dpi.initialize(config));
    ASSERT_TRUE(dpi.start());
    
    // Wait for proxy to fully start
    std::this_thread::sleep_for(100ms);
    
    auto start_time = std::chrono::steady_clock::now();
    dpi.stop();
    auto end_time = std::chrono::steady_clock::now();
    
    auto shutdown_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    EXPECT_LT(shutdown_duration.count(), 500) 
        << "Shutdown should complete in < 500ms, took " 
        << shutdown_duration.count() << "ms";
    
    std::cout << "✓ Shutdown test: completed in " 
              << shutdown_duration.count() << "ms\n";
}

TEST(DPIBypassIntegration, ResponsiveShutdown_MultipleStarts) {
    // Test that multiple start/stop cycles work correctly
    DPIBypass dpi;
    DPIConfig config;
    config.mode = DPIMode::PROXY;
    config.listen_port = 18082;
    config.target_host = "127.0.0.1";
    config.target_port = 443;
    
    ASSERT_TRUE(dpi.initialize(config));
    
    for (int i = 0; i < 5; ++i) {
        ASSERT_TRUE(dpi.start()) << "Start failed on iteration " << i;
        std::this_thread::sleep_for(100ms);
        
        auto start_time = std::chrono::steady_clock::now();
        dpi.stop();
        auto end_time = std::chrono::steady_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        
        EXPECT_LT(duration.count(), 500) 
            << "Iteration " << i << " shutdown took " << duration.count() << "ms";
    }
    
    std::cout << "✓ Multiple start/stop cycles completed\n";
}

// ==================== Test #4: Realistic Fake ClientHello ====================

TEST(TLSManipulatorIntegration, FakeClientHello_HasRequiredFields) {
    TLSManipulator manip;
    auto fake_hello = manip.create_fake_client_hello("www.example.com");
    
    ASSERT_GE(fake_hello.size(), 200) << "ClientHello should be at least 200 bytes";
    
    // Check TLS record header
    EXPECT_EQ(fake_hello[0], 0x16) << "Should be Handshake record";
    EXPECT_EQ(fake_hello[1], 0x03) << "Should be TLS 1.x";
    
    // Check handshake type
    EXPECT_EQ(fake_hello[5], 0x01) << "Should be ClientHello";
    
    // Check client version
    EXPECT_EQ(fake_hello[9], 0x03) << "Client version should be 0x03";
    EXPECT_EQ(fake_hello[10], 0x03) << "Client version should be 0x0303 (TLS 1.2)";
    
    // Check that random bytes exist (32 bytes after version)
    bool has_non_zero_random = false;
    for (size_t i = 11; i < 11 + 32; ++i) {
        if (fake_hello[i] != 0) {
            has_non_zero_random = true;
            break;
        }
    }
    EXPECT_TRUE(has_non_zero_random) << "Random field should have non-zero bytes";
    
    // Check session ID length (should be 32)
    EXPECT_EQ(fake_hello[43], 32) << "Session ID should be 32 bytes";
    
    // Check that session ID is random (not all zeros)
    bool has_non_zero_session = false;
    for (size_t i = 44; i < 44 + 32; ++i) {
        if (fake_hello[i] != 0) {
            has_non_zero_session = true;
            break;
        }
    }
    EXPECT_TRUE(has_non_zero_session) << "Session ID should be random";
    
    std::cout << "✓ Fake ClientHello size: " << fake_hello.size() << " bytes\n";
}

TEST(TLSManipulatorIntegration, FakeClientHello_HasMultipleCipherSuites) {
    TLSManipulator manip;
    auto fake_hello = manip.create_fake_client_hello("www.example.com");
    
    // Session ID ends at byte 76 (44 + 32)
    // Cipher suites length is at 76-77
    ASSERT_GE(fake_hello.size(), 78);
    
    uint16_t cipher_len = (static_cast<uint16_t>(fake_hello[76]) << 8) | 
                          fake_hello[77];
    size_t num_ciphers = cipher_len / 2;
    
    EXPECT_GE(num_ciphers, 15) << "Should have at least 15 cipher suites";
    EXPECT_LE(num_ciphers, 20) << "Should have at most 20 cipher suites";
    
    std::cout << "✓ Fake ClientHello has " << num_ciphers << " cipher suites\n";
}

TEST(TLSManipulatorIntegration, FakeClientHello_HasCriticalExtensions) {
    TLSManipulator manip;
    auto fake_hello = manip.create_fake_client_hello("www.example.com");
    
    // Parse extensions to find critical ones
    bool has_sni = false;
    bool has_supported_versions = false;
    bool has_supported_groups = false;
    bool has_signature_algorithms = false;
    bool has_grease = false;
    
    // Find extensions section (skip to compression methods + 1)
    size_t pos = 76; // After session ID
    if (pos + 2 > fake_hello.size()) return;
    
    uint16_t cipher_len = (fake_hello[pos] << 8) | fake_hello[pos + 1];
    pos += 2 + cipher_len;
    
    if (pos + 1 > fake_hello.size()) return;
    uint8_t comp_len = fake_hello[pos];
    pos += 1 + comp_len;
    
    if (pos + 2 > fake_hello.size()) return;
    uint16_t ext_len = (fake_hello[pos] << 8) | fake_hello[pos + 1];
    pos += 2;
    
    size_t ext_end = pos + ext_len;
    while (pos + 4 <= ext_end && pos + 4 <= fake_hello.size()) {
        uint16_t ext_type = (fake_hello[pos] << 8) | fake_hello[pos + 1];
        uint16_t ext_data_len = (fake_hello[pos + 2] << 8) | fake_hello[pos + 3];
        pos += 4;
        
        if (pos + ext_data_len > fake_hello.size()) break;
        
        switch (ext_type) {
            case 0x0000: has_sni = true; break;
            case 0x002B: has_supported_versions = true; break;
            case 0x000A: has_supported_groups = true; break;
            case 0x000D: has_signature_algorithms = true; break;
            default:
                // Check for GREASE (0x?A?A pattern)
                if ((ext_type & 0x0F0F) == 0x0A0A) {
                    has_grease = true;
                }
                break;
        }
        
        pos += ext_data_len;
    }
    
    EXPECT_TRUE(has_sni) << "Should have SNI extension";
    EXPECT_TRUE(has_supported_versions) << "Should have supported_versions extension";
    EXPECT_TRUE(has_supported_groups) << "Should have supported_groups extension";
    EXPECT_TRUE(has_signature_algorithms) << "Should have signature_algorithms extension";
    EXPECT_TRUE(has_grease) << "Should have GREASE extension";
    
    std::cout << "✓ Fake ClientHello has all critical extensions\n";
}

// ==================== Performance Tests ====================

TEST(DPIBypassPerformance, ConfigSnapshot_LowOverhead) {
    DPIBypass dpi;
    DPIConfig config;
    config.mode = DPIMode::PROXY;
    config.listen_port = 18083;
    config.target_host = "127.0.0.1";
    config.target_port = 443;
    
    ASSERT_TRUE(dpi.initialize(config));
    ASSERT_TRUE(dpi.start());
    
    const int iterations = 10000;
    auto start_time = std::chrono::steady_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto cfg = dpi.get_config(); // Simulates config snapshot
        volatile int dummy = cfg.fragment_size;
        (void)dummy;
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        end_time - start_time);
    
    double avg_us = duration.count() / static_cast<double>(iterations);
    
    EXPECT_LT(avg_us, 1.0) << "Config snapshot should take < 1μs on average";
    
    std::cout << "✓ Config snapshot overhead: " << avg_us << "μs per call\n";
    
    dpi.stop();
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    // Initialize libsodium for CSPRNG
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }
    
    return RUN_ALL_TESTS();
}