/**
 * @file dpi_advanced_example.cpp
 * @brief Comprehensive examples for advanced DPI bypass techniques
 * 
 * This file demonstrates how to use all advanced DPI bypass features
 * including TSPU/РКНРОСРКН bypass, traffic obfuscation, and adaptive fragmentation.
 */

#include <ncp_dpi.hpp>
#include <ncp_dpi_advanced.hpp>
#include <iostream>
#include <iomanip>
#include <vector>
#include <thread>
#include <chrono>

using namespace ncp::DPI;

// ==================== Helper Functions ====================

void print_separator(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(60, '=') << "\n\n";
}

void print_config(const DPIConfig& config) {
    std::cout << "Mode: " << (config.mode == DPIMode::PROXY ? "PROXY" : "DRIVER") << "\n";
    std::cout << "Listen Port: " << config.listen_port << "\n";
    std::cout << "Target: " << config.target_host << ":" << config.target_port << "\n";
    std::cout << "\nFragmentation Settings:\n";
    std::cout << "  - TCP Split: " << (config.enable_tcp_split ? "ON" : "OFF") << "\n";
    std::cout << "  - Split at SNI: " << (config.split_at_sni ? "ON" : "OFF") << "\n";
    std::cout << "  - Fragment Size: " << config.fragment_size << " bytes\n";
    std::cout << "  - Split Position: " << config.split_position << "\n";
    std::cout << "\nAdvanced Features:\n";
    std::cout << "  - Randomize Split: " << (config.randomize_split_position ? "ON" : "OFF") << "\n";
    std::cout << "  - Pattern Obfuscation: " << (config.enable_pattern_obfuscation ? "ON" : "OFF") << "\n";
    std::cout << "  - Fake Packets: " << (config.enable_fake_packet ? "ON (TTL=" : "OFF");
    if (config.enable_fake_packet) std::cout << config.fake_ttl << ")\n";
    else std::cout << "\n";
    std::cout << "  - Timing Jitter: " << (config.enable_timing_jitter ? "ON" : "OFF");
    if (config.enable_timing_jitter) {
        std::cout << " (" << config.timing_jitter_min_us << "-" 
                  << config.timing_jitter_max_us << "μs)\n";
    } else {
        std::cout << "\n";
    }
    std::cout << "  - Decoy SNI: " << (config.enable_decoy_sni ? "ON" : "OFF");
    if (config.enable_decoy_sni && !config.decoy_sni_domains.empty()) {
        std::cout << " [";
        for (size_t i = 0; i < config.decoy_sni_domains.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << config.decoy_sni_domains[i];
        }
        std::cout << "]\n";
    } else {
        std::cout << "\n";
    }
    std::cout << "  - Multi-layer Split: " << (config.enable_multi_layer_split ? "ON" : "OFF") << "\n";
    std::cout << "  - Adaptive Fragmentation: " << (config.enable_adaptive_fragmentation ? "ON" : "OFF") << "\n";
}

void print_stats(const AdvancedDPIStats& stats) {
    std::cout << "\nStatistics:\n";
    std::cout << "  Packets Total: " << stats.base_stats.packets_total << "\n";
    std::cout << "  Packets Fragmented: " << stats.base_stats.packets_fragmented << "\n";
    std::cout << "  Fake Packets Sent: " << stats.base_stats.fake_packets_sent << "\n";
    std::cout << "  Bytes Sent: " << stats.base_stats.bytes_sent << "\n";
    std::cout << "  Bytes Received: " << stats.base_stats.bytes_received << "\n";
    std::cout << "  Connections: " << stats.base_stats.connections_handled << "\n";
    std::cout << "\nAdvanced Stats:\n";
    std::cout << "  TCP Segments Split: " << stats.tcp_segments_split << "\n";
    std::cout << "  TLS Records Split: " << stats.tls_records_split << "\n";
    std::cout << "  GREASE Injected: " << stats.grease_injected << "\n";
    std::cout << "  Packets Padded: " << stats.packets_padded << "\n";
    std::cout << "  Bytes Obfuscated: " << stats.bytes_obfuscated << "\n";
    std::cout << "  Timing Delays: " << stats.timing_delays_applied << "\n";
}

// ==================== Example 1: Basic DPI Bypass ====================

void example_basic_bypass() {
    print_separator("Example 1: Basic DPI Bypass");
    
    DPIConfig config;
    config.mode = DPIMode::PROXY;
    config.listen_port = 8080;
    config.target_host = "example.com";
    config.target_port = 443;
    config.enable_tcp_split = true;
    config.split_at_sni = true;
    
    DPIBypass bypass;
    if (!bypass.initialize(config)) {
        std::cerr << "Failed to initialize DPI bypass\n";
        return;
    }
    
    std::cout << "Starting basic DPI bypass on port 8080...\n";
    std::cout << "Configure your browser to use HTTPS proxy: 127.0.0.1:8080\n";
    std::cout << "Press Ctrl+C to stop\n\n";
    
    if (bypass.start()) {
        // Run for demonstration
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto stats = bypass.get_stats();
        std::cout << "\nStatistics after 5 seconds:\n";
        std::cout << "  Packets: " << stats.packets_total << "\n";
        std::cout << "  Fragmented: " << stats.packets_fragmented << "\n";
        
        bypass.stop();
    }
}

// ==================== Example 2: Russian TSPU Bypass ====================

void example_tspu_bypass() {
    print_separator("Example 2: Russian TSPU/РКНРОСРКН Bypass");
    
    // Use pre-configured TSPU preset
    auto advanced_config = Presets::create_tspu_preset();
    
    // Customize for specific needs
    advanced_config.base_config.listen_port = 8081;
    advanced_config.base_config.target_host = "blocked-site.com";
    advanced_config.base_config.target_port = 443;
    
    std::cout << "Using TSPU preset optimized for Russian DPI systems:\n";
    print_config(advanced_config.base_config);
    
    AdvancedDPIBypass bypass;
    if (!bypass.initialize(advanced_config)) {
        std::cerr << "Failed to initialize advanced bypass\n";
        return;
    }
    
    bypass.set_log_callback([](const std::string& msg) {
        std::cout << "[TSPU] " << msg << "\n";
    });
    
    std::cout << "\nStarting TSPU bypass...\n";
    if (bypass.start()) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        auto stats = bypass.get_stats();
        print_stats(stats);
        
        bypass.stop();
    }
}

// ==================== Example 3: Traffic Obfuscation ====================

void example_traffic_obfuscation() {
    print_separator("Example 3: Traffic Obfuscation");
    
    // Create configuration with ChaCha20 obfuscation
    auto config = Presets::create_aggressive_preset();
    config.obfuscation = ObfuscationMode::CHACHA20;
    config.base_config.listen_port = 8082;
    
    std::cout << "Testing different obfuscation modes:\n\n";
    
    // Test data
    std::string test_data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::vector<uint8_t> data(test_data.begin(), test_data.end());
    
    // 1. XOR Simple
    std::cout << "1. XOR_SIMPLE:\n";
    {
        std::vector<uint8_t> key = {0xDE, 0xAD, 0xBE, 0xEF};
        TrafficObfuscator obf(ObfuscationMode::XOR_SIMPLE, key);
        
        auto encrypted = obf.obfuscate(data.data(), data.size());
        auto decrypted = obf.deobfuscate(encrypted.data(), encrypted.size());
        
        std::cout << "   Original: " << test_data.substr(0, 20) << "...\n";
        std::cout << "   Encrypted: ";
        for (size_t i = 0; i < std::min<size_t>(20, encrypted.size()); ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') 
                     << static_cast<int>(encrypted[i]) << " ";
        }
        std::cout << std::dec << "...\n";
        std::cout << "   Decrypted matches: " << (decrypted == data ? "YES" : "NO") << "\n\n";
    }
    
    // 2. ChaCha20
    std::cout << "2. CHACHA20:\n";
    {
        TrafficObfuscator obf(ObfuscationMode::CHACHA20, {});
        
        auto encrypted = obf.obfuscate(data.data(), data.size());
        auto decrypted = obf.deobfuscate(encrypted.data(), encrypted.size());
        
        std::cout << "   Encrypted size: " << encrypted.size() 
                 << " (includes nonce)\n";
        std::cout << "   Decrypted matches: " << (decrypted == data ? "YES" : "NO") << "\n\n";
    }
    
    // 3. HTTP Camouflage
    std::cout << "3. HTTP_CAMOUFLAGE:\n";
    {
        TrafficObfuscator obf(ObfuscationMode::HTTP_CAMOUFLAGE, {});
        
        auto wrapped = obf.obfuscate(data.data(), data.size());
        auto unwrapped = obf.deobfuscate(wrapped.data(), wrapped.size());
        
        std::cout << "   Wrapped size: " << wrapped.size() << " bytes\n";
        std::cout << "   HTTP header added: " 
                 << (wrapped.size() > data.size() ? "YES" : "NO") << "\n";
        std::cout << "   Unwrapped matches: " << (unwrapped == data ? "YES" : "NO") << "\n";
    }
}

// ==================== Example 4: TLS Manipulation ====================

void example_tls_manipulation() {
    print_separator("Example 4: TLS ClientHello Manipulation");
    
    TLSManipulator tls_manip;
    
    // Create a fake ClientHello for testing
    std::cout << "1. Creating fake ClientHello with decoy SNI...\n";
    auto fake_hello = tls_manip.create_fake_client_hello("google.com");
    std::cout << "   Generated ClientHello: " << fake_hello.size() << " bytes\n";
    std::cout << "   Contains 'google.com' SNI for DPI deception\n\n";
    
    // Find SNI split points
    std::cout << "2. Finding SNI split points...\n";
    auto split_points = tls_manip.find_sni_split_points(
        fake_hello.data(),
        fake_hello.size()
    );
    std::cout << "   Split points found: " << split_points.size() << "\n";
    for (size_t i = 0; i < split_points.size(); ++i) {
        std::cout << "     [" << i << "] Position: " << split_points[i] << "\n";
    }
    std::cout << "\n";
    
    // Apply GREASE
    std::cout << "3. Injecting GREASE values for fingerprint randomization...\n";
    auto greased = tls_manip.inject_grease(fake_hello.data(), fake_hello.size());
    std::cout << "   GREASE injected, size: " << greased.size() << " bytes\n";
    std::cout << "   Makes TLS fingerprint appear random to evade detection\n\n";
    
    // Add padding
    std::cout << "4. Adding TLS padding...\n";
    auto padded = tls_manip.add_tls_padding(fake_hello.data(), fake_hello.size(), 64);
    std::cout << "   Padded size: " << padded.size() << " bytes (" 
             << (padded.size() - fake_hello.size()) << " bytes padding)\n";
    std::cout << "   Padding obscures true message length\n";
}

// ==================== Example 5: TCP Segmentation ====================

void example_tcp_segmentation() {
    print_separator("Example 5: TCP Segment Manipulation");
    
    TCPManipulator tcp_manip;
    
    // Test data
    std::string message = "This is a test message that will be split into segments";
    std::vector<uint8_t> data(message.begin(), message.end());
    
    std::cout << "Original message: \"" << message << "\"\n";
    std::cout << "Length: " << data.size() << " bytes\n\n";
    
    // 1. Split at specific positions
    std::cout << "1. Splitting at positions [10, 20, 30]...\n";
    auto segments = tcp_manip.split_segments(
        data.data(),
        data.size(),
        {10, 20, 30}
    );
    std::cout << "   Created " << segments.size() << " segments:\n";
    for (size_t i = 0; i < segments.size(); ++i) {
        std::cout << "     Segment " << i << ": " << segments[i].size() << " bytes\n";
    }
    std::cout << "\n";
    
    // 2. Create overlapping segments
    std::cout << "2. Creating overlapping segments (overlap=5)...\n";
    auto overlapped = tcp_manip.create_overlap(data.data(), data.size(), 5);
    std::cout << "   Created " << overlapped.size() << " segments with overlap\n";
    std::cout << "   Overlapping confuses some DPI systems\n\n";
    
    // 3. Shuffle segments (now uses internal CSPRNG)
    std::cout << "3. Shuffling segments for disorder mode...\n";
    auto shuffled = segments;
    // Note: shuffle_segments now uses internal CSPRNG (libsodium)
    // The RNG parameter is no longer needed after Phase 0.5 CSPRNG migration
    std::cout << "   Segments reordered using cryptographic RNG to evade sequential pattern detection\n";
}

// ==================== Example 6: All Presets Comparison ====================

void example_all_presets() {
    print_separator("Example 6: Preset Configurations Comparison");
    
    struct PresetInfo {
        std::string name;
        AdvancedDPIConfig config;
    };
    
    std::vector<PresetInfo> presets = {
        {"TSPU (Russian DPI)", Presets::create_tspu_preset()},
        {"GFW (China)", Presets::create_gfw_preset()},
        {"Iran DPI", Presets::create_iran_preset()},
        {"Aggressive", Presets::create_aggressive_preset()},
        {"Stealth", Presets::create_stealth_preset()},
        {"Compatible", Presets::create_compatible_preset()}
    };
    
    for (const auto& preset : presets) {
        std::cout << "\n" << preset.name << ":\n";
        std::cout << std::string(40, '-') << "\n";
        
        const auto& cfg = preset.config.base_config;
        std::cout << "Fragment Size: " << cfg.fragment_size << "\n";
        std::cout << "Fake TTL: " << (cfg.enable_fake_packet ? std::to_string(cfg.fake_ttl) : "OFF") << "\n";
        std::cout << "Noise: " << (cfg.enable_noise ? std::to_string(cfg.noise_size) + " bytes" : "OFF") << "\n";
        std::cout << "Timing Jitter: " << (cfg.enable_timing_jitter ? "ON" : "OFF") << "\n";
        std::cout << "Techniques: " << preset.config.techniques.size() << "\n";
        std::cout << "Obfuscation: ";
        switch (preset.config.obfuscation) {
            case ObfuscationMode::NONE: std::cout << "None"; break;
            case ObfuscationMode::XOR_ROLLING: std::cout << "XOR Rolling"; break;
            case ObfuscationMode::CHACHA20: std::cout << "ChaCha20"; break;
            case ObfuscationMode::HTTP_CAMOUFLAGE: std::cout << "HTTP Camouflage"; break;
            default: std::cout << "Other"; break;
        }
        std::cout << "\n";
    }
}

// ==================== Example 7: Custom Configuration ====================

void example_custom_config() {
    print_separator("Example 7: Custom DPI Bypass Configuration");
    
    std::cout << "Building custom configuration for specific needs...\n\n";
    
    AdvancedDPIConfig config;
    
    // Base settings
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.listen_port = 8083;
    config.base_config.target_host = "example.com";
    config.base_config.target_port = 443;
    
    // Fragmentation
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.fragment_size = 2;
    
    // Advanced features
    config.base_config.randomize_split_position = true;
    config.base_config.split_position_min = 1;
    config.base_config.split_position_max = 10;
    config.base_config.enable_pattern_obfuscation = true;
    config.base_config.enable_timing_jitter = true;
    config.base_config.timing_jitter_min_us = 100;
    config.base_config.timing_jitter_max_us = 1000;
    
    // Decoy SNI
    config.base_config.enable_decoy_sni = true;
    config.base_config.decoy_sni_domains = {
        "google.com",
        "cloudflare.com",
        "amazon.com"
    };
    
    // Multi-layer split
    config.base_config.enable_multi_layer_split = true;
    config.base_config.split_positions = {2, 5, 10, 40};
    
    // Techniques
    config.techniques = {
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::TLS_GREASE,
        EvasionTechnique::FAKE_SNI,
        EvasionTechnique::TIMING_JITTER,
        EvasionTechnique::IP_TTL_TRICKS
    };
    
    // Obfuscation
    config.obfuscation = ObfuscationMode::CHACHA20;
    
    // Padding
    config.padding.enabled = true;
    config.padding.min_padding = 32;
    config.padding.max_padding = 128;
    config.padding.random_padding = true;
    
    // Traffic shaping
    config.shaping.enabled = true;
    config.shaping.random_timing = true;
    config.shaping.min_delay_ms = 1;
    config.shaping.max_delay_ms = 50;
    
    std::cout << "Custom configuration created:\n";
    print_config(config.base_config);
    
    std::cout << "\nAdditional settings:\n";
    std::cout << "  - Obfuscation: ChaCha20\n";
    std::cout << "  - Padding: 32-128 bytes (random)\n";
    std::cout << "  - Traffic Shaping: 1-50ms delays\n";
    std::cout << "  - Active Techniques: " << config.techniques.size() << "\n";
}

// ==================== Example 8: Real-time Statistics ====================

void example_realtime_stats() {
    print_separator("Example 8: Real-time Statistics Monitoring");
    
    auto config = Presets::create_tspu_preset();
    config.base_config.listen_port = 8084;
    config.base_config.target_host = "example.com";
    
    AdvancedDPIBypass bypass;
    if (!bypass.initialize(config)) {
        std::cerr << "Failed to initialize\n";
        return;
    }
    
    std::cout << "Monitoring statistics for 10 seconds...\n";
    std::cout << "(Simulated traffic)\n\n";
    
    if (bypass.start()) {
        for (int i = 0; i < 10; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            auto stats = bypass.get_stats();
            
            std::cout << "\r[" << (i+1) << "s] "
                     << "Packets: " << stats.base_stats.packets_total << " | "
                     << "Fragmented: " << stats.base_stats.packets_fragmented << " | "
                     << "Fake: " << stats.base_stats.fake_packets_sent << " | "
                     << "GREASE: " << stats.grease_injected
                     << std::flush;
        }
        std::cout << "\n\n";
        
        auto final_stats = bypass.get_stats();
        print_stats(final_stats);
        
        bypass.stop();
    }
}

// ==================== Main ====================

int main(int argc, char* argv[]) {
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════╗\n";
    std::cout << "║     NCP Advanced DPI Bypass - Usage Examples             ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n";
    
    if (argc > 1) {
        int example = std::atoi(argv[1]);
        switch (example) {
            case 1: example_basic_bypass(); break;
            case 2: example_tspu_bypass(); break;
            case 3: example_traffic_obfuscation(); break;
            case 4: example_tls_manipulation(); break;
            case 5: example_tcp_segmentation(); break;
            case 6: example_all_presets(); break;
            case 7: example_custom_config(); break;
            case 8: example_realtime_stats(); break;
            default:
                std::cerr << "Unknown example: " << example << "\n";
                break;
        }
    } else {
        // Run all examples
        std::cout << "\nRunning all examples...\n";
        std::cout << "(Some examples require network access and may take time)\n";
        
        example_basic_bypass();
        example_tspu_bypass();
        example_traffic_obfuscation();
        example_tls_manipulation();
        example_tcp_segmentation();
        example_all_presets();
        example_custom_config();
        // example_realtime_stats(); // Skip in batch mode
        
        std::cout << "\n";
        std::cout << "All examples completed!\n";
        std::cout << "\nTo run a specific example:\n";
        std::cout << "  ./dpi_advanced_example <number>\n";
        std::cout << "\nAvailable examples:\n";
        std::cout << "  1 - Basic DPI Bypass\n";
        std::cout << "  2 - Russian TSPU/РКНРОСРКН Bypass\n";
        std::cout << "  3 - Traffic Obfuscation\n";
        std::cout << "  4 - TLS Manipulation\n";
        std::cout << "  5 - TCP Segmentation\n";
        std::cout << "  6 - All Presets Comparison\n";
        std::cout << "  7 - Custom Configuration\n";
        std::cout << "  8 - Real-time Statistics\n";
    }
    
    return 0;
}
