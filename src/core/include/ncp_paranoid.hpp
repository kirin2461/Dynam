#ifndef NCP_PARANOID_HPP
#define NCP_PARANOID_HPP

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>
#include <map>

namespace ncp {

/**
 * @brief Paranoid Mode - Extreme Privacy and Security
 * Multi-layered anonymization with maximum protection
 */
class ParanoidMode {
public:
    enum class ThreatLevel {
        MODERATE,           // ISP surveillance
        HIGH,               // State-level monitoring
        EXTREME,            // Advanced persistent threats
        TINFOIL_HAT         // Maximum paranoia, all features enabled
    };

    struct LayeredConfig {
        // Layer 1: Entry obfuscation
        bool use_bridge_nodes = true;
        bool rotate_entry_guards = true;
        int entry_guard_lifetime_hours = 6;
        
        // Layer 2: Multiple anonymization networks
        bool enable_tor_over_i2p = true;
        bool enable_vpn_chain = false;  // VPN -> Tor -> I2P
        int vpn_chain_count = 2;
        
        // Layer 3: Traffic obfuscation
        bool enable_constant_rate_traffic = true;
        size_t cover_traffic_rate_kbps = 128;
        bool enable_traffic_morphing = true;
        bool randomize_packet_sizes = true;
        
        // Layer 4: Timing attacks prevention
        bool enable_random_delays = true;
        int min_delay_ms = 50;
        int max_delay_ms = 500;
        bool enable_batching = true;
        int batch_size = 10;
        
        // Layer 5: Metadata stripping
        bool strip_all_metadata = true;
        bool sanitize_headers = true;
        bool remove_fingerprints = true;
        
        // Layer 6: Advanced crypto
        bool enable_post_quantum_crypto = true;
        bool enable_forward_secrecy = true;
        bool enable_deniable_encryption = true;
        int rekeying_interval_minutes = 15;
        
        // Layer 7: Anti-correlation
        bool enable_traffic_splitting = true;
        bool use_multiple_circuits = true;
        int simultaneous_circuits = 3;
        bool disable_circuit_reuse = true;
        
        // Layer 8: System-level protection
        bool enable_memory_wiping = true;
        bool disable_disk_cache = true;
        bool disable_swap = true;
        bool enable_secure_delete = true;
    };

    struct NetworkIsolation {
        // Prevent leaks
        bool block_ipv6 = true;
        bool block_webrtc = true;
        bool block_local_connections = true;
        bool force_dns_over_anonymizer = true;
        
        // Network compartmentalization  
        bool isolate_per_domain = true;
        bool isolate_per_tab = true;
        bool prevent_cross_origin_leaks = true;
        
        // Kill switch
        bool enable_kill_switch = true;
        bool block_on_vpn_drop = true;
        bool block_on_tor_drop = true;
        std::vector<std::string> whitelist_ips;
    };

    struct ForensicResistance {
        // RAM protection
        bool encrypt_memory = true;
        bool clear_memory_on_exit = true;
        bool prevent_memory_dumps = true;
        
        // Disk protection
        bool use_ram_only = false;          // Run entirely from RAM
        bool encrypt_temp_files = true;
        bool secure_delete_on_exit = true;
        int overwrite_passes = 7;           // DOD 5220.22-M standard
        
        // Log protection
        bool disable_all_logging = true;
        bool encrypt_logs = true;
        bool auto_delete_logs_hours = 1;
        
        // Process protection
        bool hide_from_process_list = false; // Advanced feature
        bool prevent_screenshots = false;
        bool disable_crash_dumps = true;
    };

    struct TrafficAnalysisResistance {
        // Padding strategies
        bool enable_packet_padding = true;
        bool pad_to_fixed_size = true;
        size_t fixed_packet_size = 1500;
        
        // Timing obfuscation
        bool enable_constant_rate = true;
        bool enable_burst_suppression = true;
        bool enable_traffic_shaping = true;
        
        // Pattern disruption
        bool inject_dummy_packets = true;
        bool randomize_order = true;
        bool split_across_circuits = true;
        
        // Website fingerprinting resistance
        bool enable_wfp_defense = true;
        std::string wfp_strategy = "CS-BuFLO"; // Constant-rate Buffered Fixed-Length Obfuscator
    };

    struct AdvancedFeatures {
        // Pluggable transports
        bool use_obfs4 = true;
        bool use_meek = false;              // Domain fronting
        bool use_snowflake = false;          // Ephemeral proxies
        bool use_custom_transport = false;
        
        // Decoy routing
        bool enable_decoy_routing = false;   // TapDance, Conjure
        std::vector<std::string> decoy_destinations;
        
        // Steganography
        bool enable_steg = false;
        std::string steg_method = "none";   // "image", "audio", "video"
        
        // Deniable encryption
        bool enable_hidden_volume = false;
        std::string decoy_data_path;
    };

    ParanoidMode();
    ~ParanoidMode();

    // Configuration
    void set_threat_level(ThreatLevel level);
    ThreatLevel get_threat_level() const;
    void set_layered_config(const LayeredConfig& config);
    void set_network_isolation(const NetworkIsolation& config);
    void set_forensic_resistance(const ForensicResistance& config);
    void set_traffic_analysis_resistance(const TrafficAnalysisResistance& config);
    void set_advanced_features(const AdvancedFeatures& config);

    // Activation
    bool activate();
    bool deactivate();
    bool is_active() const;
    
    // Multi-hop configuration
    struct HopChain {
        std::vector<std::string> nodes;
        std::string entry_type;  // "bridge", "guard", "direct"
        std::string exit_type;   // "i2p", "tor", "vpn"
    };
    bool configure_hop_chain(const HopChain& chain);
    std::vector<HopChain> get_active_chains() const;
    
    // Traffic management
    void start_cover_traffic();
    void stop_cover_traffic();
    void inject_dummy_traffic(size_t bytes_per_second);
    void enable_constant_rate_shaping(size_t rate_kbps);
    
    // Circuit management
    std::string create_isolated_circuit(const std::string& destination);
    void destroy_circuit(const std::string& circuit_id);
    void rotate_all_circuits();
    void configure_circuit_isolation(bool per_domain, bool per_identity);
    
    // Metadata protection
    void strip_metadata(std::vector<uint8_t>& data);
    void sanitize_http_headers(std::map<std::string, std::string>& headers);
    void remove_browser_fingerprints();
    
    // Timing protection
    void add_random_delay();
    void enable_request_batching(int batch_size, int max_delay_ms);
    std::chrono::milliseconds calculate_safe_delay();
    
    // Forensic protection
    void enable_ram_only_mode();
    void wipe_memory_on_exit();
    void secure_delete_file(const std::string& path, int passes = 7);
    void clear_all_traces();
    
    // Emergency protocols
    void panic_mode();              // Immediately destroy all data
    void canary_trigger();          // Dead man's switch
    void set_panic_callback(std::function<void()> callback);
    
    // Monitoring and alerts
    struct SecurityAlert {
        std::string type;
        std::string description;
        std::chrono::system_clock::time_point timestamp;
        int severity;  // 1-10
    };
    std::vector<SecurityAlert> get_security_alerts() const;
    void clear_alerts();
    
    // Validation and testing
    struct SecurityAudit {
        bool dns_leak = false;
        bool ip_leak = false;
        bool webrtc_leak = false;
        bool timing_correlation_risk = false;
        bool fingerprinting_risk = false;
        std::vector<std::string> vulnerabilities;
        int security_score = 0;  // 0-100
    };
    SecurityAudit perform_security_audit();
    bool test_anonymity_set();
    double estimate_anonymity_bits();  // Entropy estimation
    
    // Statistics (anonymized)
    struct ParanoidStats {
        uint64_t circuits_created = 0;
        uint64_t circuits_destroyed = 0;
        uint64_t cover_traffic_sent = 0;
        uint64_t metadata_stripped = 0;
        std::chrono::milliseconds avg_latency{0};
        double anonymity_set_size = 0;
    };
    ParanoidStats get_statistics() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    ThreatLevel threat_level_ = ThreatLevel::HIGH;
    LayeredConfig layered_config_;
    NetworkIsolation network_isolation_;
    ForensicResistance forensic_resistance_;
    TrafficAnalysisResistance traffic_analysis_resistance_;
    AdvancedFeatures advanced_features_;
    
    bool is_active_ = false;
    std::vector<SecurityAlert> security_alerts_;
    std::function<void()> panic_callback_;
    
    // Internal methods
    void setup_bridge_nodes();
    void configure_multi_hop();
    void start_cover_traffic_generator();
    void enable_memory_protection();
    void setup_kill_switch();
    void monitor_security_threats();
    
    // Advanced protections
    void enable_traffic_morphing();
    void configure_website_fingerprinting_defense();
    void setup_decoy_routing();
    void initialize_pluggable_transports();
    
    // Forensic countermeasures
    void overwrite_memory_region(void* ptr, size_t size);
    void shred_file(const std::string& path, int passes);
    void clear_system_traces();
    
    // Emergency procedures
    void execute_panic_protocol();
    void destroy_all_evidence();
};

} // namespace ncp

#endif // NCP_PARANOID_HPP
