#ifndef NCP_SECURITY_HPP
#define NCP_SECURITY_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <chrono>
#include <mutex>
#include <fstream>
#include <random>

namespace ncp {

/**
 * @brief Security enhancement features for NCP
 * 
 * Implements recommended security features:
 * - Certificate Pinning
 * - Latency Monitoring
 * - Traffic Padding
 * - Forensic Logging
 * - Auto Route Switching
 * - Canary Tokens
 */

// ==================== Certificate Pinning ====================

/**
 * @brief Certificate pinning for DoH servers
 */
class CertificatePinner {
public:
    struct PinnedCert {
        std::string hostname;
        std::string sha256_hash;  // Base64 encoded SHA256 of certificate
        bool is_backup;           // Backup pin for key rotation
    };

    CertificatePinner();
    ~CertificatePinner();

    // Add pinned certificates
    void add_pin(const std::string& hostname, const std::string& sha256_hash, bool is_backup = false);
    void add_pins(const std::vector<PinnedCert>& pins);
    
    // Load default pins for known DoH providers
    void load_default_pins();
    
    // Verify certificate against pins
    bool verify_certificate(const std::string& hostname, const std::string& cert_hash) const;
    
    // Get pins for hostname
    std::vector<PinnedCert> get_pins(const std::string& hostname) const;
    
    // Clear all pins
    void clear_pins();

private:
    std::vector<PinnedCert> pins_;
    mutable std::mutex mutex_;
};

// ==================== Latency Monitoring ====================

/**
 * @brief Monitor DNS query latency for anomaly detection
 */
class LatencyMonitor {
public:
    struct LatencyStats {
        uint32_t min_ms;
        uint32_t max_ms;
        uint32_t avg_ms;
        uint32_t stddev_ms;
        uint64_t sample_count;
        std::chrono::system_clock::time_point last_update;
    };

    struct LatencyAlert {
        std::string provider;
        uint32_t latency_ms;
        uint32_t threshold_ms;
        std::chrono::system_clock::time_point timestamp;
        std::string message;
    };

    using AlertCallback = std::function<void(const LatencyAlert&)>;

    LatencyMonitor(uint32_t threshold_ms = 500);
    ~LatencyMonitor();

    // Record a latency measurement
    void record_latency(const std::string& provider, uint32_t latency_ms);
    
    // Get statistics for a provider
    LatencyStats get_stats(const std::string& provider) const;
    
    // Set alert threshold
    void set_threshold(uint32_t threshold_ms);
    uint32_t get_threshold() const;
    
    // Set callback for alerts
    void set_alert_callback(AlertCallback callback);
    
    // Check if latency is anomalous
    bool is_anomalous(const std::string& provider, uint32_t latency_ms) const;
    
    // Reset statistics
    void reset_stats();

private:
    uint32_t threshold_ms_;
    std::map<std::string, std::vector<uint32_t>> latency_history_;
    AlertCallback alert_callback_;
    mutable std::mutex mutex_;
};

// ==================== Traffic Padding ====================

/**
 * @brief Add random padding to DNS queries to prevent traffic analysis
 */
class TrafficPadder {
public:
    TrafficPadder(uint32_t min_size = 128, uint32_t max_size = 512);
    ~TrafficPadder();

    // Add padding to data
    std::vector<uint8_t> add_padding(const std::vector<uint8_t>& data);
    
    // Remove padding from data
    std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& data);
    
    // Configure padding size range
    void set_padding_range(uint32_t min_size, uint32_t max_size);
    
    // Get current padding configuration
    uint32_t get_min_size() const { return min_size_; }
    uint32_t get_max_size() const { return max_size_; }

private:
    uint32_t min_size_;
    uint32_t max_size_;
    std::mt19937 rng_;
    std::mutex mutex_;
};

// ==================== Forensic Logging ====================

/**
 * @brief Secure logging for security events
 */
class ForensicLogger {
public:
    enum class EventType {
        DNS_QUERY,
        DNS_RESPONSE,
        CERTIFICATE_VERIFICATION,
        LATENCY_ALERT,
        ROUTE_SWITCH,
        CANARY_TRIGGERED,
        ERROR,
        WARNING,
        INFO
    };

    struct LogEntry {
        std::chrono::system_clock::time_point timestamp;
        EventType type;
        std::string source;
        std::string message;
        std::map<std::string, std::string> metadata;
    };

    ForensicLogger();
    explicit ForensicLogger(const std::string& log_path);
    ~ForensicLogger();

    // Log an event
    void log(EventType type, const std::string& source, const std::string& message,
             const std::map<std::string, std::string>& metadata = {});
    
    // Convenience methods
    void log_dns_query(const std::string& hostname, const std::string& provider);
    void log_dns_response(const std::string& hostname, uint32_t latency_ms, bool success);
    void log_cert_verification(const std::string& hostname, bool valid);
    void log_latency_alert(const std::string& provider, uint32_t latency_ms);
    void log_route_switch(const std::string& from_provider, const std::string& to_provider, const std::string& reason);
    void log_canary_triggered(const std::string& domain, const std::string& details);
    void log_error(const std::string& source, const std::string& message);
    void log_warning(const std::string& source, const std::string& message);
    void log_info(const std::string& source, const std::string& message);
    
    // Set log file path
    void set_log_path(const std::string& path);
    
    // Enable/disable logging
    void set_enabled(bool enabled);
    bool is_enabled() const { return enabled_; }
    
    // Flush logs to disk
    void flush();
    
    // Get recent entries
    std::vector<LogEntry> get_recent_entries(size_t count) const;

private:
    std::string log_path_;
    std::ofstream log_file_;
    std::vector<LogEntry> entries_;
    bool enabled_;
    mutable std::mutex mutex_;
    
    std::string event_type_to_string(EventType type) const;
    void write_entry(const LogEntry& entry);
};

// ==================== Auto Route Switch ====================

/**
 * @brief Automatically switch DoH providers on failure
 */
class AutoRouteSwitch {
public:
    struct ProviderStatus {
        std::string name;
        uint32_t consecutive_failures;
        uint32_t total_failures;
        uint32_t total_successes;
        bool is_active;
        std::chrono::system_clock::time_point last_failure;
        std::chrono::system_clock::time_point last_success;
    };

    using SwitchCallback = std::function<void(const std::string& from, const std::string& to, const std::string& reason)>;

    AutoRouteSwitch(uint32_t failure_threshold = 3);
    ~AutoRouteSwitch();

    // Register a provider
    void register_provider(const std::string& name, int priority = 0);
    
    // Record success/failure
    void record_success(const std::string& provider);
    void record_failure(const std::string& provider);
    
    // Get current active provider
    std::string get_active_provider() const;
    
    // Get next provider (for failover)
    std::string get_next_provider() const;
    
    // Get provider status
    ProviderStatus get_provider_status(const std::string& provider) const;
    std::vector<ProviderStatus> get_all_provider_status() const;
    
    // Set failure threshold
    void set_failure_threshold(uint32_t threshold);
    
    // Set callback for route switches
    void set_switch_callback(SwitchCallback callback);
    
    // Reset provider status
    void reset_provider(const std::string& provider);
    void reset_all();

private:
    uint32_t failure_threshold_;
    std::vector<std::pair<std::string, int>> providers_;  // name, priority
    std::map<std::string, ProviderStatus> status_;
    std::string active_provider_;
    SwitchCallback switch_callback_;
    mutable std::mutex mutex_;
    
    void check_and_switch(const std::string& failed_provider);
};

// ==================== Canary Tokens ====================

/**
 * @brief Detect traffic interception using canary domains
 */
class CanaryTokens {
public:
    struct CanaryResult {
        std::string domain;
        bool triggered;
        std::string expected_response;
        std::string actual_response;
        std::chrono::system_clock::time_point check_time;
        std::string details;
    };

    using TriggerCallback = std::function<void(const CanaryResult&)>;

    CanaryTokens();
    ~CanaryTokens();

    // Add a canary domain with expected response
    void add_canary(const std::string& domain, const std::string& expected_response);
    
    // Remove a canary
    void remove_canary(const std::string& domain);
    
    // Check a canary (returns true if NOT triggered, false if intercepted)
    CanaryResult check_canary(const std::string& domain, const std::string& actual_response);
    
    // Check all canaries
    std::vector<CanaryResult> check_all_canaries(
        std::function<std::string(const std::string&)> resolver);
    
    // Set callback for triggered canaries
    void set_trigger_callback(TriggerCallback callback);
    
    // Get list of canary domains
    std::vector<std::string> get_canary_domains() const;
    
    // Clear all canaries
    void clear_canaries();

private:
    std::map<std::string, std::string> canaries_;  // domain -> expected_response
    TriggerCallback trigger_callback_;
    mutable std::mutex mutex_;
};

// ==================== Security Manager ====================

/**
 * @brief Unified security manager combining all security features
 */
class SecurityManager {
public:
    struct Config {
        bool enable_certificate_pinning = true;
        bool enable_latency_monitoring = true;
        uint32_t latency_threshold_ms = 500;
        bool enable_traffic_padding = true;
        uint32_t min_padding_size = 128;
        uint32_t max_padding_size = 512;
        bool enable_forensic_logging = false;
        std::string forensic_log_path;
        bool enable_auto_route_switch = true;
        uint32_t route_switch_threshold = 3;
        bool enable_canary_tokens = false;
    };

    SecurityManager();
    explicit SecurityManager(const Config& config);
    ~SecurityManager();

    // Configure
    void configure(const Config& config);
    Config get_config() const;

    // Access individual components
    CertificatePinner& certificate_pinner() { return cert_pinner_; }
    LatencyMonitor& latency_monitor() { return latency_monitor_; }
    TrafficPadder& traffic_padder() { return traffic_padder_; }
    ForensicLogger& forensic_logger() { return forensic_logger_; }
    AutoRouteSwitch& auto_route_switch() { return auto_route_switch_; }
    CanaryTokens& canary_tokens() { return canary_tokens_; }

    const CertificatePinner& certificate_pinner() const { return cert_pinner_; }
    const LatencyMonitor& latency_monitor() const { return latency_monitor_; }
    const TrafficPadder& traffic_padder() const { return traffic_padder_; }
    const ForensicLogger& forensic_logger() const { return forensic_logger_; }
    const AutoRouteSwitch& auto_route_switch() const { return auto_route_switch_; }
    const CanaryTokens& canary_tokens() const { return canary_tokens_; }

private:
    Config config_;

// ===================== Anti-Forensics & Advanced Security =====================

/**
 * @brief Anti-forensics manager to prevent evidence collection
 */
class AntiForensics {
public:
    struct Config {
        bool secure_delete = true;          // Overwrite deleted files
        int overwrite_passes = 7;           // DoD 5220.22-M standard
        bool clear_memory_on_exit = true;   // Zero sensitive memory
        bool disable_core_dumps = true;     // Prevent core dumps
        bool disable_swap = false;          // Disable swap (risky)
        bool clear_temp_files = true;       // Clear temp files
        bool clear_logs = false;            // Clear application logs
    };
    
    AntiForensics();
    explicit AntiForensics(const Config& config);
    
    // Secure file operations
    bool secure_delete_file(const std::string& path);
    bool secure_delete_directory(const std::string& path);
    
    // Memory protection
    bool lock_memory(void* ptr, size_t size);     // Prevent swapping
    bool unlock_memory(void* ptr, size_t size);
    bool secure_zero_memory(void* ptr, size_t size);
    
    // Process protection
    bool disable_ptrace();                         // Prevent debugging
    bool enable_aslr();                            // Address space randomization
    bool set_process_dumpable(bool dumpable);
    
    // Cleanup
    bool clear_bash_history();
    bool clear_system_logs();
    bool clear_browser_cache();
    
private:
    Config config_;
};

/**
 * @brief System monitoring detection
 */
class MonitoringDetector {
public:
    struct ThreatInfo {
        bool debugger_detected = false;
        bool vm_detected = false;
        bool sandbox_detected = false;
        bool wireshark_detected = false;
        bool process_monitor_detected = false;
        std::vector<std::string> suspicious_processes;
    };
    
    MonitoringDetector();
    
    // Detection methods
    bool is_debugger_present();
    bool is_running_in_vm();
    bool is_running_in_sandbox();
    bool is_network_monitored();
    
    ThreatInfo scan_threats();
    
    // Evasion
    bool evade_debugger();
    bool break_on_debug();
    
private:
    bool check_debugger_linux();
    bool check_vm_artifacts();
    bool detect_wireshark();
};

/**
 * @brief Process hiding and stealth
 */
class ProcessStealth {
public:
    struct Config {
        bool hide_from_ps = false;          // Hide from process list
        bool hide_network_conns = false;    // Hide network connections
        bool fake_process_name = false;     // Masquerade as another process
        std::string fake_name = "systemd";
    };
    
    ProcessStealth();
    
    bool hide_process();
    bool unhide_process();
    
    bool hide_network_connections();
    bool set_fake_process_name(const std::string& name);
    
private:
    Config config_;
    std::string original_name_;
};


    CertificatePinner cert_pinner_;
    LatencyMonitor latency_monitor_;
    TrafficPadder traffic_padder_;
    ForensicLogger forensic_logger_;
    AutoRouteSwitch auto_route_switch_;
    CanaryTokens canary_tokens_;
};

} // namespace ncp

#endif // NCP_SECURITY_HPP
