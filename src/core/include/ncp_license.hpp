#ifndef NCP_LICENSE_HPP
#define NCP_LICENSE_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <chrono>
#include <memory>
#include <map>
#include <functional>

namespace NCP {

class Crypto; // Forward declaration

class License {
public:
    enum class ValidationResult {
        VALID,
        INVALID_HWID,
        HWID_MISMATCH,
        EXPIRED,
        INVALID_SIGNATURE,
        INVALID_KEY,
        INVALID_FORMAT,
        FILE_NOT_FOUND,
        SERVER_ERROR,
        CORRUPTED,
        DEBUGGER_DETECTED,
        VM_DETECTED,
        TAMPERED,
        BLACKLISTED,
        RATE_LIMITED,
        REGION_BLOCKED
    };

    enum class LicenseType {
        TRIAL,
        BASIC,
        PREMIUM,
        ENTERPRISE,
        LIFETIME
    };

    enum class AntiTamperFlag {
        NONE = 0,
        CHECK_DEBUGGER = 1 << 0,
        CHECK_VM = 1 << 1,
        CHECK_INTEGRITY = 1 << 2,
        CHECK_MEMORY = 1 << 3,
        CHECK_PROCESS = 1 << 4,
        OBFUSCATE_STRINGS = 1 << 5,
        ENCRYPT_MEMORY = 1 << 6,
        ALL = 0xFF
    };

    struct LicenseInfo {
        std::string hwid;
        std::chrono::system_clock::time_point expiry_date;
        std::chrono::system_clock::time_point activation_date;
        std::string plan;
        LicenseType type;
        int days_remaining;
        int max_activations;
        int current_activations;
        bool is_valid;
        bool is_trial;
        bool is_transferable;
        std::string user_id;
        std::string machine_fingerprint;
        std::vector<std::string> features;
    };

    struct HardwareProfile {
        std::string cpu_id;
        std::string motherboard_uuid;
        std::string mac_address;
        std::string hdd_serial;
        std::string bios_serial;
        std::string system_uuid;
        uint64_t total_ram;
        std::string gpu_id;
    };

    struct AntiDebugInfo {
        bool debugger_present = false;
        bool remote_debugger = false;
        bool kernel_debugger = false;
        bool vm_detected = false;
        std::string vm_type;
        bool sandbox_detected = false;
        bool memory_tampering = false;
        bool code_integrity_failed = false;
    };

    License();
    ~License();

    // HWID Generation (multi-factor hardware fingerprinting)
    std::string get_hwid();
    HardwareProfile get_hardware_profile();
    std::string generate_machine_fingerprint();
    std::string compute_composite_hwid(const HardwareProfile& profile);

    // License Validation
    bool is_expired(const std::chrono::system_clock::time_point& expiry_date);
    ValidationResult validate_offline(
        const std::string& hwid,
        const std::string& license_file
    );
    ValidationResult validate_online(
        const std::string& hwid,
        const std::string& license_key,
        const std::string& server_url
    );
    ValidationResult validate_with_server(
        const std::string& license_key,
        const std::string& server_url,
        bool check_blacklist = true
    );

    // License Generation and Management
    bool generate_license_file(
        const std::string& hwid,
        const std::string& license_key,
        const std::chrono::system_clock::time_point& expiration_date,
        const std::string& output_file,
        LicenseType type = LicenseType::BASIC
    );
    LicenseInfo get_license_info(const std::string& license_file);
    bool activate_license(const std::string& license_key, const std::string& server_url);
    bool deactivate_license(const std::string& license_key, const std::string& server_url);
    bool transfer_license(const std::string& old_hwid, const std::string& new_hwid,
                         const std::string& server_url);

    // Anti-Tamper and Anti-Debug
    void enable_anti_tamper(uint8_t flags);
    AntiDebugInfo check_anti_debug();
    bool detect_debugger();
    bool detect_vm();
    bool detect_sandbox();
    bool check_code_integrity();
    bool check_memory_integrity();
    void obfuscate_license_data();
    
    // Runtime Protection
    void start_periodic_validation(int interval_minutes = 30);
    void stop_periodic_validation();
    bool verify_license_signature(const std::string& license_data,
                                  const std::string& signature);
    std::string encrypt_license_data(const std::string& data);
    std::string decrypt_license_data(const std::string& encrypted_data);

    // Blacklist and Rate Limiting
    bool is_hwid_blacklisted(const std::string& hwid);
    bool is_ip_rate_limited(const std::string& ip_address);
    void update_blacklist(const std::vector<std::string>& blacklisted_hwids);

    // Trial Management
    bool create_trial_license(int days, const std::string& output_file);
    bool is_trial_expired();
    int get_trial_days_remaining();
    bool has_trial_been_used(); // Persistent trial tracking

    // Feature Flags
    bool is_feature_enabled(const std::string& feature_name);
    std::vector<std::string> get_enabled_features();
    void set_feature_flag(const std::string& feature_name, bool enabled);

    // License Telemetry (anonymized)
    struct TelemetryData {
        std::chrono::system_clock::time_point last_validation;
        uint32_t validation_attempts;
        uint32_t failed_attempts;
        bool online_mode;
        std::string last_error;
    };
    TelemetryData get_telemetry() const;
    void send_telemetry(const std::string& server_url);

    // Security Callbacks
    using SecurityCallback = std::function<void(const std::string&)>;
    void set_tamper_callback(SecurityCallback callback);
    void set_expiry_callback(SecurityCallback callback);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::unique_ptr<Crypto> crypto_;
    
    // Hardware fingerprinting
    std::string get_mac_address();
    std::string get_cpu_id();
    std::string get_os_uuid();
    std::string get_motherboard_uuid();
    std::string get_hdd_serial();
    std::string get_bios_serial();
    std::string get_gpu_id();
    uint64_t get_total_ram();

    // Anti-debug implementation
    bool check_debugger_flags();
    bool check_parent_process();
    bool check_timing_attack();
    bool scan_debugger_artifacts();
    bool check_breakpoints();
    
    // VM detection implementation
    bool check_vm_registry_keys();
    bool check_vm_processes();
    bool check_vm_drivers();
    bool check_vm_mac_prefix();
    bool check_hypervisor_brand();
    
    // Code integrity
    std::string compute_code_hash();
    bool verify_code_sections();
    void protect_license_memory();
    
    // License storage
    bool store_license_securely(const std::string& data);
    std::string retrieve_secure_license();
    void clear_license_cache();
    
    // Encryption helpers
    std::vector<uint8_t> derive_key_from_hwid(const std::string& hwid);
    std::string sign_license_data(const std::string& data);
    
    // Validation cache
    struct ValidationCache {
        std::chrono::system_clock::time_point timestamp;
        ValidationResult result;
        bool valid = false;
    };
    std::map<std::string, ValidationCache> validation_cache_;
    
    // Anti-tamper state
    uint8_t anti_tamper_flags_ = 0;
    SecurityCallback tamper_callback_;
    SecurityCallback expiry_callback_;
    
    // Periodic validation
    bool periodic_validation_active_ = false;
    std::chrono::minutes validation_interval_{30};
    
    void invoke_tamper_callback(const std::string& reason);
    void schedule_next_validation();
};

// Inline operators for flags
inline uint8_t operator|(License::AntiTamperFlag a, License::AntiTamperFlag b) {
    return static_cast<uint8_t>(a) | static_cast<uint8_t>(b);
}

} // namespace NCP

#endif // NCP_LICENSE_HPP
