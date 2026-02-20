#ifndef NCP_SPOOFER_HPP
#define NCP_SPOOFER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

namespace ncp {

/**
 * @brief Network Identity Spoofer
 * @description Dynamically changes IP, IPv6, MAC and DNS with auto-restore
 */
class NetworkSpoofer {
public:
    // TCP/IP Fingerprint Profile
    struct TcpFingerprintProfile {
        std::string name;
        uint8_t ttl;
        uint16_t window_size;
        uint16_t mss;
        uint8_t window_scale;
        bool sack_permitted;
        bool df_bit;
        std::string tcp_options_order; // e.g., "MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK"
        
        // Presets
        static TcpFingerprintProfile Windows10();
        static TcpFingerprintProfile Linux5x();
        static TcpFingerprintProfile MacOS12();
    };
    
    // Configuration for spoofing behavior
    struct SpoofConfig {
        bool spoof_ipv4 = true;
        bool spoof_ipv6 = true;
        bool spoof_mac = true;
        bool spoof_dns = true;
        bool spoof_hw_info = true;
        bool enable_chaffing = false;
        
        // ==================== PHASE 1: SMBIOS / DMI Serials ====================
        bool spoof_smbios = true;              // SMBIOS/DMI spoofing
        std::string custom_board_serial;       // Empty = random
        std::string custom_system_serial;      // Empty = random
        std::string custom_system_uuid;        // Empty = random
        std::string custom_bios_vendor;        // e.g., "American Megatrends Inc."
        std::string custom_bios_version;       // e.g., "F20a"
        
        // ==================== PHASE 2: Disk Serials ====================
        bool spoof_disk_serial = true;         // Disk serial number spoofing
        std::string custom_disk_serial;        // Empty = random
        
        // ==================== PHASE 3: DHCP Client ID ====================
        bool spoof_dhcp_client_id = true;      // DHCP Option 61 spoofing
        std::string custom_dhcp_client_id;     // Empty = use spoofed MAC
        
        // ==================== PHASE 4: TCP/IP Fingerprint ====================
        bool spoof_tcp_fingerprint = false;    // TCP/IP stack fingerprint
        TcpFingerprintProfile tcp_profile;     // Default: current OS
        std::string target_os_fingerprint;     // "Windows10", "Linux", "macOS"
        
        bool spoof_mtu = false;                // MTU size spoofing
        int custom_mtu = 1500;
        
        // Rotation intervals (0 = no auto-rotation)
        int ipv4_rotation_seconds = 0;
        int ipv6_rotation_seconds = 0;
        int mac_rotation_seconds = 0;
        int dns_rotation_seconds = 0;
        int hostname_rotation_seconds = 0;
        int hw_info_rotation_seconds = 0;
        int smbios_rotation_seconds = 0;      // NEW: SMBIOS auto-rotation
        int disk_serial_rotation_seconds = 0; // NEW: Disk serial auto-rotation
        
        // Custom values (empty = generate random)
        std::string custom_ipv4;
        std::string custom_ipv6;
        std::string custom_mac;
        std::string custom_hostname;
        std::string custom_hw_serial;          // Legacy field
        std::vector<std::string> custom_dns_servers;
        
        // Stealth features
        bool hide_in_routing_table = false;
        uint8_t stealth_ttl = 128;
        
        // DNS over HTTPS providers
        std::vector<std::string> doh_servers;
        
        // Advanced anti-correlation features
        bool enable_traffic_padding = false;
        int min_padding_bytes = 0;
        int max_padding_bytes = 256;
        
        bool enable_timing_randomization = true;
        int timing_variance_percent = 20;
        
        bool coordinated_rotation = true;
        bool enable_decoy_traffic = false;
        int decoy_packets_per_minute = 10;
        
        // Advanced network behavior
        bool enable_multi_path = false;
        bool randomize_packet_order = false;
        
        // Anti-tracking features 
        bool clear_arp_cache = true;
        bool flush_dns_cache = true;
        bool reset_tcp_timestamps = true;
        
        SpoofConfig() {
            doh_servers = {
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
                "https://9.9.9.9/dns-query"
            };
        }
    };
    
    // Original network identity (saved for restore)
    struct NetworkIdentity {
        std::string interface_name;
        std::string ipv4_address;
        std::string ipv4_netmask;
        std::string ipv4_gateway;
        std::string ipv6_address;
        std::string ipv6_prefix;
        std::string mac_address;
        std::string hostname;
        std::vector<std::string> dns_servers;
        
        // Full resolv.conf backup for complete restoration
        // (preserves search/domain/options directives, not just nameservers)
        std::vector<std::string> resolv_conf_lines;
        
        // Original SMBIOS/HW identifiers
        std::string original_board_serial;
        std::string original_system_serial;
        std::string original_system_uuid;
        std::string original_disk_serial;

        // Windows: adapter registry subkey index (e.g. "0001") for MAC spoofing
        // Discovered during save_original_identity() by matching adapter GUID
        std::string adapter_reg_index;
    };
    
    // Spoof status
    struct SpoofStatus {
        bool ipv4_spoofed = false;
        bool ipv6_spoofed = false;
        bool mac_spoofed = false;
        bool dns_spoofed = false;
        bool hostname_spoofed = false;
        bool hw_info_spoofed = false;
        bool smbios_spoofed = false;
        bool disk_serial_spoofed = false;
        bool dhcp_client_id_spoofed = false;
        bool tcp_fingerprint_spoofed = false;
        
        std::string current_ipv4;
        std::string current_ipv6;
        std::string current_mac;
        std::string current_hostname;
        std::string current_hw_serial;
        std::string current_board_serial;
        std::string current_system_serial;
        std::string current_disk_serial;
        std::string current_dhcp_client_id;
        std::vector<std::string> current_dns;
        
        std::chrono::steady_clock::time_point last_ipv4_rotation;
        std::chrono::steady_clock::time_point last_ipv6_rotation;
        std::chrono::steady_clock::time_point last_mac_rotation;
        std::chrono::steady_clock::time_point last_dns_rotation;
        std::chrono::steady_clock::time_point last_hostname_rotation;
        std::chrono::steady_clock::time_point last_hw_info_rotation;
        std::chrono::steady_clock::time_point last_smbios_rotation;
        std::chrono::steady_clock::time_point last_disk_serial_rotation;
    };
    
    NetworkSpoofer();
    ~NetworkSpoofer();
    
    // Enable/disable spoofing
    bool enable(const std::string& interface_name, const SpoofConfig& config = SpoofConfig());
    bool disable();
    bool is_enabled() const { return enabled_; }
    
    // Get current status (thread-safe copy)
    SpoofStatus get_status() const {
        std::lock_guard<std::mutex> lock(mu_);
        return status_;
    }
    NetworkIdentity get_original_identity() const { return original_identity_; }
    
    // Manual rotation
    bool rotate_ipv4();
    bool rotate_ipv6();
    bool rotate_mac();
    bool rotate_dns();
    bool rotate_hostname();
    bool rotate_hw_info();
    bool rotate_smbios();
    bool rotate_disk_serial();
    bool rotate_all();
    
    // Set custom values (thread-safe)
    bool set_custom_ipv4(const std::string& ipv4);
    bool set_custom_ipv6(const std::string& ipv6);
    bool set_custom_mac(const std::string& mac);
    bool set_custom_hostname(const std::string& hostname);
    bool set_custom_hw_serial(const std::string& serial);
    bool set_custom_dns(const std::vector<std::string>& dns_servers);
    bool set_custom_smbios(const std::string& board_serial, const std::string& system_serial, const std::string& uuid);
    bool set_custom_disk_serial(const std::string& disk_serial);
    
    // Random value generators
    std::string generate_random_ipv4();
    std::string generate_random_ipv6();
    std::string generate_random_mac();
    std::string generate_random_hostname();
    std::string generate_random_hw_serial();
    std::string generate_random_board_serial();
    std::string generate_random_system_serial();
    std::string generate_random_uuid();
    std::string generate_random_disk_serial();
    
    // Callbacks for rotation events
    using RotationCallback = std::function<void(const std::string& type, const std::string& old_value, const std::string& new_value)>;
    void set_rotation_callback(RotationCallback callback) { rotation_callback_ = callback; }
    
private:
    // Platform-specific implementations
    bool save_original_identity(const std::string& interface_name);
    bool restore_original_identity();
    
    bool apply_ipv4(const std::string& ipv4);
    bool apply_ipv6(const std::string& ipv6);
    bool apply_mac(const std::string& mac);
    bool apply_dns(const std::vector<std::string>& dns_servers);
    bool apply_hostname(const std::string& hostname);
    bool apply_hw_info(const std::string& serial);
    bool apply_smbios(const std::string& board_serial, const std::string& system_serial, const std::string& uuid);
    bool apply_disk_serial(const std::string& disk_serial);
    bool apply_tcp_fingerprint(const TcpFingerprintProfile& profile);
    // Overloaded declarations matching .cpp implementations
    bool apply_smbios(const std::string& bios_vendor, const std::string& bios_version,
        const std::string& board_manufacturer, const std::string& board_product,
        const std::string& board_serial, const std::string& system_manufacturer,
        const std::string& system_product, const std::string& system_serial);
    bool apply_dhcp_client_id(const std::string& interface_name, const std::string& client_id);
    bool apply_tcp_fingerprint_impl(const TcpFingerprintProfile& profile);
    
    // Auto-rotation thread
    void rotation_thread_func();
    
    std::atomic<bool> enabled_{false};
    std::atomic<bool> rotation_running_{false};
    std::thread rotation_thread_;
    
    // FIX #49.2: Mutex protecting config_ and status_ from data races
    // between rotation_thread_func() and public API calls.
    // Must be held when reading or writing config_ or status_.
    mutable std::mutex mu_;
    
    SpoofConfig config_;            // GUARDED_BY(mu_)
    NetworkIdentity original_identity_;
    SpoofStatus status_;            // GUARDED_BY(mu_)
    
    RotationCallback rotation_callback_;
    
    // CSPRNG helpers (replaces insecure mt19937)
    static uint8_t csprng_byte();
    static uint32_t csprng_uniform(uint32_t upper_bound);
};

} // namespace ncp

#endif // NCP_SPOOFER_HPP
