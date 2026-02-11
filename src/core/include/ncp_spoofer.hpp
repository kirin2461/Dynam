#ifndef NCP_SPOOFER_HPP
#define NCP_SPOOFER_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>
#include <random>

namespace NCP {

/**
 * @brief Network Identity Spoofer
 * @description Dynamically changes IP, IPv6, MAC and DNS with auto-restore
 */
class NetworkSpoofer {
public:
    // Configuration for spoofing behavior
    struct SpoofConfig {
        bool spoof_ipv4 = true;
        bool spoof_ipv6 = true;
        bool spoof_mac = true;
        bool spoof_dns = true;
        bool spoof_hw_info = true;
        bool enable_chaffing = false;
        
        // Rotation intervals (0 = no auto-rotation)
        int ipv4_rotation_seconds = 0;
        int ipv6_rotation_seconds = 0;
        int mac_rotation_seconds = 0;
        int dns_rotation_seconds = 0;
        int hostname_rotation_seconds = 0;
        int hw_info_rotation_seconds = 0;
        
        // Custom values (empty = generate random)
        std::string custom_ipv4;
        std::string custom_ipv6;
        std::string custom_mac;
        std::string custom_hostname;
        std::string custom_hw_serial;
        std::vector<std::string> custom_dns_servers;
        
        // Stealth features
        bool hide_in_routing_table = false;
        uint8_t stealth_ttl = 128;
        
        // DNS over HTTPS providers
        std::vector<std::string> doh_servers;
        
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
    };
    
    // Spoof status
    struct SpoofStatus {
        bool ipv4_spoofed = false;
        bool ipv6_spoofed = false;
        bool mac_spoofed = false;
        bool dns_spoofed = false;
        bool hostname_spoofed = false;
        bool hw_info_spoofed = false;
        
        std::string current_ipv4;
        std::string current_ipv6;
        std::string current_mac;
        std::string current_hostname;
        std::string current_hw_serial;
        std::vector<std::string> current_dns;
        
        std::chrono::steady_clock::time_point last_ipv4_rotation;
        std::chrono::steady_clock::time_point last_ipv6_rotation;
        std::chrono::steady_clock::time_point last_mac_rotation;
        std::chrono::steady_clock::time_point last_dns_rotation;
        std::chrono::steady_clock::time_point last_hostname_rotation;
        std::chrono::steady_clock::time_point last_hw_info_rotation;
    };
    
    NetworkSpoofer();
    ~NetworkSpoofer();
    
    // Enable/disable spoofing
    bool enable(const std::string& interface_name, const SpoofConfig& config = SpoofConfig());
    bool disable();
    bool is_enabled() const { return enabled_; }
    
    // Get current status
    SpoofStatus get_status() const { return status_; }
    NetworkIdentity get_original_identity() const { return original_identity_; }
    
    // Manual rotation
    bool rotate_ipv4();
    bool rotate_ipv6();
    bool rotate_mac();
    bool rotate_dns();
    bool rotate_hostname();
    bool rotate_hw_info();
    bool rotate_all();
    
    // Set custom values
    bool set_custom_ipv4(const std::string& ipv4);
    bool set_custom_ipv6(const std::string& ipv6);
    bool set_custom_mac(const std::string& mac);
    bool set_custom_hostname(const std::string& hostname);
    bool set_custom_hw_serial(const std::string& serial);
    bool set_custom_dns(const std::vector<std::string>& dns_servers);
    
    // Random value generators (instance methods, not static)
    std::string generate_random_ipv4();
    std::string generate_random_ipv6();
    std::string generate_random_mac();
    std::string generate_random_hostname();
    std::string generate_random_hw_serial();
    
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
    
    // Auto-rotation thread
    void rotation_thread_func();
    
    std::atomic<bool> enabled_{false};
    std::atomic<bool> rotation_running_{false};
    std::thread rotation_thread_;
    
    SpoofConfig config_;
    NetworkIdentity original_identity_;
    SpoofStatus status_;
    
    RotationCallback rotation_callback_;
    
    // Random number generator
    std::mt19937 rng_;
    std::uniform_int_distribution<int> dist_{0, 255};
};

} // namespace NCP

#endif // NCP_SPOOFER_HPP
