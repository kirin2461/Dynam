#ifndef NCP_NETWORK_MANAGER_HPP
#define NCP_NETWORK_MANAGER_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <functional>

namespace ncp {

struct NetworkInterface {
    std::string name;
    std::string display_name;
    std::string description;
    std::string mac_address;
    std::string ip_address;
    bool is_up = false;
    bool is_loopback = false;
    bool is_wireless = false;
};

struct NetworkStats {
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    double upload_speed = 0.0;
    double download_speed = 0.0;
};

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();
    
    // Interface management
    std::vector<NetworkInterface> get_interfaces() const;
    NetworkInterface get_interface(const std::string& name) const;
    bool set_active_interface(const std::string& name);
    std::string get_active_interface_name() const { return active_interface_; }
    
    // Statistics
    NetworkStats get_stats() const;
    NetworkStats get_interface_stats(const std::string& name) const;
    
    // Connection testing
    bool test_connection(const std::string& host = "8.8.8.8", int port = 53);
    int get_latency(const std::string& host = "8.8.8.8");
    
    // Callbacks
    using StatsCallback = std::function<void(const NetworkStats&)>;
    void set_stats_callback(StatsCallback callback) { stats_callback_ = callback; }
    
    // Update stats (call periodically)
    void update_stats();
    
private:
    std::string active_interface_;
    NetworkStats current_stats_;
    StatsCallback stats_callback_;
    
    // Platform-specific helpers
    std::vector<NetworkInterface> enumerate_interfaces() const;
};

} // namespace ncp

#endif // NCP_NETWORK_MANAGER_HPP
