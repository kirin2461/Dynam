#ifndef NCP_CONNECTION_MONITOR_HPP
#define NCP_CONNECTION_MONITOR_HPP

#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>

namespace ncp {

enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Limited,
    Error
};

struct ConnectionInfo {
    ConnectionState state = ConnectionState::Disconnected;
    std::string interface_name;
    std::string ip_address;
    std::string gateway;
    std::string dns_primary;
    std::string dns_secondary;
    int signal_strength = 0;  // For wireless
    int latency_ms = 0;
    bool internet_available = false;
};

class ConnectionMonitor {
public:
    ConnectionMonitor();
    ~ConnectionMonitor();
    
    // Start/stop monitoring
    void start(int interval_ms = 1000);
    void stop();
    bool is_running() const { return running_; }
    
    // Get current state
    ConnectionInfo get_info() const { return info_; }
    ConnectionState get_state() const { return info_.state; }
    
    // Check internet connectivity
    bool check_internet();
    int measure_latency(const std::string& host = "8.8.8.8");
    
    // Callbacks
    using StateCallback = std::function<void(ConnectionState, ConnectionState)>; // old, new
    using InfoCallback = std::function<void(const ConnectionInfo&)>;
    
    void set_state_callback(StateCallback callback) { state_callback_ = callback; }
    void set_info_callback(InfoCallback callback) { info_callback_ = callback; }
    
private:
    void monitor_thread_func();
    void update_info();
    
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    int interval_ms_ = 1000;
    
    ConnectionInfo info_;
    StateCallback state_callback_;
    InfoCallback info_callback_;
};

} // namespace ncp

#endif // NCP_CONNECTION_MONITOR_HPP
