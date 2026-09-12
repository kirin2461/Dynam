#ifndef NCP_CONNECTION_MONITOR_HPP
#define NCP_CONNECTION_MONITOR_HPP

#include <string>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>

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
    
    // Start/stop monitoring (thread-safe: concurrent start()/stop() calls
    // are serialized; double start is a no-op)
    void start(int interval_ms = 1000);
    void stop();
    bool is_running() const { return running_; }

    // Get current state
    ConnectionInfo get_info() const {
        std::lock_guard<std::mutex> lock(info_mutex_);
        return info_;
    }
    ConnectionState get_state() const {
        std::lock_guard<std::mutex> lock(info_mutex_);
        return info_.state;
    }

    // Check internet connectivity
    bool check_internet();
    int measure_latency(const std::string& host = "8.8.8.8");

    // Callbacks
    using StateCallback = std::function<void(ConnectionState, ConnectionState)>; // old, new
    using InfoCallback = std::function<void(const ConnectionInfo&)>;

    void set_state_callback(StateCallback callback) {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        state_callback_ = std::move(callback);
    }
    void set_info_callback(InfoCallback callback) {
        std::lock_guard<std::mutex> lock(cb_mutex_);
        info_callback_ = std::move(callback);
    }

private:
    void monitor_thread_func();
    void update_info();

    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    std::atomic<int> interval_ms_{1000};  // R7-ORCH-07: atomic for thread-safe access

    // info_mutex_ guards info_ (contains std::string — not atomic-safe);
    // thread_mutex_ serializes start()/stop() and owns monitor_thread_.
    mutable std::mutex info_mutex_;
    std::mutex cb_mutex_;
    std::mutex thread_mutex_;

    ConnectionInfo info_;
    StateCallback state_callback_;
    InfoCallback info_callback_;
};

} // namespace ncp

#endif // NCP_CONNECTION_MONITOR_HPP
