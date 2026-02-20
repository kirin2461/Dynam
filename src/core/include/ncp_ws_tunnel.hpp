#pragma once
#ifdef HAVE_LIBWEBSOCKETS

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

namespace ncp {

struct WSTunnelConfig {
    std::string server_url;           // wss://relay.example.com/tunnel
    std::string path = "/";
    uint16_t local_port = 8081;       // local SOCKS5/proxy port
    std::string sni_override;         // domain fronting SNI
    bool enable_compression = false;  // permessage-deflate
    int ping_interval_sec = 30;
    int reconnect_delay_ms = 1000;
    int max_reconnect_attempts = 10;
    
    // TLS settings
    std::string ca_cert_path;
    bool verify_peer = true;
    
    // Camouflage headers
    std::string user_agent = "Mozilla/5.0";
    std::vector<std::pair<std::string, std::string>> extra_headers;
};

class WSTunnel {
public:
    WSTunnel();
    ~WSTunnel();
    
    WSTunnel(const WSTunnel&) = delete;
    WSTunnel& operator=(const WSTunnel&) = delete;
    
    bool initialize(const WSTunnelConfig& config);
    bool start();
    void stop();
    bool is_connected() const;
    
    // Send data through WS tunnel
    bool send(const uint8_t* data, size_t len);
    
    // Callback for received data
    using ReceiveCallback = std::function<void(const uint8_t*, size_t)>;
    void set_receive_callback(ReceiveCallback cb);
    
    // Callback for connection state changes
    using StateCallback = std::function<void(bool connected)>;
    void set_state_callback(StateCallback cb);
    
    struct Stats {
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t frames_sent = 0;
        uint64_t frames_received = 0;
        uint64_t reconnects = 0;
    };
    Stats get_stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ncp
#endif // HAVE_LIBWEBSOCKETS
