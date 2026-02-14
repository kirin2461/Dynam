#ifndef NCP_NETWORK_HPP
#define NCP_NETWORK_HPP

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <chrono>

#ifdef HAVE_PCAP
// Forward declaration for pcap_t
struct pcap;
typedef struct pcap pcap_t;
#endif

namespace ncp {

#ifdef HAVE_PCAP
// Custom deleter for pcap_handle_ (moved inside namespace to avoid global namespace pollution)
struct pcap_handle_deleter {
    void operator()(pcap_t* p) const noexcept;
};
#endif

// DPI Bypass techniques enumeration
enum class BypassTechnique {
    NONE,
    TTL_MODIFICATION,
    TCP_FRAGMENTATION,
    SNI_SPOOFING,
    FAKE_PACKET,
    DISORDER,
    OBFUSCATION,
    HTTP_MIMICRY,
    TLS_MIMICRY
};

// Unified NetworkStats for use across all modules
struct NetworkStats {
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t dns_queries = 0;
    uint64_t doh_queries = 0;
    double upload_speed = 0.0;
    double download_speed = 0.0;
    std::chrono::steady_clock::time_point last_update;
};

class Network {
public:
    struct PacketInfo {
        std::vector<uint8_t> data;
        std::string source_ip;
        std::string dest_ip;
        uint16_t source_port;
        uint16_t dest_port;
        uint8_t protocol;
    };

    struct InterfaceInfo {
        std::string name;
        std::string ip_address;
        std::string mac_address;
        bool is_up;
        bool is_loopback;
    };

    struct BypassConfig {
        uint8_t ttl_value = 64;
        uint8_t retransmit_ttl = 64;
        size_t fragment_size = 8;
        size_t fragment_offset = 0;
        std::string fake_sni;
        bool split_sni = false;
        bool use_bad_checksum = false;
        bool fake_seq_number = false;
        bool spoof_source_ip = false;
        std::string custom_source_ip;
        bool disorder_enabled = false;
        int disorder_delay_ms = 0;
        bool obfuscation_enabled = false;
        uint8_t obfuscation_key = 0x55;
        bool dns_leak_protection = true;
        bool mimicry_enabled = false;
        std::string mimicry_profile = "HTTP";
    };

    struct TorConfig {
        bool enabled = false;
        std::string proxy_host = "127.0.0.1";
        uint16_t proxy_port = 9050;
        int hops = 3;
        bool use_bridges = false;
    };

    struct I2PConfig {
        bool enabled = false;
        std::string proxy_host = "127.0.0.1";
        uint16_t proxy_port = 4444;
    };

    using PacketCallback = std::function<void(const std::vector<uint8_t>&, time_t)>;

    Network();
    ~Network();

    bool set_tor_config(const TorConfig& config);
    bool is_tor_active() const;

        std::vector<InterfaceInfo> get_interfaces();
    InterfaceInfo get_interface_info(const std::string& iface_name);

    bool initialize_capture(const std::string& interface_name);
    void start_capture(PacketCallback callback, int timeout_ms = 5000);    void stop_capture();

    bool send_raw_packet(
        const std::string& dest_ip,
        const std::vector<uint8_t>& data
    );

    bool send_tcp_packet(
        const std::string& dest_ip,
        uint16_t dest_port,
        const std::vector<uint8_t>& payload,
        uint8_t flags
    );

    bool enable_bypass(BypassTechnique technique);
    void disable_bypass();
    void apply_bypass_to_packet(std::vector<uint8_t>& packet);
    void fragment_packet(std::vector<uint8_t>& packet);

    bool inject_fragmented_packets(
        const std::vector<std::vector<uint8_t>>& packets,
        int delay_ms
    );

    void set_tcp_window_size(uint16_t size);

    std::string resolve_dns(const std::string& hostname, bool use_doh);
    std::string resolve_dns_over_https(const std::string& hostname);

    std::string get_network_stats();
    NetworkStats get_stats() const;
    void reset_stats();
    std::string get_last_error() const;

private:
    bool setup_ttl_bypass();
    bool setup_fragmentation_bypass();
    bool setup_sni_spoofing();
    bool setup_fake_packet();
    bool setup_packet_disorder();
    void cleanup_bypass();

#ifdef HAVE_PCAP
    std::unique_ptr<pcap_t, pcap_handle_deleter> pcap_handle_;
#endif
    BypassTechnique current_technique_;
    BypassConfig bypass_config_;
    TorConfig tor_config_;
    bool capture_running_;
    std::thread capture_thread_;
    NetworkStats stats_;
    std::string last_error_;

    // Additional members used in implementation
    bool is_capturing_ = false;
    bool bypass_enabled_ = false;
    std::string current_interface_;
    std::function<void(const std::vector<uint8_t>&, time_t)> packet_cb_;
    mutable std::mutex mutex_;
};

} // namespace ncp

#endif // NCP_NETWORK_HPP
