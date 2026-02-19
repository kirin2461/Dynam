#ifndef NCP_PACKET_INTERCEPTOR_HPP
#define NCP_PACKET_INTERCEPTOR_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>

namespace ncp {

/**
 * @brief Packet Interceptor for Phase 2 L3 Stealth
 *
 * Intercepts ALL outgoing packets at kernel level via:
 *  - Linux: NFQUEUE (iptables -j NFQUEUE)
 *  - Windows: WFP (Windows Filtering Platform) callout driver
 *
 * Capabilities:
 *  - MTU enforcement (fragment packets >1500 before they leave)
 *  - Post-tunnel TTL normalization (rewrite TTL after VPN/tunnel)
 *  - GRE/IPIP/VXLAN encapsulation
 *  - Protocol obfuscation (GRE→UDP masking, XOR payload)
 *  - Integration with L3Stealth for IPID/TTL/MSS processing
 *
 * Does NOT require:
 *  - Npcap
 *  - AF_PACKET
 *  - Kernel modules (uses existing netfilter on Linux, WFP API on Windows)
 */
class PacketInterceptor {
public:
    // ==================== Backend Types ====================
    enum class Backend {
        AUTO,           // Auto-detect: NFQUEUE on Linux, WFP on Windows
        NFQUEUE,        // Linux netfilter_queue
        WFP,            // Windows Filtering Platform
        NONE            // Disabled (pass-through)
    };

    // ==================== Tunnel Protocols ====================
    enum class TunnelProtocol {
        NONE,           // No tunneling
        GRE,            // Generic Routing Encapsulation (IP protocol 47)
        IPIP,           // IP-in-IP (IP protocol 4)
        VXLAN,          // VXLAN over UDP (port 4789)
        GRE_OBFUSCATED  // GRE masked as UDP + XOR obfuscation
    };

    // ==================== Verdict for intercepted packets ====================
    enum class Verdict {
        ACCEPT,         // Accept packet as-is
        DROP,           // Drop packet
        MODIFIED,       // Accept packet with modifications
        QUEUE           // Re-queue for further processing
    };

    // ==================== Packet Handler Callback ====================
    using PacketHandler = std::function<Verdict(
        std::vector<uint8_t>& packet,  // Packet data (mutable)
        bool is_outbound               // true=outbound, false=inbound
    )>;

    // ==================== Configuration ====================
    struct Config {
        // --- Backend Selection ---
        Backend backend = Backend::AUTO;

        // --- NFQUEUE Config (Linux) ---
        uint16_t nfqueue_num = 0;           // Queue number (0-65535)
        bool nfqueue_outbound_only = true;  // Only intercept OUTPUT chain
        uint32_t nfqueue_max_len = 1024;    // Queue length

        // --- WFP Config (Windows) ---
        std::string wfp_sublayer_name = "NCP_PacketInterceptor";
        uint64_t wfp_weight = 0x8000;       // Filter weight (higher = earlier)

        // --- MTU Enforcement ---
        bool enable_mtu_enforcement = true;
        uint16_t enforce_mtu = 1500;        // Force all packets to this MTU

        // --- Post-Tunnel TTL Rewrite ---
        bool enable_post_tunnel_ttl_rewrite = true;
        uint8_t target_ttl = 64;            // Rewrite TTL to this value after tunnel

        // --- Tunneling ---
        bool enable_tunneling = false;
        TunnelProtocol tunnel_protocol = TunnelProtocol::NONE;
        std::string tunnel_remote_ip;       // Remote tunnel endpoint
        uint16_t tunnel_remote_port = 0;    // For UDP-based tunnels (VXLAN, GRE_OBFUSCATED)
        uint32_t tunnel_id = 0;             // GRE key / VXLAN VNI

        // --- Protocol Obfuscation ---
        bool enable_protocol_obfuscation = false;
        uint8_t xor_key = 0x5A;             // XOR key for payload obfuscation
        bool masquerade_as_udp = false;     // Wrap GRE in fake UDP header
        uint16_t fake_udp_src_port = 53;    // DNS-like traffic
        uint16_t fake_udp_dst_port = 53;

        // --- TUN Interface (for userspace tunneling) ---
        bool enable_tun_interface = false;
        std::string tun_interface_name = "ncp0";
        std::string tun_interface_ip = "10.255.0.1";
        std::string tun_interface_netmask = "255.255.255.0";

        // --- Integration with L3Stealth ---
        bool integrate_l3_stealth = true;   // Apply L3Stealth processing to intercepted packets

        // --- Logging ---
        bool enable_logging = false;
    };

    // ==================== Statistics ====================
    struct Stats {
        std::atomic<uint64_t> packets_intercepted{0};
        std::atomic<uint64_t> packets_modified{0};
        std::atomic<uint64_t> packets_dropped{0};
        std::atomic<uint64_t> packets_fragmented{0};
        std::atomic<uint64_t> packets_tunneled{0};
        std::atomic<uint64_t> ttl_rewrites{0};
        std::atomic<uint64_t> bytes_processed{0};

        Stats() = default;
        Stats(const Stats& o)
            : packets_intercepted(o.packets_intercepted.load())
            , packets_modified(o.packets_modified.load())
            , packets_dropped(o.packets_dropped.load())
            , packets_fragmented(o.packets_fragmented.load())
            , packets_tunneled(o.packets_tunneled.load())
            , ttl_rewrites(o.ttl_rewrites.load())
            , bytes_processed(o.bytes_processed.load()) {}

        void reset() {
            packets_intercepted.store(0);
            packets_modified.store(0);
            packets_dropped.store(0);
            packets_fragmented.store(0);
            packets_tunneled.store(0);
            ttl_rewrites.store(0);
            bytes_processed.store(0);
        }
    };

    // ==================== Lifecycle ====================
    PacketInterceptor();
    ~PacketInterceptor();

    PacketInterceptor(const PacketInterceptor&) = delete;
    PacketInterceptor& operator=(const PacketInterceptor&) = delete;

    /**
     * @brief Initialize with config.
     *
     * On Linux: Sets up NFQUEUE binding (requires root).
     * On Windows: Registers WFP filters (requires admin).
     *
     * @return true if backend initialized successfully
     */
    bool initialize(const Config& config = Config{});

    /**
     * @brief Start intercepting packets.
     *
     * Spawns worker thread to process queue.
     */
    bool start();

    /**
     * @brief Stop interception and clean up.
     */
    void stop();

    /**
     * @brief Check if currently running.
     */
    bool is_running() const;

    /**
     * @brief Update config at runtime (thread-safe).
     *
     * Some settings (like backend type) cannot be changed after start.
     */
    bool update_config(const Config& config);

    /**
     * @brief Get current config.
     */
    Config get_config() const;

    /**
     * @brief Set custom packet handler.
     *
     * Handler is called for each intercepted packet.
     * If not set, uses default handler (MTU enforcement + L3Stealth).
     */
    void set_packet_handler(PacketHandler handler);

    // ==================== Statistics ====================
    Stats get_stats() const;
    void reset_stats();

    // ==================== Logging ====================
    using LogCallback = std::function<void(const std::string&)>;
    void set_log_callback(LogCallback cb);

    // ==================== Static Helpers ====================

    /**
     * @brief Check if running with elevated privileges.
     */
    static bool is_elevated();

    /**
     * @brief Check if NFQUEUE is available (Linux only).
     */
    static bool is_nfqueue_available();

    /**
     * @brief Check if WFP is available (Windows only).
     */
    static bool is_wfp_available();

    /**
     * @brief Get recommended backend for current platform.
     */
    static Backend detect_backend();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    mutable std::mutex config_mutex_;
    Config config_;
    bool initialized_ = false;
    std::atomic<bool> running_{false};
    Stats stats_;
    LogCallback log_cb_;
    PacketHandler packet_handler_;

    void log(const std::string& msg);
    Verdict default_packet_handler(std::vector<uint8_t>& packet, bool is_outbound);
};

} // namespace ncp

#endif // NCP_PACKET_INTERCEPTOR_HPP
