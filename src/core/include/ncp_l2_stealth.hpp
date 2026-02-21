#ifndef NCP_L2_STEALTH_HPP
#define NCP_L2_STEALTH_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>

namespace ncp {

/**
 * @brief L2 Stealth - Phase 3 Anti-ISP Fingerprinting
 *
 * Covers Data Link Layer (OSI Layer 2) normalization:
 *   - ARP rate shaping & timing normalization
 *   - Gratuitous ARP suppression after MAC rotation
 *   - LLDP/CDP/SSDP suppression (prevents device fingerprinting)
 *   - System VLAN management (iproute2/PowerShell)
 *   - Optional: 802.1Q inject, frame padding, MAC per-packet (if HAVE_PCAP)
 *
 * Works WITHOUT Npcap on Windows / libpcap on Linux:
 *   - Uses arptables/ebtables for ARP/LLDP control
 *   - System VLAN via iproute2 (Linux) or PowerShell (Windows)
 *   - Graceful degradation when libpcap unavailable
 *
 * With HAVE_PCAP:
 *   - Full 802.1Q tag injection per-packet
 *   - Ethernet frame padding to fixed size
 *   - Source MAC per-packet control
 */
class L2Stealth {
public:
    // ==================== Configuration ====================
    struct Config {
        // --- ARP Normalization ---
        bool     enable_arp_rate_shaping = true;
        uint32_t arp_max_rate_per_sec    = 10;          // Max ARP packets/sec
        bool     enable_arp_timing_jitter = true;
        uint32_t arp_jitter_ms           = 50;          // Random delay 0-50ms
        bool     suppress_gratuitous_arp = true;        // Block gratuitous ARP after MAC rotation

        // --- Protocol Suppression ---
        bool suppress_lldp = true;          // Block LLDP (Link Layer Discovery Protocol)
        bool suppress_cdp  = true;          // Block CDP (Cisco Discovery Protocol)
        bool suppress_ssdp = true;          // Block SSDP (Simple Service Discovery Protocol)

        // --- VLAN Management ---
        bool        enable_vlan_management = false;
        uint16_t    vlan_id               = 0;          // VLAN ID (1-4094)
        std::string vlan_interface_name;                // e.g. "eth0.100"
        std::string parent_interface;                   // e.g. "eth0"

        // --- 802.1Q Injection (requires HAVE_PCAP) ---
        bool     enable_8021q_inject = false;
        uint16_t inject_vlan_id     = 0;
        uint8_t  inject_priority    = 0;    // 802.1p priority (0-7)

        // --- Frame Padding (requires HAVE_PCAP) ---
        bool     enable_frame_padding = false;
        uint16_t target_frame_size    = 64; // Pad to this size (min Ethernet = 64)

        // --- MAC per-packet (requires HAVE_PCAP) ---
        bool                     enable_mac_per_packet = false;
        std::vector<std::string> mac_pool;              // MAC addresses to rotate

        // --- Platform-specific ---
        bool use_arptables  = true;   // Linux: use arptables for ARP control
        bool use_ebtables   = true;   // Linux: use ebtables for L2 filtering
        bool use_powershell = false;  // Windows: use PowerShell for VLAN

        // --- Logging ---
        bool enable_logging = false;
    };

    // ==================== Statistics ====================
    struct Stats {
        std::atomic<uint64_t> arp_packets_shaped{0};
        std::atomic<uint64_t> arp_packets_dropped{0};
        std::atomic<uint64_t> lldp_packets_blocked{0};
        std::atomic<uint64_t> cdp_packets_blocked{0};
        std::atomic<uint64_t> vlan_tags_injected{0};
        std::atomic<uint64_t> frames_padded{0};
        std::atomic<uint64_t> mac_rotations{0};

        Stats() = default;
        Stats(const Stats& o)
            : arp_packets_shaped(o.arp_packets_shaped.load())
            , arp_packets_dropped(o.arp_packets_dropped.load())
            , lldp_packets_blocked(o.lldp_packets_blocked.load())
            , cdp_packets_blocked(o.cdp_packets_blocked.load())
            , vlan_tags_injected(o.vlan_tags_injected.load())
            , frames_padded(o.frames_padded.load())
            , mac_rotations(o.mac_rotations.load())
        {}

        void reset() {
            arp_packets_shaped.store(0);
            arp_packets_dropped.store(0);
            lldp_packets_blocked.store(0);
            cdp_packets_blocked.store(0);
            vlan_tags_injected.store(0);
            frames_padded.store(0);
            mac_rotations.store(0);
        }
    };

    // ==================== Lifecycle ====================
    L2Stealth();
    ~L2Stealth();
    L2Stealth(const L2Stealth&) = delete;
    L2Stealth& operator=(const L2Stealth&) = delete;

    /**
     * @brief Initialize with config.
     *
     * Sets up:
     *   - arptables rules (Linux)
     *   - ebtables rules (Linux)
     *   - VLAN interface (if enabled)
     *   - Pcap handle (if HAVE_PCAP)
     *
     * @return true if initialized successfully
     */
    bool initialize(const Config& config);
    bool initialize(); ///< Initialize with default Config

    /**
     * @brief Start L2 processing.
     */
    bool start();

    /**
     * @brief Stop and clean up.
     */
    void stop();

    /**
     * @brief Check if running.
     */
    bool is_running() const;

    /**
     * @brief Update config at runtime.
     */
    bool update_config(const Config& config);

    /**
     * @brief Get current config.
     */
    Config get_config() const;

    // ==================== Statistics ====================
    Stats get_stats() const;
    void  reset_stats();

    // ==================== Logging ====================
    using LogCallback = std::function<void(const std::string&)>;
    void set_log_callback(LogCallback cb);

    // ==================== Static Helpers ====================
    /**
     * @brief Check if arptables is available (Linux).
     */
    static bool is_arptables_available();

    /**
     * @brief Check if ebtables is available (Linux).
     */
    static bool is_ebtables_available();

    /**
     * @brief Check if libpcap is available.
     */
    static bool is_pcap_available();

    /**
     * @brief Create system VLAN interface.
     *
     * Linux: iproute2
     * Windows: PowerShell
     *
     * @param parent   Parent interface (e.g. "eth0")
     * @param vlan_id  VLAN ID (1-4094)
     * @param vlan_name VLAN interface name (e.g. "eth0.100")
     * @return true if created successfully
     */
    static bool create_vlan_interface(const std::string& parent,
                                      uint16_t vlan_id,
                                      const std::string& vlan_name);

    /**
     * @brief Delete system VLAN interface.
     */
    static bool delete_vlan_interface(const std::string& vlan_name);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    mutable std::mutex    config_mutex_;
    Config                config_;
    bool                  initialized_ = false;
    std::atomic<bool>     running_{false};
    Stats                 stats_;
    LogCallback           log_cb_;

    void log(const std::string& msg);
};

} // namespace ncp

#endif // NCP_L2_STEALTH_HPP
