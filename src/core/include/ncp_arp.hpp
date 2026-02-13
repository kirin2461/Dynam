#pragma once

/**
 * @file ncp_arp.hpp
 * @brief ARPController - Phase 3
 *
 * Manages ARP cache manipulation and gratuitous ARP announcements
 * for MAC address spoofing support. Ensures the network sees
 * the spoofed MAC address as valid for the host's IP.
 */

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ncp {
namespace DPI {

/**
 * @brief MAC address type (6 bytes)
 */
using MACAddress = std::array<uint8_t, 6>;

/**
 * @brief IPv4 address type (4 bytes)
 */
using IPv4Address = std::array<uint8_t, 4>;

/**
 * @brief ARP entry representing a host on the network
 */
struct ARPEntry {
    MACAddress  mac;
    IPv4Address ip;
    bool        is_static  = false;
    uint64_t    last_seen  = 0;     ///< Timestamp of last ARP activity
    uint32_t    ttl_sec    = 300;   ///< Time to live in seconds
};

/**
 * @brief ARP statistics
 */
struct ARPStats {
    uint64_t gratuitous_sent     = 0;   ///< Gratuitous ARP packets sent
    uint64_t replies_sent        = 0;   ///< ARP reply packets sent
    uint64_t requests_received   = 0;   ///< ARP requests received
    uint64_t cache_entries       = 0;   ///< Current ARP cache entries
    uint64_t conflicts_detected  = 0;   ///< IP/MAC conflicts detected
};

/**
 * @brief ARPController - manages ARP for MAC spoofing
 *
 * Handles:
 * - Sending gratuitous ARP to announce spoofed MAC
 * - Monitoring ARP requests and replying with spoofed MAC
 * - Detecting ARP conflicts
 * - Periodic ARP announcements to maintain cache entries
 *
 * Usage:
 *   ARPController arp;
 *   arp.set_interface("eth0");
 *   arp.set_spoofed_mac({0xF0, 0x18, 0x98, 0xAA, 0xBB, 0xCC});
 *   arp.start();
 *   // ... network operations ...
 *   arp.stop();
 */
class ARPController {
public:
    ARPController();
    ~ARPController();

    // Non-copyable, movable
    ARPController(const ARPController&) = delete;
    ARPController& operator=(const ARPController&) = delete;
    ARPController(ARPController&&) noexcept;
    ARPController& operator=(ARPController&&) noexcept;

    /**
     * @brief Set the network interface to operate on
     * @param iface Interface name (e.g., "eth0", "wlan0")
     */
    void set_interface(const std::string& iface);

    /**
     * @brief Set the spoofed MAC address to announce
     * @param mac MAC address bytes
     */
    void set_spoofed_mac(const MACAddress& mac);

    /**
     * @brief Set our IP address for ARP operations
     * @param ip IPv4 address bytes
     */
    void set_ip(const IPv4Address& ip);

    /**
     * @brief Start ARP controller (background thread)
     *
     * Sends initial gratuitous ARP and starts monitoring.
     */
    void start();

    /**
     * @brief Stop ARP controller
     */
    void stop();

    /**
     * @brief Check if controller is running
     */
    bool is_running() const;

    /**
     * @brief Send a single gratuitous ARP announcement
     * @return true if sent successfully
     */
    bool send_gratuitous_arp();

    /**
     * @brief Send ARP reply to a specific target
     * @param target_mac  Target MAC address
     * @param target_ip   Target IPv4 address
     * @return true if sent successfully
     */
    bool send_arp_reply(const MACAddress& target_mac, const IPv4Address& target_ip);

    /**
     * @brief Get the current ARP cache snapshot
     * @return Vector of ARP entries
     */
    std::vector<ARPEntry> get_cache() const;

    /**
     * @brief Set the interval for periodic gratuitous ARP
     * @param interval_sec Interval in seconds (0 to disable)
     */
    void set_announce_interval(uint32_t interval_sec);

    /**
     * @brief Get ARP statistics
     */
    ARPStats get_stats() const;

    /**
     * @brief Reset ARP statistics
     */
    void reset_stats();

    /**
     * @brief Convert MAC address to string representation
     * @param mac MAC address bytes
     * @return String like "AA:BB:CC:DD:EE:FF"
     */
    static std::string mac_to_string(const MACAddress& mac);

    /**
     * @brief Parse MAC address from string
     * @param str String like "AA:BB:CC:DD:EE:FF"
     * @return MAC address bytes
     */
    static MACAddress string_to_mac(const std::string& str);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace DPI
} // namespace ncp
