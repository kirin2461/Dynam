#pragma once

/**
 * @file ncp_identity.hpp
 * @brief IdentityRotation - Phase 7
 *
 * Periodically rotates device identity (MAC, hostname, DHCP fingerprint)
 * to prevent long-term tracking. Works with NetworkSpoofer and ARPController.
 */

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ncp {
namespace DPI {

/**
 * @brief Device identity profile for rotation
 */
struct DeviceIdentity {
    std::array<uint8_t, 6>  mac;           ///< MAC address
    std::string             hostname;      ///< DHCP hostname
    std::string             vendor;        ///< Vendor identifier
    std::vector<uint8_t>    dhcp_options;  ///< DHCP fingerprint options

    /// Built-in profiles
    static DeviceIdentity iphone15();
    static DeviceIdentity samsung_s24();
    static DeviceIdentity windows_laptop();
    static DeviceIdentity linux_desktop();
    static DeviceIdentity random_device();
};

/**
 * @brief Rotation configuration
 */
struct RotationConfig {
    uint32_t interval_sec   = 300;    ///< Rotation interval in seconds
    bool     rotate_mac     = true;   ///< Rotate MAC address
    bool     rotate_host    = true;   ///< Rotate hostname
    bool     rotate_dhcp    = true;   ///< Rotate DHCP fingerprint
    bool     keep_vendor    = true;   ///< Keep same vendor OUI prefix
    size_t   pool_size      = 10;     ///< Number of identities in rotation pool
};

/**
 * @brief Rotation statistics
 */
struct RotationStats {
    uint64_t rotations_total    = 0;  ///< Total identity rotations performed
    uint64_t mac_changes        = 0;  ///< MAC address changes
    uint64_t hostname_changes   = 0;  ///< Hostname changes
    uint64_t current_identity   = 0;  ///< Index of current identity in pool
};

/**
 * @brief Callback when identity rotates
 *
 * Called with the new identity after each rotation.
 * Use this to update ARP, DHCP, and other subsystems.
 */
using IdentityChangeCallback = std::function<void(const DeviceIdentity&)>;

/**
 * @brief IdentityRotation - periodic identity rotation manager
 *
 * Manages a pool of device identities and rotates through them
 * on a configurable schedule to prevent tracking.
 */
class IdentityRotation {
public:
    IdentityRotation();
    ~IdentityRotation();

    // Non-copyable, movable
    IdentityRotation(const IdentityRotation&) = delete;
    IdentityRotation& operator=(const IdentityRotation&) = delete;
    IdentityRotation(IdentityRotation&&) noexcept;
    IdentityRotation& operator=(IdentityRotation&&) noexcept;

    /**
     * @brief Start automatic identity rotation
     * @param config  Rotation configuration
     * @param on_change Callback when identity changes
     */
    void start(const RotationConfig& config, IdentityChangeCallback on_change);

    /**
     * @brief Stop automatic rotation
     */
    void stop();

    /**
     * @brief Check if rotation is active
     */
    bool is_running() const;

    /**
     * @brief Force an immediate identity rotation
     */
    void rotate_now();

    /**
     * @brief Get the current active identity
     */
    DeviceIdentity get_current() const;

    /**
     * @brief Add an identity to the rotation pool
     * @param identity Device identity to add
     */
    void add_identity(const DeviceIdentity& identity);

    /**
     * @brief Clear all identities from pool
     */
    void clear_pool();

    /**
     * @brief Generate a pool of random identities
     * @param count Number of identities to generate
     */
    void generate_pool(size_t count);

    /**
     * @brief Get rotation statistics
     */
    RotationStats get_stats() const;

    /**
     * @brief Reset rotation statistics
     */
    void reset_stats();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace DPI
} // namespace ncp
