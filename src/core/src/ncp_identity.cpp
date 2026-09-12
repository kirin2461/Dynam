/**
 * @file ncp_identity.cpp
 * @brief IdentityRotation implementation - Phase 7
 *
 * Periodic device identity rotation to prevent tracking.
 * Manages pool of identities (MAC, hostname, DHCP fingerprint).
 *
 * Phase 0.11: Replaced std::mt19937/std::shuffle with CSPRNG-based Fisher-Yates.
 */

#include "ncp_identity.hpp"
#include "ncp_csprng.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <sodium.h>
#include <thread>

namespace ncp {
namespace DPI {

// ─── DeviceIdentity factory methods ───────────────────────────────────────────

DeviceIdentity DeviceIdentity::iphone15() {
    DeviceIdentity id;
    id.mac      = {0xF0, 0x18, 0x98, 0x00, 0x00, 0x00};
    id.hostname = "iPhone";
    id.vendor   = "Apple";
    id.dhcp_options = {1, 121, 3, 6, 15, 119, 252};  // Apple DHCP fingerprint
    return id;
}

DeviceIdentity DeviceIdentity::samsung_s24() {
    DeviceIdentity id;
    id.mac      = {0x8C, 0x45, 0x00, 0x00, 0x00, 0x00};
    id.hostname = "Galaxy-S24";
    id.vendor   = "Samsung";
    id.dhcp_options = {1, 3, 6, 15, 28, 51, 58, 59};  // Samsung DHCP fingerprint
    return id;
}

DeviceIdentity DeviceIdentity::windows_laptop() {
    DeviceIdentity id;
    id.mac      = {0xDC, 0x41, 0xA9, 0x00, 0x00, 0x00};
    id.hostname = "DESKTOP-PC";
    id.vendor   = "Intel";
    id.dhcp_options = {1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 252};
    return id;
}

DeviceIdentity DeviceIdentity::linux_desktop() {
    DeviceIdentity id;
    id.mac      = {0x52, 0x54, 0x00, 0x00, 0x00, 0x00};
    id.hostname = "linux-pc";
    id.vendor   = "QEMU";
    id.dhcp_options = {1, 28, 2, 3, 15, 6, 12};
    return id;
}

DeviceIdentity DeviceIdentity::random_device() {
    // Using libsodium CSPRNG

    DeviceIdentity id;
    // Generate random MAC with locally-administered bit set
    for (auto& b : id.mac) {
        b = static_cast<uint8_t>(randombytes_uniform(256));
    }
    id.mac[0] = (id.mac[0] & 0xFC) | 0x02;  // locally administered, unicast

    // Random hostname
    static const char* prefixes[] = {"PC", "Device", "Host", "Node", "Station"};
    id.hostname = std::string(prefixes[randombytes_uniform(5)]) + "-" + std::to_string(randombytes_uniform(9000) + 1000);
    id.vendor = "Generic";
    id.dhcp_options = {1, 3, 6, 15};

    return id;
}

// ─── Impl ─────────────────────────────────────────────────────────────────────

struct IdentityRotation::Impl {
    RotationConfig                       config;
    IdentityChangeCallback               on_change;
    std::vector<DeviceIdentity>          pool;
    size_t                               current_index = 0;
    RotationStats                        stats{};

    mutable std::mutex                   mu;
    std::atomic<bool>                    running{false};
    std::thread                          worker;

    Impl() {}

    // ── Worker thread ───────────────────────────────────────────────────────
    void worker_loop() {
        auto next_rotation = std::chrono::steady_clock::now() +
                             std::chrono::seconds(config.interval_sec);

        while (running.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            auto now = std::chrono::steady_clock::now();
            if (now >= next_rotation) {
                do_rotate();
                next_rotation = now + std::chrono::seconds(config.interval_sec);
            }
        }
    }

    // ── Perform rotation ────────────────────────────────────────────────────
    //
    // This class rotates the ACTIVE IDENTITY PROFILE only. It deliberately
    // does NOT touch the operating system (no ioctl/ip-link MAC changes, no
    // sethostname) — applying the new identity to the OS is the documented
    // responsibility of the on_change consumer (NetworkSpoofer/ARPController,
    // DHCP client). Statistics below therefore count only mutations that were
    // actually performed on the identity handed to the callback.
    void do_rotate() {
        std::lock_guard<std::mutex> lock(mu);

        if (pool.empty()) return;

        // Advance to next identity (round-robin with shuffle)
        const size_t prev_index = current_index;
        current_index = (current_index + 1) % pool.size();

        DeviceIdentity& next = pool[current_index];

        // Optionally randomize the MAC of the new active identity
        if (config.rotate_mac) {
            if (config.keep_vendor) {
                // Keep OUI prefix (first 3 bytes), randomize NIC part
                for (size_t i = 3; i < 6; ++i) {
                    next.mac[i] = static_cast<uint8_t>(randombytes_uniform(256));
                }
            } else {
                // Full randomization, keeping locally-administered/unicast bits
                for (size_t i = 0; i < 6; ++i) {
                    next.mac[i] = static_cast<uint8_t>(randombytes_uniform(256));
                }
                next.mac[0] = (next.mac[0] & 0xFC) | 0x02;
            }
        }

        // Optionally rotate the hostname of the new active identity
        if (config.rotate_host) {
            static const char* prefixes[] = {"PC", "Device", "Host", "Node", "Station"};
            next.hostname = std::string(prefixes[randombytes_uniform(5)]) + "-" +
                            std::to_string(randombytes_uniform(9000) + 1000);
        }

        // Count only REAL changes: the new active identity actually differs
        // from the previously active one (or was mutated above).
        const bool mac_changed =
            config.rotate_mac ||
            (pool.size() > 1 && next.mac != pool[prev_index].mac);
        const bool host_changed =
            config.rotate_host ||
            (pool.size() > 1 && next.hostname != pool[prev_index].hostname);

        if (mac_changed) stats.mac_changes++;
        if (host_changed) stats.hostname_changes++;

        stats.rotations_total++;
        stats.current_identity = current_index;

        // Fire callback
        if (on_change) {
            on_change(next);
        }
    }
};

// ─── Constructor / Destructor ─────────────────────────────────────────────────

IdentityRotation::IdentityRotation()
    : impl_(std::make_unique<Impl>())
{}

IdentityRotation::~IdentityRotation() {
    if (impl_ && impl_->running.load()) {
        stop();
    }
}

IdentityRotation::IdentityRotation(IdentityRotation&&) noexcept = default;
IdentityRotation& IdentityRotation::operator=(IdentityRotation&&) noexcept = default;

// ─── start / stop ─────────────────────────────────────────────────────────────

void IdentityRotation::start(const RotationConfig& config,
                             IdentityChangeCallback on_change) {
    if (impl_->running.load()) stop();

    impl_->config    = config;
    impl_->on_change = std::move(on_change);

    if (impl_->pool.empty()) {
        generate_pool(config.pool_size);
    }

    impl_->running.store(true, std::memory_order_release);
    impl_->worker = std::thread([this] {
        impl_->worker_loop();
    });
}

void IdentityRotation::stop() {
    impl_->running.store(false, std::memory_order_release);
    if (impl_->worker.joinable()) {
        impl_->worker.join();
    }
}

bool IdentityRotation::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

// ─── rotate_now ───────────────────────────────────────────────────────────────

void IdentityRotation::rotate_now() {
    impl_->do_rotate();
}

// ─── get_current ──────────────────────────────────────────────────────────────

DeviceIdentity IdentityRotation::get_current() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    if (impl_->pool.empty()) {
        return DeviceIdentity::random_device();
    }
    return impl_->pool[impl_->current_index];
}

// ─── Pool management ──────────────────────────────────────────────────────────

void IdentityRotation::add_identity(const DeviceIdentity& identity) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->pool.push_back(identity);
}

void IdentityRotation::clear_pool() {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->pool.clear();
    impl_->current_index = 0;
}

void IdentityRotation::generate_pool(size_t count) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->pool.clear();

    // Add some known profiles
    if (count >= 4) {
        impl_->pool.push_back(DeviceIdentity::iphone15());
        impl_->pool.push_back(DeviceIdentity::samsung_s24());
        impl_->pool.push_back(DeviceIdentity::windows_laptop());
        impl_->pool.push_back(DeviceIdentity::linux_desktop());
    }

    // Fill rest with random
    while (impl_->pool.size() < count) {
        impl_->pool.push_back(DeviceIdentity::random_device());
    }

    // CSPRNG-based Fisher-Yates shuffle (replaces std::shuffle + mt19937)
    ncp::CSPRNG::shuffle(impl_->pool);
    impl_->current_index = 0;
}

// ─── Stats ────────────────────────────────────────────────────────────────────

RotationStats IdentityRotation::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->stats;
}

void IdentityRotation::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->stats = RotationStats{};
}

} // namespace DPI
} // namespace ncp
