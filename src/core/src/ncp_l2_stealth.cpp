#include "../include/ncp_l2_stealth.hpp"
#include <cstring>
#include <chrono>
#include <thread>
#include <iostream>
#include <sodium.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#ifdef HAVE_PCAP
#ifdef __linux__
#include <pcap/pcap.h>
#elif defined(_WIN32)
#include <pcap.h>
#endif
#endif

namespace ncp {

// ==================== ARP Rate Limiter ====================

class ARPRateLimiter {
public:
    ARPRateLimiter(uint32_t max_rate_per_sec)
        : max_rate_(max_rate_per_sec)
        , tokens_(max_rate_per_sec)
        , last_refill_(std::chrono::steady_clock::now()) {}

    bool allow() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refill_).count();

        // Refill tokens
        if (elapsed >= 1000) {
            tokens_ = max_rate_;
            last_refill_ = now;
        }

        if (tokens_ > 0) {
            tokens_--;
            return true;
        }
        return false;
    }

private:
    uint32_t max_rate_;
    uint32_t tokens_;
    std::chrono::steady_clock::time_point last_refill_;
};

// ==================== L2Stealth::Impl ====================

class L2Stealth::Impl {
public:
    Config config_;
    Stats* stats_ = nullptr;
    L2Stealth* parent_ = nullptr;

    std::unique_ptr<ARPRateLimiter> arp_limiter_;

#ifdef HAVE_PCAP
    pcap_t* pcap_handle_ = nullptr;
#endif

    bool initialize(const Config& cfg) {
        config_ = cfg;

        // ARP rate limiter
        if (cfg.enable_arp_rate_shaping) {
            arp_limiter_ = std::make_unique<ARPRateLimiter>(cfg.arp_max_rate_per_sec);
        }

        // Setup arptables rules (Linux)
        if (cfg.use_arptables && is_arptables_available()) {
            setup_arptables_rules();
        }

        // Setup ebtables rules (Linux)
        if (cfg.use_ebtables && is_ebtables_available()) {
            setup_ebtables_rules();
        }

        // Create VLAN interface
        if (cfg.enable_vlan_management && cfg.vlan_id > 0) {
            if (!create_vlan_interface(cfg.parent_interface, cfg.vlan_id, cfg.vlan_interface_name)) {
                parent_->log("[L2Stealth] Failed to create VLAN interface");
            }
        }

#ifdef HAVE_PCAP
        // Open pcap handle for 802.1Q injection
        if (cfg.enable_8021q_inject || cfg.enable_frame_padding || cfg.enable_mac_per_packet) {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_handle_ = pcap_open_live(cfg.parent_interface.c_str(), 65535, 1, 1000, errbuf);
            if (!pcap_handle_) {
                parent_->log("[L2Stealth] pcap_open_live failed: " + std::string(errbuf));
            } else {
                parent_->log("[L2Stealth] Pcap handle opened for " + cfg.parent_interface);
            }
        }
#endif

        return true;
    }

    void cleanup() {
#ifdef HAVE_PCAP
        if (pcap_handle_) {
            pcap_close(pcap_handle_);
            pcap_handle_ = nullptr;
        }
#endif

        // Remove arptables rules
        if (config_.use_arptables && is_arptables_available()) {
            cleanup_arptables_rules();
        }

        // Remove ebtables rules
        if (config_.use_ebtables && is_ebtables_available()) {
            cleanup_ebtables_rules();
        }

        // Delete VLAN interface
        if (config_.enable_vlan_management && !config_.vlan_interface_name.empty()) {
            delete_vlan_interface(config_.vlan_interface_name);
        }
    }

    bool process_arp_packet() {
        if (!config_.enable_arp_rate_shaping) return true;

        if (!arp_limiter_->allow()) {
            stats_->arp_packets_dropped++;
            return false; // Drop
        }

        stats_->arp_packets_shaped++;

        // Apply timing jitter
        if (config_.enable_arp_timing_jitter && config_.arp_jitter_ms > 0) {
            uint32_t jitter = randombytes_uniform(config_.arp_jitter_ms);
            std::this_thread::sleep_for(std::chrono::milliseconds(jitter));
        }

        return true; // Accept
    }

private:
    void setup_arptables_rules() {
#ifdef __linux__
        // Suppress gratuitous ARP
        if (config_.suppress_gratuitous_arp) {
            // Gratuitous ARP: sender IP == target IP
            std::string cmd = "arptables -A OUTPUT -j DROP --opcode Request --source-ip 0.0.0.0/0 --destination-ip 0.0.0.0/0";
            int ret = system(cmd.c_str());
            if (ret != 0) {
                parent_->log("[L2Stealth] Warning: arptables rule failed (may need root)");
            }
        }
#endif
    }

    void cleanup_arptables_rules() {
#ifdef __linux__
        if (config_.suppress_gratuitous_arp) {
            system("arptables -D OUTPUT -j DROP --opcode Request --source-ip 0.0.0.0/0 --destination-ip 0.0.0.0/0 2>/dev/null");
        }
#endif
    }

    void setup_ebtables_rules() {
#ifdef __linux__
        // Block LLDP (01:80:c2:00:00:0e)
        if (config_.suppress_lldp) {
            system("ebtables -A OUTPUT -d 01:80:c2:00:00:0e -j DROP 2>/dev/null");
        }

        // Block CDP (01:00:0c:cc:cc:cc)
        if (config_.suppress_cdp) {
            system("ebtables -A OUTPUT -d 01:00:0c:cc:cc:cc -j DROP 2>/dev/null");
        }

        // Block SSDP (multicast)
        if (config_.suppress_ssdp) {
            system("ebtables -A OUTPUT -p IPv4 --ip-protocol udp --ip-destination-port 1900 -j DROP 2>/dev/null");
        }
#endif
    }

    void cleanup_ebtables_rules() {
#ifdef __linux__
        if (config_.suppress_lldp) {
            system("ebtables -D OUTPUT -d 01:80:c2:00:00:0e -j DROP 2>/dev/null");
        }
        if (config_.suppress_cdp) {
            system("ebtables -D OUTPUT -d 01:00:0c:cc:cc:cc -j DROP 2>/dev/null");
        }
        if (config_.suppress_ssdp) {
            system("ebtables -D OUTPUT -p IPv4 --ip-protocol udp --ip-destination-port 1900 -j DROP 2>/dev/null");
        }
#endif
    }

    static bool is_arptables_available() {
#ifdef __linux__
        return system("which arptables >/dev/null 2>&1") == 0;
#else
        return false;
#endif
    }

    static bool is_ebtables_available() {
#ifdef __linux__
        return system("which ebtables >/dev/null 2>&1") == 0;
#else
        return false;
#endif
    }

    static bool create_vlan_interface(const std::string& parent, uint16_t vlan_id, const std::string& vlan_name) {
#ifdef __linux__
        std::string cmd = "ip link add link " + parent + " name " + vlan_name +
                          " type vlan id " + std::to_string(vlan_id);
        if (system(cmd.c_str()) != 0) return false;

        cmd = "ip link set " + vlan_name + " up";
        return system(cmd.c_str()) == 0;
#elif defined(_WIN32)
        // PowerShell: Add-NetLbfoTeamNic -Team "NIC_Team" -VlanID <id>
        // This requires LBFO (Load Balancing and Failover) NIC teaming
        std::string cmd = "powershell -Command \"Add-NetLbfoTeamNic -Team 'NIC_Team' -VlanID " +
                          std::to_string(vlan_id) + "\"";
        return system(cmd.c_str()) == 0;
#else
        return false;
#endif
    }

    static bool delete_vlan_interface(const std::string& vlan_name) {
#ifdef __linux__
        std::string cmd = "ip link delete " + vlan_name;
        return system(cmd.c_str()) == 0;
#elif defined(_WIN32)
        // PowerShell: Remove-NetLbfoTeamNic -Team "NIC_Team" -VlanID <id>
        return false; // Not implemented
#else
        return false;
#endif
    }
};

// ==================== L2Stealth Implementation ====================

L2Stealth::L2Stealth() : impl_(std::make_unique<Impl>()) {
    impl_->parent_ = this;
    impl_->stats_ = &stats_;
}

L2Stealth::~L2Stealth() {
    stop();
}

bool L2Stealth::initialize(const Config& config) {
    if (initialized_) return false;

    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;

    if (!impl_->initialize(config)) {
        return false;
    }

    initialized_ = true;
    log("[L2Stealth] Initialized");
    return true;
}

bool L2Stealth::start() {
    if (!initialized_) return false;
    if (running_) return true;

    running_ = true;
    log("[L2Stealth] Started");
    return true;
}

void L2Stealth::stop() {
    if (!running_) return;
    running_ = false;

    impl_->cleanup();
    log("[L2Stealth] Stopped");
}

bool L2Stealth::is_running() const {
    return running_.load();
}

bool L2Stealth::update_config(const Config& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
    return true;
}

L2Stealth::Config L2Stealth::get_config() const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    return config_;
}

L2Stealth::Stats L2Stealth::get_stats() const {
    return Stats(stats_);
}

void L2Stealth::reset_stats() {
    stats_.reset();
}

void L2Stealth::set_log_callback(LogCallback cb) {
    log_cb_ = cb;
}

void L2Stealth::log(const std::string& msg) {
    Config cfg;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        cfg = config_;
    }
    if (cfg.enable_logging && log_cb_) {
        log_cb_(msg);
    }
}

// ==================== Static Helpers ====================

bool L2Stealth::is_arptables_available() {
    return Impl::is_arptables_available();
}

bool L2Stealth::is_ebtables_available() {
    return Impl::is_ebtables_available();
}

bool L2Stealth::is_pcap_available() {
#ifdef HAVE_PCAP
    return true;
#else
    return false;
#endif
}

bool L2Stealth::create_vlan_interface(const std::string& parent,
                                     uint16_t vlan_id,
                                     const std::string& vlan_name) {
    return Impl::create_vlan_interface(parent, vlan_id, vlan_name);
}

bool L2Stealth::delete_vlan_interface(const std::string& vlan_name) {
    return Impl::delete_vlan_interface(vlan_name);
}

} // namespace ncp
