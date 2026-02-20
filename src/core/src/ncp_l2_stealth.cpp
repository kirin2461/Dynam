#include "../include/ncp_l2_stealth.hpp"
#include <cstring>
#include <chrono>
#include <thread>
#include <iostream>
#include <sodium.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <cerrno>
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

// ==================== Safe exec (no shell) ====================

#ifdef __linux__
/**
 * @brief Execute a command with explicit argv, bypassing shell entirely.
 *
 * Uses fork()+execvp() — no shell metacharacter interpretation.
 * All arguments are passed as discrete C strings.
 *
 * @param argv  Null-terminated argument vector (argv[0] = binary name)
 * @return process exit code, or -1 on fork/exec failure
 */
static int safe_exec(const char* const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;  // fork failed

    if (pid == 0) {
        // Child: redirect stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(argv[0], const_cast<char* const*>(argv));
        _exit(127);  // execvp failed
    }

    // Parent: wait for child
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/**
 * @brief Validate interface name: alphanumeric, dots, hyphens only.
 *
 * Rejects any string containing shell metacharacters.
 * Max length 15 (IFNAMSIZ - 1 on Linux).
 */
static bool is_valid_ifname(const std::string& name) {
    if (name.empty() || name.size() > 15) return false;
    for (char c : name) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}
#endif // __linux__

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

    // Rollback tracking — which subsystems were successfully set up
    bool arptables_setup_ = false;
    bool ebtables_setup_ = false;
    bool vlan_created_ = false;

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
            if (!setup_arptables_rules()) {
                parent_->log("[L2Stealth] Warning: arptables setup failed");
                // Non-fatal — continue
            } else {
                arptables_setup_ = true;
            }
        }

        // Setup ebtables rules (Linux)
        if (cfg.use_ebtables && is_ebtables_available()) {
            if (!setup_ebtables_rules()) {
                parent_->log("[L2Stealth] Warning: ebtables setup failed");
                // Rollback arptables if ebtables failed
                if (arptables_setup_) {
                    cleanup_arptables_rules();
                    arptables_setup_ = false;
                }
                return false;
            }
            ebtables_setup_ = true;
        }

        // Create VLAN interface — validate names first
        if (cfg.enable_vlan_management && cfg.vlan_id > 0) {
            if (!create_vlan_interface(cfg.parent_interface, cfg.vlan_id, cfg.vlan_interface_name)) {
                parent_->log("[L2Stealth] Failed to create VLAN interface");
                // Rollback previous setup
                rollback_all();
                return false;
            }
            vlan_created_ = true;
        }

#ifdef HAVE_PCAP
        // Open pcap handle for 802.1Q injection
        if (cfg.enable_8021q_inject || cfg.enable_frame_padding || cfg.enable_mac_per_packet) {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_handle_ = pcap_open_live(cfg.parent_interface.c_str(), 65535, 1, 1000, errbuf);
            if (!pcap_handle_) {
                parent_->log("[L2Stealth] pcap_open_live failed: " + std::string(errbuf));
                rollback_all();
                return false;
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
        rollback_all();
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
    void rollback_all() {
        if (arptables_setup_) {
            cleanup_arptables_rules();
            arptables_setup_ = false;
        }
        if (ebtables_setup_) {
            cleanup_ebtables_rules();
            ebtables_setup_ = false;
        }
        if (vlan_created_ && !config_.vlan_interface_name.empty()) {
            delete_vlan_interface(config_.vlan_interface_name);
            vlan_created_ = false;
        }
    }

    bool setup_arptables_rules() {
#ifdef __linux__
        if (config_.suppress_gratuitous_arp) {
            const char* argv[] = {
                "arptables", "-A", "OUTPUT", "-j", "DROP",
                "--opcode", "Request",
                "--source-ip", "0.0.0.0/0",
                "--destination-ip", "0.0.0.0/0",
                nullptr
            };
            if (safe_exec(argv) != 0) {
                parent_->log("[L2Stealth] Warning: arptables rule failed (may need root)");
                return false;
            }
        }
        return true;
#else
        return false;
#endif
    }

    void cleanup_arptables_rules() {
#ifdef __linux__
        if (config_.suppress_gratuitous_arp) {
            const char* argv[] = {
                "arptables", "-D", "OUTPUT", "-j", "DROP",
                "--opcode", "Request",
                "--source-ip", "0.0.0.0/0",
                "--destination-ip", "0.0.0.0/0",
                nullptr
            };
            safe_exec(argv);  // best-effort, ignore return
        }
#endif
    }

    bool setup_ebtables_rules() {
#ifdef __linux__
        bool ok = true;

        // Block LLDP (01:80:c2:00:00:0e)
        if (config_.suppress_lldp) {
            const char* argv[] = {
                "ebtables", "-A", "OUTPUT",
                "-d", "01:80:c2:00:00:0e", "-j", "DROP",
                nullptr
            };
            if (safe_exec(argv) != 0) ok = false;
        }

        // Block CDP (01:00:0c:cc:cc:cc)
        if (config_.suppress_cdp) {
            const char* argv[] = {
                "ebtables", "-A", "OUTPUT",
                "-d", "01:00:0c:cc:cc:cc", "-j", "DROP",
                nullptr
            };
            if (safe_exec(argv) != 0) ok = false;
        }

        // Block SSDP (multicast UDP 1900)
        if (config_.suppress_ssdp) {
            const char* argv[] = {
                "ebtables", "-A", "OUTPUT",
                "-p", "IPv4", "--ip-protocol", "udp",
                "--ip-destination-port", "1900", "-j", "DROP",
                nullptr
            };
            if (safe_exec(argv) != 0) ok = false;
        }

        return ok;
#else
        return false;
#endif
    }

    void cleanup_ebtables_rules() {
#ifdef __linux__
        if (config_.suppress_lldp) {
            const char* argv[] = {
                "ebtables", "-D", "OUTPUT",
                "-d", "01:80:c2:00:00:0e", "-j", "DROP",
                nullptr
            };
            safe_exec(argv);
        }
        if (config_.suppress_cdp) {
            const char* argv[] = {
                "ebtables", "-D", "OUTPUT",
                "-d", "01:00:0c:cc:cc:cc", "-j", "DROP",
                nullptr
            };
            safe_exec(argv);
        }
        if (config_.suppress_ssdp) {
            const char* argv[] = {
                "ebtables", "-D", "OUTPUT",
                "-p", "IPv4", "--ip-protocol", "udp",
                "--ip-destination-port", "1900", "-j", "DROP",
                nullptr
            };
            safe_exec(argv);
        }
#endif
    }

    static bool is_arptables_available() {
#ifdef __linux__
        // access() instead of system("which ...") — no shell invocation
        return access("/usr/sbin/arptables", X_OK) == 0 ||
               access("/sbin/arptables", X_OK) == 0 ||
               access("/usr/bin/arptables", X_OK) == 0;
#else
        return false;
#endif
    }

    static bool is_ebtables_available() {
#ifdef __linux__
        return access("/usr/sbin/ebtables", X_OK) == 0 ||
               access("/sbin/ebtables", X_OK) == 0 ||
               access("/usr/bin/ebtables", X_OK) == 0;
#else
        return false;
#endif
    }

    static bool create_vlan_interface(const std::string& parent, uint16_t vlan_id, const std::string& vlan_name) {
#ifdef __linux__
        // Validate interface names — prevents command injection
        if (!is_valid_ifname(parent) || !is_valid_ifname(vlan_name)) {
            return false;
        }
        if (vlan_id == 0 || vlan_id > 4094) {
            return false;
        }

        std::string vid_str = std::to_string(vlan_id);

        const char* add_argv[] = {
            "ip", "link", "add", "link", parent.c_str(),
            "name", vlan_name.c_str(),
            "type", "vlan", "id", vid_str.c_str(),
            nullptr
        };
        if (safe_exec(add_argv) != 0) return false;

        const char* up_argv[] = {
            "ip", "link", "set", vlan_name.c_str(), "up",
            nullptr
        };
        return safe_exec(up_argv) == 0;
#elif defined(_WIN32)
        // Windows: PowerShell VLAN management
        if (vlan_id == 0 || vlan_id > 4094) return false;

        // Validate parent for safety
        for (char c : parent) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '_')) {
                return false;
            }
        }

        std::string vid_str = std::to_string(vlan_id);

        const char* argv[] = {
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "Add-NetLbfoTeamNic", "-Team", "NIC_Team",
            "-VlanID", vid_str.c_str(),
            nullptr
        };
        return safe_exec(argv) == 0;
#else
        return false;
#endif
    }

    static bool delete_vlan_interface(const std::string& vlan_name) {
#ifdef __linux__
        if (!is_valid_ifname(vlan_name)) return false;

        const char* argv[] = {
            "ip", "link", "delete", vlan_name.c_str(),
            nullptr
        };
        return safe_exec(argv) == 0;
#elif defined(_WIN32)
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
