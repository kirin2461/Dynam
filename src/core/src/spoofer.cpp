#include "ncp_spoofer.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <fstream>
#include <regex>
#include <array>
#include <set>
#include <vector>
#include <iostream>
#include <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#ifdef __linux__
#include <linux/if_ether.h>
#endif
#endif

namespace ncp {

// ==================== Safe Command Execution ====================
// NOTE: 'mount' removed from whitelist — it requires root and enables
// privilege escalation (e.g. mounting tmpfs over system directories).
static const std::set<std::string> ALLOWED_COMMANDS = {
    "ip", "ifconfig", "netsh", "arp", "route", "hostname", "sysctl",
    "reg", "systemctl"
};

static bool is_command_allowed(const std::string& cmd_name) {
    return ALLOWED_COMMANDS.find(cmd_name) != ALLOWED_COMMANDS.end();
}

// FIX: Also reject space characters to prevent argument injection
// on Windows where CreateProcessA concatenates args with spaces.
static bool is_safe_argument(const std::string& arg) {
    const std::string dangerous_chars = ";|&$`\"'\\<>(){}[]!#~ ";
    for (char c : arg) {
        if (dangerous_chars.find(c) != std::string::npos) {
            return false;
        }
    }
    return true;
}

static std::string execute_command_safe(const std::string& command, const std::vector<std::string>& args) {
    if (!is_command_allowed(command)) {
        return "Error: Command not allowed";
    }
    for (const auto& arg : args) {
        if (!is_safe_argument(arg)) {
            return "Error: Invalid argument detected";
        }
    }

#ifdef _WIN32
    std::string cmd_line = command;
    for (const auto& arg : args) {
        cmd_line += " " + arg;
    }
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    std::array<char, 4096> buffer;
    std::string result;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return "Error: pipe";
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    std::vector<char> cmd_buf(cmd_line.begin(), cmd_line.end());
    cmd_buf.push_back('\0');
    if (!CreateProcessA(NULL, cmd_buf.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "Error: exec";
    }
    CloseHandle(hWritePipe);
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer.data(), static_cast<DWORD>(buffer.size() - 1), &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer.data();
    }
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
#else
    int pipefd[2];
    if (pipe(pipefd) == -1) return "Error: pipe";
    pid_t pid = fork();
    if (pid == -1) { close(pipefd[0]); close(pipefd[1]); return "Error: fork"; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        std::vector<const char*> argv;
        argv.push_back(command.c_str());
        for (const auto& arg : args) argv.push_back(arg.c_str());
        argv.push_back(nullptr);
        execvp(command.c_str(), const_cast<char**>(argv.data()));
        _exit(127);
    }
    close(pipefd[1]);
    std::string result;
    std::array<char, 4096> buffer;
    ssize_t n;
    while ((n = read(pipefd[0], buffer.data(), buffer.size() - 1)) > 0) {
        buffer[n] = '\0';
        result += buffer.data();
    }
    close(pipefd[0]);
    int status;
    waitpid(pid, &status, 0);
    return result;
#endif
}

// ==================== Constructor/Destructor ====================
NetworkSpoofer::NetworkSpoofer() {}

NetworkSpoofer::~NetworkSpoofer() {
    if (enabled_) {
        disable();
    }
}

// ==================== Enable/Disable ====================
bool NetworkSpoofer::enable(const std::string& interface_name, const SpoofConfig& config) {
    if (enabled_) return false;

    // Lock: we write config_ and status_ here
    std::lock_guard<std::mutex> lock(mu_);
    config_ = config;

    if (!save_original_identity(interface_name)) return false;

    bool success = true;

    if (config_.spoof_mac) {
        std::string new_mac = config_.custom_mac.empty() ? generate_random_mac() : config_.custom_mac;
        if (apply_mac(new_mac)) {
            status_.current_mac = new_mac;
            status_.mac_spoofed = true;
            status_.last_mac_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_ipv4) {
        std::string new_ip = config_.custom_ipv4.empty() ? generate_random_ipv4() : config_.custom_ipv4;
        if (apply_ipv4(new_ip)) {
            status_.current_ipv4 = new_ip;
            status_.ipv4_spoofed = true;
            status_.last_ipv4_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_ipv6) {
        std::string new_ipv6 = config_.custom_ipv6.empty() ? generate_random_ipv6() : config_.custom_ipv6;
        if (apply_ipv6(new_ipv6)) {
            status_.current_ipv6 = new_ipv6;
            status_.ipv6_spoofed = true;
            status_.last_ipv6_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_dns && !config_.custom_dns_servers.empty()) {
        if (apply_dns(config_.custom_dns_servers)) {
            status_.current_dns = config_.custom_dns_servers;
            status_.dns_spoofed = true;
            status_.last_dns_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_hw_info) {
        std::string new_serial = config_.custom_hw_serial.empty() ? generate_random_hw_serial() : config_.custom_hw_serial;
        if (apply_hw_info(new_serial)) {
            status_.current_hw_serial = new_serial;
            status_.hw_info_spoofed = true;
            status_.last_hw_info_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    enabled_ = true;

    bool needs_rotation = (config_.ipv4_rotation_seconds > 0) ||
        (config_.ipv6_rotation_seconds > 0) || (config_.mac_rotation_seconds > 0) ||
        (config_.dns_rotation_seconds > 0) || (config_.hw_info_rotation_seconds > 0);

    if (needs_rotation || config_.enable_chaffing) {
        rotation_running_ = true;
        rotation_thread_ = std::thread(&NetworkSpoofer::rotation_thread_func, this);
    }
    return success;
}

bool NetworkSpoofer::disable() {
    if (!enabled_) return false;
    rotation_running_ = false;
    if (rotation_thread_.joinable()) rotation_thread_.join();

    std::lock_guard<std::mutex> lock(mu_);
    bool success = restore_original_identity();
    enabled_ = false;
    status_ = SpoofStatus();
    return success;
}

// ==================== Rotation Methods ====================
bool NetworkSpoofer::rotate_ipv4() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_ipv4) return false;
    std::string old_ip = status_.current_ipv4;
    std::string new_ip = generate_random_ipv4();
    if (apply_ipv4(new_ip)) {
        status_.current_ipv4 = new_ip;
        status_.last_ipv4_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("ipv4", old_ip, new_ip);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_ipv6() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_ipv6) return false;
    std::string old = status_.current_ipv6;
    std::string n = generate_random_ipv6();
    if (apply_ipv6(n)) {
        status_.current_ipv6 = n;
        status_.last_ipv6_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("ipv6", old, n);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_mac() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_mac) return false;
    std::string old = status_.current_mac;
    std::string n = generate_random_mac();
    if (apply_mac(n)) {
        status_.current_mac = n;
        status_.last_mac_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("mac", old, n);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_dns() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_dns) return false;
    // TODO: Make DNS providers configurable via SpoofConfig instead of hardcoding.
    // Hardcoded rotation between well-known providers creates a detectable fingerprint.
    std::vector<std::string> providers = {"1.1.1.1","8.8.8.8","9.9.9.9","1.0.0.1","8.8.4.4"};
    // SECURITY FIX: Use unbiased csprng_uniform for Fisher-Yates shuffle
    for (size_t i = providers.size()-1; i > 0; --i) {
        std::swap(providers[i], providers[csprng_uniform(static_cast<uint32_t>(i+1))]);
    }
    std::vector<std::string> selected = {providers[0], providers[1]};
    if (apply_dns(selected)) {
        status_.current_dns = selected;
        status_.last_dns_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("dns", "previous", selected[0]);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_hostname() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_) return false;
    std::string n = generate_random_hostname();
    if (apply_hostname(n)) {
        status_.current_hostname = n;
        status_.last_hostname_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("hostname", "previous", n);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_hw_info() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_hw_info) return false;
    std::string old = status_.current_hw_serial;
    std::string n = generate_random_hw_serial();
    if (apply_hw_info(n)) {
        status_.current_hw_serial = n;
        status_.last_hw_info_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("hw_serial", old, n);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_all() {
    // Note: each rotate_*() acquires mu_ individually to avoid
    // holding the lock during long apply_*() calls
    bool s = true;
    if (config_.spoof_ipv4) s &= rotate_ipv4();
    if (config_.spoof_ipv6) s &= rotate_ipv6();
    if (config_.spoof_mac) s &= rotate_mac();
    if (config_.spoof_dns) s &= rotate_dns();
    if (config_.spoof_hw_info) s &= rotate_hw_info();
    s &= rotate_hostname();
    return s;
}

// ==================== Generators ====================
std::string NetworkSpoofer::generate_random_ipv4() {
    std::ostringstream oss;
    oss << "10." << csprng_byte() << "." << csprng_byte() << "." << (1 + csprng_byte() % 254);
    return oss.str();
}

// FIX #49.3: Added static_cast<uint16_t> to suppress MSVC C4334 warning
// about implicit int promotion when shifting uint8_t << 8.
std::string NetworkSpoofer::generate_random_ipv6() {
    std::ostringstream oss;
    oss << "fd" << std::hex << std::setfill('0');
    for (int i = 0; i < 7; ++i)
        oss << ":" << std::setw(4)
            << static_cast<uint16_t>(csprng_byte() << 8 | csprng_byte());
    return oss.str();
}

std::string NetworkSpoofer::generate_random_mac() {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(2) << ((csprng_byte() & 0xFC) | 0x02);
    for (int i = 0; i < 5; ++i)
        oss << ":" << std::setw(2) << csprng_byte();
    return oss.str();
}

// SECURITY FIX: Use csprng_uniform(9000) for full 1000-9999 range
// Previously csprng_byte() % 9000 only produced 0-255
std::string NetworkSpoofer::generate_random_hostname() {
    std::vector<std::string> prefixes = {"PC-","WORK-","HOME-","LAPTOP-","NODE-"};
    return prefixes[csprng_uniform(static_cast<uint32_t>(prefixes.size()))]
         + std::to_string(1000 + csprng_uniform(9000));
}

std::string NetworkSpoofer::generate_random_hw_serial() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial;
    for (int i = 0; i < 12; ++i)
        serial += chars[csprng_uniform(static_cast<uint32_t>(chars.length()))];
    return serial;
}

// ==================== Setters (thread-safe) ====================
// FIX #49.2: All setters now hold mu_ to prevent data races with
// rotation_thread_func() which reads config_ fields.
bool NetworkSpoofer::set_custom_ipv4(const std::string& ipv4) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_ipv4 = ipv4;
    return true;
}
bool NetworkSpoofer::set_custom_ipv6(const std::string& ipv6) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_ipv6 = ipv6;
    return true;
}
bool NetworkSpoofer::set_custom_mac(const std::string& mac) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_mac = mac;
    return true;
}
bool NetworkSpoofer::set_custom_hostname(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_hostname = hostname;
    return true;
}
bool NetworkSpoofer::set_custom_hw_serial(const std::string& serial) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_hw_serial = serial;
    return true;
}
bool NetworkSpoofer::set_custom_dns(const std::vector<std::string>& dns_servers) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_dns_servers = dns_servers;
    return true;
}

// ==================== Rotation Thread ====================
// FIX #49.2: rotation_thread_func() now acquires mu_ before reading
// config_ intervals and status_ timestamps. The lock is released before
// calling rotate_*() methods (which acquire mu_ individually) to avoid
// holding the lock during potentially slow apply_*() system calls.
void NetworkSpoofer::rotation_thread_func() {
    while (rotation_running_) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto now = std::chrono::steady_clock::now();

            // Snapshot rotation intervals and last-rotation timestamps
            // under the lock, then decide what to rotate.
            struct RotationCheck {
                int interval;
                std::chrono::steady_clock::time_point last;
                bool due;
            };

            auto check = [&](int interval, const std::chrono::steady_clock::time_point& last) -> bool {
                if (interval > 0) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last).count();
                    return elapsed >= interval;
                }
                return false;
            };

            // We collect which rotations are due under the lock,
            // but perform them outside (they acquire mu_ themselves)
            bool do_ipv4 = check(config_.ipv4_rotation_seconds, status_.last_ipv4_rotation);
            bool do_mac  = check(config_.mac_rotation_seconds, status_.last_mac_rotation);
            bool do_dns  = check(config_.dns_rotation_seconds, status_.last_dns_rotation);
            bool do_host = check(config_.hostname_rotation_seconds, status_.last_hostname_rotation);
            bool do_hw   = check(config_.hw_info_rotation_seconds, status_.last_hw_info_rotation);

            // Release lock before calling rotate methods
            // (unlock happens at end of this scope)
            // Store flags for use after unlock
            // Actually we need to release first, so use a different pattern:
            // We'll break out and use the flags below.
            // -- restructured: unlock, then rotate --
            // Can't easily break lock_guard scope, so we store and proceed.
            // The rotate_*() methods re-acquire mu_ safely (non-recursive).
            // Since we drop the lock at scope end, this is safe.

            // Drop lock at scope end, then rotate
            // Store decisions as locals visible after scope
            if (do_ipv4) { /* will call outside */ }
            if (do_mac)  { /* will call outside */ }
            if (do_dns)  { /* will call outside */ }
            if (do_host) { /* will call outside */ }
            if (do_hw)   { /* will call outside */ }

            // Hmm, the flags are local to this block. Let's restructure:
            // We use a unique_lock instead so we can manually unlock.
        }
        // Restructured: use unique_lock pattern
        bool do_ipv4 = false, do_mac = false, do_dns = false;
        bool do_host = false, do_hw = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto now = std::chrono::steady_clock::now();
            auto elapsed_s = [&](const std::chrono::steady_clock::time_point& last) {
                return std::chrono::duration_cast<std::chrono::seconds>(now - last).count();
            };
            if (config_.ipv4_rotation_seconds > 0 &&
                elapsed_s(status_.last_ipv4_rotation) >= config_.ipv4_rotation_seconds)
                do_ipv4 = true;
            if (config_.mac_rotation_seconds > 0 &&
                elapsed_s(status_.last_mac_rotation) >= config_.mac_rotation_seconds)
                do_mac = true;
            if (config_.dns_rotation_seconds > 0 &&
                elapsed_s(status_.last_dns_rotation) >= config_.dns_rotation_seconds)
                do_dns = true;
            if (config_.hostname_rotation_seconds > 0 &&
                elapsed_s(status_.last_hostname_rotation) >= config_.hostname_rotation_seconds)
                do_host = true;
            if (config_.hw_info_rotation_seconds > 0 &&
                elapsed_s(status_.last_hw_info_rotation) >= config_.hw_info_rotation_seconds)
                do_hw = true;
        }
        // Lock released — safe to call rotate_*() which re-acquire mu_
        if (do_ipv4) rotate_ipv4();
        if (do_mac)  rotate_mac();
        if (do_dns)  rotate_dns();
        if (do_host) rotate_hostname();
        if (do_hw)   rotate_hw_info();

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ==================== Platform-specific: Save/Restore Identity ====================
bool NetworkSpoofer::save_original_identity(const std::string& interface_name) {
    original_identity_.interface_name = interface_name;
#ifdef _WIN32
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    if (!addresses) return false;
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize) != NO_ERROR) {
        free(addresses);
        return false;
    }
    for (PIP_ADAPTER_ADDRESSES addr = addresses; addr; addr = addr->Next) {
        if (interface_name == addr->AdapterName) {
            if (addr->PhysicalAddressLength > 0) {
                char mac[32];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    addr->PhysicalAddress[0], addr->PhysicalAddress[1],
                    addr->PhysicalAddress[2], addr->PhysicalAddress[3],
                    addr->PhysicalAddress[4], addr->PhysicalAddress[5]);
                original_identity_.mac_address = mac;
            }
            for (auto ua = addr->FirstUnicastAddress; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
                    original_identity_.ipv4_address = ip;
                }
            }
            break;
        }
    }
    free(addresses);

    // FIX #49.1: Discover the adapter registry subkey index for MAC spoofing.
    // Windows stores NetworkAddress under:
    //   HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-...}\00XX
    // We enumerate subkeys and match by DriverDesc or NetCfgInstanceId
    // to the adapter GUID (interface_name on Windows).
    {
        const std::string net_class_key =
            "SYSTEM\\CurrentControlSet\\Control\\Class\\"
            "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        HKEY hClassKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, net_class_key.c_str(), 0,
                          KEY_READ, &hClassKey) == ERROR_SUCCESS) {
            char subkey_name[16];
            DWORD subkey_len;
            for (DWORD idx = 0; ; ++idx) {
                subkey_len = sizeof(subkey_name);
                if (RegEnumKeyExA(hClassKey, idx, subkey_name, &subkey_len,
                                  NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
                    break;
                // Open each subkey and check NetCfgInstanceId
                HKEY hSubKey;
                std::string full_subkey = net_class_key + "\\" + subkey_name;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_subkey.c_str(), 0,
                                  KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    char instance_id[256];
                    DWORD id_len = sizeof(instance_id);
                    DWORD type = 0;
                    if (RegQueryValueExA(hSubKey, "NetCfgInstanceId", NULL,
                                         &type, (BYTE*)instance_id, &id_len) == ERROR_SUCCESS) {
                        if (interface_name == instance_id) {
                            original_identity_.adapter_reg_index = subkey_name;
                            RegCloseKey(hSubKey);
                            break;
                        }
                    }
                    RegCloseKey(hSubKey);
                }
            }
            RegCloseKey(hClassKey);
        }
    }

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0)
        original_identity_.hostname = hostname;
    return true;
#else
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
        original_identity_.ipv4_address = inet_ntoa(addr->sin_addr);
    }

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
        struct sockaddr_in* mask = (struct sockaddr_in*)&ifr.ifr_netmask;
        original_identity_.ipv4_netmask = inet_ntoa(mask->sin_addr);
    }

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        original_identity_.mac_address = mac_str;
    }
    close(fd);

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0)
        original_identity_.hostname = hostname;

    // FIX: Save ALL lines from resolv.conf, not just nameserver entries
    std::ifstream resolv("/etc/resolv.conf");
    std::string line;
    while (std::getline(resolv, line)) {
        if (line.substr(0, 11) == "nameserver ") {
            original_identity_.dns_servers.push_back(line.substr(11));
        }
        // Store full resolv.conf content for complete restoration
        original_identity_.resolv_conf_lines.push_back(line);
    }
    return true;
#endif
}

bool NetworkSpoofer::restore_original_identity() {
    bool success = true;
    const auto& id = original_identity_;
    if (status_.mac_spoofed && !id.mac_address.empty())
        success &= apply_mac(id.mac_address);
    if (status_.ipv4_spoofed && !id.ipv4_address.empty())
        success &= apply_ipv4(id.ipv4_address);
    if (status_.dns_spoofed && !id.dns_servers.empty()) {
#ifndef _WIN32
        // FIX: Restore full resolv.conf content (search/domain directives too)
        if (!id.resolv_conf_lines.empty()) {
            std::ofstream resolv("/etc/resolv.conf", std::ios::trunc);
            if (resolv.is_open()) {
                for (const auto& line : id.resolv_conf_lines) {
                    resolv << line << "\n";
                }
                resolv.close();
            } else {
                success = false;
            }
        } else {
            success &= apply_dns(id.dns_servers);
        }
#else
        success &= apply_dns(id.dns_servers);
#endif
    }
    if (status_.hostname_spoofed && !id.hostname.empty())
        success &= apply_hostname(id.hostname);
    return success;
}

// ==================== Platform-specific: Apply Functions ====================
bool NetworkSpoofer::apply_ipv4(const std::string& ipv4) {
    if (ipv4.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    std::string result = execute_command_safe("netsh", {
        "interface", "ip", "set", "address",
        "name=" + iface, "static", ipv4, "255.255.255.0"
    });
    return result.find("Error") == std::string::npos;
#else
    std::string result = execute_command_safe("ip", {
        "addr", "replace", ipv4 + "/24", "dev", iface
    });
    return result.find("Error") == std::string::npos;
#endif
}

bool NetworkSpoofer::apply_ipv6(const std::string& ipv6) {
    if (ipv6.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    std::string result = execute_command_safe("netsh", {
        "interface", "ipv6", "add", "address",
        "interface=" + iface, "address=" + ipv6
    });
    return result.find("Error") == std::string::npos;
#else
    std::string result = execute_command_safe("ip", {
        "-6", "addr", "add", ipv6 + "/64", "dev", iface
    });
    return result.find("Error") == std::string::npos;
#endif
}

// FIX #49.1: apply_mac() on Windows now writes NetworkAddress to the registry
// before disable/enable cycle. Without this step the MAC was never changed —
// the interface was just bounced with the old address.
//
// Algorithm:
//   1. Strip colons from MAC → "AABBCCDDEEFF"
//   2. Write to registry: HKLM\...\{4D36E972-...}\<adapter_index>\NetworkAddress
//   3. Disable interface via netsh
//   4. Enable interface via netsh → driver reads new MAC from registry
//
// The adapter_reg_index is discovered in save_original_identity() by matching
// the NetCfgInstanceId to the adapter GUID.
bool NetworkSpoofer::apply_mac(const std::string& mac) {
    if (mac.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    // Build MAC without colons for registry value
    std::string reg_mac;
    for (char c : mac) if (c != ':') reg_mac += c;

    // Step 1: Write NetworkAddress to the adapter's registry key
    if (!original_identity_.adapter_reg_index.empty()) {
        std::string reg_key =
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\"
            "{4D36E972-E325-11CE-BFC1-08002BE10318}\\" +
            original_identity_.adapter_reg_index;

        auto reg_result = execute_command_safe("reg", {
            "add", reg_key,
            "/v", "NetworkAddress",
            "/t", "REG_SZ",
            "/d", reg_mac,
            "/f"
        });

        if (reg_result.find("Error") != std::string::npos) {
            return false; // Registry write failed — don't bounce the interface
        }
    } else {
        // No adapter registry index found — cannot set MAC on Windows
        return false;
    }

    // Step 2: Disable interface so driver re-reads NetworkAddress
    std::string result = execute_command_safe("netsh", {
        "interface", "set", "interface", "name=" + iface, "admin=disable"
    });

    // Step 3: Re-enable interface with new MAC
    execute_command_safe("netsh", {
        "interface", "set", "interface", "name=" + iface, "admin=enable"
    });

    return result.find("Error") == std::string::npos;
#else
    execute_command_safe("ip", {"link", "set", iface, "down"});
    std::string result = execute_command_safe("ip", {
        "link", "set", iface, "address", mac
    });
    execute_command_safe("ip", {"link", "set", iface, "up"});
    return result.find("Error") == std::string::npos;
#endif
}

bool NetworkSpoofer::apply_dns(const std::vector<std::string>& dns_servers) {
    if (dns_servers.empty()) return false;
#ifdef _WIN32
    const auto& iface = original_identity_.interface_name;
    bool first = true;
    for (const auto& dns : dns_servers) {
        if (first) {
            execute_command_safe("netsh", {
                "interface", "ip", "set", "dns",
                "name=" + iface, "static", dns
            });
            first = false;
        } else {
            execute_command_safe("netsh", {
                "interface", "ip", "add", "dns",
                "name=" + iface, dns, "index=2"
            });
        }
    }
    return true;
#else
    // FIX: Preserve existing search/domain/options directives from resolv.conf
    // instead of blindly truncating the entire file.
    std::vector<std::string> preserved_lines;
    {
        std::ifstream resolv("/etc/resolv.conf");
        std::string line;
        while (std::getline(resolv, line)) {
            // Keep non-nameserver lines (search, domain, options, sortlist, comments)
            if (line.substr(0, 11) != "nameserver ") {
                preserved_lines.push_back(line);
            }
        }
    }

    std::ofstream resolv("/etc/resolv.conf", std::ios::trunc);
    if (!resolv.is_open()) return false;

    // Write back preserved directives first
    for (const auto& line : preserved_lines) {
        resolv << line << "\n";
    }
    // Then write new nameservers
    for (const auto& dns : dns_servers) {
        resolv << "nameserver " << dns << "\n";
    }
    resolv.close();
    return true;
#endif
}

bool NetworkSpoofer::apply_hostname(const std::string& hostname) {
    if (hostname.empty()) return false;
#ifdef _WIN32
    return SetComputerNameExA(ComputerNamePhysicalDnsHostname, hostname.c_str()) != 0;
#else
    if (sethostname(hostname.c_str(), hostname.length()) != 0)
        return false;
    std::ofstream hf("/etc/hostname", std::ios::trunc);
    if (hf.is_open()) {
        hf << hostname << "\n";
        hf.close();
    }
    return true;
#endif
}

bool NetworkSpoofer::apply_hw_info(const std::string& serial) {
    if (serial.empty()) return false;
#ifdef _WIN32
    return true;
#else
    std::ofstream sf("/sys/class/dmi/id/board_serial", std::ios::trunc);
    if (sf.is_open()) {
        sf << serial;
        sf.close();
        return true;
    }
    return false;
#endif
}

// ==================== TCP/IP Fingerprint Profiles ====================
NetworkSpoofer::TcpFingerprintProfile NetworkSpoofer::TcpFingerprintProfile::Windows10() {
    TcpFingerprintProfile profile;
    profile.name = "Windows 10";
    profile.ttl = 128;
    profile.window_size = 8192;
    profile.mss = 1460;
    profile.window_scale = 8;
    profile.sack_permitted = true;
    profile.df_bit = true;
    profile.tcp_options_order = "MSS,NOP,WS,NOP,NOP,TS,NOP,NOP,SACK";
    return profile;
}

NetworkSpoofer::TcpFingerprintProfile NetworkSpoofer::TcpFingerprintProfile::Linux5x() {
    TcpFingerprintProfile profile;
    profile.name = "Linux 5.x";
    profile.ttl = 64;
    profile.window_size = 29200;
    profile.mss = 1460;
    profile.window_scale = 7;
    profile.sack_permitted = true;
    profile.df_bit = true;
    profile.tcp_options_order = "MSS,SACK,TS,NOP,WS";
    return profile;
}

NetworkSpoofer::TcpFingerprintProfile NetworkSpoofer::TcpFingerprintProfile::MacOS12() {
    TcpFingerprintProfile profile;
    profile.name = "macOS 12";
    profile.ttl = 64;
    profile.window_size = 65535;
    profile.mss = 1460;
    profile.window_scale = 6;
    profile.sack_permitted = true;
    profile.df_bit = true;
    profile.tcp_options_order = "MSS,NOP,WS,NOP,NOP,TS,SACK,EOL";
    return profile;
}

// ==================== New Random Generators ====================
std::string NetworkSpoofer::generate_random_board_serial() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial = "PF";
    for (int i = 0; i < 8; ++i)
        serial += chars[csprng_uniform(static_cast<uint32_t>(chars.length()))];
    return serial;
}

std::string NetworkSpoofer::generate_random_system_serial() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial;
    for (int i = 0; i < 10; ++i)
        serial += chars[csprng_uniform(static_cast<uint32_t>(chars.length()))];
    return serial;
}

// SECURITY FIX: Readable UUID generator using randombytes_buf
std::string NetworkSpoofer::generate_random_uuid() {
    uint8_t bytes[16];
    randombytes_buf(bytes, sizeof(bytes));
    
    // Set version 4 (random) and variant 1 (RFC 4122)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;  // Version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80;  // Variant 1
    
    char uuid_str[37];
    snprintf(uuid_str, sizeof(uuid_str),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    
    return std::string(uuid_str);
}

std::string NetworkSpoofer::generate_random_disk_serial() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial = "WD-WMAYP";
    for (int i = 0; i < 7; ++i)
        serial += chars[csprng_uniform(static_cast<uint32_t>(chars.length()))];
    return serial;
}

// ==================== New Rotation Methods ====================
bool NetworkSpoofer::rotate_smbios() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_smbios) return false;
    std::string old_board = status_.current_board_serial;
    
    std::string new_board = generate_random_board_serial();
    std::string new_system = generate_random_system_serial();
    std::string new_uuid = generate_random_uuid();
    
    if (apply_smbios(new_board, new_system, new_uuid)) {
        status_.current_board_serial = new_board;
        status_.current_system_serial = new_system;
        status_.last_smbios_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("smbios", old_board, new_board);
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_disk_serial() {
    std::lock_guard<std::mutex> lock(mu_);
    if (!enabled_ || !config_.spoof_disk_serial) return false;
    std::string old = status_.current_disk_serial;
    std::string n = generate_random_disk_serial();
    if (apply_disk_serial(n)) {
        status_.current_disk_serial = n;
        status_.last_disk_serial_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) rotation_callback_("disk_serial", old, n);
        return true;
    }
    return false;
}

// ==================== New Setter Methods ====================
bool NetworkSpoofer::set_custom_smbios(const std::string& board_serial, 
                                        const std::string& system_serial, 
                                        const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_board_serial = board_serial;
    config_.custom_system_serial = system_serial;
    config_.custom_system_uuid = uuid;
    return true;
}

bool NetworkSpoofer::set_custom_disk_serial(const std::string& disk_serial) {
    std::lock_guard<std::mutex> lock(mu_);
    config_.custom_disk_serial = disk_serial;
    return true;
}

// ==================== Platform-specific: SMBIOS Spoofing (3-arg) ====================
bool NetworkSpoofer::apply_smbios(const std::string& board_serial, 
                                   const std::string& system_serial, 
                                   const std::string& uuid) {
    if (board_serial.empty() && system_serial.empty() && uuid.empty()) return false;
    
#ifdef _WIN32
    const std::string base_key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, base_key.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    bool success = true;
    
    if (!board_serial.empty()) {
        result = RegSetValueExA(hKey, "BaseBoardSerialNumber", 0, REG_SZ, 
                                (const BYTE*)board_serial.c_str(), static_cast<DWORD>(board_serial.length() + 1));
        if (result != ERROR_SUCCESS) success = false;
    }
    
    if (!system_serial.empty()) {
        result = RegSetValueExA(hKey, "SystemSerialNumber", 0, REG_SZ,
                                (const BYTE*)system_serial.c_str(), static_cast<DWORD>(system_serial.length() + 1));
        if (result != ERROR_SUCCESS) success = false;
    }
    
    if (!uuid.empty()) {
        result = RegSetValueExA(hKey, "SystemProductName", 0, REG_SZ,
                                (const BYTE*)uuid.c_str(), static_cast<DWORD>(uuid.length() + 1));
        if (result != ERROR_SUCCESS) success = false;
    }
    
    RegCloseKey(hKey);
    return success;
#else
    bool success = true;
    
    if (!board_serial.empty()) {
        std::ofstream sf("/sys/class/dmi/id/board_serial", std::ios::trunc);
        if (sf.is_open()) { sf << board_serial; sf.close(); }
        else { success = false; }
    }
    
    if (!system_serial.empty()) {
        std::ofstream sf("/sys/class/dmi/id/product_serial", std::ios::trunc);
        if (sf.is_open()) { sf << system_serial; sf.close(); }
        else { success = false; }
    }
    
    if (!uuid.empty()) {
        std::ofstream sf("/sys/class/dmi/id/product_uuid", std::ios::trunc);
        if (sf.is_open()) { sf << uuid; sf.close(); }
        else { success = false; }
    }
    
    return success;
#endif
}

// ==================== Platform-specific: SMBIOS Spoofing (8-arg, delegates to 3-arg) ====================
bool NetworkSpoofer::apply_smbios(
    [[maybe_unused]] const std::string& bios_vendor,
    [[maybe_unused]] const std::string& bios_version,
    [[maybe_unused]] const std::string& board_manufacturer,
    [[maybe_unused]] const std::string& board_product,
    const std::string& board_serial,
    [[maybe_unused]] const std::string& system_manufacturer,
    [[maybe_unused]] const std::string& system_product,
    const std::string& system_serial)
{
    std::string uuid;
    if (!config_.custom_system_uuid.empty()) {
        uuid = config_.custom_system_uuid;
    } else {
        uuid = generate_random_uuid();
    }
    return apply_smbios(board_serial, system_serial, uuid);
}

// ==================== Platform-specific: Disk Serial Spoofing ====================
bool NetworkSpoofer::apply_disk_serial(const std::string& disk_serial) {
    if (disk_serial.empty()) return false;
    
#ifdef _WIN32
    const std::string base_key = "SYSTEM\\CurrentControlSet\\Services\\disk\\Enum";
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, base_key.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    result = RegSetValueExA(hKey, "0", 0, REG_SZ, 
                            (const BYTE*)disk_serial.c_str(), static_cast<DWORD>(disk_serial.length() + 1));
    
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
#else
    return false;
#endif
}

// ==================== Platform-specific: DHCP Client ID Spoofing ====================
bool NetworkSpoofer::apply_dhcp_client_id(const std::string& interface_name, const std::string& client_id) {
    if (client_id.empty()) return false;
#ifdef _WIN32
    auto result = execute_command_safe("netsh", {"interface", "ipv4", "set", "interface", interface_name, "dhcpclientid="+client_id});
    return result.find("Error") == std::string::npos;
#else
    (void)interface_name;
    std::ofstream dhcp_conf("/etc/dhcp/dhclient.conf", std::ios::app);
    if (dhcp_conf.is_open()) {
        dhcp_conf << "\nsend dhcp-client-identifier \"" << client_id << "\";\n";
        dhcp_conf.close();
        auto result = execute_command_safe("systemctl", {"restart", "dhclient"});
        return result.find("Error") == std::string::npos;
    }
    return false;
#endif
}

// ==================== Platform-specific: TCP Fingerprint Spoofing ====================
bool NetworkSpoofer::apply_tcp_fingerprint(const TcpFingerprintProfile& profile) {
    config_.tcp_profile = profile;
    return apply_tcp_fingerprint_impl(profile);
}

bool NetworkSpoofer::apply_tcp_fingerprint_impl(const TcpFingerprintProfile& profile) {
#ifdef _WIN32
    std::string reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    auto result1 = execute_command_safe("reg", {"add", reg_path, "/v", "DefaultTTL", "/t", "REG_DWORD", "/d", std::to_string(profile.ttl), "/f"});
    auto result2 = execute_command_safe("reg", {"add", reg_path, "/v", "TcpWindowSize", "/t", "REG_DWORD", "/d", std::to_string(profile.window_size), "/f"});
    auto result3 = execute_command_safe("reg", {"add", reg_path + "\\Interfaces", "/v", "TcpMaxSegmentSize", "/t", "REG_DWORD", "/d", std::to_string(profile.mss), "/f"});
    return result1.find("Error") == std::string::npos && 
           result2.find("Error") == std::string::npos && 
           result3.find("Error") == std::string::npos;
#else
    std::ofstream("/proc/sys/net/ipv4/ip_default_ttl") << profile.ttl;
    execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_window_scaling=1"});
    execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_rmem=4096 " + std::to_string(profile.window_size) + " " + std::to_string(profile.window_size*2)});
    execute_command_safe("ip", {"link", "set", "dev", "eth0", "mtu", std::to_string(profile.mss + 40)});
    if (profile.sack_permitted) {
        execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_sack=1"});
    }
    return true;
#endif
}

// ==================== CSPRNG Implementation ====================
uint8_t NetworkSpoofer::csprng_byte() {
    uint8_t val;
    randombytes_buf(&val, sizeof(val));
    return val;
}

// SECURITY FIX: Use libsodium's randombytes_uniform for unbiased random
// Replaces manual BCrypt/urandom + modulo which had modulo bias
uint32_t NetworkSpoofer::csprng_uniform(uint32_t upper_bound) {
    if (upper_bound <= 1) return 0;
    return randombytes_uniform(upper_bound);
}

} // namespace ncp
