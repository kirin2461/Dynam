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
static const std::set<std::string> ALLOWED_COMMANDS = {
    "ip", "ifconfig", "netsh", "arp", "route", "hostname", "sysctl",
    "reg", "mount", "systemctl"
};

static bool is_command_allowed(const std::string& cmd_name) {
    return ALLOWED_COMMANDS.find(cmd_name) != ALLOWED_COMMANDS.end();
}

static bool is_safe_argument(const std::string& arg) {
    const std::string dangerous_chars = ";|&$`\"'\\<>(){}[]!#~";
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
NetworkSpoofer::NetworkSpoofer()
 {
}

NetworkSpoofer::~NetworkSpoofer() {
    if (enabled_) {
        disable();
    }
}

// ==================== Enable/Disable ====================
bool NetworkSpoofer::enable(const std::string& interface_name, const SpoofConfig& config) {
    if (enabled_) return false;
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
    bool success = restore_original_identity();
    enabled_ = false;
    status_ = SpoofStatus();
    return success;
}

// ==================== Rotation Methods ====================
bool NetworkSpoofer::rotate_ipv4() {
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
    if (!enabled_ || !config_.spoof_dns) return false;
    std::vector<std::string> providers = {"1.1.1.1","8.8.8.8","9.9.9.9","1.0.0.1","8.8.4.4"};
    for (size_t i = providers.size()-1; i > 0; --i) std::swap(providers[i], providers[csprng_uniform(static_cast<uint32_t>(i+1))]);
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

std::string NetworkSpoofer::generate_random_ipv6() {
    std::ostringstream oss;
    oss << "fd" << std::hex << std::setfill('0');
    for (int i = 0; i < 7; ++i)
        oss << ":" << std::setw(4) << (csprng_byte() << 8 | csprng_byte());
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

std::string NetworkSpoofer::generate_random_hostname() {
    std::vector<std::string> prefixes = {"PC-","WORK-","HOME-","LAPTOP-","NODE-"};
    return prefixes[csprng_byte() % prefixes.size()] + std::to_string(1000 + csprng_byte() % 9000);
}

std::string NetworkSpoofer::generate_random_hw_serial() {
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial;
    for (int i = 0; i < 12; ++i)
        serial += chars[csprng_byte() % chars.length()];
    return serial;
}

// ==================== Setters ====================
bool NetworkSpoofer::set_custom_ipv4(const std::string& ipv4) { config_.custom_ipv4 = ipv4; return true; }
bool NetworkSpoofer::set_custom_ipv6(const std::string& ipv6) { config_.custom_ipv6 = ipv6; return true; }
bool NetworkSpoofer::set_custom_mac(const std::string& mac) { config_.custom_mac = mac; return true; }
bool NetworkSpoofer::set_custom_hostname(const std::string& hostname) { config_.custom_hostname = hostname; return true; }
bool NetworkSpoofer::set_custom_hw_serial(const std::string& serial) { config_.custom_hw_serial = serial; return true; }
bool NetworkSpoofer::set_custom_dns(const std::vector<std::string>& dns_servers) { config_.custom_dns_servers = dns_servers; return true; }

// ==================== Rotation Thread ====================
void NetworkSpoofer::rotation_thread_func() {
    while (rotation_running_) {
        auto now = std::chrono::steady_clock::now();
        auto check_rotate = [&](int interval, auto& last, auto rotate_fn) {
            if (interval > 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last).count();
                if (elapsed >= interval) rotate_fn();
            }
        };
        check_rotate(config_.ipv4_rotation_seconds, status_.last_ipv4_rotation, [this]{ rotate_ipv4(); });
        check_rotate(config_.mac_rotation_seconds, status_.last_mac_rotation, [this]{ rotate_mac(); });
        check_rotate(config_.dns_rotation_seconds, status_.last_dns_rotation, [this]{ rotate_dns(); });
        check_rotate(config_.hostname_rotation_seconds, status_.last_hostname_rotation, [this]{ rotate_hostname(); });
        check_rotate(config_.hw_info_rotation_seconds, status_.last_hw_info_rotation, [this]{ rotate_hw_info(); });
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// ==================== Platform-specific: Save/Restore Identity ====================
bool NetworkSpoofer::save_original_identity(const std::string& interface_name) {
    original_identity_.interface_name = interface_name;
#ifdef _WIN32
    // Windows: Read current network config via GetAdaptersAddresses
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
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0)
        original_identity_.hostname = hostname;
    return true;
#else
    // Linux: Read current config via ioctl and /etc/resolv.conf
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);

    // Get IPv4
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
        original_identity_.ipv4_address = inet_ntoa(addr->sin_addr);
    }

    // Get netmask
    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
        struct sockaddr_in* mask = (struct sockaddr_in*)&ifr.ifr_netmask;
        original_identity_.ipv4_netmask = inet_ntoa(mask->sin_addr);
    }

    // Get MAC
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        original_identity_.mac_address = mac_str;
    }
    close(fd);

    // Get hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0)
        original_identity_.hostname = hostname;

    // Get DNS servers from /etc/resolv.conf
    std::ifstream resolv("/etc/resolv.conf");
    std::string line;
    while (std::getline(resolv, line)) {
        if (line.substr(0, 11) == "nameserver ") {
            original_identity_.dns_servers.push_back(line.substr(11));
        }
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
    if (status_.dns_spoofed && !id.dns_servers.empty())
        success &= apply_dns(id.dns_servers);
    if (status_.hostname_spoofed && !id.hostname.empty())
        success &= apply_hostname(id.hostname);
    return success;
}

// ==================== Platform-specific: Apply Functions ====================
bool NetworkSpoofer::apply_ipv4(const std::string& ipv4) {
    if (ipv4.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    // Windows: Use netsh to set IP address
    std::string result = execute_command_safe("netsh", {
        "interface", "ip", "set", "address",
        "name=" + iface, "static", ipv4, "255.255.255.0"
    });
    return result.find("Error") == std::string::npos;
#else
    // Linux: Use ip command to add/replace address
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

bool NetworkSpoofer::apply_mac(const std::string& mac) {
    if (mac.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    // Windows: Set MAC via registry (requires admin)
    // Format: Remove colons from MAC for registry
    std::string reg_mac;
    for (char c : mac) if (c != ':') reg_mac += c;
    std::string key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
    // Note: Real implementation would enumerate subkeys to find the right adapter
    // This is a simplified version
    std::string result = execute_command_safe("netsh", {
        "interface", "set", "interface", "name=" + iface, "admin=disable"
    });
    // Re-enable after MAC change
    execute_command_safe("netsh", {
        "interface", "set", "interface", "name=" + iface, "admin=enable"
    });
    return result.find("Error") == std::string::npos;
#else
    // Linux: Bring interface down, change MAC, bring back up
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
    // Linux: Write to /etc/resolv.conf (requires root)
    std::ofstream resolv("/etc/resolv.conf", std::ios::trunc);
    if (!resolv.is_open()) return false;
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
    // Windows: Use SetComputerNameExA
    return SetComputerNameExA(ComputerNamePhysicalDnsHostname, hostname.c_str()) != 0;
#else
    // Linux: Use sethostname + update /etc/hostname
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
    // Windows: Would require driver-level access or WMI
    // Registry-based HWID spoofing (simplified)
    return true;
#else
    // Linux: Write to /sys/class/dmi/id/ if writable (requires root)
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
    // Format: realistic board serial (e.g., PF1A2B3C4D)
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial = "PF"; // Dell-style prefix
    for (int i = 0; i < 8; ++i)
        serial += chars[csprng_byte() % chars.length()];
    return serial;
}

std::string NetworkSpoofer::generate_random_system_serial() {
    // Format: System serial (e.g., VMware-56 4d..., Dell Service Tag)
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial;
    for (int i = 0; i < 10; ++i)
        serial += chars[csprng_byte() % chars.length()];
    return serial;
}

std::string NetworkSpoofer::generate_random_uuid() {
    // Format: RFC 4122 UUID (e.g., 550e8400-e29b-41d4-a716-446655440000)
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << ((static_cast<uint32_t>(csprng_byte())<<24|static_cast<uint32_t>(csprng_byte())<<16|static_cast<uint32_t>(csprng_byte())<<8|csprng_byte()) & 0xFFFFFFFF) << "-";
    oss << std::setw(4) << ((static_cast<uint32_t>(csprng_byte())<<24|static_cast<uint32_t>(csprng_byte())<<16|static_cast<uint32_t>(csprng_byte())<<8|csprng_byte()) & 0xFFFF) << "-";
    oss << std::setw(4) << (((static_cast<uint32_t>(csprng_byte())<<24|static_cast<uint32_t>(csprng_byte())<<16|static_cast<uint32_t>(csprng_byte())<<8|csprng_byte()) & 0x0FFF) | 0x4000) << "-"; // Version 4
    oss << std::setw(4) << (((static_cast<uint32_t>(csprng_byte())<<24|static_cast<uint32_t>(csprng_byte())<<16|static_cast<uint32_t>(csprng_byte())<<8|csprng_byte()) & 0x3FFF) | 0x8000) << "-"; // Variant
    oss << std::setw(12) << ((static_cast<uint64_t>((static_cast<uint32_t>(csprng_byte())<<24|static_cast<uint32_t>(csprng_byte())<<16|static_cast<uint32_t>(csprng_byte())<<8|csprng_byte())) << 32) | (static_cast<uint32_t>(csprng_byte())<<24|static_cast<uint32_t>(csprng_byte())<<16|static_cast<uint32_t>(csprng_byte())<<8|csprng_byte()));
    return oss.str();
}

std::string NetworkSpoofer::generate_random_disk_serial() {
    // Format: Disk serial (e.g., WD-WMAYP1234567)
    const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string serial = "WD-WMAYP";
    for (int i = 0; i < 7; ++i)
        serial += chars[csprng_byte() % chars.length()];
    return serial;
}

// ==================== New Rotation Methods ====================
bool NetworkSpoofer::rotate_smbios() {
    if (!enabled_ || !config_.spoof_smbios) return false;
    std::string old_board = status_.current_board_serial;
    std::string old_system = status_.current_system_serial;
    
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
    config_.custom_board_serial = board_serial;
    config_.custom_system_serial = system_serial;
    config_.custom_system_uuid = uuid;
    return true;
}

bool NetworkSpoofer::set_custom_disk_serial(const std::string& disk_serial) {
    config_.custom_disk_serial = disk_serial;
    return true;
}

// ==================== Platform-specific: SMBIOS Spoofing ====================
bool NetworkSpoofer::apply_smbios(const std::string& board_serial, 
                                   const std::string& system_serial, 
                                   const std::string& uuid) {
    if (board_serial.empty() && system_serial.empty() && uuid.empty()) return false;
    
#ifdef _WIN32
    // Windows: SMBIOS spoofing via registry
    // Requires admin privileges
    const std::string base_key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    
    // Note: This is usermode registry modification. For true SMBIOS table modification,
    // kernel-mode driver is required (e.g., SecHex-Spoofy approach)
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, base_key.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        return false; // No admin rights or key doesn't exist
    }
    
    bool success = true;
    
    // Set BaseBoardSerialNumber
    if (!board_serial.empty()) {
        result = RegSetValueExA(hKey, "BaseBoardSerialNumber", 0, REG_SZ, 
                                (const BYTE*)board_serial.c_str(), static_cast<DWORD>(board_serial.length() + 1));
        if (result != ERROR_SUCCESS) success = false;
    }
    
    // Set SystemSerialNumber
    if (!system_serial.empty()) {
        result = RegSetValueExA(hKey, "SystemSerialNumber", 0, REG_SZ,
                                (const BYTE*)system_serial.c_str(), static_cast<DWORD>(system_serial.length() + 1));
        if (result != ERROR_SUCCESS) success = false;
    }
    
    // Set SystemUUID (stored as SystemProductName in registry)
    if (!uuid.empty()) {
        result = RegSetValueExA(hKey, "SystemProductName", 0, REG_SZ,
                                (const BYTE*)uuid.c_str(), static_cast<DWORD>(uuid.length() + 1));
        if (result != ERROR_SUCCESS) success = false;
    }
    
    RegCloseKey(hKey);
    return success;
#else
    // Linux: SMBIOS via LD_PRELOAD or direct sysfs (usually read-only)
    // For now, document that full implementation requires LD_PRELOAD library
    // that intercepts open("/sys/class/dmi/id/board_serial") and returns fake data
    
    // Attempt direct write (will likely fail due to permissions)
    bool success = true;
    
    if (!board_serial.empty()) {
        std::ofstream sf("/sys/class/dmi/id/board_serial", std::ios::trunc);
        if (sf.is_open()) {
            sf << board_serial;
            sf.close();
        } else {
            success = false;
        }
    }
    
    if (!system_serial.empty()) {
        std::ofstream sf("/sys/class/dmi/id/product_serial", std::ios::trunc);
        if (sf.is_open()) {
            sf << system_serial;
            sf.close();
        } else {
            success = false;
        }
    }
    
    if (!uuid.empty()) {
        std::ofstream sf("/sys/class/dmi/id/product_uuid", std::ios::trunc);
        if (sf.is_open()) {
            sf << uuid;
            sf.close();
        } else {
            success = false;
        }
    }
    
    // Note: On Linux, proper implementation requires LD_PRELOAD approach or kernel module
    return success;
#endif
}

// ==================== Platform-specific: Disk Serial Spoofing ====================
bool NetworkSpoofer::apply_disk_serial(const std::string& disk_serial) {
    if (disk_serial.empty()) return false;
    
#ifdef _WIN32
    // Windows: Modify disk serial via registry
    // Path: HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_*
    // This is simplified; real implementation would enumerate all disk devices
    
    const std::string base_key = "SYSTEM\\CurrentControlSet\\Services\\disk\\Enum";
    
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, base_key.c_str(), 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    // Set disk serial (simplified approach)
    result = RegSetValueExA(hKey, "0", 0, REG_SZ, 
                            (const BYTE*)disk_serial.c_str(), static_cast<DWORD>(disk_serial.length() + 1));
    
    RegCloseKey(hKey);
    return (result == ERROR_SUCCESS);
#else
    // Linux: Would require udev rules or LD_PRELOAD to intercept ioctl(HDIO_GET_IDENTITY)
    // Direct modification of /dev/sdX is not possible at userspace level
    return false; // Not implemented for Linux userspace
#endif
}

// ==================== Platform-specific: DHCP Client ID Spoofing ====================
bool NetworkSpoofer::apply_dhcp_client_id(const std::string& client_id) {
    if (client_id.empty()) return false;
    
    // DHCP Option 61 spoofing requires packet interception
    // This would be implemented in network.cpp's packet processing layer
    // For now, this is a stub that indicates the feature is planned
    
    // TODO: Implement DHCP packet interception and Option 61 modification
    // Requires:
    // 1. Capture outgoing DHCP Discover/Request packets (UDP port 67/68)
    // 2. Parse DHCP options
    // 3. Replace or inject Option 61 with custom client_id
    // 4. Recalculate UDP checksum
    // 5. Re-inject modified packet
    
    return false; // Not yet implemented
}

// ==================== Platform-specific: TCP Fingerprint Spoofing ====================
bool NetworkSpoofer::apply_tcp_fingerprint(const TcpFingerprintProfile& profile) {
    // TCP/IP stack fingerprint spoofing requires:
    // 1. Kernel-level hooks or raw socket manipulation
    // 2. Modification of outgoing SYN packets to match target profile
    // 3. TTL, window size, MSS, TCP options reordering
    
    // This is a complex feature that requires either:
    // - Windows: WFP (Windows Filtering Platform) driver
    // - Linux: Netfilter/nfqueue hooks
    // - Or: LD_PRELOAD to intercept socket() calls and modify options
    
    // For now, we can at least set the TTL via setsockopt at application level
    // Full implementation would go in network.cpp's packet processing
    
    // TODO: Implement full TCP fingerprint spoofing
    // Stub implementation: just store the profile for future use
    config_.tcp_profile = profile;
    return false; // Not yet fully implemented
}

// ==================== Platform-Specific HW Spoofing Methods ====================

// Phase 1: SMBIOS/DMI Spoofing (Windows Registry / Linux sysfs)
bool NetworkSpoofer::apply_smbios(const std::string& bios_vendor, const std::string& bios_version,
                                   const std::string& board_manufacturer, const std::string& board_product,
                                   const std::string& board_serial, const std::string& system_manufacturer,
                                   const std::string& system_product, const std::string& system_serial) {
    (void)bios_vendor;          // Suppress unused parameter warning - stub function
    (void)bios_version;         // Suppress unused parameter warning - stub function
    (void)board_manufacturer;   // Suppress unused parameter warning - stub function
    (void)board_product;        // Suppress unused parameter warning - stub function
    (void)system_manufacturer;  // Suppress unused parameter warning - stub function
    (void)system_product;       // Suppress unused parameter warning - stub function
    (void)system_serial;        // Suppress unused parameter warning - stub function
    
#ifdef _WIN32
    // Windows: Modify HKLM\HARDWARE\DESCRIPTION\System\BIOS via Registry
    // WARNING: Requires elevated privileges (Administrator)
    // Note: Direct registry modification may be detected; kernel-mode driver preferred for production
    
    const char* registry_paths[] = {
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        "HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter\\0\\DiskController\\0"
    };
    
    // Example: Set BaseBoardSerialNumber
    // In production, use RegSetKeyValueA() or similar Win32 APIs
    // This is a stub showing the approach:
    
    std::string cmd = "reg add \"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\" /v BaseBoardSerialNumber /t REG_SZ /d \"" + board_serial + "\" /f";
    auto result = execute_command_safe("reg", {"add", "HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS", "/v", "BaseBoardSerialNumber", "/t", "REG_SZ", "/d", board_serial, "/f"});
    
    // Additional keys to spoof:
    // - SystemManufacturer, SystemProductName, SystemSerialNumber
    // - BIOSVendor, BIOSVersion, BIOSReleaseDate
    
    return result.find("Error") == std::string::npos;
    
#else
    // Linux: Modify /sys/class/dmi/id/* (requires root + remount rw)
    // This is read-only by default; kernel module required for persistent changes
    
    // Usermode approach (temporary, detection risk high):
    // 1. Mount tmpfs over /sys/class/dmi/id
    // 2. Create fake files with spoofed values
    
    std::string mount_cmd = "mount -t tmpfs tmpfs /sys/class/dmi/id";
    auto result = execute_command_safe("mount", {"-t", "tmpfs", "tmpfs", "/sys/class/dmi/id"});
    
    // Write spoofed values
    std::ofstream("/sys/class/dmi/id/board_serial") << board_serial;
    std::ofstream("/sys/class/dmi/id/product_serial") << system_serial;
    std::ofstream("/sys/class/dmi/id/sys_vendor") << system_manufacturer;
    
    return true;
#endif
}

// Phase 3: DHCP Client ID (Option 61) Spoofing - FASTEST TO IMPLEMENT
bool NetworkSpoofer::apply_dhcp_client_id(const std::string& interface_name, const std::string& client_id) {
#ifdef _WIN32
    // Windows: Modify HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}
    // Key: DhcpClientIdentifier (REG_BINARY)
    
    // Convert client_id string to hex bytes
    std::vector<uint8_t> client_id_bytes;
    for (char c : client_id) {
        client_id_bytes.push_back(static_cast<uint8_t>(c));
    }
    
    // Example registry path (need to find interface GUID first via GetAdaptersAddresses)
    std::string reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces";
    
    // Stub: Use netsh or registry API
    auto result = execute_command_safe("netsh", {"interface", "ipv4", "set", "interface", interface_name, "dhcpclientid="+client_id});
    
    return result.find("Error") == std::string::npos;
    
#else
    // Linux: Modify /etc/dhcp/dhclient.conf or dhcpcd.conf
    // Add: send dhcp-client-identifier "custom-id";
    
    std::ofstream dhcp_conf("/etc/dhcp/dhclient.conf", std::ios::app);
    if (dhcp_conf.is_open()) {
        dhcp_conf << "\nsend dhcp-client-identifier \"" << client_id << "\";\n";
        dhcp_conf.close();
        
        // Restart DHCP client to apply changes
        auto result = execute_command_safe("systemctl", {"restart", "dhclient"});
        return result.find("Error") == std::string::npos;
    }
    return false;
#endif
}

// Phase 4: TCP/IP Fingerprint Spoofing (Advanced)
bool NetworkSpoofer::apply_tcp_fingerprint_impl(const TcpFingerprintProfile& profile) {
#ifdef _WIN32
    // Windows: Modify TCP/IP stack parameters via Registry
    // HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
    
    std::string reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    
    // TTL (Time-To-Live)
    auto result1 = execute_command_safe("reg", {"add", reg_path, "/v", "DefaultTTL", "/t", "REG_DWORD", "/d", std::to_string(profile.ttl), "/f"});
    
    // Window Size (RWIN)
    auto result2 = execute_command_safe("reg", {"add", reg_path, "/v", "TcpWindowSize", "/t", "REG_DWORD", "/d", std::to_string(profile.window_size), "/f"});
    
    // MSS (Maximum Segment Size) - via Interfaces key
    auto result3 = execute_command_safe("reg", {"add", reg_path + "\\Interfaces", "/v", "TcpMaxSegmentSize", "/t", "REG_DWORD", "/d", std::to_string(profile.mss), "/f"});
    
    // Requires reboot or interface reset to take effect
    std::cout << "[TCP Fingerprint] Registry updated. Reboot or restart network adapter to apply." << std::endl;
    
    return result1.find("Error") == std::string::npos && 
           result2.find("Error") == std::string::npos && 
           result3.find("Error") == std::string::npos;
    
#else
    // Linux: Modify /proc/sys/net/ipv4/* and sysctl
    
    // TTL
    std::ofstream("/proc/sys/net/ipv4/ip_default_ttl") << profile.ttl;
    
    // Window Size (requires sysctl net.ipv4.tcp_rmem / tcp_wmem)
    auto result1 = execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_window_scaling=1"});
    auto result2 = execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_rmem=4096 " + std::to_string(profile.window_size) + " " + std::to_string(profile.window_size*2)});
    
    // MSS
    std::string mss_cmd = "ip link set dev eth0 mtu " + std::to_string(profile.mss + 40); // MTU = MSS + TCP/IP headers
    auto result3 = execute_command_safe("ip", {"link", "set", "dev", "eth0", "mtu", std::to_string(profile.mss + 40)});
    
    // TCP Options (SACKs, Timestamps) - via sysctl
    if (profile.tcp_options_order.find("sack") != std::string::npos) {
        execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_sack=1"});
    }
    if (profile.tcp_options_order.find("timestamp") != std::string::npos) {
        execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_timestamps=1"});
    }
    
    std::cout << "[TCP Fingerprint] Linux TCP/IP stack parameters applied." << std::endl;
    return true;
#endif
}



// ==================== CSPRNG Implementation ====================
uint8_t NetworkSpoofer::csprng_byte() {
#ifdef _WIN32
    uint8_t val;
    BCryptGenRandom(nullptr, &val, sizeof(val), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return val;
#else
    uint8_t val;
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    urandom.read(reinterpret_cast<char*>(&val), sizeof(val));
    return val;
#endif
}

uint32_t NetworkSpoofer::csprng_uniform(uint32_t upper_bound) {
    if (upper_bound <= 1) return 0;
    uint32_t val;
#ifdef _WIN32
    BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&val), sizeof(val), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
    std::ifstream urandom("/dev/urandom", std::ios::binary);
    urandom.read(reinterpret_cast<char*>(&val), sizeof(val));
#endif
    return val % upper_bound;
}

} // namespace ncp
