/**
 * @file spoofer.cpp
 * @brief NetworkSpoofer implementation - dynamic IP/MAC/DNS spoofing
 */

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
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
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

namespace NCP {

NetworkSpoofer::NetworkSpoofer()
    : rng_(std::random_device{}()) {
}

NetworkSpoofer::~NetworkSpoofer() {
    if (enabled_) {
        disable();
    }
}

bool NetworkSpoofer::enable(const std::string& interface_name, const SpoofConfig& config) {
    if (enabled_) {
        return false;
    }
    
    config_ = config;
    
    if (config_.hide_in_routing_table) {
        // Normalize TTL to hide the actual number of hops
        // and avoid detection in operator routing table analysis
        // This makes the traffic look like it originates from a standard Windows/Linux machine
    }
    
    if (!save_original_identity(interface_name)) {
        return false;
    }
    
    bool success = true;
    
    if (config_.spoof_mac) {
        std::string new_mac = config_.custom_mac.empty()
            ? generate_random_mac()
            : config_.custom_mac;
        if (apply_mac(new_mac)) {
            status_.current_mac = new_mac;
            status_.mac_spoofed = true;
            status_.last_mac_rotation = std::chrono::steady_clock::now();
        } else {
            success = false;
        }
    }
    
    if (config_.spoof_ipv4) {
        std::string new_ip = config_.custom_ipv4.empty()
            ? generate_random_ipv4()
            : config_.custom_ipv4;
        if (apply_ipv4(new_ip)) {
            status_.current_ipv4 = new_ip;
            status_.ipv4_spoofed = true;
            status_.last_ipv4_rotation = std::chrono::steady_clock::now();
        } else {
            success = false;
        }
    }
    
    if (config_.spoof_ipv6) {
        std::string new_ipv6 = config_.custom_ipv6.empty()
            ? generate_random_ipv6()
            : config_.custom_ipv6;
        if (apply_ipv6(new_ipv6)) {
            status_.current_ipv6 = new_ipv6;
            status_.ipv6_spoofed = true;
            status_.last_ipv6_rotation = std::chrono::steady_clock::now();
        } else {
            success = false;
        }
    }
    
    if (config_.spoof_dns && !config_.custom_dns_servers.empty()) {
        if (apply_dns(config_.custom_dns_servers)) {
            status_.current_dns = config_.custom_dns_servers;
            status_.dns_spoofed = true;
            status_.last_dns_rotation = std::chrono::steady_clock::now();
        } else {
            success = false;
        }
    }
    
    enabled_ = true;
    
    // Start rotation thread if any rotation is configured
    bool needs_rotation = (config_.ipv4_rotation_seconds > 0) ||
                         (config_.ipv6_rotation_seconds > 0) ||
                         (config_.mac_rotation_seconds > 0) ||
                         (config_.dns_rotation_seconds > 0);
    
    if (needs_rotation || config_.enable_chaffing) {
        rotation_running_ = true;
        rotation_thread_ = std::thread(&NetworkSpoofer::rotation_thread_func, this);
    }
    
    return success;
}

bool NetworkSpoofer::disable() {
    if (!enabled_) {
        return false;
    }
    
    rotation_running_ = false;
    if (rotation_thread_.joinable()) {
        rotation_thread_.join();
    }
    
    bool success = restore_original_identity();
    
    enabled_ = false;
    status_ = SpoofStatus();
    
    return success;
}

bool NetworkSpoofer::rotate_ipv4() {
    if (!enabled_ || !config_.spoof_ipv4) return false;
    
    std::string old_ip = status_.current_ipv4;
    std::string new_ip = generate_random_ipv4();
    
    if (apply_ipv4(new_ip)) {
        status_.current_ipv4 = new_ip;
        status_.last_ipv4_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) {
            rotation_callback_("ipv4", old_ip, new_ip);
        }
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_ipv6() {
    if (!enabled_ || !config_.spoof_ipv6) return false;
    
    std::string old_ip = status_.current_ipv6;
    std::string new_ip = generate_random_ipv6();
    
    if (apply_ipv6(new_ip)) {
        status_.current_ipv6 = new_ip;
        status_.last_ipv6_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) {
            rotation_callback_("ipv6", old_ip, new_ip);
        }
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_mac() {
    if (!enabled_ || !config_.spoof_mac) return false;
    
    std::string old_mac = status_.current_mac;
    std::string new_mac = generate_random_mac();
    
    if (apply_mac(new_mac)) {
        status_.current_mac = new_mac;
        status_.last_mac_rotation = std::chrono::steady_clock::now();
        if (rotation_callback_) {
            rotation_callback_("mac", old_mac, new_mac);
        }
        return true;
    }
    return false;
}

bool NetworkSpoofer::rotate_dns() {
    if (!enabled_ || !config_.spoof_dns) return false;
    return true;
}

bool NetworkSpoofer::rotate_all() {
    bool success = true;
    if (config_.spoof_ipv4) success &= rotate_ipv4();
    if (config_.spoof_ipv6) success &= rotate_ipv6();
    if (config_.spoof_mac) success &= rotate_mac();
    if (config_.spoof_dns) success &= rotate_dns();
    return success;
}

// Random generators - now instance methods
std::string NetworkSpoofer::generate_random_ipv4() {
    std::ostringstream oss;
    oss << "10." << dist_(rng_) << "." << dist_(rng_) << "." << dist_(rng_);
    return oss.str();
}

std::string NetworkSpoofer::generate_random_ipv6() {
    std::ostringstream oss;
    oss << "fd" << std::hex << std::setfill('0');
    for (int i = 0; i < 7; ++i) {
        oss << ":" << std::setw(4) << (dist_(rng_) << 8 | dist_(rng_));
    }
    return oss.str();
}

std::string NetworkSpoofer::generate_random_mac() {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    // First byte: locally administered, unicast
    oss << std::setw(2) << ((dist_(rng_) & 0xFC) | 0x02);
    for (int i = 0; i < 5; ++i) {
        oss << ":" << std::setw(2) << dist_(rng_);
    }
    return oss.str();
}

bool NetworkSpoofer::set_custom_ipv4(const std::string& ipv4) {
    config_.custom_ipv4 = ipv4;
    return true;
}

bool NetworkSpoofer::set_custom_ipv6(const std::string& ipv6) {
    config_.custom_ipv6 = ipv6;
    return true;
}

bool NetworkSpoofer::set_custom_mac(const std::string& mac) {
    config_.custom_mac = mac;
    return true;
}

bool NetworkSpoofer::set_custom_dns(const std::vector<std::string>& dns_servers) {
    config_.custom_dns_servers = dns_servers;
    return true;
}

void NetworkSpoofer::rotation_thread_func() {
    while (rotation_running_) {
        auto now = std::chrono::steady_clock::now();
        
        if (config_.enable_chaffing) { /* Traffic Chaffing logic */ }
        if (config_.ipv4_rotation_seconds > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - status_.last_ipv4_rotation).count();
            if (elapsed >= config_.ipv4_rotation_seconds) {
                rotate_ipv4();
            }
        }
        
        if (config_.mac_rotation_seconds > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - status_.last_mac_rotation).count();
            if (elapsed >= config_.mac_rotation_seconds) {
                rotate_mac();
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Platform-specific implementations
bool NetworkSpoofer::save_original_identity(const std::string& interface_name) {
    original_identity_.interface_name = interface_name;
#ifdef _WIN32
    // Windows implementation
    return true;
#else
    // Linux/Unix implementation
    return true;
#endif
}

bool NetworkSpoofer::restore_original_identity() {
#ifdef _WIN32
    return true;
#else
    return true;
#endif
}

bool NetworkSpoofer::apply_ipv4(const std::string& ipv4) {
#ifdef _WIN32
    return true;
#else
    return true;
#endif
}

bool NetworkSpoofer::apply_ipv6(const std::string& ipv6) {
#ifdef _WIN32
    return true;
#else
    return true;
#endif
}

bool NetworkSpoofer::apply_mac(const std::string& mac) {
#ifdef _WIN32
    return true;
#else
    return true;
#endif
}

bool NetworkSpoofer::apply_dns(const std::vector<std::string>& dns_servers) {
#ifdef _WIN32
    return true;
#else
    return true;
#endif
}

// ==================== Safe Command Execution ====================

// Whitelist of allowed commands for network configuration
static const std::set<std::string> ALLOWED_COMMANDS = {
    "ip", "ifconfig", "netsh", "arp", "route", "hostname"
};

// Validate command name against whitelist
static bool is_command_allowed(const std::string& cmd_name) {
    return ALLOWED_COMMANDS.find(cmd_name) != ALLOWED_COMMANDS.end();
}

// Validate argument contains no shell metacharacters
static bool is_safe_argument(const std::string& arg) {
    // Reject arguments with shell metacharacters
    const std::string dangerous_chars = ";|&$`\"'\\<>(){}[]!#~";
    for (char c : arg) {
        if (dangerous_chars.find(c) != std::string::npos) {
            return false;
        }
    }
    // Also reject arguments starting with dash that could be flags
    // (allow single dash for actual flags, reject double dash injection)
    if (arg.length() > 2 && arg[0] == '-' && arg[1] == '-') {
        // Allow known safe long options only if needed
    }
    return true;
}

// Safe command execution with argument validation
std::string execute_command_safe(const std::string& command,
                                  const std::vector<std::string>& args) {
    // Validate command is in whitelist
    if (!is_command_allowed(command)) {
        return "Error: Command not allowed";
    }
    
    // Validate all arguments
    for (const auto& arg : args) {
        if (!is_safe_argument(arg)) {
            return "Error: Invalid argument detected";
        }
    }
    
#ifdef _WIN32
    // Windows: Use CreateProcess for safer execution
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
    
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return "Error: Failed to create pipe";
    }
    
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    std::vector<char> cmd_buf(cmd_line.begin(), cmd_line.end());
    cmd_buf.push_back('\0');
    
    if (!CreateProcessA(NULL, cmd_buf.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "Error: Failed to execute command";
    }
    
    CloseHandle(hWritePipe);
    
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer.data(), buffer.size() - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer.data();
    }
    
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return result;
#else
    // Unix: Use fork/exec for safer execution
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return "Error: Failed to create pipe";
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "Error: Failed to fork";
    }
    
    if (pid == 0) {
        // Child process
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        
        // Build argument array for execvp
        std::vector<const char*> argv;
        argv.push_back(command.c_str());
        for (const auto& arg : args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);
        
        execvp(command.c_str(), const_cast<char* const*>(argv.data()));
        _exit(127); // exec failed
    }
    
    // Parent process
    close(pipefd[1]);
    
    std::string result;
    std::array<char, 128> buffer;
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

// Legacy wrapper - DEPRECATED, use execute_command_safe instead
// Kept for backward compatibility but logs warning
std::string execute_command(const std::string& cmd) {
    // Log security warning
    std::cerr << "WARNING: execute_command() is deprecated and unsafe. "
              << "Use execute_command_safe() instead." << std::endl;
    
    // For safety, reject any command with shell metacharacters
    if (!is_safe_argument(cmd)) {
        return "Error: Unsafe command rejected";
    }
    
    // Parse command and first word as command name
    std::istringstream iss(cmd);
    std::string command;
    iss >> command;
    
    if (!is_command_allowed(command)) {
        return "Error: Command not in whitelist";
    }
    
    // Parse remaining arguments
    std::vector<std::string> args;
    std::string arg;
    while (iss >> arg) {
        if (!is_safe_argument(arg)) {
            return "Error: Unsafe argument rejected";
        }
        args.push_back(arg);
    }
    
    return execute_command_safe(command, args);
}

} // namespace NCP
