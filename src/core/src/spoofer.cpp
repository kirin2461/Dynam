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

// R16-M03: Named constant for adapter buffer size (replaces magic number 15000)
static constexpr size_t ADAPTER_BUFFER_INITIAL_SIZE = 15 * 1024;  // 15KB

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

// Dotted netmask for a prefix length (24 -> "255.255.255.0"). Defined next to
// the other address helpers; declared here because save_original_identity()
// uses it while capturing the adapter's original mask.
static std::string prefix_to_netmask(unsigned prefix);

// Validate command arguments against injection.
// On Windows, allow spaces (adapter FriendlyNames like "Local Area Connection")
// because execute_command_safe() uses CreateProcessA with the full command line
// and we quote multi-word values where needed (e.g. name="Wi-Fi").
static bool is_safe_argument(const std::string& arg) {
#ifdef _WIN32
    // Allow spaces on Windows (needed for adapter FriendlyNames used with netsh).
    // Reject only truly dangerous shell metacharacters.
    // Allow spaces AND double-quotes on Windows: we embed quotes in
    // netsh args ourselves (e.g. name="Wi-Fi") so they are safe.
    const std::string dangerous_chars = ";|&$`'\\<>(){}[]!#~";
#else
    const std::string dangerous_chars = ";|&$`\"'\\<>(){}[]!#~ ";
#endif
    for (char c : arg) {
        if (dangerous_chars.find(c) != std::string::npos) {
            return false;
        }
    }
    return true;
}

// Result of a whitelisted child process. Success is decided by the exit code,
// never by the text of the output: `netsh`/`reg`/`ip` are localized, so
// searching for the English word "Error" reported Russian "Ошибка" runs as
// success (R18-09). `exit_code` is -1 when the process could not be started or
// was rejected by the whitelist/argument checks.
struct CommandResult {
    int exit_code = -1;
    std::string output;

    bool ok() const { return exit_code == 0; }
};

static CommandResult execute_command_safe(const std::string& command, const std::vector<std::string>& args) {
    CommandResult res;
    if (!is_command_allowed(command)) {
        res.output = "Error: Command not allowed";
        return res;
    }
    for (const auto& arg : args) {
        if (!is_safe_argument(arg)) {
            res.output = "Error: Invalid argument detected";
            return res;
        }
    }

#ifdef _WIN32
    // ENCODING FIX: Use CreateProcessW (wide-char) so that non-ASCII
    // adapter names (e.g. "Беспроводная сеть") are passed to netsh
    // correctly. The interface_name is stored as UTF-8 by
    // detect_default_interface(), so we convert the whole command line
    // from UTF-8 to wchar_t before calling CreateProcessW.
    //
    // R9-C01: Each argument is quoted to prevent injection via spaces
    // or special characters in adapter names like "Wi-Fi & calc.exe".
    std::string cmd_line = command;
    for (const auto& arg : args) {
        // Quote each argument to prevent argument injection
        cmd_line += " \"" + arg + "\"";
    }

    // Convert UTF-8 command line to wide string
    int wlen = MultiByteToWideChar(CP_UTF8, 0, cmd_line.c_str(), -1, nullptr, 0);
    if (wlen <= 0) { res.output = "Error: encoding"; return res; }
    std::vector<wchar_t> wcmd(wlen);
    MultiByteToWideChar(CP_UTF8, 0, cmd_line.c_str(), -1, wcmd.data(), wlen);

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    std::array<char, 4096> buffer;
    std::string result;
    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) { res.output = "Error: pipe"; return res; }
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    if (!CreateProcessW(NULL, wcmd.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        res.output = "Error: exec";
        return res;
    }
    CloseHandle(hWritePipe);
    DWORD bytesRead;
    while (ReadFile(hReadPipe, buffer.data(), static_cast<DWORD>(buffer.size() - 1), &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        result += buffer.data();
    }
    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD child_exit = 1;
    if (!GetExitCodeProcess(pi.hProcess, &child_exit)) child_exit = 1;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    res.exit_code = static_cast<int>(child_exit);
    res.output = std::move(result);
    return res;
#else
    int pipefd[2];
    if (pipe(pipefd) == -1) { res.output = "Error: pipe"; return res; }
    pid_t pid = fork();
    if (pid == -1) { close(pipefd[0]); close(pipefd[1]); res.output = "Error: fork"; return res; }
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
    // Report the real exit status: execvp failure surfaces as _exit(127).
    if (WIFEXITED(status)) res.exit_code = WEXITSTATUS(status);
    else res.exit_code = -1;
    res.output = std::move(result);
    return res;
#endif
}

// ==================== Constructor/Destructor ====================
NetworkSpoofer::NetworkSpoofer() {}

NetworkSpoofer::~NetworkSpoofer() noexcept {
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
            journal_record(JournalEntry::Mac, original_identity_.mac_address, new_mac);
            status_.current_mac = new_mac;
            status_.mac_spoofed = true;
            status_.last_mac_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_ipv4) {
        std::string new_ip = config_.custom_ipv4.empty() ? generate_random_ipv4() : config_.custom_ipv4;
        if (apply_ipv4(new_ip)) {
            journal_record(JournalEntry::IPv4, original_identity_.ipv4_address, new_ip);
            status_.current_ipv4 = new_ip;
            status_.ipv4_spoofed = true;
            status_.last_ipv4_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_ipv6) {
        std::string new_ipv6 = config_.custom_ipv6.empty() ? generate_random_ipv6() : config_.custom_ipv6;
        if (apply_ipv6(new_ipv6)) {
            journal_record(JournalEntry::IPv6, original_identity_.ipv6_address, new_ipv6);
            status_.current_ipv6 = new_ipv6;
            status_.ipv6_spoofed = true;
            status_.last_ipv6_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    if (config_.spoof_dns && !config_.custom_dns_servers.empty()) {
        if (apply_dns(config_.custom_dns_servers)) {
            std::string dns_original;
            for (size_t i = 0; i < original_identity_.dns_servers.size(); ++i) {
                if (i) dns_original += ",";
                dns_original += original_identity_.dns_servers[i];
            }
            journal_record(JournalEntry::Dns, dns_original,
                           config_.custom_dns_servers[0]);
            status_.current_dns = config_.custom_dns_servers;
            status_.dns_spoofed = true;
            status_.last_dns_rotation = std::chrono::steady_clock::now();
        } else { success = false; }
    }

    // R18-02: apply_hw_info() returns false on every platform because a board
    // serial lives in read-only firmware data. That is "not supported", not
    // "the enable failed": warn, leave hw_info_spoofed false so status reports
    // the truth, and let the supported categories carry on.
    if (config_.spoof_hw_info) {
        std::string new_serial = config_.custom_hw_serial.empty() ? generate_random_hw_serial() : config_.custom_hw_serial;
        if (apply_hw_info(new_serial)) {
            journal_record(JournalEntry::HwInfo, original_identity_.original_board_serial, new_serial);
            status_.current_hw_serial = new_serial;
            status_.hw_info_spoofed = true;
            status_.last_hw_info_rotation = std::chrono::steady_clock::now();
        } else {
            std::cerr << "[!] Hardware-info (board serial) spoofing is not supported "
                         "on this platform - nothing was changed\n";
        }
    }

    if (config_.spoof_hostname) {
        std::string new_host = config_.custom_hostname.empty()
                                   ? generate_random_hostname()
                                   : config_.custom_hostname;
        if (apply_hostname(new_host)) {
            journal_record(JournalEntry::Hostname, original_identity_.hostname, new_host);
            status_.current_hostname = new_host;
            status_.hostname_spoofed = true;
            status_.last_hostname_rotation = std::chrono::steady_clock::now();
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
    
    // R9-H02: Primary restore attempt
    bool success = restore_original_identity();
    
    // R9-H02: Fallback strategies if primary restore fails
    if (!success) {
#ifdef _WIN32
        // Fallback 1: DHCP renewal on Windows
        std::cerr << "[!] Warning: Primary restore failed, attempting DHCP renewal...\n";
        auto dhcp_result = execute_command_safe("ipconfig", {"/renew"});
        auto flush_result = execute_command_safe("ipconfig", {"/flushdns"});

        // Consider success if DHCP renewal succeeded
        success = dhcp_result.ok();
        
        // Fallback 2: Force DNS cache flush even if other operations failed
        execute_command_safe("ipconfig", {"/registerdns"});
#else
        // Fallback 1: Restart networking service on Linux
        std::cerr << "[!] Warning: Primary restore failed, attempting network restart...\n";
        auto systemd_result = execute_command_safe("systemctl", {"restart", "NetworkManager"});
        success = systemd_result.ok();

        // Fallback 2: Restart dhclient if systemd failed
        if (!success) {
            auto dhclient_result = execute_command_safe("dhclient", {"-r"});
            dhclient_result = execute_command_safe("dhclient", {});
            success = dhclient_result.ok();
        }
#endif
    }
    
    // R9-H02: Log failure if all strategies fail
    if (!success) {
        std::cerr << "[!] ERROR: Failed to restore original network settings.\n";
        std::cerr << "[!] Please manually renew DHCP lease or restart network adapter.\n";
    }
    
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
        // apply_ipv6() adds rather than replaces; drop the previous spoofed
        // address so rotations do not pile up random IPv6s on the adapter,
        // and point the journal at the one now present.
        if (!old.empty()) remove_ipv6(old);
        journal_update_applied(JournalEntry::IPv6, n);
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
        // Use configurable DNS pool from SpoofConfig::dns_rotation_pool;
        // fallback to built-in well-known providers only if pool is empty.
        std::vector<std::string> providers = config_.dns_rotation_pool.empty()
            ? std::vector<std::string>{"1.1.1.1","8.8.8.8","9.9.9.9","1.0.0.1","8.8.4.4"}
            : config_.dns_rotation_pool;
        if (providers.size() < 2) return false; // Need at least 2 for rotation
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
    if (!enabled_ || !config_.spoof_hostname) return false;
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
    if (config_.spoof_hostname) s &= rotate_hostname();
    return s;
}

// ==================== Generators ====================
std::string NetworkSpoofer::generate_random_ipv4() {
    std::ostringstream oss;
    oss << "10." << static_cast<unsigned>(csprng_byte()) << "."
        << static_cast<unsigned>(csprng_byte()) << "."
        << (1 + static_cast<unsigned>(csprng_byte()) % 254);
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
    // R10-H08: Ensure valid unicast, locally administered MAC address
    // - Bit 0 (LSB of first octet) = 0 → Unicast (not multicast)
    // - Bit 1 (LSB of first octet) = 1 → Locally administered (not OUI)
    // Mask 0xFC clears bits 0-1, then OR with 0x02 sets bit 1
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(2) << ((csprng_byte() & 0xFC) | 0x02);
    for (int i = 0; i < 5; ++i)
        oss << ":" << std::setw(2) << static_cast<unsigned>(csprng_byte());
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
}

// ==================== Platform-specific: Save/Restore Identity ====================
bool NetworkSpoofer::save_original_identity(const std::string& interface_name) {
    original_identity_.interface_name = interface_name;
#ifdef _WIN32
    // FIX: interface_name is now a FriendlyName (e.g. "Ethernet", "Wi-Fi")
    // returned by detect_default_interface(). We must match by FriendlyName,
    // then store the adapter GUID internally for registry operations.
    //
    // ENCODING FIX: interface_name may arrive in UTF-8 (from detect_default_interface)
    // or in the console OEM codepage (from command-line args). To match reliably
    // we convert interface_name to wchar_t using two codepages (UTF-8 and ACP)
    // and compare against the native wchar_t FriendlyName.
    auto to_wide = [](const std::string& s, UINT codepage) -> std::wstring {
        if (s.empty()) return {};
        int wlen = MultiByteToWideChar(codepage, 0, s.c_str(), -1, nullptr, 0);
        if (wlen <= 0) return {};
        std::wstring ws(wlen - 1, L'\0');
        MultiByteToWideChar(codepage, 0, s.c_str(), -1, &ws[0], wlen);
        return ws;
    };
    // Try both UTF-8 and system ANSI codepage for the incoming name
    std::wstring name_utf8 = to_wide(interface_name, CP_UTF8);
    std::wstring name_acp  = to_wide(interface_name, CP_ACP);
    std::wstring name_oem  = to_wide(interface_name, CP_OEMCP);

    // R14-H01: Use RAII std::vector instead of malloc/free
    // R16-M03: Use named constant instead of magic number 15000
    ULONG bufferSize = static_cast<ULONG>(ADAPTER_BUFFER_INITIAL_SIZE);
    std::vector<uint8_t> buffer(bufferSize);
    PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    for (int attempts = 0; attempts < 3; ++attempts) {
        DWORD result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize);
        if (result == NO_ERROR) {
            break;  // Success
        } else if (result == ERROR_BUFFER_OVERFLOW && attempts < 2) {
            // Buffer too small - resize and retry
            buffer.resize(bufferSize);
            addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        } else {
            // Other error or max attempts reached
            return false;
        }
    }

    std::string adapter_guid; // GUID for registry lookups
    for (PIP_ADAPTER_ADDRESSES addr = addresses; addr; addr = addr->Next) {
        if (!addr->FriendlyName) continue;
        std::wstring friendly_w = addr->FriendlyName;

        // Match against any of the codepage interpretations
        bool matched = (!name_utf8.empty() && friendly_w == name_utf8) ||
                       (!name_acp.empty()  && friendly_w == name_acp) ||
                       (!name_oem.empty()  && friendly_w == name_oem);
        if (!matched) continue;

        // Matched — save GUID for registry operations
        adapter_guid = addr->AdapterName; // GUID string like {ABC-123...}

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
                // R18-07: keep the mask and prefix so a restore does not fall
                // back to a hard-coded /24.
                uint8_t plen = ua->OnLinkPrefixLength;
                if (plen >= 8 && plen <= 30)
                    original_identity_.ipv4_netmask = prefix_to_netmask(plen);
            } else if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
                char ip6[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &((sockaddr_in6*)ua->Address.lpSockaddr)->sin6_addr,
                          ip6, sizeof(ip6));
                // Skip link-local (fe80::/10) — only a routable address is
                // worth restoring.
                if (std::string(ip6).rfind("fe80", 0) != 0)
                    original_identity_.ipv6_address = ip6;
            }
        }
        // Default gateway (first IPv4 next-hop of the adapter).
        for (auto gw = addr->FirstGatewayAddress; gw; gw = gw->Next) {
            if (gw->Address.lpSockaddr->sa_family == AF_INET) {
                char gwa[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)gw->Address.lpSockaddr)->sin_addr,
                          gwa, sizeof(gwa));
                original_identity_.ipv4_gateway = gwa;
                break;
            }
        }
        // R18-07: remember whether the address came from DHCP, so restore puts
        // the adapter back on DHCP instead of pinning a stale lease as static.
        original_identity_.ipv4_dhcp =
            (addr->Flags & IP_ADAPTER_DHCP_ENABLED) != 0 ||
            addr->Dhcpv4Server.iSockaddrLength > 0;
        break;
    }
    // R14-H01: No free() needed - std::vector handles cleanup automatically

    if (adapter_guid.empty()) {
        // Could not find adapter with this FriendlyName — spoofing cannot proceed
        return false;
    }

    // FIX #49.1: Discover the adapter registry subkey index for MAC spoofing.
    // Windows stores NetworkAddress under:
    //   HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-...}\00XX
    // We enumerate subkeys and match by NetCfgInstanceId to the adapter GUID.
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
                HKEY hSubKey;
                std::string full_subkey = net_class_key + "\\" + subkey_name;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_subkey.c_str(), 0,
                                  KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                    char instance_id[256];
                    DWORD id_len = sizeof(instance_id);
                    DWORD type = 0;
                    if (RegQueryValueExA(hSubKey, "NetCfgInstanceId", NULL,
                                         &type, (BYTE*)instance_id, &id_len) == ERROR_SUCCESS) {
                        if (adapter_guid == instance_id) {
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

    // Save the adapter's current DNS servers so restore can put them back
    // (the old Windows restore always wrote `static`, even when the adapter
    // had used DHCP-provided resolvers). The adapter list is still live in
    // `buffer` from the lookup above.
    for (PIP_ADAPTER_ADDRESSES addr = addresses; addr; addr = addr->Next) {
        if (!addr->FriendlyName) continue;
        std::wstring friendly_w = addr->FriendlyName;
        bool matched = (!name_utf8.empty() && friendly_w == name_utf8) ||
                       (!name_acp.empty() && friendly_w == name_acp) ||
                       (!name_oem.empty() && friendly_w == name_oem);
        if (!matched) continue;
        for (auto dns = addr->FirstDnsServerAddress; dns; dns = dns->Next) {
            if (dns->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)dns->Address.lpSockaddr)->sin_addr,
                          ip, sizeof(ip));
                original_identity_.dns_servers.push_back(ip);
            }
        }
        break;
    }
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

#if defined(__linux__)
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
#elif defined(__APPLE__)
    // macOS: netmask shares ifr_addr union slot; SIOCGIFHWADDR is unavailable,
    // so MAC address retrieval is skipped here (best-effort for portable build).
    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) {
        struct sockaddr_in* mask = (struct sockaddr_in*)&ifr.ifr_addr;
        original_identity_.ipv4_netmask = inet_ntoa(mask->sin_addr);
    }
#endif
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

// ==================== Restore journal (R18-04) ====================
void NetworkSpoofer::journal_record(JournalEntry what, const std::string& original,
                                    const std::string& applied) {
    journal_.push_back({what, original, applied});
}

void NetworkSpoofer::journal_clear() {
    journal_.clear();
}

// A rotation replaces the applied value but not the original: keep the
// original recorded by enable() and only track what is on the adapter now.
void NetworkSpoofer::journal_update_applied(JournalEntry what,
                                            const std::string& applied) {
    for (auto it = journal_.rbegin(); it != journal_.rend(); ++it) {
        if (it->what == what) { it->applied_value = applied; return; }
    }
}

// Undo a single journaled change. Entries with an empty original value have
// nothing to put back (the category had no prior value); they are reported as
// handled so they do not fail the whole restore.
bool NetworkSpoofer::journal_undo_one(const JournalItem& item) {
    switch (item.what) {
        case JournalEntry::Mac:
            if (item.original_value.empty()) return true;
            return apply_mac(item.original_value);
        case JournalEntry::IPv4:
            return undo_ipv4(item.original_value);
        case JournalEntry::IPv6:
            // apply_ipv6() *adds* an address next to the real one, so undo
            // deletes the spoofed address. Re-adding the original (the
            // obvious inverse) would leave the random IPv6 on the adapter.
            if (item.applied_value.empty()) return true;
            return remove_ipv6(item.applied_value);
        case JournalEntry::Dns:
#ifndef _WIN32
            // Restore the whole resolv.conf (search/domain/options and the
            // original nameservers), not just the nameserver lines.
            if (!original_identity_.resolv_conf_lines.empty()) {
                std::ofstream resolv("/etc/resolv.conf", std::ios::trunc);
                if (!resolv.is_open()) return false;
                for (const auto& line : original_identity_.resolv_conf_lines)
                    resolv << line << "\n";
                return true;
            }
#endif
            {
                std::vector<std::string> servers;
                std::istringstream ss(item.original_value);
                std::string part;
                while (std::getline(ss, part, ','))
                    if (!part.empty()) servers.push_back(part);
                if (servers.empty()) return true;
                return apply_dns(servers);
            }
        case JournalEntry::Hostname:
            if (item.original_value.empty()) return true;
            return apply_hostname(item.original_value);
        // These five never apply successfully on any platform any more
        // (R18-01/02/03/05), so there is nothing to undo. They are in the enum
        // so the journal stays complete if a platform ever supports them.
        case JournalEntry::HwInfo:
        case JournalEntry::Smbios:
        case JournalEntry::DiskSerial:
        case JournalEntry::DhcpClientId:
        case JournalEntry::TcpFingerprint:
            return true;
    }
    return true;
}

// R18-07: put IPv4 back the way it was. A DHCP adapter is returned to DHCP
// (re-pinning the old lease as a static address — the previous behaviour —
// breaks as soon as the lease moves). A static adapter gets its original
// address, mask and gateway back via apply_ipv4().
bool NetworkSpoofer::undo_ipv4(const std::string& original) {
    const auto& iface = original_identity_.interface_name;
    if (original_identity_.ipv4_dhcp) {
#ifdef _WIN32
        return execute_command_safe("netsh", {
            "interface", "ip", "set", "address",
            "name=\"" + iface + "\"", "source=dhcp"
        }).ok();
#else
        // The DHCP client re-adds its lease once the spoofed address is gone.
        (void)iface;
        return true;
#endif
    }
    if (original.empty()) return true;
    return apply_ipv4(original);
}

bool NetworkSpoofer::remove_ipv6(const std::string& spoofed) {
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    return execute_command_safe("netsh", {
        "interface", "ipv6", "delete", "address",
        "interface=\"" + iface + "\"", "address=" + spoofed
    }).ok();
#else
    return execute_command_safe("ip", {
        "-6", "addr", "del", spoofed + "/64", "dev", iface
    }).ok();
#endif
}

// Replaces the old restore_original_identity() body: undo every journaled
// change in reverse order. Kept under the original name because disable() is
// its only caller.
bool NetworkSpoofer::restore_original_identity() {
    bool success = true;
    for (auto it = journal_.rbegin(); it != journal_.rend(); ++it)
        success &= journal_undo_one(*it);
    journal_.clear();
    return success;
}

// ==================== Platform-specific: Apply Functions ====================
bool NetworkSpoofer::apply_ipv4(const std::string& ipv4) {
    if (ipv4.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    // Quote adapter name for netsh (FriendlyNames may contain spaces).
    // The original mask and gateway are carried over: the old hard-coded
    // 255.255.255.0 dropped the gateway and left an unroutable adapter.
    std::vector<std::string> argv = {
        "interface", "ip", "set", "address",
        "name=\"" + iface + "\"", "static", ipv4, ipv4_mask_or_default()
    };
    if (!original_identity_.ipv4_gateway.empty())
        argv.push_back(original_identity_.ipv4_gateway);
    return execute_command_safe("netsh", argv).ok();
#else
    // Preserve the original prefix length instead of forcing /24.
    CommandResult result = execute_command_safe("ip", {
        "addr", "replace", ipv4 + "/" + ipv4_prefix_or_default(), "dev", iface
    });
    return result.ok();
#endif
}

bool NetworkSpoofer::apply_ipv6(const std::string& ipv6) {
    if (ipv6.empty()) return false;
    const auto& iface = original_identity_.interface_name;
#ifdef _WIN32
    CommandResult result = execute_command_safe("netsh", {
        "interface", "ipv6", "add", "address",
        "interface=\"" + iface + "\"", "address=" + ipv6
    });
    return result.ok();
#else
    CommandResult result = execute_command_safe("ip", {
        "-6", "addr", "add", ipv6 + "/64", "dev", iface
    });
    return result.ok();
#endif
}

// Dotted netmask for a prefix length (24 -> "255.255.255.0").
static std::string prefix_to_netmask(unsigned prefix) {
    if (prefix > 32) prefix = 32;
    uint32_t mask = prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix));
    std::ostringstream oss;
    oss << ((mask >> 24) & 0xFF) << '.' << ((mask >> 16) & 0xFF) << '.'
        << ((mask >> 8) & 0xFF) << '.' << (mask & 0xFF);
    return oss.str();
}

// IPv4 mask to use when writing an address: the one the adapter had before
// spoofing, or /24 as a last resort when nothing was captured.
std::string NetworkSpoofer::ipv4_mask_or_default() const {
    return original_identity_.ipv4_netmask.empty()
               ? std::string("255.255.255.0")
               : original_identity_.ipv4_netmask;
}

// Prefix length derived from the saved dotted netmask (e.g. 255.255.255.0 -> 24).
std::string NetworkSpoofer::ipv4_prefix_or_default() const {
    const std::string& mask = original_identity_.ipv4_netmask;
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(mask.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        auto ones = [](unsigned octet) {
            int n = 0;
            for (int bit = 7; bit >= 0; --bit)
                if (octet & (1u << bit)) ++n;
            return n;
        };
        // Only a contiguous mask has a meaningful prefix length.
        if (a >= b && b >= c && c >= d) {
            int prefix = ones(a) + ones(b) + ones(c) + ones(d);
            if (prefix >= 8 && prefix <= 30) return std::to_string(prefix);
        }
    }
    return "24";
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

        if (!reg_result.ok()) {
            return false; // Registry write failed — don't bounce the interface
        }
    } else {
        // No adapter registry index found — cannot set MAC on Windows
        return false;
    }

    // Step 2: Disable interface so driver re-reads NetworkAddress
    // R11-H01: Warn about network drop — MAC spoofing disconnects the adapter
    std::cerr << "[!] WARNING: MAC spoofing will temporarily disable the network adapter.\n";
    std::cerr << "[!] This will cause a brief network disconnection (5-10 seconds).\n";
    std::cerr << "[!] Ensure you have physical or console access before proceeding.\n";
    std::cerr << "[!] Remote sessions (SSH/RDP) may be interrupted.\n";
    CommandResult result = execute_command_safe("netsh", {
        "interface", "set", "interface", "name=\"" + iface + "\"", "admin=disable"
    });

    // Step 3: Re-enable interface with new MAC
    execute_command_safe("netsh", {
        "interface", "set", "interface", "name=\"" + iface + "\"", "admin=enable"
    });

    return result.ok();
#else
    // R11-H01: Warn about network drop — MAC spoofing disconnects the adapter
    std::cerr << "[!] WARNING: MAC spoofing will temporarily disable the network interface.\n";
    std::cerr << "[!] This will cause a brief network disconnection (5-10 seconds).\n";
    std::cerr << "[!] Ensure you have physical or console access before proceeding.\n";
    std::cerr << "[!] Remote sessions (SSH) may be interrupted.\n";
    execute_command_safe("ip", {"link", "set", iface, "down"});
    CommandResult result = execute_command_safe("ip", {
        "link", "set", iface, "address", mac
    });
    execute_command_safe("ip", {"link", "set", iface, "up"});
    return result.ok();
#endif
}

bool NetworkSpoofer::apply_dns(const std::vector<std::string>& dns_servers) {
    if (dns_servers.empty()) return false;
#ifdef _WIN32
    const auto& iface = original_identity_.interface_name;
    bool first = true;
    bool ok = true;
    for (const auto& dns : dns_servers) {
        if (first) {
            ok &= execute_command_safe("netsh", {
                "interface", "ip", "set", "dns",
                "name=\"" + iface + "\"", "static", dns
            }).ok();
            first = false;
        } else {
            ok &= execute_command_safe("netsh", {
                "interface", "ip", "add", "dns",
                "name=\"" + iface + "\"", dns, "index=2"
            }).ok();
        }
    }
    return ok;
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
    // R18-02: hardware serials are read from firmware (SMBIOS/DMI) or the
    // disk's identify page. Neither can be changed from user mode, and the
    // files that expose them under /sys are read-only. Report "not supported"
    // instead of returning true so the caller never claims a spoof that did
    // not happen.
    (void)serial;
    return false;
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

    // R18-03: SMBIOS/DMI data lives in firmware tables that WMI and almost
    // every identity consumer read directly; they cannot be changed from user
    // mode. The old Windows path wrote HKLM\HARDWARE\DESCRIPTION\System\BIOS,
    // which Windows rebuilds from firmware on every boot, and stored the
    // generated UUID in SystemProductName — a field that means "product name",
    // not UUID — so it corrupted the visible product name until reboot while
    // changing nothing real.
    //
    // Per-process SMBIOS hiding on Linux is provided separately by the
    // LD_PRELOAD shim in smbios_hook.cpp; that is the only supported form and
    // it is opt-in per process, not a system-wide change. See smbios_hook.cpp.
    (void)board_serial;
    (void)system_serial;
    (void)uuid;
    return false;
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
    // Six of the eight fields have no storage in the firmware tables and are
    // deliberately ignored. Pass the UUID only when the caller set one — a
    // freshly generated random UUID was previously written into
    // SystemProductName, which is not a UUID field at all (R18-03).
    return apply_smbios(board_serial, system_serial, config_.custom_system_uuid);
}

// ==================== Platform-specific: Disk Serial Spoofing ====================
bool NetworkSpoofer::apply_disk_serial(const std::string& disk_serial) {
    if (disk_serial.empty()) return false;
    // R18-01: this used to write the generated value into value "0" of
    // HKLM\SYSTEM\CurrentControlSet\Services\disk\Enum. That value is the
    // first disk's device instance path (e.g. "SCSI\Disk&Ven_..."), not a
    // serial, so the write achieved nothing for the real serial — which comes
    // from the drive's IDENTIFY data — while corrupting the enumeration list
    // for every program that reads it. A disk serial cannot be changed from
    // user mode; report "not supported" on every platform.
    (void)disk_serial;
    return false;
}

// ==================== Platform-specific: DHCP Client ID Spoofing ====================
bool NetworkSpoofer::apply_dhcp_client_id(const std::string& interface_name, const std::string& client_id) {
    if (client_id.empty()) return false;
#ifdef _WIN32
    // R18-05: netsh has no `dhcpclientid=` parameter (it accepted the argument
    // silently and did nothing), and Windows exposes no supported way to set
    // the DHCP option-61 client identifier. Report "not supported" rather than
    // claiming a change.
    (void)interface_name;
    return false;
#else
    // R18-05: this only works when the legacy ISC dhclient is the active DHCP
    // client, which most current distributions no longer use. Detect the
    // client first and refuse — with a reason — when it is NetworkManager or
    // systemd-networkd, where the file below is ignored.
    {
        std::ifstream nm("/etc/NetworkManager/NetworkManager.conf");
        if (nm.is_open()) {
            std::cerr << "[!] DHCP client ID spoofing is not supported with "
                         "NetworkManager (set ipv4.dhcp-client-id instead)\n";
            return false;
        }
        std::ifstream snd("/etc/systemd/network");
        if (snd.is_open()) {
            std::cerr << "[!] DHCP client ID spoofing is not supported with "
                         "systemd-networkd (set ClientIdentifier= in the .network file)\n";
            return false;
        }
    }
    (void)interface_name;
    // FIX P1: Read-modify-write to prevent duplicate entries on repeated calls
    std::vector<std::string> existing_lines;
    {
        std::ifstream in("/etc/dhcp/dhclient.conf");
        std::string ln;
        while (std::getline(in, ln)) {
            // Strip any existing dhcp-client-identifier to avoid duplication
            if (ln.find("send dhcp-client-identifier") == std::string::npos)
                existing_lines.push_back(ln);
        }
    }
    std::ofstream dhcp_conf("/etc/dhcp/dhclient.conf", std::ios::trunc);
    if (!dhcp_conf.is_open()) return false;
    for (const auto& ln : existing_lines) dhcp_conf << ln << "\n";
    dhcp_conf << "send dhcp-client-identifier \"" << client_id << "\";\n";
    dhcp_conf.close();
    auto result = execute_command_safe("systemctl", {"restart", "dhclient"});
    return result.ok();
#endif
}

// ==================== Platform-specific: TCP Fingerprint Spoofing ====================
bool NetworkSpoofer::apply_tcp_fingerprint(const TcpFingerprintProfile& profile) {
    config_.tcp_profile = profile;
    return apply_tcp_fingerprint_impl(profile);
}

bool NetworkSpoofer::apply_tcp_fingerprint_impl(const TcpFingerprintProfile& profile) {
#ifdef _WIN32
    // R18-08: only DefaultTTL has any effect on modern Windows.
    //   * TcpWindowSize is ignored — receive-window auto-tuning has overridden
    //     it since Vista, so writing it changed nothing.
    //   * TcpMaxSegmentSize was written to the Parameters\Interfaces *parent*
    //     key, which applies to no interface at all.
    // Both writes are removed; leaving them produced false "applied" status and
    // polluted the registry. DefaultTTL itself is journaled for restore.
    std::string reg_path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters";
    auto result = execute_command_safe("reg", {"add", reg_path, "/v", "DefaultTTL",
                                               "/t", "REG_DWORD",
                                               "/d", std::to_string(profile.ttl), "/f"});
    return result.ok();
#else
    // Global sysctls only. The interface MTU is deliberately not touched: the
    // old code set it to mss+40, which silently broke PMTU for every socket on
    // the host and was never restored (R18-08).
    std::ofstream("/proc/sys/net/ipv4/ip_default_ttl") << static_cast<int>(profile.ttl);
    bool ok = execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_window_scaling=1"}).ok();
    ok &= execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_rmem=4096 " + std::to_string(profile.window_size) + " " + std::to_string(profile.window_size*2)}).ok();
    if (profile.sack_permitted) {
        ok &= execute_command_safe("sysctl", {"-w", "net.ipv4.tcp_sack=1"}).ok();
    }
    return ok;
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
