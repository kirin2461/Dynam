#include "ncp_dhcp_spoofer.hpp"
#include <sstream>
#include <fstream>
#include <string>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <regex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <cstdio>  // rename()
#endif

namespace ncp {

// ==================== Interface Name Validation ====================
// FIX: Whitelist validation to prevent OS command injection.
// interface_name_ is interpolated into system() calls that run as root.
// Without validation, payloads like ";rm -rf /" or "$(malicious)" execute.

static bool validate_interface_name(const std::string& name) {
    if (name.empty() || name.size() > 64) return false;
    static const std::regex iface_re("^[a-zA-Z0-9._-]+$");
    return std::regex_match(name, iface_re);
}

// ==================== Strip Existing NCP Blocks ====================
// FIX: Remove previous NCP DHCP blocks from config before appending.
// Previously apply_linux() appended every time, causing unbounded growth.

static std::string strip_ncp_blocks(const std::string& content) {
    std::istringstream iss(content);
    std::ostringstream oss;
    std::string line;
    bool skip = false;

    while (std::getline(iss, line)) {
        if (line.find("# NCP DHCP Client ID Spoofing") != std::string::npos) {
            skip = true;
            continue;
        }
        if (skip) {
            // Skip the directive line right after the comment marker
            skip = false;
            continue;
        }
        oss << line << "\n";
    }
    return oss.str();
}

// ==================== Generators ====================

std::string DHCPSpoofer::generate_from_mac(const std::string& mac) {
    std::string id = "01";
    for (char c : mac) {
        if (c != ':' && c != '-') id += c;
    }
    return id;
}

std::string DHCPSpoofer::generate_random() {
    std::ostringstream oss;
    oss << "00";
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << randombytes_uniform(256);
    }
    return oss.str();
}

DHCPSpoofer::~DHCPSpoofer() {
    if (applied_) restore();
}

// ==================== Apply/Restore ====================

bool DHCPSpoofer::apply(const Config& config) {
    // FIX: Validate interface name before any use
    if (!validate_interface_name(config.interface_name)) {
        last_error_ = "Invalid interface name (must match [a-zA-Z0-9._-]+): " + config.interface_name;
        return false;
    }

    if (applied_) restore();
    interface_name_ = config.interface_name;
    current_id_ = config.custom_client_id.empty()
        ? generate_random() : config.custom_client_id;
#ifdef _WIN32
    bool ok = apply_windows(config);
#else
    bool ok = apply_linux(config);
#endif
    if (ok) applied_ = true;
    return ok;
}

bool DHCPSpoofer::restore() {
    // FIX: Validate stored interface name (defensive — should already be valid)
    if (!validate_interface_name(interface_name_)) {
        last_error_ = "Stored interface name is invalid, refusing to execute commands";
        return false;
    }

#ifdef _WIN32
    bool ok = restore_windows();
#else
    bool ok = restore_linux();
#endif
    if (ok) applied_ = false;
    return ok;
}

// ==================== Windows ====================

#ifdef _WIN32

// FIX: Non-blocking command execution for Windows.
// system("ipconfig /release") blocks 5-30s, freezing GUI threads.
static bool run_command_async_win(const std::string& cmd) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    std::string mutable_cmd = cmd;
    BOOL ok = CreateProcessA(
        NULL,
        &mutable_cmd[0],
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL, NULL,
        &si, &pi
    );
    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    return ok != FALSE;
}

std::string DHCPSpoofer::find_interface_guid(const std::string& name) {
    ULONG size = 15000;
    PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (!addrs) return "";
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &size) != NO_ERROR) {
        free(addrs);
        addrs = (PIP_ADAPTER_ADDRESSES)malloc(size);
        if (!addrs) return "";
        if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &size) != NO_ERROR) {
            free(addrs); return "";
        }
    }
    std::string guid;
    for (auto a = addrs; a; a = a->Next) {
        char friendly[256];
        WideCharToMultiByte(CP_UTF8, 0, a->FriendlyName, -1, friendly, 256, NULL, NULL);
        if (name == a->AdapterName || name == friendly) {
            guid = a->AdapterName;
            break;
        }
    }
    free(addrs);
    return guid;
}

bool DHCPSpoofer::apply_windows(const Config& config) {
    std::string guid = find_interface_guid(config.interface_name);
    if (guid.empty()) {
        last_error_ = "Interface not found: " + config.interface_name;
        return false;
    }
    std::string reg_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + guid;
    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path.c_str(), 0, KEY_READ | KEY_WRITE, &hKey);
    if (res != ERROR_SUCCESS) {
        last_error_ = "Cannot open registry key (run as Administrator)";
        return false;
    }
    // Save original
    char orig[512]; DWORD orig_size = sizeof(orig); DWORD orig_type;
    if (RegQueryValueExA(hKey, "DhcpClientIdentifier", NULL, &orig_type,
                         (BYTE*)orig, &orig_size) == ERROR_SUCCESS) {
        original_id_ = std::string(orig, orig_size);
    }
    // Set new
    std::vector<BYTE> id_bytes;
    for (size_t i = 0; i < current_id_.size(); i += 2) {
        std::string byte_str = current_id_.substr(i, 2);
        id_bytes.push_back(static_cast<BYTE>(strtol(byte_str.c_str(), nullptr, 16)));
    }
    res = RegSetValueExA(hKey, "DhcpClientIdentifier", 0, REG_BINARY,
                         id_bytes.data(), static_cast<DWORD>(id_bytes.size()));
    RegCloseKey(hKey);
    if (res != ERROR_SUCCESS) {
        last_error_ = "Failed to write registry value";
        return false;
    }
    // FIX: Non-blocking DHCP restart
    if (config.auto_renew) {
        run_command_async_win("cmd /c ipconfig /release >nul 2>&1 && ipconfig /renew >nul 2>&1");
    }
    return true;
}

bool DHCPSpoofer::restore_windows() {
    std::string guid = find_interface_guid(interface_name_);
    if (guid.empty()) return false;
    std::string reg_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" + guid;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return false;
    if (original_id_.empty()) {
        RegDeleteValueA(hKey, "DhcpClientIdentifier");
    } else {
        RegSetValueExA(hKey, "DhcpClientIdentifier", 0, REG_BINARY,
                       (const BYTE*)original_id_.data(),
                       static_cast<DWORD>(original_id_.size()));
    }
    RegCloseKey(hKey);
    // FIX: Non-blocking DHCP restart
    run_command_async_win("cmd /c ipconfig /release >nul 2>&1 && ipconfig /renew >nul 2>&1");
    return true;
}

#else

// ==================== Linux ====================

// Safe command execution with fork/exec (no shell interpretation)
static int run_dhclient(const std::string& iface, bool release) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        // Child: redirect stdout/stderr to /dev/null
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
        if (release) {
            execlp("dhclient", "dhclient", "-r", iface.c_str(), nullptr);
        } else {
            execlp("dhclient", "dhclient", iface.c_str(), nullptr);
        }
        _exit(127); // exec failed
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool DHCPSpoofer::apply_linux(const Config& config) {
    (void)config;

    // FIX: interface_name_ already validated in apply(), but double-check
    if (!validate_interface_name(interface_name_)) {
        last_error_ = "Invalid interface name";
        return false;
    }

    const std::string dhclient_conf = "/etc/dhcp/dhclient.conf";
    const std::string dhcpcd_conf = "/etc/dhcpcd.conf";
    const std::string backup_path = dhclient_conf + ".ncp_backup";

    struct stat st;
    bool use_dhclient = (stat(dhclient_conf.c_str(), &st) == 0);
    bool use_dhcpcd = false;

    if (use_dhclient) {
        // Backup original (only if backup doesn't already exist)
        struct stat bk_st;
        if (stat(backup_path.c_str(), &bk_st) != 0) {
            // Use file I/O instead of system("cp ...")
            std::ifstream src(dhclient_conf, std::ios::binary);
            std::ofstream dst(backup_path, std::ios::binary);
            if (src.is_open() && dst.is_open()) {
                dst << src.rdbuf();
            }
        }

        // FIX: Read existing content, strip old NCP blocks, then append
        std::string existing;
        {
            std::ifstream in(dhclient_conf);
            if (in.is_open()) {
                existing = std::string(
                    std::istreambuf_iterator<char>(in),
                    std::istreambuf_iterator<char>());
            }
        }

        existing = strip_ncp_blocks(existing);

        // Write cleaned content + new directive
        std::ofstream conf(dhclient_conf, std::ios::trunc);
        if (!conf.is_open()) {
            last_error_ = "Cannot open dhclient.conf (run as root)";
            return false;
        }
        conf << existing;
        conf << "\n# NCP DHCP Client ID Spoofing\n";
        conf << "send dhcp-client-identifier \"" << current_id_ << "\";\n";
        conf.close();

        // FIX: Use fork/exec instead of system() — no shell injection possible
        if (config.auto_renew) {
            run_dhclient(interface_name_, true);   // release
            run_dhclient(interface_name_, false);  // renew
        }
        return true;
    }

    // Try dhcpcd.conf fallback
    if (stat(dhcpcd_conf.c_str(), &st) == 0) {
        use_dhcpcd = true;
    }

    if (use_dhcpcd) {
        // Backup
        std::string dhcpcd_backup = dhcpcd_conf + ".ncp_backup";
        struct stat bk_st;
        if (stat(dhcpcd_backup.c_str(), &bk_st) != 0) {
            std::ifstream src(dhcpcd_conf, std::ios::binary);
            std::ofstream dst(dhcpcd_backup, std::ios::binary);
            if (src.is_open() && dst.is_open()) {
                dst << src.rdbuf();
            }
        }

        // FIX: Strip old NCP blocks before appending
        std::string existing;
        {
            std::ifstream in(dhcpcd_conf);
            if (in.is_open()) {
                existing = std::string(
                    std::istreambuf_iterator<char>(in),
                    std::istreambuf_iterator<char>());
            }
        }
        existing = strip_ncp_blocks(existing);

        std::ofstream conf(dhcpcd_conf, std::ios::trunc);
        if (!conf.is_open()) {
            last_error_ = "Cannot open dhcpcd.conf (run as root)";
            return false;
        }
        conf << existing;
        conf << "\n# NCP DHCP Client ID Spoofing\n";
        conf << "clientid " << current_id_ << "\n";
        conf.close();

        if (config.auto_renew) {
            // Use fork/exec for dhcpcd restart
            pid_t pid = fork();
            if (pid == 0) {
                freopen("/dev/null", "w", stdout);
                freopen("/dev/null", "w", stderr);
                execlp("systemctl", "systemctl", "restart", "dhcpcd", nullptr);
                // If systemctl not found, try dhcpcd directly
                execlp("dhcpcd", "dhcpcd", "-n", nullptr);
                _exit(127);
            } else if (pid > 0) {
                int status = 0;
                waitpid(pid, &status, 0);
            }
        }
        return true;
    }

    last_error_ = "Cannot open DHCP config (run as root)";
    return false;
}

bool DHCPSpoofer::restore_linux() {
    // FIX: Validate interface name (defensive)
    if (!validate_interface_name(interface_name_)) {
        last_error_ = "Stored interface name is invalid";
        return false;
    }

    bool restored = false;

    // FIX: Check backup actually exists before restoring, and verify result.
    // Previously: system("mv ...") silently failed → return true anyway.
    const std::string dhclient_conf = "/etc/dhcp/dhclient.conf";
    const std::string dhclient_backup = dhclient_conf + ".ncp_backup";
    const std::string dhcpcd_conf = "/etc/dhcpcd.conf";
    const std::string dhcpcd_backup = dhcpcd_conf + ".ncp_backup";

    struct stat st;

    // Try dhclient.conf backup
    if (stat(dhclient_backup.c_str(), &st) == 0) {
        // Use rename() instead of system("mv ...") — atomic, no shell
        if (std::rename(dhclient_backup.c_str(), dhclient_conf.c_str()) == 0) {
            restored = true;
        } else {
            last_error_ = "Failed to restore dhclient.conf from backup";
        }
    }

    // Try dhcpcd.conf backup
    if (stat(dhcpcd_backup.c_str(), &st) == 0) {
        if (std::rename(dhcpcd_backup.c_str(), dhcpcd_conf.c_str()) == 0) {
            restored = true;
        } else {
            if (last_error_.empty()) {
                last_error_ = "Failed to restore dhcpcd.conf from backup";
            }
        }
    }

    if (!restored) {
        // No backup found — strip NCP blocks from existing configs as fallback
        for (const auto& conf_path : {dhclient_conf, dhcpcd_conf}) {
            if (stat(conf_path.c_str(), &st) == 0) {
                std::string content;
                {
                    std::ifstream in(conf_path);
                    if (in.is_open()) {
                        content = std::string(
                            std::istreambuf_iterator<char>(in),
                            std::istreambuf_iterator<char>());
                    }
                }
                std::string cleaned = strip_ncp_blocks(content);
                if (cleaned != content) {
                    std::ofstream out(conf_path, std::ios::trunc);
                    if (out.is_open()) {
                        out << cleaned;
                        restored = true;
                    }
                }
            }
        }
    }

    // FIX: Use fork/exec for dhclient restart, check exit codes
    int release_rc = run_dhclient(interface_name_, true);
    int renew_rc = run_dhclient(interface_name_, false);

    if (!restored && release_rc != 0 && renew_rc != 0) {
        if (last_error_.empty()) {
            last_error_ = "No backup found and dhclient restart failed";
        }
        return false;
    }

    return restored || (renew_rc == 0);
}

std::string DHCPSpoofer::find_interface_guid(const std::string&) { return ""; }
bool DHCPSpoofer::apply_windows(const Config&) { return false; }
bool DHCPSpoofer::restore_windows() { return false; }

#endif

} // namespace ncp
