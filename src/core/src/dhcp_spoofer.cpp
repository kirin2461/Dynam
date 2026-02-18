#include "ncp_dhcp_spoofer.hpp"
#include <sstream>
#include <fstream>
#include <string>
#include <random>
#include <iomanip>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#endif

namespace ncp {

// ==================== Generators ====================

std::string DHCPSpoofer::generate_from_mac(const std::string& mac) {
    std::string id = "01";
    for (char c : mac) {
        if (c != ':' && c != '-') id += c;
    }
    return id;
}

std::string DHCPSpoofer::generate_random() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::ostringstream oss;
    oss << "00";
    for (int i = 0; i < 8; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << dist(gen);
    }
    return oss.str();
}

DHCPSpoofer::~DHCPSpoofer() {
    if (applied_) restore();
}

// ==================== Apply/Restore ====================

bool DHCPSpoofer::apply(const Config& config) {
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
    // Restart DHCP if requested
    if (config.auto_renew) {
        system("ipconfig /release >nul 2>&1");
        system("ipconfig /renew >nul 2>&1");
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
    system("ipconfig /release >nul 2>&1");
    system("ipconfig /renew >nul 2>&1");
    return true;
}

#else

// ==================== Linux ====================

bool DHCPSpoofer::apply_linux(const Config& config) {
    (void)config;
    // Backup original dhclient.conf
    struct stat st;
    if (stat("/etc/dhcp/dhclient.conf", &st) == 0) {
        system("cp /etc/dhcp/dhclient.conf /etc/dhcp/dhclient.conf.ncp_backup 2>/dev/null");
    }
    // Append client-id directive
    std::ofstream conf("/etc/dhcp/dhclient.conf", std::ios::app);
    if (!conf.is_open()) {
        // Try dhcpcd.conf for systems using dhcpcd
        conf.open("/etc/dhcpcd.conf", std::ios::app);
        if (!conf.is_open()) {
            last_error_ = "Cannot open DHCP config (run as root)";
            return false;
        }
        conf << "\n# NCP DHCP Client ID Spoofing\n";
        conf << "clientid " << current_id_ << "\n";
        conf.close();
        if (config.auto_renew) {
            system("systemctl restart dhcpcd 2>/dev/null || dhcpcd -n 2>/dev/null");
        }
        return true;
    }
    conf << "\n# NCP DHCP Client ID Spoofing\n";
    conf << "send dhcp-client-identifier \"" << current_id_ << "\";\n";
    conf.close();
    if (config.auto_renew) {
        std::string cmd = "dhclient -r " + interface_name_ + " 2>/dev/null; "
                          "dhclient " + interface_name_ + " 2>/dev/null";
        system(cmd.c_str());
    }
    return true;
}

bool DHCPSpoofer::restore_linux() {
    // Restore backup
    struct stat st;
    if (stat("/etc/dhcp/dhclient.conf.ncp_backup", &st) == 0) {
        system("mv /etc/dhcp/dhclient.conf.ncp_backup /etc/dhcp/dhclient.conf 2>/dev/null");
    }
    std::string cmd = "dhclient -r " + interface_name_ + " 2>/dev/null; "
                      "dhclient " + interface_name_ + " 2>/dev/null";
    system(cmd.c_str());
    return true;
}

std::string DHCPSpoofer::find_interface_guid(const std::string&) { return ""; }
bool DHCPSpoofer::apply_windows(const Config&) { return false; }
bool DHCPSpoofer::restore_windows() { return false; }

#endif

} // namespace ncp
