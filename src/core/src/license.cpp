#include "../include/ncp_crypto.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <vector>
#include <array>
#include "../include/ncp_license.hpp"
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <regex>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/utsname.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#ifdef __APPLE__
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <net/if_dl.h>
#endif
#endif

namespace ncp {

// Pimpl implementation
struct License::Impl {
    // Implementation details
};

License::License() : crypto_(std::make_unique<Crypto>()) {}

License::~License() = default;

// ==================== HWID Generation ====================

std::string License::get_hwid() {
    std::string hwid_components;

    // Component 1: MAC Address
    hwid_components += get_mac_address();

    // Component 2: CPU ID
    hwid_components += get_cpu_id();

    // Component 3: OS UUID
    hwid_components += get_os_uuid();

    // FIX: Convert to SecureMemory for hash_sha256
    SecureMemory input(hwid_components.size());
    std::memcpy(input.data(), hwid_components.data(), hwid_components.size());
    SecureMemory hash = crypto_->hash_sha256(input);

    // Convert to hex string using SecureMemory accessors
    std::stringstream ss;
    for (size_t i = 0; i < hash.size(); ++i) {
        ss << std::hex << std::setfill('0') << std::setw(2)
           << static_cast<int>(hash.data()[i]);
    }

    return ss.str();
}

std::string License::get_mac_address() {
#ifdef _WIN32
    IP_ADAPTER_INFO adapter_info[16];
    DWORD buf_len = sizeof(adapter_info);
    if (GetAdaptersInfo(adapter_info, &buf_len) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        std::stringstream ss;
        for (UINT i = 0; i < adapter->AddressLength; i++) {
            ss << std::hex << std::setfill('0') << std::setw(2)
               << static_cast<int>(adapter->Address[i]);
        }
        return ss.str();
    }
    return "000000000000";
#elif defined(__APPLE__)
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return "000000000000";
    }

    std::string mac = "000000000000";
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
            if (sdl->sdl_alen == 6) {
                unsigned char* hw = reinterpret_cast<unsigned char*>(LLADDR(sdl));
                std::stringstream ss;
                for (int i = 0; i < 6; i++) {
                    ss << std::hex << std::setfill('0') << std::setw(2)
                       << static_cast<int>(hw[i]);
                }
                mac = ss.str();
                if (mac != "000000000000") {
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddr);
    return mac;
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return "000000000000";
    }

    std::string mac = "000000000000";
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) continue;

        struct ifreq ifr;
        strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
            unsigned char* hw = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
            std::stringstream ss;
            for (int i = 0; i < 6; i++) {
                ss << std::hex << std::setfill('0') << std::setw(2)
                   << static_cast<int>(hw[i]);
            }
            mac = ss.str();
            if (mac != "000000000000") {
                close(fd);
                break;
            }
        }
        close(fd);
    }
    freeifaddrs(ifaddr);
    return mac;
#endif
}

std::string License::get_cpu_id() {
#ifdef _WIN32
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 0);
    std::stringstream ss;
    ss << std::hex << cpu_info[1] << cpu_info[3] << cpu_info[2];
    return ss.str();
#elif defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0));
    std::stringstream ss;
    ss << std::hex << ebx << edx << ecx;
    return ss.str();
#else
    return "generic_cpu";
#endif
}

std::string License::get_os_uuid() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                      KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char uuid[256];
        DWORD size = sizeof(uuid);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(uuid), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(uuid);
        }
        RegCloseKey(hKey);
    }
    return "unknown-windows-uuid";
#elif defined(__APPLE__)
    io_registry_entry_t ioRegistryRoot = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    CFStringRef uuid_cf = (CFStringRef)IORegistryEntryCreateCFProperty(
        ioRegistryRoot, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(ioRegistryRoot);
    if (uuid_cf) {
        char uuid[128];
        CFStringGetCString(uuid_cf, uuid, sizeof(uuid), kCFStringEncodingUTF8);
        CFRelease(uuid_cf);
        return std::string(uuid);
    }
    return "unknown-macos-uuid";
#else
    std::ifstream file("/etc/machine-id");
    if (file.is_open()) {
        std::string uuid;
        std::getline(file, uuid);
        return uuid;
    }
    file.open("/sys/class/dmi/id/product_uuid");
    if (file.is_open()) {
        std::string uuid;
        std::getline(file, uuid);
        return uuid;
    }
    return "unknown-linux-uuid";
#endif
}

// ==================== License Validation ====================

License::ValidationResult License::validate_offline(
    const std::string& hwid,
    const std::string& license_file) {
    std::ifstream file(license_file, std::ios::binary);
    if (!file.is_open()) {
        return ValidationResult::FILE_NOT_FOUND;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    // Parse license file (format: HWID|EXPIRY|SIGNATURE)
    std::regex pattern(R"(([^|]+)\|([^|]+)\|(.+))");
    std::smatch matches;
    if (!std::regex_match(content, matches, pattern)) {
        return ValidationResult::INVALID_FORMAT;
    }

    std::string stored_hwid = matches[1].str();
    std::string expiry_str = matches[2].str();
    std::string signature_b64 = matches[3].str();

    // Verify HWID
    if (stored_hwid != hwid) {
        return ValidationResult::HWID_MISMATCH;
    }

    // Parse and check expiry
    std::tm tm = {};
    std::istringstream ss(expiry_str);
    ss >> std::get_time(&tm, "%Y-%m-%d");
    auto expiry = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    if (std::chrono::system_clock::now() > expiry) {
        return ValidationResult::EXPIRED;
    }

    // Verify signature
    std::string data_to_verify = stored_hwid + "|" + expiry_str;
    // Decode base64 signature and verify with public key
    // (simplified - in production use proper base64 and key storage)
    if (signature_b64.empty()) {
        return ValidationResult::INVALID_SIGNATURE;
    }

    return ValidationResult::VALID;
}

License::ValidationResult License::validate_online(
    const std::string& hwid,
    const std::string& license_key,
    const std::string& server_url) {
    (void)hwid;  // Suppress unused parameter warning - used in production implementation
    
    // In production: HTTPS request to validation server
    // For now: simulate validation
    if (license_key.empty()) {
        return ValidationResult::INVALID_KEY;
    }
    if (server_url.empty()) {
        return ValidationResult::SERVER_ERROR;
    }

    // Validate license key format (XXXX-XXXX-XXXX-XXXX)
    std::regex key_pattern(R"([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})");
    if (!std::regex_match(license_key, key_pattern)) {
        return ValidationResult::INVALID_KEY;
    }

    // TODO: Implement actual HTTPS validation
    // curl/libcurl or cpp-httplib for HTTP requests
    return ValidationResult::VALID;
}

// ==================== License File Generation ====================

bool License::generate_license_file(
    const std::string& hwid,
    const std::string& license_key,
    const std::chrono::system_clock::time_point& expiration_date,
    const std::string& output_file,
    LicenseType type) {
    (void)license_key;  // Suppress unused parameter warning - reserved for future use
    (void)type;         // Suppress unused parameter warning - reserved for future use
    
    auto time_t_expiry = std::chrono::system_clock::to_time_t(expiration_date);
    #ifdef _WIN32
    std::tm tm_buf;
    localtime_s(&tm_buf, &time_t_expiry);
    std::tm* tm = &tm_buf;
#else
    std::tm* tm = std::localtime(&time_t_expiry);
#endif
    std::stringstream date_ss;
    date_ss << std::put_time(tm, "%Y-%m-%d");
    std::string expiry_str = date_ss.str();

    // Create data to sign
    std::string data = hwid + "|" + expiry_str;

    // Generate signature (using Ed25519)
    auto keypair = crypto_->generate_keypair();

    // FIX: Convert data to SecureMemory for sign_ed25519
    SecureMemory msg(data.size());
    std::memcpy(msg.data(), data.data(), data.size());
    SecureMemory signature = crypto_->sign_ed25519(msg, keypair.secret_key);

    // Encode signature to hex string using SecureMemory accessors
    std::stringstream sig_ss;
    for (size_t i = 0; i < signature.size(); ++i) {
        sig_ss << std::hex << std::setfill('0') << std::setw(2)
               << static_cast<int>(signature.data()[i]);
    }

    // Write license file
    std::string license_content = data + "|" + sig_ss.str();
    std::ofstream file(output_file, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file << license_content;
    file.close();

    return true;
}

// ==================== License Info ====================

License::LicenseInfo License::get_license_info(const std::string& license_file) {
    LicenseInfo info;
    info.is_valid = false;
    info.is_trial = false;
    info.days_remaining = 0;
    info.plan = "Unknown";

    std::ifstream file(license_file);
    if (!file.is_open()) {
        return info;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();

    std::regex pattern(R"(([^|]+)\|([^|]+)\|(.+))");
    std::smatch matches;
    if (!std::regex_match(content, matches, pattern)) {
        return info;
    }

    info.hwid = matches[1].str();
    std::string expiry_str = matches[2].str();

    std::tm tm = {};
    std::istringstream ss(expiry_str);
    ss >> std::get_time(&tm, "%Y-%m-%d");
    info.expiry_date = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    auto now = std::chrono::system_clock::now();
    auto diff = info.expiry_date - now;
    info.days_remaining = std::chrono::duration_cast<std::chrono::hours>(diff).count() / 24;
    info.is_valid = (info.days_remaining > 0);
    info.is_trial = (info.plan == "Trial");

    return info;
}

bool License::is_expired(const std::chrono::system_clock::time_point& expiry_date) {
    return std::chrono::system_clock::now() > expiry_date;
}

} // namespace ncp
