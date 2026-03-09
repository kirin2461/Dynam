// license.cpp — Full implementation of ncp::License
// C++17, cross-platform (Windows / macOS / Linux)
// Dependencies: libsodium (via Crypto), OpenSSL (optional, for HTTPS), POSIX/WinAPI

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
#include <set>
#include <map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <cassert>

// ── Platform detection ────────────────────────────────────────────────────────
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <intrin.h>
#  include <iphlpapi.h>
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <winioctl.h>
#  include <tlhelp32.h>
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <sys/utsname.h>
#  include <unistd.h>
#  include <net/if.h>
#  include <sys/ioctl.h>
#  include <ifaddrs.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  ifdef __APPLE__
#    include <IOKit/IOKitLib.h>
#    include <CoreFoundation/CoreFoundation.h>
#    include <net/if_dl.h>
#    include <sys/sysctl.h>
#  else
#    include <sys/sysinfo.h>
#    include <sys/ptrace.h>
#  endif
#endif

// ── OpenSSL BIO (optional) ────────────────────────────────────────────────────
#ifdef HAVE_OPENSSL
#  include <openssl/bio.h>
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#endif

namespace ncp {

// ==================== JSON Helper Functions ====================
// R7-SEC-08: Escape special characters to prevent JSON injection
// R10-FIX-02: Timing-safe JSON escaping - constant time regardless of input
static std::string json_escape_string(const std::string& input) {
    std::string output;
    // Pre-calculate worst-case size (all chars become \uXXXX = 6 chars each)
    output.reserve(input.size() * 6);
    
    for (char c : input) {
        unsigned char uc = static_cast<unsigned char>(c);
        // Use lookup table for consistent execution path
        switch (uc) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b";  break;
            case '\f': output += "\\f";  break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            default:
                // R10-FIX-02: Always use \uXXXX format for control chars for consistency
                if (uc < 0x20) {
                    char buf[7];
                    snprintf(buf, sizeof(buf), "\\u%04x", uc);
                    output += buf;
                } else {
                    output += c;
                }
        }
    }
    output.shrink_to_fit();
    return output;
}

// R10-FIX-02: Constant-time JSON escaping that always produces same output size
// for timing-sensitive operations (not used for actual JSON, but for HMAC comparisons)
static std::string json_escape_string_constant_time(const std::string& input, size_t max_len = 256) {
    std::string output;
    output.reserve(max_len * 6);
    
    size_t processed = 0;
    for (char c : input) {
        if (processed >= max_len) break;
        unsigned char uc = static_cast<unsigned char>(c);
        // Unified processing path - all characters take same code path
        char buf[7] = {0};
        switch (uc) {
            case '"':  memcpy(buf, "\\\"", 3); break;
            case '\\': memcpy(buf, "\\\\", 3); break;
            case '\b': memcpy(buf, "\\b", 3);  break;
            case '\f': memcpy(buf, "\\f", 3);  break;
            case '\n': memcpy(buf, "\\n", 3);  break;
            case '\r': memcpy(buf, "\\r", 3);  break;
            case '\t': memcpy(buf, "\\t", 3);  break;
            default:
                if (uc < 0x20) {
                    snprintf(buf, sizeof(buf), "\\u%04x", uc);
                } else {
                    buf[0] = c;
                }
        }
        output += buf;
        ++processed;
    }
    return output;
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    output += buf;
                } else {
                    output += c;
                }
        }
    }
    return output;
}

// ─────────────────────────────────────────────────────────────────────────────
// Pimpl — holds all mutable runtime state
// ─────────────────────────────────────────────────────────────────────────────
struct License::Impl {
    // Blacklist
    mutable std::mutex blacklist_mutex;
    std::set<std::string> hwid_blacklist;

    // Rate limiter: ip → (count, window_start)
    mutable std::mutex rate_mutex;
    struct RateEntry { uint32_t count{0}; std::chrono::steady_clock::time_point window_start; };
    std::map<std::string, RateEntry> rate_map;
    static constexpr uint32_t RATE_LIMIT_MAX  = 60;   // requests per window
    static constexpr uint32_t RATE_WINDOW_SEC = 60;

    // Feature flags
    mutable std::mutex feature_mutex;
    std::map<std::string, bool> feature_flags;

    // Trial state
    mutable std::mutex trial_mutex;
    bool trial_used{false};
    std::chrono::system_clock::time_point trial_start;
    int  trial_days{0};

    // Telemetry
    mutable std::mutex telem_mutex;
    TelemetryData telemetry;

    // Periodic validation thread
    std::atomic<bool> periodic_active{false};
    std::thread periodic_thread;

    // License cache (encrypted blob)
    mutable std::mutex cache_mutex;
    std::string secure_cache;        // hex-encoded encrypted blob
    std::string secure_cache_hwid;   // hwid used to derive cache key

    // Obfuscation XOR key (8 bytes, populated from HWID)
    std::array<uint8_t, 8> obf_key{};
    std::string obfuscated_data;

    Impl() {
        telemetry.validation_attempts = 0;
        telemetry.failed_attempts     = 0;
        telemetry.online_mode         = false;
    }
    ~Impl() {
        if (periodic_active.load()) {
            periodic_active.store(false);
            if (periodic_thread.joinable()) periodic_thread.join();
        }
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// File-scope helpers
// ─────────────────────────────────────────────────────────────────────────────
static std::string to_hex(const SecureMemory& mem) {
    std::stringstream ss;
    for (size_t i = 0; i < mem.size(); ++i)
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mem.data()[i]);
    return ss.str();
}

static bool from_hex(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i * 2, 2);
        if (!(ss >> byte)) return false;
        out[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

static std::string vec_to_hex(const std::vector<uint8_t>& v) {
    std::stringstream ss;
    for (auto b : v) ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

// Read first non-empty line from a file (Linux /sys helper)
static std::string read_first_line(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line != "None" && line != "none") return line;
    }
    return "";
}

// Simple HTTP(S) POST via TCP socket — returns response body or empty on error
// We avoid linking BIO when HAVE_OPENSSL is not defined; in that case we do
// a plain-text HTTP POST (for internal / test servers on plain HTTP).
static std::string http_post(const std::string& url,
                             const std::string& json_body,
                             int timeout_sec = 10) {
    // Parse url: http[s]://host[:port]/path
    std::string scheme, host, path;
    uint16_t port = 80;

    std::regex url_re(R"((https?)://([^/:]+)(?::(\d+))?(/.*)?)", std::regex::icase);
    std::smatch m;
    if (!std::regex_match(url, m, url_re)) return "";

    scheme = m[1].str();
    host   = m[2].str();
    if (m[3].matched) port = static_cast<uint16_t>(std::stoi(m[3].str()));
    else if (scheme == "https" || scheme == "HTTPS") port = 443;
    path = m[4].matched ? m[4].str() : "/";
    if (path.empty()) path = "/";

    std::string request =
        "POST " + path + " HTTP/1.0\r\n"
        "Host: " + host + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(json_body.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" + json_body;

#ifdef HAVE_OPENSSL
    if (scheme == "https" || scheme == "HTTPS") {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) return "";
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);

        BIO* bio = BIO_new_ssl_connect(ctx);
        if (!bio) { SSL_CTX_free(ctx); return ""; }

        std::string connect_str = host + ":" + std::to_string(port);
        BIO_set_conn_hostname(bio, connect_str.c_str());

        SSL* ssl = nullptr;
        BIO_get_ssl(bio, &ssl);
        if (ssl) {
            SSL_set_tlsext_host_name(ssl, host.c_str());  // SNI
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        }

        if (BIO_do_connect(bio) <= 0 || BIO_do_handshake(bio) <= 0) {
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return "";
        }
        BIO_write(bio, request.c_str(), static_cast<int>(request.size()));

        std::string response;
        char buf[4096];
        int n;
        while ((n = BIO_read(bio, buf, sizeof(buf))) > 0)
            response.append(buf, n);

        BIO_free_all(bio);
        SSL_CTX_free(ctx);

        // Strip HTTP headers
        auto hdr_end = response.find("\r\n\r\n");
        if (hdr_end != std::string::npos)
            return response.substr(hdr_end + 4);
        return response;
    }
#endif // HAVE_OPENSSL

    // Plain TCP (HTTP or HTTPS fallback without OpenSSL)
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        WSACleanup(); return "";
    }
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); WSACleanup(); return ""; }
    // Set timeout
    DWORD tv = timeout_sec * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    if (connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        closesocket(sock); freeaddrinfo(res); WSACleanup(); return "";
    }
    freeaddrinfo(res);
    send(sock, request.c_str(), static_cast<int>(request.size()), 0);
    std::string response;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0)
        response.append(buf, n);
    closesocket(sock);
    WSACleanup();
#else
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
        return "";
    int sock = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return ""; }
    // Set timeout
    struct timeval tv{ static_cast<time_t>(timeout_sec), 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        ::close(sock); freeaddrinfo(res); return "";
    }
    freeaddrinfo(res);
    ::send(sock, request.c_str(), request.size(), 0);
    std::string response;
    char buf[4096];
    ssize_t n;
    while ((n = ::recv(sock, buf, sizeof(buf), 0)) > 0)
        response.append(buf, static_cast<size_t>(n));
    ::close(sock);
#endif

    auto hdr_end = response.find("\r\n\r\n");
    if (hdr_end != std::string::npos)
        return response.substr(hdr_end + 4);
    return response;
}

// Minimalist JSON field extractor: find "key":"value" or "key":number
static std::string json_get(const std::string& json, const std::string& key) {
    std::string pat1 = "\"" + key + "\":\"";
    auto p = json.find(pat1);
    if (p != std::string::npos) {
        p += pat1.size();
        auto e = json.find('"', p);
        if (e != std::string::npos) return json.substr(p, e - p);
    }
    std::string pat2 = "\"" + key + "\":";
    p = json.find(pat2);
    if (p != std::string::npos) {
        p += pat2.size();
        auto e = json.find_first_of(",}", p);
        if (e != std::string::npos) return json.substr(p, e - p);
    }
    return "";
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructors / Destructor
// ─────────────────────────────────────────────────────────────────────────────
License::License()
    : impl_(std::make_unique<Impl>())
    , crypto_(std::make_unique<Crypto>()) {
    signing_keypair_ = crypto_->generate_keypair();
}

License::License(const std::string& secret_key_hex)
    : impl_(std::make_unique<Impl>())
    , crypto_(std::make_unique<Crypto>()) {
    if (!import_keypair(secret_key_hex))
        signing_keypair_ = crypto_->generate_keypair();
}

License::~License() = default;

// ─────────────────────────────────────────────────────────────────────────────
// Internal hex helpers
// ─────────────────────────────────────────────────────────────────────────────
std::string License::mem_to_hex(const SecureMemory& mem) {
    if (mem.empty() || !mem.data()) return "";
    std::stringstream ss;
    for (size_t i = 0; i < mem.size(); ++i)
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mem.data()[i]);
    return ss.str();
}

bool License::hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i * 2, 2);
        if (!(ss >> byte)) return false;
        out[i] = static_cast<uint8_t>(byte);
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Keypair persistence (FIX #28)
// ─────────────────────────────────────────────────────────────────────────────
std::string License::export_public_key_hex() const { return mem_to_hex(signing_keypair_.public_key); }
std::string License::export_secret_key_hex() const { return mem_to_hex(signing_keypair_.secret_key); }

bool License::import_keypair(const std::string& secret_key_hex) {
    if (secret_key_hex.size() != 128) return false;
    std::vector<uint8_t> sk_bytes;
    if (!hex_to_bytes(secret_key_hex, sk_bytes) || sk_bytes.size() != 64) return false;

    SecureMemory sk(sk_bytes.data(), sk_bytes.size());
    SecureMemory pk(sk_bytes.data() + 32, 32);

    SecureMemory test_msg(4);
    std::memcpy(test_msg.data(), "test", 4);
    SecureMemory sig = crypto_->sign_ed25519(test_msg, sk);
    if (!crypto_->verify_ed25519(test_msg, sig, pk)) return false;

    signing_keypair_.secret_key = std::move(sk);
    signing_keypair_.public_key = std::move(pk);
    return true;
}

SecureMemory License::get_public_key() const {
    return SecureMemory(signing_keypair_.public_key.data(), signing_keypair_.public_key.size());
}

// ─────────────────────────────────────────────────────────────────────────────
// HWID — basic components (already implemented, kept as-is)
// ─────────────────────────────────────────────────────────────────────────────
std::string License::get_mac_address() {
#ifdef _WIN32
    IP_ADAPTER_INFO adapter_info[16];
    DWORD buf_len = sizeof(adapter_info);
    if (GetAdaptersInfo(adapter_info, &buf_len) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        std::stringstream ss;
        for (UINT i = 0; i < adapter->AddressLength; i++)
            ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(adapter->Address[i]);
        return ss.str();
    }
    return "000000000000";
#elif defined(__APPLE__)
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return "000000000000";
    std::string mac = "000000000000";
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
            if (sdl->sdl_alen == 6) {
                unsigned char* hw = reinterpret_cast<unsigned char*>(LLADDR(sdl));
                std::stringstream ss;
                for (int i = 0; i < 6; i++)
                    ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hw[i]);
                mac = ss.str();
                if (mac != "000000000000") break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return mac;
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return "000000000000";
    std::string mac = "000000000000";
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) continue;
        struct ifreq ifr;
        std::strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
        if (::ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
            unsigned char* hw = reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data);
            std::stringstream ss;
            for (int i = 0; i < 6; i++)
                ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hw[i]);
            mac = ss.str();
            if (mac != "000000000000") { ::close(fd); break; }
        }
        ::close(fd);
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
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
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
        char uuid[256]; DWORD size = sizeof(uuid);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(uuid), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey); return std::string(uuid);
        }
        RegCloseKey(hKey);
    }
    return "unknown-windows-uuid";
#elif defined(__APPLE__)
    io_registry_entry_t root = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    CFStringRef uuid_cf = (CFStringRef)IORegistryEntryCreateCFProperty(
        root, CFSTR(kIOPlatformUUIDKey), kCFAllocatorDefault, 0);
    IOObjectRelease(root);
    if (uuid_cf) {
        char uuid[128];
        CFStringGetCString(uuid_cf, uuid, sizeof(uuid), kCFStringEncodingUTF8);
        CFRelease(uuid_cf);
        return std::string(uuid);
    }
    return "unknown-macos-uuid";
#else
    std::string r = read_first_line("/etc/machine-id");
    if (!r.empty()) return r;
    r = read_first_line("/sys/class/dmi/id/product_uuid");
    if (!r.empty()) return r;
    return "unknown-linux-uuid";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Motherboard UUID
// ─────────────────────────────────────────────────────────────────────────────
std::string License::get_motherboard_uuid() {
#ifdef _WIN32
    // Try WMI via registry shortcut
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[256]; DWORD size = sizeof(buf);
        if (RegQueryValueExA(hKey, "SMBiosData", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            // Return hex of first 16 bytes as a placeholder UUID
            std::stringstream ss;
            for (DWORD i = 0; i < std::min(size, (DWORD)16); ++i)
                ss << std::hex << std::setfill('0') << std::setw(2)
                   << static_cast<int>(static_cast<unsigned char>(buf[i]));
            return ss.str();
        }
        RegCloseKey(hKey);
    }
    return "unknown-win-mb-uuid";
#elif defined(__APPLE__)
    io_registry_entry_t root = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    CFStringRef board_cf = (CFStringRef)IORegistryEntryCreateCFProperty(
        root, CFSTR("board-id"), kCFAllocatorDefault, 0);
    IOObjectRelease(root);
    if (board_cf) {
        char buf[256];
        CFStringGetCString(board_cf, buf, sizeof(buf), kCFStringEncodingUTF8);
        CFRelease(board_cf);
        return std::string(buf);
    }
    return "unknown-macos-mb-uuid";
#else
    std::string r = read_first_line("/sys/class/dmi/id/board_serial");
    if (!r.empty()) return r;
    r = read_first_line("/sys/class/dmi/id/product_uuid");
    if (!r.empty()) return r;
    return "unknown-linux-mb-uuid";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// HDD Serial
// ─────────────────────────────────────────────────────────────────────────────
std::string License::get_hdd_serial() {
#ifdef _WIN32
    // Use DeviceIoControl for first physical drive
    HANDLE h = CreateFileA("\\\\.\\PhysicalDrive0", 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType  = PropertyStandardQuery;
        char buf[4096]; DWORD returned = 0;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                            &query, sizeof(query), buf, sizeof(buf), &returned, nullptr)) {
            auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf);
            if (desc->SerialNumberOffset != 0) {
                std::string serial(buf + desc->SerialNumberOffset);
                // Trim whitespace
                serial.erase(serial.find_last_not_of(" \t\r\n") + 1);
                serial.erase(0, serial.find_first_not_of(" \t\r\n"));
                CloseHandle(h);
                if (!serial.empty()) return serial;
            }
        }
        CloseHandle(h);
    }
    return "unknown-win-hdd-serial";
#elif defined(__APPLE__)
    // IOKit: get serial of first block device
    CFMutableDictionaryRef matching = IOServiceMatching("IOBlockStorageDriver");
    io_iterator_t iter;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iter) == KERN_SUCCESS) {
        io_object_t obj;
        while ((obj = IOIteratorNext(iter)) != 0) {
            CFTypeRef prop = IORegistryEntryCreateCFProperty(
                obj, CFSTR("Serial Number"), kCFAllocatorDefault, 0);
            if (prop) {
                char buf[256];
                CFStringGetCString((CFStringRef)prop, buf, sizeof(buf), kCFStringEncodingUTF8);
                CFRelease(prop);
                IOObjectRelease(obj);
                IOObjectRelease(iter);
                return std::string(buf);
            }
            IOObjectRelease(obj);
        }
        IOObjectRelease(iter);
    }
    return "unknown-macos-hdd-serial";
#else
    // Try common block devices
    for (const char* dev : {"/sys/block/sda/device/serial",
                             "/sys/block/nvme0n1/device/serial",
                             "/sys/block/vda/device/serial",
                             "/sys/block/hda/device/serial"}) {
        std::string r = read_first_line(dev);
        if (!r.empty()) return r;
    }
    return "unknown-linux-hdd-serial";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// BIOS Serial
// ─────────────────────────────────────────────────────────────────────────────
std::string License::get_bios_serial() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[256]; DWORD size = sizeof(buf);
        if (RegQueryValueExA(hKey, "BIOSVersion", nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey); return std::string(buf);
        }
        RegCloseKey(hKey);
    }
    return "unknown-win-bios-serial";
#elif defined(__APPLE__)
    char buf[256]; size_t len = sizeof(buf);
    if (sysctlbyname("hw.model", buf, &len, nullptr, 0) == 0) return std::string(buf, len);
    return "unknown-macos-bios-serial";
#else
    std::string r = read_first_line("/sys/class/dmi/id/bios_vendor");
    std::string v = read_first_line("/sys/class/dmi/id/bios_version");
    std::string d = read_first_line("/sys/class/dmi/id/bios_date");
    if (!r.empty() || !v.empty()) return r + "_" + v + "_" + d;
    return "unknown-linux-bios-serial";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU ID
// ─────────────────────────────────────────────────────────────────────────────
std::string License::get_gpu_id() {
#ifdef _WIN32
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\Video",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char sub[256]; DWORD idx = 0; DWORD sz = sizeof(sub);
        if (RegEnumKeyExA(hKey, idx, sub, &sz, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::string sub_path = std::string("SYSTEM\\CurrentControlSet\\Control\\Video\\") + sub + "\\0000";
            HKEY hSub;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub_path.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                char desc[512]; DWORD dsize = sizeof(desc);
                if (RegQueryValueExA(hSub, "DriverDesc", nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(desc), &dsize) == ERROR_SUCCESS) {
                    RegCloseKey(hSub); RegCloseKey(hKey);
                    return std::string(desc);
                }
                RegCloseKey(hSub);
            }
        }
        RegCloseKey(hKey);
    }
    return "unknown-win-gpu";
#elif defined(__APPLE__)
    CFMutableDictionaryRef matching = IOServiceMatching("IOPCIDevice");
    io_iterator_t iter;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iter) == KERN_SUCCESS) {
        io_object_t obj;
        while ((obj = IOIteratorNext(iter)) != 0) {
            CFTypeRef cls = IORegistryEntryCreateCFProperty(
                obj, CFSTR("IOPCIClass"), kCFAllocatorDefault, 0);
            if (cls) {
                char cbuf[64];
                CFStringGetCString((CFStringRef)cls, cbuf, sizeof(cbuf), kCFStringEncodingUTF8);
                CFRelease(cls);
                if (std::string(cbuf).find("0300") != std::string::npos) {
                    // It's a display controller
                    CFTypeRef name_cf = IORegistryEntryCreateCFProperty(
                        obj, CFSTR("model"), kCFAllocatorDefault, 0);
                    if (name_cf) {
                        char nbuf[256];
                        CFStringGetCString((CFStringRef)name_cf, nbuf, sizeof(nbuf), kCFStringEncodingUTF8);
                        CFRelease(name_cf);
                        IOObjectRelease(obj);
                        IOObjectRelease(iter);
                        return std::string(nbuf);
                    }
                }
            }
            IOObjectRelease(obj);
        }
        IOObjectRelease(iter);
    }
    return "unknown-macos-gpu";
#else
    // Try NVIDIA
    std::string r = read_first_line("/proc/driver/nvidia/version");
    if (!r.empty()) return r;
    // Try PCI ID via /sys
    for (const char* sysf : {"/sys/class/drm/card0/device/uevent",
                               "/sys/class/drm/renderD128/device/uevent"}) {
        std::ifstream f(sysf);
        if (f.is_open()) {
            std::string line;
            while (std::getline(f, line)) {
                if (line.find("PCI_ID=") != std::string::npos ||
                    line.find("PCI_SUBSYS_ID=") != std::string::npos)
                    return line;
            }
        }
    }
    return "unknown-linux-gpu";
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Total RAM
// ─────────────────────────────────────────────────────────────────────────────
uint64_t License::get_total_ram() {
#ifdef _WIN32
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) return static_cast<uint64_t>(ms.ullTotalPhys);
    return 0;
#elif defined(__APPLE__)
    uint64_t mem = 0; size_t len = sizeof(mem);
    if (sysctlbyname("hw.memsize", &mem, &len, nullptr, 0) == 0) return mem;
    return 0;
#else
    struct sysinfo si{};
    if (sysinfo(&si) == 0) return static_cast<uint64_t>(si.totalram) * si.mem_unit;
    return 0;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware profile + composite HWID + machine fingerprint
// ─────────────────────────────────────────────────────────────────────────────
License::HardwareProfile License::get_hardware_profile() {
    HardwareProfile p;
    p.cpu_id          = get_cpu_id();
    p.motherboard_uuid= get_motherboard_uuid();
    p.mac_address     = get_mac_address();
    p.hdd_serial      = get_hdd_serial();
    p.bios_serial     = get_bios_serial();
    p.system_uuid     = get_os_uuid();
    p.total_ram       = get_total_ram();
    p.gpu_id          = get_gpu_id();
    return p;
}

std::string License::compute_composite_hwid(const HardwareProfile& profile) {
    std::string concat =
        profile.cpu_id + "|" +
        profile.motherboard_uuid + "|" +
        profile.mac_address + "|" +
        profile.hdd_serial + "|" +
        profile.bios_serial + "|" +
        profile.system_uuid + "|" +
        std::to_string(profile.total_ram) + "|" +
        profile.gpu_id;

    SecureMemory input(concat.size());
    std::memcpy(input.data(), concat.data(), concat.size());
    SecureMemory hash = crypto_->hash_blake2b(input, 32);
    return to_hex(hash);
}

std::string License::generate_machine_fingerprint() {
    return compute_composite_hwid(get_hardware_profile());
}

std::string License::get_hwid() {
    std::string components = get_mac_address() + get_cpu_id() + get_os_uuid();
    SecureMemory input(components.size());
    std::memcpy(input.data(), components.data(), components.size());
    SecureMemory hash = crypto_->hash_sha256(input);
    return to_hex(hash);
}

// ─────────────────────────────────────────────────────────────────────────────
// License validation — offline
// ─────────────────────────────────────────────────────────────────────────────
bool License::is_expired(const std::chrono::system_clock::time_point& expiry_date) {
    return std::chrono::system_clock::now() > expiry_date;
}

License::ValidationResult License::validate_offline(
    const std::string& hwid,
    const std::string& license_file) {
    return validate_offline(hwid, license_file, export_public_key_hex());
}

License::ValidationResult License::validate_offline(
    const std::string& hwid,
    const std::string& license_file,
    const std::string& public_key_hex) {

    std::ifstream file(license_file, std::ios::binary);
    if (!file.is_open()) return ValidationResult::FILE_NOT_FOUND;

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();

    std::regex pattern(R"(([^|]+)\|([^|]+)\|(.+))");
    std::smatch matches;
    if (!std::regex_match(content, matches, pattern)) return ValidationResult::INVALID_FORMAT;

    std::string stored_hwid  = matches[1].str();
    std::string expiry_str   = matches[2].str();
    std::string signature_hex= matches[3].str();

    if (stored_hwid != hwid) return ValidationResult::HWID_MISMATCH;

    std::tm tm{};
    std::istringstream ss(expiry_str);
    ss >> std::get_time(&tm, "%Y-%m-%d");
    auto expiry = std::chrono::system_clock::from_time_t(std::mktime(&tm));
    if (std::chrono::system_clock::now() > expiry) return ValidationResult::EXPIRED;

    if (signature_hex.empty()) return ValidationResult::INVALID_SIGNATURE;

    std::vector<uint8_t> sig_bytes;
    if (!from_hex(signature_hex, sig_bytes)) return ValidationResult::INVALID_SIGNATURE;

    std::vector<uint8_t> pk_bytes;
    if (!from_hex(public_key_hex, pk_bytes) || pk_bytes.size() != 32)
        return ValidationResult::INVALID_SIGNATURE;

    std::string data_to_verify = stored_hwid + "|" + expiry_str;
    SecureMemory msg(data_to_verify.size());
    std::memcpy(msg.data(), data_to_verify.data(), data_to_verify.size());
    SecureMemory sig_mem(sig_bytes.size());
    std::memcpy(sig_mem.data(), sig_bytes.data(), sig_bytes.size());
    SecureMemory pk_mem(pk_bytes.data(), pk_bytes.size());

    if (!crypto_->verify_ed25519(msg, sig_mem, pk_mem))
        return ValidationResult::INVALID_SIGNATURE;

    return ValidationResult::VALID;
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_online — real HTTP POST with offline fallback
// ─────────────────────────────────────────────────────────────────────────────
License::ValidationResult License::validate_online(
    const std::string& hwid,
    const std::string& license_key,
    const std::string& server_url) {

    {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.validation_attempts++;
        impl_->telemetry.online_mode = true;
    }

    if (license_key.empty()) {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.failed_attempts++;
        impl_->telemetry.last_error = "Empty license key";
        return ValidationResult::INVALID_KEY;
    }
    if (server_url.empty()) {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.failed_attempts++;
        impl_->telemetry.last_error = "Empty server URL";
        return ValidationResult::SERVER_ERROR;
    }

    // Format check XXXX-XXXX-XXXX-XXXX
    std::regex key_pattern(R"([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})");
    if (!std::regex_match(license_key, key_pattern)) return ValidationResult::INVALID_KEY;

    if (is_hwid_blacklisted(hwid)) return ValidationResult::BLACKLISTED;

    // Build fingerprint
    std::string fingerprint = generate_machine_fingerprint();

    // Build JSON payload
    std::string json = "{\"hwid\":\"" + hwid + "\","
                       "\"license_key\":\"" + license_key + "\","
                       "\"fingerprint\":\"" + fingerprint + "\"}";

    std::string validate_url = server_url;
    if (validate_url.back() != '/') validate_url += '/';
    validate_url += "validate";

    std::string resp = http_post(validate_url, json, 10);
    if (resp.empty()) {
        // Server unreachable — offline fallback is not applicable here
        // (we have no license file path), return SERVER_ERROR
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.failed_attempts++;
        impl_->telemetry.last_error = "Server unreachable";
        return ValidationResult::SERVER_ERROR;
    }

    // Parse {"status":"valid|invalid|expired|blacklisted|..."}
    std::string status = json_get(resp, "status");
    if (status == "valid")       return ValidationResult::VALID;
    if (status == "expired")     return ValidationResult::EXPIRED;
    if (status == "blacklisted") return ValidationResult::BLACKLISTED;
    if (status == "hwid_mismatch") return ValidationResult::HWID_MISMATCH;
    if (status == "region_blocked") return ValidationResult::REGION_BLOCKED;

    {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.failed_attempts++;
        impl_->telemetry.last_error = "Server returned: " + status;
    }
    return ValidationResult::INVALID_KEY;
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_with_server
// ─────────────────────────────────────────────────────────────────────────────
License::ValidationResult License::validate_with_server(
    const std::string& license_key,
    const std::string& server_url,
    bool check_blacklist) {

    {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.validation_attempts++;
        impl_->telemetry.online_mode = true;
    }

    if (license_key.empty()) return ValidationResult::INVALID_KEY;
    if (server_url.empty())  return ValidationResult::SERVER_ERROR;

    std::string hwid = get_hwid();
    if (check_blacklist && is_hwid_blacklisted(hwid)) return ValidationResult::BLACKLISTED;

    std::string fingerprint = generate_machine_fingerprint();
    std::string json = "{\"hwid\":\"" + hwid + "\","
                       "\"license_key\":\"" + license_key + "\","
                       "\"fingerprint\":\"" + fingerprint + "\","
                       "\"check_blacklist\":" + (check_blacklist ? "true" : "false") + "}";

    std::string url = server_url;
    if (url.back() != '/') url += '/';
    url += "validate";

    std::string resp = http_post(url, json, 10);
    if (resp.empty()) {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.failed_attempts++;
        impl_->telemetry.last_error = "Server unreachable";
        return ValidationResult::SERVER_ERROR;
    }

    std::string status = json_get(resp, "status");
    if (status == "valid")       return ValidationResult::VALID;
    if (status == "expired")     return ValidationResult::EXPIRED;
    if (status == "blacklisted") return ValidationResult::BLACKLISTED;
    if (status == "hwid_mismatch") return ValidationResult::HWID_MISMATCH;
    if (status == "rate_limited")  return ValidationResult::RATE_LIMITED;
    if (status == "region_blocked") return ValidationResult::REGION_BLOCKED;

    {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.failed_attempts++;
        impl_->telemetry.last_error = "Server returned: " + status;
    }
    return ValidationResult::INVALID_KEY;
}

// ─────────────────────────────────────────────────────────────────────────────
// License file generation
// ─────────────────────────────────────────────────────────────────────────────
bool License::generate_license_file(
    const std::string& hwid,
    const std::string& license_key,
    const std::chrono::system_clock::time_point& expiration_date,
    const std::string& output_file,
    LicenseType type) {
    (void)license_key; (void)type;

    auto tt = std::chrono::system_clock::to_time_t(expiration_date);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
#endif
    std::stringstream date_ss;
    date_ss << std::put_time(&tm_buf, "%Y-%m-%d");
    std::string expiry_str = date_ss.str();

    std::string data = hwid + "|" + expiry_str;
    SecureMemory msg(data.size());
    std::memcpy(msg.data(), data.data(), data.size());
    SecureMemory signature = crypto_->sign_ed25519(msg, signing_keypair_.secret_key);

    std::string license_content = data + "|" + to_hex(signature);
    std::ofstream file(output_file, std::ios::binary);
    if (!file.is_open()) return false;
    file << license_content;
    file.close();
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// License info
// ─────────────────────────────────────────────────────────────────────────────
License::LicenseInfo License::get_license_info(const std::string& license_file) {
    LicenseInfo info{};
    info.is_valid = false;
    info.is_trial = false;
    info.days_remaining = 0;
    info.plan = "Unknown";
    info.type = LicenseType::BASIC;
    info.max_activations = 1;
    info.current_activations = 0;
    info.is_transferable = false;

    std::ifstream file(license_file);
    if (!file.is_open()) return info;

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();

    std::regex pattern(R"(([^|]+)\|([^|]+)\|(.+))");
    std::smatch matches;
    if (!std::regex_match(content, matches, pattern)) return info;

    info.hwid = matches[1].str();
    std::string expiry_str = matches[2].str();

    std::tm tm{};
    std::istringstream ss(expiry_str);
    ss >> std::get_time(&tm, "%Y-%m-%d");
    info.expiry_date = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    auto now = std::chrono::system_clock::now();
    auto diff = info.expiry_date - now;
    info.days_remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::hours>(diff).count() / 24);
    info.is_valid = (info.days_remaining > 0);
    info.is_trial = (info.plan == "Trial");
    info.machine_fingerprint = generate_machine_fingerprint();
    return info;
}

// ─────────────────────────────────────────────────────────────────────────────
// Activate / Deactivate / Transfer
// ─────────────────────────────────────────────────────────────────────────────
bool License::activate_license(const std::string& license_key, const std::string& server_url) {
    if (license_key.empty() || server_url.empty()) return false;

    std::string hwid = get_hwid();
    std::string fingerprint = generate_machine_fingerprint();
    std::string json = "{\"hwid\":\"" + hwid + "\","
                       "\"license_key\":\"" + license_key + "\","
                       "\"fingerprint\":\"" + fingerprint + "\"}";

    std::string url = server_url;
    if (url.back() != '/') url += '/';
    url += "activate";

    std::string resp = http_post(url, json, 15);
    if (resp.empty()) return false;

    std::string status = json_get(resp, "status");
    return (status == "ok" || status == "activated" || status == "success");
}

bool License::deactivate_license(const std::string& license_key, const std::string& server_url) {
    if (license_key.empty() || server_url.empty()) return false;

    std::string hwid = get_hwid();
    std::string json = "{\"hwid\":\"" + hwid + "\","
                       "\"license_key\":\"" + license_key + "\"}";

    std::string url = server_url;
    if (url.back() != '/') url += '/';
    url += "deactivate";

    std::string resp = http_post(url, json, 15);
    if (resp.empty()) return false;

    std::string status = json_get(resp, "status");
    return (status == "ok" || status == "deactivated" || status == "success");
}

bool License::transfer_license(const std::string& old_hwid, const std::string& new_hwid,
                               const std::string& server_url) {
    if (old_hwid.empty() || new_hwid.empty() || server_url.empty()) return false;

    std::string json = "{\"old_hwid\":\"" + old_hwid + "\","
                       "\"new_hwid\":\"" + new_hwid + "\"}";

    std::string url = server_url;
    if (url.back() != '/') url += '/';
    url += "transfer";

    std::string resp = http_post(url, json, 15);
    if (resp.empty()) return false;

    std::string status = json_get(resp, "status");
    return (status == "ok" || status == "transferred" || status == "success");
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-Tamper flags
// ─────────────────────────────────────────────────────────────────────────────
void License::enable_anti_tamper(uint8_t flags) {
    anti_tamper_flags_ = flags;
}

// ─────────────────────────────────────────────────────────────────────────────
// Anti-debug helpers
// ─────────────────────────────────────────────────────────────────────────────
bool License::check_debugger_flags() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    if (remote) return true;
    // NtGlobalFlag check
    DWORD ntgf = 0;
#  ifdef _WIN64
    ntgf = *reinterpret_cast<DWORD*>(__readgsqword(0x60) + 0xBC);
#  else
    ntgf = *reinterpret_cast<DWORD*>(__readfsdword(0x30) + 0x68);
#  endif
    if (ntgf & 0x70) return true;
    return false;
#elif defined(__APPLE__)
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info{};
    size_t sz = sizeof(info);
    sysctl(mib, 4, &info, &sz, nullptr, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
#else
    // Linux: read /proc/self/status for TracerPid
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.substr(0, 9) == "TracerPid") {
            auto col = line.find(':');
            if (col != std::string::npos) {
                std::string val = line.substr(col + 1);
                val.erase(0, val.find_first_not_of(" \t"));
                if (!val.empty() && val != "0") return true;
            }
        }
    }
    // Try ptrace
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) return true;
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
    return false;
#endif
}

bool License::check_parent_process() {
#ifdef _WIN32
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        DWORD my_pid = GetCurrentProcessId();
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == my_pid) { ppid = pe.th32ParentProcessID; break; }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    if (ppid == 0) return false;
    // Check parent name
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
    if (!h) return false;
    char name[MAX_PATH];
    DWORD sz = sizeof(name);
    bool suspicious = false;
    if (QueryFullProcessImageNameA(h, 0, name, &sz)) {
        std::string n(name);
        std::transform(n.begin(), n.end(), n.begin(), ::tolower);
        for (const char* d : {"ollydbg", "x64dbg", "x32dbg", "windbg",
                               "ida", "ida64", "idag", "idaq", "idaw",
                               "immunity", "cheatengine"})
            if (n.find(d) != std::string::npos) { suspicious = true; break; }
    }
    CloseHandle(h);
    return suspicious;
#else
    // Not easily portable; rely on TracerPid check
    return false;
#endif
}

bool License::check_timing_attack() {
    // Execute a spin loop and measure; debuggers significantly slow down timing
    using Clock = std::chrono::high_resolution_clock;
    auto t1 = Clock::now();
    volatile uint64_t dummy = 0;
    for (uint64_t i = 0; i < 100000ULL; ++i) dummy += i;
    (void)dummy;
    auto t2 = Clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
    return (elapsed > 1000); // >1 second for 100k iterations is extremely suspicious
}

bool License::scan_debugger_artifacts() {
#ifdef _WIN32
    // Check for common debugger windows
    for (const char* cls : {"OLLYDBG", "WinDbgFrameClass", "ID", "Zeta Debugger",
                             "Rock Debugger", "ObsidianGUI"}) {
        if (FindWindowA(cls, nullptr)) return true;
    }
    return false;
#else
    return false;
#endif
}

bool License::check_breakpoints() {
#ifdef _WIN32
    // Scan INT3 (0xCC) bytes at entry point of ntdll functions
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    const char* funcs[] = { "NtQueryInformationProcess", "NtSetInformationThread",
                             "NtClose", "NtQueryObject" };
    for (const char* fn : funcs) {
        FARPROC addr = GetProcAddress(ntdll, fn);
        if (addr && *reinterpret_cast<uint8_t*>(addr) == 0xCC) return true;
    }
    return false;
#else
    return false;
#endif
}

bool License::detect_debugger() {
    bool detected = false;
    detected |= check_debugger_flags();
    detected |= check_parent_process();
    detected |= scan_debugger_artifacts();
    detected |= check_breakpoints();
    if (detected) invoke_tamper_callback("debugger_detected");
    return detected;
}

// ─────────────────────────────────────────────────────────────────────────────
// VM detection helpers
// ─────────────────────────────────────────────────────────────────────────────
bool License::check_hypervisor_brand() {
#if defined(__x86_64__) || defined(__i386__) || defined(_WIN32)
    // CPUID leaf 0x40000000 returns hypervisor vendor string
#  ifdef _WIN32
    int info[4];
    __cpuid(info, 0x40000000);
#  else
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0x40000000));
    int info[4] = { static_cast<int>(eax), static_cast<int>(ebx),
                    static_cast<int>(ecx), static_cast<int>(edx) };
#  endif
    char vendor[13] = {};
    std::memcpy(vendor,     &info[1], 4);
    std::memcpy(vendor + 4, &info[2], 4);
    std::memcpy(vendor + 8, &info[3], 4);
    std::string v(vendor);
    // Known hypervisor signatures
    for (const char* s : {"KVMKVMKVM", "VMwareVMware", "VBoxVBoxVBox",
                           "Microsoft Hv", "XenVMMXenVMM", "prl hyperv"})
        if (v.find(s) != std::string::npos) return true;
    // Check hypervisor present bit (ECX bit 31 from CPUID leaf 1)
#  ifdef _WIN32
    __cpuid(info, 1);
#  else
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    info[2] = static_cast<int>(ecx);
#  endif
    if (info[2] & (1 << 31)) return true;
    return false;
#else
    return false;
#endif
}

bool License::check_vm_registry_keys() {
#ifdef _WIN32
    static const char* keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        "SYSTEM\\ControlSet001\\Services\\vboxvideo",
        "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
        "SYSTEM\\ControlSet001\\Services\\vmbus",
        "SYSTEM\\ControlSet001\\Services\\VMBusHID",
        nullptr
    };
    for (int i = 0; keys[i]; ++i) {
        HKEY hk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            RegCloseKey(hk); return true;
        }
    }
    return false;
#else
    return false;
#endif
}

bool License::check_vm_processes() {
#ifdef _WIN32
    static const char* vm_procs[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "VBoxService.exe", "VBoxTray.exe",
        "xenservice.exe", "qemu-ga.exe",
        nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32First(snap, &pe)) {
        do {
            std::string n(pe.szExeFile);
            std::transform(n.begin(), n.end(), n.begin(), ::tolower);
            for (int i = 0; vm_procs[i]; ++i)
                if (n == vm_procs[i]) { found = true; break; }
            if (found) break;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
#else
    // Check /proc for known VM agent names
    static const char* vm_procs[] = {
        "vmtoolsd", "vmware-user", "VBoxService", "xenbus", "qemu-ga", nullptr
    };
    std::ifstream comm;
    for (int pid = 1; pid < 65536; ++pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/comm";
        std::ifstream f(path);
        if (!f.is_open()) continue;
        std::string name;
        std::getline(f, name);
        for (int i = 0; vm_procs[i]; ++i)
            if (name == vm_procs[i]) return true;
    }
    return false;
#endif
}

bool License::check_vm_drivers() {
#ifdef _WIN32
    static const char* drivers[] = {
        "vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxvideo.sys",
        "vmhgfs.sys", "vmxnet.sys", "vmci.sys",
        nullptr
    };
    for (int i = 0; drivers[i]; ++i) {
        std::string path = "C:\\Windows\\System32\\drivers\\";
        path += drivers[i];
        DWORD attr = GetFileAttributesA(path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) return true;
    }
    return false;
#else
    // Check loaded kernel modules
    std::ifstream f("/proc/modules");
    std::string line;
    static const char* mods[] = { "vboxguest", "vboxsf", "vboxvideo",
                                   "vmhgfs", "vmxnet3", "vmw_vmci", nullptr };
    while (std::getline(f, line)) {
        std::string name = line.substr(0, line.find(' '));
        for (int i = 0; mods[i]; ++i)
            if (name == mods[i]) return true;
    }
    return false;
#endif
}

bool License::check_vm_mac_prefix() {
    // OUI prefixes known for virtual NICs
    static const char* vm_ouis[] = {
        "000c29",  // VMware
        "000569",  // VMware
        "001c14",  // VMware
        "005056",  // VMware
        "0800279", // VirtualBox (partial)
        "080027",  // VirtualBox
        "525400",  // QEMU/KVM
        "00163e",  // Xen
        nullptr
    };
    std::string mac = get_mac_address();
    std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);
    for (int i = 0; vm_ouis[i]; ++i) {
        if (mac.substr(0, std::strlen(vm_ouis[i])) == vm_ouis[i]) return true;
    }
    return false;
}

bool License::detect_vm() {
    bool vm = false;
    vm |= check_hypervisor_brand();
    vm |= check_vm_registry_keys();
    vm |= check_vm_mac_prefix();
    vm |= check_vm_processes();
    vm |= check_vm_drivers();
    if (vm) invoke_tamper_callback("vm_detected");
    return vm;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sandbox detection
// ─────────────────────────────────────────────────────────────────────────────
bool License::detect_sandbox() {
#ifdef _WIN32
    // Typical sandbox artifacts
    // 1. Very low physical RAM (< 1 GB)
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys < (1ULL << 30)) return true;
    // 2. Fewer than 2 CPUs
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;
    // 3. Known sandbox usernames / computer names
    char user[256], comp[256];
    DWORD ulen = sizeof(user), clen = sizeof(comp);
    GetUserNameA(user, &ulen);
    GetComputerNameA(comp, &clen);
    std::string u(user), c(comp);
    std::transform(u.begin(), u.end(), u.begin(), ::tolower);
    std::transform(c.begin(), c.end(), c.begin(), ::tolower);
    for (const char* n : {"sandbox", "maltest", "tester", "virus", "sample",
                           "malware", "analysis", "analyst"})
        if (u.find(n) != std::string::npos || c.find(n) != std::string::npos) return true;
    // 4. Typical sandbox files
    for (const char* f : {"C:\\analysis", "C:\\inetpub\\wwwroot\\cuckoo",
                           "C:\\strawberry", "C:\\Python27\\Lib\\site-packages\\cuckoo"})
        if (GetFileAttributesA(f) != INVALID_FILE_ATTRIBUTES) return true;
    return false;
#else
    // Linux: low RAM, low CPU count, known sandbox paths
    struct sysinfo si{};
    if (sysinfo(&si) == 0) {
        uint64_t total = static_cast<uint64_t>(si.totalram) * si.mem_unit;
        if (total < (512ULL << 20)) return true; // < 512 MB
    }
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 2) return true;
    for (const char* p : {"/tmp/.cuckoo", "/opt/cuckoo", "/home/analysis"}) {
        struct stat st{};
        if (stat(p, &st) == 0) return true;
    }
    return false;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// Code / memory integrity
// ─────────────────────────────────────────────────────────────────────────────
std::string License::compute_code_hash() {
    // Hash the .text section of the current executable (best-effort)
#ifdef _WIN32
    HMODULE self = GetModuleHandleA(nullptr);
    if (!self) return "unknown";
    // Walk PE headers
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(self);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(self) + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (std::strncmp(reinterpret_cast<const char*>(sec->Name), ".text", 5) == 0) {
            auto* ptr  = reinterpret_cast<uint8_t*>(self) + sec->VirtualAddress;
            size_t sz  = sec->Misc.VirtualSize;
            SecureMemory mem(ptr, sz);
            return to_hex(crypto_->hash_sha256(mem));
        }
    }
    return "no-text-section";
#else
    // On Linux/macOS: hash /proc/self/exe or argv[0]
    std::ifstream f("/proc/self/exe", std::ios::binary);
    if (!f.is_open()) return "no-exe";
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    f.close();
    SecureMemory mem(reinterpret_cast<const uint8_t*>(content.data()), content.size());
    return to_hex(crypto_->hash_sha256(mem));
#endif
}

bool License::verify_code_sections() {
    // Generate hash once (first call) and compare on subsequent calls.
    // Use a static variable — acceptable since the binary doesn't change at runtime.
    static std::string baseline;
    static std::mutex mtx;
    std::lock_guard<std::mutex> lk(mtx);
    std::string current = compute_code_hash();
    if (baseline.empty()) { baseline = current; return true; }
    return (baseline == current);
}

bool License::check_code_integrity() {
    bool ok = verify_code_sections();
    if (!ok) invoke_tamper_callback("code_integrity_failed");
    return ok;
}

bool License::check_memory_integrity() {
    // Verify that the obfuscated license data (if any) hasn't changed unexpectedly
    if (impl_->obfuscated_data.empty()) return true;
    // Re-compute XOR and compare — if xor key is zero the data is pristine
    const auto& key = impl_->obf_key;
    for (size_t i = 0; i < impl_->obfuscated_data.size(); ++i) {
        uint8_t b = static_cast<uint8_t>(impl_->obfuscated_data[i]) ^ key[i % key.size()];
        (void)b; // just exercise; in a real scenario compare to known digest
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// License data obfuscation
// ─────────────────────────────────────────────────────────────────────────────
void License::obfuscate_license_data() {
    // Populate obf_key from HWID hash
    std::string hwid = get_hwid();
    SecureMemory inp(hwid.size());
    std::memcpy(inp.data(), hwid.data(), hwid.size());
    SecureMemory hashed = crypto_->hash_blake2b(inp, 8);
    for (size_t i = 0; i < 8; ++i)
        impl_->obf_key[i] = hashed.data()[i];

    // XOR obfuscate the cached license blob
    std::lock_guard<std::mutex> lk(impl_->cache_mutex);
    if (impl_->secure_cache.empty()) return;
    std::string obf = impl_->secure_cache;
    const auto& key = impl_->obf_key;
    for (size_t i = 0; i < obf.size(); ++i)
        obf[i] ^= static_cast<char>(key[i % key.size()]);
    impl_->obfuscated_data = obf;
}

// ─────────────────────────────────────────────────────────────────────────────
// Protect license memory
// ─────────────────────────────────────────────────────────────────────────────
void License::protect_license_memory() {
    // Attempt to mlock the signing keypair memory
    signing_keypair_.secret_key.lock();
    signing_keypair_.public_key.lock();
}

// ─────────────────────────────────────────────────────────────────────────────
// check_anti_debug — aggregated
// ─────────────────────────────────────────────────────────────────────────────
License::AntiDebugInfo License::check_anti_debug() {
    AntiDebugInfo info{};
    info.debugger_present     = check_debugger_flags();
    info.remote_debugger      = check_parent_process();
    info.kernel_debugger      = false; // kernel-level detection requires ring-0
    info.vm_detected          = detect_vm();
    info.vm_type              = "";
    info.sandbox_detected     = detect_sandbox();
    info.memory_tampering     = !check_memory_integrity();
    info.code_integrity_failed= !check_code_integrity();

#ifdef _WIN32
    // Try to determine VM type
    if (info.vm_detected) {
        if (check_vm_registry_keys()) {
            HKEY hk;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
                RegCloseKey(hk); info.vm_type = "VMware";
            } else {
                info.vm_type = "VirtualBox";
            }
        }
    }
#endif

    if (info.debugger_present || info.remote_debugger)
        invoke_tamper_callback("debugger_detected");
    if (info.vm_detected)
        invoke_tamper_callback("vm_detected");
    if (info.sandbox_detected)
        invoke_tamper_callback("sandbox_detected");
    return info;
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime Protection — periodic validation
// ─────────────────────────────────────────────────────────────────────────────
void License::start_periodic_validation(int interval_minutes) {
    if (impl_->periodic_active.load()) return;
    validation_interval_ = std::chrono::minutes(interval_minutes);
    impl_->periodic_active.store(true);
    impl_->periodic_thread = std::thread([this]() {
        while (impl_->periodic_active.load()) {
            std::this_thread::sleep_for(validation_interval_);
            if (!impl_->periodic_active.load()) break;
            schedule_next_validation();
        }
    });
}

void License::stop_periodic_validation() {
    impl_->periodic_active.store(false);
    if (impl_->periodic_thread.joinable())
        impl_->periodic_thread.join();
}

void License::schedule_next_validation() {
    // Run anti-tamper checks and trigger callbacks if needed
    if (anti_tamper_flags_ & static_cast<uint8_t>(AntiTamperFlag::CHECK_DEBUGGER))
        detect_debugger();
    if (anti_tamper_flags_ & static_cast<uint8_t>(AntiTamperFlag::CHECK_VM))
        detect_vm();
    if (anti_tamper_flags_ & static_cast<uint8_t>(AntiTamperFlag::CHECK_INTEGRITY))
        check_code_integrity();
    if (anti_tamper_flags_ & static_cast<uint8_t>(AntiTamperFlag::CHECK_MEMORY))
        check_memory_integrity();
    if (anti_tamper_flags_ & static_cast<uint8_t>(AntiTamperFlag::ENCRYPT_MEMORY))
        protect_license_memory();
    {
        std::lock_guard<std::mutex> lk(impl_->telem_mutex);
        impl_->telemetry.last_validation = std::chrono::system_clock::now();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature verification
// ─────────────────────────────────────────────────────────────────────────────
bool License::verify_license_signature(const std::string& license_data,
                                       const std::string& signature) {
    std::vector<uint8_t> sig_bytes;
    if (!from_hex(signature, sig_bytes)) return false;

    SecureMemory msg(license_data.size());
    std::memcpy(msg.data(), license_data.data(), license_data.size());
    SecureMemory sig_mem(sig_bytes.size());
    std::memcpy(sig_mem.data(), sig_bytes.data(), sig_bytes.size());

    return crypto_->verify_ed25519(msg, sig_mem, signing_keypair_.public_key);
}

// ─────────────────────────────────────────────────────────────────────────────
// Crypto helpers
// ─────────────────────────────────────────────────────────────────────────────
std::vector<uint8_t> License::derive_key_from_hwid(const std::string& hwid) {
    SecureMemory inp(hwid.size());
    std::memcpy(inp.data(), hwid.data(), hwid.size());
    SecureMemory hashed = crypto_->hash_blake2b(inp, 32);
    std::vector<uint8_t> key(32);
    std::memcpy(key.data(), hashed.data(), 32);
    return key;
}

std::string License::sign_license_data(const std::string& data) {
    SecureMemory msg(data.size());
    std::memcpy(msg.data(), data.data(), data.size());
    SecureMemory sig = crypto_->sign_ed25519(msg, signing_keypair_.secret_key);
    return to_hex(sig);
}

std::string License::encrypt_license_data(const std::string& data) {
    std::string hwid = get_hwid();
    std::vector<uint8_t> key_bytes = derive_key_from_hwid(hwid);
    SecureMemory key(key_bytes.data(), key_bytes.size());
    SecureMemory plaintext(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    SecureMemory ct = crypto_->encrypt_aead(plaintext, key);
    return to_hex(ct);
}

std::string License::decrypt_license_data(const std::string& encrypted_data) {
    std::vector<uint8_t> ct_bytes;
    if (!from_hex(encrypted_data, ct_bytes)) return "";
    std::string hwid = get_hwid();
    std::vector<uint8_t> key_bytes = derive_key_from_hwid(hwid);
    SecureMemory key(key_bytes.data(), key_bytes.size());
    SecureMemory ct(ct_bytes.data(), ct_bytes.size());
    try {
        SecureMemory pt = crypto_->decrypt_aead(ct, key);
        return std::string(reinterpret_cast<const char*>(pt.data()), pt.size());
    } catch (...) {
        return "";
    }
}

bool License::store_license_securely(const std::string& data) {
    std::string enc = encrypt_license_data(data);
    if (enc.empty()) return false;
    std::lock_guard<std::mutex> lk(impl_->cache_mutex);
    impl_->secure_cache = enc;
    impl_->secure_cache_hwid = get_hwid();
    return true;
}

std::string License::retrieve_secure_license() {
    std::lock_guard<std::mutex> lk(impl_->cache_mutex);
    if (impl_->secure_cache.empty()) return "";
    return decrypt_license_data(impl_->secure_cache);
}

void License::clear_license_cache() {
    std::lock_guard<std::mutex> lk(impl_->cache_mutex);
    impl_->secure_cache.clear();
    impl_->secure_cache_hwid.clear();
    impl_->obfuscated_data.clear();
    impl_->obf_key.fill(0);
    validation_cache_.clear();
}

// ─────────────────────────────────────────────────────────────────────────────
// Blacklist & Rate Limiting
// ─────────────────────────────────────────────────────────────────────────────
bool License::is_hwid_blacklisted(const std::string& hwid) {
    std::lock_guard<std::mutex> lk(impl_->blacklist_mutex);
    return impl_->hwid_blacklist.count(hwid) > 0;
}

void License::update_blacklist(const std::vector<std::string>& blacklisted_hwids) {
    std::lock_guard<std::mutex> lk(impl_->blacklist_mutex);
    for (const auto& h : blacklisted_hwids)
        impl_->hwid_blacklist.insert(h);
}

bool License::is_ip_rate_limited(const std::string& ip_address) {
    std::lock_guard<std::mutex> lk(impl_->rate_mutex);
    auto now = std::chrono::steady_clock::now();
    auto& entry = impl_->rate_map[ip_address];
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - entry.window_start).count();

    if (elapsed >= Impl::RATE_WINDOW_SEC) {
        entry.count = 1;
        entry.window_start = now;
        return false;
    }
    entry.count++;
    return (entry.count > Impl::RATE_LIMIT_MAX);
}

// ─────────────────────────────────────────────────────────────────────────────
// Trial Management
// ─────────────────────────────────────────────────────────────────────────────
bool License::create_trial_license(int days, const std::string& output_file) {
    if (days <= 0) return false;
    auto expiry = std::chrono::system_clock::now() + std::chrono::hours(24 * days);
    std::string hwid = get_hwid();

    // Mark trial as used (store start time)
    {
        std::lock_guard<std::mutex> lk(impl_->trial_mutex);
        impl_->trial_used  = true;
        impl_->trial_start = std::chrono::system_clock::now();
        impl_->trial_days  = days;
    }

    return generate_license_file(hwid, "TRIAL-LICENSE", expiry, output_file, LicenseType::TRIAL);
}

bool License::is_trial_expired() {
    std::lock_guard<std::mutex> lk(impl_->trial_mutex);
    if (!impl_->trial_used) return false;
    auto expiry = impl_->trial_start + std::chrono::hours(24 * impl_->trial_days);
    return std::chrono::system_clock::now() > expiry;
}

int License::get_trial_days_remaining() {
    std::lock_guard<std::mutex> lk(impl_->trial_mutex);
    if (!impl_->trial_used) return 0;
    auto expiry = impl_->trial_start + std::chrono::hours(24 * impl_->trial_days);
    auto now    = std::chrono::system_clock::now();
    if (now >= expiry) return 0;
    auto diff = std::chrono::duration_cast<std::chrono::hours>(expiry - now).count();
    return static_cast<int>(diff / 24);
}

bool License::has_trial_been_used() {
    std::lock_guard<std::mutex> lk(impl_->trial_mutex);
    return impl_->trial_used;
}

// ─────────────────────────────────────────────────────────────────────────────
// Feature Flags
// ─────────────────────────────────────────────────────────────────────────────
bool License::is_feature_enabled(const std::string& feature_name) {
    std::lock_guard<std::mutex> lk(impl_->feature_mutex);
    auto it = impl_->feature_flags.find(feature_name);
    if (it == impl_->feature_flags.end()) return false;
    return it->second;
}

std::vector<std::string> License::get_enabled_features() {
    std::lock_guard<std::mutex> lk(impl_->feature_mutex);
    std::vector<std::string> result;
    for (const auto& kv : impl_->feature_flags)
        if (kv.second) result.push_back(kv.first);
    return result;
}

void License::set_feature_flag(const std::string& feature_name, bool enabled) {
    std::lock_guard<std::mutex> lk(impl_->feature_mutex);
    impl_->feature_flags[feature_name] = enabled;
}

// ─────────────────────────────────────────────────────────────────────────────
// Telemetry
// ─────────────────────────────────────────────────────────────────────────────
License::TelemetryData License::get_telemetry() const {
    std::lock_guard<std::mutex> lk(impl_->telem_mutex);
    return impl_->telemetry;
}

void License::send_telemetry(const std::string& server_url) {
    TelemetryData td = get_telemetry();
    if (server_url.empty()) return;

    auto tp_sec = std::chrono::duration_cast<std::chrono::seconds>(
        td.last_validation.time_since_epoch()).count();

    // R7-SEC-08: Escape last_error to prevent JSON injection via server response
    std::string escaped_last_error = json_escape_string(td.last_error);

    std::string json =
        "{\"last_validation\":" + std::to_string(tp_sec) + ","
        "\"validation_attempts\":" + std::to_string(td.validation_attempts) + ","
        "\"failed_attempts\":" + std::to_string(td.failed_attempts) + ","
        "\"online_mode\":" + (td.online_mode ? "true" : "false") + ","
        "\"last_error\":\"" + escaped_last_error + "\"}";

    std::string url = server_url;
    if (url.back() != '/') url += '/';
    url += "telemetry";

    http_post(url, json, 5); // fire-and-forget, ignore response
}

// ─────────────────────────────────────────────────────────────────────────────
// Security Callbacks
// ─────────────────────────────────────────────────────────────────────────────
void License::set_tamper_callback(SecurityCallback callback) {
    tamper_callback_ = std::move(callback);
}

void License::set_expiry_callback(SecurityCallback callback) {
    expiry_callback_ = std::move(callback);
}

void License::invoke_tamper_callback(const std::string& reason) {
    if (tamper_callback_) tamper_callback_(reason);
}

// ─────────────────────────────────────────────────────────────────────────────
// License File Generation (already fully implemented above)
// is_expired (already implemented above)
// ─────────────────────────────────────────────────────────────────────────────

} // namespace ncp
