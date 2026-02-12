#include "NetworkManager.hpp"
#include <cstring>
#include <chrono>
#include <stdexcept>
#include <set>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <fcntl.h>
#include <poll.h>
#endif

namespace ncp {

NetworkManager::NetworkManager() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
#endif
}

NetworkManager::~NetworkManager() {
#ifdef _WIN32
    WSACleanup();
#endif
}

std::vector<NetworkInterface> NetworkManager::get_interfaces() const {
    return enumerate_interfaces();
}

NetworkInterface NetworkManager::get_interface(const std::string& name) const {
    if (name.empty()) {
        return NetworkInterface{};
    }
    auto interfaces = enumerate_interfaces();
    for (const auto& iface : interfaces) {
        if (iface.name == name) {
            return iface;
        }
    }
    return NetworkInterface{};
}

bool NetworkManager::set_active_interface(const std::string& name) {
    if (name.empty()) return false;
    auto interfaces = enumerate_interfaces();
    for (const auto& iface : interfaces) {
        if (iface.name == name) {
            std::lock_guard<std::mutex> lock(mutex_);
            active_interface_ = name;
            return true;
        }
    }
    return false;
}

std::string NetworkManager::get_active_interface_name() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_interface_;
}

NetworkStats NetworkManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_stats_;
}

NetworkStats NetworkManager::get_interface_stats(const std::string& name) const {
    NetworkStats stats;
    if (name.empty()) return stats;

#ifdef _WIN32
    MIB_IF_ROW2 row;
    memset(&row, 0, sizeof(row));
    // Try to find the interface by alias
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    if (!addresses) return stats;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addresses, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (!addresses) return stats;
        if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addresses, &bufferSize) != NO_ERROR) {
            free(addresses);
            return stats;
        }
    }
    for (PIP_ADAPTER_ADDRESSES addr = addresses; addr; addr = addr->Next) {
        if (addr->AdapterName == name) {
            row.InterfaceIndex = addr->IfIndex;
            if (GetIfEntry2(&row) == NO_ERROR) {
                stats.bytes_sent = row.OutOctets;
                stats.bytes_received = row.InOctets;
                stats.packets_sent = row.OutUcastPkts;
                stats.packets_received = row.InUcastPkts;
            }
            break;
        }
    }
    free(addresses);
#else
    // Linux: read /proc/net/dev or /sys/class/net
    std::string path = "/sys/class/net/" + name + "/statistics/";
    auto read_stat = [](const std::string& filepath) -> uint64_t {
        FILE* f = fopen(filepath.c_str(), "r");
        if (!f) return 0;
        uint64_t val = 0;
        if (fscanf(f, "%lu", &val) != 1) val = 0;
        fclose(f);
        return val;
    };
    stats.bytes_sent = read_stat(path + "tx_bytes");
    stats.bytes_received = read_stat(path + "rx_bytes");
    stats.packets_sent = read_stat(path + "tx_packets");
    stats.packets_received = read_stat(path + "rx_packets");
#endif
    stats.last_update = std::chrono::steady_clock::now();
    return stats;
}

void NetworkManager::set_stats_callback(StatsCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_callback_ = std::move(callback);
}

bool NetworkManager::test_connection(const std::string& host, int port, int timeout_ms) {
    if (host.empty() || port <= 0 || port > 65535) return false;

#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        closesocket(sock);
        return false;
    }

    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    connect(sock, (sockaddr*)&addr, sizeof(addr));

    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(0, nullptr, &writefds, nullptr, &tv);
    closesocket(sock);
    return result > 0;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(sock);
        return false;
    }

    connect(sock, (sockaddr*)&addr, sizeof(addr));

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    int result = poll(&pfd, 1, timeout_ms);

    close(sock);
    return result > 0 && (pfd.revents & POLLOUT);
#endif
}

int NetworkManager::get_latency(const std::string& host) {
    auto start = std::chrono::high_resolution_clock::now();
    bool connected = test_connection(host, 53, 5000);
    auto end = std::chrono::high_resolution_clock::now();

    if (!connected) return -1;

    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count());
}

void NetworkManager::update_stats() {
    std::string iface_name;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        iface_name = active_interface_;
    }

    if (iface_name.empty()) return;

    NetworkStats new_stats = get_interface_stats(iface_name);

    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            new_stats.last_update - current_stats_.last_update).count();

        if (elapsed > 0) {
            double seconds = elapsed / 1000.0;
            new_stats.upload_speed = static_cast<double>(
                new_stats.bytes_sent - current_stats_.bytes_sent) / seconds;
            new_stats.download_speed = static_cast<double>(
                new_stats.bytes_received - current_stats_.bytes_received) / seconds;
        }

        current_stats_ = new_stats;

        if (stats_callback_) {
            stats_callback_(current_stats_);
        }
    }
}

std::vector<NetworkInterface> NetworkManager::enumerate_interfaces() const {
    std::vector<NetworkInterface> result;

#ifdef _WIN32
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    if (!addresses) return result;

    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        if (!addresses) return result;
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize);
    }

    if (ret == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES addr = addresses; addr != nullptr; addr = addr->Next) {
            NetworkInterface iface;
            char name[256];
            wcstombs(name, addr->FriendlyName, sizeof(name));
            iface.name = addr->AdapterName;
            iface.display_name = name;

            if (addr->PhysicalAddressLength > 0) {
                char mac[32];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    addr->PhysicalAddress[0], addr->PhysicalAddress[1],
                    addr->PhysicalAddress[2], addr->PhysicalAddress[3],
                    addr->PhysicalAddress[4], addr->PhysicalAddress[5]);
                iface.mac_address = mac;
            }

            iface.is_up = (addr->OperStatus == IfOperStatusUp);
            iface.is_loopback = (addr->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
            iface.is_wireless = (addr->IfType == IF_TYPE_IEEE80211);

            for (auto ua = addr->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
                    iface.ip_address = ip;
                    break;
                }
            }
            result.push_back(std::move(iface));
        }
    }
    free(addresses);
#else
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) return result;

    // Use a set to avoid duplicate interface names
    std::set<std::string> seen;
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name) continue;
        std::string iface_name = ifa->ifa_name;

        if (seen.count(iface_name) == 0) {
            seen.insert(iface_name);
            NetworkInterface iface;
            iface.name = iface_name;
            iface.display_name = iface_name;
            iface.is_up = (ifa->ifa_flags & IFF_UP) != 0;
            iface.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            result.push_back(std::move(iface));
        }

        // Update IP for existing entry
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            for (auto& iface : result) {
                if (iface.name == iface_name && iface.ip_address.empty()) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in*)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
                    iface.ip_address = ip;
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddr);
#endif

    return result;
}

} // namespace ncp
