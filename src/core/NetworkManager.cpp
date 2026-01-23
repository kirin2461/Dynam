#include "NetworkManager.hpp"
#include <cstring>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
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
#endif

namespace ncp {

NetworkManager::NetworkManager() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
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
    auto interfaces = enumerate_interfaces();
    for (const auto& iface : interfaces) {
        if (iface.name == name) {
            return iface;
        }
    }
    return NetworkInterface{};
}

bool NetworkManager::set_active_interface(const std::string& name) {
    auto interfaces = enumerate_interfaces();
    for (const auto& iface : interfaces) {
        if (iface.name == name) {
            active_interface_ = name;
            return true;
        }
    }
    return false;
}

NetworkStats NetworkManager::get_stats() const {
    return current_stats_;
}

NetworkStats NetworkManager::get_interface_stats(const std::string& name) const {
    // Platform-specific implementation would go here
    return NetworkStats{};
}

bool NetworkManager::test_connection(const std::string& host, int port) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    // Set non-blocking with timeout
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    
    int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
    closesocket(sock);
    
    return result == 0 || WSAGetLastError() == WSAEWOULDBLOCK;
#else
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int result = connect(sock, (sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    return result == 0;
#endif
}

int NetworkManager::get_latency(const std::string& host) {
    auto start = std::chrono::high_resolution_clock::now();
    bool connected = test_connection(host, 53);
    auto end = std::chrono::high_resolution_clock::now();
    
    if (!connected) return -1;
    
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

void NetworkManager::update_stats() {
    // Update stats from system
    if (stats_callback_) {
        stats_callback_(current_stats_);
    }
}

std::vector<NetworkInterface> NetworkManager::enumerate_interfaces() const {
    std::vector<NetworkInterface> result;
    
#ifdef _WIN32
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES addr = addresses; addr != nullptr; addr = addr->Next) {
            NetworkInterface iface;
            
            // Convert wide string to narrow
            char name[256];
            wcstombs(name, addr->FriendlyName, sizeof(name));
            iface.name = addr->AdapterName;
            iface.display_name = name;
            
            // MAC address
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
            
            // Get IP address
            for (auto ua = addr->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
                    iface.ip_address = ip;
                    break;
                }
            }
            
            result.push_back(iface);
        }
    }
    free(addresses);
#else
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            
            NetworkInterface iface;
            iface.name = ifa->ifa_name;
            iface.display_name = ifa->ifa_name;
            iface.is_up = (ifa->ifa_flags & IFF_UP) != 0;
            iface.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            
            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
                iface.ip_address = ip;
            }
            
            result.push_back(iface);
        }
        freeifaddrs(ifaddr);
    }
#endif
    
    return result;
}

} // namespace ncp
