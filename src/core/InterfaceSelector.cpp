#include "InterfaceSelector.hpp"
#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

namespace ncp {

InterfaceSelector::InterfaceSelector() {
    enumerate_interfaces();
}

InterfaceSelector::~InterfaceSelector() {
}

std::vector<InterfaceInfo> InterfaceSelector::get_available_interfaces() const {
    return interfaces_;
}

void InterfaceSelector::refresh_interfaces() {
    enumerate_interfaces();
}

bool InterfaceSelector::select_interface(const std::string& name) {
    for (const auto& iface : interfaces_) {
        if (iface.name == name) {
            selected_ = iface;
            if (selection_callback_) {
                selection_callback_(selected_);
            }
            return true;
        }
    }
    return false;
}

bool InterfaceSelector::select_best_interface() {
    auto active = get_active_interfaces();
    if (active.empty()) return false;
    
    // Prefer wired over wireless
    for (const auto& iface : active) {
        if (!iface.is_wireless && !iface.is_loopback) {
            return select_interface(iface.name);
        }
    }
    
    // Fall back to any active interface
    for (const auto& iface : active) {
        if (!iface.is_loopback) {
            return select_interface(iface.name);
        }
    }
    
    return false;
}

std::vector<InterfaceInfo> InterfaceSelector::get_active_interfaces() const {
    std::vector<InterfaceInfo> result;
    for (const auto& iface : interfaces_) {
        if (iface.is_up && !iface.ip_address.empty()) {
            result.push_back(iface);
        }
    }
    return result;
}

std::vector<InterfaceInfo> InterfaceSelector::get_wireless_interfaces() const {
    std::vector<InterfaceInfo> result;
    for (const auto& iface : interfaces_) {
        if (iface.is_wireless) {
            result.push_back(iface);
        }
    }
    return result;
}

std::vector<InterfaceInfo> InterfaceSelector::get_wired_interfaces() const {
    std::vector<InterfaceInfo> result;
    for (const auto& iface : interfaces_) {
        if (!iface.is_wireless && !iface.is_loopback) {
            result.push_back(iface);
        }
    }
    return result;
}

void InterfaceSelector::enumerate_interfaces() {
    interfaces_.clear();
    
#ifdef _WIN32
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES addresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES addr = addresses; addr != nullptr; addr = addr->Next) {
            InterfaceInfo info;
            
            char name[256];
            wcstombs(name, addr->FriendlyName, sizeof(name));
            info.name = addr->AdapterName;
            info.display_name = name;
            
            if (addr->PhysicalAddressLength > 0) {
                char mac[32];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                    addr->PhysicalAddress[0], addr->PhysicalAddress[1],
                    addr->PhysicalAddress[2], addr->PhysicalAddress[3],
                    addr->PhysicalAddress[4], addr->PhysicalAddress[5]);
                info.mac_address = mac;
            }
            
            info.is_up = (addr->OperStatus == IfOperStatusUp);
            info.is_loopback = (addr->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
            info.is_wireless = (addr->IfType == IF_TYPE_IEEE80211);
            
            for (auto ua = addr->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr, ip, sizeof(ip));
                    info.ip_address = ip;
                    break;
                }
            }
            
            interfaces_.push_back(info);
        }
    }
    free(addresses);
#else
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr) continue;
            
            InterfaceInfo info;
            info.name = ifa->ifa_name;
            info.display_name = ifa->ifa_name;
            info.is_up = (ifa->ifa_flags & IFF_UP) != 0;
            info.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            
            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((sockaddr_in*)ifa->ifa_addr)->sin_addr, ip, sizeof(ip));
                info.ip_address = ip;
            }
            
            interfaces_.push_back(info);
        }
        freeifaddrs(ifaddr);
    }
#endif
}

} // namespace ncp
