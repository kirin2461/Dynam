#include "../include/ncp_network.hpp"
#include "../include/ncp_mimicry.hpp"
#include <stdexcept>
#include <cstring>
#include <string>
#include <algorithm>
#include <thread>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#ifdef HAVE_PCAP
#include <pcap.h>
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif
#endif

namespace ncp {

#ifdef HAVE_PCAP
// pcap_handle_deleter implementation (moved inside namespace ncp)
void pcap_handle_deleter::operator()(pcap_t* p) const noexcept {
    if (p) pcap_close(p);
}
#endif

// ==================== Constructor/Destructor ====================

Network::Network()
#ifdef HAVE_PCAP
    : pcap_handle_(nullptr)
    , is_capturing_(false)
#else
    : is_capturing_(false)
#endif
    , bypass_enabled_(false)
    , current_technique_(BypassTechnique::NONE) {
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        throw std::runtime_error("Failed to initialize Winsock");
    }
#endif
}

Network::~Network() {
    stop_capture();
    disable_bypass();
#ifdef _WIN32
    WSACleanup();
#endif
}

// ==================== Interface Management ====================

std::vector<std::string> Network::get_interfaces() {
    std::vector<std::string> interfaces;

#ifdef _WIN32
    PIP_ADAPTER_INFO adapter_info = nullptr;
    ULONG buf_len = 0;
    GetAdaptersInfo(adapter_info, &buf_len);
    adapter_info = (IP_ADAPTER_INFO*)malloc(buf_len);

    if (GetAdaptersInfo(adapter_info, &buf_len) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        while (adapter) {
            interfaces.push_back(adapter->AdapterName);
            adapter = adapter->Next;
        }
    }
    free(adapter_info);
#else
#ifdef HAVE_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if (d->name) {
                interfaces.push_back(d->name);
            }
        }
        pcap_freealldevs(alldevs);
    }
#endif
#endif

    return interfaces;
}

Network::InterfaceInfo Network::get_interface_info(const std::string& iface_name) {
    InterfaceInfo info;
    info.name = iface_name;
    info.is_up = false;
    info.is_loopback = false;

#ifndef _WIN32
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return info;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface_name.c_str(), IFNAMSIZ - 1);

    // Get flags
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
        info.is_up = (ifr.ifr_flags & IFF_UP) != 0;
        info.is_loopback = (ifr.ifr_flags & IFF_LOOPBACK) != 0;
    }

    // Get IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
        info.ip_address = inet_ntoa(addr->sin_addr);
    }

#ifdef __linux__
    // Get MAC address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        info.mac_address = mac_str;
    }
#endif

    close(fd);
#endif

    return info;
}

// ==================== Packet Capture ====================

bool Network::initialize_capture(const std::string& interface_name) {
#ifdef HAVE_PCAP
#ifndef _WIN32
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle_.reset(pcap_open_live(
        interface_name.c_str(),
        65535,  // Snapshot length
        1,      // Promiscuous mode
        1000,   // Timeout in ms
        errbuf
    ));

    if (!pcap_handle_) {
        last_error_ = errbuf;
        return false;
    }

    current_interface_ = interface_name;
    return true;
#else
    // Windows: use Npcap/WinPcap
    return false;
#endif
#else
    last_error_ = "Packet capture not supported (HAVE_PCAP not defined)";
    return false;
#endif
}

void Network::start_capture(PacketCallback callback, int timeout_ms) {
#ifdef HAVE_PCAP
    if (!pcap_handle_) return;

    packet_cb_ = callback;
    is_capturing_ = true;

    capture_thread_ = std::thread([this, timeout_ms]() {
#ifndef _WIN32
        struct pcap_pkthdr* header;
        const u_char* packet;
        while (is_capturing_) {
            int res = pcap_next_ex(pcap_handle_.get(), &header, &packet);
            if (res == 1 && packet_cb_) {
                std::vector<uint8_t> data(packet, packet + header->caplen);
                packet_cb_(data, header->ts.tv_sec);
            }
        }
#endif
    });
#endif
}

void Network::stop_capture() {
    is_capturing_ = false;
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
#ifdef HAVE_PCAP
    pcap_handle_.reset();
#endif
}
}
