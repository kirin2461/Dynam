#include "../include/ncp_network.hpp"
#include "../include/ncp_mimicry.hpp"
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <thread>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <pcap/pcap.h>
#endif

namespace NCP {

// ==================== Constructor/Destructor ====================

Network::Network() 
    : pcap_handle_(nullptr)
    , is_capturing_(false)
    , bypass_enabled_(false)
    , current_technique_(BypassTechnique::NONE) {
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
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
    
    // Get MAC address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        info.mac_address = mac_str;
    }
    
    close(fd);
#endif
    
    return info;
}

// ==================== Packet Capture ====================

bool Network::initialize_capture(const std::string& interface_name) {
#ifndef _WIN32
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_handle_ = pcap_open_live(
        interface_name.c_str(),
        65535,      // Snapshot length
        1,          // Promiscuous mode
        1000,       // Timeout in ms
        errbuf
    );
    
    if (pcap_handle_ == nullptr) {
        last_error_ = errbuf;
        return false;
    }
    
    current_interface_ = interface_name;
    return true;
#else
    // Windows: use Npcap/WinPcap
    return false;
#endif
}

void Network::start_capture(PacketCallback callback, int timeout_ms) {
    if (!pcap_handle_) return;
    
    packet_cb_ = callback;
    is_capturing_ = true;
    
    capture_thread_ = std::thread([this, timeout_ms]() {
#ifndef _WIN32
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        while (is_capturing_) {
            int res = pcap_next_ex(static_cast<pcap_t*>(pcap_handle_), &header, &packet);
            if (res == 1 && packet_cb_) {
                std::vector<uint8_t> data(packet, packet + header->caplen);
                packet_cb_(data, header->ts.tv_sec);
            }
        }
#endif
    });
}

void Network::stop_capture() {
    is_capturing_ = false;
    
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    
#ifndef _WIN32
    if (pcap_handle_) {
        pcap_close(static_cast<pcap_t*>(pcap_handle_));
        pcap_handle_ = nullptr;
    }
#endif
}

// ==================== DPI Bypass Techniques ====================

bool Network::enable_bypass(BypassTechnique technique) {
    current_technique_ = technique;
    bypass_enabled_ = true;
    
    switch (technique) {
        case BypassTechnique::TTL_MODIFICATION:
            return setup_ttl_bypass();
        case BypassTechnique::TCP_FRAGMENTATION:
            return setup_fragmentation_bypass();
        case BypassTechnique::SNI_SPOOFING:
            return setup_sni_spoofing();
        case BypassTechnique::FAKE_PACKET:
            return setup_fake_packet();
        case BypassTechnique::DISORDER:
            return setup_packet_disorder();
        case BypassTechnique::OBFUSCATION:
            bypass_config_.obfuscation_enabled = true;
            return true;
        case BypassTechnique::HTTP_MIMICRY:
            bypass_config_.mimicry_enabled = true;
            bypass_config_.mimicry_profile = "HTTP";
            return true;
        case BypassTechnique::TLS_MIMICRY:
            bypass_config_.mimicry_enabled = true;
            bypass_config_.mimicry_profile = "TLS";
            return true;
        default:
            return false;
    }
}

bool Network::set_tor_config(const TorConfig& config) {
    // Basic Tor configuration - in a real app, this would integrate with a SOCKS5 client
    return true; 
}

bool Network::is_tor_active() const {
    return false; // Stub implementation
}

void Network::disable_bypass() {
    bypass_enabled_ = false;
    current_technique_ = BypassTechnique::NONE;
    
    // Cleanup bypass resources
    cleanup_bypass();
}

bool Network::setup_ttl_bypass() {
    // TTL modification: Send packet with low TTL that expires at DPI
    // but retransmit with normal TTL
    
    bypass_config_.ttl_value = 1;  // Will expire at first hop
    bypass_config_.retransmit_ttl = 64;  // Normal TTL for retransmit
    
    return true;
}

bool Network::setup_fragmentation_bypass() {
    // Fragment TCP segments so DPI can't reassemble
    
    bypass_config_.fragment_size = 8;  // Very small fragments
    bypass_config_.fragment_offset = 0;
    
    return true;
}

bool Network::setup_sni_spoofing() {
    // Modify or split SNI in TLS ClientHello
    
    bypass_config_.fake_sni = "www.google.com";
    bypass_config_.split_sni = true;
    
    return true;
}

bool Network::setup_fake_packet() {
    // Send fake packets with bad checksums that DPI processes
    // but target server ignores
    
    bypass_config_.use_bad_checksum = true;
    bypass_config_.fake_seq_number = true;
    
    return true;
}

bool Network::setup_packet_disorder() {
    // Send packets out of order to confuse DPI
    
    bypass_config_.disorder_enabled = true;
    bypass_config_.disorder_delay_ms = 50;
    
    return true;
}

void Network::cleanup_bypass() {
    bypass_config_ = BypassConfig();
}

// ==================== Raw Packet Operations ====================

bool Network::send_raw_packet(
        const std::string& dest_ip,
        const std::vector<uint8_t>& data) {
    
#ifndef _WIN32
        // SECURITY FIX: Check for raw socket privileges (Linux only)
    if (geteuid() != 0) {
        last_error_ = "Raw sockets require root/admin privileges";
        return false;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        last_error_ = "Failed to create raw socket";
        return false;
    }
    
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip.c_str());
    
    ssize_t sent = sendto(sock, data.data(), data.size(), 0,
                          (struct sockaddr*)&dest, sizeof(dest));
    
    close(sock);
    return sent > 0;
#else
    return false;
#endif
}

bool Network::send_tcp_packet(
        const std::string& dest_ip,
        uint16_t dest_port,
        const std::vector<uint8_t>& payload,
        uint8_t flags) {
    
    // Build TCP packet with bypass modifications if enabled
    std::vector<uint8_t> packet;
    
    // IP header (20 bytes)
    packet.resize(20 + 20 + payload.size());  // IP + TCP + payload
    
    // Fill IP header
    packet[0] = 0x45;  // Version + IHL
    packet[8] = bypass_enabled_ ? bypass_config_.ttl_value : 64;  // TTL
    packet[9] = IPPROTO_TCP;  // Protocol
    
    // Source IP spoofing
    if (bypass_enabled_ && bypass_config_.spoof_source_ip && !bypass_config_.custom_source_ip.empty()) {
        struct in_addr src_addr;
        if (inet_aton(bypass_config_.custom_source_ip.c_str(), &src_addr)) {
            memcpy(&packet[12], &src_addr.s_addr, 4);
        }
    }
    
    // Fill TCP header
    // ... (detailed TCP header construction)
    
    // Apply bypass technique if enabled
    if (bypass_enabled_) {
        apply_bypass_to_packet(packet);
    }
    
    return send_raw_packet(dest_ip, packet);
}

void Network::apply_bypass_to_packet(std::vector<uint8_t>& packet) {
    switch (current_technique_) {
        case BypassTechnique::TTL_MODIFICATION:
            // Already applied in TTL field
            break;
            
        case BypassTechnique::TCP_FRAGMENTATION:
            // Fragment the packet
            fragment_packet(packet);
            break;
            
        case BypassTechnique::FAKE_PACKET:
            // Corrupt checksum so DPI sees it but server drops
            if (bypass_config_.use_bad_checksum) {
                packet[10] = 0xFF;  // Bad IP checksum
                packet[11] = 0xFF;
            }
            break;
            
        case BypassTechnique::OBFUSCATION:
            if (bypass_config_.obfuscation_enabled) {
                for (size_t i = 20; i < packet.size(); ++i) { // Skip IP header
                    packet[i] ^= bypass_config_.obfuscation_key;
                }
            }
            break;
            
        default:
            break;
    }
}

void Network::fragment_packet(std::vector<uint8_t>& packet) {
    // Split packet into small fragments
    // Each fragment < MTU but data split across multiple
    
    size_t frag_size = bypass_config_.fragment_size;
    // Implementation would create multiple IP fragments
}

// ==================== DNS Operations ====================

std::string Network::resolve_dns(const std::string& hostname, bool use_doh) {
    if (use_doh) {
        return resolve_dns_over_https(hostname);
    }
    
    // Standard DNS resolution
    struct addrinfo hints = {};
    struct addrinfo* result = nullptr;
    
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0) {
        return "";
    }
    
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
    
    freeaddrinfo(result);
    return std::string(ip_str);
}

std::string Network::resolve_dns_over_https(const std::string& hostname) {
    // DNS-over-HTTPS implementation
    // Would use HTTPS request to Cloudflare (1.1.1.1) or Google (8.8.8.8)
    
    // For now, return empty - full implementation requires HTTP client
    return "";
}

// ==================== Statistics ====================

NetworkStats Network::get_stats() const {
    return stats_;
}

void Network::reset_stats() {
    stats_ = NetworkStats();
}

std::string Network::get_last_error() const {
    return last_error_;
}

} // namespace NCP
