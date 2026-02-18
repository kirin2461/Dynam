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

std::vector<Network::InterfaceInfo> Network::get_interfaces() {
    std::vector<InterfaceInfo> interfaces;

#ifdef _WIN32
    PIP_ADAPTER_INFO adapter_info = nullptr;
    ULONG buf_len = 0;
    GetAdaptersInfo(adapter_info, &buf_len);
    adapter_info = (IP_ADAPTER_INFO*)malloc(buf_len);
   
    if (GetAdaptersInfo(adapter_info, &buf_len) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        while (adapter) {
            InterfaceInfo info = get_interface_info(adapter->AdapterName);
            interfaces.push_back(info);
            adapter = adapter->Next;
        }
    }
    free(adapter_info);
#else
#ifdef HAVE_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs = nullptr;
    int rc = pcap_findalldevs(&alldevs, errbuf);
   
    if (rc == 0 && alldevs != nullptr) {
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            if (d->name) {
                InterfaceInfo info = get_interface_info(d->name);
                interfaces.push_back(info);
            }
        }
        pcap_freealldevs(alldevs);
    }
#endif
#endif

    return interfaces;
}

Network::InterfaceInfo Network::get_interface_info(const std::string& interface_name) {
    (void)interface_name; // suppress MSVC C4100 (unreferenced parameter)

    InterfaceInfo info;
    info.is_up = false;
    info.is_loopback = false;

#ifndef _WIN32
    // TODO: Implement interface info retrieval
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
    (void)interface_name; // Suppress unused parameter warning
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
#else
        (void)timeout_ms;
#endif
    });
#else
    (void)callback;
    (void)timeout_ms;
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
    tor_config_ = config;
    return true;
}

bool Network::is_tor_active() const {
    return tor_config_.enabled;
}

void Network::disable_bypass() {
    bypass_enabled_ = false;
    current_technique_ = BypassTechnique::NONE;
    cleanup_bypass();
}

bool Network::setup_ttl_bypass() {
    bypass_config_.ttl_value = 1;
    bypass_config_.retransmit_ttl = 64;
    return true;
}

bool Network::setup_fragmentation_bypass() {
    bypass_config_.fragment_size = 8;
    bypass_config_.fragment_offset = 0;
    return true;
}

bool Network::setup_sni_spoofing() {
    bypass_config_.fake_sni = "www.google.com";
    bypass_config_.split_sni = true;
    return true;
}

bool Network::setup_fake_packet() {
    bypass_config_.use_bad_checksum = true;
    bypass_config_.fake_seq_number = true;
    return true;
}

bool Network::setup_packet_disorder() {
    bypass_config_.disorder_enabled = true;
    bypass_config_.disorder_delay_ms = 50;
    return true;
}

void Network::cleanup_bypass() {
    bypass_config_ = BypassConfig();
}

// ==================== Raw Packet Operations ====================

bool Network::send_raw_packet(const std::string& dest_ip, const std::vector<uint8_t>& data) {
    (void)dest_ip; // suppress MSVC C4100 (unreferenced parameter)
    (void)data;    // suppress MSVC C4100 (unreferenced parameter)

#ifndef _WIN32
    if (geteuid() != 0) {
        last_error_ = "Raw sockets require root privileges";
        return false;
    }
    // TODO: Implement raw packet sending
    return false;
#else
    return false;
#endif
}

bool Network::send_tcp_packet(
    const std::string& dest_ip,
    uint16_t dest_port,
    const std::vector<uint8_t>& payload,
    uint8_t flags
) {
    (void)dest_ip;  // suppress MSVC C4100 (unreferenced parameter)
    (void)dest_port; // suppress MSVC C4100 (unreferenced parameter)
    (void)payload;  // suppress MSVC C4100 (unreferenced parameter)
    (void)flags;    // suppress MSVC C4100 (unreferenced parameter)

    return false;
}

void Network::apply_bypass_to_packet(std::vector<uint8_t>& packet) {
    (void)packet; // suppress MSVC C4100 (unreferenced parameter)
}

void Network::fragment_packet(std::vector<uint8_t>& packet) {
    (void)packet; // suppress MSVC C4100 (unreferenced parameter)
}

bool Network::inject_fragmented_packets(
    const std::vector<std::vector<uint8_t>>& packets,
    int delay_ms
) {
    (void)packets;  // suppress MSVC C4100 (unreferenced parameter)
    (void)delay_ms; // suppress MSVC C4100 (unreferenced parameter)

    return false;
}

void Network::set_tcp_window_size(uint16_t size) {
    (void)size; // suppress MSVC C4100 (unreferenced parameter)
}

// ==================== DNS Operations ====================

std::string Network::resolve_dns(const std::string& hostname, bool use_doh) {
    if (use_doh) {
        return resolve_dns_over_https(hostname);
    }
    struct addrinfo hints = {}, *result = nullptr;
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
    (void)hostname; // suppress MSVC C4100 (unreferenced parameter)

    return "";
}

// ==================== Statistics ====================

std::string Network::get_network_stats() {
    return "";
}

NetworkStats Network::get_stats() const {
    return stats_;
}

void Network::reset_stats() {
    stats_ = NetworkStats();
}

std::string Network::get_last_error() const {
    return last_error_;

}

}  // namespace ncp
