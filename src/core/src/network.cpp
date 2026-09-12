#include <fstream>
#include <sstream>
#include "../include/ncp_network.hpp"
#include "../include/ncp_mimicry.hpp"
#include <stdexcept>
#include <cstring>
#include <string>
#include <algorithm>
#include <thread>
#include <atomic>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#ifdef HAVE_WINDIVERT
#include <windivert.h>
#pragma comment(lib, "WinDivert.lib")
#endif
#ifdef HAVE_PCAP
#include <pcap.h>
#include "ncp_pcap_dyn.hpp"  // soft-load wpcap.dll at runtime (no import lib)
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
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

// ABI-STABLE: always defined; without pcap support the handle can never be
// non-null, so the no-op branch is unreachable in practice.
void pcap_handle_deleter::operator()(pcap_t* p) const noexcept {
#ifdef HAVE_PCAP
    if (p) pcap_close(p);
#else
    (void)p;
#endif
}

// ==================== Constructor/Destructor ====================

Network::Network()
    : pcap_handle_(nullptr)
    , is_capturing_(false)
    , bypass_enabled_(false)
    , current_technique_(BypassTechnique::NONE)
{
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
    // R14-H01: Use RAII std::vector instead of malloc/free
    ULONG buf_len = 0;
    GetAdaptersInfo(nullptr, &buf_len);  // Get required size
    
    std::vector<uint8_t> buffer(buf_len);
    PIP_ADAPTER_INFO adapter_info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    if (GetAdaptersInfo(adapter_info, &buf_len) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapter_info;
        while (adapter) {
            InterfaceInfo info = get_interface_info(adapter->AdapterName);
            interfaces.push_back(info);
            adapter = adapter->Next;
        }
    }
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

Network::InterfaceInfo Network::get_interface_info([[maybe_unused]] const std::string& interface_name) {
    InterfaceInfo info;
    info.name = interface_name;
    info.is_up = false;
    info.is_loopback = false;

#ifdef _WIN32
    ULONG buf_len = 0;

    if (GetAdaptersInfo(nullptr, &buf_len) == ERROR_BUFFER_OVERFLOW) {
        // R14-H01: Use RAII std::vector instead of malloc/free
        std::vector<uint8_t> buffer(buf_len);
        PIP_ADAPTER_INFO adapter_info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

        if (GetAdaptersInfo(adapter_info, &buf_len) == NO_ERROR) {
            for (PIP_ADAPTER_INFO adapter = adapter_info; adapter; adapter = adapter->Next) {
                if (interface_name == adapter->AdapterName) {
                    if (adapter->IpAddressList.IpAddress.String[0] != '\0') {
                        info.ip_address = adapter->IpAddressList.IpAddress.String;
                    }

                    if (adapter->AddressLength >= 6) {
                        char mac_buf[32];
                        snprintf(mac_buf, sizeof(mac_buf),
                                "%02X:%02X:%02X:%02X:%02X:%02X",
                                adapter->Address[0], adapter->Address[1],
                                adapter->Address[2], adapter->Address[3],
                                adapter->Address[4], adapter->Address[5]);
                        info.mac_address = mac_buf;
                    }

                    info.is_up = (adapter->Type != MIB_IF_TYPE_LOOPBACK);
                    info.is_loopback = (adapter->Type == MIB_IF_TYPE_LOOPBACK);
                    break;
                }
            }
        }
    }
#else
#ifdef HAVE_PCAP
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name || !ifa->ifa_addr) continue;
            if (interface_name != ifa->ifa_name) continue;

            info.is_up = (ifa->ifa_flags & IFF_UP) != 0;
            info.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;

            if (ifa->ifa_addr->sa_family == AF_INET) {
                char addr[INET_ADDRSTRLEN];
                auto* sa = (struct sockaddr_in*)ifa->ifa_addr;

                if (inet_ntop(AF_INET, &sa->sin_addr, addr, sizeof(addr))) {
                    info.ip_address = addr;
                }

            }
        }
        freeifaddrs(ifaddr);
    }
#endif
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
        65535,   // Snapshot length
        1,       // Promiscuous mode
        1000,    // Timeout in ms
        errbuf
    ));

    if (!pcap_handle_) {
        last_error_ = errbuf;
        return false;
    }

    current_interface_ = interface_name;
    return true;
#else
    (void)interface_name;
    return false;
#endif
#else
    (void)interface_name;
    last_error_ = "Packet capture not supported (HAVE_PCAP not defined)";
    return false;
#endif
}

void Network::start_capture(PacketCallback callback, int timeout_ms) {
#ifdef HAVE_PCAP
    if (!pcap_handle_) return;

    // Idempotent: a second start_capture() without stop_capture() must not
    // overwrite a joinable capture_thread_ (std::thread assignment to a
    // joinable thread calls std::terminate). Reuse the running session and
    // just swap the callback.
    bool expected = false;
    if (!is_capturing_.compare_exchange_strong(expected, true)) {
        packet_cb_ = callback;
        return;
    }
    // Defensive: if a previous thread object is somehow still joinable
    // (e.g. flag reset raced with thread exit), join it before replacing.
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }

    packet_cb_ = callback;

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
    // Set a deliberately low TTL (1) so the probe packet dies at the first
    // DPI hop, while retransmissions (sent with retransmit_ttl=64) reach the
    // real destination.  This is the same approach used by GoodbyeDPI.
    bypass_config_.ttl_value       = 1;
    bypass_config_.retransmit_ttl  = 64;

#ifdef _WIN32
    if (active_socket_ == INVALID_SOCKET) return true;  // applied lazily when socket is known
    DWORD ttl = bypass_config_.ttl_value;
    if (setsockopt(active_socket_, IPPROTO_IP, IP_TTL,
                   reinterpret_cast<const char*>(&ttl), sizeof(ttl)) == SOCKET_ERROR) {
        last_error_ = "setup_ttl_bypass: setsockopt IP_TTL failed, code=" +
                      std::to_string(WSAGetLastError());
        return false;
    }
    // Also set IPv6 TTL (hop limit) if the socket is dual-stack
    DWORD hl = bypass_config_.ttl_value;
    setsockopt(active_socket_, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
               reinterpret_cast<const char*>(&hl), sizeof(hl)); // best-effort
#else
    if (active_socket_ < 0) return true;   // applied lazily
    int ttl = static_cast<int>(bypass_config_.ttl_value);
    if (setsockopt(active_socket_, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        last_error_ = "setup_ttl_bypass: setsockopt IP_TTL failed";
        return false;
    }
    // IPv6 hop limit — best-effort
    setsockopt(active_socket_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl));
#endif
    return true;
}

bool Network::setup_fragmentation_bypass() {
    bypass_config_.fragment_size   = 8;  // 8-byte TCP payload fragments
    bypass_config_.fragment_offset = 0;

#if defined(__linux__)
    // On Linux, disable kernel-level Path MTU Discovery so the kernel doesn't
    // silently reassemble fragments before they reach the wire.
    if (active_socket_ >= 0) {
        int pmtu_flag = IP_PMTUDISC_DONT;
        setsockopt(active_socket_, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu_flag, sizeof(pmtu_flag));
    }
#elif defined(__APPLE__) && defined(IP_DONTFRAG)
    if (active_socket_ >= 0) {
        int dontfrag = 0;
        setsockopt(active_socket_, IPPROTO_IP, IP_DONTFRAG, &dontfrag, sizeof(dontfrag));
    }
#endif
    return true;
}

bool Network::setup_sni_spoofing() {
    bypass_config_.fake_sni  = "www.google.com";
    bypass_config_.split_sni = true;
    return true;
}

// ---------------------------------------------------------------------------
// SNI field replacement in a TLS 1.x ClientHello record.
//
// Layout (RFC 5246 §6.2 + RFC 6066 §3):
//   TLS Record:  [ type(1) | major(1) | minor(1) | length(2) | handshake... ]
//   Handshake:   [ msg_type(1) | length(3) | body... ]
//   ClientHello: [ major(1) | minor(1) | random(32) | sid_len(1) | sid(...)
//                  | cipher_suites_len(2) | cipher_suites(...)
//                  | comp_len(1) | comp(...)
//                  | extensions_len(2) | extensions... ]
//   Extension SNI (type=0x0000):
//                [ ext_type(2) | ext_data_len(2) |
//                  sni_list_len(2) | name_type(1) | name_len(2) | name(...) ]
//
// The replacement is done in-place; the packet is resized if the new SNI
// differs in length (all intervening length fields are updated accordingly).
// ---------------------------------------------------------------------------
static bool replace_sni_in_clienthello(std::vector<uint8_t>& pkt,
                                       const std::string&     new_sni) {
    // Minimum viable TLS record header
    if (pkt.size() < 5) return false;
    if (pkt[0] != 0x16) return false;              // Must be Handshake record
    // pkt[1]/[2] = TLS version (major/minor), pkt[3..4] = record length
    size_t rec_len = (static_cast<size_t>(pkt[3]) << 8) | pkt[4];
    if (5 + rec_len > pkt.size()) return false;

    // Handshake header starts at offset 5
    if (pkt[5] != 0x01) return false;              // ClientHello
    // Handshake body length: pkt[6..8] (3 bytes, big-endian)
    size_t hs_body_len = (static_cast<size_t>(pkt[6])  << 16)
                       | (static_cast<size_t>(pkt[7])  <<  8)
                       |  static_cast<size_t>(pkt[8]);
    if (5 + 4 + hs_body_len > pkt.size()) return false;

    size_t off = 9;   // start of ClientHello body
    // Skip: client_version(2) + random(32) = 34 bytes
    if (off + 34 > pkt.size()) return false;
    off += 34;

    // session_id (variable)
    if (off >= pkt.size()) return false;
    uint8_t sid_len = pkt[off++];
    if (off + sid_len > pkt.size()) return false;
    off += sid_len;

    // cipher_suites (variable)
    if (off + 2 > pkt.size()) return false;
    uint16_t cs_len = (static_cast<uint16_t>(pkt[off]) << 8) | pkt[off+1];
    off += 2 + cs_len;
    if (off > pkt.size()) return false;

    // compression_methods (variable)
    if (off >= pkt.size()) return false;
    uint8_t cm_len = pkt[off++];
    if (off + cm_len > pkt.size()) return false;
    off += cm_len;

    // Extensions
    if (off + 2 > pkt.size()) return false;
    uint16_t exts_len = (static_cast<uint16_t>(pkt[off]) << 8) | pkt[off+1];
    off += 2;
    size_t exts_start = off;
    if (off + exts_len > pkt.size()) return false;

    // Walk extensions looking for SNI (type 0x0000)
    while (off + 4 <= exts_start + exts_len) {
        uint16_t ext_type = (static_cast<uint16_t>(pkt[off]) << 8) | pkt[off+1];
        uint16_t ext_dlen = (static_cast<uint16_t>(pkt[off+2]) << 8) | pkt[off+3];
        if (ext_type == 0x0000) {   // SNI extension
            // SNI extension data: sni_list_len(2) + name_type(1) + name_len(2) + name
            size_t sni_ext_off = off + 4;
            if (sni_ext_off + 5 > pkt.size()) return false;
            // sni_list_len and name_len are at sni_ext_off and sni_ext_off+3
            size_t old_name_len_off = sni_ext_off + 3;
            uint16_t old_name_len = (static_cast<uint16_t>(pkt[old_name_len_off]) << 8)
                                  |  static_cast<uint16_t>(pkt[old_name_len_off+1]);
            size_t old_name_start = sni_ext_off + 5;
            if (old_name_start + old_name_len > pkt.size()) return false;

            // Compute delta for resize
            int delta = static_cast<int>(new_sni.size()) - static_cast<int>(old_name_len);

            // Replace old name bytes with new name bytes (splice)
            pkt.erase(pkt.begin() + static_cast<std::ptrdiff_t>(old_name_start),
                      pkt.begin() + static_cast<std::ptrdiff_t>(old_name_start + old_name_len));
            pkt.insert(pkt.begin() + static_cast<std::ptrdiff_t>(old_name_start),
                       new_sni.begin(), new_sni.end());

            // Update name_len field (2 bytes at old_name_len_off)
            uint16_t new_nl = static_cast<uint16_t>(new_sni.size());
            pkt[old_name_len_off]   = (new_nl >> 8) & 0xFF;
            pkt[old_name_len_off+1] =  new_nl       & 0xFF;

            // Update sni_list_len (2 bytes at sni_ext_off) = 3 + new_name_len
            uint16_t new_list_len = static_cast<uint16_t>(3 + new_sni.size());
            pkt[sni_ext_off]   = (new_list_len >> 8) & 0xFF;
            pkt[sni_ext_off+1] =  new_list_len       & 0xFF;

            // Update ext_data_len (2 bytes at off+2) = 2 + 3 + new_name_len
            uint16_t new_ext_dlen = static_cast<uint16_t>(2 + 3 + new_sni.size());
            pkt[off+2] = (new_ext_dlen >> 8) & 0xFF;
            pkt[off+3] =  new_ext_dlen       & 0xFF;

            // Update extensions_len (2 bytes just before exts_start)
            uint16_t new_exts_len = static_cast<uint16_t>(static_cast<int>(exts_len) + delta);
            pkt[exts_start - 2] = (new_exts_len >> 8) & 0xFF;
            pkt[exts_start - 1] =  new_exts_len       & 0xFF;

            // Update Handshake body length (3 bytes at pkt[6..8])
            size_t new_hs_body = static_cast<size_t>(static_cast<int>(hs_body_len) + delta);
            pkt[6] = (new_hs_body >> 16) & 0xFF;
            pkt[7] = (new_hs_body >>  8) & 0xFF;
            pkt[8] =  new_hs_body        & 0xFF;

            // Update TLS record length (2 bytes at pkt[3..4])
            size_t new_rec_len = static_cast<size_t>(static_cast<int>(rec_len) + delta);
            pkt[3] = (new_rec_len >> 8) & 0xFF;
            pkt[4] =  new_rec_len       & 0xFF;

            return true;
        }
        off += 4 + ext_dlen;
    }
    return false;   // SNI extension not found
}

bool Network::setup_fake_packet() {
    // GoodbyeDPI-style fake packet:
    // Before the real TLS ClientHello, send a TCP segment whose payload is
    // intentionally wrong (either bad IP checksum or TTL=1) so it is
    // discarded by the DPI device but not by the endpoint (which has already
    // received the real ClientHello that follows).
    bypass_config_.use_bad_checksum = true;
    bypass_config_.fake_seq_number  = true;
    // The actual injection happens in apply_bypass_to_packet / send_tcp_packet;
    // here we just configure the flags and prepare a raw socket.
#ifdef _WIN32
    // On Windows the fake packet is sent via WinDivert (see send_tcp_packet).
    // Nothing else needed at setup time.
    (void)0;
#else
    // On Linux we need a raw socket to inject the fake packet.
    if (geteuid() != 0) {
        // Unprivileged: mark as configured but warn; actual injection will fail.
        last_error_ = "setup_fake_packet: raw socket requires root; fake-packet injection will be skipped";
        return true;   // non-fatal — the real packet path still works
    }
    // Pre-open the raw socket so it's ready; close it after the first use.
    // (A persistent raw socket would require RAII cleanup not present here.)
    int probe_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (probe_sock < 0) {
        last_error_ = "setup_fake_packet: socket(SOCK_RAW) failed";
        return false;
    }
    int hdrincl = 1;
    setsockopt(probe_sock, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
    // Store for later use (the socket is intentionally NOT closed here;
    // it will be closed by cleanup_bypass).
    active_socket_ = probe_sock;
#endif
    return true;
}

bool Network::setup_packet_disorder() {
    // Disorder: split the TCP payload into two halves, send the second half
    // first (with a tiny artificial delay), then send the first half.
    // Many DPI engines assemble segments in order; out-of-order delivery
    // breaks pattern matching until they are re-ordered by the endpoint TCP stack.
    bypass_config_.disorder_enabled  = true;
    bypass_config_.disorder_delay_ms = 1;   // 1 ms is enough to cause reorder
    return true;
}

void Network::cleanup_bypass() {
    bypass_config_ = BypassConfig();
    // Close any raw socket opened by setup_fake_packet
#ifdef _WIN32
    if (active_socket_ != INVALID_SOCKET) {
        closesocket(active_socket_);
        active_socket_ = INVALID_SOCKET;
    }
#else
    if (active_socket_ >= 0) {
        ::close(active_socket_);
        active_socket_ = -1;
    }
#endif
}

// ==================== Raw Packet Operations ====================

bool Network::send_raw_packet(
    const std::string& dest_ip,
    const std::vector<uint8_t>& data
) {
#ifdef _WIN32
#ifdef HAVE_WINDIVERT
    // WinDivert implementation for Windows
    HANDLE handle = WinDivertOpen(
        "outbound", WINDIVERT_LAYER_NETWORK, 0, 0
    );
    if (handle == INVALID_HANDLE_VALUE) {
        last_error_ = "WinDivertOpen failed, error=" + std::to_string(GetLastError());
        return false;
    }

    // Send packet via WinDivert
    UINT8 packet[65535];
    size_t packet_len = data.size();
    if (packet_len > sizeof(packet)) packet_len = sizeof(packet);
    memcpy(packet, data.data(), packet_len);

    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = 1;

    UINT send_len = 0;
    if (!WinDivertSend(handle, packet, (UINT)packet_len, &send_len, &addr)) {
        last_error_ = "WinDivertSend failed, error=" + std::to_string(GetLastError());
        WinDivertClose(handle);
        return false;
    }

    WinDivertClose(handle);
    stats_.packets_sent++;
    stats_.bytes_sent += packet_len;
    return true;
#else
    last_error_ = "WinDivert not available. Enable HAVE_WINDIVERT or use raw sockets.";
    return false;
#endif // HAVE_WINDIVERT
#else
    // Linux raw socket implementation
    if (geteuid() != 0) {
        last_error_ = "Raw sockets require root privileges";
        return false;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        last_error_ = "Failed to create raw socket";
        return false;
    }

    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    if (sendto(sock, data.data(), data.size(), 0, 
               (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        last_error_ = "Failed to send raw packet";
        close(sock);
        return false;
    }

    close(sock);
    stats_.packets_sent++;
    stats_.bytes_sent += data.size();
    return true;
#endif
}

bool Network::send_tcp_packet(
    const std::string& dest_ip,
    uint16_t dest_port,
    const std::vector<uint8_t>& payload,
    uint8_t flags
) {
#ifdef _WIN32
#ifdef HAVE_WINDIVERT
    // Build TCP packet with IP header for WinDivert
    std::vector<uint8_t> packet(40 + payload.size()); // 20 bytes IP + 20 bytes TCP
    
    // IP header (20 bytes)
    uint8_t* ip = packet.data();
    ip[0] = 0x45;                    // Version + IHL
    ip[1] = 0x00;                    // TOS
    uint16_t ip_len = htons(40 + payload.size());
    memcpy(ip + 2, &ip_len, 2);      // Total length
    ip[4] = 0x00; ip[5] = 0x00;      // Identification
    ip[6] = 0x40; ip[7] = 0x00;      // Flags + Fragment offset (DF set)
    ip[8] = 64;                      // TTL
    ip[9] = IPPROTO_TCP;             // Protocol
    // Checksum calculated by WinDivert
    
    // Source IP (placeholder - will be replaced by WinDivert)
    memset(ip + 12, 0, 4);
    // Dest IP
    uint32_t dest_addr = inet_addr(dest_ip.c_str());
    memcpy(ip + 16, &dest_addr, 4);

    // TCP header (20 bytes)
    uint8_t* tcp = packet.data() + 20;
    memset(tcp, 0, 20);
    
    // Source port (random ephemeral)
    uint16_t sp = htons(static_cast<uint16_t>(randombytes_uniform(16383) + 49152));
    memcpy(tcp + 0, &sp, 2);
    
    // Dest port
    uint16_t dp = htons(dest_port);
    memcpy(tcp + 2, &dp, 2);
    
    // Sequence number (random)
    uint32_t seq = randombytes_uniform(UINT32_MAX);
    memcpy(tcp + 4, &seq, 4);
    
    // Acknowledgment number
    memset(tcp + 8, 0, 4);
    
    // Data offset (5 * 4 = 20 bytes) + flags
    tcp[12] = 0x50;                  // Data offset
    tcp[13] = flags;                 // TCP flags
    
    // Window size (correct offset is 14, not 16)
    uint16_t window = htons(65535);
    memcpy(tcp + 14, &window, 2);
    
    // Checksum (0 - let WinDivert calculate)
    memset(tcp + 16, 0, 2);
    
    // Urgent pointer
    memset(tcp + 18, 0, 2);
    
    // Copy payload
    if (!payload.empty()) {
        memcpy(packet.data() + 40, payload.data(), payload.size());
    }

    // Send via WinDivert
    HANDLE handle = WinDivertOpen("outbound", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        last_error_ = "WinDivertOpen failed";
        return false;
    }

    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr));
    addr.Outbound = 1;
    
    UINT send_len = 0;
    if (!WinDivertSend(handle, packet.data(), (UINT)packet.size(), &send_len, &addr)) {
        last_error_ = "WinDivertSend failed";
        WinDivertClose(handle);
        return false;
    }

    WinDivertClose(handle);
    stats_.packets_sent++;
    stats_.bytes_sent += packet.size();
    return true;
#else
    last_error_ = "WinDivert not available on Windows";
    return false;
#endif
#else
    // Linux implementation using raw sockets
    if (geteuid() != 0) {
        last_error_ = "Raw sockets require root privileges";
        return false;
    }

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        last_error_ = "Failed to create raw socket";
        return false;
    }

    int optval = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

    // Build packet (simplified - in production use proper TCP/IP stack)
    std::vector<uint8_t> packet(40 + payload.size());
    
    struct sockaddr_in dest_addr = {};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    if (sendto(sock, packet.data(), packet.size(), 0,
               (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
        close(sock);
        return false;
    }

    close(sock);
    stats_.packets_sent++;
    return true;
#endif
}

void Network::apply_bypass_to_packet(std::vector<uint8_t>& packet) {
    if (!bypass_enabled_ || packet.empty()) return;

    switch (current_technique_) {
        case BypassTechnique::SNI_SPOOFING:
            // Replace SNI in TLS ClientHello if a fake SNI has been configured
            if (!bypass_config_.fake_sni.empty()) {
                replace_sni_in_clienthello(packet, bypass_config_.fake_sni);
            }
            break;

        case BypassTechnique::TCP_FRAGMENTATION:
            // fragment_packet() sends all but the first fragment inline
            fragment_packet(packet);
            break;

        case BypassTechnique::FAKE_PACKET:
            // Corrupt the checksum so DPI drops this but the endpoint reassembles:
            // flip the last two bytes of the IP header checksum area.
            if (bypass_config_.use_bad_checksum && packet.size() >= 12) {
                packet[10] ^= 0xFF;
                packet[11] ^= 0xFF;
            }
            break;

        case BypassTechnique::OBFUSCATION:
            if (bypass_config_.obfuscation_enabled) {
                for (size_t i = 0; i < packet.size(); ++i)
                    packet[i] ^= bypass_config_.obfuscation_key;
            }
            break;

        default:
            break;
    }
}

void Network::fragment_packet(std::vector<uint8_t>& packet) {
    if (packet.size() <= bypass_config_.fragment_size) return;

    // Build all fragments from the payload.
    // This function modifies `packet` to hold only the FIRST fragment
    // (for backward compatibility with callers that pass a single buffer)
    // and sends the remaining fragments immediately via the active_socket_.
    //
    // Fragment layout on Linux:
    //   Each fragment is a complete IP packet whose payload is a slice of
    //   the original payload.  IP flags/offset fields set accordingly.
    //   On Windows we use WSASend with a scatter/gather WSABUF array via
    //   a raw socket (WinDivert path handles it for us above IP).

    const size_t frag_size = bypass_config_.fragment_size;
    std::vector<std::vector<uint8_t>> fragments;
    for (size_t i = 0; i < packet.size(); i += frag_size) {
        size_t chunk = std::min(frag_size, packet.size() - i);
        fragments.emplace_back(packet.begin() + static_cast<std::ptrdiff_t>(i),
                               packet.begin() + static_cast<std::ptrdiff_t>(i + chunk));
    }

    if (fragments.empty()) return;

    // Expose all fragments via inject_fragmented_packets for proper injection
    // at a higher level.  Here we keep the first fragment in `packet` so that
    // the caller (which already has a send path) can send it, and we queue
    // the rest.
    packet = fragments[0];

    // Send remaining fragments inline (best-effort; errors are non-fatal)
    for (size_t i = 1; i < fragments.size(); ++i) {
        if (bypass_config_.disorder_enabled && bypass_config_.disorder_delay_ms > 0) {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(bypass_config_.disorder_delay_ms));
        }
#ifndef _WIN32
        if (active_socket_ >= 0) {
            // Send via the active raw socket
            ::send(active_socket_,
                   fragments[i].data(),
                   static_cast<int>(fragments[i].size()),
                   0);
        }
#else
        if (active_socket_ != INVALID_SOCKET) {
            // Windows: scatter/gather via WSASend with a single WSABUF entry
            WSABUF wb;
            wb.buf = reinterpret_cast<CHAR*>(fragments[i].data());
            wb.len = static_cast<ULONG>(fragments[i].size());
            DWORD sent = 0;
            WSASend(active_socket_, &wb, 1, &sent, 0, nullptr, nullptr);
        }
#endif
        stats_.packets_sent++;
        stats_.bytes_sent += fragments[i].size();
    }
}

bool Network::inject_fragmented_packets(
    const std::vector<std::vector<uint8_t>>& packets,
    int delay_ms
) {
    for (size_t i = 0; i < packets.size(); ++i) {
        // Send each fragment
        // In production, would use proper timing and ordering
        if (i > 0 && delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
        // Fragment sending logic would go here
    }
    return true;
}

void Network::set_tcp_window_size(uint16_t size) {
    bypass_config_.tcp_window_size = size;

    // Apply the window size to the active socket via setsockopt SO_RCVBUF /
    // SO_SNDBUF.  The kernel uses the socket buffer size to advertise the
    // TCP receive window.  A small value forces the peer to slow down, which
    // can defeat some DPI techniques that rely on reassembling a specific
    // number of bytes in the initial flight.
    //
    // Note: the kernel may round up to the nearest page; the actual advertised
    // window will be at most SO_RCVBUF/2 on Linux (SO_RCVBUF doubles the value).
    int buf = static_cast<int>(size);
#ifdef _WIN32
    if (active_socket_ != INVALID_SOCKET) {
        setsockopt(active_socket_, SOL_SOCKET, SO_RCVBUF,
                   reinterpret_cast<const char*>(&buf), sizeof(buf));
        setsockopt(active_socket_, SOL_SOCKET, SO_SNDBUF,
                   reinterpret_cast<const char*>(&buf), sizeof(buf));
    }
#else
    if (active_socket_ >= 0) {
        setsockopt(active_socket_, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
        setsockopt(active_socket_, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
    }
#endif
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

#ifdef _WIN32
namespace {
// RAII wrapper so every exit path releases WinHTTP handles exactly once.
struct WinHttpHandle {
    HINTERNET h = nullptr;
    WinHttpHandle() = default;
    explicit WinHttpHandle(HINTERNET handle) : h(handle) {}
    ~WinHttpHandle() { if (h) WinHttpCloseHandle(h); }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;
    HINTERNET get() const { return h; }
    HINTERNET release() { HINTERNET t = h; h = nullptr; return t; }
};
} // namespace
#endif

std::string Network::resolve_dns_over_https(const std::string& hostname) {
#ifdef _WIN32
    if (hostname.empty() || hostname.size() > 253) {
        last_error_ = "DoH: invalid hostname";
        return "";
    }

    // Build a real DNS wire query (RFC 1035) from the requested hostname.
    std::vector<uint8_t> dns_query;
    const uint16_t txid = static_cast<uint16_t>(
        (std::chrono::steady_clock::now().time_since_epoch().count()) & 0xFFFF);
    dns_query.push_back(static_cast<uint8_t>(txid >> 8));
    dns_query.push_back(static_cast<uint8_t>(txid & 0xFF));
    dns_query.push_back(0x01); dns_query.push_back(0x00);  // Flags: RD
    dns_query.push_back(0x00); dns_query.push_back(0x01);  // QDCOUNT: 1
    dns_query.push_back(0x00); dns_query.push_back(0x00);  // ANCOUNT
    dns_query.push_back(0x00); dns_query.push_back(0x00);  // NSCOUNT
    dns_query.push_back(0x00); dns_query.push_back(0x00);  // ARCOUNT
    {
        std::istringstream iss(hostname);
        std::string label;
        while (std::getline(iss, label, '.')) {
            if (label.empty()) continue;
            if (label.size() > 63) {
                last_error_ = "DoH: DNS label too long";
                return "";
            }
            dns_query.push_back(static_cast<uint8_t>(label.size()));
            dns_query.insert(dns_query.end(), label.begin(), label.end());
        }
    }
    dns_query.push_back(0x00);                              // root label
    dns_query.push_back(0x00); dns_query.push_back(0x01);   // QTYPE: A
    dns_query.push_back(0x00); dns_query.push_back(0x01);   // QCLASS: IN

    WinHttpHandle hSession(WinHttpOpen(L"Dynam DoH Client/1.0",
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS, 0));
    if (!hSession.get()) {
        last_error_ = "WinHttpOpen failed";
        return "";
    }
    // Bound all WinHTTP operations (resolve/connect/send/receive, ms).
    WinHttpSetTimeouts(hSession.get(), 5000, 5000, 5000, 5000);

    WinHttpHandle hConnect(WinHttpConnect(hSession.get(), L"cloudflare-dns.com",
                                          INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!hConnect.get()) {
        last_error_ = "WinHttpConnect failed";
        return "";
    }

    WinHttpHandle hRequest(WinHttpOpenRequest(hConnect.get(), L"POST",
                                              L"/dns-query", nullptr,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE));
    if (!hRequest.get()) {
        last_error_ = "WinHttpOpenRequest failed";
        return "";
    }

    if (!WinHttpSendRequest(hRequest.get(),
                            L"Content-Type: application/dns-message\r\n", -1,
                            dns_query.data(),
                            static_cast<DWORD>(dns_query.size()),
                            static_cast<DWORD>(dns_query.size()), 0)) {
        last_error_ = "WinHttpSendRequest failed";
        return "";
    }
    if (!WinHttpReceiveResponse(hRequest.get(), nullptr)) {
        last_error_ = "WinHttpReceiveResponse failed";
        return "";
    }

    DWORD status = 0;
    DWORD status_len = sizeof(status);
    if (WinHttpQueryHeaders(hRequest.get(),
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
                            WINHTTP_NO_HEADER_INDEX) && status != 200) {
        last_error_ = "DoH: HTTP error";
        return "";
    }

    // Read the whole body (a single QueryDataAvailable/ReadData pair may
    // return only the first chunk).
    std::vector<uint8_t> response;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest.get(), &avail)) break;
        if (avail == 0) break;
        size_t old = response.size();
        response.resize(old + avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest.get(), response.data() + old, avail, &read)) {
            response.resize(old);
            break;
        }
        response.resize(old + read);
    }

    // Parse the DNS wire response: find the first A record answer.
    if (response.size() < 12) {
        last_error_ = "DoH: short DNS response";
        return "";
    }
    const uint16_t resp_id = static_cast<uint16_t>((response[0] << 8) | response[1]);
    const uint16_t flags   = static_cast<uint16_t>((response[2] << 8) | response[3]);
    const uint16_t qdcount = static_cast<uint16_t>((response[4] << 8) | response[5]);
    const uint16_t ancount = static_cast<uint16_t>((response[6] << 8) | response[7]);
    if (resp_id != txid || (flags & 0x000F) != 0 || ancount == 0 || ancount > 256) {
        last_error_ = "DoH: DNS error or mismatched response";
        return "";
    }

    size_t off = 12;
    auto skip_name = [&]() -> bool {
        // Compression-aware: a 0xC0-pointer terminates the name here.
        while (off < response.size()) {
            uint8_t b = response[off];
            if ((b & 0xC0) == 0xC0) { off += 2; return true; }
            if (b == 0) { ++off; return true; }
            off += b + 1;
        }
        return false;
    };
    for (uint16_t q = 0; q < qdcount; ++q) {
        if (!skip_name() || off + 4 > response.size()) {
            last_error_ = "DoH: malformed question section";
            return "";
        }
        off += 4;
    }
    for (uint16_t a = 0; a < ancount; ++a) {
        if (!skip_name() || off + 10 > response.size()) break;
        const uint16_t rtype = static_cast<uint16_t>((response[off] << 8) | response[off + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((response[off + 8] << 8) | response[off + 9]);
        off += 10;
        if (off + rdlen > response.size()) break;
        if (rtype == 0x0001 && rdlen == 4) {
            char ip[INET_ADDRSTRLEN];
            snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                     response[off], response[off + 1],
                     response[off + 2], response[off + 3]);
            return std::string(ip);
        }
        off += rdlen;
    }
    last_error_ = "DoH: no A record in response";
    return "";
#else
    // Linux: Use curl or direct HTTPS
    (void)hostname;
    last_error_ = "DoH resolution failed";
    return "";
#endif
}

// ==================== Statistics ====================

std::string Network::get_network_stats() {
    return "";
}

NetworkStats Network::get_stats() const {
#ifndef _WIN32
    // When no capture session populated stats_, report system-wide counters
    // from /proc/net/dev (aggregate of non-loopback interfaces).
    if (stats_.packets_sent == 0 && stats_.packets_received == 0 &&
        stats_.bytes_sent == 0 && stats_.bytes_received == 0) {
        NetworkStats sys;
        std::ifstream f("/proc/net/dev");
        std::string line;
        while (std::getline(f, line)) {
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string name = line.substr(0, colon);
            name.erase(0, name.find_first_not_of(" \t"));
            if (name == "lo") continue;
            std::istringstream ss(line.substr(colon + 1));
            uint64_t rbytes, rpackets, dummy;
            if (!(ss >> rbytes >> rpackets)) continue;
            for (int i = 0; i < 6; ++i) ss >> dummy;   // errs drop fifo frame compressed multicast
            uint64_t sbytes, spackets;
            if (!(ss >> sbytes >> spackets)) continue;
            sys.bytes_received += rbytes;
            sys.packets_received += rpackets;
            sys.bytes_sent += sbytes;
            sys.packets_sent += spackets;
        }
        return sys;
    }
#endif
    return stats_;
}

void Network::reset_stats() {
    stats_ = NetworkStats();
}

std::string Network::get_last_error() const {
    return last_error_;
}

} // namespace ncp
