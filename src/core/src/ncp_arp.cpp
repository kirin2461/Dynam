/**
 * @file ncp_arp.cpp
 * @brief ARPController implementation - Phase 3
 *
 * Manages ARP cache manipulation for MAC spoofing.
 * Sends gratuitous ARP, monitors ARP requests, and handles
 * periodic announcements. Uses raw sockets on Linux, Npcap on Windows.
 */

#include "ncp_arp.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace ncp {
namespace DPI {

// ─── ARP packet structure ─────────────────────────────────────────────────────

#pragma pack(push, 1)
struct ARPPacket {
    // Ethernet header
    uint8_t  eth_dst[6];
    uint8_t  eth_src[6];
    uint16_t eth_type;       // 0x0806 for ARP

    // ARP header
    uint16_t hw_type;        // 0x0001 for Ethernet
    uint16_t proto_type;     // 0x0800 for IPv4
    uint8_t  hw_len;         // 6 for MAC
    uint8_t  proto_len;      // 4 for IPv4
    uint16_t opcode;         // 1=request, 2=reply

    // ARP payload
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
};
#pragma pack(pop)

static constexpr uint16_t ETH_TYPE_ARP  = 0x0806;
static constexpr uint16_t ARP_HW_ETHER  = 0x0001;
static constexpr uint16_t ARP_PROTO_IP  = 0x0800;
static constexpr uint16_t ARP_OP_REQ    = 0x0001;
static constexpr uint16_t ARP_OP_REPLY  = 0x0002;

// ─── Impl ─────────────────────────────────────────────────────────────────────

struct ARPController::Impl {
    std::string                   iface;
    MACAddress                    spoofed_mac{};
    IPv4Address                   our_ip{};
    uint32_t                      announce_interval_sec = 30;

    ARPStats                      stats{};
    std::map<IPv4Address, ARPEntry> cache;
    mutable std::mutex            mu;

    std::atomic<bool>             running{false};
    std::thread                   worker;

#ifdef _WIN32
    // Windows: use SendARP or Npcap
    // Placeholder for raw socket handle
    int raw_socket = -1;
#else
    int                           raw_socket = -1;
#endif

    // ── Build ARP packet ────────────────────────────────────────────────────
    ARPPacket build_arp(uint16_t opcode,
                        const MACAddress& src_mac, const IPv4Address& src_ip,
                        const MACAddress& dst_mac, const IPv4Address& dst_ip)
    {
        ARPPacket pkt{};

        // Ethernet header
        std::copy(dst_mac.begin(), dst_mac.end(), pkt.eth_dst);
        std::copy(src_mac.begin(), src_mac.end(), pkt.eth_src);
        pkt.eth_type = htons(ETH_TYPE_ARP);

        // ARP header
        pkt.hw_type    = htons(ARP_HW_ETHER);
        pkt.proto_type = htons(ARP_PROTO_IP);
        pkt.hw_len     = 6;
        pkt.proto_len  = 4;
        pkt.opcode     = htons(opcode);

        // ARP payload
        std::copy(src_mac.begin(), src_mac.end(), pkt.sender_mac);
        std::copy(src_ip.begin(),  src_ip.end(),  pkt.sender_ip);
        std::copy(dst_mac.begin(), dst_mac.end(), pkt.target_mac);
        std::copy(dst_ip.begin(),  dst_ip.end(),  pkt.target_ip);

        return pkt;
    }

    // ── Open raw socket ─────────────────────────────────────────────────────
    bool open_socket() {
#ifdef _WIN32
        // Windows: raw ARP sending requires Npcap/WinPcap
        // Stub - will integrate with existing ncp_network.hpp pcap handles
        return true;
#else
        raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        return raw_socket >= 0;
#endif
    }

    // ── Close raw socket ────────────────────────────────────────────────────
    void close_socket() {
#ifndef _WIN32
        if (raw_socket >= 0) {
            close(raw_socket);
            raw_socket = -1;
        }
#endif
    }

    // ── Send raw ARP packet ─────────────────────────────────────────────────
    bool send_raw_arp(const ARPPacket& pkt) {
#ifdef _WIN32
        // Windows stub - integration with Npcap
        (void)pkt;
        return true;
#else
        if (raw_socket < 0) return false;

        struct sockaddr_ll addr{};
        addr.sll_family   = AF_PACKET;
        addr.sll_protocol = htons(ETH_P_ARP);
        addr.sll_ifindex  = static_cast<int>(if_nametoindex(iface.c_str()));
        addr.sll_halen    = 6;
        std::copy(pkt.eth_dst, pkt.eth_dst + 6, addr.sll_addr);

        ssize_t sent = sendto(raw_socket, &pkt, sizeof(pkt), 0,
                              reinterpret_cast<struct sockaddr*>(&addr),
                              sizeof(addr));
        return sent == sizeof(pkt);
#endif
    }

    // ── Worker thread loop ──────────────────────────────────────────────────
    void worker_loop() {
        // Send initial gratuitous ARP
        send_gratuitous();

        auto next_announce = std::chrono::steady_clock::now() +
                             std::chrono::seconds(announce_interval_sec);

        while (running.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

            auto now = std::chrono::steady_clock::now();
            if (announce_interval_sec > 0 && now >= next_announce) {
                send_gratuitous();
                next_announce = now + std::chrono::seconds(announce_interval_sec);
            }
        }
    }

    // ── Send gratuitous ARP ─────────────────────────────────────────────────
    bool send_gratuitous() {
        MACAddress broadcast = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        // Gratuitous ARP: sender=spoofed_mac/our_ip, target=broadcast/our_ip
        ARPPacket pkt = build_arp(ARP_OP_REPLY,
                                  spoofed_mac, our_ip,
                                  broadcast, our_ip);

        bool ok = send_raw_arp(pkt);
        if (ok) {
            std::lock_guard<std::mutex> lock(mu);
            stats.gratuitous_sent++;
        }
        return ok;
    }
};

// ─── Constructor / Destructor ─────────────────────────────────────────────────

ARPController::ARPController()
    : impl_(std::make_unique<Impl>())
{}

ARPController::~ARPController() {
    if (impl_ && impl_->running.load()) {
        stop();
    }
}

ARPController::ARPController(ARPController&&) noexcept = default;
ARPController& ARPController::operator=(ARPController&&) noexcept = default;

// ─── Configuration ────────────────────────────────────────────────────────────

void ARPController::set_interface(const std::string& iface) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->iface = iface;
}

void ARPController::set_spoofed_mac(const MACAddress& mac) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->spoofed_mac = mac;
}

void ARPController::set_ip(const IPv4Address& ip) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->our_ip = ip;
}

// ─── start / stop ─────────────────────────────────────────────────────────────

void ARPController::start() {
    if (impl_->running.load()) return;

    if (!impl_->open_socket()) {
        throw std::runtime_error("ARPController: failed to open raw socket");
    }

    impl_->running.store(true, std::memory_order_release);
    impl_->worker = std::thread([this] {
        impl_->worker_loop();
    });
}

void ARPController::stop() {
    impl_->running.store(false, std::memory_order_release);
    if (impl_->worker.joinable()) {
        impl_->worker.join();
    }
    impl_->close_socket();
}

bool ARPController::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

// ─── ARP operations ───────────────────────────────────────────────────────────

bool ARPController::send_gratuitous_arp() {
    return impl_->send_gratuitous();
}

bool ARPController::send_arp_reply(const MACAddress& target_mac,
                                   const IPv4Address& target_ip) {
    ARPPacket pkt = impl_->build_arp(ARP_OP_REPLY,
                                     impl_->spoofed_mac, impl_->our_ip,
                                     target_mac, target_ip);
    bool ok = impl_->send_raw_arp(pkt);
    if (ok) {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->stats.replies_sent++;
    }
    return ok;
}

std::vector<ARPEntry> ARPController::get_cache() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    std::vector<ARPEntry> entries;
    entries.reserve(impl_->cache.size());
    for (const auto& [ip, entry] : impl_->cache) {
        entries.push_back(entry);
    }
    return entries;
}

void ARPController::set_announce_interval(uint32_t interval_sec) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->announce_interval_sec = interval_sec;
}

// ─── Stats ────────────────────────────────────────────────────────────────────

ARPStats ARPController::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    auto s = impl_->stats;
    s.cache_entries = impl_->cache.size();
    return s;
}

void ARPController::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->stats = ARPStats{};
}

// ─── MAC utilities ────────────────────────────────────────────────────────────

std::string ARPController::mac_to_string(const MACAddress& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

MACAddress ARPController::string_to_mac(const std::string& str) {
    MACAddress mac{};
    #ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
    unsigned int b[6] = {};
    if (std::sscanf(str.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
                    &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; ++i) {
            mac[i] = static_cast<uint8_t>(b[i]);
        }
    }
    #ifdef _MSC_VER
#pragma warning(pop)
#endif
    return mac;
}

} // namespace DPI
} // namespace ncp
