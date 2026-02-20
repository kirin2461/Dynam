#include "../include/ncp_network_backend.hpp"
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace ncp {

// ==================== IP/TCP Header Structs ====================

#pragma pack(push, 1)
struct RawIPHeader {
    uint8_t  ihl_ver;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct RawTCPHeader {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  res_doff;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct PseudoHeader {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_length;
};
#pragma pack(pop)

// ==================== Checksum ====================

static uint16_t calculate_checksum(const void* data, int len) {
    const uint16_t* buf = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(buf);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// ==================== RawSocketBackend ====================

class RawSocketBackend : public INetworkBackend {
public:
    RawSocketBackend() = default;

    ~RawSocketBackend() override {
        shutdown();
    }

    bool initialize(const std::string& interface_name) override {
        (void)interface_name;
#ifdef _WIN32
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            last_error_ = "WSAStartup failed";
            return false;
        }
        sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock_ == INVALID_SOCKET) {
            last_error_ = "Failed to create raw socket (run as Administrator)";
            return false;
        }
        BOOL opt = TRUE;
        setsockopt(sock_, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt));
#else
        sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock_ < 0) {
            last_error_ = "Failed to create raw socket (run as root)";
            return false;
        }
        int opt = 1;
        setsockopt(sock_, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
#endif
        initialized_ = true;
        return true;
    }

    void shutdown() override {
        stop_capture();
        if (initialized_) {
#ifdef _WIN32
            if (sock_ != INVALID_SOCKET) { closesocket(sock_); sock_ = INVALID_SOCKET; }
            WSACleanup();
#else
            if (sock_ >= 0) { close(sock_); sock_ = -1; }
#endif
            initialized_ = false;
        }
    }

    bool is_initialized() const override { return initialized_; }

    bool start_capture(CaptureCallback callback) override {
        if (!initialized_) return false;
        capturing_ = true;
        capture_cb_ = callback;
        capture_thread_ = std::thread([this]() {
            uint8_t buf[65535];
            while (capturing_) {
#ifdef _WIN32
                struct sockaddr_in from;
                int fromlen = sizeof(from);
                int n = recvfrom(sock_, (char*)buf, sizeof(buf), 0,
                                 (struct sockaddr*)&from, &fromlen);
#else
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);
                ssize_t n = recvfrom(sock_, buf, sizeof(buf), 0,
                                     (struct sockaddr*)&from, &fromlen);
#endif
                if (n > 0 && capture_cb_) {
                    std::vector<uint8_t> data(buf, buf + n);
                    capture_cb_(data, time(nullptr));
                }
            }
        });
        return true;
    }

    void stop_capture() override {
        capturing_ = false;
        if (capture_thread_.joinable()) capture_thread_.join();
    }

    bool is_capturing() const override { return capturing_; }

    bool send_raw_packet(
        const std::string& dest_ip,
        const std::vector<uint8_t>& data
    ) override {
        if (!initialized_) return false;
        struct sockaddr_in dest{};
        dest.sin_family = AF_INET;
        inet_pton(AF_INET, dest_ip.c_str(), &dest.sin_addr);
#ifdef _WIN32
        int sent = sendto(sock_, (const char*)data.data(),
                          static_cast<int>(data.size()), 0,
                          (struct sockaddr*)&dest, sizeof(dest));
        return sent == static_cast<int>(data.size());
#else
        ssize_t sent = sendto(sock_, data.data(), data.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        return sent == static_cast<ssize_t>(data.size());
#endif
    }

    bool send_tcp_packet(
        const std::string& src_ip,
        const std::string& dst_ip,
        uint16_t src_port,
        uint16_t dst_port,
        const std::vector<uint8_t>& payload,
        uint8_t tcp_flags,
        uint8_t ttl
    ) override {
        if (!initialized_) return false;

        size_t ip_len = sizeof(RawIPHeader);
        size_t tcp_len = sizeof(RawTCPHeader);
        size_t total = ip_len + tcp_len + payload.size();
        std::vector<uint8_t> packet(total, 0);

        auto* ip = reinterpret_cast<RawIPHeader*>(packet.data());
        auto* tcp = reinterpret_cast<RawTCPHeader*>(packet.data() + ip_len);

        // IP header
        ip->ihl_ver = 0x45;
        ip->tos = 0;
        ip->tot_len = htons(static_cast<uint16_t>(total));
        // SECURITY FIX: Use cryptographically secure random from libsodium
        ip->id = htons(static_cast<uint16_t>(randombytes_uniform(65536)));
        ip->frag_off = 0;
        ip->ttl = ttl;
        ip->protocol = IPPROTO_TCP;
        ip->check = 0;
        inet_pton(AF_INET, src_ip.c_str(), &ip->saddr);
        inet_pton(AF_INET, dst_ip.c_str(), &ip->daddr);
        ip->check = calculate_checksum(ip, static_cast<int>(ip_len));

        // TCP header
        tcp->source = htons(src_port);
        tcp->dest = htons(dst_port);
        // SECURITY FIX: Use cryptographically secure random for TCP seq
        tcp->seq = htonl(randombytes_random());
        tcp->ack_seq = 0;
        tcp->res_doff = 0x50; // data offset = 5 (20 bytes)
        tcp->flags = tcp_flags;
        tcp->window = htons(65535);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        // Copy payload
        if (!payload.empty()) {
            std::memcpy(packet.data() + ip_len + tcp_len,
                        payload.data(), payload.size());
        }

        // TCP checksum with pseudo-header
        PseudoHeader psh{};
        psh.saddr = ip->saddr;
        psh.daddr = ip->daddr;
        psh.zero = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(static_cast<uint16_t>(tcp_len + payload.size()));

        size_t psh_total = sizeof(PseudoHeader) + tcp_len + payload.size();
        std::vector<uint8_t> tcp_buf(psh_total);
        std::memcpy(tcp_buf.data(), &psh, sizeof(PseudoHeader));
        std::memcpy(tcp_buf.data() + sizeof(PseudoHeader), tcp,
                    tcp_len + payload.size());

        tcp->check = calculate_checksum(tcp_buf.data(), static_cast<int>(psh_total));

        return send_raw_packet(dst_ip, packet);
    }

    std::string get_backend_name() const override { return "RawSocket"; }
    std::string get_last_error() const override { return last_error_; }
    bool requires_admin() const override { return true; }

private:
#ifdef _WIN32
    SOCKET sock_ = INVALID_SOCKET;
#else
    int sock_ = -1;
#endif
    bool initialized_ = false;
    std::atomic<bool> capturing_{false};
    std::thread capture_thread_;
    CaptureCallback capture_cb_;
    std::string last_error_;
};

// ==================== ProxyOnlyBackend ====================

class ProxyOnlyBackend : public INetworkBackend {
public:
    bool initialize(const std::string&) override { initialized_ = true; return true; }
    void shutdown() override { initialized_ = false; }
    bool is_initialized() const override { return initialized_; }

    bool start_capture(CaptureCallback) override {
        last_error_ = "Capture not supported in proxy-only mode";
        return false;
    }
    void stop_capture() override {}
    bool is_capturing() const override { return false; }

    bool send_raw_packet(const std::string&, const std::vector<uint8_t>&) override {
        last_error_ = "Raw packets not supported in proxy-only mode";
        return false;
    }

    bool send_tcp_packet(const std::string&, const std::string&,
                         uint16_t, uint16_t, const std::vector<uint8_t>&,
                         uint8_t, uint8_t) override {
        last_error_ = "Raw TCP not supported in proxy-only mode";
        return false;
    }

    std::string get_backend_name() const override { return "ProxyOnly"; }
    std::string get_last_error() const override { return last_error_; }
    bool requires_admin() const override { return false; }

private:
    bool initialized_ = false;
    std::string last_error_;
};

// ==================== Factory ====================

bool NetworkBackendFactory::is_elevated() {
#ifdef _WIN32
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te;
        DWORD size = sizeof(te);
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size)) {
            elevated = te.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated != FALSE;
#else
    return geteuid() == 0;
#endif
}

std::vector<NetworkBackendType> NetworkBackendFactory::available_backends() {
    std::vector<NetworkBackendType> backends;
    backends.push_back(NetworkBackendType::PROXY_ONLY); // Always available
    if (is_elevated()) {
        backends.push_back(NetworkBackendType::RAW_SOCKETS);
    }
#ifdef _WIN32
    backends.push_back(NetworkBackendType::ETW_CAPTURE);
#endif
#ifdef HAVE_NFQUEUE
    if (is_elevated()) {
        backends.push_back(NetworkBackendType::NFQUEUE);
    }
#endif
    return backends;
}

std::unique_ptr<INetworkBackend> NetworkBackendFactory::create(NetworkBackendType type) {
    if (type == NetworkBackendType::AUTO) {
        if (is_elevated()) {
            return std::make_unique<RawSocketBackend>();
        }
        return std::make_unique<ProxyOnlyBackend>();
    }

    switch (type) {
    case NetworkBackendType::RAW_SOCKETS:
        return std::make_unique<RawSocketBackend>();
    case NetworkBackendType::PROXY_ONLY:
        return std::make_unique<ProxyOnlyBackend>();
    default:
        return std::make_unique<ProxyOnlyBackend>();
    }
}

} // namespace ncp
