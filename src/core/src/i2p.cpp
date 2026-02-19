#include "ncp_i2p.hpp"
#include <iostream>
#include <array>
#include <algorithm>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using ssize_t = ptrdiff_t;
// FIX HIGH #7: SOCKET is UINT_PTR (8 bytes on x64), int is 4 bytes.
// Use platform_socket_t to avoid truncation.
using platform_socket_t = SOCKET;
static constexpr platform_socket_t INVALID_SOCK = INVALID_SOCKET;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
using platform_socket_t = int;
static constexpr platform_socket_t INVALID_SOCK = -1;
#endif

namespace ncp {

// Impl definition with SAM Bridge connection
struct I2PManager::Impl {
    platform_socket_t sam_socket = INVALID_SOCK;
    std::string session_id;
    std::string destination_keys;
    bool sam_connected = false;
    
    bool send_sam_command(const std::string& cmd, std::string& response) {
        if (sam_socket == INVALID_SOCK) return false;
        
        std::string full_cmd = cmd + "\n";
        ssize_t sent = send(sam_socket, full_cmd.c_str(), static_cast<int>(full_cmd.length()), 0);
        if (sent <= 0) return false;
        
        char buffer[4096];
        response.clear();
        while (true) {
            ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
            if (received <= 0) {
                return !response.empty();
            }
            buffer[received] = '\0';
            response.append(buffer, received);
            
            if (response.find('\n') != std::string::npos) {
                break;
            }
        }
        return true;
    }
    
    void close_sam() {
        if (sam_socket != INVALID_SOCK) {
#ifdef _WIN32
            closesocket(sam_socket);
#else
            close(sam_socket);
#endif
            sam_socket = INVALID_SOCK;
        }
        sam_connected = false;
    }
};

I2PManager::I2PManager() : impl_(std::make_unique<Impl>()), is_initialized_(false) {}

I2PManager::~I2PManager() {
    if (impl_) {
        impl_->close_sam();
    }
}

bool I2PManager::initialize(const Config& config) {
    config_ = config;
    
#ifdef _WIN32
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return false;
    }
#endif
    
    // FIX HIGH #7: No truncation — socket() returns platform_socket_t directly
    impl_->sam_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (impl_->sam_socket == INVALID_SOCK) {
        return false;
    }
    
    // Set non-blocking mode
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(impl_->sam_socket, FIONBIO, &mode);
#else
    int flags = fcntl(impl_->sam_socket, F_GETFL, 0);
    fcntl(impl_->sam_socket, F_SETFL, flags | O_NONBLOCK);
#endif
    
    struct sockaddr_in sam_addr{};
    sam_addr.sin_family = AF_INET;
    sam_addr.sin_port = htons(config.sam_port);
    inet_pton(AF_INET, config.sam_host.c_str(), &sam_addr.sin_addr);
    
    int connect_result = connect(impl_->sam_socket, (struct sockaddr*)&sam_addr, sizeof(sam_addr));
    
#ifdef _WIN32
    if (connect_result == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        impl_->close_sam();
        return false;
    }
    
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(impl_->sam_socket, &wset);
    struct timeval tv = {2, 0};
    
    if (select(0, nullptr, &wset, nullptr, &tv) <= 0) {
        impl_->close_sam();
        return false;
    }
    
    int error = 0;
    int len = sizeof(error);
    getsockopt(impl_->sam_socket, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
    if (error != 0) {
        impl_->close_sam();
        return false;
    }
    
    mode = 0;
    ioctlsocket(impl_->sam_socket, FIONBIO, &mode);
#else
    if (connect_result < 0 && errno != EINPROGRESS) {
        impl_->close_sam();
        return false;
    }
    
    struct pollfd pfd = {impl_->sam_socket, POLLOUT, 0};
    if (poll(&pfd, 1, 2000) <= 0) {
        impl_->close_sam();
        return false;
    }
    
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(impl_->sam_socket, SOL_SOCKET, SO_ERROR, &error, &len);
    if (error != 0) {
        impl_->close_sam();
        return false;
    }
    
    flags = fcntl(impl_->sam_socket, F_GETFL, 0);
    fcntl(impl_->sam_socket, F_SETFL, flags & ~O_NONBLOCK);
#endif
    
    // SAM Handshake: HELLO VERSION
    std::string response;
    if (!impl_->send_sam_command("HELLO VERSION MIN=3.0 MAX=3.3", response)) {
        impl_->close_sam();
        return false;
    }
    
    if (response.find("HELLO REPLY RESULT=OK") == std::string::npos) {
        impl_->close_sam();
        return false;
    }
    
    impl_->sam_connected = true;
    is_initialized_ = true;
    
    if (current_dest_.empty()) {
        current_dest_ = create_ephemeral_destination();
    }
    
    return true;
}

bool I2PManager::is_active() const {
    return config_.enabled && is_initialized_ && impl_->sam_connected;
}

void I2PManager::set_enabled(bool enabled) {
    config_.enabled = enabled;
}

std::string I2PManager::get_destination() const {
    return current_dest_;
}

bool I2PManager::create_tunnel(const std::string& name, uint16_t local_port,
                               const std::string& remote_dest, TunnelType type) {
    (void)local_port;
    
    if (!is_active()) return false;
    
    std::string style = (type == TunnelType::CLIENT) ? "STREAM" : "STREAM";
    std::string direction = (type == TunnelType::SERVER) ? "FORWARD" : "CONNECT";
    
    std::ostringstream cmd;
    cmd << "SESSION CREATE STYLE=" << style
        << " ID=" << name
        << " DESTINATION=" << (type == TunnelType::CLIENT ? "TRANSIENT" : current_dest_)
        << " inbound.length=" << config_.tunnel_length
        << " outbound.length=" << config_.tunnel_length
        << " inbound.quantity=" << config_.tunnel_quantity
        << " outbound.quantity=" << config_.tunnel_quantity;
    
    std::string response;
    if (!impl_->send_sam_command(cmd.str(), response)) {
        return false;
    }
    
    if (response.find("SESSION STATUS RESULT=OK") == std::string::npos) {
        return false;
    }
    
    size_t dest_pos = response.find("DESTINATION=");
    if (dest_pos != std::string::npos) {
        impl_->destination_keys = response.substr(dest_pos + 12);
    }
    
    TunnelInfo info;
    info.tunnel_id = name;
    info.type = type;
    info.local_dest = current_dest_;
    info.remote_dest = remote_dest;
    info.created = std::chrono::system_clock::now();
    info.expires = info.created + std::chrono::hours(24);
    tunnels_[name] = info;
    
    return true;
}

bool I2PManager::create_server_tunnel(const std::string& name, uint16_t local_port) {
    if (!is_active()) return false;
    
    std::ostringstream cmd;
    cmd << "SESSION CREATE STYLE=STREAM ID=" << name
        << " DESTINATION=" << current_dest_
        << " FROM_PORT=" << local_port;
    
    std::string response;
    if (!impl_->send_sam_command(cmd.str(), response)) {
        return false;
    }
    
    return response.find("SESSION STATUS RESULT=OK") != std::string::npos;
}

std::vector<I2PManager::TunnelInfo> I2PManager::get_active_tunnels() const {
    std::vector<TunnelInfo> result;
    for (const auto& pair : tunnels_) {
        result.push_back(pair.second);
    }
    return result;
}

bool I2PManager::destroy_tunnel(const std::string& tunnel_id) {
    auto it = tunnels_.find(tunnel_id);
    if (it == tunnels_.end()) return false;
    
    tunnels_.erase(it);
    return true;
}

std::string I2PManager::create_ephemeral_destination() {
    if (!impl_->sam_connected) return "";
    
    std::string response;
    if (!impl_->send_sam_command("DEST GENERATE", response)) {
        return "";
    }
    
    size_t pub_pos = response.find("PUB=");
    size_t priv_pos = response.find("PRIV=");
    
    if (pub_pos != std::string::npos && priv_pos != std::string::npos) {
        size_t pub_start = pub_pos + 4;
        size_t pub_end = response.find(' ', pub_start);
        if (pub_end == std::string::npos) pub_end = response.find('\n', pub_start);
        
        return response.substr(pub_start, pub_end - pub_start);
    }
    
    return "";
}

void I2PManager::rotate_tunnels() {
    // Rotate implementation
}

void I2PManager::enable_traffic_mixing(bool enable, uint32_t interval_ms) {
    (void)enable;
    (void)interval_ms;
}

std::vector<uint8_t> I2PManager::pad_message(const std::vector<uint8_t>& message, size_t block_size) {
    if (block_size == 0) return message;
    
    size_t padded_size = ((message.size() + block_size - 1) / block_size) * block_size;
    std::vector<uint8_t> result = message;
    result.resize(padded_size);
    
    if (result.size() > message.size()) {
        randombytes_buf(result.data() + message.size(), result.size() - message.size());
    }
    
    return result;
}

I2PManager::Statistics I2PManager::get_statistics() const {
    Statistics stats{};
    stats.active_tunnels = tunnels_.size();
    return stats;
}

} // namespace ncp
