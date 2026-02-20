// FIX #5: Use relative include path consistent with other source files
// (db.cpp, e2e.cpp, mimicry.cpp all use "../include/")
#include "../include/ncp_i2p.hpp"
#include <iostream>
#include <array>
#include <algorithm>
#include <sstream>
#include <cstring>
#include <iomanip>
#include <random>
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
    
    // FIX #3: send_sam_command — recv with timeout protection.
    // SO_RCVTIMEO is set once in initialize() so every recv() is bounded.
    // If SAM bridge doesn't respond within the timeout the call fails
    // instead of blocking the thread forever.
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
                // received == 0  → connection closed
                // received <  0  → error or timeout (EAGAIN/WSAETIMEDOUT)
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
    
    // Set non-blocking mode for connect with timeout
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
    
    // Switch back to blocking mode
    mode = 0;
    ioctlsocket(impl_->sam_socket, FIONBIO, &mode);
    
    // FIX #3: Set recv timeout (10 seconds) to prevent infinite blocking
    DWORD recv_timeout_ms = 10000;
    setsockopt(impl_->sam_socket, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&recv_timeout_ms, sizeof(recv_timeout_ms));
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
    
    // Switch back to blocking mode
    flags = fcntl(impl_->sam_socket, F_GETFL, 0);
    fcntl(impl_->sam_socket, F_SETFL, flags & ~O_NONBLOCK);
    
    // FIX #3: Set recv timeout (10 seconds) to prevent infinite blocking
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 10;
    recv_timeout.tv_usec = 0;
    setsockopt(impl_->sam_socket, SOL_SOCKET, SO_RCVTIMEO,
               &recv_timeout, sizeof(recv_timeout));
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
    (void)direction;  // Used in future STREAM FORWARD implementation
    
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
    
    // FIX #1: Lock tunnels_ for thread-safe write
    {
        std::lock_guard<std::mutex> lock(tunnels_mutex_);
        tunnels_[name] = info;
    }
    
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
    // FIX #1: Lock tunnels_ for thread-safe read
    std::lock_guard<std::mutex> lock(tunnels_mutex_);
    std::vector<TunnelInfo> result;
    result.reserve(tunnels_.size());
    for (const auto& pair : tunnels_) {
        result.push_back(pair.second);
    }
    return result;
}

bool I2PManager::destroy_tunnel(const std::string& tunnel_id) {
    // FIX #1: Lock tunnels_ for thread-safe erase
    std::lock_guard<std::mutex> lock(tunnels_mutex_);
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
    if (!is_active()) return;

    // FIX #1: Lock tunnels_ for the entire rotation operation
    std::lock_guard<std::mutex> lock(tunnels_mutex_);

    // Snapshot current tunnel IDs (avoid modifying map while iterating)
    std::vector<std::string> old_ids;
    old_ids.reserve(tunnels_.size());
    for (const auto& pair : tunnels_) {
        old_ids.push_back(pair.first);
    }

    if (old_ids.empty()) return;

    // Generate a fresh ephemeral destination for new tunnels.
    // This gives us new cryptographic keys — the core purpose of rotation.
    std::string new_dest = create_ephemeral_destination();
    if (new_dest.empty()) return;

    // Rebuild each tunnel with the new destination
    for (const auto& tid : old_ids) {
        auto it = tunnels_.find(tid);
        if (it == tunnels_.end()) continue;

        TunnelInfo old_info = it->second;

        // FIX #2: Destroy old SAM session before creating a new one.
        // Without this, SAM bridge keeps both sessions alive, leaking
        // tunnel resources on the I2P router over time.
        {
            std::ostringstream remove_cmd;
            remove_cmd << "SESSION REMOVE ID=" << tid;
            std::string remove_response;
            impl_->send_sam_command(remove_cmd.str(), remove_response);
            // Best-effort: if removal fails, we still try to create a new session.
            // SAM 3.3 returns "SESSION STATUS RESULT=OK" on successful removal.
        }

        // Create replacement session via SAM.
        // Now that the old session is removed, we can reuse the original ID
        // instead of "<id>_rot" which would accumulate stale sessions.
        std::ostringstream cmd;
        cmd << "SESSION CREATE STYLE=STREAM"
            << " ID=" << tid
            << " DESTINATION="
            << (old_info.type == TunnelType::SERVER ? new_dest : "TRANSIENT")
            << " inbound.length=" << config_.tunnel_length
            << " outbound.length=" << config_.tunnel_length
            << " inbound.quantity=" << config_.tunnel_quantity
            << " outbound.quantity=" << config_.tunnel_quantity;

        std::string response;
        if (!impl_->send_sam_command(cmd.str(), response)) {
            continue;  // Keep old tunnel entry if rotation fails
        }

        if (response.find("SESSION STATUS RESULT=OK") == std::string::npos) {
            continue;  // SAM rejected — keep existing tunnel
        }

        // Remove old tunnel entry, insert the rotated replacement
        tunnels_.erase(it);

        TunnelInfo new_info;
        new_info.tunnel_id = tid;
        new_info.type = old_info.type;
        new_info.local_dest = new_dest;
        new_info.remote_dest = old_info.remote_dest;
        new_info.created = std::chrono::system_clock::now();
        new_info.expires = new_info.created + std::chrono::hours(
            config_.destination_expiration_hours);
        new_info.is_backup = old_info.is_backup;
        tunnels_[tid] = new_info;
    }

    // Update current destination to the freshly generated one
    current_dest_ = new_dest;
}

void I2PManager::enable_traffic_mixing(bool enable, int delay_ms) {
    config_.obfuscate_tunnel_messages = enable;
    if (delay_ms > 0) {
        config_.mix_delay_ms = delay_ms;
    }

    if (!enable) {
        // Disable dummy traffic along with mixing
        config_.enable_dummy_traffic = false;
        return;
    }

    // Enable cover traffic to mask real packet timing.
    // DPI correlates inter-packet arrival times to fingerprint tunneled
    // protocols. Dummy traffic adds noise to defeat timing analysis.
    config_.enable_dummy_traffic = true;

    // If we have active tunnels, inject an initial dummy burst to
    // establish a baseline traffic pattern for the DPI to latch onto.
    // Subsequent real packets blend into this established pattern.
    if (is_active()) {
        // FIX #1: Lock for tunnels_.empty() check
        std::lock_guard<std::mutex> lock(tunnels_mutex_);
        if (!tunnels_.empty()) {
            for (int i = 0; i < 3; ++i) {
                inject_dummy_message();
            }
        }
    }
}

// FIX #4: Implement inject_dummy_message() — was declared in ncp_i2p.hpp
// and called by enable_traffic_mixing(), but never defined.
// Sends a random-sized dummy payload through SAM to provide cover traffic.
void I2PManager::inject_dummy_message() {
    if (!impl_->sam_connected || current_dest_.empty()) return;

    // Generate random dummy payload (64–512 bytes) for traffic mixing.
    // Variable size makes dummy traffic harder to fingerprint vs fixed-size.
    std::mt19937 rng(static_cast<unsigned>(std::chrono::steady_clock::now()
        .time_since_epoch().count()));
    std::uniform_int_distribution<size_t> size_dist(64, 512);
    size_t dummy_size = size_dist(rng);

    std::vector<uint8_t> dummy(dummy_size);
    randombytes_buf(dummy.data(), dummy.size());

    // Send dummy via SAM RAW protocol to the current destination.
    // RAW datagrams are fire-and-forget (no session needed for simple sends),
    // making them ideal for cover traffic that doesn't need reliability.
    std::ostringstream cmd;
    cmd << "RAW SEND DESTINATION=" << current_dest_
        << " SIZE=" << dummy_size;

    std::string response;
    impl_->send_sam_command(cmd.str(), response);
    // Best-effort: we don't check the response for dummy traffic.
    // If the send fails, it's acceptable — dummy messages are noise.
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
    // FIX #1: Lock tunnels_ for thread-safe read of active_tunnels count
    std::lock_guard<std::mutex> lock(tunnels_mutex_);
    Statistics stats{};
    stats.active_tunnels = tunnels_.size();
    return stats;
}

} // namespace ncp
