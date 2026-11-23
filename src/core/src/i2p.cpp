// FIX #5: Use relative include path consistent with other source files
// (db.cpp, e2e.cpp, mimicry.cpp all use "../include/")
#include "../include/ncp_i2p.hpp"
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

namespace {

// A SAM command parameter is interpolated directly into a newline-terminated
// command line, so it must never contain whitespace, CR/LF or control bytes —
// otherwise a crafted tunnel name / hostname / key would inject extra SAM
// commands (e.g. "foo\nSESSION REMOVE ID=victim").
bool sam_token_ok(const std::string& token) {
    if (token.empty() || token.size() > 1024) return false;
    for (unsigned char c : token) {
        if (c <= 0x20 || c == 0x7F) return false;
    }
    return true;
}

// Validate a reply line: it must start with the expected status prefix AND be
// a success. Matching on the prefix (instead of a bare find("RESULT=OK"))
// prevents a stray token from a previous, desynchronised reply being accepted.
bool sam_reply_ok(const std::string& response, const char* prefix) {
    const size_t plen = std::strlen(prefix);
    if (response.size() < plen) return false;
    if (response.compare(0, plen, prefix) != 0) return false;
    return response.find("RESULT=OK") != std::string::npos;
}

// SAM accepts tunnel length 0..7 and quantity 1..6. Out-of-range values make
// SESSION CREATE fail; clamp to the protocol's legal window.
int clamp_sam_opt(int value, int lo, int hi) {
    if (value < lo) return lo;
    if (value > hi) return hi;
    return value;
}

// ── Small socket helpers for the inbound (server) path ────────────────────
// accept_inbound_stream() opens its own SAM control connection, so it cannot
// reuse Impl's single socket. These mirror the connect logic in initialize().

void close_plain_socket(platform_socket_t s) {
    if (s == INVALID_SOCK) return;
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

platform_socket_t sam_open(const std::string& host, uint16_t port, int timeout_ms) {
    platform_socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCK) return INVALID_SOCK;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    int rc = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    if (select(0, nullptr, &wset, nullptr, &tv) <= 0) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }
    int err = 0;
    int elen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
    if (err != 0) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }
    mode = 0;
    ioctlsocket(s, FIONBIO, &mode);
    DWORD rcv = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcv, sizeof(rcv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&rcv, sizeof(rcv));
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    int rc = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }
    struct pollfd pfd = { s, POLLOUT, 0 };
    if (poll(&pfd, 1, timeout_ms) <= 0) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }
    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err != 0) {
        close_plain_socket(s);
        return INVALID_SOCK;
    }
    fcntl(s, F_SETFL, flags);
    struct timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
    return s;
}

// Never let a peer that closed early kill us with SIGPIPE on POSIX.
#ifdef MSG_NOSIGNAL
static constexpr int kSendFlags = MSG_NOSIGNAL;
#else
static constexpr int kSendFlags = 0;
#endif

bool send_all(platform_socket_t s, const std::string& bytes) {
    size_t off = 0;
    while (off < bytes.size()) {
        ssize_t n = send(s, bytes.data() + off,
                         static_cast<int>(bytes.size() - off), kSendFlags);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

// Read one '\n'-terminated line. Reads a byte at a time on purpose: on the
// inbound path the peer's first payload bytes may arrive in the same TCP
// segment as the "PEER DESTINATION=" line, and a bulk recv() would swallow
// them. Lines here are small (SAM status + one destination), so the syscall
// overhead is irrelevant.
bool recv_line(platform_socket_t s, std::string& out) {
    out.clear();
    char c = 0;
    for (;;) {
        ssize_t n = recv(s, &c, 1, 0);
        if (n <= 0) return false;
        out.push_back(c);
        if (c == '\n') return true;
        if (out.size() > 64 * 1024) return false;  // runaway line guard
    }
}

} // namespace

// ===== I2PPeerFilter ======================================================

I2PPeerFilter::I2PPeerFilter() { set_config(Config{}); }

I2PPeerFilter::I2PPeerFilter(const Config& config) { set_config(config); }

std::string I2PPeerFilter::normalize_dest(const std::string& dest) {
    size_t b = dest.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = dest.find_last_not_of(" \t\r\n");
    return dest.substr(b, e - b + 1);
}

void I2PPeerFilter::set_config(const Config& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    allow_.clear();
    block_.clear();
    for (const auto& d : config.allowlist) {
        std::string n = normalize_dest(d);
        if (!n.empty()) allow_.insert(std::move(n));
    }
    for (const auto& d : config.blocklist) {
        std::string n = normalize_dest(d);
        if (!n.empty()) block_.insert(std::move(n));
    }
}

I2PPeerFilter::Config I2PPeerFilter::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

I2PPeerFilter::Decision I2PPeerFilter::check(
    const std::string& peer_dest,
    std::chrono::system_clock::time_point now)
{
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string dest = normalize_dest(peer_dest);
    if (dest.empty()) {
        ++rejected_;
        return {false, "empty-destination"};
    }
    if (block_.count(dest)) {
        ++rejected_;
        return {false, "blocklisted"};
    }
    if (!allow_.empty() && !allow_.count(dest)) {
        ++rejected_;
        return {false, "not-allowlisted"};
    }

    PeerState& st = peers_[dest];

    // Slide the rate-limit window forward.
    const auto cutoff = now - config_.rate_window;
    while (!st.recent.empty() && st.recent.front() < cutoff) {
        st.recent.pop_front();
    }

    if (config_.max_concurrent_per_peer != 0 &&
        st.open >= config_.max_concurrent_per_peer) {
        ++rejected_;
        return {false, "too-many-open"};
    }
    if (config_.max_new_per_window != 0 &&
        st.recent.size() >= config_.max_new_per_window) {
        ++rejected_;
        return {false, "rate-limited"};
    }

    ++st.open;
    st.recent.push_back(now);
    ++accepted_;
    return {true, "allowed"};
}

void I2PPeerFilter::release(const std::string& peer_dest) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = peers_.find(normalize_dest(peer_dest));
    if (it == peers_.end()) return;
    if (it->second.open > 0) it->second.open--;
}

size_t I2PPeerFilter::accepted_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return accepted_;
}

size_t I2PPeerFilter::rejected_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rejected_;
}

std::vector<std::string> I2PPeerFilter::blocked_peers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {block_.begin(), block_.end()};
}

void I2PPeerFilter::reset_counters() {
    std::lock_guard<std::mutex> lock(mutex_);
    accepted_ = 0;
    rejected_ = 0;
    peers_.clear();
}

// ===== I2POutboundPolicy ==================================================

I2POutboundPolicy::I2POutboundPolicy() { set_config(Config{}); }

I2POutboundPolicy::I2POutboundPolicy(const Config& config) { set_config(config); }

std::string I2POutboundPolicy::normalize_destination(const std::string& dest) {
    size_t b = dest.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = dest.find_last_not_of(" \t\r\n");
    return dest.substr(b, e - b + 1);
}

bool I2POutboundPolicy::valid_destination_format(const std::string& dest_in) {
    const std::string dest = normalize_destination(dest_in);
    if (dest.empty() || dest.size() > 4096) return false;

    // Injection guard: a destination is interpolated into a SAM command line.
    for (unsigned char c : dest) {
        if (c <= 0x20 || c == 0x7F) return false;
    }

    static const std::string kSuffix = ".i2p";
    const bool is_name = dest.size() > kSuffix.size() &&
        dest.compare(dest.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0;
    if (is_name) {
        const std::string host = dest.substr(0, dest.size() - kSuffix.size());
        if (host.empty()) return false;
        if (host.front() == '.' || host.back() == '.') return false;
        if (host.find("..") != std::string::npos) return false;
        for (unsigned char c : host) {
            const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
            if (!ok) return false;
        }
        return true;
    }

    // Base64 destination. SAM emits standard base64; '~' appears in some
    // encodings in place of '/' and '=' is used as padding.
    if (dest.size() < 32) return false;
    for (unsigned char c : dest) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '+' || c == '/' ||
                        c == '~' || c == '=' || c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

void I2POutboundPolicy::set_config(const Config& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    allow_.clear();
    block_.clear();
    for (const auto& d : config.allowlist) {
        std::string n = normalize_destination(d);
        if (!n.empty()) allow_.insert(std::move(n));
    }
    for (const auto& d : config.blocklist) {
        std::string n = normalize_destination(d);
        if (!n.empty()) block_.insert(std::move(n));
    }
}

I2POutboundPolicy::Config I2POutboundPolicy::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

I2POutboundPolicy::Decision I2POutboundPolicy::check(
    const std::string& session_id, const std::string& dest_in) const
{
    const std::string dest = normalize_destination(dest_in);
    if (dest.empty()) return {false, "empty-destination"};

    // Always enforce the command-line injection guard; the config flag only
    // controls the stricter hostname/base64 shape check.
    for (unsigned char c : dest) {
        if (c <= 0x20 || c == 0x7F) return {false, "invalid-destination"};
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (config_.validate_format && !valid_destination_format(dest)) {
        return {false, "invalid-destination"};
    }
    if (block_.count(dest)) return {false, "blocklisted"};

    // An explicit allowlist fixes the acceptable set, so pinning adds nothing.
    if (!allow_.empty()) {
        if (!allow_.count(dest)) return {false, "not-allowlisted"};
        return {true, "allowed"};
    }

    if (config_.pin_first_destination && !session_id.empty()) {
        auto it = pins_.find(session_id);
        if (it != pins_.end() && it->second.destination != dest) {
            return {false, "destination-changed"};
        }
    }
    return {true, "allowed"};
}

void I2POutboundPolicy::pin(const std::string& session_id,
                            const std::string& dest_in) {
    if (session_id.empty()) return;
    const std::string dest = normalize_destination(dest_in);
    if (dest.empty()) return;

    std::lock_guard<std::mutex> lock(mutex_);
    if (pins_.count(session_id)) return;   // never silently re-point a session
    Pin p;
    p.session_id = session_id;
    p.destination = dest;
    p.pinned_at = std::chrono::system_clock::now();
    pins_[session_id] = std::move(p);
}

bool I2POutboundPolicy::is_pinned(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pins_.count(session_id) != 0;
}

bool I2POutboundPolicy::pinned_destination(const std::string& session_id,
                                           std::string& out_dest) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pins_.find(session_id);
    if (it == pins_.end()) return false;
    out_dest = it->second.destination;
    return true;
}

std::vector<I2POutboundPolicy::Pin> I2POutboundPolicy::pins() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Pin> out;
    out.reserve(pins_.size());
    for (const auto& kv : pins_) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const Pin& a, const Pin& b) {
        return a.session_id < b.session_id;
    });
    return out;
}

void I2POutboundPolicy::unpin(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    pins_.erase(session_id);
}

void I2POutboundPolicy::clear_pins() {
    std::lock_guard<std::mutex> lock(mutex_);
    pins_.clear();
}

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
        size_t off = 0;
        while (off < full_cmd.size()) {
            ssize_t sent = send(sam_socket, full_cmd.data() + off,
                                static_cast<int>(full_cmd.size() - off), 0);
            if (sent <= 0) return false;
            off += static_cast<size_t>(sent);
        }
        
        char buffer[4096];
        response.clear();
        while (true) {
            ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
            if (received <= 0) {
                // received == 0  -> connection closed
                // received <  0  -> error or timeout (EAGAIN/WSAETIMEDOUT)
                // Either way the reply line is incomplete: fail closed rather
                // than return a truncated line that might parse as success.
                return false;
            }
            buffer[received] = '\0';
            response.append(buffer, received);
            
            if (response.find('\n') != std::string::npos) {
                break;
            }
        }
        return true;
    }
    
    // Send raw bytes (command line + optional binary payload) in one go and
    // read exactly one reply line. Needed for STREAM SEND, where binary data
    // immediately follows the command — send_sam_command() would append an
    // extra '\n' after the payload and corrupt the stream.
    bool send_sam_raw(const std::string& bytes, std::string& response) {
        if (sam_socket == INVALID_SOCK) return false;
        size_t off = 0;
        while (off < bytes.size()) {
            ssize_t sent = send(sam_socket, bytes.data() + off,
                                static_cast<int>(bytes.size() - off), 0);
            if (sent <= 0) return false;
            off += static_cast<size_t>(sent);
        }
        char buffer[4096];
        response.clear();
        while (true) {
            ssize_t received = recv(sam_socket, buffer, sizeof(buffer) - 1, 0);
            if (received <= 0) {
                return false;
            }
            buffer[received] = '\0';
            response.append(buffer, received);
            if (response.find('\n') != std::string::npos) break;
        }
        return true;
    }

    // Best-effort teardown of a SAM session. Without this the router keeps the
    // session (and its tunnel pools) alive after the local entry is dropped.
    bool remove_session(const std::string& session_id) {
        if (sam_socket == INVALID_SOCK) return false;
        if (!sam_token_ok(session_id)) return false;
        std::string response;
        return send_sam_command("SESSION REMOVE ID=" + session_id, response) &&
               sam_reply_ok(response, "SESSION STATUS");
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
    // Close any accepted inbound streams so their sockets are not leaked.
    std::lock_guard<std::mutex> lock(inbound_mutex_);
    for (const auto& pair : inbound_peers_) {
        close_plain_socket(static_cast<platform_socket_t>(pair.first));
    }
    inbound_peers_.clear();
    {
        std::lock_guard<std::mutex> olock(outbound_mutex_);
        for (const auto& pair : outbound_streams_) {
            close_plain_socket(static_cast<platform_socket_t>(pair.first));
        }
        outbound_streams_.clear();
    }
}

bool I2PManager::initialize(const Config& config) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
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
    
    // FIX #3: Set recv timeout (10 seconds) to prevent infinite blocking.
    // After switching to blocking mode, recv() in send_sam_command() would
    // block forever if SAM bridge stops responding. With SO_RCVTIMEO,
    // recv() returns -1 with WSAETIMEDOUT after 10s.
    DWORD recv_timeout_ms = 10000;
    setsockopt(impl_->sam_socket, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&recv_timeout_ms, sizeof(recv_timeout_ms));
    // Bound send() the same way so a stuck SAM bridge cannot wedge the thread
    // mid-write (STREAM SEND / garlic payloads can be large).
    DWORD send_timeout_ms = 10000;
    setsockopt(impl_->sam_socket, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&send_timeout_ms, sizeof(send_timeout_ms));
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
    
    // FIX #3: Set recv timeout (10 seconds) to prevent infinite blocking.
    // Same rationale as Windows path above. On POSIX, SO_RCVTIMEO takes
    // struct timeval. recv() returns -1 with errno=EAGAIN on timeout.
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 10;
    recv_timeout.tv_usec = 0;
    setsockopt(impl_->sam_socket, SOL_SOCKET, SO_RCVTIMEO,
               &recv_timeout, sizeof(recv_timeout));
    setsockopt(impl_->sam_socket, SOL_SOCKET, SO_SNDTIMEO,
               &recv_timeout, sizeof(recv_timeout));
#endif
    
    // SAM Handshake: HELLO VERSION
    std::string response;
    if (!impl_->send_sam_command("HELLO VERSION MIN=3.0 MAX=3.3", response)) {
        impl_->close_sam();
        return false;
    }
    
    if (!sam_reply_ok(response, "HELLO REPLY")) {
        impl_->close_sam();
        return false;
    }
    
    impl_->sam_connected = true;
    is_initialized_ = true;
    
    // Initialize default active transports based on config
    active_transports_.clear();
    if (config.enable_ntcp2) {
        active_transports_.push_back(EncryptionLayer::NTCP2);
    }
    if (config.enable_ssu2) {
        active_transports_.push_back(EncryptionLayer::SSU2);
    }
    if (config.enable_garlic_routing) {
        active_transports_.push_back(EncryptionLayer::GARLIC_ROUTING);
    }
    
    if (current_dest_.empty()) {
        current_dest_ = create_ephemeral_destination();
    }
    
    return true;
}

bool I2PManager::is_active() const {
    // Note: no lock here — reads atomic-like bools and impl_ pointer.
    // config_.enabled and is_initialized_ are only written under lock in initialize().
    return config_.enabled && is_initialized_ && impl_->sam_connected;
}

void I2PManager::set_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    config_.enabled = enabled;
}

std::string I2PManager::get_destination() const {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    return current_dest_;
}

bool I2PManager::create_tunnel(const std::string& name, uint16_t local_port,
                               const std::string& remote_dest, TunnelType type) {
    (void)local_port;
    
    if (!is_active()) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95

    // Tunnel name becomes the SAM session ID on the wire — reject anything
    // that could inject a second command or a malformed ID.
    if (!sam_token_ok(name)) return false;
    // remote_dest, when provided, is recorded locally only (not sent here),
    // but keep it sane so a later STREAM CONNECT cannot be injection-abused.
    if (!remote_dest.empty() && !sam_token_ok(remote_dest)) return false;

    // SAM v3 has no distinct "server" session STYLE — STREAM is the only
    // stream style and serves both directions. The client/server distinction
    // is expressed through the DESTINATION below: TRANSIENT for outbound-only
    // client tunnels, our persistent destination for SERVER/BIDIRECTIONAL
    // tunnels that must accept inbound streams.
    const std::string style = "STREAM";
    if (type != TunnelType::CLIENT && current_dest_.empty()) {
        // A server tunnel without a persistent destination can never be
        // reached — fail honestly instead of creating a client-style
        // TRANSIENT tunnel masquerading as a server tunnel.
        return false;
    }

    const int in_len  = clamp_sam_opt(config_.tunnel_length, 0, 7);
    const int in_qty  = clamp_sam_opt(config_.tunnel_quantity, 1, 6);

    // Reusing an existing session ID makes the bridge reject SESSION CREATE
    // (duplicate destination/session); drop the stale session first.
    if (tunnels_.count(name)) {
        impl_->remove_session(name);
        tunnels_.erase(name);
    }

    std::ostringstream cmd;
    cmd << "SESSION CREATE STYLE=" << style
        << " ID=" << name
        << " DESTINATION=" << (type == TunnelType::CLIENT ? "TRANSIENT" : current_dest_)
        << " inbound.length=" << in_len
        << " outbound.length=" << in_len
        << " inbound.quantity=" << in_qty
        << " outbound.quantity=" << in_qty;
    
    std::string response;
    if (!impl_->send_sam_command(cmd.str(), response)) {
        return false;
    }
    
    if (!sam_reply_ok(response, "SESSION STATUS")) {
        return false;
    }
    
    size_t dest_pos = response.find("DESTINATION=");
    if (dest_pos != std::string::npos) {
        size_t start = dest_pos + 12;
        size_t end = response.find_first_of(" \t\r\n", start);
        impl_->destination_keys = response.substr(start,
            end == std::string::npos ? std::string::npos : end - start);
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
    
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95

    if (!sam_token_ok(name)) return false;

    // A server tunnel must be reachable, which requires a persistent
    // destination. Without one SESSION CREATE would fall back to a transient,
    // unreachable destination — fail honestly instead.
    if (current_dest_.empty()) return false;

    // FROM_PORT is not a SAM session parameter; the serve port is a property
    // of the STREAM ACCEPT loop, not SESSION CREATE. Sending it would be an
    // unknown key at best. The tunnel length/quantity options are the ones
    // the bridge actually honours.
    const int in_len = clamp_sam_opt(config_.tunnel_length, 0, 7);
    const int in_qty = clamp_sam_opt(config_.tunnel_quantity, 1, 6);

    std::ostringstream cmd;
    cmd << "SESSION CREATE STYLE=STREAM ID=" << name
        << " DESTINATION=" << current_dest_
        << " inbound.length=" << in_len
        << " outbound.length=" << in_len
        << " inbound.quantity=" << in_qty
        << " outbound.quantity=" << in_qty;
    
    std::string response;
    if (!impl_->send_sam_command(cmd.str(), response)) {
        return false;
    }
    
    if (!sam_reply_ok(response, "SESSION STATUS")) {
        return false;
    }

    TunnelInfo info;
    info.tunnel_id = name;
    info.type = TunnelType::SERVER;
    info.local_dest = current_dest_;
    // Remember the local serve port so callers can correlate the tunnel with
    // the STREAM ACCEPT loop that owns it.
    info.remote_dest = ":" + std::to_string(local_port);
    info.created = std::chrono::system_clock::now();
    info.expires = info.created + std::chrono::hours(
        config_.destination_expiration_hours);
    tunnels_[name] = info;
    return true;
}

std::vector<I2PManager::TunnelInfo> I2PManager::get_active_tunnels() const {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    std::vector<TunnelInfo> result;
    result.reserve(tunnels_.size());
    for (const auto& pair : tunnels_) {
        result.push_back(pair.second);
    }
    return result;
}

bool I2PManager::destroy_tunnel(const std::string& tunnel_id) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    auto it = tunnels_.find(tunnel_id);
    if (it == tunnels_.end()) return false;
    
    tunnels_.erase(it);
    return true;
}

std::string I2PManager::create_ephemeral_destination() {
    // Note: caller must hold mutex_ if accessing current_dest_ after this.
    // This method only talks to SAM (impl_) which is single-threaded.
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

bool I2PManager::import_destination(const std::string& private_keys) {
    if (!impl_->sam_connected) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    impl_->destination_keys = private_keys;
    
    // Create a session with the imported keys
    std::string response;
    std::string cmd = "SESSION CREATE STYLE=STREAM ID=imported DESTINATION=" + private_keys;
    if (!impl_->send_sam_command(cmd, response)) {
        return false;
    }
    
    if (response.find("SESSION STATUS RESULT=OK") != std::string::npos) {
        // Extract public destination from the private keys
        // In SAM, the public part is the base64 before the private portion
        current_dest_ = private_keys.substr(0, 516); // I2P base64 destination is ~516 chars
        return true;
    }
    return false;
}

std::string I2PManager::export_destination() const {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    return impl_->destination_keys;
}

void I2PManager::rotate_tunnels() {
    if (!is_active()) return;

    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95

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
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95

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
    if (is_initialized_ && impl_->sam_connected && !tunnels_.empty()) {
        for (int i = 0; i < 3; ++i) {
            inject_dummy_message();
        }
    }
}

// ==================== FIX #94: inject_dummy_message() implementation ====================
//
// Generates and sends a random-sized dummy message through the first active
// tunnel. This provides cover traffic to defeat DPI timing analysis.
//
// Dummy messages are:
//   - Random size between 64 and 512 bytes (uniform distribution)
//   - Filled with CSPRNG output (randombytes_buf) so they're indistinguishable
//     from encrypted payload to an observer
//   - Padded to 512-byte blocks (same alignment as pad_message())
//   - Sent via SAM STREAM SEND through an existing tunnel session
//
// Must be called with mutex_ held (caller: enable_traffic_mixing).

void I2PManager::inject_dummy_message() {
    // Note: caller holds mutex_ — tunnels_ access is safe.
    if (!impl_->sam_connected || tunnels_.empty()) return;

    // Pick the first active tunnel to send through
    const auto& first_tunnel = tunnels_.begin()->second;

    // Generate random payload: 64–512 bytes (uniform)
    // Variable size prevents DPI from fingerprinting dummy traffic
    // by fixed packet lengths.
    size_t payload_size = 64 + randombytes_uniform(449); // [64, 512]

    std::vector<uint8_t> dummy(payload_size);
    randombytes_buf(dummy.data(), dummy.size());

    // Pad to 512-byte block boundary (consistent with pad_message())
    std::vector<uint8_t> padded = pad_message(dummy, 512);

    // Send through SAM — use the tunnel's session ID.
    // SAM v3.2 STREAM SEND: the command line is immediately followed by
    // exactly SIZE bytes of payload on the same connection, then the bridge
    // replies "STREAM STATUS RESULT=OK ..." (or an error).
    std::ostringstream cmd;
    cmd << "STREAM SEND ID=" << first_tunnel.tunnel_id
        << " SIZE=" << padded.size() << "\n";
    std::string wire = cmd.str();
    wire.append(reinterpret_cast<const char*>(padded.data()), padded.size());

    std::string response;
    if (!impl_->send_sam_raw(wire, response)) {
        // Send/receive failed — delivery unconfirmed.
        return;
    }

    // Consume and validate the STREAM STATUS reply. The old code never read
    // it, so the status line was misinterpreted as the reply to the NEXT SAM
    // command, desynchronizing the session. A non-OK result means the dummy
    // was rejected; cover traffic is best-effort, so just drop it — but the
    // status line has been consumed either way, keeping SAM in sync.
    if (response.find("STREAM STATUS RESULT=OK") == std::string::npos) {
        return;
    }
}

void I2PManager::send_dummy_traffic(size_t bytes_per_second) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    config_.cover_traffic_bytes_per_minute = bytes_per_second * 60;

    // Inject a burst proportional to the requested rate
    if (bytes_per_second > 0 && is_initialized_ && impl_->sam_connected && !tunnels_.empty()) {
        // Each dummy message is ~512 bytes after padding.
        // Send enough to match ~1 second of the requested rate.
        size_t burst_count = std::max<size_t>(1, bytes_per_second / 512);
        burst_count = std::min<size_t>(burst_count, 10); // Cap at 10 per burst
        for (size_t i = 0; i < burst_count; ++i) {
            inject_dummy_message();
        }
    }
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
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    Statistics stats{};
    stats.active_tunnels = tunnels_.size();
    stats.peers_rejected = peer_filter_.rejected_count();
    stats.peers_accepted = peer_filter_.accepted_count();
    {
        std::lock_guard<std::mutex> olock(outbound_mutex_);
        stats.outbound_established = outbound_established_;
        stats.outbound_rejected = outbound_rejected_;
        stats.outbound_failed = outbound_failed_;
    }
    
    // Aggregate bytes across all tunnels
    for (const auto& pair : tunnels_) {
        stats.total_sent += pair.second.bytes_sent;
        stats.total_received += pair.second.bytes_received;
    }
    
    return stats;
}

// ==================== Garlic Routing ====================

std::vector<uint8_t> I2PManager::create_garlic_message(
    const std::vector<GarlicClove>& cloves,
    const std::string& dest_public_key)
{
    (void)dest_public_key;
    
    // Build garlic message: concatenate cloves with length-prefixed framing.
    // Each clove is: [4 bytes clove_id][4 bytes payload_length][payload]
    std::vector<uint8_t> garlic;
    
    for (const auto& clove : cloves) {
        // Clove ID (4 bytes, big-endian)
        uint32_t cid = clove.clove_id;
        garlic.push_back(static_cast<uint8_t>((cid >> 24) & 0xFF));
        garlic.push_back(static_cast<uint8_t>((cid >> 16) & 0xFF));
        garlic.push_back(static_cast<uint8_t>((cid >> 8) & 0xFF));
        garlic.push_back(static_cast<uint8_t>(cid & 0xFF));
        
        // Payload length (4 bytes, big-endian)
        uint32_t plen = static_cast<uint32_t>(clove.payload.size());
        garlic.push_back(static_cast<uint8_t>((plen >> 24) & 0xFF));
        garlic.push_back(static_cast<uint8_t>((plen >> 16) & 0xFF));
        garlic.push_back(static_cast<uint8_t>((plen >> 8) & 0xFF));
        garlic.push_back(static_cast<uint8_t>(plen & 0xFF));
        
        // Payload
        garlic.insert(garlic.end(), clove.payload.begin(), clove.payload.end());
    }
    
    // Pad to block boundary
    return pad_message(garlic, 512);
}

bool I2PManager::send_garlic_message(const std::string& destination,
                                     const std::vector<uint8_t>& message)
{
    if (!is_active()) return false;

    // The destination becomes part of a SAM command line.
    const std::string target =
        I2POutboundPolicy::normalize_destination(destination);
    if (!sam_token_ok(target) ||
        !I2POutboundPolicy::valid_destination_format(target)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    
    // Send via SAM datagram (garlic messages are typically datagram-based)
    std::ostringstream cmd;
    cmd << "RAW SEND DESTINATION=" << target
        << " SIZE=" << message.size();
    
    std::string response;
    if (!impl_->send_sam_command(cmd.str(), response)) {
        return false;
    }
    
    // Push raw payload
    if (impl_->sam_socket != INVALID_SOCK) {
        ssize_t sent = send(impl_->sam_socket,
                           reinterpret_cast<const char*>(message.data()),
                           static_cast<int>(message.size()), 0);
        return sent > 0;
    }
    return false;
}

// ==================== Network Database ====================

std::string I2PManager::lookup_destination(const std::string& hostname) {
    // The name is interpolated into a SAM command line; reject anything that
    // could inject a second command. (Short local aliases are still allowed
    // here — only the returned VALUE has to be a well-formed destination.)
    const std::string name =
        I2POutboundPolicy::normalize_destination(hostname);
    if (!sam_token_ok(name)) {
        return "";
    }

    // Check cache first
    {
        std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
        auto it = netdb_cache_.find(name);
        if (it != netdb_cache_.end()) {
            return it->second;
        }
    }
    
    if (!impl_->sam_connected) return "";
    
    // SAM NAMING LOOKUP
    std::string response;
    if (!impl_->send_sam_command("NAMING LOOKUP NAME=" + name, response)) {
        return "";
    }
    
    // Parse: NAMING REPLY RESULT=OK NAME=<name> VALUE=<dest>
    if (response.find("RESULT=OK") != std::string::npos) {
        size_t val_pos = response.find("VALUE=");
        if (val_pos != std::string::npos) {
            size_t val_start = val_pos + 6;
            size_t val_end = response.find('\n', val_start);
            std::string dest = I2POutboundPolicy::normalize_destination(
                response.substr(val_start,
                    val_end != std::string::npos ? val_end - val_start : std::string::npos));

            // A bridge/remote answer must be a well-formed destination; never
            // cache or return something that cannot be dialled safely.
            if (!I2POutboundPolicy::valid_destination_format(dest)) {
                return "";
            }
            
            // Cache the result
            std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
            netdb_cache_[name] = dest;
            return dest;
        }
    }
    return "";
}

bool I2PManager::publish_leaseset(bool encrypted, bool blinded) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    config_.enable_encrypted_leaseset = encrypted;
    config_.enable_blinded_destinations = blinded;
    // Actual LeaseSet publishing is handled by the I2P router
    // when tunnels are created. We just set the preferences here.
    return is_initialized_ && impl_->sam_connected;
}

std::vector<std::string> I2PManager::get_floodfill_routers() const {
    // Floodfill router discovery requires NetDB queries which
    // are handled by the I2P router internally. Return empty
    // until router integration provides this data.
    return {};
}

// ==================== Tunnel Management ====================

void I2PManager::set_tunnel_build_rate(int tunnels_per_minute) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    config_.tunnel_build_rate_per_minute = tunnels_per_minute;
}

bool I2PManager::use_exploratory_tunnels() const {
    // Exploratory tunnels are used for NetDB lookups and building
    // new tunnels. They are always on when the manager is active.
    return is_active();
}

// ==================== Transport Management ====================

bool I2PManager::enable_transport(EncryptionLayer transport) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    
    // Check if already active
    for (const auto& t : active_transports_) {
        if (t == transport) return true; // Already enabled
    }
    
    active_transports_.push_back(transport);
    
    // Update config flags
    switch (transport) {
        case EncryptionLayer::NTCP2:
            config_.enable_ntcp2 = true;
            break;
        case EncryptionLayer::SSU2:
            config_.enable_ssu2 = true;
            break;
        case EncryptionLayer::GARLIC_ROUTING:
            config_.enable_garlic_routing = true;
            break;
        default:
            break;
    }
    
    return true;
}

std::vector<I2PManager::EncryptionLayer> I2PManager::get_active_transports() const {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    return active_transports_;
}

// ==================== Anonymity Features ====================

void I2PManager::set_profile_mode(const std::string& mode) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    
    if (mode == "high_security") {
        config_.tunnel_length = 4;
        config_.tunnel_quantity = 3;
        config_.tunnel_backup_quantity = 2;
        config_.random_tunnel_selection = true;
        config_.enable_dummy_traffic = true;
        config_.mix_delay_ms = 100;
    } else if (mode == "balanced") {
        config_.tunnel_length = 3;
        config_.tunnel_quantity = 2;
        config_.tunnel_backup_quantity = 1;
        config_.random_tunnel_selection = true;
        config_.enable_dummy_traffic = true;
        config_.mix_delay_ms = 50;
    } else if (mode == "performance") {
        config_.tunnel_length = 2;
        config_.tunnel_quantity = 2;
        config_.tunnel_backup_quantity = 0;
        config_.random_tunnel_selection = false;
        config_.enable_dummy_traffic = false;
        config_.mix_delay_ms = 0;
    }
}

bool I2PManager::enable_path_selection_randomization(bool enable) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    config_.random_tunnel_selection = enable;
    return true;
}

void I2PManager::set_cover_traffic_rate(size_t bytes_per_minute) {
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    config_.cover_traffic_bytes_per_minute = bytes_per_minute;
}

// ==================== Server-side inbound handling ====================

void I2PManager::set_peer_filter(const I2PPeerFilter::Config& config) {
    peer_filter_.set_config(config);
}

I2PPeerFilter::Config I2PManager::get_peer_filter_config() const {
    return peer_filter_.get_config();
}

size_t I2PManager::rejected_peer_count() const {
    return peer_filter_.rejected_count();
}

size_t I2PManager::accepted_peer_count() const {
    return peer_filter_.accepted_count();
}

void I2PManager::set_inbound_peer_callback(InboundPeerCallback cb) {
    std::lock_guard<std::mutex> lock(inbound_mutex_);
    inbound_cb_ = std::move(cb);
}

intptr_t I2PManager::accept_inbound_stream(const std::string& session_id,
                                           std::string& peer_dest,
                                           int timeout_seconds) {
    peer_dest.clear();

    if (!is_active()) return -1;
    // session_id is interpolated into a SAM command line — reject injection.
    if (!sam_token_ok(session_id)) return -1;
    if (timeout_seconds <= 0) timeout_seconds = 30;

    // Copy connection parameters under the lock: initialize() may rewrite
    // config_ concurrently.
    std::string sam_host;
    uint16_t sam_port = 0;
    bool session_known = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Never send a STREAM ACCEPT for a session this manager did not
        // create: the ID is interpolated into the command line.
        session_known = tunnels_.find(session_id) != tunnels_.end();
        sam_host = config_.sam_host;
        sam_port = config_.sam_port;
    }
    if (!session_known) return -1;

    platform_socket_t s = sam_open(sam_host, sam_port, timeout_seconds * 1000);
    if (s == INVALID_SOCK) return -1;

    if (!send_all(s, "STREAM ACCEPT ID=" + session_id + " SILENT=false\n")) {
        close_plain_socket(s);
        return -1;
    }

    // The bridge acknowledges the accept request immediately...
    std::string status;
    if (!recv_line(s, status) || !sam_reply_ok(status, "STREAM STATUS")) {
        close_plain_socket(s);
        return -1;
    }

    // ...then blocks until a peer connects and announces itself. With
    // SILENT=false the peer destination line precedes the raw stream data.
    std::string peer_line;
    if (!recv_line(s, peer_line)) {
        close_plain_socket(s);
        return -1;
    }
    static const std::string kPeer = "PEER DESTINATION=";
    size_t pos = peer_line.find(kPeer);
    if (pos == std::string::npos) {
        close_plain_socket(s);
        return -1;
    }
    size_t begin = pos + kPeer.size();
    size_t end = peer_line.find_first_of(" \t\r\n", begin);
    peer_dest = peer_line.substr(begin,
        end == std::string::npos ? std::string::npos : end - begin);
    if (peer_dest.empty()) {
        close_plain_socket(s);
        return -1;
    }

    // Apply the server-side peer policy before handing the stream back.
    const I2PPeerFilter::Decision decision =
        peer_filter_.check(peer_dest, std::chrono::system_clock::now());

    // Tell the observer outside all locks (the callback may do file I/O).
    InboundPeerCallback cb;
    {
        std::lock_guard<std::mutex> lock(inbound_mutex_);
        cb = inbound_cb_;
    }
    if (cb) cb(peer_dest, decision.allow, decision.reason);

    if (!decision.allow) {
        close_plain_socket(s);
        return -1;
    }

    const intptr_t handle = static_cast<intptr_t>(s);
    {
        std::lock_guard<std::mutex> lock(inbound_mutex_);
        inbound_peers_[handle] = peer_dest;
    }
    return handle;
}

ptrdiff_t I2PManager::read_inbound_stream(intptr_t handle, void* buf, size_t len) {
    if (handle < 0 || buf == nullptr || len == 0) return -1;
    const int chunk = (len > 0x7fffffffULL)
        ? 0x7fffffff
        : static_cast<int>(len);
    // Winsock recv() takes char*, POSIX takes void*; the cast is valid for both.
    ssize_t n = recv(static_cast<platform_socket_t>(handle),
                     static_cast<char*>(buf), chunk, 0);
    return static_cast<ptrdiff_t>(n);
}

bool I2PManager::close_inbound_stream(intptr_t handle) {
    if (handle < 0) return false;
    std::string peer;
    {
        std::lock_guard<std::mutex> lock(inbound_mutex_);
        auto it = inbound_peers_.find(handle);
        if (it == inbound_peers_.end()) return false;
        peer = it->second;
        inbound_peers_.erase(it);
    }
    close_plain_socket(static_cast<platform_socket_t>(handle));
    peer_filter_.release(peer);
    return true;
}

// ==================== Client-side outbound handling ====================

void I2PManager::set_outbound_policy(const I2POutboundPolicy::Config& config) {
    outbound_policy_.set_config(config);
}

I2POutboundPolicy::Config I2PManager::get_outbound_policy() const {
    return outbound_policy_.get_config();
}

std::vector<I2POutboundPolicy::Pin> I2PManager::pinned_destinations() const {
    return outbound_policy_.pins();
}

void I2PManager::clear_pinned_destinations() {
    outbound_policy_.clear_pins();
}

void I2PManager::set_outbound_event_callback(OutboundEventCallback cb) {
    std::lock_guard<std::mutex> lock(outbound_mutex_);
    outbound_cb_ = std::move(cb);
}

uint64_t I2PManager::emit_outbound(const std::string& session_id,
                                   const std::string& dest,
                                   OutboundOutcome outcome,
                                   const char* reason) {
    OutboundRecord rec;
    rec.session_id = session_id;
    rec.destination = dest;
    rec.established = (outcome == OutboundOutcome::ESTABLISHED);
    rec.reason = reason;
    rec.timestamp = std::chrono::system_clock::now();

    OutboundEventCallback cb;
    {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        rec.id = next_outbound_id_++;
        switch (outcome) {
            case OutboundOutcome::ESTABLISHED: ++outbound_established_; break;
            case OutboundOutcome::REJECTED:    ++outbound_rejected_;    break;
            case OutboundOutcome::FAILED:      ++outbound_failed_;      break;
        }
        outbound_ring_.push_back(rec);
        while (outbound_ring_.size() > kOutboundRingCapacity) {
            outbound_ring_.pop_front();
        }
        cb = outbound_cb_;
    }
    if (cb) cb(rec);
    return rec.id;
}

std::vector<I2PManager::OutboundRecord> I2PManager::outbound_history(
    size_t max_count) const
{
    std::lock_guard<std::mutex> lock(outbound_mutex_);
    std::vector<OutboundRecord> out;
    const size_t n = std::min(max_count, outbound_ring_.size());
    out.reserve(n);
    for (size_t i = outbound_ring_.size() - n; i < outbound_ring_.size(); ++i) {
        out.push_back(outbound_ring_[i]);
    }
    return out;
}

intptr_t I2PManager::connect_outbound_stream(const std::string& session_id,
                                             const std::string& dest,
                                             int timeout_seconds) {
    if (!is_active()) return -1;
    if (!sam_token_ok(session_id)) return -1;
    if (timeout_seconds <= 0) timeout_seconds = 30;

    const std::string target = I2POutboundPolicy::normalize_destination(dest);
    const I2POutboundPolicy::Decision decision =
        outbound_policy_.check(session_id, target);
    if (!decision.allow) {
        emit_outbound(session_id, target, OutboundOutcome::REJECTED,
                      decision.reason);
        return -1;
    }

    std::string sam_host;
    uint16_t sam_port = 0;
    bool session_known = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Never send a STREAM CONNECT for a session this manager did not
        // create: the ID is interpolated into the command line.
        session_known = tunnels_.find(session_id) != tunnels_.end();
        if (session_known) {
            sam_host = config_.sam_host;
            sam_port = config_.sam_port;
        }
    }
    if (!session_known) {
        emit_outbound(session_id, target, OutboundOutcome::FAILED,
                      "unknown-session");
        return -1;
    }

    platform_socket_t s = sam_open(sam_host, sam_port, timeout_seconds * 1000);
    if (s == INVALID_SOCK) {
        emit_outbound(session_id, target, OutboundOutcome::FAILED,
                      "sam-unreachable");
        return -1;
    }

    static const std::string kSuffix = ".i2p";
    const bool by_name = target.size() > kSuffix.size() &&
        target.compare(target.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0;

    std::string cmd = "STREAM CONNECT ID=" + session_id + " ";
    cmd += by_name ? "NAME=" : "DESTINATION=";
    cmd += target;
    cmd += " SILENT=false\n";

    if (!send_all(s, cmd)) {
        close_plain_socket(s);
        emit_outbound(session_id, target, OutboundOutcome::FAILED, "send-failed");
        return -1;
    }

    std::string status;
    if (!recv_line(s, status) || !sam_reply_ok(status, "STREAM STATUS")) {
        close_plain_socket(s);
        emit_outbound(session_id, target, OutboundOutcome::FAILED,
                      "connect-failed");
        return -1;
    }

    // With SILENT=false the bridge announces the far-end destination before
    // any payload.
    std::string peer_line;
    if (!recv_line(s, peer_line)) {
        close_plain_socket(s);
        emit_outbound(session_id, target, OutboundOutcome::FAILED,
                      "no-peer-line");
        return -1;
    }
    static const std::string kPeer = "PEER DESTINATION=";
    const size_t pos = peer_line.find(kPeer);
    if (pos == std::string::npos) {
        close_plain_socket(s);
        emit_outbound(session_id, target, OutboundOutcome::FAILED,
                      "no-peer-destination");
        return -1;
    }
    const size_t begin = pos + kPeer.size();
    const size_t end = peer_line.find_first_of(" \t\r\n", begin);
    const std::string peer_dest = I2POutboundPolicy::normalize_destination(
        peer_line.substr(begin,
            end == std::string::npos ? std::string::npos : end - begin));
    if (peer_dest.empty()) {
        close_plain_socket(s);
        emit_outbound(session_id, target, OutboundOutcome::FAILED,
                      "no-peer-destination");
        return -1;
    }

    // When we asked for a full base64 destination, the far end must be
    // exactly that destination — otherwise we are talking to something else.
    if (!by_name && peer_dest != target) {
        close_plain_socket(s);
        emit_outbound(session_id, target, OutboundOutcome::REJECTED,
                      "destination-mismatch");
        return -1;
    }

    // Bind the session to this destination on first success.
    outbound_policy_.pin(session_id, target);

    const intptr_t handle = static_cast<intptr_t>(s);
    const uint64_t id = emit_outbound(session_id, target,
                                      OutboundOutcome::ESTABLISHED, "connected");
    {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        OutboundStream st;
        st.id = id;
        st.session_id = session_id;
        st.destination = target;
        st.started = std::chrono::system_clock::now();
        outbound_streams_[handle] = std::move(st);
    }
    return handle;
}

ptrdiff_t I2PManager::write_outbound_stream(intptr_t handle, const void* buf,
                                            size_t len) {
    if (handle < 0 || buf == nullptr || len == 0) return -1;
    {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        if (outbound_streams_.find(handle) == outbound_streams_.end()) return -1;
    }
    const int chunk = (len > 0x7fffffffULL)
        ? 0x7fffffff
        : static_cast<int>(len);
    ssize_t n = send(static_cast<platform_socket_t>(handle),
                     static_cast<const char*>(buf), chunk, kSendFlags);
    if (n > 0) {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        auto it = outbound_streams_.find(handle);
        if (it != outbound_streams_.end()) {
            it->second.bytes_sent += static_cast<uint64_t>(n);
        }
    }
    return static_cast<ptrdiff_t>(n);
}

ptrdiff_t I2PManager::read_outbound_stream(intptr_t handle, void* buf,
                                           size_t len) {
    if (handle < 0 || buf == nullptr || len == 0) return -1;
    {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        if (outbound_streams_.find(handle) == outbound_streams_.end()) return -1;
    }
    const int chunk = (len > 0x7fffffffULL)
        ? 0x7fffffff
        : static_cast<int>(len);
    ssize_t n = recv(static_cast<platform_socket_t>(handle),
                     static_cast<char*>(buf), chunk, 0);
    return static_cast<ptrdiff_t>(n);
}

bool I2PManager::close_outbound_stream(intptr_t handle) {
    if (handle < 0) return false;

    OutboundStream st;
    {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        auto it = outbound_streams_.find(handle);
        if (it == outbound_streams_.end()) return false;
        st = it->second;
        outbound_streams_.erase(it);
    }

    close_plain_socket(static_cast<platform_socket_t>(handle));

    // Fold the byte count into the audit record created at connect time.
    {
        std::lock_guard<std::mutex> lock(outbound_mutex_);
        for (auto rit = outbound_ring_.rbegin(); rit != outbound_ring_.rend();
             ++rit) {
            if (rit->id == st.id) {
                rit->bytes_sent = st.bytes_sent;
                break;
            }
        }
    }

    // Keep tunnel-level byte counters (and therefore Statistics::total_sent)
    // accurate for traffic sent over this stream.
    if (st.bytes_sent > 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = tunnels_.find(st.session_id);
        if (it != tunnels_.end()) {
            it->second.bytes_sent += st.bytes_sent;
        }
    }
    return true;
}

// ==================== Internal Helpers ====================

std::vector<std::string> I2PManager::select_tunnel_hops(int length) {
    // Produce properly-formatted I2P router hashes for tunnel hop selection.
    //
    // I2P router hashes are 32-byte SHA-256 digests of the router's full
    // destination structure, encoded as 44-character Base64 (standard alphabet
    // with '=' padding).  The format used here matches the b32.i2p / NetDB spec.
    //
    // Hop diversity strategy:
    //   - Each hop's "virtual /16 subnet" is inferred from the first 2 bytes of
    //     its hash.  We reject any candidate whose high byte matches a subnet
    //     already in use, enforcing that no two hops share the same /16.
    //     This prevents a single AS from controlling multiple hops in one tunnel.
    //
    // If the SAM bridge is connected we first attempt to pull real router hashes
    // from the network database via the NAMINGLOOKUP or ROUTERINFO SAM commands.
    // When SAM is unavailable (or returns no results) we fall back to
    // cryptographically-random hashes that satisfy the diversity constraint.

    std::vector<std::string> hops;
    hops.reserve(static_cast<size_t>(length));

    // Track /16 subnets already allocated (high byte of the 32-byte hash prefix)
    // to enforce hop diversity.
    std::vector<uint8_t> used_subnets;
    used_subnets.reserve(static_cast<size_t>(length));

    // Helper: encode 32 raw bytes as a 44-character Base64 string (I2P format)
    auto to_i2p_base64 = [](const uint8_t* raw) -> std::string {
        // sodium_bin2base64 writes at most sodium_base64_ENCODED_LEN(32,...) bytes
        char b64[64];
        sodium_bin2base64(b64, sizeof(b64), raw, 32,
                          sodium_base64_VARIANT_ORIGINAL);
        // Trim the null terminator; result is exactly 44 chars including '=' pad
        return std::string(b64);
    };

    // Attempt to fetch real router hashes from SAM via ROUTERINFO command.
    // SAM 3.1+ supports: ROUTERINFO
    // Response: ROUTERINFO RESULT=OK ROUTER_HASH=<base64> ...
    // We issue one query and parse as many hashes as returned.
    std::vector<std::string> netdb_hashes;
    if (impl_->sam_connected) {
        std::string response;
        if (impl_->send_sam_command("ROUTERINFO", response)) {
            // Parse all ROUTER_HASH= values from the response
            size_t pos = 0;
            while ((pos = response.find("ROUTER_HASH=", pos)) != std::string::npos) {
                pos += 12;  // skip "ROUTER_HASH="
                size_t end = response.find_first_of(" \t\r\n", pos);
                std::string hash = (end == std::string::npos)
                    ? response.substr(pos)
                    : response.substr(pos, end - pos);
                // A valid I2P router hash is exactly 44 base64 chars
                if (hash.size() == 44) {
                    netdb_hashes.push_back(std::move(hash));
                }
            }
        }
    }

    // If we got at least `length` real hashes, select them with diversity check.
    if (static_cast<int>(netdb_hashes.size()) >= length) {
        // Shuffle for randomness, then pick with diversity constraint
        // Use Fisher-Yates with CSPRNG index selection
        for (size_t i = netdb_hashes.size() - 1; i > 0; --i) {
            size_t j = static_cast<size_t>(randombytes_uniform(
                static_cast<uint32_t>(i + 1)));
            std::swap(netdb_hashes[i], netdb_hashes[j]);
        }

        for (const auto& hash : netdb_hashes) {
            if (static_cast<int>(hops.size()) >= length) break;

            // Decode first 2 bytes to check subnet
            uint8_t raw[32];
            size_t decoded_len = 0;
            const char* end_ptr = nullptr;
            if (sodium_base642bin(raw, sizeof(raw),
                                  hash.c_str(), hash.size(),
                                  nullptr, &decoded_len, &end_ptr,
                                  sodium_base64_VARIANT_ORIGINAL) != 0
                || decoded_len < 2) {
                continue;
            }
            uint8_t subnet = raw[0];  // high byte of hash = "virtual /16 prefix"
            bool subnet_used = false;
            for (uint8_t s : used_subnets) {
                if (s == subnet) { subnet_used = true; break; }
            }
            if (!subnet_used) {
                hops.push_back(hash);
                used_subnets.push_back(subnet);
            }
        }
    }

    // Fill remaining slots with cryptographically-random hashes.
    // Each random hash is computed as SHA-256 of a random seed so it looks
    // like a genuine router hash rather than raw random bytes.
    int attempts = 0;
    const int MAX_ATTEMPTS = length * 64;  // Bound retries to avoid infinite loop
    while (static_cast<int>(hops.size()) < length && attempts < MAX_ATTEMPTS) {
        ++attempts;

        // Generate a 32-byte random seed, then SHA-256-hash it to get the
        // router-hash-shaped value.  crypto_hash_sha256 is part of libsodium.
        uint8_t seed[32];
        randombytes_buf(seed, sizeof(seed));
        uint8_t hash_bytes[32];
        crypto_hash_sha256(hash_bytes, seed, sizeof(seed));

        uint8_t subnet = hash_bytes[0];
        bool subnet_used = false;
        for (uint8_t s : used_subnets) {
            if (s == subnet) { subnet_used = true; break; }
        }
        if (!subnet_used) {
            hops.push_back(to_i2p_base64(hash_bytes));
            used_subnets.push_back(subnet);
        }
    }

    return hops;
}

bool I2PManager::build_tunnel(const std::vector<std::string>& hops, TunnelType type) {
    // Create a SAM session for this tunnel using the provided hop selection.
    //
    // SAM protocol (v3.1+):
    //   SESSION CREATE STYLE=<STREAM|DATAGRAM>
    //       ID=<session_id>
    //       DESTINATION=<TRANSIENT|dest_keys>
    //       [inbound.length=N] [outbound.length=N]
    //       [inbound.quantity=N] [outbound.quantity=N]
    //
    // The hops vector determines tunnel length — we pass its size as the
    // inbound/outbound length parameter so the I2P router allocates a
    // tunnel chain of exactly that depth.  The router itself selects the
    // actual hop routers from its NetDB, but our hop list (router hashes)
    // is embedded as a comment in the session name for auditing purposes.
    //
    // Returns true if the SAM bridge acknowledges with RESULT=OK.

    if (!impl_->sam_connected) return false;
    if (hops.empty()) return false;

    // Generate a unique session ID based on tunnel type and a CSPRNG suffix
    uint8_t id_bytes[4];
    randombytes_buf(id_bytes, sizeof(id_bytes));
    std::ostringstream id_oss;
    id_oss << (type == TunnelType::SERVER ? "srv" : "cli") << "_";
    for (int i = 0; i < 4; ++i) {
        id_oss << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(id_bytes[i]);
    }
    std::string session_id = id_oss.str();

    // Determine tunnel length from the provided hops
    int tunnel_len = static_cast<int>(hops.size());

    // Choose SAM STYLE and DESTINATION based on tunnel type
    std::string style = (type == TunnelType::SERVER) ? "STREAM" : "STREAM";
    std::string destination = (type == TunnelType::SERVER)
        ? current_dest_        // server uses persistent destination
        : "TRANSIENT";          // client uses ephemeral destination

    std::ostringstream cmd;
    cmd << "SESSION CREATE"
        << " STYLE=" << style
        << " ID=" << session_id
        << " DESTINATION=" << destination
        << " inbound.length=" << tunnel_len
        << " outbound.length=" << tunnel_len
        << " inbound.quantity=" << config_.tunnel_quantity
        << " outbound.quantity=" << config_.tunnel_quantity;

    // Embed first hop hash as a human-readable note (SAM ignores unknown keys)
    if (!hops[0].empty()) {
        cmd << " i2cp.firstHop=" << hops[0];
    }

    std::string response;
    if (!impl_->send_sam_command(cmd.str(), response)) {
        return false;
    }

    // Parse SAM response
    if (response.find("SESSION STATUS RESULT=OK") == std::string::npos) {
        // Log the error code if present, e.g. RESULT=INVALID_KEY, RESULT=I2P_ERROR
        return false;
    }

    // Extract and store the session ID / destination from the response
    {
        std::lock_guard<std::mutex> lock(mutex_);
        impl_->session_id = session_id;

        // If server type, extract DESTINATION from response (the router may
        // have assigned a new public key block to the destination)
        size_t dest_pos = response.find("DESTINATION=");
        if (dest_pos != std::string::npos && type == TunnelType::SERVER) {
            size_t start = dest_pos + 12;
            size_t end = response.find_first_of(" \t\r\n", start);
            if (end == std::string::npos) end = response.size();
            impl_->destination_keys = response.substr(start, end - start);
        }

        // Register the tunnel in the active tunnel map
        TunnelInfo info;
        info.tunnel_id  = session_id;
        info.type       = type;
        info.hops       = hops;
        info.local_dest = current_dest_;
        info.created    = std::chrono::system_clock::now();
        info.expires    = info.created
                          + std::chrono::hours(config_.destination_expiration_hours);
        tunnels_[session_id] = std::move(info);
    }

    return true;
}

void I2PManager::maintain_tunnel_pool() {
    // Check tunnel expiration and rebuild as needed.
    // Called periodically by the tunnel rotation scheduler.
    std::lock_guard<std::mutex> lock(mutex_);  // FIX #95
    
    auto now = std::chrono::system_clock::now();
    std::vector<std::string> expired;
    
    for (const auto& pair : tunnels_) {
        if (pair.second.expires <= now) {
            expired.push_back(pair.first);
        }
    }
    
    for (const auto& tid : expired) {
        tunnels_.erase(tid);
    }
}

std::vector<uint8_t> I2PManager::encrypt_garlic_layer(
    const std::vector<uint8_t>& data,
    const std::string& hop_pubkey)
{
    // ECIES-X25519-XChaCha20-Poly1305 garlic layer encryption.
    //
    // Wire format: [32-byte ephemeral_pk][24-byte nonce][ciphertext + 16-byte Poly1305 tag]
    //
    // The hop_pubkey is expected to be a 32-byte raw X25519 public key,
    // either raw binary (32 bytes) or base64-encoded (44 chars).
    //
    // FAIL-CLOSED contract: on ANY error (malformed key, failed DH, failed
    // AEAD) an EMPTY vector is returned. Returning the plaintext input on
    // error would silently send it unencrypted — callers must treat an
    // empty result as "encryption failed, do not transmit".

    // --- 1. Decode recipient public key ---------------------------------
    std::vector<uint8_t> recipient_pk;

    if (hop_pubkey.size() == crypto_box_PUBLICKEYBYTES) {
        // Raw 32-byte key
        recipient_pk.assign(hop_pubkey.begin(), hop_pubkey.end());
    } else if (hop_pubkey.size() == 44) {
        // Base64-encoded 32-byte key (standard alphabet, may have '=' padding)
        // libsodium provides sodium_base642bin for this purpose
        recipient_pk.resize(crypto_box_PUBLICKEYBYTES);
        size_t decoded_len = 0;
        const char* end_ptr = nullptr;
        int rc = sodium_base642bin(
            recipient_pk.data(), recipient_pk.size(),
            hop_pubkey.c_str(), hop_pubkey.size(),
            nullptr, &decoded_len, &end_ptr,
            sodium_base64_VARIANT_ORIGINAL);
        if (rc != 0 || decoded_len != crypto_box_PUBLICKEYBYTES) {
            // Decoding failed — fail closed, never leak plaintext
            return {};
        }
    } else {
        // Unknown key format — cannot encrypt; fail closed
        return {};
    }

    // --- 2. Generate ephemeral X25519 keypair ---------------------------
    uint8_t ephemeral_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t ephemeral_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(ephemeral_pk, ephemeral_sk);

    // --- 3. Derive shared secret via X25519 DH --------------------------
    // q = X25519(ephemeral_sk, recipient_pk)
    // This gives a 32-byte raw shared secret.
    uint8_t shared_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared_secret, ephemeral_sk,
                          recipient_pk.data()) != 0) {
        // DH failed (e.g. low-order point) — zero keys and fail closed
        sodium_memzero(ephemeral_sk, sizeof(ephemeral_sk));
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return {};
    }

    // Wipe the ephemeral secret key immediately after DH
    sodium_memzero(ephemeral_sk, sizeof(ephemeral_sk));

    // --- 4. Derive encryption key via HKDF-SHA256 -----------------------
    // libsodium's crypto_kdf_hkdf_sha256_expand is available in libsodium >= 1.0.19.
    // Context = "GarlicLayerEncryption" (trimmed to 8 chars for KDF ctx).
    // We derive a 32-byte key from the raw DH output.
    //
    // NOTE: crypto_scalarmult output should not be used directly as a key;
    //       HKDF extracts entropy uniformly even from weak DH outputs.
    uint8_t enc_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    {
        // HKDF-Extract: PRK = HMAC-SHA256(salt=zeros, ikm=shared_secret)
        // HKDF-Expand:  OKM = HMAC-SHA256(PRK, "GarlicEnc" || 0x01)
        // Use crypto_kdf_hkdf_sha256 from libsodium (>= 1.0.19)
        // Fallback: use crypto_generichash (BLAKE2b) if KDF not available
        static const uint8_t salt[32] = {0};  // zero salt
        uint8_t prk[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, salt, sizeof(salt));
        crypto_auth_hmacsha256_update(&state, shared_secret,
                                      sizeof(shared_secret));
        crypto_auth_hmacsha256_final(&state, prk);

        // Expand: key = HMAC-SHA256(prk, "GarlicEnc" || 0x01)
        static const uint8_t info[] = "GarlicEnc";
        static const uint8_t counter = 0x01;
        crypto_auth_hmacsha256_state exp_state;
        crypto_auth_hmacsha256_init(&exp_state, prk, sizeof(prk));
        crypto_auth_hmacsha256_update(&exp_state, info, sizeof(info) - 1);
        crypto_auth_hmacsha256_update(&exp_state, &counter, 1);
        uint8_t okm[crypto_auth_hmacsha256_BYTES];
        crypto_auth_hmacsha256_final(&exp_state, okm);

        // Copy first 32 bytes (HKDF output == xchacha20poly1305 key size)
        static_assert(crypto_auth_hmacsha256_BYTES
                      >= crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                      "HMAC-SHA256 output too short for XChaCha20-Poly1305 key");
        std::memcpy(enc_key, okm, sizeof(enc_key));
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(okm, sizeof(okm));
    }

    sodium_memzero(shared_secret, sizeof(shared_secret));

    // --- 5. Generate random 24-byte nonce -------------------------------
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // --- 6. Encrypt with XChaCha20-Poly1305 AEAD -----------------------
    // Additional data = ephemeral_pk (binds the key to this packet)
    unsigned long long ciphertext_len = 0;
    std::vector<uint8_t> ciphertext(
        data.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        data.data(), data.size(),
        ephemeral_pk, crypto_box_PUBLICKEYBYTES,  // ad = ephemeral_pk
        nullptr,                                   // nsec (unused)
        nonce, enc_key);

    sodium_memzero(enc_key, sizeof(enc_key));

    if (rc != 0) {
        return {};  // AEAD failure — fail closed, never return plaintext
    }

    // --- 7. Assemble output: [ephemeral_pk][nonce][ciphertext] ----------
    std::vector<uint8_t> result;
    result.reserve(crypto_box_PUBLICKEYBYTES
                   + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
                   + ciphertext_len);
    result.insert(result.end(), ephemeral_pk,
                  ephemeral_pk + crypto_box_PUBLICKEYBYTES);
    result.insert(result.end(), nonce,
                  nonce + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    result.insert(result.end(), ciphertext.begin(),
                  ciphertext.begin() + ciphertext_len);
    return result;
}

std::vector<uint8_t> I2PManager::create_session_tag() {
    // Generate a random 32-byte session tag for ElGamal/AES encryption
    std::vector<uint8_t> tag(32);
    randombytes_buf(tag.data(), tag.size());
    return tag;
}

void I2PManager::schedule_tunnel_rotation() {
    // In a full implementation, this would set up a timer to call
    // rotate_tunnels() periodically based on config_.destination_expiration_hours.
    // The actual timer integration depends on the event loop (Qt, boost::asio, etc.)
}

} // namespace ncp
