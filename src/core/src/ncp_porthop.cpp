/**
 * @file ncp_porthop.cpp
 * @brief M2 — QUIC/UDP Port-Hopping transport (see ncp_porthop.hpp)
 */

#include "ncp_porthop.hpp"
#include "ncp_logger.hpp"

#include <algorithm>
#include <cstring>
#include <sodium.h>

#ifndef _WIN32
# include <arpa/inet.h>
# include <errno.h>
# include <fcntl.h>
# include <netinet/in.h>
# include <sys/select.h>
# include <sys/socket.h>
# include <unistd.h>
#endif

namespace ncp {

namespace {

constexpr uint8_t kMagic0 = 'P';
constexpr uint8_t kMagic1 = 'H';
constexpr uint8_t kVersion = 1;
constexpr size_t kMaxDatagram = 65535;

void store_u32_be(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

uint32_t load_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

void store_u64_be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = static_cast<uint8_t>(v >> ((7 - i) * 8));
}

uint64_t load_u64_be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | p[i];
    return v;
}

#ifndef _WIN32
bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::string addr_to_ip(const struct sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf)))
        return {};
    return buf;
}
#endif

} // namespace

// ==================== HopSchedule ====================

HopSchedule::HopSchedule(std::vector<uint8_t> secret,
                         uint16_t base_port,
                         uint16_t port_range,
                         uint32_t interval_sec)
    : secret_(std::move(secret)),
      base_port_(base_port),
      port_range_(port_range == 0 ? 1 : port_range),
      interval_sec_(interval_sec) {}

uint16_t HopSchedule::port_for_epoch(uint32_t epoch) const {
    // port(epoch) = base + (HMAC-SHA256(secret, epoch_u64_BE)[0..2] % range)
    uint8_t msg[8];
    store_u64_be(msg, static_cast<uint64_t>(epoch));

    uint8_t mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, secret_.data(), secret_.size());
    crypto_auth_hmacsha256_update(&st, msg, sizeof(msg));
    crypto_auth_hmacsha256_final(&st, mac);

    uint32_t v = (static_cast<uint32_t>(mac[0]) << 16) |
                 (static_cast<uint32_t>(mac[1]) << 8)  |
                 static_cast<uint32_t>(mac[2]);
    return static_cast<uint16_t>(base_port_ + (v % port_range_));
}

// ==================== PortHopSession ====================

PortHopSession::PortHopSession(uint64_t session_id, HopSchedule schedule)
    : session_id_(session_id),
      schedule_(std::move(schedule)),
      epoch_start_(std::chrono::steady_clock::now()) {}

std::vector<uint8_t> PortHopSession::encode(const uint8_t* payload,
                                            size_t payload_len,
                                            uint8_t flags) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<uint8_t> out(HEADER_SIZE + payload_len);
    out[0] = kMagic0;
    out[1] = kMagic1;
    out[2] = kVersion;
    store_u64_be(out.data() + 3, session_id_);
    store_u32_be(out.data() + 11, epoch_);
    uint32_t seq = next_seq_++;
    store_u32_be(out.data() + 15, seq);
    out[19] = flags;
    if (payload_len > 0 && payload)
        std::memcpy(out.data() + HEADER_SIZE, payload, payload_len);

    if (flags & PH_FLAG_ACK_REQUEST)
        unacked_.push_back(seq);

    return out;
}

std::optional<PortHopFrame> PortHopSession::decode_raw(const uint8_t* data,
                                                       size_t len) {
    if (!data || len < HEADER_SIZE)
        return std::nullopt;
    if (data[0] != kMagic0 || data[1] != kMagic1 || data[2] != kVersion)
        return std::nullopt;

    PortHopFrame f;
    f.session_id = load_u64_be(data + 3);
    f.epoch = load_u32_be(data + 11);
    f.seq = load_u32_be(data + 15);
    f.flags = data[19];
    f.payload.assign(data + HEADER_SIZE, data + len);
    return f;
}

std::optional<PortHopFrame> PortHopSession::decode(const uint8_t* data,
                                                   size_t len) {
    auto raw = decode_raw(data, len);
    if (!raw)
        return std::nullopt;

    std::lock_guard<std::mutex> lock(mutex_);
    if (raw->session_id != session_id_)
        return std::nullopt;

    // ACK frame: seq echoes the acknowledged sequence number.
    if (raw->flags & PH_FLAG_ACK) {
        if (raw->seq > last_ack_seq_ || last_ack_seq_ == 0)
            last_ack_seq_ = raw->seq;
        unacked_.erase(
            std::remove_if(unacked_.begin(), unacked_.end(),
                           [&](uint32_t s) { return s <= raw->seq; }),
            unacked_.end());
    }

    // HOP_NOTIFY: peer announces its next epoch in the payload (u32 BE).
    if ((raw->flags & PH_FLAG_HOP_NOTIFY) && raw->payload.size() >= 4) {
        uint32_t next_epoch = load_u32_be(raw->payload.data());
        if (next_epoch > epoch_) {
            epoch_ = next_epoch;
            epoch_start_ = std::chrono::steady_clock::now();
            unacked_.clear();
        }
    }

    return raw;
}

bool PortHopSession::should_hop(
    std::chrono::steady_clock::time_point now) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (unacked_.size() > 3)
        return true;
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - epoch_start_);
    return elapsed.count() > static_cast<int64_t>(schedule_.interval_sec());
}

void PortHopSession::hop() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++epoch_;
    epoch_start_ = std::chrono::steady_clock::now();
    unacked_.clear();
}

uint32_t PortHopSession::current_epoch() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return epoch_;
}

uint32_t PortHopSession::next_seq() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return next_seq_;
}

uint32_t PortHopSession::last_ack_seq() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_ack_seq_;
}

size_t PortHopSession::unacked_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return unacked_.size();
}

uint16_t PortHopSession::current_port() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return schedule_.port_for_epoch(epoch_);
}

// ==================== PortHopServer ====================

PortHopServer::PortHopServer(HopSchedule schedule)
    : schedule_(std::move(schedule)) {}

PortHopServer::~PortHopServer() {
    close();
}

bool PortHopServer::bind_all() {
#ifdef _WIN32
    NCP_LOG_ERROR("PortHopServer: Windows not supported in this module");
    return false;
#else
    if (bound_) return true;

    uint16_t range = schedule_.port_range();
    if (range > kMaxRange) {
        NCP_LOG_WARN("PortHopServer: port range capped at 64");
        range = kMaxRange;
    }

    for (uint16_t i = 0; i < range; ++i) {
        uint16_t port = static_cast<uint16_t>(schedule_.base_port() + i);

        int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            close();
            return false;
        }

        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

        struct sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr),
                   sizeof(addr)) != 0) {
            NCP_LOG_ERROR("PortHopServer: bind failed on port " +
                          std::to_string(port) + ": " + strerror(errno));
            ::close(fd);
            close();
            return false;
        }

        if (!set_nonblocking(fd)) {
            ::close(fd);
            close();
            return false;
        }

        sockets_.push_back(fd);
        bound_ports_.push_back(port);
    }

    bound_ = true;
    return true;
#endif
}

void PortHopServer::close() {
#ifndef _WIN32
    for (int fd : sockets_)
        ::close(fd);
#endif
    sockets_.clear();
    bound_ports_.clear();
    bound_ = false;
}

bool PortHopServer::is_bound() const {
    return bound_;
}

void PortHopServer::register_session(uint64_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.try_emplace(session_id, session_id, schedule_);
}

void PortHopServer::remove_session(uint64_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.erase(session_id);
}

bool PortHopServer::has_session(uint64_t session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.count(session_id) != 0;
}

std::vector<PortHopReceived> PortHopServer::poll(int timeout_ms) {
    std::vector<PortHopReceived> out;
#ifndef _WIN32
    if (!bound_ || sockets_.empty())
        return out;

    fd_set rfds;
    FD_ZERO(&rfds);
    int max_fd = -1;
    for (int fd : sockets_) {
        FD_SET(fd, &rfds);
        if (fd > max_fd) max_fd = fd;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ready = ::select(max_fd + 1, &rfds, nullptr, nullptr,
                         timeout_ms >= 0 ? &tv : nullptr);
    if (ready <= 0)
        return out;

    uint8_t buf[kMaxDatagram];
    for (size_t i = 0; i < sockets_.size(); ++i) {
        int fd = sockets_[i];
        if (!FD_ISSET(fd, &rfds))
            continue;

        // Drain this socket (it is non-blocking).
        for (;;) {
            struct sockaddr_in from;
            socklen_t from_len = sizeof(from);
            ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
                                   reinterpret_cast<struct sockaddr*>(&from),
                                   &from_len);
            if (n <= 0)
                break;

            auto raw = PortHopSession::decode_raw(buf, static_cast<size_t>(n));
            if (!raw) {
                std::lock_guard<std::mutex> lock(mutex_);
                ++malformed_;
                continue;
            }

            std::lock_guard<std::mutex> lock(mutex_);
            auto it = sessions_.find(raw->session_id);
            if (it == sessions_.end()) {
                ++rejected_unknown_;
                continue;
            }

            SessionState& st = it->second;
            auto frame = st.session.decode(buf, static_cast<size_t>(n));
            if (!frame) {
                ++malformed_;
                continue;
            }

            // Learn/refresh the client address from any port (roaming-safe).
            std::memcpy(st.peer_addr.data(), &from,
                        std::min<size_t>(sizeof(from), st.peer_addr.size()));
            st.peer_addr_len = static_cast<uint32_t>(
                std::min<size_t>(sizeof(from), st.peer_addr.size()));
            st.peer_known = true;
            ++st.frames;

            PortHopReceived rec;
            rec.frame = std::move(*frame);
            rec.from_ip = addr_to_ip(from);
            rec.from_port = ntohs(from.sin_port);
            rec.local_port = bound_ports_[i];
            out.push_back(std::move(rec));
        }
    }
#else
    (void)timeout_ms;
#endif
    return out;
}

bool PortHopServer::send_to_session(uint64_t session_id,
                                    const uint8_t* payload,
                                    size_t payload_len,
                                    uint8_t flags) {
#ifdef _WIN32
    (void)session_id; (void)payload; (void)payload_len; (void)flags;
    return false;
#else
    if (!bound_ || sockets_.empty())
        return false;

    std::vector<uint8_t> wire;
    struct sockaddr_in peer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end() || !it->second.peer_known)
            return false;
        wire = it->second.session.encode(payload, payload_len, flags);
        std::memcpy(&peer, it->second.peer_addr.data(), sizeof(peer));
    }

    ssize_t n = ::sendto(sockets_.front(), wire.data(), wire.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&peer),
                         sizeof(peer));
    return n == static_cast<ssize_t>(wire.size());
#endif
}

bool PortHopServer::send_ack(uint64_t session_id, uint32_t acked_seq) {
#ifdef _WIN32
    (void)session_id; (void)acked_seq;
    return false;
#else
    if (!bound_ || sockets_.empty())
        return false;

    std::vector<uint8_t> wire;
    struct sockaddr_in peer;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end() || !it->second.peer_known)
            return false;
        // Empty-payload ACK whose seq field echoes the acked seq.
        wire = it->second.session.encode(nullptr, 0, PH_FLAG_ACK);
        // Overwrite seq with the echoed value.
        wire[15] = static_cast<uint8_t>(acked_seq >> 24);
        wire[16] = static_cast<uint8_t>(acked_seq >> 16);
        wire[17] = static_cast<uint8_t>(acked_seq >> 8);
        wire[18] = static_cast<uint8_t>(acked_seq);
        std::memcpy(&peer, it->second.peer_addr.data(), sizeof(peer));
    }

    ssize_t n = ::sendto(sockets_.front(), wire.data(), wire.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&peer),
                         sizeof(peer));
    return n == static_cast<ssize_t>(wire.size());
#endif
}

uint64_t PortHopServer::frames_received() const {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t total = 0;
    for (const auto& kv : sessions_)
        total += kv.second.frames;
    return total;
}

uint64_t PortHopServer::frames_rejected_unknown_session() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rejected_unknown_;
}

uint64_t PortHopServer::frames_malformed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return malformed_;
}

uint64_t PortHopServer::session_frame_count(uint64_t session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    return it == sessions_.end() ? 0 : it->second.frames;
}

// ==================== PortHopClient ====================

PortHopClient::PortHopClient(std::string server_ip,
                             HopSchedule schedule,
                             uint64_t session_id)
    : server_ip_(std::move(server_ip)),
      schedule_(schedule),
      session_id_(session_id),
      session_(session_id, schedule) {}

PortHopClient::~PortHopClient() {
    close();
}

bool PortHopClient::open() {
#ifdef _WIN32
    return false;
#else
    if (socket_ >= 0) return true;

    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    if (!set_nonblocking(fd)) {
        ::close(fd);
        return false;
    }

    // Bind to an ephemeral port so replies have a stable source.
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(0);
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr),
               sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }

    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr),
                      &len) == 0)
        local_port_ = ntohs(addr.sin_port);

    socket_ = fd;
    return true;
#endif
}

void PortHopClient::close() {
#ifndef _WIN32
    if (socket_ >= 0)
        ::close(socket_);
#endif
    socket_ = -1;
}

bool PortHopClient::is_open() const {
    return socket_ >= 0;
}

bool PortHopClient::send(const uint8_t* payload, size_t payload_len,
                         uint8_t flags) {
#ifdef _WIN32
    (void)payload; (void)payload_len; (void)flags;
    return false;
#else
    if (socket_ < 0) return false;

    std::vector<uint8_t> wire = session_.encode(payload, payload_len, flags);
    uint16_t port = schedule_.port_for_epoch(session_.current_epoch());

    struct sockaddr_in to;
    std::memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    if (::inet_pton(AF_INET, server_ip_.c_str(), &to.sin_addr) != 1)
        return false;

    ssize_t n = ::sendto(socket_, wire.data(), wire.size(), 0,
                         reinterpret_cast<struct sockaddr*>(&to), sizeof(to));
    return n == static_cast<ssize_t>(wire.size());
#endif
}

bool PortHopClient::send(const std::vector<uint8_t>& payload, uint8_t flags) {
    return send(payload.data(), payload.size(), flags);
}

std::vector<PortHopReceived> PortHopClient::poll(int timeout_ms) {
    std::vector<PortHopReceived> out;
#ifndef _WIN32
    if (socket_ < 0) return out;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(socket_, &rfds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int ready = ::select(socket_ + 1, &rfds, nullptr, nullptr, &tv);
    if (ready <= 0)
        return out;

    uint8_t buf[kMaxDatagram];
    for (;;) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = ::recvfrom(socket_, buf, sizeof(buf), 0,
                               reinterpret_cast<struct sockaddr*>(&from),
                               &from_len);
        if (n <= 0)
            break;

        auto frame = session_.decode(buf, static_cast<size_t>(n));
        if (!frame)
            continue;

        PortHopReceived rec;
        rec.frame = std::move(*frame);
        rec.from_ip = addr_to_ip(from);
        rec.from_port = ntohs(from.sin_port);
        rec.local_port = local_port_;
        out.push_back(std::move(rec));
    }
#else
    (void)timeout_ms;
#endif
    return out;
}

void PortHopClient::hop() {
    session_.hop();
}

uint16_t PortHopClient::current_target_port() const {
    return schedule_.port_for_epoch(session_.current_epoch());
}

uint32_t PortHopClient::current_epoch() const {
    return session_.current_epoch();
}

uint16_t PortHopClient::local_port() const {
    return local_port_;
}

} // namespace ncp
