/**
 * @file ncp_fog.cpp
 * @brief Cooperative Fog Mesh overlay relay (M7) — implementation.
 *
 * Single-threaded UDP relay with TTL routing, a (origin,seq) loop-guard,
 * trust-scored peer table and ROUTE_AD peer gossip.
 */

#include "ncp_fog.hpp"

#include <cstdio>
#include <cstring>
#include <cmath>
#include <algorithm>

#include <sodium.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>

// Minimal local logging (standalone-build friendly).
#ifndef NCPX_FOG_LOG
#define NCPX_FOG_LOG(level, msg) \
    do { std::fprintf(stderr, "[ncp_fog][%s] %s\n", level, msg); } while (0)
#endif

namespace ncp {

// ===== FogPeerId =====

FogPeerId FogPeerId::random() {
    FogPeerId id{};
    randombytes_buf(id.bytes.data(), id.bytes.size());
    // Avoid the reserved all-zero (broadcast) id.
    if (id.is_broadcast()) id.bytes[0] = 1;
    return id;
}

std::string FogPeerId::to_hex() const {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

// ===== Stringify =====

const char* fog_msg_type_to_string(FogMsgType t) noexcept {
    switch (t) {
        case FogMsgType::DATA:     return "DATA";
        case FogMsgType::PING:     return "PING";
        case FogMsgType::PONG:     return "PONG";
        case FogMsgType::ROUTE_AD: return "ROUTE_AD";
    }
    return "UNKNOWN";
}

const char* fog_error_to_string(FogError e) noexcept {
    switch (e) {
        case FogError::OK:            return "OK";
        case FogError::INVALID_FRAME: return "INVALID_FRAME";
        case FogError::TTL_EXPIRED:   return "TTL_EXPIRED";
        case FogError::DUPLICATE:     return "DUPLICATE";
        case FogError::NOT_BOUND:     return "NOT_BOUND";
        case FogError::SEND_FAILED:   return "SEND_FAILED";
        case FogError::NO_ROUTE:      return "NO_ROUTE";
    }
    return "UNKNOWN";
}

// ===== Frame pack / parse =====

std::vector<uint8_t> FogFrame::pack() const {
    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + payload.size());
    out.push_back('F'); out.push_back('O'); out.push_back('G');
    out.push_back(kVersion);
    out.push_back(ttl);
    out.push_back(static_cast<uint8_t>(type));
    out.insert(out.end(), target_id.bytes.begin(), target_id.bytes.end());
    out.insert(out.end(), origin_id.bytes.begin(), origin_id.bytes.end());
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<uint8_t>((seq >> (i * 8)) & 0xFF));
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::optional<FogFrame> FogFrame::parse(const uint8_t* data, size_t len) {
    if (!data || len < kHeaderSize) return std::nullopt;
    if (data[0] != 'F' || data[1] != 'O' || data[2] != 'G') return std::nullopt;
    if (data[3] != kVersion) return std::nullopt;
    FogFrame f;
    f.ttl  = data[4];
    uint8_t mt = data[5];
    if (mt < 1 || mt > 4) return std::nullopt;
    f.type = static_cast<FogMsgType>(mt);
    std::copy(data + 6,  data + 22, f.target_id.bytes.begin());
    std::copy(data + 22, data + 38, f.origin_id.bytes.begin());
    uint64_t s = 0;
    for (int i = 0; i < 8; ++i) s = (s << 8) | data[38 + i];
    f.seq = s;
    f.payload.assign(data + kHeaderSize, data + len);
    return f;
}

// ===== Peer table =====

void FogPeerTable::register_peer(const FogPeerInfo& info, uint64_t now) {
    if (info.id.is_broadcast()) return;
    std::lock_guard<std::mutex> lk(mtx_);
    FogPeerInfo copy = info;
    if (copy.last_seen == 0) copy.last_seen = now;
    if (copy.trust_score < 0.0) copy.trust_score = 0.0;
    if (copy.trust_score > 1.0) copy.trust_score = 1.0;

    auto it = peers_.find(copy.id.to_key());
    if (it != peers_.end()) {
        // Upsert: keep the higher trust watermark fields fresh.
        it->second = copy;
        return;
    }
    if (peers_.size() >= kMaxPeers) {
        // Evict the lowest-trust peer.
        auto worst = peers_.begin();
        for (auto i = peers_.begin(); i != peers_.end(); ++i) {
            if (i->second.trust_score < worst->second.trust_score) worst = i;
        }
        peers_.erase(worst);
    }
    peers_.emplace(copy.id.to_key(), copy);
}

void FogPeerTable::decay(uint64_t now) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (last_decay_ == 0) { last_decay_ = now; return; }
    if (now <= last_decay_) return;
    double minutes = static_cast<double>(now - last_decay_) / 60.0;
    double factor  = std::pow(kDecayPerMinute, minutes);
    for (auto& kv : peers_) {
        kv.second.trust_score *= factor;
    }
    last_decay_ = now;
}

std::optional<FogPeerInfo> FogPeerTable::best_relay(const FogPeerId& exclude,
                                                    uint64_t now) const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::optional<FogPeerInfo> best;
    for (const auto& kv : peers_) {
        const FogPeerInfo& p = kv.second;
        if (p.id == exclude) continue;
        if (now < p.last_seen || (now - p.last_seen) >= kRelayFreshSec) continue;
        if (!best || p.trust_score > best->trust_score) best = p;
    }
    return best;
}

std::optional<FogPeerInfo> FogPeerTable::find(const FogPeerId& id) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = peers_.find(id.to_key());
    if (it == peers_.end()) return std::nullopt;
    return it->second;
}

size_t FogPeerTable::size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return peers_.size();
}

void FogPeerTable::clear() {
    std::lock_guard<std::mutex> lk(mtx_);
    peers_.clear();
}

// ===== Fog node =====

FogNode::FogNode(Config cfg) : cfg_(cfg) {
    if (sodium_init() < 0) {
        NCPX_FOG_LOG("ERROR", "sodium_init failed");
    }
}

FogNode::~FogNode() { stop(); }

FogError FogNode::start() {
    if (sock_ >= 0) return FogError::OK;
    sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) {
        NCPX_FOG_LOG("ERROR", "socket() failed");
        return FogError::NOT_BOUND;
    }
    int flags = fcntl(sock_, F_GETFL, 0);
    fcntl(sock_, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(cfg_.bind_port);
    if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        NCPX_FOG_LOG("ERROR", "bind() failed");
        ::close(sock_);
        sock_ = -1;
        return FogError::NOT_BOUND;
    }
    socklen_t alen = sizeof(addr);
    if (::getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &alen) == 0) {
        bound_port_ = ntohs(addr.sin_port);
    }
    return FogError::OK;
}

void FogNode::stop() {
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
}

bool FogNode::running() const { return sock_ >= 0; }
uint16_t FogNode::bound_port() const { return bound_port_; }

uint64_t FogNode::next_seq_unlocked() { return ++seq_counter_; }

FogError FogNode::send_data(const FogPeerId& target,
                            const std::vector<uint8_t>& payload,
                            uint64_t now) {
    if (sock_ < 0) return FogError::NOT_BOUND;
    FogFrame f;
    f.ttl = cfg_.default_ttl;
    f.type = FogMsgType::DATA;
    f.target_id = target;
    f.origin_id = cfg_.id;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        f.seq = next_seq_unlocked();
    }
    f.payload = payload;
    remember(f);
    return forward(f, now);
}

FogError FogNode::send_ping(const FogPeerId& target, uint64_t now) {
    if (sock_ < 0) return FogError::NOT_BOUND;
    FogFrame f;
    f.ttl = cfg_.default_ttl;
    f.type = FogMsgType::PING;
    f.target_id = target;
    f.origin_id = cfg_.id;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        f.seq = next_seq_unlocked();
    }
    remember(f);
    return forward(f, now);
}

FogError FogNode::send_route_ad(const FogPeerInfo& neighbour, uint64_t now) {
    if (sock_ < 0) return FogError::NOT_BOUND;
    FogFrame f;
    f.ttl = 1; // gossip is one-hop
    f.type = FogMsgType::ROUTE_AD;
    f.target_id = neighbour.id;
    f.origin_id = cfg_.id;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        f.seq = next_seq_unlocked();
    }
    // Serialize entries: id(16) | ipv4(4,BE) | port(2,BE) | trust(1).
    // We advertise our own presence; richer gossip selection (top-N by
    // trust) is left to higher layers.
    FogPeerInfo self;
    self.id = cfg_.id;
    self.ipv4 = 0x7F000001; // loopback by default; real deployments fill in
    self.port = bound_port_;
    self.trust_score = 1.0;
    self.last_seen = now;
    auto enc_peer = [](const FogPeerInfo& p, std::vector<uint8_t>& out) {
        out.insert(out.end(), p.id.bytes.begin(), p.id.bytes.end());
        for (int i = 3; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((p.ipv4 >> (i * 8)) & 0xFF));
        out.push_back(static_cast<uint8_t>((p.port >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(p.port & 0xFF));
        double t = p.trust_score;
        if (t < 0.0) t = 0.0; if (t > 1.0) t = 1.0;
        out.push_back(static_cast<uint8_t>(t * 255.0 + 0.5));
    };
    enc_peer(self, f.payload);
    remember(f);
    return send_frame_to(f, neighbour.ipv4, neighbour.port);
}

FogError FogNode::send_frame_to(const FogFrame& f, uint32_t ip, uint16_t port) {
    if (sock_ < 0) return FogError::NOT_BOUND;
    std::vector<uint8_t> buf = f.pack();
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(ip);
    dst.sin_port = htons(port);
    ssize_t sent = ::sendto(sock_, buf.data(), buf.size(), 0,
                            reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (sent != static_cast<ssize_t>(buf.size())) {
        NCPX_FOG_LOG("WARN", "sendto() short/failed");
        return FogError::SEND_FAILED;
    }
    return FogError::OK;
}

FogError FogNode::forward(const FogFrame& f, uint64_t now) {
    // Prefer a direct route to the target.
    auto direct = table_.find(f.target_id);
    if (direct) {
        return send_frame_to(f, direct->ipv4, direct->port);
    }
    // Otherwise hand it to the best relay (never back to the origin).
    auto relay = table_.best_relay(f.origin_id, now);
    if (!relay) return FogError::NO_ROUTE;
    return send_frame_to(f, relay->ipv4, relay->port);
}

bool FogNode::seen_before(const FogFrame& f) {
    std::string key = f.origin_id.to_key();
    key.append(reinterpret_cast<const char*>(&f.seq), sizeof(f.seq));
    std::lock_guard<std::mutex> lk(mtx_);
    return seen_set_.count(key) != 0;
}

void FogNode::remember(const FogFrame& f) {
    std::string key = f.origin_id.to_key();
    key.append(reinterpret_cast<const char*>(&f.seq), sizeof(f.seq));
    std::lock_guard<std::mutex> lk(mtx_);
    if (seen_set_.count(key)) return;
    if (seen_order_.size() >= kSeenCacheMax) {
        seen_set_.erase(seen_order_.front());
        seen_order_.pop_front();
    }
    seen_order_.push_back(key);
    seen_set_.insert(std::move(key));
}

void FogNode::merge_route_ad(const FogFrame& f, uint64_t now) {
    // Entries: id(16) | ipv4(4,BE) | port(2,BE) | trust(1) — 23 bytes each.
    const size_t kEntry = 23;
    size_t n = f.payload.size() / kEntry;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = f.payload.data() + i * kEntry;
        FogPeerInfo p;
        std::copy(e, e + 16, p.id.bytes.begin());
        if (p.id == cfg_.id) continue; // never add ourselves
        p.ipv4 = (uint32_t(e[16]) << 24) | (uint32_t(e[17]) << 16) |
                 (uint32_t(e[18]) << 8)  |  uint32_t(e[19]);
        p.port = static_cast<uint16_t>((e[20] << 8) | e[21]);
        p.trust_score = static_cast<double>(e[22]) / 255.0;
        p.last_seen = now;
        table_.register_peer(p, now);
    }
}

void FogNode::handle_frame(const FogFrame& f, uint32_t src_ip, uint16_t src_port,
                           uint64_t now) {
    // Loop-guard: drop duplicates of (origin_id, seq) for relayed types.
    if (f.type == FogMsgType::DATA || f.type == FogMsgType::ROUTE_AD) {
        if (seen_before(f)) {
            ++dropped_dup_;
            return;
        }
        remember(f);
    }

    // Learn the sender as a peer (any sender is a potential neighbour).
    if (f.origin_id != cfg_.id && !f.origin_id.is_broadcast()) {
        FogPeerInfo sender;
        sender.id = f.origin_id;
        sender.ipv4 = src_ip;
        sender.port = src_port;
        sender.trust_score = 0.5;
        sender.last_seen = now;
        // Do not downgrade an existing entry's trust via upsert semantics:
        // register_peer replaces, so only insert if absent.
        if (!table_.find(f.origin_id)) {
            table_.register_peer(sender, now);
        } else {
            auto existing = table_.find(f.origin_id);
            existing->last_seen = now;
            existing->ipv4 = src_ip;
            existing->port = src_port;
            table_.register_peer(*existing, now);
        }
    }

    const bool for_us = (f.target_id == cfg_.id);

    switch (f.type) {
        case FogMsgType::DATA: {
            if (for_us) {
                std::lock_guard<std::mutex> lk(mtx_);
                inbox_.push_back(f.payload);
                return;
            }
            break; // relay below
        }
        case FogMsgType::PING: {
            if (for_us || f.target_id.is_broadcast()) {
                FogFrame pong;
                pong.ttl = cfg_.default_ttl;
                pong.type = FogMsgType::PONG;
                pong.target_id = f.origin_id;
                pong.origin_id = cfg_.id;
                {
                    std::lock_guard<std::mutex> lk(mtx_);
                    pong.seq = next_seq_unlocked();
                }
                remember(pong);
                send_frame_to(pong, src_ip, src_port);
                return;
            }
            break; // relay below
        }
        case FogMsgType::PONG: {
            return; // nothing to do; liveness is tracked via last_seen
        }
        case FogMsgType::ROUTE_AD: {
            merge_route_ad(f, now);
            break; // may be relayed further below
        }
    }

    // Relay path: decrement TTL and forward; drop when TTL hits 0.
    if (for_us) return;
    if (f.ttl <= 1) {
        ++dropped_ttl_;
        return;
    }
    FogFrame fwd = f;
    fwd.ttl = f.ttl - 1;
    if (forward(fwd, now) == FogError::OK) {
        ++relayed_;
        auto orig = table_.find(f.origin_id);
        if (orig) {
            orig->bytes_relayed += f.payload.size();
            table_.register_peer(*orig, now);
        }
    }
    // No route: the frame silently dies here (NO_ROUTE from forward()).
}

int FogNode::poll(int timeout_ms, uint64_t now) {
    if (sock_ < 0) return 0;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock_, &rfds);
    timeval tv{};
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = ::select(sock_ + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0) return 0;

    int handled = 0;
    // Drain whatever is pending (bounded batch).
    for (int i = 0; i < 64; ++i) {
        uint8_t buf[65535];
        sockaddr_in src{};
        socklen_t slen = sizeof(src);
        ssize_t n = ::recvfrom(sock_, buf, sizeof(buf), MSG_DONTWAIT,
                               reinterpret_cast<sockaddr*>(&src), &slen);
        if (n <= 0) break;
        auto frame = FogFrame::parse(buf, static_cast<size_t>(n));
        if (!frame) continue;
        handle_frame(*frame, ntohl(src.sin_addr.s_addr), ntohs(src.sin_port), now);
        ++handled;
    }
    return handled;
}

bool FogNode::inbox_pop(std::vector<uint8_t>& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (inbox_.empty()) return false;
    out = std::move(inbox_.front());
    inbox_.pop_front();
    return true;
}

size_t FogNode::inbox_size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return inbox_.size();
}

} // namespace ncp
