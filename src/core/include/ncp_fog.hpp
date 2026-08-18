#pragma once

/**
 * @file ncp_fog.hpp
 * @brief Cooperative Fog Mesh overlay relay (M7)
 *
 * Clients inside the censored zone relay each other's traffic over a
 * Kademlia-like overlay before it exits abroad, so DPI sees only
 * internal flows between ordinary hosts.
 *
 * Wire frame:
 *   magic(3)="FOG" | ver(1)=1 | ttl(1) | msg_type(1) |
 *   target_id(16) | origin_id(16) | seq(8,BE) | payload
 *
 * msg_type: DATA=1, PING=2, PONG=3, ROUTE_AD=4.
 *
 * Notes:
 *   - No exceptions cross the public API; errors are returned as enums
 *     or std::optional.
 *   - All public methods are thread-safe (internal mutex).
 *   - The UDP loop is single-threaded: call poll() from one thread.
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <mutex>
#include <optional>

namespace ncp {

// ===== Peer identity =====

struct FogPeerId {
    std::array<uint8_t, 16> bytes{};

    bool operator==(const FogPeerId& o) const noexcept { return bytes == o.bytes; }
    bool operator!=(const FogPeerId& o) const noexcept { return bytes != o.bytes; }
    bool operator<(const FogPeerId& o) const noexcept { return bytes < o.bytes; }

    std::string to_key() const {
        return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
    static FogPeerId from_key(const std::string& k) {
        FogPeerId id{};
        if (k.size() == bytes_size()) {
            std::copy(k.begin(), k.end(), id.bytes.begin());
        }
        return id;
    }
    static constexpr size_t bytes_size() { return 16; }
    static FogPeerId random();       // CSPRNG (libsodium)
    static FogPeerId broadcast() { return FogPeerId{}; }  // all-zero id
    bool is_broadcast() const noexcept {
        for (auto b : bytes) if (b != 0) return false;
        return true;
    }
    std::string to_hex() const;
};

// ===== Message types =====

enum class FogMsgType : uint8_t {
    DATA     = 1,
    PING     = 2,
    PONG     = 3,
    ROUTE_AD = 4
};

const char* fog_msg_type_to_string(FogMsgType t) noexcept;

// ===== Error codes =====

enum class FogError {
    OK = 0,
    INVALID_FRAME,   // bad magic/version/length
    TTL_EXPIRED,     // dropped because ttl reached 0
    DUPLICATE,       // (origin_id, seq) already seen
    NOT_BOUND,       // start() not called / socket closed
    SEND_FAILED,     // sendto() failed
    NO_ROUTE         // no known route toward target
};

const char* fog_error_to_string(FogError e) noexcept;

// ===== Wire frame =====

struct FogFrame {
    static constexpr size_t kHeaderSize = 3 + 1 + 1 + 1 + 16 + 16 + 8; // 46
    static constexpr uint8_t kVersion = 1;

    uint8_t     ttl = 8;
    FogMsgType  type = FogMsgType::DATA;
    FogPeerId   target_id{};
    FogPeerId   origin_id{};
    uint64_t    seq = 0;
    std::vector<uint8_t> payload;

    std::vector<uint8_t> pack() const;
    static std::optional<FogFrame> parse(const uint8_t* data, size_t len);
};

// ===== Peer table =====

struct FogPeerInfo {
    FogPeerId id{};
    uint32_t  ipv4 = 0;          // host byte order (e.g. 0x7F000001 for 127.0.0.1)
    uint16_t  port = 0;          // host byte order
    double    trust_score = 0.5; // 0..1
    uint64_t  last_seen = 0;     // unix seconds
    uint64_t  bytes_relayed = 0;
};

class FogPeerTable {
public:
    static constexpr size_t   kMaxPeers        = 256;
    static constexpr uint64_t kRelayFreshSec   = 60;    // "seen < 60 s ago"
    static constexpr double   kDecayPerMinute  = 0.99;

    // Upsert a peer. When the table is full, the lowest-trust peer is evicted.
    void register_peer(const FogPeerInfo& info, uint64_t now);

    // trust *= 0.99 per elapsed minute since the previous decay() call.
    void decay(uint64_t now);

    // Highest-trust peer seen < 60 s ago, excluding `exclude` (the origin).
    std::optional<FogPeerInfo> best_relay(const FogPeerId& exclude, uint64_t now) const;

    std::optional<FogPeerInfo> find(const FogPeerId& id) const;
    size_t size() const;
    void clear();

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, FogPeerInfo> peers_; // key: id.to_key()
    uint64_t last_decay_ = 0;
};

// ===== Fog node =====

class FogNode {
public:
    struct Config {
        uint16_t  bind_port   = 0;   // 0 = ephemeral
        FogPeerId id{};
        uint8_t   default_ttl = 8;
    };

    explicit FogNode(Config cfg);
    ~FogNode();

    FogNode(const FogNode&) = delete;
    FogNode& operator=(const FogNode&) = delete;

    // Bind the UDP socket (non-blocking). Safe to call once.
    FogError start();
    void     stop();
    bool     running() const;
    uint16_t bound_port() const;    // actual bound port (after start)
    const FogPeerId& id() const { return cfg_.id; }

    FogPeerTable& table() { return table_; }

    // Send DATA toward `target`. If the target is a known peer, the frame
    // goes directly; otherwise it is handed to the best relay.
    FogError send_data(const FogPeerId& target,
                       const std::vector<uint8_t>& payload, uint64_t now);

    // Send PING toward `target` (direct if known, else via best relay).
    FogError send_ping(const FogPeerId& target, uint64_t now);

    // Advertise our peer table to a direct neighbour.
    FogError send_route_ad(const FogPeerInfo& neighbour, uint64_t now);

    // Process pending datagrams for up to timeout_ms. Returns the number
    // of frames handled. Single-threaded receive loop.
    int poll(int timeout_ms, uint64_t now);

    // Delivered DATA payloads addressed to this node.
    bool   inbox_pop(std::vector<uint8_t>& out);
    size_t inbox_size() const;

    // Counters (mostly for tests/diagnostics).
    uint64_t dropped_ttl() const { return dropped_ttl_; }
    uint64_t dropped_dup() const { return dropped_dup_; }
    uint64_t relayed()     const { return relayed_; }

private:
    void handle_frame(const FogFrame& f, uint32_t src_ip, uint16_t src_port,
                      uint64_t now);
    FogError forward(const FogFrame& f, uint64_t now);
    FogError send_frame_to(const FogFrame& f, uint32_t ip, uint16_t port);
    bool     seen_before(const FogFrame& f);
    void     remember(const FogFrame& f);
    void     merge_route_ad(const FogFrame& f, uint64_t now);
    uint64_t next_seq_unlocked();

    Config        cfg_;
    FogPeerTable  table_;
    int           sock_ = -1;
    uint16_t      bound_port_ = 0;
    uint64_t      seq_counter_ = 0;

    mutable std::mutex mtx_;
    std::deque<std::vector<uint8_t>> inbox_;

    // Loop-guard: (origin_id || seq) seen recently (FIFO, capped).
    std::unordered_set<std::string> seen_set_;
    std::deque<std::string>         seen_order_;
    static constexpr size_t kSeenCacheMax = 10000;

    uint64_t dropped_ttl_ = 0;
    uint64_t dropped_dup_ = 0;
    uint64_t relayed_     = 0;
};

} // namespace ncp
