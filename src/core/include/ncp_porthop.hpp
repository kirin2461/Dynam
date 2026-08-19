#pragma once

/**
 * @file ncp_porthop.hpp
 * @brief M2 — QUIC/UDP Port-Hopping transport
 *
 * Defeats UDP shaping by rotating the destination/source UDP port
 * mid-session on a schedule derived from a shared secret, without
 * breaking the logical session.
 *
 * Hop schedule:
 *   port(epoch) = base + (HMAC-SHA256(secret, epoch_u64_BE)[0..2] % range)
 * The epoch advances every `hop_interval_sec` or on demand (loss-triggered).
 *
 * Wire frame format (20-byte header):
 *   magic(2) = "PH" | ver(1) = 1 | session_id(8) | epoch(4, BE) |
 *   seq(4, BE) | flags(1) | payload...
 *
 * flags bits:
 *   bit0 (0x01) ACK_REQUEST — receiver should echo seq in an ACK frame
 *   bit1 (0x02) ACK         — seq field echoes the acknowledged seq
 *   bit2 (0x04) HOP_NOTIFY  — payload = next epoch u32 BE
 *
 * Server binds every port in [base, base+range) via SO_REUSEPORT sockets
 * (range is capped at 64 for tests) and demultiplexes by session_id.
 * The client address is learned per session from any port, so the scheme
 * is roaming-safe.
 *
 * Security notes:
 *   - HMAC-SHA256 via libsodium (crypto_auth_hmacsha256)
 *   - No exceptions cross the public API — bool/std::optional returns
 *   - Session state is protected by std::mutex
 */

#include <cstdint>
#include <cstddef>
#include <array>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "ncp_winsock_init.hpp"

namespace ncp {

// ===== Frame flags =====

enum PortHopFlags : uint8_t {
    PH_FLAG_NONE        = 0x00,
    PH_FLAG_ACK_REQUEST = 0x01,  // bit0: receiver must ACK this seq
    PH_FLAG_ACK         = 0x02,  // bit1: seq echoes the acknowledged seq
    PH_FLAG_HOP_NOTIFY  = 0x04,  // bit2: payload = next epoch (u32 BE)
};

// ===== Decoded frame =====

struct PortHopFrame {
    uint64_t session_id = 0;
    uint32_t epoch = 0;
    uint32_t seq = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
};

// ===== Hop schedule =====

class HopSchedule {
public:
    HopSchedule(std::vector<uint8_t> secret,
                uint16_t base_port,
                uint16_t port_range,
                uint32_t interval_sec);

    /// Deterministic port for an epoch. Always in [base, base+range).
    uint16_t port_for_epoch(uint32_t epoch) const;

    uint16_t base_port() const noexcept { return base_port_; }
    uint16_t port_range() const noexcept { return port_range_; }
    uint32_t interval_sec() const noexcept { return interval_sec_; }

private:
    std::vector<uint8_t> secret_;
    uint16_t base_port_;
    uint16_t port_range_;
    uint32_t interval_sec_;
};

// ===== Shared session logic (used by both client and server side) =====

class PortHopSession {
public:
    PortHopSession(uint64_t session_id, HopSchedule schedule);

    PortHopSession(const PortHopSession&) = delete;
    PortHopSession& operator=(const PortHopSession&) = delete;

    /// Encode a frame: stamps current epoch, next seq, flags.
    /// If PH_FLAG_ACK_REQUEST is set, the packet is tracked as unacked.
    std::vector<uint8_t> encode(const uint8_t* payload, size_t payload_len,
                                uint8_t flags = PH_FLAG_NONE);

    /// Validate + decode an incoming frame.
    /// Checks magic/version/session_id. Tracks ACK frames (bit1) and
    /// applies HOP_NOTIFY (bit2) epochs. Returns nullopt on any mismatch.
    std::optional<PortHopFrame> decode(const uint8_t* data, size_t len);

    /// Session-independent frame parser: validates magic/version only.
    static std::optional<PortHopFrame> decode_raw(const uint8_t* data, size_t len);

    /// Hop decision: more than 3 unacked packets or epoch expired.
    bool should_hop(std::chrono::steady_clock::time_point now) const;

    /// Advance to the next epoch (resets epoch timer and unacked set).
    void hop();

    uint64_t session_id() const noexcept { return session_id_; }
    uint32_t current_epoch() const;
    uint32_t next_seq() const;
    uint32_t last_ack_seq() const;
    size_t unacked_count() const;
    uint16_t current_port() const;   // schedule port for current epoch

    static constexpr size_t HEADER_SIZE = 20;  // 2+1+8+4+4+1

private:
    uint64_t session_id_;
    HopSchedule schedule_;
    uint32_t epoch_ = 0;
    uint32_t next_seq_ = 0;
    uint32_t last_ack_seq_ = 0;
    std::vector<uint32_t> unacked_;  // seqs sent with ACK_REQUEST, awaiting ACK
    std::chrono::steady_clock::time_point epoch_start_;
    mutable std::mutex mutex_;
};

// ===== Received frame with transport metadata =====

struct PortHopReceived {
    PortHopFrame frame;
    std::string from_ip;
    uint16_t from_port = 0;   // sender's source port
    uint16_t local_port = 0;  // which bound port received the datagram
};

// ===== Server =====

class PortHopServer {
public:
    /// range > kMaxRange is clamped to kMaxRange (cap for tests).
    static constexpr uint16_t kMaxRange = 64;

    explicit PortHopServer(HopSchedule schedule);
    ~PortHopServer();

    PortHopServer(const PortHopServer&) = delete;
    PortHopServer& operator=(const PortHopServer&) = delete;

    /// Bind one UDP socket (SO_REUSEPORT) per port in [base, base+range).
    /// Returns false if any socket fails.
    bool bind_all();
    void close();
    bool is_bound() const;

    /// Whitelist a session_id. Datagrams from unknown sessions are dropped.
    void register_session(uint64_t session_id);
    void remove_session(uint64_t session_id);
    bool has_session(uint64_t session_id) const;

    /// Non-blocking-ish receive pump: waits up to timeout_ms, drains all
    /// pending datagrams, returns frames from registered sessions.
    std::vector<PortHopReceived> poll(int timeout_ms = 0);

    /// Send a frame back to the learned client address of a session.
    bool send_to_session(uint64_t session_id,
                         const uint8_t* payload, size_t payload_len,
                         uint8_t flags = PH_FLAG_NONE);

    /// Convenience: ACK the given seq back to the session's client.
    bool send_ack(uint64_t session_id, uint32_t acked_seq);

    // Counters
    uint64_t frames_received() const;
    uint64_t frames_rejected_unknown_session() const;
    uint64_t frames_malformed() const;
    /// Number of frames associated with a session (0 if unknown).
    uint64_t session_frame_count(uint64_t session_id) const;

private:
    struct SessionState {
        PortHopSession session;
        std::array<uint8_t, 128> peer_addr{};  // opaque; holds sockaddr_storage
        uint32_t peer_addr_len = 0;
        bool peer_known = false;
        uint64_t frames = 0;
        SessionState(uint64_t sid, const HopSchedule& sched)
            : session(sid, sched) {}
        SessionState(const SessionState&) = delete;
        SessionState& operator=(const SessionState&) = delete;
    };

    HopSchedule schedule_;
    std::vector<socket_t> sockets_;      // one socket per bound port
    std::vector<uint16_t> bound_ports_;  // parallel to sockets_
    std::unordered_map<uint64_t, SessionState> sessions_;
    mutable std::mutex mutex_;
    uint64_t rejected_unknown_ = 0;
    uint64_t malformed_ = 0;
    bool bound_ = false;
};

// ===== Client =====

class PortHopClient {
public:
    PortHopClient(std::string server_ip,
                  HopSchedule schedule,
                  uint64_t session_id);
    ~PortHopClient();

    PortHopClient(const PortHopClient&) = delete;
    PortHopClient& operator=(const PortHopClient&) = delete;

    bool open();
    void close();
    bool is_open() const;

    /// Send payload to the currently scheduled server port.
    bool send(const uint8_t* payload, size_t payload_len,
              uint8_t flags = PH_FLAG_NONE);
    bool send(const std::vector<uint8_t>& payload,
              uint8_t flags = PH_FLAG_NONE);

    /// Receive replies (ACKs / server frames).
    std::vector<PortHopReceived> poll(int timeout_ms = 0);

    /// Advance epoch; next send() targets the new scheduled port.
    void hop();

    uint16_t current_target_port() const;
    uint32_t current_epoch() const;
    uint16_t local_port() const;  // ephemeral source port
    PortHopSession& session() noexcept { return session_; }

private:
    std::string server_ip_;
    HopSchedule schedule_;
    uint64_t session_id_;
    PortHopSession session_;
    socket_t socket_ = kInvalidSocket;
    uint16_t local_port_ = 0;
};

} // namespace ncp
