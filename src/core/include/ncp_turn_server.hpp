#ifndef NCP_TURN_SERVER_HPP
#define NCP_TURN_SERVER_HPP

// ══════════════════════════════════════════════════════════════════════════════
// ncp_turn_server.hpp
//
// G5: REAL TURN-over-UDP/IPv4 server (RFC 5766 / RFC 5389), native C++17.
//
// Scope and guarantees:
//   * UDP/IPv4 only. No TCP/TLS listeners are created or attempted.
//   * Long-term credential mechanism (RFC 5389 §10): unauthenticated requests
//     are challenged with 401 (REALM/NONCE); requests with a signed but
//     expired nonce get 438 Stale Nonce; requests with a bad nonce, unknown
//     user, wrong realm, missing/bad MESSAGE-INTEGRITY fail CLOSED (401/438,
//     never silently accepted). There is no plaintext/auth bypass path.
//   * Credentials (username -> password map) are supplied independently by
//     the caller. They are NEVER derived from HopSecret / E2E keys /
//     traffic-mask material.
//   * Implements: Allocate (REQUESTED-TRANSPORT=UDP only; XOR-RELAYED-ADDRESS,
//     XOR-MAPPED-ADDRESS, LIFETIME), Refresh (including lifetime=0 delete),
//     CreatePermission, ChannelBind, Send/Data indications, and ChannelData
//     relay in both directions (client->peer and peer->client), natural
//     expiry of allocations/permissions/channel bindings, transaction-id
//     replay response cache (retransmitted requests get the cached response),
//     and fail-closed drops for malformed/unauthenticated data-plane
//     datagrams.
//   * Bounded state: configurable caps on allocations, permissions per
//     allocation, channels per allocation, nonce window, and replay cache.
//   * One poll-loop owner: the server is single-threaded and non-blocking;
//     the caller drives poll(). No internal threads are created.
//
// Note on SASLprep: credentials are used byte-for-byte as supplied (no
// SASLprep string preparation). Callers must pre-normalize if needed.
// ══════════════════════════════════════════════════════════════════════════════

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ncp_turn_client.hpp"  // STUN codec/types shared with the client

namespace ncp {
namespace turn {

struct TurnServerConfig {
    std::string bind_ip   = "0.0.0.0";  // listening socket address (IPv4)
    uint16_t    bind_port = 3478;       // 0 => ephemeral; see bound_port()
    std::string relay_ip;               // relayed-address IP; empty => bind_ip

    std::string realm;                  // required, sent in 401/438 challenges

    // Independently supplied long-term credentials: username -> password.
    // Never derived from HopSecret / E2E / mask material.
    std::map<std::string, std::string> users;

    uint32_t default_lifetime    = 600;   // Allocate/Refresh when unspecified
    uint32_t max_lifetime        = 3600;  // cap for requested lifetimes
    uint32_t nonce_lifetime      = 3600;  // seconds; older nonces -> 438
    uint32_t permission_lifetime = 300;   // RFC 5766 §8: 300 s
    uint32_t channel_lifetime    = 600;   // RFC 5766 §11: 600 s

    // Bounded state (fail closed with an error response / drop at the cap).
    size_t max_allocations                = 64;
    size_t max_permissions_per_allocation = 32;
    size_t max_channels_per_allocation    = 16;
    size_t replay_cache_size              = 256;

    // Max datagrams drained per poll() call (work bound per iteration).
    size_t max_datagrams_per_poll = 64;
};

struct TurnServerStats {
    uint64_t allocations_active = 0;      // current live allocations (gauge)
    uint64_t allocations_total = 0;       // successful Allocate count
    uint64_t refresh_total = 0;
    uint64_t deleted_via_refresh = 0;
    uint64_t expired_allocations = 0;     // natural expiry (wall clock)
    uint64_t expired_permissions = 0;
    uint64_t expired_channels = 0;

    uint64_t auth_challenges_401 = 0;     // 401 sent (missing/bad auth)
    uint64_t stale_nonce_438 = 0;         // 438 sent (expired nonce)
    uint64_t bad_nonce_rejected = 0;      // nonce signature invalid
    uint64_t unknown_user_rejected = 0;
    uint64_t bad_realm_rejected = 0;
    uint64_t bad_integrity_rejected = 0;  // MESSAGE-INTEGRITY mismatch

    uint64_t replay_cache_hits = 0;       // retransmitted request -> cached resp
    uint64_t malformed_dropped = 0;       // undecodable datagrams, silent drop
    uint64_t bad_fingerprint_dropped = 0;
    uint64_t no_allocation_dropped = 0;   // data plane from unknown 5-tuple
    uint64_t permission_denied_dropped = 0; // peer traffic w/o permission
    uint64_t unknown_channel_dropped = 0;
    uint64_t quota_rejected = 0;          // 486/508 responses
    uint64_t bad_request_400 = 0;
    uint64_t unsupported_transport_442 = 0;
    uint64_t allocation_mismatch_437 = 0;

    uint64_t send_indications_relayed = 0;
    uint64_t data_indications_sent = 0;
    uint64_t channel_data_to_peer = 0;
    uint64_t channel_data_to_client = 0;
    uint64_t bytes_relayed_to_peer = 0;
    uint64_t bytes_relayed_to_client = 0;
};

class TurnServer {
public:
    explicit TurnServer(TurnServerConfig cfg);
    ~TurnServer();

    TurnServer(const TurnServer&) = delete;
    TurnServer& operator=(const TurnServer&) = delete;

    // Create and bind the non-blocking listening socket. Idempotent.
    bool open(std::string* err = nullptr);

    // Drive the single owner poll loop: drains the listening socket and all
    // relay sockets (bounded per call), performs natural-expiry sweeps.
    // timeout_ms < 0 blocks until a datagram arrives; 0 is non-blocking.
    // Returns the number of datagrams processed, or -1 on error (last_error).
    int poll(int timeout_ms, std::string* err = nullptr);

    // Delete all allocations and close all sockets. Idempotent.
    void close();

    // ── Accessors ────────────────────────────────────────────────────────
    bool is_open() const;
    uint16_t bound_port() const { return bound_port_; }  // actual bound port
    uint32_t relay_addr_be() const { return relay_addr_be_; }
    const TurnServerStats& stats() const { return stats_; }
    std::string last_error() const { return last_error_; }

private:
    struct Allocation;  // pimpl-ish internal state (defined in .cpp)

    void handle_listen_datagram(const uint8_t* data, size_t len,
                                uint32_t src_addr_be, uint16_t src_port);
    void handle_relay_datagram(Allocation& alloc, const uint8_t* data,
                               size_t len, uint32_t peer_addr_be,
                               uint16_t peer_port);

    // Request pipeline (all fail-closed).
    void handle_request(const struct StunMessage& req,
                        uint32_t src_addr_be, uint16_t src_port);
    void handle_indication(const struct StunMessage& ind,
                           uint32_t src_addr_be, uint16_t src_port);

    // Auth: returns true when the request is fully authenticated; on false a
    // 401/438 error response has already been sent (fail closed).
    bool authenticate(const struct StunMessage& req,
                      uint32_t src_addr_be, uint16_t src_port,
                      std::array<uint8_t, 16>* key_out);

    // Per-method handlers. All assume a successfully authenticated request.
    void do_allocate(const struct StunMessage& req,
                     uint32_t src_addr_be, uint16_t src_port,
                     const std::array<uint8_t, 16>& key);
    void do_refresh(const struct StunMessage& req,
                    uint32_t src_addr_be, uint16_t src_port,
                    const std::array<uint8_t, 16>& key);
    void do_create_permission(const struct StunMessage& req,
                              uint32_t src_addr_be, uint16_t src_port,
                              const std::array<uint8_t, 16>& key);
    void do_channel_bind(const struct StunMessage& req,
                         uint32_t src_addr_be, uint16_t src_port,
                         const std::array<uint8_t, 16>& key);

    // Response helpers (cache into the replay cache, then send).
    void send_success(const struct StunMessage& req,
                      uint32_t dst_addr_be, uint16_t dst_port,
                      std::vector<struct StunAttribute> attrs,
                      const uint8_t* mi_key);
    void send_error(const struct StunMessage& req,
                    uint32_t dst_addr_be, uint16_t dst_port,
                    uint32_t code, const char* reason,
                    bool include_realm_nonce,
                    const uint8_t* mi_key);
    void respond(const struct StunMessage& req,
                 uint32_t dst_addr_be, uint16_t dst_port,
                 struct StunMessage& resp, const uint8_t* mi_key);

    // Allocations.
    Allocation* find_allocation(uint32_t addr_be, uint16_t port);
    void destroy_allocation(Allocation& alloc, bool natural_expiry);
    void sweep_expired();

    // Nonce: stateless HMAC-signed timestamp tokens (fail closed).
    std::string make_nonce() const;
    // 0 = valid, 1 = expired (stale -> 438), 2 = invalid (-> 401).
    int validate_nonce(const std::string& nonce) const;

    TurnServerConfig cfg_;
    TurnServerStats  stats_;
    std::string last_error_;

    int      sock_ = -1;               // listening socket (non-blocking)
    uint16_t bound_port_ = 0;
    uint32_t bind_addr_be_ = 0;
    uint32_t relay_addr_be_ = 0;

    std::vector<std::unique_ptr<Allocation>> allocations_;

    // Transaction-id replay response cache (RFC 5389 §7.1 retransmissions):
    // key = src addr|port|txn id, value = exact response bytes.
    std::map<std::string, std::vector<uint8_t>> replay_cache_;
    std::vector<std::string> replay_order_;   // FIFO eviction order

    std::array<uint8_t, 16> nonce_key_{};     // random per open()
    std::vector<uint8_t> rx_buf_;             // recv scratch (no per-call alloc)
};

} // namespace turn
} // namespace ncp

#endif // NCP_TURN_SERVER_HPP
