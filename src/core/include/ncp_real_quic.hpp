#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP REAL QUIC transport (G4) — production wrapper over the MsQuic C API.
//
// Unlike ncp_quic.hpp (fake Initial generator for DPI desync), this module
// performs REAL TLS 1.3 QUIC handshakes and transports real application data
// over a single, fixed UDP path (fixed local address/port, fixed remote
// address/port, QUIC migration disabled, no port hopping of any kind).
//
// Security posture:
//   * Real TLS 1.3 handshake via MsQuic (OpenSSL backend on Linux).
//   * Client verifies the server certificate chain against the system CA
//     store by default; an explicit CA file may be configured, and an
//     explicit TEST-ONLY insecure mode exists (insecure_skip_verify) which
//     must never be enabled in production builds.
//   * No fake wire masks, no plaintext fallback: anything that is not a
//     valid QUIC/TLS handshake is rejected by the TLS/QUIC layer and never
//     surfaced as application data.
//
// Data model (focused, interoperable):
//   * Message API: one application message == one reliable bidirectional
//     stream. The sender transmits the payload and half-closes (FIN); the
//     receiver gets the fully assembled payload after FIN. respond() writes
//     back on the same stream, which is the classic QUIC echo pattern and
//     interoperates with other stacks (ngtcp2, aioquic, quiche).
//   * Optional QUIC DATAGRAM (RFC 9221) API when enable_datagrams is set.
//
// Threading: MsQuic invokes callbacks on its own worker threads; this class
// translates them into a bounded, mutex/condition-variable protected
// poll/wait API. The destructor performs a clean, ordered shutdown and never
// leaves callbacks referencing freed memory. No global or strategy state is
// used; each instance owns its MsQuic registration.
// ═══════════════════════════════════════════════════════════════════════════

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ncp {

class RealQuicEndpoint {
public:
    enum class Role { Client, Server };

    struct Config {
        Role role = Role::Client;

        // ALPN negotiated for this application protocol.
        std::string alpn = "ncp-echo";
        // MsQuic registration (execution profile) name.
        std::string app_name = "ncp-real-quic";

        // ---- Fixed local UDP path (both roles) ----
        // Empty = wildcard/any. Use e.g. "127.0.0.1" for loopback pinning.
        std::string local_address;
        // 0 = ephemeral. The port never changes for the lifetime of the
        // endpoint: no PortHop, no scheduled hopping.
        uint16_t local_port = 0;

        // ---- Fixed remote UDP path (client role only) ----
        std::string remote_address;     // e.g. "127.0.0.1" or a DNS name
        uint16_t remote_port = 0;
        // TLS SNI / certificate verification hostname.
        // Defaults to remote_address when empty.
        std::string server_name;

        // ---- TLS credentials ----
        // Server role: PEM certificate chain and private key files (required).
        std::string certificate_file;
        std::string private_key_file;
        // Client role: optional PEM CA bundle used to verify the server
        // certificate (OpenSSL backend). When empty and insecure_skip_verify
        // is false, the system default CA store is used.
        std::string ca_file;
        // TEST ONLY: disables all server certificate validation on the
        // client. Never set this in production; it exists so loopback tests
        // can use ad-hoc self-signed certificates.
        bool insecure_skip_verify = false;

        // ---- Transport tuning ----
        uint32_t idle_timeout_ms = 30000;
        uint16_t peer_bidi_stream_count = 64;
        uint16_t peer_unidi_stream_count = 0;
        bool enable_datagrams = false;  // RFC 9221 QUIC DATAGRAM

        // ---- Bounded queues (backpressure/drop policy) ----
        size_t max_inbound_messages = 256;    // assembled stream messages
        size_t max_message_size = 1u << 20;   // per-message byte cap
        size_t max_inbound_datagrams = 256;
    };

    struct Message {
        uint64_t connection_id = 0;  // server: accepted-connection id; client: 0
        uint64_t stream_id = 0;      // QUIC stream id carrying the message
        std::vector<uint8_t> payload;
    };

    struct Datagram {
        uint64_t connection_id = 0;
        std::vector<uint8_t> payload;
    };

    struct Stats {
        uint64_t messages_received = 0;
        uint64_t messages_dropped_queue_full = 0;
        uint64_t datagrams_received = 0;
        uint64_t datagrams_dropped_queue_full = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
    };

    explicit RealQuicEndpoint(Config cfg);
    ~RealQuicEndpoint();

    RealQuicEndpoint(const RealQuicEndpoint&) = delete;
    RealQuicEndpoint& operator=(const RealQuicEndpoint&) = delete;
    RealQuicEndpoint(RealQuicEndpoint&&) = delete;
    RealQuicEndpoint& operator=(RealQuicEndpoint&&) = delete;

    // Client: opens the connection and starts the TLS 1.3 handshake
    // (asynchronous; use wait_connected). Server: binds the fixed local UDP
    // address/port and starts listening.
    bool start();

    // Idempotent clean shutdown. Also performed by the destructor.
    void shutdown();

    // Client: waits until the handshake completes (true) or fails/timeout.
    // Server: waits until the first client handshake completes.
    bool wait_connected(uint32_t timeout_ms);

    // Server only: waits for the next accepted + handshaken client
    // connection; returns its connection id (> 0) or 0 on timeout.
    uint64_t wait_connection(uint32_t timeout_ms);

    // Opens a new bidirectional stream on the given connection (client: 0),
    // sends the payload and half-closes (FIN). Returns the QUIC stream id
    // via stream_id_out when non-null. Fails if the payload exceeds
    // max_message_size or the endpoint is not connected.
    bool send_message(const std::vector<uint8_t>& payload,
                      uint64_t* stream_id_out = nullptr,
                      uint64_t connection_id = 0);

    // Receives the next fully-assembled inbound message (payload received
    // with FIN on a peer stream). Returns false on timeout.
    bool recv_message(Message& out, uint32_t timeout_ms);

    // Writes a response payload + FIN back on the stream that delivered a
    // message (echo pattern). The stream is looked up by connection id and
    // stream id from the received Message.
    bool respond(uint64_t connection_id, uint64_t stream_id,
                 const std::vector<uint8_t>& payload);

    // ---- Optional QUIC DATAGRAM API (requires enable_datagrams) ----
    bool send_datagram(const std::vector<uint8_t>& payload,
                       uint64_t connection_id = 0);
    bool recv_datagram(Datagram& out, uint32_t timeout_ms);
    // Maximum payload that currently fits a single QUIC datagram (0 when
    // datagrams are not negotiated/yet available).
    uint16_t datagram_max_send_length() const;

    // ---- State / diagnostics ----
    Role role() const noexcept;          // immutable configured endpoint role
    bool is_running() const;
    bool is_connected() const;          // at least one handshake completed
    std::string last_error() const;     // last transport/TLS error, if any
    Stats stats() const;

    // Fixed-path introspection (for tests/audits).
    uint16_t bound_local_port() const;  // actual bound UDP port after start()
    std::string local_address_str() const;   // "ip:port" of the local path
    std::string remote_address_str() const;  // "ip:port" of the peer path (client)

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ncp
