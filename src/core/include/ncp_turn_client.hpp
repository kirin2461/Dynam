#ifndef NCP_TURN_CLIENT_HPP
#define NCP_TURN_CLIENT_HPP

// ══════════════════════════════════════════════════════════════════════════════
// ncp_turn_client.hpp
//
// G5: REAL TURN-over-UDP client (RFC 5766 / RFC 5769 / RFC 5389), native C++17.
//
// Scope and guarantees:
//   * UDP transport only. No TCP/TLS fallback is implemented or attempted.
//   * Long-term credential mechanism (RFC 5389 §10): 401 Unauthorized ->
//     REALM/NONCE -> MESSAGE-INTEGRITY (HMAC-SHA1 over MD5(user:realm:pass)).
//   * Credentials (username/password) are supplied independently by the caller.
//     They are NEVER derived from HopSecret / E2E keys / traffic-mask material.
//   * Implements: Allocate, CreatePermission, ChannelBind, Refresh (incl.
//     lifetime=0 delete), Send/Data indications (bootstrap path before a
//     channel is bound), and ChannelData application flow (20-byte STUN header
//     vs 4-byte ChannelData framing demux).
//   * Transaction layer with RFC 5389 retransmit bounds, unknown/replayed
//     transaction-id handling, and stale-nonce (438) refresh.
//
// Note on SASLprep: credentials are used byte-for-byte as supplied (no
// SASLprep string preparation). Callers must pre-normalize if needed.
// ══════════════════════════════════════════════════════════════════════════════

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ncp {
namespace turn {

// ── STUN constants (RFC 5389 / RFC 5766) ─────────────────────────────────────

constexpr uint32_t kStunMagicCookie = 0x2112A442u;
constexpr size_t   kStunHeaderSize  = 20;      // STUN message header
constexpr size_t   kChannelDataHeaderSize = 4; // ChannelData framing header

// STUN methods
constexpr uint16_t kMethodBinding          = 0x001;
constexpr uint16_t kMethodAllocate         = 0x003;
constexpr uint16_t kMethodRefresh          = 0x004;
constexpr uint16_t kMethodSend             = 0x006;
constexpr uint16_t kMethodData             = 0x007;
constexpr uint16_t kMethodCreatePermission = 0x008;
constexpr uint16_t kMethodChannelBind      = 0x009;

// STUN attributes
constexpr uint16_t kAttrMappedAddress      = 0x0001;
constexpr uint16_t kAttrUsername           = 0x0006;
constexpr uint16_t kAttrMessageIntegrity   = 0x0008;
constexpr uint16_t kAttrErrorCode          = 0x0009;
constexpr uint16_t kAttrChannelNumber      = 0x000C;
constexpr uint16_t kAttrLifetime           = 0x000D;
constexpr uint16_t kAttrXorPeerAddress     = 0x0012;
constexpr uint16_t kAttrData               = 0x0013;
constexpr uint16_t kAttrRealm              = 0x0014;
constexpr uint16_t kAttrNonce              = 0x0015;
constexpr uint16_t kAttrXorRelayedAddress  = 0x0016;
constexpr uint16_t kAttrRequestedAddressFamily = 0x0017;  // RFC 6156
constexpr uint16_t kAttrEvenPort           = 0x0018;      // RFC 5766 §6.1
constexpr uint16_t kAttrRequestedTransport = 0x0019;
constexpr uint16_t kAttrXorMappedAddress   = 0x0020;
constexpr uint16_t kAttrSoftware           = 0x8022;
constexpr uint16_t kAttrFingerprint        = 0x8028;

// Error codes
constexpr uint32_t kErrorUnauthorized      = 401;
constexpr uint32_t kErrorStaleNonce        = 438;

// Channel number range (RFC 5766 §11)
constexpr uint16_t kChannelNumberMin = 0x4000;
constexpr uint16_t kChannelNumberMax = 0x7FFF;

enum class StunClass : uint8_t {
    Request         = 0,
    Indication      = 1,
    SuccessResponse = 2,
    ErrorResponse   = 3,
};

struct StunAttribute {
    uint16_t type = 0;
    std::vector<uint8_t> value;
};

struct StunMessage {
    uint16_t method = 0;
    StunClass cls = StunClass::Request;
    std::array<uint8_t, 12> txn_id{};
    std::vector<StunAttribute> attributes;

    // Populated by stun_decode():
    std::vector<uint8_t> raw;           // exact received bytes
    size_t integrity_attr_offset = 0;   // offset of MI attr header in raw
    bool has_message_integrity = false;
    bool has_fingerprint = false;

    const StunAttribute* find(uint16_t type) const;
    std::string find_string(uint16_t type) const;
};

// ── Codec (exposed for unit testing; RFC 5769 vectors exercised in tests) ────

// MD5(username ":" realm ":" password) — RFC 5389 §15.4 long-term key.
std::array<uint8_t, 16> long_term_key(const std::string& username,
                                      const std::string& realm,
                                      const std::string& password);

// Encode a STUN message. If mi_key != nullptr, MESSAGE-INTEGRITY (HMAC-SHA1)
// is appended; if add_fingerprint, FINGERPRINT (CRC32 ^ 0x5354554e) is appended
// last. The message header length field is adjusted accordingly.
std::vector<uint8_t> stun_encode(const StunMessage& msg,
                                 const uint8_t* mi_key = nullptr,
                                 size_t mi_key_len = 0,
                                 bool add_fingerprint = true);

// Decode a STUN message (header + attributes). Validates framing, padding,
// magic cookie, and length. Returns false with err set on malformed input.
bool stun_decode(const uint8_t* data, size_t len,
                 StunMessage& out, std::string& err);

// Verify MESSAGE-INTEGRITY of a decoded message using its retained raw bytes.
bool stun_verify_integrity(const StunMessage& msg,
                           const uint8_t* key, size_t key_len);

// Verify FINGERPRINT of a decoded message.
bool stun_verify_fingerprint(const StunMessage& msg);

// CRC32 (ISO 3309, as used by FINGERPRINT) — exposed for tests.
uint32_t stun_crc32(const uint8_t* data, size_t len);

// 20-byte ChannelData framing (RFC 5766 §11.4).
std::vector<uint8_t> channel_data_encode(uint16_t channel,
                                         const uint8_t* payload, size_t len);
// Parse a ChannelData datagram. Returns false if framing invalid.
bool channel_data_decode(const uint8_t* data, size_t len,
                         uint16_t& channel_out,
                         const uint8_t*& payload_out, size_t& payload_len_out);

// Returns true if the datagram is ChannelData (first two bits 01) rather
// than a STUN message (first two bits 00).
bool is_channel_data(const uint8_t* data, size_t len);

// XOR-address attribute helpers (XOR-MAPPED / XOR-RELAYED / XOR-PEER).
// IPv4 only for peer/relay addresses (see class doc: UDP/IPv4 relay scope).
std::vector<uint8_t> encode_xor_address_ipv4(uint32_t addr_be, uint16_t port,
                                             const std::array<uint8_t, 12>& txn_id);
bool decode_xor_address_ipv4(const StunAttribute& attr,
                             const std::array<uint8_t, 12>& txn_id,
                             uint32_t& addr_be_out, uint16_t& port_out);

// ── TURN client ──────────────────────────────────────────────────────────────

enum class TurnState {
    Idle,        // socket not open / not started
    Allocating,  // Allocate transaction in flight
    Allocated,   // allocation active (relayed address known)
    Bound,       // at least one channel bound
    Closed,      // allocation deleted / socket closed
    Failed,      // unrecoverable error (see last_error())
};

struct TurnConfig {
    std::string server_address;      // dotted IPv4 or hostname of TURN server
    uint16_t    server_port = 3478;

    // Independently supplied long-term credentials. Never derived from
    // HopSecret / E2E key material / traffic masks.
    std::string username;
    std::string password;

    uint32_t requested_lifetime = 600;   // seconds, Allocate/Refresh
    uint16_t requested_channel  = 0;     // 0 => auto-pick from kChannelNumberMin

    // RFC 5389 §7.2.1 retransmission policy (UDP):
    //   send, wait rto_ms, retransmit doubling the wait (capped at
    //   rto_ms * rto_cap_multiplier), give up after max_retransmits sends.
    int rto_ms              = 500;
    int max_retransmits     = 7;         // Rc
    int rto_cap_multiplier  = 16;        // Rm

    // Maximum relayed application datagrams buffered while the caller is not
    // in poll(). Additional datagrams are dropped and counted; zero disables
    // buffering. This bound also applies while transactions are in flight.
    size_t max_pending_rx = 256;
};

struct TurnReceivedData {
    bool        via_channel = false;   // true: ChannelData; false: Data indication
    uint16_t    channel = 0;           // channel number when via_channel
    uint32_t    peer_addr_be = 0;      // peer IPv4 (network byte order) for Data ind.
    uint16_t    peer_port = 0;
    std::vector<uint8_t> payload;
};

struct TurnStats {
    uint64_t retransmits = 0;          // retransmitted requests
    uint64_t timeouts = 0;             // transactions that exhausted retransmits
    uint64_t unknown_txn_dropped = 0;  // responses with unknown transaction id
    uint64_t replayed_txn_dropped = 0; // re-delivered responses (recent txn ids)
    uint64_t bad_integrity_dropped = 0;
    uint64_t channel_data_rx = 0;
    uint64_t data_indication_rx = 0;
    uint64_t pending_rx_dropped_queue_full = 0;
};

class TurnClient {
public:
    explicit TurnClient(TurnConfig cfg);
    ~TurnClient();

    TurnClient(const TurnClient&) = delete;
    TurnClient& operator=(const TurnClient&) = delete;

    // Open the UDP socket and (if needed) resolve server_address. No traffic
    // is sent. Idempotent.
    bool open(std::string* err = nullptr);

    // Allocate a relay address. Handles the 401 Unauthorized long-term
    // credential handshake internally (nonce/realm acquisition + retry with
    // MESSAGE-INTEGRITY). Blocking with retransmission bounds from config.
    bool allocate(std::string* err = nullptr);

    // Install a permission for a peer (required before the peer's traffic is
    // relayed). port=0 permits any port from that address on the wire, but we
    // always send a concrete port here for interoperability clarity.
    bool create_permission(uint32_t peer_addr_be, uint16_t peer_port,
                           std::string* err = nullptr);
    bool create_permission(const std::string& peer_ip, uint16_t peer_port,
                           std::string* err = nullptr);

    // Bind a channel (0x4000-0x7FFF) to a peer. channel=0 uses
    // config.requested_channel (or auto-picks).
    bool channel_bind(uint32_t peer_addr_be, uint16_t peer_port, uint16_t channel,
                      std::string* err = nullptr);
    bool channel_bind(const std::string& peer_ip, uint16_t peer_port, uint16_t channel,
                      std::string* err = nullptr);

    // Refresh the allocation. lifetime=0 deletes it (allocation closed).
    bool refresh(uint32_t lifetime, std::string* err = nullptr);

    // Bootstrap-only data path: Send indication to a peer before a channel
    // bind. Once a channel is bound, established application flow must use
    // send_channel_data(); this method then fails closed. Peer bootstrap
    // replies arrive as Data indications via poll().
    bool send_indication(uint32_t peer_addr_be, uint16_t peer_port,
                         const uint8_t* data, size_t len, std::string* err = nullptr);
    bool send_indication(const std::string& peer_ip, uint16_t peer_port,
                         const uint8_t* data, size_t len, std::string* err = nullptr);

    // ChannelData data path: requires a successful channel_bind().
    bool send_channel_data(const uint8_t* data, size_t len, std::string* err = nullptr);

    // Receive relayed application data (ChannelData on the bound channel and
    // Data indications). timeout_ms<0 blocks indefinitely; 0 is non-blocking.
    bool poll(int timeout_ms, std::vector<TurnReceivedData>* out,
              std::string* err = nullptr);

    // Delete allocation (best effort) and close the socket.
    void close();

    // ── Accessors ────────────────────────────────────────────────────────
    TurnState  state() const { return state_; }
    const TurnStats& stats() const { return stats_; }
    std::string last_error() const { return last_error_; }
    uint32_t relayed_addr_be() const { return relayed_addr_be_; }
    uint16_t relayed_port() const { return relayed_port_; }
    uint32_t granted_lifetime() const { return granted_lifetime_; }
    const std::string& realm() const { return realm_; }
    const std::string& nonce() const { return nonce_; }
    bool has_credentials_context() const { return have_key_; }

    // Seconds until the allocation expires, from last granted lifetime.
    // Returns 0 when no allocation or already expired.
    uint32_t lifetime_remaining() const;

private:
    // One STUN transaction: encode (with MI if authenticated), send with
    // retransmissions, demux incoming datagrams until a matching response or
    // timeout. Handles 401/438 re-authentication internally when
    // allow_auth_retry is set.
    bool transact(StunMessage& req, StunMessage& resp,
                  bool allow_auth_retry, std::string& err);

    bool send_request(StunMessage& req, std::string& err);
    bool wait_response(const std::array<uint8_t, 12>& txn_id,
                       int timeout_ms, StunMessage& resp, bool& got_response,
                       std::string& err);

    // Handle one received datagram: demux STUN vs ChannelData, enqueue app
    // data, match transactions, drop unknown/replayed txn ids.
    // Returns true when resp was filled with the awaited response.
    bool handle_datagram(const uint8_t* data, size_t len,
                         const std::array<uint8_t, 12>* awaited_txn,
                         StunMessage& resp, bool& matched);

    bool apply_auth_attributes(StunMessage& req);
    void enqueue_received(TurnReceivedData&& rx);
    bool parse_error_code(const StunMessage& msg, uint32_t& code_out) const;
    bool ensure_open(std::string& err);
    bool ensure_allocated(std::string& err);
    void set_failed(const std::string& err);

    static bool parse_ipv4(const std::string& ip, uint32_t& addr_be);

    TurnConfig cfg_;
    TurnState  state_ = TurnState::Idle;
    TurnStats  stats_;
    std::string last_error_;

    int sock_ = -1;
    uint32_t server_addr_be_ = 0;
    uint16_t server_port_ = 0;

    // Long-term credential context (filled after first 401).
    bool have_key_ = false;
    std::string realm_;
    std::string nonce_;
    std::array<uint8_t, 16> key_{};   // MD5(user:realm:pass)

    // Allocation state.
    uint32_t relayed_addr_be_ = 0;
    uint16_t relayed_port_ = 0;
    uint32_t granted_lifetime_ = 0;
    std::chrono::steady_clock::time_point lifetime_granted_at_{};

    // Bound channel (single-channel client scope for G5).
    bool     channel_bound_ = false;
    uint16_t channel_number_ = 0;
    uint32_t peer_addr_be_ = 0;
    uint16_t peer_port_ = 0;

    // Recently completed transaction ids (replay window).
    std::deque<std::array<uint8_t, 12>> recent_txn_order_;
    std::set<std::array<uint8_t, 12>>   recent_txn_ids_;
    static constexpr size_t kRecentTxnWindow = 32;

    // Application data received while waiting for transaction responses.
    std::vector<TurnReceivedData> pending_rx_;

    // Random transaction id generation.
    std::array<uint8_t, 12> make_txn_id();
    uint64_t rng_state_ = 0;
};

} // namespace turn
} // namespace ncp

#endif // NCP_TURN_CLIENT_HPP
