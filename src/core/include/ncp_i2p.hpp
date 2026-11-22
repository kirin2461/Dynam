#ifndef NCP_I2P_HPP
#define NCP_I2P_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <map>
#include <deque>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <functional>

namespace ncp {

// ===== Inbound peer policy (server-side self-defence) ======================
//
// Decides whether an inbound I2P stream from `peer_dest` should be accepted.
// This is pure policy logic (no sockets), so it is unit-testable without a
// running SAM bridge. I2PManager::accept_inbound_stream() applies it to every
// accepted stream.
//
// Destinations are compared verbatim (after trimming surrounding whitespace).
// I2P base64 destinations are case-sensitive, so no case folding is applied.
class I2PPeerFilter {
public:
    struct Decision {
        bool allow = true;
        const char* reason = "allowed";   ///< static string — safe to log
    };

    struct Config {
        /// If non-empty, ONLY these destinations are accepted.
        std::vector<std::string> allowlist;
        /// Always rejected (checked before the allowlist).
        std::vector<std::string> blocklist;
        /// Max concurrently open inbound streams per peer (0 = unlimited).
        size_t max_concurrent_per_peer = 8;
        /// Max new streams per peer within `rate_window` (0 = unlimited).
        size_t max_new_per_window = 60;
        /// Sliding window for max_new_per_window.
        std::chrono::seconds rate_window{60};
    };

    I2PPeerFilter();
    explicit I2PPeerFilter(const Config& config);

    void set_config(const Config& config);
    Config get_config() const;

    /// Decide on a new inbound stream. Thread-safe. When the decision is
    /// "allow", the stream is recorded as open until release() is called.
    Decision check(const std::string& peer_dest,
                   std::chrono::system_clock::time_point now);

    /// Mark a previously accepted stream as closed.
    void release(const std::string& peer_dest);

    size_t accepted_count() const;
    size_t rejected_count() const;
    std::vector<std::string> blocked_peers() const;
    void reset_counters();

private:
    struct PeerState {
        size_t open = 0;
        std::deque<std::chrono::system_clock::time_point> recent;
    };

    static std::string normalize_dest(const std::string& dest);

    mutable std::mutex mutex_;
    Config config_;
    std::unordered_set<std::string> allow_;
    std::unordered_set<std::string> block_;
    std::map<std::string, PeerState> peers_;
    size_t accepted_ = 0;
    size_t rejected_ = 0;
};

// ===== Outbound connection policy (client-side self-defence) ===============
//
// Decides whether the client may open an outbound stream to `dest` from
// `session_id`. All the work happens before a socket is touched, so it is
// unit-testable without a SAM bridge.
//
// Two defences beyond an allow/block list:
//   - format validation: catches malformed destinations before they are
//     interpolated into a SAM command line;
//   - first-use pinning: the first destination a session connects to is
//     remembered; a later attempt from the same session to a different
//     destination is refused unless the operator allowlisted it. That is the
//     server-impersonation case — a tunnel cannot silently be re-pointed.
class I2POutboundPolicy {
public:
    struct Decision {
        bool allow = true;
        const char* reason = "allowed";   ///< static string — safe to log
    };

    struct Config {
        /// If non-empty, ONLY these destinations may be dialled. Disables
        /// pinning (an explicit list already fixes the set).
        std::vector<std::string> allowlist;
        /// Never dialled (checked before everything else).
        std::vector<std::string> blocklist;
        /// Remember the first destination used per session and refuse changes.
        bool pin_first_destination = true;
        /// Require hostname (`.i2p`) or base64 destination shape.
        bool validate_format = true;
    };

    struct Pin {
        std::string session_id;
        std::string destination;
        std::chrono::system_clock::time_point pinned_at;
    };

    I2POutboundPolicy();
    explicit I2POutboundPolicy(const Config& config);

    void set_config(const Config& config);
    Config get_config() const;

    /// Trim outer whitespace; used for both comparison and the SAM command.
    static std::string normalize_destination(const std::string& dest);

    /// Hostname or base64-destination shape check (no whitespace/control
    /// bytes, sane label or alphabet).
    static bool valid_destination_format(const std::string& dest);

    Decision check(const std::string& session_id, const std::string& dest) const;

    /// Record the destination a session is now bound to. Never overwrites an
    /// existing different pin — call unpin()/clear_pins() for legitimate
    /// rotation.
    void pin(const std::string& session_id, const std::string& dest);
    bool is_pinned(const std::string& session_id) const;
    bool pinned_destination(const std::string& session_id,
                            std::string& out_dest) const;
    std::vector<Pin> pins() const;
    void unpin(const std::string& session_id);
    void clear_pins();

private:
    mutable std::mutex mutex_;
    Config config_;
    std::unordered_set<std::string> allow_;
    std::unordered_set<std::string> block_;
    std::map<std::string, Pin> pins_;
};

class I2PManager {
public:
    enum class TunnelType {
        CLIENT,
        SERVER,
        BIDIRECTIONAL
    };

    enum class EncryptionLayer {
        GARLIC_ROUTING,     // End-to-end encryption through multiple hops
        ELGAMAL_AES,        // ElGamal/AES+SessionTag encryption
        NTCP2,              // Transport layer encryption
        SSU2                // UDP-based encrypted transport
    };

    struct Config {
        bool enabled = false;
        std::string sam_host = "127.0.0.1";
        uint16_t sam_port = 7656;
        std::string proxy_host = "127.0.0.1";
        uint16_t proxy_port = 4444;
        bool use_http_proxy = true;
        
        // Advanced I2P features
        bool enable_garlic_routing = true;
        int tunnel_length = 3;           // Hops per tunnel (default 3)
        int tunnel_quantity = 2;         // Number of parallel tunnels
        int tunnel_backup_quantity = 1;  // Backup tunnels
        bool enable_multihoming = true;  // Multiple transport protocols
        bool enable_floodfill = false;   // Act as network database node
        
        // Encryption preferences
        EncryptionLayer primary_encryption = EncryptionLayer::GARLIC_ROUTING;
        bool enable_ntcp2 = true;
        bool enable_ssu2 = true;
        
        // Anonymity enhancements
        bool random_tunnel_selection = true;
        bool obfuscate_tunnel_messages = true;
        int mix_delay_ms = 50;           // Message mixing delay
        bool enable_dummy_traffic = true; // Padding/dummy messages
        
        // Network database protection
        bool enable_encrypted_leaseset = true;
        bool enable_blinded_destinations = true;
        int destination_expiration_hours = 24;

        // Cover traffic
        size_t cover_traffic_bytes_per_minute = 0;
        int tunnel_build_rate_per_minute = 2;
    };

    struct TunnelInfo {
        std::string tunnel_id;
        TunnelType type;
        std::string local_dest;
        std::string remote_dest;
        std::vector<std::string> hops;   // List of router hashes in tunnel
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point expires;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        bool is_backup = false;
    };

    struct GarlicClove {
        std::string destination;
        std::vector<uint8_t> payload;
        uint32_t clove_id;
        std::chrono::system_clock::time_point expiration;
    };

    I2PManager();
    ~I2PManager();

    bool initialize(const Config& config);
    bool is_active() const;
    void set_enabled(bool enabled);

    // Destination management
    std::string get_destination() const;
    std::string create_ephemeral_destination();
    bool import_destination(const std::string& private_keys);
    std::string export_destination() const;
    
    // Advanced tunnel creation
    bool create_tunnel(const std::string& name, uint16_t local_port, 
                      const std::string& remote_dest, TunnelType type = TunnelType::CLIENT);
    bool create_server_tunnel(const std::string& name, uint16_t local_port);
    std::vector<TunnelInfo> get_active_tunnels() const;
    bool destroy_tunnel(const std::string& tunnel_id);
    
    // Garlic routing (end-to-end encryption)
    std::vector<uint8_t> create_garlic_message(const std::vector<GarlicClove>& cloves,
                                                const std::string& dest_public_key);
    bool send_garlic_message(const std::string& destination, 
                            const std::vector<uint8_t>& message);
    
    // Network database operations
    std::string lookup_destination(const std::string& hostname);
    bool publish_leaseset(bool encrypted = true, bool blinded = false);
    std::vector<std::string> get_floodfill_routers() const;
    
    // Traffic obfuscation
    void enable_traffic_mixing(bool enable, int delay_ms = 50);
    void send_dummy_traffic(size_t bytes_per_second);
    std::vector<uint8_t> pad_message(const std::vector<uint8_t>& msg, size_t target_size);
    
    // Tunnel management and rotation
    void rotate_tunnels();
    void set_tunnel_build_rate(int tunnels_per_minute);
    bool use_exploratory_tunnels() const;
    
    // Statistics and monitoring (anonymized)
    struct Statistics {
        uint64_t total_sent = 0;
        uint64_t total_received = 0;
        size_t active_tunnels = 0;
        size_t known_routers = 0;
        double tunnel_success_rate = 0.0;
        std::chrono::milliseconds avg_tunnel_latency{0};
        uint64_t peers_rejected = 0;   ///< inbound peers refused by the filter
        uint64_t peers_accepted = 0;   ///< inbound peers admitted by the filter
        uint64_t outbound_established = 0; ///< outbound streams that connected
        uint64_t outbound_rejected = 0;    ///< outbound attempts blocked by policy
        uint64_t outbound_failed = 0;      ///< outbound attempts that errored
    };
    Statistics get_statistics() const;
    
    // Multihoming support (NTCP2 + SSU2)
    bool enable_transport(EncryptionLayer transport);
    std::vector<EncryptionLayer> get_active_transports() const;
    
    // Advanced anonymity features
    void set_profile_mode(const std::string& mode); // "high_security", "balanced", "performance"
    bool enable_path_selection_randomization(bool enable);
    void set_cover_traffic_rate(size_t bytes_per_minute);

    // ===== Server-side inbound handling ==================================
    //
    // A server tunnel only becomes reachable once someone runs STREAM ACCEPT
    // on its session. accept_inbound_stream() opens a dedicated SAM control
    // connection, waits for one peer (bounded by timeout_seconds), applies the
    // peer filter, and hands back a raw stream handle for read/close.
    void set_peer_filter(const I2PPeerFilter::Config& config);
    I2PPeerFilter::Config get_peer_filter_config() const;
    size_t rejected_peer_count() const;
    size_t accepted_peer_count() const;

    /// Observes every inbound peer as it is accepted or rejected. Fired from
    /// accept_inbound_stream() outside all internal locks, so the callback may
    /// log, persist or raise UI events. `reason` is a static string.
    using InboundPeerCallback =
        std::function<void(const std::string& peer_dest, bool allowed,
                           const char* reason)>;
    void set_inbound_peer_callback(InboundPeerCallback cb);

    // ===== Client-side outbound handling ==================================
    //
    // connect_outbound_stream() opens a dedicated SAM connection, issues
    // STREAM CONNECT, checks the destination against I2POutboundPolicy and
    // returns a stream handle. The policy is consulted before the bridge is
    // touched, so a blocked destination never leaves the process.
    void set_outbound_policy(const I2POutboundPolicy::Config& config);
    I2POutboundPolicy::Config get_outbound_policy() const;
    std::vector<I2POutboundPolicy::Pin> pinned_destinations() const;
    void clear_pinned_destinations();

    struct OutboundRecord {
        uint64_t id = 0;
        std::string session_id;
        std::string destination;
        bool established = false;
        const char* reason = "allowed";  ///< static string
        uint64_t bytes_sent = 0;         ///< filled in when the stream closes
        std::chrono::system_clock::time_point timestamp;
    };

    /// Observes every outbound attempt: blocked, failed or established.
    using OutboundEventCallback = std::function<void(const OutboundRecord&)>;
    void set_outbound_event_callback(OutboundEventCallback cb);

    /// Oldest-to-newest audit trail of outbound attempts (bounded ring).
    std::vector<OutboundRecord> outbound_history(size_t max_count = 64) const;

    /// Returns >= 0 on success (opaque handle), -1 when the policy refused the
    /// destination, the bridge failed, or the connected peer did not match a
    /// full base64 destination.
    intptr_t connect_outbound_stream(const std::string& session_id,
                                     const std::string& dest,
                                     int timeout_seconds = 30);
    /// Send bytes on an outbound stream. Returns bytes written, or -1.
    ptrdiff_t write_outbound_stream(intptr_t handle, const void* buf, size_t len);
    /// Receive bytes. >0 bytes, 0 = peer closed, -1 = error.
    ptrdiff_t read_outbound_stream(intptr_t handle, void* buf, size_t len);
    /// Close the stream and fold its byte count into the audit record.
    bool close_outbound_stream(intptr_t handle);

    /// Returns >= 0 on success (opaque handle), -1 on timeout/SAM error or
    /// when the peer was rejected by the filter. `peer_dest` receives the
    /// connecting destination (empty on failure).
    intptr_t accept_inbound_stream(const std::string& session_id,
                                   std::string& peer_dest,
                                   int timeout_seconds = 30);
    /// Read from an accepted stream. >0 bytes, 0 = peer closed, -1 = error.
    ptrdiff_t read_inbound_stream(intptr_t handle, void* buf, size_t len);
    /// Close an accepted stream and release it from the peer filter.
    bool close_inbound_stream(intptr_t handle);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    
    Config config_;
    bool is_initialized_ = false;
    std::string current_dest_;
    std::map<std::string, TunnelInfo> tunnels_;

    // FIX #95: Mutex protecting tunnels_, config_, current_dest_
    // Used by create_tunnel(), destroy_tunnel(), rotate_tunnels(),
    // get_active_tunnels(), get_statistics(), enable_traffic_mixing().
    // Mutable so const methods (get_active_tunnels, get_statistics) can lock.
    mutable std::mutex mutex_;

    // Active transports tracking
    std::vector<EncryptionLayer> active_transports_;

    // Inbound peer policy + live accepted-stream bookkeeping.
    I2PPeerFilter peer_filter_;
    mutable std::mutex inbound_mutex_;
    std::map<intptr_t, std::string> inbound_peers_;  // handle -> peer dest
    InboundPeerCallback inbound_cb_;

    // Outbound policy + live outbound-stream bookkeeping / audit ring.
    I2POutboundPolicy outbound_policy_;
    mutable std::mutex outbound_mutex_;

    enum class OutboundOutcome : uint8_t {
        ESTABLISHED = 0,
        REJECTED = 1,
        FAILED = 2
    };

    struct OutboundStream {
        uint64_t id = 0;
        std::string session_id;
        std::string destination;
        uint64_t bytes_sent = 0;
        std::chrono::system_clock::time_point started;
    };

    uint64_t emit_outbound(const std::string& session_id,
                           const std::string& dest,
                           OutboundOutcome outcome, const char* reason);

    std::map<intptr_t, OutboundStream> outbound_streams_;
    std::deque<OutboundRecord> outbound_ring_;
    static constexpr size_t kOutboundRingCapacity = 128;
    OutboundEventCallback outbound_cb_;
    uint64_t next_outbound_id_ = 1;
    uint64_t outbound_established_ = 0;
    uint64_t outbound_rejected_ = 0;
    uint64_t outbound_failed_ = 0;
    
    // Internal tunnel operations
    std::vector<std::string> select_tunnel_hops(int length);
    bool build_tunnel(const std::vector<std::string>& hops, TunnelType type);
    void maintain_tunnel_pool();
    
    // Encryption helpers
    // FAIL-CLOSED: returns an empty vector on any error (bad key, failed
    // DH/AEAD). Callers MUST check for empty and must NOT send `data`
    // unencrypted in that case.
    std::vector<uint8_t> encrypt_garlic_layer(const std::vector<uint8_t>& data,
                                              const std::string& hop_pubkey);
    std::vector<uint8_t> create_session_tag();
    
    // Network database cache
    std::map<std::string, std::string> netdb_cache_;
    std::chrono::system_clock::time_point last_netdb_update_;
    
    void schedule_tunnel_rotation();
    void inject_dummy_message();
};

} // namespace ncp

#endif // NCP_I2P_HPP
