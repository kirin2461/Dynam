#pragma once

/**
 * @file ncp_server_roster.hpp
 * @brief Server-side record of which clients connected, and whether they
 *        came from the server's own LAN.
 *
 * Threat addressed: "is a machine on my local network connecting to my
 * server?" A client that reaches you from inside your own subnet is not
 * an anonymous internet peer — it is a device on your LAN, and in the
 * common colocation case it is the server host itself. That distinction
 * is invisible in per-session state because a session only knows its
 * remote address; deciding "near" requires the set of local subnets.
 *
 * Two things are deliberately NOT claimed here:
 *
 *  - A LAN origin is not evidence of compromise. Legitimate clients on
 *    the same subnet are normal. The roster reports it so you can look.
 *  - Addresses can be spoofed on-path, but completing the handshake
 *    requires answering a reply, and a blind spoofer cannot. So an entry
 *    in this roster means "someone who could actually talk to me", which
 *    is a stronger statement than a packet log.
 *
 * Attribution is deliberately weak: sessions are keyed by the client's
 * ephemeral E2E public key (the same value PortHop/MimicrySession binds),
 * NOT by a stable account identity. Requiring a stable per-user identity
 * is a separate design decision (see docs/SERVER_IDENTITY.md) because it
 * trades away the anonymity this project exists to provide.
 *
 * Threading: ServerRoster::record_connection / record_disconnect are
 * called from the datagram poll loop; snapshot() and find() are safe to
 * call from a GUI/web thread. All public methods lock.
 */

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ncp {

/// How a recorded address relates to the server's own subnets.
enum class Locality {
    Unknown,   ///< the client address could not be parsed
    Loopback,  ///< 127.0.0.0/8 or ::1 — the server host itself
    Lan,       ///< inside a subnet configured on one of our interfaces
    External   ///< routed, not on any local subnet
};

const char* locality_to_string(Locality l) noexcept;

/// One contiguous local subnet, as configured on an interface.
struct LocalSubnet {
    std::string interface_name;
    std::string network;      ///< canonical form, e.g. "192.168.1.0"
    uint8_t prefix_len = 0;   ///< 0..32 for IPv4, 0..128 for IPv6
    bool is_ipv6 = false;

    /// "192.168.1.0/24"
    std::string to_string() const;
};

/**
 * @brief Parse "a.b.c.d/len" (or a bare address, treated as /32).
 *        Returns false on malformed input. host bits are cleared.
 */
bool parse_local_subnet(const std::string& cidr,
                        std::string& network_out,
                        uint8_t& prefix_out,
                        bool& is_ipv6_out);

/**
 * @brief Classify an address against a subnet list.
 *
 * Host bits in `address` are irrelevant. An unparsable address yields
 * Unknown, never External — "I could not tell" must not be reported as
 * "it is definitely remote".
 */
Locality classify_address(const std::string& address,
                          const std::vector<LocalSubnet>& subnets);

/// Discover the subnets configured on this host's interfaces.
/// Read-only, no packets sent. Returns an empty vector on total failure.
/// `include_loopback` is honoured only for the purpose of reporting; the
/// classifier treats loopback as Loopback regardless.
std::vector<LocalSubnet> discover_local_subnets(bool include_loopback = false);

/// One recorded client connection.
struct RosterEntry {
    std::string client_key_hex;   ///< client E2E public key; the roster key
    std::string address;          ///< last observed address
    uint16_t port = 0;            ///< last observed source port
    Locality locality = Locality::Unknown;
    std::string matched_subnet;   ///< subnet that produced Locality::Lan
    std::chrono::system_clock::time_point first_seen{};
    std::chrono::system_clock::time_point last_seen{};
    uint64_t connections = 0;     ///< handshakes from this key
    bool connected = false;       ///< true while a session is live
};

/// Filter for snapshot().
struct RosterFilter {
    /// Only entries classified Lan / Loopback. Used by `ncp roster --local`.
    bool local_only = false;
    /// Only live sessions.
    bool connected_only = false;
};

/**
 * @brief Bounded, thread-safe server connection roster.
 *
 * Bounded because it is fed by unauthenticated-ish network events: an
 * attacker who completes many handshakes could otherwise grow this
 * without limit. When full, the least-recently-seen disconnected entry
 * is evicted; if every entry is connected, new entries are refused and
 * counted in dropped_full() rather than evicting a live session.
 */
class ServerRoster {
public:
    static constexpr size_t kDefaultCapacity = 4096;

    explicit ServerRoster(size_t capacity = kDefaultCapacity);
    ~ServerRoster();
    ServerRoster(const ServerRoster&) = delete;
    ServerRoster& operator=(const ServerRoster&) = delete;

    /// Replace the subnet list (e.g. after a DHCP lease change or a
    /// config reload). Until this is called, locality is Unknown.
    void set_local_subnets(std::vector<LocalSubnet> subnets);
    std::vector<LocalSubnet> local_subnets() const;

    /**
     * @brief Record a completed handshake.
     *
     * @param client_key      Client's E2E public key (32 bytes). Empty or
     *                        wrong-sized keys are recorded under a
     *                        synthetic "unknown:<address>" key rather than
     *                        dropped, so a rogue peer is still visible.
     * @param address         Remote address as reported by the transport.
     * @param port            Remote source port.
     */
    void record_connection(const std::vector<uint8_t>& client_key,
                           const std::string& address,
                           uint16_t port);

    /// Mark a key's session closed. Keeps the entry for the record.
    void record_disconnect(const std::string& client_key_hex);

    /// Re-classify an entry's address without touching session state.
    void update_address(const std::string& client_key_hex,
                        const std::string& address,
                        uint16_t port);

    bool find(const std::string& client_key_hex, RosterEntry& out) const;

    std::vector<RosterEntry> snapshot(const RosterFilter& filter = {}) const;

    size_t size() const;
    size_t connected_count() const;
    size_t dropped_full() const;

    void clear();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// The roster key for a client public key, or a synthetic key when the
/// public key is unusable. Exposed so tests and callers agree on it.
std::string roster_key_for(const std::vector<uint8_t>& client_key,
                           const std::string& address);

} // namespace ncp
