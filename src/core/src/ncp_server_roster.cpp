/**
 * @file ncp_server_roster.cpp
 * @brief Server-side connection roster + LAN classification — implementation.
 *
 * See ncp_server_roster.hpp for the threat model and the deliberate
 * limits on what a "Lan" verdict means.
 */

#include "ncp_server_roster.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#else
#  include <arpa/inet.h>
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

namespace ncp {

namespace {

// ── address parsing ────────────────────────────────────────────────────────
//
// We deliberately do not use inet_pton + getaddrinfo here because neither
// is available identically on both platforms in this project's build, and
// the roster only ever sees numeric addresses from recvfrom().

bool split_ipv4(const std::string& s, std::array<uint32_t, 4>& parts) {
    size_t start = 0;
    for (size_t i = 0; i < 4; ++i) {
        const size_t dot = s.find('.', start);
        const bool last = (i == 3);
        if (last != (dot == std::string::npos)) return false;
        const size_t end = last ? s.size() : dot;
        if (end <= start || end - start > 3) return false;
        uint32_t v = 0;
        for (size_t k = start; k < end; ++k) {
            const char c = s[k];
            if (c < '0' || c > '9') return false;
            v = v * 10 + static_cast<uint32_t>(c - '0');
        }
        if (v > 255) return false;
        parts[i] = v;
        start = end + 1;
    }
    return true;
}

bool parse_ipv4_be(const std::string& s, uint32_t& out_be) {
    std::array<uint32_t, 4> p{};
    if (!split_ipv4(s, p)) return false;
    out_be = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
    return true;
}

std::string ipv4_to_string(uint32_t be) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (be >> 24) & 0xFFu, (be >> 16) & 0xFFu,
                  (be >> 8) & 0xFFu, be & 0xFFu);
    return std::string(buf);
}

uint32_t prefix_mask4(uint8_t prefix) {
    if (prefix == 0) return 0u;
    if (prefix >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - prefix);
}

bool is_ipv6_literal(const std::string& s) {
    return s.find(':') != std::string::npos;
}

/// Expand an IPv6 literal to 16 bytes. Handles "::" compression and an
/// embedded dotted-quad tail. Rejects anything it cannot expand exactly.
bool parse_ipv6(const std::string& s, std::array<uint8_t, 16>& out) {
    out.fill(0);
    if (s.empty()) return false;

    // Split off an embedded IPv4 tail ("::ffff:1.2.3.4", "1:2:3:4:5:6:1.2.3.4").
    // The tail becomes two 16-bit groups, so it has to participate in the
    // "::" expansion count rather than being appended afterwards.
    std::vector<uint16_t> tail;
    std::string head = s;
    const size_t last_colon = s.find_last_of(':');
    if (last_colon != std::string::npos &&
        s.find('.', last_colon) != std::string::npos) {
        const std::string v4tail = s.substr(last_colon + 1);
        head = s.substr(0, last_colon);
        // "::1.2.3.4" leaves a single trailing ':' behind; put the "::" back
        // so the compression below sees the real head.
        if (!head.empty() && head.back() == ':') head.push_back(':');
        uint32_t v4 = 0;
        if (!parse_ipv4_be(v4tail, v4)) return false;
        tail.push_back(static_cast<uint16_t>((v4 >> 16) & 0xFFFF));
        tail.push_back(static_cast<uint16_t>(v4 & 0xFFFF));
    }

    bool compressed = false;
    size_t double_colon = head.find("::");
    if (double_colon != std::string::npos) {
        compressed = true;
        // Only one "::" is legal.
        if (head.find("::", double_colon + 1) != std::string::npos) return false;
    }

    auto parse_side = [](const std::string& side, std::vector<uint16_t>& out_groups) -> bool {
        if (side.empty()) return true;
        size_t start = 0;
        while (start <= side.size()) {
            const size_t colon = side.find(':', start);
            const std::string tok = side.substr(
                start, colon == std::string::npos ? std::string::npos : colon - start);
            if (tok.empty() || tok.size() > 4) return false;
            uint32_t v = 0;
            for (char c : tok) {
                int nib;
                if (c >= '0' && c <= '9') nib = c - '0';
                else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
                else return false;
                v = (v << 4) | static_cast<uint32_t>(nib);
            }
            out_groups.push_back(static_cast<uint16_t>(v));
            if (colon == std::string::npos) break;
            start = colon + 1;
        }
        return true;
    };

    std::vector<uint16_t> left, right;
    if (compressed) {
        if (!parse_side(head.substr(0, double_colon), left)) return false;
        if (!parse_side(head.substr(double_colon + 2), right)) return false;
    } else {
        if (!parse_side(head, left)) return false;
    }

    std::vector<uint16_t> all;
    if (compressed) {
        // "::" must stand for at least one zero group, hence the 7.
        if (left.size() + right.size() + tail.size() > 7) return false;
        all = left;
        all.insert(all.end(), 8 - left.size() - right.size() - tail.size(), 0);
        all.insert(all.end(), right.begin(), right.end());
    } else {
        all = left;
    }
    all.insert(all.end(), tail.begin(), tail.end());

    if (all.size() != 8) return false;
    for (size_t i = 0; i < 8; ++i) {
        out[i * 2]     = static_cast<uint8_t>((all[i] >> 8) & 0xFF);
        out[i * 2 + 1] = static_cast<uint8_t>(all[i] & 0xFF);
    }
    return true;
}

bool prefix_match6(const std::array<uint8_t, 16>& a,
                   const std::array<uint8_t, 16>& b,
                   uint8_t prefix) {
    const size_t full = prefix / 8;
    const size_t rem = prefix % 8;
    if (full > 0 && std::memcmp(a.data(), b.data(), full) != 0) return false;
    if (rem == 0) return true;
    if (full >= 16) return true;
    const uint8_t mask = static_cast<uint8_t>(0xFF << (8 - rem));
    return (a[full] & mask) == (b[full] & mask);
}

std::string hex_of(const std::vector<uint8_t>& bytes, size_t max_bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    const size_t n = std::min(bytes.size(), max_bytes);
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[(bytes[i] >> 4) & 0x0F]);
        out.push_back(kHex[bytes[i] & 0x0F]);
    }
    return out;
}

} // namespace

// ============================================================================
// Locality primitive types
// ============================================================================

const char* locality_to_string(Locality l) noexcept {
    switch (l) {
        case Locality::Unknown:  return "unknown";
        case Locality::Loopback: return "loopback";
        case Locality::Lan:      return "lan";
        case Locality::External: return "external";
    }
    return "unknown";
}

std::string LocalSubnet::to_string() const {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "/%u", static_cast<unsigned>(prefix_len));
    return network + buf;
}

bool parse_local_subnet(const std::string& cidr,
                        std::string& network_out,
                        uint8_t& prefix_out,
                        bool& is_ipv6_out) {
    if (cidr.empty()) return false;
    const size_t slash = cidr.find('/');
    const std::string addr = cidr.substr(0, slash);
    std::string prefix_text;
    if (slash != std::string::npos) prefix_text = cidr.substr(slash + 1);

    const bool v6 = is_ipv6_literal(addr);
    long prefix = -1;
    if (!prefix_text.empty()) {
        char* end = nullptr;
        prefix = std::strtol(prefix_text.c_str(), &end, 10);
        if (!end || *end != '\0' || prefix < 0) return false;
    }

    if (!v6) {
        uint32_t be = 0;
        if (!parse_ipv4_be(addr, be)) return false;
        const long max_prefix = 32;
        const long p = (prefix < 0) ? 32 : prefix;
        if (p > max_prefix) return false;
        network_out = ipv4_to_string(be & prefix_mask4(static_cast<uint8_t>(p)));
        prefix_out = static_cast<uint8_t>(p);
        is_ipv6_out = false;
        return true;
    }

    std::array<uint8_t, 16> raw{};
    if (!parse_ipv6(addr, raw)) return false;
    const long max_prefix = 128;
    const long p = (prefix < 0) ? 128 : prefix;
    if (p > max_prefix) return false;

    // Zero host bits so the stored network form is canonical.
    std::array<uint8_t, 16> net{};
    const size_t full = static_cast<size_t>(p) / 8;
    const size_t rem = static_cast<size_t>(p) % 8;
    if (full > 0) std::memcpy(net.data(), raw.data(), full);
    if (rem != 0 && full < 16) {
        net[full] = static_cast<uint8_t>(raw[full] & (0xFF << (8 - rem)));
    }

    char text[64];
    std::snprintf(text, sizeof(text),
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  net[0], net[1], net[2], net[3], net[4], net[5], net[6], net[7],
                  net[8], net[9], net[10], net[11], net[12], net[13], net[14], net[15]);
    network_out = text;
    prefix_out = static_cast<uint8_t>(p);
    is_ipv6_out = true;
    return true;
}

Locality classify_address(const std::string& address,
                          const std::vector<LocalSubnet>& subnets) {
    if (address.empty()) return Locality::Unknown;

    const bool v6 = is_ipv6_literal(address);

    if (!v6) {
        uint32_t be = 0;
        if (!parse_ipv4_be(address, be)) return Locality::Unknown;
        if ((be >> 24) == 127) return Locality::Loopback;

        bool saw_ipv4_subnet = false;
        for (const auto& s : subnets) {
            if (s.is_ipv6) continue;
            uint32_t net = 0;
            if (!parse_ipv4_be(s.network, net)) continue;
            saw_ipv4_subnet = true;
            if ((be & prefix_mask4(s.prefix_len)) == net) return Locality::Lan;
        }
        // No usable subnet list means we genuinely do not know. Reporting
        // External here would turn "not configured yet" into a false claim.
        return saw_ipv4_subnet ? Locality::External : Locality::Unknown;
    }

    std::array<uint8_t, 16> raw{};
    if (!parse_ipv6(address, raw)) return Locality::Unknown;

    // Dual-stack listeners report IPv4 peers as ::ffff:a.b.c.d. Unwrap and
    // classify them as the IPv4 address they are — otherwise a LAN peer
    // accepted on a dual-stack socket can never match an IPv4 subnet.
    bool mapped = true;
    for (size_t i = 0; i < 10; ++i) {
        if (raw[i] != 0) { mapped = false; break; }
    }
    if (mapped && raw[10] == 0xFF && raw[11] == 0xFF) {
        const uint32_t be = (static_cast<uint32_t>(raw[12]) << 24) |
                            (static_cast<uint32_t>(raw[13]) << 16) |
                            (static_cast<uint32_t>(raw[14]) << 8) |
                            static_cast<uint32_t>(raw[15]);
        return classify_address(ipv4_to_string(be), subnets);
    }

    static const std::array<uint8_t, 16> kLoopback = {
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1
    };
    if (raw == kLoopback) return Locality::Loopback;

    bool saw_ipv6_subnet = false;
    for (const auto& s : subnets) {
        if (!s.is_ipv6) continue;
        std::array<uint8_t, 16> net{};
        if (!parse_ipv6(s.network, net)) continue;
        saw_ipv6_subnet = true;
        if (prefix_match6(raw, net, s.prefix_len)) return Locality::Lan;
    }
    return saw_ipv6_subnet ? Locality::External : Locality::Unknown;
}

// ============================================================================
// Subnet discovery
// ============================================================================

std::vector<LocalSubnet> discover_local_subnets(bool include_loopback) {
    std::vector<LocalSubnet> out;

#ifdef _WIN32
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buf(size);
    ULONG ret = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3; ++attempt) {
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST |
                                               GAA_FLAG_SKIP_MULTICAST |
                                               GAA_FLAG_SKIP_DNS_SERVER,
                                   nullptr,
                                   reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                                   &size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            buf.resize(size);
            continue;
        }
        break;
    }
    if (ret != NO_ERROR) return out;

    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
         a; a = a->Next) {
        if (!include_loopback && (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr) continue;
            const auto family = u->Address.lpSockaddr->sa_family;
            char text[INET6_ADDRSTRLEN] = {0};
            if (family == AF_INET) {
                const auto* sa = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
                inet_ntop(AF_INET, &sa->sin_addr, text, sizeof(text));
            } else if (family == AF_INET6) {
                const auto* sa = reinterpret_cast<const sockaddr_in6*>(u->Address.lpSockaddr);
                inet_ntop(AF_INET6, &sa->sin6_addr, text, sizeof(text));
            } else {
                continue;
            }
            LocalSubnet s;
            s.interface_name = a->AdapterName ? a->AdapterName : "";
            s.is_ipv6 = (family == AF_INET6);
            if (!parse_local_subnet(
                    std::string(text) + "/" + std::to_string(u->OnLinkPrefixLength),
                    s.network, s.prefix_len, s.is_ipv6)) {
                continue;
            }
            out.push_back(std::move(s));
        }
    }
#else
    struct ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) != 0) return out;
    for (auto* i = ifs; i; i = i->ifa_next) {
        if (!i->ifa_addr || !i->ifa_netmask) continue;
        const auto family = i->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6) continue;
        if (!include_loopback && (i->ifa_flags & IFF_LOOPBACK)) continue;

        char text[INET6_ADDRSTRLEN] = {0};
        uint8_t prefix = 0;
        bool v6 = (family == AF_INET6);
        if (!v6) {
            const auto* sa = reinterpret_cast<const sockaddr_in*>(i->ifa_addr);
            const auto* nm = reinterpret_cast<const sockaddr_in*>(i->ifa_netmask);
            inet_ntop(AF_INET, &sa->sin_addr, text, sizeof(text));
            const uint32_t mask = ntohl(nm->sin_addr.s_addr);
            while (prefix < 32 && (mask & (0x80000000u >> prefix))) ++prefix;
        } else {
            const auto* sa = reinterpret_cast<const sockaddr_in6*>(i->ifa_addr);
            const auto* nm = reinterpret_cast<const sockaddr_in6*>(i->ifa_netmask);
            inet_ntop(AF_INET6, &sa->sin6_addr, text, sizeof(text));
            for (size_t b = 0; b < 16; ++b) {
                const uint8_t byte = nm->sin6_addr.s6_addr[b];
                if (byte == 0xFF) { prefix += 8; continue; }
                for (int bit = 7; bit >= 0; --bit) {
                    if (byte & (1 << bit)) ++prefix; else { b = 16; break; }
                }
            }
        }

        LocalSubnet s;
        s.interface_name = i->ifa_name ? i->ifa_name : "";
        s.is_ipv6 = v6;
        if (!parse_local_subnet(std::string(text) + "/" + std::to_string(prefix),
                                s.network, s.prefix_len, s.is_ipv6)) {
            continue;
        }
        out.push_back(std::move(s));
    }
    freeifaddrs(ifs);
#endif

    // Stable order so snapshots and tests do not depend on the OS's
    // enumeration order.
    std::sort(out.begin(), out.end(), [](const LocalSubnet& a, const LocalSubnet& b) {
        if (a.is_ipv6 != b.is_ipv6) return !a.is_ipv6;
        if (a.network != b.network) return a.network < b.network;
        return a.prefix_len < b.prefix_len;
    });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const LocalSubnet& a, const LocalSubnet& b) {
                              return a.network == b.network &&
                                     a.prefix_len == b.prefix_len &&
                                     a.is_ipv6 == b.is_ipv6;
                          }),
              out.end());
    return out;
}

// ============================================================================
// ServerRoster
// ============================================================================

std::string roster_key_for(const std::vector<uint8_t>& client_key,
                           const std::string& address) {
    // A 32-byte key is the normal case: the client's E2E public key.
    if (client_key.size() == 32) return hex_of(client_key, 32);
    // Anything else is a peer we cannot attribute. Keep it visible under a
    // synthetic key rather than dropping it — a malformed key is exactly
    // the peer an operator wants to see.
    return "unknown:" + address + ":" + hex_of(client_key, 8);
}

struct ServerRoster::Impl {
    explicit Impl(size_t cap) : capacity(cap == 0 ? kDefaultCapacity : cap) {}

    mutable std::mutex mutex;
    size_t capacity;
    std::vector<LocalSubnet> subnets;
    std::unordered_map<std::string, RosterEntry> entries;
    size_t dropped_full = 0;

    Locality classify(const std::string& address, std::string* matched) const {
        const Locality l = classify_address(address, subnets);
        if (matched) {
            matched->clear();
            if (l == Locality::Lan) {
                for (const auto& s : subnets) {
                    // Re-run the per-subnet test so we can name the match.
                    std::vector<LocalSubnet> one{s};
                    if (classify_address(address, one) == Locality::Lan) {
                        *matched = s.to_string();
                        break;
                    }
                }
            }
        }
        return l;
    }

    /// Evict the least-recently-seen DISCONNECTED entry. Returns false if
    /// every entry is live (a live session is never evicted).
    bool evict_one_locked() {
        auto victim = entries.end();
        for (auto it = entries.begin(); it != entries.end(); ++it) {
            if (it->second.connected) continue;
            if (victim == entries.end() ||
                it->second.last_seen < victim->second.last_seen) {
                victim = it;
            }
        }
        if (victim == entries.end()) return false;
        entries.erase(victim);
        return true;
    }
};

ServerRoster::ServerRoster(size_t capacity)
    : impl_(new Impl(capacity)) {}

ServerRoster::~ServerRoster() = default;

void ServerRoster::set_local_subnets(std::vector<LocalSubnet> subnets) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->subnets = std::move(subnets);
    // Re-classify existing entries: a subnet change (DHCP, VPN up/down)
    // must not leave stale "external" verdicts on local peers.
    for (auto& kv : impl_->entries) {
        kv.second.matched_subnet.clear();
        kv.second.locality = impl_->classify(kv.second.address,
                                             &kv.second.matched_subnet);
    }
}

std::vector<LocalSubnet> ServerRoster::local_subnets() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->subnets;
}

void ServerRoster::record_connection(const std::vector<uint8_t>& client_key,
                                     const std::string& address,
                                     uint16_t port) {
    const std::string key = roster_key_for(client_key, address);
    const auto now = std::chrono::system_clock::now();

    std::lock_guard<std::mutex> lock(impl_->mutex);

    auto it = impl_->entries.find(key);
    if (it == impl_->entries.end()) {
        if (impl_->entries.size() >= impl_->capacity && !impl_->evict_one_locked()) {
            ++impl_->dropped_full;
            return;
        }
        RosterEntry e;
        e.client_key_hex = key;
        e.address = address;
        e.port = port;
        e.locality = impl_->classify(address, &e.matched_subnet);
        e.first_seen = now;
        e.last_seen = now;
        e.connections = 1;
        e.connected = true;
        impl_->entries.emplace(key, std::move(e));
        return;
    }

    RosterEntry& e = it->second;
    if (e.address != address) {
        // Roaming client, or address reuse. Re-classify rather than
        // assuming the old locality still applies.
        e.address = address;
        e.matched_subnet.clear();
        e.locality = impl_->classify(address, &e.matched_subnet);
    }
    e.port = port;
    e.last_seen = now;
    e.connections += 1;
    e.connected = true;
}

void ServerRoster::record_disconnect(const std::string& client_key_hex) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const auto it = impl_->entries.find(client_key_hex);
    if (it == impl_->entries.end()) return;
    it->second.connected = false;
    it->second.last_seen = std::chrono::system_clock::now();
}

void ServerRoster::update_address(const std::string& client_key_hex,
                                  const std::string& address,
                                  uint16_t port) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const auto it = impl_->entries.find(client_key_hex);
    if (it == impl_->entries.end()) return;
    it->second.address = address;
    it->second.port = port;
    it->second.matched_subnet.clear();
    it->second.locality = impl_->classify(address, &it->second.matched_subnet);
    it->second.last_seen = std::chrono::system_clock::now();
}

bool ServerRoster::find(const std::string& client_key_hex, RosterEntry& out) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const auto it = impl_->entries.find(client_key_hex);
    if (it == impl_->entries.end()) return false;
    out = it->second;
    return true;
}

std::vector<RosterEntry> ServerRoster::snapshot(const RosterFilter& filter) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::vector<RosterEntry> out;
    out.reserve(impl_->entries.size());
    for (const auto& kv : impl_->entries) {
        const RosterEntry& e = kv.second;
        if (filter.local_only &&
            e.locality != Locality::Lan && e.locality != Locality::Loopback) {
            continue;
        }
        if (filter.connected_only && !e.connected) continue;
        out.push_back(e);
    }
    // Most recent first: the interesting entries are the ones that just
    // showed up, not the oldest.
    std::sort(out.begin(), out.end(), [](const RosterEntry& a, const RosterEntry& b) {
        if (a.last_seen != b.last_seen) return a.last_seen > b.last_seen;
        return a.client_key_hex < b.client_key_hex;
    });
    return out;
}

size_t ServerRoster::size() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->entries.size();
}

size_t ServerRoster::connected_count() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    size_t n = 0;
    for (const auto& kv : impl_->entries) {
        if (kv.second.connected) ++n;
    }
    return n;
}

size_t ServerRoster::dropped_full() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->dropped_full;
}

void ServerRoster::clear() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->entries.clear();
    impl_->dropped_full = 0;
}

} // namespace ncp
