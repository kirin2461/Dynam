// ══════════════════════════════════════════════════════════════════════════════
// ncp_turn_server.cpp
//
// G5: REAL TURN-over-UDP/IPv4 server (RFC 5766 / RFC 5389), native C++17.
// UDP only — no TCP/TLS listeners. Long-term credentials are supplied
// independently by the caller; they are never derived from HopSecret / E2E /
// mask material. Single-threaded, non-blocking, caller-driven poll loop.
// ══════════════════════════════════════════════════════════════════════════════

#include "ncp_turn_server.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace ncp {
namespace turn {

namespace {

constexpr uint32_t kErrorBadRequest            = 400;
constexpr uint32_t kErrorUnknownAttribute      = 420;
constexpr uint32_t kErrorAllocationMismatch    = 437;
constexpr uint32_t kErrorAddressFamilyNotSupported = 440;
constexpr uint32_t kErrorUnsupportedTransport  = 442;
constexpr uint32_t kErrorAllocationQuota       = 486;
constexpr uint32_t kErrorInsufficientCapacity  = 508;
constexpr uint16_t kAttrUnknownAttributes      = 0x000A;

void put_u32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}
uint16_t get_u16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
uint32_t get_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           (static_cast<uint32_t>(p[3]));
}

uint64_t now_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= static_cast<uint8_t>(a[i] ^ b[i]);
    return d == 0;
}

bool set_nonblocking(int fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

void close_fd(int& fd) {
    if (fd < 0) return;
#ifdef _WIN32
    closesocket(fd);
#else
    ::close(fd);
#endif
    fd = -1;
}

} // anonymous namespace

// ── Allocation (internal) ────────────────────────────────────────────────────

struct TurnServer::Allocation {
    uint32_t client_addr_be = 0;
    uint16_t client_port = 0;
    int      relay_sock = -1;            // non-blocking, bound to relay_ip:0
    uint16_t relay_port = 0;
    std::chrono::steady_clock::time_point expires_at{};
    std::array<uint8_t, 16> key{};       // long-term key of the owner

    // Permissions: peer IPv4 (network order) -> expiry. IP-only (RFC 5766 §8).
    std::map<uint32_t, std::chrono::steady_clock::time_point> permissions;
    // Channels: channel number -> (peer, expiry).
    struct ChannelBinding {
        uint32_t peer_addr_be = 0;
        uint16_t peer_port = 0;
        std::chrono::steady_clock::time_point expires_at{};
    };
    std::map<uint16_t, ChannelBinding> channels;
};

// ── TurnServer ───────────────────────────────────────────────────────────────

TurnServer::TurnServer(TurnServerConfig cfg) : cfg_(std::move(cfg)) {
    rx_buf_.resize(65536);
}

TurnServer::~TurnServer() {
    close();
}

bool TurnServer::is_open() const { return sock_ >= 0; }

bool TurnServer::open(std::string* err) {
    if (sock_ >= 0) return true;
    std::string local_err;
    std::string& e = err ? *err : local_err;

    if (cfg_.realm.empty()) {
        e = "realm must be configured";
        last_error_ = e;
        return false;
    }
    if (cfg_.users.empty()) {
        e = "at least one independently supplied credential is required";
        last_error_ = e;
        return false;
    }

#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        e = "WSAStartup failed";
        last_error_ = e;
        return false;
    }
#endif

    in_addr bind_addr{};
    if (inet_pton(AF_INET, cfg_.bind_ip.c_str(), &bind_addr) != 1) {
        e = "bad bind IPv4 address: " + cfg_.bind_ip;
        last_error_ = e;
        return false;
    }
    bind_addr_be_ = bind_addr.s_addr;

    const std::string& relay_ip =
        cfg_.relay_ip.empty() ? cfg_.bind_ip : cfg_.relay_ip;
    in_addr relay_addr{};
    if (inet_pton(AF_INET, relay_ip.c_str(), &relay_addr) != 1) {
        e = "bad relay IPv4 address: " + relay_ip;
        last_error_ = e;
        return false;
    }
    relay_addr_be_ = relay_addr.s_addr;

    sock_ = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (sock_ < 0) {
        e = "socket() failed";
        last_error_ = e;
        return false;
    }
    // UDP only by construction: SOCK_DGRAM/IPPROTO_UDP. No TCP/TLS listener.
    int one = 1;
    ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&one), sizeof(one));
    if (!set_nonblocking(sock_)) {
        e = "failed to set listening socket non-blocking";
        last_error_ = e;
        close_fd(sock_);
        return false;
    }

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(cfg_.bind_port);
    sa.sin_addr.s_addr = bind_addr_be_;
    if (::bind(sock_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        e = "bind() failed on " + cfg_.bind_ip + ":" +
            std::to_string(cfg_.bind_port);
        last_error_ = e;
        close_fd(sock_);
        return false;
    }
    sockaddr_in actual{};
#ifdef _WIN32
    int alen = sizeof(actual);
#else
    socklen_t alen = sizeof(actual);
#endif
    if (::getsockname(sock_, reinterpret_cast<sockaddr*>(&actual), &alen) != 0) {
        e = "getsockname() failed";
        last_error_ = e;
        close_fd(sock_);
        return false;
    }
    bound_port_ = ntohs(actual.sin_port);

    // Per-instance nonce signing key (never derived from external material).
    if (RAND_bytes(nonce_key_.data(), static_cast<int>(nonce_key_.size())) != 1) {
        e = "RAND_bytes failed for nonce key";
        last_error_ = e;
        close_fd(sock_);
        return false;
    }
    return true;
}

void TurnServer::close() {
    for (auto& a : allocations_) close_fd(a->relay_sock);
    allocations_.clear();
    stats_.allocations_active = 0;
    close_fd(sock_);
    bound_port_ = 0;
    replay_cache_.clear();
    replay_order_.clear();
    nonce_key_.fill(0);
}

// ── Nonce (stateless, HMAC-signed, fail closed) ─────────────────────────────

std::string TurnServer::make_nonce() const {
    // nonce = hex8(epoch_seconds) || hex40(HMAC-SHA1(nonce_key, epoch_hex))
    char ts[9];
    std::snprintf(ts, sizeof(ts), "%08lx",
                  static_cast<unsigned long>(now_seconds() & 0xFFFFFFFFul));
    uint8_t mac[20];
    unsigned int mac_len = 0;
    HMAC(EVP_sha1(), nonce_key_.data(), static_cast<int>(nonce_key_.size()),
         reinterpret_cast<const uint8_t*>(ts), 8, mac, &mac_len);
    static const char* k = "0123456789abcdef";
    std::string out(ts, 8);
    out.reserve(48);
    for (size_t i = 0; i < 20; ++i) {
        out += k[mac[i] >> 4];
        out += k[mac[i] & 0xF];
    }
    return out;
}

int TurnServer::validate_nonce(const std::string& nonce) const {
    if (nonce.size() != 48) return 2;
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    uint8_t got[20];
    for (size_t i = 0; i < 20; ++i) {
        int hi = hexval(nonce[8 + i * 2]);
        int lo = hexval(nonce[8 + i * 2 + 1]);
        if (hi < 0 || lo < 0) return 2;
        got[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    const std::string ts = nonce.substr(0, 8);
    uint8_t mac[20];
    unsigned int mac_len = 0;
    HMAC(EVP_sha1(), nonce_key_.data(), static_cast<int>(nonce_key_.size()),
         reinterpret_cast<const uint8_t*>(ts.data()), ts.size(),
         mac, &mac_len);
    if (mac_len != 20 || !ct_equal(mac, got, 20)) return 2;  // bad nonce

    uint64_t issued = 0;
    for (char c : ts) {
        int v = hexval(c);
        if (v < 0) return 2;
        issued = (issued << 4) | static_cast<uint64_t>(v);
    }
    uint64_t now = now_seconds();
    // Expired, or issued implausibly far in the future (clock tamper guard):
    // both fail closed as stale so the client re-challenges.
    if (issued + cfg_.nonce_lifetime < now || issued > now + 60) return 1;
    return 0;
}

// ── Response helpers ─────────────────────────────────────────────────────────

void TurnServer::respond(const StunMessage& req,
                         uint32_t dst_addr_be, uint16_t dst_port,
                         StunMessage& resp, const uint8_t* mi_key) {
    resp.method = req.method;
    resp.txn_id = req.txn_id;
    std::vector<uint8_t> bytes = stun_encode(resp, mi_key, mi_key ? 16 : 0,
                                             /*add_fingerprint=*/true);
    if (bytes.empty()) return;

    // Transaction-id replay response cache (bounded FIFO).
    if (cfg_.replay_cache_size > 0) {
        std::string key(reinterpret_cast<const char*>(&dst_addr_be), 4);
        uint16_t p = htons(dst_port);
        key.append(reinterpret_cast<const char*>(&p), 2);
        key.append(reinterpret_cast<const char*>(req.txn_id.data()), 12);
        if (replay_cache_.find(key) == replay_cache_.end()) {
            replay_order_.push_back(key);
            while (replay_order_.size() > cfg_.replay_cache_size) {
                replay_cache_.erase(replay_order_.front());
                replay_order_.erase(replay_order_.begin());
            }
        }
        replay_cache_[key] = bytes;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = dst_addr_be;
    ::sendto(sock_, reinterpret_cast<const char*>(bytes.data()),
             static_cast<int>(bytes.size()), 0,
             reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
}

void TurnServer::send_success(const StunMessage& req,
                              uint32_t dst_addr_be, uint16_t dst_port,
                              std::vector<StunAttribute> attrs,
                              const uint8_t* mi_key) {
    StunMessage resp;
    resp.cls = StunClass::SuccessResponse;
    resp.attributes = std::move(attrs);
    respond(req, dst_addr_be, dst_port, resp, mi_key);
}

void TurnServer::send_error(const StunMessage& req,
                            uint32_t dst_addr_be, uint16_t dst_port,
                            uint32_t code, const char* reason,
                            bool include_realm_nonce,
                            const uint8_t* mi_key) {
    StunMessage resp;
    resp.cls = StunClass::ErrorResponse;
    std::vector<uint8_t> ec;
    ec.reserve(4 + std::strlen(reason));
    ec.push_back(0);
    ec.push_back(0);
    ec.push_back(static_cast<uint8_t>(code / 100));
    ec.push_back(static_cast<uint8_t>(code % 100));
    ec.insert(ec.end(), reason, reason + std::strlen(reason));
    resp.attributes.push_back({kAttrErrorCode, std::move(ec)});
    if (include_realm_nonce) {
        resp.attributes.push_back({kAttrRealm,
            {cfg_.realm.begin(), cfg_.realm.end()}});
        std::string nonce = make_nonce();
        resp.attributes.push_back({kAttrNonce,
            {nonce.begin(), nonce.end()}});
    }
    // 401/438 challenges are unauthenticated by definition; other errors to
    // authenticated requests carry MESSAGE-INTEGRITY (mi_key != nullptr).
    respond(req, dst_addr_be, dst_port, resp, mi_key);
}

// ── Authentication (fail closed) ─────────────────────────────────────────────

bool TurnServer::authenticate(const StunMessage& req,
                              uint32_t src_addr_be, uint16_t src_port,
                              std::array<uint8_t, 16>* key_out) {
    const StunAttribute* user_a  = req.find(kAttrUsername);
    const StunAttribute* realm_a = req.find(kAttrRealm);
    const StunAttribute* nonce_a = req.find(kAttrNonce);

    auto challenge401 = [&](const char* /*why*/) {
        ++stats_.auth_challenges_401;
        send_error(req, src_addr_be, src_port, kErrorUnauthorized,
                   "Unauthorized", /*include_realm_nonce=*/true, nullptr);
    };

    if (!user_a || !realm_a || !nonce_a || !req.has_message_integrity) {
        challenge401("missing auth attributes");
        return false;
    }
    std::string realm = req.find_string(kAttrRealm);
    if (realm != cfg_.realm) {
        ++stats_.bad_realm_rejected;
        challenge401("wrong realm");
        return false;
    }
    std::string user = req.find_string(kAttrUsername);
    auto it = cfg_.users.find(user);
    if (it == cfg_.users.end()) {
        ++stats_.unknown_user_rejected;
        challenge401("unknown user");
        return false;
    }
    std::string nonce = req.find_string(kAttrNonce);
    int nv = validate_nonce(nonce);
    if (nv == 2) {
        ++stats_.bad_nonce_rejected;
        challenge401("bad nonce");
        return false;
    }
    if (nv == 1) {
        ++stats_.stale_nonce_438;
        send_error(req, src_addr_be, src_port, kErrorStaleNonce,
                   "Stale Nonce", /*include_realm_nonce=*/true, nullptr);
        return false;
    }

    std::array<uint8_t, 16> key = long_term_key(user, cfg_.realm, it->second);
    if (!stun_verify_integrity(req, key.data(), key.size())) {
        ++stats_.bad_integrity_rejected;
        ++stats_.auth_challenges_401;
        send_error(req, src_addr_be, src_port, kErrorUnauthorized,
                   "Unauthorized", /*include_realm_nonce=*/true, nullptr);
        return false;
    }
    if (key_out) *key_out = key;
    return true;
}

// ── Allocation lookup/expiry ─────────────────────────────────────────────────

TurnServer::Allocation* TurnServer::find_allocation(uint32_t addr_be,
                                                    uint16_t port) {
    for (auto& a : allocations_)
        if (a->client_addr_be == addr_be && a->client_port == port)
            return a.get();
    return nullptr;
}

void TurnServer::destroy_allocation(Allocation& alloc, bool natural_expiry) {
    close_fd(alloc.relay_sock);
    auto it = std::find_if(allocations_.begin(), allocations_.end(),
        [&](const std::unique_ptr<Allocation>& p) { return p.get() == &alloc; });
    if (it != allocations_.end()) allocations_.erase(it);
    if (stats_.allocations_active > 0) --stats_.allocations_active;
    if (natural_expiry) ++stats_.expired_allocations;
}

void TurnServer::sweep_expired() {
    auto now = std::chrono::steady_clock::now();
    for (auto& a : allocations_) {
        // Permissions.
        for (auto it = a->permissions.begin(); it != a->permissions.end();) {
            if (it->second <= now) {
                it = a->permissions.erase(it);
                ++stats_.expired_permissions;
            } else {
                ++it;
            }
        }
        // Channel bindings.
        for (auto it = a->channels.begin(); it != a->channels.end();) {
            if (it->second.expires_at <= now) {
                it = a->channels.erase(it);
                ++stats_.expired_channels;
            } else {
                ++it;
            }
        }
    }
    // Allocations (natural expiry: granted lifetime elapsed, no Refresh).
    for (size_t i = 0; i < allocations_.size();) {
        if (allocations_[i]->expires_at <= now) {
            destroy_allocation(*allocations_[i], /*natural_expiry=*/true);
        } else {
            ++i;
        }
    }
}

// ── Per-method handlers ──────────────────────────────────────────────────────

void TurnServer::do_allocate(const StunMessage& req,
                             uint32_t src_addr_be, uint16_t src_port,
                             const std::array<uint8_t, 16>& key) {
    // REQUESTED-TRANSPORT must be present and UDP (17) (RFC 5766 §6.1).
    const StunAttribute* rt = req.find(kAttrRequestedTransport);
    if (!rt || rt->value.size() != 4 || rt->value[0] != 17) {
        ++stats_.unsupported_transport_442;
        send_error(req, src_addr_be, src_port, kErrorUnsupportedTransport,
                   "Unsupported Transport Protocol", false, key.data());
        return;
    }
    // REQUESTED-ADDRESS-FAMILY (RFC 6156): this server is IPv4-only.
    const StunAttribute* raf = req.find(kAttrRequestedAddressFamily);
    if (raf && (raf->value.empty() || raf->value[0] != 0x01)) {
        send_error(req, src_addr_be, src_port,
                   kErrorAddressFamilyNotSupported,
                   "Address Family not Supported", false, key.data());
        return;
    }
    // EVEN-PORT (RFC 5766 §6.1): R bit requests an even relayed port.
    bool want_even_port = false;
    const StunAttribute* ep = req.find(kAttrEvenPort);
    if (ep) {
        if (ep->value.size() != 1) {
            ++stats_.bad_request_400;
            send_error(req, src_addr_be, src_port, kErrorBadRequest,
                       "Bad Request", false, key.data());
            return;
        }
        want_even_port = (ep->value[0] & 0x80) != 0;
    }
    if (find_allocation(src_addr_be, src_port)) {
        ++stats_.allocation_mismatch_437;
        send_error(req, src_addr_be, src_port, kErrorAllocationMismatch,
                   "Allocation Mismatch", false, key.data());
        return;
    }
    if (allocations_.size() >= cfg_.max_allocations) {
        ++stats_.quota_rejected;
        send_error(req, src_addr_be, src_port, kErrorAllocationQuota,
                   "Allocation Quota Reached", false, key.data());
        return;
    }

    // Relay socket: UDP/IPv4, non-blocking, bound to relay_ip (ephemeral
    // port; rebound up to a bounded number of times when EVEN-PORT asks for
    // an even port).
    int rsock = -1;
    uint16_t relay_port_got = 0;
    for (int attempt = 0; attempt < 32; ++attempt) {
        rsock = static_cast<int>(::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        if (rsock >= 0 && !set_nonblocking(rsock)) {
            close_fd(rsock);
            rsock = -1;
        }
        sockaddr_in rsa{};
        rsa.sin_family = AF_INET;
        rsa.sin_port = htons(0);
        rsa.sin_addr.s_addr = relay_addr_be_;
        if (rsock < 0 ||
            ::bind(rsock, reinterpret_cast<sockaddr*>(&rsa), sizeof(rsa)) != 0) {
            if (rsock >= 0) close_fd(rsock);
            rsock = -1;
            break;
        }
        sockaddr_in actual{};
#ifdef _WIN32
        int alen = sizeof(actual);
#else
        socklen_t alen = sizeof(actual);
#endif
        if (::getsockname(rsock, reinterpret_cast<sockaddr*>(&actual),
                          &alen) != 0) {
            close_fd(rsock);
            rsock = -1;
            break;
        }
        relay_port_got = ntohs(actual.sin_port);
        if (!want_even_port || (relay_port_got & 1u) == 0) break;
        close_fd(rsock);
        rsock = -1;
    }
    if (rsock < 0) {
        ++stats_.quota_rejected;
        send_error(req, src_addr_be, src_port, kErrorInsufficientCapacity,
                   "Insufficient Capacity", false, key.data());
        return;
    }

    uint32_t lifetime = cfg_.default_lifetime;
    const StunAttribute* lt = req.find(kAttrLifetime);
    if (lt && lt->value.size() == 4) {
        uint32_t requested = get_u32(lt->value.data());
        lifetime = requested > 0
            ? std::min(requested, cfg_.max_lifetime)
            : cfg_.default_lifetime;
    }

    auto alloc = std::make_unique<Allocation>();
    alloc->client_addr_be = src_addr_be;
    alloc->client_port = src_port;
    alloc->relay_sock = rsock;
    alloc->relay_port = relay_port_got;
    alloc->expires_at = std::chrono::steady_clock::now() +
                        std::chrono::seconds(lifetime);
    alloc->key = key;
    const uint16_t relay_port = alloc->relay_port;
    allocations_.push_back(std::move(alloc));
    ++stats_.allocations_total;
    stats_.allocations_active = allocations_.size();

    std::vector<StunAttribute> attrs;
    attrs.push_back({kAttrXorRelayedAddress,
        encode_xor_address_ipv4(relay_addr_be_, relay_port, req.txn_id)});
    attrs.push_back({kAttrXorMappedAddress,
        encode_xor_address_ipv4(src_addr_be, src_port, req.txn_id)});
    std::vector<uint8_t> ltv;
    put_u32(ltv, lifetime);
    attrs.push_back({kAttrLifetime, std::move(ltv)});
    send_success(req, src_addr_be, src_port, std::move(attrs), key.data());
}

void TurnServer::do_refresh(const StunMessage& req,
                            uint32_t src_addr_be, uint16_t src_port,
                            const std::array<uint8_t, 16>& key) {
    Allocation* alloc = find_allocation(src_addr_be, src_port);
    if (!alloc) {
        ++stats_.allocation_mismatch_437;
        send_error(req, src_addr_be, src_port, kErrorAllocationMismatch,
                   "Allocation Mismatch", false, key.data());
        return;
    }
    uint32_t lifetime = cfg_.default_lifetime;
    const StunAttribute* lt = req.find(kAttrLifetime);
    if (lt) {
        if (lt->value.size() != 4) {
            ++stats_.bad_request_400;
            send_error(req, src_addr_be, src_port, kErrorBadRequest,
                       "Bad Request", false, key.data());
            return;
        }
        lifetime = get_u32(lt->value.data());
    }
    if (lifetime > 0) lifetime = std::min(lifetime, cfg_.max_lifetime);

    ++stats_.refresh_total;
    if (lifetime == 0) {
        // RFC 5766 §7: zero-lifetime Refresh deletes the allocation now.
        uint16_t cport = src_port;
        uint32_t caddr = src_addr_be;
        destroy_allocation(*alloc, /*natural_expiry=*/false);
        ++stats_.deleted_via_refresh;
        std::vector<uint8_t> ltv;
        put_u32(ltv, 0);
        std::vector<StunAttribute> attrs;
        attrs.push_back({kAttrLifetime, std::move(ltv)});
        send_success(req, caddr, cport, std::move(attrs), key.data());
        return;
    }
    alloc->expires_at = std::chrono::steady_clock::now() +
                        std::chrono::seconds(lifetime);
    std::vector<uint8_t> ltv;
    put_u32(ltv, lifetime);
    std::vector<StunAttribute> attrs;
    attrs.push_back({kAttrLifetime, std::move(ltv)});
    send_success(req, src_addr_be, src_port, std::move(attrs), key.data());
}

void TurnServer::do_create_permission(const StunMessage& req,
                                      uint32_t src_addr_be, uint16_t src_port,
                                      const std::array<uint8_t, 16>& key) {
    Allocation* alloc = find_allocation(src_addr_be, src_port);
    if (!alloc) {
        ++stats_.allocation_mismatch_437;
        send_error(req, src_addr_be, src_port, kErrorAllocationMismatch,
                   "Allocation Mismatch", false, key.data());
        return;
    }
    // At least one XOR-PEER-ADDRESS required (RFC 5766 §9.1).
    size_t peer_count = 0;
    for (const auto& a : req.attributes)
        if (a.type == kAttrXorPeerAddress) ++peer_count;
    if (peer_count == 0) {
        ++stats_.bad_request_400;
        send_error(req, src_addr_be, src_port, kErrorBadRequest,
                   "Bad Request", false, key.data());
        return;
    }
    auto expiry = std::chrono::steady_clock::now() +
                  std::chrono::seconds(cfg_.permission_lifetime);
    for (const auto& a : req.attributes) {
        if (a.type != kAttrXorPeerAddress) continue;
        uint32_t peer_addr = 0;
        uint16_t peer_port = 0;  // ignored: permissions are IP-only
        if (!decode_xor_address_ipv4(a, req.txn_id, peer_addr, peer_port)) {
            ++stats_.bad_request_400;
            send_error(req, src_addr_be, src_port, kErrorBadRequest,
                       "Bad Request", false, key.data());
            return;
        }
        if (alloc->permissions.find(peer_addr) == alloc->permissions.end() &&
            alloc->permissions.size() >= cfg_.max_permissions_per_allocation) {
            ++stats_.quota_rejected;
            send_error(req, src_addr_be, src_port, kErrorInsufficientCapacity,
                       "Insufficient Capacity", false, key.data());
            return;
        }
        alloc->permissions[peer_addr] = expiry;
    }
    send_success(req, src_addr_be, src_port, {}, key.data());
}

void TurnServer::do_channel_bind(const StunMessage& req,
                                 uint32_t src_addr_be, uint16_t src_port,
                                 const std::array<uint8_t, 16>& key) {
    Allocation* alloc = find_allocation(src_addr_be, src_port);
    if (!alloc) {
        ++stats_.allocation_mismatch_437;
        send_error(req, src_addr_be, src_port, kErrorAllocationMismatch,
                   "Allocation Mismatch", false, key.data());
        return;
    }
    const StunAttribute* ch_a = req.find(kAttrChannelNumber);
    const StunAttribute* peer_a = req.find(kAttrXorPeerAddress);
    if (!ch_a || ch_a->value.size() != 4 || !peer_a) {
        ++stats_.bad_request_400;
        send_error(req, src_addr_be, src_port, kErrorBadRequest,
                   "Bad Request", false, key.data());
        return;
    }
    uint16_t channel = get_u16(ch_a->value.data());
    uint32_t peer_addr = 0;
    uint16_t peer_port = 0;
    if (channel < kChannelNumberMin || channel > kChannelNumberMax ||
        !decode_xor_address_ipv4(*peer_a, req.txn_id, peer_addr, peer_port)) {
        ++stats_.bad_request_400;
        send_error(req, src_addr_be, src_port, kErrorBadRequest,
                   "Bad Request", false, key.data());
        return;
    }
    // Rebinding rules (RFC 5766 §11): same channel to a different peer, or
    // same peer to a different channel, is rejected with 400.
    auto ch_it = alloc->channels.find(channel);
    if (ch_it != alloc->channels.end() &&
        (ch_it->second.peer_addr_be != peer_addr ||
         ch_it->second.peer_port != peer_port)) {
        ++stats_.bad_request_400;
        send_error(req, src_addr_be, src_port, kErrorBadRequest,
                   "Bad Request", false, key.data());
        return;
    }
    for (const auto& kv : alloc->channels) {
        if (kv.first != channel &&
            kv.second.peer_addr_be == peer_addr &&
            kv.second.peer_port == peer_port) {
            ++stats_.bad_request_400;
            send_error(req, src_addr_be, src_port, kErrorBadRequest,
                       "Bad Request", false, key.data());
            return;
        }
    }
    if (ch_it == alloc->channels.end() &&
        alloc->channels.size() >= cfg_.max_channels_per_allocation) {
        ++stats_.quota_rejected;
        send_error(req, src_addr_be, src_port, kErrorInsufficientCapacity,
                   "Insufficient Capacity", false, key.data());
        return;
    }

    auto expiry = std::chrono::steady_clock::now() +
                  std::chrono::seconds(cfg_.channel_lifetime);
    Allocation::ChannelBinding b;
    b.peer_addr_be = peer_addr;
    b.peer_port = peer_port;
    b.expires_at = expiry;
    alloc->channels[channel] = b;
    // A channel binding also installs/refreshes a permission for the peer
    // (RFC 5766 §11.1), bounded like any other permission.
    if (alloc->permissions.find(peer_addr) != alloc->permissions.end() ||
        alloc->permissions.size() < cfg_.max_permissions_per_allocation) {
        alloc->permissions[peer_addr] =
            std::chrono::steady_clock::now() +
            std::chrono::seconds(cfg_.permission_lifetime);
    }
    send_success(req, src_addr_be, src_port, {}, key.data());
}

// ── Request / indication dispatch ────────────────────────────────────────────

void TurnServer::handle_request(const StunMessage& req,
                                uint32_t src_addr_be, uint16_t src_port) {
    // Binding requests are unauthenticated by design (RFC 5389).
    if (req.method == kMethodBinding) {
        std::vector<StunAttribute> attrs;
        attrs.push_back({kAttrXorMappedAddress,
            encode_xor_address_ipv4(src_addr_be, src_port, req.txn_id)});
        send_success(req, src_addr_be, src_port, std::move(attrs), nullptr);
        return;
    }

    // Long-term credential check first: every TURN method here requires an
    // authenticated request (fail closed on any deviation).
    std::array<uint8_t, 16> key{};
    if (!authenticate(req, src_addr_be, src_port, &key)) return;

    // Unknown comprehension-required attributes -> 420 (RFC 5389 §7.3.1).
    std::vector<uint8_t> unknown;
    for (const auto& a : req.attributes) {
        if (a.type >= 0x8000) continue;  // comprehension-optional: ignore
        switch (a.type) {
            case kAttrMappedAddress:
            case kAttrUsername:
            case kAttrMessageIntegrity:
            case kAttrErrorCode:
            case kAttrChannelNumber:
            case kAttrLifetime:
            case kAttrXorPeerAddress:
            case kAttrData:
            case kAttrRealm:
            case kAttrNonce:
            case kAttrXorRelayedAddress:
            case kAttrRequestedTransport:
            case kAttrXorMappedAddress:
            case kAttrRequestedAddressFamily:
            case kAttrEvenPort:
                break;
            default:
                unknown.push_back(static_cast<uint8_t>(a.type >> 8));
                unknown.push_back(static_cast<uint8_t>(a.type & 0xFF));
                break;
        }
    }
    if (!unknown.empty()) {
        send_error(req, src_addr_be, src_port, kErrorUnknownAttribute,
                   "Unknown Attribute", false, key.data());
        return;
    }

    switch (req.method) {
        case kMethodAllocate:         do_allocate(req, src_addr_be, src_port, key); break;
        case kMethodRefresh:          do_refresh(req, src_addr_be, src_port, key); break;
        case kMethodCreatePermission: do_create_permission(req, src_addr_be, src_port, key); break;
        case kMethodChannelBind:      do_channel_bind(req, src_addr_be, src_port, key); break;
        default:
            ++stats_.bad_request_400;
            send_error(req, src_addr_be, src_port, kErrorBadRequest,
                       "Bad Request", false, key.data());
            break;
    }
}

void TurnServer::handle_indication(const StunMessage& ind,
                                   uint32_t src_addr_be, uint16_t src_port) {
    // Only Send indications are defined for the server (RFC 5766 §10). They
    // are unauthenticated, but the data plane still fails closed: without an
    // allocation for this exact 5-tuple the datagram is dropped.
    if (ind.method != kMethodSend) return;
    Allocation* alloc = find_allocation(src_addr_be, src_port);
    if (!alloc) {
        ++stats_.no_allocation_dropped;
        return;
    }
    const StunAttribute* peer_a = ind.find(kAttrXorPeerAddress);
    const StunAttribute* data_a = ind.find(kAttrData);
    if (!peer_a || !data_a) {
        ++stats_.malformed_dropped;
        return;
    }
    uint32_t peer_addr = 0;
    uint16_t peer_port = 0;
    if (!decode_xor_address_ipv4(*peer_a, ind.txn_id, peer_addr, peer_port)) {
        ++stats_.malformed_dropped;
        return;
    }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(peer_port);
    dst.sin_addr.s_addr = peer_addr;
    int n = ::sendto(alloc->relay_sock,
                     reinterpret_cast<const char*>(data_a->value.data()),
                     static_cast<int>(data_a->value.size()), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (n == static_cast<int>(data_a->value.size())) {
        ++stats_.send_indications_relayed;
        stats_.bytes_relayed_to_peer += data_a->value.size();
    }
}

// ── Datagram entry points ────────────────────────────────────────────────────

void TurnServer::handle_listen_datagram(const uint8_t* data, size_t len,
                                        uint32_t src_addr_be,
                                        uint16_t src_port) {
    // ChannelData framing: first two bits 01 (RFC 5766 §11.4).
    if (is_channel_data(data, len)) {
        Allocation* alloc = find_allocation(src_addr_be, src_port);
        if (!alloc) {
            ++stats_.no_allocation_dropped;  // fail closed
            return;
        }
        uint16_t channel = 0;
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        if (!channel_data_decode(data, len, channel, payload, payload_len)) {
            ++stats_.malformed_dropped;
            return;
        }
        auto it = alloc->channels.find(channel);
        if (it == alloc->channels.end()) {
            ++stats_.unknown_channel_dropped;  // fail closed
            return;
        }
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(it->second.peer_port);
        dst.sin_addr.s_addr = it->second.peer_addr_be;
        int n = ::sendto(alloc->relay_sock,
                         reinterpret_cast<const char*>(payload),
                         static_cast<int>(payload_len), 0,
                         reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        if (n == static_cast<int>(payload_len)) {
            ++stats_.channel_data_to_peer;
            stats_.bytes_relayed_to_peer += payload_len;
        }
        return;
    }

    StunMessage msg;
    std::string derr;
    if (!stun_decode(data, len, msg, derr)) {
        ++stats_.malformed_dropped;  // fail closed: silent drop
        return;
    }
    if (msg.has_fingerprint && !stun_verify_fingerprint(msg)) {
        ++stats_.bad_fingerprint_dropped;  // fail closed
        return;
    }

    if (msg.cls == StunClass::Indication) {
        handle_indication(msg, src_addr_be, src_port);
        return;
    }
    if (msg.cls != StunClass::Request) {
        // Servers never receive responses; drop.
        ++stats_.malformed_dropped;
        return;
    }

    // Transaction-id replay response cache: a retransmitted request (same
    // 5-tuple + txn id) gets the cached response verbatim (RFC 5389 §7.1).
    std::string rkey(reinterpret_cast<const char*>(&src_addr_be), 4);
    uint16_t p = htons(src_port);
    rkey.append(reinterpret_cast<const char*>(&p), 2);
    rkey.append(reinterpret_cast<const char*>(msg.txn_id.data()), 12);
    auto rit = replay_cache_.find(rkey);
    if (rit != replay_cache_.end()) {
        ++stats_.replay_cache_hits;
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(src_port);
        dst.sin_addr.s_addr = src_addr_be;
        ::sendto(sock_, reinterpret_cast<const char*>(rit->second.data()),
                 static_cast<int>(rit->second.size()), 0,
                 reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
        return;
    }

    handle_request(msg, src_addr_be, src_port);
}

void TurnServer::handle_relay_datagram(Allocation& alloc, const uint8_t* data,
                                       size_t len, uint32_t peer_addr_be,
                                       uint16_t peer_port) {
    // Permissions gate ALL peer->client traffic (RFC 5766 §8): fail closed.
    auto perm = alloc.permissions.find(peer_addr_be);
    if (perm == alloc.permissions.end() ||
        perm->second <= std::chrono::steady_clock::now()) {
        ++stats_.permission_denied_dropped;
        return;
    }

    // If a channel is bound to this exact peer transport address, relay as
    // ChannelData; otherwise use a Data indication (RFC 5766 §10.4).
    for (const auto& kv : alloc.channels) {
        if (kv.second.peer_addr_be == peer_addr_be &&
            kv.second.peer_port == peer_port) {
            std::vector<uint8_t> out = channel_data_encode(kv.first, data, len);
            if (out.empty()) {
                ++stats_.malformed_dropped;
                return;
            }
            sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_port = htons(alloc.client_port);
            dst.sin_addr.s_addr = alloc.client_addr_be;
            int n = ::sendto(sock_, reinterpret_cast<const char*>(out.data()),
                             static_cast<int>(out.size()), 0,
                             reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
            if (n == static_cast<int>(out.size())) {
                ++stats_.channel_data_to_client;
                stats_.bytes_relayed_to_client += len;
            }
            return;
        }
    }

    StunMessage ind;
    ind.method = kMethodData;
    ind.cls = StunClass::Indication;
    if (RAND_bytes(ind.txn_id.data(), static_cast<int>(ind.txn_id.size())) != 1)
        ind.txn_id.fill(0xA5);
    ind.attributes.push_back({kAttrXorPeerAddress,
        encode_xor_address_ipv4(peer_addr_be, peer_port, ind.txn_id)});
    ind.attributes.push_back({kAttrData,
        std::vector<uint8_t>(data, data + len)});
    std::vector<uint8_t> bytes = stun_encode(ind, nullptr, 0,
                                             /*add_fingerprint=*/true);
    if (bytes.empty()) return;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(alloc.client_port);
    dst.sin_addr.s_addr = alloc.client_addr_be;
    int n = ::sendto(sock_, reinterpret_cast<const char*>(bytes.data()),
                     static_cast<int>(bytes.size()), 0,
                     reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (n == static_cast<int>(bytes.size())) {
        ++stats_.data_indications_sent;
        stats_.bytes_relayed_to_client += len;
    }
}

// ── Poll loop (single owner, non-blocking) ───────────────────────────────────

int TurnServer::poll(int timeout_ms, std::string* err) {
    if (sock_ < 0) {
        last_error_ = "socket not open (call open())";
        if (err) *err = last_error_;
        return -1;
    }

    sweep_expired();

    // Build the fd set: listening socket + all live relay sockets.
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(sock_, &rfds);
    int maxfd = sock_;
    for (auto& a : allocations_) {
        if (a->relay_sock >= 0) {
            FD_SET(a->relay_sock, &rfds);
            if (a->relay_sock > maxfd) maxfd = a->relay_sock;
        }
    }

    const bool infinite = timeout_ms < 0;
    timeval tv{};
    timeval* tvp = nullptr;
    if (!infinite) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tvp = &tv;
    }
    int r = ::select(maxfd + 1, &rfds, nullptr, nullptr, tvp);
    if (r < 0) {
#ifdef _WIN32
        if (WSAGetLastError() == WSAEINTR) return 0;
#else
        if (errno == EINTR) return 0;
#endif
        last_error_ = "select() failed";
        if (err) *err = last_error_;
        return -1;
    }
    if (r == 0) {
        sweep_expired();
        return 0;
    }

    size_t budget = cfg_.max_datagrams_per_poll;
    int processed = 0;

    // Drain the listening socket (bounded).
    while (budget > 0) {
        sockaddr_in from{};
#ifdef _WIN32
        int fromlen = sizeof(from);
#else
        socklen_t fromlen = sizeof(from);
#endif
        int n = ::recvfrom(sock_, reinterpret_cast<char*>(rx_buf_.data()),
                           static_cast<int>(rx_buf_.size()), 0,
                           reinterpret_cast<sockaddr*>(&from), &fromlen);
        if (n <= 0) break;  // EWOULDBLOCK or error: nothing more to read
        --budget;
        ++processed;
        handle_listen_datagram(rx_buf_.data(), static_cast<size_t>(n),
                               from.sin_addr.s_addr, ntohs(from.sin_port));
    }

    // Drain relay sockets (bounded). Snapshot: relay datagrams can tear down
    // nothing here (only the listen path mutates allocations), but iterate
    // defensively by index with a size check.
    for (size_t i = 0; i < allocations_.size() && budget > 0; ++i) {
        Allocation* alloc = allocations_[i].get();
        if (alloc->relay_sock < 0) continue;
        if (!FD_ISSET(alloc->relay_sock, &rfds)) continue;
        while (budget > 0) {
            sockaddr_in from{};
#ifdef _WIN32
            int fromlen = sizeof(from);
#else
            socklen_t fromlen = sizeof(from);
#endif
            int n = ::recvfrom(alloc->relay_sock,
                               reinterpret_cast<char*>(rx_buf_.data()),
                               static_cast<int>(rx_buf_.size()), 0,
                               reinterpret_cast<sockaddr*>(&from), &fromlen);
            if (n <= 0) break;
            --budget;
            ++processed;
            handle_relay_datagram(*alloc, rx_buf_.data(),
                                  static_cast<size_t>(n),
                                  from.sin_addr.s_addr, ntohs(from.sin_port));
        }
    }

    sweep_expired();
    return processed;
}

} // namespace turn
} // namespace ncp
