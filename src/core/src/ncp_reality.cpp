#include "ncp_reality.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <vector>

#include <sodium.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace ncp {

namespace {

// ===== One-time libsodium init =====
void ensure_sodium() {
    static std::once_flag flag;
    std::call_once(flag, [] { const int rc = sodium_init(); (void)rc; });
}

// ===== base32 (RFC4648, lowercase, padding stripped) =====
constexpr char kB32Alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

std::string b32_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        acc = (acc << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kB32Alphabet[(acc >> bits) & 31u]);
        }
    }
    if (bits > 0) {
        out.push_back(kB32Alphabet[(acc << (5 - bits)) & 31u]);
    }
    return out;
}

// ===== Token helpers =====
constexpr uint64_t kWindowSec = 60;
constexpr size_t   kTokenLen  = 26;  // base32 chars in the SNI label
const char kTokenPrefix[] = "ncp-reality";

// message = "ncp-reality" || gateway_domain || window(u64, big-endian)
std::vector<uint8_t> build_message(const std::string& gateway_domain,
                                   uint64_t window) {
    std::vector<uint8_t> msg;
    msg.reserve(sizeof(kTokenPrefix) - 1 + gateway_domain.size() + 8);
    msg.insert(msg.end(), kTokenPrefix, kTokenPrefix + sizeof(kTokenPrefix) - 1);
    msg.insert(msg.end(), gateway_domain.begin(), gateway_domain.end());
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<uint8_t>((window >> (i * 8)) & 0xFF));
    }
    return msg;
}

// Deterministic Ed25519 signature for (domain, window) -> first 26 base32 chars.
std::string token_for_window(const std::array<uint8_t, 64>& secret_key,
                             const std::string& gateway_domain,
                             uint64_t window) {
    std::vector<uint8_t> msg = build_message(gateway_domain, window);
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(),
                         secret_key.data());
    std::string b32 = b32_encode(sig.data(), sig.size());
    return b32.substr(0, kTokenLen);
}

bool is_valid_token(const std::string& tok) {
    if (tok.size() != kTokenLen) return false;
    for (char c : tok) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
        if (!ok) return false;
    }
    return true;
}

// Split "<token>.gw.<domain>" -> fill token/domain; false on wrong shape.
bool split_sni(const std::string& sni, std::string& token,
               std::string& domain) {
    const size_t dot1 = sni.find('.');
    if (dot1 == std::string::npos || dot1 == 0) return false;
    const size_t dot2 = sni.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;
    if (sni.compare(dot1 + 1, dot2 - dot1 - 1, "gw") != 0) return false;
    if (dot2 + 1 >= sni.size()) return false;
    token = sni.substr(0, dot1);
    domain = sni.substr(dot2 + 1);
    return true;
}

// Write all bytes, retrying on EINTR; MSG_NOSIGNAL against SIGPIPE.
// Windows: the TCP splice path is not supported yet, stubbed out.
bool write_all([[maybe_unused]] int fd, [[maybe_unused]] const uint8_t* data,
               [[maybe_unused]] size_t len) noexcept {
#ifdef _WIN32
    return false;
#else
    size_t off = 0;
    while (off < len) {
        const ssize_t n = ::send(fd, data + off, len - off, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
#endif
}

int connect_to([[maybe_unused]] const std::string& host,
               [[maybe_unused]] uint16_t port) noexcept {
#ifdef _WIN32
    return -1;  // TCP fallback dial is not supported on Windows yet
#else
    struct addrinfo hints {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    const std::string port_str = std::to_string(port);
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return -1;
    }
    int fd = -1;
    for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    return fd;
#endif
}

} // anonymous namespace

// ===== RealityDecision =====

const char* reality_decision_to_string(RealityDecision d) noexcept {
    switch (d) {
        case RealityDecision::AUTHORIZED: return "AUTHORIZED";
        case RealityDecision::FALLBACK:   return "FALLBACK";
        case RealityDecision::NOT_TLS:    return "NOT_TLS";
        default:                          return "UNKNOWN";
    }
}

// ===== RealityAuth =====

struct RealityAuth::Impl {
    struct KeyEntry {
        std::array<uint8_t, 32> pubkey{};
        bool has_secret = false;
        std::array<uint8_t, 64> secret{};
    };
    std::map<std::string, KeyEntry> keys;
    mutable std::shared_mutex mu;
};

RealityAuth::RealityAuth() : impl_(std::make_shared<Impl>()) {
    ensure_sodium();
}

RealityAuth::RealityAuth(
    std::map<std::string, std::array<uint8_t, 32>> client_pubkeys)
    : RealityAuth() {
    for (auto& kv : client_pubkeys) {
        add_key(kv.first, kv.second);
    }
}

void RealityAuth::add_key(const std::string& key_id,
                          const std::array<uint8_t, 32>& pubkey) {
    std::unique_lock<std::shared_mutex> lk(impl_->mu);
    auto& e = impl_->keys[key_id];
    e.pubkey = pubkey;
}

void RealityAuth::provision_secret(
    const std::string& key_id,
    const std::array<uint8_t, 64>& secret_key) {
    std::unique_lock<std::shared_mutex> lk(impl_->mu);
    auto it = impl_->keys.find(key_id);
    if (it == impl_->keys.end()) return;
    it->second.secret = secret_key;
    it->second.has_secret = true;
}

size_t RealityAuth::key_count() const {
    std::shared_lock<std::shared_mutex> lk(impl_->mu);
    return impl_->keys.size();
}

bool RealityAuth::verify_sni(const std::string& sni, uint64_t now) const {
    std::string token, domain;
    if (!split_sni(sni, token, domain)) return false;
    if (!is_valid_token(token)) return false;

    const uint64_t window = now / kWindowSec;
    std::shared_lock<std::shared_mutex> lk(impl_->mu);
    for (const auto& kv : impl_->keys) {
        const Impl::KeyEntry& e = kv.second;
        if (!e.has_secret) continue;  // pubkey-only entries cannot verify
        const uint64_t prev = (window > 0) ? window - 1 : window;
        for (uint64_t w : {window, prev}) {
            const std::string cand = token_for_window(e.secret, domain, w);
            if (cand.size() == token.size() &&
                sodium_memcmp(cand.data(), token.data(), token.size()) == 0) {
                return true;
            }
        }
    }
    return false;
}

// ===== RealityTokenBuilder =====

std::string RealityTokenBuilder::make_sni(
    const std::string& key_id,
    const std::array<uint8_t, 64>& secret_key,
    const std::string& gateway_domain,
    uint64_t now) {
    (void)key_id;  // identifies the key server-side; not present on the wire
    ensure_sodium();
    return token_for_window(secret_key, gateway_domain, now / kWindowSec) +
           ".gw." + gateway_domain;
}

// ===== TLS ClientHello parsing =====

bool RealityServer::extract_sni(const uint8_t* buf, size_t len,
                                std::string& out_sni) noexcept {
    if (buf == nullptr || len < 5) return false;
    if (buf[0] != 0x16 || buf[1] != 0x03) return false;  // handshake, TLS
    const size_t rec_len = (static_cast<size_t>(buf[3]) << 8) | buf[4];
    if (rec_len < 4 || len < 5 + rec_len) return false;

    size_t p = 5;  // start of handshake payload
    const size_t end = 5 + rec_len;
    if (buf[p] != 0x01) return false;  // ClientHello
    const size_t hs_len = (static_cast<size_t>(buf[p + 1]) << 16) |
                          (static_cast<size_t>(buf[p + 2]) << 8) | buf[p + 3];
    if (p + 4 + hs_len > end) return false;
    p += 4;
    const size_t hs_end = p + hs_len;

    if (p + 34 > hs_end) return false;  // version(2) + random(32)
    p += 34;

    if (p + 1 > hs_end) return false;
    const size_t sid_len = buf[p];
    p += 1;
    if (p + sid_len > hs_end) return false;
    p += sid_len;

    if (p + 2 > hs_end) return false;
    const size_t cs_len = (static_cast<size_t>(buf[p]) << 8) | buf[p + 1];
    p += 2;
    if (p + cs_len > hs_end) return false;
    p += cs_len;

    if (p + 1 > hs_end) return false;
    const size_t comp_len = buf[p];
    p += 1;
    if (p + comp_len > hs_end) return false;
    p += comp_len;

    if (p == hs_end) return false;  // no extensions block
    if (p + 2 > hs_end) return false;
    const size_t ext_total = (static_cast<size_t>(buf[p]) << 8) | buf[p + 1];
    p += 2;
    if (p + ext_total > hs_end) return false;
    const size_t ext_end = p + ext_total;

    while (p + 4 <= ext_end) {
        const uint16_t ext_type =
            static_cast<uint16_t>((buf[p] << 8) | buf[p + 1]);
        const size_t ext_len = (static_cast<size_t>(buf[p + 2]) << 8) | buf[p + 3];
        p += 4;
        if (p + ext_len > ext_end) return false;
        if (ext_type == 0x0000) {  // server_name
            if (ext_len < 2 + 3) return false;
            const uint8_t* e = buf + p;
            const size_t list_len =
                (static_cast<size_t>(e[0]) << 8) | e[1];
            if (list_len + 2 > ext_len || list_len < 3) return false;
            if (e[2] != 0x00) return false;  // host_name type
            const size_t name_len =
                (static_cast<size_t>(e[3]) << 8) | e[4];
            if (3 + name_len > list_len || name_len == 0) return false;
            out_sni.assign(reinterpret_cast<const char*>(e + 5), name_len);
            return true;
        }
        p += ext_len;
    }
    return false;  // well-formed ClientHello without SNI
}

// ===== RealityServer =====

RealityServer::RealityServer(RealityConfig cfg) : cfg_(std::move(cfg)) {
    ensure_sodium();
}

RealityServer::Decision RealityServer::classify(const uint8_t* clienthello,
                                                size_t len,
                                                uint64_t now) const {
    if (clienthello == nullptr || len < 5) return Decision::NOT_TLS;
    if (clienthello[0] != 0x16 || clienthello[1] != 0x03) {
        return Decision::NOT_TLS;
    }
    std::string sni;
    if (!extract_sni(clienthello, len, sni)) return Decision::FALLBACK;
    if (cfg_.auth.verify_sni(sni, now)) return Decision::AUTHORIZED;
    return Decision::FALLBACK;
}

void RealityServer::splice([[maybe_unused]] int fd_a,
                           [[maybe_unused]] int fd_b) noexcept {
#ifdef _WIN32
    return;  // bidirectional splice is not supported on Windows yet
#else
    if (fd_a < 0 || fd_b < 0) return;
    bool read_a = true;  // still reading from fd_a
    bool read_b = true;  // still reading from fd_b
    std::array<uint8_t, 16384> buf{};

    while (read_a || read_b) {
        struct pollfd pfds[2];
        pfds[0].fd = read_a ? fd_a : -1;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = read_b ? fd_b : -1;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;

        const int rc = ::poll(pfds, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int side = 0; side < 2; ++side) {
            const bool is_a = (side == 0);
            bool& reading = is_a ? read_a : read_b;
            if (!reading) continue;
            const short rev = pfds[side].revents;
            if ((rev & (POLLIN | POLLHUP | POLLERR)) == 0) continue;

            const int src = is_a ? fd_a : fd_b;
            const int dst = is_a ? fd_b : fd_a;
            const ssize_t n = ::recv(src, buf.data(), buf.size(), 0);
            if (n > 0) {
                if (!write_all(dst, buf.data(), static_cast<size_t>(n))) {
                    // Peer write side is dead: stop forwarding both ways.
                    ::shutdown(dst, SHUT_WR);
                    reading = false;
                    (is_a ? read_b : read_a) = false;
                }
            } else {
                // EOF or error: half-close the opposite direction and
                // keep forwarding the remaining direction.
                ::shutdown(dst, SHUT_WR);
                reading = false;
            }
        }
    }
#endif
}

bool RealityServer::handle_client([[maybe_unused]] int client_fd,
                                  [[maybe_unused]] uint64_t now) const noexcept {
#ifdef _WIN32
    return false;  // fallback relay is not supported on Windows yet
#else
    if (client_fd < 0) return false;

    // Read the ClientHello (single record, capped at 16 KiB).
    std::array<uint8_t, 16384> hello{};
    size_t have = 0;
    while (have < hello.size()) {
        const ssize_t n = ::recv(client_fd, hello.data() + have,
                                 hello.size() - have, 0);
        if (n <= 0) return false;
        have += static_cast<size_t>(n);
        if (have >= 5) {
            const size_t rec_len =
                (static_cast<size_t>(hello[3]) << 8) | hello[4];
            if (5 + rec_len > hello.size()) return false;  // oversize record
            if (have >= 5 + rec_len) break;
        }
    }

    const Decision d = classify(hello.data(), have, now);
    if (d == Decision::NOT_TLS) return false;

    const std::string& host = (d == Decision::AUTHORIZED)
                                  ? cfg_.internal_host
                                  : cfg_.fallback_host;
    const uint16_t port = (d == Decision::AUTHORIZED)
                              ? cfg_.internal_port
                              : cfg_.fallback_port;

    const int upstream = connect_to(host, port);
    if (upstream < 0) return false;

    // Replay the consumed ClientHello bytes to the chosen upstream.
    if (!write_all(upstream, hello.data(), have)) {
        ::close(upstream);
        return false;
    }
    splice(client_fd, upstream);
    ::close(upstream);
    return true;
#endif
}

} // namespace ncp
