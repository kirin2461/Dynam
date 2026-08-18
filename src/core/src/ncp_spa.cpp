/**
 * @file ncp_spa.cpp
 * @brief Enterprise Single Packet Authorization (SPA) — implementation
 *
 * See ncp_spa.hpp for the wire format and design notes.
 */

#include "ncp_spa.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>

#include <sodium.h>

#ifndef _WIN32
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

namespace ncp {

// ============================================================================
// base64 helpers
// ============================================================================

std::string spa_base64_encode(const uint8_t* data, size_t len) {
    if (!data || len == 0) return "";
    const size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(b64_len, '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

bool spa_base64_decode(const std::string& b64, std::vector<uint8_t>& out) {
    out.clear();
    if (b64.empty()) return false;
    out.resize(b64.size());  // upper bound
    size_t bin_len = 0;
    if (sodium_base642bin(out.data(), out.size(),
                          b64.c_str(), b64.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        out.clear();
        return false;
    }
    out.resize(bin_len);
    return true;
}

// ============================================================================
// SpaResult
// ============================================================================

const char* spa_result_to_string(SpaResult r) noexcept {
    switch (r) {
        case SpaResult::GRANTED:         return "GRANTED";
        case SpaResult::BAD_FORMAT:      return "BAD_FORMAT";
        case SpaResult::UNKNOWN_KEY:     return "UNKNOWN_KEY";
        case SpaResult::STALE_TIMESTAMP: return "STALE_TIMESTAMP";
        case SpaResult::REPLAY:          return "REPLAY";
        case SpaResult::BAD_SIGNATURE:   return "BAD_SIGNATURE";
    }
    return "UNKNOWN";
}

// ============================================================================
// IpSetAccessController
// ============================================================================

IpSetAccessController::IpSetAccessController(std::string set_name, bool dry_run)
    : set_name_(std::move(set_name)), dry_run_(dry_run) {}

std::string IpSetAccessController::iptables_rule_hint(uint8_t proto, uint16_t port,
                                                      const std::string& set_name) {
    std::ostringstream oss;
    oss << "iptables -A INPUT -p "
        << (proto == 17 ? "udp" : "tcp")
        << " --dport " << port
        << " -m set ! --match-set " << set_name << " src -j DROP";
    return oss.str();
}

void IpSetAccessController::set_command_runner(CommandRunner runner) {
    std::lock_guard<std::mutex> lk(mu_);
    runner_ = std::move(runner);
}

std::string IpSetAccessController::last_command() const {
    std::lock_guard<std::mutex> lk(mu_);
    return last_command_;
}

int IpSetAccessController::run_command(const std::string& cmd) {
    CommandRunner runner;
    {
        std::lock_guard<std::mutex> lk(mu_);
        last_command_ = cmd;
        runner = runner_;
    }
    NCP_LOG_INFO(std::string("[SPA] ipset: ") + cmd +
                 (dry_run_ ? " (dry-run, not executed)" : ""));
    if (dry_run_) return 0;
    if (runner) return runner(cmd);
    NCP_LOG_DEBUG(std::string("[SPA] system(\"") + cmd + "\")");
    return ::system(cmd.c_str());
}

bool IpSetAccessController::ensure_set() {
    if (set_ensured_) return true;
    const std::string cmd = "ipset create " + set_name_ + " hash:ip timeout 0 -exist";
    if (run_command(cmd) == 0) {
        set_ensured_ = true;
        return true;
    }
    NCP_LOG_ERROR(std::string("[SPA] failed to create ipset '") + set_name_ + "'");
    return false;
}

bool IpSetAccessController::grant(const std::string& src_ip, uint8_t proto,
                                  uint16_t port, uint32_t ttl_sec) {
    (void)proto;  // ipset hash:ip is protocol-agnostic; proto is for logging/rules
    (void)port;
    if (!ensure_set()) return false;
    const std::string cmd = "ipset add " + set_name_ + " " + src_ip +
                            " timeout " + std::to_string(ttl_sec) + " -exist";
    if (run_command(cmd) != 0) {
        NCP_LOG_ERROR(std::string("[SPA] ipset add failed for ") + src_ip);
        return false;
    }
    NCP_LOG_INFO(std::string("[SPA] granted ") + src_ip + " ttl=" +
                 std::to_string(ttl_sec) + "s");
    return true;
}

// ============================================================================
// SpaServer
// ============================================================================

SpaServer::SpaServer() = default;

SpaServer::SpaServer(Config cfg) : cfg_(cfg) {}

void SpaServer::set_access_controller(std::shared_ptr<IAccessController> ctrl) {
    controller_ = std::move(ctrl);
}

SpaKeyId SpaServer::key_id_for(const uint8_t* pubkey, size_t len) {
    SpaKeyId id{};
    if (!pubkey || len != 32) return id;
    // BLAKE2b-64 (8-byte output) — Crypto::hash_blake2b enforces
    // crypto_generichash_BYTES_MIN (16), so call libsodium directly.
    crypto_generichash(id.data(), id.size(), pubkey, len, nullptr, 0);
    return id;
}

bool SpaServer::add_authorized_key(const uint8_t* pubkey, size_t len) {
    if (!pubkey || len != 32) return false;
    SpaKeyId id = key_id_for(pubkey, len);
    std::array<uint8_t, 32> pk{};
    std::memcpy(pk.data(), pubkey, 32);
    std::string id_str(reinterpret_cast<const char*>(id.data()), id.size());
    {
        std::unique_lock<std::shared_mutex> lk(keys_mu_);
        keys_[id_str] = pk;
    }
    NCP_LOG_INFO(std::string("[SPA] authorized key added, key_id=") +
                 Crypto::bytes_to_hex(SecureMemory(id.data(), id.size())));
    return true;
}

bool SpaServer::load_authorized_keys(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        NCP_LOG_ERROR(std::string("[SPA] cannot open authorized_keys: ") + path);
        return false;
    }
    size_t added = 0;
    std::string line;
    while (std::getline(f, line)) {
        const size_t b = line.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;             // blank
        if (line[b] == '#') continue;                     // comment
        const size_t e = line.find_last_not_of(" \t\r\n");
        std::vector<uint8_t> pk;
        if (!spa_base64_decode(line.substr(b, e - b + 1), pk) || pk.size() != 32) {
            NCP_LOG_WARN(std::string("[SPA] skipping invalid authorized_keys line: ") +
                         line.substr(b, e - b + 1));
            continue;
        }
        if (add_authorized_key(pk.data(), pk.size())) ++added;
    }
    NCP_LOG_INFO(std::string("[SPA] loaded ") + std::to_string(added) +
                 " authorized key(s) from " + path);
    return added > 0;
}

size_t SpaServer::authorized_key_count() const {
    std::shared_lock<std::shared_mutex> lk(keys_mu_);
    return keys_.size();
}

void SpaServer::sweep_replay_cache_locked(std::chrono::steady_clock::time_point now) {
    const auto ttl = std::chrono::seconds(cfg_.nonce_ttl_sec);
    for (auto it = replay_cache_.begin(); it != replay_cache_.end();) {
        auto& nonces = it->second;
        for (auto n = nonces.begin(); n != nonces.end();) {
            if (now - n->second > ttl) n = nonces.erase(n);
            else ++n;
        }
        if (nonces.empty()) it = replay_cache_.erase(it);
        else ++it;
    }
}

SpaResult SpaServer::process_packet(const uint8_t* data, size_t len,
                                    const std::string& src_ip) noexcept {
    auto log_decision = [&](SpaResult r) {
        NCP_LOG_INFO(std::string("[SPA] ") + spa_result_to_string(r) +
                     " src=" + src_ip);
    };

    // 1. size / magic / version
    if (!data || len != SPA_PACKET_SIZE ||
        data[0] != 'S' || data[1] != 'P' || data[2] != SPA_VERSION) {
        log_decision(SpaResult::BAD_FORMAT);
        return SpaResult::BAD_FORMAT;
    }

    // 2. key_id known?
    const std::string key_id(reinterpret_cast<const char*>(data + 3), SPA_KEY_ID_LEN);
    std::array<uint8_t, 32> pubkey{};
    {
        std::shared_lock<std::shared_mutex> lk(keys_mu_);
        auto it = keys_.find(key_id);
        if (it == keys_.end()) {
            log_decision(SpaResult::UNKNOWN_KEY);
            return SpaResult::UNKNOWN_KEY;
        }
        pubkey = it->second;
    }

    // 3. timestamp window
    uint64_t ts = 0;
    for (size_t i = 0; i < 8; ++i) ts = (ts << 8) | data[11 + i];
    const uint64_t now_s = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const uint64_t diff = (now_s > ts) ? (now_s - ts) : (ts - now_s);
    if (diff > cfg_.timestamp_window_sec) {
        log_decision(SpaResult::STALE_TIMESTAMP);
        return SpaResult::STALE_TIMESTAMP;
    }

    // 4. nonce replay check
    const std::string nonce(reinterpret_cast<const char*>(data + 19), SPA_NONCE_LEN);
    {
        std::lock_guard<std::mutex> lk(replay_mu_);
        sweep_replay_cache_locked(std::chrono::steady_clock::now());
        auto kit = replay_cache_.find(key_id);
        if (kit != replay_cache_.end() && kit->second.count(nonce) != 0) {
            log_decision(SpaResult::REPLAY);
            return SpaResult::REPLAY;
        }
    }

    // 5. Ed25519 verify over bytes [0..42)
    SecureMemory msg(data, SPA_SIGNED_LEN);
    SecureMemory sig(data + SPA_SIGNATURE_OFFSET, 64);
    SecureMemory pk(pubkey.data(), pubkey.size());
    if (!crypto_.verify_ed25519(msg, sig, pk)) {
        log_decision(SpaResult::BAD_SIGNATURE);
        return SpaResult::BAD_SIGNATURE;
    }

    // 6. success — record nonce, grant access
    const uint8_t  proto = data[35];
    const uint16_t port  = static_cast<uint16_t>((data[36] << 8) | data[37]);
    uint32_t ttl = 0;
    for (size_t i = 0; i < 4; ++i) ttl = (ttl << 8) | data[38 + i];
    if (ttl == 0) ttl = cfg_.default_ttl_sec;
    ttl = (std::min)(ttl, cfg_.max_ttl_sec);

    {
        std::lock_guard<std::mutex> lk(replay_mu_);
        replay_cache_[key_id][nonce] = std::chrono::steady_clock::now();
    }

    if (controller_) {
        if (!controller_->grant(src_ip, proto, port, ttl)) {
            NCP_LOG_ERROR(std::string("[SPA] access controller failed for ") + src_ip);
        }
    } else {
        NCP_LOG_WARN("[SPA] no access controller configured — packet valid but no grant issued");
    }

    NCP_LOG_INFO(std::string("[SPA] GRANTED src=") + src_ip +
                 " proto=" + std::to_string(proto) +
                 " port=" + std::to_string(port) +
                 " ttl=" + std::to_string(ttl) + "s");
    return SpaResult::GRANTED;
}

// ============================================================================
// SpaClient
// ============================================================================

SpaClient::SpaClient() = default;

bool SpaClient::has_key() const noexcept {
    return secret_key_.size() == 64 && public_key_.size() == 32;
}

bool SpaClient::generate() {
    Crypto crypto;
    auto kp = crypto.generate_keypair();
    if (!kp.is_valid() || kp.secret_key.size() != 64 || kp.public_key.size() != 32) {
        return false;
    }
    secret_key_ = SecureMemory(kp.secret_key.data(), kp.secret_key.size());
    public_key_ = SecureMemory(kp.public_key.data(), kp.public_key.size());
    return true;
}

bool SpaClient::load_keyfile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        NCP_LOG_ERROR(std::string("[SPA] cannot open key file: ") + path);
        return false;
    }
    std::string line;
    std::getline(f, line);
    const size_t b = line.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return false;
    const size_t e = line.find_last_not_of(" \t\r\n");

    std::vector<uint8_t> blob;
    if (!spa_base64_decode(line.substr(b, e - b + 1), blob) || blob.size() != 96) {
        NCP_LOG_ERROR(std::string("[SPA] invalid key file format: ") + path);
        return false;
    }
    secret_key_ = SecureMemory(blob.data(), 64);
    // Derive the pubkey from the secret key; fall back to the stored half.
    std::array<uint8_t, 32> derived{};
    if (crypto_sign_ed25519_sk_to_pk(derived.data(), secret_key_.data()) == 0 &&
        std::memcmp(derived.data(), blob.data() + 64, 32) == 0) {
        public_key_ = SecureMemory(blob.data() + 64, 32);
    } else {
        NCP_LOG_ERROR(std::string("[SPA] key file pubkey mismatch: ") + path);
        secret_key_ = SecureMemory{};
        return false;
    }
    SecureMemory::secure_zero(blob.data(), blob.size());
    return true;
}

bool SpaClient::save_keyfile(const std::string& path) const {
    if (!has_key()) return false;
    std::vector<uint8_t> blob(96);
    std::memcpy(blob.data(), secret_key_.data(), 64);
    std::memcpy(blob.data() + 64, public_key_.data(), 32);
    const std::string b64 = spa_base64_encode(blob.data(), blob.size());
    SecureMemory::secure_zero(blob.data(), blob.size());

    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) {
        NCP_LOG_ERROR(std::string("[SPA] cannot write key file: ") + path);
        return false;
    }
    f << b64 << "\n";
    return static_cast<bool>(f);
}

std::vector<uint8_t> SpaClient::build_packet(uint8_t proto, uint16_t allow_port,
                                             uint32_t ttl_sec) const {
    const uint64_t now_s = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    return build_packet_ts(proto, allow_port, ttl_sec, now_s);
}

std::vector<uint8_t> SpaClient::build_packet_ts(uint8_t proto, uint16_t allow_port,
                                                uint32_t ttl_sec,
                                                uint64_t timestamp_unix) const {
    std::vector<uint8_t> pkt;
    if (!has_key()) return pkt;
    pkt.assign(SPA_PACKET_SIZE, 0);

    pkt[0] = 'S';
    pkt[1] = 'P';
    pkt[2] = SPA_VERSION;

    const SpaKeyId id = key_id();
    std::memcpy(pkt.data() + 3, id.data(), SPA_KEY_ID_LEN);

    for (size_t i = 0; i < 8; ++i)
        pkt[11 + i] = static_cast<uint8_t>((timestamp_unix >> (56 - i * 8)) & 0xFF);

    csprng_fill(pkt.data() + 19, SPA_NONCE_LEN);

    pkt[35] = proto;
    pkt[36] = static_cast<uint8_t>((allow_port >> 8) & 0xFF);
    pkt[37] = static_cast<uint8_t>(allow_port & 0xFF);
    for (size_t i = 0; i < 4; ++i)
        pkt[38 + i] = static_cast<uint8_t>((ttl_sec >> (24 - i * 8)) & 0xFF);

    SecureMemory msg(pkt.data(), SPA_SIGNED_LEN);
    SecureMemory sig = crypto_.sign_ed25519(msg, secret_key_);
    if (sig.size() != 64) {
        pkt.clear();
        return pkt;
    }
    std::memcpy(pkt.data() + SPA_SIGNATURE_OFFSET, sig.data(), 64);

    csprng_fill(pkt.data() + SPA_PADDING_OFFSET, SPA_PACKET_SIZE - SPA_PADDING_OFFSET);
    return pkt;
}

SpaKeyId SpaClient::key_id() const {
    if (public_key_.size() != 32) return SpaKeyId{};
    return SpaServer::key_id_for(public_key_.data(), public_key_.size());
}

std::string SpaClient::key_id_hex() const {
    const SpaKeyId id = key_id();
    return Crypto::bytes_to_hex(SecureMemory(id.data(), id.size()));
}

std::string SpaClient::pubkey_base64() const {
    if (public_key_.size() != 32) return "";
    return spa_base64_encode(public_key_.data(), public_key_.size());
}

bool SpaClient::knock(const std::string& host, uint16_t udp_port, uint8_t proto,
                      uint16_t allow_port, uint32_t ttl_sec) const {
    const std::vector<uint8_t> pkt = build_packet(proto, allow_port, ttl_sec);
    return send_packet(host, udp_port, pkt);
}

bool SpaClient::send_packet(const std::string& host, uint16_t udp_port,
                            const std::vector<uint8_t>& packet) const {
    const std::vector<uint8_t>& pkt = packet;
    if (pkt.size() != SPA_PACKET_SIZE) return false;

#ifdef _WIN32
    NCP_LOG_ERROR("[SPA] knock is not supported on Windows yet");
    (void)host; (void)udp_port;
    return false;
#else
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = nullptr;
    const std::string port_str = std::to_string(udp_port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        NCP_LOG_ERROR(std::string("[SPA] cannot resolve ") + host);
        return false;
    }
    bool sent = false;
    for (struct addrinfo* ai = res; ai && !sent; ai = ai->ai_next) {
        int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        const ssize_t n = ::sendto(s, pkt.data(), pkt.size(), 0,
                                   ai->ai_addr, ai->ai_addrlen);
        ::close(s);
        sent = (n == static_cast<ssize_t>(pkt.size()));
    }
    freeaddrinfo(res);
    if (!sent) {
        NCP_LOG_ERROR(std::string("[SPA] knock send failed to ") + host);
    }
    return sent;
#endif
}

// ============================================================================
// SpaDaemon
// ============================================================================

SpaDaemon::SpaDaemon(SpaServer& server, uint16_t port, std::string bind_addr)
    : server_(server), port_(port), bind_addr_(std::move(bind_addr)) {}

SpaDaemon::~SpaDaemon() {
    stop();
}

bool SpaDaemon::start() {
#ifdef _WIN32
    NCP_LOG_ERROR("[SPA] SpaDaemon is not supported on Windows yet");
    return false;
#else
    if (running_.load()) return true;

    sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) {
        NCP_LOG_ERROR(std::string("[SPA] socket() failed: ") + std::strerror(errno));
        return false;
    }

    int one = 1;
    ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct timeval tv{};
    tv.tv_sec = 1;  // SO_RCVTIMEO — 1 s loop so stop() is responsive
    tv.tv_usec = 0;
    ::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (::inet_pton(AF_INET, bind_addr_.c_str(), &addr.sin_addr) != 1) {
        NCP_LOG_ERROR(std::string("[SPA] invalid bind address: ") + bind_addr_);
        ::close(sock_);
        sock_ = -1;
        return false;
    }
    if (::bind(sock_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        NCP_LOG_ERROR(std::string("[SPA] bind ") + bind_addr_ + ":" +
                      std::to_string(port_) + " failed: " + std::strerror(errno));
        ::close(sock_);
        sock_ = -1;
        return false;
    }

    stop_flag_.store(false);
    running_.store(true);
    thread_ = std::thread(&SpaDaemon::loop, this);
    NCP_LOG_INFO(std::string("[SPA] daemon listening on UDP ") + bind_addr_ +
                 ":" + std::to_string(port_));
    return true;
#endif
}

void SpaDaemon::stop() {
    stop_flag_.store(true);
    if (thread_.joinable()) thread_.join();
#ifndef _WIN32
    if (sock_ >= 0) {
        ::close(sock_);
        sock_ = -1;
    }
#endif
    running_.store(false);
}

void SpaDaemon::loop() {
#ifndef _WIN32
    std::vector<uint8_t> buf(SPA_PACKET_SIZE + 64);
    while (!stop_flag_.load()) {
        struct sockaddr_in src{};
        socklen_t src_len = sizeof(src);
        const ssize_t n = ::recvfrom(sock_, buf.data(), buf.size(), 0,
                                     reinterpret_cast<struct sockaddr*>(&src), &src_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;  // 1 s tick
            if (stop_flag_.load()) break;
            NCP_LOG_WARN(std::string("[SPA] recvfrom error: ") + std::strerror(errno));
            continue;
        }
        char ip_str[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &src.sin_addr, ip_str, sizeof(ip_str));
        server_.process_packet(buf.data(), static_cast<size_t>(n), ip_str);
        // Never send replies — the port must stay silent.
    }
#endif
}

} // namespace ncp
