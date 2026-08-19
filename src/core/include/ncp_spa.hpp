#pragma once

/**
 * @file ncp_spa.hpp
 * @brief Enterprise Single Packet Authorization (SPA) — Ed25519 + ipset
 *
 * Replaces/extends the symmetric-HMAC SPA inside PortKnock with an
 * asymmetric scheme:
 *   - Client signs a fixed 256-byte UDP packet with its Ed25519 secret key.
 *   - Server only stores public keys (authorized_keys file), so a server
 *     compromise does not reveal any client secret material.
 *   - key_id = first 8 bytes of BLAKE2b-64(pubkey) — packets carry no
 *     identity beyond an opaque key fingerprint.
 *   - Replay protection: per-key nonce cache (16-byte CSPRNG nonces,
 *     entries expire after 120 s) plus a +/-60 s timestamp window.
 *   - On success the source IP is added to an ipset with a TTL; the
 *     protected TCP/UDP services stay fully DROP otherwise.
 *
 * Wire format (UDP payload, fixed 256 bytes, all integers big-endian):
 *   offset  size  field
 *   0       2     magic "SP" (0x53 0x50)
 *   2       1     version = 1
 *   3       8     key_id = BLAKE2b-64 of client Ed25519 pubkey
 *   11      8     timestamp_unix (seconds)
 *   19      16    nonce (CSPRNG)
 *   35      1     protocol (6=TCP, 17=UDP)
 *   36      2     allow_port — port the client wants opened
 *   38      4     requested_ttl_sec (0 = server default)
 *   42      64    Ed25519 signature over bytes [0..42)
 *   106     150   random padding (CSPRNG)
 *
 * Capture rationale (v1): SpaDaemon binds a plain UDP socket on the SPA
 * listen port. UDP has no connection state, so binding the port does not
 * expose any handshake surface for the protected TCP services — those stay
 * fully DROP. The SPA port itself answers nothing (never sends replies),
 * so a scanner only sees an open/closed UDP port that never responds.
 * NFQUEUE-based fully-stealth capture (no bound socket at all) is a
 * documented follow-up.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "ncp_crypto.hpp"
#include "ncp_secure_memory.hpp"

namespace ncp {

// ===== Wire format constants =====

constexpr size_t   SPA_PACKET_SIZE        = 256;
constexpr size_t   SPA_SIGNED_LEN         = 42;   // bytes covered by the signature
constexpr uint8_t  SPA_VERSION            = 1;
constexpr size_t   SPA_KEY_ID_LEN         = 8;
constexpr size_t   SPA_NONCE_LEN          = 16;
constexpr size_t   SPA_SIGNATURE_OFFSET   = 42;
constexpr size_t   SPA_PADDING_OFFSET     = 106;
constexpr uint16_t SPA_DEFAULT_PORT       = 54117;

using SpaKeyId = std::array<uint8_t, SPA_KEY_ID_LEN>;

// ===== Server decision result =====

enum class SpaResult {
    GRANTED,          // signature valid, access granted
    BAD_FORMAT,       // size/magic/version mismatch
    UNKNOWN_KEY,      // key_id not in authorized_keys
    STALE_TIMESTAMP,  // |now - ts| > window
    REPLAY,           // nonce already seen for this key
    BAD_SIGNATURE     // Ed25519 verification failed
};

const char* spa_result_to_string(SpaResult r) noexcept;

// ===== Access controller interface =====

struct IAccessController {
    virtual ~IAccessController() = default;
    virtual bool grant(const std::string& src_ip, uint8_t proto,
                       uint16_t port, uint32_t ttl_sec) = 0;
};

/**
 * @brief ipset-backed access controller.
 *
 * Ensures `ipset create <set> hash:ip timeout 0 -exist`, then on grant:
 *   `ipset add <set> <src_ip> timeout <ttl> -exist`
 * Commands are executed via an injectable command runner (default ::system,
 * consistent with ncp_dns_leak_prevention.cpp). In dry_run mode commands
 * are only logged/recorded, never executed. Every command is logged.
 */
class IpSetAccessController : public IAccessController {
public:
    using CommandRunner = std::function<int(const std::string& cmd)>;

    IpSetAccessController(std::string set_name, bool dry_run);

    bool grant(const std::string& src_ip, uint8_t proto,
               uint16_t port, uint32_t ttl_sec) override;

    /// Create the ipset if missing (idempotent). Called lazily on first grant.
    bool ensure_set();

    /// Documented companion iptables rule for README/logging.
    static std::string iptables_rule_hint(uint8_t proto, uint16_t port,
                                          const std::string& set_name);

    /// Test hook: replace the command executor.
    void set_command_runner(CommandRunner runner);

    /// Test hook: last ipset command issued (empty if none).
    std::string last_command() const;

    const std::string& set_name() const noexcept { return set_name_; }
    bool dry_run() const noexcept { return dry_run_; }

private:
    int run_command(const std::string& cmd);

    std::string set_name_;
    bool dry_run_;
    bool set_ensured_ = false;
    CommandRunner runner_;
    mutable std::mutex mu_;
    std::string last_command_;
};

// ===== SPA server =====

class SpaServer {
public:
    struct Config {
        uint32_t default_ttl_sec      = 300;    // used when packet ttl == 0
        uint32_t max_ttl_sec          = 86400;  // hard clamp
        uint64_t timestamp_window_sec = 60;     // +/- window
        uint64_t nonce_ttl_sec        = 120;    // replay-cache entry lifetime
    };

    SpaServer();
    explicit SpaServer(Config cfg);

    void set_access_controller(std::shared_ptr<IAccessController> ctrl);

    /// Load authorized_keys: one base64 Ed25519 pubkey (32 raw bytes) per
    /// line; '#' comments and blank lines allowed. Returns false if the file
    /// cannot be opened or contains no valid keys.
    bool load_authorized_keys(const std::string& path);

    /// Add a single raw 32-byte Ed25519 pubkey (test/embedding helper).
    bool add_authorized_key(const uint8_t* pubkey, size_t len);

    size_t authorized_key_count() const;

    /// Full verification pipeline; never throws.
    SpaResult process_packet(const uint8_t* data, size_t len,
                             const std::string& src_ip) noexcept;
    SpaResult process_packet(const std::vector<uint8_t>& data,
                             const std::string& src_ip) noexcept {
        return process_packet(data.data(), data.size(), src_ip);
    }

    /// Compute key_id for a raw 32-byte pubkey.
    static SpaKeyId key_id_for(const uint8_t* pubkey, size_t len);

private:
    void sweep_replay_cache_locked(std::chrono::steady_clock::time_point now);

    Config cfg_;
    Crypto crypto_;
    std::shared_ptr<IAccessController> controller_;

    mutable std::shared_mutex keys_mu_;
    std::unordered_map<std::string, std::array<uint8_t, 32>> keys_;  // key_id -> pubkey

    mutable std::mutex replay_mu_;
    // key_id -> (nonce -> first-seen time)
    std::unordered_map<std::string,
        std::unordered_map<std::string, std::chrono::steady_clock::time_point>> replay_cache_;
};

// ===== SPA client =====

/**
 * @brief Holds an Ed25519 keypair and builds/knocks SPA packets.
 *
 * Key file format (created by `ncp spa keygen`): a single base64 line of
 * the 96-byte blob [64-byte libsodium secret key || 32-byte pubkey].
 */
class SpaClient {
public:
    SpaClient();

    /// Generate a fresh keypair (invalidates any previously loaded one).
    bool generate();

    bool load_keyfile(const std::string& path);
    bool save_keyfile(const std::string& path) const;

    bool has_key() const noexcept;

    /// Build a 256-byte packet per the wire format (timestamp = now).
    std::vector<uint8_t> build_packet(uint8_t proto, uint16_t allow_port,
                                      uint32_t ttl_sec) const;

    /// Same as build_packet but with an explicit unix timestamp
    /// (testing / clock-skew scenarios).
    std::vector<uint8_t> build_packet_ts(uint8_t proto, uint16_t allow_port,
                                         uint32_t ttl_sec,
                                         uint64_t timestamp_unix) const;

    /// Send a single UDP datagram to host:udp_port. Returns true if sent.
    bool knock(const std::string& host, uint16_t udp_port, uint8_t proto,
               uint16_t allow_port, uint32_t ttl_sec) const;

    /// Send an already-built packet verbatim (replay self-test helper).
    bool send_packet(const std::string& host, uint16_t udp_port,
                     const std::vector<uint8_t>& packet) const;

    SpaKeyId key_id() const;
    std::string key_id_hex() const;

    /// base64 of the raw 32-byte pubkey — the authorized_keys line.
    std::string pubkey_base64() const;

private:
    SecureMemory secret_key_;  // 64 bytes (libsodium format)
    SecureMemory public_key_;  // 32 bytes
    mutable Crypto crypto_;
};

// ===== SPA daemon (UDP capture, v1) =====

/**
 * @brief Binds a UDP socket and feeds datagrams to SpaServer.
 *
 * Loop: recvfrom with SO_RCVTIMEO 1 s, check stop flag, dispatch. The
 * daemon never sends replies. See file header for the capture rationale.
 */
class SpaDaemon {
public:
    SpaDaemon(SpaServer& server, uint16_t port,
              std::string bind_addr = "0.0.0.0");
    ~SpaDaemon();

    SpaDaemon(const SpaDaemon&) = delete;
    SpaDaemon& operator=(const SpaDaemon&) = delete;

    /// Bind + spawn the receive thread. False on bind failure.
    bool start();
    void stop();
    bool running() const noexcept { return running_.load(); }

private:
    void loop();

    SpaServer& server_;
    uint16_t port_;
    std::string bind_addr_;
    int sock_ = -1;
    std::atomic<bool> stop_flag_{false};
    std::atomic<bool> running_{false};
    std::thread thread_;
};

// ===== base64 helpers (VARIANT_ORIGINAL, no padding surprises) =====

std::string spa_base64_encode(const uint8_t* data, size_t len);
bool spa_base64_decode(const std::string& b64, std::vector<uint8_t>& out);

} // namespace ncp
