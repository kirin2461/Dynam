#pragma once

/**
 * @file ncp_reality.hpp
 * @brief XTLS-Reality-style fallback server (dest-mapping) — Enterprise wave 1 (M1)
 *
 * The server listens on TCP. The first bytes of a connection must be a TLS
 * ClientHello. AUTHORIZED clients embed an access token in the left-most SNI
 * label of the gateway domain; everyone else is transparently spliced to a
 * real fallback domain (e.g. www.microsoft.com:443) so probes and scanners
 * observe a genuine TLS session with the real site.
 *
 * Token scheme:
 *   token = Ed25519_sign(client_key, "ncp-reality" || gateway_domain || window)
 *   window = unix_time / 60 (8 bytes, big-endian)
 * The signature is base32-encoded (RFC4648, lowercase, no padding) and the
 * first 26 characters become the left-most SNI label:
 *   <token26>.gw.<gateway_domain>
 *
 * Verification note: a 26-character base32 token carries only ~130 bits of
 * the 512-bit Ed25519 signature, so a public-key-only check of the truncated
 * signature is not possible with libsodium (crypto_sign_verify_detached
 * requires the full 64-byte signature). Because Ed25519 signatures are
 * deterministic, the server re-computes the candidate signature for the
 * current and previous time window and compares the token prefix in
 * constant time. This requires the server to hold the client secret keys
 * (provision_secret()); public-key-only entries cannot verify tokens and
 * are skipped. This preserves the wire format and API shape from the SPEC.
 *
 * Security notes:
 *   - Ed25519 via libsodium (crypto_sign_detached), consistent with ncp_spa
 *   - Constant-time token comparison (sodium_memcmp)
 *   - RealityAuth is internally synchronized; RealityServer is reentrant
 *   - No exceptions across the public API
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "ncp_winsock_init.hpp"

namespace ncp {

// ===== Classification result =====

enum class RealityDecision {
    AUTHORIZED,  // Valid token in SNI — forward to the internal service
    FALLBACK,    // TLS ClientHello but not authorized — splice to fallback
    NOT_TLS      // First bytes are not a TLS record — drop
};

const char* reality_decision_to_string(RealityDecision d) noexcept;

// ===== Server-side token verification =====

class RealityAuth {
public:
    RealityAuth();
    explicit RealityAuth(std::map<std::string, std::array<uint8_t, 32>> client_pubkeys);

    // Register an authorized client public key.
    void add_key(const std::string& key_id, const std::array<uint8_t, 32>& pubkey);

    // Provision the client secret key for an already-registered key_id.
    // Required for verification (see file header note). Keys without a
    // provisioned secret are skipped during verification.
    void provision_secret(const std::string& key_id,
                          const std::array<uint8_t, 64>& secret_key);

    // Extract the token label from sni (<token26>.gw.<gateway_domain>) and
    // verify it against the current and previous 60-second time window.
    // Returns false for malformed SNI, unknown keys and stale/future windows.
    bool verify_sni(const std::string& sni, uint64_t now) const;

    size_t key_count() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;  // shared_ptr: copyable for RealityConfig
};

// ===== Client-side token / SNI builder =====

class RealityTokenBuilder {
public:
    // Build "<token26>.gw.<gateway_domain>" for the current time window.
    // key_id identifies the client key on the server side (not sent on wire).
    static std::string make_sni(const std::string& key_id,
                                const std::array<uint8_t, 64>& secret_key,
                                const std::string& gateway_domain,
                                uint64_t now);
};

// ===== Server configuration =====

struct RealityConfig {
    uint16_t    listen_port    = 443;
    std::string fallback_host  = "www.microsoft.com";
    uint16_t    fallback_port  = 443;
    std::string internal_host  = "127.0.0.1";
    uint16_t    internal_port  = 8443;
    RealityAuth auth;
};

// ===== Fallback server (testable core) =====

class RealityServer {
public:
    using Decision = RealityDecision;

    explicit RealityServer(RealityConfig cfg);

    // Classify the first bytes of a connection (expected: TLS ClientHello).
    Decision classify(const uint8_t* clienthello, size_t len, uint64_t now) const;

    // Minimal TLS ClientHello parser: extracts the SNI host name.
    // Returns false if the buffer is not a well-formed ClientHello record or
    // carries no SNI extension.
    static bool extract_sni(const uint8_t* clienthello, size_t len,
                            std::string& out_sni) noexcept;

    // Bidirectional byte splicing between two connected sockets using
    // poll() (POSIX) / WSAPoll() (Windows). Half-close aware: EOF on one
    // side shutdown()s the opposite write half; returns once both
    // directions are closed. Single-threaded.
    // socket_t is int on POSIX and Winsock SOCKET on Windows.
    static void splice(socket_t fd_a, socket_t fd_b) noexcept;

    // Read the ClientHello from client_fd, classify it, connect to the
    // internal service (AUTHORIZED) or the fallback domain (FALLBACK) and
    // splice the connection. NOT_TLS connections are closed immediately.
    // Returns true if the connection was spliced to an upstream.
    bool handle_client(socket_t client_fd, uint64_t now) const noexcept;

    const RealityConfig& config() const noexcept { return cfg_; }

private:
    RealityConfig cfg_;
};

} // namespace ncp
