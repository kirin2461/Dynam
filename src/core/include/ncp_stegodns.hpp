#pragma once

/**
 * @file ncp_stegodns.hpp
 * @brief Zero-Knowledge Stego-DNS records — Enterprise wave 1 (M4)
 *
 * Publishes server bootstrap parameters as a DNS TXT record that is
 * indistinguishable from an ordinary SPF record. Only holders of the
 * master passphrase (decryption) can read it; only the holder of the
 * signing key (publisher) can create valid records.
 *
 * Payload (43 bytes, big-endian where applicable):
 *   magic(2) = "ND" | ver(1) = 1 | ipv4(4) | port(2, BE) |
 *   spa_pubkey(32) | expires_unix(4, BE)
 *
 * Wire format:
 *   key        = BLAKE2b(master_passphrase, 32)
 *   ciphertext = XChaCha20-Poly1305(key, payload)           (43 + 16 bytes)
 *   nonce      = random 24 bytes (prepended to ciphertext)
 *   sig        = Ed25519_sign(signing_key, nonce || ciphertext)  (64 bytes)
 *   blob       = sig || nonce || ciphertext                 (147 bytes)
 *
 * Encoding: base32 (RFC4648, lowercase, '=' stripped) of blob, split 60/40
 * across two syntactically valid SPF terms:
 *   v=spf1 ip4:<b32-part1> include:<b32-part2>._ncp.<domain> ~all
 *
 * Security notes:
 *   - AEAD (XChaCha20-Poly1305) gives confidentiality + integrity;
 *     Ed25519 signature authenticates the publisher.
 *   - expires_unix == 0 means "never expires".
 *   - Encoder/decoder are immutable after construction (thread-safe).
 *   - No exceptions across the public API; decode failures yield nullopt.
 */

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ncp {

// ===== Node parameters carried inside the TXT record =====

struct NodeParams {
    std::array<uint8_t, 4>  ipv4{};          // dotted-quad bytes, in order
    uint16_t                port = 0;
    std::array<uint8_t, 32> spa_pubkey{};    // SPA server public key
    uint32_t                expires_unix = 0;  // 0 = never expires

    bool operator==(const NodeParams& o) const {
        return ipv4 == o.ipv4 && port == o.port &&
               spa_pubkey == o.spa_pubkey && expires_unix == o.expires_unix;
    }
    bool operator!=(const NodeParams& o) const { return !(*this == o); }
};

// ===== Publisher side =====

class StegoDnsEncoder {
public:
    // signing_secret_key: 64-byte libsodium Ed25519 secret key.
    StegoDnsEncoder(const std::string& master_passphrase,
                    const std::array<uint8_t, 64>& signing_secret_key);

    // Random-nonce production path.
    std::string encode_txt(const NodeParams& params,
                           const std::string& domain) const;

    // Deterministic testing hook (golden vectors): caller supplies the nonce.
    std::string encode_txt(const NodeParams& params,
                           const std::string& domain,
                           const std::array<uint8_t, 24>& fixed_nonce) const;

private:
    std::array<uint8_t, 32> enc_key_{};
    std::array<uint8_t, 64> sign_sk_{};
};

// ===== Consumer side =====

class StegoDnsDecoder {
public:
    StegoDnsDecoder(const std::string& master_passphrase,
                    const std::array<uint8_t, 32>& verify_pubkey);

    // Validate SPF shape, reassemble the blob, verify the signature, decrypt
    // and check expiry against `now` (unix time). Any failure -> nullopt.
    std::optional<NodeParams> decode_txt(std::string_view txt,
                                         uint64_t now) const;

private:
    std::array<uint8_t, 32> enc_key_{};
    std::array<uint8_t, 32> verify_pk_{};
};

} // namespace ncp
