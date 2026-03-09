/**
 * @file ncp_crypto_constants.hpp
 * @brief Cryptographic constants and magic numbers
 *
 * FIXED Issue #17.10: Replace magic numbers with named constants
 * for better code readability and maintainability.
 */

#ifndef NCP_CRYPTO_CONSTANTS_HPP
#define NCP_CRYPTO_CONSTANTS_HPP

#include <cstddef>

namespace ncp {
namespace crypto {

// ==================== Key Sizes ====================

/// Ed25519 public key size (32 bytes)
constexpr size_t ED25519_PUBLIC_KEY_BYTES = 32;

/// Ed25519 secret key size (64 bytes)
constexpr size_t ED25519_SECRET_KEY_BYTES = 64;

/// Ed25519 signature size (64 bytes)
constexpr size_t ED25519_SIGNATURE_BYTES = 64;

/// ChaCha20-Poly1305 key size (32 bytes)
constexpr size_t CHACHA20_KEY_BYTES = 32;

/// ChaCha20-Poly1305 nonce size (12 bytes for IETF variant)
constexpr size_t CHACHA20_NONCE_BYTES = 12;

/// ChaCha20-Poly1305 authentication tag size (16 bytes)
constexpr size_t CHACHA20_MAC_BYTES = 16;

/// XChaCha20-Poly1305 key size (32 bytes)
constexpr size_t XCHACHA20_KEY_BYTES = 32;

/// XChaCha20-Poly1305 nonce size (24 bytes)
constexpr size_t XCHACHA20_NONCE_BYTES = 24;

/// XChaCha20-Poly1305 authentication tag size (16 bytes)
constexpr size_t XCHACHA20_MAC_BYTES = 16;

/// Generic symmetric key size (32 bytes)
constexpr size_t SYMMETRIC_KEY_BYTES = 32;

// ==================== Hash Sizes ====================

/// SHA-256 hash output size (32 bytes)
constexpr size_t SHA256_HASH_BYTES = 32;

/// SHA-512 hash output size (64 bytes)
constexpr size_t SHA512_HASH_BYTES = 64;

/// BLAKE2b default hash output size (32 bytes)
constexpr size_t BLAKE2B_HASH_BYTES = 32;

/// BLAKE2b maximum hash output size (64 bytes)
constexpr size_t BLAKE2B_MAX_HASH_BYTES = 64;

/// Generic hash size (32 bytes, compatible with BLAKE2b)
constexpr size_t GENERIC_HASH_BYTES = 32;

// ==================== Password Hashing ====================

/// Argon2 salt size (16 bytes minimum)
constexpr size_t PASSWORD_SALT_BYTES = 16;

/// Argon2 recommended output size (32 bytes)
constexpr size_t PASSWORD_HASH_BYTES = 32;

/// Argon2id operations limit (interactive)
constexpr unsigned long long PASSWORD_OPSLIMIT_INTERACTIVE = 2;

/// Argon2id memory limit (interactive, ~64 MB)
constexpr size_t PASSWORD_MEMLIMIT_INTERACTIVE = 67108864;

/// Argon2id operations limit (moderate)
constexpr unsigned long long PASSWORD_OPSLIMIT_MODERATE = 3;

/// Argon2id memory limit (moderate, ~256 MB)
constexpr size_t PASSWORD_MEMLIMIT_MODERATE = 268435456;

/// Argon2id operations limit (sensitive)
constexpr unsigned long long PASSWORD_OPSLIMIT_SENSITIVE = 4;

/// Argon2id memory limit (sensitive, ~1 GB)
constexpr size_t PASSWORD_MEMLIMIT_SENSITIVE = 1073741824;

// ==================== Random Number Generation ====================

/// Recommended random seed size (32 bytes)
constexpr size_t RANDOM_SEED_BYTES = 32;

/// Random bytes buffer size for bulk generation (4096 bytes)
constexpr size_t RANDOM_BUFFER_BYTES = 4096;

// ==================== Post-Quantum Cryptography ====================

/// Dilithium5 public key size (2592 bytes)
constexpr size_t DILITHIUM5_PUBLIC_KEY_BYTES = 2592;

/// Dilithium5 secret key size (4864 bytes)
constexpr size_t DILITHIUM5_SECRET_KEY_BYTES = 4864;

/// Dilithium5 signature size (4595 bytes)
constexpr size_t DILITHIUM5_SIGNATURE_BYTES = 4595;

/// Kyber1024 public key size (1568 bytes)
constexpr size_t KYBER1024_PUBLIC_KEY_BYTES = 1568;

/// Kyber1024 secret key size (3168 bytes)
constexpr size_t KYBER1024_SECRET_KEY_BYTES = 3168;

/// Kyber1024 ciphertext size (1568 bytes)
constexpr size_t KYBER1024_CIPHERTEXT_BYTES = 1568;

/// Kyber1024 shared secret size (32 bytes)
constexpr size_t KYBER1024_SHARED_SECRET_BYTES = 32;

// ==================== Memory and Buffer Sizes ====================

/// Default secure memory allocation size (4096 bytes, page-aligned)
constexpr size_t DEFAULT_SECURE_BUFFER_SIZE = 4096;

/// Maximum secure memory allocation size (16 MB)
constexpr size_t MAX_SECURE_BUFFER_SIZE = 16777216;

/// Minimum secure memory allocation size (16 bytes)
constexpr size_t MIN_SECURE_BUFFER_SIZE = 16;

// ==================== Network Protocol Constants ====================

/// Maximum packet size for DPI evasion (1400 bytes, avoids fragmentation)
constexpr size_t MAX_PACKET_SIZE = 1400;

/// Minimum packet size (64 bytes)
constexpr size_t MIN_PACKET_SIZE = 64;

/// TLS record maximum size (16384 bytes)
constexpr size_t TLS_RECORD_MAX_SIZE = 16384;

// ==================== Timing Constants ====================

/// Key rotation interval (24 hours in seconds)
constexpr unsigned int KEY_ROTATION_INTERVAL_SECONDS = 86400;

/// Session timeout (30 minutes in seconds)
constexpr unsigned int SESSION_TIMEOUT_SECONDS = 1800;

/// Handshake timeout (10 seconds)
constexpr unsigned int HANDSHAKE_TIMEOUT_SECONDS = 10;

// ==================== Entropy and Randomness ====================

/// Minimum entropy bits required for key generation
constexpr size_t MIN_ENTROPY_BITS = 256;

/// Target entropy bits for high-security operations
constexpr size_t TARGET_ENTROPY_BITS = 512;

// ==================== Protocol Version ====================

/// NCP protocol major version
constexpr uint8_t PROTOCOL_VERSION_MAJOR = 1;

/// NCP protocol minor version
constexpr uint8_t PROTOCOL_VERSION_MINOR = 2;

/// NCP protocol patch version (bumped for mimicry wire format v2)
constexpr uint8_t PROTOCOL_VERSION_PATCH = 1;

// ==================== Helper Functions ====================

/**
 * @brief Get protocol version as packed uint32_t
 * @return Version in format 0xMMmmpppp (major, minor, patch)
 */
constexpr uint32_t get_protocol_version() noexcept {
    return (static_cast<uint32_t>(PROTOCOL_VERSION_MAJOR) << 24) |
           (static_cast<uint32_t>(PROTOCOL_VERSION_MINOR) << 16) |
           (static_cast<uint32_t>(PROTOCOL_VERSION_PATCH));
}

/**
 * @brief Check if buffer size is valid for secure allocation
 * @param size Buffer size to validate
 * @return true if size is within valid range
 */
constexpr bool is_valid_buffer_size(size_t size) noexcept {
    return size >= MIN_SECURE_BUFFER_SIZE && size <= MAX_SECURE_BUFFER_SIZE;
}

/**
 * @brief Round up size to nearest page boundary (4096)
 * @param size Size to round up
 * @return Page-aligned size
 */
constexpr size_t align_to_page(size_t size) noexcept {
    constexpr size_t PAGE_SIZE = 4096;
    return ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
}

} // namespace crypto
} // namespace ncp

#endif // NCP_CRYPTO_CONSTANTS_HPP
