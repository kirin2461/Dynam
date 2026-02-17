#ifndef NCP_ECH_HPP
#define NCP_ECH_HPP

/**
 * @file ncp_ech.hpp
 * @brief Encrypted Client Hello (ECH) implementation using HPKE (RFC 9180)
 * 
 * This implements TLS Encrypted Client Hello as specified in:
 * - draft-ietf-tls-esni (ECH specification)
 * - RFC 9180 (HPKE - Hybrid Public Key Encryption)
 * 
 * Requires OpenSSL 3.2+ for HPKE support.
 */

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <optional>

namespace ncp {
namespace DPI {
namespace ECH {

/**
 * @brief HPKE KEM (Key Encapsulation Mechanism) algorithms
 */
enum class HPKEKem : uint16_t {
    DHKEM_P256_HKDF_SHA256 = 0x0010,
    DHKEM_P384_HKDF_SHA384 = 0x0011,
    DHKEM_P521_HKDF_SHA512 = 0x0012,
    DHKEM_X25519_HKDF_SHA256 = 0x0020,
    DHKEM_X448_HKDF_SHA512 = 0x0021,
};

/**
 * @brief HPKE KDF (Key Derivation Function) algorithms
 */
enum class HPKEKDF : uint16_t {
    HKDF_SHA256 = 0x0001,
    HKDF_SHA384 = 0x0002,
    HKDF_SHA512 = 0x0003,
};

/**
 * @brief HPKE AEAD algorithms
 */
enum class HPKEAEAD : uint16_t {
    AES_128_GCM = 0x0001,
    AES_256_GCM = 0x0002,
    CHACHA20_POLY1305 = 0x0003,
};

/**
 * @brief HPKE cipher suite (KEM + KDF + AEAD)
 */
struct HPKECipherSuite {
    HPKEKem kem_id;
    HPKEKDF kdf_id;
    HPKEAEAD aead_id;

    HPKECipherSuite()
        : kem_id(HPKEKem::DHKEM_X25519_HKDF_SHA256),
          kdf_id(HPKEKDF::HKDF_SHA256),
          aead_id(HPKEAEAD::AES_128_GCM) {}

    HPKECipherSuite(HPKEKem kem, HPKEKDF kdf, HPKEAEAD aead)
        : kem_id(kem), kdf_id(kdf), aead_id(aead) {}
};

/**
 * @brief ECH configuration (simplified ECHConfig structure)
 */
struct ECHConfig {
    uint16_t version = 0xfe0d;  // ECH version (draft) - changed from uint8_t to uint16_t
    uint8_t config_id = 0;
    std::vector<uint8_t> public_key;  // Server's HPKE public key
    std::vector<HPKECipherSuite> cipher_suites;
    uint16_t maximum_name_length = 0;
    std::string public_name;  // Public name (for outer SNI)

    // Serialized ECHConfig for HPKE AAD
    std::vector<uint8_t> raw_config;
};

/**
 * @brief ECH client context for encryption
 */
class ECHClientContext {
public:
    ECHClientContext();
    ~ECHClientContext();

    /**
     * @brief Initialize with ECHConfig
     * @param config ECH configuration from DNS/HTTPS record
     * @return true on success
     */
    bool init(const ECHConfig& config);

    /**
     * @brief Encrypt ClientHelloInner using HPKE
     * @param client_hello_inner Plaintext inner ClientHello
     * @param client_hello_outer_aad Outer ClientHello for AAD binding
     * @param enc Output: HPKE encapsulated key
     * @param encrypted_payload Output: Encrypted inner ClientHello
     * @return true on success
     */
    bool encrypt(
        const std::vector<uint8_t>& client_hello_inner,
        const std::vector<uint8_t>& client_hello_outer_aad,
        std::vector<uint8_t>& enc,
        std::vector<uint8_t>& encrypted_payload
    );

    /**
     * @brief Get selected cipher suite
     */
    HPKECipherSuite get_cipher_suite() const;

    /**
     * @brief Get config ID
     */
    uint8_t get_config_id() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief ECH server context for decryption
 */
class ECHServerContext {
public:
    ECHServerContext();
    ~ECHServerContext();

    /**
     * @brief Initialize with server private key
     * @param private_key HPKE private key
     * @param cipher_suite Supported cipher suite
     * @return true on success
     */
    bool init(
        const std::vector<uint8_t>& private_key,
        const HPKECipherSuite& cipher_suite
    );

    /**
     * @brief Decrypt ClientHelloInner using HPKE
     * @param enc HPKE encapsulated key from client
     * @param encrypted_payload Encrypted inner ClientHello
     * @param client_hello_outer_aad Outer ClientHello for AAD verification
     * @param client_hello_inner Output: Decrypted inner ClientHello
     * @return true on success
     */
    bool decrypt(
        const std::vector<uint8_t>& enc,
        const std::vector<uint8_t>& encrypted_payload,
        const std::vector<uint8_t>& client_hello_outer_aad,
        std::vector<uint8_t>& client_hello_inner
    );

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Parse ECHConfig from wire format
 * @param data Raw ECHConfig bytes
 * @param config Output parsed config
 * @return true on success
 */
bool parse_ech_config(const std::vector<uint8_t>& data, ECHConfig& config);

/**
 * @brief Create ECHConfig for testing (generates keypair)
 * @param public_name Public name for outer SNI
 * @param cipher_suite HPKE cipher suite
 * @param private_key Output: Generated private key
 * @return ECHConfig with generated public key
 */
ECHConfig create_test_ech_config(
    const std::string& public_name,
    const HPKECipherSuite& cipher_suite,
    std::vector<uint8_t>& private_key
);

/**
 * @brief Apply ECH to ClientHello (replaces old insecure stub)
 * @param client_hello Original ClientHello
 * @param ech_config ECH configuration
 * @return ClientHello with ECH extension, or original on failure
 */
std::vector<uint8_t> apply_ech(
    const std::vector<uint8_t>& client_hello,
    const ECHConfig& ech_config
);

} // namespace ECH
} // namespace DPI
} // namespace ncp

#endif // NCP_ECH_HPP
