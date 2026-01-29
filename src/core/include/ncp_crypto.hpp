#ifndef NCP_CRYPTO_HPP
#define NCP_CRYPTO_HPP

#include <vector>
#include <string>
#include <cstdint>

namespace NCP {

class Crypto {
public:
    // Key pair structure
    struct KeyPair {
        std::vector<uint8_t> public_key;  // 32 bytes for Ed25519
        std::vector<uint8_t> secret_key;  // 64 bytes for Ed25519
    };

    Crypto();
    ~Crypto() = default;

    // Key generation
    KeyPair generate_keypair();

    // Random generation
    std::vector<uint8_t> generate_random(size_t size);

    // Digital signatures
    std::vector<uint8_t> sign_message(
        const std::string& message,
        const std::vector<uint8_t>& secret_key
    );

    bool verify_signature(
        const std::string& message,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key
    );

#ifdef HAVE_LIBOQS
    // Post-quantum signatures (CRYSTALS-Dilithium)
    KeyPair generate_dilithium_keypair();
    
    std::vector<uint8_t> sign_dilithium(
        const std::vector<unsigned char>& message,
        const std::vector<unsigned char>& secret_key
    );
    
    bool verify_dilithium(
        const std::vector<unsigned char>& message,
        const std::vector<unsigned char>& signature,
        const std::vector<unsigned char>& public_key
    );
#endif

    // ChaCha20 encryption/decryption
    std::vector<uint8_t> encrypt_chacha20(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key
    );

    std::vector<uint8_t> decrypt_chacha20(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key
    );

    // Hashing - both overloads
    std::vector<uint8_t> hash_sha256(const std::string& data);
    std::vector<uint8_t> hash_sha256(const std::vector<uint8_t>& data);

    // Utility functions
    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);

private:
    void init_libsodium();
};

} // namespace NCP

#endif // NCP_CRYPTO_HPP
