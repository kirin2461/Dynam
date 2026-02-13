#ifndef NCP_CRYPTO_HPP
#define NCP_CRYPTO_HPP

#include "ncp_secure_memory.hpp"
#include "ncp_secure_buffer.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace ncp {

class Crypto {
public:
    // Key pair structure with SecureMemory
    struct KeyPair {
        SecureMemory public_key;
        SecureMemory secret_key;
    };
    
    Crypto();
        ~Crypto() noexcept = default;
    
    // Key generation
    KeyPair generate_keypair();
    
    // Random generation - returns SecureMemory
    SecureMemory generate_random(size_t size);
    
    // Digital signatures (Ed25519)
    SecureMemory sign_ed25519(
        const SecureMemory& message,
        const SecureMemory& secret_key
    );
    
    bool verify_ed25519(
        const SecureMemory& message,
        const SecureMemory& signature,
        const SecureMemory& public_key
    );
    
    // Encryption/Decryption (ChaCha20-Poly1305)
    SecureMemory encrypt_chacha20(
        const SecureMemory& plaintext,
        const SecureMemory& key
    );
    
    SecureMemory decrypt_chacha20(
        const SecureMemory& ciphertext,
        const SecureMemory& key
    );
    
    // Hashing functions
    SecureMemory hash_sha256(const SecureMemory& data);
    SecureMemory hash_sha512(const SecureMemory& data);
    SecureMemory hash_blake2b(const SecureMemory& data, size_t output_len = 32);
    
    // Post-quantum signatures (Dilithium5) - requires liboqs
    KeyPair generate_dilithium_keypair();
    
    SecureMemory sign_dilithium(
        const SecureMemory& message,
        const SecureMemory& secret_key
    );
    
    bool verify_dilithium(
        const SecureMemory& message,
        const SecureMemory& signature,
        const SecureMemory& public_key
    );

    // AEAD encryption (XChaCha20-Poly1305)
    SecureMemory encrypt_aead(
        const SecureMemory& plaintext,
        const SecureMemory& key,
        const SecureMemory& additional_data = {}
    );

    SecureMemory decrypt_aead(
        const SecureMemory& ciphertext,
        const SecureMemory& key,
        const SecureMemory& additional_data = {}
    );

    // Utility: convert SecureMemory to hex string
        static std::string bytes_to_hex(const SecureMemory& mem) noexcept {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 0; i < mem.size(); ++i) {
            oss << std::setw(2) << static_cast<int>(mem.data()[i]);
        }
        return oss.str();
    }
    
private:
    void init_libsodium();
};

} // namespace ncp

#endif // NCP_CRYPTO_HPP
