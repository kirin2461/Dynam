#include "../include/ncp_e2e.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cstring>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

// Implementation details
struct E2ESession::Impl {
    E2EConfig config;
    std::mutex mutex;
    std::string session_id;
    
    explicit Impl(const E2EConfig& cfg) : config(cfg) {
        generate_session_id();
    }
    
    void generate_session_id();
};

void E2ESession::Impl::generate_session_id() {
    std::vector<uint8_t> random_bytes(16);
    randombytes_buf(random_bytes.data(), random_bytes.size());
    
    std::ostringstream oss;
    for (auto byte : random_bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    session_id = oss.str();
}

// E2ESession implementation
E2ESession::E2ESession(const E2EConfig& config)
    : pImpl_(std::make_unique<Impl>(config)) {}

E2ESession::~E2ESession() = default;

KeyPair E2ESession::generate_key_pair() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    KeyPair kp;
    kp.protocol = pImpl_->config.key_exchange;
    kp.created_at = std::chrono::system_clock::now();
    kp.expires_at = kp.created_at + std::chrono::hours(24);
    
    switch (kp.protocol) {
        case KeyExchangeProtocol::X25519:
            kp.public_key = SecureMemory(crypto_box_PUBLICKEYBYTES);
            kp.private_key = SecureMemory(crypto_box_SECRETKEYBYTES);
            crypto_box_keypair(kp.public_key.data(), kp.private_key.data());
            break;
            
        case KeyExchangeProtocol::X448:
            throw std::runtime_error("X448 not supported by libsodium - use X25519 or implement with OpenSSL");
            
        case KeyExchangeProtocol::ECDH_P256:
            throw std::runtime_error("ECDH P-256 not supported by libsodium - use X25519 or implement with OpenSSL");
            
        case KeyExchangeProtocol::Kyber1024:
#ifdef HAVE_LIBOQS
            {
                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
                if (!kem) {
                    throw std::runtime_error("Failed to initialize Kyber1024 KEM");
                }
                
                kp.public_key = SecureMemory(kem->length_public_key);
                kp.private_key = SecureMemory(kem->length_secret_key);
                
                if (OQS_KEM_keypair(kem, kp.public_key.data(), kp.private_key.data()) != OQS_SUCCESS) {
                    OQS_KEM_free(kem);
                    throw std::runtime_error("Failed to generate Kyber1024 keypair");
                }
                
                OQS_KEM_free(kem);
            }
#else
            throw std::runtime_error("Kyber1024 requires liboqs - recompile with HAVE_LIBOQS");
#endif
            break;
    }
    
    return kp;
}

SecureMemory E2ESession::compute_shared_secret(
    const KeyPair& local_keypair,
    const std::vector<uint8_t>& peer_public_key
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    if (local_keypair.protocol != pImpl_->config.key_exchange) {
        throw std::runtime_error("Key exchange protocol mismatch");
    }
    
    switch (local_keypair.protocol) {
        case KeyExchangeProtocol::X25519: {
            if (peer_public_key.size() != crypto_box_PUBLICKEYBYTES) {
                throw std::runtime_error("Invalid peer public key size for X25519");
            }
            
            SecureMemory shared_secret(crypto_scalarmult_BYTES);
            if (crypto_scalarmult(shared_secret.data(), 
                                 local_keypair.private_key.data(),
                                 peer_public_key.data()) != 0) {
                throw std::runtime_error("Failed to compute X25519 shared secret");
            }
            return shared_secret;
        }
        
        case KeyExchangeProtocol::X448:
            throw std::runtime_error("X448 not supported by libsodium");
            
        case KeyExchangeProtocol::ECDH_P256:
            throw std::runtime_error("ECDH P-256 not supported by libsodium");
            
        case KeyExchangeProtocol::Kyber1024:
#ifdef HAVE_LIBOQS
            {
                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
                if (!kem) {
                    throw std::runtime_error("Failed to initialize Kyber1024 KEM");
                }
                
                SecureMemory ciphertext(kem->length_ciphertext);
                SecureMemory shared_secret(kem->length_shared_secret);
                
                if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(),
                                   peer_public_key.data()) != OQS_SUCCESS) {
                    OQS_KEM_free(kem);
                    throw std::runtime_error("Failed to encapsulate with Kyber1024");
                }
                
                OQS_KEM_free(kem);
                return shared_secret;
            }
#else
            throw std::runtime_error("Kyber1024 requires liboqs - recompile with HAVE_LIBOQS");
#endif
    }
    
    throw std::runtime_error("Unsupported key exchange protocol");
}

SecureMemory E2ESession::derive_keys(
    const SecureMemory& shared_secret,
    const std::string& context,
    size_t key_length
) {
    if (key_length < crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Key length too small");
    }
    
    SecureMemory derived_key(key_length);
    
    // Context must be exactly 8 bytes for crypto_kdf_derive_from_key
        char kdf_context[crypto_kdf_CONTEXTBYTES];
    std::memset(kdf_context, 0, sizeof(kdf_context));
    size_t copy_len = std::min(context.size(), sizeof(kdf_context));
    std::memcpy(kdf_context, context.data(), copy_len);
    
    // Master key from shared secret
    uint8_t master_key[crypto_kdf_KEYBYTES];
    crypto_generichash(master_key, sizeof(master_key),
                      shared_secret.data(), shared_secret.size(),
                      nullptr, 0);
    
    // Derive subkeys
    size_t derived = 0;
    uint64_t subkey_id = 0;
    
    while (derived < key_length) {
        uint8_t subkey[crypto_kdf_BYTES_MAX];
        size_t to_derive = std::min(key_length - derived, sizeof(subkey));
        
        if (crypto_kdf_derive_from_key(subkey, to_derive, subkey_id++,
                                                               kdf_context, master_key) != 0) {
            sodium_memzero(master_key, sizeof(master_key));
            throw std::runtime_error("Failed to derive key");
        }
        
        std::memcpy(derived_key.data() + derived, subkey, to_derive);
        derived += to_derive;
        sodium_memzero(subkey, sizeof(subkey));
    }
    
    sodium_memzero(master_key, sizeof(master_key));
    sodium_memzero(kdf_context, sizeof(kdf_context));
    
    return derived_key;
}

EncryptedMessage E2ESession::encrypt_message(
    const std::vector<uint8_t>& plaintext,
    const SecureMemory& encryption_key
) {
    if (encryption_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid encryption key size");
    }
    
    EncryptedMessage msg;
    msg.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.nonce.data(), msg.nonce.size());
    
    msg.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    unsigned long long ciphertext_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            msg.ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr,
            msg.nonce.data(),
            encryption_key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }
    
    msg.ciphertext.resize(ciphertext_len);
    msg.timestamp = std::chrono::system_clock::now();
    
    return msg;
}

std::vector<uint8_t> E2ESession::decrypt_message(
    const EncryptedMessage& message,
    const SecureMemory& decryption_key
) {
    if (decryption_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid decryption key size");
    }
    
    if (message.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        throw std::runtime_error("Invalid nonce size");
    }
    
    std::vector<uint8_t> plaintext(message.ciphertext.size());
    unsigned long long plaintext_len;
    
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            message.ciphertext.data(), message.ciphertext.size(),
            nullptr, 0,
            message.nonce.data(),
            decryption_key.data()) != 0) {
        throw std::runtime_error("Decryption failed or authentication tag invalid");
    }
    
    plaintext.resize(plaintext_len);
    return plaintext;
}

std::string E2ESession::get_session_id() const {
    return pImpl_->session_id;
}

} // namespace ncp
