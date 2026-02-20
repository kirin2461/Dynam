#include "../include/ncp_e2e.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cstring>

// OpenSSL for X448 and ECDH_P256
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

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

// ===== Phase 2.3: generate_key_pair() — X448 + ECDH_P256 implementation =====
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

        case KeyExchangeProtocol::X448: {
            // X448 key generation via OpenSSL EVP API
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
            if (!pctx) {
                throw std::runtime_error("Failed to create X448 context");
            }

            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to initialize X448 keygen");
            }

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to generate X448 keypair");
            }
            EVP_PKEY_CTX_free(pctx);

            // Extract raw public key (56 bytes for X448)
            size_t pubkey_len = 56;
            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract X448 public key");
            }
            kp.public_key.resize(pubkey_len);

            // Extract raw private key (56 bytes for X448)
            size_t privkey_len = 56;
            kp.private_key = SecureMemory(privkey_len);
            if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &privkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract X448 private key");
            }
            kp.private_key.resize(privkey_len);

            EVP_PKEY_free(pkey);
            break;
        }

        case KeyExchangeProtocol::ECDH_P256: {
            // ECDH P-256 key generation via OpenSSL EVP API
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!pctx) {
                throw std::runtime_error("Failed to create ECDH P-256 context");
            }

            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to initialize ECDH P-256 keygen");
            }

            // Set curve to P-256 (NID_X9_62_prime256v1)
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to set ECDH P-256 curve");
            }

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to generate ECDH P-256 keypair");
            }
            EVP_PKEY_CTX_free(pctx);

            // Extract public key (uncompressed point: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes)
            size_t pubkey_len = 0;
            if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to query ECDH P-256 public key size");
            }

            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract ECDH P-256 public key");
            }

            // Extract private key (32 bytes scalar)
            size_t privkey_len = 0;
            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &privkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to query ECDH P-256 private key size");
            }

            kp.private_key = SecureMemory(privkey_len);
            if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &privkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract ECDH P-256 private key");
            }

            EVP_PKEY_free(pkey);
            break;
        }

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

// ===== Phase 2.3: compute_shared_secret() — X448 + ECDH_P256 implementation =====
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

        case KeyExchangeProtocol::X448: {
            // X448 shared secret computation via OpenSSL EVP_PKEY_derive
            if (peer_public_key.size() != 56) {
                throw std::runtime_error("Invalid peer public key size for X448 (expected 56 bytes)");
            }

            // Load local private key
            EVP_PKEY* local_pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, nullptr,
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            );
            if (!local_pkey) {
                throw std::runtime_error("Failed to load X448 local private key");
            }

            // Load peer public key
            EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X448, nullptr,
                peer_public_key.data(),
                peer_public_key.size()
            );
            if (!peer_pkey) {
                EVP_PKEY_free(local_pkey);
                throw std::runtime_error("Failed to load X448 peer public key");
            }

            // Derive shared secret
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_pkey, nullptr);
            if (!ctx) {
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to create X448 derive context");
            }

            if (EVP_PKEY_derive_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to initialize X448 derive");
            }

            if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to set X448 peer key");
            }

            size_t secret_len = 0;
            if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to query X448 shared secret size");
            }

            SecureMemory shared_secret(secret_len);
            if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to derive X448 shared secret");
            }

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(local_pkey);
            EVP_PKEY_free(peer_pkey);

            return shared_secret;
        }

        case KeyExchangeProtocol::ECDH_P256: {
            // ECDH P-256 shared secret computation via OpenSSL EVP_PKEY_derive
            if (peer_public_key.size() != 65) {  // Uncompressed point: 0x04 + 32 + 32
                throw std::runtime_error("Invalid peer public key size for ECDH P-256 (expected 65 bytes)");
            }

            // Load local private key
            EVP_PKEY* local_pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_EC, nullptr,
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            );
            if (!local_pkey) {
                throw std::runtime_error("Failed to load ECDH P-256 local private key");
            }

            // Load peer public key
            EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_EC, nullptr,
                peer_public_key.data(),
                peer_public_key.size()
            );
            if (!peer_pkey) {
                EVP_PKEY_free(local_pkey);
                throw std::runtime_error("Failed to load ECDH P-256 peer public key");
            }

            // Derive shared secret
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_pkey, nullptr);
            if (!ctx) {
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to create ECDH P-256 derive context");
            }

            if (EVP_PKEY_derive_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to initialize ECDH P-256 derive");
            }

            if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to set ECDH P-256 peer key");
            }

            size_t secret_len = 0;
            if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to query ECDH P-256 shared secret size");
            }

            SecureMemory shared_secret(secret_len);
            if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to derive ECDH P-256 shared secret");
            }

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(local_pkey);
            EVP_PKEY_free(peer_pkey);

            return shared_secret;
        }

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
            sodium_memzero(kdf_context, sizeof(kdf_context));
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

    // Guard against integer overflow: plaintext + ABYTES must not overflow
    if (plaintext.size() > SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error("Plaintext too large");
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

    // Ciphertext must contain at least the authentication tag
    if (message.ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error("Ciphertext too short - missing authentication tag");
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
        // Zero the plaintext buffer before throwing to avoid leaking partial data
        sodium_memzero(plaintext.data(), plaintext.size());
        throw std::runtime_error("Decryption failed or authentication tag invalid");
    }

    plaintext.resize(plaintext_len);
    return plaintext;
}

std::string E2ESession::get_session_id() const {
    return pImpl_->session_id;
}

} // namespace ncp
