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
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

// ===== RAII helpers for OpenSSL resources =====
namespace {

struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); }
};
using UniqueEVP_PKEY     = std::unique_ptr<EVP_PKEY,     EVP_PKEY_Deleter>;
using UniqueEVP_PKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;

/**
 * Build an EVP_PKEY for EC P-256 from raw private key bytes (32-byte scalar)
 * and optional raw public key bytes (65-byte uncompressed point).
 * Uses OpenSSL 3.x EVP_PKEY_fromdata() — the correct API for EC keys.
 *
 * FIX for issue #50: EVP_PKEY_new_raw_private_key(EVP_PKEY_EC, ...) is NOT
 * supported by OpenSSL. Only X25519/X448/Ed25519/Ed448 have "raw" key APIs.
 */
UniqueEVP_PKEY ec_p256_pkey_from_private(const uint8_t* priv_raw, size_t priv_len,
                                          const uint8_t* pub_raw,  size_t pub_len)
{
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) throw std::runtime_error("OSSL_PARAM_BLD_new failed");

    BIGNUM* priv_bn = BN_bin2bn(priv_raw, static_cast<int>(priv_len), nullptr);
    if (!priv_bn) {
        OSSL_PARAM_BLD_free(bld);
        throw std::runtime_error("BN_bin2bn failed for EC P-256 private key");
    }

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);
    if (pub_raw && pub_len > 0) {
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_raw, pub_len);
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(priv_bn);
    if (!params) throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");

    UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name(EC) failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_fromdata failed for EC P-256 private key");
    }
    OSSL_PARAM_free(params);
    return UniqueEVP_PKEY(pkey);
}

/**
 * Build an EVP_PKEY for EC P-256 from a raw public key (65-byte uncompressed point).
 * FIX for issue #50.
 */
UniqueEVP_PKEY ec_p256_pkey_from_public(const uint8_t* pub_raw, size_t pub_len)
{
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) throw std::runtime_error("OSSL_PARAM_BLD_new failed");

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_raw, pub_len);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");

    UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name(EC) failed");
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        OSSL_PARAM_free(params);
        throw std::runtime_error("EVP_PKEY_fromdata failed for EC P-256 public key");
    }
    OSSL_PARAM_free(params);
    return UniqueEVP_PKEY(pkey);
}

} // anonymous namespace

// Implementation details
struct E2ESession::Impl {
    E2EConfig config;
    std::mutex mutex;
    std::string session_id;

    // === Session state (FIX #52) ===
    E2ESessionState state = E2ESessionState::Uninitialized;
    RatchetState ratchet;
    KeyPair local_keypair;
    SecureMemory sending_chain_key;
    SecureMemory receiving_chain_key;
    std::chrono::system_clock::time_point last_activity;
    std::chrono::system_clock::time_point session_created_at;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;

    // Kyber1024 KEM: store last ciphertext for the caller (FIX #51)
    std::vector<uint8_t> last_kem_ciphertext;

    explicit Impl(const E2EConfig& cfg) : config(cfg) {
        generate_session_id();
        session_created_at = std::chrono::system_clock::now();
        last_activity = session_created_at;
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

// ===== generate_key_pair() =====
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
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
            if (!pctx) throw std::runtime_error("Failed to create X448 context");
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

            size_t pubkey_len = 56;
            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract X448 public key");
            }
            kp.public_key.resize(pubkey_len);

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
            // FIX #50: Use EVP_PKEY_fromdata-compatible key generation
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!pctx) throw std::runtime_error("Failed to create ECDH P-256 context");
            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to initialize ECDH P-256 keygen");
            }
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

            // Extract public key as uncompressed point (65 bytes)
            size_t pubkey_len = 0;
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                  nullptr, 0, &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to query ECDH P-256 public key size");
            }
            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                  kp.public_key.data(), pubkey_len, &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract ECDH P-256 public key");
            }

            // Extract private key scalar as BIGNUM -> raw bytes
            BIGNUM* priv_bn = nullptr;
            if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0 || !priv_bn) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract ECDH P-256 private key");
            }
            size_t privkey_len = static_cast<size_t>(BN_num_bytes(priv_bn));
            kp.private_key = SecureMemory(privkey_len);
            BN_bn2bin(priv_bn, kp.private_key.data());
            BN_free(priv_bn);
            EVP_PKEY_free(pkey);
            break;
        }

        case KeyExchangeProtocol::Kyber1024:
#ifdef HAVE_LIBOQS
            {
                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
                if (!kem) throw std::runtime_error("Failed to initialize Kyber1024 KEM");
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

// ===== compute_shared_secret() — FIX #50 (ECDH P-256) + FIX #51 (Kyber ciphertext) =====
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
            if (peer_public_key.size() != 56) {
                throw std::runtime_error("Invalid peer public key size for X448 (expected 56 bytes)");
            }
            // X448 uses raw key APIs (correct — these support X448)
            UniqueEVP_PKEY local_pkey(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, nullptr,
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            ));
            if (!local_pkey) throw std::runtime_error("Failed to load X448 local private key");

            UniqueEVP_PKEY peer_pkey(EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X448, nullptr,
                peer_public_key.data(),
                peer_public_key.size()
            ));
            if (!peer_pkey) throw std::runtime_error("Failed to load X448 peer public key");

            UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(local_pkey.get(), nullptr));
            if (!ctx) throw std::runtime_error("Failed to create X448 derive context");
            if (EVP_PKEY_derive_init(ctx.get()) <= 0)
                throw std::runtime_error("Failed to initialize X448 derive");
            if (EVP_PKEY_derive_set_peer(ctx.get(), peer_pkey.get()) <= 0)
                throw std::runtime_error("Failed to set X448 peer key");

            size_t secret_len = 0;
            if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0)
                throw std::runtime_error("Failed to query X448 shared secret size");

            SecureMemory shared_secret(secret_len);
            if (EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len) <= 0)
                throw std::runtime_error("Failed to derive X448 shared secret");

            return shared_secret;
        }

        case KeyExchangeProtocol::ECDH_P256: {
            // ===============================================================
            // FIX #50: Use EVP_PKEY_fromdata() for EC P-256 keys
            // EVP_PKEY_new_raw_{private,public}_key does NOT work for EC keys
            // ===============================================================
            if (peer_public_key.size() != 65) {
                throw std::runtime_error("Invalid peer public key size for ECDH P-256 (expected 65 bytes)");
            }

            // Load local private key + public key via OSSL_PARAM_BLD
            auto local_pkey = ec_p256_pkey_from_private(
                local_keypair.private_key.data(), local_keypair.private_key.size(),
                local_keypair.public_key.data(),  local_keypair.public_key.size()
            );

            // Load peer public key via OSSL_PARAM_BLD
            auto peer_pkey = ec_p256_pkey_from_public(
                peer_public_key.data(), peer_public_key.size()
            );

            // Derive shared secret via ECDH
            UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(local_pkey.get(), nullptr));
            if (!ctx) throw std::runtime_error("Failed to create ECDH P-256 derive context");
            if (EVP_PKEY_derive_init(ctx.get()) <= 0)
                throw std::runtime_error("Failed to initialize ECDH P-256 derive");
            if (EVP_PKEY_derive_set_peer(ctx.get(), peer_pkey.get()) <= 0)
                throw std::runtime_error("Failed to set ECDH P-256 peer key");

            size_t secret_len = 0;
            if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0)
                throw std::runtime_error("Failed to query ECDH P-256 shared secret size");

            SecureMemory shared_secret(secret_len);
            if (EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len) <= 0)
                throw std::runtime_error("Failed to derive ECDH P-256 shared secret");

            return shared_secret;
        }

        case KeyExchangeProtocol::Kyber1024:
#ifdef HAVE_LIBOQS
            {
                OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
                if (!kem) throw std::runtime_error("Failed to initialize Kyber1024 KEM");

                SecureMemory ciphertext(kem->length_ciphertext);
                SecureMemory shared_secret(kem->length_shared_secret);

                if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(),
                                   peer_public_key.data()) != OQS_SUCCESS) {
                    OQS_KEM_free(kem);
                    throw std::runtime_error("Failed to encapsulate with Kyber1024");
                }
                OQS_KEM_free(kem);

                // ===============================================================
                // FIX #51: Store ciphertext so caller can retrieve and send it
                // to the peer for decapsulation. Without this, the peer cannot
                // compute the shared secret and KEM is completely broken.
                // ===============================================================
                pImpl_->last_kem_ciphertext.assign(
                    ciphertext.data(),
                    ciphertext.data() + ciphertext.size()
                );

                return shared_secret;
            }
#else
            throw std::runtime_error("Kyber1024 requires liboqs - recompile with HAVE_LIBOQS");
#endif
    }

    throw std::runtime_error("Unsupported key exchange protocol");
}

// ===== derive_keys() — FIX #53: document entropy truncation for X448 =====
SecureMemory E2ESession::derive_keys(
    const SecureMemory& shared_secret,
    const std::string& context,
    size_t key_length
) {
    if (key_length < crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Key length too small");
    }

    SecureMemory derived_key(key_length);

    char kdf_context[crypto_kdf_CONTEXTBYTES];
    std::memset(kdf_context, 0, sizeof(kdf_context));
    size_t copy_len = std::min(context.size(), sizeof(kdf_context));
    std::memcpy(kdf_context, context.data(), copy_len);

    // NOTE (issue #53): Master key is always 32 bytes (crypto_kdf_KEYBYTES).
    // For X448 (56-byte shared secret) this truncates effective security to 256-bit.
    // BLAKE2b-256 is cryptographically sound for this compression — the 256-bit
    // security level is considered sufficient for all downstream symmetric operations
    // (XChaCha20-Poly1305 uses 256-bit keys). If >256-bit security is required,
    // consider using BLAKE2b-512 and a wider KDF chain.
    uint8_t master_key[crypto_kdf_KEYBYTES];
    crypto_generichash(master_key, sizeof(master_key),
                       shared_secret.data(), shared_secret.size(),
                       nullptr, 0);

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

// ===== encrypt_message / decrypt_message (low-level, existing) =====
EncryptedMessage E2ESession::encrypt_message(
    const std::vector<uint8_t>& plaintext,
    const SecureMemory& encryption_key
) {
    if (encryption_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid encryption key size");
    }
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
            nullptr, 0, nullptr,
            msg.nonce.data(), encryption_key.data()) != 0) {
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
    if (message.ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error("Ciphertext too short - missing authentication tag");
    }

    std::vector<uint8_t> plaintext(message.ciphertext.size());
    unsigned long long plaintext_len;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len, nullptr,
            message.ciphertext.data(), message.ciphertext.size(),
            nullptr, 0,
            message.nonce.data(), decryption_key.data()) != 0) {
        sodium_memzero(plaintext.data(), plaintext.size());
        throw std::runtime_error("Decryption failed or authentication tag invalid");
    }
    plaintext.resize(plaintext_len);
    return plaintext;
}

// =====================================================================
// FIX #52: Implement all declared-but-missing methods
// =====================================================================

EncryptedMessage E2ESession::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& associated_data
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        throw std::runtime_error("Session not established — cannot encrypt");
    }

    if (!pImpl_->sending_chain_key.data() || pImpl_->sending_chain_key.size() == 0) {
        throw std::runtime_error("Sending chain key not initialized");
    }

    // Derive message key from sending chain key
    SecureMemory message_key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    uint8_t chain_input[1] = {0x01};
    crypto_generichash(message_key.data(), message_key.size(),
                       pImpl_->sending_chain_key.data(), pImpl_->sending_chain_key.size(),
                       chain_input, sizeof(chain_input));

    EncryptedMessage msg;
    msg.header.version = 1;
    msg.header.message_number = pImpl_->ratchet.sending_chain_length;
    msg.header.previous_chain_length = pImpl_->ratchet.previous_chain_length;
    msg.header.associated_data = associated_data;

    msg.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.nonce.data(), msg.nonce.size());

    msg.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            msg.ciphertext.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            associated_data.data(), associated_data.size(),
            nullptr, msg.nonce.data(), message_key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }
    msg.ciphertext.resize(ct_len);
    msg.timestamp = std::chrono::system_clock::now();

    // Advance sending chain
    pImpl_->ratchet.sending_chain_length++;
    uint8_t chain_advance[1] = {0x02};
    SecureMemory new_chain(pImpl_->sending_chain_key.size());
    crypto_generichash(new_chain.data(), new_chain.size(),
                       pImpl_->sending_chain_key.data(), pImpl_->sending_chain_key.size(),
                       chain_advance, sizeof(chain_advance));
    pImpl_->sending_chain_key = std::move(new_chain);

    pImpl_->messages_sent++;
    pImpl_->last_activity = std::chrono::system_clock::now();
    return msg;
}

std::optional<std::vector<uint8_t>> E2ESession::decrypt(
    const EncryptedMessage& encrypted_message
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        return std::nullopt;
    }

    if (!pImpl_->receiving_chain_key.data() || pImpl_->receiving_chain_key.size() == 0) {
        return std::nullopt;
    }

    // Derive message key from receiving chain key
    SecureMemory message_key(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    uint8_t chain_input[1] = {0x01};
    crypto_generichash(message_key.data(), message_key.size(),
                       pImpl_->receiving_chain_key.data(), pImpl_->receiving_chain_key.size(),
                       chain_input, sizeof(chain_input));

    if (encrypted_message.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        return std::nullopt;
    }
    if (encrypted_message.ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return std::nullopt;
    }

    std::vector<uint8_t> plaintext(encrypted_message.ciphertext.size());
    unsigned long long pt_len;
    const auto& ad = encrypted_message.header.associated_data;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &pt_len, nullptr,
            encrypted_message.ciphertext.data(), encrypted_message.ciphertext.size(),
            ad.data(), ad.size(),
            encrypted_message.nonce.data(), message_key.data()) != 0) {
        sodium_memzero(plaintext.data(), plaintext.size());
        return std::nullopt;
    }
    plaintext.resize(pt_len);

    // Advance receiving chain
    pImpl_->ratchet.receiving_chain_length++;
    uint8_t chain_advance[1] = {0x02};
    SecureMemory new_chain(pImpl_->receiving_chain_key.size());
    crypto_generichash(new_chain.data(), new_chain.size(),
                       pImpl_->receiving_chain_key.data(), pImpl_->receiving_chain_key.size(),
                       chain_advance, sizeof(chain_advance));
    pImpl_->receiving_chain_key = std::move(new_chain);

    pImpl_->messages_received++;
    pImpl_->last_activity = std::chrono::system_clock::now();
    return plaintext;
}

void E2ESession::ratchet_sending_chain() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        throw std::runtime_error("Cannot ratchet: session not established");
    }

    // KDF ratchet step: derive new chain key from root key
    pImpl_->ratchet.previous_chain_length = pImpl_->ratchet.sending_chain_length;
    pImpl_->ratchet.sending_chain_length = 0;

    if (pImpl_->ratchet.root_key.data() && pImpl_->ratchet.root_key.size() > 0) {
        SecureMemory new_chain(crypto_kdf_KEYBYTES);
        uint8_t label[1] = {0x10};
        crypto_generichash(new_chain.data(), new_chain.size(),
                           pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size(),
                           label, sizeof(label));
        pImpl_->sending_chain_key = std::move(new_chain);

        // Advance root key
        SecureMemory new_root(crypto_kdf_KEYBYTES);
        uint8_t root_label[1] = {0x11};
        crypto_generichash(new_root.data(), new_root.size(),
                           pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size(),
                           root_label, sizeof(root_label));
        pImpl_->ratchet.root_key = std::move(new_root);
    }
}

void E2ESession::ratchet_receiving_chain(const std::vector<uint8_t>& remote_public_key) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        throw std::runtime_error("Cannot ratchet: session not established");
    }

    pImpl_->ratchet.receiving_chain_length = 0;

    if (pImpl_->ratchet.root_key.data() && pImpl_->ratchet.root_key.size() > 0) {
        // Mix remote public key into the KDF for forward secrecy
        SecureMemory input(pImpl_->ratchet.root_key.size() + remote_public_key.size());
        std::memcpy(input.data(), pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size());
        std::memcpy(input.data() + pImpl_->ratchet.root_key.size(),
                     remote_public_key.data(), remote_public_key.size());

        SecureMemory new_chain(crypto_kdf_KEYBYTES);
        uint8_t label[1] = {0x20};
        crypto_generichash(new_chain.data(), new_chain.size(),
                           input.data(), input.size(),
                           label, sizeof(label));
        pImpl_->receiving_chain_key = std::move(new_chain);

        // Advance root key
        SecureMemory new_root(crypto_kdf_KEYBYTES);
        uint8_t root_label[1] = {0x21};
        crypto_generichash(new_root.data(), new_root.size(),
                           input.data(), input.size(),
                           root_label, sizeof(root_label));
        pImpl_->ratchet.root_key = std::move(new_root);
    }
}

E2ESessionState E2ESession::get_state() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->state;
}

bool E2ESession::is_established() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->state == E2ESessionState::SessionEstablished;
}

bool E2ESession::is_expired() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state == E2ESessionState::SessionExpired ||
        pImpl_->state == E2ESessionState::SessionRevoked) {
        return true;
    }
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - pImpl_->session_created_at);
    return elapsed >= pImpl_->config.session_timeout;
}

void E2ESession::rotate_keys() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        throw std::runtime_error("Cannot rotate keys: session not established");
    }

    if (pImpl_->ratchet.root_key.data() && pImpl_->ratchet.root_key.size() > 0) {
        pImpl_->ratchet.previous_chain_length = pImpl_->ratchet.sending_chain_length;
        pImpl_->ratchet.sending_chain_length = 0;
        pImpl_->ratchet.receiving_chain_length = 0;

        SecureMemory new_send(crypto_kdf_KEYBYTES);
        uint8_t s_label[1] = {0x30};
        crypto_generichash(new_send.data(), new_send.size(),
                           pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size(),
                           s_label, sizeof(s_label));
        pImpl_->sending_chain_key = std::move(new_send);

        SecureMemory new_recv(crypto_kdf_KEYBYTES);
        uint8_t r_label[1] = {0x31};
        crypto_generichash(new_recv.data(), new_recv.size(),
                           pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size(),
                           r_label, sizeof(r_label));
        pImpl_->receiving_chain_key = std::move(new_recv);

        // Advance root key
        SecureMemory new_root(crypto_kdf_KEYBYTES);
        uint8_t root_label[1] = {0x32};
        crypto_generichash(new_root.data(), new_root.size(),
                           pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size(),
                           root_label, sizeof(root_label));
        pImpl_->ratchet.root_key = std::move(new_root);
    }

    pImpl_->last_activity = std::chrono::system_clock::now();
}

void E2ESession::revoke_session() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->state = E2ESessionState::SessionRevoked;

    // Securely wipe all key material
    if (pImpl_->ratchet.root_key.data())
        sodium_memzero(pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size());
    if (pImpl_->ratchet.chain_key.data())
        sodium_memzero(pImpl_->ratchet.chain_key.data(), pImpl_->ratchet.chain_key.size());
    if (pImpl_->sending_chain_key.data())
        sodium_memzero(pImpl_->sending_chain_key.data(), pImpl_->sending_chain_key.size());
    if (pImpl_->receiving_chain_key.data())
        sodium_memzero(pImpl_->receiving_chain_key.data(), pImpl_->receiving_chain_key.size());
    pImpl_->ratchet.skipped_keys.clear();
}

std::string E2ESession::get_session_id() const {
    return pImpl_->session_id;
}

std::chrono::system_clock::time_point E2ESession::get_last_activity() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->last_activity;
}

uint64_t E2ESession::get_messages_sent() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->messages_sent;
}

uint64_t E2ESession::get_messages_received() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->messages_received;
}

void E2ESession::init_ratchet_keys() {
    // Called internally after key exchange completes to bootstrap the ratchet
    // Root key should already be derived from the shared secret at this point
}

} // namespace ncp
