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
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

// ==================== RAII helpers for OpenSSL ====================

struct EVP_PKEY_Deleter   { void operator()(EVP_PKEY* p)     const { if (p) EVP_PKEY_free(p); } };
struct EVP_PKEY_CTX_Deleter { void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); } };
struct EC_KEY_Deleter      { void operator()(EC_KEY* p)       const { if (p) EC_KEY_free(p); } };
struct BN_Deleter          { void operator()(BIGNUM* p)       const { if (p) BN_free(p); } };
struct EC_POINT_Deleter    { void operator()(EC_POINT* p)     const { if (p) EC_POINT_free(p); } };
struct EC_GROUP_Deleter    { void operator()(EC_GROUP* p)     const { if (p) EC_GROUP_free(p); } };

using UniqueEVP_PKEY     = std::unique_ptr<EVP_PKEY,     EVP_PKEY_Deleter>;
using UniqueEVP_PKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using UniqueEC_KEY       = std::unique_ptr<EC_KEY,       EC_KEY_Deleter>;
using UniqueBN           = std::unique_ptr<BIGNUM,       BN_Deleter>;
using UniqueEC_POINT     = std::unique_ptr<EC_POINT,     EC_POINT_Deleter>;

// ==================== Implementation details ====================

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

E2ESession::E2ESession(const E2EConfig& config)
    : pImpl_(std::make_unique<Impl>(config)) {}

E2ESession::~E2ESession() = default;

// ==================== AAD builder ====================

std::vector<uint8_t> E2ESession::build_aad() const {
    // Bind ciphertexts to session context to prevent cross-session replay
    const std::string& sid = pImpl_->session_id;
    std::vector<uint8_t> aad;
    // Tag: "ncp-e2e-v1\x00"
    const char* tag = "ncp-e2e-v1";
    aad.insert(aad.end(), tag, tag + 10);
    aad.push_back(0x00);
    // Session ID bytes
    aad.insert(aad.end(), sid.begin(), sid.end());
    return aad;
}

// ==================== EC P-256 helpers ====================

/// Build EVP_PKEY from raw EC private key (32 bytes scalar) for P-256.
static UniqueEVP_PKEY ec_p256_pkey_from_private_raw(
    const uint8_t* priv_data, size_t priv_len
) {
    UniqueEC_KEY eckey(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!eckey) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    UniqueBN priv_bn(BN_bin2bn(priv_data, static_cast<int>(priv_len), nullptr));
    if (!priv_bn) throw std::runtime_error("BN_bin2bn failed for EC private key");

    if (EC_KEY_set_private_key(eckey.get(), priv_bn.get()) != 1) {
        throw std::runtime_error("EC_KEY_set_private_key failed");
    }

    // Derive public key from private key: pub = priv * G
    const EC_GROUP* group = EC_KEY_get0_group(eckey.get());
    UniqueEC_POINT pub_point(EC_POINT_new(group));
    if (!pub_point) throw std::runtime_error("EC_POINT_new failed");

    if (EC_POINT_mul(group, pub_point.get(), priv_bn.get(), nullptr, nullptr, nullptr) != 1) {
        throw std::runtime_error("EC_POINT_mul failed (deriving public key)");
    }
    if (EC_KEY_set_public_key(eckey.get(), pub_point.get()) != 1) {
        throw std::runtime_error("EC_KEY_set_public_key failed");
    }

    UniqueEVP_PKEY pkey(EVP_PKEY_new());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new failed");
    // EVP_PKEY_assign_EC_KEY takes ownership of eckey
    if (EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.release()) != 1) {
        throw std::runtime_error("EVP_PKEY_assign_EC_KEY failed");
    }
    return pkey;
}

/// Build EVP_PKEY from uncompressed EC public key (65 bytes: 04 || X || Y) for P-256.
static UniqueEVP_PKEY ec_p256_pkey_from_public_raw(
    const uint8_t* pub_data, size_t pub_len
) {
    UniqueEC_KEY eckey(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!eckey) throw std::runtime_error("EC_KEY_new_by_curve_name failed");

    const EC_GROUP* group = EC_KEY_get0_group(eckey.get());
    UniqueEC_POINT point(EC_POINT_new(group));
    if (!point) throw std::runtime_error("EC_POINT_new failed");

    if (EC_POINT_oct2point(group, point.get(), pub_data, pub_len, nullptr) != 1) {
        throw std::runtime_error("EC_POINT_oct2point failed (invalid public key)");
    }
    if (EC_KEY_set_public_key(eckey.get(), point.get()) != 1) {
        throw std::runtime_error("EC_KEY_set_public_key failed");
    }

    UniqueEVP_PKEY pkey(EVP_PKEY_new());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new failed");
    if (EVP_PKEY_assign_EC_KEY(pkey.get(), eckey.release()) != 1) {
        throw std::runtime_error("EVP_PKEY_assign_EC_KEY failed");
    }
    return pkey;
}

// ==================== generate_key_pair() ====================

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
            // X448 key generation via OpenSSL EVP API (raw keys supported)
            UniqueEVP_PKEY_CTX pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr));
            if (!pctx) throw std::runtime_error("Failed to create X448 context");

            if (EVP_PKEY_keygen_init(pctx.get()) <= 0)
                throw std::runtime_error("Failed to initialize X448 keygen");

            EVP_PKEY* pkey_raw = nullptr;
            if (EVP_PKEY_keygen(pctx.get(), &pkey_raw) <= 0)
                throw std::runtime_error("Failed to generate X448 keypair");
            UniqueEVP_PKEY pkey(pkey_raw);

            // Extract raw public key (56 bytes for X448)
            size_t pubkey_len = 56;
            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_raw_public_key(pkey.get(), kp.public_key.data(), &pubkey_len) <= 0)
                throw std::runtime_error("Failed to extract X448 public key");
            kp.public_key.resize(pubkey_len);

            // Extract raw private key (56 bytes for X448)
            size_t privkey_len = 56;
            kp.private_key = SecureMemory(privkey_len);
            if (EVP_PKEY_get_raw_private_key(pkey.get(), kp.private_key.data(), &privkey_len) <= 0)
                throw std::runtime_error("Failed to extract X448 private key");
            kp.private_key.resize(privkey_len);
            break;
        }

        case KeyExchangeProtocol::ECDH_P256: {
            // ECDH P-256: generate via EVP, extract via EC_KEY API
            // (EVP_PKEY_get_raw_public/private_key does NOT work for EC keys)
            UniqueEVP_PKEY_CTX pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
            if (!pctx) throw std::runtime_error("Failed to create ECDH P-256 context");

            if (EVP_PKEY_keygen_init(pctx.get()) <= 0)
                throw std::runtime_error("Failed to initialize ECDH P-256 keygen");

            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0)
                throw std::runtime_error("Failed to set ECDH P-256 curve");

            EVP_PKEY* pkey_raw = nullptr;
            if (EVP_PKEY_keygen(pctx.get(), &pkey_raw) <= 0)
                throw std::runtime_error("Failed to generate ECDH P-256 keypair");
            UniqueEVP_PKEY pkey(pkey_raw);

            // Get EC_KEY from EVP_PKEY
            const EC_KEY* eckey = EVP_PKEY_get0_EC_KEY(pkey.get());
            if (!eckey) throw std::runtime_error("EVP_PKEY_get0_EC_KEY failed");

            const EC_GROUP* group = EC_KEY_get0_group(eckey);

            // Extract public key as uncompressed point (04 || X || Y = 65 bytes)
            const EC_POINT* pub_point = EC_KEY_get0_public_key(eckey);
            if (!pub_point) throw std::runtime_error("EC_KEY_get0_public_key returned null");

            size_t pubkey_len = EC_POINT_point2oct(
                group, pub_point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr
            );
            kp.public_key = SecureMemory(pubkey_len);
            EC_POINT_point2oct(
                group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                kp.public_key.data(), pubkey_len, nullptr
            );

            // Extract private key as raw scalar (32 bytes)
            const BIGNUM* priv_bn = EC_KEY_get0_private_key(eckey);
            if (!priv_bn) throw std::runtime_error("EC_KEY_get0_private_key returned null");

            int privkey_len = BN_num_bytes(priv_bn);
            kp.private_key = SecureMemory(static_cast<size_t>(privkey_len));
            BN_bn2bin(priv_bn, kp.private_key.data());
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

// ==================== compute_shared_secret() — DH-based only ====================

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
            if (peer_public_key.size() != crypto_box_PUBLICKEYBYTES)
                throw std::runtime_error("Invalid peer public key size for X25519");

            SecureMemory shared_secret(crypto_scalarmult_BYTES);
            if (crypto_scalarmult(shared_secret.data(),
                                  local_keypair.private_key.data(),
                                  peer_public_key.data()) != 0)
                throw std::runtime_error("Failed to compute X25519 shared secret");
            return shared_secret;
        }

        case KeyExchangeProtocol::X448: {
            if (peer_public_key.size() != 56)
                throw std::runtime_error("Invalid peer public key size for X448 (expected 56 bytes)");

            // X448: raw key API works fine
            UniqueEVP_PKEY local_pkey(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, nullptr,
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            ));
            if (!local_pkey)
                throw std::runtime_error("Failed to load X448 local private key");

            UniqueEVP_PKEY peer_pkey(EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X448, nullptr,
                peer_public_key.data(),
                peer_public_key.size()
            ));
            if (!peer_pkey)
                throw std::runtime_error("Failed to load X448 peer public key");

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
            // ECDH P-256: reconstruct EVP_PKEY via EC_KEY API
            // (EVP_PKEY_new_raw_private_key(EVP_PKEY_EC) does NOT work)
            if (peer_public_key.size() != 65)
                throw std::runtime_error("Invalid peer public key size for ECDH P-256 (expected 65 bytes)");

            auto local_pkey = ec_p256_pkey_from_private_raw(
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            );

            auto peer_pkey = ec_p256_pkey_from_public_raw(
                peer_public_key.data(),
                peer_public_key.size()
            );

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
            throw std::runtime_error(
                "Kyber1024 is a KEM, not DH. Use encapsulate_shared_secret() / "
                "decapsulate_shared_secret() instead of compute_shared_secret()"
            );
    }

    throw std::runtime_error("Unsupported key exchange protocol");
}

// ==================== Kyber KEM: encapsulate / decapsulate ====================

KEMEncapsResult E2ESession::encapsulate_shared_secret(
    const std::vector<uint8_t>& peer_public_key
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    if (pImpl_->config.key_exchange != KeyExchangeProtocol::Kyber1024)
        throw std::runtime_error("encapsulate_shared_secret() is only for Kyber KEM");

#ifdef HAVE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) throw std::runtime_error("Failed to initialize Kyber1024 KEM");

    if (peer_public_key.size() != kem->length_public_key) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Invalid Kyber1024 public key size");
    }

    KEMEncapsResult result;
    result.ciphertext.resize(kem->length_ciphertext);
    result.shared_secret = SecureMemory(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, result.ciphertext.data(),
                       result.shared_secret.data(),
                       peer_public_key.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Kyber1024 encapsulation failed");
    }

    OQS_KEM_free(kem);
    return result;
#else
    throw std::runtime_error("Kyber1024 requires liboqs - recompile with HAVE_LIBOQS");
#endif
}

SecureMemory E2ESession::decapsulate_shared_secret(
    const KeyPair& local_keypair,
    const std::vector<uint8_t>& ciphertext
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    if (local_keypair.protocol != KeyExchangeProtocol::Kyber1024)
        throw std::runtime_error("decapsulate_shared_secret() is only for Kyber KEM");

#ifdef HAVE_LIBOQS
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) throw std::runtime_error("Failed to initialize Kyber1024 KEM");

    if (ciphertext.size() != kem->length_ciphertext) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Invalid Kyber1024 ciphertext size");
    }
    if (local_keypair.private_key.size() != kem->length_secret_key) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Invalid Kyber1024 secret key size");
    }

    SecureMemory shared_secret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, shared_secret.data(),
                       ciphertext.data(),
                       local_keypair.private_key.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Kyber1024 decapsulation failed");
    }

    OQS_KEM_free(kem);
    return shared_secret;
#else
    throw std::runtime_error("Kyber1024 requires liboqs - recompile with HAVE_LIBOQS");
#endif
}

// ==================== derive_keys() ====================

SecureMemory E2ESession::derive_keys(
    const SecureMemory& shared_secret,
    const std::string& context,
    size_t key_length
) {
    if (key_length < crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        throw std::runtime_error("Key length too small");

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

// ==================== encrypt_message() — with AAD ====================

EncryptedMessage E2ESession::encrypt_message(
    const std::vector<uint8_t>& plaintext,
    const SecureMemory& encryption_key
) {
    if (encryption_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        throw std::runtime_error("Invalid encryption key size");

    if (plaintext.size() > SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error("Plaintext too large");

    // Build AAD from session context to bind ciphertext to this session
    auto aad = build_aad();

    EncryptedMessage msg;
    msg.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.nonce.data(), msg.nonce.size());

    msg.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    unsigned long long ciphertext_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            msg.ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr,
            msg.nonce.data(),
            encryption_key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }

    msg.ciphertext.resize(ciphertext_len);
    msg.timestamp = std::chrono::system_clock::now();

    return msg;
}

// ==================== decrypt_message() — with AAD ====================

std::vector<uint8_t> E2ESession::decrypt_message(
    const EncryptedMessage& message,
    const SecureMemory& decryption_key
) {
    if (decryption_key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
        throw std::runtime_error("Invalid decryption key size");

    if (message.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
        throw std::runtime_error("Invalid nonce size");

    if (message.ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error("Ciphertext too short - missing authentication tag");

    // Rebuild same AAD that was used during encryption
    auto aad = build_aad();

    std::vector<uint8_t> plaintext(message.ciphertext.size());
    unsigned long long plaintext_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            message.ciphertext.data(), message.ciphertext.size(),
            aad.data(), aad.size(),
            message.nonce.data(),
            decryption_key.data()) != 0) {
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
