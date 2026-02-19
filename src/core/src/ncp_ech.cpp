/**
 * @file ncp_ech.cpp
 * @brief Encrypted Client Hello (ECH) implementation using HPKE
 */

#include "../include/ncp_ech.hpp"
#include <string>
#include <algorithm>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#endif

namespace ncp {
namespace DPI {
namespace ECH {

#ifdef HAVE_OPENSSL

// ==================== Helper Functions ====================

static uint16_t hpke_kem_to_id(HPKEKem kem) {
    switch (kem) {
        case HPKEKem::DHKEM_P256_HKDF_SHA256:    return OSSL_HPKE_KEM_ID_P256;
        case HPKEKem::DHKEM_P384_HKDF_SHA384:     return OSSL_HPKE_KEM_ID_P384;
        case HPKEKem::DHKEM_P521_HKDF_SHA512:     return OSSL_HPKE_KEM_ID_P521;
        case HPKEKem::DHKEM_X25519_HKDF_SHA256:   return OSSL_HPKE_KEM_ID_X25519;
        case HPKEKem::DHKEM_X448_HKDF_SHA512:     return OSSL_HPKE_KEM_ID_X448;
        default: return 0;
    }
}

static uint16_t hpke_kdf_to_id(HPKEKDF kdf) {
    switch (kdf) {
        case HPKEKDF::HKDF_SHA256: return OSSL_HPKE_KDF_ID_HKDF_SHA256;
        case HPKEKDF::HKDF_SHA384: return OSSL_HPKE_KDF_ID_HKDF_SHA384;
        case HPKEKDF::HKDF_SHA512: return OSSL_HPKE_KDF_ID_HKDF_SHA512;
        default: return 0;
    }
}

static uint16_t hpke_aead_to_id(HPKEAEAD aead) {
    switch (aead) {
        case HPKEAEAD::AES_128_GCM:         return OSSL_HPKE_AEAD_ID_AES_GCM_128;
        case HPKEAEAD::AES_256_GCM:         return OSSL_HPKE_AEAD_ID_AES_GCM_256;
        case HPKEAEAD::CHACHA20_POLY1305:   return OSSL_HPKE_AEAD_ID_CHACHA20_POLY1305;
        default: return 0;
    }
}

static OSSL_HPKE_SUITE make_suite(const HPKECipherSuite& cs) {
    OSSL_HPKE_SUITE suite;
    suite.kem_id  = hpke_kem_to_id(cs.kem_id);
    suite.kdf_id  = hpke_kdf_to_id(cs.kdf_id);
    suite.aead_id = hpke_aead_to_id(cs.aead_id);
    return suite;
}

// ==================== ECHClientContext Implementation ====================

struct ECHClientContext::Impl {
    ECHConfig config;
    OSSL_HPKE_CTX* hpke_ctx = nullptr;
    OSSL_HPKE_SUITE suite{};

    ~Impl() {
        if (hpke_ctx) {
            OSSL_HPKE_CTX_free(hpke_ctx);
        }
    }
};

ECHClientContext::ECHClientContext() : impl_(std::make_unique<Impl>()) {}
ECHClientContext::~ECHClientContext() = default;

bool ECHClientContext::init(const ECHConfig& config) {
    impl_->config = config;

    if (config.cipher_suites.empty()) {
        return false;
    }

    // Use first supported cipher suite
    const auto& cs = config.cipher_suites[0];
    impl_->suite = make_suite(cs);

    if (impl_->suite.kem_id == 0 || impl_->suite.kdf_id == 0 || impl_->suite.aead_id == 0) {
        return false;
    }

    // Create HPKE context for sender (client)
    impl_->hpke_ctx = OSSL_HPKE_CTX_new(
        OSSL_HPKE_MODE_BASE,
        impl_->suite,
        OSSL_HPKE_ROLE_SENDER,
        nullptr,  // libctx
        nullptr   // propq
    );

    return impl_->hpke_ctx != nullptr;
}

bool ECHClientContext::encrypt(
    const std::vector<uint8_t>& client_hello_inner,
    const std::vector<uint8_t>& client_hello_outer_aad,
    std::vector<uint8_t>& enc,
    std::vector<uint8_t>& encrypted_payload
) {
    if (!impl_->hpke_ctx || impl_->config.public_key.empty()) {
        return false;
    }

    // Prepare info string: "tls ech" || 0x00 || ECHConfig
    std::vector<uint8_t> info;
    const char* label = "tls ech";
    info.insert(info.end(), label, label + 7);
    info.push_back(0x00);
    info.insert(info.end(), impl_->config.raw_config.begin(),
                impl_->config.raw_config.end());

    // Setup HPKE encapsulation (client side)
    // First call to get required enc size
    size_t enc_len = 0;
    if (OSSL_HPKE_encap(
            impl_->hpke_ctx,
            nullptr, &enc_len,  // Get required enc size
            impl_->config.public_key.data(),
            impl_->config.public_key.size(),
            info.data(), info.size()
        ) != 1) {
        return false;
    }

    enc.resize(enc_len);
    if (OSSL_HPKE_encap(
            impl_->hpke_ctx,
            enc.data(), &enc_len,
            impl_->config.public_key.data(),
            impl_->config.public_key.size(),
            info.data(), info.size()
        ) != 1) {
        return false;
    }
    enc.resize(enc_len);

    // Use OSSL_HPKE_get_ciphertext_size instead of EVP_AEAD_MAX_OVERHEAD
    size_t ct_len = OSSL_HPKE_get_ciphertext_size(impl_->suite, client_hello_inner.size());
    if (ct_len == 0) {
        // Fallback: plaintext size + 32 bytes overhead (AES-GCM / ChaCha20-Poly1305 tag)
        ct_len = client_hello_inner.size() + 32;
    }
    encrypted_payload.resize(ct_len);

    if (OSSL_HPKE_seal(
            impl_->hpke_ctx,
            encrypted_payload.data(), &ct_len,
            client_hello_outer_aad.data(), client_hello_outer_aad.size(),
            client_hello_inner.data(), client_hello_inner.size()
        ) != 1) {
        return false;
    }
    encrypted_payload.resize(ct_len);

    return true;
}

HPKECipherSuite ECHClientContext::get_cipher_suite() const {
    if (impl_->config.cipher_suites.empty()) {
        return HPKECipherSuite();
    }
    return impl_->config.cipher_suites[0];
}

uint8_t ECHClientContext::get_config_id() const {
    return impl_->config.config_id;
}

// ==================== ECHServerContext Implementation ====================

struct ECHServerContext::Impl {
    EVP_PKEY* priv_key = nullptr;
    HPKECipherSuite cipher_suite;
    OSSL_HPKE_CTX* hpke_ctx = nullptr;
    OSSL_HPKE_SUITE suite{};

    ~Impl() {
        if (hpke_ctx) {
            OSSL_HPKE_CTX_free(hpke_ctx);
        }
        if (priv_key) {
            EVP_PKEY_free(priv_key);
        }
    }
};

ECHServerContext::ECHServerContext() : impl_(std::make_unique<Impl>()) {}
ECHServerContext::~ECHServerContext() = default;

bool ECHServerContext::init(
    const std::vector<uint8_t>& private_key,
    const HPKECipherSuite& cipher_suite
) {
    impl_->cipher_suite = cipher_suite;
    impl_->suite = make_suite(cipher_suite);

    if (impl_->suite.kem_id == 0 || impl_->suite.kdf_id == 0 || impl_->suite.aead_id == 0) {
        return false;
    }

    // Import raw private key into EVP_PKEY
    // Determine NID based on KEM
    int nid = 0;
    switch (cipher_suite.kem_id) {
        case HPKEKem::DHKEM_X25519_HKDF_SHA256:
            nid = EVP_PKEY_X25519;
            break;
        case HPKEKem::DHKEM_X448_HKDF_SHA512:
            nid = EVP_PKEY_X448;
            break;
        default:
            // For EC-based KEMs (P-256, P-384, P-521), raw import is more complex.
            // For now, only X25519/X448 are supported for raw key import.
            return false;
    }

    impl_->priv_key = EVP_PKEY_new_raw_private_key(
        nid, nullptr,
        private_key.data(), private_key.size()
    );
    if (!impl_->priv_key) {
        return false;
    }

    // Create HPKE context for receiver (server)
    impl_->hpke_ctx = OSSL_HPKE_CTX_new(
        OSSL_HPKE_MODE_BASE,
        impl_->suite,
        OSSL_HPKE_ROLE_RECEIVER,
        nullptr,
        nullptr
    );

    return impl_->hpke_ctx != nullptr;
}

bool ECHServerContext::decrypt(
    const std::vector<uint8_t>& enc,
    const std::vector<uint8_t>& encrypted_payload,
    const std::vector<uint8_t>& client_hello_outer_aad,
    std::vector<uint8_t>& client_hello_inner
) {
    if (!impl_->hpke_ctx || !impl_->priv_key) {
        return false;
    }

    // Prepare info (should match client's info)
    std::vector<uint8_t> info;
    const char* label = "tls ech";
    info.insert(info.end(), label, label + 7);
    info.push_back(0x00);
    // Note: ECHConfig should be available to server from its own config

    // Setup HPKE decapsulation (server side)
    // OSSL_HPKE_decap takes EVP_PKEY* for the recipient private key
    if (OSSL_HPKE_decap(
            impl_->hpke_ctx,
            enc.data(), enc.size(),
            impl_->priv_key,
            info.data(), info.size()
        ) != 1) {
        return false;
    }

    // Open (decrypt) encrypted payload
    client_hello_inner.resize(encrypted_payload.size());
    size_t pt_len = client_hello_inner.size();

    if (OSSL_HPKE_open(
            impl_->hpke_ctx,
            client_hello_inner.data(), &pt_len,
            client_hello_outer_aad.data(), client_hello_outer_aad.size(),
            encrypted_payload.data(), encrypted_payload.size()
        ) != 1) {
        return false;
    }
    client_hello_inner.resize(pt_len);

    return true;
}

// ==================== Utility Functions ====================

bool parse_ech_config(const std::vector<uint8_t>& data, ECHConfig& config) {
    if (data.size() < 10) {
        return false;
    }

    size_t pos = 0;

    // Version (2 bytes)
    config.version = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    // Config ID (1 byte)
    config.config_id = data[pos++];

    // KEM ID (2 bytes)
    uint16_t kem_id = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    // Public key length (2 bytes)
    if (pos + 2 > data.size()) return false;
    uint16_t pk_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    // Public key
    if (pos + pk_len > data.size()) return false;
    config.public_key.assign(data.begin() + pos, data.begin() + pos + pk_len);
    pos += pk_len;

    // Store raw config
    config.raw_config = data;

    // Basic cipher suite setup
    HPKECipherSuite cs;
    cs.kem_id = static_cast<HPKEKem>(kem_id);
    cs.kdf_id = HPKEKDF::HKDF_SHA256;  // Default
    cs.aead_id = HPKEAEAD::AES_128_GCM;  // Default
    config.cipher_suites.push_back(cs);

    return true;
}

std::vector<uint8_t> apply_ech(
    const std::vector<uint8_t>& client_hello,
    const ECHConfig& config
) {
    ECHClientContext ctx;
    if (!ctx.init(config)) {
        return client_hello;  // Return unmodified on failure
    }

    std::vector<uint8_t> enc, encrypted;
    std::vector<uint8_t> aad;  // Empty AAD for now

    if (!ctx.encrypt(client_hello, aad, enc, encrypted)) {
        return client_hello;  // Return unmodified on failure
    }

    // Build ECH extension
    std::vector<uint8_t> result;
    // ECH extension type (0xfe0d for draft)
    result.push_back(0xfe);
    result.push_back(0x0d);
    // Config ID
    result.push_back(ctx.get_config_id());
    // Enc
    result.push_back(static_cast<uint8_t>(enc.size() >> 8));
    result.push_back(static_cast<uint8_t>(enc.size() & 0xFF));
    result.insert(result.end(), enc.begin(), enc.end());
    // Encrypted payload
    result.push_back(static_cast<uint8_t>(encrypted.size() >> 8));
    result.push_back(static_cast<uint8_t>(encrypted.size() & 0xFF));
    result.insert(result.end(), encrypted.begin(), encrypted.end());

    return result;
}

#else // !HAVE_OPENSSL

// Stub implementations when OpenSSL is not available

bool parse_ech_config(const std::vector<uint8_t>&, ECHConfig&) {
    return false;
}

std::vector<uint8_t> apply_ech(
    const std::vector<uint8_t>& client_hello,
    const ECHConfig&
) {
    return client_hello;
}

#endif // HAVE_OPENSSL

} // namespace ECH
} // namespace DPI
} // namespace ncp
