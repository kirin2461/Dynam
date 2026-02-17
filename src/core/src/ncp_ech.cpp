/**
 * @file ncp_ech.cpp
 * @brief Encrypted Client Hello (ECH) implementation using HPKE
 */

#include "../include/ncp_ech.hpp"
#include <cstring>
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

static int hpke_kem_to_nid(HPKEKem kem) {
    switch (kem) {
        case HPKEKem::DHKEM_P256_HKDF_SHA256: return EVP_HPKE_KEM_ID_P256_HKDF_SHA256;
        case HPKEKem::DHKEM_P384_HKDF_SHA384: return EVP_HPKE_KEM_ID_P384_HKDF_SHA384;
        case HPKEKem::DHKEM_P521_HKDF_SHA512: return EVP_HPKE_KEM_ID_P521_HKDF_SHA512;
        case HPKEKem::DHKEM_X25519_HKDF_SHA256: return EVP_HPKE_KEM_ID_X25519_HKDF_SHA256;
        case HPKEKem::DHKEM_X448_HKDF_SHA512: return EVP_HPKE_KEM_ID_X448_HKDF_SHA512;
        default: return 0;
    }
}

static int hpke_kdf_to_nid(HPKEKDF kdf) {
    switch (kdf) {
        case HPKEKDF::HKDF_SHA256: return EVP_HPKE_KDF_ID_HKDF_SHA256;
        case HPKEKDF::HKDF_SHA384: return EVP_HPKE_KDF_ID_HKDF_SHA384;
        case HPKEKDF::HKDF_SHA512: return EVP_HPKE_KDF_ID_HKDF_SHA512;
        default: return 0;
    }
}

static int hpke_aead_to_nid(HPKEAEAD aead) {
    switch (aead) {
        case HPKEAEAD::AES_128_GCM: return EVP_HPKE_AEAD_ID_AES_GCM_128;
        case HPKEAEAD::AES_256_GCM: return EVP_HPKE_AEAD_ID_AES_GCM_256;
        case HPKEAEAD::CHACHA20_POLY1305: return EVP_HPKE_AEAD_ID_CHACHA20_POLY1305;
        default: return 0;
    }
}

// ==================== ECHClientContext Implementation ====================

struct ECHClientContext::Impl {
    ECHConfig config;
    OSSL_HPKE_CTX* hpke_ctx = nullptr;

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
    const auto& suite = config.cipher_suites[0];

    int kem_id = hpke_kem_to_nid(suite.kem_id);
    int kdf_id = hpke_kdf_to_nid(suite.kdf_id);
    int aead_id = hpke_aead_to_nid(suite.aead_id);

    if (kem_id == 0 || kdf_id == 0 || aead_id == 0) {
        return false;
    }

    // Create HPKE context for sender (client)
    impl_->hpke_ctx = OSSL_HPKE_CTX_new(
        OSSL_HPKE_MODE_BASE,
        kem_id,
        kdf_id,
        aead_id,
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
    info.insert(info.end(), impl_->config.raw_config.begin(), impl_->config.raw_config.end());

    // Setup HPKE encapsulation (client side)
    size_t enc_len = 0;
    if (OSSL_HPKE_encap(
            impl_->hpke_ctx,
            nullptr, &enc_len,  // Get required enc size
            impl_->config.public_key.data(),
            impl_->config.public_key.size(),
            info.data(),
            info.size()
        ) != 1) {
        return false;
    }

    enc.resize(enc_len);
    if (OSSL_HPKE_encap(
            impl_->hpke_ctx,
            enc.data(), &enc_len,
            impl_->config.public_key.data(),
            impl_->config.public_key.size(),
            info.data(),
            info.size()
        ) != 1) {
        return false;
    }
    enc.resize(enc_len);

    // Seal (encrypt) ClientHelloInner with ClientHelloOuter as AAD
    size_t ct_len = client_hello_inner.size() + EVP_AEAD_MAX_OVERHEAD;
    encrypted_payload.resize(ct_len);

    if (OSSL_HPKE_seal(
            impl_->hpke_ctx,
            encrypted_payload.data(), &ct_len,
            client_hello_outer_aad.data(),
            client_hello_outer_aad.size(),
            client_hello_inner.data(),
            client_hello_inner.size()
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
    std::vector<uint8_t> private_key;
    HPKECipherSuite cipher_suite;
    OSSL_HPKE_CTX* hpke_ctx = nullptr;

    ~Impl() {
        if (hpke_ctx) {
            OSSL_HPKE_CTX_free(hpke_ctx);
        }
    }
};

ECHServerContext::ECHServerContext() : impl_(std::make_unique<Impl>()) {}
ECHServerContext::~ECHServerContext() = default;

bool ECHServerContext::init(
    const std::vector<uint8_t>& private_key,
    const HPKECipherSuite& cipher_suite
) {
    impl_->private_key = private_key;
    impl_->cipher_suite = cipher_suite;

    int kem_id = hpke_kem_to_nid(cipher_suite.kem_id);
    int kdf_id = hpke_kdf_to_nid(cipher_suite.kdf_id);
    int aead_id = hpke_aead_to_nid(cipher_suite.aead_id);

    if (kem_id == 0 || kdf_id == 0 || aead_id == 0) {
        return false;
    }

    // Create HPKE context for receiver (server)
    impl_->hpke_ctx = OSSL_HPKE_CTX_new(
        OSSL_HPKE_MODE_BASE,
        kem_id,
        kdf_id,
        aead_id,
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
    if (!impl_->hpke_ctx || impl_->private_key.empty()) {
        return false;
    }

    // Prepare info (should match client's info)
    std::vector<uint8_t> info;
    const char* label = "tls ech";
    info.insert(info.end(), label, label + 7);
    info.push_back(0x00);
    // Note: ECHConfig should be available to server from its own config

    // Setup HPKE decapsulation (server side)
    if (OSSL_HPKE_decap(
            impl_->hpke_ctx,
            enc.data(),
            enc.size(),
            impl_->private_key.data(),
            impl_->private_key.size(),
            info.data(),
            info.size()
        ) != 1) {
        return false;
    }

    // Open (decrypt) encrypted payload
    client_hello_inner.resize(encrypted_payload.size());
    size_t pt_len = client_hello_inner.size();

    if (OSSL_HPKE_open(
            impl_->hpke_ctx,
            client_hello_inner.data(), &pt_len,
            client_hello_outer_aad.data(),
            client_hello_outer_aad.size(),
            encrypted_payload.data(),
            encrypted_payload.size()
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

    // Cipher suites count (2 bytes)
    if (pos + 2 > data.size()) return false;
    uint16_t suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;

    // Parse cipher suites (each is 6 bytes: KDF(2) + AEAD(2))
    for (size_t i = 0; i < suites_len / 4 && pos + 4 <= data.size(); i++) {
        uint16_t kdf_id = (data[pos] << 8) | data[pos + 1];
        uint16_t aead_id = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        HPKECipherSuite suite(
            static_cast<HPKEKem>(kem_id),
            static_cast<HPKEKDF>(kdf_id),
            static_cast<HPKEAEAD>(aead_id)
        );
        config.cipher_suites.push_back(suite);
    }

    // Save raw config for HPKE info
    config.raw_config = data;

    return true;
}

ECHConfig create_test_ech_config(
    const std::string& public_name,
    const HPKECipherSuite& cipher_suite,
    std::vector<uint8_t>& private_key
) {
    ECHConfig config;
    config.public_name = public_name;
    config.config_id = 0;
    config.cipher_suites.push_back(cipher_suite);

    int kem_id = hpke_kem_to_nid(cipher_suite.kem_id);

    // Generate keypair
    EVP_PKEY* pkey = nullptr;
    if (OSSL_HPKE_keygen(
            OSSL_HPKE_CTX_new(OSSL_HPKE_MODE_BASE, kem_id, 0, 0, nullptr, nullptr),
            nullptr, 0,
            &pkey,
            nullptr, nullptr
        ) == 1 && pkey) {

        // Export public key
        size_t pub_len = 0;
        if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pub_len) == 1) {
            config.public_key.resize(pub_len);
            EVP_PKEY_get_raw_public_key(pkey, config.public_key.data(), &pub_len);
        }

        // Export private key
        size_t priv_len = 0;
        if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &priv_len) == 1) {
            private_key.resize(priv_len);
            EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &priv_len);
        }

        EVP_PKEY_free(pkey);
    }

    return config;
}

std::vector<uint8_t> apply_ech(
    const std::vector<uint8_t>& client_hello,
    const ECHConfig& ech_config
) {
    // Create ECH client context
    ECHClientContext ctx;
    if (!ctx.init(ech_config)) {
        return client_hello;  // Fallback to unencrypted
    }

    // TODO: Extract ClientHelloInner from client_hello
    // For now, use entire ClientHello as inner
    std::vector<uint8_t> client_hello_inner = client_hello;

    // Create ClientHelloOuter (simplified - should construct properly)
    std::vector<uint8_t> client_hello_outer_aad = client_hello;

    // Encrypt
    std::vector<uint8_t> enc, encrypted_payload;
    if (!ctx.encrypt(client_hello_inner, client_hello_outer_aad, enc, encrypted_payload)) {
        return client_hello;  // Fallback
    }

    // Build ClientHello with ECH extension
    std::vector<uint8_t> result = client_hello;

    // Add ECH extension (0xfe0d)
    std::vector<uint8_t> ech_extension;
    ech_extension.push_back(0xfe);  // Extension type high
    ech_extension.push_back(0x0d);  // Extension type low

    // Extension data length (2 bytes) - placeholder
    size_t ext_len_pos = ech_extension.size();
    ech_extension.push_back(0x00);
    ech_extension.push_back(0x00);

    // ECH type (outer = 0)
    ech_extension.push_back(0x00);

    // Cipher suite
    auto suite = ctx.get_cipher_suite();
    ech_extension.push_back(static_cast<uint8_t>(static_cast<uint16_t>(suite.kdf_id) >> 8));
    ech_extension.push_back(static_cast<uint8_t>(static_cast<uint16_t>(suite.kdf_id) & 0xFF));
    ech_extension.push_back(static_cast<uint8_t>(static_cast<uint16_t>(suite.aead_id) >> 8));
    ech_extension.push_back(static_cast<uint8_t>(static_cast<uint16_t>(suite.aead_id) & 0xFF));

    // Config ID
    ech_extension.push_back(ctx.get_config_id());

    // Encapsulated key (enc) - 2 byte length prefix
    ech_extension.push_back(static_cast<uint8_t>(enc.size() >> 8));
    ech_extension.push_back(static_cast<uint8_t>(enc.size() & 0xFF));
    ech_extension.insert(ech_extension.end(), enc.begin(), enc.end());

    // Encrypted payload - 2 byte length prefix
    ech_extension.push_back(static_cast<uint8_t>(encrypted_payload.size() >> 8));
    ech_extension.push_back(static_cast<uint8_t>(encrypted_payload.size() & 0xFF));
    ech_extension.insert(ech_extension.end(), encrypted_payload.begin(), encrypted_payload.end());

    // Update extension length
    uint16_t ext_data_len = ech_extension.size() - ext_len_pos - 2;
    ech_extension[ext_len_pos] = static_cast<uint8_t>(ext_data_len >> 8);
    ech_extension[ext_len_pos + 1] = static_cast<uint8_t>(ext_data_len & 0xFF);

    // Append ECH extension to ClientHello
    result.insert(result.end(), ech_extension.begin(), ech_extension.end());

    return result;
}

#else  // !HAVE_OPENSSL

// Stub implementations when OpenSSL is not available

struct ECHClientContext::Impl {};
ECHClientContext::ECHClientContext() : impl_(std::make_unique<Impl>()) {}
ECHClientContext::~ECHClientContext() = default;
bool ECHClientContext::init(const ECHConfig&) { return false; }
bool ECHClientContext::encrypt(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                                std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }
HPKECipherSuite ECHClientContext::get_cipher_suite() const { return HPKECipherSuite(); }
uint8_t ECHClientContext::get_config_id() const { return 0; }

struct ECHServerContext::Impl {};
ECHServerContext::ECHServerContext() : impl_(std::make_unique<Impl>()) {}
ECHServerContext::~ECHServerContext() = default;
bool ECHServerContext::init(const std::vector<uint8_t>&, const HPKECipherSuite&) { return false; }
bool ECHServerContext::decrypt(const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                                const std::vector<uint8_t>&, std::vector<uint8_t>&) { return false; }

bool parse_ech_config(const std::vector<uint8_t>&, ECHConfig&) { return false; }

ECHConfig create_test_ech_config(const std::string&, const HPKECipherSuite&,
                                 std::vector<uint8_t>&) { return ECHConfig(); }

std::vector<uint8_t> apply_ech(const std::vector<uint8_t>& client_hello, const ECHConfig&) {
    return client_hello;  // Return unmodified
}

#endif  // HAVE_OPENSSL

} // namespace ECH
} // namespace DPI
} // namespace ncp
