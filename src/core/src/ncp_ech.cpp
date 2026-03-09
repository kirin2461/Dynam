/**
 * @file ncp_ech.cpp
 * @brief Encrypted Client Hello (ECH) implementation using HPKE
 */

#include "../include/ncp_ech.hpp"
#include <string>
#include <algorithm>
#include <cstring>
#include <sodium.h>

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
        case HPKEAEAD::CHACHA20_POLY1305:   return OSSL_HPKE_AEAD_ID_CHACHA_POLY1305;
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

// ==================== ClientHello Parser Helpers ====================

static bool find_extensions_block(
    const uint8_t* data, size_t len,
    size_t& ext_offset, size_t& ext_end
) {
    if (!data || len < 44) return false;
    if (data[0] != 0x16) return false;           // ContentType: Handshake
    if (data[5] != 0x01) return false;           // HandshakeType: ClientHello

    size_t pos = 9;  // skip record header(5) + handshake header(4)

    // ClientVersion
    pos += 2; // [9..10]
    if (pos > len) return false;

    // Random
    pos += 32; // [11..42]
    if (pos >= len) return false;

    // SessionID
    uint8_t sid_len = data[pos];
    pos += 1 + sid_len;
    if (pos + 2 > len) return false;

    // CipherSuites
    uint16_t cs_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2 + cs_len;
    if (pos + 1 > len) return false;

    // CompressionMethods
    uint8_t comp_len = data[pos];
    pos += 1 + comp_len;
    if (pos + 2 > len) return false;

    // Extensions length field starts here
    ext_offset = pos;
    uint16_t exts_len = (static_cast<uint16_t>(data[pos]) << 8) | data[pos + 1];
    pos += 2;

    ext_end = pos + exts_len;
    if (ext_end > len) {
        ext_end = len;  // clamp
    }

    return true;
}

static std::vector<uint8_t> rewrite_sni(
    const std::vector<uint8_t>& ch,
    const std::string& new_name
) {
    size_t ext_offset = 0, ext_end = 0;
    if (!find_extensions_block(ch.data(), ch.size(), ext_offset, ext_end)) {
        return ch;
    }

    // Walk extensions to find SNI (type 0x0000)
    size_t pos = ext_offset + 2;  // skip extensions_length
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (static_cast<uint16_t>(ch[pos]) << 8) | ch[pos + 1];
        uint16_t ext_data_len = (static_cast<uint16_t>(ch[pos + 2]) << 8) | ch[pos + 3];
        size_t ext_start = pos;

        if (ext_type == 0x0000 && ext_data_len >= 5) {
            // Found SNI extension
            size_t sni_body = pos + 4;  // start of extension data
            if (sni_body + 5 > ext_end) break;

            size_t hn_len_offset = sni_body + 2 + 1;  // after sni_list_len + name_type
            if (hn_len_offset + 2 > ext_end) break;
            uint16_t old_hn_len = (static_cast<uint16_t>(ch[hn_len_offset]) << 8) |
                                  ch[hn_len_offset + 1];
            size_t hn_start = hn_len_offset + 2;
            if (hn_start + old_hn_len > ext_end) break;
            // R10-FIX-04: Prevent integer underflow in size calculation
            if (old_hn_len > ch.size()) {
                return ch;  // Malformed: hostname length exceeds packet size
            }

            std::vector<uint8_t> result;
            result.reserve(ch.size() - old_hn_len + new_name.size());

            // Copy up to hostname
            result.insert(result.end(), ch.begin(), ch.begin() + hn_start);
            // Insert new hostname
            result.insert(result.end(), new_name.begin(), new_name.end());
            // Copy after old hostname
            result.insert(result.end(),
                          ch.begin() + hn_start + old_hn_len,
                          ch.end());

            int16_t delta = static_cast<int16_t>(new_name.size()) -
                            static_cast<int16_t>(old_hn_len);

            if (delta != 0) {
                // Patch hostname_len
                uint16_t new_hn_len = static_cast<uint16_t>(new_name.size());
                result[hn_len_offset]     = static_cast<uint8_t>(new_hn_len >> 8);
                result[hn_len_offset + 1] = static_cast<uint8_t>(new_hn_len & 0xFF);

                // Patch sni_list_len
                uint16_t old_list_len = (static_cast<uint16_t>(ch[sni_body]) << 8) |
                                        ch[sni_body + 1];
                uint16_t new_list_len = static_cast<uint16_t>(old_list_len + delta);
                result[sni_body]     = static_cast<uint8_t>(new_list_len >> 8);
                result[sni_body + 1] = static_cast<uint8_t>(new_list_len & 0xFF);

                // Patch extension data length
                uint16_t new_ext_data_len = static_cast<uint16_t>(ext_data_len + delta);
                result[ext_start + 2] = static_cast<uint8_t>(new_ext_data_len >> 8);
                result[ext_start + 3] = static_cast<uint8_t>(new_ext_data_len & 0xFF);

                // Patch extensions_length
                uint16_t old_exts_len = (static_cast<uint16_t>(ch[ext_offset]) << 8) |
                                        ch[ext_offset + 1];
                uint16_t new_exts_len = static_cast<uint16_t>(old_exts_len + delta);
                result[ext_offset]     = static_cast<uint8_t>(new_exts_len >> 8);
                result[ext_offset + 1] = static_cast<uint8_t>(new_exts_len & 0xFF);

                // Patch Handshake length (3 bytes at offset 6..8)
                uint32_t old_hs_len = (static_cast<uint32_t>(ch[6]) << 16) |
                                      (static_cast<uint32_t>(ch[7]) << 8) |
                                      static_cast<uint32_t>(ch[8]);
                uint32_t new_hs_len = static_cast<uint32_t>(static_cast<int32_t>(old_hs_len) + delta);
                result[6] = static_cast<uint8_t>((new_hs_len >> 16) & 0xFF);
                result[7] = static_cast<uint8_t>((new_hs_len >> 8) & 0xFF);
                result[8] = static_cast<uint8_t>(new_hs_len & 0xFF);

                // Patch TLS record length (2 bytes at offset 3..4)
                uint16_t old_rec_len = (static_cast<uint16_t>(ch[3]) << 8) |
                                       static_cast<uint16_t>(ch[4]);
                uint16_t new_rec_len = static_cast<uint16_t>(old_rec_len + delta);
                result[3] = static_cast<uint8_t>(new_rec_len >> 8);
                result[4] = static_cast<uint8_t>(new_rec_len & 0xFF);
            }

            return result;
        }

        pos += 4 + ext_data_len;
    }

    return ch;  // SNI not found, return unchanged
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

    // Prepare info string: "tls ech" || 0x00 || config_id || public_key || cipher_suite
    // This canonical format ensures client and server use identical info strings
    // even if ECHConfig was created differently (DNS vs. test config)
    std::vector<uint8_t> info;
    const char* label = "tls ech";
    info.insert(info.end(), label, label + 7);
    info.push_back(0x00);
    // Use canonical fields instead of raw_config to avoid mismatch
    info.push_back(impl_->config.config_id);
    info.insert(info.end(), impl_->config.public_key.begin(),
                impl_->config.public_key.end());
    // Add cipher suite for uniqueness
    if (!impl_->config.cipher_suites.empty()) {
        const auto& cs = impl_->config.cipher_suites[0];
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kem_id) >> 8));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kem_id) & 0xFF));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kdf_id) >> 8));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kdf_id) & 0xFF));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.aead_id) >> 8));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.aead_id) & 0xFF));
    }

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
    ECHConfig ech_config;  // Store ECHConfig for info vector in decrypt()

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
    const HPKECipherSuite& cipher_suite,
    const ECHConfig& ech_config
) {
    impl_->cipher_suite = cipher_suite;
    impl_->suite = make_suite(cipher_suite);
    impl_->ech_config = ech_config;

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

    // Prepare info: "tls ech" || 0x00 || config_id || public_key || cipher_suite
    // Must match client's info string exactly (canonical format)
    std::vector<uint8_t> info;
    const char* label = "tls ech";
    info.insert(info.end(), label, label + 7);
    info.push_back(0x00);
    // Use canonical fields instead of raw_config to avoid mismatch
    info.push_back(impl_->ech_config.config_id);
    info.insert(info.end(), impl_->ech_config.public_key.begin(),
                impl_->ech_config.public_key.end());
    // Add cipher suite for uniqueness
    if (!impl_->ech_config.cipher_suites.empty()) {
        const auto& cs = impl_->ech_config.cipher_suites[0];
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kem_id) >> 8));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kem_id) & 0xFF));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kdf_id) >> 8));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.kdf_id) & 0xFF));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.aead_id) >> 8));
        info.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cs.aead_id) & 0xFF));
    }

    // Setup HPKE decapsulation (server side)
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

ECHConfig create_test_ech_config(
    const std::string& public_name,
    const HPKECipherSuite& cipher_suite,
    std::vector<uint8_t>& private_key
) {
    ECHConfig config;
    config.public_name = public_name;
    config.config_id = 1;
    config.cipher_suites.push_back(cipher_suite);

    // Generate HPKE keypair based on KEM
    switch (cipher_suite.kem_id) {
        case HPKEKem::DHKEM_X25519_HKDF_SHA256: {
            // X25519: 32-byte private key, 32-byte public key
            private_key.resize(32);
            config.public_key.resize(32);
            
#ifdef HAVE_OPENSSL
            EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X25519, nullptr,
                private_key.data(), private_key.size());
            if (!pkey) {
                // Generate new keypair if import fails
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
                EVP_PKEY_keygen_init(ctx);
                EVP_PKEY_keygen(ctx, &pkey);
                size_t priv_key_len = private_key.size();
                size_t pub_key_len = config.public_key.size();
                EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &priv_key_len);
                EVP_PKEY_get_raw_public_key(pkey, config.public_key.data(), &pub_key_len);
                EVP_PKEY_CTX_free(ctx);
            } else {
                size_t pub_key_len = config.public_key.size();
                EVP_PKEY_get_raw_public_key(pkey, config.public_key.data(), &pub_key_len);
                EVP_PKEY_free(pkey);
            }
#else
            // Fallback: use libsodium for X25519
            crypto_box_keypair(config.public_key.data(), private_key.data());
#endif
            break;
        }
        case HPKEKem::DHKEM_X448_HKDF_SHA512: {
            // X448: 56-byte private key, 56-byte public key
            private_key.resize(56);
            config.public_key.resize(56);
            
#ifdef HAVE_OPENSSL
            EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, nullptr,
                private_key.data(), private_key.size());
            if (!pkey) {
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
                EVP_PKEY_keygen_init(ctx);
                EVP_PKEY_keygen(ctx, &pkey);
                size_t priv_key_len2 = private_key.size();
                size_t pub_key_len2 = config.public_key.size();
                EVP_PKEY_get_raw_private_key(pkey, private_key.data(), &priv_key_len2);
                EVP_PKEY_get_raw_public_key(pkey, config.public_key.data(), &pub_key_len2);
                EVP_PKEY_CTX_free(ctx);
            } else {
                size_t pub_key_len2 = config.public_key.size();
                EVP_PKEY_get_raw_public_key(pkey, config.public_key.data(), &pub_key_len2);
                EVP_PKEY_free(pkey);
            }
#else
            // X448 not available in libsodium - fallback to X25519
            private_key.resize(32);
            config.public_key.resize(32);
            crypto_box_keypair(config.public_key.data(), private_key.data());
#endif
            break;
        }
        default:
            // Unsupported KEM - fallback to X25519
            private_key.resize(32);
            config.public_key.resize(32);
            crypto_box_keypair(config.public_key.data(), private_key.data());
            break;
    }

    // Build canonical raw_config for wire format
    // Format: version(2) + config_id(1) + kem_id(2) + pk_len(2) + public_key
    config.raw_config.clear();
    config.raw_config.reserve(9 + config.public_key.size());
    
    // Version
    config.raw_config.push_back(static_cast<uint8_t>(config.version >> 8));
    config.raw_config.push_back(static_cast<uint8_t>(config.version & 0xFF));
    
    // Config ID
    config.raw_config.push_back(config.config_id);
    
    // KEM ID
    config.raw_config.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cipher_suite.kem_id) >> 8));
    config.raw_config.push_back(static_cast<uint8_t>(static_cast<uint16_t>(cipher_suite.kem_id) & 0xFF));
    
    // Public key length
    config.raw_config.push_back(static_cast<uint8_t>(config.public_key.size() >> 8));
    config.raw_config.push_back(static_cast<uint8_t>(config.public_key.size() & 0xFF));
    
    // Public key
    config.raw_config.insert(config.raw_config.end(), 
                             config.public_key.begin(), 
                             config.public_key.end());

    return config;
}

std::vector<uint8_t> apply_ech(
    const std::vector<uint8_t>& client_hello,
    const ECHConfig& config
) {
    // Validate basic structure: TLS Handshake / ClientHello
    if (client_hello.size() < 44) return client_hello;
    if (client_hello[0] != 0x16) return client_hello;
    if (client_hello[5] != 0x01) return client_hello;

    size_t ext_offset = 0, ext_end = 0;
    if (!find_extensions_block(client_hello.data(), client_hello.size(),
                               ext_offset, ext_end)) {
        return client_hello;
    }

    ECHClientContext ctx;
    if (!ctx.init(config)) {
        return client_hello;
    }

    std::vector<uint8_t> enc, encrypted;
    std::vector<uint8_t> aad = client_hello;  // use full outer CH as AAD

    if (!ctx.encrypt(client_hello, aad, enc, encrypted)) {
        return client_hello;
    }

    const auto& cs = config.cipher_suites.empty()
                     ? HPKECipherSuite() : config.cipher_suites[0];

    std::vector<uint8_t> ech_payload;
    ech_payload.reserve(1 + 4 + 1 + 2 + enc.size() + 2 + encrypted.size());

    // type = 0 (outer)
    ech_payload.push_back(0x00);

    // cipher_suite: kdf_id (2) + aead_id (2)
    uint16_t kdf_val = static_cast<uint16_t>(cs.kdf_id);
    uint16_t aead_val = static_cast<uint16_t>(cs.aead_id);
    ech_payload.push_back(static_cast<uint8_t>(kdf_val >> 8));
    ech_payload.push_back(static_cast<uint8_t>(kdf_val & 0xFF));
    ech_payload.push_back(static_cast<uint8_t>(aead_val >> 8));
    ech_payload.push_back(static_cast<uint8_t>(aead_val & 0xFF));

    // config_id
    ech_payload.push_back(ctx.get_config_id());

    // enc_len + enc
    ech_payload.push_back(static_cast<uint8_t>(enc.size() >> 8));
    ech_payload.push_back(static_cast<uint8_t>(enc.size() & 0xFF));
    ech_payload.insert(ech_payload.end(), enc.begin(), enc.end());

    // payload_len + payload
    ech_payload.push_back(static_cast<uint8_t>(encrypted.size() >> 8));
    ech_payload.push_back(static_cast<uint8_t>(encrypted.size() & 0xFF));
    ech_payload.insert(ech_payload.end(), encrypted.begin(), encrypted.end());

    // Wrap as TLS extension
    std::vector<uint8_t> ech_ext;
    ech_ext.reserve(4 + ech_payload.size());
    ech_ext.push_back(0xfe);  // extension type: 0xfe0d (draft ECH)
    ech_ext.push_back(0x0d);
    uint16_t payload_len = static_cast<uint16_t>(ech_payload.size());
    ech_ext.push_back(static_cast<uint8_t>(payload_len >> 8));
    ech_ext.push_back(static_cast<uint8_t>(payload_len & 0xFF));
    ech_ext.insert(ech_ext.end(), ech_payload.begin(), ech_payload.end());

    std::vector<uint8_t> result = client_hello;

    // Append ECH extension to extensions block
    result.insert(result.begin() + ext_end,
                  ech_ext.begin(), ech_ext.end());

    uint16_t ech_ext_total = static_cast<uint16_t>(ech_ext.size());

    // Patch extensions_length
    uint16_t old_exts_len = (static_cast<uint16_t>(result[ext_offset]) << 8) |
                            result[ext_offset + 1];
    uint16_t new_exts_len = static_cast<uint16_t>(old_exts_len + ech_ext_total);
    result[ext_offset]     = static_cast<uint8_t>(new_exts_len >> 8);
    result[ext_offset + 1] = static_cast<uint8_t>(new_exts_len & 0xFF);

    // Patch Handshake length (3 bytes at offset 6..8)
    uint32_t old_hs_len = (static_cast<uint32_t>(result[6]) << 16) |
                          (static_cast<uint32_t>(result[7]) << 8) |
                          static_cast<uint32_t>(result[8]);
    uint32_t new_hs_len = old_hs_len + ech_ext_total;
    result[6] = static_cast<uint8_t>((new_hs_len >> 16) & 0xFF);
    result[7] = static_cast<uint8_t>((new_hs_len >> 8) & 0xFF);
    result[8] = static_cast<uint8_t>(new_hs_len & 0xFF);

    // Patch TLS record length (2 bytes at offset 3..4)
    uint16_t old_rec_len = (static_cast<uint16_t>(result[3]) << 8) |
                           static_cast<uint16_t>(result[4]);
    uint16_t new_rec_len = static_cast<uint16_t>(old_rec_len + ech_ext_total);
    result[3] = static_cast<uint8_t>(new_rec_len >> 8);
    result[4] = static_cast<uint8_t>(new_rec_len & 0xFF);

    return result;
}

#else // !HAVE_OPENSSL

// ==================== Fallback Implementations (no OpenSSL) ====================
//
// Without OpenSSL 3.2+ HPKE, we provide:
//   parse_ech_config() — full binary parser for ECHConfig wire format
//                         (draft-ietf-tls-esni § 4, version 0xfe0d)
//   apply_ech()        — real encryption using libsodium X25519 + XChaCha20-Poly1305
//                         (not RFC 9180-compliant HPKE, but provides actual SNI confidentiality)
//   ECHClientContext   — wraps the libsodium-based encrypt()
//   ECHServerContext   — decrypt stub (cannot invert without matching HPKE decap)
//
// The libsodium fallback follows this wire format for apply_ech():
//
//   ECH extension value (0xfe0d):
//     type (1)          = 0x01 (NCP-sodium variant tag, distinguishes from HPKE outer=0x00)
//     cipher_suite (4)  = KDF=0x0001 AEAD=0x0003 (hard-coded X25519+XChaCha20Poly1305)
//     config_id (1)
//     enc_len (2) + enc (32)   = client ephemeral X25519 public key
//     payload_len (2) + payload = crypto_box ciphertext of inner ClientHello
//                                 (includes 24-byte nonce prepended by sender)
//
// Encryption procedure:
//   1. Generate ephemeral X25519 keypair  (ephem_pk, ephem_sk)  via libsodium
//   2. Compute shared secret = X25519(ephem_sk, server_pk)
//   3. Derive symmetric key = Blake2b(shared_secret || server_pk || ephem_pk, 32)
//   4. Generate random 24-byte nonce
//   5. Encrypt inner CH = XChaCha20Poly1305_seal(inner_CH, aad=outer_CH, key, nonce)
//   6. Wire payload = nonce (24) || ciphertext

#include <sodium.h>

// Impl stubs — needed so std::make_unique<Impl>() compiles without OpenSSL

struct ECHClientContext::Impl {
    ECHConfig config;
    bool initialized = false;
};

ECHClientContext::ECHClientContext() : impl_(std::make_unique<Impl>()) {}
ECHClientContext::~ECHClientContext() = default;

bool ECHClientContext::init(const ECHConfig& config) {
    if (config.public_key.size() != crypto_box_PUBLICKEYBYTES) {
        // Fallback: accept any 32-byte key (X25519 public key)
        // If key is wrong size, we cannot do X25519
        if (config.public_key.size() != 32) return false;
    }
    impl_->config = config;
    impl_->initialized = true;
    return true;
}

bool ECHClientContext::encrypt(
    const std::vector<uint8_t>& client_hello_inner,
    const std::vector<uint8_t>& client_hello_outer_aad,
    std::vector<uint8_t>& enc,
    std::vector<uint8_t>& encrypted_payload
) {
    if (!impl_->initialized || impl_->config.public_key.empty()) return false;
    if (impl_->config.public_key.size() != crypto_box_PUBLICKEYBYTES) return false;

    // 1. Generate ephemeral X25519 keypair
    uint8_t ephem_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t ephem_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(ephem_pk, ephem_sk);

    // 2. Compute raw X25519 shared secret
    uint8_t raw_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(raw_secret, ephem_sk,
                          impl_->config.public_key.data()) != 0) {
        sodium_memzero(ephem_sk, sizeof(ephem_sk));
        return false;
    }
    sodium_memzero(ephem_sk, sizeof(ephem_sk));

    // 3. Derive 32-byte symmetric key via Blake2b
    //    key = Blake2b-256(raw_secret || server_pk || ephem_pk)
    //    Using crypto_generichash (Blake2b with variable output)
    uint8_t sym_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES]; // 32
    {
        crypto_generichash_state st;
        crypto_generichash_init(&st, nullptr, 0, sizeof(sym_key));
        crypto_generichash_update(&st, raw_secret, sizeof(raw_secret));
        crypto_generichash_update(&st, impl_->config.public_key.data(),
                                  impl_->config.public_key.size());
        crypto_generichash_update(&st, ephem_pk, sizeof(ephem_pk));
        crypto_generichash_final(&st, sym_key, sizeof(sym_key));
        sodium_memzero(raw_secret, sizeof(raw_secret));
    }

    // 4. Generate 24-byte nonce
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; // 24
    randombytes_buf(nonce, sizeof(nonce));

    // 5. Build AAD: mix of outer ClientHello + config_id for binding
    //    We hash the outer CH to keep the AAD size manageable
    uint8_t aad[crypto_generichash_BYTES]; // 32
    {
        crypto_generichash_state st;
        crypto_generichash_init(&st, nullptr, 0, sizeof(aad));
        if (!client_hello_outer_aad.empty()) {
            crypto_generichash_update(&st, client_hello_outer_aad.data(),
                                      client_hello_outer_aad.size());
        }
        uint8_t cfg_id = impl_->config.config_id;
        crypto_generichash_update(&st, &cfg_id, 1);
        crypto_generichash_final(&st, aad, sizeof(aad));
    }

    // 6. Encrypt: payload = nonce || XChaCha20Poly1305(inner_CH, aad, sym_key, nonce)
    size_t ct_len = client_hello_inner.size() +
                    crypto_aead_xchacha20poly1305_ietf_ABYTES; // +16 byte tag
    encrypted_payload.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + ct_len);

    // Prepend nonce
    std::memcpy(encrypted_payload.data(), nonce, sizeof(nonce));

    unsigned long long actual_ct_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted_payload.data() + sizeof(nonce), // ciphertext output
        &actual_ct_len,
        client_hello_inner.data(), client_hello_inner.size(),
        aad, sizeof(aad),
        nullptr,   // no secret nonce
        nonce,
        sym_key
    );
    sodium_memzero(sym_key, sizeof(sym_key));
    sodium_memzero(nonce, sizeof(nonce));

    if (rc != 0) {
        encrypted_payload.clear();
        return false;
    }
    encrypted_payload.resize(sizeof(nonce) + static_cast<size_t>(actual_ct_len));

    // enc = ephemeral public key (32 bytes)
    enc.assign(ephem_pk, ephem_pk + sizeof(ephem_pk));

    return true;
}

HPKECipherSuite ECHClientContext::get_cipher_suite() const {
    HPKECipherSuite cs;
    cs.kem_id  = HPKEKem::DHKEM_X25519_HKDF_SHA256;
    cs.kdf_id  = HPKEKDF::HKDF_SHA256;
    cs.aead_id = HPKEAEAD::CHACHA20_POLY1305;
    return cs;
}

uint8_t ECHClientContext::get_config_id() const {
    return impl_->config.config_id;
}

struct ECHServerContext::Impl {
    HPKECipherSuite cipher_suite;
    ECHConfig ech_config;
    std::vector<uint8_t> private_key;
};

ECHServerContext::ECHServerContext() : impl_(std::make_unique<Impl>()) {}
ECHServerContext::~ECHServerContext() = default;

bool ECHServerContext::init(
    const std::vector<uint8_t>& private_key,
    const HPKECipherSuite& cipher_suite,
    const ECHConfig& ech_config
) {
    if (private_key.size() != crypto_box_SECRETKEYBYTES) return false;
    impl_->private_key = private_key;
    impl_->cipher_suite = cipher_suite;
    impl_->ech_config = ech_config;
    return true;
}

bool ECHServerContext::decrypt(
    const std::vector<uint8_t>& enc,
    const std::vector<uint8_t>& encrypted_payload,
    const std::vector<uint8_t>& client_hello_outer_aad,
    std::vector<uint8_t>& client_hello_inner
) {
    // enc = ephemeral client public key (32 bytes)
    // encrypted_payload = nonce(24) || ciphertext
    if (impl_->private_key.empty()) return false;
    if (enc.size() != crypto_box_PUBLICKEYBYTES) return false;
    if (encrypted_payload.size() < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
                                   crypto_aead_xchacha20poly1305_ietf_ABYTES) return false;

    // Recompute shared secret: X25519(server_sk, ephem_pk)
    uint8_t raw_secret[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(raw_secret, impl_->private_key.data(), enc.data()) != 0) {
        return false;
    }

    // Recompute symmetric key: Blake2b-256(raw_secret || server_pk || ephem_pk)
    uint8_t sym_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    {
        crypto_generichash_state st;
        crypto_generichash_init(&st, nullptr, 0, sizeof(sym_key));
        crypto_generichash_update(&st, raw_secret, sizeof(raw_secret));
        crypto_generichash_update(&st, impl_->ech_config.public_key.data(),
                                  impl_->ech_config.public_key.size());
        crypto_generichash_update(&st, enc.data(), enc.size());
        crypto_generichash_final(&st, sym_key, sizeof(sym_key));
        sodium_memzero(raw_secret, sizeof(raw_secret));
    }

    // Rebuild AAD
    uint8_t aad[crypto_generichash_BYTES];
    {
        crypto_generichash_state st;
        crypto_generichash_init(&st, nullptr, 0, sizeof(aad));
        if (!client_hello_outer_aad.empty()) {
            crypto_generichash_update(&st, client_hello_outer_aad.data(),
                                      client_hello_outer_aad.size());
        }
        uint8_t cfg_id = impl_->ech_config.config_id;
        crypto_generichash_update(&st, &cfg_id, 1);
        crypto_generichash_final(&st, aad, sizeof(aad));
    }

    const uint8_t* nonce = encrypted_payload.data(); // first 24 bytes
    const uint8_t* ct    = encrypted_payload.data() +
                           crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    size_t         ct_len = encrypted_payload.size() -
                           crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    size_t pt_max = ct_len; // at most plaintext size
    client_hello_inner.resize(pt_max);
    unsigned long long actual_pt_len = 0;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        client_hello_inner.data(), &actual_pt_len,
        nullptr,
        ct, ct_len,
        aad, sizeof(aad),
        nonce,
        sym_key
    );
    sodium_memzero(sym_key, sizeof(sym_key));

    if (rc != 0) {
        client_hello_inner.clear();
        return false;
    }
    client_hello_inner.resize(static_cast<size_t>(actual_pt_len));
    return true;
}

// ==================== parse_ech_config (no-OpenSSL) ====================
//
// Parses the ECHConfig binary format from draft-ietf-tls-esni.
//
// ECHConfig structure (wire format, version 0xfe0d):
//   version        (2)  — must be 0xfe0d
//   length         (2)  — length of the following ECHConfigContents
//   ECHConfigContents:
//     config_id    (1)
//     kem_id       (2)
//     public_key   (2 len-prefixed) — raw HPKE public key
//     cipher_suites (2 len-prefixed list of 4-byte entries: kdf_id(2) + aead_id(2))
//     maximum_name_length (1)
//     public_name  (1 len-prefixed) — outer SNI hostname
//     extensions   (2 len-prefixed)
//
bool parse_ech_config(const std::vector<uint8_t>& data, ECHConfig& config) {
    if (data.size() < 6) return false; // minimum: version(2)+length(2)+config_id(1)+kem_id(2)

    size_t pos = 0;

    // version (2 bytes)
    config.version = (static_cast<uint16_t>(data[pos]) << 8) |
                      static_cast<uint16_t>(data[pos + 1]);
    pos += 2;

    // contents_length (2 bytes) — remaining bytes after this field
    if (pos + 2 > data.size()) return false;
    uint16_t contents_len = (static_cast<uint16_t>(data[pos]) << 8) |
                             static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    size_t contents_end = pos + contents_len;
    if (contents_end > data.size()) contents_end = data.size(); // clamp

    // config_id (1 byte)
    if (pos >= contents_end) return false;
    config.config_id = data[pos++];

    // kem_id (2 bytes)
    if (pos + 2 > contents_end) return false;
    uint16_t kem_id = (static_cast<uint16_t>(data[pos]) << 8) |
                       static_cast<uint16_t>(data[pos + 1]);
    pos += 2;

    // public_key: 2-byte length-prefix + bytes
    if (pos + 2 > contents_end) return false;
    uint16_t pk_len = (static_cast<uint16_t>(data[pos]) << 8) |
                       static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    if (pos + pk_len > contents_end) return false;
    config.public_key.assign(data.begin() + pos, data.begin() + pos + pk_len);
    pos += pk_len;

    // cipher_suites: 2-byte list length, then N * (kdf_id(2) + aead_id(2)) entries
    if (pos + 2 > contents_end) return false;
    uint16_t cs_list_len = (static_cast<uint16_t>(data[pos]) << 8) |
                            static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    size_t cs_end = pos + cs_list_len;
    if (cs_end > contents_end) cs_end = contents_end;
    config.cipher_suites.clear();
    while (pos + 4 <= cs_end) {
        HPKECipherSuite cs;
        cs.kem_id  = static_cast<HPKEKem>(kem_id); // apply the parsed KEM ID to all suites
        cs.kdf_id  = static_cast<HPKEKDF>(
                        (static_cast<uint16_t>(data[pos]) << 8) |
                         static_cast<uint16_t>(data[pos + 1]));
        pos += 2;
        cs.aead_id = static_cast<HPKEAEAD>(
                        (static_cast<uint16_t>(data[pos]) << 8) |
                         static_cast<uint16_t>(data[pos + 1]));
        pos += 2;
        config.cipher_suites.push_back(cs);
    }
    pos = cs_end; // skip any trailing bytes in the list

    // If no cipher suites parsed, add a sensible default
    if (config.cipher_suites.empty()) {
        HPKECipherSuite cs;
        cs.kem_id  = static_cast<HPKEKem>(kem_id);
        cs.kdf_id  = HPKEKDF::HKDF_SHA256;
        cs.aead_id = HPKEAEAD::CHACHA20_POLY1305;
        config.cipher_suites.push_back(cs);
    }

    // maximum_name_length (1 byte)
    if (pos < contents_end) {
        config.maximum_name_length = data[pos++];
    }

    // public_name: 1-byte length-prefix + bytes
    if (pos < contents_end) {
        uint8_t name_len = data[pos++];
        if (pos + name_len <= contents_end) {
            config.public_name.assign(
                reinterpret_cast<const char*>(data.data() + pos), name_len);
            pos += name_len;
        }
    }

    // extensions: 2-byte length-prefix + bytes (skip them)
    // (no extensions defined in draft-ietf-tls-esni-18)

    // Store raw bytes for HPKE info construction
    config.raw_config = data;

    return true; // success
}

// ==================== apply_ech (no-OpenSSL) ====================
//
// Encrypts the SNI by embedding a non-standard ECH extension containing:
//   - The ephemeral X25519 public key (enc)
//   - XChaCha20Poly1305 ciphertext of the inner ClientHello
//   - 24-byte nonce prepended to the ciphertext field
//
// The outer ClientHello SNI is rewritten to config.public_name so the
// server’s identity is concealed from passive observers.
//
std::vector<uint8_t> apply_ech(
    const std::vector<uint8_t>& client_hello,
    const ECHConfig& ech_config
) {
    // Basic structure validation
    if (client_hello.size() < 44) return client_hello;
    if (client_hello[0] != 0x16) return client_hello; // must be TLS Handshake
    if (client_hello[5] != 0x01) return client_hello; // must be ClientHello

    // Initialise ECHClientContext (libsodium-based)
    ECHClientContext ctx;
    if (!ctx.init(ech_config)) {
        // Key size mismatch or uninitialised config — return unmodified
        return client_hello;
    }

    std::vector<uint8_t> enc, encrypted_payload;
    // Use the full outer CH (unmodified) as AAD
    const std::vector<uint8_t>& outer_aad = client_hello;

    if (!ctx.encrypt(client_hello, outer_aad, enc, encrypted_payload)) {
        return client_hello;
    }

    // Build the NCP-sodium ECH extension payload
    // Format (see file-level comment):
    //   type(1)=0x01  +  kdf(2)=0x0001  +  aead(2)=0x0003  +  config_id(1)
    //   +  enc_len(2) + enc(32)
    //   +  payload_len(2) + payload(nonce+ciphertext)
    std::vector<uint8_t> ech_payload;
    ech_payload.reserve(1 + 4 + 1 + 2 + enc.size() + 2 + encrypted_payload.size());

    ech_payload.push_back(0x01);          // type = NCP-sodium variant
    ech_payload.push_back(0x00); ech_payload.push_back(0x01); // KDF = HKDF-SHA256
    ech_payload.push_back(0x00); ech_payload.push_back(0x03); // AEAD = ChaCha20Poly1305
    ech_payload.push_back(ctx.get_config_id());

    // enc (ephemeral public key)
    ech_payload.push_back(static_cast<uint8_t>(enc.size() >> 8));
    ech_payload.push_back(static_cast<uint8_t>(enc.size() & 0xFF));
    ech_payload.insert(ech_payload.end(), enc.begin(), enc.end());

    // payload (nonce + ciphertext)
    ech_payload.push_back(static_cast<uint8_t>(encrypted_payload.size() >> 8));
    ech_payload.push_back(static_cast<uint8_t>(encrypted_payload.size() & 0xFF));
    ech_payload.insert(ech_payload.end(),
                       encrypted_payload.begin(), encrypted_payload.end());

    // Wrap as TLS extension type 0xfe0d
    std::vector<uint8_t> ech_ext;
    ech_ext.reserve(4 + ech_payload.size());
    ech_ext.push_back(0xfe);
    ech_ext.push_back(0x0d);
    uint16_t payload_len_field = static_cast<uint16_t>(ech_payload.size());
    ech_ext.push_back(static_cast<uint8_t>(payload_len_field >> 8));
    ech_ext.push_back(static_cast<uint8_t>(payload_len_field & 0xFF));
    ech_ext.insert(ech_ext.end(), ech_payload.begin(), ech_payload.end());

    // Find the extensions block to know where to insert
    // We parse manually since find_extensions_block is defined only in the
    // HAVE_OPENSSL block.  Minimal re-implementation:
    size_t pos = 9; // skip record(5) + handshake type(1) + hs length(3)
    auto bounds_ok = [&](size_t n) { return pos + n <= client_hello.size(); };
    if (!bounds_ok(2)) return client_hello;
    pos += 2; // ClientVersion
    if (!bounds_ok(32)) return client_hello;
    pos += 32; // Random
    if (!bounds_ok(1)) return client_hello;
    uint8_t sid_len = client_hello[pos++];
    if (!bounds_ok(sid_len + 2)) return client_hello;
    pos += sid_len;
    uint16_t cs_len2 = (static_cast<uint16_t>(client_hello[pos]) << 8) |
                        client_hello[pos + 1];
    pos += 2 + cs_len2;
    if (!bounds_ok(1)) return client_hello;
    uint8_t comp_len = client_hello[pos++];
    pos += comp_len;
    if (!bounds_ok(2)) return client_hello;

    size_t ext_len_offset = pos; // position of the 2-byte extensions_length field
    uint16_t old_exts_len = (static_cast<uint16_t>(client_hello[pos]) << 8) |
                             client_hello[pos + 1];
    pos += 2;
    size_t ext_end = pos + old_exts_len;
    if (ext_end > client_hello.size()) ext_end = client_hello.size();

    uint16_t ech_ext_total = static_cast<uint16_t>(ech_ext.size());

    // Build result: insert ECH extension at ext_end
    std::vector<uint8_t> result = client_hello;
    result.insert(result.begin() + ext_end, ech_ext.begin(), ech_ext.end());

    // Patch extensions_length
    uint16_t new_exts_len = static_cast<uint16_t>(old_exts_len + ech_ext_total);
    result[ext_len_offset]     = static_cast<uint8_t>(new_exts_len >> 8);
    result[ext_len_offset + 1] = static_cast<uint8_t>(new_exts_len & 0xFF);

    // Patch Handshake length (3 bytes at offsets 6..8)
    uint32_t old_hs_len = (static_cast<uint32_t>(result[6]) << 16) |
                          (static_cast<uint32_t>(result[7]) << 8) |
                           static_cast<uint32_t>(result[8]);
    uint32_t new_hs_len = old_hs_len + ech_ext_total;
    result[6] = static_cast<uint8_t>((new_hs_len >> 16) & 0xFF);
    result[7] = static_cast<uint8_t>((new_hs_len >> 8)  & 0xFF);
    result[8] = static_cast<uint8_t>( new_hs_len        & 0xFF);

    // Patch TLS record length (2 bytes at offsets 3..4)
    uint16_t old_rec_len = (static_cast<uint16_t>(result[3]) << 8) |
                            static_cast<uint16_t>(result[4]);
    uint16_t new_rec_len = static_cast<uint16_t>(old_rec_len + ech_ext_total);
    result[3] = static_cast<uint8_t>(new_rec_len >> 8);
    result[4] = static_cast<uint8_t>(new_rec_len & 0xFF);

    // R7-10: Replace SNI in outer ClientHello with public_name to hide server identity
    if (!ech_config.public_name.empty()) {
        // Parse and replace SNI extension (type 0x0000)
        size_t sni_pos = 9; // start of ClientHello body
        if (result.size() >= 44 && result[0] == 0x16 && result[5] == 0x01) {
            // Skip version(2) + random(32)
            sni_pos += 34;
            if (sni_pos < result.size()) {
                uint8_t sid_len = result[sni_pos++];
                sni_pos += sid_len;
                // cipher_suites
                if (sni_pos + 2 < result.size()) {
                    uint16_t cs_len = (static_cast<uint16_t>(result[sni_pos]) << 8) | result[sni_pos + 1];
                    sni_pos += 2 + cs_len;
                    // compression
                    if (sni_pos < result.size()) {
                        uint8_t cm_len = result[sni_pos++];
                        sni_pos += cm_len;
                        // extensions
                        if (sni_pos + 2 < result.size()) {
                            uint16_t exts_len = (static_cast<uint16_t>(result[sni_pos]) << 8) | result[sni_pos + 1];
                            sni_pos += 2;
                            size_t exts_end = sni_pos + exts_len;
                            // Find SNI extension
                            while (sni_pos + 4 <= exts_end) {
                                uint16_t ext_type = (static_cast<uint16_t>(result[sni_pos]) << 8) | result[sni_pos + 1];
                                uint16_t ext_dlen = (static_cast<uint16_t>(result[sni_pos + 2]) << 8) | result[sni_pos + 3];
                                if (ext_type == 0x0000) {
                                    // Found SNI extension
                                    size_t sni_data_off = sni_pos + 4;
                                    if (sni_data_off + 5 < result.size()) {
                                        uint16_t old_name_len = (static_cast<uint16_t>(result[sni_data_off + 3]) << 8) | result[sni_data_off + 4];
                                        size_t old_name_start = sni_data_off + 5;
                                        if (old_name_start + old_name_len <= result.size()) {
                                            int delta = static_cast<int>(ech_config.public_name.size()) - static_cast<int>(old_name_len);
                                            // Replace name bytes
                                            result.erase(result.begin() + old_name_start, result.begin() + old_name_start + old_name_len);
                                            result.insert(result.begin() + old_name_start, ech_config.public_name.begin(), ech_config.public_name.end());
                                            // Update name_len field
                                            uint16_t new_nl = static_cast<uint16_t>(ech_config.public_name.size());
                                            result[sni_data_off + 3] = (new_nl >> 8) & 0xFF;
                                            result[sni_data_off + 4] = new_nl & 0xFF;
                                            // Update sni_list_len
                                            uint16_t new_list_len = static_cast<uint16_t>(3 + ech_config.public_name.size());
                                            result[sni_data_off] = (new_list_len >> 8) & 0xFF;
                                            result[sni_data_off + 1] = new_list_len & 0xFF;
                                            // Update ext_data_len
                                            uint16_t new_ext_dlen = static_cast<uint16_t>(2 + 3 + ech_config.public_name.size());
                                            result[sni_pos + 2] = (new_ext_dlen >> 8) & 0xFF;
                                            result[sni_pos + 3] = new_ext_dlen & 0xFF;
                                            // Update extensions_len
                                            uint16_t new_exts_len = static_cast<uint16_t>(static_cast<int>(exts_len) + delta);
                                            result[sni_pos - 2] = (new_exts_len >> 8) & 0xFF;
                                            result[sni_pos - 1] = new_exts_len & 0xFF;
                                            // Update Handshake body length
                                            size_t hs_body_off = 6;
                                            uint32_t hs_body = (static_cast<uint32_t>(result[hs_body_off]) << 16) | (static_cast<uint32_t>(result[hs_body_off + 1]) << 8) | result[hs_body_off + 2];
                                            uint32_t new_hs_body = static_cast<uint32_t>(static_cast<int>(hs_body) + delta);
                                            result[hs_body_off] = (new_hs_body >> 16) & 0xFF;
                                            result[hs_body_off + 1] = (new_hs_body >> 8) & 0xFF;
                                            result[hs_body_off + 2] = new_hs_body & 0xFF;
                                            // Update record length
                                            uint16_t rec_len_off = 3;
                                            uint16_t rec_len_val = (static_cast<uint16_t>(result[rec_len_off]) << 8) | result[rec_len_off + 1];
                                            uint16_t new_rec_len_val = static_cast<uint16_t>(static_cast<int>(rec_len_val) + delta);
                                            result[rec_len_off] = (new_rec_len_val >> 8) & 0xFF;
                                            result[rec_len_off + 1] = new_rec_len_val & 0xFF;
                                        }
                                    }
                                    break;
                                }
                                sni_pos += 4 + ext_dlen;
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}

#endif // HAVE_OPENSSL

} // namespace ECH
} // namespace DPI
} // namespace ncp
