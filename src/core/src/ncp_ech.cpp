/**
 * @file ncp_ech.cpp
 * @brief Encrypted Client Hello (ECH) implementation using HPKE
 */

#include "../include/ncp_ech.hpp"
#include <string>
#include <algorithm>
#include <cstring>

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
