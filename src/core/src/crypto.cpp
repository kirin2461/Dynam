/**
 * @file crypto.cpp
 * @brief Cryptographic operations for NCP with SecureMemory
 * @note libsodium is REQUIRED - no fallback implementations
 */

#include "../include/ncp_crypto.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <stdexcept>
#include <cstring>

// libsodium is required - no fallback implementations allowed
#ifndef HAVE_SODIUM
#error "libsodium is required for cryptographic operations. Please install libsodium and rebuild with -DHAVE_SODIUM=ON"
#endif

#include <sodium.h>

// Post-quantum signature support via liboqs
#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

Crypto::Crypto() {
    init_libsodium();
}

void Crypto::init_libsodium() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

Crypto::KeyPair Crypto::generate_keypair() {
    KeyPair kp;
    kp.public_key = SecureMemory(crypto_sign_PUBLICKEYBYTES);
    kp.secret_key = SecureMemory(crypto_sign_SECRETKEYBYTES);
    
    if (crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("Failed to generate keypair");
    }
    
    return kp;
}

SecureMemory Crypto::generate_random(size_t size) {
    SecureMemory result(size);
    randombytes_buf(result.data(), size);
    return result;
}

// ==================== ChaCha20-Poly1305 IETF (RFC 8439) ====================
// FIX #63: Previously used crypto_secretbox_easy() which is XSalsa20-Poly1305.
// Now uses crypto_aead_chacha20poly1305_ietf — actual ChaCha20-Poly1305.
//
// Encryption always produces new format:
//   Wire format: [nonce:12][ciphertext + Poly1305 tag:N+16]
//
// Decryption supports BOTH formats for backward compatibility:
//   - Legacy:  [nonce:24][ciphertext + Poly1305 tag:N+16]  (XSalsa20, crypto_secretbox)
//   - New:     [nonce:12][ciphertext + Poly1305 tag:N+16]  (ChaCha20 IETF)
// Detection is automatic based on ciphertext size heuristics.

// --- Constants ---
static constexpr size_t CHACHA20_NONCE_LEN = crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // 12
static constexpr size_t CHACHA20_TAG_LEN   = crypto_aead_chacha20poly1305_ietf_ABYTES;    // 16
static constexpr size_t XSALSA20_NONCE_LEN = crypto_secretbox_NONCEBYTES;                 // 24
static constexpr size_t XSALSA20_TAG_LEN   = crypto_secretbox_MACBYTES;                   // 16

SecureMemory Crypto::encrypt_chacha20(
    const SecureMemory& plaintext,
    const SecureMemory& key
) {
    if (key.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid key size for ChaCha20-Poly1305 (expected 32 bytes)");
    }
    
    SecureMemory nonce(CHACHA20_NONCE_LEN);
    randombytes_buf(nonce.data(), CHACHA20_NONCE_LEN);
    
    SecureMemory ciphertext(CHACHA20_NONCE_LEN + plaintext.size() + CHACHA20_TAG_LEN);
    std::memcpy(ciphertext.data(), nonce.data(), CHACHA20_NONCE_LEN);
    
    unsigned long long ciphertext_len = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data() + CHACHA20_NONCE_LEN,
            &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0,
            nullptr,
            nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("ChaCha20-Poly1305 encryption failed");
    }
    
    return ciphertext;
}

// Legacy XSalsa20-Poly1305 decryption (for old data)
static SecureMemory decrypt_legacy_xsalsa20(
    const SecureMemory& ciphertext,
    const SecureMemory& key
) {
    const uint8_t* nonce = ciphertext.data();
    const uint8_t* encrypted_data = ciphertext.data() + XSALSA20_NONCE_LEN;
    size_t encrypted_len = ciphertext.size() - XSALSA20_NONCE_LEN;
    
    SecureMemory plaintext(encrypted_len - XSALSA20_TAG_LEN);
    
    if (crypto_secretbox_open_easy(
            plaintext.data(),
            encrypted_data, encrypted_len,
            nonce, key.data()) != 0) {
        throw std::runtime_error("Legacy XSalsa20 decryption failed or authentication failed");
    }
    
    return plaintext;
}

// New ChaCha20-Poly1305 IETF decryption
static SecureMemory decrypt_chacha20_ietf(
    const SecureMemory& ciphertext,
    const SecureMemory& key
) {
    const uint8_t* nonce = ciphertext.data();
    const uint8_t* encrypted_data = ciphertext.data() + CHACHA20_NONCE_LEN;
    size_t encrypted_len = ciphertext.size() - CHACHA20_NONCE_LEN;
    
    SecureMemory plaintext(encrypted_len - CHACHA20_TAG_LEN);
    unsigned long long plaintext_len = 0;
    
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintext_len,
            nullptr,
            encrypted_data, encrypted_len,
            nullptr, 0,
            nonce,
            key.data()) != 0) {
        throw std::runtime_error("ChaCha20-Poly1305 decryption failed or authentication failed");
    }
    
    return plaintext;
}

SecureMemory Crypto::decrypt_chacha20(
    const SecureMemory& ciphertext,
    const SecureMemory& key
) {
    if (key.size() != 32) {
        throw std::runtime_error("Invalid key size for ChaCha20-Poly1305 (expected 32 bytes)");
    }
    
    // Minimum sizes:
    //   New format (ChaCha20 IETF): 12 (nonce) + 16 (tag) = 28
    //   Legacy format (XSalsa20):   24 (nonce) + 16 (tag) = 40
    if (ciphertext.size() < CHACHA20_NONCE_LEN + CHACHA20_TAG_LEN) {
        throw std::runtime_error("Ciphertext too short");
    }
    
    // Auto-detect format: try new ChaCha20 IETF first, fall back to legacy XSalsa20.
    //
    // Rationale: both formats have the same key size (32) and tag size (16),
    // differing only in nonce length (12 vs 24). Since AEAD auth will fail
    // if the wrong algorithm is used, we can safely try-and-fallback.
    // New format is tried first since all new encryptions use it.
    
    try {
        return decrypt_chacha20_ietf(ciphertext, key);
    } catch (const std::runtime_error&) {
        // New format failed — try legacy XSalsa20 if ciphertext is large enough
        if (ciphertext.size() >= XSALSA20_NONCE_LEN + XSALSA20_TAG_LEN) {
            try {
                return decrypt_legacy_xsalsa20(ciphertext, key);
            } catch (const std::runtime_error&) {
                // Both failed — throw with informative message
            }
        }
        throw std::runtime_error(
            "Decryption failed: ciphertext is not valid ChaCha20-Poly1305 IETF "
            "or legacy XSalsa20-Poly1305 format");
    }
}

SecureMemory Crypto::hash_sha256(const SecureMemory& data) {
    SecureMemory hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
}

SecureMemory Crypto::hash_sha512(const SecureMemory& data) {
    SecureMemory hash(crypto_hash_sha512_BYTES);
    crypto_hash_sha512(hash.data(), data.data(), data.size());
    return hash;
}

SecureMemory Crypto::hash_blake2b(const SecureMemory& data, size_t output_len) {
    if (output_len < crypto_generichash_BYTES_MIN || output_len > crypto_generichash_BYTES_MAX) {
        throw std::runtime_error("Invalid BLAKE2b output length");
    }
    
    SecureMemory hash(output_len);
    if (crypto_generichash(hash.data(), output_len, data.data(), data.size(), nullptr, 0) != 0) {
        throw std::runtime_error("BLAKE2b hashing failed");
    }
    
    return hash;
}

SecureMemory Crypto::sign_ed25519(
    const SecureMemory& message,
    const SecureMemory& secret_key
) {
    if (secret_key.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error("Invalid Ed25519 secret key size");
    }
    
    SecureMemory signature(crypto_sign_BYTES);
    
    if (crypto_sign_detached(signature.data(), nullptr,
                            message.data(), message.size(),
                            secret_key.data()) != 0) {
        throw std::runtime_error("Ed25519 signing failed");
    }
    
    return signature;
}

bool Crypto::verify_ed25519(
    const SecureMemory& message,
    const SecureMemory& signature,
    const SecureMemory& public_key
) {
    if (signature.size() != crypto_sign_BYTES) {
        return false;
    }
    
    if (public_key.size() != crypto_sign_PUBLICKEYBYTES) {
        return false;
    }
    
    return crypto_sign_verify_detached(
        signature.data(),
        message.data(), message.size(),
        public_key.data()) == 0;
}

#ifdef HAVE_LIBOQS

Crypto::KeyPair Crypto::generate_dilithium_keypair() {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        throw std::runtime_error("Failed to initialize Dilithium5");
    }
    
    KeyPair kp;
    kp.public_key = SecureMemory(sig->length_public_key);
    kp.secret_key = SecureMemory(sig->length_secret_key);
    
    if (OQS_SIG_keypair(sig, kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("Failed to generate Dilithium keypair");
    }
    
    OQS_SIG_free(sig);
    return kp;
}

SecureMemory Crypto::sign_dilithium(
    const SecureMemory& message,
    const SecureMemory& secret_key
) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        throw std::runtime_error("Failed to initialize Dilithium5");
    }
    
    if (secret_key.size() != sig->length_secret_key) {
        OQS_SIG_free(sig);
        throw std::runtime_error("Invalid Dilithium secret key size");
    }
    
    SecureMemory signature(sig->length_signature);
    size_t signature_len;
    
    if (OQS_SIG_sign(sig, signature.data(), &signature_len,
                     message.data(), message.size(),
                     secret_key.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("Dilithium signing failed");
    }
    
    OQS_SIG_free(sig);
    signature.resize(signature_len);
    return signature;
}

bool Crypto::verify_dilithium(
    const SecureMemory& message,
    const SecureMemory& signature,
    const SecureMemory& public_key
) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_5);
    if (!sig) {
        return false;
    }
    
    if (public_key.size() != sig->length_public_key) {
        OQS_SIG_free(sig);
        return false;
    }
    
    OQS_STATUS result = OQS_SIG_verify(sig,
                                       message.data(), message.size(),
                                       signature.data(), signature.size(),
                                       public_key.data());
    
    OQS_SIG_free(sig);
    return result == OQS_SUCCESS;
}

#else

// Fallback: throw exceptions when liboqs is not available
Crypto::KeyPair Crypto::generate_dilithium_keypair() {
    throw std::runtime_error("Dilithium not available: liboqs required");
}

SecureMemory Crypto::sign_dilithium(
    const SecureMemory& /*message*/,
    const SecureMemory& /*secret_key*/
) {
    throw std::runtime_error("Dilithium not available: liboqs required");
}

bool Crypto::verify_dilithium(
    const SecureMemory& /*message*/,
    const SecureMemory& /*signature*/,
    const SecureMemory& /*public_key*/
) {
    throw std::runtime_error("Dilithium not available: liboqs required");
}

#endif // HAVE_LIBOQS

// ==================== AEAD Encryption (XChaCha20-Poly1305) ====================

SecureMemory Crypto::encrypt_aead(
    const SecureMemory& plaintext,
    const SecureMemory& key,
    const SecureMemory& additional_data
) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid key size for XChaCha20-Poly1305 AEAD");
    }

    // Generate random nonce
    SecureMemory nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // Ciphertext will be: nonce + encrypted_data + auth_tag
    size_t ciphertext_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
                            plaintext.size() + 
                            crypto_aead_xchacha20poly1305_ietf_ABYTES;
    SecureMemory ciphertext(ciphertext_len);

    // Copy nonce to beginning
    std::memcpy(ciphertext.data(), nonce.data(), nonce.size());

    // Encrypt with AEAD
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
            &actual_ciphertext_len,
            plaintext.data(),
            plaintext.size(),
            additional_data.size() > 0 ? additional_data.data() : nullptr,
            additional_data.size(),
            nullptr,  // nsec (not used)
            nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("AEAD encryption failed");
    }

    return ciphertext;
}

SecureMemory Crypto::decrypt_aead(
    const SecureMemory& ciphertext,
    const SecureMemory& key,
    const SecureMemory& additional_data
) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid key size for XChaCha20-Poly1305 AEAD");
    }

    size_t min_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 
                      crypto_aead_xchacha20poly1305_ietf_ABYTES;
    if (ciphertext.size() < min_size) {
        throw std::runtime_error("Ciphertext too short for AEAD decryption");
    }

    // Extract nonce from beginning
    const uint8_t* nonce = ciphertext.data();
    const uint8_t* encrypted_data = ciphertext.data() + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    size_t encrypted_len = ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    // Decrypt
    SecureMemory plaintext(encrypted_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long actual_plaintext_len;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &actual_plaintext_len,
            nullptr,  // nsec (not used)
            encrypted_data,
            encrypted_len,
            additional_data.size() > 0 ? additional_data.data() : nullptr,
            additional_data.size(),
            nonce,
            key.data()) != 0) {
        throw std::runtime_error("AEAD decryption failed or authentication failed");
    }

    return plaintext;
}

} // namespace ncp
