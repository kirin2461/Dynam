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

SecureMemory Crypto::encrypt_chacha20(
    const SecureMemory& plaintext,
    const SecureMemory& key
) {
    if (key.size() != crypto_secretbox_KEYBYTES) {
        throw std::runtime_error("Invalid key size for ChaCha20");
    }
    
    // Generate random nonce
    SecureMemory nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Ciphertext will be: nonce + encrypted_data + auth_tag
    SecureMemory ciphertext(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + plaintext.size());
    
    // Copy nonce to beginning
    std::memcpy(ciphertext.data(), nonce.data(), nonce.size());
    
    // Encrypt
    if (crypto_secretbox_easy(
            ciphertext.data() + crypto_secretbox_NONCEBYTES,
            plaintext.data(), plaintext.size(),
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }
    
    return ciphertext;
}

 SecureMemory Crypto::decrypt_chacha20(
    const SecureMemory& ciphertext,
    const SecureMemory& key
) {
    if (key.size() != crypto_secretbox_KEYBYTES) {
        throw std::runtime_error("Invalid key size for ChaCha20");
    }
    
    if (ciphertext.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Ciphertext too short");
    }
    
    // Extract nonce
    const uint8_t* nonce = ciphertext.data();
    const uint8_t* encrypted_data = ciphertext.data() + crypto_secretbox_NONCEBYTES;
    size_t encrypted_len = ciphertext.size() - crypto_secretbox_NONCEBYTES;
    
    // Decrypt
     plaintext(encrypted_len - crypto_secretbox_MACBYTES);
    
    if (crypto_secretbox_open_easy(
            plaintext.data(),
                SecureMemory encrypted_data, encrypted_len,
            nonce, key.data()) != 0) {
        throw std::runtime_error("Decryption failed or authentication failed");
    }
    
    return plaintext;
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

} // namespace ncp
