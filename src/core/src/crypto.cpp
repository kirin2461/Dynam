/**
 * @file crypto.cpp
 * @brief Cryptographic operations for NCP
 * @note Requires libsodium when HAVE_SODIUM is defined
 */

#include "../include/ncp_crypto.hpp"
#include <stdexcept>
#include <cstring>
#include <random>
#include <algorithm>

#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

namespace NCP {

Crypto::Crypto() {
    init_libsodium();
}

void Crypto::init_libsodium() {
#ifdef HAVE_SODIUM
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
#endif
}

Crypto::KeyPair Crypto::generate_keypair() {
    KeyPair kp;
#ifdef HAVE_SODIUM
    kp.public_key.resize(crypto_sign_PUBLICKEYBYTES);
    kp.secret_key.resize(crypto_sign_SECRETKEYBYTES);
    if (crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("Failed to generate keypair");
    }
#else
    // Fallback: generate random keys (NOT cryptographically secure!)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    kp.public_key.resize(32);
    kp.secret_key.resize(64);
    
    for (auto& b : kp.public_key) b = static_cast<uint8_t>(dis(gen));
    for (auto& b : kp.secret_key) b = static_cast<uint8_t>(dis(gen));
#endif
    return kp;
}

std::vector<uint8_t> Crypto::generate_random(size_t size) {
    std::vector<uint8_t> result(size);
#ifdef HAVE_SODIUM
    randombytes_buf(result.data(), size);
#else
    // Fallback: use std::random_device (may not be cryptographically secure)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (auto& b : result) {
        b = static_cast<uint8_t>(dis(gen));
    }
#endif
    return result;
}

std::vector<uint8_t> Crypto::encrypt_chacha20(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key) {
    
#ifdef HAVE_SODIUM
    if (key.size() != crypto_secretbox_KEYBYTES) {
        throw std::runtime_error("Invalid key size for ChaCha20");
    }
    
    // Generate random nonce
    std::vector<uint8_t> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    
    // Ciphertext will be: nonce + encrypted_data + auth_tag
    std::vector<uint8_t> ciphertext(crypto_secretbox_NONCEBYTES + plaintext.size() + crypto_secretbox_MACBYTES);
    
    // Copy nonce to beginning of ciphertext
    std::memcpy(ciphertext.data(), nonce.data(), nonce.size());
    
    // Encrypt
    if (crypto_secretbox_easy(
            ciphertext.data() + crypto_secretbox_NONCEBYTES,
            plaintext.data(),
            plaintext.size(),
            nonce.data(),
            key.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }
    
    return ciphertext;
#else
    // Fallback: simple XOR (NOT secure!)
    std::vector<uint8_t> result = plaintext;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
#endif
}

std::vector<uint8_t> Crypto::decrypt_chacha20(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key) {
    
#ifdef HAVE_SODIUM
    if (key.size() != crypto_secretbox_KEYBYTES) {
        return {}; // Return empty vector on invalid key size
    }
    
    if (ciphertext.size() < crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        return {}; // Return empty vector on ciphertext too short
    }
    
    // Extract nonce from beginning
    const unsigned char* nonce = ciphertext.data();
    const unsigned char* encrypted = ciphertext.data() + crypto_secretbox_NONCEBYTES;
    size_t encrypted_len = ciphertext.size() - crypto_secretbox_NONCEBYTES;
    
    std::vector<uint8_t> plaintext(encrypted_len - crypto_secretbox_MACBYTES);
    
    if (crypto_secretbox_open_easy(
            plaintext.data(),
            encrypted,
            encrypted_len,
            nonce,
            key.data()) != 0) {
        return {}; // Return empty vector on authentication failure
    }
    
    return plaintext;
#else
    // Fallback: simple XOR (NOT secure!)
    std::vector<uint8_t> result = ciphertext;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
#endif
}

std::vector<uint8_t> Crypto::sign_message(
    const std::string& message,
    const std::vector<uint8_t>& secret_key) {
    
#ifdef HAVE_SODIUM
    std::vector<uint8_t> signature(crypto_sign_BYTES);
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(signature.data(), &sig_len,
            reinterpret_cast<const unsigned char*>(message.data()),
            message.size(), secret_key.data()) != 0) {
        throw std::runtime_error("Failed to sign message");
    }
    signature.resize(sig_len);
    return signature;
#else
    // Fallback: simple hash-based signature (NOT secure!)
    std::vector<uint8_t> signature(64);
    std::hash<std::string> hasher;
    size_t hash = hasher(message);
    std::memcpy(signature.data(), &hash, sizeof(hash));
    return signature;
#endif
}

bool Crypto::verify_signature(
    const std::string& message,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key) {
    
#ifdef HAVE_SODIUM
    return crypto_sign_verify_detached(
        signature.data(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        public_key.data()) == 0;
#else
    // Fallback: always return true (NOT secure!)
    return true;
#endif
}

std::vector<uint8_t> Crypto::hash_sha256(const std::string& data) {
#ifdef HAVE_SODIUM
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size());
    return hash;
#else
    // Fallback: simple hash (NOT cryptographically secure!)
    std::vector<uint8_t> hash(32);
    std::hash<std::string> hasher;
    size_t h = hasher(data);
    std::memcpy(hash.data(), &h, sizeof(h));
    return hash;
#endif
}

std::vector<uint8_t> Crypto::hash_sha256(const std::vector<uint8_t>& data) {
#ifdef HAVE_SODIUM
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
#else
    std::vector<uint8_t> hash(32);
    size_t h = 0;
    for (auto b : data) h = h * 31 + b;
    std::memcpy(hash.data(), &h, sizeof(h));
    return hash;
#endif
}

std::string Crypto::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

std::vector<uint8_t> Crypto::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            byte <<= 4;
            if (c >= '0' && c <= '9') byte |= (c - '0');
            else if (c >= 'a' && c <= 'f') byte |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') byte |= (c - 'A' + 10);
        }
        bytes.push_back(byte);
    }
    return bytes;
}

} // namespace NCP
