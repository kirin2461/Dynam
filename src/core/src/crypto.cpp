/**
 * @file crypto.cpp
 * @brief Cryptographic operations for NCP
 * @note libsodium is REQUIRED - no fallback implementations
 */

#include "../include/ncp_crypto.hpp"
#include <stdexcept>
#include <cstring>

// libsodium is required - no fallback implementations allowed
#ifndef HAVE_SODIUM
#error "libsodium is required for cryptographic operations. Please install libsodium and rebuild with -DHAVE_SODIUM=ON"
#endif

#include <sodium.h>

namespace NCP {

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
    kp.public_key.resize(crypto_sign_PUBLICKEYBYTES);
    kp.secret_key.resize(crypto_sign_SECRETKEYBYTES);
    if (crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
        throw std::runtime_error("Failed to generate keypair");
    }
    return kp;
}

std::vector<uint8_t> Crypto::generate_random(size_t size) {
    std::vector<uint8_t> result(size);
    randombytes_buf(result.data(), size);
    return result;
}

std::vector<uint8_t> Crypto::encrypt_chacha20(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key) {
    
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
}

std::vector<uint8_t> Crypto::decrypt_chacha20(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key) {
    
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
}

std::vector<uint8_t> Crypto::sign_message(
    const std::string& message,
    const std::vector<uint8_t>& secret_key) {
    
    std::vector<uint8_t> signature(crypto_sign_BYTES);
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(signature.data(), &sig_len,
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(), secret_key.data()) != 0) {
        throw std::runtime_error("Failed to sign message");
    }
    signature.resize(sig_len);
    return signature;
}

bool Crypto::verify_signature(
    const std::string& message,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key) {
    
    return crypto_sign_verify_detached(
        signature.data(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        public_key.data()) == 0;
}

std::vector<uint8_t> Crypto::hash_sha256(const std::string& data) {
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size());
    return hash;
}

std::vector<uint8_t> Crypto::hash_sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
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
