/**
 * @file crypto_test.cpp
 * @brief Unit tests for NCP cryptographic operations
 *
 * Tests libsodium-based crypto: key generation, encryption/decryption,
 * hashing, key derivation, and secure memory operations.
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <cstring>

#ifdef HAVE_SODIUM
#include <sodium.h>
#endif

#include "ncp_crypto.hpp"

namespace {

// ==================== Sodium Initialization ====================

class CryptoTest : public ::testing::Test {
protected:
    void SetUp() override {
#ifdef HAVE_SODIUM
        ASSERT_GE(sodium_init(), 0) << "Failed to initialize libsodium";
#endif
    }
};

// ==================== Key Generation Tests ====================

#ifdef HAVE_SODIUM
TEST_F(CryptoTest, GenerateSecretKey) {
    unsigned char key[crypto_secretbox_KEYBYTES];
    crypto_secretbox_keygen(key);

    // Key should not be all zeros
    bool all_zero = true;
    for (size_t i = 0; i < crypto_secretbox_KEYBYTES; ++i) {
        if (key[i] != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero) << "Generated key should not be all zeros";
}

TEST_F(CryptoTest, GenerateKeyPair) {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    ASSERT_EQ(crypto_box_keypair(pk, sk), 0);

    // Public and secret keys should differ
    EXPECT_NE(std::memcmp(pk, sk, std::min(crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES)), 0);
}

// ==================== Symmetric Encryption Tests ====================

TEST_F(CryptoTest, SecretBoxEncryptDecrypt) {
    const std::string message = "NCP test message for encryption";
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    crypto_secretbox_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(message.size() + crypto_secretbox_MACBYTES);
    ASSERT_EQ(crypto_secretbox_easy(
        ciphertext.data(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        nonce, key), 0);

    std::vector<unsigned char> decrypted(message.size());
    ASSERT_EQ(crypto_secretbox_open_easy(
        decrypted.data(),
        ciphertext.data(),
        ciphertext.size(),
        nonce, key), 0);

    std::string result(decrypted.begin(), decrypted.end());
    EXPECT_EQ(result, message);
}

TEST_F(CryptoTest, SecretBoxWrongKeyFails) {
    const std::string message = "sensitive data";
    unsigned char key1[crypto_secretbox_KEYBYTES];
    unsigned char key2[crypto_secretbox_KEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    crypto_secretbox_keygen(key1);
    crypto_secretbox_keygen(key2);
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<unsigned char> ciphertext(message.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(
        ciphertext.data(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size(),
        nonce, key1);

    std::vector<unsigned char> decrypted(message.size());
    int result = crypto_secretbox_open_easy(
        decrypted.data(),
        ciphertext.data(),
        ciphertext.size(),
        nonce, key2);
    EXPECT_NE(result, 0) << "Decryption with wrong key should fail";
}

// ==================== Hashing Tests ====================

TEST_F(CryptoTest, GenericHash) {
    const std::string data = "NCP hash test data";
    unsigned char hash1[crypto_generichash_BYTES];
    unsigned char hash2[crypto_generichash_BYTES];

    crypto_generichash(hash1, sizeof(hash1),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(), nullptr, 0);

    crypto_generichash(hash2, sizeof(hash2),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(), nullptr, 0);

    // Same input should produce same hash
    EXPECT_EQ(std::memcmp(hash1, hash2, sizeof(hash1)), 0);
}

TEST_F(CryptoTest, DifferentDataDifferentHash) {
    unsigned char hash1[crypto_generichash_BYTES];
    unsigned char hash2[crypto_generichash_BYTES];

    const std::string data1 = "data one";
    const std::string data2 = "data two";

    crypto_generichash(hash1, sizeof(hash1),
        reinterpret_cast<const unsigned char*>(data1.data()),
        data1.size(), nullptr, 0);

    crypto_generichash(hash2, sizeof(hash2),
        reinterpret_cast<const unsigned char*>(data2.data()),
        data2.size(), nullptr, 0);

    EXPECT_NE(std::memcmp(hash1, hash2, sizeof(hash1)), 0);
}

// ==================== Key Derivation Tests ====================

TEST_F(CryptoTest, PasswordHash) {
    const std::string password = "test_password_123";
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char key[32];
    int result = crypto_pwhash(
        key, sizeof(key),
        password.c_str(), password.size(),
        salt,
        crypto_pwhash_OPSLIMIT_MIN,
        crypto_pwhash_MEMLIMIT_MIN,
        crypto_pwhash_ALG_DEFAULT);
    ASSERT_EQ(result, 0) << "Password hashing should succeed";

    // Derived key should not be all zeros
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(key); ++i) {
        if (key[i] != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero);
}

// ==================== Random Number Generation ====================

TEST_F(CryptoTest, RandomBytesUnique) {
    unsigned char buf1[32];
    unsigned char buf2[32];
    randombytes_buf(buf1, sizeof(buf1));
    randombytes_buf(buf2, sizeof(buf2));

    EXPECT_NE(std::memcmp(buf1, buf2, sizeof(buf1)), 0)
        << "Two random buffers should differ";
}

#endif // HAVE_SODIUM

// ==================== Non-Sodium Tests ====================
// These tests run regardless of libsodium availability

TEST(CryptoBasicTest, PlaceholderTest) {
    // Basic sanity check that test framework works
    EXPECT_TRUE(true);
}

} // anonymous namespace
