#include <gtest/gtest.h>
#include "ncp_crypto.hpp"

using namespace NCP;

class CryptoTest : public ::testing::Test {
protected:
    Crypto crypto;
};

TEST_F(CryptoTest, GenerateKeypair) {
    auto kp = crypto.generate_keypair();
    
    EXPECT_EQ(kp.public_key.size(), 32);
    EXPECT_EQ(kp.secret_key.size(), 64);
    EXPECT_FALSE(kp.public_key.empty());
    EXPECT_FALSE(kp.secret_key.empty());
}

TEST_F(CryptoTest, GenerateRandomBytes) {
    auto random1 = crypto.generate_random(32);
    auto random2 = crypto.generate_random(32);
    
    EXPECT_EQ(random1.size(), 32);
    EXPECT_EQ(random2.size(), 32);
    // Random bytes should be different
    EXPECT_NE(random1, random2);
}

TEST_F(CryptoTest, SignAndVerifyMessage) {
    auto kp = crypto.generate_keypair();
    std::string message = "Test message";
    
    auto signature = crypto.sign_message(message, kp.secret_key);
    EXPECT_EQ(signature.size(), 64);
    
    bool valid = crypto.verify_signature(message, signature, kp.public_key);
    EXPECT_TRUE(valid);
}

TEST_F(CryptoTest, VerifyFailsWithModifiedMessage) {
    auto kp = crypto.generate_keypair();
    std::string message = "Test message";
    std::string modified_message = "Modified message";
    
    auto signature = crypto.sign_message(message, kp.secret_key);
    
    bool valid = crypto.verify_signature(modified_message, signature, kp.public_key);
    EXPECT_FALSE(valid);
}

TEST_F(CryptoTest, EncryptDecryptChaCha20) {
    auto key = crypto.generate_random(32);
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    
    auto ciphertext = crypto.encrypt_chacha20(plaintext, key);
    EXPECT_GT(ciphertext.size(), plaintext.size());
    
    auto decrypted = crypto.decrypt_chacha20(ciphertext, key);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(CryptoTest, DecryptWithWrongKeyFails) {
    auto key1 = crypto.generate_random(32);
    auto key2 = crypto.generate_random(32);
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    
    auto ciphertext = crypto.encrypt_chacha20(plaintext, key1);
    auto decrypted = crypto.decrypt_chacha20(ciphertext, key2);
    
    EXPECT_EQ(decrypted.size(), 0);  // Should fail and return empty vector
}
