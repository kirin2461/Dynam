/**
 * @file test_e2e_extended.cpp
 * @brief Extended unit tests for E2E encryption (X448, ECDH_P256)
 * @phase Phase 2.3 - X448/ECDH_P256 via OpenSSL
 */

#include <gtest/gtest.h>
#include "ncp_e2e.hpp"
#include <vector>
#include <string>
#include <cstring>

using namespace ncp;

class E2EExtendedTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Configs for each protocol
        x448_config.key_exchange = KeyExchangeProtocol::X448;
        p256_config.key_exchange = KeyExchangeProtocol::ECDH_P256;
    }
    
    E2EConfig x448_config;
    E2EConfig p256_config;
};

// ======================== X448 Key Generation Tests ========================

TEST_F(E2EExtendedTest, X448_KeyGeneration) {
    E2ESession session(x448_config);
    
    KeyPair keypair = session.generate_key_pair();
    
    // X448 keys should be 56 bytes
    EXPECT_EQ(keypair.public_key.size(), 56) << "X448 public key must be 56 bytes";
    EXPECT_EQ(keypair.private_key.size(), 56) << "X448 private key must be 56 bytes";
    EXPECT_EQ(keypair.protocol, KeyExchangeProtocol::X448);
}

TEST_F(E2EExtendedTest, X448_KeyPairUniqueness) {
    E2ESession session(x448_config);
    
    KeyPair keypair1 = session.generate_key_pair();
    KeyPair keypair2 = session.generate_key_pair();
    
    // Public keys must be different
    ASSERT_EQ(keypair1.public_key.size(), keypair2.public_key.size());
    bool keys_different = (std::memcmp(
        keypair1.public_key.data(),
        keypair2.public_key.data(),
        keypair1.public_key.size()) != 0);
    EXPECT_TRUE(keys_different) << "X448: Two generated key pairs must be unique";
}

TEST_F(E2EExtendedTest, X448_KeysNonZero) {
    E2ESession session(x448_config);
    KeyPair keypair = session.generate_key_pair();
    
    // Keys should not be all zeros
    bool public_nonzero = false;
    bool private_nonzero = false;
    
    for (size_t i = 0; i < keypair.public_key.size(); ++i) {
        if (keypair.public_key.data()[i] != 0) {
            public_nonzero = true;
            break;
        }
    }
    
    for (size_t i = 0; i < keypair.private_key.size(); ++i) {
        if (keypair.private_key.data()[i] != 0) {
            private_nonzero = true;
            break;
        }
    }
    
    EXPECT_TRUE(public_nonzero) << "X448 public key must not be all zeros";
    EXPECT_TRUE(private_nonzero) << "X448 private key must not be all zeros";
}

// ======================== ECDH_P256 Key Generation Tests ========================

TEST_F(E2EExtendedTest, ECDH_P256_KeyGeneration) {
    E2ESession session(p256_config);
    
    KeyPair keypair = session.generate_key_pair();
    
    // ECDH P-256 public key: 65 bytes (0x04 || X || Y)
    // ECDH P-256 private key: 32 bytes (scalar)
    EXPECT_EQ(keypair.public_key.size(), 65) << "ECDH P-256 public key must be 65 bytes (uncompressed point)";
    EXPECT_EQ(keypair.private_key.size(), 32) << "ECDH P-256 private key must be 32 bytes";
    EXPECT_EQ(keypair.protocol, KeyExchangeProtocol::ECDH_P256);
    
    // First byte of public key should be 0x04 (uncompressed point indicator)
    EXPECT_EQ(keypair.public_key.data()[0], 0x04) << "ECDH P-256 public key must start with 0x04";
}

TEST_F(E2EExtendedTest, ECDH_P256_KeyPairUniqueness) {
    E2ESession session(p256_config);
    
    KeyPair keypair1 = session.generate_key_pair();
    KeyPair keypair2 = session.generate_key_pair();
    
    // Public keys must be different
    ASSERT_EQ(keypair1.public_key.size(), keypair2.public_key.size());
    bool keys_different = (std::memcmp(
        keypair1.public_key.data(),
        keypair2.public_key.data(),
        keypair1.public_key.size()) != 0);
    EXPECT_TRUE(keys_different) << "ECDH P-256: Two generated key pairs must be unique";
}

TEST_F(E2EExtendedTest, ECDH_P256_KeysNonZero) {
    E2ESession session(p256_config);
    KeyPair keypair = session.generate_key_pair();
    
    // Check that keys are not all zeros (excluding first byte 0x04)
    bool public_nonzero = false;
    for (size_t i = 1; i < keypair.public_key.size(); ++i) {
        if (keypair.public_key.data()[i] != 0) {
            public_nonzero = true;
            break;
        }
    }
    
    bool private_nonzero = false;
    for (size_t i = 0; i < keypair.private_key.size(); ++i) {
        if (keypair.private_key.data()[i] != 0) {
            private_nonzero = true;
            break;
        }
    }
    
    EXPECT_TRUE(public_nonzero) << "ECDH P-256 public key must not be all zeros";
    EXPECT_TRUE(private_nonzero) << "ECDH P-256 private key must not be all zeros";
}

// ======================== X448 Shared Secret Tests ========================

TEST_F(E2EExtendedTest, X448_SharedSecretComputation) {
    E2ESession alice(x448_config);
    E2ESession bob(x448_config);
    
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    // Alice computes shared secret with Bob's public key
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory alice_secret = alice.compute_shared_secret(alice_keys, bob_public);
    
    // Bob computes shared secret with Alice's public key
    std::vector<uint8_t> alice_public(alice_keys.public_key.data(),
                                      alice_keys.public_key.data() + alice_keys.public_key.size());
    SecureMemory bob_secret = bob.compute_shared_secret(bob_keys, alice_public);
    
    // Both should arrive at the same shared secret (56 bytes for X448)
    ASSERT_EQ(alice_secret.size(), 56) << "X448 shared secret must be 56 bytes";
    ASSERT_EQ(bob_secret.size(), 56) << "X448 shared secret must be 56 bytes";
    ASSERT_EQ(alice_secret.size(), bob_secret.size());
    EXPECT_EQ(std::memcmp(alice_secret.data(), bob_secret.data(), alice_secret.size()), 0)
        << "X448: Alice and Bob must compute identical shared secrets";
}

TEST_F(E2EExtendedTest, X448_SharedSecretNonZero) {
    E2ESession alice(x448_config);
    E2ESession bob(x448_config);
    
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory alice_secret = alice.compute_shared_secret(alice_keys, bob_public);
    
    // Shared secret should not be all zeros
    bool nonzero = false;
    for (size_t i = 0; i < alice_secret.size(); ++i) {
        if (alice_secret.data()[i] != 0) {
            nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(nonzero) << "X448 shared secret must not be all zeros";
}

TEST_F(E2EExtendedTest, X448_InvalidKeySize) {
    E2ESession session(x448_config);
    KeyPair keypair = session.generate_key_pair();
    
    // Try to compute shared secret with wrong-sized public key
    std::vector<uint8_t> invalid_key(32);  // X25519 size instead of X448
    
    EXPECT_THROW({
        session.compute_shared_secret(keypair, invalid_key);
    }, std::exception) << "X448: Invalid key size (32 bytes) must throw";
}

// ======================== ECDH_P256 Shared Secret Tests ========================

TEST_F(E2EExtendedTest, ECDH_P256_SharedSecretComputation) {
    E2ESession alice(p256_config);
    E2ESession bob(p256_config);
    
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    // Alice computes shared secret with Bob's public key
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory alice_secret = alice.compute_shared_secret(alice_keys, bob_public);
    
    // Bob computes shared secret with Alice's public key
    std::vector<uint8_t> alice_public(alice_keys.public_key.data(),
                                      alice_keys.public_key.data() + alice_keys.public_key.size());
    SecureMemory bob_secret = bob.compute_shared_secret(bob_keys, alice_public);
    
    // Both should arrive at the same shared secret (32 bytes for ECDH P-256)
    ASSERT_EQ(alice_secret.size(), 32) << "ECDH P-256 shared secret must be 32 bytes";
    ASSERT_EQ(bob_secret.size(), 32) << "ECDH P-256 shared secret must be 32 bytes";
    ASSERT_EQ(alice_secret.size(), bob_secret.size());
    EXPECT_EQ(std::memcmp(alice_secret.data(), bob_secret.data(), alice_secret.size()), 0)
        << "ECDH P-256: Alice and Bob must compute identical shared secrets";
}

TEST_F(E2EExtendedTest, ECDH_P256_SharedSecretNonZero) {
    E2ESession alice(p256_config);
    E2ESession bob(p256_config);
    
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory alice_secret = alice.compute_shared_secret(alice_keys, bob_public);
    
    // Shared secret should not be all zeros
    bool nonzero = false;
    for (size_t i = 0; i < alice_secret.size(); ++i) {
        if (alice_secret.data()[i] != 0) {
            nonzero = true;
            break;
        }
    }
    EXPECT_TRUE(nonzero) << "ECDH P-256 shared secret must not be all zeros";
}

TEST_F(E2EExtendedTest, ECDH_P256_InvalidKeySize) {
    E2ESession session(p256_config);
    KeyPair keypair = session.generate_key_pair();
    
    // Try to compute shared secret with wrong-sized public key
    std::vector<uint8_t> invalid_key(32);  // Wrong size
    
    EXPECT_THROW({
        session.compute_shared_secret(keypair, invalid_key);
    }, std::exception) << "ECDH P-256: Invalid key size (32 bytes) must throw";
}

// ======================== End-to-End Encryption Tests ========================

TEST_F(E2EExtendedTest, X448_EncryptDecryptRoundtrip) {
    E2ESession alice(x448_config);
    E2ESession bob(x448_config);
    
    // Key exchange
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory shared_secret = alice.compute_shared_secret(alice_keys, bob_public);
    SecureMemory encryption_key = alice.derive_keys(shared_secret, "X448_test", 32);
    
    // Original plaintext
    std::vector<uint8_t> plaintext = {'X', '4', '4', '8', ' ', 'T', 'e', 's', 't'};
    
    // Encrypt
    EncryptedMessage encrypted = alice.encrypt_message(plaintext, encryption_key);
    EXPECT_FALSE(encrypted.ciphertext.empty());
    
    // Decrypt
    std::vector<uint8_t> decrypted = alice.decrypt_message(encrypted, encryption_key);
    
    // Should match original
    EXPECT_EQ(plaintext, decrypted) << "X448: Encrypt/decrypt roundtrip must preserve plaintext";
}

TEST_F(E2EExtendedTest, ECDH_P256_EncryptDecryptRoundtrip) {
    E2ESession alice(p256_config);
    E2ESession bob(p256_config);
    
    // Key exchange
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory shared_secret = alice.compute_shared_secret(alice_keys, bob_public);
    SecureMemory encryption_key = alice.derive_keys(shared_secret, "P256_test", 32);
    
    // Original plaintext
    std::vector<uint8_t> plaintext = {'E', 'C', 'D', 'H', ' ', 'P', '-', '2', '5', '6'};
    
    // Encrypt
    EncryptedMessage encrypted = alice.encrypt_message(plaintext, encryption_key);
    EXPECT_FALSE(encrypted.ciphertext.empty());
    
    // Decrypt
    std::vector<uint8_t> decrypted = alice.decrypt_message(encrypted, encryption_key);
    
    // Should match original
    EXPECT_EQ(plaintext, decrypted) << "ECDH P-256: Encrypt/decrypt roundtrip must preserve plaintext";
}

// ======================== Cross-Protocol Isolation Tests ========================

TEST_F(E2EExtendedTest, ProtocolMismatch) {
    E2EConfig x25519_config;  // Defaults to X25519
    x25519_config.key_exchange = KeyExchangeProtocol::X25519;
    
    E2ESession x25519_session(x25519_config);
    E2ESession x448_session(x448_config);
    
    KeyPair x25519_keys = x25519_session.generate_key_pair();
    KeyPair x448_keys = x448_session.generate_key_pair();
    
    // Attempt to compute shared secret with mismatched protocol
    std::vector<uint8_t> x448_public(x448_keys.public_key.data(),
                                     x448_keys.public_key.data() + x448_keys.public_key.size());
    
    // This should throw because x25519_keys is X25519 but x448_public is X448 (56 bytes)
    EXPECT_THROW({
        x25519_session.compute_shared_secret(x25519_keys, x448_public);
    }, std::exception) << "Protocol mismatch (X25519 with X448 key) must throw";
}

// ======================== Edge Cases ========================

TEST_F(E2EExtendedTest, X448_EmptyMessageEncryption) {
    E2ESession session(x448_config);
    
    KeyPair keypair = session.generate_key_pair();
    std::vector<uint8_t> fake_peer_public(56, 0xAB);
    SecureMemory shared_secret = session.compute_shared_secret(keypair, fake_peer_public);
    SecureMemory key = session.derive_keys(shared_secret, "test", 32);
    
    std::vector<uint8_t> empty_plaintext;
    
    EncryptedMessage encrypted = session.encrypt_message(empty_plaintext, key);
    std::vector<uint8_t> decrypted = session.decrypt_message(encrypted, key);
    
    EXPECT_EQ(empty_plaintext, decrypted) << "X448: Empty message encryption/decryption must work";
}

TEST_F(E2EExtendedTest, ECDH_P256_EmptyMessageEncryption) {
    E2ESession session(p256_config);
    
    KeyPair keypair = session.generate_key_pair();
    
    // Create a fake peer public key (65 bytes, uncompressed point)
    std::vector<uint8_t> fake_peer_public(65);
    fake_peer_public[0] = 0x04;  // Uncompressed indicator
    for (size_t i = 1; i < 65; ++i) {
        fake_peer_public[i] = static_cast<uint8_t>(i);
    }
    
    SecureMemory shared_secret = session.compute_shared_secret(keypair, fake_peer_public);
    SecureMemory key = session.derive_keys(shared_secret, "test", 32);
    
    std::vector<uint8_t> empty_plaintext;
    
    EncryptedMessage encrypted = session.encrypt_message(empty_plaintext, key);
    std::vector<uint8_t> decrypted = session.decrypt_message(encrypted, key);
    
    EXPECT_EQ(empty_plaintext, decrypted) << "ECDH P-256: Empty message encryption/decryption must work";
}
