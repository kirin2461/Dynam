/**
 * @file test_e2e.cpp
 * @brief Unit tests for E2E encryption module
 */

#include <gtest/gtest.h>
#include "ncp_e2e.hpp"
#include <vector>
#include <string>
#include <cstring>

using namespace ncp;

class E2ETest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize libsodium if needed
    }
    
    E2EConfig default_config;
};

// ---- Key Generation Tests ----

TEST_F(E2ETest, X25519KeyGeneration) {
    E2ESession session(default_config);
    
    KeyPair keypair = session.generate_key_pair();
    
    // X25519 keys should be 32 bytes
    EXPECT_EQ(keypair.public_key.size(), 32);
    EXPECT_EQ(keypair.private_key.size(), 32);
    EXPECT_EQ(keypair.protocol, KeyExchangeProtocol::X25519);
}

TEST_F(E2ETest, KeyPairUniqueness) {
    E2ESession session(default_config);
    
    KeyPair keypair1 = session.generate_key_pair();
    KeyPair keypair2 = session.generate_key_pair();
    
    // Two generated key pairs should be different
    bool keys_different = false;
    if (keypair1.public_key.size() == keypair2.public_key.size()) {
        keys_different = (std::memcmp(
            keypair1.public_key.data(),
            keypair2.public_key.data(),
            keypair1.public_key.size()) != 0);
    }
    EXPECT_TRUE(keys_different);
}

// ---- Shared Secret Tests ----

TEST_F(E2ETest, SharedSecretComputation) {
    E2ESession alice(default_config);
    E2ESession bob(default_config);
    
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
    
    // Both should arrive at the same shared secret
    ASSERT_EQ(alice_secret.size(), bob_secret.size());
    EXPECT_EQ(std::memcmp(alice_secret.data(), bob_secret.data(), alice_secret.size()), 0);
}

// ---- Key Derivation Tests ----

TEST_F(E2ETest, KeyDerivation) {
    E2ESession session(default_config);
    
    KeyPair keypair = session.generate_key_pair();
    
    // Create a fake shared secret for testing
    SecureMemory shared_secret(32);
    std::memset(shared_secret.data(), 0xAB, 32);
    
    // Derive 64 bytes of key material
    SecureMemory derived = session.derive_keys(shared_secret, "test_context", 64);
    
    EXPECT_EQ(derived.size(), 64);
    
    // Derived keys should be different from input
    bool is_different = (std::memcmp(derived.data(), shared_secret.data(), 32) != 0);
    EXPECT_TRUE(is_different);
}

TEST_F(E2ETest, KeyDerivationDeterministic) {
    E2ESession session(default_config);
    
    SecureMemory shared_secret(32);
    std::memset(shared_secret.data(), 0x42, 32);
    
    SecureMemory derived1 = session.derive_keys(shared_secret, "same_context", 32);
    SecureMemory derived2 = session.derive_keys(shared_secret, "same_context", 32);
    
    // Same input should produce same output
    ASSERT_EQ(derived1.size(), derived2.size());
    EXPECT_EQ(std::memcmp(derived1.data(), derived2.data(), derived1.size()), 0);
}

// ---- Encryption/Decryption Tests ----

TEST_F(E2ETest, EncryptDecryptRoundtrip) {
    E2ESession alice(default_config);
    E2ESession bob(default_config);
    
    // Set up key exchange
    KeyPair alice_keys = alice.generate_key_pair();
    KeyPair bob_keys = bob.generate_key_pair();
    
    std::vector<uint8_t> bob_public(bob_keys.public_key.data(),
                                    bob_keys.public_key.data() + bob_keys.public_key.size());
    SecureMemory shared_secret = alice.compute_shared_secret(alice_keys, bob_public);
    SecureMemory encryption_key = alice.derive_keys(shared_secret, "encryption", 32);
    
    // Original plaintext
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ',', ' ', 
                                      'W', 'o', 'r', 'l', 'd', '!'};
    
    // Encrypt
    EncryptedMessage encrypted = alice.encrypt_message(plaintext, encryption_key);
    EXPECT_FALSE(encrypted.ciphertext.empty());
    
    // Decrypt
    std::vector<uint8_t> decrypted = alice.decrypt_message(encrypted, encryption_key);
    
    // Should match original
    EXPECT_EQ(plaintext, decrypted);
}

TEST_F(E2ETest, EncryptDecryptEmptyMessage) {
    E2ESession session(default_config);
    
    SecureMemory key(32);
    std::memset(key.data(), 0x11, 32);
    
    std::vector<uint8_t> empty_plaintext;
    
    EncryptedMessage encrypted = session.encrypt_message(empty_plaintext, key);
    std::vector<uint8_t> decrypted = session.decrypt_message(encrypted, key);
    
    EXPECT_EQ(empty_plaintext, decrypted);
}

TEST_F(E2ETest, EncryptDecryptLargeMessage) {
    E2ESession session(default_config);
    
    SecureMemory key(32);
    std::memset(key.data(), 0x22, 32);
    
    // Create a large message (1 MB)
    std::vector<uint8_t> large_plaintext(1024 * 1024);
    for (size_t i = 0; i < large_plaintext.size(); ++i) {
        large_plaintext[i] = static_cast<uint8_t>(i % 256);
    }
    
    EncryptedMessage encrypted = session.encrypt_message(large_plaintext, key);
    std::vector<uint8_t> decrypted = session.decrypt_message(encrypted, key);
    
    EXPECT_EQ(large_plaintext, decrypted);
}

TEST_F(E2ETest, DecryptWithWrongKey) {
    E2ESession session(default_config);
    
    SecureMemory correct_key(32);
    SecureMemory wrong_key(32);
    std::memset(correct_key.data(), 0x33, 32);
    std::memset(wrong_key.data(), 0x44, 32);
    
    std::vector<uint8_t> plaintext = {'S', 'e', 'c', 'r', 'e', 't'};
    
    EncryptedMessage encrypted = session.encrypt_message(plaintext, correct_key);
    
    // Decrypting with wrong key should throw or return different data
    EXPECT_THROW({
        session.decrypt_message(encrypted, wrong_key);
    }, std::exception);
}

TEST_F(E2ETest, TamperedCiphertext) {
    E2ESession session(default_config);
    
    SecureMemory key(32);
    std::memset(key.data(), 0x55, 32);
    
    std::vector<uint8_t> plaintext = {'T', 'e', 's', 't'};
    
    EncryptedMessage encrypted = session.encrypt_message(plaintext, key);
    
    // Tamper with ciphertext
    if (!encrypted.ciphertext.empty()) {
        encrypted.ciphertext[0] ^= 0xFF;
    }
    
    // Should fail authentication
    EXPECT_THROW({
        session.decrypt_message(encrypted, key);
    }, std::exception);
}

// ---- Session Management Tests ----

TEST_F(E2ETest, SessionIdUniqueness) {
    E2ESession session1(default_config);
    E2ESession session2(default_config);
    
    std::string id1 = session1.get_session_id();
    std::string id2 = session2.get_session_id();
    
    EXPECT_FALSE(id1.empty());
    EXPECT_FALSE(id2.empty());
    EXPECT_NE(id1, id2);
}

TEST_F(E2ETest, SessionStateTransitions) {
    E2ESession session(default_config);
    
    // Initial state should be Uninitialized
    EXPECT_EQ(session.get_state(), E2ESessionState::Uninitialized);
    EXPECT_FALSE(session.is_established());
}

TEST_F(E2ETest, SessionRevocation) {
    E2ESession session(default_config);
    
    session.revoke_session();
    
    EXPECT_EQ(session.get_state(), E2ESessionState::SessionRevoked);
}

// ---- E2EManager Tests ----

TEST_F(E2ETest, ManagerCreateSession) {
    E2EManager manager;
    
    auto session = manager.create_session("peer_alice");
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(manager.get_session_count(), 1);
}

TEST_F(E2ETest, ManagerGetSession) {
    E2EManager manager;
    
    auto created = manager.create_session("peer_bob");
    auto retrieved = manager.get_session("peer_bob");
    
    EXPECT_EQ(created, retrieved);
}

TEST_F(E2ETest, ManagerRemoveSession) {
    E2EManager manager;
    
    manager.create_session("peer_charlie");
    EXPECT_EQ(manager.get_session_count(), 1);
    
    manager.remove_session("peer_charlie");
    EXPECT_EQ(manager.get_session_count(), 0);
    EXPECT_EQ(manager.get_session("peer_charlie"), nullptr);
}

TEST_F(E2ETest, ManagerActiveSessions) {
    E2EManager manager;
    
    manager.create_session("peer_1");
    manager.create_session("peer_2");
    manager.create_session("peer_3");
    
    auto sessions = manager.get_active_sessions();
    EXPECT_EQ(sessions.size(), 3);
}

// ---- Utility Tests ----

TEST_F(E2ETest, MessagePadding) {
    std::vector<uint8_t> message = {'A', 'B', 'C'};
    
    auto padded = E2EUtils::pad_message(message, 16);
    
    EXPECT_EQ(padded.size() % 16, 0);
    EXPECT_GE(padded.size(), message.size());
    
    auto unpadded = E2EUtils::unpad_message(padded);
    ASSERT_TRUE(unpadded.has_value());
    EXPECT_EQ(unpadded.value(), message);
}

TEST_F(E2ETest, MessageSerialization) {
    EncryptedMessage msg;
    msg.header.version = 1;
    msg.header.message_number = 42;
    msg.ciphertext = {'C', 'I', 'P', 'H', 'E', 'R'};
    msg.auth_tag = {'T', 'A', 'G'};
    msg.nonce = std::vector<uint8_t>(24, 0x00);
    
    auto serialized = E2EUtils::serialize_message(msg);
    EXPECT_FALSE(serialized.empty());
    
    auto deserialized = E2EUtils::deserialize_message(serialized);
    ASSERT_TRUE(deserialized.has_value());
    EXPECT_EQ(deserialized->header.message_number, 42);
    EXPECT_EQ(deserialized->ciphertext, msg.ciphertext);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
