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

namespace {

void establish_x25519(E2ESession& initiator, E2ESession& responder) {
    auto initiator_keys = initiator.generate_key_pair();
    auto responder_keys = responder.generate_key_pair();
    auto request = initiator.create_key_exchange_request(initiator_keys);
    auto response = responder.process_key_exchange_request(request, responder_keys);
    ASSERT_TRUE(initiator.complete_key_exchange(response, initiator_keys));
    ASSERT_TRUE(initiator.is_established());
    ASSERT_TRUE(responder.is_established());
}

std::vector<uint8_t> bytes(const char* text) {
    return std::vector<uint8_t>(text, text + std::strlen(text));
}

} // namespace

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

TEST_F(E2ETest, DoubleRatchetHandshakeBidirectionalRoundtrip) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    auto a0 = alice.encrypt(bytes("alice-0"));
    auto b0 = bob.encrypt(bytes("bob-0"));
    EXPECT_EQ(a0.header.message_number, 0u);
    EXPECT_EQ(b0.header.message_number, 0u);

    auto at_bob = bob.decrypt(a0);
    auto at_alice = alice.decrypt(b0);
    ASSERT_TRUE(at_bob.has_value());
    ASSERT_TRUE(at_alice.has_value());
    EXPECT_EQ(*at_bob, bytes("alice-0"));
    EXPECT_EQ(*at_alice, bytes("bob-0"));
    EXPECT_EQ(alice.get_sending_chain_length(), 1u);
    EXPECT_EQ(alice.get_receiving_chain_length(), 1u);
    EXPECT_EQ(bob.get_sending_chain_length(), 1u);
    EXPECT_EQ(bob.get_receiving_chain_length(), 1u);

    auto a1 = alice.encrypt(bytes("alice-1"));
    ASSERT_TRUE(bob.decrypt(a1).has_value());
    EXPECT_EQ(a1.header.message_number, 1u);
    EXPECT_EQ(alice.get_sending_chain_length(), 2u);
    EXPECT_EQ(bob.get_receiving_chain_length(), 2u);
}

TEST_F(E2ETest, DoubleRatchetReorderSkippedKeysAndReplay) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    auto m0 = alice.encrypt(bytes("zero"));
    auto m1 = alice.encrypt(bytes("one"));
    auto m2 = alice.encrypt(bytes("two"));

    // Deliver the newest packet first, then the skipped packets out of order.
    auto two = bob.decrypt(m2);
    ASSERT_TRUE(two.has_value());
    EXPECT_EQ(*two, bytes("two"));
    auto zero = bob.decrypt(m0);
    ASSERT_TRUE(zero.has_value());
    EXPECT_EQ(*zero, bytes("zero"));
    auto one = bob.decrypt(m1);
    ASSERT_TRUE(one.has_value());
    EXPECT_EQ(*one, bytes("one"));

    // Neither a current-chain replay nor a consumed skipped-key replay is
    // accepted a second time.
    EXPECT_FALSE(bob.decrypt(m2).has_value());
    EXPECT_FALSE(bob.decrypt(m0).has_value());
    EXPECT_EQ(alice.get_sending_chain_length(), 3u);
    EXPECT_EQ(bob.get_receiving_chain_length(), 3u);
}

// H1 regression: rotate_keys() before the peer's first inbound message (i.e.
// before the peer's ratchet key is pinned) must not desync the session.
TEST_F(E2ETest, RotateKeysBeforeFirstInboundMessageIsSafe) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    // Neither side has received a message yet, so no peer ratchet key is
    // pinned. Rotation must be deferred rather than break the chains.
    alice.rotate_keys();
    bob.rotate_keys();

    auto a0 = alice.encrypt(bytes("a0"));
    auto at_bob = bob.decrypt(a0);
    ASSERT_TRUE(at_bob.has_value());
    EXPECT_EQ(*at_bob, bytes("a0"));

    auto b0 = bob.encrypt(bytes("b0"));
    auto at_alice = alice.decrypt(b0);
    ASSERT_TRUE(at_alice.has_value());
    EXPECT_EQ(*at_alice, bytes("b0"));

    // Both chains keep advancing normally afterwards.
    auto a1 = alice.encrypt(bytes("a1"));
    ASSERT_TRUE(bob.decrypt(a1).has_value());
    auto b1 = bob.encrypt(bytes("b1"));
    ASSERT_TRUE(alice.decrypt(b1).has_value());
    EXPECT_EQ(alice.get_sending_chain_length(), 2u);
    EXPECT_EQ(bob.get_receiving_chain_length(), 2u);
}

// Post-pin rotation performs a sending-half DH ratchet; the peer must
// DH-step on receipt and the session must keep working in both directions.
TEST_F(E2ETest, RotateKeysAfterPinRoundtrip) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    // Exchange one message each way so both sides pin the peer ratchet key.
    auto a0 = alice.encrypt(bytes("a0"));
    ASSERT_TRUE(bob.decrypt(a0).has_value());
    auto b0 = bob.encrypt(bytes("b0"));
    ASSERT_TRUE(alice.decrypt(b0).has_value());

    alice.rotate_keys();
    auto a1 = alice.encrypt(bytes("a1"));
    EXPECT_EQ(a1.header.message_number, 0u);          // fresh sending chain
    EXPECT_EQ(a1.header.previous_chain_length, 1u);
    auto d1 = bob.decrypt(a1);                         // bob DH-steps
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("a1"));

    auto b1 = bob.encrypt(bytes("b1"));
    auto d2 = alice.decrypt(b1);                       // alice DH-steps
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("b1"));

    // Chains continue after the rotation.
    auto a2 = alice.encrypt(bytes("a2"));
    ASSERT_TRUE(bob.decrypt(a2).has_value());
    auto b2 = bob.encrypt(bytes("b2"));
    ASSERT_TRUE(alice.decrypt(b2).has_value());

    // Crypto epoch: alice bumps on her local rotation and on each
    // authenticated inbound DH commit (b1 and b2 each carry a fresh peer
    // ratchet key); bob bumps on each inbound commit (a1, a2).
    EXPECT_EQ(alice.get_crypto_epoch(), 3u);
    EXPECT_EQ(bob.get_crypto_epoch(), 2u);
}

// H2 regression: a forged first packet must not poison the initial ratchet
// pin or any other state; the legitimate peer must still get through.
TEST_F(E2ETest, ForgedFirstPacketDoesNotPoisonSession) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    EncryptedMessage forged;
    forged.header.version = 2;
    forged.header.message_number = 0;
    forged.header.previous_chain_length = 0;
    forged.header.dh_public_key = std::vector<uint8_t>(32, 0xAA);
    forged.nonce = std::vector<uint8_t>(24, 0xBB);
    forged.ciphertext = std::vector<uint8_t>(64, 0xCC);
    EXPECT_FALSE(bob.decrypt(forged).has_value());

    // No pin, no chain advancement, no counters.
    EXPECT_EQ(bob.get_receiving_chain_length(), 0u);
    EXPECT_EQ(bob.get_messages_received(), 0u);

    // The legitimate peer still establishes the ratchet and communicates.
    auto a0 = alice.encrypt(bytes("hello"));
    auto d0 = bob.decrypt(a0);
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(*d0, bytes("hello"));
    auto b0 = bob.encrypt(bytes("world"));
    auto d1 = alice.decrypt(b0);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("world"));
}

// H2 regression: forged packets against an active session (tampered
// ciphertext, forged new DH key, malformed DH key) must leave all ratchet
// state untouched, and legitimate/out-of-order packets must still decrypt.
TEST_F(E2ETest, ForgedCurrentChainPacketPreservesState) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    auto a0 = alice.encrypt(bytes("first"));
    ASSERT_TRUE(bob.decrypt(a0).has_value());
    auto a1 = alice.encrypt(bytes("second"));
    auto a2 = alice.encrypt(bytes("third"));

    const auto recv_len = bob.get_receiving_chain_length();
    const auto received = bob.get_messages_received();

    // 1) Tampered copy of a legitimate current-chain packet.
    auto tampered = a1;
    tampered.ciphertext[0] ^= 0x01;
    EXPECT_FALSE(bob.decrypt(tampered).has_value());

    // 2) Forged packet with a new (attacker) DH key: exercises the tentative
    //    DH ratchet step; must fail verification without committing.
    EncryptedMessage forged;
    forged.header.version = 2;
    forged.header.message_number = 1;
    forged.header.previous_chain_length = 0;
    forged.header.dh_public_key = std::vector<uint8_t>(32, 0x11);
    forged.nonce = std::vector<uint8_t>(24, 0x22);
    forged.ciphertext = std::vector<uint8_t>(64, 0x33);
    EXPECT_FALSE(bob.decrypt(forged).has_value());

    // 3) Malformed DH key size (must be rejected without throwing or
    //    mutating state).
    auto bad_size = forged;
    bad_size.header.dh_public_key = std::vector<uint8_t>(5, 0x44);
    EXPECT_FALSE(bob.decrypt(bad_size).has_value());

    // No ratchet state changed.
    EXPECT_EQ(bob.get_receiving_chain_length(), recv_len);
    EXPECT_EQ(bob.get_messages_received(), received);

    // The legitimate packets — including the out-of-order one whose key is
    // derived via the skip list — still decrypt.
    auto d2 = bob.decrypt(a2);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("third"));

    // A forged packet colliding with the staged skipped key's message
    // number must not consume that key.
    auto forged_skipped = a1;
    forged_skipped.ciphertext[0] ^= 0x02;
    forged_skipped.nonce[0] ^= 0x02;
    EXPECT_FALSE(bob.decrypt(forged_skipped).has_value());

    auto d1 = bob.decrypt(a1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("second"));

    // Failed/forged decrypts never advance the crypto epoch.
    EXPECT_EQ(bob.get_crypto_epoch(), 0u);
}

// Skipped message keys must survive a DH ratchet boundary: delayed packets
// from the pre-rotation chain still decrypt after the peer ratchets.
TEST_F(E2ETest, ReorderAcrossDhRatchetRotation) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    auto b0 = bob.encrypt(bytes("b0"));
    ASSERT_TRUE(alice.decrypt(b0).has_value());  // alice pins bob's key

    auto m0 = alice.encrypt(bytes("m0"));
    auto m1 = alice.encrypt(bytes("m1"));

    // Bob receives m1 first: pins alice's key and stages m0's skipped key.
    auto d1 = bob.decrypt(m1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("m1"));

    // Alice rotates (send-half DH ratchet) and sends on the new chain.
    alice.rotate_keys();
    auto m2 = alice.encrypt(bytes("m2"));
    EXPECT_EQ(m2.header.message_number, 0u);
    EXPECT_EQ(m2.header.previous_chain_length, 2u);

    auto d2 = bob.decrypt(m2);  // DH-step boundary
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("m2"));

    // The delayed pre-rotation packet still decrypts via its skipped key.
    auto d0 = bob.decrypt(m0);
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(*d0, bytes("m0"));

    // Replays of consumed old-chain packets are rejected without disturbing
    // the new chain.
    EXPECT_FALSE(bob.decrypt(m0).has_value());
    EXPECT_FALSE(bob.decrypt(m1).has_value());

    // The post-rotation chains keep working in both directions.
    auto m3 = alice.encrypt(bytes("m3"));
    ASSERT_TRUE(bob.decrypt(m3).has_value());
    auto r0 = bob.encrypt(bytes("r0"));
    ASSERT_TRUE(alice.decrypt(r0).has_value());
}

// Serialized state (v3) must preserve namespaced skipped keys so a restored
// session can still decrypt delayed out-of-order packets.
TEST_F(E2ETest, SessionStateSerializeRestoreRoundtrip) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);

    auto a0 = alice.encrypt(bytes("a0"));
    auto a1 = alice.encrypt(bytes("a1"));
    // Bob receives a1 first: a0's message key lands in the skip list.
    ASSERT_TRUE(bob.decrypt(a1).has_value());

    auto state = bob.serialize_session_state();
    E2ESession restored(default_config);
    ASSERT_TRUE(restored.restore_session_state(state));
    EXPECT_EQ(restored.get_receiving_chain_length(), 2u);

    // The restored session decrypts the delayed packet via the restored
    // skipped key, then keeps the chain going.
    auto d0 = restored.decrypt(a0);
    ASSERT_TRUE(d0.has_value());
    EXPECT_EQ(*d0, bytes("a0"));
    auto a2 = alice.encrypt(bytes("a2"));
    auto d2 = restored.decrypt(a2);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("a2"));
}

// ---- Rotation policy regression tests (HIGH: desync on simultaneous /
// double / lost-rotation scenarios) ----

// Simultaneous periodic rotate_all_keys() on both peers' managers must not
// cross the DH ratchets: only the initiator rotates spontaneously, and the
// fence makes repeated invocations idempotent until the peer answers.
TEST_F(E2ETest, SimultaneousRotateAllKeysStaysSynchronized) {
    E2EManager manager_a, manager_b;
    auto alice = manager_a.create_session("bob", default_config);
    auto bob = manager_b.create_session("alice", default_config);
    establish_x25519(*alice, *bob);

    // Pin both directions.
    ASSERT_TRUE(bob->decrypt(alice->encrypt(bytes("a0"))).has_value());
    ASSERT_TRUE(alice->decrypt(bob->encrypt(bytes("b0"))).has_value());

    // Simultaneous + repeated periodic rotation on both sides.
    manager_a.rotate_all_keys();
    manager_b.rotate_all_keys();
    manager_a.rotate_all_keys();
    manager_b.rotate_all_keys();

    // Exactly one rotation happened (initiator only, fenced).
    auto a1 = alice->encrypt(bytes("a1"));
    EXPECT_EQ(a1.header.message_number, 0u);
    EXPECT_EQ(a1.header.previous_chain_length, 1u);
    auto d1 = bob->decrypt(a1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("a1"));

    auto b1 = bob->encrypt(bytes("b1"));
    auto d2 = alice->decrypt(b1);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("b1"));

    // The peer's reply cleared the fence: the next periodic round rotates
    // again and keeps working.
    manager_a.rotate_all_keys();
    manager_b.rotate_all_keys();
    auto a2 = alice->encrypt(bytes("a2"));
    EXPECT_EQ(a2.header.message_number, 0u);
    // Alice never sent on her post-commit intermediate chain, so its
    // previous-chain length is truthfully 0.
    EXPECT_EQ(a2.header.previous_chain_length, 0u);
    ASSERT_TRUE(bob->decrypt(a2).has_value());
    ASSERT_TRUE(alice->decrypt(bob->encrypt(bytes("b2"))).has_value());

    // Two full rotation cycles: alice bumps on local rotate + inbound commit
    // (2 per cycle), bob on inbound commit only (1 per cycle).
    EXPECT_EQ(alice->get_crypto_epoch(), 4u);
    EXPECT_EQ(bob->get_crypto_epoch(), 2u);
}

// A second rotation before the peer's authenticated DH reply is a fenced
// no-op; without the fence the root keys diverge permanently.
TEST_F(E2ETest, DoubleRotateWithoutPeerReplyStaysSynchronized) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);
    ASSERT_TRUE(bob.decrypt(alice.encrypt(bytes("a0"))).has_value());
    ASSERT_TRUE(alice.decrypt(bob.encrypt(bytes("b0"))).has_value());

    alice.rotate_keys();
    alice.rotate_keys();  // fenced no-op — previously a permanent desync

    auto a1 = alice.encrypt(bytes("a1"));
    // A real second rotation would have reset previous_chain_length to 0.
    EXPECT_EQ(a1.header.message_number, 0u);
    EXPECT_EQ(a1.header.previous_chain_length, 1u);
    auto d1 = bob.decrypt(a1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("a1"));

    auto b1 = bob.encrypt(bytes("b1"));
    auto d2 = alice.decrypt(b1);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("b1"));
}

// The first packet on a rotated chain is lost; the periodic timer fires
// again before any peer reply. The fence keeps the advertised key stable, so
// the retransmitted/new packets stay on a chain the peer can derive.
TEST_F(E2ETest, FirstRotatedPacketLostThenRetried) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);
    ASSERT_TRUE(bob.decrypt(alice.encrypt(bytes("a0"))).has_value());
    ASSERT_TRUE(alice.decrypt(bob.encrypt(bytes("b0"))).has_value());

    alice.rotate_keys();
    auto m1 = alice.encrypt(bytes("m1"));  // lost in transit
    alice.rotate_keys();                   // timer fires again: fenced no-op
    auto m2 = alice.encrypt(bytes("m2"));
    EXPECT_EQ(m1.header.dh_public_key, m2.header.dh_public_key);

    // m2 arrives first; m1 is still outstanding.
    auto d2 = bob.decrypt(m2);
    ASSERT_TRUE(d2.has_value());
    EXPECT_EQ(*d2, bytes("m2"));

    // The retransmitted m1 decrypts via its staged skipped key.
    auto d1 = bob.decrypt(m1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("m1"));

    // Bob's reply clears the fence; the next periodic rotation works again.
    auto b1 = bob.encrypt(bytes("b1"));
    ASSERT_TRUE(alice.decrypt(b1).has_value());
    alice.rotate_keys();
    auto m3 = alice.encrypt(bytes("m3"));
    EXPECT_EQ(m3.header.message_number, 0u);
    ASSERT_TRUE(bob.decrypt(m3).has_value());
}

// The responder never rotates spontaneously (role gate): its advertised
// ratchet key and chain counters are untouched by rotate_keys().
TEST_F(E2ETest, ResponderSpontaneousRotationIsSuppressed) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);
    ASSERT_TRUE(bob.decrypt(alice.encrypt(bytes("a0"))).has_value());
    ASSERT_TRUE(alice.decrypt(bob.encrypt(bytes("b0"))).has_value());

    auto b_pre = bob.encrypt(bytes("b1"));
    bob.rotate_keys();  // responder: no-op
    auto b_post = bob.encrypt(bytes("b2"));

    EXPECT_EQ(b_pre.header.dh_public_key, b_post.header.dh_public_key);
    EXPECT_EQ(b_post.header.message_number, 2u);  // chain continued, not reset
    EXPECT_EQ(bob.get_crypto_epoch(), 0u);

    ASSERT_TRUE(alice.decrypt(b_pre).has_value());
    ASSERT_TRUE(alice.decrypt(b_post).has_value());
}

// Serialized v4 state preserves the handshake role and crypto epoch: a
// restored initiator may rotate; a restored responder may not.
TEST_F(E2ETest, RestorePreservesRotationRoleAndEpoch) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);
    ASSERT_TRUE(bob.decrypt(alice.encrypt(bytes("a0"))).has_value());
    ASSERT_TRUE(alice.decrypt(bob.encrypt(bytes("b0"))).has_value());

    auto state = alice.serialize_session_state();
    E2ESession alice2(default_config);
    ASSERT_TRUE(alice2.restore_session_state(state));
    EXPECT_EQ(alice2.get_crypto_epoch(), 0u);

    alice2.rotate_keys();  // honored: initiator role survived the restore
    auto m = alice2.encrypt(bytes("rot"));
    EXPECT_EQ(m.header.message_number, 0u);
    EXPECT_EQ(m.header.previous_chain_length, 1u);
    EXPECT_EQ(alice2.get_crypto_epoch(), 1u);
    ASSERT_TRUE(bob.decrypt(m).has_value());
    ASSERT_TRUE(alice2.decrypt(bob.encrypt(bytes("reply"))).has_value());
    EXPECT_EQ(alice2.get_crypto_epoch(), 2u);

    // Restored responder: spontaneous rotation stays suppressed. The live
    // peer of bob2 is alice2 (the restored initiator that actually rotated);
    // the original alice object never saw that rotation and cannot derive
    // bob's post-step chain by design.
    auto bstate = bob.serialize_session_state();
    E2ESession bob2(default_config);
    ASSERT_TRUE(bob2.restore_session_state(bstate));
    auto probe = bob2.encrypt(bytes("probe"));
    bob2.rotate_keys();
    auto bm = bob2.encrypt(bytes("b"));
    // A rotation would have changed the advertised ratchet key.
    EXPECT_EQ(probe.header.dh_public_key, bm.header.dh_public_key);
    ASSERT_TRUE(alice2.decrypt(probe).has_value());
    ASSERT_TRUE(alice2.decrypt(bm).has_value());
}

// ---- Re-handshake rejection (MEDIUM: replayed KX resets replay window) ----

TEST_F(E2ETest, DuplicateHandshakeRejectedAndReplayWindowIntact) {
    E2ESession alice(default_config), bob(default_config);
    auto alice_keys = alice.generate_key_pair();
    auto bob_keys = bob.generate_key_pair();
    auto request = alice.create_key_exchange_request(alice_keys);
    auto response = bob.process_key_exchange_request(request, bob_keys);
    ASSERT_TRUE(alice.complete_key_exchange(response, alice_keys));

    auto a0 = alice.encrypt(bytes("old"));
    ASSERT_TRUE(bob.decrypt(a0).has_value());  // consumed

    // Replayed KX request on the established responder: rejected, and the
    // replay window is NOT reset.
    EXPECT_THROW(bob.process_key_exchange_request(request, bob_keys),
                 std::exception);
    EXPECT_EQ(bob.get_receiving_chain_length(), 1u);
    EXPECT_EQ(bob.get_messages_received(), 1u);

    // Replayed KX response on the established initiator: rejected.
    EXPECT_FALSE(alice.complete_key_exchange(response, alice_keys));
    EXPECT_EQ(alice.get_sending_chain_length(), 1u);

    // The old ciphertext still cannot be replayed.
    EXPECT_FALSE(bob.decrypt(a0).has_value());

    // The session keeps working in both directions.
    auto a1 = alice.encrypt(bytes("new"));
    auto d1 = bob.decrypt(a1);
    ASSERT_TRUE(d1.has_value());
    EXPECT_EQ(*d1, bytes("new"));
    auto b1 = bob.encrypt(bytes("ok"));
    ASSERT_TRUE(alice.decrypt(b1).has_value());

    // A fresh session object (explicit fresh state) may still answer the
    // same request; only re-handshake on an established session is refused.
    E2ESession bob2(default_config);
    auto bob2_keys = bob2.generate_key_pair();
    EXPECT_FALSE(bob2.process_key_exchange_request(request, bob2_keys).empty());
}

// A response with no matching outstanding request is rejected as well.
TEST_F(E2ETest, HandshakeResponseWithoutRequestRejected) {
    E2ESession alice(default_config), bob(default_config);
    auto alice_keys = alice.generate_key_pair();
    auto bob_keys = bob.generate_key_pair();
    auto request = alice.create_key_exchange_request(alice_keys);
    auto response = bob.process_key_exchange_request(request, bob_keys);

    E2ESession stranger(default_config);
    auto stranger_keys = stranger.generate_key_pair();
    EXPECT_FALSE(stranger.complete_key_exchange(response, stranger_keys));
    (void)alice_keys; (void)bob_keys;
}

// ---- previous_chain_length bound into AAD (wire v3) ----

TEST_F(E2ETest, TamperedPreviousChainLengthRejected) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);
    ASSERT_TRUE(bob.decrypt(alice.encrypt(bytes("a0"))).has_value());
    ASSERT_TRUE(alice.decrypt(bob.encrypt(bytes("b0"))).has_value());

    alice.rotate_keys();
    auto m = alice.encrypt(bytes("rot"));
    auto bad = m;
    bad.header.previous_chain_length ^= 1;
    // AEAD verification fails: previous_chain_length is part of the AAD.
    EXPECT_FALSE(bob.decrypt(bad).has_value());

    // The untampered copy still decrypts (failed attempt mutated nothing).
    auto d = bob.decrypt(m);
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(*d, bytes("rot"));
}

// ---- Padding failures must not leak padded plaintext ----

TEST_F(E2ETest, PaddingUnpadFailureRejected) {
    // Utility level: corrupted ISO 7816-4 padding is rejected.
    auto padded = E2EUtils::pad_message(bytes("abc"), 16);
    auto corrupted = padded;
    corrupted.back() = 0x01;  // trailing zero clobbered
    EXPECT_FALSE(E2EUtils::unpad_message(corrupted).has_value());
    EXPECT_FALSE(E2EUtils::unpad_message(std::vector<uint8_t>(16, 0)).has_value());
    EXPECT_TRUE(E2EUtils::unpad_message(padded).has_value());

    // Session level: sender without padding, receiver expecting padding.
    // AEAD verifies, but unpadding the raw plaintext must fail closed
    // (nullopt) instead of returning the raw buffer.
    E2EConfig no_pad = default_config;
    no_pad.enable_padding = false;
    E2ESession alice(no_pad), bob(default_config);
    establish_x25519(alice, bob);
    auto m = alice.encrypt(bytes("raw"));  // no 0x80 terminator present
    EXPECT_FALSE(bob.decrypt(m).has_value());
}

// ---- Restore-time structural validation ----

TEST_F(E2ETest, RestoreRejectsCorruptEnumsAndSkippedCap) {
    E2ESession alice(default_config), bob(default_config);
    establish_x25519(alice, bob);
    auto state = bob.serialize_session_state();
    ASSERT_GE(state.size(), 8u);

    // Layout: ver(1) | u16 sid_len | sid | state(1) | kex(1) | ...
    const size_t sid_len = (static_cast<size_t>(state[1]) << 8) | state[2];
    const size_t state_off = 3 + sid_len;

    auto bad_state = state;
    bad_state[state_off] = 0x7F;  // out-of-range E2ESessionState
    E2ESession s1(default_config);
    EXPECT_FALSE(s1.restore_session_state(bad_state));

    auto bad_kex = state;
    bad_kex[state_off + 1] = 0x7F;  // out-of-range KeyExchangeProtocol
    E2ESession s2(default_config);
    EXPECT_FALSE(s2.restore_session_state(bad_kex));

    // No messages were exchanged, so the blob ends with skipped-count == 0.
    auto bad_cap = state;
    const size_t n = bad_cap.size();
    bad_cap[n - 4] = 0xFF; bad_cap[n - 3] = 0xFF;
    bad_cap[n - 2] = 0xFF; bad_cap[n - 1] = 0xFF;  // 4B skipped keys > cap
    E2ESession s3(default_config);
    EXPECT_FALSE(s3.restore_session_state(bad_cap));

    // The untampered blob still restores.
    E2ESession s4(default_config);
    EXPECT_TRUE(s4.restore_session_state(state));
}

// Session state management tests - disabled due to missing implementations
/*
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
*/

// E2EManager tests - disabled due to missing implementations
/*
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
*/

// Utility tests - disabled due to missing implementations
/*
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
*/
