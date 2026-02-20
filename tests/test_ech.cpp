/**
 * @file test_ech.cpp
 * @brief Unit tests for HPKE-based ECH implementation
 */

#include <gtest/gtest.h>
#include "../src/core/include/ncp_ech.hpp"
#include <vector>
#include <string>

using namespace ncp::DPI::ECH;

class ECHTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize libsodium if needed
    }
};

// Test 1: ECHConfig creation and parsing
TEST_F(ECHTest, CreateAndParseECHConfig) {
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite(
        HPKEKem::DHKEM_X25519_HKDF_SHA256,
        HPKEKDF::HKDF_SHA256,
        HPKEAEAD::AES_128_GCM
    );

    // Create test config
    auto config = create_test_ech_config("example.com", suite, private_key);

    EXPECT_EQ(config.public_name, "example.com");
    EXPECT_FALSE(config.public_key.empty());
    EXPECT_FALSE(private_key.empty());
    EXPECT_EQ(config.cipher_suites.size(), 1);
}

// Test 2: HPKE encryption/decryption round-trip
TEST_F(ECHTest, HPKEEncryptDecryptRoundTrip) {
    // Generate keypair
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite;
    auto config = create_test_ech_config("cloudflare.com", suite, private_key);

    // Client: Initialize and encrypt
    ECHClientContext client;
    ASSERT_TRUE(client.init(config));

    std::vector<uint8_t> client_hello_inner = {
        0x16, 0x03, 0x03, 0x00, 0x10,  // TLS record header
        0x01, 0x00, 0x00, 0x0c,        // ClientHello
        0x03, 0x03,                    // TLS 1.2
        0x01, 0x02, 0x03, 0x04         // Random data
    };

    std::vector<uint8_t> client_hello_outer_aad = {
        0x16, 0x03, 0x03, 0x00, 0x05,
        0x01, 0x00, 0x00, 0x01, 0x00
    };

    std::vector<uint8_t> enc, encrypted;
    ASSERT_TRUE(client.encrypt(
        client_hello_inner,
        client_hello_outer_aad,
        enc,
        encrypted
    ));

    EXPECT_FALSE(enc.empty());
    EXPECT_FALSE(encrypted.empty());
    EXPECT_NE(encrypted, client_hello_inner);  // Should be different

    // Server: Initialize and decrypt (pass config for info vector match)
    ECHServerContext server;
    ASSERT_TRUE(server.init(private_key, suite, config));

    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(server.decrypt(
        enc,
        encrypted,
        client_hello_outer_aad,
        decrypted
    ));

    // Verify decrypted matches original
    EXPECT_EQ(decrypted, client_hello_inner);
}

// Test 3: Different cipher suites
TEST_F(ECHTest, MultipleCipherSuites) {
    std::vector<HPKECipherSuite> suites = {
        {HPKEKem::DHKEM_X25519_HKDF_SHA256, HPKEKDF::HKDF_SHA256, HPKEAEAD::AES_128_GCM},
        {HPKEKem::DHKEM_P256_HKDF_SHA256, HPKEKDF::HKDF_SHA256, HPKEAEAD::AES_256_GCM},
        {HPKEKem::DHKEM_X25519_HKDF_SHA256, HPKEKDF::HKDF_SHA256, HPKEAEAD::CHACHA20_POLY1305}
    };

    for (const auto& suite : suites) {
        std::vector<uint8_t> private_key;
        auto config = create_test_ech_config("test.com", suite, private_key);

        EXPECT_FALSE(config.public_key.empty());
        EXPECT_FALSE(private_key.empty());
    }
}

// Test 4: apply_ech integration
TEST_F(ECHTest, ApplyECHToClientHello) {
    // Create test ECHConfig
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite;
    auto config = create_test_ech_config("example.org", suite, private_key);

    // Minimal ClientHello
    std::vector<uint8_t> client_hello = {
        0x16, 0x03, 0x03, 0x00, 0x40,  // TLS record
        0x01, 0x00, 0x00, 0x3c,        // Handshake: ClientHello
        0x03, 0x03,                    // Version
    };
    // Add 32 bytes random
    for (int i = 0; i < 32; i++) {
        client_hello.push_back(static_cast<uint8_t>(i));
    }
    // Session ID length
    client_hello.push_back(0x00);
    // Cipher suites
    client_hello.push_back(0x00);
    client_hello.push_back(0x02);
    client_hello.push_back(0x13);
    client_hello.push_back(0x01);
    // Compression
    client_hello.push_back(0x01);
    client_hello.push_back(0x00);

    auto result = apply_ech(client_hello, config);

    // Result should be larger (ECH extension added)
    EXPECT_GE(result.size(), client_hello.size());
}

// Test 5: Invalid inputs
TEST_F(ECHTest, HandleInvalidInputs) {
    ECHClientContext client;
    ECHConfig empty_config;

    // Should fail with empty config
    EXPECT_FALSE(client.init(empty_config));

    // Empty data
    std::vector<uint8_t> enc, encrypted;
    EXPECT_FALSE(client.encrypt({}, {}, enc, encrypted));
}

// Test 6: AAD tampering detection
TEST_F(ECHTest, DetectAADTampering) {
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite;
    auto config = create_test_ech_config("secure.com", suite, private_key);

    ECHClientContext client;
    ASSERT_TRUE(client.init(config));

    std::vector<uint8_t> inner = {0x01, 0x02, 0x03};
    std::vector<uint8_t> aad = {0x04, 0x05, 0x06};
    std::vector<uint8_t> enc, encrypted;

    ASSERT_TRUE(client.encrypt(inner, aad, enc, encrypted));

    // Tamper with AAD
    std::vector<uint8_t> tampered_aad = {0x04, 0x05, 0x07};

    ECHServerContext server;
    ASSERT_TRUE(server.init(private_key, suite, config));

    std::vector<uint8_t> decrypted;
    // Should fail due to AAD mismatch
    EXPECT_FALSE(server.decrypt(enc, encrypted, tampered_aad, decrypted));
}

// Test 7: Config ID handling
TEST_F(ECHTest, ConfigIDMatching) {
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite;
    auto config = create_test_ech_config("test.net", suite, private_key);
    config.config_id = 42;

    ECHClientContext client;
    ASSERT_TRUE(client.init(config));

    EXPECT_EQ(client.get_config_id(), 42);
}

// Test 8: Large payload encryption
TEST_F(ECHTest, LargePayloadEncryption) {
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite;
    auto config = create_test_ech_config("large.com", suite, private_key);

    ECHClientContext client;
    ASSERT_TRUE(client.init(config));

    // 4KB payload
    std::vector<uint8_t> large_inner(4096, 0xAB);
    std::vector<uint8_t> aad = {0x01, 0x02};
    std::vector<uint8_t> enc, encrypted;

    ASSERT_TRUE(client.encrypt(large_inner, aad, enc, encrypted));

    ECHServerContext server;
    ASSERT_TRUE(server.init(private_key, suite, config));

    std::vector<uint8_t> decrypted;
    ASSERT_TRUE(server.decrypt(enc, encrypted, aad, decrypted));

    EXPECT_EQ(decrypted.size(), 4096);
    EXPECT_EQ(decrypted, large_inner);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
