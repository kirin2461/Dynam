/**
 * @file ech_example.cpp
 * @brief Example: Using ECH with DoH config fetching
 */

#include <iostream>
#include <string>
#include "../src/core/include/ncp_ech.hpp"
#include "../src/core/include/ncp_ech_fetch.hpp"

using namespace ncp::DPI::ECH;

int main() {
    std::cout << "=== ECH (Encrypted Client Hello) Example ===\n\n";

    // Example 1: Fetch ECHConfig from DNS-over-HTTPS
    std::cout << "1. Fetching ECHConfig for cloudflare.com via DoH...\n";
    
    auto config_opt = fetch_ech_config_simple("cloudflare.com");
    
    if (config_opt.has_value()) {
        auto& config = config_opt.value();
        std::cout << "   ✓ ECHConfig fetched successfully\n";
        std::cout << "   - Config ID: " << static_cast<int>(config.config_id) << "\n";
        std::cout << "   - Public Name: " << config.public_name << "\n";
        std::cout << "   - Public Key Size: " << config.public_key.size() << " bytes\n";
        std::cout << "   - Cipher Suites: " << config.cipher_suites.size() << "\n\n";

        // Example 2: Encrypt ClientHello using fetched config
        std::cout << "2. Encrypting ClientHello with ECH...\n";

        // Create minimal ClientHello
        std::vector<uint8_t> client_hello = {
            0x16, 0x03, 0x03, 0x00, 0x40,  // TLS record
            0x01, 0x00, 0x00, 0x3c,        // Handshake
            0x03, 0x03,                    // TLS version
        };
        // Add random
        for (int i = 0; i < 32; i++) {
            client_hello.push_back(static_cast<uint8_t>(rand() % 256));
        }

        auto encrypted_hello = apply_ech(client_hello, config);

        std::cout << "   ✓ ClientHello encrypted\n";
        std::cout << "   - Original size: " << client_hello.size() << " bytes\n";
        std::cout << "   - Encrypted size: " << encrypted_hello.size() << " bytes\n\n";

    } else {
        std::cout << "   ✗ Failed to fetch ECHConfig\n";
        std::cout << "   (Domain may not support ECH yet)\n\n";
    }

    // Example 3: Manual encryption/decryption
    std::cout << "3. Manual HPKE encryption/decryption test...\n";

    // Generate test config
    std::vector<uint8_t> private_key;
    HPKECipherSuite suite(
        HPKEKem::DHKEM_X25519_HKDF_SHA256,
        HPKEKDF::HKDF_SHA256,
        HPKEAEAD::AES_128_GCM
    );
    auto test_config = create_test_ech_config("example.com", suite, private_key);

    // Client: Encrypt
    ECHClientContext client;
    if (client.init(test_config)) {
        std::vector<uint8_t> inner_hello = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
        std::vector<uint8_t> outer_aad = {0x41, 0x41, 0x44};
        std::vector<uint8_t> enc, encrypted;

        if (client.encrypt(inner_hello, outer_aad, enc, encrypted)) {
            std::cout << "   ✓ Client encryption successful\n";
            std::cout << "   - Encapsulated key size: " << enc.size() << " bytes\n";
            std::cout << "   - Encrypted payload size: " << encrypted.size() << " bytes\n";

            // Server: Decrypt
            ECHServerContext server;
            if (server.init(private_key, suite)) {
                std::vector<uint8_t> decrypted;
                if (server.decrypt(enc, encrypted, outer_aad, decrypted)) {
                    std::cout << "   ✓ Server decryption successful\n";
                    std::cout << "   - Decrypted matches original: ";
                    std::cout << (decrypted == inner_hello ? "YES" : "NO") << "\n\n";
                } else {
                    std::cout << "   ✗ Server decryption failed\n\n";
                }
            }
        } else {
            std::cout << "   ✗ Client encryption failed\n\n";
        }
    }

    std::cout << "=== Example Complete ===\n";
    return 0;
}
