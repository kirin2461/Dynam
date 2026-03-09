#include "ncp_crypto.hpp"
#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 16) return 0;

    ncp::Crypto crypto;
    std::vector<uint8_t> input(data, data + size);

    // Test hashing with fuzzed input
    crypto.hash_sha256(input);
    crypto.hash_sha512(input);
    crypto.hash_blake2b(input);

    // Test encrypt/decrypt roundtrip with fuzzed data as plaintext
    if (size >= 32) {
        auto key = crypto.generate_random(32);
        auto encrypted = crypto.encrypt_chacha20(input, key);
        if (encrypted.size() > 0) {
            crypto.decrypt_chacha20(encrypted, key);
        }
    }

    // Test signature verification with fuzzed data
    if (size >= 64) {
        auto keypair = crypto.generate_keypair();
        auto signature = crypto.sign_ed25519(input, keypair.secret_key);
        std::vector<uint8_t> pub_key(keypair.public_key.data(),
                                     keypair.public_key.data() + keypair.public_key.size());
        crypto.verify_ed25519(input, signature, pub_key);
    }

    return 0;
}
