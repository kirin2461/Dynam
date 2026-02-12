#ifndef NCP_E2E_HPP
#define NCP_E2E_HPP

// Only depends on secure memory types, NOT on TLS fingerprinting
#include "ncp_secure_memory.hpp"

#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <map>
#include <cstdint>

namespace NCP {

enum class E2ESessionState {
    Uninitialized,
    KeyExchangeInitiated,
    KeyExchangeCompleted,
    SessionEstablished,
    SessionExpired,
    SessionRevoked
};

/**
 * @brief Key exchange protocols
 *
 * Only protocols with real implementations are listed.
 * X448 and ECDH_P256 were removed: X448 had a broken implementation
 * (called crypto_scalarmult_base with 56-byte keys on Curve25519),
 * and ECDH_P256 was silently falling back to X25519.
 */
enum class KeyExchangeProtocol {
    X25519,         // Curve25519 Diffie-Hellman (libsodium)
    Kyber1024       // Post-quantum KEM (requires liboqs)
};

struct RatchetState {
    SecureMemory root_key;      // 32 bytes
    SecureMemory chain_key;     // 32 bytes
    uint32_t sending_chain_length = 0;
    uint32_t receiving_chain_length = 0;
    uint32_t previous_chain_length = 0;
    std::map<uint32_t, SecureMemory> skipped_keys;
};

struct KeyPair {
    SecureMemory public_key;
    SecureMemory private_key;
    KeyExchangeProtocol protocol = KeyExchangeProtocol::X25519;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
};

struct MessageHeader {
    uint8_t version = 1;
    uint32_t message_number = 0;
    uint32_t previous_chain_length = 0;
    std::vector<uint8_t> dh_public_key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> associated_data;
};

struct EncryptedMessage {
    MessageHeader header;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> auth_tag;
};

struct E2EConfig {
    KeyExchangeProtocol key_exchange = KeyExchangeProtocol::X25519;
    bool enable_forward_secrecy = true;
    bool enable_post_quantum = false;
    uint32_t max_skip_messages = 1000;
    std::chrono::seconds session_timeout{3600};
    std::chrono::seconds key_rotation_interval{300};
    bool enable_padding = true;
};

class E2ESession {
public:
    explicit E2ESession(const E2EConfig& config = E2EConfig{});
    ~E2ESession();

    E2ESession(const E2ESession&) = delete;
    E2ESession& operator=(const E2ESession&) = delete;

    // Key exchange
    KeyPair generate_key_pair();
    std::vector<uint8_t> create_key_exchange_request(const KeyPair& local_keys);

    std::vector<uint8_t> process_key_exchange_request(
        const std::vector<uint8_t>& request,
        const KeyPair& local_keys
    );

    bool complete_key_exchange(
        const std::vector<uint8_t>& response,
        const KeyPair& local_keys
    );

    // Encryption/decryption (uses XChaCha20-Poly1305 with 24-byte nonce)
    EncryptedMessage encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& associated_data = {}
    );

    std::optional<std::vector<uint8_t>> decrypt(
        const EncryptedMessage& encrypted_message
    );

    // Ratcheting
    void ratchet_sending_chain();
    void ratchet_receiving_chain(const std::vector<uint8_t>& remote_public_key);

    // Session management
    E2ESessionState get_state() const;
    bool is_established() const;
    bool is_expired() const;
    void rotate_keys();
    void revoke_session();

    std::string get_session_id() const;
    std::chrono::system_clock::time_point get_last_activity() const;
    uint64_t get_messages_sent() const;
    uint64_t get_messages_received() const;

private:
    void init_ratchet_keys();
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

class E2EManager {
public:
    E2EManager();
    ~E2EManager();

    std::shared_ptr<E2ESession> create_session(
        const std::string& peer_id,
        const E2EConfig& config = E2EConfig{}
    );

    std::shared_ptr<E2ESession> get_session(const std::string& peer_id);
    void remove_session(const std::string& peer_id);
    void remove_expired_sessions();

    std::vector<std::string> get_active_sessions() const;
    size_t get_session_count() const;

    void rotate_all_keys();
    void export_keys(const std::string& filepath, const SecureString& password);
    bool import_keys(const std::string& filepath, const SecureString& password);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

namespace E2EUtils {
    SecureMemory derive_key(
        const SecureMemory& input_key_material,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info,
        size_t output_length
    );

    SecureMemory hkdf_expand(
        const SecureMemory& prk,
        const std::vector<uint8_t>& info,
        size_t length
    );

    std::vector<uint8_t> pad_message(
        const std::vector<uint8_t>& message,
        size_t block_size = 128
    );

    std::optional<std::vector<uint8_t>> unpad_message(
        const std::vector<uint8_t>& padded_message
    );

    std::vector<uint8_t> serialize_message(const EncryptedMessage& msg);
    std::optional<EncryptedMessage> deserialize_message(
        const std::vector<uint8_t>& data
    );
}

} // namespace NCP

#endif // NCP_E2E_HPP
