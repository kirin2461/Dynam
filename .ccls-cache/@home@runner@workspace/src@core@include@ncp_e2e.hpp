#ifndef NCP_E2E_HPP
#define NCP_E2E_HPP

#include "ncp_tls_fingerprint.hpp"
#include <sodium.h>
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <map>

namespace ncp {

/**
 * @brief End-to-End encryption session states
 */
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
 */
enum class KeyExchangeProtocol {
    X25519,          // Curve25519 Diffie-Hellman
    X448,            // Curve448 Diffie-Hellman
    ECDH_P256,       // NIST P-256
    Kyber1024        // Post-quantum KEM
};

/**
 * @brief Forward secrecy ratchet state
 */
struct RatchetState {
    SecureMemory root_key;           // 32 bytes
    SecureMemory chain_key;          // 32 bytes
    SecureMemory message_keys;       // Variable size
    uint32_t sending_chain_length;
    uint32_t receiving_chain_length;
    uint32_t previous_chain_length;
    std::map<uint32_t, SecureMemory> skipped_keys;  // Out-of-order message keys
};

/**
 * @brief Public/Private key pair
 */
struct KeyPair {
    SecureMemory public_key;
    SecureMemory private_key;
    KeyExchangeProtocol protocol;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
};

/**
 * @brief Encrypted message header
 */
struct MessageHeader {
    uint8_t version;                 // Protocol version
    uint32_t message_number;         // Message sequence number
    uint32_t previous_chain_length;  // For ratcheting
    std::vector<uint8_t> dh_public_key;  // Ephemeral DH public key
    std::vector<uint8_t> nonce;      // Message nonce
    std::vector<uint8_t> associated_data;  // Additional authenticated data
};

/**
 * @brief Encrypted message
 */
struct EncryptedMessage {
    MessageHeader header;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> auth_tag;   // AEAD authentication tag
};

/**
 * @brief E2E session configuration
 */
struct E2EConfig {
    KeyExchangeProtocol key_exchange = KeyExchangeProtocol::X25519;
    bool enable_forward_secrecy = true;
    bool enable_post_quantum = false;
    uint32_t max_skip_messages = 1000;  // Max out-of-order messages
    std::chrono::seconds session_timeout{3600};  // 1 hour
    std::chrono::seconds key_rotation_interval{300};  // 5 minutes
    bool enable_padding = true;         // Pad messages to hide length
};

/**
 * @brief End-to-End encryption session
 */
class E2ESession {
public:
    explicit E2ESession(const E2EConfig& config = E2EConfig{});
    ~E2ESession();

    // Non-copyable
    E2ESession(const E2ESession&) = delete;
    E2ESession& operator=(const E2ESession&) = delete;

    // Key exchange - initiator side
    KeyPair generate_key_pair();
    std::vector<uint8_t> create_key_exchange_request(const KeyPair& local_keys);
    
    // Key exchange - responder side
    std::vector<uint8_t> process_key_exchange_request(
        const std::vector<uint8_t>& request,
        const KeyPair& local_keys
    );
    
    // Complete key exchange
    bool complete_key_exchange(
        const std::vector<uint8_t>& response,
        const KeyPair& local_keys
    );

    // Message encryption/decryption
    EncryptedMessage encrypt(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& associated_data = {}
    );
    
    std::optional<std::vector<uint8_t>> decrypt(
        const EncryptedMessage& encrypted_message
    );

    // Ratcheting for forward secrecy
    void ratchet_sending_chain();
    void ratchet_receiving_chain(const std::vector<uint8_t>& remote_public_key);

    // Session management
    E2ESessionState get_state() const;
    bool is_established() const;
    bool is_expired() const;
    void rotate_keys();
    void revoke_session();
    
    // Session info
    std::string get_session_id() const;
    std::chrono::system_clock::time_point get_last_activity() const;
    uint64_t get_messages_sent() const;
    uint64_t get_messages_received() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

/**
 * @brief E2E encryption manager for multiple sessions
 */
class E2EManager {
public:
    E2EManager();
    ~E2EManager();

    // Session management
    std::shared_ptr<E2ESession> create_session(
        const std::string& peer_id,
        const E2EConfig& config = E2EConfig{}
    );
    
    std::shared_ptr<E2ESession> get_session(const std::string& peer_id);
    void remove_session(const std::string& peer_id);
    void remove_expired_sessions();
    
    std::vector<std::string> get_active_sessions() const;
    size_t get_session_count() const;

    // Key management
    void rotate_all_keys();
    void export_keys(const std::string& filepath, const SecureString& password);
    bool import_keys(const std::string& filepath, const SecureString& password);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

/**
 * @brief Utility functions for E2E encryption
 */
namespace E2EUtils {
    // Key derivation
    SecureMemory derive_key(
        const SecureMemory& input_key_material,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info,
        size_t output_length
    );
    
    // HKDF (HMAC-based Key Derivation Function)
    SecureMemory hkdf_expand(
        const SecureMemory& prk,
        const std::vector<uint8_t>& info,
        size_t length
    );
    
    // Message padding
    std::vector<uint8_t> pad_message(
        const std::vector<uint8_t>& message,
        size_t block_size = 128
    );
    
    std::optional<std::vector<uint8_t>> unpad_message(
        const std::vector<uint8_t>& padded_message
    );
    
    // Serialization
    std::vector<uint8_t> serialize_message(const EncryptedMessage& msg);
    std::optional<EncryptedMessage> deserialize_message(
        const std::vector<uint8_t>& data
    );
}

}  // namespace NCP

#endif  // NCP_E2E_HPP
