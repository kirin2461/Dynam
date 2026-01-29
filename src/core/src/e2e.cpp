#include "../include/ncp_e2e.hpp"
#include <sodium.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace NCP {

// E2ESession::Impl - Private implementation
struct E2ESession::Impl {
    E2EConfig config;
    E2ESessionState state = E2ESessionState::Uninitialized;
    
    // Ratchet state
    RatchetState ratchet;
    
    // Local and remote keys
    KeyPair local_identity_keys;
    SecureMemory remote_identity_public_key;
    KeyPair local_ephemeral_keys;
    SecureMemory remote_ephemeral_public_key;
    
    // Session metadata
    std::string session_id;
    std::chrono::system_clock::time_point last_activity;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;
    
    mutable std::mutex mutex;
    
    Impl(const E2EConfig& cfg) : config(cfg) {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
        last_activity = std::chrono::system_clock::now();
        generate_session_id();
    }
    
    void generate_session_id() {
        std::vector<uint8_t> random_bytes(16);
        randombytes_buf(random_bytes.data(), random_bytes.size());
        
        std::ostringstream oss;
        for (auto byte : random_bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        session_id = oss.str();
    }
};

// E2ESession implementation
E2ESession::E2ESession(const E2EConfig& config)
    : pImpl_(std::make_unique<Impl>(config)) {}

E2ESession::~E2ESession() = default;

KeyPair E2ESession::generate_key_pair() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    KeyPair kp;
    kp.protocol = pImpl_->config.key_exchange;
    kp.created_at = std::chrono::system_clock::now();
    kp.expires_at = kp.created_at + std::chrono::hours(24);
    
    switch (kp.protocol) {
        case KeyExchangeProtocol::X25519:
            kp.public_key = SecureMemory(crypto_box_PUBLICKEYBYTES);
            kp.private_key = SecureMemory(crypto_box_SECRETKEYBYTES);
            crypto_box_keypair(kp.public_key.data(), kp.private_key.data());
            break;
            
        case KeyExchangeProtocol::X448:
        case KeyExchangeProtocol::ECDH_P256:
        case KeyExchangeProtocol::Kyber1024:
            throw std::runtime_error("Key exchange protocol not yet implemented");
    }
    
    return kp;
}

std::vector<uint8_t> E2ESession::create_key_exchange_request(
    const KeyPair& local_keys
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    pImpl_->local_identity_keys = local_keys;
    pImpl_->state = E2ESessionState::KeyExchangeInitiated;
    
    // Create request: [protocol][public_key]
    std::vector<uint8_t> request;
    request.push_back(static_cast<uint8_t>(local_keys.protocol));
    request.insert(request.end(),
                   local_keys.public_key.data(),
                   local_keys.public_key.data() + local_keys.public_key.size());
    
    return request;
}

std::vector<uint8_t> E2ESession::process_key_exchange_request(
    const std::vector<uint8_t>& request,
    const KeyPair& local_keys
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    if (request.empty()) {
        throw std::invalid_argument("Empty key exchange request");
    }
    
    // Parse protocol and remote public key
    KeyExchangeProtocol protocol = static_cast<KeyExchangeProtocol>(request[0]);
    
    pImpl_->local_identity_keys = local_keys;
    pImpl_->remote_identity_public_key = SecureMemory(request.size() - 1);
    std::memcpy(pImpl_->remote_identity_public_key.data(),
                request.data() + 1,
                request.size() - 1);
    
    pImpl_->state = E2ESessionState::KeyExchangeCompleted;
    
    // Create response with local public key
    std::vector<uint8_t> response;
    response.push_back(static_cast<uint8_t>(protocol));
    response.insert(response.end(),
                    local_keys.public_key.data(),
                    local_keys.public_key.data() + local_keys.public_key.size());
    
    // Perform Diffie-Hellman and derive shared secret
    init_ratchet_keys();
    
    return response;
}

bool E2ESession::complete_key_exchange(
    const std::vector<uint8_t>& response,
    const KeyPair& local_keys
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    if (response.size() <= 1) {
        return false;
    }
    
    pImpl_->remote_identity_public_key = SecureMemory(response.size() - 1);
    std::memcpy(pImpl_->remote_identity_public_key.data(),
                response.data() + 1,
                response.size() - 1);
    
    init_ratchet_keys();
    pImpl_->state = E2ESessionState::SessionEstablished;
    
    return true;
}

// Private helper function to initialize ratchet keys
void E2ESession::init_ratchet_keys() {
    // Compute shared secret using X25519
    SecureMemory shared_secret(crypto_scalarmult_BYTES);
    
    if (crypto_scalarmult(
            shared_secret.data(),
            pImpl_->local_identity_keys.private_key.data(),
            pImpl_->remote_identity_public_key.data()) != 0) {
        throw std::runtime_error("Failed to compute shared secret");
    }
    
    // Derive root key and chain key using HKDF
    pImpl_->ratchet.root_key = SecureMemory(32);
    pImpl_->ratchet.chain_key = SecureMemory(32);
    
    // KDF to derive root and chain keys
    unsigned char info[] = "NCP_E2E_INIT";
    crypto_kdf_derive_from_key(
        pImpl_->ratchet.root_key.data(), 32,
        1, (const char*)info,
        shared_secret.data());
    crypto_kdf_derive_from_key(
        pImpl_->ratchet.chain_key.data(), 32,
        2, (const char*)info,
        shared_secret.data());
    
    pImpl_->ratchet.sending_chain_length = 0;
    pImpl_->ratchet.receiving_chain_length = 0;
}

EncryptedMessage E2ESession::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& associated_data
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        throw std::runtime_error("Session not established");
    }
    
    EncryptedMessage msg;
    msg.header.version = 1;
    msg.header.message_number = pImpl_->ratchet.sending_chain_length++;
    msg.header.associated_data = associated_data;
    
    // Generate nonce
    msg.header.nonce.resize(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.header.nonce.data(), msg.header.nonce.size());
    
    // Derive message key from chain key
    SecureMemory message_key(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    unsigned char info[] = "NCP_MSG_KEY";
    crypto_kdf_derive_from_key(
        message_key.data(), message_key.size(),
        msg.header.message_number, (const char*)info,
        pImpl_->ratchet.chain_key.data());
    
    // Encrypt with ChaCha20-Poly1305
    msg.ciphertext.resize(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;
    
    crypto_aead_chacha20poly1305_ietf_encrypt(
        msg.ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        associated_data.data(), associated_data.size(),
        nullptr,
        msg.header.nonce.data(),
        message_key.data());
    
    msg.ciphertext.resize(ciphertext_len);
    pImpl_->messages_sent++;
    pImpl_->last_activity = std::chrono::system_clock::now();
    
    return msg;
}

std::optional<std::vector<uint8_t>> E2ESession::decrypt(
    const EncryptedMessage& encrypted_message
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        return std::nullopt;
    }
    
    // Derive message key
    SecureMemory message_key(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    unsigned char info[] = "NCP_MSG_KEY";
    crypto_kdf_derive_from_key(
        message_key.data(), message_key.size(),
        encrypted_message.header.message_number, (const char*)info,
        pImpl_->ratchet.chain_key.data());
    
    // Decrypt with ChaCha20-Poly1305
    std::vector<uint8_t> plaintext(
        encrypted_message.ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;
    
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            encrypted_message.ciphertext.data(),
            encrypted_message.ciphertext.size(),
            encrypted_message.header.associated_data.data(),
            encrypted_message.header.associated_data.size(),
            encrypted_message.header.nonce.data(),
            message_key.data()) != 0) {
        return std::nullopt;  // Decryption failed
    }
    
    plaintext.resize(plaintext_len);
    pImpl_->messages_received++;
    pImpl_->last_activity = std::chrono::system_clock::now();
    
    return plaintext;
}

void E2ESession::ratchet_sending_chain() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    SecureMemory new_chain_key(32);
    unsigned char info[] = "NCP_RATCHET";
    crypto_kdf_derive_from_key(
        new_chain_key.data(), 32,
        pImpl_->ratchet.sending_chain_length, (const char*)info,
        pImpl_->ratchet.chain_key.data());
    
    pImpl_->ratchet.chain_key = std::move(new_chain_key);
    pImpl_->ratchet.sending_chain_length = 0;
}

void E2ESession::ratchet_receiving_chain(
    const std::vector<uint8_t>& remote_public_key
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    
    // Update remote ephemeral key
    pImpl_->remote_ephemeral_public_key = SecureMemory(remote_public_key.size());
    std::memcpy(pImpl_->remote_ephemeral_public_key.data(),
                remote_public_key.data(),
                remote_public_key.size());
    
    // Generate new ephemeral key pair
    pImpl_->local_ephemeral_keys.public_key = SecureMemory(crypto_box_PUBLICKEYBYTES);
    pImpl_->local_ephemeral_keys.private_key = SecureMemory(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(
        pImpl_->local_ephemeral_keys.public_key.data(),
        pImpl_->local_ephemeral_keys.private_key.data());
    
    // Compute new shared secret
    SecureMemory shared_secret(crypto_scalarmult_BYTES);
    crypto_scalarmult(
        shared_secret.data(),
        pImpl_->local_ephemeral_keys.private_key.data(),
        pImpl_->remote_ephemeral_public_key.data());
    
    // Derive new chain key
    unsigned char info[] = "NCP_RATCHET";
    crypto_kdf_derive_from_key(
        pImpl_->ratchet.chain_key.data(), 32,
        1, (const char*)info,
        shared_secret.data());
    
    pImpl_->ratchet.receiving_chain_length = 0;
}

// Session management functions
E2ESessionState E2ESession::get_state() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->state;
}

bool E2ESession::is_established() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->state == E2ESessionState::SessionEstablished;
}

bool E2ESession::is_expired() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto now = std::chrono::system_clock::now();
    return (now - pImpl_->last_activity) > pImpl_->config.session_timeout;
}

void E2ESession::rotate_keys() {
    ratchet_sending_chain();
}

void E2ESession::revoke_session() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->state = E2ESessionState::SessionRevoked;
    pImpl_->ratchet.root_key.zero();
    pImpl_->ratchet.chain_key.zero();
}

std::string E2ESession::get_session_id() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->session_id;
}

std::chrono::system_clock::time_point E2ESession::get_last_activity() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->last_activity;
}

uint64_t E2ESession::get_messages_sent() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->messages_sent;
}

uint64_t E2ESession::get_messages_received() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->messages_received;
}

// E2EManager implementation
struct E2EManager::Impl {
    std::unordered_map<std::string, std::shared_ptr<E2ESession>> sessions;
    mutable std::mutex mutex;
};

E2EManager::E2EManager() : pImpl_(std::make_unique<Impl>()) {}
E2EManager::~E2EManager() = default;

std::shared_ptr<E2ESession> E2EManager::create_session(
    const std::string& peer_id,
    const E2EConfig& config
) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto session = std::make_shared<E2ESession>(config);
    pImpl_->sessions[peer_id] = session;
    return session;
}

std::shared_ptr<E2ESession> E2EManager::get_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto it = pImpl_->sessions.find(peer_id);
    return (it != pImpl_->sessions.end()) ? it->second : nullptr;
}

void E2EManager::remove_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->sessions.erase(peer_id);
}

void E2EManager::remove_expired_sessions() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    for (auto it = pImpl_->sessions.begin(); it != pImpl_->sessions.end(); ) {
        if (it->second->is_expired()) {
            it = pImpl_->sessions.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<std::string> E2EManager::get_active_sessions() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<std::string> result;
    result.reserve(pImpl_->sessions.size());
    for (const auto& [peer_id, session] : pImpl_->sessions) {
        if (session->is_established()) {
            result.push_back(peer_id);
        }
    }
    return result;
}

size_t E2EManager::get_session_count() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->sessions.size();
}

void E2EManager::rotate_all_keys() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    for (auto& [peer_id, session] : pImpl_->sessions) {
        session->rotate_keys();
    }
}

void E2EManager::export_keys(
    const std::string& filepath,
    const SecureString& password
) {
    // Export encrypted key bundle (not implemented for security)
    throw std::runtime_error("Key export requires additional security review");
}

bool E2EManager::import_keys(
    const std::string& filepath,
    const SecureString& password
) {
    // Import encrypted key bundle (not implemented for security)
    throw std::runtime_error("Key import requires additional security review");
}

// E2EUtils namespace implementation
namespace E2EUtils {

SecureMemory derive_key(
    const SecureMemory& input_key_material,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t output_length
) {
    SecureMemory output(output_length);
    
    // Use HKDF with SHA-256
    crypto_auth_hmacsha256_state state;
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    
    // Extract
    crypto_auth_hmacsha256_init(&state, salt.data(), salt.size());
    crypto_auth_hmacsha256_update(&state, input_key_material.data(), input_key_material.size());
    crypto_auth_hmacsha256_final(&state, prk);
    
    // Expand
    size_t done = 0;
    uint8_t counter = 1;
    unsigned char prev[crypto_auth_hmacsha256_BYTES] = {0};
    
    while (done < output_length) {
        crypto_auth_hmacsha256_init(&state, prk, sizeof(prk));
        if (counter > 1) {
            crypto_auth_hmacsha256_update(&state, prev, sizeof(prev));
        }
        crypto_auth_hmacsha256_update(&state, info.data(), info.size());
        crypto_auth_hmacsha256_update(&state, &counter, 1);
        crypto_auth_hmacsha256_final(&state, prev);
        
        size_t to_copy = std::min(sizeof(prev), output_length - done);
        std::memcpy(output.data() + done, prev, to_copy);
        done += to_copy;
        counter++;
    }
    
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(prev, sizeof(prev));
    
    return output;
}

SecureMemory hkdf_expand(
    const SecureMemory& prk,
    const std::vector<uint8_t>& info,
    size_t length
) {
    return derive_key(prk, {}, info, length);
}

std::vector<uint8_t> pad_message(
    const std::vector<uint8_t>& message,
    size_t block_size
) {
    size_t padding_length = block_size - (message.size() % block_size);
    if (padding_length == 0) padding_length = block_size;
    
    std::vector<uint8_t> padded(message.size() + padding_length);
    std::memcpy(padded.data(), message.data(), message.size());
    
    // PKCS#7 padding
    std::memset(padded.data() + message.size(),
                static_cast<uint8_t>(padding_length),
                padding_length);
    
    return padded;
}

std::optional<std::vector<uint8_t>> unpad_message(
    const std::vector<uint8_t>& padded_message
) {
    if (padded_message.empty()) {
        return std::nullopt;
    }
    
    uint8_t padding_length = padded_message.back();
    
    if (padding_length == 0 || padding_length > padded_message.size()) {
        return std::nullopt;
    }
    
    // Verify padding
    for (size_t i = padded_message.size() - padding_length;
         i < padded_message.size(); ++i) {
        if (padded_message[i] != padding_length) {
            return std::nullopt;
        }
    }
    
    return std::vector<uint8_t>(
        padded_message.begin(),
        padded_message.end() - padding_length);
}

std::vector<uint8_t> serialize_message(const EncryptedMessage& msg) {
    std::vector<uint8_t> result;
    
    // Header
    result.push_back(msg.header.version);
    
    // Message number (4 bytes, big endian)
    result.push_back((msg.header.message_number >> 24) & 0xFF);
    result.push_back((msg.header.message_number >> 16) & 0xFF);
    result.push_back((msg.header.message_number >> 8) & 0xFF);
    result.push_back(msg.header.message_number & 0xFF);
    
    // Nonce length and data
    result.push_back(static_cast<uint8_t>(msg.header.nonce.size()));
    result.insert(result.end(), msg.header.nonce.begin(), msg.header.nonce.end());
    
    // Ciphertext length (4 bytes) and data
    uint32_t ct_len = static_cast<uint32_t>(msg.ciphertext.size());
    result.push_back((ct_len >> 24) & 0xFF);
    result.push_back((ct_len >> 16) & 0xFF);
    result.push_back((ct_len >> 8) & 0xFF);
    result.push_back(ct_len & 0xFF);
    result.insert(result.end(), msg.ciphertext.begin(), msg.ciphertext.end());
    
    return result;
}

std::optional<EncryptedMessage> deserialize_message(
    const std::vector<uint8_t>& data
) {
    if (data.size() < 10) return std::nullopt;
    
    EncryptedMessage msg;
    size_t pos = 0;
    
    msg.header.version = data[pos++];
    msg.header.message_number = (data[pos] << 24) | (data[pos+1] << 16) |
                                (data[pos+2] << 8) | data[pos+3];
    pos += 4;
    
    size_t nonce_len = data[pos++];
    if (pos + nonce_len > data.size()) return std::nullopt;
    msg.header.nonce.assign(data.begin() + pos, data.begin() + pos + nonce_len);
    pos += nonce_len;
    
    if (pos + 4 > data.size()) return std::nullopt;
    uint32_t ct_len = (data[pos] << 24) | (data[pos+1] << 16) |
                      (data[pos+2] << 8) | data[pos+3];
    pos += 4;
    
    if (pos + ct_len > data.size()) return std::nullopt;
    msg.ciphertext.assign(data.begin() + pos, data.begin() + pos + ct_len);
    
    return msg;
}

}  // namespace E2EUtils

}  // namespace NCP
