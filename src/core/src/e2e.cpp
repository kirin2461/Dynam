#include "../include/ncp_e2e.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cstring>
#include <algorithm>

// OpenSSL for X448 and ECDH_P256
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

// ==================== Impl ====================

struct E2ESession::Impl {
    E2EConfig config;
    std::mutex mutex;
    std::string session_id;
    E2ESessionState state = E2ESessionState::Uninitialized;
    std::chrono::system_clock::time_point last_activity;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;

    // Shared secret established during key exchange
    SecureMemory shared_secret;

    // Double Ratchet state
    RatchetState ratchet;
    KeyPair local_ratchet_kp;            // Current sending ratchet DH keypair
    std::vector<uint8_t> remote_ratchet_pub; // Last received remote ratchet public key
    bool ratchet_initialized = false;

    explicit Impl(const E2EConfig& cfg) : config(cfg) {
        generate_session_id();
        last_activity = std::chrono::system_clock::now();
    }

    void generate_session_id() {
        uint8_t id_bytes[16];
        randombytes_buf(id_bytes, sizeof(id_bytes));
        std::ostringstream oss;
        for (int i = 0; i < 16; ++i)
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(id_bytes[i]);
        session_id = oss.str();
    }

    // ===== KDF: Root Key Ratchet =====
    // Derives new_root_key and new_chain_key from current root_key + DH output
    void kdf_rk(const SecureMemory& root_key, const SecureMemory& dh_output,
                SecureMemory& new_root_key, SecureMemory& new_chain_key) {
        uint8_t prk[crypto_auth_hmacsha512256_BYTES];
        crypto_auth_hmacsha512256_state st;
        crypto_auth_hmacsha512256_init(&st, root_key.data(), root_key.size());
        crypto_auth_hmacsha512256_update(&st, dh_output.data(), dh_output.size());
        crypto_auth_hmacsha512256_final(&st, prk);

        new_root_key = SecureMemory(32);
        new_chain_key = SecureMemory(32);

        uint8_t info_rk = 0x01;
        crypto_generichash(new_root_key.data(), 32, prk, sizeof(prk), &info_rk, 1);
        uint8_t info_ck = 0x02;
        crypto_generichash(new_chain_key.data(), 32, prk, sizeof(prk), &info_ck, 1);

        sodium_memzero(prk, sizeof(prk));
    }

    // ===== KDF: Chain Key Ratchet =====
    // Derives a message_key and advances chain_key in-place
    void kdf_ck(SecureMemory& chain_key, SecureMemory& message_key) {
        message_key = SecureMemory(32);
        SecureMemory new_ck(32);

        uint8_t derive_mk = 0x01;
        crypto_auth_hmacsha512256_state st;
        crypto_auth_hmacsha512256_init(&st, chain_key.data(), chain_key.size());
        crypto_auth_hmacsha512256_update(&st, &derive_mk, 1);
        uint8_t mk_buf[crypto_auth_hmacsha512256_BYTES];
        crypto_auth_hmacsha512256_final(&st, mk_buf);
        std::memcpy(message_key.data(), mk_buf, 32);

        uint8_t derive_ck = 0x02;
        crypto_auth_hmacsha512256_init(&st, chain_key.data(), chain_key.size());
        crypto_auth_hmacsha512256_update(&st, &derive_ck, 1);
        uint8_t ck_buf[crypto_auth_hmacsha512256_BYTES];
        crypto_auth_hmacsha512256_final(&st, ck_buf);
        std::memcpy(new_ck.data(), ck_buf, 32);

        chain_key = std::move(new_ck);

        sodium_memzero(mk_buf, sizeof(mk_buf));
        sodium_memzero(ck_buf, sizeof(ck_buf));
    }

    // ===== DH Ratchet Step =====
    // Called when we receive a new remote ratchet public key
    void dh_ratchet_step(const std::vector<uint8_t>& new_remote_pub) {
        remote_ratchet_pub = new_remote_pub;

        // DH with our current private key and their new public key → receive chain
        SecureMemory dh_recv(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(dh_recv.data(),
                              local_ratchet_kp.private_key.data(),
                              new_remote_pub.data()) != 0) {
            return; // DH failed
        }

        SecureMemory new_root, new_recv_chain;
        kdf_rk(ratchet.root_key, dh_recv, new_root, new_recv_chain);
        ratchet.root_key = std::move(new_root);

        // Store previous sending chain length for header
        ratchet.previous_chain_length = ratchet.sending_chain_length;
        ratchet.receiving_chain_length = 0;

        // Save the new receiving chain key (we'll use it for decryption)
        // We re-use chain_key temporarily for receiving;
        // for a production impl, you'd have separate send/recv chain keys.
        // Here we do a second DH step to get a new sending chain:

        // Generate new sending keypair
        local_ratchet_kp.public_key = SecureMemory(crypto_scalarmult_BYTES);
        local_ratchet_kp.private_key = SecureMemory(crypto_scalarmult_SCALARBYTES);
        crypto_box_keypair(local_ratchet_kp.public_key.data(),
                           local_ratchet_kp.private_key.data());
        local_ratchet_kp.created_at = std::chrono::system_clock::now();

        // DH with new private key and their public key → sending chain
        SecureMemory dh_send(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(dh_send.data(),
                              local_ratchet_kp.private_key.data(),
                              new_remote_pub.data()) != 0) {
            return;
        }

        SecureMemory new_root2, new_send_chain;
        kdf_rk(ratchet.root_key, dh_send, new_root2, new_send_chain);
        ratchet.root_key = std::move(new_root2);
        ratchet.chain_key = std::move(new_send_chain);
        ratchet.sending_chain_length = 0;
    }

    // ===== Skipped Message Keys =====
    // Pre-compute and store message keys for gaps in counter
    bool skip_message_keys(SecureMemory& recv_chain_key, uint32_t& recv_counter,
                           uint32_t until) {
        if (until < recv_counter) return false;
        if (until - recv_counter > config.max_skip_messages) return false;

        while (recv_counter < until) {
            SecureMemory mk;
            kdf_ck(recv_chain_key, mk);
            ratchet.skipped_keys[recv_counter] = std::move(mk);
            recv_counter++;
        }
        return true;
    }

    // Try to decrypt using a previously skipped message key
    bool try_skipped_message_keys(uint32_t msg_number, SecureMemory& out_key) {
        auto it = ratchet.skipped_keys.find(msg_number);
        if (it == ratchet.skipped_keys.end()) return false;
        out_key = std::move(it->second);
        ratchet.skipped_keys.erase(it);
        return true;
    }
};

// ==================== Constructor / Destructor ====================

E2ESession::E2ESession(const E2EConfig& config)
    : pImpl_(std::make_unique<Impl>(config)) {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
}

E2ESession::~E2ESession() = default;

// ===== Phase 2.3: generate_key_pair() — X448 + ECDH_P256 implementation =====
// ==================== Key Pair Generation ====================

KeyPair E2ESession::generate_key_pair() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    KeyPair kp;
    kp.protocol = pImpl_->config.key_exchange;

    switch (kp.protocol) {
        case KeyExchangeProtocol::X25519: {
            kp.public_key = SecureMemory(crypto_scalarmult_BYTES);
            kp.private_key = SecureMemory(crypto_scalarmult_SCALARBYTES);
            crypto_box_keypair(kp.public_key.data(), kp.private_key.data());
            break;

        case KeyExchangeProtocol::X448: {
            // X448 key generation via OpenSSL EVP API
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr);
            if (!pctx) {
                throw std::runtime_error("Failed to create X448 context");
            }

            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to initialize X448 keygen");
            }

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to generate X448 keypair");
            }
            EVP_PKEY_CTX_free(pctx);

            // Extract raw public key (56 bytes for X448)
            size_t pubkey_len = 56;
            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract X448 public key");
            }
            kp.public_key.resize(pubkey_len);

            // Extract raw private key (56 bytes for X448)
            size_t privkey_len = 56;
            kp.private_key = SecureMemory(privkey_len);
            if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &privkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract X448 private key");
            }
            kp.private_key.resize(privkey_len);

            EVP_PKEY_free(pkey);
            break;
        }

        case KeyExchangeProtocol::ECDH_P256: {
            // ECDH P-256 key generation via OpenSSL EVP API
            EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
            if (!pctx) {
                throw std::runtime_error("Failed to create ECDH P-256 context");
            }

            if (EVP_PKEY_keygen_init(pctx) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to initialize ECDH P-256 keygen");
            }

            // Set curve to P-256 (NID_X9_62_prime256v1)
            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to set ECDH P-256 curve");
            }

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
                EVP_PKEY_CTX_free(pctx);
                throw std::runtime_error("Failed to generate ECDH P-256 keypair");
            }
            EVP_PKEY_CTX_free(pctx);

            // Extract public key (uncompressed point: 0x04 + 32 bytes X + 32 bytes Y = 65 bytes)
            size_t pubkey_len = 0;
            if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to query ECDH P-256 public key size");
            }

            kp.public_key = SecureMemory(pubkey_len);
            if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pubkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract ECDH P-256 public key");
            }

            // Extract private key (32 bytes scalar)
            size_t privkey_len = 0;
            if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &privkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to query ECDH P-256 private key size");
            }

            kp.private_key = SecureMemory(privkey_len);
            if (EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &privkey_len) <= 0) {
                EVP_PKEY_free(pkey);
                throw std::runtime_error("Failed to extract ECDH P-256 private key");
            }

            EVP_PKEY_free(pkey);
            break;
        }

        case KeyExchangeProtocol::Kyber1024:
        }
#ifdef HAVE_LIBOQS
        case KeyExchangeProtocol::Kyber1024: {
            OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
            if (!kem) throw std::runtime_error("Kyber1024 not available");
            kp.public_key = SecureMemory(kem->length_public_key);
            kp.private_key = SecureMemory(kem->length_secret_key);
            OQS_KEM_keypair(kem, kp.public_key.data(), kp.private_key.data());
            OQS_KEM_free(kem);
            break;
        }
#endif
        default:
            throw std::runtime_error("Unsupported key exchange protocol");
    }

    kp.created_at = std::chrono::system_clock::now();
    kp.expires_at = kp.created_at + pImpl_->config.session_timeout;
    return kp;
}

// ===== Phase 2.3: compute_shared_secret() — X448 + ECDH_P256 implementation =====
// ==================== Shared Secret ====================

SecureMemory E2ESession::compute_shared_secret(
    const KeyPair& local_keypair,
    const std::vector<uint8_t>& peer_public_key) {

    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    switch (local_keypair.protocol) {
        case KeyExchangeProtocol::X25519: {
            SecureMemory shared(crypto_scalarmult_BYTES);
            if (crypto_scalarmult(shared.data(),
                                  local_keypair.private_key.data(),
                                  peer_public_key.data()) != 0) {
                throw std::runtime_error("X25519 scalar multiplication failed");
            }
            return shared;
        }

        case KeyExchangeProtocol::X448: {
            // X448 shared secret computation via OpenSSL EVP_PKEY_derive
            if (peer_public_key.size() != 56) {
                throw std::runtime_error("Invalid peer public key size for X448 (expected 56 bytes)");
            }

            // Load local private key
            EVP_PKEY* local_pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, nullptr,
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            );
            if (!local_pkey) {
                throw std::runtime_error("Failed to load X448 local private key");
            }

            // Load peer public key
            EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X448, nullptr,
                peer_public_key.data(),
                peer_public_key.size()
            );
            if (!peer_pkey) {
                EVP_PKEY_free(local_pkey);
                throw std::runtime_error("Failed to load X448 peer public key");
            }

            // Derive shared secret
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_pkey, nullptr);
            if (!ctx) {
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to create X448 derive context");
            }

            if (EVP_PKEY_derive_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to initialize X448 derive");
            }

            if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to set X448 peer key");
            }

            size_t secret_len = 0;
            if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to query X448 shared secret size");
            }

            SecureMemory shared_secret(secret_len);
            if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to derive X448 shared secret");
            }

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(local_pkey);
            EVP_PKEY_free(peer_pkey);

            return shared_secret;
        }

        case KeyExchangeProtocol::ECDH_P256: {
            // ECDH P-256 shared secret computation via OpenSSL EVP_PKEY_derive
            if (peer_public_key.size() != 65) {  // Uncompressed point: 0x04 + 32 + 32
                throw std::runtime_error("Invalid peer public key size for ECDH P-256 (expected 65 bytes)");
            }

            // Load local private key
            EVP_PKEY* local_pkey = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_EC, nullptr,
                local_keypair.private_key.data(),
                local_keypair.private_key.size()
            );
            if (!local_pkey) {
                throw std::runtime_error("Failed to load ECDH P-256 local private key");
            }

            // Load peer public key
            EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_EC, nullptr,
                peer_public_key.data(),
                peer_public_key.size()
            );
            if (!peer_pkey) {
                EVP_PKEY_free(local_pkey);
                throw std::runtime_error("Failed to load ECDH P-256 peer public key");
            }

            // Derive shared secret
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(local_pkey, nullptr);
            if (!ctx) {
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to create ECDH P-256 derive context");
            }

            if (EVP_PKEY_derive_init(ctx) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to initialize ECDH P-256 derive");
            }

            if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to set ECDH P-256 peer key");
            }

            size_t secret_len = 0;
            if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to query ECDH P-256 shared secret size");
            }

            SecureMemory shared_secret(secret_len);
            if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                EVP_PKEY_free(local_pkey);
                EVP_PKEY_free(peer_pkey);
                throw std::runtime_error("Failed to derive ECDH P-256 shared secret");
            }

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(local_pkey);
            EVP_PKEY_free(peer_pkey);

            return shared_secret;
        }

        case KeyExchangeProtocol::Kyber1024:
#ifdef HAVE_LIBOQS
        case KeyExchangeProtocol::Kyber1024: {
            OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
            if (!kem) throw std::runtime_error("Kyber1024 not available");
            SecureMemory shared(kem->length_shared_secret);
            if (OQS_KEM_decaps(kem, shared.data(),
                               peer_public_key.data(),
                               local_keypair.private_key.data()) != OQS_SUCCESS) {
                OQS_KEM_free(kem);
                throw std::runtime_error("Kyber1024 decapsulation failed");
            }
            OQS_KEM_free(kem);
            return shared;
        }
#endif
        default:
            throw std::runtime_error("Unsupported key exchange protocol");
    }
}

SecureMemory E2ESession::derive_keys(
    const SecureMemory& shared_secret,
    const std::string& context,
    size_t key_length) {

    SecureMemory derived(key_length);
    std::vector<uint8_t> ctx(context.begin(), context.end());

    crypto_generichash(derived.data(), key_length,
                       shared_secret.data(), shared_secret.size(),
                       ctx.data(), ctx.size());
    return derived;
}

// ==================== Init Ratchet ====================

void E2ESession::init_ratchet_keys() {
    auto& impl = *pImpl_;

    if (impl.shared_secret.size() == 0) return;

    // Derive initial root key and chain key from shared secret via HKDF
    impl.ratchet.root_key = SecureMemory(32);
    impl.ratchet.chain_key = SecureMemory(32);

    uint8_t salt[32] = {0}; // Zero salt for initial derivation
    uint8_t info_root[] = "NCP-DR-ROOT-v1";
    uint8_t info_chain[] = "NCP-DR-CHAIN-v1";

    crypto_generichash(impl.ratchet.root_key.data(), 32,
                       impl.shared_secret.data(), impl.shared_secret.size(),
                       info_root, sizeof(info_root) - 1);

    crypto_generichash(impl.ratchet.chain_key.data(), 32,
                       impl.shared_secret.data(), impl.shared_secret.size(),
                       info_chain, sizeof(info_chain) - 1);

    // Generate initial ratchet keypair
    impl.local_ratchet_kp.public_key = SecureMemory(crypto_scalarmult_BYTES);
    impl.local_ratchet_kp.private_key = SecureMemory(crypto_scalarmult_SCALARBYTES);
    crypto_box_keypair(impl.local_ratchet_kp.public_key.data(),
                       impl.local_ratchet_kp.private_key.data());
    impl.local_ratchet_kp.protocol = KeyExchangeProtocol::X25519;
    impl.local_ratchet_kp.created_at = std::chrono::system_clock::now();

    impl.ratchet.sending_chain_length = 0;
    impl.ratchet.receiving_chain_length = 0;
    impl.ratchet.previous_chain_length = 0;
    impl.ratchet.skipped_keys.clear();

    impl.ratchet_initialized = true;
}

// ==================== Key Exchange ====================

std::vector<uint8_t> E2ESession::create_key_exchange_request(const KeyPair& local_keys) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->state = E2ESessionState::KeyExchangeInitiated;
    pImpl_->last_activity = std::chrono::system_clock::now();

    std::vector<uint8_t> request;
    request.push_back(0x01); // Version
    request.push_back(static_cast<uint8_t>(local_keys.protocol));

    uint16_t pk_len = static_cast<uint16_t>(local_keys.public_key.size());
    request.push_back((pk_len >> 8) & 0xFF);
    request.push_back(pk_len & 0xFF);
    request.insert(request.end(),
                   local_keys.public_key.data(),
                   local_keys.public_key.data() + local_keys.public_key.size());

    return request;
}

std::vector<uint8_t> E2ESession::process_key_exchange_request(
    const std::vector<uint8_t>& request,
    const KeyPair& local_keys) {

    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    if (request.size() < 4) {
        throw std::runtime_error("Invalid key exchange request");
    }

    uint16_t pk_len = (request[2] << 8) | request[3];
    if (request.size() < 4u + pk_len) {
        throw std::runtime_error("Key exchange request too short");
    }

    std::vector<uint8_t> peer_public(request.begin() + 4, request.begin() + 4 + pk_len);

    // Compute shared secret
    pImpl_->shared_secret = compute_shared_secret(local_keys, peer_public);

    // Store remote ratchet public key
    pImpl_->remote_ratchet_pub = peer_public;

    // Initialize ratchet
    init_ratchet_keys();

    pImpl_->state = E2ESessionState::SessionEstablished;
    pImpl_->last_activity = std::chrono::system_clock::now();

    // Build response with our public key
    std::vector<uint8_t> response;
    response.push_back(0x02); // Version/response marker
    response.push_back(static_cast<uint8_t>(local_keys.protocol));
    uint16_t our_pk_len = static_cast<uint16_t>(local_keys.public_key.size());
    response.push_back((our_pk_len >> 8) & 0xFF);
    response.push_back(our_pk_len & 0xFF);
    response.insert(response.end(),
                    local_keys.public_key.data(),
                    local_keys.public_key.data() + local_keys.public_key.size());
    return response;
}

bool E2ESession::complete_key_exchange(
    const std::vector<uint8_t>& response,
    const KeyPair& local_keys) {

    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    if (response.size() < 4) return false;
    uint16_t pk_len = (response[2] << 8) | response[3];
    if (response.size() < 4u + pk_len) return false;

    std::vector<uint8_t> peer_public(response.begin() + 4, response.begin() + 4 + pk_len);

    pImpl_->shared_secret = compute_shared_secret(local_keys, peer_public);
    pImpl_->remote_ratchet_pub = peer_public;

    init_ratchet_keys();

    pImpl_->state = E2ESessionState::SessionEstablished;
    pImpl_->last_activity = std::chrono::system_clock::now();
    return true;
}

// ==================== Low-level Encrypt/Decrypt ====================

EncryptedMessage E2ESession::encrypt_message(
    const std::vector<uint8_t>& plaintext,
    const SecureMemory& encryption_key) {

    EncryptedMessage msg;
    msg.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.nonce.data(), msg.nonce.size());

    msg.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    unsigned long long ciphertext_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        msg.ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        nullptr, 0,  // no additional data for low-level API
        nullptr,
        msg.nonce.data(),
        encryption_key.data());

    msg.ciphertext.resize(static_cast<size_t>(ciphertext_len));
    msg.timestamp = std::chrono::system_clock::now();
    return msg;
}

std::vector<uint8_t> E2ESession::decrypt_message(
    const EncryptedMessage& message,
    const SecureMemory& decryption_key) {

    std::vector<uint8_t> plaintext(message.ciphertext.size());
    unsigned long long plaintext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            message.ciphertext.data(), message.ciphertext.size(),
            nullptr, 0,
            message.nonce.data(),
            decryption_key.data()) != 0) {
        throw std::runtime_error("Decryption failed: authentication error");
    }

    plaintext.resize(static_cast<size_t>(plaintext_len));
    return plaintext;
}

// ==================== Ratcheting Encrypt ====================

EncryptedMessage E2ESession::encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& associated_data) {

    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        throw std::runtime_error("Session not established");
    }
    if (!pImpl_->ratchet_initialized) {
        throw std::runtime_error("Ratchet not initialized");
    }

    // Derive per-message key from sending chain
    SecureMemory message_key;
    pImpl_->kdf_ck(pImpl_->ratchet.chain_key, message_key);

    // Build header
    MessageHeader hdr;
    hdr.version = 1;
    hdr.message_number = pImpl_->ratchet.sending_chain_length;
    hdr.previous_chain_length = pImpl_->ratchet.previous_chain_length;
    hdr.dh_public_key.assign(
        pImpl_->local_ratchet_kp.public_key.data(),
        pImpl_->local_ratchet_kp.public_key.data() +
            pImpl_->local_ratchet_kp.public_key.size());
    hdr.associated_data = associated_data;

    pImpl_->ratchet.sending_chain_length++;

    // Pad plaintext
    std::vector<uint8_t> padded = plaintext;
    if (pImpl_->config.enable_padding) {
        padded = E2EUtils::pad_message(plaintext, 128);
    }

    // Encrypt with XChaCha20-Poly1305
    EncryptedMessage msg;
    msg.header = hdr;
    msg.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.nonce.data(), msg.nonce.size());

    // Build AAD: header fields + user-provided associated_data
    std::vector<uint8_t> aad;
    aad.push_back(hdr.version);
    uint32_t mn = hdr.message_number;
    aad.push_back((mn >> 24) & 0xFF); aad.push_back((mn >> 16) & 0xFF);
    aad.push_back((mn >> 8) & 0xFF);  aad.push_back(mn & 0xFF);
    aad.insert(aad.end(), hdr.dh_public_key.begin(), hdr.dh_public_key.end());
    aad.insert(aad.end(), associated_data.begin(), associated_data.end());

    msg.ciphertext.resize(padded.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
        msg.ciphertext.data(), &ct_len,
        padded.data(), padded.size(),
        aad.data(), aad.size(),
        nullptr,
        msg.nonce.data(),
        message_key.data());

    msg.ciphertext.resize(static_cast<size_t>(ct_len));
    msg.timestamp = std::chrono::system_clock::now();

    pImpl_->messages_sent++;
    pImpl_->last_activity = std::chrono::system_clock::now();

    return msg;
}

// ==================== Ratcheting Decrypt ====================

std::optional<std::vector<uint8_t>> E2ESession::decrypt(
    const EncryptedMessage& encrypted_message) {

    std::lock_guard<std::mutex> lock(pImpl_->mutex);

    if (pImpl_->state != E2ESessionState::SessionEstablished) {
        return std::nullopt;
    }
    if (!pImpl_->ratchet_initialized) {
        return std::nullopt;
    }

    const auto& hdr = encrypted_message.header;
    uint32_t msg_num = hdr.message_number;

    // 1. Try skipped message keys (out-of-order messages)
    SecureMemory skipped_key;
    if (pImpl_->try_skipped_message_keys(msg_num, skipped_key)) {
        return decrypt_with_key_(encrypted_message, skipped_key);
    }

    // 2. Check if remote sent a new DH public key → DH ratchet step
    bool new_ratchet = false;
    if (!hdr.dh_public_key.empty() &&
        hdr.dh_public_key != pImpl_->remote_ratchet_pub) {

        // Skip any message keys we haven't received yet on current receiving chain
        // (We need a separate receiving chain key for this; for simplicity we
        // derive it from root + remote's old key. In a full implementation
        // you'd store send_chain and recv_chain separately.)

        new_ratchet = true;
        pImpl_->dh_ratchet_step(hdr.dh_public_key);
    }

    // 3. Skip message keys up to msg_num if there's a gap
    if (msg_num > pImpl_->ratchet.receiving_chain_length) {
        // We need to advance the receiving chain key. Since in our simplified
        // model chain_key is the sending chain after DH ratchet, and the
        // receiving chain is derived inside dh_ratchet_step, we skip on
        // the current chain_key for now:
        SecureMemory recv_ck = SecureMemory(32);
        // Derive a temporary receiving chain key from root + remote pub
        uint8_t info_recv[] = "NCP-DR-RECV-v1";
        crypto_generichash(recv_ck.data(), 32,
                           pImpl_->ratchet.root_key.data(),
                           pImpl_->ratchet.root_key.size(),
                           info_recv, sizeof(info_recv) - 1);

        uint32_t counter = pImpl_->ratchet.receiving_chain_length;
        if (!pImpl_->skip_message_keys(recv_ck, counter, msg_num)) {
            return std::nullopt; // Too many skipped messages
        }
        pImpl_->ratchet.receiving_chain_length = counter;
    }

    // 4. Derive the message key for this message
    SecureMemory recv_chain(32);
    uint8_t info_recv[] = "NCP-DR-RECV-v1";
    crypto_generichash(recv_chain.data(), 32,
                       pImpl_->ratchet.root_key.data(),
                       pImpl_->ratchet.root_key.size(),
                       info_recv, sizeof(info_recv) - 1);

    // Advance receiving chain to get the correct message key
    for (uint32_t i = 0; i <= msg_num - pImpl_->ratchet.receiving_chain_length; ++i) {
        SecureMemory mk;
        pImpl_->kdf_ck(recv_chain, mk);
        if (i + pImpl_->ratchet.receiving_chain_length == msg_num) {
            pImpl_->ratchet.receiving_chain_length = msg_num + 1;
            return decrypt_with_key_(encrypted_message, mk);
        }
    }

    return std::nullopt;
}

std::optional<std::vector<uint8_t>> E2ESession::decrypt_with_key_(
    const EncryptedMessage& msg,
    const SecureMemory& message_key) {

    const auto& hdr = msg.header;

    // Rebuild AAD
    std::vector<uint8_t> aad;
    aad.push_back(hdr.version);
    uint32_t mn = hdr.message_number;
    aad.push_back((mn >> 24) & 0xFF); aad.push_back((mn >> 16) & 0xFF);
    aad.push_back((mn >> 8) & 0xFF);  aad.push_back(mn & 0xFF);
    aad.insert(aad.end(), hdr.dh_public_key.begin(), hdr.dh_public_key.end());
    aad.insert(aad.end(), hdr.associated_data.begin(), hdr.associated_data.end());

    std::vector<uint8_t> plaintext(msg.ciphertext.size());
    unsigned long long pt_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &pt_len,
            nullptr,
            msg.ciphertext.data(), msg.ciphertext.size(),
            aad.data(), aad.size(),
            msg.nonce.data(),
            message_key.data()) != 0) {
        return std::nullopt; // Authentication failed
    }

    plaintext.resize(static_cast<size_t>(pt_len));

    // Unpad
    if (pImpl_->config.enable_padding) {
        auto unpadded = E2EUtils::unpad_message(plaintext);
        if (!unpadded) return std::nullopt;
        plaintext = std::move(*unpadded);
    }

    pImpl_->messages_received++;
    pImpl_->last_activity = std::chrono::system_clock::now();
    return plaintext;
}

// ==================== Public Ratchet API ====================

void E2ESession::ratchet_sending_chain() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (!pImpl_->ratchet_initialized) return;

    SecureMemory mk;
    pImpl_->kdf_ck(pImpl_->ratchet.chain_key, mk);
    pImpl_->ratchet.sending_chain_length++;
    // mk is discarded — this just advances the chain
}

void E2ESession::ratchet_receiving_chain(const std::vector<uint8_t>& remote_public_key) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (!pImpl_->ratchet_initialized) return;

    if (remote_public_key != pImpl_->remote_ratchet_pub) {
        pImpl_->dh_ratchet_step(remote_public_key);
    }
}

// ==================== Session Management ====================

E2ESessionState E2ESession::get_state() const {
    return pImpl_->state;
}

bool E2ESession::is_established() const {
    return pImpl_->state == E2ESessionState::SessionEstablished;
}

bool E2ESession::is_expired() const {
    if (pImpl_->state == E2ESessionState::SessionExpired) return true;
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - pImpl_->last_activity);
    return elapsed > pImpl_->config.session_timeout;
}

void E2ESession::rotate_keys() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (!pImpl_->ratchet_initialized) return;

    // Trigger a DH ratchet step with a synthetic "self-rotation"
    // Generate new keypair and re-derive chains
    pImpl_->local_ratchet_kp.public_key = SecureMemory(crypto_scalarmult_BYTES);
    pImpl_->local_ratchet_kp.private_key = SecureMemory(crypto_scalarmult_SCALARBYTES);
    crypto_box_keypair(pImpl_->local_ratchet_kp.public_key.data(),
                       pImpl_->local_ratchet_kp.private_key.data());
    pImpl_->local_ratchet_kp.created_at = std::chrono::system_clock::now();

    if (!pImpl_->remote_ratchet_pub.empty()) {
        SecureMemory dh_out(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(dh_out.data(),
                              pImpl_->local_ratchet_kp.private_key.data(),
                              pImpl_->remote_ratchet_pub.data()) == 0) {
            SecureMemory new_root, new_chain;
            pImpl_->kdf_rk(pImpl_->ratchet.root_key, dh_out, new_root, new_chain);
            pImpl_->ratchet.root_key = std::move(new_root);
            pImpl_->ratchet.chain_key = std::move(new_chain);
            pImpl_->ratchet.previous_chain_length = pImpl_->ratchet.sending_chain_length;
            pImpl_->ratchet.sending_chain_length = 0;
        }
    }
}

void E2ESession::revoke_session() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->state = E2ESessionState::SessionRevoked;

    // Zeroize ratchet state
    if (pImpl_->ratchet.root_key.size() > 0)
        sodium_memzero(pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size());
    if (pImpl_->ratchet.chain_key.size() > 0)
        sodium_memzero(pImpl_->ratchet.chain_key.data(), pImpl_->ratchet.chain_key.size());
    pImpl_->ratchet.skipped_keys.clear();
}

std::string E2ESession::get_session_id() const {
    return pImpl_->session_id;
}

std::chrono::system_clock::time_point E2ESession::get_last_activity() const {
    return pImpl_->last_activity;
}

uint64_t E2ESession::get_messages_sent() const {
    return pImpl_->messages_sent;
}

uint64_t E2ESession::get_messages_received() const {
    return pImpl_->messages_received;
}

// ==================== E2EManager ====================

struct E2EManager::Impl {
    std::mutex mutex;
    std::map<std::string, std::shared_ptr<E2ESession>> sessions;
};

E2EManager::E2EManager() : pImpl_(std::make_unique<Impl>()) {}
E2EManager::~E2EManager() = default;

std::shared_ptr<E2ESession> E2EManager::create_session(
    const std::string& peer_id, const E2EConfig& config) {
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
    for (auto it = pImpl_->sessions.begin(); it != pImpl_->sessions.end();) {
        if (it->second->is_expired()) {
            it = pImpl_->sessions.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<std::string> E2EManager::get_active_sessions() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<std::string> ids;
    for (const auto& [id, session] : pImpl_->sessions) {
        if (session->is_established() && !session->is_expired()) {
            ids.push_back(id);
        }
    }
    return ids;
}

size_t E2EManager::get_session_count() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return pImpl_->sessions.size();
}

void E2EManager::rotate_all_keys() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    for (auto& [id, session] : pImpl_->sessions) {
        if (session->is_established() && !session->is_expired()) {
            session->rotate_keys();
        }
    }
}

void E2EManager::export_keys(const std::string& filepath, const SecureString& password) {
    (void)filepath; (void)password;
    // TODO: Serialize session keys to encrypted file
}

bool E2EManager::import_keys(const std::string& filepath, const SecureString& password) {
    (void)filepath; (void)password;
    // TODO: Deserialize session keys from encrypted file
    return false;
}

// ==================== E2EUtils ====================

namespace E2EUtils {

SecureMemory derive_key(
    const SecureMemory& input_key_material,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info,
    size_t output_length) {

    // Extract: PRK = HMAC-SHA512/256(salt, IKM)
    uint8_t prk[crypto_auth_hmacsha512256_BYTES];
    crypto_auth_hmacsha512256_state st;

    if (salt.empty()) {
        uint8_t zero_salt[crypto_auth_hmacsha512256_KEYBYTES] = {0};
        crypto_auth_hmacsha512256_init(&st, zero_salt, sizeof(zero_salt));
    } else {
        crypto_auth_hmacsha512256_init(&st, salt.data(), salt.size());
    }
    crypto_auth_hmacsha512256_update(&st,
        input_key_material.data(), input_key_material.size());
    crypto_auth_hmacsha512256_final(&st, prk);

    // Expand
    SecureMemory prk_mem(sizeof(prk));
    std::memcpy(prk_mem.data(), prk, sizeof(prk));
    sodium_memzero(prk, sizeof(prk));

    return hkdf_expand(prk_mem, info, output_length);
}

SecureMemory hkdf_expand(
    const SecureMemory& prk,
    const std::vector<uint8_t>& info,
    size_t length) {

    SecureMemory output(length);
    size_t offset = 0;
    uint8_t counter = 1;
    uint8_t prev_block[crypto_auth_hmacsha512256_BYTES] = {0};
    size_t prev_len = 0;

    while (offset < length) {
        crypto_auth_hmacsha512256_state st;
        crypto_auth_hmacsha512256_init(&st, prk.data(), prk.size());
        if (prev_len > 0) {
            crypto_auth_hmacsha512256_update(&st, prev_block, prev_len);
        }
        crypto_auth_hmacsha512256_update(&st, info.data(), info.size());
        crypto_auth_hmacsha512256_update(&st, &counter, 1);
        crypto_auth_hmacsha512256_final(&st, prev_block);

        prev_len = sizeof(prev_block);
        size_t to_copy = std::min(prev_len, length - offset);
        std::memcpy(output.data() + offset, prev_block, to_copy);
        offset += to_copy;
        counter++;
    }

    sodium_memzero(prev_block, sizeof(prev_block));
    return output;
}

std::vector<uint8_t> pad_message(
    const std::vector<uint8_t>& message,
    size_t block_size) {

    if (block_size == 0 || block_size > 255) block_size = 128;

    size_t pad_len = block_size - (message.size() % block_size);
    if (pad_len == 0) pad_len = block_size;

    std::vector<uint8_t> padded = message;
    padded.resize(message.size() + pad_len, static_cast<uint8_t>(pad_len));
    return padded;
}

std::optional<std::vector<uint8_t>> unpad_message(
    const std::vector<uint8_t>& padded_message) {

    if (padded_message.empty()) return std::nullopt;

    uint8_t pad_len = padded_message.back();
    if (pad_len == 0 || pad_len > padded_message.size()) return std::nullopt;

    // Verify all padding bytes are correct (constant-time)
    uint8_t check = 0;
    for (size_t i = padded_message.size() - pad_len; i < padded_message.size(); ++i) {
        check |= padded_message[i] ^ pad_len;
    }
    if (check != 0) return std::nullopt;

    return std::vector<uint8_t>(
        padded_message.begin(),
        padded_message.end() - pad_len);
}

std::vector<uint8_t> serialize_message(const EncryptedMessage& msg) {
    std::vector<uint8_t> data;

    // Header
    data.push_back(msg.header.version);

    uint32_t mn = msg.header.message_number;
    data.push_back((mn >> 24) & 0xFF); data.push_back((mn >> 16) & 0xFF);
    data.push_back((mn >> 8) & 0xFF);  data.push_back(mn & 0xFF);

    uint32_t pcl = msg.header.previous_chain_length;
    data.push_back((pcl >> 24) & 0xFF); data.push_back((pcl >> 16) & 0xFF);
    data.push_back((pcl >> 8) & 0xFF);  data.push_back(pcl & 0xFF);

    // DH public key
    uint16_t dh_len = static_cast<uint16_t>(msg.header.dh_public_key.size());
    data.push_back((dh_len >> 8) & 0xFF); data.push_back(dh_len & 0xFF);
    data.insert(data.end(), msg.header.dh_public_key.begin(),
                msg.header.dh_public_key.end());

    // Nonce
    uint8_t nonce_len = static_cast<uint8_t>(msg.nonce.size());
    data.push_back(nonce_len);
    data.insert(data.end(), msg.nonce.begin(), msg.nonce.end());

    // Ciphertext
    uint32_t ct_len = static_cast<uint32_t>(msg.ciphertext.size());
    data.push_back((ct_len >> 24) & 0xFF); data.push_back((ct_len >> 16) & 0xFF);
    data.push_back((ct_len >> 8) & 0xFF);  data.push_back(ct_len & 0xFF);
    data.insert(data.end(), msg.ciphertext.begin(), msg.ciphertext.end());

    // Associated data
    uint16_t ad_len = static_cast<uint16_t>(msg.header.associated_data.size());
    data.push_back((ad_len >> 8) & 0xFF); data.push_back(ad_len & 0xFF);
    data.insert(data.end(), msg.header.associated_data.begin(),
                msg.header.associated_data.end());

    return data;
}

std::optional<EncryptedMessage> deserialize_message(
    const std::vector<uint8_t>& data) {

    if (data.size() < 12) return std::nullopt;

    EncryptedMessage msg;
    size_t pos = 0;

    msg.header.version = data[pos++];

    msg.header.message_number =
        (static_cast<uint32_t>(data[pos]) << 24) |
        (static_cast<uint32_t>(data[pos+1]) << 16) |
        (static_cast<uint32_t>(data[pos+2]) << 8) |
         static_cast<uint32_t>(data[pos+3]);
    pos += 4;

    msg.header.previous_chain_length =
        (static_cast<uint32_t>(data[pos]) << 24) |
        (static_cast<uint32_t>(data[pos+1]) << 16) |
        (static_cast<uint32_t>(data[pos+2]) << 8) |
         static_cast<uint32_t>(data[pos+3]);
    pos += 4;

    if (pos + 2 > data.size()) return std::nullopt;
    uint16_t dh_len = (data[pos] << 8) | data[pos+1]; pos += 2;
    if (pos + dh_len > data.size()) return std::nullopt;
    msg.header.dh_public_key.assign(data.begin() + pos, data.begin() + pos + dh_len);
    pos += dh_len;

    if (pos + 1 > data.size()) return std::nullopt;
    uint8_t nonce_len = data[pos++];
    if (pos + nonce_len > data.size()) return std::nullopt;
    msg.nonce.assign(data.begin() + pos, data.begin() + pos + nonce_len);
    pos += nonce_len;

    if (pos + 4 > data.size()) return std::nullopt;
    uint32_t ct_len =
        (static_cast<uint32_t>(data[pos]) << 24) |
        (static_cast<uint32_t>(data[pos+1]) << 16) |
        (static_cast<uint32_t>(data[pos+2]) << 8) |
         static_cast<uint32_t>(data[pos+3]);
    pos += 4;
    if (pos + ct_len > data.size()) return std::nullopt;
    msg.ciphertext.assign(data.begin() + pos, data.begin() + pos + ct_len);
    pos += ct_len;

    if (pos + 2 <= data.size()) {
        uint16_t ad_len = (data[pos] << 8) | data[pos+1]; pos += 2;
        if (pos + ad_len <= data.size()) {
            msg.header.associated_data.assign(
                data.begin() + pos, data.begin() + pos + ad_len);
        }
    }

    msg.timestamp = std::chrono::system_clock::now();
    return msg;
}

} // namespace E2EUtils

} // namespace ncp
