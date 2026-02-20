#include "../include/ncp_e2e.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cstring>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

struct E2ESession::Impl {
    E2EConfig config;
    std::mutex mutex;
    std::string session_id;
    E2ESessionState state = E2ESessionState::Uninitialized;
    std::chrono::system_clock::time_point last_activity;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;

    // Double Ratchet state
    RatchetState ratchet;
    KeyPair local_ratchet_kp;     // Current ratchet DH keypair
    bool ratchet_initialized = false;

    explicit Impl(const E2EConfig& cfg) : config(cfg) {
        generate_session_id();
        last_activity = std::chrono::system_clock::now();
    }

    void generate_session_id();

    // HKDF-like KDF using libsodium: derive two 32-byte keys from root_key + DH output
    void kdf_rk(const SecureMemory& root_key, const SecureMemory& dh_output,
                SecureMemory& new_root_key, SecureMemory& new_chain_key) {
        // PRK = HMAC-SHA512/256(root_key, dh_output)
        uint8_t prk[crypto_auth_hmacsha512256_BYTES];
        crypto_auth_hmacsha512256_state st;
        crypto_auth_hmacsha512256_init(&st, root_key.data(), root_key.size());
        crypto_auth_hmacsha512256_update(&st, dh_output.data(), dh_output.size());
        crypto_auth_hmacsha512256_final(&st, prk);

        // Derive 64 bytes via two rounds of hash
        new_root_key = SecureMemory(32);
        new_chain_key = SecureMemory(32);

        uint8_t info_rk = 0x01;
        crypto_generichash(new_root_key.data(), 32, prk, sizeof(prk), &info_rk, 1);
        uint8_t info_ck = 0x02