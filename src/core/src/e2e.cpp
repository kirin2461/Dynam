#include "../include/ncp_e2e.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <cstring>
#include <algorithm>
#include <fstream>

// OpenSSL for X448 and ECDH_P256
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace ncp {

void init_library() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
    // OpenSSL 1.1.1+ handles threading automatically, but we ensure it's initialized
    OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, nullptr);
}

// ===== RAII helpers for OpenSSL resources =====
namespace {

struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); }
};
struct BN_Deleter {
    void operator()(BIGNUM* p) const { if (p) BN_free(p); }
};
struct OSSL_PARAM_BLD_Deleter {
    void operator()(OSSL_PARAM_BLD* p) const { if (p) OSSL_PARAM_BLD_free(p); }
};
struct OSSL_PARAM_Deleter {
    void operator()(OSSL_PARAM* p) const { if (p) OSSL_PARAM_free(p); }
};

using UniqueEVP_PKEY     = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using UniqueEVP_PKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using UniqueBN           = std::unique_ptr<BIGNUM, BN_Deleter>;
using UniqueOSSL_PARAM_BLD = std::unique_ptr<OSSL_PARAM_BLD, OSSL_PARAM_BLD_Deleter>;
using UniqueOSSL_PARAM     = std::unique_ptr<OSSL_PARAM, OSSL_PARAM_Deleter>;

UniqueEVP_PKEY ec_p256_pkey_from_private(const uint8_t* priv_raw, size_t priv_len,
                                       const uint8_t* pub_raw, size_t pub_len) 
{
    UniqueOSSL_PARAM_BLD bld(OSSL_PARAM_BLD_new());
    if (!bld) throw std::runtime_error("OSSL_PARAM_BLD_new failed");

    UniqueBN priv_bn(BN_bin2bn(priv_raw, static_cast<int>(priv_len), nullptr));
    if (!priv_bn) throw std::runtime_error("BN_bin2bn failed for EC P-256 private key");

    OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv_bn.get());
    if (pub_raw && pub_len > 0) {
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub_raw, pub_len);
    }

    UniqueOSSL_PARAM params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");

    UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_from_name(EC) failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
        throw std::runtime_error("EVP_PKEY_fromdata failed for EC P-256 private key");
    }
    return UniqueEVP_PKEY(pkey);
}

UniqueEVP_PKEY ec_p256_pkey_from_public(const uint8_t* pub_raw, size_t pub_len) {
    UniqueOSSL_PARAM_BLD bld(OSSL_PARAM_BLD_new());
    if (!bld) throw std::runtime_error("OSSL_PARAM_BLD_new failed");

    OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    // Flexible: OpenSSL handles compressed/uncompressed octet strings automatically
    OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, pub_raw, pub_len);

    UniqueOSSL_PARAM params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params) throw std::runtime_error("OSSL_PARAM_BLD_to_param failed");

    UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_from_name(EC) failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata_init(ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
        throw std::runtime_error("EVP_PKEY_fromdata failed for EC P-256 public key");
    }
    return UniqueEVP_PKEY(pkey);
}

// ===== Ratchet DH helpers (protocol-aware) =====
KeyPair generate_ratchet_keypair(KeyExchangeProtocol protocol) {
    KeyPair kp;
    kp.protocol = protocol;
    kp.created_at = std::chrono::system_clock::now();

    switch (protocol) {
        case KeyExchangeProtocol::X448: {
            UniqueEVP_PKEY_CTX pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X448, nullptr));
            if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0) 
                throw std::runtime_error("X448 ratchet keygen init failed");

            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) 
                throw std::runtime_error("X448 ratchet keygen failed");
            UniqueEVP_PKEY upkey(pkey);

            size_t pub_len = 56, priv_len = 56;
            kp.public_key = SecureMemory(pub_len);
            kp.private_key = SecureMemory(priv_len);
            EVP_PKEY_get_raw_public_key(upkey.get(), kp.public_key.data(), &pub_len);
            EVP_PKEY_get_raw_private_key(upkey.get(), kp.private_key.data(), &priv_len);
            break;
        }
        case KeyExchangeProtocol::ECDH_P256: {
            UniqueEVP_PKEY_CTX pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
            if (!pctx || EVP_PKEY_keygen_init(pctx.get()) <= 0 ||
                EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) {
                throw std::runtime_error("P256 ratchet keygen init failed");
            }
            EVP_PKEY* pkey = nullptr;
            if (EVP_PKEY_keygen(pctx.get(), &pkey) <= 0) 
                throw std::runtime_error("P256 ratchet keygen failed");
            UniqueEVP_PKEY upkey(pkey);

            size_t pub_len = 0;
            EVP_PKEY_get_octet_string_param(upkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pub_len);
            kp.public_key = SecureMemory(pub_len);
            EVP_PKEY_get_octet_string_param(upkey.get(), OSSL_PKEY_PARAM_PUB_KEY, kp.public_key.data(), pub_len, &pub_len);

            UniqueBN priv_bn;
            BIGNUM* raw_bn = nullptr;
            EVP_PKEY_get_bn_param(upkey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &raw_bn);
            priv_bn.reset(raw_bn);
            
            size_t priv_len = static_cast<size_t>(BN_num_bytes(priv_bn.get()));
            kp.private_key = SecureMemory(priv_len);
            BN_bn2bin(priv_bn.get(), kp.private_key.data());
            break;
        }
        case KeyExchangeProtocol::X25519:
        case KeyExchangeProtocol::Kyber1024:
        default: {
            kp.public_key = SecureMemory(crypto_scalarmult_BYTES);
            kp.private_key = SecureMemory(crypto_scalarmult_SCALARBYTES);
            crypto_box_keypair(kp.public_key.data(), kp.private_key.data());
            kp.protocol = KeyExchangeProtocol::X25519;
            break;
        }
    }
    return kp;
}

SecureMemory ratchet_dh(const KeyPair& local_kp, const std::vector<uint8_t>& remote_pub) {
    switch (local_kp.protocol) {
        case KeyExchangeProtocol::X448: {
            auto local_pkey = UniqueEVP_PKEY(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, nullptr, local_kp.private_key.data(), local_kp.private_key.size()));
            auto peer_pkey = UniqueEVP_PKEY(EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X448, nullptr, remote_pub.data(), remote_pub.size()));
            if (!local_pkey || !peer_pkey) throw std::runtime_error("X448 ratchet DH key load failed");

            UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(local_pkey.get(), nullptr));
            EVP_PKEY_derive_init(ctx.get());
            EVP_PKEY_derive_set_peer(ctx.get(), peer_pkey.get());
            size_t len = 0;
            EVP_PKEY_derive(ctx.get(), nullptr, &len);
            SecureMemory out(len);
            EVP_PKEY_derive(ctx.get(), out.data(), &len);
            return out;
        }
        case KeyExchangeProtocol::ECDH_P256: {
            auto local_pkey = ec_p256_pkey_from_private(
                local_kp.private_key.data(), local_kp.private_key.size(),
                local_kp.public_key.data(), local_kp.public_key.size());
            auto peer_pkey = ec_p256_pkey_from_public(remote_pub.data(), remote_pub.size());

            UniqueEVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(local_pkey.get(), nullptr));
            EVP_PKEY_derive_init(ctx.get());
            EVP_PKEY_derive_set_peer(ctx.get(), peer_pkey.get());
            size_t len = 0;
            EVP_PKEY_derive(ctx.get(), nullptr, &len);
            SecureMemory out(len);
            EVP_PKEY_derive(ctx.get(), out.data(), &len);
            return out;
        }
        default: {
            SecureMemory out(crypto_scalarmult_BYTES);
            if (crypto_scalarmult(out.data(), local_kp.private_key.data(), remote_pub.data()) != 0) {
                throw std::runtime_error("X25519 ratchet DH failed");
            }
            return out;
        }
    }
}

// ===== Export/Import helpers =====
static constexpr uint8_t EXPORT_MAGIC[4] = {'N','C','E','2'};
static constexpr uint8_t EXPORT_VERSION = 2; // Bumped version

void append_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}
void append_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}
uint32_t read_u32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}
void append_blob(std::vector<uint8_t>& out, const uint8_t* data, size_t len) {
    append_u16(out, static_cast<uint16_t>(std::min(len, size_t(65535))));
    out.insert(out.end(), data, data + std::min(len, size_t(65535)));
}
void append_blob(std::vector<uint8_t>& out, const SecureMemory& mem) { append_blob(out, mem.data(), mem.size()); }
void append_blob(std::vector<uint8_t>& out, const std::vector<uint8_t>& vec) { append_blob(out, vec.data(), vec.size()); }

} // anonymous namespace

struct E2ESession::Impl {
    E2EConfig config;
    std::mutex mutex;
    std::string session_id;
    E2ESessionState state = E2ESessionState::Uninitialized;
    std::chrono::system_clock::time_point last_activity;
    std::chrono::system_clock::time_point session_created_at;
    uint64_t messages_sent = 0;
    uint64_t messages_received = 0;

    SecureMemory shared_secret;
    SecureMemory last_kem_ciphertext;
    std::vector<uint8_t> last_kx_request_hash; // Task 1

    RatchetState ratchet;
    KeyPair local_ratchet_kp;
    std::vector<uint8_t> remote_ratchet_pub;
    bool ratchet_initialized = false;

    SecureMemory sending_chain_key;
    SecureMemory receiving_chain_key;

    explicit Impl(const E2EConfig& cfg) : config(cfg) {
        generate_session_id();
        session_created_at = std::chrono::system_clock::now();
        last_activity = session_created_at;
        last_kx_request_hash.resize(32, 0);
    }

    void generate_session_id() {
        uint8_t id_bytes[16];
        randombytes_buf(id_bytes, sizeof(id_bytes));
        std::ostringstream oss;
        for (int i = 0; i < 16; ++i) oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(id_bytes[i]);
        session_id = oss.str();
    }

    void kdf_rk(const SecureMemory& root_key, const SecureMemory& dh_output, SecureMemory& new_root_key, SecureMemory& new_chain_key) {
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

    void dh_ratchet_step(const std::vector<uint8_t>& new_remote_pub) {
        remote_ratchet_pub = new_remote_pub;
        SecureMemory dh_recv = ratchet_dh(local_ratchet_kp, new_remote_pub);
        SecureMemory new_root, new_recv_chain;
        kdf_rk(ratchet.root_key, dh_recv, new_root, new_recv_chain);
        ratchet.root_key = std::move(new_root);
        receiving_chain_key = std::move(new_recv_chain);

        ratchet.previous_chain_length = ratchet.sending_chain_length;
        ratchet.receiving_chain_length = 0;

        local_ratchet_kp = generate_ratchet_keypair(config.key_exchange);
        SecureMemory dh_send = ratchet_dh(local_ratchet_kp, new_remote_pub);
        SecureMemory new_root2, new_send_chain;
        kdf_rk(ratchet.root_key, dh_send, new_root2, new_send_chain);
        ratchet.root_key = std::move(new_root2);
        ratchet.chain_key = new_send_chain;
        sending_chain_key = std::move(new_send_chain);
        ratchet.sending_chain_length = 0;
    }

    bool skip_message_keys(SecureMemory& recv_chain_key, uint32_t& recv_counter, uint32_t until) {
        if (until < recv_counter || until - recv_counter > config.max_skip_messages) return false;
        while (recv_counter < until) {
            SecureMemory mk;
            kdf_ck(recv_chain_key, mk);
            ratchet.skipped_keys[recv_counter] = std::move(mk);
            recv_counter++;
        }
        return true;
    }

    bool try_skipped_message_keys(uint32_t msg_number, SecureMemory& out_key) {
        auto it = ratchet.skipped_keys.find(msg_number);
        if (it == ratchet.skipped_keys.end()) return false;
        out_key = std::move(it->second);
        ratchet.skipped_keys.erase(it);
        return true;
    }
};

E2ESession::E2ESession(const E2EConfig& config) : pImpl_(std::make_unique<Impl>(config)) {
    // libsodium/openssl init is now in init_library(), but we call it here for safety if not called
    static std::once_flag init_flag;
    std::call_once(init_flag, [](){ ncp::init_library(); });
}
E2ESession::~E2ESession() = default;

KeyPair E2ESession::generate_key_pair() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    return generate_ratchet_keypair(pImpl_->config.key_exchange);
}

SecureMemory E2ESession::encapsulate(const std::vector<uint8_t>& peer_public_key, std::vector<uint8_t>& out_ciphertext) {
#ifdef HAVE_LIBOQS
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) throw std::runtime_error("Kyber1024 KEM init failed");
    out_ciphertext.resize(kem->length_ciphertext);
    SecureMemory shared(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, out_ciphertext.data(), shared.data(), peer_public_key.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Kyber1024 encapsulation failed");
    }
    OQS_KEM_free(kem);
    return shared;
#else
    throw std::runtime_error("Kyber1024 requires liboqs");
#endif
}

SecureMemory E2ESession::decapsulate(const KeyPair& local_keypair, const std::vector<uint8_t>& ciphertext) {
#ifdef HAVE_LIBOQS
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
    if (!kem) throw std::runtime_error("Kyber1024 KEM init failed");
    SecureMemory shared(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, shared.data(), ciphertext.data(), local_keypair.private_key.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        throw std::runtime_error("Kyber1024 decapsulation failed");
    }
    OQS_KEM_free(kem);
    return shared;
#else
    throw std::runtime_error("Kyber1024 requires liboqs");
#endif
}

SecureMemory E2ESession::compute_shared_secret(const KeyPair& local_keypair, const std::vector<uint8_t>& peer_public_key) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (local_keypair.protocol == KeyExchangeProtocol::Kyber1024) {
        std::vector<uint8_t> ct;
        auto shared = encapsulate(peer_public_key, ct);
        pImpl_->last_kem_ciphertext = SecureMemory(ct.size());
        std::memcpy(pImpl_->last_kem_ciphertext.data(), ct.data(), ct.size());
        return shared;
    }
    return ratchet_dh(local_keypair, peer_public_key);
}

std::vector<uint8_t> E2ESession::get_last_kem_ciphertext() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->last_kem_ciphertext.size() == 0) return {};
    return std::vector<uint8_t>(pImpl_->last_kem_ciphertext.data(), pImpl_->last_kem_ciphertext.data() + pImpl_->last_kem_ciphertext.size());
}

SecureMemory E2ESession::derive_keys(const SecureMemory& shared_secret, const std::string& context, size_t key_length) {
    SecureMemory derived_key(key_length);
    char kdf_context[crypto_kdf_CONTEXTBYTES];
    crypto_generichash(reinterpret_cast<uint8_t*>(kdf_context), sizeof(kdf_context), reinterpret_cast<const uint8_t*>(context.data()), context.size(), nullptr, 0);
    uint8_t master_key[crypto_kdf_KEYBYTES];
    crypto_generichash(master_key, sizeof(master_key), shared_secret.data(), shared_secret.size(), nullptr, 0);
    
    size_t derived = 0;
    uint64_t subkey_id = 0;
    while (derived < key_length) {
        uint8_t subkey[crypto_kdf_BYTES_MAX];
        size_t to_derive = std::min(key_length - derived, sizeof(subkey));
        if (crypto_kdf_derive_from_key(subkey, to_derive, subkey_id++, kdf_context, master_key) != 0) {
            sodium_memzero(master_key, sizeof(master_key));
            throw std::runtime_error("Failed to derive key");
        }
        std::memcpy(derived_key.data() + derived, subkey, to_derive);
        derived += to_derive;
    }
    sodium_memzero(master_key, sizeof(master_key));
    return derived_key;
}

void E2ESession::init_ratchet_keys() {
    auto& impl = *pImpl_;
    if (impl.shared_secret.size() == 0) return;

    impl.ratchet.root_key = SecureMemory(32);
    uint8_t info_root[] = "NCP-DR-ROOT-v1";
    crypto_generichash(impl.ratchet.root_key.data(), 32, impl.shared_secret.data(), impl.shared_secret.size(), info_root, sizeof(info_root)-1);

    impl.sending_chain_key = SecureMemory(32);
    uint8_t info_chain[] = "NCP-DR-CHAIN-v1";
    crypto_generichash(impl.sending_chain_key.data(), 32, impl.shared_secret.data(), impl.shared_secret.size(), info_chain, sizeof(info_chain)-1);
    impl.ratchet.chain_key = impl.sending_chain_key;

    impl.receiving_chain_key = SecureMemory(32);
    uint8_t info_recv[] = "NCP-DR-RECV-v1";
    crypto_generichash(impl.receiving_chain_key.data(), 32, impl.ratchet.root_key.data(), impl.ratchet.root_key.size(), info_recv, sizeof(info_recv)-1);

    impl.local_ratchet_kp = generate_ratchet_keypair(impl.config.key_exchange);
    impl.ratchet.sending_chain_length = 0;
    impl.ratchet.receiving_chain_length = 0;
    impl.ratchet.skipped_keys.clear();
    impl.ratchet_initialized = true;
}

std::vector<uint8_t> E2ESession::create_key_exchange_request(const KeyPair& local_keys) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->state = E2ESessionState::KeyExchangeInitiated;
    std::vector<uint8_t> request;
    request.push_back(0x10); // Format version
    request.push_back(static_cast<uint8_t>(local_keys.protocol));
    append_u16(request, static_cast<uint16_t>(local_keys.public_key.size()));
    request.insert(request.end(), local_keys.public_key.data(), local_keys.public_key.data() + local_keys.public_key.size());
    
    // Store transcript hash of our own request
    crypto_generichash(pImpl_->last_kx_request_hash.data(), 32, request.data(), request.size(), nullptr, 0);
    
    return request;
}

std::vector<uint8_t> E2ESession::process_key_exchange_request(const std::vector<uint8_t>& request, const KeyPair& local_keys) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (request.size() < 4) throw std::runtime_error("Invalid KX request");
    uint16_t pk_len = read_u16(request.data() + 2);
    if (request.size() < 4u + pk_len) throw std::runtime_error("KX request too short");

    std::vector<uint8_t> peer_public(request.begin() + 4, request.begin() + 4 + pk_len);
    pImpl_->shared_secret = compute_shared_secret(local_keys, peer_public);
    pImpl_->remote_ratchet_pub = peer_public;
    init_ratchet_keys();

    pImpl_->state = E2ESessionState::SessionEstablished;
    std::vector<uint8_t> response;
    response.push_back(0x20); // Version 2.0
    response.push_back(static_cast<uint8_t>(local_keys.protocol));
    append_u16(response, static_cast<uint16_t>(local_keys.public_key.size()));
    response.insert(response.end(), local_keys.public_key.data(), local_keys.public_key.data() + local_keys.public_key.size());

    // Transcript hash for tamper detection
    uint8_t hash[32];
    crypto_generichash(hash, 32, request.data(), request.size(), nullptr, 0);
    response.insert(response.end(), hash, hash + 32);
    
    return response;
}

bool E2ESession::complete_key_exchange(const std::vector<uint8_t>& response, const KeyPair& local_keys) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (response.size() < 4) return false;
    uint16_t pk_len = read_u16(response.data() + 2);
    if (response.size() < 4u + pk_len) return false;

    // Verify transcript hash if present
    if (response[0] == 0x20 && response.size() >= 4u + pk_len + 32) {
        uint8_t received_hash[32];
        std::memcpy(received_hash, response.data() + 4 + pk_len, 32);
        if (sodium_memcmp(received_hash, pImpl_->last_kx_request_hash.data(), 32) != 0) {
            return false; // Hash mismatch
        }
    }

    std::vector<uint8_t> peer_public(response.begin() + 4, response.begin() + 4 + pk_len);
    pImpl_->shared_secret = compute_shared_secret(local_keys, peer_public);
    pImpl_->remote_ratchet_pub = peer_public;
    init_ratchet_keys();

    pImpl_->state = E2ESessionState::SessionEstablished;
    return true;
}

// ... Encrypt/Decrypt methods (mostly unchanged, ensuring message version 2) ...
EncryptedMessage E2ESession::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& associated_data) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished || !pImpl_->ratchet_initialized)
        throw std::runtime_error("Session not established");

    SecureMemory message_key;
    pImpl_->kdf_ck(pImpl_->sending_chain_key, message_key);
    pImpl_->ratchet.chain_key = pImpl_->sending_chain_key;

    MessageHeader hdr;
    hdr.version = 2; // Bump version
    hdr.message_number = pImpl_->ratchet.sending_chain_length;
    hdr.previous_chain_length = pImpl_->ratchet.previous_chain_length;
    hdr.dh_public_key.assign(pImpl_->local_ratchet_kp.public_key.data(), pImpl_->local_ratchet_kp.public_key.data() + pImpl_->local_ratchet_kp.public_key.size());
    hdr.associated_data = associated_data;
    pImpl_->ratchet.sending_chain_length++;

    std::vector<uint8_t> padded = pImpl_->config.enable_padding ? E2EUtils::pad_message(plaintext, 128) : plaintext;
    
    EncryptedMessage msg;
    msg.header = hdr;
    msg.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(msg.nonce.data(), msg.nonce.size());

    std::vector<uint8_t> aad;
    aad.push_back(hdr.version);
    append_u32(aad, hdr.message_number);
    aad.insert(aad.end(), hdr.dh_public_key.begin(), hdr.dh_public_key.end());
    aad.insert(aad.end(), associated_data.begin(), associated_data.end());

    msg.ciphertext.resize(padded.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(msg.ciphertext.data(), &ct_len, padded.data(), padded.size(), aad.data(), aad.size(), nullptr, msg.nonce.data(), message_key.data());
    msg.ciphertext.resize(static_cast<size_t>(ct_len));
    msg.timestamp = std::chrono::system_clock::now();
    
    pImpl_->messages_sent++;
    return msg;
}

std::optional<std::vector<uint8_t>> E2ESession::decrypt(const EncryptedMessage& encrypted_message) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (pImpl_->state != E2ESessionState::SessionEstablished || !pImpl_->ratchet_initialized) return std::nullopt;

    const auto& hdr = encrypted_message.header;
    uint32_t msg_num = hdr.message_number;

    SecureMemory skipped_key;
    if (pImpl_->try_skipped_message_keys(msg_num, skipped_key)) {
        return decrypt_with_key_(encrypted_message, skipped_key);
    }

    if (!hdr.dh_public_key.empty() && hdr.dh_public_key != pImpl_->remote_ratchet_pub) {
        pImpl_->dh_ratchet_step(hdr.dh_public_key);
    }

    if (msg_num > pImpl_->ratchet.receiving_chain_length) {
        uint32_t counter = pImpl_->ratchet.receiving_chain_length;
        if (!pImpl_->skip_message_keys(pImpl_->receiving_chain_key, counter, msg_num)) return std::nullopt;
        pImpl_->ratchet.receiving_chain_length = counter;
    }

    SecureMemory message_key;
    pImpl_->kdf_ck(pImpl_->receiving_chain_key, message_key);
    pImpl_->ratchet.receiving_chain_length = msg_num + 1;
    
    return decrypt_with_key_(encrypted_message, message_key);
}

// ... Rest of the implementation (Serialization, revoke_session, E2EManager, etc.) ...
// Ensure serialize_session_state includes version check

std::vector<uint8_t> E2ESession::serialize_session_state() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<uint8_t> out;
    out.push_back(0x02); // Serialized version 2
    
    append_u16(out, static_cast<uint16_t>(pImpl_->session_id.size()));
    out.insert(out.end(), pImpl_->session_id.begin(), pImpl_->session_id.end());
    // ... rest of fields ...
    out.push_back(static_cast<uint8_t>(pImpl_->state));
    out.push_back(static_cast<uint8_t>(pImpl_->config.key_exchange));
    out.push_back(pImpl_->config.enable_forward_secrecy ? 1 : 0);
    out.push_back(pImpl_->config.enable_post_quantum ? 1 : 0);
    append_u32(out, pImpl_->config.max_skip_messages);

    append_u32(out, static_cast<uint32_t>(pImpl_->messages_sent & 0xFFFFFFFF));
    append_u32(out, static_cast<uint32_t>(pImpl_->messages_received & 0xFFFFFFFF));

    append_blob(out, pImpl_->ratchet.root_key);
    append_blob(out, pImpl_->sending_chain_key);
    append_blob(out, pImpl_->receiving_chain_key);
    append_u32(out, pImpl_->ratchet.sending_chain_length);
    append_u32(out, pImpl_->ratchet.receiving_chain_length);
    append_u32(out, pImpl_->ratchet.previous_chain_length);

    append_blob(out, pImpl_->local_ratchet_kp.public_key);
    append_blob(out, pImpl_->local_ratchet_kp.private_key);
    append_blob(out, pImpl_->remote_ratchet_pub);
    out.push_back(pImpl_->ratchet_initialized ? 1 : 0);

    append_u32(out, static_cast<uint32_t>(pImpl_->ratchet.skipped_keys.size()));
    for (const auto& [msg_num, key] : pImpl_->ratchet.skipped_keys) {
        append_u32(out, msg_num);
        append_blob(out, key);
    }
    return out;
}

bool E2ESession::restore_session_state(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (data.size() < 21) return false;
    size_t pos = 0;
    uint8_t ver = data[pos++];
    if (ver < 1 || ver > 2) return false;

    auto safe_read = [&](size_t n) { return pos + n <= data.size(); };
    auto read_secure_blob = [&](SecureMemory& mem) -> bool {
        if (!safe_read(2)) return false;
        uint16_t len = read_u16(data.data() + pos); pos += 2;
        if (!safe_read(len)) return false;
        mem = SecureMemory(len);
        std::memcpy(mem.data(), data.data() + pos, len);
        pos += len; return true;
    };
    auto read_vec_blob = [&](std::vector<uint8_t>& vec) -> bool {
        if (!safe_read(2)) return false;
        uint16_t len = read_u16(data.data() + pos); pos += 2;
        if (!safe_read(len)) return false;
        vec.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len; return true;
    };

    if (!safe_read(2)) return false;
    uint16_t sid_len = read_u16(data.data() + pos); pos += 2;
    if (!safe_read(sid_len)) return false;
    pImpl_->session_id.assign(data.begin() + pos, data.begin() + pos + sid_len);
    pos += sid_len;

    if (!safe_read(1)) return false;
    pImpl_->state = static_cast<E2ESessionState>(data[pos++]);
    if (!safe_read(7)) return false;
    pImpl_->config.key_exchange = static_cast<KeyExchangeProtocol>(data[pos++]);
    pImpl_->config.enable_forward_secrecy = data[pos++] != 0;
    pImpl_->config.enable_post_quantum = data[pos++] != 0;
    pImpl_->config.max_skip_messages = read_u32(data.data() + pos); pos += 4;

    if (!safe_read(8)) return false;
    pImpl_->messages_sent = read_u32(data.data() + pos); pos += 4;
    pImpl_->messages_received = read_u32(data.data() + pos); pos += 4;

    if (!read_secure_blob(pImpl_->ratchet.root_key)) return false;
    if (!read_secure_blob(pImpl_->sending_chain_key)) return false;
    if (!read_secure_blob(pImpl_->receiving_chain_key)) return false;
    pImpl_->ratchet.chain_key = pImpl_->sending_chain_key;

    if (!safe_read(12)) return false;
    pImpl_->ratchet.sending_chain_length = read_u32(data.data() + pos); pos += 4;
    pImpl_->ratchet.receiving_chain_length = read_u32(data.data() + pos); pos += 4;
    pImpl_->ratchet.previous_chain_length = read_u32(data.data() + pos); pos += 4;

    if (!read_secure_blob(pImpl_->local_ratchet_kp.public_key)) return false;
    if (!read_secure_blob(pImpl_->local_ratchet_kp.private_key)) return false;
    if (!read_vec_blob(pImpl_->remote_ratchet_pub)) return false;
    if (!safe_read(1)) return false;
    pImpl_->ratchet_initialized = data[pos++] != 0;

    if (!safe_read(4)) return false;
    uint32_t num_skipped = read_u32(data.data() + pos); pos += 4;
    pImpl_->ratchet.skipped_keys.clear();
    for (uint32_t i = 0; i < num_skipped; ++i) {
        if (!safe_read(4)) return false;
        uint32_t m = read_u32(data.data() + pos); pos += 4;
        SecureMemory k;
        if (!read_secure_blob(k)) return false;
        pImpl_->ratchet.skipped_keys[m] = std::move(k);
    }
    return true;
}

E2ESessionState E2ESession::get_state() const { return pImpl_->state; }
bool E2ESession::is_established() const { std::lock_guard<std::mutex> lock(pImpl_->mutex); return pImpl_->state == E2ESessionState::SessionEstablished; }
bool E2ESession::is_expired() const { 
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto now = std::chrono::system_clock::now();
    return (now - pImpl_->session_created_at) >= pImpl_->config.session_timeout;
}
void E2ESession::rotate_keys() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    if (!pImpl_->ratchet_initialized) return;
    pImpl_->local_ratchet_kp = generate_ratchet_keypair(pImpl_->config.key_exchange);
    if (!pImpl_->remote_ratchet_pub.empty()) pImpl_->dh_ratchet_step(pImpl_->remote_ratchet_pub);
}
void E2ESession::revoke_session() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    pImpl_->state = E2ESessionState::SessionRevoked;
    if (pImpl_->ratchet.root_key.size() > 0) sodium_memzero(pImpl_->ratchet.root_key.data(), pImpl_->ratchet.root_key.size());
    if (pImpl_->sending_chain_key.size() > 0) sodium_memzero(pImpl_->sending_chain_key.data(), pImpl_->sending_chain_key.size());
    if (pImpl_->receiving_chain_key.size() > 0) sodium_memzero(pImpl_->receiving_chain_key.data(), pImpl_->receiving_chain_key.size());
    if (pImpl_->shared_secret.size() > 0) sodium_memzero(pImpl_->shared_secret.data(), pImpl_->shared_secret.size());
    pImpl_->ratchet.skipped_keys.clear();
}
std::string E2ESession::get_session_id() const { return pImpl_->session_id; }
std::chrono::system_clock::time_point E2ESession::get_last_activity() const { std::lock_guard<std::mutex> lock(pImpl_->mutex); return pImpl_->last_activity; }
uint64_t E2ESession::get_messages_sent() const { std::lock_guard<std::mutex> lock(pImpl_->mutex); return pImpl_->messages_sent; }
uint64_t E2ESession::get_messages_received() const { std::lock_guard<std::mutex> lock(pImpl_->mutex); return pImpl_->messages_received; }

// ===== E2EManager =====
struct E2EManager::Impl {
    std::mutex mutex;
    std::map<std::string, std::shared_ptr<E2ESession>> sessions;
};
E2EManager::E2EManager() : pImpl_(std::make_unique<Impl>()) {}
E2EManager::~E2EManager() = default;
std::shared_ptr<E2ESession> E2EManager::create_session(const std::string& peer_id, const E2EConfig& config) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto s = std::make_shared<E2ESession>(config);
    pImpl_->sessions[peer_id] = s; return s;
}
std::shared_ptr<E2ESession> E2EManager::get_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto it = pImpl_->sessions.find(peer_id);
    return (it != pImpl_->sessions.end()) ? it->second : nullptr;
}
void E2EManager::remove_session(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    auto it = pImpl_->sessions.find(peer_id);
    if (it != pImpl_->sessions.end()) { it->second->revoke_session(); pImpl_->sessions.erase(it); }
}
void E2EManager::remove_expired_sessions() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    for (auto it = pImpl_->sessions.begin(); it != pImpl_->sessions.end();) {
        if (it->second->is_expired()) { it->second->revoke_session(); it = pImpl_->sessions.erase(it); }
        else ++it;
    }
}
std::vector<std::string> E2EManager::get_active_sessions() const {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<std::string> ids;
    for (const auto& [id, s] : pImpl_->sessions) if (s->is_established() && !s->is_expired()) ids.push_back(id);
    return ids;
}
size_t E2EManager::get_session_count() const { std::lock_guard<std::mutex> lock(pImpl_->mutex); return pImpl_->sessions.size(); }
void E2EManager::rotate_all_keys() {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    for (auto& [id, s] : pImpl_->sessions) if (s->is_established() && !s->is_expired()) s->rotate_keys();
}

// ... export/import implementation ...
void E2EManager::export_keys(const std::string& filepath, const SecureString& password) {
    std::lock_guard<std::mutex> lock(pImpl_->mutex);
    std::vector<uint8_t> payload;
    uint32_t count = 0;
    for (auto& [id, s] : pImpl_->sessions) if (s->is_established() && !s->is_expired()) count++;
    append_u32(payload, count);
    for (auto& [id, s] : pImpl_->sessions) {
        if (!s->is_established() || s->is_expired()) continue;
        append_u16(payload, static_cast<uint16_t>(id.size()));
        payload.insert(payload.end(), id.begin(), id.end());
        auto state = s->serialize_session_state();
        append_u32(payload, static_cast<uint32_t>(state.size()));
        payload.insert(payload.end(), state.begin(), state.end());
    }
    // (Derivation and Encryption logic as before, but with version check)
    // ...
}

bool E2EManager::import_keys(const std::string& filepath, const SecureString& password) {
    // ...
    return true;
}

namespace E2EUtils {
    // HKDF and other utils...
    // ... (unchanged or updated for versioning)
}

} // namespace ncp Note: I will provide the full implementation in the final step
    return out;
}

// ... (E2EUtils, E2EManager methods) ...

} // namespace ncp
