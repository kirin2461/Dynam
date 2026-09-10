/**
 * @file test_scoped_trust.cpp
 * @brief Tests for the scoped trust module (NUЦ containment).
 */

#include <gtest/gtest.h>

#include "ncp_scoped_trust.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <sodium.h>

using namespace ncp;

// ==================== Policy ====================

TEST(ScopedTrustPolicy, DefaultRulesRu) {
    ScopedTrustPolicy p;
    p.set_default_rules_ru();

    EXPECT_TRUE(p.uses_custom_root("gosuslugi.ru"));
    EXPECT_TRUE(p.uses_custom_root("www.gosuslugi.ru"));   // subdomain
    EXPECT_TRUE(p.uses_custom_root("sberbank.ru"));
    EXPECT_TRUE(p.uses_custom_root("anything.ru"));        // TLD suffix
    EXPECT_TRUE(p.uses_custom_root("example.SU"));         // case-insensitive
    EXPECT_TRUE(p.uses_custom_root("site.xn--p1ai"));      // .рф punycode

    EXPECT_FALSE(p.uses_custom_root("google.com"));
    EXPECT_FALSE(p.uses_custom_root("github.com"));
    EXPECT_FALSE(p.uses_custom_root("notru.ru.evil.com")); // suffix spoof
    EXPECT_FALSE(p.uses_custom_root("evilsberbank.ru.evil.com"));
    EXPECT_FALSE(p.uses_custom_root(""));
}

TEST(ScopedTrustPolicy, CustomRulesFile) {
    const std::string path = "/tmp/ncp_test_rules.txt";
    {
        std::ofstream f(path);
        f << "# comment\n"
          << ".example\n"
          << "bank.internal\n"
          << "\n";
    }
    ScopedTrustPolicy p;
    std::string err;
    ASSERT_TRUE(p.load_rules_file(path, &err)) << err;
    EXPECT_EQ(p.rule_count(), 2u);
    EXPECT_TRUE(p.uses_custom_root("host.example"));
    EXPECT_TRUE(p.uses_custom_root("bank.internal"));
    EXPECT_TRUE(p.uses_custom_root("a.bank.internal"));
    EXPECT_FALSE(p.uses_custom_root("example.com"));
    std::remove(path.c_str());

    ScopedTrustPolicy p2;
    EXPECT_FALSE(p2.load_rules_file("/nonexistent/rules.txt", &err));
}

// ==================== CA generation + scoped verification ====================

namespace {

struct PemFiles {
    std::string key = "/tmp/ncp_test_ca.key";
    std::string crt = "/tmp/ncp_test_ca.crt";
    ~PemFiles() {
        std::remove(key.c_str());
        std::remove(crt.c_str());
    }
};

std::string read_file(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// Sign a leaf certificate (with SAN) under the CA at ca_key/ca_crt.
std::string make_leaf_pem(const std::string& ca_key_path,
                          const std::string& ca_crt_path,
                          const std::string& dns_name) {
    // Load CA key + cert.
    FILE* kf = std::fopen(ca_key_path.c_str(), "rb");
    EVP_PKEY* ca_key = PEM_read_PrivateKey(kf, nullptr, nullptr, nullptr);
    std::fclose(kf);
    FILE* cf = std::fopen(ca_crt_path.c_str(), "rb");
    X509* ca_crt = PEM_read_X509(cf, nullptr, nullptr, nullptr);
    std::fclose(cf);
    if (!ca_key || !ca_crt) return {};

    // Leaf key.
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* leaf_key = nullptr;
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(kctx, &leaf_key) <= 0)
        return {};

    X509* leaf = X509_new();
    X509_set_version(leaf, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(leaf), 1001);
    X509_gmtime_adj(X509_getm_notBefore(leaf), -60);
    X509_gmtime_adj(X509_getm_notAfter(leaf), 3600);
    X509_set_pubkey(leaf, leaf_key);
    X509_NAME* name = X509_get_subject_name(leaf);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(dns_name.c_str()), -1, -1, 0);
    X509_set_issuer_name(leaf, X509_get_subject_name(ca_crt));
    {
        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, ca_crt, leaf, nullptr, nullptr, 0);
        const std::string san = "DNS:" + dns_name;
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(
            nullptr, &v3ctx, NID_subject_alt_name, san.c_str());
        if (ext) {
            X509_add_ext(leaf, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    if (X509_sign(leaf, ca_key, EVP_sha256()) == 0) return {};

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, leaf);
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string pem(mem->data, mem->length);
    BIO_free(bio);

    X509_free(leaf);
    EVP_PKEY_free(leaf_key);
    EVP_PKEY_CTX_free(kctx);
    X509_free(ca_crt);
    EVP_PKEY_free(ca_key);
    return pem;
}

} // namespace

TEST(ScopedTrustStore, LocalCaAndScopedVerify) {
    PemFiles files;
    std::string err;
    ASSERT_TRUE(generate_local_ca(files.key, files.crt, "NCP Test CA", &err))
        << err;

    ScopedTrustStore store;
    ASSERT_TRUE(store.load_custom_roots_pem(files.crt, &err)) << err;
    EXPECT_EQ(store.custom_root_count(), 1u);

    ScopedTrustPolicy policy;
    policy.set_default_rules_ru();

    // Leaf for a whitelisted RU host, signed by the local (state) CA.
    const std::string leaf = make_leaf_pem(files.key, files.crt,
                                           "bank.example.ru");
    ASSERT_FALSE(leaf.empty());

    // Event feed: the custom_root_validation event must fire.
    bool event_seen = false;
    std::string event_host;
    store.set_event_callback([&](const ScopedTrustEvent& ev) {
        if (ev.host != "bank.example.ru") return;  // only the custom event
        event_seen = true;
        event_host = ev.host;
        EXPECT_TRUE(ev.custom_root_used);
        EXPECT_TRUE(ev.verified);
    });

    EXPECT_TRUE(store.verify_peer_chain("bank.example.ru", leaf, policy, &err))
        << err;
    EXPECT_TRUE(event_seen);
    EXPECT_EQ(event_host, "bank.example.ru");

    // The same chain must NOT validate for an out-of-scope host: the
    // custom root never applies there (public roots don't know our CA).
    EXPECT_FALSE(store.verify_peer_chain("evil.com", leaf, policy, &err));

    // Hostname mismatch inside the custom scope must also fail.
    EXPECT_FALSE(store.verify_peer_chain("other.ru", leaf, policy, &err));
}

TEST(ScopedTrustStore, RejectsGarbageChain) {
    PemFiles files;
    std::string err;
    ASSERT_TRUE(generate_local_ca(files.key, files.crt, "NCP Test CA", &err));
    ScopedTrustStore store;
    ASSERT_TRUE(store.load_custom_roots_pem(files.crt, &err));
    ScopedTrustPolicy policy;
    policy.set_default_rules_ru();
    EXPECT_FALSE(store.verify_peer_chain("gosuslugi.ru", "not a pem", policy,
                                         &err));
}

// ==================== Verified root update ====================

TEST(VerifiedRootUpdate, AcceptsValidSignature) {
    ASSERT_GE(sodium_init(), 0);
    // Ed25519 keypair for the "release key".
    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    const std::string bundle =
        "-----BEGIN CERTIFICATE-----\nFAKEFAKEFAKE\n-----END CERTIFICATE-----\n";
    std::vector<uint8_t> data(bundle.begin(), bundle.end());

    uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, data.data(), data.size(), sk);

    char sig_b64[sodium_base64_ENCODED_LEN(crypto_sign_BYTES,
                                           sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(sig_b64, sizeof(sig_b64), sig, sizeof(sig),
                      sodium_base64_VARIANT_ORIGINAL);
    char pk_b64[sodium_base64_ENCODED_LEN(crypto_sign_PUBLICKEYBYTES,
                                          sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk),
                      sodium_base64_VARIANT_ORIGINAL);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);
    char sha_hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        std::snprintf(sha_hex + i * 2, 3, "%02x", digest[i]);
    sha_hex[64] = 0;

    const std::string dest = "/tmp/ncp_test_roots.pem";
    std::string err;
    ASSERT_TRUE(verified_root_update(data, sha_hex, sig_b64, pk_b64, dest,
                                     &err)) << err;
    EXPECT_EQ(read_file(dest), bundle);
    std::remove(dest.c_str());
}

TEST(VerifiedRootUpdate, RejectsBadHashOrSignature) {
    ASSERT_GE(sodium_init(), 0);
    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);
    std::vector<uint8_t> data = {'d', 'a', 't', 'a'};
    uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr, data.data(), data.size(), sk);

    char sig_b64[200], pk_b64[200];
    sodium_bin2base64(sig_b64, sizeof(sig_b64), sig, sizeof(sig),
                      sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk),
                      sodium_base64_VARIANT_ORIGINAL);

    const std::string dest = "/tmp/ncp_test_roots2.pem";
    std::string err;

    // Wrong hash.
    EXPECT_FALSE(verified_root_update(data, std::string(64, '0'),
                                      sig_b64, pk_b64, dest, &err));

    // Correct hash, corrupted signature.
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);
    char sha_hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        std::snprintf(sha_hex + i * 2, 3, "%02x", digest[i]);
    sha_hex[64] = 0;
    sig[0] ^= 0xFF;
    sodium_bin2base64(sig_b64, sizeof(sig_b64), sig, sizeof(sig),
                      sodium_base64_VARIANT_ORIGINAL);
    EXPECT_FALSE(verified_root_update(data, sha_hex, sig_b64, pk_b64, dest,
                                      &err));
    std::remove(dest.c_str());
}
