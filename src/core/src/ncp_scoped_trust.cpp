/**
 * @file ncp_scoped_trust.cpp
 * @brief Scoped trust proxy core (see ncp_scoped_trust.hpp)
 */

#include "ncp_scoped_trust.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>

#ifndef _WIN32
# include <sys/stat.h>
#endif

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <sodium.h>

namespace ncp {

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string hex_encode(const uint8_t* p, size_t n) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0x0F]);
    }
    return out;
}

bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
    // Reuse libsodium's base64 (ORIGINAL variant, ignores whitespace).
    out.resize(in.size());
    size_t out_len = 0;
    if (sodium_base642bin(out.data(), out.size(), in.data(), in.size(),
                          " \t\r\n", &out_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return false;
    out.resize(out_len);
    return true;
}

} // namespace

// ==================== ScopedTrustPolicy ====================

ScopedTrustPolicy::ScopedTrustPolicy() = default;

std::string ScopedTrustPolicy::normalize(std::string s) {
    s = to_lower(trim(std::move(s)));
    while (!s.empty() && s.back() == '.') s.pop_back();  // trailing FQDN dot
    return s;
}

void ScopedTrustPolicy::add_suffix_rule(const std::string& suffix) {
    std::string s = normalize(suffix);
    if (s.empty()) return;
    if (s.front() != '.') s = "." + s;
    suffixes_.push_back(s);
    ++rule_count_;
}

void ScopedTrustPolicy::add_domain(const std::string& domain) {
    std::string d = normalize(domain);
    if (d.empty()) return;
    if (!d.empty() && d.front() == '.') d.erase(d.begin());
    domains_.push_back(d);
    ++rule_count_;
}

bool ScopedTrustPolicy::load_rules_file(const std::string& path,
                                        std::string* err) {
    std::ifstream f(path);
    if (!f.is_open()) {
        if (err) *err = "cannot open " + path;
        return false;
    }
    std::string line;
    while (std::getline(f, line)) {
        const size_t hash = line.find('#');
        if (hash != std::string::npos) line.erase(hash);
        line = trim(line);
        if (line.empty()) continue;
        if (line.front() == '.')
            add_suffix_rule(line);
        else
            add_domain(line);
    }
    return true;
}

void ScopedTrustPolicy::set_default_rules_ru() {
    add_suffix_rule(".ru");
    add_suffix_rule(".su");
    // .рф and its punycode form
    add_suffix_rule(".xn--p1ai");
    // Well-known bank/gov domains (explicit, for paranoid configurations
    // that do not want blanket TLD rules).
    static const char* kDomains[] = {
        "gosuslugi.ru", "nalog.ru", "sberbank.ru", "sber.ru", "vtb.ru",
        "tinkoff.ru", "tbank.ru", "alfabank.ru", "gazprombank.ru",
        "rshb.ru", "raiffeisen.ru", "open.ru", "sovcombank.ru",
        "mos.ru", "lkfl2.nalog.ru", "esia.gosuslugi.ru",
    };
    for (const char* d : kDomains)
        add_domain(d);
}

bool ScopedTrustPolicy::uses_custom_root(const std::string& host_in) const {
    const std::string host = normalize(host_in);
    if (host.empty()) return false;
    for (const auto& d : domains_) {
        if (host == d) return true;
        if (host.size() > d.size() &&
            host.compare(host.size() - d.size(), d.size(), d) == 0 &&
            host[host.size() - d.size() - 1] == '.')
            return true;
    }
    for (const auto& s : suffixes_) {
        if (host.size() > s.size() &&
            host.compare(host.size() - s.size(), s.size(), s) == 0)
            return true;
        if (host == s.substr(1))  // bare TLD-ish entry
            return true;
    }
    return false;
}

// ==================== ScopedTrustStore ====================

struct ScopedTrustStore::Impl {
    X509_STORE* custom = nullptr;
    Impl() {
        custom = X509_STORE_new();
    }
    ~Impl() {
        if (custom) X509_STORE_free(custom);
    }
};

ScopedTrustStore::ScopedTrustStore() : impl_(new Impl()) {}
ScopedTrustStore::~ScopedTrustStore() = default;

void ScopedTrustStore::set_event_callback(ScopedTrustEventCallback cb) {
    cb_ = std::move(cb);
}

bool ScopedTrustStore::load_custom_roots_pem(const std::string& pem_path,
                                             std::string* err) {
    if (!impl_->custom) {
        if (err) *err = "X509_STORE allocation failed";
        return false;
    }
    BIO* bio = BIO_new_file(pem_path.c_str(), "r");
    if (!bio) {
        if (err) *err = "cannot open " + pem_path;
        return false;
    }
    size_t loaded = 0;
    for (;;) {
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (!cert) break;  // PEM block exhausted
        if (X509_STORE_add_cert(impl_->custom, cert) == 1)
            ++loaded;
        X509_free(cert);
    }
    BIO_free(bio);
    if (loaded == 0) {
        if (err) *err = "no certificates found in " + pem_path;
        return false;
    }
    custom_root_count_ += loaded;
    return true;
}

bool ScopedTrustStore::verify_with_store(void* store_v, const std::string& host,
                                         const std::string& pem_chain,
                                         std::string* err) const {
    X509_STORE* store = static_cast<X509_STORE*>(store_v);
    if (!store) {
        if (err) *err = "null store";
        return false;
    }
    BIO* bio = BIO_new_mem_buf(pem_chain.data(),
                               static_cast<int>(pem_chain.size()));
    if (!bio) {
        if (err) *err = "BIO allocation failed";
        return false;
    }
    X509* leaf = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (!leaf) {
        BIO_free(bio);
        if (err) *err = "no leaf certificate in chain";
        return false;
    }
    STACK_OF(X509)* untrusted = sk_X509_new_null();
    for (;;) {
        X509* c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        if (!c) break;
        sk_X509_push(untrusted, c);
    }
    BIO_free(bio);

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    bool ok = false;
    if (ctx && X509_STORE_CTX_init(ctx, store, leaf, untrusted) == 1) {
        // Hostname verification (X509_check_host).
        X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_hostflags(param,
                                        X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, host.c_str(), host.size());
        ok = (X509_verify_cert(ctx) == 1);
        if (!ok && err) {
            const int v = X509_STORE_CTX_get_error(ctx);
            *err = X509_verify_cert_error_string(v);
        }
    }
    if (ctx) X509_STORE_CTX_free(ctx);
    sk_X509_pop_free(untrusted, X509_free);
    X509_free(leaf);
    return ok;
}

bool ScopedTrustStore::verify_peer_chain(const std::string& host,
                                         const std::string& pem_chain,
                                         const ScopedTrustPolicy& policy,
                                         std::string* err) const {
    const bool custom = policy.uses_custom_root(host);

    if (custom) {
        // Custom path: the state root applies. Also accept publicly rooted
        // chains so the site keeps working with a normal certificate.
        std::string local_err;
        if (verify_with_store(impl_->custom, host, pem_chain, &local_err)) {
            if (cb_) {
                ScopedTrustEvent ev;
                ev.host = host;
                ev.custom_root_used = true;
                ev.verified = true;
                ev.details = "validated against in-process custom root";
                cb_(ev);
            }
            return true;
        }
        X509_STORE* pub = X509_STORE_new();
        if (pub && X509_STORE_set_default_paths(pub) == 1) {
            const bool ok = verify_with_store(pub, host, pem_chain, err);
            X509_STORE_free(pub);
            if (ok && cb_) {
                ScopedTrustEvent ev;
                ev.host = host;
                ev.custom_root_used = true;  // host is in the custom scope…
                ev.verified = true;
                ev.details = "validated against public roots";
                cb_(ev);
            }
            return ok;
        }
        if (pub) X509_STORE_free(pub);
        if (err) *err = local_err;
        return false;
    }

    // Public path: default system roots only — the state root never
    // applies here.
    X509_STORE* pub = X509_STORE_new();
    if (!pub) {
        if (err) *err = "X509_STORE allocation failed";
        return false;
    }
    bool ok = false;
    if (X509_STORE_set_default_paths(pub) == 1)
        ok = verify_with_store(pub, host, pem_chain, err);
    else if (err)
        *err = "cannot load default public root paths";
    X509_STORE_free(pub);
    if (cb_) {
        ScopedTrustEvent ev;
        ev.host = host;
        ev.custom_root_used = false;
        ev.verified = ok;
        ev.details = ok ? "public roots" : (err ? *err : "verify failed");
        cb_(ev);
    }
    return ok;
}

// ==================== Local CA ====================

bool generate_local_ca(const std::string& key_out_path,
                       const std::string& cert_out_path,
                       const std::string& common_name,
                       std::string* err) {
    bool ok = false;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* kctx = nullptr;
    X509* cert = nullptr;
    FILE* kf = nullptr;
    FILE* cf = nullptr;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx,
                                               NID_secp384r1) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        if (err) *err = "EC keygen failed";
        goto done;
    }

    cert = X509_new();
    if (!cert) {
        if (err) *err = "X509_new failed";
        goto done;
    }
    X509_set_version(cert, 2);  // v3
    {
        // Random 128-bit serial.
        uint8_t serial[16];
        randombytes_buf(serial, sizeof(serial));
        serial[0] &= 0x7F;  // keep positive
        BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
        ASN1_INTEGER* ai = X509_get_serialNumber(cert);
        BN_to_ASN1_INTEGER(bn, ai);
        BN_free(bn);
    }
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert),
                    60L * 60 * 24 * 365 * 10);  // 10 years
    X509_set_pubkey(cert, pkey);
    {
        X509_NAME* name = X509_get_subject_name(cert);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name.c_str()),
            -1, -1, 0);
        X509_set_issuer_name(cert, name);
    }
    {
        // basicConstraints=critical,CA:TRUE,pathlen:0 + keyUsage.
        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, cert, cert, nullptr, nullptr, 0);
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(
            nullptr, &v3ctx, NID_basic_constraints,
            "critical,CA:TRUE,pathlen:0");
        if (!ext) {
            if (err) *err = "basicConstraints failed";
            goto done;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        ext = X509V3_EXT_conf_nid(nullptr, &v3ctx, NID_key_usage,
                                  "critical,keyCertSign,cRLSign");
        if (!ext) {
            if (err) *err = "keyUsage failed";
            goto done;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(cert, pkey, EVP_sha384()) == 0) {
        if (err) *err = "self-sign failed";
        goto done;
    }

    kf = std::fopen(key_out_path.c_str(), "wb");
    if (!kf || PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0,
                                    nullptr, nullptr) != 1) {
        if (err) *err = "cannot write key to " + key_out_path;
        goto done;
    }
    std::fclose(kf);
    kf = nullptr;
#ifndef _WIN32
    chmod(key_out_path.c_str(), 0600);
#endif
    cf = std::fopen(cert_out_path.c_str(), "wb");
    if (!cf || PEM_write_X509(cf, cert) != 1) {
        if (err) *err = "cannot write cert to " + cert_out_path;
        goto done;
    }
    ok = true;

done:
    if (kf) std::fclose(kf);
    if (cf) std::fclose(cf);
    if (cert) X509_free(cert);
    if (pkey) EVP_PKEY_free(pkey);
    if (kctx) EVP_PKEY_CTX_free(kctx);
    return ok;
}

// ==================== Verified root update ====================

bool verified_root_update(const std::vector<uint8_t>& data,
                          const std::string& expected_sha256_hex,
                          const std::string& signature_b64,
                          const std::string& pubkey_b64,
                          const std::string& dest_path,
                          std::string* err) {
    if (sodium_init() < 0) {
        if (err) *err = "sodium_init failed";
        return false;
    }
    // 1. SHA-256 pin.
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);
    if (to_lower(hex_encode(digest, sizeof(digest))) !=
        to_lower(trim(expected_sha256_hex))) {
        if (err) *err = "SHA-256 mismatch";
        return false;
    }
    // 2. Ed25519 signature.
    std::vector<uint8_t> sig, pk;
    if (!b64_decode(signature_b64, sig) ||
        sig.size() != crypto_sign_BYTES ||
        !b64_decode(pubkey_b64, pk) ||
        pk.size() != crypto_sign_PUBLICKEYBYTES) {
        if (err) *err = "bad signature/pubkey encoding";
        return false;
    }
    if (crypto_sign_verify_detached(sig.data(), data.data(), data.size(),
                                    pk.data()) != 0) {
        if (err) *err = "Ed25519 signature verification failed";
        return false;
    }
    // 3. Atomic write (tmp + rename), mode 0600.
    const std::string tmp = dest_path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            if (err) *err = "cannot write " + tmp;
            return false;
        }
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
#ifndef _WIN32
    chmod(tmp.c_str(), 0600);
#endif
    if (std::rename(tmp.c_str(), dest_path.c_str()) != 0) {
        std::remove(tmp.c_str());
        if (err) *err = "rename to " + dest_path + " failed";
        return false;
    }
    return true;
}

} // namespace ncp
