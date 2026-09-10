#pragma once

/**
 * @file ncp_scoped_trust.hpp
 * @brief Scoped trust proxy core — NUЦ (Russian national CA) containment.
 *
 * Threat model: a state root CA installed into the *system* trust store
 * can issue trusted certificates for any domain in the world, enabling
 * silent MITM of all traffic (Certificate Transparency does not cover
 * locally installed roots). Strategy: minimise the scope of trust instead
 * of a binary install/don't-install choice.
 *
 * This module keeps the state root INSIDE the NCP process and applies it
 * ONLY to whitelisted RU domains:
 *
 *   - ScopedTrustPolicy: per-domain decision which root set applies.
 *     Default RU rules cover .ru/.рф/.su (+ punycode) and an explicit
 *     bank/gov list. Everything else uses the public root set.
 *   - ScopedTrustStore: an in-process OpenSSL X509_STORE with the custom
 *     roots; the system store is never touched.
 *   - verify_peer_chain(): pick the store per policy and verify a PEM
 *     chain against it. Emits a `custom_root_validation` event whenever a
 *     chain validates against the custom (state) root.
 *   - generate_local_ca(): per-installation local CA (for the browser
 *     side of the scoped trust proxy).
 *   - verified_root_update(): auto-update of the custom root bundle with
 *     SHA-256 pin + Ed25519 signature (same mechanism as NCP releases).
 */

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ncp {

// ==================== Policy ====================

class ScopedTrustPolicy {
public:
    ScopedTrustPolicy();

    /// Suffix rule: ".ru", ".рф", ".xn--p1ai" (leading dot optional).
    void add_suffix_rule(const std::string& suffix);
    /// Exact domain plus its subdomains: "gosuslugi.ru".
    void add_domain(const std::string& domain);
    /// One rule per line; '#' comments; entries as above.
    bool load_rules_file(const std::string& path, std::string* err = nullptr);

    /// Default RU containment rules (.ru/.рф/.su/.xn--p1ai + well-known
    /// bank/gov domains).
    void set_default_rules_ru();

    /// true => host may be validated with the custom (state) root.
    bool uses_custom_root(const std::string& host) const;

    size_t rule_count() const noexcept { return rule_count_; }

private:
    std::vector<std::string> suffixes_;   // lowercase, leading dot
    std::vector<std::string> domains_;    // lowercase, exact+subdomains
    size_t rule_count_ = 0;

    static std::string normalize(std::string s);
};

// ==================== Event feed ====================

struct ScopedTrustEvent {
    std::string host;
    bool custom_root_used = false;   // chain validated against custom root
    bool verified = false;
    std::string details;
};

using ScopedTrustEventCallback = std::function<void(const ScopedTrustEvent&)>;

// ==================== Store + verification ====================

class ScopedTrustStore {
public:
    ScopedTrustStore();
    ~ScopedTrustStore();

    ScopedTrustStore(const ScopedTrustStore&) = delete;
    ScopedTrustStore& operator=(const ScopedTrustStore&) = delete;

    /// Load PEM-encoded root(s) into the in-process custom store.
    bool load_custom_roots_pem(const std::string& pem_path,
                               std::string* err = nullptr);
    size_t custom_root_count() const noexcept { return custom_root_count_; }

    /// Attach an event callback (GUI event feed integration).
    void set_event_callback(ScopedTrustEventCallback cb);

    /// Verify a PEM-encoded server chain for `host`:
    ///   - policy says custom root  => verify against custom store
    ///     (falls back to public roots as well, so the site keeps working
    ///      when it presents a publicly-issued certificate);
    ///   - otherwise                => verify against the system default
    ///     public roots only.
    /// Emits a `custom_root_validation` event on the custom-root path.
    bool verify_peer_chain(const std::string& host,
                           const std::string& pem_chain,
                           const ScopedTrustPolicy& policy,
                           std::string* err = nullptr) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    size_t custom_root_count_ = 0;
    ScopedTrustEventCallback cb_;

    bool verify_with_store(void* store, const std::string& host,
                           const std::string& pem_chain,
                           std::string* err) const;
};

// ==================== Local CA ====================

/// Generate a per-installation local CA (EC P-384, 10y, CA:TRUE,
/// pathlen:0). Writes PEM key/cert (key file must be chmod 600).
bool generate_local_ca(const std::string& key_out_path,
                       const std::string& cert_out_path,
                       const std::string& common_name,
                       std::string* err = nullptr);

// ==================== Verified root update ====================

/// Verify a downloaded root bundle before installing it:
/// SHA-256 of `data` must equal `expected_sha256_hex` and `signature_b64`
/// must be a valid Ed25519 signature of `data` under `pubkey_b64`.
/// Only then is `dest_path` written (atomically, mode 0600).
bool verified_root_update(const std::vector<uint8_t>& data,
                          const std::string& expected_sha256_hex,
                          const std::string& signature_b64,
                          const std::string& pubkey_b64,
                          const std::string& dest_path,
                          std::string* err = nullptr);

} // namespace ncp
