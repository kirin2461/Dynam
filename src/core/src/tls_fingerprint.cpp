#include "../include/ncp_tls_fingerprint.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <vector>

namespace ncp {

// File-scope PRNG seeded once per thread (avoids repeated std::random_device overhead)
static thread_local std::mt19937 tls_rng(std::random_device{}());

// NOTE: SecureMemory, SecureString, and SecureOps implementations are in ncp_secure_memory.cpp
// Do NOT duplicate them here to avoid ODR violations (LNK4006 on MSVC)

// TLSFingerprint::Impl stub
struct TLSFingerprint::Impl {
    FingerprintProfile profile = FingerprintProfile::CHROME;
    TLSVersion version = TLSVersion::TLS_1_3;
    std::vector<uint16_t> ciphers;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> curves;
    std::string sni;
    std::vector<std::string> alpn;
    bool esni_enabled = false;
    Statistics stats;
};

// TLSFingerprint implementation
TLSFingerprint::TLSFingerprint() : pImpl(std::make_unique<Impl>()) {}
TLSFingerprint::TLSFingerprint(FingerprintProfile profile) : pImpl(std::make_unique<Impl>()) {
    pImpl->profile = profile;
}
TLSFingerprint::~TLSFingerprint() = default;

void TLSFingerprint::set_profile(FingerprintProfile profile) { pImpl->profile = profile; }
TLSFingerprint::FingerprintProfile TLSFingerprint::get_profile() const { return pImpl->profile; }

TLSFingerprint::JA3Fingerprint TLSFingerprint::generate_ja3() const { return {}; }
void TLSFingerprint::apply_ja3(const JA3Fingerprint&) {}
std::string TLSFingerprint::get_ja3_string() const { return "stub"; }
std::string TLSFingerprint::get_ja3_hash() const { return "stub"; }

TLSFingerprint::JA4Fingerprint TLSFingerprint::generate_ja4() const { return {}; }
void TLSFingerprint::apply_ja4(const JA4Fingerprint&) {}
std::string TLSFingerprint::get_ja4_string() const { return "stub"; }

void TLSFingerprint::randomize_all() {
    randomize_ciphers();
    randomize_extensions();
    randomize_curves();
    shuffle_order();
}

void TLSFingerprint::randomize_ciphers() {
    auto all_ciphers = get_profile_ciphers(pImpl->profile);
    if (all_ciphers.size() > 1) {
        std::shuffle(all_ciphers.begin(), all_ciphers.end(), tls_rng);
    }
    pImpl->ciphers = std::move(all_ciphers);
}

void TLSFingerprint::randomize_extensions() {
    auto all_exts = get_profile_extensions(pImpl->profile);
    if (all_exts.size() > 1) {
        std::shuffle(all_exts.begin(), all_exts.end(), tls_rng);
    }
    pImpl->extensions = std::move(all_exts);
}

void TLSFingerprint::randomize_curves() {
    auto all_curves = get_profile_curves(pImpl->profile);
    if (all_curves.size() > 1) {
        std::shuffle(all_curves.begin(), all_curves.end(), tls_rng);
    }
    pImpl->curves = std::move(all_curves);
}

void TLSFingerprint::shuffle_order() {
    if (pImpl->ciphers.size() > 1) {
        std::shuffle(pImpl->ciphers.begin(), pImpl->ciphers.end(), tls_rng);
    }
}

void TLSFingerprint::enable_esni(const ESNIConfig&) { pImpl->esni_enabled = true; }
void TLSFingerprint::enable_ech(const std::vector<uint8_t>&) { pImpl->esni_enabled = true; }
void TLSFingerprint::disable_esni_ech() { pImpl->esni_enabled = false; }
bool TLSFingerprint::is_esni_ech_enabled() const { return pImpl->esni_enabled; }

void TLSFingerprint::set_sni(const std::string& hostname) {
    if (hostname.size() > 255) {
        throw std::invalid_argument("SNI hostname exceeds maximum length");
    }
    pImpl->sni = hostname;
}

std::string TLSFingerprint::get_sni() const { return pImpl->sni; }
void TLSFingerprint::encrypt_sni(const std::vector<uint8_t>&) {}

void TLSFingerprint::set_tls_version(TLSVersion version) { pImpl->version = version; }
TLSFingerprint::TLSVersion TLSFingerprint::get_tls_version() const { return pImpl->version; }

void TLSFingerprint::add_cipher_suite(uint16_t cipher) { pImpl->ciphers.push_back(cipher); }
void TLSFingerprint::set_cipher_suites(const std::vector<uint16_t>& ciphers) { pImpl->ciphers = ciphers; }
std::vector<uint16_t> TLSFingerprint::get_cipher_suites() const { return pImpl->ciphers; }

void TLSFingerprint::add_extension(uint16_t extension) { pImpl->extensions.push_back(extension); }
void TLSFingerprint::set_extensions(const std::vector<uint16_t>& extensions) { pImpl->extensions = extensions; }
std::vector<uint16_t> TLSFingerprint::get_extensions() const { return pImpl->extensions; }

void TLSFingerprint::set_alpn(const std::vector<std::string>& protocols) { pImpl->alpn = protocols; }
std::vector<std::string> TLSFingerprint::get_alpn() const { return pImpl->alpn; }

void TLSFingerprint::protect_session_keys() {}
void TLSFingerprint::clear_sensitive_data() {}

TLSFingerprint::Statistics TLSFingerprint::get_statistics() const { return pImpl->stats; }

// Private methods
std::vector<uint16_t> TLSFingerprint::get_profile_ciphers(FingerprintProfile) const {
    return {0x1301, 0x1302, 0x1303};
}
std::vector<uint16_t> TLSFingerprint::get_profile_extensions(FingerprintProfile) const {
    return {0, 10, 13, 16, 43};
}
std::vector<uint16_t> TLSFingerprint::get_profile_curves(FingerprintProfile) const {
    return {0x001d, 0x0017};
}
void TLSFingerprint::load_browser_profile(BrowserType) {}

// JA3/JA4 methods
std::string TLSFingerprint::JA3Fingerprint::to_string() const { return "stub"; }
std::string TLSFingerprint::JA3Fingerprint::hash() const { return "stub"; }
std::string TLSFingerprint::JA4Fingerprint::to_string() const { return "stub"; }
std::string TLSFingerprint::JA4Fingerprint::hash() const { return "stub"; }

} // namespace ncp
