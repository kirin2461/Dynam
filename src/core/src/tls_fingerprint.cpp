#include "../include/ncp_tls_fingerprint.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <vector>

namespace ncp {

// SecureMemory implementation
SecureMemory::SecureMemory() : data_(nullptr), size_(0) {}

SecureMemory::SecureMemory(size_t size) : data_(nullptr), size_(size) {
    if (size == 0) return;
    data_ = static_cast<uint8_t*>(sodium_malloc(size));
    if (!data_) throw std::bad_alloc();
    sodium_mlock(data_, size_);
}

SecureMemory::~SecureMemory() {
    if (data_) {
        sodium_munlock(data_, size_);
        sodium_free(data_);
    }
}

SecureMemory::SecureMemory(SecureMemory&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureMemory& SecureMemory::operator=(SecureMemory&& other) noexcept {
    if (this != &other) {
        if (data_) {
            sodium_munlock(data_, size_);
            sodium_free(data_);
        }
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void SecureMemory::zero() {
    if (data_ && size_ > 0) {
        sodium_memzero(data_, size_);
    }
}

void SecureMemory::secure_zero(void* ptr, size_t size) {
    sodium_memzero(ptr, size);
}

bool SecureMemory::lock_memory(void* ptr, size_t size) {
    return sodium_mlock(ptr, size) == 0;
}

bool SecureMemory::unlock_memory(void* ptr, size_t size) {
    return sodium_munlock(ptr, size) == 0;
}

// SecureString implementation  
SecureString::SecureString() : data_(nullptr), size_(0), capacity_(0) {}

SecureString::SecureString(const std::string& str) 
    : data_(static_cast<char*>(sodium_malloc(str.size() + 1))),
      size_(str.size()),
      capacity_(str.size() + 1) {
    if (!data_) throw std::bad_alloc();
    std::memcpy(data_, str.c_str(), str.size());
    data_[str.size()] = '\0';
    sodium_mlock(data_, capacity_);
}

SecureString::SecureString(const char* str, size_t len)
    : data_(static_cast<char*>(sodium_malloc(len + 1))),
      size_(len),
      capacity_(len + 1) {
    if (!data_) throw std::bad_alloc();
    std::memcpy(data_, str, len);
    data_[len] = '\0';
    sodium_mlock(data_, capacity_);
}

SecureString::~SecureString() {
    if (data_) {
        sodium_memzero(data_, capacity_);
        sodium_munlock(data_, capacity_);
        sodium_free(data_);
    }
}

SecureString::SecureString(SecureString&& other) noexcept
    : data_(other.data_), size_(other.size_), capacity_(other.capacity_) {
    other.data_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
}

SecureString& SecureString::operator=(SecureString&& other) noexcept {
    if (this != &other) {
        if (data_) {
            sodium_memzero(data_, capacity_);
            sodium_munlock(data_, capacity_);
            sodium_free(data_);
        }
        data_ = other.data_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.data_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    return *this;
}

void SecureString::clear() {
    if (data_) {
        sodium_memzero(data_, capacity_);
        size_ = 0;
    }
}

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

TLSFingerprint::JA3Fingerprint TLSFingerprint::generate_ja3() const {
    return {};
}

void TLSFingerprint::apply_ja3(const JA3Fingerprint&) {}
std::string TLSFingerprint::get_ja3_string() const { return "stub"; }
std::string TLSFingerprint::get_ja3_hash() const { return "stub"; }

TLSFingerprint::JA4Fingerprint TLSFingerprint::generate_ja4() const {
    return {};
}

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
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(all_ciphers.begin(), all_ciphers.end(), g);
    pImpl->ciphers = all_ciphers;
}

void TLSFingerprint::randomize_extensions() {
    auto all_exts = get_profile_extensions(pImpl->profile);
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(all_exts.begin(), all_exts.end(), g);
    pImpl->extensions = all_exts;
}

void TLSFingerprint::randomize_curves() {
    auto all_curves = get_profile_curves(pImpl->profile);
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(all_curves.begin(), all_curves.end(), g);
    pImpl->curves = all_curves;
}

void TLSFingerprint::shuffle_order() {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(pImpl->ciphers.begin(), pImpl->ciphers.end(), g);
}

void TLSFingerprint::enable_esni(const ESNIConfig&) { pImpl->esni_enabled = true; }
void TLSFingerprint::enable_ech(const std::vector<uint8_t>&) { pImpl->esni_enabled = true; }
void TLSFingerprint::disable_esni_ech() { pImpl->esni_enabled = false; }
bool TLSFingerprint::is_esni_ech_enabled() const { return pImpl->esni_enabled; }

void TLSFingerprint::set_sni(const std::string& hostname) { pImpl->sni = hostname; }
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

// SecureOps namespace
namespace SecureOps {
    bool constant_time_compare(const void* a, const void* b, size_t len) {
        return sodium_memcmp(a, b, len) == 0;
    }

    std::vector<uint8_t> generate_random(size_t size) {
        std::vector<uint8_t> result(size);
        randombytes_buf(result.data(), size);
        return result;
    }

    SecureString hash_password(const SecureString& password, const std::vector<uint8_t>&) {
        return SecureString(password.c_str(), password.length());
    }
}

} // namespace ncp
