#include "../include/ncp_tls_fingerprint.hpp"
#include <sodium.h>
#include <random>
#include <algorithm>
#include <cstring>
#include <stdexcept>

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#endif

namespace NCP {

// SecureMemory implementation
SecureMemory::SecureMemory(size_t size) : data_(nullptr), size_(size) {
    if (size == 0) {
        data_ = nullptr;
        return;
    }
    
    data_ = static_cast<uint8_t*>(sodium_malloc(size));
    if (!data_) {
        throw std::bad_alloc();
    }
    sodium_mlock(data_, size_);
}

SecureMemory::~SecureMemory() {
    if (data_) {
        sodium_munlock(data_, size_);
        sodium_free(data_);
        data_ = nullptr;
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

uint8_t* SecureMemory::data() { return data_; }
const uint8_t* SecureMemory::data() const { return data_; }
size_t SecureMemory::size() const { return size_; }

// SecureString implementation
SecureString::SecureString(const std::string& str) {
    memory_ = SecureMemory(str.size() + 1);
    std::memcpy(memory_.data(), str.c_str(), str.size());
    memory_.data()[str.size()] = '\0';
}

SecureString::SecureString(const char* str, size_t len) {
    memory_ = SecureMemory(len + 1);
    std::memcpy(memory_.data(), str, len);
    memory_.data()[len] = '\0';
}

const char* SecureString::c_str() const {
    return reinterpret_cast<const char*>(memory_.data());
}

size_t SecureString::length() const {
    return memory_.size() > 0 ? memory_.size() - 1 : 0;
}

// FingerprintProfile implementation
FingerprintProfile::FingerprintProfile() {}

FingerprintProfile::FingerprintProfile(BrowserType type, const std::string& version)
    : browser_type(type), version(version) {}

// TLSFingerprint implementation
TLSFingerprint::TLSFingerprint() {}

TLSFingerprint::~TLSFingerprint() {}

std::vector<uint16_t> TLSFingerprint::get_cipher_suites(BrowserType browser) const {
    return {
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035
    };
}

std::vector<uint16_t> TLSFingerprint::get_extensions(BrowserType browser) const {
    return {
        0x0000, 0x0017, 0x0023, 0x000d, 0x0005, 0x000a, 0x000b,
        0x0010, 0x0012, 0x002b, 0x002d, 0x001b, 0x0033, 0xfe0d
    };
}

std::vector<uint16_t> TLSFingerprint::get_supported_groups(BrowserType browser) const {
    return {0x001d, 0x0017, 0x0018, 0x0019};
}

std::vector<uint8_t> TLSFingerprint::get_signature_algorithms(BrowserType browser) const {
    return {0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06};
}

std::vector<uint16_t> TLSFingerprint::get_supported_versions(BrowserType browser) const {
    return {0x0304, 0x0303};
}

std::string TLSFingerprint::generate_ja3_fingerprint(BrowserType browser) const {
    return "stub_ja3";
}

std::string TLSFingerprint::generate_ja4_fingerprint(BrowserType browser) const {
    return "stub_ja4";
}

bool TLSFingerprint::validate_fingerprint(const std::string& fp) const {
    return !fp.empty();
}

FingerprintProfile TLSFingerprint::get_profile(BrowserType browser) const {
    return FingerprintProfile(browser, "1.0");
}

void TLSFingerprint::set_custom_profile(const FingerprintProfile& profile) {
    custom_profile_ = profile;
}

void TLSFingerprint::randomize_fingerprint() {}

std::string TLSFingerprint::get_client_hello_data(BrowserType browser) const {
    return "client_hello_stub";
}

void TLSFingerprint::apply_to_connection(void* ssl_ctx, BrowserType browser) {}

void TLSFingerprint::load_browser_profile(BrowserType browser) {}

// JA3Fingerprint implementation
std::string TLSFingerprint::JA3Fingerprint::to_string() const {
    return "stub";
}

std::string TLSFingerprint::JA3Fingerprint::hash() const {
    return "stub";
}

// JA4Fingerprint implementation
std::string TLSFingerprint::JA4Fingerprint::to_string() const {
    return "stub";
}

std::string TLSFingerprint::JA4Fingerprint::hash() const {
    return "stub";
}

} // namespace NCP
