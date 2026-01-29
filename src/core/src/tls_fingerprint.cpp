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
SecureMemory::SecureMemory(size_t size) : size_(size) {
    if (size == 0) {
        data_ = nullptr;
        return;
    }
    
    data_ = static_cast<uint8_t*>(sodium_malloc(size));
    if (!data_) {
        throw std::bad_alloc();
    }
    sodium_mlock(data_, size);
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

void SecureMemory::zero() {
    if (data_ && size_ > 0) {
        sodium_memzero(data_, size_);
    }
}

uint8_t* SecureMemory::data() { return data_; }
const uint8_t* SecureMemory::data() const { return data_; }
size_t SecureMemory::size() const { return size_; }

// SecureString implementation
SecureString::SecureString(const std::string& str)
    : memory_(str.length() + 1) {
    if (str.length() > 0) {
        std::memcpy(memory_.data(), str.c_str(), str.length() + 1);
    }
}

SecureString::SecureString(const char* str)
    : memory_(str ? std::strlen(str) + 1 : 0) {
    if (str && memory_.size() > 0) {
        std::memcpy(memory_.data(), str, memory_.size());
    }
}

SecureString::~SecureString() {
    memory_.zero();
}

const char* SecureString::c_str() const {
    return reinterpret_cast<const char*>(memory_.data());
}

size_t SecureString::length() const {
    return memory_.size() > 0 ? memory_.size() - 1 : 0;
}

// TLSFingerprint implementation
TLSFingerprint::TLSFingerprint() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
    init_default_profiles();
}

std::string TLSFingerprint::generate_ja3() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    std::string ja3_str = std::to_string(current_profile_.tls_version) + ",";
    
    // Ciphers
    for (size_t i = 0; i < current_profile_.cipher_suites.size(); ++i) {
        ja3_str += std::to_string(current_profile_.cipher_suites[i]);
        if (i < current_profile_.cipher_suites.size() - 1) ja3_str += "-";
    }
    ja3_str += ",";
    
    // Extensions
    for (size_t i = 0; i < current_profile_.extensions.size(); ++i) {
        ja3_str += std::to_string(current_profile_.extensions[i]);
        if (i < current_profile_.extensions.size() - 1) ja3_str += "-";
    }
    ja3_str += ",";
    
    // Curves
    for (size_t i = 0; i < current_profile_.supported_groups.size(); ++i) {
        ja3_str += std::to_string(current_profile_.supported_groups[i]);
        if (i < current_profile_.supported_groups.size() - 1) ja3_str += "-";
    }
    ja3_str += ",0";  // Point formats
    
    // MD5 hash of JA3 string (per JA3 specification)
#ifdef HAVE_OPENSSL
    unsigned char hash[16]; // MD5 produces 16 bytes
    MD5(reinterpret_cast<const unsigned char*>(ja3_str.c_str()), ja3_str.length(), hash);
#else
    // Fallback to SHA-256 truncated to 16 bytes when OpenSSL not available
    unsigned char full_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(full_hash, reinterpret_cast<const unsigned char*>(ja3_str.c_str()), ja3_str.length());
    unsigned char hash[16];
    memcpy(hash, full_hash, 16);
#endif
    
    // Convert to hex
    std::string result;
    for (size_t i = 0; i < 16; ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        result += hex;
    }
    
    stats_.ja3_generated++;
    return result;
}

std::string TLSFingerprint::generate_ja4() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // JA4 format: [QUIC/TLS][Version][SNI][Cipher_count][Extension_count]_[Cipher_hash]_[Extension_hash]
    std::string ja4_str = "t";  // TLS (not QUIC)
    ja4_str += std::to_string(current_profile_.tls_version / 256);
    ja4_str += std::to_string(current_profile_.tls_version % 256);
    ja4_str += "d";  // SNI present
    
    char counts[16];
    snprintf(counts, sizeof(counts), "%02zu%02zu_", 
             current_profile_.cipher_suites.size(),
             current_profile_.extensions.size());
    ja4_str += counts;
    
    stats_.ja4_generated++;
    return ja4_str;
}

void TLSFingerprint::randomize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Shuffle cipher suites
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(current_profile_.cipher_suites.begin(),
                 current_profile_.cipher_suites.end(), gen);
    
    // Shuffle extensions (but keep critical ones at start)
    if (current_profile_.extensions.size() > 3) {
        std::shuffle(current_profile_.extensions.begin() + 3,
                     current_profile_.extensions.end(), gen);
    }
    
    // Shuffle supported groups
    std::shuffle(current_profile_.supported_groups.begin(),
                 current_profile_.supported_groups.end(), gen);
    
    stats_.randomizations++;
}

void TLSFingerprint::set_profile(const FingerprintProfile& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_profile_ = profile;
}

FingerprintProfile TLSFingerprint::get_profile() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_profile_;
}

Statistics TLSFingerprint::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void TLSFingerprint::init_default_profiles() {
    // Chrome-like profile
    current_profile_.tls_version = 0x0303;  // TLS 1.2
    current_profile_.cipher_suites = {
        0x1301, 0x1302, 0x1303,  // TLS 1.3 ciphers
        0xc02b, 0xc02f, 0xcca9, 0xcca8,
        0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d
    };
    
    current_profile_.extensions = {
        0x0000,  // server_name
        0x0017,  // extended_master_secret
        0x0023,  // session_ticket
        0x000d,  // signature_algorithms
        0x000a,  // supported_groups
        0x000b,  // ec_point_formats
        0x0010,  // application_layer_protocol_negotiation
        0x0005,  // status_request
        0x0012   // signed_certificate_timestamp
    };
    
    current_profile_.supported_groups = {
        0x001d,  // x25519
        0x0017,  // secp256r1
        0x0018,  // secp384r1
        0x0019   // secp521r1
    };
}

// SecureOps namespace implementation
namespace SecureOps {

bool constant_time_compare(const void* a, const void* b, size_t len) {
    return sodium_memcmp(a, b, len) == 0;
}

std::vector<uint8_t> generate_random(size_t size) {
    std::vector<uint8_t> buffer(size);
    randombytes_buf(buffer.data(), size);
    return buffer;
}

SecureString hash_password(const SecureString& password, const std::vector<uint8_t>& salt) {
    if (salt.size() < crypto_pwhash_SALTBYTES) {
        throw std::invalid_argument("Salt too short");
    }
    
    SecureMemory hash(64);
    
    if (crypto_pwhash(hash.data(), hash.size(),
                      password.c_str(), password.length(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Password hashing failed");
    }
    
    // Convert to hex string
    std::string hex_hash;
    for (size_t i = 0; i < hash.size(); ++i) {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", hash.data()[i]);
        hex_hash += hex;
    }
    
    return SecureString(hex_hash);
}

}  // namespace SecureOps

// FingerprintProfile implementation
void FingerprintProfile::load_browser_profile(BrowserType browser) {
    switch (browser) {
        case BrowserType::Chrome:
            tls_version = 0x0303;
            cipher_suites = {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f};
            extensions = {0x0000, 0x0017, 0x0023, 0x000d, 0x000a};
            supported_groups = {0x001d, 0x0017, 0x0018};
            break;
        case BrowserType::Firefox:
            tls_version = 0x0303;
            cipher_suites = {0x1301, 0x1302, 0x1303, 0xc02c, 0xc030};
            extensions = {0x0000, 0x000a, 0x000b, 0x000d, 0x0010};
            supported_groups = {0x001d, 0x0017, 0x0018, 0x0019};
            break;
        case BrowserType::Safari:
            tls_version = 0x0303;
            cipher_suites = {0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c};
            extensions = {0x0000, 0x000a, 0x000b, 0x000d};
            supported_groups = {0x001d, 0x0017};
            break;
    }
}

}  // namespace NCP
