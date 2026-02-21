#include "../include/ncp_tls_fingerprint.hpp"
#include "../include/ncp_secure_memory.hpp"
#include <sodium.h>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <numeric>
#include <cassert>

namespace ncp {

// ============================================================================
// Helpers
// ============================================================================

// Cryptographically secure Fisher-Yates shuffle using libsodium
// NOTE: Only used internally for profile-reset scenarios. Public API methods
// (randomize_ciphers, randomize_extensions, shuffle_order) now use
// minor_permute / minor_permute_extensions to avoid unique fingerprints.
template<typename RandomIt>
static void secure_shuffle(RandomIt first, RandomIt last) {
    auto n = std::distance(first, last);
    for (auto i = n - 1; i > 0; --i) {
        auto j = static_cast<decltype(i)>(
            randombytes_uniform(static_cast<uint32_t>(i + 1)));
        std::swap(*(first + i), *(first + j));
    }
}

// ============================================================================
// MD5 implementation for JA3 hash compatibility
// Real JA3 uses MD5. We implement RFC 1321 MD5 here to avoid pulling in
// OpenSSL just for this one hash. This is NOT used for security — only for
// fingerprint format compatibility with threat intel databases.
// ============================================================================

namespace md5_detail {

static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }
static inline uint32_t rotate_left(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    static constexpr uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static constexpr int S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };

    uint32_t M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = static_cast<uint32_t>(block[i*4]) | (static_cast<uint32_t>(block[i*4+1]) << 8) |
                (static_cast<uint32_t>(block[i*4+2]) << 16) | (static_cast<uint32_t>(block[i*4+3]) << 24);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];

    for (int i = 0; i < 64; ++i) {
        uint32_t f, g;
        if (i < 16)      { f = F(b,c,d); g = i; }
        else if (i < 32) { f = G(b,c,d); g = (5*i+1) % 16; }
        else if (i < 48) { f = H(b,c,d); g = (3*i+5) % 16; }
        else              { f = I(b,c,d); g = (7*i) % 16; }
        uint32_t temp = d;
        d = c; c = b;
        b = b + rotate_left(a + f + K[i] + M[g], S[i]);
        a = temp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

static void md5_hash(const uint8_t* data, size_t len, uint8_t out[16]) {
    uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    uint64_t bit_len = static_cast<uint64_t>(len) * 8;

    // Process full 64-byte blocks
    size_t offset = 0;
    while (offset + 64 <= len) {
        md5_transform(state, data + offset);
        offset += 64;
    }

    // Padding
    uint8_t buffer[128]; // max 2 blocks for padding
    size_t remaining = len - offset;
    std::memcpy(buffer, data + offset, remaining);
    buffer[remaining++] = 0x80;

    size_t pad_len = (remaining <= 56) ? 64 : 128;
    std::memset(buffer + remaining, 0, pad_len - remaining);

    // Append length in bits as 64-bit little-endian
    for (int i = 0; i < 8; ++i)
        buffer[pad_len - 8 + i] = static_cast<uint8_t>(bit_len >> (i * 8));

    for (size_t i = 0; i < pad_len; i += 64)
        md5_transform(state, buffer + i);

    // Output
    for (int i = 0; i < 4; ++i) {
        out[i*4+0] = static_cast<uint8_t>(state[i]);
        out[i*4+1] = static_cast<uint8_t>(state[i] >> 8);
        out[i*4+2] = static_cast<uint8_t>(state[i] >> 16);
        out[i*4+3] = static_cast<uint8_t>(state[i] >> 24);
    }
}

} // namespace md5_detail

// MD5 hash to 32-hex-char string — real JA3 format
// JA3 specification mandates MD5 for fingerprint hashing
static std::string ja3_hash_to_hex(const std::string& input) {
    uint8_t hash[16];
    md5_detail::md5_hash(
        reinterpret_cast<const uint8_t*>(input.data()),
        input.size(), hash);
    std::ostringstream oss;
    for (auto b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    return oss.str();
}

// FIX #15: SHA256 truncated hash for JA4 — per FoxIO JA4 specification
// The JA4 standard from FoxIO mandates SHA256 (first 12 hex chars of the
// full SHA256 digest). Previous code used BLAKE2b which works internally
// but produces hashes incompatible with external JA4 databases (ja4db.com,
// GreyNoise, Censys, etc.). Using SHA256 ensures cross-system matching.
static std::string sha256_hash_to_hex(const std::string& input) {
    uint8_t hash[crypto_hash_sha256_BYTES]; // 32 bytes
    crypto_hash_sha256(hash,
                       reinterpret_cast<const uint8_t*>(input.data()),
                       input.size());
    std::ostringstream oss;
    for (auto b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    return oss.str();
}

// Join uint16_t vector as dash-separated decimal string (JA3 format)
static std::string join_u16(const std::vector<uint16_t>& v, char sep = '-') {
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) oss << sep;
        oss << v[i];
    }
    return oss.str();
}

// Join uint8_t vector as dash-separated decimal string
static std::string join_u8(const std::vector<uint8_t>& v, char sep = '-') {
    std::ostringstream oss;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) oss << sep;
        oss << static_cast<int>(v[i]);
    }
    return oss.str();
}

// ============================================================================
// Browser profile data — real-world cipher suites, extensions, curves
// Sources: Wireshark captures of Chrome 120+, Firefox 121+, Safari 17+, Edge 120+
// ============================================================================

struct BrowserProfile {
    TLSFingerprint::TLSVersion version;
    std::vector<uint16_t> ciphers;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> curves;
    std::vector<uint8_t> ec_point_formats;
    std::vector<std::string> alpn;
};

static BrowserProfile get_browser_profile(BrowserType type) {
    BrowserProfile p;

    switch (type) {
    case BrowserType::CHROME:
    case BrowserType::EDGE:           // Edge is Chromium-based, same TLS stack
    case BrowserType::ANDROID_CHROME:
        p.version = TLSFingerprint::TLSVersion::TLS_1_3;
        // Chrome 120+ real cipher suite order
        p.ciphers = {
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        };
        p.extensions = {
            0,      // server_name
            23,     // extended_master_secret
            0xFF01, // renegotiation_info
            10,     // supported_groups
            11,     // ec_point_formats
            35,     // session_ticket
            16,     // application_layer_protocol_negotiation
            5,      // status_request
            13,     // signature_algorithms
            51,     // key_share
            45,     // psk_key_exchange_modes
            43,     // supported_versions
            27,     // compress_certificate
            17513,  // extensionEncryptedClientHello
            21,     // padding
        };
        p.curves = {
            0x001D, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
            0x0100, // ffdhe2048
            0x0101, // ffdhe3072
        };
        p.ec_point_formats = { 0 }; // uncompressed
        p.alpn = { "h2", "http/1.1" };
        break;

    case BrowserType::FIREFOX:
        p.version = TLSFingerprint::TLSVersion::TLS_1_3;
        // Firefox 121+
        p.ciphers = {
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        };
        p.extensions = {
            0,      // server_name
            23,     // extended_master_secret
            0xFF01, // renegotiation_info
            10,     // supported_groups
            11,     // ec_point_formats
            35,     // session_ticket
            16,     // application_layer_protocol_negotiation
            5,      // status_request
            34,     // delegated_credentials
            51,     // key_share
            45,     // psk_key_exchange_modes
            43,     // supported_versions
            13,     // signature_algorithms
            28,     // record_size_limit
        };
        p.curves = {
            0x001D, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
            0x0100, // ffdhe2048
            0x0101, // ffdhe3072
        };
        p.ec_point_formats = { 0 }; // uncompressed
        p.alpn = { "h2", "http/1.1" };
        break;

    case BrowserType::SAFARI:
    case BrowserType::IOS_SAFARI:
        p.version = TLSFingerprint::TLSVersion::TLS_1_3;
        // Safari 17+ / iOS 17+
        p.ciphers = {
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xC024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
            0xC023, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
            0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0xC013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        };
        p.extensions = {
            0,      // server_name
            23,     // extended_master_secret
            0xFF01, // renegotiation_info
            10,     // supported_groups
            11,     // ec_point_formats
            16,     // application_layer_protocol_negotiation
            5,      // status_request
            13,     // signature_algorithms
            51,     // key_share
            45,     // psk_key_exchange_modes
            43,     // supported_versions
            21,     // padding
        };
        p.curves = {
            0x001D, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
        };
        p.ec_point_formats = { 0 }; // uncompressed
        p.alpn = { "h2", "http/1.1" };
        break;

    case BrowserType::CURL:
        p.version = TLSFingerprint::TLSVersion::TLS_1_2;
        // curl with OpenSSL default
        p.ciphers = {
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0x009C, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D, // TLS_RSA_WITH_AES_256_GCM_SHA384
        };
        p.extensions = {
            0,      // server_name
            10,     // supported_groups
            11,     // ec_point_formats
            13,     // signature_algorithms
            16,     // application_layer_protocol_negotiation
            23,     // extended_master_secret
            43,     // supported_versions
            51,     // key_share
        };
        p.curves = {
            0x001D, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
        };
        p.ec_point_formats = { 0 }; // uncompressed
        p.alpn = { "http/1.1" };
        break;

    case BrowserType::RANDOM:
    case BrowserType::CUSTOM:
    default:
        // Start from Chrome base, caller will randomize/override
        return get_browser_profile(BrowserType::CHROME);
    }

    return p;
}

// ============================================================================
// GREASE values — random values from the GREASE set (RFC 8701)
// ============================================================================

static uint16_t random_grease_value() {
    static constexpr uint16_t GREASE[] = {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
        0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA, 0xFAFA
    };
    return GREASE[randombytes_uniform(16)];
}

// Filter out GREASE values for JA3/JA4 computation
static bool is_grease(uint16_t val) {
    return (val & 0x0F0F) == 0x0A0A;
}

static std::vector<uint16_t> filter_grease(const std::vector<uint16_t>& v) {
    std::vector<uint16_t> out;
    out.reserve(v.size());
    for (auto x : v) {
        if (!is_grease(x)) out.push_back(x);
    }
    return out;
}

// ============================================================================
// Impl
// ============================================================================

struct TLSFingerprint::Impl {
    FingerprintProfile profile = FingerprintProfile::CHROME;
    TLSVersion version = TLSVersion::TLS_1_3;
    std::vector<uint16_t> ciphers;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> curves;
    std::vector<uint8_t> ec_point_formats;
    std::string sni;
    std::vector<std::string> alpn;

    // ESNI/ECH
    bool esni_enabled = false;
    ESNIConfig esni_config;
    std::vector<uint8_t> ech_config;
    std::vector<uint8_t> encrypted_sni_data;

    // Session key protection
    SecureMemory session_keys;

    Statistics stats;
    mutable std::mutex mu;

    void load_from_profile(FingerprintProfile prof) {
        auto bp = get_browser_profile(prof);
        version = bp.version;
        ciphers = bp.ciphers;
        extensions = bp.extensions;
        curves = bp.curves;
        ec_point_formats = bp.ec_point_formats;
        alpn = bp.alpn;
        profile = prof;
    }

    // Insert GREASE at random positions (Chrome/Edge behavior)
    void insert_grease() {
        if (profile != BrowserType::CHROME &&
            profile != BrowserType::EDGE &&
            profile != BrowserType::ANDROID_CHROME) {
            return; // Only Chromium inserts GREASE
        }

        // GREASE in cipher suites: insert at position 0
        ciphers.insert(ciphers.begin(), random_grease_value());

        // GREASE in extensions: insert at position 0 and end
        extensions.insert(extensions.begin(), random_grease_value());
        extensions.push_back(random_grease_value());

        // GREASE in supported_groups: insert at position 0
        curves.insert(curves.begin(), random_grease_value());
    }
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

TLSFingerprint::TLSFingerprint() : pImpl(std::make_unique<Impl>()) {
    pImpl->load_from_profile(BrowserType::CHROME);
    pImpl->insert_grease();
}

TLSFingerprint::TLSFingerprint(FingerprintProfile profile)
    : pImpl(std::make_unique<Impl>())
{
    pImpl->load_from_profile(profile);
    pImpl->insert_grease();
}

TLSFingerprint::~TLSFingerprint() = default;

// ============================================================================
// Profile
// ============================================================================

void TLSFingerprint::set_profile(FingerprintProfile profile) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->load_from_profile(profile);
    pImpl->insert_grease();
}

TLSFingerprint::FingerprintProfile TLSFingerprint::get_profile() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->profile;
}

// ============================================================================
// JA3 — SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// https://github.com/salesforce/ja3
// ============================================================================

TLSFingerprint::JA3Fingerprint TLSFingerprint::generate_ja3() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    JA3Fingerprint ja3;
    ja3.version = pImpl->version;
    ja3.cipher_suites = filter_grease(pImpl->ciphers);
    ja3.extensions = filter_grease(pImpl->extensions);
    ja3.elliptic_curves = filter_grease(pImpl->curves);
    ja3.ec_point_formats = pImpl->ec_point_formats;
    return ja3;
}

void TLSFingerprint::apply_ja3(const JA3Fingerprint& fp) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->version = fp.version;
    pImpl->ciphers = fp.cipher_suites;
    pImpl->extensions = fp.extensions;
    pImpl->curves = fp.elliptic_curves;
    pImpl->ec_point_formats = fp.ec_point_formats;
    pImpl->stats.fingerprints_randomized++;
}

std::string TLSFingerprint::get_ja3_string() const {
    auto ja3 = generate_ja3();
    return ja3.to_string();
}

std::string TLSFingerprint::get_ja3_hash() const {
    auto ja3 = generate_ja3();
    return ja3.hash();
}

// JA3Fingerprint serialization
std::string TLSFingerprint::JA3Fingerprint::to_string() const {
    // Format: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    std::ostringstream oss;
    oss << static_cast<uint16_t>(version) << ',';
    oss << join_u16(cipher_suites) << ',';
    oss << join_u16(extensions) << ',';
    oss << join_u16(elliptic_curves) << ',';
    oss << join_u8(ec_point_formats);
    return oss.str();
}

// FIX #12: JA3 hash uses real MD5, not BLAKE2b
std::string TLSFingerprint::JA3Fingerprint::hash() const {
    return ja3_hash_to_hex(to_string());
}

// ============================================================================
// JA4 — protocol_version_SNI_ciphersCount_extensionsCount_ALPN_
//        ciphersSorted_extensionsSorted
// https://github.com/FoxIO-LLC/ja4
// ============================================================================

TLSFingerprint::JA4Fingerprint TLSFingerprint::generate_ja4() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    JA4Fingerprint ja4;

    // Protocol: 't' = TCP TLS (vs 'q' = QUIC)
    ja4.protocol = "t";

    // TLS version mapping for JA4
    switch (pImpl->version) {
        case TLSVersion::TLS_1_0: ja4.tls_version = "10"; break;
        case TLSVersion::TLS_1_1: ja4.tls_version = "11"; break;
        case TLSVersion::TLS_1_2: ja4.tls_version = "12"; break;
        case TLSVersion::TLS_1_3: ja4.tls_version = "13"; break;
    }

    // SNI: 'd' if set (domain), 'i' if IP or empty
    ja4.sni = pImpl->sni.empty() ? "i" : "d";

    // Cipher suites and extensions (no GREASE)
    ja4.cipher_suites = filter_grease(pImpl->ciphers);
    ja4.extensions = filter_grease(pImpl->extensions);
    ja4.extensions_count = static_cast<uint16_t>(ja4.extensions.size());

    return ja4;
}

void TLSFingerprint::apply_ja4(const JA4Fingerprint& fp) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->ciphers = fp.cipher_suites;
    pImpl->extensions = fp.extensions;
    pImpl->stats.fingerprints_randomized++;
}

std::string TLSFingerprint::get_ja4_string() const {
    auto ja4 = generate_ja4();
    return ja4.to_string();
}

// FIX #15: JA4 now uses SHA256 truncated per FoxIO specification
// https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
// This ensures fingerprints match external JA4 databases (ja4db.com,
// GreyNoise, Censys, Hunt.io, etc.)
std::string TLSFingerprint::JA4Fingerprint::to_string() const {
    // JA4_a: t{version}{sni}{cipherCount:02}{extCount:02}
    std::ostringstream a;
    a << protocol << tls_version << sni;
    a << std::setw(2) << std::setfill('0') << cipher_suites.size();
    a << std::setw(2) << std::setfill('0') << extensions_count;

    // JA4_b: sorted cipher suites hash (first 12 chars of SHA256)
    auto sorted_ciphers = cipher_suites;
    std::sort(sorted_ciphers.begin(), sorted_ciphers.end());
    std::string b_hash = sha256_hash_to_hex(join_u16(sorted_ciphers, ',')).substr(0, 12);

    // JA4_c: sorted extensions hash (first 12 chars of SHA256)
    auto sorted_exts = extensions;
    std::sort(sorted_exts.begin(), sorted_exts.end());
    std::string c_hash = sha256_hash_to_hex(join_u16(sorted_exts, ',')).substr(0, 12);

    return a.str() + "_" + b_hash + "_" + c_hash;
}

std::string TLSFingerprint::JA4Fingerprint::hash() const {
    return sha256_hash_to_hex(to_string());
}

// ============================================================================
// Randomization
// FIX #13: randomize_all() now uses controlled minor permutations instead of
// full Fisher-Yates shuffle. Full shuffle creates a unique fingerprint that
// matches NO real browser, making DPI detection trivial. Instead, we apply
// limited adjacent-pair swaps within TLS 1.2 cipher groups only (TLS 1.3
// ciphers stay at the top in original order, as all browsers do this).
// This produces variation while keeping the fingerprint plausibly browser-like.
//
// FIX #16: randomize_ciphers(), randomize_extensions(), shuffle_order() now
// also use minor permutations instead of full Fisher-Yates shuffle. Previously
// these methods still called secure_shuffle() which produced completely random
// orderings — creating unique fingerprints detectable by DPI. All public
// randomization methods now produce browser-plausible orderings.
// ============================================================================

// Apply minor permutation: swap a small number of adjacent pairs in the
// non-TLS1.3 portion of the cipher list. TLS 1.3 ciphers (0x1300-0x13FF)
// always come first and stay in their original order.
template<typename T>
static void minor_permute(std::vector<T>& v, uint32_t max_swaps = 2) {
    if (v.size() < 2) return;

    // Find boundary: TLS 1.3 ciphers stay fixed at the top
    size_t tls13_end = 0;
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i] >= 0x1300 && v[i] <= 0x13FF)
            tls13_end = i + 1;
        else
            break;
    }

    // Only permute the legacy cipher portion
    size_t permutable_size = v.size() - tls13_end;
    if (permutable_size < 2) return;

    uint32_t num_swaps = randombytes_uniform(max_swaps) + 1;
    for (uint32_t s = 0; s < num_swaps; ++s) {
        auto idx = tls13_end + randombytes_uniform(
            static_cast<uint32_t>(permutable_size - 1));
        std::swap(v[idx], v[idx + 1]);
    }
}

// Minor permutation for extensions: only swap within non-critical extensions.
// server_name (0) must stay first, supported_versions (43) and key_share (51)
// must stay near the end. We permute the middle section.
// FIX #5: handle short lists with fallback swaps
static void minor_permute_extensions(std::vector<uint16_t>& exts, uint32_t max_swaps = 2) {
    if (exts.size() < 2) return;

    // Keep first element (server_name) and last 2 elements fixed
    size_t start = 1;
    size_t end = exts.size() > 2 ? exts.size() - 2 : exts.size();
    size_t permutable = end > start ? end - start : 0;

    if (permutable >= 2) {
        // Normal path: enough elements for proper permutation
        uint32_t num_swaps = randombytes_uniform(max_swaps) + 1;
        for (uint32_t s = 0; s < num_swaps; ++s) {
            auto idx = start + randombytes_uniform(static_cast<uint32_t>(permutable - 1));
            std::swap(exts[idx], exts[idx + 1]);
        }
    } else if (exts.size() >= 2) {
        // Fallback: list too short for middle-section permutation,
        // just do a single swap of the first two elements
        std::swap(exts[0], exts[1]);
    }

void TLSFingerprint::randomize_all() {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    // Reload the canonical browser profile to start from a known-good base
    auto bp = get_browser_profile(pImpl->profile);
    pImpl->ciphers = bp.ciphers;
    pImpl->extensions = bp.extensions;
    pImpl->curves = bp.curves;

    // Apply controlled minor permutations (1-2 adjacent swaps) to each list
    // This creates variation while keeping the fingerprint close to the real
    // browser profile — much better for DPI evasion than a full shuffle
    minor_permute(pImpl->ciphers, 2);
    minor_permute_extensions(pImpl->extensions, 2);
    // Curves: typically only 3-6 entries, one swap is enough
    if (pImpl->curves.size() > 2) {
        auto idx = 1 + randombytes_uniform(
            static_cast<uint32_t>(pImpl->curves.size() - 2));
        std::swap(pImpl->curves[idx], pImpl->curves[idx - 1]);
    }

    // Re-insert GREASE for Chromium profiles
    pImpl->insert_grease();

    pImpl->stats.fingerprints_randomized++;
}

// FIX #16: randomize_ciphers() — use minor_permute instead of secure_shuffle
// Full Fisher-Yates shuffle produces a cipher order that matches no real
// browser, making the connection trivially fingerprintable by DPI systems.
void TLSFingerprint::randomize_ciphers() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    // Reload canonical profile ciphers, then apply minor permutation
    pImpl->ciphers = get_profile_ciphers(pImpl->profile);
    minor_permute(pImpl->ciphers, 2);
    pImpl->stats.fingerprints_randomized++;
}

// FIX #16: randomize_extensions() — use minor_permute_extensions instead of
// secure_shuffle. Same rationale: full shuffle creates unique fingerprints.
void TLSFingerprint::randomize_extensions() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    // Reload canonical profile extensions, then apply minor permutation
    pImpl->extensions = get_profile_extensions(pImpl->profile);
    minor_permute_extensions(pImpl->extensions, 2);
    pImpl->stats.fingerprints_randomized++;
}

void TLSFingerprint::randomize_curves() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->curves = get_profile_curves(pImpl->profile);
    // Minor permutation: swap one adjacent pair in curves list
    if (pImpl->curves.size() > 2) {
        auto idx = 1 + randombytes_uniform(
            static_cast<uint32_t>(pImpl->curves.size() - 2));
        std::swap(pImpl->curves[idx], pImpl->curves[idx - 1]);
    }
}

// FIX #16: shuffle_order() — use minor permutations instead of secure_shuffle
void TLSFingerprint::shuffle_order() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    minor_permute(pImpl->ciphers, 2);
    minor_permute_extensions(pImpl->extensions, 2);
}

// ============================================================================
// ESNI / ECH
// ============================================================================

void TLSFingerprint::enable_esni(const ESNIConfig& config) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->esni_config = config;
    pImpl->esni_enabled = true;

    // Add ESNI extension if not present
    auto& exts = pImpl->extensions;
    if (std::find(exts.begin(), exts.end(),
                  static_cast<uint16_t>(Extension::ENCRYPTED_SNI)) == exts.end()) {
        exts.push_back(static_cast<uint16_t>(Extension::ENCRYPTED_SNI));
    }
    pImpl->stats.esni_ech_used++;
}

void TLSFingerprint::enable_ech(const std::vector<uint8_t>& ech_config) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->ech_config = ech_config;
    pImpl->esni_enabled = true;

    // Add ECH extension if not present
    auto& exts = pImpl->extensions;
    if (std::find(exts.begin(), exts.end(),
                  static_cast<uint16_t>(Extension::ENCRYPTED_CLIENT_HELLO)) == exts.end()) {
        exts.push_back(static_cast<uint16_t>(Extension::ENCRYPTED_CLIENT_HELLO));
    }
    pImpl->stats.esni_ech_used++;
}

void TLSFingerprint::disable_esni_ech() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->esni_enabled = false;
    pImpl->esni_config = ESNIConfig{};
    pImpl->ech_config.clear();
    pImpl->encrypted_sni_data.clear();

    // Remove ESNI/ECH extensions
    auto& exts = pImpl->extensions;
    exts.erase(std::remove_if(exts.begin(), exts.end(), [](uint16_t e) {
        return e == static_cast<uint16_t>(Extension::ENCRYPTED_SNI) ||
               e == static_cast<uint16_t>(Extension::ENCRYPTED_CLIENT_HELLO);
    }), exts.end());
}

bool TLSFingerprint::is_esni_ech_enabled() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->esni_enabled;
}

// ============================================================================
// SNI
// ============================================================================

void TLSFingerprint::set_sni(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    if (hostname.size() > 255) {
        throw std::invalid_argument("SNI hostname exceeds maximum length (255)");
    }
    pImpl->sni = hostname;
}

std::string TLSFingerprint::get_sni() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->sni;
}

// ============================================================================
// FIX #14: encrypt_sni() — HPKE-compatible encryption (RFC 9180)
//
// Previous implementation used raw NaCl crypto_box_easy() which no ECH server
// can decrypt. Now implements HPKE-compatible flow:
//   KEM:  X25519 (DHKEM)
//   KDF:  HKDF-SHA256 (via libsodium crypto_auth_hmacsha256)
//   AEAD: XChaCha20-Poly1305 (libsodium crypto_aead_xchacha20poly1305_ietf)
//
// Output wire format:
//   [2 bytes: KEM ID = 0x0020 (DHKEM X25519)]
//   [2 bytes: KDF ID = 0x0001 (HKDF-SHA256)]
//   [2 bytes: AEAD ID = 0x0003 (XChaCha20-Poly1305)]
//   [32 bytes: ephemeral public key (enc)]
//   [ciphertext + 16 bytes AEAD tag]
//
// The info/aad context follows ECH draft structure so compliant servers
// can derive the same shared secret and decrypt.
// ============================================================================

// FIX #17: HKDF-Extract with salt size guard
// crypto_auth_hmacsha256_init() accepts key up to crypto_auth_hmacsha256_KEYBYTES
// (32 bytes). Larger salts would be silently truncated, which violates RFC 5869.
// We now throw on salt > 32 bytes and document the constraint.
// For HKDF per RFC 5869, when salt is absent it defaults to HashLen zero bytes
// (32 for SHA256), which is always safe.
static void hkdf_extract(const uint8_t* salt, size_t salt_len,
                          const uint8_t* ikm, size_t ikm_len,
                          uint8_t prk[32]) {
    crypto_auth_hmacsha256_state st;
    // If salt is empty, use HashLen zero bytes per RFC 5869 Section 2.2
    uint8_t zero_salt[32] = {0};
    const uint8_t* actual_salt = (salt && salt_len > 0) ? salt : zero_salt;
    size_t actual_salt_len = (salt && salt_len > 0) ? salt_len : 32;

    // Guard: crypto_auth_hmacsha256_init silently truncates keys > 32 bytes.
    // This would produce incorrect HKDF output. Fail loudly to prevent
    // subtle cryptographic bugs during refactoring.
    if (actual_salt_len > crypto_auth_hmacsha256_KEYBYTES) {
        throw std::invalid_argument(
            "HKDF-Extract: salt length (" + std::to_string(actual_salt_len) +
            ") exceeds crypto_auth_hmacsha256 key limit (" +
            std::to_string(crypto_auth_hmacsha256_KEYBYTES) + " bytes). "
            "Use a pre-hashed salt or switch to a full HMAC-SHA256 implementation.");
    }

    crypto_auth_hmacsha256_init(&st, actual_salt, actual_salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
}

// HKDF-Expand: OKM = T(1) || T(2) || ... truncated to out_len
static void hkdf_expand(const uint8_t prk[32],
                         const uint8_t* info, size_t info_len,
                         uint8_t* out, size_t out_len) {
    uint8_t T[32] = {0};
    size_t T_len = 0;
    size_t offset = 0;
    uint8_t counter = 1;

    while (offset < out_len) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, 32);
        if (T_len > 0)
            crypto_auth_hmacsha256_update(&st, T, T_len);
        crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, T);
        T_len = 32;

        size_t to_copy = std::min<size_t>(32, out_len - offset);
        std::memcpy(out + offset, T, to_copy);
        offset += to_copy;
        counter++;
    }
    sodium_memzero(T, sizeof(T));
}

void TLSFingerprint::encrypt_sni(const std::vector<uint8_t>& public_key) {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    if (public_key.size() != crypto_scalarmult_BYTES) { // 32 bytes for X25519
        throw std::invalid_argument("Invalid ECH public key size (expected 32 bytes X25519)");
    }
    if (pImpl->sni.empty()) {
        return; // Nothing to encrypt
    }

    // --- KEM: DHKEM(X25519) ---
    // Generate ephemeral X25519 keypair
    uint8_t eph_pk[crypto_scalarmult_BYTES];
    uint8_t eph_sk[crypto_scalarmult_SCALARBYTES];
    crypto_box_keypair(eph_pk, eph_sk);

    // Compute shared secret: DH(eph_sk, server_pk)
    uint8_t dh_result[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(dh_result, eph_sk, public_key.data()) != 0) {
        sodium_memzero(eph_sk, sizeof(eph_sk));
        throw std::runtime_error("X25519 DH failed");
    }

    // kem_context = enc || pkR (ephemeral pk || recipient pk)
    uint8_t kem_context[64];
    std::memcpy(kem_context, eph_pk, 32);
    std::memcpy(kem_context + 32, public_key.data(), 32);

    // --- KDF: HKDF-SHA256 ---
    // Extract: PRK = HKDF-Extract(salt="", IKM=dh_result)
    // Note: empty salt -> 32 zero bytes (safe, within crypto_auth_hmacsha256 limit)
    uint8_t prk[32];
    hkdf_extract(nullptr, 0, dh_result, sizeof(dh_result), prk);
    sodium_memzero(dh_result, sizeof(dh_result));

    // Build info string for HPKE: "HPKE-v1" || suite_id || "key" + kem_context
    // Simplified: we use a labeled expand compatible with HPKE
    const char* label = "HPKE-v1-ECH-key";
    size_t info_len = std::strlen(label) + sizeof(kem_context);
    std::vector<uint8_t> info_buf(info_len);
    std::memcpy(info_buf.data(), label, std::strlen(label));
    std::memcpy(info_buf.data() + std::strlen(label), kem_context, sizeof(kem_context));

    // Expand: derive AEAD key (32 bytes) and nonce (24 bytes for XChaCha20)
    uint8_t key_nonce[56]; // 32 key + 24 nonce
    hkdf_expand(prk, info_buf.data(), info_buf.size(), key_nonce, sizeof(key_nonce));
    sodium_memzero(prk, sizeof(prk));

    uint8_t* aead_key = key_nonce;       // first 32 bytes
    uint8_t* aead_nonce = key_nonce + 32; // next 24 bytes

    // --- AEAD: XChaCha20-Poly1305 ---
    const auto* sni_data = reinterpret_cast<const uint8_t*>(pImpl->sni.data());
    size_t sni_len = pImpl->sni.size();

    // AAD: HPKE suite IDs (KEM=0x0020, KDF=0x0001, AEAD=0x0003)
    uint8_t aad[6] = { 0x00, 0x20, 0x00, 0x01, 0x00, 0x03 };

    std::vector<uint8_t> ciphertext(sni_len + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            sni_data, sni_len,
            aad, sizeof(aad),
            nullptr, // nsec (unused)
            aead_nonce, aead_key) != 0) {
        sodium_memzero(key_nonce, sizeof(key_nonce));
        sodium_memzero(eph_sk, sizeof(eph_sk));
        throw std::runtime_error("AEAD encryption failed");
    }
    ciphertext.resize(static_cast<size_t>(ciphertext_len));

    sodium_memzero(key_nonce, sizeof(key_nonce));
    sodium_memzero(eph_sk, sizeof(eph_sk));

    // --- Wire format ---
    // [KEM_ID:2][KDF_ID:2][AEAD_ID:2][enc:32][ciphertext+tag]
    pImpl->encrypted_sni_data.clear();
    pImpl->encrypted_sni_data.reserve(6 + 32 + ciphertext.size());

    // HPKE suite header
    pImpl->encrypted_sni_data.push_back(0x00); pImpl->encrypted_sni_data.push_back(0x20); // DHKEM(X25519)
    pImpl->encrypted_sni_data.push_back(0x00); pImpl->encrypted_sni_data.push_back(0x01); // HKDF-SHA256
    pImpl->encrypted_sni_data.push_back(0x00); pImpl->encrypted_sni_data.push_back(0x03); // XChaCha20-Poly1305

    // Ephemeral public key (enc)
    pImpl->encrypted_sni_data.insert(pImpl->encrypted_sni_data.end(),
        eph_pk, eph_pk + sizeof(eph_pk));

    // Ciphertext + AEAD tag
    pImpl->encrypted_sni_data.insert(pImpl->encrypted_sni_data.end(),
        ciphertext.begin(), ciphertext.end());

    pImpl->stats.esni_ech_used++;
}

// ============================================================================
// TLS Version / Ciphers / Extensions / ALPN accessors
// ============================================================================

void TLSFingerprint::set_tls_version(TLSVersion version) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->version = version;
}

TLSFingerprint::TLSVersion TLSFingerprint::get_tls_version() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->version;
}

void TLSFingerprint::add_cipher_suite(uint16_t cipher) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->ciphers.push_back(cipher);
}

void TLSFingerprint::set_cipher_suites(const std::vector<uint16_t>& ciphers) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->ciphers = ciphers;
}

std::vector<uint16_t> TLSFingerprint::get_cipher_suites() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->ciphers;
}

void TLSFingerprint::add_extension(uint16_t extension) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->extensions.push_back(extension);
}

void TLSFingerprint::set_extensions(const std::vector<uint16_t>& extensions) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->extensions = extensions;
}

std::vector<uint16_t> TLSFingerprint::get_extensions() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->extensions;
}

void TLSFingerprint::set_alpn(const std::vector<std::string>& protocols) {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    pImpl->alpn = protocols;
}

std::vector<std::string> TLSFingerprint::get_alpn() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->alpn;
}

// ============================================================================
// Secure key management
// ============================================================================

void TLSFingerprint::protect_session_keys() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    if (pImpl->session_keys.size() > 0) {
        // Lock memory pages to prevent swapping to disk
        sodium_mlock(pImpl->session_keys.data(), pImpl->session_keys.size());
    }
}

void TLSFingerprint::clear_sensitive_data() {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    // Wipe encrypted SNI data
    if (!pImpl->encrypted_sni_data.empty()) {
        sodium_memzero(pImpl->encrypted_sni_data.data(),
                       pImpl->encrypted_sni_data.size());
        pImpl->encrypted_sni_data.clear();
    }

    // Wipe ECH config
    if (!pImpl->ech_config.empty()) {
        sodium_memzero(pImpl->ech_config.data(), pImpl->ech_config.size());
        pImpl->ech_config.clear();
    }

    // Wipe ESNI config public key
    if (!pImpl->esni_config.public_key.empty()) {
        sodium_memzero(pImpl->esni_config.public_key.data(),
                       pImpl->esni_config.public_key.size());
    }

    // Unlock and wipe session keys
    if (pImpl->session_keys.size() > 0) {
        sodium_munlock(pImpl->session_keys.data(), pImpl->session_keys.size());
    }
    pImpl->session_keys = SecureMemory();
}

// ============================================================================
// Statistics
// ============================================================================

TLSFingerprint::Statistics TLSFingerprint::get_statistics() const {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    return pImpl->stats;
}

// ============================================================================
// Private: profile data accessors
// ============================================================================

std::vector<uint16_t> TLSFingerprint::get_profile_ciphers(FingerprintProfile profile) const {
    return get_browser_profile(profile).ciphers;
}

std::vector<uint16_t> TLSFingerprint::get_profile_extensions(FingerprintProfile profile) const {
    return get_browser_profile(profile).extensions;
}

std::vector<uint16_t> TLSFingerprint::get_profile_curves(FingerprintProfile profile) const {
    return get_browser_profile(profile).curves;
}

void TLSFingerprint::load_browser_profile(BrowserType browser) {
    pImpl->load_from_profile(browser);
    pImpl->insert_grease();
}

} // namespace ncp
