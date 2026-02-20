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

namespace ncp {

// ============================================================================
// Helpers
// ============================================================================

// Cryptographically secure Fisher-Yates shuffle using libsodium
template<typename RandomIt>
static void secure_shuffle(RandomIt first, RandomIt last) {
    auto n = std::distance(first, last);
    for (auto i = n - 1; i > 0; --i) {
        auto j = static_cast<decltype(i)>(
            randombytes_uniform(static_cast<uint32_t>(i + 1)));
        std::swap(*(first + i), *(first + j));
    }
}

// BLAKE2b-128 hash to 32-hex-char string
// Used internally for JA4 and non-standard hashing.
static std::string blake2b_hash_to_hex(const std::string& input) {
    uint8_t hash[16];
    crypto_generichash(hash, sizeof(hash),
                       reinterpret_cast<const uint8_t*>(input.data()),
                       input.size(), nullptr, 0);
    std::ostringstream oss;
    for (auto b : hash) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    return oss.str();
}

// MD5-compatible hash using crypto_hash_sha256 truncated to 16 bytes.
// Real JA3 uses MD5. We approximate with SHA-256 truncated to 128 bits
// for the same 32-hex-char format, without adding an OpenSSL/MD5 dependency.
// For true MD5 compatibility, swap in OpenSSL EVP_MD_fetch(NULL, "MD5", NULL).
//
// NOTE: If exact JA3 database matching (Salesforce, Trisul, MITRE) is required,
// replace this with actual MD5. The truncated SHA-256 produces different hashes
// but maintains the same format and collision resistance properties.
static std::string md5_compat_hash_to_hex(const std::string& input) {
    uint8_t full_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(full_hash,
                       reinterpret_cast<const uint8_t*>(input.data()),
                       input.size());
    // Truncate to 16 bytes (128 bits) — same output size as MD5
    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(full_hash[i]);
    }
    return oss.str();
}

// Default hash function for JA3: MD5-compatible (for database matching)
// JA4 uses BLAKE2b internally (not compared against external databases)
static std::string hash_to_hex_ja3(const std::string& input) {
    return md5_compat_hash_to_hex(input);
}

static std::string hash_to_hex_ja4(const std::string& input) {
    return blake2b_hash_to_hex(input);
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

// Helper: check if a profile is a specific real browser (not RANDOM/CUSTOM)
static bool is_real_browser_profile(BrowserType type) {
    switch (type) {
    case BrowserType::CHROME:
    case BrowserType::EDGE:
    case BrowserType::ANDROID_CHROME:
    case BrowserType::FIREFOX:
    case BrowserType::SAFARI:
    case BrowserType::IOS_SAFARI:
    case BrowserType::CURL:
        return true;
    case BrowserType::RANDOM:
    case BrowserType::CUSTOM:
    default:
        return false;
    }
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

std::string TLSFingerprint::JA3Fingerprint::hash() const {
    // Use MD5-compatible hash for JA3 (standard JA3 databases use MD5)
    return hash_to_hex_ja3(to_string());
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

// JA4Fingerprint serialization
std::string TLSFingerprint::JA4Fingerprint::to_string() const {
    // JA4_a: t{version}{sni}{cipherCount:02}{extCount:02}
    std::ostringstream a;
    a << protocol << tls_version << sni;
    a << std::setw(2) << std::setfill('0') << cipher_suites.size();
    a << std::setw(2) << std::setfill('0') << extensions_count;

    // JA4_b: sorted cipher suites hash (first 12 chars)
    auto sorted_ciphers = cipher_suites;
    std::sort(sorted_ciphers.begin(), sorted_ciphers.end());
    std::string b_hash = hash_to_hex_ja4(join_u16(sorted_ciphers, ',')).substr(0, 12);

    // JA4_c: sorted extensions hash (first 12 chars)
    auto sorted_exts = extensions;
    std::sort(sorted_exts.begin(), sorted_exts.end());
    std::string c_hash = hash_to_hex_ja4(join_u16(sorted_exts, ',')).substr(0, 12);

    return a.str() + "_" + b_hash + "_" + c_hash;
}

std::string TLSFingerprint::JA4Fingerprint::hash() const {
    return hash_to_hex_ja4(to_string());
}

// ============================================================================
// Randomization
// FIX: Only shuffle cipher suites for RANDOM/CUSTOM profiles.
// Real browsers have fixed cipher suite order — shuffling creates a unique
// fingerprint that is easier to track than a standard browser fingerprint.
// ============================================================================

void TLSFingerprint::randomize_all() {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    auto all_ciphers = get_profile_ciphers(pImpl->profile);
    auto all_exts = get_profile_extensions(pImpl->profile);
    auto all_curves = get_profile_curves(pImpl->profile);

    // Only shuffle for RANDOM/CUSTOM profiles.
    // Real browser profiles keep their canonical cipher/extension order.
    if (!is_real_browser_profile(pImpl->profile)) {
        if (all_ciphers.size() > 1) secure_shuffle(all_ciphers.begin(), all_ciphers.end());
        if (all_exts.size() > 1)    secure_shuffle(all_exts.begin(), all_exts.end());
        if (all_curves.size() > 1)  secure_shuffle(all_curves.begin(), all_curves.end());
    }

    pImpl->ciphers = std::move(all_ciphers);
    pImpl->extensions = std::move(all_exts);
    pImpl->curves = std::move(all_curves);

    // Re-insert GREASE for Chromium profiles
    pImpl->insert_grease();

    pImpl->stats.fingerprints_randomized++;
}

void TLSFingerprint::randomize_ciphers() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    auto c = get_profile_ciphers(pImpl->profile);
    // Only shuffle for non-real-browser profiles
    if (!is_real_browser_profile(pImpl->profile)) {
        if (c.size() > 1) secure_shuffle(c.begin(), c.end());
    }
    pImpl->ciphers = std::move(c);
}

void TLSFingerprint::randomize_extensions() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    auto e = get_profile_extensions(pImpl->profile);
    // Extensions can be shuffled more safely than ciphers for some browsers,
    // but we still preserve order for real browser profiles to be safe.
    if (!is_real_browser_profile(pImpl->profile)) {
        if (e.size() > 1) secure_shuffle(e.begin(), e.end());
    }
    pImpl->extensions = std::move(e);
}

void TLSFingerprint::randomize_curves() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    auto c = get_profile_curves(pImpl->profile);
    if (!is_real_browser_profile(pImpl->profile)) {
        if (c.size() > 1) secure_shuffle(c.begin(), c.end());
    }
    pImpl->curves = std::move(c);
}

void TLSFingerprint::shuffle_order() {
    std::lock_guard<std::mutex> lock(pImpl->mu);
    // Only shuffle for RANDOM/CUSTOM profiles
    if (!is_real_browser_profile(pImpl->profile)) {
        if (pImpl->ciphers.size() > 1)
            secure_shuffle(pImpl->ciphers.begin(), pImpl->ciphers.end());
        if (pImpl->extensions.size() > 1)
            secure_shuffle(pImpl->extensions.begin(), pImpl->extensions.end());
    }
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

void TLSFingerprint::encrypt_sni(const std::vector<uint8_t>& public_key) {
    std::lock_guard<std::mutex> lock(pImpl->mu);

    if (public_key.size() != crypto_box_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid ESNI public key size");
    }
    if (pImpl->sni.empty()) {
        return; // Nothing to encrypt
    }

    // Generate ephemeral keypair for ESNI encryption
    uint8_t eph_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t eph_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(eph_pk, eph_sk);

    // Nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // Encrypt SNI
    const auto* sni_data = reinterpret_cast<const uint8_t*>(pImpl->sni.data());
    size_t sni_len = pImpl->sni.size();
    std::vector<uint8_t> ciphertext(sni_len + crypto_box_MACBYTES);

    if (crypto_box_easy(ciphertext.data(), sni_data, sni_len,
                        nonce, public_key.data(), eph_sk) != 0) {
        sodium_memzero(eph_sk, sizeof(eph_sk));
        throw std::runtime_error("Failed to encrypt SNI");
    }

    // Pack: ephemeral_pk || nonce || ciphertext
    pImpl->encrypted_sni_data.clear();
    pImpl->encrypted_sni_data.reserve(sizeof(eph_pk) + sizeof(nonce) + ciphertext.size());
    pImpl->encrypted_sni_data.insert(pImpl->encrypted_sni_data.end(),
        eph_pk, eph_pk + sizeof(eph_pk));
    pImpl->encrypted_sni_data.insert(pImpl->encrypted_sni_data.end(),
        nonce, nonce + sizeof(nonce));
    pImpl->encrypted_sni_data.insert(pImpl->encrypted_sni_data.end(),
        ciphertext.begin(), ciphertext.end());

    sodium_memzero(eph_sk, sizeof(eph_sk));
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
