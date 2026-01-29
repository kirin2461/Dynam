#ifndef NCP_TLS_FINGERPRINT_HPP
#define NCP_TLS_FINGERPRINT_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>

namespace NCP {

/**
 * @brief Secure Memory Management
 * 
 * Provides secure memory allocation with automatic zeroing
 * Protects sensitive data (keys, passwords) from memory dumps
 */
class SecureMemory {
public:
    /**
     * @brief Allocate secure memory block
     * Memory is locked (mlock) to prevent swapping
     */
    static void* allocate(size_t size);
    
    /**
     * @brief Securely deallocate memory with guaranteed zeroing
     * Uses explicit_bzero/SecureZeroMemory or volatile memset
     */
    static void deallocate(void* ptr, size_t size);
    
    /**
     * @brief Secure zero memory (cannot be optimized away by compiler)
     */
    static void secure_zero(void* ptr, size_t size);
    
    /**
     * @brief Lock memory pages to prevent swapping to disk
     */
    static bool lock_memory(void* ptr, size_t size);
    
    /**
     * @brief Unlock previously locked memory
     */
    static bool unlock_memory(void* ptr, size_t size);
};

/**
 * @brief Secure string with auto-zeroing destructor
 */
class SecureString {
public:
    SecureString();
    explicit SecureString(const std::string& str);
    explicit SecureString(const char* str, size_t len);
    ~SecureString();
    
    // Disable copy to prevent sensitive data duplication
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    
    // Allow move
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;
    
    const char* data() const;
    size_t size() const;
    bool empty() const;
    void clear();
    
private:
    char* data_;
    size_t size_;
    size_t capacity_;
};

/**
 * @brief TLS Fingerprint Randomization (JA3/JA4 Spoofing)
 * 
 * Randomizes TLS ClientHello parameters to evade fingerprinting
 * Supports JA3, JA3S, JA4, JA4+ fingerprints
 */
class TLSFingerprint {
public:
    /**
     * @brief TLS version constants
     */
    enum class TLSVersion : uint16_t {
        TLS_1_0 = 0x0301,
        TLS_1_1 = 0x0302,
        TLS_1_2 = 0x0303,
        TLS_1_3 = 0x0304
    };
    
    /**
     * @brief Common cipher suites
     */
    enum CipherSuite : uint16_t {
        // TLS 1.3 ciphers
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
        
        // TLS 1.2 ciphers
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 = 0xCCA8,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    };
    
    /**
     * @brief Supported extensions
     */
    enum Extension : uint16_t {
        SERVER_NAME = 0,                    // SNI
        SUPPORTED_GROUPS = 10,              // Elliptic curves
        EC_POINT_FORMATS = 11,
        SIGNATURE_ALGORITHMS = 13,
        ALPN = 16,                          // Application Layer Protocol
        ENCRYPT_THEN_MAC = 22,
        EXTENDED_MASTER_SECRET = 23,
        SESSION_TICKET = 35,
        SUPPORTED_VERSIONS = 43,
        PSK_KEY_EXCHANGE_MODES = 45,
        KEY_SHARE = 51,
        ENCRYPTED_CLIENT_HELLO = 0xFE0D,    // ECH (draft)
        ENCRYPTED_SNI = 0xFFCE              // ESNI (obsolete)
    };
    
    /**
     * @brief TLS fingerprint profile (browser/client emulation)
     */
    enum class FingerprintProfile {
        CHROME_LATEST,
        FIREFOX_LATEST,
        SAFARI_LATEST,
        EDGE_LATEST,
        ANDROID_CHROME,
        IOS_SAFARI,
        CURL_OPENSSL,
        RANDOM,              // Fully randomized
        CUSTOM               // User-defined
    };
    
    /**
     * @brief JA3 fingerprint structure
     * Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
     */
    struct JA3Fingerprint {
        TLSVersion version;
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        std::vector<uint16_t> elliptic_curves;
        std::vector<uint8_t> ec_point_formats;
        
        std::string to_string() const;
        std::string hash() const;  // MD5 hash
    };
    
    /**
     * @brief JA4 fingerprint (newer, more robust than JA3)
     */
    struct JA4Fingerprint {
        std::string protocol;  // "t" for TCP, "q" for QUIC
        std::string tls_version;
        std::string sni;
        uint16_t extensions_count;
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        
        std::string to_string() const;
        std::string hash() const;
    };
    
    /**
     * @brief ESNI/ECH configuration
     */
    struct ESNIConfig {
        bool enabled = false;
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> encrypted_sni;
        uint16_t cipher_suite;
        uint16_t key_share_entry;
    };
    
    // Constructor
    TLSFingerprint();
    explicit TLSFingerprint(FingerprintProfile profile);
    ~TLSFingerprint();
    
    // Profile management
    void set_profile(FingerprintProfile profile);
    FingerprintProfile get_profile() const;
    
    // JA3 operations
    JA3Fingerprint generate_ja3() const;
    void apply_ja3(const JA3Fingerprint& fingerprint);
    std::string get_ja3_string() const;
    std::string get_ja3_hash() const;
    
    // JA4 operations
    JA4Fingerprint generate_ja4() const;
    void apply_ja4(const JA4Fingerprint& fingerprint);
    std::string get_ja4_string() const;
    
    // Randomization
    void randomize_all();
    void randomize_ciphers();
    void randomize_extensions();
    void randomize_curves();
    void shuffle_order();  // Randomize order of extensions/ciphers
    
    // ESNI/ECH support
    void enable_esni(const ESNIConfig& config);
    void enable_ech(const std::vector<uint8_t>& ech_config);
    void disable_esni_ech();
    bool is_esni_ech_enabled() const;
    
    // SNI operations
    void set_sni(const std::string& hostname);
    std::string get_sni() const;
    void encrypt_sni(const std::vector<uint8_t>& public_key);
    
    // TLS parameters
    void set_tls_version(TLSVersion version);
    TLSVersion get_tls_version() const;
    void add_cipher_suite(uint16_t cipher);
    void set_cipher_suites(const std::vector<uint16_t>& ciphers);
    std::vector<uint16_t> get_cipher_suites() const;
    void add_extension(uint16_t extension);
    void set_extensions(const std::vector<uint16_t>& extensions);
    std::vector<uint16_t> get_extensions() const;
    
    // ALPN
    void set_alpn(const std::vector<std::string>& protocols);
    std::vector<std::string> get_alpn() const;
    
    // Key material protection
    void protect_session_keys();
    void clear_sensitive_data();
    
    // Statistics
    struct Statistics {
        uint64_t connections_made = 0;
        uint64_t fingerprints_randomized = 0;
        uint64_t esni_ech_used = 0;
        std::map<std::string, uint32_t> ja3_usage;  // Track JA3 diversity
    };
    Statistics get_statistics() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    
    // Helper methods
    std::vector<uint16_t> get_profile_ciphers(FingerprintProfile profile) const;
    std::vector<uint16_t> get_profile_extensions(FingerprintProfile profile) const;
    std::vector<uint16_t> get_profile_curves(FingerprintProfile profile) const;
    void load_browser_profile(FingerprintProfile profile);
};

/**
 * @brief Global helpers for secure operations
 */
namespace SecureOps {
    /**
     * @brief Compare two memory regions in constant time
     * Prevents timing attacks
     */
    bool constant_time_compare(const void* a, const void* b, size_t len);
    
    /**
     * @brief Generate cryptographically secure random bytes
     */
    std::vector<uint8_t> generate_random(size_t size);
    
    /**
     * @brief Hash password with secure salt
     */
    SecureString hash_password(const SecureString& password, const std::vector<uint8_t>& salt);
}

} // namespace NCP

#endif // NCP_TLS_FINGERPRINT_HPP
