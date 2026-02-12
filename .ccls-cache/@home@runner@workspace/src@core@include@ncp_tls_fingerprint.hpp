#ifndef NCP_TLS_FINGERPRINT_HPP
#define NCP_TLS_FINGERPRINT_HPP

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <map>

namespace ncp {

/**
 * @brief Secure Memory Management with auto-zeroing
 */
class SecureMemory {
public:
    SecureMemory(size_t size);
    ~SecureMemory();
    
    // Disable copy
    SecureMemory(const SecureMemory&) = delete;
    SecureMemory& operator=(const SecureMemory&) = delete;
    
    // Allow move
    SecureMemory(SecureMemory&& other) noexcept;
    SecureMemory& operator=(SecureMemory&& other) noexcept;
    
    uint8_t* data() { return data_; }
    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }
    
    // Static utility functions
    static void secure_zero(void* ptr, size_t size);
    static bool lock_memory(void* ptr, size_t size);
    static bool unlock_memory(void* ptr, size_t size);
    
private:
    uint8_t* data_;
    size_t size_;
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
    
    // Disable copy
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;
    
    // Allow move
    SecureString(SecureString&& other) noexcept;
    SecureString& operator=(SecureString&& other) noexcept;
    
    const char* c_str() const { return data_; }
    const char* data() const { return data_; }
    size_t size() const { return size_; }
    size_t length() const { return size_; }
    bool empty() const { return size_ == 0; }
    void clear();
    
private:
    char* data_;
    size_t size_;
    size_t capacity_;
};

// Browser type enum for fingerprint profiles
enum class BrowserType {
    CHROME,
    FIREFOX,
    SAFARI,
    EDGE,
    ANDROID_CHROME,
    IOS_SAFARI,
    CURL,
    RANDOM,
    CUSTOM
};

/**
 * @brief TLS Fingerprint Randomization (JA3/JA4 Spoofing)
 */
class TLSFingerprint {
public:
    enum class TLSVersion : uint16_t {
        TLS_1_0 = 0x0301,
        TLS_1_1 = 0x0302,
        TLS_1_2 = 0x0303,
        TLS_1_3 = 0x0304
    };
    
    enum CipherSuite : uint16_t {
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 = 0xCCA8,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    };
    
    enum Extension : uint16_t {
        SERVER_NAME = 0,
        SUPPORTED_GROUPS = 10,
        EC_POINT_FORMATS = 11,
        SIGNATURE_ALGORITHMS = 13,
        ALPN = 16,
        ENCRYPT_THEN_MAC = 22,
        EXTENDED_MASTER_SECRET = 23,
        SESSION_TICKET = 35,
        SUPPORTED_VERSIONS = 43,
        PSK_KEY_EXCHANGE_MODES = 45,
        KEY_SHARE = 51,
        ENCRYPTED_CLIENT_HELLO = 0xFE0D,
        ENCRYPTED_SNI = 0xFFCE
    };
    
    // Use BrowserType as FingerprintProfile alias
    using FingerprintProfile = BrowserType;
    
    struct JA3Fingerprint {
        TLSVersion version;
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        std::vector<uint16_t> elliptic_curves;
        std::vector<uint8_t> ec_point_formats;
        
        std::string to_string() const;
        std::string hash() const;
    };
    
    struct JA4Fingerprint {
        std::string protocol;
        std::string tls_version;
        std::string sni;
        uint16_t extensions_count;
        std::vector<uint16_t> cipher_suites;
        std::vector<uint16_t> extensions;
        
        std::string to_string() const;
        std::string hash() const;
    };
    
    struct ESNIConfig {
        bool enabled = false;
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> encrypted_sni;
        uint16_t cipher_suite;
        uint16_t key_share_entry;
    };
    
    TLSFingerprint();
    explicit TLSFingerprint(FingerprintProfile profile);
    ~TLSFingerprint();
    
    void set_profile(FingerprintProfile profile);
    FingerprintProfile get_profile() const;
    
    JA3Fingerprint generate_ja3() const;
    void apply_ja3(const JA3Fingerprint& fingerprint);
    std::string get_ja3_string() const;
    std::string get_ja3_hash() const;
    
    JA4Fingerprint generate_ja4() const;
    void apply_ja4(const JA4Fingerprint& fingerprint);
    std::string get_ja4_string() const;
    
    void randomize_all();
    void randomize_ciphers();
    void randomize_extensions();
    void randomize_curves();
    void shuffle_order();
    
    void enable_esni(const ESNIConfig& config);
    void enable_ech(const std::vector<uint8_t>& ech_config);
    void disable_esni_ech();
    bool is_esni_ech_enabled() const;
    
    void set_sni(const std::string& hostname);
    std::string get_sni() const;
    void encrypt_sni(const std::vector<uint8_t>& public_key);
    
    void set_tls_version(TLSVersion version);
    TLSVersion get_tls_version() const;
    void add_cipher_suite(uint16_t cipher);
    void set_cipher_suites(const std::vector<uint16_t>& ciphers);
    std::vector<uint16_t> get_cipher_suites() const;
    void add_extension(uint16_t extension);
    void set_extensions(const std::vector<uint16_t>& extensions);
    std::vector<uint16_t> get_extensions() const;
    
    void set_alpn(const std::vector<std::string>& protocols);
    std::vector<std::string> get_alpn() const;
    
    void protect_session_keys();
    void clear_sensitive_data();
    
    struct Statistics {
        uint64_t connections_made = 0;
        uint64_t fingerprints_randomized = 0;
        uint64_t esni_ech_used = 0;
        std::map<std::string, uint32_t> ja3_usage;
    };
    Statistics get_statistics() const;
    
private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    
    std::vector<uint16_t> get_profile_ciphers(FingerprintProfile profile) const;
    std::vector<uint16_t> get_profile_extensions(FingerprintProfile profile) const;
    std::vector<uint16_t> get_profile_curves(FingerprintProfile profile) const;
    void load_browser_profile(BrowserType browser);
};

namespace SecureOps {
    bool constant_time_compare(const void* a, const void* b, size_t len);
    std::vector<uint8_t> generate_random(size_t size);
    SecureString hash_password(const SecureString& password, const std::vector<uint8_t>& salt);
}

} // namespace ncp

#endif // NCP_TLS_FINGERPRINT_HPP
