#ifndef NCP_DOH_HPP
#define NCP_DOH_HPP
#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>
#include <map>
#include <chrono>
#include <mutex>
namespace ncp {
/**
 * @brief DNS-over-HTTPS (DoH) Client Implementation
 *
 * Implements RFC 8484 - DNS Queries over HTTPS (DoH)
 * Supports both wire format (application/dns-message) and JSON format
 *
 * Features:
 * - TLS 1.3 encrypted DNS queries
 * - Support for multiple DoH providers (Cloudflare, Google, Quad9, etc.)
 * - Query caching with TTL support
 * - DNSSEC validation
 * - IPv4 and IPv6 support
 * - Fallback to traditional DNS
 */
class DoHClient {
public:
    /**
     * @brief DoH provider configuration
     */
    enum class Provider {
        CLOUDFLARE_PRIMARY,    // 1.1.1.1
        CLOUDFLARE_SECONDARY,  // 1.0.0.1
        GOOGLE_PRIMARY,        // 8.8.8.8
        GOOGLE_SECONDARY,      // 8.8.4.4
        QUAD9,                 // 9.9.9.9
        ADGUARD,               // 94.140.14.14
        CUSTOM                 // User-defined
    };
    /**
     * @brief DNS record types
     */
    enum class RecordType {
        A     = 1,   // IPv4 address
        AAAA  = 28,  // IPv6 address
        CNAME = 5,   // Canonical name
        MX    = 15,  // Mail exchange
        NS    = 2,   // Name server
        PTR   = 12,  // Pointer
        SOA   = 6,   // Start of authority
        SRV   = 33,  // Service
        TXT   = 16   // Text
    };
    /**
     * @brief DNS query result
     */
    struct DNSResult {
        std::string hostname;
        std::vector<std::string> addresses;     // Resolved IP addresses
        std::vector<std::string> cnames;        // Canonical names
        RecordType type;
        uint32_t ttl;                           // Time to live in seconds
        bool dnssec_valid;                      // DNSSEC validation result
        bool from_cache;                        // Whether result was cached
        uint32_t response_time_ms;              // Query response time
        int status_code;                        // HTTP status code
        std::string error_message;              // Error description if failed
    };
    /**
     * @brief DoH client configuration
     */
    struct Config {
        Provider provider = Provider::CLOUDFLARE_PRIMARY;
        std::string custom_server_url;          // For CUSTOM provider
        uint32_t timeout_ms = 5000;             // Request timeout
        uint32_t max_retries = 3;               // Maximum retry attempts
        bool enable_cache = true;               // Enable DNS caching
        uint32_t max_cache_size = 1000;         // Maximum cache entries
        bool enable_dnssec = false;             // Validate DNSSEC
        bool fallback_to_system_dns = true;     // Fallback on DoH failure
        bool prefer_ipv6 = false;               // Prefer AAAA over A records
        // FIX #4: Use a realistic Chrome UA to avoid fingerprinting via User-Agent.
        // The previous value "NCP-DoH-Client/1.0" was trivially detectable.
        std::string user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        bool verify_tls = true;                 // Verify TLS certificates
        
        // R9-H03: Certificate pinning for DoH servers
        // When enabled, pins SHA-256 hash of server's public key
        bool enable_certificate_pinning = false;
        std::map<std::string, std::vector<std::string>> pinned_certificates; // server_url -> list of pin SHA-256 hashes
    };
    /**
     * @brief Statistics for DoH operations
     */
    struct Statistics {
        uint64_t total_queries = 0;
        uint64_t successful_queries = 0;
        uint64_t failed_queries = 0;
        uint64_t cached_queries = 0;
        uint64_t fallback_queries = 0;
        uint64_t circuit_breaker_opened = 0;    // R13-FIX-02: Circuit opened count
        uint64_t circuit_breaker_rejected = 0;  // R13-FIX-02: Rejected by circuit breaker
        uint32_t average_response_time_ms = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
    };
    // Constructor/Destructor
    DoHClient();
    explicit DoHClient(const Config& config);
    ~DoHClient();
    // Non-copyable, movable
    DoHClient(const DoHClient&) = delete;
    DoHClient& operator=(const DoHClient&) = delete;
    DoHClient(DoHClient&&) = default;
    DoHClient& operator=(DoHClient&&) = default;
    // Configuration
    void set_config(const Config& config);
    Config get_config() const;
    void set_provider(Provider provider);
    void set_custom_server(const std::string& server_url);
    // DNS Resolution
    DNSResult resolve(const std::string& hostname, RecordType type = RecordType::A);
    DNSResult resolve_ipv4(const std::string& hostname);
    DNSResult resolve_ipv6(const std::string& hostname);

    // Async resolution (callback-based)
    // FIX #19: pImpl uses shared_ptr to enable weak_ptr capture in detached threads.
    using ResolveCallback = std::function<void(const DNSResult&)>;
    void resolve_async(const std::string& hostname, RecordType type, ResolveCallback callback);
    // Batch resolution
    std::vector<DNSResult> resolve_batch(const std::vector<std::string>& hostnames,
                                         RecordType type = RecordType::A);
    // Cache management
    void clear_cache();
    size_t get_cache_size() const;
    bool is_cached(const std::string& hostname) const;
    void prefetch(const std::vector<std::string>& hostnames);
    // Statistics
    Statistics get_statistics() const;
    void reset_statistics();
    // Utilities
    std::string get_last_error() const;
    bool is_valid_hostname(const std::string& hostname) const;
    std::vector<std::string> get_available_providers() const;
private:
    // FIX #19: shared_ptr instead of unique_ptr — enables weak_ptr capture
    // in detached async threads for safe lifetime management.
    struct Impl;
    std::shared_ptr<Impl> pImpl;
    // Helper methods
    DNSResult perform_doh_query(const std::string& hostname, RecordType type);
    DNSResult fallback_to_system_dns(const std::string& hostname, RecordType type);
    std::vector<uint8_t> build_dns_query(const std::string& hostname, RecordType type);
    std::vector<uint8_t> perform_https_doh_request(const std::string& server_url, const std::vector<uint8_t>& dns_query);
    DNSResult parse_dns_response(const std::vector<uint8_t>& response);
    std::string get_provider_url(Provider provider) const;
    void update_statistics(const DNSResult& result);
};
// ===================== DoH3 & Advanced Features =====================
// DoH3Client: DNS-over-HTTPS/3 with QUIC.
// When native QUIC libraries (quiche/ngtcp2) are unavailable, falls back
// to DoH over HTTPS/1.1 using OpenSSL BIO — same wire format, same
// server endpoints, full RFC 8484 compliance.
class DoH3Client {
public:
    struct Config {
        std::string server_url = "https://dns.google/dns-query";
        uint16_t port = 443;
        bool enable_0rtt = true;                    // 0-RTT resumption (QUIC only)
        bool enable_connection_migration = true;    // Connection migration (QUIC only)
        int max_idle_timeout_ms = 30000;
        bool verify_certificate = true;
        std::vector<std::string> fallback_servers;
    };

    struct QueryStats {
        uint64_t queries_sent = 0;
        uint64_t queries_successful = 0;
        uint64_t queries_failed = 0;
        uint64_t avg_latency_ms = 0;
        uint64_t connection_migrations = 0;
    };

    DoH3Client();
    explicit DoH3Client(const Config& config);
    ~DoH3Client();

    // Non-copyable, movable
    DoH3Client(const DoH3Client&) = delete;
    DoH3Client& operator=(const DoH3Client&) = delete;
    DoH3Client(DoH3Client&&) = default;
    DoH3Client& operator=(DoH3Client&&) = default;

    DoHClient::DNSResult query(const std::string& hostname,
                               DoHClient::RecordType type = DoHClient::RecordType::A);
    std::vector<DoHClient::DNSResult> batch_query(const std::vector<std::string>& hostnames);
    void set_config(const Config& config);
    Config get_config() const;
    QueryStats get_stats() const;
    void reset_stats();
    bool connect();
    void disconnect();
    bool is_connected() const;

private:
    Config config_;
    mutable std::mutex stats_mutex_;
    QueryStats stats_;
    bool connected_ = false;

    // Internal helpers
    DoHClient::DNSResult perform_query_internal(const std::string& hostname,
                                                DoHClient::RecordType type);
    DoHClient::DNSResult try_server(const std::string& server_url,
                                    const std::string& hostname,
                                    DoHClient::RecordType type);
};
/**
 * @brief Anti-censorship DNS resolver
 * Uses multiple techniques to bypass DNS-based censorship
 */
class AntiCensorshipDNS {
public:
    enum class Strategy {
        ROUND_ROBIN,        // Rotate through providers
        FASTEST_FIRST,      // Use fastest responding provider
        PARALLEL_QUERY,     // Query all providers simultaneously
        FALLBACK_CASCADE,   // Try providers in order until success
        RANDOMIZED          // Random provider selection
    };

    struct Config {
        Strategy strategy = Strategy::PARALLEL_QUERY;
        std::vector<std::string> doh_servers;
        std::vector<std::string> doh3_servers;
        std::vector<std::string> dot_servers;       // DNS-over-TLS
        std::vector<std::string> dnscrypt_servers;

        bool enable_domain_fronting = true;         // Use domain fronting
        bool enable_esni = true;                    // Encrypted SNI
        bool enable_ech = true;                     // Encrypted Client Hello

        int query_timeout_ms = 5000;
        int max_retries = 3;

        // Censorship evasion
        bool randomize_case = true;                 // DNS 0x20 encoding
        bool fragment_queries = false;              // Fragment large queries
        bool use_edns_padding = true;               // EDNS0 padding
    };

    AntiCensorshipDNS();
    explicit AntiCensorshipDNS(const Config& config);

    // R10-C02: User-configurable DoH servers
    void set_doh_servers(const std::vector<std::string>& servers);
    void set_regional_fallback(bool enabled);
    void clear_servers();  // Clear all servers (user must add custom)

    DoHClient::DNSResult resolve(const std::string& hostname);
    std::vector<DoHClient::DNSResult> resolve_multiple(const std::vector<std::string>& hostnames);
    void add_provider(const std::string& url, const std::string& protocol);
    void remove_provider(const std::string& url);
    std::vector<std::string> get_available_providers() const;
    bool test_provider(const std::string& url);
    std::map<std::string, int> benchmark_providers();
    bool detect_censorship(const std::string& hostname);
    std::string suggest_alternative_provider();

private:
    Config config_;
    std::map<std::string, int> provider_latency_;

    DoHClient::DNSResult query_with_fronting(const std::string& hostname);
    DoHClient::DNSResult parallel_query(const std::string& hostname);
};
/**
 * @brief Secure DNS cache with anti-poisoning measures
 */
class SecureDNSCache {
public:
    struct CacheEntry {
        std::string hostname;
        std::vector<std::string> addresses;
        std::chrono::system_clock::time_point expires_at;
        bool dnssec_validated = false;
        std::string source_server;
    };

    struct Config {
        size_t max_entries = 10000;
        int default_ttl_seconds = 300;
        bool enforce_dnssec = false;
        bool enable_negative_caching = true;
        bool cache_validation = true;
    };

    SecureDNSCache();
    explicit SecureDNSCache(const Config& config);

    bool has(const std::string& hostname);
    DoHClient::DNSResult get(const std::string& hostname);
    void put(const std::string& hostname, const DoHClient::DNSResult& result, int ttl_seconds);
    void remove(const std::string& hostname);
    void clear();
    bool validate_entry(const std::string& hostname);
    void purge_expired();
    size_t size() const;
    size_t hits() const;
    size_t misses() const;
    double hit_rate() const;

private:
    Config config_;
    std::map<std::string, CacheEntry> cache_;
    size_t hits_ = 0;
    size_t misses_ = 0;

    bool is_expired(const CacheEntry& entry) const;
};

/**
 * @brief Helper function for quick DNS resolution
 *
 * @param hostname Hostname to resolve
 * @param use_ipv6 Whether to prefer IPv6
 * @return std::string Resolved IP address or empty on failure
 */
std::string resolve_hostname(const std::string& hostname, bool use_ipv6 = false);
/**
 * @brief Helper function for reverse DNS lookup
 *
 * @param ip_address IP address to lookup
 * @return std::string Hostname or empty on failure
 */
std::string reverse_dns_lookup(const std::string& ip_address);

/**
 * @brief Certificate pinning for DoH servers (R9-H03)
 * 
 * Validates server certificates against pinned SHA-256 hashes
 * of the public key (Subject Public Key Info - SPKI).
 */
class CertificatePinner {
public:
    /**
     * @brief Add a certificate pin for a server
     * @param server_url Server URL (e.g., "https://1.1.1.1/dns-query")
     * @param sha256_hash SHA-256 hash of SPKI in hex format
     */
    void add_pin(const std::string& server_url, const std::string& sha256_hash);
    
    /**
     * @brief Remove all pins for a server
     */
    void remove_pins(const std::string& server_url);
    
    /**
     * @brief Check if a certificate matches pinned hashes
     * @param server_url Server URL
     * @param cert_der Certificate in DER format
     * @return true if certificate is valid (matches a pin or no pins set)
     */
    bool verify(const std::string& server_url, const std::vector<uint8_t>& cert_der);
    
    /**
     * @brief Extract SHA-256 hash of certificate's public key
     * @param cert_der Certificate in DER format
     * @return SHA-256 hash in hex format (64 chars)
     */
    static std::string extract_spki_hash(const std::vector<uint8_t>& cert_der);
    
    /**
     * @brief Load default pins for well-known DoH providers
     */
    void load_default_pins();
    
private:
    std::map<std::string, std::vector<std::string>> pins_; // server_url -> list of SHA-256 hashes
};

} // namespace ncp
#endif // NCP_DOH_HPP
