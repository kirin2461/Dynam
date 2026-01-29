/**
 * @file doh.cpp
 * @brief DNS-over-HTTPS (DoH) Client Implementation
 * @note Implements RFC 8484 - DNS Queries over HTTPS
 */

#include "../include/ncp_doh.hpp"
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

// OpenSSL for HTTPS
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#endif

namespace NCP {

// ==================== DoH Provider URLs ====================
static const std::map<DoHClient::Provider, std::string> DOH_SERVERS = {
    {DoHClient::Provider::CLOUDFLARE_PRIMARY,   "https://1.1.1.1/dns-query"},
    {DoHClient::Provider::CLOUDFLARE_SECONDARY, "https://1.0.0.1/dns-query"},
    {DoHClient::Provider::GOOGLE_PRIMARY,       "https://8.8.8.8/dns-query"},
    {DoHClient::Provider::GOOGLE_SECONDARY,     "https://8.8.4.4/dns-query"},
    {DoHClient::Provider::QUAD9,                "https://9.9.9.9/dns-query"},
    {DoHClient::Provider::ADGUARD,              "https://94.140.14.14/dns-query"}
};

// DNS Header structure (RFC 1035)
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;          // Query ID
    uint16_t flags;       // Flags and codes
    uint16_t qdcount;     // Question count
    uint16_t ancount;     // Answer count
    uint16_t nscount;     // Authority count
    uint16_t arcount;     // Additional count
};
#pragma pack(pop)

// ==================== Implementation Structure ====================
struct DoHClient::Impl {
    Config config;
    Statistics stats;
    std::string last_error;
    std::mutex cache_mutex;
    std::map<std::string, std::pair<DNSResult, std::chrono::steady_clock::time_point>> cache;
    
#ifdef HAVE_OPENSSL
    SSL_CTX* ssl_ctx = nullptr;
#endif
    
    Impl() {
        initialize_ssl();
    }
    
    ~Impl() {
        cleanup_ssl();
    }
    
    void initialize_ssl() {
#ifdef HAVE_OPENSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (ssl_ctx) {
            SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
            SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        }
#endif
    }
    
    void cleanup_ssl() {
#ifdef HAVE_OPENSSL
        if (ssl_ctx) {
            SSL_CTX_free(ssl_ctx);
            ssl_ctx = nullptr;
        }
#endif
    }
};

// ==================== Constructor/Destructor ====================

DoHClient::DoHClient() : pImpl(std::make_unique<Impl>()) {
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
}

DoHClient::DoHClient(const Config& config) : DoHClient() {
    pImpl->config = config;
}

DoHClient::~DoHClient() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// ==================== Configuration ====================

void DoHClient::set_config(const Config& config) {
    pImpl->config = config;
}

DoHClient::Config DoHClient::get_config() const {
    return pImpl->config;
}

void DoHClient::set_provider(Provider provider) {
    pImpl->config.provider = provider;
}

void DoHClient::set_custom_server(const std::string& server_url) {
    pImpl->config.provider = Provider::CUSTOM;
    pImpl->config.custom_server_url = server_url;
}

std::string DoHClient::get_provider_url(Provider provider) const {
    if (provider == Provider::CUSTOM) {
        return pImpl->config.custom_server_url;
    }
    auto it = DOH_SERVERS.find(provider);
    if (it != DOH_SERVERS.end()) {
        return it->second;
    }
    return DOH_SERVERS.at(Provider::CLOUDFLARE_PRIMARY);
}

// ==================== DNS Query Building ====================

std::vector<uint8_t> DoHClient::build_dns_query(const std::string& hostname, RecordType type) {
    std::vector<uint8_t> query;
    
    // DNS Header
    DNSHeader header = {};
    
    // Random query ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(1, 65535);
    header.id = htons(dis(gen));
    
    // Standard query with recursion desired
    header.flags = htons(0x0100);  // RD=1
    header.qdcount = htons(1);     // One question
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    
    // Add header to query
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    query.insert(query.end(), header_bytes, header_bytes + sizeof(DNSHeader));
    
    // Encode hostname (QNAME)
    std::istringstream iss(hostname);
    std::string label;
    while (std::getline(iss, label, '.')) {
        if (label.length() > 63) {
            throw std::runtime_error("DNS label too long");
        }
        query.push_back(static_cast<uint8_t>(label.length()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.push_back(0);  // Null terminator
    
    // QTYPE
    uint16_t qtype = htons(static_cast<uint16_t>(type));
    query.push_back((qtype >> 8) & 0xFF);
    query.push_back(qtype & 0xFF);
    
    // QCLASS (IN = 1)
    uint16_t qclass = htons(1);
    query.push_back((qclass >> 8) & 0xFF);
    query.push_back(qclass & 0xFF);
    
    return query;
}

// ==================== DNS Response Parsing ====================

DoHClient::DNSResult DoHClient::parse_dns_response(const std::vector<uint8_t>& response) {
    DNSResult result;
    result.dnssec_valid = false;
    result.from_cache = false;
    result.status_code = 0;
    
    if (response.size() < sizeof(DNSHeader)) {
        result.error_message = "Response too short";
        return result;
    }
    
    // Parse header
    const DNSHeader* header = reinterpret_cast<const DNSHeader*>(response.data());
    uint16_t flags = ntohs(header->flags);
    uint16_t ancount = ntohs(header->ancount);
    
    // Check for errors (RCODE in lower 4 bits of flags)
    int rcode = flags & 0x000F;
    if (rcode != 0) {
        switch (rcode) {
            case 1: result.error_message = "Format error"; break;
            case 2: result.error_message = "Server failure"; break;
            case 3: result.error_message = "Name error (NXDOMAIN)"; break;
            case 4: result.error_message = "Not implemented"; break;
            case 5: result.error_message = "Refused"; break;
            default: result.error_message = "Unknown DNS error: " + std::to_string(rcode);
        }
        return result;
    }
    
    // Skip question section
    size_t offset = sizeof(DNSHeader);
    uint16_t qdcount = ntohs(header->qdcount);
    
    for (int i = 0; i < qdcount && offset < response.size(); ++i) {
        // Skip QNAME
        while (offset < response.size() && response[offset] != 0) {
            if ((response[offset] & 0xC0) == 0xC0) {
                offset += 2;  // Compression pointer
                break;
            }
            offset += response[offset] + 1;
        }
        if (offset < response.size() && response[offset] == 0) {
            offset++;  // Skip null terminator
        }
        offset += 4;  // Skip QTYPE and QCLASS
    }
    
    // Parse answer section
    for (int i = 0; i < ancount && offset < response.size(); ++i) {
        // Skip NAME (may be compressed)
        while (offset < response.size()) {
            if ((response[offset] & 0xC0) == 0xC0) {
                offset += 2;
                break;
            } else if (response[offset] == 0) {
                offset++;
                break;
            } else {
                offset += response[offset] + 1;
            }
        }
        
        if (offset + 10 > response.size()) break;
        
        // Parse resource record
        uint16_t rtype = (response[offset] << 8) | response[offset + 1];
        offset += 2;
        
        // uint16_t rclass = (response[offset] << 8) | response[offset + 1];
        offset += 2;
        
        uint32_t ttl = (response[offset] << 24) | (response[offset + 1] << 16) |
                       (response[offset + 2] << 8) | response[offset + 3];
        offset += 4;
        result.ttl = ttl;
        
        uint16_t rdlength = (response[offset] << 8) | response[offset + 1];
        offset += 2;
        
        if (offset + rdlength > response.size()) break;
        
        // Parse RDATA based on type
        if (rtype == static_cast<uint16_t>(RecordType::A) && rdlength == 4) {
            // IPv4 address
            char ip_str[INET_ADDRSTRLEN];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     response[offset], response[offset + 1],
                     response[offset + 2], response[offset + 3]);
            result.addresses.push_back(ip_str);
            result.type = RecordType::A;
        } else if (rtype == static_cast<uint16_t>(RecordType::AAAA) && rdlength == 16) {
            // IPv6 address
            char ip_str[INET6_ADDRSTRLEN];
            struct in6_addr addr;
            memcpy(&addr, &response[offset], 16);
            inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
            result.addresses.push_back(ip_str);
            result.type = RecordType::AAAA;
        } else if (rtype == static_cast<uint16_t>(RecordType::CNAME)) {
            // CNAME - parse domain name
            std::string cname;
            size_t cname_offset = offset;
            while (cname_offset < offset + rdlength) {
                if ((response[cname_offset] & 0xC0) == 0xC0) {
                    // Compression pointer - follow it
                    size_t ptr = ((response[cname_offset] & 0x3F) << 8) | response[cname_offset + 1];
                    while (ptr < response.size() && response[ptr] != 0) {
                        if ((response[ptr] & 0xC0) == 0xC0) break;
                        if (!cname.empty()) cname += ".";
                        cname.append(reinterpret_cast<const char*>(&response[ptr + 1]), response[ptr]);
                        ptr += response[ptr] + 1;
                    }
                    break;
                } else if (response[cname_offset] == 0) {
                    break;
                } else {
                    if (!cname.empty()) cname += ".";
                    cname.append(reinterpret_cast<const char*>(&response[cname_offset + 1]), response[cname_offset]);
                    cname_offset += response[cname_offset] + 1;
                }
            }
            result.cnames.push_back(cname);
        }
        
        offset += rdlength;
    }
    
    return result;
}

// ==================== HTTPS Communication (Simplified) ====================
// Note: Full implementation would use libcurl or similar for proper HTTPS

#ifdef HAVE_OPENSSL
// Perform actual HTTPS DoH request using OpenSSL
std::vector<uint8_t> DoHClient::perform_https_doh_request(
    const std::string& server_url,
    const std::vector<uint8_t>& dns_query
) {
    std::vector<uint8_t> response;
    
    // Parse URL to extract host and path
    std::string host, path;
    size_t pos = server_url.find("://");
    if (pos != std::string::npos) {
        std::string rest = server_url.substr(pos + 3);
        size_t path_pos = rest.find('/');
        if (path_pos != std::string::npos) {
            host = rest.substr(0, path_pos);
            path = rest.substr(path_pos);
        } else {
            host = rest;
            path = "/dns-query";
        }
    } else {
        return response; // Invalid URL
    }
    
    // Base64url encode the DNS query for GET request
    std::string encoded_query;
    static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i = 0;
    uint32_t val = 0;
    int bits = 0;
    for (uint8_t byte : dns_query) {
        val = (val << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            encoded_query += base64_chars[(val >> bits) & 0x3F];
        }
    }
    if (bits > 0) {
        encoded_query += base64_chars[(val << (6 - bits)) & 0x3F];
    }
    
    // Initialize SSL
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return response;
    
    // Create BIO for connection
    std::string connect_str = host + ":443";
    BIO* bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, connect_str.c_str());
    
    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (ssl) {
        SSL_set_tlsext_host_name(ssl, host.c_str());
    }
    
    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return response;
    }
    
    // Build HTTP GET request
    std::string request = "GET " + path + "?dns=" + encoded_query + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "Accept: application/dns-message\r\n";
    request += "Connection: close\r\n\r\n";
    
    // Send request
    BIO_write(bio, request.c_str(), request.size());
    
    // Read response
    char buffer[4096];
    std::string http_response;
    int len;
    while ((len = BIO_read(bio, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        http_response.append(buffer, len);
    }
    
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    
    // Parse HTTP response - find body after \r\n\r\n
    size_t body_start = http_response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        body_start += 4;
        response.assign(http_response.begin() + body_start, http_response.end());
    }
    
    return response;
}
#endif


DoHClient::DNSResult DoHClient::perform_doh_query(const std::string& hostname, RecordType type) {
    DNSResult result;
    result.hostname = hostname;
    result.type = type;
    auto start_time = std::chrono::steady_clock::now();
    
    try {
        // Build DNS query
        std::vector<uint8_t> query = build_dns_query(hostname, type);
        
        // Get provider URL
        std::string server_url = get_provider_url(pImpl->config.provider);
        
#ifdef HAVE_OPENSSL
        // Real HTTPS DoH request using OpenSSL
        std::vector<uint8_t> response = perform_https_doh_request(server_url, query);
        if (!response.empty()) {
            result = parse_dns_response(response);
            result.status_code = 200;
        } else {
            throw std::runtime_error("Empty DoH response");
        }
#else
        // Fallback: system DNS when OpenSSL not available
        result = fallback_to_system_dns(hostname, type);
        result.status_code = 200;
#endif
        // Calculate response time
        auto end_time = std::chrono::steady_clock::now();
        result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
            
    } catch (const std::exception& e) {
        result.error_message = e.what();
        pImpl->last_error = e.what();
    }
    
    return result;
}

// ==================== System DNS Fallback ====================

DoHClient::DNSResult DoHClient::fallback_to_system_dns(const std::string& hostname, RecordType type) {
    DNSResult result;
    result.hostname = hostname;
    result.type = type;
    
    struct addrinfo hints = {};
    struct addrinfo* res = nullptr;
    
    if (type == RecordType::A) {
        hints.ai_family = AF_INET;
    } else if (type == RecordType::AAAA) {
        hints.ai_family = AF_INET6;
    } else {
        hints.ai_family = AF_UNSPEC;
    }
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (ret != 0) {
        result.error_message = gai_strerror(ret);
        return result;
    }
    
    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        char ip_str[INET6_ADDRSTRLEN];
        
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            result.addresses.push_back(ip_str);
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* addr = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &addr->sin6_addr, ip_str, sizeof(ip_str));
            result.addresses.push_back(ip_str);
        }
    }
    
    freeaddrinfo(res);
    result.ttl = 300;  // Default TTL
    return result;
}

// ==================== DNS Resolution ====================

DoHClient::DNSResult DoHClient::resolve(const std::string& hostname, RecordType type) {
    pImpl->stats.total_queries++;
    
    // Check cache first
    if (pImpl->config.enable_cache) {
        std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
        std::string cache_key = hostname + ":" + std::to_string(static_cast<int>(type));
        
        auto it = pImpl->cache.find(cache_key);
        if (it != pImpl->cache.end()) {
            auto cache_time = it->second.second;
            auto now = std::chrono::steady_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - cache_time).count();
            
            if (age < it->second.first.ttl) {
                DNSResult result = it->second.first;
                result.from_cache = true;
                pImpl->stats.cached_queries++;
                pImpl->stats.successful_queries++;
                update_statistics(result);
                return result;
            } else {
                pImpl->cache.erase(it);  // Expired
            }
        }
    }
    
    // Perform DoH query
    DNSResult result = perform_doh_query(hostname, type);
    
    if (!result.addresses.empty() || !result.cnames.empty()) {
        pImpl->stats.successful_queries++;
        
        // Cache the result
        if (pImpl->config.enable_cache) {
            std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
            std::string cache_key = hostname + ":" + std::to_string(static_cast<int>(type));
            pImpl->cache[cache_key] = {result, std::chrono::steady_clock::now()};
            
            // Limit cache size
            if (pImpl->cache.size() > pImpl->config.max_cache_size) {
                pImpl->cache.erase(pImpl->cache.begin());
            }
        }
    } else {
        pImpl->stats.failed_queries++;
        
        // Try fallback if enabled
        if (pImpl->config.fallback_to_system_dns && result.addresses.empty()) {
            result = fallback_to_system_dns(hostname, type);
            pImpl->stats.fallback_queries++;
        }
    }
    
    update_statistics(result);
    return result;
}

DoHClient::DNSResult DoHClient::resolve_ipv4(const std::string& hostname) {
    return resolve(hostname, RecordType::A);
}

DoHClient::DNSResult DoHClient::resolve_ipv6(const std::string& hostname) {
    return resolve(hostname, RecordType::AAAA);
}

// ==================== Async Resolution ====================

void DoHClient::resolve_async(const std::string& hostname, RecordType type, ResolveCallback callback) {
    std::thread([this, hostname, type, callback]() {
        DNSResult result = resolve(hostname, type);
        if (callback) {
            callback(result);
        }
    }).detach();
}

// ==================== Batch Resolution ====================

std::vector<DoHClient::DNSResult> DoHClient::resolve_batch(
    const std::vector<std::string>& hostnames, RecordType type) {
    
    std::vector<DNSResult> results;
    results.reserve(hostnames.size());
    
    for (const auto& hostname : hostnames) {
        results.push_back(resolve(hostname, type));
    }
    
    return results;
}

// ==================== Cache Management ====================

void DoHClient::clear_cache() {
    std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
    pImpl->cache.clear();
}

size_t DoHClient::get_cache_size() const {
    std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
    return pImpl->cache.size();
}

bool DoHClient::is_cached(const std::string& hostname) const {
    std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
    return pImpl->cache.find(hostname) != pImpl->cache.end();
}

void DoHClient::prefetch(const std::vector<std::string>& hostnames) {
    for (const auto& hostname : hostnames) {
        resolve_async(hostname, RecordType::A, nullptr);
    }
}

// ==================== Statistics ====================

void DoHClient::update_statistics(const DNSResult& result) {
    if (!result.from_cache) {
        uint64_t total = pImpl->stats.successful_queries + pImpl->stats.failed_queries;
        if (total > 0) {
            pImpl->stats.average_response_time_ms = 
                (pImpl->stats.average_response_time_ms * (total - 1) + result.response_time_ms) / total;
        }
    }
}

DoHClient::Statistics DoHClient::get_statistics() const {
    return pImpl->stats;
}

void DoHClient::reset_statistics() {
    pImpl->stats = Statistics();
}

// ==================== Utilities ====================

std::string DoHClient::get_last_error() const {
    return pImpl->last_error;
}

bool DoHClient::is_valid_hostname(const std::string& hostname) const {
    if (hostname.empty() || hostname.length() > 253) {
        return false;
    }
    
    // Check for valid characters
    for (char c : hostname) {
        if (!std::isalnum(c) && c != '.' && c != '-' && c != '_') {
            return false;
        }
    }
    
    return true;
}

std::vector<std::string> DoHClient::get_available_providers() const {
    return {
        "Cloudflare Primary (1.1.1.1)",
        "Cloudflare Secondary (1.0.0.1)",
        "Google Primary (8.8.8.8)",
        "Google Secondary (8.8.4.4)",
        "Quad9 (9.9.9.9)",
        "AdGuard (94.140.14.14)"
    };
}

// ==================== Helper Functions ====================

std::string resolve_hostname(const std::string& hostname, bool use_ipv6) {
    DoHClient client;
    auto result = use_ipv6 ? client.resolve_ipv6(hostname) : client.resolve_ipv4(hostname);
    return result.addresses.empty() ? "" : result.addresses[0];
}

std::string reverse_dns_lookup(const std::string& ip_address) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    char host[NI_MAXHOST];
    
    // Try IPv4
    if (inet_pton(AF_INET, ip_address.c_str(), &sa.sin_addr) == 1) {
        sa.sin_family = AF_INET;
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
            return host;
        }
    }
    // Try IPv6
    else if (inet_pton(AF_INET6, ip_address.c_str(), &sa6.sin6_addr) == 1) {
        sa6.sin6_family = AF_INET6;
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa6), sizeof(sa6),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
            return host;
        }
    }
    
    return "";
}

} // namespace NCP
