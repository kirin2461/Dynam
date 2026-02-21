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
#include <list>
#include <atomic>
#include <sodium.h>
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

namespace ncp {

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
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// FIX #20: Maximum depth for DNS compression pointer following.
// RFC 1035 compression pointers can reference other compressed names,
// but a malicious response could create circular references.
// 16 levels is far more than any legitimate DNS response needs.
static constexpr int MAX_COMPRESSION_DEPTH = 16;

// ==================== Implementation Structure ====================
// FIX #19: Impl inherits enable_shared_from_this so resolve_async()
// can capture a weak_ptr instead of a raw pointer. This eliminates
// the TOCTOU race between shutting_down check and alive_mutex lock,
// and removes the need for the unreliable sleep_for(10ms) in ~DoHClient.
struct DoHClient::Impl : public std::enable_shared_from_this<DoHClient::Impl> {
    Config config;
    Statistics stats;
    std::string last_error;
    std::mutex cache_mutex;
    std::map<std::string, std::pair<DNSResult, std::chrono::steady_clock::time_point>> cache;

    // LRU eviction: front = oldest, back = most recently used
    std::list<std::string> lru_order;
    std::map<std::string, std::list<std::string>::iterator> lru_map;

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
        // Modern OpenSSL 1.1+ initialization (replaces deprecated
        // SSL_library_init / SSL_load_error_strings / OpenSSL_add_all_algorithms)
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (ssl_ctx) {
            SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
            SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
            SSL_CTX_set_default_verify_paths(ssl_ctx);
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

    // LRU helpers (caller must hold cache_mutex)
    void lru_touch(const std::string& key) {
        auto it = lru_map.find(key);
        if (it != lru_map.end()) {
            lru_order.erase(it->second);
        }
        lru_order.push_back(key);
        lru_map[key] = std::prev(lru_order.end());
    }

    void lru_remove(const std::string& key) {
        auto it = lru_map.find(key);
        if (it != lru_map.end()) {
            lru_order.erase(it->second);
            lru_map.erase(it);
        }
    }

    void lru_evict_oldest() {
        if (lru_order.empty()) return;
        std::string oldest_key = lru_order.front();
        lru_order.pop_front();
        lru_map.erase(oldest_key);
        cache.erase(oldest_key);
    }
};

// ==================== Constructor/Destructor ====================

// FIX #19: pImpl is now shared_ptr — constructed via make_shared
DoHClient::DoHClient() : pImpl(std::make_shared<Impl>()) {
#ifdef _WIN32
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
}

DoHClient::DoHClient(const Config& config) : DoHClient() {
    pImpl->config = config;
}

// FIX #19: No more sleep_for(10ms) hack. When DoHClient is destroyed,
// pImpl (shared_ptr) ref-count drops. If async threads still hold a
// weak_ptr, their lock() calls will return nullptr — safe shutdown.
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

    DNSHeader header = {};
    header.id = htons(static_cast<uint16_t>(randombytes_uniform(65535) + 1));
    header.flags = htons(0x0100);
    header.qdcount = htons(1);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    query.insert(query.end(), header_bytes, header_bytes + sizeof(DNSHeader));

    std::istringstream iss(hostname);
    std::string label;
    while (std::getline(iss, label, '.')) {
        if (label.length() > 63) {
            throw std::runtime_error("DNS label too long");
        }
        query.push_back(static_cast<uint8_t>(label.length()));
        query.insert(query.end(), label.begin(), label.end());
    }
    query.push_back(0);

            uint16_t qtype = static_cast<uint16_t>(type);
    query.push_back((qtype >> 8) & 0xFF);
    query.push_back(qtype & 0xFF);

            uint16_t qclass = 1;
    query.push_back((qclass >> 8) & 0xFF);
    query.push_back(qclass & 0xFF);

    return query;
}

// ==================== DNS Response Parsing ====================
// FIX #20: Added depth tracking for compression pointer following
// in CNAME parsing to prevent infinite loops from malicious responses.

DoHClient::DNSResult DoHClient::parse_dns_response(const std::vector<uint8_t>& response) {
    DNSResult result;
    result.dnssec_valid = false;
    result.from_cache = false;
    result.status_code = 0;

    if (response.size() < sizeof(DNSHeader)) {
        result.error_message = "Response too short";
        return result;
    }

    const DNSHeader* header = reinterpret_cast<const DNSHeader*>(response.data());
    uint16_t flags = ntohs(header->flags);
    uint16_t ancount = ntohs(header->ancount);

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

    size_t offset = sizeof(DNSHeader);
    uint16_t qdcount = ntohs(header->qdcount);

    for (int i = 0; i < qdcount && offset < response.size(); ++i) {
        while (offset < response.size() && response[offset] != 0) {
            if ((response[offset] & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            offset += response[offset] + 1;
        }
        if (offset < response.size() && response[offset] == 0) {
            offset++;
        }
        offset += 4;
    }

    for (int i = 0; i < ancount && offset < response.size(); ++i) {
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

        uint16_t rtype = (response[offset] << 8) | response[offset + 1];
        offset += 2;
        offset += 2; // rclass

        uint32_t ttl = (response[offset] << 24) | (response[offset + 1] << 16) |
                       (response[offset + 2] << 8) | response[offset + 3];
        offset += 4;
        result.ttl = ttl;

        uint16_t rdlength = (response[offset] << 8) | response[offset + 1];
        offset += 2;

        if (offset + rdlength > response.size()) break;

        if (rtype == static_cast<uint16_t>(RecordType::A) && rdlength == 4) {
            char ip_str[INET_ADDRSTRLEN];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     response[offset], response[offset + 1],
                     response[offset + 2], response[offset + 3]);
            result.addresses.push_back(ip_str);
            result.type = RecordType::A;
        } else if (rtype == static_cast<uint16_t>(RecordType::AAAA) && rdlength == 16) {
            char ip_str[INET6_ADDRSTRLEN];
            struct in6_addr addr;
            memcpy(&addr, &response[offset], 16);
            inet_ntop(AF_INET6, &addr, ip_str, sizeof(ip_str));
            result.addresses.push_back(ip_str);
            result.type = RecordType::AAAA;
        } else if (rtype == static_cast<uint16_t>(RecordType::CNAME)) {
            // FIX #20: CNAME parsing with compression pointer depth limit
            std::string cname;
            size_t cname_offset = offset;
            int compression_depth = 0;
            while (cname_offset < offset + rdlength) {
                if ((response[cname_offset] & 0xC0) == 0xC0) {
                    // Bounds check: need 2 bytes for compression pointer
                    if (cname_offset + 1 >= response.size()) break;

                    size_t ptr = ((response[cname_offset] & 0x3F) << 8) | response[cname_offset + 1];

                    // FIX #20: Follow compression pointer with depth limit
                    // Prevents infinite loops from circular compression pointers
                    // in malicious DNS responses.
                    int ptr_depth = 0;
                    while (ptr < response.size() && response[ptr] != 0) {
                        if (ptr_depth++ >= MAX_COMPRESSION_DEPTH) break;
                        if ((response[ptr] & 0xC0) == 0xC0) {
                            // Nested compression pointer — follow it
                            if (ptr + 1 >= response.size()) break;
                            ptr = ((response[ptr] & 0x3F) << 8) | response[ptr + 1];
                            continue;
                        }
                        // Bounds check for label length
                        uint8_t label_len = response[ptr];
                        if (ptr + 1 + label_len > response.size()) break;
                        if (!cname.empty()) cname += ".";
                        cname.append(reinterpret_cast<const char*>(&response[ptr + 1]), label_len);
                        ptr += label_len + 1;
                    }
                    break;
                } else if (response[cname_offset] == 0) {
                    break;
                } else {
                    uint8_t label_len = response[cname_offset];
                    // Bounds check for inline label
                    if (cname_offset + 1 + label_len > response.size()) break;
                    if (!cname.empty()) cname += ".";
                    cname.append(reinterpret_cast<const char*>(&response[cname_offset + 1]), label_len);
                    cname_offset += label_len + 1;
                }
            }
            result.cnames.push_back(cname);
        }

        offset += rdlength;
    }

    return result;
}

// ==================== Chunked Transfer Encoding Parser ====================

static std::string parse_chunked_body(const std::string& body) {
    std::string result;
    size_t pos = 0;

    while (pos < body.size()) {
        // Find chunk size line
        size_t line_end = body.find("\r\n", pos);
        if (line_end == std::string::npos) break;

        std::string size_str = body.substr(pos, line_end - pos);
        // Strip chunk extensions (after semicolon)
        size_t semi = size_str.find(';');
        if (semi != std::string::npos) size_str = size_str.substr(0, semi);

        unsigned long chunk_size = 0;
        try {
            chunk_size = std::stoul(size_str, nullptr, 16);
        } catch (...) {
            break;
        }

        if (chunk_size == 0) break; // Terminal chunk

        pos = line_end + 2; // Skip \r\n after size
        if (pos + chunk_size > body.size()) break;

        result.append(body, pos, chunk_size);
        pos += chunk_size + 2; // Skip chunk data + trailing \r\n
    }

    return result;
}

// ==================== HTTPS Communication ====================

#ifdef HAVE_OPENSSL
std::vector<uint8_t> DoHClient::perform_https_doh_request(
    const std::string& server_url,
    const std::vector<uint8_t>& dns_query
) {
    std::vector<uint8_t> response;

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
        return response;
    }

    // Base64url encode the DNS query
    std::string encoded_query;
    static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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

    // FIX: Reuse member ssl_ctx instead of creating a new one per request.
    // Previously each call did SSL_CTX_new() + SSL_CTX_free() = leak of the member ssl_ctx.
    SSL_CTX* ctx = pImpl->ssl_ctx;
    if (!ctx) return response;

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
        return response;
    }

    std::string request = "GET " + path + "?dns=" + encoded_query + " HTTP/1.1\r\n";
    request += "Host: " + host + "\r\n";
    request += "Accept: application/dns-message\r\n";
    request += "Connection: close\r\n\r\n";

    BIO_write(bio, request.c_str(), static_cast<int>(request.size()));

    char buffer[4096];
    std::string http_response;
    int len;
    while ((len = BIO_read(bio, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        http_response.append(buffer, len);
    }

    BIO_free_all(bio);
    // NOTE: Do NOT free ctx here — it's owned by pImpl

    // Parse HTTP response — detect chunked transfer encoding
    size_t body_start = http_response.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        std::string headers_str = http_response.substr(0, body_start);
        body_start += 4;
        std::string body = http_response.substr(body_start);

        // Check for chunked transfer encoding
        std::string headers_lower = headers_str;
        std::transform(headers_lower.begin(), headers_lower.end(),
                       headers_lower.begin(), ::tolower);

        if (headers_lower.find("transfer-encoding: chunked") != std::string::npos) {
            std::string decoded = parse_chunked_body(body);
            response.assign(decoded.begin(), decoded.end());
        } else {
            response.assign(body.begin(), body.end());
        }
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
        std::vector<uint8_t> query = build_dns_query(hostname, type);
        std::string server_url = get_provider_url(pImpl->config.provider);

#ifdef HAVE_OPENSSL
        std::vector<uint8_t> response = perform_https_doh_request(server_url, query);
        if (!response.empty()) {
            result = parse_dns_response(response);
            result.status_code = 200;
        } else {
            throw std::runtime_error("Empty DoH response");
        }
#else
        result = fallback_to_system_dns(hostname, type);
        result.status_code = 200;
#endif
        auto end_time = std::chrono::steady_clock::now();
        result.response_time_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count());

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
    result.ttl = 300;
    return result;
}

// ==================== DNS Resolution ====================

DoHClient::DNSResult DoHClient::resolve(const std::string& hostname, RecordType type) {
        { std::lock_guard<std::mutex> lock(pImpl->cache_mutex); pImpl->stats.total_queries++; }

    // FIX: Cache key includes RecordType so A and AAAA are cached separately
    std::string cache_key = hostname + ":" + std::to_string(static_cast<int>(type));

    if (pImpl->config.enable_cache) {
        std::lock_guard<std::mutex> lock(pImpl->cache_mutex);

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
                pImpl->lru_touch(cache_key);
                update_statistics(result);
                return result;
            } else {
                pImpl->cache.erase(it);
                pImpl->lru_remove(cache_key);
            }
        }
    }

    DNSResult result = perform_doh_query(hostname, type);

    if (!result.addresses.empty() || !result.cnames.empty()) {
                        { std::lock_guard<std::mutex> lock(impl3->cache_mutex); impl3->stats.successful_queries++; }

        if (pImpl->config.enable_cache) {
            std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
            pImpl->cache[cache_key] = {result, std::chrono::steady_clock::now()};
            pImpl->lru_touch(cache_key);

            // FIX: LRU eviction instead of alphabetical (std::map::begin())
            while (pImpl->cache.size() > pImpl->config.max_cache_size) {
                pImpl->lru_evict_oldest();
            }
        }
    } else {
                                { std::lock_guard<std::mutex> lock(impl3->cache_mutex); impl3->stats.failed_queries++; }

        if (pImpl->config.fallback_to_system_dns && result.addresses.empty()) {
            result = fallback_to_system_dns(hostname, type);
                        { std::lock_guard<std::mutex> lock(pImpl->cache_mutex); pImpl->stats.fallback_queries++; }
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
// FIX #18 + #19: resolve_async() now performs actual DNS resolution.
//
// Previous implementation was a noop — always returned error
// "Async resolution requires external thread management" because
// it only had Impl* and couldn't call resolve() (needs DoHClient*).
//
// Solution: capture weak_ptr<Impl> instead of raw pointer. The thread
// performs DoH query and caching inline using Impl methods directly.
// If DoHClient is destroyed before thread completes, weak_ptr::lock()
// returns nullptr and thread exits safely — no TOCTOU race, no
// use-after-free, no need for shutting_down flag or sleep_for hack.

void DoHClient::resolve_async(const std::string& hostname, RecordType type, ResolveCallback callback) {
    // Capture weak_ptr to Impl — safe if DoHClient is destroyed
    std::weak_ptr<Impl> weak_impl = pImpl;

    // Also need to capture the query-building and parsing as lambdas
    // since they are member functions. We capture copies of what we need.
    auto provider_url = get_provider_url(pImpl->config.provider);
    auto config_copy = pImpl->config;

    std::thread([weak_impl, hostname, type, callback, provider_url, config_copy]() {
        try {
            // Try to lock — if DoHClient is already destroyed, bail out
            auto impl = weak_impl.lock();
            if (!impl) {
                if (callback) {
                    DNSResult error_result;
                    error_result.hostname = hostname;
                    error_result.type = type;
                    error_result.error_message = "DoH client was destroyed";
                    callback(error_result);
                }
                return;
            }

            // Check cache first
            std::string cache_key = hostname + ":" + std::to_string(static_cast<int>(type));
            if (config_copy.enable_cache) {
                std::lock_guard<std::mutex> lock(impl->cache_mutex);
                auto it = impl->cache.find(cache_key);
                if (it != impl->cache.end()) {
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - it->second.second).count();
                    if (age < it->second.first.ttl) {
                        DNSResult result = it->second.first;
                        result.from_cache = true;
                        impl->stats.cached_queries++;
                        impl->stats.successful_queries++;
                        impl->lru_touch(cache_key);
                        if (callback) callback(result);
                        return;
                    }
                }
            }

            // Build DNS query
            std::vector<uint8_t> query;
            {
                DNSHeader header = {};
                header.id = htons(static_cast<uint16_t>(randombytes_uniform(65535) + 1));
                header.flags = htons(0x0100);
                header.qdcount = htons(1);
                const uint8_t* hdr = reinterpret_cast<const uint8_t*>(&header);
                query.insert(query.end(), hdr, hdr + sizeof(DNSHeader));

                std::istringstream iss(hostname);
                std::string label;
                while (std::getline(iss, label, '.')) {
                    query.push_back(static_cast<uint8_t>(label.length()));
                    query.insert(query.end(), label.begin(), label.end());
                }
                query.push_back(0);

                        uint16_t qtype = static_cast<uint16_t>(type);
                query.push_back((qtype >> 8) & 0xFF);
                query.push_back(qtype & 0xFF);
                        uint16_t qclass = 1;
                query.push_back((qclass >> 8) & 0xFF);
                query.push_back(qclass & 0xFF);
            }

                    { std::lock_guard<std::mutex> lock(impl->cache_mutex); impl->stats.total_queries++; }
            auto start_time = std::chrono::steady_clock::now();

            DNSResult result;
            result.hostname = hostname;
            result.type = type;

#ifdef HAVE_OPENSSL
            // Perform HTTPS DoH request inline
            // Re-check impl is still alive before using ssl_ctx
            auto impl2 = weak_impl.lock();
            if (!impl2 || !impl2->ssl_ctx) {
                result.error_message = "SSL context unavailable";
                if (callback) callback(result);
                return;
            }

            // Parse URL
            std::string host, path;
            size_t pos = provider_url.find("://");
            if (pos != std::string::npos) {
                std::string rest = provider_url.substr(pos + 3);
                size_t path_pos = rest.find('/');
                if (path_pos != std::string::npos) {
                    host = rest.substr(0, path_pos);
                    path = rest.substr(path_pos);
                } else {
                    host = rest;
                    path = "/dns-query";
                }
            }

            // Base64url encode
            std::string encoded_query;
            static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            uint32_t val = 0; int bits = 0;
            for (uint8_t byte : query) {
                val = (val << 8) | byte; bits += 8;
                while (bits >= 6) { bits -= 6; encoded_query += b64[(val >> bits) & 0x3F]; }
            }
            if (bits > 0) encoded_query += b64[(val << (6 - bits)) & 0x3F];

            BIO* bio = BIO_new_ssl_connect(impl2->ssl_ctx);
            std::string connect_str = host + ":443";
            BIO_set_conn_hostname(bio, connect_str.c_str());
            SSL* ssl = nullptr;
            BIO_get_ssl(bio, &ssl);
            if (ssl) SSL_set_tlsext_host_name(ssl, host.c_str());

            if (BIO_do_connect(bio) <= 0) {
                BIO_free_all(bio);
                // Fallback to system DNS
                struct addrinfo hints = {}, *res = nullptr;
                hints.ai_family = (type == DoHClient::RecordType::AAAA) ? AF_INET6 : AF_INET;
                hints.ai_socktype = SOCK_STREAM;
                if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) == 0) {
                    for (auto* p = res; p; p = p->ai_next) {
                        char ip[INET6_ADDRSTRLEN];
                        if (p->ai_family == AF_INET)
                            inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, ip, sizeof(ip));
                        else
                            inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, ip, sizeof(ip));
                        result.addresses.push_back(ip);
                    }
                    freeaddrinfo(res);
                    result.ttl = 300;
                    impl->stats.fallback_queries++;
                }
            } else {
                std::string req = "GET " + path + "?dns=" + encoded_query + " HTTP/1.1\r\n";
                req += "Host: " + host + "\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n";
                BIO_write(bio, req.c_str(), static_cast<int>(req.size()));

                char buf[4096]; std::string http_resp; int len;
                while ((len = BIO_read(bio, buf, sizeof(buf)-1)) > 0) {
                    buf[len] = '\0'; http_resp.append(buf, len);
                }
                BIO_free_all(bio);

                size_t body_start = http_resp.find("\r\n\r\n");
                if (body_start != std::string::npos) {
                    std::string hdrs = http_resp.substr(0, body_start);
                    std::string body = http_resp.substr(body_start + 4);
                    std::string hdrs_lower = hdrs;
                    std::transform(hdrs_lower.begin(), hdrs_lower.end(), hdrs_lower.begin(), ::tolower);

                    std::vector<uint8_t> dns_resp;
                    if (hdrs_lower.find("transfer-encoding: chunked") != std::string::npos) {
                        std::string decoded = parse_chunked_body(body);
                        dns_resp.assign(decoded.begin(), decoded.end());
                    } else {
                        dns_resp.assign(body.begin(), body.end());
                    }

                    if (!dns_resp.empty()) {
                        // Re-parse inline (parse_dns_response is a member but we
                        // have the same parsing logic available — for simplicity
                        // we construct a temporary DoHClient-less parse)
                        // Actually, parse_dns_response is a static-like method
                        // that only uses the response data, so we can call it
                        // through a minimal approach. Since we can't easily call
                        // member functions from a detached thread, we inline
                        // the result extraction here.
                        result.status_code = 200;
                        // Minimal DNS response parsing for async path
                        if (dns_resp.size() >= sizeof(DNSHeader)) {
                            const DNSHeader* rhdr = reinterpret_cast<const DNSHeader*>(dns_resp.data());
                            uint16_t rflags = ntohs(rhdr->flags);
                            uint16_t rancount = ntohs(rhdr->ancount);
                            if ((rflags & 0x000F) == 0 && rancount > 0) {
                                // Skip question section
                                size_t roff = sizeof(DNSHeader);
                                uint16_t rqdcount = ntohs(rhdr->qdcount);
                                for (int q = 0; q < rqdcount && roff < dns_resp.size(); ++q) {
                                    while (roff < dns_resp.size() && dns_resp[roff] != 0) {
                                        if ((dns_resp[roff] & 0xC0) == 0xC0) { roff += 2; break; }
                                        roff += dns_resp[roff] + 1;
                                    }
                                    if (roff < dns_resp.size() && dns_resp[roff] == 0) roff++;
                                    roff += 4;
                                }
                                // Parse answers
                                for (int a = 0; a < rancount && roff < dns_resp.size(); ++a) {
                                    while (roff < dns_resp.size()) {
                                        if ((dns_resp[roff] & 0xC0) == 0xC0) { roff += 2; break; }
                                        else if (dns_resp[roff] == 0) { roff++; break; }
                                        else roff += dns_resp[roff] + 1;
                                    }
                                    if (roff + 10 > dns_resp.size()) break;
                                    uint16_t art = (dns_resp[roff]<<8)|dns_resp[roff+1]; roff += 2;
                                    roff += 2; // class
                                    uint32_t attl = (dns_resp[roff]<<24)|(dns_resp[roff+1]<<16)|(dns_resp[roff+2]<<8)|dns_resp[roff+3]; roff += 4;
                                    result.ttl = attl;
                                    uint16_t ardlen = (dns_resp[roff]<<8)|dns_resp[roff+1]; roff += 2;
                                    if (roff + ardlen > dns_resp.size()) break;
                                    if (art == 1 && ardlen == 4) {
                                        char ip[INET_ADDRSTRLEN];
                                        snprintf(ip, sizeof(ip), "%d.%d.%d.%d", dns_resp[roff], dns_resp[roff+1], dns_resp[roff+2], dns_resp[roff+3]);
                                        result.addresses.push_back(ip);
                                        result.type = DoHClient::RecordType::A;
                                    } else if (art == 28 && ardlen == 16) {
                                        char ip[INET6_ADDRSTRLEN];
                                        struct in6_addr a6; memcpy(&a6, &dns_resp[roff], 16);
                                        inet_ntop(AF_INET6, &a6, ip, sizeof(ip));
                                        result.addresses.push_back(ip);
                                        result.type = DoHClient::RecordType::AAAA;
                                    }
                                    roff += ardlen;
                                }
                            }
                        }
                    }
                }
            }
#else
            // No OpenSSL — fallback to system DNS
            struct addrinfo hints = {}, *res = nullptr;
            hints.ai_family = (type == DoHClient::RecordType::AAAA) ? AF_INET6 : AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) == 0) {
                for (auto* p = res; p; p = p->ai_next) {
                    char ip[INET6_ADDRSTRLEN];
                    if (p->ai_family == AF_INET)
                        inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, ip, sizeof(ip));
                    else
                        inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, ip, sizeof(ip));
                    result.addresses.push_back(ip);
                }
                freeaddrinfo(res);
                result.ttl = 300;
                result.status_code = 200;
            } else {
                result.error_message = "System DNS resolution failed";
            }
#endif

            auto end_time = std::chrono::steady_clock::now();
            result.response_time_ms = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

            // Update stats and cache (re-lock impl)
            auto impl3 = weak_impl.lock();
            if (impl3) {
                if (!result.addresses.empty()) {
                    impl3->stats.successful_queries++;
                    if (config_copy.enable_cache) {
                        std::lock_guard<std::mutex> lock(impl3->cache_mutex);
                        impl3->cache[cache_key] = {result, std::chrono::steady_clock::now()};
                        impl3->lru_touch(cache_key);
                        while (impl3->cache.size() > config_copy.max_cache_size) {
                            impl3->lru_evict_oldest();
                        }
                    }
                } else {
                    impl3->stats.failed_queries++;
                }
            }

            if (callback) callback(result);

        } catch (const std::exception& e) {
            DNSResult error_result;
            error_result.hostname = hostname;
            error_result.type = type;
            error_result.error_message = std::string("Async resolution failed: ") + e.what();
            if (callback) callback(error_result);
        } catch (...) {
            DNSResult error_result;
            error_result.hostname = hostname;
            error_result.type = type;
            error_result.error_message = "Async resolution failed: unknown error";
            if (callback) callback(error_result);
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
    pImpl->lru_order.clear();
    pImpl->lru_map.clear();
}

size_t DoHClient::get_cache_size() const {
    std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
    return pImpl->cache.size();
}

// FIX: is_cached() now includes RecordType in the cache key lookup,
// matching the key format used by resolve(). Default to RecordType::A
// for backward compatibility.
bool DoHClient::is_cached(const std::string& hostname) const {
    std::lock_guard<std::mutex> lock(pImpl->cache_mutex);
    // Check both A and AAAA since caller didn't specify type
    std::string key_a = hostname + ":" + std::to_string(static_cast<int>(RecordType::A));
    std::string key_aaaa = hostname + ":" + std::to_string(static_cast<int>(RecordType::AAAA));
    return pImpl->cache.find(key_a) != pImpl->cache.end() ||
           pImpl->cache.find(key_aaaa) != pImpl->cache.end();
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
            pImpl->stats.average_response_time_ms = static_cast<uint32_t>(
                (pImpl->stats.average_response_time_ms * (total - 1) + result.response_time_ms) / total);
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

    if (inet_pton(AF_INET, ip_address.c_str(), &sa.sin_addr) == 1) {
        sa.sin_family = AF_INET;
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
            return host;
        }
    }
    else if (inet_pton(AF_INET6, ip_address.c_str(), &sa6.sin6_addr) == 1) {
        sa6.sin6_family = AF_INET6;
        if (getnameinfo(reinterpret_cast<struct sockaddr*>(&sa6), sizeof(sa6),
                        host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0) {
            return host;
        }
    }

    return "";
}

} // namespace ncp
