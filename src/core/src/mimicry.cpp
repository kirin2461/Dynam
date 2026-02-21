#include "../include/ncp_mimicry.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <array>
#include <iomanip>
#include <ctime>
#include <sodium.h>

namespace ncp {

// ==================== Russian whitelist domains & paths ====================
static const std::array<const char*, 12> RU_WHITELIST_HOSTS = {{
    "yandex.ru", "www.yandex.ru", "mc.yandex.ru",
    "vk.com", "st.vk.com",
    "mail.ru", "e.mail.ru",
    "ok.ru",
    "gosuslugi.ru",
    "sberbank.ru", "online.sberbank.ru",
    "cdn.rutube.ru"
}};

static const std::array<const char*, 10> RU_WHITELIST_PATHS = {{
    "/", "/api/v2/config", "/static/js/main.js",
    "/images/logo.svg", "/feed", "/news",
    "/api/health", "/favicon.ico",
    "/cdn/dist/bundle.min.js", "/portal/config.json"
}};

static const std::array<const char*, 5> RU_USER_AGENTS = {{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 YaBrowser/24.1.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
}};

struct DnsLabel {
    const char* tld;
    uint8_t tld_len;
    const char* sld;
    uint8_t sld_len;
};

static const std::array<DnsLabel, 6> RU_DNS_LABELS = {{
    {"ru", 2, "yandex", 6},
    {"com", 3, "vk", 2},
    {"ru", 2, "mail", 4},
    {"ru", 2, "ok", 2},
    {"ru", 2, "gosuslugi", 9},
    {"ru", 2, "sberbank", 8}
}};

static const std::array<const char*, 8> RU_TLS_SNI_HOSTS = {{
    "yandex.ru", "vk.com", "mail.ru", "ok.ru",
    "gosuslugi.ru", "sberbank.ru", "rutube.ru", "dzen.ru"
}};

// ==================== Safe hex decode helper (replaces sscanf) ====================
static int hex_char_to_nibble(uint8_t c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1; // invalid
}

static bool safe_hex_decode_byte(uint8_t hi, uint8_t lo, uint8_t& out) {
    int h = hex_char_to_nibble(hi);
    int l = hex_char_to_nibble(lo);
    if (h < 0 || l < 0) return false;
    out = static_cast<uint8_t>((h << 4) | l);
    return true;
}

static unsigned int safe_hex_to_uint(const char* hex, size_t len) {
    unsigned int result = 0;
    for (size_t i = 0; i < len; ++i) {
        int n = hex_char_to_nibble(static_cast<uint8_t>(hex[i]));
        if (n < 0) return 0;
        result = (result << 4) | static_cast<unsigned int>(n);
    }
    return result;
}

// ==================== Constructors / Destructor ====================
TrafficMimicry::TrafficMimicry() {
    ncp::csprng_init();
    // Task #4: Handle wire version
    wire_version_ = static_cast<uint8_t>(ncp::csprng_range(1, 255));
    // Task #1: Generate default session key
    tls_session_key_.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(tls_session_key_.data(), tls_session_key_.size());
}

TrafficMimicry::TrafficMimicry(const MimicConfig& config) : config_(config) {
    ncp::csprng_init();
    // Task #4: Handle wire version
    if (config_.wire_version == 0) {
        wire_version_ = static_cast<uint8_t>(ncp::csprng_range(1, 255));
    } else {
        wire_version_ = config_.wire_version;
    }
    // Task #1: Generate default session key
    tls_session_key_.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(tls_session_key_.data(), tls_session_key_.size());

    if (config_.http_user_agent.empty()) {
        config_.http_user_agent = generate_random_user_agent();
    }
    if (config_.http_host.empty()) {
        config_.http_host = generate_random_hostname();
    }
    if (config_.tls_sni.empty()) {
        config_.tls_sni = config_.http_host;
    }
}

TrafficMimicry::~TrafficMimicry() {
    std::lock_guard<std::mutex> lock(tls_key_mutex_);
    if (!tls_session_key_.empty()) {
        sodium_memzero(tls_session_key_.data(), tls_session_key_.size());
    }
}

// ==================== TLS session key management ====================
void TrafficMimicry::set_tls_session_key(const std::vector<uint8_t>& key) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return;
    }
    std::lock_guard<std::mutex> lock(tls_key_mutex_);
    if (!tls_session_key_.empty()) {
        sodium_memzero(tls_session_key_.data(), tls_session_key_.size());
    }
    tls_session_key_ = key;
    tls_packets_since_key_rotation_.store(0, std::memory_order_relaxed);
}

std::vector<uint8_t> TrafficMimicry::get_tls_session_key() const {
    std::lock_guard<std::mutex> lock(tls_key_mutex_);
    return tls_session_key_;
}

void TrafficMimicry::rotate_tls_session_key() {
    std::lock_guard<std::mutex> lock(tls_key_mutex_);
    if (tls_session_key_.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        tls_session_key_.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    } else {
        sodium_memzero(tls_session_key_.data(), tls_session_key_.size());
    }
    randombytes_buf(tls_session_key_.data(), tls_session_key_.size());
    tls_packets_since_key_rotation_.store(0, std::memory_order_relaxed);
}

// ==================== wrap / unwrap with stats ====================
std::vector<uint8_t> TrafficMimicry::wrap_payload(
    const std::vector<uint8_t>& payload, MimicProfile profile) {

    // Task #3: Periodic key rotation
    if (config_.tls_key_rotation_packets > 0) {
        if (tls_packets_since_key_rotation_.fetch_add(1, std::memory_order_relaxed) >= config_.tls_key_rotation_packets) {
            rotate_tls_session_key();
        }
    }

    std::vector<uint8_t> result;
    stats_.bytes_original += payload.size();

    switch (profile) {
        case MimicProfile::HTTP_GET:           result = create_http_get_wrapper(payload); break;
        case MimicProfile::HTTP_POST:          result = create_http_post_wrapper(payload); break;
        case MimicProfile::HTTPS_CLIENT_HELLO: result = create_https_client_hello_wrapper(payload); break;
        case MimicProfile::HTTPS_APPLICATION:  result = create_https_application_wrapper(payload); break;
        case MimicProfile::DNS_QUERY:          result = create_dns_query_wrapper(payload); break;
        case MimicProfile::DNS_RESPONSE:       result = create_dns_response_wrapper(payload); break;
        case MimicProfile::QUIC_INITIAL:       result = create_quic_initial_wrapper(payload); break;
        case MimicProfile::WEBSOCKET:          result = create_websocket_wrapper(payload); break;
        case MimicProfile::BITTORRENT:         result = create_bittorrent_wrapper(payload); break;
        case MimicProfile::SKYPE:              result = create_skype_wrapper(payload); break;
        case MimicProfile::ZOOM:               result = create_zoom_wrapper(payload); break;
        case MimicProfile::GENERIC_TCP:        result = create_generic_tcp_wrapper(payload); break;
        case MimicProfile::GENERIC_UDP:
        default:                               result = create_generic_udp_wrapper(payload); break;
    }

    stats_.packets_wrapped++;
    stats_.bytes_mimicked += result.size();

    {
        std::lock_guard<std::mutex> lock(stats_overhead_mutex_);
        uint64_t orig = stats_.bytes_original.load();
        if (orig > 0) {
            stats_.average_overhead_percent = (static_cast<double>(stats_.bytes_mimicked.load()) / orig - 1.0) * 100.0;
        }
    }

    last_packet_time_ = std::chrono::steady_clock::now();
    return result;
}

std::vector<uint8_t> TrafficMimicry::wrap_payload(const std::vector<uint8_t>& payload) {
    return wrap_payload(payload, config_.profile);
}

std::vector<uint8_t> TrafficMimicry::unwrap_payload(
    const std::vector<uint8_t>& mimicked_data, MimicProfile profile) {
    std::vector<uint8_t> result;
    switch (profile) {
        case MimicProfile::HTTP_GET:
        case MimicProfile::HTTP_POST:           result = extract_http_payload(mimicked_data); break;
        case MimicProfile::HTTPS_CLIENT_HELLO:
        case MimicProfile::HTTPS_APPLICATION:   result = extract_tls_payload(mimicked_data); break;
        case MimicProfile::DNS_QUERY:
        case MimicProfile::DNS_RESPONSE:        result = extract_dns_payload(mimicked_data); break;
        case MimicProfile::QUIC_INITIAL:        result = extract_quic_payload(mimicked_data); break;
        case MimicProfile::WEBSOCKET:           result = extract_websocket_payload(mimicked_data); break;
        case MimicProfile::BITTORRENT:          result = extract_bittorrent_payload(mimicked_data); break;
        default:
            // Generic fallback uses 4-byte length prefix
            if (mimicked_data.size() > 4) {
                uint32_t len = (static_cast<uint32_t>(mimicked_data[0]) << 24) |
                               (static_cast<uint32_t>(mimicked_data[1]) << 16) |
                               (static_cast<uint32_t>(mimicked_data[2]) << 8) |
                                static_cast<uint32_t>(mimicked_data[3]);
                if (4 + len <= mimicked_data.size()) {
                    result.assign(mimicked_data.begin() + 4, mimicked_data.begin() + 4 + len);
                } else {
                    result.assign(mimicked_data.begin() + 4, mimicked_data.end());
                }
            }
            break;
    }
    stats_.packets_unwrapped++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data) {
    MimicProfile detected = detect_profile(mimicked_data);
    return unwrap_payload(mimicked_data, detected);
}

// ==================== Configuration ====================
void TrafficMimicry::set_config(const MimicConfig& config) {
    config_ = config;
    // Task #4: If config.wire_version is set, update internal version
    if (config_.wire_version != 0) {
        wire_version_ = config_.wire_version;
    }
}

TrafficMimicry::MimicConfig TrafficMimicry::get_config() const {
    return config_;
}

// ==================== Statistics ====================
TrafficMimicry::MimicStats TrafficMimicry::get_stats() const {
    MimicStats s;
    s.packets_wrapped.store(stats_.packets_wrapped.load());
    s.packets_unwrapped.store(stats_.packets_unwrapped.load());
    s.bytes_original.store(stats_.bytes_original.load());
    s.bytes_mimicked.store(stats_.bytes_mimicked.load());
    {
        std::lock_guard<std::mutex> lock(stats_overhead_mutex_);
        s.average_overhead_percent = stats_.average_overhead_percent;
    }
    return s;
}

void TrafficMimicry::reset_stats() {
    stats_.packets_wrapped.store(0);
    stats_.packets_unwrapped.store(0);
    stats_.bytes_original.store(0);
    stats_.bytes_mimicked.store(0);
    {
        std::lock_guard<std::mutex> lock(stats_overhead_mutex_);
        stats_.average_overhead_percent = 0.0;
    }
}

// ==================== Profile detection ====================
TrafficMimicry::MimicProfile TrafficMimicry::detect_profile(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return MimicProfile::GENERIC_UDP;

    if (data[0] == 0x16 || data[0] == 0x17) {
        if (data.size() >= 5 && data[1] == 0x03) {
            return (data[0] == 0x16) ? MimicProfile::HTTPS_CLIENT_HELLO : MimicProfile::HTTPS_APPLICATION;
        }
    }

    if (data.size() >= 4) {
        if (data[0]=='G' && data[1]=='E' && data[2]=='T' && data[3]==' ') return MimicProfile::HTTP_GET;
    }
    if (data.size() >= 5) {
        if (data[0]=='P' && data[1]=='O' && data[2]=='S' && data[3]==' ' && data[4]==' ') return MimicProfile::HTTP_POST;
    }

    if (data.size() >= 20 && data[0] == 19) {
        static const char* bt_proto = "BitTorrent protocol";
        if (std::memcmp(&data[1], bt_proto, 19) == 0) {
            return MimicProfile::BITTORRENT;
        }
    }

    if (data.size() >= 5 && (data[0] & 0x80)) {
        if (data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00 && data[4] == 0x01) {
            return MimicProfile::QUIC_INITIAL;
        }
    }

    // Check for DNS
    if (data.size() >= 12) {
        uint16_t flags = (data[2] << 8) | data[3];
        uint16_t qr = (flags >> 15) & 0x01;
        uint16_t opcode = (flags >> 11) & 0x0F;
        uint16_t qdcount = (data[4] << 8) | data[5];
        if (opcode == 0 && qdcount >= 1 && qdcount <= 16) {
            if (qr == 0) return MimicProfile::DNS_QUERY;
            if (qr == 1) return MimicProfile::DNS_RESPONSE;
        }
    }

    // Check for WebSocket frame
    if (data.size() >= 6) {
        bool fin = (data[0] & 0x80) != 0;
        uint8_t opcode = data[0] & 0x0F;
        bool masked = (data[1] & 0x80) != 0;
        uint8_t len7 = data[1] & 0x7F;
        if (fin && masked && opcode >= 0x01 && opcode <= 0x0A) {
            size_t header_len = 2 + 4;
            if (len7 == 126) header_len += 2;
            else if (len7 == 127) header_len += 8;
            if (data.size() >= header_len) {
                return MimicProfile::WEBSOCKET;
            }
        }
    }

    return MimicProfile::GENERIC_TCP;
}

// ==================== Timing ====================
std::chrono::milliseconds TrafficMimicry::get_next_packet_delay() {
    return calculate_realistic_delay(config_.profile, 0);
}

std::chrono::milliseconds TrafficMimicry::calculate_realistic_delay(
    MimicProfile profile, size_t packet_size) {

    if (!config_.enable_timing_mimicry) {
        return std::chrono::milliseconds(0);
    }

    int base_delay = 0;
    int jitter = 0;

    switch (profile) {
        case MimicProfile::HTTP_GET:
        case MimicProfile::HTTP_POST:           base_delay = 75;  jitter = 50; break;
        case MimicProfile::HTTPS_CLIENT_HELLO:
        case MimicProfile::HTTPS_APPLICATION:   base_delay = 100; jitter = 75; break;
        case MimicProfile::DNS_QUERY:
        case MimicProfile::DNS_RESPONSE:        base_delay = 20;  jitter = 15; break;
        case MimicProfile::QUIC_INITIAL:        base_delay = 50;  jitter = 30; break;
        case MimicProfile::WEBSOCKET:           base_delay = 10;  jitter = 10; break;
        case MimicProfile::SKYPE:
        case MimicProfile::ZOOM:                base_delay = 20;  jitter = 5;  break;
        case MimicProfile::BITTORRENT:          base_delay = 200; jitter = 150; break;
        default:                                base_delay = 50;  jitter = 25; break;
    }

    base_delay += static_cast<int>(packet_size / 1000);
    int final_delay = std::max(config_.min_inter_packet_delay,
                      std::min(config_.max_inter_packet_delay,
                               base_delay + ncp::csprng_range(-jitter, jitter)));

    return std::chrono::milliseconds(final_delay);
}

// ==================== Utility helpers ====================
std::string TrafficMimicry::generate_random_http_path() {
    int idx = ncp::csprng_range(0, static_cast<int>(RU_WHITELIST_PATHS.size()) - 1);
    return RU_WHITELIST_PATHS[idx];
}

std::string TrafficMimicry::generate_random_user_agent() {
    if (!config_.http_user_agent.empty()) return config_.http_user_agent;
    int idx = ncp::csprng_range(0, static_cast<int>(RU_USER_AGENTS.size()) - 1);
    return RU_USER_AGENTS[idx];
}

std::string TrafficMimicry::generate_random_hostname() {
    if (!config_.http_host.empty()) return config_.http_host;
    int idx = ncp::csprng_range(0, static_cast<int>(RU_WHITELIST_HOSTS.size()) - 1);
    return RU_WHITELIST_HOSTS[idx];
}

uint16_t TrafficMimicry::generate_random_port() {
    return static_cast<uint16_t>(ncp::csprng_range(1024, 65535));
}

std::vector<uint8_t> TrafficMimicry::generate_random_padding(size_t min_size, size_t max_size) {
    if (!config_.enable_size_mimicry) return {};
    size_t sz = static_cast<size_t>(ncp::csprng_range(
        static_cast<int>(min_size), static_cast<int>(max_size)));
    std::vector<uint8_t> pad(sz);
    ncp::csprng_fill(pad.data(), sz);
    return pad;
}

// ==================== Base64 ====================
static std::string base64_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) return {};
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                          (static_cast<uint32_t>(data[i + 1]) << 8) |
                           static_cast<uint32_t>(data[i + 2]);
        out += chars[(triple >> 18) & 0x3F];
        out += chars[(triple >> 12) & 0x3F];
        out += chars[(triple >> 6) & 0x3F];
        out += chars[triple & 0x3F];
    }
    size_t remaining = data.size() - i;
    if (remaining == 1) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        out += chars[(val >> 18) & 0x3F];
        out += chars[(val >> 12) & 0x3F];
        out += '='; out += '=';
    } else if (remaining == 2) {
        uint32_t val = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8);
        out += chars[(val >> 18) & 0x3F];
        out += chars[(val >> 12) & 0x3F];
        out += chars[(val >> 6) & 0x3F];
        out += '=';
    }
    return out;
}

static std::vector<uint8_t> base64_decode(const std::string& encoded) {
    if (encoded.empty()) return {};
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> decoded;
    decoded.reserve((encoded.size() / 4) * 3);
    uint32_t buf = 0;
    int bits = 0;
    for (char c : encoded) {
        if (c == '=' || c == '\0') break;
        size_t pos = chars.find(c);
        if (pos == std::string::npos) continue;
        buf = (buf << 6) | static_cast<uint32_t>(pos);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return decoded;
}

// ==================== HTTP wrappers ====================
std::vector<uint8_t> TrafficMimicry::create_http_get_wrapper(const std::vector<uint8_t>& payload) {
    if (payload.size() > 512) {
        return create_http_post_wrapper(payload);
    }
    std::string host = generate_random_hostname();
    std::string path = generate_random_http_path();
    std::string encoded = base64_encode(payload);

    std::ostringstream oss;
    oss << "GET " << path << " HTTP/1.1\r
";
    oss << "Host: " << host << "\r
";
    oss << "User-Agent: " << generate_random_user_agent() << "\r
";
    oss << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r
";
    oss << "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r
";
    oss << "Accept-Encoding: gzip, deflate, br\r
";
    oss << "Cookie: _ym_uid=" << encoded << "\r
";
    oss << "Connection: keep-alive\r
";
    for (const auto& h : config_.http_headers) oss << h << "\r
";
    oss << "\r
";

    std::string headers = oss.str();
    return std::vector<uint8_t>(headers.begin(), headers.end());
}

std::vector<uint8_t> TrafficMimicry::create_http_post_wrapper(const std::vector<uint8_t>& payload) {
    std::string host = generate_random_hostname();
    std::string encoded = base64_encode(payload);
    std::string body = "{\"v\":1,\"s\":\"" + encoded + "\",\"t\":" + std::to_string(std::time(nullptr)) + "}";

    std::ostringstream oss;
    oss << "POST /api/v2/data HTTP/1.1\r
";
    oss << "Host: " << host << "\r
";
    oss << "User-Agent: " << generate_random_user_agent() << "\r
";
    oss << "Accept: application/json\r
";
    oss << "Accept-Language: ru-RU,ru;q=0.9\r
";
    oss << "Content-Type: application/json; charset=utf-8\r
";
    oss << "Content-Length: " << body.size() << "\r
";
    oss << "Connection: keep-alive\r
";
    oss << "Origin: https://" << host << "\r
";
    oss << "Referer: https://" << host << "/\r
";
    for (const auto& h : config_.http_headers) oss << h << "\r
";
    oss << "\r
";

    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), body.begin(), body.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_http_payload(const std::vector<uint8_t>& data) {
    std::string s(data.begin(), data.end());
    size_t cookie_pos = s.find("_ym_uid=");
    if (cookie_pos != std::string::npos) {
        size_t start = cookie_pos + 8;
        size_t end = s.find_first_of(";\r
 ", start);
        if (end == std::string::npos) end = s.size();
        std::string encoded = s.substr(start, end - start);
        return base64_decode(encoded);
    }
    size_t param_pos = s.find("?d=");
    if (param_pos != std::string::npos) {
        size_t start = param_pos + 3;
        size_t end = s.find_first_of(" &\r
", start);
        std::string encoded = s.substr(start, end - start);
        return base64_decode(encoded);
    }
    size_t body_pos = s.find("\r
\r
");
    if (body_pos != std::string::npos) {
        std::string body = s.substr(body_pos + 4);
        size_t s_pos = body.find("\"s\":\"");
        if (s_pos != std::string::npos) {
            size_t start = s_pos + 5;
            size_t end = body.find('"', start);
            if (end != std::string::npos) {
                return base64_decode(body.substr(start, end - start));
            }
        }
        return std::vector<uint8_t>(data.begin() + body_pos + 4, data.end());
    }
    return data;
}

// ==================== TLS ClientHello wrapper (AEAD encryption) ====================
std::vector<uint8_t> TrafficMimicry::create_https_client_hello_wrapper(const std::vector<uint8_t>& payload) {
    std::string sni = config_.tls_sni;
    if (sni.empty()) {
        int idx = ncp::csprng_range(0, static_cast<int>(RU_TLS_SNI_HOSTS.size()) - 1);
        sni = RU_TLS_SNI_HOSTS[idx];
    }

    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; // 24 bytes
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> ciphertext(payload.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;

    {
        std::lock_guard<std::mutex> lock(tls_key_mutex_);
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ct_len,
            payload.data(), payload.size(),
            nullptr, 0, nullptr, nonce, tls_session_key_.data());
    }
    ciphertext.resize(static_cast<size_t>(ct_len));

    std::vector<uint8_t> result;
    // TLS Record header
    result.push_back(0x16);
    result.push_back(0x03);
    result.push_back(0x01);
    size_t record_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00);

    // Handshake header
    result.push_back(0x01);
    size_t handshake_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00);

    // Client version
    result.push_back(0x03);
    result.push_back(0x03);

    // Random (32 bytes): nonce (24) + version tag (1) + 7 random padding bytes
    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    result.push_back(wire_version_); // Task #4
    for (int i = 0; i < 7; ++i) result.push_back(ncp::csprng_byte());

    // Session ID: first min(32, ct_len) bytes of ciphertext
    size_t session_id_len = std::min(ciphertext.size(), size_t(32));
    result.push_back(static_cast<uint8_t>(session_id_len));
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + session_id_len);

    // Cipher suites
    std::vector<uint16_t> suites = config_.tls_cipher_suites;
    if (suites.empty()) {
        suites = {0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0x009E, 0x009C, 0x00FF};
    }
    uint16_t suites_len = static_cast<uint16_t>(suites.size() * 2);
    result.push_back(static_cast<uint8_t>(suites_len >> 8));
    result.push_back(static_cast<uint8_t>(suites_len & 0xFF));
    for (auto cs : suites) {
        result.push_back(static_cast<uint8_t>(cs >> 8));
        result.push_back(static_cast<uint8_t>(cs & 0xFF));
    }

    // Compression methods
    result.push_back(0x01);
    result.push_back(0x00);

    // Extensions
    std::vector<uint8_t> exts;
    // SNI extension (0x0000)
    {
        uint16_t name_len = static_cast<uint16_t>(sni.size());
        uint16_t list_len = name_len + 3;
        exts.push_back(0x00); exts.push_back(0x00);
        uint16_t ext_total = list_len + 2;
        exts.push_back(static_cast<uint8_t>(ext_total >> 8));
        exts.push_back(static_cast<uint8_t>(ext_total & 0xFF));
        exts.push_back(static_cast<uint8_t>(list_len >> 8));
        exts.push_back(static_cast<uint8_t>(list_len & 0xFF));
        exts.push_back(0x00);
        exts.push_back(static_cast<uint8_t>(name_len >> 8));
        exts.push_back(static_cast<uint8_t>(name_len & 0xFF));
        exts.insert(exts.end(), sni.begin(), sni.end());
    }

    // Supported versions extension (0x002B)
    exts.push_back(0x00); exts.push_back(0x2B);
    exts.push_back(0x00); exts.push_back(0x05);
    exts.push_back(0x04); exts.push_back(0x03);
    exts.push_back(0x04); exts.push_back(0x03); exts.push_back(0x03);

    // pre_shared_key extension (0x0029) — carries remaining ciphertext
    size_t remaining_ct = ciphertext.size() > session_id_len ? ciphertext.size() - session_id_len : 0;
    if (remaining_ct > 0) {
        exts.push_back(0x00); exts.push_back(0x29);
        uint16_t identity_len = static_cast<uint16_t>(remaining_ct);
        uint16_t identities_len = identity_len + 2 + 4;
        uint16_t binder_len = 32;
        uint16_t binders_len = binder_len + 1;
        uint16_t psk_total = identities_len + 2 + binders_len + 2;

        exts.push_back(static_cast<uint8_t>(psk_total >> 8));
        exts.push_back(static_cast<uint8_t>(psk_total & 0xFF));
        exts.push_back(static_cast<uint8_t>(identities_len >> 8));
        exts.push_back(static_cast<uint8_t>(identities_len & 0xFF));
        exts.push_back(static_cast<uint8_t>(identity_len >> 8));
        exts.push_back(static_cast<uint8_t>(identity_len & 0xFF));
        exts.insert(exts.end(), ciphertext.begin() + session_id_len, ciphertext.end());
        for (int i = 0; i < 4; ++i) exts.push_back(ncp::csprng_byte());
        exts.push_back(static_cast<uint8_t>(binders_len >> 8));
        exts.push_back(static_cast<uint8_t>(binders_len & 0xFF));
        exts.push_back(static_cast<uint8_t>(binder_len));
        for (uint16_t i = 0; i < binder_len; ++i) exts.push_back(ncp::csprng_byte());
    }

    uint16_t exts_len = static_cast<uint16_t>(exts.size());
    result.push_back(static_cast<uint8_t>(exts_len >> 8));
    result.push_back(static_cast<uint8_t>(exts_len & 0xFF));
    result.insert(result.end(), exts.begin(), exts.end());

    size_t total_len = result.size() - 5;
    result[record_length_pos] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
    result[record_length_pos + 1] = static_cast<uint8_t>(total_len & 0xFF);

    size_t hs_len = result.size() - 9;
    result[handshake_length_pos] = static_cast<uint8_t>((hs_len >> 16) & 0xFF);
    result[handshake_length_pos + 1] = static_cast<uint8_t>((hs_len >> 8) & 0xFF);
    result[handshake_length_pos + 2] = static_cast<uint8_t>(hs_len & 0xFF);

    tls_seq_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

// Task #1: HTTPS Application Data wrapper (AEAD encryption)
// Format: [5: TLS Header][24: Nonce][2: ct_len][var: ciphertext][var: padding]
std::vector<uint8_t> TrafficMimicry::create_https_application_wrapper(const std::vector<uint8_t>& payload) {
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> ct(payload.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;

    {
        std::lock_guard<std::mutex> lock(tls_key_mutex_);
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            payload.data(), payload.size(),
            nullptr, 0, nullptr, nonce, tls_session_key_.data());
    }
    ct.resize(static_cast<size_t>(ct_len));

    std::vector<uint8_t> result;
    result.push_back(0x17);
    result.push_back(0x03);
    result.push_back(0x03);
    size_t record_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00);

    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    result.push_back(static_cast<uint8_t>(ct.size() >> 8));
    result.push_back(static_cast<uint8_t>(ct.size() & 0xFF));
    result.insert(result.end(), ct.begin(), ct.end());

    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        auto padding = generate_random_padding(config_.min_padding, config_.max_padding);
        result.insert(result.end(), padding.begin(), padding.end());
    }

    size_t total_payload = result.size() - 5;
    result[record_length_pos] = static_cast<uint8_t>(total_payload >> 8);
    result[record_length_pos + 1] = static_cast<uint8_t>(total_payload & 0xFF);

    tls_seq_.fetch_add(1, std::memory_order_relaxed);
    return result;
}

// ==================== TLS payload extraction ====================
std::vector<uint8_t> TrafficMimicry::extract_tls_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 5) return {};

    if (data[0] == 0x17) {
        // Task #1: Application Data — AEAD format
        // Expected min: 5 (header) + 24 (nonce) + 2 (ct_len) + ABYTES (16) = 47
        if (data.size() < 47) return {};

        const uint8_t* nonce = &data[5];
        uint16_t ct_len = (static_cast<uint16_t>(data[29]) << 8) | data[30];
        const uint8_t* ciphertext = &data[31];

        if (data.size() < 31u + ct_len) return {};

        std::vector<uint8_t> plaintext(ct_len);
        unsigned long long pt_len = 0;

        std::lock_guard<std::mutex> lock(tls_key_mutex_);
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &pt_len, nullptr,
            ciphertext, ct_len, nullptr, 0,
            nonce, tls_session_key_.data()) != 0) {
            return {};
        }
        plaintext.resize(static_cast<size_t>(pt_len));
        return plaintext;

    } else if (data[0] == 0x16) {
        // ClientHello — decrypt with XChaCha20-Poly1305
        // Task #7: bounds checks
        if (data.size() < 44) return {};

        // Extract nonce from Random field (offset 11)
        uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        std::memcpy(nonce, &data[11], sizeof(nonce));

        // Task #4: Verify wire version (Random[24] = data[35])
        if (data[35] != wire_version_) return {};

        // Extract session_id
        uint8_t session_id_len = data[43];
        if (data.size() < 44u + session_id_len) return {};
        std::vector<uint8_t> ciphertext;
        ciphertext.insert(ciphertext.end(), data.begin() + 44, data.begin() + 44 + session_id_len);

        size_t pos = 44 + session_id_len;
        // Skip cipher suites
        if (pos + 2 > data.size()) return {};
        uint16_t suites_len = (data[pos] << 8) | data[pos+1];
        pos += 2 + suites_len;

        // Skip compression methods
        if (pos + 1 > data.size()) return {};
        uint8_t comp_len = data[pos];
        pos += 1 + comp_len;

        // Extensions
        if (pos + 2 <= data.size()) {
            uint16_t exts_total_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            size_t ext_end = pos + exts_total_len;
            if (ext_end > data.size()) ext_end = data.size();

            while (pos + 4 <= ext_end) {
                uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
                uint16_t ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;
                if (pos + ext_data_len > ext_end) break;

                if (ext_type == 0x0029) { // pre_shared_key
                    size_t psk_pos = pos;
                    if (psk_pos + 2 > ext_end) break;
                    uint16_t identities_len = (data[psk_pos] << 8) | data[psk_pos + 1];
                    psk_pos += 2;
                    if (psk_pos + 2 > ext_end) break;
                    uint16_t identity_len = (data[psk_pos] << 8) | data[psk_pos + 1];
                    psk_pos += 2;
                    if (psk_pos + identity_len > ext_end) break;
                    ciphertext.insert(ciphertext.end(), data.begin() + psk_pos, data.begin() + psk_pos + identity_len);
                }
                pos += ext_data_len;
            }
        }

        if (ciphertext.empty()) return {};
        std::vector<uint8_t> plaintext(ciphertext.size());
        unsigned long long pt_len = 0;

        std::lock_guard<std::mutex> lock(tls_key_mutex_);
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &pt_len, nullptr,
            ciphertext.data(), ciphertext.size(),
            nullptr, 0, nonce, tls_session_key_.data()) != 0) {
            return {};
        }
        plaintext.resize(static_cast<size_t>(pt_len));
        return plaintext;
    }

    return {};
}

// ==================== WebSocket (RFC 6455) ====================
std::vector<uint8_t> TrafficMimicry::create_websocket_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    frame.push_back(0x82);
    size_t len = payload.size();
    if (len <= 125) {
        frame.push_back(static_cast<uint8_t>(0x80 | len));
    } else if (len <= 65535) {
        frame.push_back(0x80 | 126);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; --i) frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
    }
    std::array<uint8_t, 4> mask;
    ncp::csprng_fill(mask.data(), 4);
    for (int i = 0; i < 4; ++i) frame.push_back(mask[i]);
    for (size_t i = 0; i < payload.size(); ++i) frame.push_back(payload[i] ^ mask[i % 4]);
    return frame;
}

std::vector<uint8_t> TrafficMimicry::extract_websocket_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return {};
    bool masked = data[1] & 0x80;
    uint64_t plen = data[1] & 0x7F;
    size_t pos = 2;
    if (plen == 126) {
        if (data.size() < 4) return {};
        plen = (uint64_t(data[2])<<8)|data[3];
        pos = 4;
    } else if (plen == 127) {
        if (data.size() < 10) return {};
        plen = 0;
        for (int i=0;i<8;++i) plen=(plen<<8)|data[2+i];
        pos = 10;
    }
    std::array<uint8_t, 4> mask_key = {0,0,0,0};
    if (masked) {
        if (pos + 4 > data.size()) return {};
        for (int i=0;i<4;++i) mask_key[i]=data[pos+i];
        pos+=4;
    }
    if (pos + plen > data.size()) return {};
    std::vector<uint8_t> r(static_cast<size_t>(plen));
    for (uint64_t i = 0; i < plen; ++i) r[static_cast<size_t>(i)] = data[pos+static_cast<size_t>(i)] ^ mask_key[i%4];
    return r;
}

// ==================== DNS ====================
std::vector<uint8_t> TrafficMimicry::create_dns_query_wrapper(const std::vector<uint8_t>& payload) {
    if (payload.size() > MAX_DNS_PAYLOAD) return {};

    uint16_t txn_id = static_cast<uint16_t>(ncp::csprng_range(0, 0xFFFF));
    dns_transaction_id_.store(txn_id, std::memory_order_relaxed);

    int lbl_idx = ncp::csprng_range(0, static_cast<int>(RU_DNS_LABELS.size()) - 1);
    dns_last_domain_idx_.store(lbl_idx, std::memory_order_relaxed);

    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    char len_label[8];
    snprintf(len_label, sizeof(len_label), "%04x", static_cast<unsigned int>(payload.size()));
    result.push_back(4);
    result.insert(result.end(), len_label, len_label + 4);

    size_t qname_bytes_used = 5;
    const auto& lbl = RU_DNS_LABELS[static_cast<size_t>(lbl_idx)];
    size_t suffix_size = 1 + lbl.sld_len + 1 + lbl.tld_len + 1;
    size_t pos = 0;

    while (pos < payload.size()) {
        size_t chunk = std::min({size_t(31), payload.size() - pos, (253 - qname_bytes_used - suffix_size - 1) / 2});
        if (chunk == 0) break;
        result.push_back(static_cast<uint8_t>(chunk * 2));
        for (size_t i = 0; i < chunk; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", payload[pos + i]);
            result.push_back(static_cast<uint8_t>(hex[0]));
            result.push_back(static_cast<uint8_t>(hex[1]));
        }
        qname_bytes_used += 1 + chunk * 2;
        pos += chunk;
    }

    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x10); // TYPE: TXT
    result.push_back(0x00); result.push_back(0x01); // CLASS: IN

    // OPT RR
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x29);
    result.push_back(0x10); result.push_back(0x00); // UDP payload size 4096
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x80); // DO bit
    result.push_back(0x00); result.push_back(0x00); // RDLEN

    return result;
}

std::vector<uint8_t> TrafficMimicry::create_dns_response_wrapper(const std::vector<uint8_t>& payload) {
    uint16_t txn_id = dns_transaction_id_.load(std::memory_order_relaxed);
    int lbl_idx = dns_last_domain_idx_.load(std::memory_order_relaxed);

    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };

    const auto& lbl = RU_DNS_LABELS[static_cast<size_t>(lbl_idx)];
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00);

    result.push_back(0x00); result.push_back(0x10); // TXT
    result.push_back(0x00); result.push_back(0x01); // IN

    // Answer RR
    result.push_back(0xC0); result.push_back(0x0C); // Compression to QNAME
    result.push_back(0x00); result.push_back(0x10); // TXT
    result.push_back(0x00); result.push_back(0x01); // IN
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x01); result.push_back(0x2C); // TTL 300

    std::vector<uint8_t> rdata;
    size_t ppos = 0;
    while (ppos < payload.size()) {
        size_t chunk = std::min(size_t(255), payload.size() - ppos);
        rdata.push_back(static_cast<uint8_t>(chunk));
        rdata.insert(rdata.end(), payload.begin() + ppos, payload.begin() + ppos + chunk);
        ppos += chunk;
    }
    uint16_t rdlen = static_cast<uint16_t>(rdata.size());
    result.push_back(static_cast<uint8_t>(rdlen >> 8));
    result.push_back(static_cast<uint8_t>(rdlen & 0xFF));
    result.insert(result.end(), rdata.begin(), rdata.end());

    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_dns_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 12) return {};
    uint16_t flags = (data[2] << 8) | data[3];
    bool is_response = (flags >> 15) & 0x01;

    if (is_response) {
        size_t pos = 12;
        uint16_t qdcount = (data[4] << 8) | data[5];
        for (uint16_t q = 0; q < qdcount && pos < data.size(); ++q) {
            while (pos < data.size() && data[pos] != 0) {
                if ((data[pos] & 0xC0) == 0xC0) { pos += 2; goto skip_qname; }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            skip_qname: pos += 4; // Type, Class
        }
        uint16_t ancount = (data[6] << 8) | data[7];
        for (uint16_t a = 0; a < ancount && pos < data.size(); ++a) {
            while (pos < data.size() && data[pos] != 0) {
                if ((data[pos] & 0xC0) == 0xC0) { pos += 2; break; }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            if (pos + 10 > data.size()) break;
            uint16_t type = (data[pos] << 8) | data[pos+1];
            uint16_t rdlen = (data[pos+8] << 8) | data[pos+9];
            pos += 10;
            if (type == 0x0010 && pos + rdlen <= data.size()) {
                std::vector<uint8_t> res;
                size_t rend = pos + rdlen;
                while (pos < rend) {
                    uint8_t txt_len = data[pos++];
                    if (pos + txt_len > rend) break;
                    res.insert(res.end(), data.begin() + pos, data.begin() + pos + txt_len);
                    pos += txt_len;
                }
                return res;
            }
            pos += rdlen;
        }
    } else {
        // Query: extract from QNAME
        std::vector<uint8_t> res;
        size_t pos = 12;
        if (pos >= data.size() || data[pos] != 4) return {};
        pos++;
        if (pos + 4 > data.size()) return {};
        char len_hex[5] = {0};
        std::memcpy(len_hex, &data[pos], 4);
        unsigned int expected_len = safe_hex_to_uint(len_hex, 4);
        pos += 4;
        while (pos < data.size() && data[pos] != 0 && res.size() < expected_len) {
            uint8_t label_len = data[pos++];
            if (label_len > 62 || pos + label_len > data.size()) break;
            for (uint8_t i = 0; i + 1 < label_len && res.size() < expected_len; i += 2) {
                uint8_t b;
                if (safe_hex_decode_byte(data[pos + i], data[pos + i + 1], b)) res.push_back(b);
            }
            pos += label_len;
        }
        return res;
    }
    return {};
}

// ==================== QUIC Initial (AEAD encrypted) ====================
std::vector<uint8_t> TrafficMimicry::create_quic_initial_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0xC0 | (ncp::csprng_byte() & 0x03));
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00); result.push_back(0x01); // Version 1

    uint8_t dcid[8]; ncp::csprng_fill(dcid, 8);
    result.push_back(8); result.insert(result.end(), dcid, dcid + 8);
    result.push_back(8); for (int i = 0; i < 8; ++i) result.push_back(ncp::csprng_byte()); // SCID

    result.push_back(0x00); // Token length 0

    uint8_t quic_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t quic_info[] = "NCP-QUIC-INITIAL-KEY-v1";
    crypto_generichash(quic_key, sizeof(quic_key), dcid, 8, quic_info, sizeof(quic_info) - 1);

    // Build plaintext: [version][4-byte length prefix][payload]
    uint32_t pl = static_cast<uint32_t>(payload.size());
    std::vector<uint8_t> plaintext;
    plaintext.push_back(wire_version_); // Task #4
    plaintext.push_back((pl >> 24) & 0xFF);
    plaintext.push_back((pl >> 16) & 0xFF);
    plaintext.push_back((pl >> 8) & 0xFF);
    plaintext.push_back(pl & 0xFF);
    plaintext.insert(plaintext.end(), payload.begin(), payload.end());

    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &ct_len, plaintext.data(), plaintext.size(), nullptr, 0, nullptr, nonce, quic_key);
    ct.resize(static_cast<size_t>(ct_len));

    uint16_t total_payload = static_cast<uint16_t>(sizeof(nonce) + 4 + ct.size());
    result.push_back(0x40 | ((total_payload >> 8) & 0x3F));
    result.push_back(total_payload & 0xFF);

    uint64_t pn = quic_packet_number_.fetch_add(1, std::memory_order_relaxed);
    result.push_back((pn >> 24) & 0xFF);
    result.push_back((pn >> 16) & 0xFF);
    result.push_back((pn >> 8) & 0xFF);
    result.push_back(pn & 0xFF);

    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    uint32_t ct_size = static_cast<uint32_t>(ct.size());
    result.push_back((ct_size >> 24) & 0xFF);
    result.push_back((ct_size >> 16) & 0xFF);
    result.push_back((ct_size >> 8) & 0xFF);
    result.push_back(ct_size & 0xFF);
    result.insert(result.end(), ct.begin(), ct.end());

    // Task #6: Customizable padding
    while (result.size() < config_.quic_min_packet_size) {
        result.push_back(0x00);
    }

    sodium_memzero(quic_key, sizeof(quic_key));
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_quic_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 30) return {};
    if (!(data[0] & 0x80)) return {};

    size_t pos = 5;
    if (pos >= data.size()) return {};
    uint8_t dcid_len = data[pos++];
    if (pos + dcid_len > data.size()) return {};
    const uint8_t* dcid = &data[pos];
    pos += dcid_len;

    uint8_t quic_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t quic_info[] = "NCP-QUIC-INITIAL-KEY-v1";
    crypto_generichash(quic_key, sizeof(quic_key), dcid, dcid_len, quic_info, sizeof(quic_info) - 1);

    if (pos >= data.size()) { sodium_memzero(quic_key, 32); return {}; }
    uint8_t scid_len = data[pos++];
    pos += scid_len;

    if (pos >= data.size()) { sodium_memzero(quic_key, 32); return {}; }
    uint8_t token_len = data[pos++];
    pos += token_len;

    if (pos + 1 > data.size()) { sodium_memzero(quic_key, 32); return {}; }
    if (data[pos] & 0x40) pos += 2; else pos += 1; // Length
    pos += 4; // Packet Number

    if (pos + 24 > data.size()) { sodium_memzero(quic_key, 32); return {}; }
    const uint8_t* nonce = &data[pos];
    pos += 24;

    if (pos + 4 > data.size()) { sodium_memzero(quic_key, 32); return {}; }
    uint32_t ct_size = (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos+1]) << 16) | (static_cast<uint32_t>(data[pos+2]) << 8) | data[pos+3];
    pos += 4;

    if (pos + ct_size > data.size()) { sodium_memzero(quic_key, 32); return {}; }

    std::vector<uint8_t> pt(ct_size);
    unsigned long long pt_len = 0;
    int r = crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &pt_len, nullptr, &data[pos], ct_size, nullptr, 0, nonce, quic_key);
    sodium_memzero(quic_key, 32);

    if (r != 0 || pt_len < 5) return {};
    pt.resize(static_cast<size_t>(pt_len));

    // Task #4: Verify wire version
    if (pt[0] != wire_version_) return {};
    uint32_t payload_len = (static_cast<uint32_t>(pt[1]) << 24) | (static_cast<uint32_t>(pt[2]) << 16) | (static_cast<uint32_t>(pt[3]) << 8) | pt[4];
    if (5 + payload_len > pt.size()) return {};
    return std::vector<uint8_t>(pt.begin() + 5, pt.begin() + 5 + payload_len);
}

// ==================== BitTorrent ====================
std::vector<uint8_t> TrafficMimicry::create_bittorrent_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> res;
    res.push_back(19);
    const char* pstr = "BitTorrent protocol";
    res.insert(res.end(), pstr, pstr + 19);

    uint32_t pl = static_cast<uint32_t>(payload.size());
    res.push_back((pl >> 24) & 0xFF); res.push_back((pl >> 16) & 0xFF); res.push_back((pl >> 8) & 0xFF); res.push_back(pl & 0xFF);
    res.push_back(wire_version_); // Task #4
    res.push_back(0x00); res.push_back(0x00); res.push_back(0x10);

    for (int i = 0; i < 20; ++i) res.push_back(ncp::csprng_byte());
    const char* prefix = "-qB4630-";
    res.insert(res.end(), prefix, prefix + 8);
    for (int i = 0; i < 12; ++i) res.push_back(ncp::csprng_byte());

    uint32_t msg_len = static_cast<uint32_t>(payload.size() + 9);
    res.push_back((msg_len >> 24) & 0xFF); res.push_back((msg_len >> 16) & 0xFF); res.push_back((msg_len >> 8) & 0xFF); res.push_back(msg_len & 0xFF);
    res.push_back(0x07); // msg_id: piece
    for (int i = 0; i < 4; ++i) res.push_back(ncp::csprng_byte()); // index
    for (int i = 0; i < 4; ++i) res.push_back(0x00); // begin=0
    res.insert(res.end(), payload.begin(), payload.end());
    return res;
}

std::vector<uint8_t> TrafficMimicry::extract_bittorrent_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 81) return {};
    if (data[0] != 19) return {};
    if (std::memcmp(&data[1], "BitTorrent protocol", 19) != 0) return {};
    // Task #4: Verify version
    if (data[24] != wire_version_) return {};

    uint32_t payload_len = (static_cast<uint32_t>(data[20]) << 24) | (static_cast<uint32_t>(data[21]) << 16) | (static_cast<uint32_t>(data[22]) << 8) | data[23];
    if (data[72] != 0x07) return {};
    if (81u + payload_len > data.size()) return {};
    return std::vector<uint8_t>(data.begin() + 81, data.begin() + 81 + payload_len);
}

// ==================== Skype ====================
std::vector<uint8_t> TrafficMimicry::create_skype_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> res;
    res.push_back(ncp::csprng_byte()); res.push_back(ncp::csprng_byte());
    res.push_back(0x02); res.push_back(0x00);
    uint32_t sn = skype_seq_.fetch_add(1, std::memory_order_relaxed);
    res.push_back((sn >> 8) & 0xFF); res.push_back(sn & 0xFF);
    uint16_t len = static_cast<uint16_t>(payload.size());
    res.push_back((len >> 8) & 0xFF); res.push_back(len & 0xFF);
    res.insert(res.end(), payload.begin(), payload.end());
    while (res.size() < 160) res.push_back(ncp::csprng_byte());
    return res;
}

// ==================== Zoom ====================
std::vector<uint8_t> TrafficMimicry::create_zoom_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> res;
    res.push_back(0x90); res.push_back(0x60);
    uint32_t sn = zoom_seq_.fetch_add(1, std::memory_order_relaxed);
    res.push_back((sn >> 8) & 0xFF); res.push_back(sn & 0xFF);
    uint32_t ts = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count());
    res.push_back((ts >> 24) & 0xFF); res.push_back((ts >> 16) & 0xFF); res.push_back((ts >> 8) & 0xFF); res.push_back(ts & 0xFF);
    for (int i = 0; i < 4; ++i) res.push_back(ncp::csprng_byte());
    res.push_back(0xBE); res.push_back(0xDE);
    uint16_t ext_len = static_cast<uint16_t>((payload.size() + 3) / 4);
    res.push_back((ext_len >> 8) & 0xFF); res.push_back(ext_len & 0xFF);
    uint16_t len = static_cast<uint16_t>(payload.size());
    res.push_back((len >> 8) & 0xFF); res.push_back(len & 0xFF);
    res.insert(res.end(), payload.begin(), payload.end());
    while (res.size() % 4 != 0) res.push_back(0x00);
    return res;
}

// ==================== Generic ====================
std::vector<uint8_t> TrafficMimicry::create_generic_tcp_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> res;
    uint32_t len = static_cast<uint32_t>(payload.size());
    res.push_back((len >> 24) & 0xFF); res.push_back((len >> 16) & 0xFF); res.push_back((len >> 8) & 0xFF); res.push_back(len & 0xFF);
    res.insert(res.end(), payload.begin(), payload.end());
    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        auto p = generate_random_padding(config_.min_padding, config_.max_padding);
        res.insert(res.end(), p.begin(), p.end());
    }
    return res;
}

std::vector<uint8_t> TrafficMimicry::create_generic_udp_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> res;
    uint32_t len = static_cast<uint32_t>(payload.size());
    res.push_back((len >> 24) & 0xFF); res.push_back((len >> 16) & 0xFF); res.push_back((len >> 8) & 0xFF); res.push_back(len & 0xFF);
    res.insert(res.end(), payload.begin(), payload.end());
    return res;
}

// ==================== TLS Session State Machine ====================
TlsSessionPhase TrafficMimicry::get_tls_session_phase() const {
    return static_cast<TlsSessionPhase>(tls_session_phase_.load(std::memory_order_relaxed));
}

bool TrafficMimicry::is_tls_managed() const {
    return config_.profile == MimicProfile::HTTPS_APPLICATION || config_.profile == MimicProfile::HTTPS_CLIENT_HELLO;
}

void TrafficMimicry::reset_tls_session() {
    tls_session_phase_.store(static_cast<int>(TlsSessionPhase::IDLE), std::memory_order_relaxed);
    tls_seq_.store(0, std::memory_order_relaxed);
}

std::vector<uint8_t> TrafficMimicry::create_fake_server_hello() {
    std::vector<uint8_t> res;
    res.push_back(0x16); res.push_back(0x03); res.push_back(0x03);
    size_t rlp = res.size(); res.push_back(0x00); res.push_back(0x00);
    res.push_back(0x02); size_t hlp = res.size(); res.push_back(0x00); res.push_back(0x00); res.push_back(0x00);
    res.push_back(0x03); res.push_back(0x03);
    for (int i=0;i<32;++i) res.push_back(ncp::csprng_byte());
    res.push_back(32); for (int i=0;i<32;++i) res.push_back(ncp::csprng_byte());
    res.push_back(0x13); res.push_back(0x01); res.push_back(0x00);
    std::vector<uint8_t> exts = {0x00,0x2B,0x00,0x02,0x03,0x04};
    uint16_t el = static_cast<uint16_t>(exts.size());
    res.push_back(static_cast<uint8_t>(el >> 8)); res.push_back(static_cast<uint8_t>(el & 0xFF));
    res.insert(res.end(), exts.begin(), exts.end());
    size_t tl = res.size() - 5; res[rlp] = static_cast<uint8_t>(tl >> 8); res[rlp+1] = static_cast<uint8_t>(tl & 0xFF);
    size_t hl = res.size() - 9; res[hlp] = static_cast<uint8_t>(hl >> 16); res[hlp+1] = static_cast<uint8_t>(hl >> 8); res[hlp+2] = static_cast<uint8_t>(hl & 0xFF);
    return res;
}

std::vector<uint8_t> TrafficMimicry::create_fake_change_cipher_spec() {
    return { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
}

std::vector<uint8_t> TrafficMimicry::create_fake_finished() {
    std::vector<uint8_t> res = { 0x16, 0x03, 0x03, 0x00, 0x28 };
    for (int i=0; i<40; ++i) res.push_back(ncp::csprng_byte());
    return res;
}

std::vector<std::vector<uint8_t>> TrafficMimicry::generate_tls_handshake_sequence() {
    std::vector<std::vector<uint8_t>> seq; std::vector<uint8_t> empty;
    seq.push_back(create_https_client_hello_wrapper(empty));
    seq.push_back(create_fake_server_hello());
    seq.push_back(create_fake_change_cipher_spec());
    seq.push_back(create_fake_finished());
    return seq;
}

std::vector<uint8_t> TrafficMimicry::wrap_tls_session_aware(
    const std::vector<uint8_t>& payload, std::vector<std::vector<uint8_t>>& handshake_preamble) {
    handshake_preamble.clear();
    int current_phase = tls_session_phase_.load(std::memory_order_relaxed);
    if (current_phase == static_cast<int>(TlsSessionPhase::IDLE)) {
        handshake_preamble = generate_tls_handshake_sequence();
        tls_session_phase_.store(static_cast<int>(TlsSessionPhase::APPLICATION_DATA), std::memory_order_relaxed);
    }
    return create_https_application_wrapper(payload);
}

} // namespace ncp
