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
TrafficMimicry::TrafficMimicry()
    : tls_seq_(0), skype_seq_(0), zoom_seq_(0),
      dns_transaction_id_(0), dns_last_domain_idx_(0),
      quic_packet_number_(0),
      tls_session_phase_(TlsSessionPhase::IDLE) {
    ncp::csprng_init();
    // Generate default session key for TLS mimicry encryption
    tls_session_key_.resize(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    randombytes_buf(tls_session_key_.data(), tls_session_key_.size());
}

TrafficMimicry::TrafficMimicry(const MimicConfig& config)
    : config_(config),
      tls_seq_(0), skype_seq_(0), zoom_seq_(0),
      dns_transaction_id_(0), dns_last_domain_idx_(0),
      quic_packet_number_(0),
      tls_session_phase_(TlsSessionPhase::IDLE) {
    ncp::csprng_init();
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
    if (!tls_session_key_.empty()) {
        sodium_memzero(tls_session_key_.data(), tls_session_key_.size());
    }
}

// ==================== TLS session key management ====================
void TrafficMimicry::set_tls_session_key(const std::vector<uint8_t>& key) {
    if (key.size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        return;
    }
    if (!tls_session_key_.empty()) {
        sodium_memzero(tls_session_key_.data(), tls_session_key_.size());
    }
    tls_session_key_ = key;
}

std::vector<uint8_t> TrafficMimicry::get_tls_session_key() const {
    return tls_session_key_;
}

// ==================== wrap / unwrap with stats ====================
std::vector<uint8_t> TrafficMimicry::wrap_payload(
        const std::vector<uint8_t>& payload, MimicProfile profile) {
    std::vector<uint8_t> result;
    stats_.bytes_original += payload.size();

    switch (profile) {
        case MimicProfile::HTTP_GET:            result = create_http_get_wrapper(payload); break;
        case MimicProfile::HTTP_POST:           result = create_http_post_wrapper(payload); break;
        case MimicProfile::HTTPS_CLIENT_HELLO:  result = create_https_client_hello_wrapper(payload); break;
        case MimicProfile::HTTPS_APPLICATION:   result = create_https_application_wrapper(payload); break;
        case MimicProfile::DNS_QUERY:           result = create_dns_query_wrapper(payload); break;
        case MimicProfile::DNS_RESPONSE:        result = create_dns_response_wrapper(payload); break;
        case MimicProfile::QUIC_INITIAL:        result = create_quic_initial_wrapper(payload); break;
        case MimicProfile::WEBSOCKET:           result = create_websocket_wrapper(payload); break;
        case MimicProfile::BITTORRENT:          result = create_bittorrent_wrapper(payload); break;
        case MimicProfile::SKYPE:               result = create_skype_wrapper(payload); break;
        case MimicProfile::ZOOM:                result = create_zoom_wrapper(payload); break;
        case MimicProfile::GENERIC_TCP:         result = create_generic_tcp_wrapper(payload); break;
        case MimicProfile::GENERIC_UDP:
        default:                                result = create_generic_udp_wrapper(payload); break;
    }

    stats_.packets_wrapped++;
    stats_.bytes_mimicked += result.size();
    {
        std::lock_guard<std::mutex> lock(stats_overhead_mutex_);
        uint64_t orig = stats_.bytes_original.load();
        if (orig > 0) {
            stats_.average_overhead_percent =
                (static_cast<double>(stats_.bytes_mimicked.load()) / orig - 1.0) * 100.0;
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

// Auto-detect profile then unwrap
std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data) {
    MimicProfile detected = detect_profile(mimicked_data);
    return unwrap_payload(mimicked_data, detected);
}

// ==================== Configuration ====================
void TrafficMimicry::set_config(const MimicConfig& config) { config_ = config; }
TrafficMimicry::MimicConfig TrafficMimicry::get_config() const { return config_; }

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
            return (data[0] == 0x16) ? MimicProfile::HTTPS_CLIENT_HELLO
                                     : MimicProfile::HTTPS_APPLICATION;
        }
    }

    if (data.size() >= 4) {
        if (data[0]=='G' && data[1]=='E' && data[2]=='T' && data[3]==' ')
            return MimicProfile::HTTP_GET;
    }
    if (data.size() >= 5) {
        if (data[0]=='P' && data[1]=='O' && data[2]=='S' && data[3]=='T' && data[4]==' ')
            return MimicProfile::HTTP_POST;
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

    // Check for DNS (before WebSocket to avoid false positives)
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

    // Check for WebSocket frame — require FIN bit + mask bit + length sanity
    if (data.size() >= 6) {
        bool fin = (data[0] & 0x80) != 0;
        uint8_t opcode = data[0] & 0x0F;
        bool masked = (data[1] & 0x80) != 0;
        uint8_t len7 = data[1] & 0x7F;

        if (fin && masked && opcode >= 0x01 && opcode <= 0x0A) {
            size_t header_len = 2 + 4; // base + mask key
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
        case MimicProfile::HTTP_POST:
            base_delay = 75; jitter = 50; break;
        case MimicProfile::HTTPS_CLIENT_HELLO:
        case MimicProfile::HTTPS_APPLICATION:
            base_delay = 100; jitter = 75; break;
        case MimicProfile::DNS_QUERY:
        case MimicProfile::DNS_RESPONSE:
            base_delay = 20; jitter = 15; break;
        case MimicProfile::QUIC_INITIAL:
            base_delay = 50; jitter = 30; break;
        case MimicProfile::WEBSOCKET:
            base_delay = 10; jitter = 10; break;
        case MimicProfile::SKYPE:
        case MimicProfile::ZOOM:
            base_delay = 20; jitter = 5; break;
        case MimicProfile::BITTORRENT:
            base_delay = 200; jitter = 150; break;
        default:
            base_delay = 50; jitter = 25; break;
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

    static const char* chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    // Process complete 3-byte groups
    for (; i + 2 < data.size(); i += 3) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                          (static_cast<uint32_t>(data[i + 1]) << 8) |
                           static_cast<uint32_t>(data[i + 2]);
        out += chars[(triple >> 18) & 0x3F];
        out += chars[(triple >> 12) & 0x3F];
        out += chars[(triple >> 6) & 0x3F];
        out += chars[triple & 0x3F];
    }

    // Handle remainder
    size_t remaining = data.size() - i;
    if (remaining == 1) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        out += chars[(val >> 18) & 0x3F];
        out += chars[(val >> 12) & 0x3F];
        out += '=';
        out += '=';
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

    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    oss << "GET " << path << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    oss << "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n";
    oss << "Accept-Encoding: gzip, deflate, br\r\n";
    oss << "Cookie: _ym_uid=" << encoded << "\r\n";
    oss << "Connection: keep-alive\r\n";
    for (const auto& h : config_.http_headers) oss << h << "\r\n";
    oss << "\r\n";

    std::string headers = oss.str();
    return std::vector<uint8_t>(headers.begin(), headers.end());
}

std::vector<uint8_t> TrafficMimicry::create_http_post_wrapper(const std::vector<uint8_t>& payload) {
    std::string host = generate_random_hostname();
    std::string encoded = base64_encode(payload);

    std::string body = "{\"v\":1,\"s\":\"" + encoded + "\",\"t\":" +
                       std::to_string(std::time(nullptr)) + "}";

    std::ostringstream oss;
    oss << "POST /api/v2/data HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Accept: application/json\r\n";
    oss << "Accept-Language: ru-RU,ru;q=0.9\r\n";
    oss << "Content-Type: application/json; charset=utf-8\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: keep-alive\r\n";
    oss << "Origin: https://" << host << "\r\n";
    oss << "Referer: https://" << host << "/\r\n";
    for (const auto& h : config_.http_headers) oss << h << "\r\n";
    oss << "\r\n";
    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), body.begin(), body.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_http_payload(const std::vector<uint8_t>& data) {
    std::string s(data.begin(), data.end());

    // Try Cookie extraction (GET)
    size_t cookie_pos = s.find("_ym_uid=");
    if (cookie_pos != std::string::npos) {
        size_t start = cookie_pos + 8;
        size_t end = s.find_first_of(";\r\n ", start);
        if (end == std::string::npos) end = s.size();
        std::string encoded = s.substr(start, end - start);
        return base64_decode(encoded);
    }

    // Try base64 URL parameter (legacy GET compat)
    size_t param_pos = s.find("?d=");
    if (param_pos != std::string::npos) {
        size_t start = param_pos + 3;
        size_t end = s.find_first_of(" &\r\n", start);
        std::string encoded = s.substr(start, end - start);
        return base64_decode(encoded);
    }

    // Try JSON body (POST): extract "s" field
    size_t body_pos = s.find("\r\n\r\n");
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
        // Fallback: raw body
        return std::vector<uint8_t>(data.begin() + body_pos + 4, data.end());
    }

    return data;
}

// ==================== TLS ClientHello wrapper (AEAD encryption) ====================
// Payload encrypted with XChaCha20-Poly1305 using tls_session_key_.
// - 24-byte nonce placed in Random field (24 of 32 bytes; rest is padding)
// - First min(32, ciphertext) bytes go into session_id field
// - Remaining ciphertext goes into pre_shared_key extension (0x0029)

std::vector<uint8_t> TrafficMimicry::create_https_client_hello_wrapper(const std::vector<uint8_t>& payload) {
    std::string sni = config_.tls_sni;
    if (sni.empty()) {
        int idx = ncp::csprng_range(0, static_cast<int>(RU_TLS_SNI_HOSTS.size()) - 1);
        sni = RU_TLS_SNI_HOSTS[idx];
    }

    // Encrypt payload with XChaCha20-Poly1305
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]; // 24 bytes
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> ciphertext(payload.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ct_len,
        payload.data(), payload.size(),
        nullptr, 0,
        nullptr,
        nonce,
        tls_session_key_.data());
    ciphertext.resize(static_cast<size_t>(ct_len));

    std::vector<uint8_t> result;

    // TLS Record header
    result.push_back(0x16); // Handshake
    result.push_back(0x03); result.push_back(0x01); // TLS 1.0 (legacy)
    size_t record_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); // placeholder

    // Handshake header
    result.push_back(0x01); // ClientHello
    size_t handshake_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00); // placeholder

    // Client version
    result.push_back(0x03); result.push_back(0x03); // TLS 1.2

    // Random (32 bytes): nonce (24) + 8 random padding bytes
    result.insert(result.end(), nonce, nonce + sizeof(nonce));
    for (int i = 0; i < 8; ++i) result.push_back(ncp::csprng_byte());

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
    result.push_back(0x01); result.push_back(0x00);

    // Extensions
    std::vector<uint8_t> exts;

    // SNI extension (0x0000)
    {
        uint16_t name_len = static_cast<uint16_t>(sni.size());
        uint16_t list_len = name_len + 3;
        exts.push_back(0x00); exts.push_back(0x00); // type
        uint16_t ext_total = list_len + 2;
        exts.push_back(static_cast<uint8_t>(ext_total >> 8));
        exts.push_back(static_cast<uint8_t>(ext_total & 0xFF));
        exts.push_back(static_cast<uint8_t>(list_len >> 8));
        exts.push_back(static_cast<uint8_t>(list_len & 0xFF));
        exts.push_back(0x00); // host_name type
        exts.push_back(static_cast<uint8_t>(name_len >> 8));
        exts.push_back(static_cast<uint8_t>(name_len & 0xFF));
        exts.insert(exts.end(), sni.begin(), sni.end());
    }

    // Supported versions extension (0x002B)
    exts.push_back(0x00); exts.push_back(0x2B);
    exts.push_back(0x00); exts.push_back(0x05);
    exts.push_back(0x04);
    exts.push_back(0x03); exts.push_back(0x04); // TLS 1.3
    exts.push_back(0x03); exts.push_back(0x03); // TLS 1.2

    // pre_shared_key extension (0x0029) — carries remaining ciphertext
    size_t remaining_ct = ciphertext.size() > session_id_len ? ciphertext.size() - session_id_len : 0;
    if (remaining_ct > 0) {
        exts.push_back(0x00); exts.push_back(0x29); // pre_shared_key type

        uint16_t identity_len = static_cast<uint16_t>(remaining_ct);
        uint16_t identities_len = identity_len + 2 + 4;
        uint16_t binder_len = 32;
        uint16_t binders_len = binder_len + 1;
        uint16_t psk_total = identities_len + 2 + binders_len + 2;

        exts.push_back(static_cast<uint8_t>(psk_total >> 8));
        exts.push_back(static_cast<uint8_t>(psk_total & 0xFF));

        // Identities
        exts.push_back(static_cast<uint8_t>(identities_len >> 8));
        exts.push_back(static_cast<uint8_t>(identities_len & 0xFF));
        exts.push_back(static_cast<uint8_t>(identity_len >> 8));
        exts.push_back(static_cast<uint8_t>(identity_len & 0xFF));
        exts.insert(exts.end(), ciphertext.begin() + session_id_len, ciphertext.end());

        // Obfuscated ticket age (4 bytes random)
        for (int i = 0; i < 4; ++i) exts.push_back(ncp::csprng_byte());

        // Binders
        exts.push_back(static_cast<uint8_t>(binders_len >> 8));
        exts.push_back(static_cast<uint8_t>(binders_len & 0xFF));
        exts.push_back(static_cast<uint8_t>(binder_len));
        for (uint16_t i = 0; i < binder_len; ++i) exts.push_back(ncp::csprng_byte());
    }

    // Extensions length
    uint16_t exts_len = static_cast<uint16_t>(exts.size());
    result.push_back(static_cast<uint8_t>(exts_len >> 8));
    result.push_back(static_cast<uint8_t>(exts_len & 0xFF));
    result.insert(result.end(), exts.begin(), exts.end());

    // Fix record length
    size_t total_len = result.size() - 5;
    result[record_length_pos] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
    result[record_length_pos + 1] = static_cast<uint8_t>(total_len & 0xFF);

    // Fix handshake length
    size_t hs_len = result.size() - 9;
    result[handshake_length_pos] = static_cast<uint8_t>((hs_len >> 16) & 0xFF);
    result[handshake_length_pos + 1] = static_cast<uint8_t>((hs_len >> 8) & 0xFF);
    result[handshake_length_pos + 2] = static_cast<uint8_t>(hs_len & 0xFF);

    tls_seq_++;
    return result;
}

// HTTPS Application Data wrapper (XOR obfuscation)
std::vector<uint8_t> TrafficMimicry::create_https_application_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0x17); // Application Data
    result.push_back(0x03); result.push_back(0x03); // TLS 1.2

    static constexpr size_t XOR_KEY_LEN = 16;
    std::array<uint8_t, XOR_KEY_LEN> xor_key;
    ncp::csprng_fill(xor_key.data(), XOR_KEY_LEN);

    size_t body_len = XOR_KEY_LEN + 4 + payload.size();
    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        body_len += static_cast<size_t>(ncp::csprng_range(
            config_.min_padding, config_.max_padding));
    }

    result.push_back(static_cast<uint8_t>((body_len >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(body_len & 0xFF));

    result.insert(result.end(), xor_key.begin(), xor_key.end());

    uint32_t pl = static_cast<uint32_t>(payload.size());
    uint8_t len_bytes[4] = {
        static_cast<uint8_t>((pl >> 24) & 0xFF),
        static_cast<uint8_t>((pl >> 16) & 0xFF),
        static_cast<uint8_t>((pl >> 8) & 0xFF),
        static_cast<uint8_t>(pl & 0xFF)
    };
    for (int i = 0; i < 4; ++i) {
        result.push_back(len_bytes[i] ^ xor_key[i % XOR_KEY_LEN]);
    }

    for (size_t i = 0; i < payload.size(); ++i) {
        result.push_back(payload[i] ^ xor_key[(i + 4) % XOR_KEY_LEN]);
    }

    while (result.size() < 5 + body_len) {
        result.push_back(ncp::csprng_byte());
    }

    tls_seq_++;
    return result;
}

// ==================== TLS payload extraction ====================
std::vector<uint8_t> TrafficMimicry::extract_tls_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 9) return {};
    if (data[0] != 0x16 && data[0] != 0x17) return {};

    if (data[0] == 0x17) {
        // Application Data — XOR-obfuscated format
        static constexpr size_t XOR_KEY_LEN = 16;
        if (data.size() < 5 + XOR_KEY_LEN + 4) return {};

        std::array<uint8_t, XOR_KEY_LEN> xor_key;
        std::copy(data.begin() + 5, data.begin() + 5 + XOR_KEY_LEN, xor_key.begin());

        size_t len_off = 5 + XOR_KEY_LEN;
        uint8_t len_bytes[4];
        for (int i = 0; i < 4; ++i) {
            len_bytes[i] = data[len_off + i] ^ xor_key[i % XOR_KEY_LEN];
        }
        uint32_t payload_len = (static_cast<uint32_t>(len_bytes[0]) << 24) |
                               (static_cast<uint32_t>(len_bytes[1]) << 16) |
                               (static_cast<uint32_t>(len_bytes[2]) << 8) |
                                static_cast<uint32_t>(len_bytes[3]);

        size_t payload_off = len_off + 4;
        if (data.size() < payload_off + payload_len) return {};

        std::vector<uint8_t> result(payload_len);
        for (size_t i = 0; i < payload_len; ++i) {
            result[i] = data[payload_off + i] ^ xor_key[(i + 4) % XOR_KEY_LEN];
        }
        return result;
    } else {
        // ClientHello — decrypt with XChaCha20-Poly1305
        if (data.size() < 44) return {};

        // Extract nonce from Random field (first 24 bytes)
        uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
        std::memcpy(nonce, &data[11], sizeof(nonce));

        // Extract session_id
        uint8_t session_id_len = data[43];
        if (data.size() < 44u + session_id_len) return {};

        std::vector<uint8_t> ciphertext;
        ciphertext.insert(ciphertext.end(), data.begin() + 44, data.begin() + 44 + session_id_len);

        // Skip cipher suites and compression to reach extensions
        size_t pos = 44 + session_id_len;

        if (pos + 2 <= data.size()) {
            uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
            pos += 2 + cipher_len;
        }
        if (pos + 1 <= data.size()) {
            pos += 1 + data[pos];
        }

        // Parse extensions, find pre_shared_key (0x0029)
        if (pos + 2 <= data.size()) {
            uint16_t ext_total_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            size_t ext_end = pos + ext_total_len;

            while (pos + 4 <= ext_end && pos + 4 <= data.size()) {
                uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
                uint16_t ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;

                if (ext_type == 0x0029 && pos + ext_data_len <= data.size()) {
                    size_t psk_pos = pos;
                    if (psk_pos + 2 > data.size()) break;
                    uint16_t identities_len = (data[psk_pos] << 8) | data[psk_pos + 1];
                    psk_pos += 2;
                    if (psk_pos + 2 > data.size()) break;
                    uint16_t identity_len = (data[psk_pos] << 8) | data[psk_pos + 1];
                    psk_pos += 2;
                    if (psk_pos + identity_len > data.size()) break;

                    ciphertext.insert(ciphertext.end(),
                                      data.begin() + psk_pos,
                                      data.begin() + psk_pos + identity_len);
                }
                pos += ext_data_len;
            }
        }

        if (ciphertext.empty()) return {};

        // Decrypt
        std::vector<uint8_t> plaintext(ciphertext.size());
        unsigned long long pt_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.data(), &pt_len,
                nullptr,
                ciphertext.data(), ciphertext.size(),
                nullptr, 0,
                nonce,
                tls_session_key_.data()) != 0) {
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
        for (int i = 7; i >= 0; --i)
            frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
    }
    std::array<uint8_t, 4> mask;
    ncp::csprng_fill(mask.data(), 4);
    for (int i = 0; i < 4; ++i) frame.push_back(mask[i]);
    for (size_t i = 0; i < payload.size(); ++i)
        frame.push_back(payload[i] ^ mask[i % 4]);
    return frame;
}

std::vector<uint8_t> TrafficMimicry::extract_websocket_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return {};
    bool masked = data[1] & 0x80;
    uint64_t plen = data[1] & 0x7F;
    size_t pos = 2;
    if (plen == 126) { if (data.size() < 4) return {}; plen = (uint64_t(data[2])<<8)|data[3]; pos = 4; }
    else if (plen == 127) { if (data.size() < 10) return {}; plen = 0; for (int i=0;i<8;++i) plen=(plen<<8)|data[2+i]; pos = 10; }
    std::array<uint8_t, 4> mask_key = {0,0,0,0};
    if (masked) { if (pos + 4 > data.size()) return {}; for (int i=0;i<4;++i) mask_key[i]=data[pos+i]; pos+=4; }
    if (pos + plen > data.size()) return {};
    std::vector<uint8_t> r(plen);
    for (uint64_t i = 0; i < plen; ++i) r[i] = data[pos+i] ^ mask_key[i%4];
    return r;
}

// ==================== DNS ====================
std::vector<uint8_t> TrafficMimicry::create_dns_query_wrapper(const std::vector<uint8_t>& payload) {
    if (payload.size() > MAX_DNS_PAYLOAD) {
        return {};
    }

    dns_transaction_id_ = static_cast<uint16_t>(ncp::csprng_range(0, 0xFFFF));
    uint16_t txn_id = dns_transaction_id_;

    // Pick and store domain index for query/response consistency
    dns_last_domain_idx_ = ncp::csprng_range(0, static_cast<int>(RU_DNS_LABELS.size()) - 1);

    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x01
    };

    // QNAME: length-prefix label + hex-encoded payload labels + RU domain suffix
    char len_label[8];
    snprintf(len_label, sizeof(len_label), "%04x", static_cast<unsigned>(payload.size()));
    result.push_back(4);
    result.insert(result.end(), len_label, len_label + 4);

    size_t qname_bytes_used = 5;
    const auto& lbl = RU_DNS_LABELS[dns_last_domain_idx_];
    size_t suffix_size = 1 + lbl.sld_len + 1 + lbl.tld_len + 1;

    size_t pos = 0;
    while (pos < payload.size()) {
        size_t max_label_bytes = 31; // 31 payload bytes = 62 hex chars (< 63 max)
        size_t remaining_budget = 253 - qname_bytes_used - suffix_size;
        size_t max_by_budget = (remaining_budget > 1) ? (remaining_budget - 1) / 2 : 0;
        size_t chunk = std::min({max_label_bytes, payload.size() - pos, max_by_budget});
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

    // RU domain suffix (using stored index for query/response consistency)
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00);

    result.push_back(0x00); result.push_back(0x10);
    result.push_back(0x00); result.push_back(0x01);

    // EDNS OPT
    result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x29);
    result.push_back(0x10); result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x80); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x00);

    return result;
}

std::vector<uint8_t> TrafficMimicry::create_dns_response_wrapper(const std::vector<uint8_t>& payload) {
    uint16_t txn_id = dns_transaction_id_;
    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x81, 0x80,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00
    };

    // Question section — SAME domain as the query (use stored index)
    const auto& lbl = RU_DNS_LABELS[dns_last_domain_idx_];
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x10);
    result.push_back(0x00); result.push_back(0x01);

    result.push_back(0xC0); result.push_back(0x0C);
    result.push_back(0x00); result.push_back(0x10);
    result.push_back(0x00); result.push_back(0x01);
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x01); result.push_back(0x2C); // TTL=300

    // TXT RDATA: split payload into 255-byte TXT strings (RFC 1035)
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
                if ((data[pos] & 0xC0) == 0xC0) { pos += 2; goto skip_qname_done; }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            skip_qname_done:
            pos += 4;
        }

        uint16_t ancount = (data[6] << 8) | data[7];
        for (uint16_t a = 0; a < ancount && pos < data.size(); ++a) {
            while (pos < data.size() && data[pos] != 0) {
                if ((data[pos] & 0xC0) == 0xC0) { pos += 2; goto skip_aname_done; }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            skip_aname_done:
            if (pos + 10 > data.size()) break;

            uint16_t type = (data[pos] << 8) | data[pos + 1];
            uint16_t rdlength = (data[pos + 8] << 8) | data[pos + 9];
            pos += 10;

            if (type == 0x0010 && pos + rdlength <= data.size()) { // TXT
                // Reassemble multi-string TXT RDATA
                std::vector<uint8_t> result;
                size_t rend = pos + rdlength;
                while (pos < rend) {
                    uint8_t txt_len = data[pos++];
                    if (pos + txt_len > rend) break;
                    result.insert(result.end(), data.begin() + pos, data.begin() + pos + txt_len);
                    pos += txt_len;
                }
                return result;
            }
            pos += rdlength;
        }
    } else {
        // DNS query: hex-encoded payload in labels
        std::vector<uint8_t> result;
        size_t pos = 12;

        if (pos >= data.size() || data[pos] != 4) return {};
        pos++;
        if (pos + 4 > data.size()) return {};
        char len_hex[5] = {0};
        std::memcpy(len_hex, &data[pos], 4);
        unsigned int payload_len = safe_hex_to_uint(len_hex, 4);
        pos += 4;

        while (pos < data.size() && data[pos] != 0 && result.size() < payload_len) {
            uint8_t label_len = data[pos++];
            if (label_len > 62 || pos + label_len > data.size()) break;
            for (uint8_t i = 0; i + 1 < label_len && result.size() < payload_len; i += 2) {
                uint8_t decoded_byte;
                if (safe_hex_decode_byte(data[pos + i], data[pos + i + 1], decoded_byte)) {
                    result.push_back(decoded_byte);
                }
            }
            pos += label_len;
        }
        return result;
    }
    return {};
}

// ==================== QUIC Initial (AEAD encrypted) ====================
// Ciphertext length encoded in header for O(1) extraction on receiver.

std::vector<uint8_t> TrafficMimicry::create_quic_initial_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;

    // Long header form bit + Initial type
    result.push_back(0xC0 | (ncp::csprng_byte() & 0x03));

    // Version (QUIC v1 = 0x00000001)
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x01);

    // DCID (8 bytes random)
    uint8_t dcid[8];
    ncp::csprng_fill(dcid, sizeof(dcid));
    result.push_back(8);
    result.insert(result.end(), dcid, dcid + 8);

    // SCID (8 bytes random)
    result.push_back(8);
    for (int i = 0; i < 8; ++i) result.push_back(ncp::csprng_byte());

    // Token length = 0
    result.push_back(0x00);

    // Derive encryption key from DCID
    uint8_t quic_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    uint8_t quic_info[] = "NCP-QUIC-INITIAL-KEY-v1";
    crypto_generichash(quic_key, sizeof(quic_key),
                       dcid, sizeof(dcid),
                       quic_info, sizeof(quic_info) - 1);

    // Build plaintext: 4-byte length prefix + payload
    uint32_t pl = static_cast<uint32_t>(payload.size());
    std::vector<uint8_t> plaintext;
    plaintext.push_back((pl >> 24) & 0xFF);
    plaintext.push_back((pl >> 16) & 0xFF);
    plaintext.push_back((pl >> 8) & 0xFF);
    plaintext.push_back(pl & 0xFF);
    plaintext.insert(plaintext.end(), payload.begin(), payload.end());

    // Encrypt with XChaCha20-Poly1305
    uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data(), &ct_len,
        plaintext.data(), plaintext.size(),
        nullptr, 0,
        nullptr, nonce, quic_key);
    ct.resize(static_cast<size_t>(ct_len));

    // Length field: nonce(24) + pkt_number(4) + ct_len_field(4) + ciphertext
    uint16_t total_payload = static_cast<uint16_t>(sizeof(nonce) + 4 + 4 + ct.size());
    result.push_back(0x40 | ((total_payload >> 8) & 0x3F));
    result.push_back(total_payload & 0xFF);

    // Packet number (4 bytes)
    result.push_back((quic_packet_number_ >> 24) & 0xFF);
    result.push_back((quic_packet_number_ >> 16) & 0xFF);
    result.push_back((quic_packet_number_ >> 8) & 0xFF);
    result.push_back(quic_packet_number_ & 0xFF);
    quic_packet_number_++;

    // Nonce (24 bytes)
    result.insert(result.end(), nonce, nonce + sizeof(nonce));

    // Ciphertext length (4 bytes) — enables O(1) extraction on receiver
    uint32_t ct_size = static_cast<uint32_t>(ct.size());
    result.push_back((ct_size >> 24) & 0xFF);
    result.push_back((ct_size >> 16) & 0xFF);
    result.push_back((ct_size >> 8) & 0xFF);
    result.push_back(ct_size & 0xFF);

    // Encrypted payload
    result.insert(result.end(), ct.begin(), ct.end());

    // Pad to minimum 1200 bytes — RFC 9000
    while (result.size() < 1200) {
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
    crypto_generichash(quic_key, sizeof(quic_key),
                       dcid, dcid_len,
                       quic_info, sizeof(quic_info) - 1);

    if (pos >= data.size()) { sodium_memzero(quic_key, sizeof(quic_key)); return {}; }
    uint8_t scid_len = data[pos++]; pos += scid_len;
    if (pos >= data.size()) { sodium_memzero(quic_key, sizeof(quic_key)); return {}; }
    uint8_t token_len = data[pos++]; pos += token_len;

    // Length field
    if (pos >= data.size()) { sodium_memzero(quic_key, sizeof(quic_key)); return {}; }
    if (data[pos] & 0x40) { pos += 2; } else { pos += 1; }

    // Packet number (4 bytes)
    pos += 4;

    // Nonce (24 bytes)
    if (pos + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES > data.size()) {
        sodium_memzero(quic_key, sizeof(quic_key)); return {};
    }
    const uint8_t* nonce = &data[pos];
    pos += crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    // Ciphertext length (4 bytes) — O(1) extraction
    if (pos + 4 > data.size()) { sodium_memzero(quic_key, sizeof(quic_key)); return {}; }
    uint32_t ct_size = (static_cast<uint32_t>(data[pos]) << 24) |
                       (static_cast<uint32_t>(data[pos + 1]) << 16) |
                       (static_cast<uint32_t>(data[pos + 2]) << 8) |
                        static_cast<uint32_t>(data[pos + 3]);
    pos += 4;

    if (pos + ct_size > data.size() || ct_size < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        sodium_memzero(quic_key, sizeof(quic_key)); return {};
    }

    // Decrypt
    std::vector<uint8_t> plaintext(ct_size);
    unsigned long long pt_len = 0;
    int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &pt_len,
            nullptr,
            &data[pos], ct_size,
            nullptr, 0,
            nonce, quic_key);

    sodium_memzero(quic_key, sizeof(quic_key));
    if (ret != 0 || pt_len < 4) return {};

    plaintext.resize(static_cast<size_t>(pt_len));

    uint32_t payload_len = (static_cast<uint32_t>(plaintext[0]) << 24) |
                           (static_cast<uint32_t>(plaintext[1]) << 16) |
                           (static_cast<uint32_t>(plaintext[2]) << 8) |
                            static_cast<uint32_t>(plaintext[3]);
    if (4 + payload_len > plaintext.size()) return {};
    return std::vector<uint8_t>(plaintext.begin() + 4, plaintext.begin() + 4 + payload_len);
}

// ==================== BitTorrent ====================
std::vector<uint8_t> TrafficMimicry::create_bittorrent_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;

    result.push_back(19);
    const char* pstr = "BitTorrent protocol";
    result.insert(result.end(), pstr, pstr + 19);

    // Reserved bytes (encode payload size for extraction)
    uint32_t pl = static_cast<uint32_t>(payload.size());
    result.push_back((pl >> 24) & 0xFF);
    result.push_back((pl >> 16) & 0xFF);
    result.push_back((pl >> 8) & 0xFF);
    result.push_back(pl & 0xFF);
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x10);

    // Info hash (20 bytes) — random (no payload leak)
    for (int i = 0; i < 20; ++i) result.push_back(ncp::csprng_byte());

    // Peer ID (20 bytes) — realistic qBittorrent prefix
    const char* peer_prefix = "-qB4630-";
    result.insert(result.end(), peer_prefix, peer_prefix + 8);
    for (int i = 0; i < 12; ++i) result.push_back(ncp::csprng_byte());

    // Full payload as piece message (msg_id=7)
    uint32_t msg_len = static_cast<uint32_t>(payload.size() + 9);
    result.push_back((msg_len >> 24) & 0xFF);
    result.push_back((msg_len >> 16) & 0xFF);
    result.push_back((msg_len >> 8) & 0xFF);
    result.push_back(msg_len & 0xFF);
    result.push_back(0x07); // piece
    for (int i = 0; i < 4; ++i) result.push_back(ncp::csprng_byte()); // random piece index
    for (int i = 0; i < 4; ++i) result.push_back(0x00); // begin=0
    result.insert(result.end(), payload.begin(), payload.end());

    return result;
}

// ==================== Skype ====================
std::vector<uint8_t> TrafficMimicry::create_skype_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(ncp::csprng_byte()); result.push_back(ncp::csprng_byte());
    // Type/Flags
    result.push_back(0x02); result.push_back(0x00);
    // Sequence number
    result.push_back((skype_seq_ >> 8) & 0xFF);
    result.push_back(skype_seq_ & 0xFF);
    skype_seq_++;
    // Payload length
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF); result.push_back(len & 0xFF);
    result.insert(result.end(), payload.begin(), payload.end());
    while (result.size() < 160) result.push_back(ncp::csprng_byte());
    return result;
}

// ==================== Zoom ====================
std::vector<uint8_t> TrafficMimicry::create_zoom_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0x90);
    result.push_back(0x60);
    // Sequence number
    result.push_back((zoom_seq_ >> 8) & 0xFF);
    result.push_back(zoom_seq_ & 0xFF);
    zoom_seq_++;
    // Timestamp
    uint32_t ts = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count());
    result.push_back((ts >> 24) & 0xFF); result.push_back((ts >> 16) & 0xFF);
    result.push_back((ts >> 8) & 0xFF);  result.push_back(ts & 0xFF);
    for (int i = 0; i < 4; ++i) result.push_back(ncp::csprng_byte());
    result.push_back(0xBE); result.push_back(0xDE);
    uint16_t ext_len = static_cast<uint16_t>((payload.size() + 3) / 4);
    result.push_back((ext_len >> 8) & 0xFF); result.push_back(ext_len & 0xFF);
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF); result.push_back(len & 0xFF);
    result.insert(result.end(), payload.begin(), payload.end());
    while (result.size() % 4 != 0) result.push_back(0x00);
    return result;
}

// ==================== Generic ====================
std::vector<uint8_t> TrafficMimicry::create_generic_tcp_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    uint32_t len = static_cast<uint32_t>(payload.size());
    result.push_back((len >> 24) & 0xFF); result.push_back((len >> 16) & 0xFF);
    result.push_back((len >> 8) & 0xFF);  result.push_back(len & 0xFF);
    result.insert(result.end(), payload.begin(), payload.end());
    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        auto padding = generate_random_padding(config_.min_padding, config_.max_padding);
        result.insert(result.end(), padding.begin(), padding.end());
    }
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_generic_udp_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    uint32_t len = static_cast<uint32_t>(payload.size());
    result.push_back((len >> 24) & 0xFF);
    result.push_back((len >> 16) & 0xFF);
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

// ==================== TLS Session State Machine ====================

TlsSessionPhase TrafficMimicry::get_tls_session_phase() const {
    return tls_session_phase_;
}

bool TrafficMimicry::is_tls_managed() const {
    return config_.profile == MimicProfile::HTTPS_APPLICATION ||
           config_.profile == MimicProfile::HTTPS_CLIENT_HELLO;
}

void TrafficMimicry::reset_tls_session() {
    tls_session_phase_ = TlsSessionPhase::IDLE;
    tls_seq_ = 0;
}

std::vector<uint8_t> TrafficMimicry::create_fake_server_hello() {
    std::vector<uint8_t> result;

    result.push_back(0x16);
    result.push_back(0x03);
    result.push_back(0x03);
    size_t record_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00);

    result.push_back(0x02);
    size_t handshake_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00);

    result.push_back(0x03); result.push_back(0x03);

    for (int i = 0; i < 32; ++i) result.push_back(ncp::csprng_byte());

    result.push_back(32);
    for (int i = 0; i < 32; ++i) result.push_back(ncp::csprng_byte());

    result.push_back(0x13); result.push_back(0x01);
    result.push_back(0x00);

    std::vector<uint8_t> exts;
    exts.push_back(0x00); exts.push_back(0x2B);
    exts.push_back(0x00); exts.push_back(0x02);
    exts.push_back(0x03); exts.push_back(0x04);

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

    return result;
}

std::vector<uint8_t> TrafficMimicry::create_fake_change_cipher_spec() {
    return {
        0x14,
        0x03, 0x03,
        0x00, 0x01,
        0x01
    };
}

std::vector<uint8_t> TrafficMimicry::create_fake_finished() {
    std::vector<uint8_t> result;
    result.push_back(0x16);
    result.push_back(0x03);
    result.push_back(0x03);

    const size_t finished_payload_size = 40;
    result.push_back(static_cast<uint8_t>((finished_payload_size >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(finished_payload_size & 0xFF));

    for (size_t i = 0; i < finished_payload_size; ++i) {
        result.push_back(ncp::csprng_byte());
    }
    return result;
}

std::vector<std::vector<uint8_t>> TrafficMimicry::generate_tls_handshake_sequence() {
    std::vector<std::vector<uint8_t>> sequence;

    std::vector<uint8_t> empty_payload;
    sequence.push_back(create_https_client_hello_wrapper(empty_payload));
    sequence.push_back(create_fake_server_hello());
    sequence.push_back(create_fake_change_cipher_spec());
    sequence.push_back(create_fake_finished());

    return sequence;
}

std::vector<uint8_t> TrafficMimicry::wrap_tls_session_aware(
        const std::vector<uint8_t>& payload,
        std::vector<std::vector<uint8_t>>& handshake_preamble) {

    handshake_preamble.clear();

    if (tls_session_phase_ == TlsSessionPhase::IDLE) {
        handshake_preamble = generate_tls_handshake_sequence();
        tls_session_phase_ = TlsSessionPhase::APPLICATION_DATA;
    }

    return create_https_application_wrapper(payload);
}

} // namespace ncp
