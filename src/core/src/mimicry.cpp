#include "../include/ncp_mimicry.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <array>
#include <iomanip>
#include <ctime>

namespace ncp {

// ==================== Russian whitelist domains & paths ====================
// These domains are on Roskomnadzor/TSPU whitelists and will not be blocked
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

// DNS labels for Russian domains (used in DNS mimicry QNAME)
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

// TLS SNI hostnames for ClientHello
static const std::array<const char*, 8> RU_TLS_SNI_HOSTS = {{
    "yandex.ru", "vk.com", "mail.ru", "ok.ru",
    "gosuslugi.ru", "sberbank.ru", "rutube.ru", "dzen.ru"
}};

// ==================== Constructors / Destructor ====================
TrafficMimicry::TrafficMimicry()
    : tls_sequence_number_(0), dns_transaction_id_(0), quic_packet_number_(0),
      tls_session_phase_(TlsSessionPhase::IDLE) {
    ncp::csprng_init();
}

TrafficMimicry::TrafficMimicry(const MimicConfig& config)
    : config_(config),
      tls_sequence_number_(0), dns_transaction_id_(0), quic_packet_number_(0),
      tls_session_phase_(TlsSessionPhase::IDLE) {
    ncp::csprng_init();
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

TrafficMimicry::~TrafficMimicry() = default;

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
    if (stats_.bytes_original > 0) {
        stats_.average_overhead_percent =
            (static_cast<double>(stats_.bytes_mimicked) / stats_.bytes_original - 1.0) * 100.0;
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
            // Generic extraction: skip length header
            if (mimicked_data.size() > 4) {
                result.assign(mimicked_data.begin() + 4, mimicked_data.end());
            }
            break;
    }
    stats_.packets_unwrapped++;
    return result;
}

// Auto-detect profile then unwrap (from ncp_mimicry.cpp)
std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data) {
    MimicProfile detected = detect_profile(mimicked_data);
    return unwrap_payload(mimicked_data, detected);
}

// ==================== Configuration ====================
void TrafficMimicry::set_config(const MimicConfig& config) { config_ = config; }
TrafficMimicry::MimicConfig TrafficMimicry::get_config() const { return config_; }

// ==================== Statistics ====================
TrafficMimicry::MimicStats TrafficMimicry::get_stats() const { return stats_; }
void TrafficMimicry::reset_stats() { stats_ = {}; }

// ==================== Profile detection (robust, from ncp_mimicry.cpp) ====================
TrafficMimicry::MimicProfile TrafficMimicry::detect_profile(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return MimicProfile::GENERIC_UDP;

    // Check for TLS record first (highest priority)
    if (data[0] == 0x16 || data[0] == 0x17) {
        if (data.size() >= 5 && data[1] == 0x03) {
            return (data[0] == 0x16) ? MimicProfile::HTTPS_CLIENT_HELLO
                                     : MimicProfile::HTTPS_APPLICATION;
        }
    }

    // Check for HTTP
    if (data.size() >= 4) {
        if (data[0]=='G' && data[1]=='E' && data[2]=='T' && data[3]==' ')
            return MimicProfile::HTTP_GET;
    }
    if (data.size() >= 5) {
        if (data[0]=='P' && data[1]=='O' && data[2]=='S' && data[3]=='T' && data[4]==' ')
            return MimicProfile::HTTP_POST;
    }

    // Check for BitTorrent handshake
    if (data.size() >= 20 && data[0] == 19) {
        return MimicProfile::BITTORRENT;
    }

    // Check for QUIC long header
    if (data.size() >= 5 && (data[0] & 0x80)) {
        return MimicProfile::QUIC_INITIAL;
    }

    // Check for DNS
    if (data.size() >= 12) {
        uint16_t flags = (data[2] << 8) | data[3];
        uint16_t qr = (flags >> 15) & 0x01;
        if (qr == 0) return MimicProfile::DNS_QUERY;
        if (qr == 1) return MimicProfile::DNS_RESPONSE;
    }

    // Check for WebSocket frame
    if (data.size() >= 2) {
        uint8_t opcode = data[0] & 0x0F;
        if (opcode >= 0x01 && opcode <= 0x0A) {
            return MimicProfile::WEBSOCKET;
        }
    }

    return MimicProfile::GENERIC_TCP;
}

// ==================== Timing (jitter model from ncp_mimicry.cpp + RU ranges) ====================
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

    // Larger packets take slightly longer
    base_delay += static_cast<int>(packet_size / 1000);

    int final_delay = std::max(config_.min_inter_packet_delay,
                               std::min(config_.max_inter_packet_delay,
                                        base_delay + ncp::csprng_range(-jitter, jitter)));
    return std::chrono::milliseconds(final_delay);
}

// ==================== Utility helpers (RU whitelists) ====================
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

// ==================== HTTP wrappers (RU whitelists + base64 encoding) ====================

// Base64 encoding helper
static std::string base64_encode(const std::vector<uint8_t>& data) {
    static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    size_t i = 0;
    while (i < data.size()) {
        uint32_t a = i < data.size() ? data[i++] : 0;
        uint32_t b = i < data.size() ? data[i++] : 0;
        uint32_t c = i < data.size() ? data[i++] : 0;
        uint32_t triple = (a << 16) + (b << 8) + c;
        encoded += chars[(triple >> 18) & 0x3F];
        encoded += chars[(triple >> 12) & 0x3F];
        encoded += (i > data.size() + 1) ? '=' : chars[(triple >> 6) & 0x3F];
        encoded += (i > data.size()) ? '=' : chars[triple & 0x3F];
    }
    return encoded;
}

static std::vector<uint8_t> base64_decode(const std::string& encoded) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> decoded;
    uint32_t buf = 0;
    int bits = 0;
    for (char c : encoded) {
        if (c == '=') break;
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

std::vector<uint8_t> TrafficMimicry::create_http_get_wrapper(const std::vector<uint8_t>& payload) {
    std::string host = generate_random_hostname();
    std::string path = generate_random_http_path();
    std::string encoded = base64_encode(payload);

    std::ostringstream oss;
    oss << "GET " << path << "?d=" << encoded << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    oss << "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n";
    oss << "Accept-Encoding: gzip, deflate, br\r\n";
    oss << "Connection: keep-alive\r\n";
    for (const auto& h : config_.http_headers) oss << h << "\r\n";
    oss << "\r\n";

    std::string headers = oss.str();
    return std::vector<uint8_t>(headers.begin(), headers.end());
}

std::vector<uint8_t> TrafficMimicry::create_http_post_wrapper(const std::vector<uint8_t>& payload) {
    std::string host = generate_random_hostname();
    std::ostringstream oss;
    oss << "POST /api/v2/data HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Accept: application/json\r\n";
    oss << "Accept-Language: ru-RU,ru;q=0.9\r\n";
    oss << "Content-Type: application/json; charset=utf-8\r\n";
    oss << "Content-Length: " << payload.size() << "\r\n";
    oss << "Connection: keep-alive\r\n";
    oss << "Origin: https://" << host << "\r\n";
    oss << "Referer: https://" << host << "/\r\n";
    for (const auto& h : config_.http_headers) oss << h << "\r\n";
    oss << "\r\n";
    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_http_payload(const std::vector<uint8_t>& data) {
    std::string s(data.begin(), data.end());

    // Try body first (POST)
    size_t body_pos = s.find("\r\n\r\n");

    // Try base64 URL parameter (GET)
    size_t param_pos = s.find("?d=");
    if (param_pos != std::string::npos) {
        size_t start = param_pos + 3;
        size_t end = s.find_first_of(" &\r\n", start);
        std::string encoded = s.substr(start, end - start);
        return base64_decode(encoded);
    }

    // Fallback: body after headers
    if (body_pos != std::string::npos) {
        return std::vector<uint8_t>(data.begin() + body_pos + 4, data.end());
    }

    return data;
}

// ==================== TLS wrappers (RU SNI + split payload from ncp_mimicry) ====================
std::vector<uint8_t> TrafficMimicry::create_https_client_hello_wrapper(const std::vector<uint8_t>& payload) {
    // Pick SNI from RU whitelist
    std::string sni = config_.tls_sni;
    if (sni.empty()) {
        int idx = ncp::csprng_range(0, static_cast<int>(RU_TLS_SNI_HOSTS.size()) - 1);
        sni = RU_TLS_SNI_HOSTS[idx];
    }

    std::vector<uint8_t> result;

    // TLS Record Header
    result.push_back(0x16);  // Handshake
    result.push_back(0x03);  // TLS 1.0 for record layer
    result.push_back(0x01);
    size_t record_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); // placeholder

    // Handshake Header: ClientHello
    result.push_back(0x01);
    size_t handshake_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00); // placeholder

    // Client Version (TLS 1.2)
    result.push_back(0x03); result.push_back(0x03);

    // Random (32 bytes) — embed payload length in first 4 bytes
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    result.push_back((payload_len >> 24) & 0xFF);
    result.push_back((payload_len >> 16) & 0xFF);
    result.push_back((payload_len >> 8) & 0xFF);
    result.push_back(payload_len & 0xFF);
    for (int i = 0; i < 28; ++i) result.push_back(ncp::csprng_byte());

    // Session ID — embed first 32 bytes of payload
    size_t session_id_len = std::min(payload.size(), size_t(32));
    result.push_back(static_cast<uint8_t>(session_id_len));
    result.insert(result.end(), payload.begin(), payload.begin() + session_id_len);

    // Cipher suites (realistic set)
    std::vector<uint16_t> suites = config_.tls_cipher_suites;
    if (suites.empty()) {
        suites = {0x1301,0x1302,0x1303,0xC02C,0xC02B,0xC030,0xC02F,0x009E,0x009C,0x00FF};
    }
    uint16_t suites_len = static_cast<uint16_t>(suites.size() * 2);
    result.push_back(static_cast<uint8_t>(suites_len >> 8));
    result.push_back(static_cast<uint8_t>(suites_len & 0xFF));
    for (auto cs : suites) {
        result.push_back(static_cast<uint8_t>(cs >> 8));
        result.push_back(static_cast<uint8_t>(cs & 0xFF));
    }

    // Compression: null
    result.push_back(0x01); result.push_back(0x00);

    // --- Extensions ---
    std::vector<uint8_t> exts;

    // SNI extension (type 0x0000) with RU domain
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

    // Supported versions extension (TLS 1.3 + 1.2)
    exts.push_back(0x00); exts.push_back(0x2B);
    exts.push_back(0x00); exts.push_back(0x05);
    exts.push_back(0x04);
    exts.push_back(0x03); exts.push_back(0x04); // TLS 1.3
    exts.push_back(0x03); exts.push_back(0x03); // TLS 1.2

    // Private extension 0xFF01 — remaining payload
    size_t remaining_start = session_id_len;
    size_t remaining_size = payload.size() > remaining_start ? payload.size() - remaining_start : 0;
    if (remaining_size > 0) {
        exts.push_back(0xFF); exts.push_back(0x01);
        exts.push_back(static_cast<uint8_t>((remaining_size >> 8) & 0xFF));
        exts.push_back(static_cast<uint8_t>(remaining_size & 0xFF));
        exts.insert(exts.end(), payload.begin() + remaining_start, payload.end());
    }

    // Write extensions length
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

    tls_sequence_number_++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_https_application_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0x17); // Application Data
    result.push_back(0x03); result.push_back(0x03); // TLS 1.2

    // Padded length = 4-byte length prefix + payload + optional padding
    size_t padded_len = payload.size() + 4;
    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        padded_len += static_cast<size_t>(ncp::csprng_range(
            config_.min_padding, config_.max_padding));
    }

    result.push_back(static_cast<uint8_t>((padded_len >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(padded_len & 0xFF));

    // Embed payload length for extraction
    uint32_t pl = static_cast<uint32_t>(payload.size());
    result.push_back((pl >> 24) & 0xFF);
    result.push_back((pl >> 16) & 0xFF);
    result.push_back((pl >> 8) & 0xFF);
    result.push_back(pl & 0xFF);

    result.insert(result.end(), payload.begin(), payload.end());

    // Padding
    while (result.size() < 5 + padded_len) {
        result.push_back(ncp::csprng_byte());
    }

    tls_sequence_number_++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_tls_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 9) return {};
    if (data[0] != 0x16 && data[0] != 0x17) return {};

    if (data[0] == 0x17) {
        // Application Data — extract from 4-byte length prefix
        uint32_t payload_len = (static_cast<uint32_t>(data[5]) << 24) |
                               (static_cast<uint32_t>(data[6]) << 16) |
                               (static_cast<uint32_t>(data[7]) << 8) |
                                static_cast<uint32_t>(data[8]);
        if (data.size() >= 9 + payload_len) {
            return std::vector<uint8_t>(data.begin() + 9, data.begin() + 9 + payload_len);
        }
    } else {
        // ClientHello — extract from Random length + session_id + 0xFF01 extension
        if (data.size() < 44) return {};

        uint32_t payload_len = (static_cast<uint32_t>(data[11]) << 24) |
                               (static_cast<uint32_t>(data[12]) << 16) |
                               (static_cast<uint32_t>(data[13]) << 8) |
                                static_cast<uint32_t>(data[14]);
        (void)payload_len; // Used for validation

        uint8_t session_id_len = data[43];
        std::vector<uint8_t> result;

        if (data.size() > 44u + session_id_len) {
            result.insert(result.end(), data.begin() + 44, data.begin() + 44 + session_id_len);
        }

        // Skip cipher suites + compression to reach extensions
        size_t pos = 44 + session_id_len;
        if (pos + 2 <= data.size()) {
            uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
            pos += 2 + cipher_len;
        }
        if (pos + 1 <= data.size()) {
            pos += 1 + data[pos]; // compression methods
        }

        // Parse extensions, find 0xFF01
        if (pos + 2 <= data.size()) {
            uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            size_t ext_end = pos + ext_len;

            while (pos + 4 <= ext_end && pos + 4 <= data.size()) {
                uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
                uint16_t ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;
                if (ext_type == 0xFF01 && pos + ext_data_len <= data.size()) {
                    result.insert(result.end(), data.begin() + pos, data.begin() + pos + ext_data_len);
                }
                pos += ext_data_len;
            }
        }
        return result;
    }
    return {};
}

// ==================== WebSocket (RFC 6455) ====================
std::vector<uint8_t> TrafficMimicry::create_websocket_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    frame.push_back(0x82); // FIN + binary opcode
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

// ==================== DNS (RU domains + hex subdomain labels + EDNS0) ====================
std::vector<uint8_t> TrafficMimicry::create_dns_query_wrapper(const std::vector<uint8_t>& payload) {
    dns_transaction_id_ = static_cast<uint16_t>(ncp::csprng_range(0, 0xFFFF));
    uint16_t txn_id = dns_transaction_id_;

    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x01, 0x00, // Flags: RD
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01  // ARCOUNT = 1 (for EDNS0 OPT)
    };

    // QNAME: payload length label + hex-encoded payload labels + RU domain suffix
    char len_label[8];
    snprintf(len_label, sizeof(len_label), "%04x", static_cast<unsigned>(payload.size()));
    result.push_back(4);
    result.insert(result.end(), len_label, len_label + 4);

    size_t pos = 0;
    while (pos < payload.size()) {
        size_t chunk = std::min(size_t(31), payload.size() - pos); // 31 bytes = 62 hex chars < 63 max label
        result.push_back(static_cast<uint8_t>(chunk * 2));
        for (size_t i = 0; i < chunk; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", payload[pos + i]);
            result.push_back(static_cast<uint8_t>(hex[0]));
            result.push_back(static_cast<uint8_t>(hex[1]));
        }
        pos += chunk;
    }

    // RU domain suffix
    int idx = ncp::csprng_range(0, static_cast<int>(RU_DNS_LABELS.size()) - 1);
    const auto& lbl = RU_DNS_LABELS[idx];
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00); // root

    // QTYPE=TXT, QCLASS=IN
    result.push_back(0x00); result.push_back(0x10);
    result.push_back(0x00); result.push_back(0x01);

    // EDNS0 OPT record (Additional section)
    result.push_back(0x00);                     // root name
    result.push_back(0x00); result.push_back(0x29); // TYPE: OPT
    result.push_back(0x10); result.push_back(0x00); // UDP size: 4096
    result.push_back(0x00);                     // extended RCODE
    result.push_back(0x00);                     // EDNS version
    result.push_back(0x80); result.push_back(0x00); // Flags (DO bit)
    result.push_back(0x00); result.push_back(0x00); // RDATA length

    return result;
}

std::vector<uint8_t> TrafficMimicry::create_dns_response_wrapper(const std::vector<uint8_t>& payload) {
    uint16_t txn_id = dns_transaction_id_;
    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x81, 0x80, // QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00  // ARCOUNT
    };

    // Question section — RU domain
    int idx = ncp::csprng_range(0, static_cast<int>(RU_DNS_LABELS.size()) - 1);
    const auto& lbl = RU_DNS_LABELS[idx];
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x10); // TXT
    result.push_back(0x00); result.push_back(0x01); // IN

    // Answer: TXT record with payload
    result.push_back(0xC0); result.push_back(0x0C); // name pointer
    result.push_back(0x00); result.push_back(0x10); // TXT
    result.push_back(0x00); result.push_back(0x01); // IN
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x01); result.push_back(0x2C); // TTL=300
    uint16_t rdlen = static_cast<uint16_t>(payload.size() + 1);
    result.push_back(static_cast<uint8_t>(rdlen >> 8));
    result.push_back(static_cast<uint8_t>(rdlen & 0xFF));
    result.push_back(static_cast<uint8_t>(payload.size()));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_dns_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 12) return {};

    uint16_t flags = (data[2] << 8) | data[3];
    bool is_response = (flags >> 15) & 0x01;

    if (is_response) {
        // Parse response: skip question, find TXT answer
        size_t pos = 12;
        uint16_t qdcount = (data[4] << 8) | data[5];
        for (uint16_t q = 0; q < qdcount && pos < data.size(); ++q) {
            while (pos < data.size() && data[pos] != 0) {
                if ((data[pos] & 0xC0) == 0xC0) { pos += 2; goto skip_qname_done; }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            skip_qname_done:
            pos += 4; // QTYPE + QCLASS
        }

        uint16_t ancount = (data[6] << 8) | data[7];
        for (uint16_t a = 0; a < ancount && pos < data.size(); ++a) {
            // Skip name
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
                uint8_t txt_len = data[pos];
                if (pos + 1 + txt_len <= data.size()) {
                    return std::vector<uint8_t>(data.begin() + pos + 1, data.begin() + pos + 1 + txt_len);
                }
            }
            pos += rdlength;
        }
    } else {
        // Parse query: extract hex-encoded payload from QNAME labels
        std::vector<uint8_t> result;
        size_t pos = 12;

        // First label = length (4 hex chars)
        if (pos >= data.size() || data[pos] != 4) return {};
        pos++;
        if (pos + 4 > data.size()) return {};
        char len_hex[5] = {0};
        std::memcpy(len_hex, &data[pos], 4);
        unsigned int payload_len = 0;
        sscanf(len_hex, "%x", &payload_len);
        pos += 4;

        // Read hex-encoded data labels
        while (pos < data.size() && data[pos] != 0 && result.size() < payload_len) {
            uint8_t label_len = data[pos++];
            if (label_len > 62 || pos + label_len > data.size()) break;
            for (uint8_t i = 0; i + 1 < label_len && result.size() < payload_len; i += 2) {
                char hex[3] = {static_cast<char>(data[pos + i]), static_cast<char>(data[pos + i + 1]), 0};
                unsigned int byte_val;
                if (sscanf(hex, "%x", &byte_val) == 1) {
                    result.push_back(static_cast<uint8_t>(byte_val));
                }
            }
            pos += label_len;
        }
        return result;
    }
    return {};
}

// ==================== QUIC (full v1 structure + 1200-byte padding) ====================
std::vector<uint8_t> TrafficMimicry::create_quic_initial_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;

    // Long Header: Form=1, Fixed=1, Type=Initial
    result.push_back(0xC0 | (ncp::csprng_byte() & 0x03));

    // Version (QUIC v1)
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x01);

    // Destination CID (8 bytes)
    result.push_back(8);
    for (int i = 0; i < 8; ++i) result.push_back(ncp::csprng_byte());

    // Source CID (8 bytes)
    result.push_back(8);
    for (int i = 0; i < 8; ++i) result.push_back(ncp::csprng_byte());

    // Token Length = 0
    result.push_back(0x00);

    // Payload length (VLI 2-byte) = payload + 4 (length prefix) + 20 (AEAD sim)
    uint16_t total_payload = static_cast<uint16_t>(payload.size() + 24);
    result.push_back(0x40 | ((total_payload >> 8) & 0x3F));
    result.push_back(total_payload & 0xFF);

    // Packet Number (4 bytes)
    result.push_back((quic_packet_number_ >> 24) & 0xFF);
    result.push_back((quic_packet_number_ >> 16) & 0xFF);
    result.push_back((quic_packet_number_ >> 8) & 0xFF);
    result.push_back(quic_packet_number_ & 0xFF);
    quic_packet_number_++;

    // Payload length prefix (for extraction)
    uint32_t pl = static_cast<uint32_t>(payload.size());
    result.push_back((pl >> 24) & 0xFF);
    result.push_back((pl >> 16) & 0xFF);
    result.push_back((pl >> 8) & 0xFF);
    result.push_back(pl & 0xFF);

    result.insert(result.end(), payload.begin(), payload.end());

    // Pad to minimum 1200 bytes (QUIC requirement)
    while (result.size() < 1200) {
        result.push_back(ncp::csprng_byte());
    }
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_quic_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 30) return {};
    if (!(data[0] & 0x80)) return {};

    size_t pos = 5; // header + version
    if (pos >= data.size()) return {};
    uint8_t dcid_len = data[pos++]; pos += dcid_len;
    if (pos >= data.size()) return {};
    uint8_t scid_len = data[pos++]; pos += scid_len;
    if (pos >= data.size()) return {};
    uint8_t token_len = data[pos++]; pos += token_len;

    // Skip VLI length field
    if (pos >= data.size()) return {};
    if (data[pos] & 0x40) { pos += 2; } else { pos += 1; }

    // Skip packet number (4 bytes)
    pos += 4;

    // Extract payload from 4-byte length prefix
    if (pos + 4 > data.size()) return {};
    uint32_t payload_len = (static_cast<uint32_t>(data[pos]) << 24) |
                           (static_cast<uint32_t>(data[pos+1]) << 16) |
                           (static_cast<uint32_t>(data[pos+2]) << 8) |
                            static_cast<uint32_t>(data[pos+3]);
    pos += 4;
    if (pos + payload_len > data.size()) return {};
    return std::vector<uint8_t>(data.begin() + pos, data.begin() + pos + payload_len);
}

// ==================== BitTorrent (full handshake + piece messages) ====================
std::vector<uint8_t> TrafficMimicry::create_bittorrent_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;

    // pstrlen + "BitTorrent protocol"
    result.push_back(19);
    const char* pstr = "BitTorrent protocol";
    result.insert(result.end(), pstr, pstr + 19);

    // Reserved (8 bytes) — embed payload length in first 4
    uint32_t pl = static_cast<uint32_t>(payload.size());
    result.push_back((pl >> 24) & 0xFF);
    result.push_back((pl >> 16) & 0xFF);
    result.push_back((pl >> 8) & 0xFF);
    result.push_back(pl & 0xFF);
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x10); // Extension protocol

    // Info hash (20 bytes) — embed first 20 bytes of payload
    size_t hash_len = std::min(payload.size(), size_t(20));
    result.insert(result.end(), payload.begin(), payload.begin() + hash_len);
    // Pad to 20 if needed
    for (size_t i = hash_len; i < 20; ++i) result.push_back(ncp::csprng_byte());

    // Peer ID (20 bytes) — random
    for (int i = 0; i < 20; ++i) result.push_back(ncp::csprng_byte());

    // Remaining payload as piece message (msg_id=7)
    if (payload.size() > 20) {
        uint32_t msg_len = static_cast<uint32_t>(payload.size() - 20 + 9);
        result.push_back((msg_len >> 24) & 0xFF);
        result.push_back((msg_len >> 16) & 0xFF);
        result.push_back((msg_len >> 8) & 0xFF);
        result.push_back(msg_len & 0xFF);
        result.push_back(0x07); // piece
        // index (4) + begin (4)
        for (int i = 0; i < 8; ++i) result.push_back(0x00);
        result.insert(result.end(), payload.begin() + 20, payload.end());
    }
    return result;
}

// ==================== Skype (structured packets) ====================
std::vector<uint8_t> TrafficMimicry::create_skype_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    // Object ID (2 bytes)
    result.push_back(ncp::csprng_byte()); result.push_back(ncp::csprng_byte());
    // Type/Flags
    result.push_back(0x02); result.push_back(0x00); // Data packet
    // Sequence number
    result.push_back((tls_sequence_number_ >> 8) & 0xFF);
    result.push_back(tls_sequence_number_ & 0xFF);
    tls_sequence_number_++;
    // Payload length
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF); result.push_back(len & 0xFF);
    // Payload
    result.insert(result.end(), payload.begin(), payload.end());
    // Pad to typical VoIP packet size (160 bytes)
    while (result.size() < 160) result.push_back(ncp::csprng_byte());
    return result;
}

// ==================== Zoom (RTP/SRTP structure) ====================
std::vector<uint8_t> TrafficMimicry::create_zoom_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    // V=2, P=0, X=1, CC=0
    result.push_back(0x90);
    // Marker + PT=96 (dynamic)
    result.push_back(0x60);
    // Sequence number
    result.push_back((tls_sequence_number_ >> 8) & 0xFF);
    result.push_back(tls_sequence_number_ & 0xFF);
    tls_sequence_number_++;
    // Timestamp
    uint32_t ts = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count());
    result.push_back((ts >> 24) & 0xFF); result.push_back((ts >> 16) & 0xFF);
    result.push_back((ts >> 8) & 0xFF);  result.push_back(ts & 0xFF);
    // SSRC (random)
    for (int i = 0; i < 4; ++i) result.push_back(ncp::csprng_byte());
    // Extension header (BEDE)
    result.push_back(0xBE); result.push_back(0xDE);
    uint16_t ext_len = static_cast<uint16_t>((payload.size() + 3) / 4); // 32-bit words
    result.push_back((ext_len >> 8) & 0xFF); result.push_back(ext_len & 0xFF);
    // Payload length (2 bytes)
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF); result.push_back(len & 0xFF);
    // Payload + 4-byte alignment
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
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF); result.push_back(len & 0xFF);
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

// ==================== TLS Session State Machine (Issue #57) ====================

TlsSessionPhase TrafficMimicry::get_tls_session_phase() const {
    return tls_session_phase_;
}

bool TrafficMimicry::is_tls_managed() const {
    // Mimicry manages TLS framing when using any HTTPS profile
    return config_.profile == MimicProfile::HTTPS_APPLICATION ||
           config_.profile == MimicProfile::HTTPS_CLIENT_HELLO;
}

void TrafficMimicry::reset_tls_session() {
    tls_session_phase_ = TlsSessionPhase::IDLE;
    tls_sequence_number_ = 0;
}

std::vector<uint8_t> TrafficMimicry::create_fake_server_hello() {
    // Build a minimal but structurally valid ServerHello (TLS 1.2)
    std::vector<uint8_t> result;

    // TLS Record Header
    result.push_back(0x16);  // Handshake
    result.push_back(0x03);
    result.push_back(0x03);  // TLS 1.2
    size_t record_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); // placeholder

    // Handshake Header: ServerHello (0x02)
    result.push_back(0x02);
    size_t handshake_length_pos = result.size();
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00);

    // Server Version (TLS 1.2)
    result.push_back(0x03); result.push_back(0x03);

    // Server Random (32 bytes)
    for (int i = 0; i < 32; ++i) result.push_back(ncp::csprng_byte());

    // Session ID (echo back a 32-byte random session ID)
    result.push_back(32);
    for (int i = 0; i < 32; ++i) result.push_back(ncp::csprng_byte());

    // Selected cipher suite: TLS_AES_128_GCM_SHA256 (0x1301)
    result.push_back(0x13); result.push_back(0x01);

    // Compression method: null
    result.push_back(0x00);

    // Extensions (minimal — supported_versions for TLS 1.3)
    std::vector<uint8_t> exts;
    // supported_versions (type 0x002B) — selected version TLS 1.3
    exts.push_back(0x00); exts.push_back(0x2B);
    exts.push_back(0x00); exts.push_back(0x02);
    exts.push_back(0x03); exts.push_back(0x04); // TLS 1.3

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

    return result;
}

std::vector<uint8_t> TrafficMimicry::create_fake_change_cipher_spec() {
    // ChangeCipherSpec record: exactly 1 byte payload (0x01)
    return {
        0x14,        // ChangeCipherSpec
        0x03, 0x03,  // TLS 1.2
        0x00, 0x01,  // Length = 1
        0x01         // Payload
    };
}

std::vector<uint8_t> TrafficMimicry::create_fake_finished() {
    // Encrypted Handshake (Finished) — looks like a Handshake record
    // encrypted under the handshake traffic key. We simulate it
    // as an opaque blob of plausible size (40 bytes).
    std::vector<uint8_t> result;
    result.push_back(0x16);  // Handshake (in TLS 1.2 wire format)
    result.push_back(0x03);
    result.push_back(0x03);  // TLS 1.2

    const size_t finished_payload_size = 40;
    result.push_back(static_cast<uint8_t>((finished_payload_size >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(finished_payload_size & 0xFF));

    // Opaque encrypted Finished data
    for (size_t i = 0; i < finished_payload_size; ++i) {
        result.push_back(ncp::csprng_byte());
    }
    return result;
}

std::vector<std::vector<uint8_t>> TrafficMimicry::generate_tls_handshake_sequence() {
    std::vector<std::vector<uint8_t>> sequence;

    // 1. ClientHello — use empty payload (no data to embed yet)
    std::vector<uint8_t> empty_payload;
    sequence.push_back(create_https_client_hello_wrapper(empty_payload));

    // 2. ServerHello
    sequence.push_back(create_fake_server_hello());

    // 3. ChangeCipherSpec (client -> server direction in TLS 1.2)
    sequence.push_back(create_fake_change_cipher_spec());

    // 4. Finished
    sequence.push_back(create_fake_finished());

    return sequence;
}

std::vector<uint8_t> TrafficMimicry::wrap_tls_session_aware(
        const std::vector<uint8_t>& payload,
        std::vector<std::vector<uint8_t>>& handshake_preamble) {

    handshake_preamble.clear();

    if (tls_session_phase_ == TlsSessionPhase::IDLE) {
        // First packet on this session — must emit handshake first
        handshake_preamble = generate_tls_handshake_sequence();
        tls_session_phase_ = TlsSessionPhase::APPLICATION_DATA;
    }

    // Now safe to emit Application Data (0x17)
    return create_https_application_wrapper(payload);
}

} // namespace ncp
