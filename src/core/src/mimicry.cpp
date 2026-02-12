#include "../include/ncp_mimicry.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>
#include <array>

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
    : rng_(std::random_device{}()),
      tls_sequence_number_(0), dns_transaction_id_(0), quic_packet_number_(0) {}

TrafficMimicry::TrafficMimicry(const MimicConfig& config)
    : config_(config), rng_(std::random_device{}()),
      tls_sequence_number_(0), dns_transaction_id_(0), quic_packet_number_(0) {}

TrafficMimicry::~TrafficMimicry() {}

// ==================== wrap / unwrap with stats ====================
std::vector<uint8_t> TrafficMimicry::wrap_payload(
        const std::vector<uint8_t>& payload, MimicProfile profile) {
    std::vector<uint8_t> result;
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
        case MimicProfile::GENERIC_UDP:         result = create_generic_udp_wrapper(payload); break;
        default:                                return payload;
    }
    // Update statistics
    stats_.packets_wrapped++;
    stats_.bytes_original += payload.size();
    stats_.bytes_mimicked += result.size();
    if (stats_.bytes_original > 0) {
        stats_.average_overhead_percent =
            (static_cast<double>(stats_.bytes_mimicked) / stats_.bytes_original - 1.0) * 100.0;
    }
    last_packet_time_ = std::chrono::steady_clock::now();
    
    // Apply size mimicry padding before return
    auto padding = generate_random_padding(0, 64);
    if (!padding.empty()) {
        result.insert(result.end(), padding.begin(), padding.end());
    }
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
        default:                                return mimicked_data;
    }
    stats_.packets_unwrapped++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data) {
    return unwrap_payload(mimicked_data, config_.profile);
}

// ==================== Configuration ====================
void TrafficMimicry::set_config(const MimicConfig& config) { config_ = config; }
TrafficMimicry::MimicConfig TrafficMimicry::get_config() const { return config_; }

// ==================== Statistics ====================
TrafficMimicry::MimicStats TrafficMimicry::get_stats() const { return stats_; }
void TrafficMimicry::reset_stats() { stats_ = {}; }

// ==================== Profile detection ====================
TrafficMimicry::MimicProfile TrafficMimicry::detect_profile(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return MimicProfile::GENERIC_TCP;
    if (data.size() >= 4 && data[0]=='G' && data[1]=='E' && data[2]=='T' && data[3]==' ')
        return MimicProfile::HTTP_GET;
    if (data.size() >= 5 && data[0]=='P' && data[1]=='O' && data[2]=='S' && data[3]=='T' && data[4]==' ')
        return MimicProfile::HTTP_POST;
    if (data[0] == 0x16 && data[1] == 0x03) return MimicProfile::HTTPS_CLIENT_HELLO;
    if (data[0] == 0x17 && data[1] == 0x03) return MimicProfile::HTTPS_APPLICATION;
    if ((data[0] & 0x80) && ((data[0] & 0x0F) == 0x01 || (data[0] & 0x0F) == 0x02))
        return MimicProfile::WEBSOCKET;
    if (data.size() >= 20 && data[0] == 19) return MimicProfile::BITTORRENT;
    if (data[0] == 0xC0 && data.size() >= 5) return MimicProfile::QUIC_INITIAL;
    if (data.size() >= 12 && (data[2] & 0x80) == 0) return MimicProfile::DNS_QUERY;
    if (data.size() >= 12 && (data[2] & 0x80) != 0) return MimicProfile::DNS_RESPONSE;
    return MimicProfile::GENERIC_TCP;
}

// ==================== Timing ====================
std::chrono::milliseconds TrafficMimicry::get_next_packet_delay() {
    return calculate_realistic_delay(config_.profile, 0);
}

std::chrono::milliseconds TrafficMimicry::calculate_realistic_delay(
        MimicProfile profile, size_t packet_size) {
    int base_min = config_.min_inter_packet_delay;
    int base_max = config_.max_inter_packet_delay;
    // Profile-specific timing ranges to look realistic
    switch (profile) {
        case MimicProfile::HTTPS_APPLICATION: base_min = 5;  base_max = 80;  break;
        case MimicProfile::HTTP_GET:          base_min = 20; base_max = 200; break;
        case MimicProfile::DNS_QUERY:         base_min = 1;  base_max = 30;  break;
        case MimicProfile::WEBSOCKET:         base_min = 10; base_max = 150; break;
        case MimicProfile::QUIC_INITIAL:      base_min = 2;  base_max = 50;  break;
        default: break;
    }
    // Larger packets take slightly longer
    if (packet_size > 1400) base_max += 50;
    std::uniform_int_distribution<int> dist(base_min, base_max);
    return std::chrono::milliseconds(dist(rng_));
}

// ==================== Utility helpers (RU whitelists) ====================
std::string TrafficMimicry::generate_random_http_path() {
    std::uniform_int_distribution<int> dist(0, static_cast<int>(RU_WHITELIST_PATHS.size()) - 1);
    return RU_WHITELIST_PATHS[dist(rng_)];
}

std::string TrafficMimicry::generate_random_user_agent() {
    if (!config_.http_user_agent.empty()) return config_.http_user_agent;
    std::uniform_int_distribution<int> dist(0, static_cast<int>(RU_USER_AGENTS.size()) - 1);
    return RU_USER_AGENTS[dist(rng_)];
}

std::string TrafficMimicry::generate_random_hostname() {
    if (!config_.http_host.empty()) return config_.http_host;
    std::uniform_int_distribution<int> dist(0, static_cast<int>(RU_WHITELIST_HOSTS.size()) - 1);
    return RU_WHITELIST_HOSTS[dist(rng_)];
}

uint16_t TrafficMimicry::generate_random_port() {
    std::uniform_int_distribution<uint16_t> dist(1024, 65535);
    return dist(rng_);
}

std::vector<uint8_t> TrafficMimicry::generate_random_padding(size_t min_size, size_t max_size) {
    if (!config_.enable_size_mimicry) return {};
    std::uniform_int_distribution<size_t> sz_dist(min_size, max_size);
    size_t sz = sz_dist(rng_);
    std::vector<uint8_t> pad(sz);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    for (auto& b : pad) b = static_cast<uint8_t>(byte_dist(rng_));
    return pad;
}

// ==================== HTTP wrappers (RU whitelists) ====================
std::vector<uint8_t> TrafficMimicry::create_http_get_wrapper(const std::vector<uint8_t>& payload) {
    std::string host = generate_random_hostname();
    std::ostringstream oss;
    oss << "GET " << generate_random_http_path() << " HTTP/1.1\r\n";
    oss << "Host: " << host << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    oss << "Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n";
    oss << "Accept-Encoding: gzip, deflate, br\r\n";
    oss << "Connection: keep-alive\r\n";
    oss << "Content-Length: " << payload.size() << "\r\n";
    // Add extra headers for realism
    for (const auto& h : config_.http_headers) oss << h << "\r\n";
    oss << "\r\n";
    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
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
    size_t pos = s.find("\r\n\r\n");
    if (pos != std::string::npos)
        return std::vector<uint8_t>(data.begin() + pos + 4, data.end());
    return data;
}

// ==================== TLS wrappers (with SNI for RU domains) ====================
std::vector<uint8_t> TrafficMimicry::create_https_client_hello_wrapper(const std::vector<uint8_t>& payload) {
    // Pick SNI hostname from config or RU whitelist
    std::string sni = config_.tls_sni;
    if (sni.empty()) {
        std::uniform_int_distribution<int> d(0, static_cast<int>(RU_TLS_SNI_HOSTS.size()) - 1);
        sni = RU_TLS_SNI_HOSTS[d(rng_)];
    }
    // --- Build realistic TLS 1.2 ClientHello ---
    std::vector<uint8_t> hello;
    // Client version: TLS 1.2
    hello.push_back(0x03); hello.push_back(0x03);
    // Client Random (32 bytes)
    std::uniform_int_distribution<int> bd(0, 255);
    for (int i = 0; i < 32; ++i) hello.push_back(static_cast<uint8_t>(bd(rng_)));
    // Session ID length = 32, random session ID
    hello.push_back(32);
    for (int i = 0; i < 32; ++i) hello.push_back(static_cast<uint8_t>(bd(rng_)));
    // Cipher suites
    std::vector<uint16_t> suites = config_.tls_cipher_suites;
    if (suites.empty()) {
        suites = {0x1301,0x1302,0x1303, // TLS 1.3 suites
                  0xC02C,0xC02B,0xC030,0xC02F, // TLS 1.2 ECDHE
                  0x009E,0x009C,0x00FF}; // RSA, SCSV
    }
    uint16_t suites_len = static_cast<uint16_t>(suites.size() * 2);
    hello.push_back(static_cast<uint8_t>(suites_len >> 8));
    hello.push_back(static_cast<uint8_t>(suites_len & 0xFF));
    for (auto cs : suites) {
        hello.push_back(static_cast<uint8_t>(cs >> 8));
        hello.push_back(static_cast<uint8_t>(cs & 0xFF));
    }
    // Compression methods: null
    hello.push_back(0x01); hello.push_back(0x00);
    // --- Extensions ---
    std::vector<uint8_t> exts;
    // SNI extension (type 0x0000)
    {
        std::vector<uint8_t> sni_ext;
        uint16_t name_len = static_cast<uint16_t>(sni.size());
        uint16_t list_len = name_len + 3;
        sni_ext.push_back(static_cast<uint8_t>(list_len >> 8));
        sni_ext.push_back(static_cast<uint8_t>(list_len & 0xFF));
        sni_ext.push_back(0x00); // host_name type
        sni_ext.push_back(static_cast<uint8_t>(name_len >> 8));
        sni_ext.push_back(static_cast<uint8_t>(name_len & 0xFF));
        sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());
        // Extension header
        exts.push_back(0x00); exts.push_back(0x00); // type = server_name
        uint16_t ext_len = static_cast<uint16_t>(sni_ext.size());
        exts.push_back(static_cast<uint8_t>(ext_len >> 8));
        exts.push_back(static_cast<uint8_t>(ext_len & 0xFF));
        exts.insert(exts.end(), sni_ext.begin(), sni_ext.end());
    }
    // Supported versions extension (type 0x002B) - advertise TLS 1.3 + 1.2
    exts.push_back(0x00); exts.push_back(0x2B);
    exts.push_back(0x00); exts.push_back(0x05); // len=5
    exts.push_back(0x04); // list length 4
    exts.push_back(0x03); exts.push_back(0x04); // TLS 1.3
    exts.push_back(0x03); exts.push_back(0x03); // TLS 1.2
    // Embed payload in a padding extension (type 0x0015)
    if (!payload.empty()) {
        exts.push_back(0x00); exts.push_back(0x15);
        uint16_t pl = static_cast<uint16_t>(payload.size());
        exts.push_back(static_cast<uint8_t>(pl >> 8));
        exts.push_back(static_cast<uint8_t>(pl & 0xFF));
        exts.insert(exts.end(), payload.begin(), payload.end());
    }
    // Extensions length
    uint16_t exts_len = static_cast<uint16_t>(exts.size());
    hello.push_back(static_cast<uint8_t>(exts_len >> 8));
    hello.push_back(static_cast<uint8_t>(exts_len & 0xFF));
    hello.insert(hello.end(), exts.begin(), exts.end());
    // --- Wrap in Handshake + TLS Record ---
    std::vector<uint8_t> result;
    // TLS record header
    result.push_back(0x16); // Handshake
    result.push_back(0x03); result.push_back(0x01); // TLS 1.0 (record layer)
    // Handshake header: type=ClientHello(1), length
    uint32_t hs_len = static_cast<uint32_t>(hello.size());
    std::vector<uint8_t> hs_hdr = {0x01,
        static_cast<uint8_t>((hs_len >> 16) & 0xFF),
        static_cast<uint8_t>((hs_len >> 8) & 0xFF),
        static_cast<uint8_t>(hs_len & 0xFF)};
    uint16_t rec_len = static_cast<uint16_t>(hs_hdr.size() + hello.size());
    result.push_back(static_cast<uint8_t>(rec_len >> 8));
    result.push_back(static_cast<uint8_t>(rec_len & 0xFF));
    result.insert(result.end(), hs_hdr.begin(), hs_hdr.end());
    result.insert(result.end(), hello.begin(), hello.end());
    tls_sequence_number_++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_https_application_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result = {0x17, 0x03, 0x03, 0x00, 0x00};
    result.insert(result.end(), payload.begin(), payload.end());
    uint16_t len = static_cast<uint16_t>(payload.size());
    result[3] = (len >> 8) & 0xFF;
    result[4] = len & 0xFF;
    tls_sequence_number_++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_tls_payload(const std::vector<uint8_t>& data) {
    if (data.size() > 9 && data[0] == 0x16)
        return std::vector<uint8_t>(data.begin() + 9, data.end());
    if (data.size() > 5 && data[0] == 0x17)
        return std::vector<uint8_t>(data.begin() + 5, data.end());
    return data;
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
    std::uniform_int_distribution<int> bd(0, 255);
    uint8_t mask[4];
    for (int i = 0; i < 4; ++i) { mask[i] = static_cast<uint8_t>(bd(rng_)); frame.push_back(mask[i]); }
    for (size_t i = 0; i < payload.size(); ++i)
        frame.push_back(payload[i] ^ mask[i % 4]);
    return frame;
}

std::vector<uint8_t> TrafficMimicry::extract_websocket_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return data;
    size_t off = 2;
    size_t plen = data[1] & 0x7F;
    bool masked = (data[1] & 0x80) != 0;
    if (plen == 126) { if (data.size() < 4) return data; plen = (size_t(data[2])<<8)|data[3]; off = 4; }
    else if (plen == 127) { if (data.size() < 10) return data; plen = 0; for (int i=0;i<8;++i) plen=(plen<<8)|data[2+i]; off = 10; }
    uint8_t mask[4] = {0,0,0,0};
    if (masked) { if (data.size() < off+4) return data; for (int i=0;i<4;++i) mask[i]=data[off+i]; off+=4; }
    if (data.size() < off+plen) return data;
    std::vector<uint8_t> r(plen);
    for (size_t i=0;i<plen;++i) r[i] = data[off+i] ^ mask[i%4];
    return r;
}

// ==================== DNS (RU domains) ====================
std::vector<uint8_t> TrafficMimicry::create_dns_query_wrapper(const std::vector<uint8_t>& payload) {
    dns_transaction_id_++;
    uint16_t txn_id = dns_transaction_id_;
    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // Pick random RU domain for QNAME
    std::uniform_int_distribution<int> d(0, static_cast<int>(RU_DNS_LABELS.size()) - 1);
    const auto& lbl = RU_DNS_LABELS[d(rng_)];
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00); // end QNAME
    result.push_back(0x00); result.push_back(0x01); // QTYPE=A
    result.push_back(0x00); result.push_back(0x01); // QCLASS=IN
    // Update ARCOUNT to 1 (indicate Additional record)
    result[10] = 0x00; result[11] = 0x01;

    // Add payload as TXT record in Additional section (RFC 1035)
    // NAME: pointer to QNAME (0xC00C points to offset 12)
    result.push_back(0xC0); result.push_back(0x0C);
    // TYPE: TXT (0x0010)
    result.push_back(0x00); result.push_back(0x10);
    // CLASS: IN (0x0001)
    result.push_back(0x00); result.push_back(0x01);
    // TTL: 0 (4 bytes)
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x00);
    // RDLENGTH: payload size + 1 (for length byte)
    uint16_t rdlen = static_cast<uint16_t>(payload.size() + 1);
    result.push_back(static_cast<uint8_t>(rdlen >> 8));
    result.push_back(static_cast<uint8_t>(rdlen & 0xFF));
    // TXT RDATA: <length byte> <payload data>
    result.push_back(static_cast<uint8_t>(payload.size()));
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_dns_response_wrapper(const std::vector<uint8_t>& payload) {
    dns_transaction_id_++;
    uint16_t txn_id = dns_transaction_id_;
    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    // Pick random RU domain for QNAME in Question section
    std::uniform_int_distribution<int> d(0, static_cast<int>(RU_DNS_LABELS.size()) - 1);
    const auto& lbl = RU_DNS_LABELS[d(rng_)];
    
    // Add Question section
    result.push_back(lbl.sld_len);
    result.insert(result.end(), lbl.sld, lbl.sld + lbl.sld_len);
    result.push_back(lbl.tld_len);
    result.insert(result.end(), lbl.tld, lbl.tld + lbl.tld_len);
    result.push_back(0x00); // end QNAME
    result.push_back(0x00); result.push_back(0x10); // QTYPE=TXT
    result.push_back(0x00); result.push_back(0x01); // QCLASS=IN
    
    // Add Answer section with TXT record (RFC 1035)
    // NAME: pointer to QNAME (0xC00C points to offset 12)
    result.push_back(0xC0); result.push_back(0x0C);
    // TYPE: TXT (0x0010)
    result.push_back(0x00); result.push_back(0x10);
    // CLASS: IN (0x0001)
    result.push_back(0x00); result.push_back(0x01);
    // TTL: 300 seconds (4 bytes)
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x01); result.push_back(0x2C);
    // RDLENGTH: payload size + 1 (for length byte)
    uint16_t rdlen = static_cast<uint16_t>(payload.size() + 1);
    result.push_back(static_cast<uint8_t>(rdlen >> 8));
    result.push_back(static_cast<uint8_t>(rdlen & 0xFF));
    // TXT RDATA: <length byte> <payload data>
    result.push_back(static_cast<uint8_t>(payload.size()));
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_dns_payload(const std::vector<uint8_t>& data) {
    if (data.size() <= 12) return data;
    size_t off = 12;
    while (off < data.size() && data[off] != 0x00) {
        if ((data[off] & 0xC0) == 0xC0) { off += 2; break; }
        off += data[off] + 1;
    }
    if (off < data.size() && data[off] == 0x00) off++;
    off += 4;
    if (off >= data.size()) return data;
    return std::vector<uint8_t>(data.begin() + off, data.end());
}

// ==================== QUIC ====================
std::vector<uint8_t> TrafficMimicry::create_quic_initial_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0xC0);
    result.push_back(0x00); result.push_back(0x00); result.push_back(0x00); result.push_back(0x01);
    result.push_back(0x08);
    std::uniform_int_distribution<int> bd(0, 255);
    for (int i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(bd(rng_)));
    result.push_back(0x08);
    for (int i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(bd(rng_)));
    result.push_back(0x00);
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back(static_cast<uint8_t>((len >> 8) & 0x3F));
    result.push_back(static_cast<uint8_t>(len & 0xFF));
    result.insert(result.end(), payload.begin(), payload.end());
    quic_packet_number_++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_quic_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 7) return data;
    size_t off = 5;
    uint8_t dcid_len = data[off++]; off += dcid_len;
    if (off >= data.size()) return data;
    uint8_t scid_len = data[off++]; off += scid_len;
    if (off >= data.size()) return data;
    uint8_t tok_len = data[off++]; off += tok_len;
    off += 2;
    if (off >= data.size()) return data;
    return std::vector<uint8_t>(data.begin() + off, data.end());
}

// ==================== App-specific ====================
std::vector<uint8_t> TrafficMimicry::create_bittorrent_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(19);
    const char* pstr = "BitTorrent protocol";
    result.insert(result.end(), pstr, pstr + 19);
    for (int i = 0; i < 8; ++i) result.push_back(0x00);
    std::uniform_int_distribution<int> bd(0, 255);
    for (int i = 0; i < 40; ++i) result.push_back(static_cast<uint8_t>(bd(rng_)));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_skype_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    std::uniform_int_distribution<int> bd(0, 255);
    for (int i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(bd(rng_)));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_zoom_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0x05); result.push_back(0x04);
    std::uniform_int_distribution<int> bd(0, 255);
    for (int i = 0; i < 10; ++i) result.push_back(static_cast<uint8_t>(bd(rng_)));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

// ==================== Generic ====================
std::vector<uint8_t> TrafficMimicry::create_generic_tcp_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    uint32_t len = static_cast<uint32_t>(payload.size());
    result.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    result.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(len & 0xFF));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_generic_udp_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(len & 0xFF));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

} // namespace ncp
