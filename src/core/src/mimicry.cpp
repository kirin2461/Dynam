#include "../include/ncp_mimicry.hpp"
#include <sstream>
#include <algorithm>
#include <cstring>

namespace ncp {

TrafficMimicry::TrafficMimicry() : rng_(std::random_device{}()) {}

TrafficMimicry::TrafficMimicry(const MimicConfig& config)
    : config_(config), rng_(std::random_device{}()) {}

TrafficMimicry::~TrafficMimicry() {}

// --- wrap_payload (with explicit profile) ---
std::vector<uint8_t> TrafficMimicry::wrap_payload(const std::vector<uint8_t>& payload, MimicProfile profile) {
    switch (profile) {
        case MimicProfile::HTTP_GET:
            return create_http_get_wrapper(payload);
        case MimicProfile::HTTP_POST:
            return create_http_post_wrapper(payload);
        case MimicProfile::HTTPS_CLIENT_HELLO:
            return create_https_client_hello_wrapper(payload);
        case MimicProfile::HTTPS_APPLICATION:
            return create_https_application_wrapper(payload);
        case MimicProfile::DNS_QUERY:
            return create_dns_query_wrapper(payload);
        case MimicProfile::DNS_RESPONSE:
            return create_dns_response_wrapper(payload);
        case MimicProfile::QUIC_INITIAL:
            return create_quic_initial_wrapper(payload);
        case MimicProfile::WEBSOCKET:
            return create_websocket_wrapper(payload);
        case MimicProfile::BITTORRENT:
            return create_bittorrent_wrapper(payload);
        case MimicProfile::SKYPE:
            return create_skype_wrapper(payload);
        case MimicProfile::ZOOM:
            return create_zoom_wrapper(payload);
        case MimicProfile::GENERIC_TCP:
            return create_generic_tcp_wrapper(payload);
        case MimicProfile::GENERIC_UDP:
            return create_generic_udp_wrapper(payload);
        default:
            return payload;
    }
}

// --- wrap_payload (uses config profile) ---
std::vector<uint8_t> TrafficMimicry::wrap_payload(const std::vector<uint8_t>& payload) {
    return wrap_payload(payload, config_.profile);
}

// --- unwrap_payload (with explicit profile) ---
std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data, MimicProfile profile) {
    switch (profile) {
        case MimicProfile::HTTP_GET:
        case MimicProfile::HTTP_POST:
            return extract_http_payload(mimicked_data);
        case MimicProfile::HTTPS_CLIENT_HELLO:
        case MimicProfile::HTTPS_APPLICATION:
            return extract_tls_payload(mimicked_data);
        case MimicProfile::DNS_QUERY:
        case MimicProfile::DNS_RESPONSE:
            return extract_dns_payload(mimicked_data);
        case MimicProfile::QUIC_INITIAL:
            return extract_quic_payload(mimicked_data);
        case MimicProfile::WEBSOCKET:
            return extract_websocket_payload(mimicked_data);
        default:
            return mimicked_data;
    }
}

// --- unwrap_payload (uses config profile) ---
std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data) {
    return unwrap_payload(mimicked_data, config_.profile);
}

// --- Configuration ---
void TrafficMimicry::set_config(const MimicConfig& config) { config_ = config; }
TrafficMimicry::MimicConfig TrafficMimicry::get_config() const { return config_; }

// --- Statistics ---
TrafficMimicry::MimicStats TrafficMimicry::get_stats() const { return stats_; }
void TrafficMimicry::reset_stats() { stats_ = {}; }

// --- Profile detection ---
TrafficMimicry::MimicProfile TrafficMimicry::detect_profile(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return MimicProfile::GENERIC_TCP;
    // HTTP
    if (data.size() >= 4 && data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
        return MimicProfile::HTTP_GET;
    if (data.size() >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ')
        return MimicProfile::HTTP_POST;
    // TLS
    if (data[0] == 0x16 && data[1] == 0x03)
        return MimicProfile::HTTPS_CLIENT_HELLO;
    if (data[0] == 0x17 && data[1] == 0x03)
        return MimicProfile::HTTPS_APPLICATION;
    // WebSocket (binary frame opcode 0x82 or text 0x81)
    if ((data[0] & 0x0F) == 0x01 || (data[0] & 0x0F) == 0x02)
        if (data[0] & 0x80) return MimicProfile::WEBSOCKET;
    // DNS (starts with 2-byte ID, then flags)
    if (data.size() >= 12 && (data[2] & 0x80) == 0)
        return MimicProfile::DNS_QUERY;
    return MimicProfile::GENERIC_TCP;
}

// --- Timing ---
std::chrono::milliseconds TrafficMimicry::get_next_packet_delay() {
    return calculate_realistic_delay(config_.profile, 0);
}

std::chrono::milliseconds TrafficMimicry::calculate_realistic_delay(MimicProfile profile, size_t) {
    std::uniform_int_distribution<int> dist(config_.min_inter_packet_delay, config_.max_inter_packet_delay);
    return std::chrono::milliseconds(dist(rng_));
}

// --- Utility helpers ---
std::string TrafficMimicry::generate_random_http_path() {
    static const char* paths[] = {"/index.html", "/api/v1/data", "/images/logo.png", "/css/style.css", "/js/app.js"};
    std::uniform_int_distribution<int> dist(0, 4);
    return paths[dist(rng_)];
}

std::string TrafficMimicry::generate_random_user_agent() {
    static const char* agents[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
    };
    std::uniform_int_distribution<int> dist(0, 2);
    return agents[dist(rng_)];
}

std::string TrafficMimicry::generate_random_hostname() {
    static const char* hosts[] = {"www.google.com", "cdn.cloudflare.com", "api.github.com", "static.example.com"};
    std::uniform_int_distribution<int> dist(0, 3);
    return hosts[dist(rng_)];
}

uint16_t TrafficMimicry::generate_random_port() {
    std::uniform_int_distribution<uint16_t> dist(1024, 65535);
    return dist(rng_);
}

std::vector<uint8_t> TrafficMimicry::generate_random_padding(size_t min_size, size_t max_size) {
    std::uniform_int_distribution<size_t> size_dist(min_size, max_size);
    size_t sz = size_dist(rng_);
    std::vector<uint8_t> pad(sz);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    for (auto& b : pad) b = static_cast<uint8_t>(byte_dist(rng_));
    return pad;
}

// ========== HTTP wrappers ==========
std::vector<uint8_t> TrafficMimicry::create_http_get_wrapper(const std::vector<uint8_t>& payload) {
    std::ostringstream oss;
    oss << "GET " << generate_random_http_path() << " HTTP/1.1\r\n";
    oss << "Host: " << generate_random_hostname() << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Accept: */*\r\n";
    oss << "Content-Length: " << payload.size() << "\r\n";
    oss << "\r\n";
    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_http_post_wrapper(const std::vector<uint8_t>& payload) {
    std::ostringstream oss;
    oss << "POST " << generate_random_http_path() << " HTTP/1.1\r\n";
    oss << "Host: " << generate_random_hostname() << "\r\n";
    oss << "User-Agent: " << generate_random_user_agent() << "\r\n";
    oss << "Content-Type: application/octet-stream\r\n";
    oss << "Content-Length: " << payload.size() << "\r\n";
    oss << "\r\n";
    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_http_payload(const std::vector<uint8_t>& data) {
    std::string s(data.begin(), data.end());
    size_t pos = s.find("\r\n\r\n");
    if (pos != std::string::npos) {
        return std::vector<uint8_t>(data.begin() + pos + 4, data.end());
    }
    return data;
}

// ========== TLS wrappers ==========
std::vector<uint8_t> TrafficMimicry::create_https_client_hello_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result = {
        0x16, 0x03, 0x01, // Handshake, TLS 1.0
        0x00, 0x00        // Length placeholder
    };
    result.push_back(0x01); // ClientHello
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00); // Handshake length placeholder
    result.insert(result.end(), payload.begin(), payload.end());
    uint16_t total_len = static_cast<uint16_t>(result.size() - 5);
    result[3] = (total_len >> 8) & 0xFF;
    result[4] = total_len & 0xFF;
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_https_application_wrapper(const std::vector<uint8_t>& payload) {
    // TLS Application Data record
    std::vector<uint8_t> result = {
        0x17, 0x03, 0x03, // Application Data, TLS 1.2
        0x00, 0x00        // Length placeholder
    };
    result.insert(result.end(), payload.begin(), payload.end());
    uint16_t len = static_cast<uint16_t>(payload.size());
    result[3] = (len >> 8) & 0xFF;
    result[4] = len & 0xFF;
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_tls_payload(const std::vector<uint8_t>& data) {
    // Skip 5-byte TLS record header + 4-byte handshake header if ClientHello
    if (data.size() > 9 && data[0] == 0x16) {
        return std::vector<uint8_t>(data.begin() + 9, data.end());
    }
    // Application Data: skip 5-byte header
    if (data.size() > 5 && data[0] == 0x17) {
        return std::vector<uint8_t>(data.begin() + 5, data.end());
    }
    return data;
}

// ========== WebSocket wrappers (RFC 6455, no libwebsockets needed) ==========
std::vector<uint8_t> TrafficMimicry::create_websocket_wrapper(const std::vector<uint8_t>& payload) {
    // Build a WebSocket binary frame (opcode 0x02, FIN=1, MASK=1)
    std::vector<uint8_t> frame;
    // Byte 0: FIN(1) + RSV(000) + opcode(0010) = 0x82
    frame.push_back(0x82);

    // Byte 1+: MASK(1) + payload length
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

    // 4-byte masking key
    std::uniform_int_distribution<int> dist(0, 255);
    uint8_t mask[4];
    for (int i = 0; i < 4; ++i) {
        mask[i] = static_cast<uint8_t>(dist(rng_));
        frame.push_back(mask[i]);
    }

    // Masked payload
    for (size_t i = 0; i < payload.size(); ++i) {
        frame.push_back(payload[i] ^ mask[i % 4]);
    }

    return frame;
}

std::vector<uint8_t> TrafficMimicry::extract_websocket_payload(const std::vector<uint8_t>& data) {
    if (data.size() < 2) return data;

    size_t offset = 2;
    size_t payload_len = data[1] & 0x7F;
    bool masked = (data[1] & 0x80) != 0;

    if (payload_len == 126) {
        if (data.size() < 4) return data;
        payload_len = (static_cast<size_t>(data[2]) << 8) | data[3];
        offset = 4;
    } else if (payload_len == 127) {
        if (data.size() < 10) return data;
        payload_len = 0;
        for (int i = 0; i < 8; ++i)
            payload_len = (payload_len << 8) | data[2 + i];
        offset = 10;
    }

    uint8_t mask[4] = {0, 0, 0, 0};
    if (masked) {
        if (data.size() < offset + 4) return data;
        for (int i = 0; i < 4; ++i)
            mask[i] = data[offset + i];
        offset += 4;
    }

    if (data.size() < offset + payload_len) return data;

    std::vector<uint8_t> result(payload_len);
    for (size_t i = 0; i < payload_len; ++i) {
        result[i] = data[offset + i] ^ mask[i % 4];
    }
    return result;
}

// ========== DNS wrappers ==========
std::vector<uint8_t> TrafficMimicry::create_dns_query_wrapper(const std::vector<uint8_t>& payload) {
    // DNS header: ID(2) + Flags(2) + QCount(2) + ANCount(2) + NSCount(2) + ARCount(2) = 12 bytes
    std::uniform_int_distribution<int> id_dist(0, 65535);
    uint16_t txn_id = static_cast<uint16_t>(id_dist(rng_));
    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x01, 0x00, // Standard query, recursion desired
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // Encode payload as a fake QNAME + payload in additional data
    result.push_back(0x06); // label length
    const char* label = "google";
    result.insert(result.end(), label, label + 6);
    result.push_back(0x03);
    result.insert(result.end(), {'c','o','m'});
    result.push_back(0x00); // end of QNAME
    result.push_back(0x00); result.push_back(0x10); // QTYPE=TXT
    result.push_back(0x00); result.push_back(0x01); // QCLASS=IN
    // Append payload as additional section data
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_dns_response_wrapper(const std::vector<uint8_t>& payload) {
    std::uniform_int_distribution<int> id_dist(0, 65535);
    uint16_t txn_id = static_cast<uint16_t>(id_dist(rng_));
    std::vector<uint8_t> result = {
        static_cast<uint8_t>(txn_id >> 8), static_cast<uint8_t>(txn_id & 0xFF),
        0x81, 0x80, // Response, recursion available
        0x00, 0x01, // 1 question
        0x00, 0x01, // 1 answer
        0x00, 0x00, 0x00, 0x00
    };
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_dns_payload(const std::vector<uint8_t>& data) {
    // Skip 12-byte DNS header + query section (find end of QNAME)
    if (data.size() <= 12) return data;
    size_t offset = 12;
    // Skip QNAME labels
    while (offset < data.size() && data[offset] != 0x00) {
        if ((data[offset] & 0xC0) == 0xC0) { offset += 2; break; }
        offset += data[offset] + 1;
    }
    if (offset < data.size() && data[offset] == 0x00) offset++;
    offset += 4; // skip QTYPE + QCLASS
    if (offset >= data.size()) return data;
    return std::vector<uint8_t>(data.begin() + offset, data.end());
}

// ========== QUIC wrapper ==========
std::vector<uint8_t> TrafficMimicry::create_quic_initial_wrapper(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> result;
    result.push_back(0xC0); // Long header, Initial type
    result.push_back(0x00); result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x01); // QUIC v1
    result.push_back(0x08); // DCID len
    std::uniform_int_distribution<int> dist(0, 255);
    for (int i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(dist(rng_)));
    result.push_back(0x08); // SCID len
    for (int i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(dist(rng_)));
    result.push_back(0x00); // Token len
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back(static_cast<uint8_t>((len >> 8) & 0x3F));
    result.push_back(static_cast<uint8_t>(len & 0xFF));
    result.insert(result.end(), payload.begin(), payload.end());
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

// ========== Application-specific wrappers ==========
std::vector<uint8_t> TrafficMimicry::create_bittorrent_wrapper(const std::vector<uint8_t>& payload) {
    // BitTorrent protocol handshake header
    std::vector<uint8_t> result;
    result.push_back(19); // pstrlen
    const char* pstr = "BitTorrent protocol";
    result.insert(result.end(), pstr, pstr + 19);
    // 8 reserved bytes
    for (int i = 0; i < 8; ++i) result.push_back(0x00);
    // 20-byte info hash (random)
    std::uniform_int_distribution<int> dist(0, 255);
    for (int i = 0; i < 20; ++i) result.push_back(static_cast<uint8_t>(dist(rng_)));
    // 20-byte peer ID (random)
    for (int i = 0; i < 20; ++i) result.push_back(static_cast<uint8_t>(dist(rng_)));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_skype_wrapper(const std::vector<uint8_t>& payload) {
    // Skype-like UDP packet with random-looking header
    std::vector<uint8_t> result;
    std::uniform_int_distribution<int> dist(0, 255);
    // 2-byte ID + 2-byte type + 4-byte sequence
    for (int i = 0; i < 8; ++i) result.push_back(static_cast<uint8_t>(dist(rng_)));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_zoom_wrapper(const std::vector<uint8_t>& payload) {
    // Zoom-like media packet header
    std::vector<uint8_t> result;
    result.push_back(0x05); // version-like byte
    result.push_back(0x04); // type: media
    std::uniform_int_distribution<int> dist(0, 255);
    // 4-byte SSRC + 4-byte timestamp + 2-byte sequence
    for (int i = 0; i < 10; ++i) result.push_back(static_cast<uint8_t>(dist(rng_)));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

// ========== Generic wrappers ==========
std::vector<uint8_t> TrafficMimicry::create_generic_tcp_wrapper(const std::vector<uint8_t>& payload) {
    // Simple length-prefixed framing
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
    // Simple 2-byte length prefix for UDP
    std::vector<uint8_t> result;
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(len & 0xFF));
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

} // namespace ncp
