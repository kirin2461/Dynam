#include "ncp_mimicry.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace ncp {

// ---- Constructor / Destructor ----------------------------------------

TrafficMimicry::TrafficMimicry()
    : config_(),
      stats_(),
      rng_(std::random_device{}()),
      last_packet_time_(std::chrono::steady_clock::now()),
      tls_sequence_number_(0),
      dns_transaction_id_(0),
      quic_packet_number_(0) {
    // Set default User-Agent
    config_.http_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    config_.http_host = "www.google.com";
    config_.tls_sni = "www.google.com";
}

TrafficMimicry::TrafficMimicry(const MimicConfig& config)
    : config_(config),
      stats_(),
      rng_(std::random_device{}()),
      last_packet_time_(std::chrono::steady_clock::now()),
      tls_sequence_number_(0),
      dns_transaction_id_(0),
      quic_packet_number_(0) {
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

// ---- Public Interface ------------------------------------------------

std::vector<uint8_t> TrafficMimicry::wrap_payload(
    const std::vector<uint8_t>& payload,
    MimicProfile profile) {
    
    std::vector<uint8_t> result;
    stats_.bytes_original += payload.size();
    
    switch (profile) {
        case MimicProfile::HTTP_GET:
            result = create_http_get_wrapper(payload);
            break;
        case MimicProfile::HTTP_POST:
            result = create_http_post_wrapper(payload);
            break;
        case MimicProfile::HTTPS_CLIENT_HELLO:
            result = create_https_client_hello_wrapper(payload);
            break;
        case MimicProfile::HTTPS_APPLICATION:
            result = create_https_application_wrapper(payload);
            break;
        case MimicProfile::DNS_QUERY:
            result = create_dns_query_wrapper(payload);
            break;
        case MimicProfile::DNS_RESPONSE:
            result = create_dns_response_wrapper(payload);
            break;
        case MimicProfile::QUIC_INITIAL:
            result = create_quic_initial_wrapper(payload);
            break;
        case MimicProfile::WEBSOCKET:
            result = create_websocket_wrapper(payload);
            break;
        case MimicProfile::BITTORRENT:
            result = create_bittorrent_wrapper(payload);
            break;
        case MimicProfile::SKYPE:
            result = create_skype_wrapper(payload);
            break;
        case MimicProfile::ZOOM:
            result = create_zoom_wrapper(payload);
            break;
        case MimicProfile::GENERIC_TCP:
            result = create_generic_tcp_wrapper(payload);
            break;
        case MimicProfile::GENERIC_UDP:
        default:
            result = create_generic_udp_wrapper(payload);
            break;
    }
    
    stats_.packets_wrapped++;
    stats_.bytes_mimicked += result.size();
    
    if (stats_.bytes_original > 0) {
        stats_.average_overhead_percent = 
            ((double)stats_.bytes_mimicked / stats_.bytes_original - 1.0) * 100.0;
    }
    
    last_packet_time_ = std::chrono::steady_clock::now();
    return result;
}

std::vector<uint8_t> TrafficMimicry::wrap_payload(
    const std::vector<uint8_t>& payload) {
    return wrap_payload(payload, config_.profile);
}

std::vector<uint8_t> TrafficMimicry::unwrap_payload(
    const std::vector<uint8_t>& mimicked_data,
    MimicProfile profile) {
    
    std::vector<uint8_t> result;
    
    switch (profile) {
        case MimicProfile::HTTP_GET:
        case MimicProfile::HTTP_POST:
            result = extract_http_payload(mimicked_data);
            break;
        case MimicProfile::HTTPS_CLIENT_HELLO:
        case MimicProfile::HTTPS_APPLICATION:
            result = extract_tls_payload(mimicked_data);
            break;
        case MimicProfile::DNS_QUERY:
        case MimicProfile::DNS_RESPONSE:
            result = extract_dns_payload(mimicked_data);
            break;
        case MimicProfile::QUIC_INITIAL:
            result = extract_quic_payload(mimicked_data);
            break;
        case MimicProfile::WEBSOCKET:
            result = extract_websocket_payload(mimicked_data);
            break;
        default:
            // Generic extraction: skip first 4 bytes (length header)
            if (mimicked_data.size() > 4) {
                result.assign(mimicked_data.begin() + 4, mimicked_data.end());
            }
            break;
    }
    
    stats_.packets_unwrapped++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::unwrap_payload(
    const std::vector<uint8_t>& mimicked_data) {
    MimicProfile detected = detect_profile(mimicked_data);
    return unwrap_payload(mimicked_data, detected);
}

void TrafficMimicry::set_config(const MimicConfig& config) {
    config_ = config;
}

TrafficMimicry::MimicConfig TrafficMimicry::get_config() const {
    return config_;
}

TrafficMimicry::MimicStats TrafficMimicry::get_stats() const {
    return stats_;
}

void TrafficMimicry::reset_stats() {
    stats_ = MimicStats();
}

TrafficMimicry::MimicProfile TrafficMimicry::detect_profile(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 2) {
        return MimicProfile::GENERIC_UDP;
    }
    
    // Check for TLS record
    if (data[0] == 0x16 || data[0] == 0x17) {
        if (data.size() >= 5 && data[1] == 0x03) {
            return (data[0] == 0x16) ? MimicProfile::HTTPS_CLIENT_HELLO 
                                     : MimicProfile::HTTPS_APPLICATION;
        }
    }
    
    // Check for HTTP
    if (data.size() >= 4) {
        std::string start(data.begin(), data.begin() + std::min(data.size(), size_t(10)));
        if (start.find("GET ") == 0 || start.find("HTTP") == 0) {
            return MimicProfile::HTTP_GET;
        }
        if (start.find("POST ") == 0) {
            return MimicProfile::HTTP_POST;
        }
    }
    
    // Check for DNS (port 53 not available, check structure)
    if (data.size() >= 12) {
        uint16_t flags = (data[2] << 8) | data[3];
        uint16_t qr = (flags >> 15) & 0x01;
        if (qr == 0) return MimicProfile::DNS_QUERY;
        if (qr == 1) return MimicProfile::DNS_RESPONSE;
    }
    
    // Check for QUIC
    if (data.size() >= 5 && (data[0] & 0x80)) {
        return MimicProfile::QUIC_INITIAL;
    }
    
    // Check for WebSocket frame
    if (data.size() >= 2) {
        uint8_t opcode = data[0] & 0x0F;
        if (opcode >= 0x00 && opcode <= 0x0A) {
            return MimicProfile::WEBSOCKET;
        }
    }
    
    return MimicProfile::GENERIC_TCP;
}

std::chrono::milliseconds TrafficMimicry::get_next_packet_delay() {
    return calculate_realistic_delay(config_.profile, 0);
}

// ---- HTTP Mimicry ----------------------------------------------------

std::vector<uint8_t> TrafficMimicry::create_http_get_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::ostringstream ss;
    std::string path = generate_random_http_path();
    
    // Base64-encode payload in URL parameter
    std::string encoded;
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    size_t i = 0;
    uint32_t octet_a, octet_b, octet_c, triple;
    
    while (i < payload.size()) {
        octet_a = i < payload.size() ? payload[i++] : 0;
        octet_b = i < payload.size() ? payload[i++] : 0;
        octet_c = i < payload.size() ? payload[i++] : 0;
        
        triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        encoded += base64_chars[(triple >> 18) & 0x3F];
        encoded += base64_chars[(triple >> 12) & 0x3F];
        encoded += (i > payload.size() + 1) ? '=' : base64_chars[(triple >> 6) & 0x3F];
        encoded += (i > payload.size()) ? '=' : base64_chars[triple & 0x3F];
    }
    
    ss << "GET " << path << "?d=" << encoded << " HTTP/1.1\r\n";
    ss << "Host: " << config_.http_host << "\r\n";
    ss << "User-Agent: " << config_.http_user_agent << "\r\n";
    ss << "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    ss << "Accept-Language: en-US,en;q=0.5\r\n";
    ss << "Accept-Encoding: gzip, deflate, br\r\n";
    ss << "Connection: keep-alive\r\n";
    
    for (const auto& header : config_.http_headers) {
        ss << header << "\r\n";
    }
    
    ss << "\r\n";
    
    std::string http_request = ss.str();
    return std::vector<uint8_t>(http_request.begin(), http_request.end());
}

std::vector<uint8_t> TrafficMimicry::create_http_post_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::ostringstream ss;
    std::string path = generate_random_http_path();
    
    ss << "POST " << path << " HTTP/1.1\r\n";
    ss << "Host: " << config_.http_host << "\r\n";
    ss << "User-Agent: " << config_.http_user_agent << "\r\n";
    ss << "Accept: application/json, text/plain, */*\r\n";
    ss << "Content-Type: application/octet-stream\r\n";
    ss << "Content-Length: " << payload.size() << "\r\n";
    ss << "Connection: keep-alive\r\n";
    ss << "\r\n";
    
    std::string headers = ss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), payload.begin(), payload.end());
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_http_payload(
    const std::vector<uint8_t>& data) {
    
    std::string http_data(data.begin(), data.end());
    
    // Find Content-Length or chunked body
    size_t body_start = http_data.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        body_start += 4;
        return std::vector<uint8_t>(data.begin() + body_start, data.end());
    }
    
    // Try to extract from GET parameter
    size_t param_start = http_data.find("?d=");
    if (param_start != std::string::npos) {
        param_start += 3;
        size_t param_end = http_data.find_first_of(" &\r\n", param_start);
        std::string encoded = http_data.substr(param_start, param_end - param_start);
        
        // Base64 decode
        static const std::string base64_chars = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        std::vector<uint8_t> decoded;
        int i = 0;
        uint32_t buf = 0;
        int bits = 0;
        
        for (char c : encoded) {
            if (c == '=') break;
            size_t pos = base64_chars.find(c);
            if (pos == std::string::npos) continue;
            
            buf = (buf << 6) | pos;
            bits += 6;
            
            if (bits >= 8) {
                bits -= 8;
                decoded.push_back((buf >> bits) & 0xFF);
            }
        }
        
        return decoded;
    }
    
    return {};
}

// ---- HTTPS/TLS Mimicry -----------------------------------------------

std::vector<uint8_t> TrafficMimicry::create_https_client_hello_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // TLS Record Header
    result.push_back(0x16);  // Handshake
    result.push_back(0x03);  // TLS 1.0 for ClientHello
    result.push_back(0x01);
    
    // Placeholder for record length
    size_t record_length_pos = result.size();
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Handshake Header
    result.push_back(0x01);  // ClientHello
    
    // Placeholder for handshake length (3 bytes)
    size_t handshake_length_pos = result.size();
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Client Version (TLS 1.2)
    result.push_back(0x03);
    result.push_back(0x03);
    
    // Random (32 bytes) - embed payload length in first 4 bytes
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    result.push_back((payload_len >> 24) & 0xFF);
    result.push_back((payload_len >> 16) & 0xFF);
    result.push_back((payload_len >> 8) & 0xFF);
    result.push_back(payload_len & 0xFF);
    
    // Fill rest of random with actual random data
    for (int i = 0; i < 28; ++i) {
        result.push_back(rng_() & 0xFF);
    }
    
    // Session ID Length (embedded payload starts here)
    result.push_back(static_cast<uint8_t>(std::min(payload.size(), size_t(32))));
    
    // Session ID (first 32 bytes of payload or less)
    size_t session_id_len = std::min(payload.size(), size_t(32));
    result.insert(result.end(), payload.begin(), payload.begin() + session_id_len);
    
    // Cipher Suites Length
    result.push_back(0x00);
    result.push_back(0x08);
    
    // Cipher Suites (common ones)
    result.push_back(0x13); result.push_back(0x02);  // TLS_AES_256_GCM_SHA384
    result.push_back(0x13); result.push_back(0x01);  // TLS_AES_128_GCM_SHA256
    result.push_back(0xC0); result.push_back(0x2C);  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    result.push_back(0xC0); result.push_back(0x2B);  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    
    // Compression Methods
    result.push_back(0x01);  // Length
    result.push_back(0x00);  // null compression
    
    // Extensions placeholder - embed remaining payload
    size_t remaining_payload_start = session_id_len;
    size_t remaining_payload_size = payload.size() - remaining_payload_start;
    
    // Extensions length (2 bytes)
    uint16_t ext_len = static_cast<uint16_t>(remaining_payload_size + 50);
    result.push_back((ext_len >> 8) & 0xFF);
    result.push_back(ext_len & 0xFF);
    
    // SNI Extension
    std::string sni = config_.tls_sni.empty() ? "www.google.com" : config_.tls_sni;
    result.push_back(0x00); result.push_back(0x00);  // SNI extension type
    uint16_t sni_ext_len = static_cast<uint16_t>(sni.size() + 5);
    result.push_back((sni_ext_len >> 8) & 0xFF);
    result.push_back(sni_ext_len & 0xFF);
    uint16_t sni_list_len = static_cast<uint16_t>(sni.size() + 3);
    result.push_back((sni_list_len >> 8) & 0xFF);
    result.push_back(sni_list_len & 0xFF);
    result.push_back(0x00);  // host_name type
    uint16_t sni_len = static_cast<uint16_t>(sni.size());
    result.push_back((sni_len >> 8) & 0xFF);
    result.push_back(sni_len & 0xFF);
    result.insert(result.end(), sni.begin(), sni.end());
    
    // Remaining payload in "unknown" extension
    if (remaining_payload_size > 0) {
        result.push_back(0xFF); result.push_back(0x01);  // Private extension type
        result.push_back((remaining_payload_size >> 8) & 0xFF);
        result.push_back(remaining_payload_size & 0xFF);
        result.insert(result.end(), 
                      payload.begin() + remaining_payload_start, 
                      payload.end());
    }
    
    // Fix lengths
    size_t total_len = result.size() - 5;
    result[record_length_pos] = (total_len >> 8) & 0xFF;
    result[record_length_pos + 1] = total_len & 0xFF;
    
    size_t handshake_len = result.size() - 9;
    result[handshake_length_pos] = (handshake_len >> 16) & 0xFF;
    result[handshake_length_pos + 1] = (handshake_len >> 8) & 0xFF;
    result[handshake_length_pos + 2] = handshake_len & 0xFF;
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_https_application_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // TLS Application Data Record
    result.push_back(0x17);  // Application Data
    result.push_back(0x03);  // TLS 1.2
    result.push_back(0x03);
    
    // Payload length includes 4-byte length prefix and optional padding
    size_t padded_len = payload.size() + 4;
    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        std::uniform_int_distribution<int> dist(config_.min_padding, config_.max_padding);
        padded_len += dist(rng_);
    }
    
    result.push_back((padded_len >> 8) & 0xFF);
    result.push_back(padded_len & 0xFF);
    
    // Embed payload length (for extraction)
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    result.push_back((payload_len >> 24) & 0xFF);
    result.push_back((payload_len >> 16) & 0xFF);
    result.push_back((payload_len >> 8) & 0xFF);
    result.push_back(payload_len & 0xFF);
    
    // Payload
    result.insert(result.end(), payload.begin(), payload.end());
    
    // Padding
    while (result.size() < 5 + padded_len) {
        result.push_back(rng_() & 0xFF);
    }
    
    tls_sequence_number_++;
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_tls_payload(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 9) return {};
    
    // Check TLS record
    if (data[0] != 0x16 && data[0] != 0x17) return {};
    
    if (data[0] == 0x17) {
        // Application Data - extract from length prefix
        uint32_t payload_len = (data[5] << 24) | (data[6] << 16) | 
                               (data[7] << 8) | data[8];
        if (data.size() >= 9 + payload_len) {
            return std::vector<uint8_t>(data.begin() + 9, 
                                        data.begin() + 9 + payload_len);
        }
    } else {
        // ClientHello - extract from Random field length prefix + session ID + extension
        if (data.size() < 43) return {};
        
        // Payload length from Random field (first 4 bytes)
        uint32_t payload_len = (data[11] << 24) | (data[12] << 16) | 
                               (data[13] << 8) | data[14];
        
        // Session ID
        uint8_t session_id_len = data[43];
        std::vector<uint8_t> result;
        
        if (data.size() > 44 + session_id_len) {
            result.insert(result.end(), data.begin() + 44, 
                          data.begin() + 44 + session_id_len);
        }
        
        // Look for private extension 0xFF01
        size_t pos = 44 + session_id_len;
        // Skip cipher suites and compression
        if (pos + 2 <= data.size()) {
            uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
            pos += 2 + cipher_len;
        }
        if (pos + 1 <= data.size()) {
            uint8_t comp_len = data[pos];
            pos += 1 + comp_len;
        }
        
        // Extensions
        if (pos + 2 <= data.size()) {
            uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            size_t ext_end = pos + ext_len;
            
            while (pos + 4 <= ext_end && pos + 4 <= data.size()) {
                uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
                uint16_t ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
                pos += 4;
                
                if (ext_type == 0xFF01 && pos + ext_data_len <= data.size()) {
                    result.insert(result.end(), data.begin() + pos, 
                                  data.begin() + pos + ext_data_len);
                }
                pos += ext_data_len;
            }
        }
        
        return result;
    }
    
    return {};
}

// ---- DNS Mimicry -----------------------------------------------------

std::vector<uint8_t> TrafficMimicry::create_dns_query_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // Transaction ID (random)
    dns_transaction_id_ = rng_() & 0xFFFF;
    result.push_back((dns_transaction_id_ >> 8) & 0xFF);
    result.push_back(dns_transaction_id_ & 0xFF);
    
    // Flags (Standard Query)
    result.push_back(0x01);  // RD (Recursion Desired)
    result.push_back(0x00);
    
    // Questions: 1
    result.push_back(0x00);
    result.push_back(0x01);
    
    // Answer/Authority/Additional: 0
    result.push_back(0x00); result.push_back(0x00);  // ANCOUNT
    result.push_back(0x00); result.push_back(0x00);  // NSCOUNT
    result.push_back(0x00); result.push_back(0x01);  // ARCOUNT (for EDNS0)
    
    // Question: encode payload as subdomain labels
    std::string hostname = generate_random_hostname();
    
    // First label: payload length (2 bytes big-endian, hex encoded)
    char len_label[8];
    snprintf(len_label, sizeof(len_label), "%04x", (unsigned)payload.size());
    result.push_back(4);
    result.insert(result.end(), len_label, len_label + 4);
    
    // Subsequent labels: payload data (hex encoded, 63 chars max per label)
    size_t pos = 0;
    while (pos < payload.size()) {
        size_t chunk_size = std::min(size_t(31), payload.size() - pos);  // 31 bytes = 62 hex chars
        result.push_back(static_cast<uint8_t>(chunk_size * 2));
        
        for (size_t i = 0; i < chunk_size; ++i) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", payload[pos + i]);
            result.push_back(hex[0]);
            result.push_back(hex[1]);
        }
        pos += chunk_size;
    }
    
    // Domain suffix
    std::vector<std::string> parts = {"cdn", "net"};
    for (const auto& part : parts) {
        result.push_back(static_cast<uint8_t>(part.size()));
        result.insert(result.end(), part.begin(), part.end());
    }
    result.push_back(0x00);  // Root label
    
    // Type: TXT (16)
    result.push_back(0x00);
    result.push_back(0x10);
    
    // Class: IN (1)
    result.push_back(0x00);
    result.push_back(0x01);
    
    // EDNS0 OPT record
    result.push_back(0x00);  // Root name
    result.push_back(0x00); result.push_back(0x29);  // Type: OPT
    result.push_back(0x10); result.push_back(0x00);  // UDP payload size: 4096
    result.push_back(0x00);  // Extended RCODE
    result.push_back(0x00);  // EDNS version
    result.push_back(0x80); result.push_back(0x00);  // Flags (DO bit)
    result.push_back(0x00); result.push_back(0x00);  // RDATA length
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_dns_response_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // Transaction ID
    result.push_back((dns_transaction_id_ >> 8) & 0xFF);
    result.push_back(dns_transaction_id_ & 0xFF);
    
    // Flags (Standard Response)
    result.push_back(0x81);  // QR=1, RD=1
    result.push_back(0x80);  // RA=1
    
    // Questions: 1, Answers: 1
    result.push_back(0x00); result.push_back(0x01);  // QDCOUNT
    result.push_back(0x00); result.push_back(0x01);  // ANCOUNT
    result.push_back(0x00); result.push_back(0x00);  // NSCOUNT
    result.push_back(0x00); result.push_back(0x00);  // ARCOUNT
    
    // Question (compressed reference will follow)
    std::string qname = "data.cdn.net";
    for (const auto& label : std::vector<std::string>{"data", "cdn", "net"}) {
        result.push_back(static_cast<uint8_t>(label.size()));
        result.insert(result.end(), label.begin(), label.end());
    }
    result.push_back(0x00);
    result.push_back(0x00); result.push_back(0x10);  // Type: TXT
    result.push_back(0x00); result.push_back(0x01);  // Class: IN
    
    // Answer with payload in TXT record
    result.push_back(0xC0); result.push_back(0x0C);  // Name compression pointer
    result.push_back(0x00); result.push_back(0x10);  // Type: TXT
    result.push_back(0x00); result.push_back(0x01);  // Class: IN
    result.push_back(0x00); result.push_back(0x00);  // TTL (high)
    result.push_back(0x00); result.push_back(0x3C);  // TTL: 60 seconds
    
    // RDATA length (payload + 1 for txt length)
    uint16_t rdata_len = static_cast<uint16_t>(payload.size() + 1);
    result.push_back((rdata_len >> 8) & 0xFF);
    result.push_back(rdata_len & 0xFF);
    
    // TXT data
    result.push_back(static_cast<uint8_t>(payload.size()));
    result.insert(result.end(), payload.begin(), payload.end());
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_dns_payload(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 12) return {};
    
    uint16_t flags = (data[2] << 8) | data[3];
    bool is_response = (flags >> 15) & 0x01;
    
    if (is_response) {
        // Find TXT answer
        size_t pos = 12;
        
        // Skip question
        uint16_t qdcount = (data[4] << 8) | data[5];
        for (uint16_t q = 0; q < qdcount && pos < data.size(); ++q) {
            while (pos < data.size() && data[pos] != 0) {
                if ((data[pos] & 0xC0) == 0xC0) {
                    pos += 2;
                    break;
                }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            pos += 4;  // Type + Class
        }
        
        // Find answer
        uint16_t ancount = (data[6] << 8) | data[7];
        for (uint16_t a = 0; a < ancount && pos < data.size(); ++a) {
            // Skip name
            while (pos < data.size() && data[pos] != 0) {
                if ((data[pos] & 0xC0) == 0xC0) {
                    pos += 2;
                    break;
                }
                pos += data[pos] + 1;
            }
            if (pos < data.size() && data[pos] == 0) pos++;
            
            if (pos + 10 > data.size()) break;
            
            uint16_t type = (data[pos] << 8) | data[pos + 1];
            uint16_t rdlength = (data[pos + 8] << 8) | data[pos + 9];
            pos += 10;
            
            if (type == 16 && pos + rdlength <= data.size()) {  // TXT
                uint8_t txt_len = data[pos];
                if (pos + 1 + txt_len <= data.size()) {
                    return std::vector<uint8_t>(data.begin() + pos + 1,
                                                data.begin() + pos + 1 + txt_len);
                }
            }
            pos += rdlength;
        }
    } else {
        // Query: extract from QNAME labels (hex encoded)
        std::vector<uint8_t> result;
        size_t pos = 12;
        
        // First label is length (4 hex chars)
        if (pos >= data.size() || data[pos] != 4) return {};
        pos++;
        
        char len_hex[5] = {0};
        if (pos + 4 > data.size()) return {};
        memcpy(len_hex, &data[pos], 4);
        unsigned int payload_len = 0;
        sscanf(len_hex, "%x", &payload_len);
        pos += 4;
        
        // Read hex-encoded data labels
        while (pos < data.size() && data[pos] != 0 && result.size() < payload_len) {
            uint8_t label_len = data[pos++];
            if (label_len > 62 || pos + label_len > data.size()) break;
            
            for (uint8_t i = 0; i + 1 < label_len && result.size() < payload_len; i += 2) {
                char hex[3] = {(char)data[pos + i], (char)data[pos + i + 1], 0};
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

// ---- QUIC Mimicry ----------------------------------------------------

std::vector<uint8_t> TrafficMimicry::create_quic_initial_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // Header Form + Fixed Bit + Long Packet Type (Initial = 0)
    result.push_back(0xC0 | (rng_() & 0x03));  // Form=1, Fixed=1, Type=Initial
    
    // Version (QUIC v1)
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x01);
    
    // Destination Connection ID
    uint8_t dcid_len = 8;
    result.push_back(dcid_len);
    for (int i = 0; i < dcid_len; ++i) {
        result.push_back(rng_() & 0xFF);
    }
    
    // Source Connection ID  
    uint8_t scid_len = 8;
    result.push_back(scid_len);
    for (int i = 0; i < scid_len; ++i) {
        result.push_back(rng_() & 0xFF);
    }
    
    // Token Length (Variable Length Integer - 0 for initial)
    result.push_back(0x00);
    
    // Payload length (Variable Length Integer - 2 bytes for simplicity)
    uint16_t total_len = static_cast<uint16_t>(payload.size() + 20);  // +20 for AEAD overhead simulation
    result.push_back(0x40 | ((total_len >> 8) & 0x3F));
    result.push_back(total_len & 0xFF);
    
    // Packet Number (4 bytes for simplicity)
    result.push_back((quic_packet_number_ >> 24) & 0xFF);
    result.push_back((quic_packet_number_ >> 16) & 0xFF);
    result.push_back((quic_packet_number_ >> 8) & 0xFF);
    result.push_back(quic_packet_number_ & 0xFF);
    quic_packet_number_++;
    
    // Payload length prefix (for extraction)
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    result.push_back((payload_len >> 24) & 0xFF);
    result.push_back((payload_len >> 16) & 0xFF);
    result.push_back((payload_len >> 8) & 0xFF);
    result.push_back(payload_len & 0xFF);
    
    // Actual payload
    result.insert(result.end(), payload.begin(), payload.end());
    
    // Padding to minimum 1200 bytes (QUIC requirement)
    while (result.size() < 1200) {
        result.push_back(rng_() & 0xFF);
    }
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_quic_payload(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 30) return {};
    
    // Check QUIC long header
    if (!(data[0] & 0x80)) return {};
    
    size_t pos = 5;  // Skip header byte + version
    
    // Skip Destination Connection ID
    if (pos >= data.size()) return {};
    uint8_t dcid_len = data[pos++];
    pos += dcid_len;
    
    // Skip Source Connection ID
    if (pos >= data.size()) return {};
    uint8_t scid_len = data[pos++];
    pos += scid_len;
    
    // Skip token
    if (pos >= data.size()) return {};
    uint8_t token_len = data[pos++];
    pos += token_len;
    
    // Skip length field (Variable Length Integer)
    if (pos >= data.size()) return {};
    if (data[pos] & 0x40) {
        pos += 2;
    } else {
        pos += 1;
    }
    
    // Skip packet number (4 bytes)
    pos += 4;
    
    // Extract payload length prefix
    if (pos + 4 > data.size()) return {};
    uint32_t payload_len = (data[pos] << 24) | (data[pos + 1] << 16) | 
                           (data[pos + 2] << 8) | data[pos + 3];
    pos += 4;
    
    if (pos + payload_len > data.size()) return {};
    
    return std::vector<uint8_t>(data.begin() + pos, 
                                data.begin() + pos + payload_len);
}

// ---- WebSocket Mimicry -----------------------------------------------

std::vector<uint8_t> TrafficMimicry::create_websocket_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // FIN + Opcode (Binary frame = 0x02)
    result.push_back(0x82);
    
    // Mask bit + Payload length
    bool masked = true;  // Client frames are masked
    
    if (payload.size() <= 125) {
        result.push_back((masked ? 0x80 : 0x00) | static_cast<uint8_t>(payload.size()));
    } else if (payload.size() <= 65535) {
        result.push_back((masked ? 0x80 : 0x00) | 126);
        result.push_back((payload.size() >> 8) & 0xFF);
        result.push_back(payload.size() & 0xFF);
    } else {
        result.push_back((masked ? 0x80 : 0x00) | 127);
        for (int i = 7; i >= 0; --i) {
            result.push_back((payload.size() >> (i * 8)) & 0xFF);
        }
    }
    
    // Masking key (4 bytes)
    std::array<uint8_t, 4> mask_key;
    for (int i = 0; i < 4; ++i) {
        mask_key[i] = rng_() & 0xFF;
        result.push_back(mask_key[i]);
    }
    
    // Masked payload
    for (size_t i = 0; i < payload.size(); ++i) {
        result.push_back(payload[i] ^ mask_key[i % 4]);
    }
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::extract_websocket_payload(
    const std::vector<uint8_t>& data) {
    
    if (data.size() < 2) return {};
    
    bool masked = data[1] & 0x80;
    uint64_t payload_len = data[1] & 0x7F;
    size_t pos = 2;
    
    if (payload_len == 126) {
        if (data.size() < 4) return {};
        payload_len = (data[2] << 8) | data[3];
        pos = 4;
    } else if (payload_len == 127) {
        if (data.size() < 10) return {};
        payload_len = 0;
        for (int i = 0; i < 8; ++i) {
            payload_len = (payload_len << 8) | data[2 + i];
        }
        pos = 10;
    }
    
    std::array<uint8_t, 4> mask_key = {0, 0, 0, 0};
    if (masked) {
        if (pos + 4 > data.size()) return {};
        for (int i = 0; i < 4; ++i) {
            mask_key[i] = data[pos++];
        }
    }
    
    if (pos + payload_len > data.size()) return {};
    
    std::vector<uint8_t> result;
    for (uint64_t i = 0; i < payload_len; ++i) {
        result.push_back(data[pos + i] ^ mask_key[i % 4]);
    }
    
    return result;
}

// ---- Application-Specific Mimicry -----------------------------------

std::vector<uint8_t> TrafficMimicry::create_bittorrent_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // BitTorrent Protocol handshake format
    // pstrlen (1 byte) + pstr (19 bytes) + reserved (8 bytes) + info_hash (20 bytes) + peer_id (20 bytes)
    
    // Protocol string length
    result.push_back(19);
    
    // Protocol string "BitTorrent protocol"
    const char* pstr = "BitTorrent protocol";
    result.insert(result.end(), pstr, pstr + 19);
    
    // Reserved bytes (embed payload length in first 4)
    uint32_t payload_len = static_cast<uint32_t>(payload.size());
    result.push_back((payload_len >> 24) & 0xFF);
    result.push_back((payload_len >> 16) & 0xFF);
    result.push_back((payload_len >> 8) & 0xFF);
    result.push_back(payload_len & 0xFF);
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x10);  // Extension protocol support
    
    // Info hash (20 bytes) - embed first 20 bytes of payload
    size_t hash_len = std::min(payload.size(), size_t(20));
    result.insert(result.end(), payload.begin(), payload.begin() + hash_len);
    while (result.size() < 48 + hash_len) {
        result.push_back(rng_() & 0xFF);
    }
    
    // Peer ID (20 bytes) - random
    for (int i = 0; i < 20; ++i) {
        result.push_back(rng_() & 0xFF);
    }
    
    // Remaining payload as "piece" message
    if (payload.size() > 20) {
        // Message length
        uint32_t msg_len = static_cast<uint32_t>(payload.size() - 20 + 9);
        result.push_back((msg_len >> 24) & 0xFF);
        result.push_back((msg_len >> 16) & 0xFF);
        result.push_back((msg_len >> 8) & 0xFF);
        result.push_back(msg_len & 0xFF);
        
        // Message ID (7 = piece)
        result.push_back(0x07);
        
        // Index (4 bytes)
        result.push_back(0x00);
        result.push_back(0x00);
        result.push_back(0x00);
        result.push_back(0x00);
        
        // Begin (4 bytes)
        result.push_back(0x00);
        result.push_back(0x00);
        result.push_back(0x00);
        result.push_back(0x00);
        
        // Block (rest of payload)
        result.insert(result.end(), payload.begin() + 20, payload.end());
    }
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_skype_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // Skype-like UDP packet structure
    // Object ID (2 bytes)
    result.push_back(rng_() & 0xFF);
    result.push_back(rng_() & 0xFF);
    
    // Type/Flags
    result.push_back(0x02);  // Data packet
    result.push_back(0x00);
    
    // Sequence number
    result.push_back((tls_sequence_number_ >> 8) & 0xFF);
    result.push_back(tls_sequence_number_ & 0xFF);
    tls_sequence_number_++;
    
    // Payload length
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    
    // Payload
    result.insert(result.end(), payload.begin(), payload.end());
    
    // Padding to typical VoIP packet size
    while (result.size() < 160) {
        result.push_back(rng_() & 0xFF);
    }
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_zoom_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // Zoom-like RTP/SRTP packet structure
    // Version (2) + Padding (0) + Extension (1) + CC (0)
    result.push_back(0x90);
    
    // Marker + Payload Type (96 = dynamic)
    result.push_back(0x60);
    
    // Sequence number
    result.push_back((tls_sequence_number_ >> 8) & 0xFF);
    result.push_back(tls_sequence_number_ & 0xFF);
    tls_sequence_number_++;
    
    // Timestamp
    uint32_t timestamp = static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count());
    result.push_back((timestamp >> 24) & 0xFF);
    result.push_back((timestamp >> 16) & 0xFF);
    result.push_back((timestamp >> 8) & 0xFF);
    result.push_back(timestamp & 0xFF);
    
    // SSRC
    for (int i = 0; i < 4; ++i) {
        result.push_back(rng_() & 0xFF);
    }
    
    // Extension header (payload length embedded)
    result.push_back(0xBE);
    result.push_back(0xDE);
    uint16_t ext_len = static_cast<uint16_t>((payload.size() + 3) / 4);  // In 32-bit words
    result.push_back((ext_len >> 8) & 0xFF);
    result.push_back(ext_len & 0xFF);
    
    // Payload length (2 bytes)
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    
    // Payload with padding to 4-byte boundary
    result.insert(result.end(), payload.begin(), payload.end());
    while (result.size() % 4 != 0) {
        result.push_back(0x00);
    }
    
    return result;
}

// ---- Generic Wrappers ------------------------------------------------

std::vector<uint8_t> TrafficMimicry::create_generic_tcp_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // Simple length-prefixed format
    uint32_t len = static_cast<uint32_t>(payload.size());
    result.push_back((len >> 24) & 0xFF);
    result.push_back((len >> 16) & 0xFF);
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    
    result.insert(result.end(), payload.begin(), payload.end());
    
    // Optional padding
    if (config_.enable_size_mimicry && config_.max_padding > 0) {
        auto padding = generate_random_padding(config_.min_padding, config_.max_padding);
        result.insert(result.end(), padding.begin(), padding.end());
    }
    
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_generic_udp_wrapper(
    const std::vector<uint8_t>& payload) {
    
    std::vector<uint8_t> result;
    
    // 2-byte length prefix for UDP
    uint16_t len = static_cast<uint16_t>(payload.size());
    result.push_back((len >> 8) & 0xFF);
    result.push_back(len & 0xFF);
    
    result.insert(result.end(), payload.begin(), payload.end());
    
    return result;
}

// ---- Utilities -------------------------------------------------------

std::string TrafficMimicry::generate_random_http_path() {
    static const std::vector<std::string> paths = {
        "/api/v1/data",
        "/cdn/assets/main.js",
        "/static/images/logo.png",
        "/analytics/collect",
        "/api/user/profile",
        "/content/article",
        "/search",
        "/feed/updates",
        "/notifications",
        "/api/sync"
    };
    
    std::uniform_int_distribution<size_t> dist(0, paths.size() - 1);
    return paths[dist(rng_)];
}

std::string TrafficMimicry::generate_random_user_agent() {
    static const std::vector<std::string> agents = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    };
    
    std::uniform_int_distribution<size_t> dist(0, agents.size() - 1);
    return agents[dist(rng_)];
}

std::string TrafficMimicry::generate_random_hostname() {
    static const std::vector<std::string> domains = {
        "www.google.com",
        "cdn.cloudflare.com",
        "api.microsoft.com",
        "static.akamaized.net",
        "assets.github.com",
        "media.amazonaws.com",
        "fonts.googleapis.com",
        "ajax.googleapis.com",
        "cdn.jsdelivr.net",
        "unpkg.com"
    };
    
    std::uniform_int_distribution<size_t> dist(0, domains.size() - 1);
    return domains[dist(rng_)];
}

uint16_t TrafficMimicry::generate_random_port() {
    static const std::vector<uint16_t> common_ports = {
        80, 443, 8080, 8443, 3000, 5000, 8000, 9000
    };
    
    std::uniform_int_distribution<size_t> dist(0, common_ports.size() - 1);
    return common_ports[dist(rng_)];
}

std::vector<uint8_t> TrafficMimicry::generate_random_padding(
    size_t min_size, size_t max_size) {
    
    std::uniform_int_distribution<size_t> size_dist(min_size, max_size);
    size_t pad_size = size_dist(rng_);
    
    std::vector<uint8_t> padding(pad_size);
    for (size_t i = 0; i < pad_size; ++i) {
        padding[i] = rng_() & 0xFF;
    }
    
    return padding;
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
            // HTTP: typical RTT 50-200ms
            base_delay = 75;
            jitter = 50;
            break;
            
        case MimicProfile::HTTPS_CLIENT_HELLO:
        case MimicProfile::HTTPS_APPLICATION:
            // HTTPS: similar to HTTP with TLS overhead
            base_delay = 100;
            jitter = 75;
            break;
            
        case MimicProfile::DNS_QUERY:
        case MimicProfile::DNS_RESPONSE:
            // DNS: typically fast, 10-50ms
            base_delay = 20;
            jitter = 15;
            break;
            
        case MimicProfile::QUIC_INITIAL:
            // QUIC: optimized, 30-100ms
            base_delay = 50;
            jitter = 30;
            break;
            
        case MimicProfile::WEBSOCKET:
            // WebSocket: persistent, low latency 5-30ms
            base_delay = 10;
            jitter = 10;
            break;
            
        case MimicProfile::SKYPE:
        case MimicProfile::ZOOM:
            // VoIP/Video: real-time, 20ms intervals
            base_delay = 20;
            jitter = 5;
            break;
            
        case MimicProfile::BITTORRENT:
            // P2P: variable, 100-500ms
            base_delay = 200;
            jitter = 150;
            break;
            
        default:
            base_delay = 50;
            jitter = 25;
            break;
    }
    
    // Add size-based delay (larger packets = slightly longer)
    base_delay += static_cast<int>(packet_size / 1000);
    
    std::uniform_int_distribution<int> dist(-jitter, jitter);
    int final_delay = std::max(config_.min_inter_packet_delay, 
                               std::min(config_.max_inter_packet_delay, 
                                        base_delay + dist(rng_)));
    
    return std::chrono::milliseconds(final_delay);
}

} // namespace ncp
