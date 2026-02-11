#include "../include/ncp_mimicry.hpp"
#include <sstream>
#include <algorithm>

namespace NCP {

TrafficMimicry::TrafficMimicry() : rng_(std::random_device{}()) {}
TrafficMimicry::~TrafficMimicry() {}

std::vector<uint8_t> TrafficMimicry::wrap_payload(const std::vector<uint8_t>& payload, MimicProfile profile) {
    switch (profile) {
        case MimicProfile::HTTP_GET:
            return create_http_get_wrapper(payload);
        case MimicProfile::HTTPS_CLIENT_HELLO:
            return create_https_hello_wrapper(payload);
        default:
            return payload;
    }
}

std::vector<uint8_t> TrafficMimicry::unwrap_payload(const std::vector<uint8_t>& mimicked_data, MimicProfile profile) {
    // Basic implementation: find payload marker or offset
    if (profile == MimicProfile::HTTP_GET) {
        // Look for double newline (end of headers)
        std::string s(mimicked_data.begin(), mimicked_data.end());
        size_t pos = s.find("\r\n\r\n");
        if (pos != std::string::npos) {
            return std::vector<uint8_t>(mimicked_data.begin() + pos + 4, mimicked_data.end());
        }
    }
    return mimicked_data;
}

std::vector<uint8_t> TrafficMimicry::create_http_get_wrapper(const std::vector<uint8_t>& payload) {
    std::ostringstream oss;
    oss << "GET /index.html HTTP/1.1\r\n";
    oss << "Host: www.google.com\r\n";
    oss << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n";
    oss << "Accept: */*\r\n";
    oss << "Content-Length: " << payload.size() << "\r\n";
    oss << "\r\n";
    
    std::string headers = oss.str();
    std::vector<uint8_t> result(headers.begin(), headers.end());
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<uint8_t> TrafficMimicry::create_https_hello_wrapper(const std::vector<uint8_t>& payload) {
    // Simplified TLS ClientHello structure for mimicry
    std::vector<uint8_t> result = {
        0x16, 0x03, 0x01, // Handshake, TLS 1.0
        0x00, 0x00        // Length (placeholder)
    };
    
    // Handshake header
    result.push_back(0x01); // ClientHello
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00); // Length (placeholder)
    
    // Payload as part of the extensions or session ID
    result.insert(result.end(), payload.begin(), payload.end());
    
    // Update lengths (simplified)
    uint16_t total_len = result.size() - 5;
    result[3] = (total_len >> 8) & 0xFF;
    result[4] = total_len & 0xFF;
    
    return result;
}

} // namespace NCP
