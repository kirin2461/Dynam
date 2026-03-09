/**
 * @file ncp_covert_channel.cpp
 * @brief CovertChannelManager implementation
 */

#include "ncp_covert_channel.hpp"
#include "ncp_csprng.hpp"
#include "ncp_logger.hpp"
#include "ncp_config.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cassert>

namespace ncp {

// =====================================================================
// RFC 4648 base32 alphabet (uppercase A–Z, 2–7)
// We store lowercase in DNS labels.
// =====================================================================

static const char BASE32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// =====================================================================
// CovertChannelStats
// =====================================================================

void CovertChannelStats::reset() noexcept {
    messages_sent.store(0);
    messages_received.store(0);
    bytes_hidden.store(0);
    bytes_extracted.store(0);
    channel_switches.store(0);
    encoding_errors.store(0);
}

// =====================================================================
// Construction
// =====================================================================

CovertChannelManager::CovertChannelManager() {
    // Apply config key overrides from Config::instance()
    config_.enabled = Config::instance().getBool("covert_channel.enabled", false);
    config_.dns_cover_domain = Config::instance().get(
        "covert_channel.dns_cover_domain", "cdn-static.example.com");
    config_.max_bytes_per_message = static_cast<size_t>(
        Config::instance().getInt("covert_channel.max_bytes_per_message", 512));

    // Default cover headers
    config_.cover_headers = {
        "X-Request-ID",
        "X-Correlation-ID",
        "X-Trace-ID",
        "X-Session-Token"
    };

    NCP_LOG_DEBUG("CovertChannelManager: initialized (default config)");
}

CovertChannelManager::CovertChannelManager(const CovertChannelConfig& cfg)
    : config_(cfg)
{
    // Ensure default cover headers if none supplied
    if (config_.cover_headers.empty()) {
        config_.cover_headers = {
            "X-Request-ID",
            "X-Correlation-ID",
            "X-Trace-ID",
            "X-Session-Token"
        };
    }
    NCP_LOG_DEBUG("CovertChannelManager: initialized (custom config)");
}

// =====================================================================
// Accessors
// =====================================================================

void CovertChannelManager::set_config(const CovertChannelConfig& cfg) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = cfg;
    if (config_.cover_headers.empty()) {
        config_.cover_headers = {
            "X-Request-ID", "X-Correlation-ID",
            "X-Trace-ID",   "X-Session-Token"
        };
    }
}

CovertChannelConfig CovertChannelManager::get_config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

CovertChannelStats CovertChannelManager::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void CovertChannelManager::reset_stats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.reset();
}

void CovertChannelManager::set_threat_level(ncp::DPI::ThreatLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    threat_level_ = level;
    NCP_LOG_DEBUG(std::string("CovertChannelManager: threat level set to ") +
        std::to_string(static_cast<int>(level)));
}

// =====================================================================
// Internal helpers
// =====================================================================

CovertChannelType CovertChannelManager::active_channel_() const {
    // Called under lock
    return using_fallback_ ? config_.fallback_channel : config_.primary_channel;
}

bool CovertChannelManager::should_activate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_.enabled &&
           (threat_level_ >= ncp::DPI::ThreatLevel::CRITICAL);
}

void CovertChannelManager::switch_to_fallback() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!using_fallback_) {
        using_fallback_ = true;
        stats_.channel_switches.fetch_add(1);
        NCP_LOG_INFO("CovertChannelManager: switched to fallback channel");
    }
}

// =====================================================================
// Base32 encode (RFC 4648, no padding, lowercase output)
// =====================================================================

std::string CovertChannelManager::base32_encode_(const std::vector<uint8_t>& data) {
    std::string out;
    if (data.empty()) return out;

    out.reserve((data.size() * 8 + 4) / 5);

    uint32_t buffer = 0;
    int      bits   = 0;

    for (uint8_t byte : data) {
        buffer = (buffer << 8) | byte;
        bits  += 8;
        while (bits >= 5) {
            bits -= 5;
            out += static_cast<char>(
                std::tolower(static_cast<unsigned char>(
                    BASE32_ALPHA[(buffer >> bits) & 0x1F])));
        }
    }
    if (bits > 0) {
        out += static_cast<char>(
            std::tolower(static_cast<unsigned char>(
                BASE32_ALPHA[(buffer << (5 - bits)) & 0x1F])));
    }
    return out;
}

// =====================================================================
// Base32 decode (RFC 4648 alphabet, case-insensitive)
// =====================================================================

std::vector<uint8_t> CovertChannelManager::base32_decode_(const std::string& encoded) {
    std::vector<uint8_t> out;
    if (encoded.empty()) return out;

    auto char_to_val = [](char c) -> int {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= '2' && c <= '7') return 26 + (c - '2');
        return -1; // invalid
    };

    uint32_t buffer = 0;
    int      bits   = 0;
    out.reserve(encoded.size() * 5 / 8);

    for (char ch : encoded) {
        if (ch == '=') break; // padding — stop
        int val = char_to_val(ch);
        if (val < 0) continue; // skip unknown chars

        buffer = (buffer << 5) | static_cast<uint32_t>(val);
        bits  += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

// =====================================================================
// chunk_data_
// =====================================================================

std::vector<std::vector<uint8_t>> CovertChannelManager::chunk_data_(
    const std::vector<uint8_t>& data, size_t max_chunk)
{
    std::vector<std::vector<uint8_t>> chunks;
    if (max_chunk == 0 || data.empty()) return chunks;

    size_t offset = 0;
    while (offset < data.size()) {
        size_t end = std::min(offset + max_chunk, data.size());
        chunks.emplace_back(data.begin() + static_cast<ptrdiff_t>(offset),
                            data.begin() + static_cast<ptrdiff_t>(end));
        offset = end;
    }
    return chunks;
}

// =====================================================================
// encode_dns_query
// =====================================================================

std::string CovertChannelManager::encode_dns_query(const std::vector<uint8_t>& data) {
    // Determine label length (max chars per DNS label)
    const size_t max_label_len = config_.max_label_length;

    // Encode all data as base32
    std::string b32 = base32_encode_(data);

    // Split b32 string into label-sized pieces
    std::string query_name;
    size_t pos   = 0;
    size_t count = 0;
    while (pos < b32.size() && count < config_.max_subdomain_labels) {
        size_t len = std::min(max_label_len, b32.size() - pos);
        if (!query_name.empty()) query_name += '.';
        query_name += b32.substr(pos, len);
        pos   += len;
        count += 1;
    }

    // Append cover domain
    if (!query_name.empty()) query_name += '.';
    query_name += config_.dns_cover_domain;

    NCP_LOG_DEBUG("CovertChannelManager: DNS query encoded, labels=" +
        std::to_string(count) + " query=" + query_name);
    return query_name;
}

// =====================================================================
// decode_dns_query
// =====================================================================

std::vector<uint8_t> CovertChannelManager::decode_dns_query(const std::string& query_name) {
    // Strip the cover domain suffix
    std::string cover = config_.dns_cover_domain;
    std::string name  = query_name;

    // Find where cover domain starts
    size_t suffix_pos = name.rfind('.' + cover);
    if (suffix_pos == std::string::npos) {
        // Try without leading dot
        if (name.size() >= cover.size() &&
            name.substr(name.size() - cover.size()) == cover) {
            suffix_pos = name.size() - cover.size();
            if (suffix_pos > 0) suffix_pos -= 1; // remove preceding dot
        } else {
            NCP_LOG_WARN("CovertChannelManager: DNS decode failed — cover domain not found");
            return {};
        }
    }
    // Extract the encoded part (everything before .cover_domain)
    std::string encoded_part = name.substr(0, suffix_pos);

    // Concatenate labels (remove dots)
    std::string b32;
    b32.reserve(encoded_part.size());
    for (char c : encoded_part) {
        if (c != '.') b32 += c;
    }

    return base32_decode_(b32);
}

// =====================================================================
// encode_http_headers
// =====================================================================

std::string CovertChannelManager::encode_http_headers(const std::vector<uint8_t>& data) {
    // We distribute the data across available cover headers.
    // Each header value = realistic prefix (UUID-like hex) + STEGO_MARKER_ + hex(chunk)
    //
    // Example:
    //   X-Request-ID: a1b2c3d4-ncp1-<hexdata>
    //   X-Correlation-ID: e5f6a7b8-ncp1-<hexdata>

    const auto& headers = config_.cover_headers;
    if (headers.empty()) {
        NCP_LOG_ERROR("CovertChannelManager: no cover headers configured");
        stats_.encoding_errors.fetch_add(1);
        return {};
    }

    // Split data into one chunk per header (round-robin)
    size_t bytes_per_header = (config_.max_header_payload + headers.size() - 1)
                               / headers.size();
    auto chunks = chunk_data_(data, bytes_per_header);

    std::ostringstream oss;
    for (size_t i = 0; i < chunks.size() && i < headers.size(); ++i) {
        // Generate a realistic-looking prefix (8 hex chars from CSPRNG)
        uint32_t rand_prefix = csprng_uint32();
        oss << headers[i] << ": ";
        oss << std::hex << std::setw(8) << std::setfill('0') << rand_prefix;
        oss << '-' << STEGO_MARKER_ << '-';

        // Encode chunk as hex
        for (uint8_t b : chunks[i]) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(b);
        }
        oss << "\r\n";
    }

    NCP_LOG_DEBUG("CovertChannelManager: HTTP headers encoded, chunks=" +
        std::to_string(chunks.size()));
    return oss.str();
}

// =====================================================================
// decode_http_headers
// =====================================================================

std::vector<uint8_t> CovertChannelManager::decode_http_headers(const std::string& headers) {
    // Scan each line for STEGO_MARKER_ and extract hex after it
    std::vector<uint8_t> result;
    std::istringstream ss(headers);
    std::string line;
    std::string marker = std::string("-") + STEGO_MARKER_ + "-";

    while (std::getline(ss, line)) {
        // Strip trailing \r
        if (!line.empty() && line.back() == '\r') line.pop_back();

        size_t mpos = line.find(marker);
        if (mpos == std::string::npos) continue;

        std::string hex_part = line.substr(mpos + marker.size());
        // Remove any trailing whitespace
        while (!hex_part.empty() &&
               (hex_part.back() == ' ' || hex_part.back() == '\t')) {
            hex_part.pop_back();
        }

        // Decode pairs of hex digits
        for (size_t i = 0; i + 1 < hex_part.size(); i += 2) {
            try {
                uint8_t byte = static_cast<uint8_t>(
                    std::stoi(hex_part.substr(i, 2), nullptr, 16));
                result.push_back(byte);
            } catch (...) {
                break;
            }
        }
    }

    NCP_LOG_DEBUG("CovertChannelManager: HTTP headers decoded, bytes=" +
        std::to_string(result.size()));
    return result;
}

// =====================================================================
// Cookie stego helpers
// =====================================================================

std::string CovertChannelManager::generate_cover_cookie_(const std::vector<uint8_t>& data) {
    // Cookie value = base32(data) — only uses chars allowed in cookie values
    std::string cookie_val = base32_encode_(data);
    return "ncpsess=" + cookie_val;
}

std::vector<uint8_t> CovertChannelManager::extract_from_cookie_(const std::string& cookie) {
    const std::string prefix = "ncpsess=";
    size_t pos = cookie.find(prefix);
    if (pos == std::string::npos) return {};
    std::string encoded = cookie.substr(pos + prefix.size());
    // Remove any trailing semicolon or whitespace
    auto end = encoded.find_first_of("; \t\r\n");
    if (end != std::string::npos) encoded = encoded.substr(0, end);
    return base32_decode_(encoded);
}

// =====================================================================
// Generic encode / decode dispatch
// =====================================================================

std::vector<uint8_t> CovertChannelManager::encode(
    const std::vector<uint8_t>& payload,
    CovertChannelType channel)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (payload.size() > config_.max_bytes_per_message) {
        NCP_LOG_WARN("CovertChannelManager: payload exceeds max_bytes_per_message, truncating");
    }

    std::vector<uint8_t> limited(
        payload.begin(),
        payload.begin() + static_cast<ptrdiff_t>(
            std::min(payload.size(), config_.max_bytes_per_message)));

    std::vector<uint8_t> result;
    try {
        switch (channel) {
        case CovertChannelType::DNS_SUBDOMAIN:
        case CovertChannelType::DNS_TXT_RECORD: {
            std::string q = encode_dns_query(limited);
            result.assign(q.begin(), q.end());
            break;
        }
        case CovertChannelType::HTTP_HEADER_STEGO:
        case CovertChannelType::HTTPS_PADDING: {
            std::string h = encode_http_headers(limited);
            result.assign(h.begin(), h.end());
            break;
        }
        case CovertChannelType::HTTP_COOKIE_STEGO: {
            std::string c = generate_cover_cookie_(limited);
            result.assign(c.begin(), c.end());
            break;
        }
        }
        stats_.messages_sent.fetch_add(1);
        stats_.bytes_hidden.fetch_add(limited.size());
    } catch (const std::exception& ex) {
        NCP_LOG_ERROR(std::string("CovertChannelManager::encode exception: ") + ex.what());
        stats_.encoding_errors.fetch_add(1);
    }
    return result;
}

std::vector<uint8_t> CovertChannelManager::decode(
    const std::vector<uint8_t>& cover_message,
    CovertChannelType channel)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string msg(cover_message.begin(), cover_message.end());

    std::vector<uint8_t> result;
    try {
        switch (channel) {
        case CovertChannelType::DNS_SUBDOMAIN:
        case CovertChannelType::DNS_TXT_RECORD:
            result = decode_dns_query(msg);
            break;
        case CovertChannelType::HTTP_HEADER_STEGO:
        case CovertChannelType::HTTPS_PADDING:
            result = decode_http_headers(msg);
            break;
        case CovertChannelType::HTTP_COOKIE_STEGO:
            result = extract_from_cookie_(msg);
            break;
        }
        if (!result.empty()) {
            stats_.messages_received.fetch_add(1);
            stats_.bytes_extracted.fetch_add(result.size());
        }
    } catch (const std::exception& ex) {
        NCP_LOG_ERROR(std::string("CovertChannelManager::decode exception: ") + ex.what());
        stats_.encoding_errors.fetch_add(1);
    }
    return result;
}

} // namespace ncp
