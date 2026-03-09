#pragma once
/**
 * @file ncp_covert_channel.hpp
 * @brief DNS/HTTP steganography covert channel manager
 *
 * Activated when threat_level >= CRITICAL. Encodes data into
 * DNS query subdomain labels (base32) or HTTP header fields.
 * Supports primary + fallback channel with automatic switching.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#include "ncp_orchestrator.hpp"   // ncp::DPI::ThreatLevel

namespace ncp {

// =====================================================================
// Enumerations
// =====================================================================

enum class CovertChannelType {
    DNS_SUBDOMAIN,      ///< Encode data in subdomain labels: <base32data>.example.com
    DNS_TXT_RECORD,     ///< Encode in TXT record queries/responses
    HTTP_HEADER_STEGO,  ///< Hide data in HTTP header ordering / values
    HTTP_COOKIE_STEGO,  ///< Encode in cookie values using allowed chars
    HTTPS_PADDING       ///< Data in TLS record padding bytes
};

// =====================================================================
// Configuration
// =====================================================================

struct CovertChannelConfig {
    bool enabled = false;   ///< Only activated at CRITICAL threat

    CovertChannelType primary_channel  = CovertChannelType::DNS_SUBDOMAIN;
    CovertChannelType fallback_channel = CovertChannelType::HTTP_HEADER_STEGO;

    // --- DNS channel settings ---
    std::string dns_cover_domain  = "cdn-static.example.com";
    size_t max_label_length       = 63;   ///< DNS label max (RFC 1035)
    size_t max_subdomain_labels   = 4;    ///< Max encoded labels per query

    // --- HTTP channel settings ---
    size_t max_header_payload = 256;      ///< Max bytes hidden per HTTP request
    std::vector<std::string> cover_headers;  ///< Headers to use for stego

    // --- Performance ---
    size_t max_bytes_per_message    = 512;
    double channel_bandwidth_bps    = 1000.0;  ///< Target bandwidth (bytes/sec)
};

// =====================================================================
// Statistics
// =====================================================================

struct CovertChannelStats {
    std::atomic<uint64_t> messages_sent{0};
    std::atomic<uint64_t> messages_received{0};
    std::atomic<uint64_t> bytes_hidden{0};
    std::atomic<uint64_t> bytes_extracted{0};
    std::atomic<uint64_t> channel_switches{0};
    std::atomic<uint64_t> encoding_errors{0};

    void reset() noexcept;

    // Copyable stats (required for atomic members)
    CovertChannelStats() = default;
    CovertChannelStats(const CovertChannelStats& o) noexcept
        : messages_sent(o.messages_sent.load())
        , messages_received(o.messages_received.load())
        , bytes_hidden(o.bytes_hidden.load())
        , bytes_extracted(o.bytes_extracted.load())
        , channel_switches(o.channel_switches.load())
        , encoding_errors(o.encoding_errors.load())
    {}
    CovertChannelStats& operator=(const CovertChannelStats& o) noexcept {
        if (this != &o) {
            messages_sent.store(o.messages_sent.load());
            messages_received.store(o.messages_received.load());
            bytes_hidden.store(o.bytes_hidden.load());
            bytes_extracted.store(o.bytes_extracted.load());
            channel_switches.store(o.channel_switches.load());
            encoding_errors.store(o.encoding_errors.load());
        }
        return *this;
    }
};

// =====================================================================
// Main class
// =====================================================================

class CovertChannelManager {
public:
    CovertChannelManager();
    explicit CovertChannelManager(const CovertChannelConfig& cfg);

    // -----------------------------------------------------------------
    // Generic encode / decode
    // -----------------------------------------------------------------

    /**
     * @brief Encode payload into a covert channel message.
     * @param payload  Raw bytes to hide.
     * @param channel  Target channel type.
     * @return Cover message bytes (DNS query string, HTTP headers, etc.)
     *         as a raw byte buffer.
     */
    std::vector<uint8_t> encode(const std::vector<uint8_t>& payload,
                                CovertChannelType channel = CovertChannelType::DNS_SUBDOMAIN);

    /**
     * @brief Decode payload from a covert channel message.
     * @param cover_message  Raw cover message bytes.
     * @param channel        Channel type used during encoding.
     * @return Recovered payload bytes (empty on failure).
     */
    std::vector<uint8_t> decode(const std::vector<uint8_t>& cover_message,
                                CovertChannelType channel = CovertChannelType::DNS_SUBDOMAIN);

    // -----------------------------------------------------------------
    // DNS-specific helpers
    // -----------------------------------------------------------------

    /**
     * @brief Generate a DNS query name with data embedded as base32 labels.
     *
     * Format: <label0>.<label1>...<labelN>.<cover_domain>
     * e.g.  aebagbaf.cdab.cdn-static.example.com
     *
     * @param data  Bytes to embed.
     * @return Full DNS query name string.
     */
    std::string encode_dns_query(const std::vector<uint8_t>& data);

    /**
     * @brief Extract data from a DNS query name produced by encode_dns_query().
     * @param query_name  Full DNS query name.
     * @return Decoded bytes (empty on failure).
     */
    std::vector<uint8_t> decode_dns_query(const std::string& query_name);

    // -----------------------------------------------------------------
    // HTTP-specific helpers
    // -----------------------------------------------------------------

    /**
     * @brief Produce HTTP header block with data encoded in header values.
     *
     * Uses cover_headers (X-Request-ID, X-Correlation-ID, etc.) and
     * encodes payload chunks as realistic-looking hex values.
     *
     * @param data  Bytes to embed.
     * @return Multi-line HTTP header block string.
     */
    std::string encode_http_headers(const std::vector<uint8_t>& data);

    /**
     * @brief Extract data from an HTTP header block produced by encode_http_headers().
     * @param headers  Raw HTTP header block.
     * @return Decoded bytes (empty on failure).
     */
    std::vector<uint8_t> decode_http_headers(const std::string& headers);

    // -----------------------------------------------------------------
    // Control
    // -----------------------------------------------------------------

    /// Returns true when threat_level_ >= CRITICAL and channel is enabled.
    bool should_activate() const;

    /// Switch active channel to the configured fallback.
    void switch_to_fallback();

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------

    void                 set_config(const CovertChannelConfig& cfg);
    CovertChannelConfig  get_config() const;
    CovertChannelStats   get_stats()  const;
    void                 reset_stats();
    void                 set_threat_level(ncp::DPI::ThreatLevel level);

private:
    CovertChannelConfig         config_;
    CovertChannelStats          stats_;
    mutable std::mutex          mutex_;
    ncp::DPI::ThreatLevel       threat_level_ = ncp::DPI::ThreatLevel::NONE;
    bool                        using_fallback_ = false;

    // -----------------------------------------------------------------
    // Base32 (RFC 4648, no padding) — lowercase for DNS labels
    // -----------------------------------------------------------------
    static std::string              base32_encode_(const std::vector<uint8_t>& data);
    static std::vector<uint8_t>     base32_decode_(const std::string& encoded);

    // -----------------------------------------------------------------
    // HTTP cookie stego helpers
    // -----------------------------------------------------------------
    std::string             generate_cover_cookie_(const std::vector<uint8_t>& data);
    std::vector<uint8_t>    extract_from_cookie_(const std::string& cookie);

    // -----------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------
    /// Split data into chunks of at most max_chunk bytes each.
    static std::vector<std::vector<uint8_t>> chunk_data_(
        const std::vector<uint8_t>& data, size_t max_chunk);

    /// Return the active channel type (primary or fallback).
    CovertChannelType active_channel_() const;

    // Sentinel value embedded in header values to mark stego content.
    static constexpr char STEGO_MARKER_[] = "ncp1";
};

} // namespace ncp
