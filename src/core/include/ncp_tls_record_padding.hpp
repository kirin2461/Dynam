#ifndef NCP_TLS_RECORD_PADDING_HPP
#define NCP_TLS_RECORD_PADDING_HPP

/**
 * @file ncp_tls_record_padding.hpp
 * @brief TLS Record Padding (Channel #4)
 *
 * Thin wrapper around the existing TrafficPadder that operates
 * specifically on TLS Application-Data records (content type 0x17).
 *
 * Approach:
 *   - Parses incoming TLS record header (5 bytes: type, version, length)
 *   - Delegates padding generation to TrafficPadder (HMAC-authenticated,
 *     CSPRNG-backed random fill)
 *   - Appends RFC 8446 §5.4-style padding to the plaintext fragment
 *     before the record is encrypted, OR pads the entire record payload
 *     to a uniform bucket size (power-of-two) to defeat length-based
 *     traffic analysis
 *   - Updates the TLS record length field accordingly
 *
 * Two APIs for different integration points:
 *
 *   pad_plaintext() / unpad_plaintext()
 *     Pre-encryption padding per RFC 8446 §5.4.
 *     Zero-fill padding. Receiver scans backwards past 0x00 bytes
 *     to recover the content type byte.
 *
 *   pad_record()
 *     Post-encryption padding for already-encrypted TLS records.
 *     CSPRNG-fill padding (indistinguishable from ciphertext).
 *     Receiver strips by comparing wire length vs expected ciphertext
 *     length, or by peer-agreed target size.
 *
 * Thread-safety: config_ and stats_ are protected by mutex_.
 * TrafficPadder has its own internal lock.
 */

#include "ncp_security.hpp"
#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>

namespace ncp {

/// Padding strategy for TLS records
enum class TLSPaddingStrategy {
    /// Pad to next power-of-two bucket (defeats exact length fingerprinting)
    BUCKET_POW2,
    /// Pad to a fixed block size (e.g., 128, 256, 512 bytes)
    FIXED_BLOCK,
    /// Random padding within [min, max] range (delegates to TrafficPadder)
    RANDOM_RANGE,
    /// Pad all records to max_size (constant-length, maximum privacy)
    CONSTANT_LENGTH,
};

struct TLSRecordPaddingConfig {
    bool enabled = true;
    TLSPaddingStrategy strategy = TLSPaddingStrategy::BUCKET_POW2;
    uint16_t fixed_block_size = 128;       ///< For FIXED_BLOCK strategy
    uint16_t min_padding = 0;              ///< For RANDOM_RANGE strategy
    uint16_t max_padding = 256;            ///< For RANDOM_RANGE / upper bound
    uint16_t max_record_size = 16384;      ///< TLS max: 2^14 = 16384
    bool pad_only_app_data = true;         ///< Only pad content type 0x17
};

struct TLSRecordPaddingStats {
    uint64_t records_processed = 0;
    uint64_t records_padded = 0;
    uint64_t total_padding_bytes = 0;
    uint64_t records_skipped = 0;          ///< Non-app-data or too large
};

/**
 * @brief TLS Record Padding engine
 *
 * Minimal code — reuses TrafficPadder for CSPRNG and HMAC.
 *
 * Two modes:
 *   - pad_plaintext(): RFC 8446 §5.4 inner plaintext (pre-encryption, zero-fill)
 *   - pad_record(): post-encryption record extension (CSPRNG-fill)
 */
class TLSRecordPadding {
public:
    explicit TLSRecordPadding(
        const TLSRecordPaddingConfig& config = {},
        TrafficPadder* external_padder = nullptr);

    ~TLSRecordPadding() = default;

    // Non-copyable
    TLSRecordPadding(const TLSRecordPadding&) = delete;
    TLSRecordPadding& operator=(const TLSRecordPadding&) = delete;

    /**
     * @brief Pad a plaintext fragment before TLS encryption (RFC 8446 §5.4).
     *
     * Produces inner plaintext: [content][content_type][zeros...]
     * Zero-fill padding — receiver uses unpad_plaintext() to scan
     * backwards past 0x00 bytes to recover the real content type.
     *
     * @param plaintext  The plaintext content to be placed in a TLS record.
     * @param content_type  TLS content type (0x17 = Application Data).
     * @return Padded inner plaintext. If disabled or too large, returns input as-is.
     */
    std::vector<uint8_t> pad_plaintext(
        const std::vector<uint8_t>& plaintext,
        uint8_t content_type = 0x17);

    /**
     * @brief Remove padding from a decrypted TLS inner plaintext.
     *
     * Scans backwards for the real content type byte per RFC 8446 §5.4.
     *
     * @param padded  Decrypted inner plaintext (content + type + zeros).
     * @param[out] content_type  Recovered content type.
     * @return Original plaintext with padding and type byte removed.
     */
    static std::vector<uint8_t> unpad_plaintext(
        const std::vector<uint8_t>& padded,
        uint8_t& content_type);

    /**
     * @brief Pad a complete TLS record (header + payload) in-place.
     *
     * Post-encryption API: extends an already-encrypted TLS record with
     * CSPRNG-filled bytes (indistinguishable from ciphertext to observers).
     * Updates the 5-byte header length field.
     *
     * The receiver must know the agreed target size or the original
     * ciphertext length to strip the padding.
     *
     * @param record  Complete TLS record (modified in-place).
     * @return true if padding was applied, false if skipped.
     */
    bool pad_record(std::vector<uint8_t>& record);

    /// Reconfigure at runtime (thread-safe)
    void set_config(const TLSRecordPaddingConfig& config);
    TLSRecordPaddingConfig get_config() const;

    /// Statistics (thread-safe)
    TLSRecordPaddingStats get_stats() const;
    void reset_stats();

private:
    mutable std::mutex mutex_;
    TLSRecordPaddingConfig config_;
    TLSRecordPaddingStats stats_;
    std::unique_ptr<TrafficPadder> owned_padder_;   ///< Owned if no external
    TrafficPadder* padder_;                          ///< Active padder ptr

    /// Calculate target padded size based on strategy (caller holds mutex_)
    size_t compute_padded_size(size_t original_size) const;
};

} // namespace ncp

#endif // NCP_TLS_RECORD_PADDING_HPP
