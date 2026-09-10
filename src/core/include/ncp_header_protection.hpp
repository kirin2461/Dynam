#pragma once

/**
 * @file ncp_header_protection.hpp
 * @brief AWG 3.1-inspired header protection for NCP wire protocols.
 *
 * AmneziaWG 3.1 encrypts/obfuscates the fixed parts of packet headers so
 * that DPI cannot match on static byte signatures. NCP had the same
 * problem: fixed magic prefixes "PH" (port-hopping), "FOG" (fog mesh) and
 * "RS" (AEMM shards) are ready-made DPI signatures.
 *
 * This module replaces static magic bytes with session-derived prefixes:
 *
 *   prefix(tag) = HKDF-SHA256(secret, salt="ncp-hp-v1",
 *                             info=context || tag_u64_BE)[0..N)
 *
 * The tag is a frame field that sits at a fixed offset (epoch for
 * port-hopping, seq for fog, block_id for AEMM), so the receiver parses
 * the fields optimistically and then verifies the prefix in constant
 * time. Tampering with the tag breaks the prefix match.
 *
 * Additionally provides:
 *   - Version-range randomisation (AWG H1-H4 analogue): the version/type
 *     byte is drawn at random from a per-installation range; the receiver
 *     accepts any value in the range, so no universal DPI rule exists.
 *   - Content padding (AWG ContentPaddingAddition analogue): pads every
 *     datagram with a random number of bytes to break the 16-byte
 *     multiple patterns that statistical classifiers look for.
 *
 * HKDF-SHA256 (RFC 5869) is implemented on top of libsodium's
 * crypto_auth_hmacsha256 so it works with libsodium >= 1.0.18
 * (crypto_kdf_hkdf_* is unavailable before 1.0.19).
 */

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace ncp {

// ==================== HKDF-SHA256 (RFC 5869) ====================

/// HKDF-Extract + HKDF-Expand with SHA-256.
/// out_len must be <= 255 * 32. Returns false on bad arguments.
bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

// ==================== HeaderProtection ====================

class HeaderProtection {
public:
    /// Default: disabled (legacy static magic bytes are used).
    HeaderProtection() = default;

    /// @param secret   Shared session secret (any length; 16+ bytes advised).
    /// @param context  Protocol separation string, e.g. "ncp-ph", "ncp-fog".
    HeaderProtection(std::vector<uint8_t> secret, std::string context);

    bool enabled() const noexcept { return enabled_; }

    /// Derive up to 32 prefix bytes bound to `tag` (epoch / seq / block_id).
    void prefix(uint64_t tag, uint8_t* out, size_t out_len) const;

    /// Constant-time check that data[0..len) equals prefix(tag).
    bool matches(uint64_t tag, const uint8_t* data, size_t len) const;

    // ----- Version-range randomisation (AWG H1-H4 analogue) -----

    /// Configure the accepted version-byte range [min_v, max_v].
    /// Default [1,1] reproduces legacy behaviour exactly.
    void set_version_range(uint8_t min_v, uint8_t max_v);
    uint8_t ver_min() const noexcept { return ver_min_; }
    uint8_t ver_max() const noexcept { return ver_max_; }

    /// Random version byte from the configured range (CSPRNG).
    uint8_t random_version() const;

    /// Whether v is inside the configured range.
    bool version_accepted(uint8_t v) const noexcept {
        return v >= ver_min_ && v <= ver_max_;
    }

    /// Parse "min-max" or single "v" (clamped to [1, 255]).
    static std::optional<std::pair<uint8_t, uint8_t>>
    parse_version_range(const std::string& spec);

private:
    std::vector<uint8_t> prk_;      // HKDF-Extract output (32 bytes)
    std::string context_;           // protocol separation string
    uint8_t ver_min_ = 1;
    uint8_t ver_max_ = 1;
    bool enabled_ = false;
};

// ==================== Content padding ====================

/// AWG ContentPaddingAddition analogue: append `pad_len` random bytes plus
/// one trailing length byte; the receiver strips `pad_len + 1` bytes.
struct ContentPaddingConfig {
    uint16_t min_pad = 0;   ///< minimum padding bytes (0 = disabled)
    uint16_t max_pad = 0;   ///< maximum padding bytes (0 = disabled)

    bool enabled() const noexcept {
        return max_pad > 0 && max_pad >= min_pad;
    }

    /// Parse "<min>-<max>" or single "<n>". Caps at [0, 1400].
    static std::optional<ContentPaddingConfig> parse(const std::string& spec);

    /// Random padding length in [min_pad, max_pad] (CSPRNG).
    uint16_t sample() const;
};

/// Append random padding to `buf`: buf || random(pad_len) || pad_len(1).
/// Returns the chosen pad_len (0 when disabled or on overflow of max_size).
uint16_t content_pad_append(std::vector<uint8_t>& buf,
                            const ContentPaddingConfig& cfg,
                            size_t max_size);

/// Strip padding appended by content_pad_append(). Returns payload size,
/// or std::nullopt on malformed input. `buf_size` includes the padding.
std::optional<size_t> content_pad_strip(const uint8_t* buf, size_t buf_size);

} // namespace ncp
