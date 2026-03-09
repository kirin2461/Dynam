#ifndef NCP_ENTROPY_MASKING_HPP
#define NCP_ENTROPY_MASKING_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ncp {
namespace DPI {

/**
 * @brief Entropy profile for masking high-entropy (encrypted) traffic
 */
struct EntropyProfile {
    double target_bit_density = 0.35;   // Target bit density (0.0-0.5)
    size_t padding_ratio = 20;          // Padding as % of original size
    size_t min_ascii_ratio = 30;        // Minimum % of ASCII-printable bytes
    bool enable_zero_padding = true;    // Add zero-byte padding

    static EntropyProfile low_entropy() {
        return {0.30, 30, 40, true};
    }
    static EntropyProfile moderate() {
        return {0.35, 20, 30, true};
    }
    static EntropyProfile minimal() {
        return {0.40, 10, 20, true};
    }
};

/**
 * @brief Entropy masking controller for defeating GFW Algorithm-1 style detection
 *
 * High-entropy traffic (encrypted/random data) is a strong signal for DPI systems.
 * This controller reduces detectable entropy by injecting structured padding.
 *
 * Wire format (output of mask_entropy):
 *   [seed:32][orig_len:4][profile_flags:4][masked_payload...]
 *
 * seed         — random seed for deterministic position generation
 * orig_len     — original data length (big-endian uint32)
 * profile_flags — [padding_ratio:1][min_ascii_ratio:1][flags:1][reserved:1]
 *                 flags bit 0 = enable_zero_padding
 *
 * Both mask and unmask derive identical insertion positions from the seed,
 * enabling the receiver to strip injected bytes without out-of-band metadata.
 */
class EntropyController {
public:
    EntropyController();
    ~EntropyController();

    /// Header size: seed(32) + orig_len(4) + profile_flags(4)
    static constexpr size_t HEADER_SIZE = 40;

    /// Mask entropy of data according to profile
    std::vector<uint8_t> mask_entropy(
        const uint8_t* data, size_t len,
        const EntropyProfile& profile = EntropyProfile::moderate()
    );

    /// Unmask (restore) previously masked data
    std::vector<uint8_t> unmask_entropy(
        const uint8_t* masked_data, size_t len
    );

    /// Calculate Shannon entropy (bits/byte) of data
    double calculate_entropy(const uint8_t* data, size_t len) const;

    /// Calculate bit density (ratio of 1-bits to total bits)
    double calculate_bit_density(const uint8_t* data, size_t len) const;

private:
    /**
     * @brief Generate deterministic insertion positions from seed.
     *
     * Uses crypto_stream_xchacha20 to expand seed into a position sequence.
     * Returned positions are sequential (each relative to array size at that point).
     *
     * @param seed       32-byte random seed
     * @param count      number of positions to generate
     * @param data_len   original data length
     * @return vector of insertion positions
     */
    static std::vector<size_t> derive_positions(
        const uint8_t seed[32], size_t count, size_t data_len
    );

    /**
     * @brief Generate deterministic byte values from seed.
     *
     * @param seed       32-byte seed
     * @param count      how many bytes to generate
     * @param ascii_only if true, constrain to 0x20-0x7E range
     * @return vector of byte values
     */
    static std::vector<uint8_t> derive_bytes(
        const uint8_t seed[32], size_t count, bool ascii_only
    );

    // CSPRNG helpers
    static uint8_t csprng_byte();
    static uint32_t csprng_uniform(uint32_t upper_bound);
};

} // namespace DPI
} // namespace ncp

#endif // NCP_ENTROPY_MASKING_HPP
