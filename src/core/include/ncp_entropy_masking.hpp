#ifndef NCP_ENTROPY_MASKING_HPP
#define NCP_ENTROPY_MASKING_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <random>

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
 */
class EntropyController {
public:
    EntropyController();
    ~EntropyController();

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
    void apply_zero_padding(std::vector<uint8_t>& data, size_t padding_bytes);
    void inject_ascii_bytes(std::vector<uint8_t>& data, size_t target_ratio);

    std::mt19937 rng_;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_ENTROPY_MASKING_HPP
