#include "ncp_entropy_masking.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <cstring>

namespace ncp {
namespace DPI {

// ---- Construction / Destruction ----------------------------------------

EntropyController::EntropyController()
    : rng_(std::random_device{}()) {}

EntropyController::~EntropyController() = default;

// ---- Public API --------------------------------------------------------

std::vector<uint8_t> EntropyController::mask_entropy(
    const uint8_t* data, size_t len,
    const EntropyProfile& profile)
{
    if (!data || len == 0) return {};

    // Start with a copy of original data
    std::vector<uint8_t> result(data, data + len);

    // Prepend original length as 4-byte header for unmask
    uint32_t orig_len = static_cast<uint32_t>(len);
    std::vector<uint8_t> output(4);
    std::memcpy(output.data(), &orig_len, 4);
    output.insert(output.end(), result.begin(), result.end());

    // Calculate padding bytes
    size_t padding_bytes = (len * profile.padding_ratio) / 100;
    if (padding_bytes < 4) padding_bytes = 4;

    // Apply zero-byte padding if enabled
    if (profile.enable_zero_padding) {
        apply_zero_padding(output, padding_bytes / 2);
    }

    // Inject ASCII-printable bytes to lower entropy signature
    inject_ascii_bytes(output, profile.min_ascii_ratio);

    // Additional padding to reach target bit density
    double current_density = calculate_bit_density(output.data(), output.size());
    size_t max_extra = len; // cap extra padding
    size_t extra = 0;
    while (current_density > profile.target_bit_density && extra < max_extra) {
        output.push_back(0x00);
        ++extra;
        current_density = calculate_bit_density(output.data(), output.size());
    }

    return output;
}

std::vector<uint8_t> EntropyController::unmask_entropy(
    const uint8_t* masked_data, size_t len)
{
    if (!masked_data || len < 4) return {};

    // Read original length from header
    uint32_t orig_len = 0;
    std::memcpy(&orig_len, masked_data, 4);

    if (orig_len > len - 4) {
        // Corrupted header, return what we can
        return {};
    }

    // Extract original data after header
    return std::vector<uint8_t>(masked_data + 4, masked_data + 4 + orig_len);
}

double EntropyController::calculate_entropy(
    const uint8_t* data, size_t len) const
{
    if (!data || len == 0) return 0.0;

    // Count byte frequencies
    size_t freq[256] = {};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }

    // Shannon entropy: H = -sum(p * log2(p))
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) / static_cast<double>(len);
        entropy -= p * std::log2(p);
    }
    return entropy;
}

double EntropyController::calculate_bit_density(
    const uint8_t* data, size_t len) const
{
    if (!data || len == 0) return 0.0;

    size_t one_bits = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        // Count set bits (Brian Kernighan)
        while (byte) {
            one_bits++;
            byte &= byte - 1;
        }
    }
    return static_cast<double>(one_bits) / static_cast<double>(len * 8);
}

// ---- Private helpers ---------------------------------------------------

void EntropyController::apply_zero_padding(
    std::vector<uint8_t>& data, size_t padding_bytes)
{
    for (size_t i = 0; i < padding_bytes; ++i) {
        // Insert zero bytes at random positions
        std::uniform_int_distribution<size_t> dist(0, data.size());
        size_t pos = dist(rng_);
        data.insert(data.begin() + static_cast<long>(pos), 0x00);
    }
}

void EntropyController::inject_ascii_bytes(
    std::vector<uint8_t>& data, size_t target_ratio)
{
    if (data.empty() || target_ratio == 0) return;

    // Count current ASCII-printable bytes (0x20-0x7E)
    size_t ascii_count = 0;
    for (uint8_t b : data) {
        if (b >= 0x20 && b <= 0x7E) ++ascii_count;
    }

    size_t target_count = (data.size() * target_ratio) / 100;
    if (ascii_count >= target_count) return;

    // Inject random ASCII-printable bytes
    std::uniform_int_distribution<unsigned short> ascii_dist(0x20, 0x7E);
    size_t to_inject = target_count - ascii_count;
    for (size_t i = 0; i < to_inject; ++i) {
        data.push_back(static_cast<uint8_t>(ascii_dist(rng_)));
    }
}

} // namespace DPI
} // namespace ncp
