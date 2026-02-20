#include "../include/ncp_entropy_masking.hpp"
#include <sodium.h>
#include <cmath>
#include <algorithm>

namespace ncp {
namespace DPI {

// ==================== CSPRNG Helpers ====================
uint8_t EntropyController::csprng_byte() {
    uint8_t val;
    randombytes_buf(&val, sizeof(val));
    return val;
}

uint32_t EntropyController::csprng_uniform(uint32_t upper_bound) {
    if (upper_bound <= 1) return 0;
    return randombytes_uniform(upper_bound);
}

// ==================== Constructor/Destructor ====================
EntropyController::EntropyController() {}
EntropyController::~EntropyController() {}

// ==================== Entropy Masking ====================
std::vector<uint8_t> EntropyController::mask_entropy(
    const uint8_t* data,
    size_t len,
    const EntropyProfile& profile
) {
    if (!data || len == 0) return {};
    
    std::vector<uint8_t> result(data, data + len);
    
    // Apply zero padding if enabled
    if (profile.enable_zero_padding) {
        size_t padding_bytes = (len * profile.padding_ratio) / 100;
        apply_zero_padding(result, padding_bytes);
    }
    
    // Inject ASCII bytes to reduce entropy
    inject_ascii_bytes(result, profile.min_ascii_ratio);
    
    return result;
}

std::vector<uint8_t> EntropyController::unmask_entropy(
    const uint8_t* masked_data,
    size_t len
) {
    // Stub: In real implementation, would strip padding and ASCII bytes
    // For now, just return copy
    if (!masked_data || len == 0) return {};
    return std::vector<uint8_t>(masked_data, masked_data + len);
}

// ==================== Private Helpers ====================
void EntropyController::apply_zero_padding(std::vector<uint8_t>& data, size_t padding_bytes) {
    if (padding_bytes == 0) return;
    
    // Insert zero bytes at random positions
    for (size_t i = 0; i < padding_bytes; ++i) {
        size_t pos = csprng_uniform(static_cast<uint32_t>(data.size() + 1));
        data.insert(data.begin() + pos, 0x00);
    }
}

void EntropyController::inject_ascii_bytes(std::vector<uint8_t>& data, size_t target_ratio) {
    if (target_ratio == 0 || data.empty()) return;
    
    // Count current ASCII bytes
    size_t ascii_count = 0;
    for (uint8_t byte : data) {
        if (byte >= 0x20 && byte <= 0x7E) ascii_count++;
    }
    
    size_t current_ratio = (ascii_count * 100) / data.size();
    if (current_ratio >= target_ratio) return;
    
    // Calculate how many ASCII bytes to inject
    size_t needed = ((target_ratio * data.size()) / 100) - ascii_count;
    
    // Inject printable ASCII at random positions
    for (size_t i = 0; i < needed; ++i) {
        uint8_t ascii_byte = 0x20 + csprng_uniform(0x5F); // 0x20-0x7E range
        size_t pos = csprng_uniform(static_cast<uint32_t>(data.size() + 1));
        data.insert(data.begin() + pos, ascii_byte);
    }
}

// ==================== Entropy Calculation ====================
double EntropyController::calculate_entropy(const uint8_t* data, size_t len) const {
    if (!data || len == 0) return 0.0;
    
    // Count byte frequencies
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < len; ++i) {
        freq[data[i]]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / len;
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

double EntropyController::calculate_bit_density(const uint8_t* data, size_t len) const {
    if (!data || len == 0) return 0.0;
    
    uint64_t bit_count = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];
        // Count set bits using Brian Kernighan's algorithm
        while (byte) {
            byte &= (byte - 1);
            bit_count++;
        }
    }
    
    return static_cast<double>(bit_count) / (len * 8);
}

} // namespace DPI
} // namespace ncp
