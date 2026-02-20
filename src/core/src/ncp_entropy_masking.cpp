#include "../include/ncp_entropy_masking.hpp"
#include <sodium.h>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <numeric>

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

// ==================== Deterministic position/byte derivation ====================

std::vector<size_t> EntropyController::derive_positions(
    const uint8_t seed[32], size_t count, size_t data_len
) {
    if (count == 0 || data_len == 0) return {};

    // Use crypto_stream_xchacha20 to expand seed into deterministic random bytes.
    // We need 4 bytes per position (uint32_t), so we generate count*4 bytes.
    // Nonce = first 24 bytes of SHA-256(seed || "positions") to separate domains.
    uint8_t nonce[crypto_stream_xchacha20_NONCEBYTES]; // 24
    uint8_t domain_input[32 + 9]; // seed + "positions"
    std::memcpy(domain_input, seed, 32);
    std::memcpy(domain_input + 32, "positions", 9);
    crypto_generichash(nonce, sizeof(nonce), domain_input, sizeof(domain_input), nullptr, 0);

    size_t stream_len = count * 4;
    std::vector<uint8_t> stream(stream_len);
    crypto_stream_xchacha20(stream.data(), stream_len, nonce, seed);

    // Derive positions: each insertion shifts the array, so position[i] is
    // relative to the array size at that point: data_len + i
    std::vector<size_t> positions(count);
    for (size_t i = 0; i < count; ++i) {
        uint32_t raw = (static_cast<uint32_t>(stream[i * 4]) << 24) |
                       (static_cast<uint32_t>(stream[i * 4 + 1]) << 16) |
                       (static_cast<uint32_t>(stream[i * 4 + 2]) << 8) |
                        static_cast<uint32_t>(stream[i * 4 + 3]);
        // Position within [0, data_len + i] (inclusive — can insert at end)
        positions[i] = raw % (data_len + i + 1);
    }

    return positions;
}

std::vector<uint8_t> EntropyController::derive_bytes(
    const uint8_t seed[32], size_t count, bool ascii_only
) {
    if (count == 0) return {};

    // Separate domain from positions
    uint8_t nonce[crypto_stream_xchacha20_NONCEBYTES];
    uint8_t domain_input[32 + 5]; // seed + "bytes"
    std::memcpy(domain_input, seed, 32);
    std::memcpy(domain_input + 32, "bytes", 5);
    crypto_generichash(nonce, sizeof(nonce), domain_input, sizeof(domain_input), nullptr, 0);

    std::vector<uint8_t> stream(count);
    crypto_stream_xchacha20(stream.data(), count, nonce, seed);

    if (ascii_only) {
        for (size_t i = 0; i < count; ++i) {
            // Map to printable ASCII range 0x20-0x7E (95 values)
            stream[i] = 0x20 + (stream[i] % 95);
        }
    }

    return stream;
}

// ==================== Entropy Masking ====================

std::vector<uint8_t> EntropyController::mask_entropy(
    const uint8_t* data,
    size_t len,
    const EntropyProfile& profile
) {
    if (!data || len == 0) return {};
    if (len > 0xFFFFFFFF) return {}; // uint32 overflow guard

    // Generate random seed for this message
    uint8_t seed[32];
    randombytes_buf(seed, sizeof(seed));

    // Compute how many bytes to inject
    size_t zero_count = 0;
    if (profile.enable_zero_padding) {
        zero_count = (len * profile.padding_ratio) / 100;
    }

    // Count current ASCII bytes to determine how many ASCII to inject
    size_t ascii_count = 0;
    for (size_t i = 0; i < len; ++i) {
        if (data[i] >= 0x20 && data[i] <= 0x7E) ascii_count++;
    }
    size_t current_ratio = (ascii_count * 100) / len;
    size_t ascii_inject_count = 0;
    if (current_ratio < profile.min_ascii_ratio) {
        ascii_inject_count = ((profile.min_ascii_ratio * len) / 100) - ascii_count;
    }

    size_t total_inject = zero_count + ascii_inject_count;

    // Derive deterministic positions and values
    auto positions = derive_positions(seed, total_inject, len);
    auto ascii_values = derive_bytes(seed, ascii_inject_count, true);

    // Build masked payload: start with original data
    std::vector<uint8_t> payload(data, data + len);

    // Insert bytes at derived positions (in order — each insert shifts subsequent indices)
    for (size_t i = 0; i < total_inject; ++i) {
        size_t pos = positions[i];
        if (pos > payload.size()) pos = payload.size();

        uint8_t value;
        if (i < zero_count) {
            value = 0x00; // zero padding
        } else {
            value = ascii_values[i - zero_count];
        }
        payload.insert(payload.begin() + static_cast<ptrdiff_t>(pos), value);
    }

    // Build output: [seed:32][orig_len:4][profile_flags:4][masked_payload...]
    std::vector<uint8_t> result;
    result.reserve(HEADER_SIZE + payload.size());

    // Seed (32 bytes)
    result.insert(result.end(), seed, seed + 32);

    // Original length (4 bytes, big-endian)
    uint32_t orig_len = static_cast<uint32_t>(len);
    result.push_back((orig_len >> 24) & 0xFF);
    result.push_back((orig_len >> 16) & 0xFF);
    result.push_back((orig_len >> 8) & 0xFF);
    result.push_back(orig_len & 0xFF);

    // Profile flags (4 bytes): [padding_ratio][min_ascii_ratio][flags][reserved]
    result.push_back(static_cast<uint8_t>(profile.padding_ratio & 0xFF));
    result.push_back(static_cast<uint8_t>(profile.min_ascii_ratio & 0xFF));
    result.push_back(profile.enable_zero_padding ? 0x01 : 0x00);
    result.push_back(0x00); // reserved

    // Masked payload
    result.insert(result.end(), payload.begin(), payload.end());

    // Zero seed from stack
    sodium_memzero(seed, sizeof(seed));

    return result;
}

std::vector<uint8_t> EntropyController::unmask_entropy(
    const uint8_t* masked_data,
    size_t len
) {
    if (!masked_data || len <= HEADER_SIZE) return {};

    // Parse header
    const uint8_t* seed = masked_data; // first 32 bytes

    uint32_t orig_len = (static_cast<uint32_t>(masked_data[32]) << 24) |
                        (static_cast<uint32_t>(masked_data[33]) << 16) |
                        (static_cast<uint32_t>(masked_data[34]) << 8) |
                         static_cast<uint32_t>(masked_data[35]);

    uint8_t padding_ratio    = masked_data[36];
    uint8_t min_ascii_ratio  = masked_data[37];
    bool enable_zero_padding = (masked_data[38] & 0x01) != 0;
    // masked_data[39] reserved

    const uint8_t* payload_data = masked_data + HEADER_SIZE;
    size_t payload_len = len - HEADER_SIZE;

    // Sanity check: original length must be <= payload length
    if (orig_len > payload_len) return {};

    // Recompute injection counts (same logic as mask_entropy)
    size_t zero_count = 0;
    if (enable_zero_padding) {
        zero_count = (static_cast<size_t>(orig_len) * padding_ratio) / 100;
    }

    // total_inject = payload_len - orig_len (exact, by construction)
    size_t total_inject = payload_len - orig_len;

    // Validate: zero_count can't exceed total_inject
    if (zero_count > total_inject) {
        return {}; // corrupted or wrong version
    }

    // Re-derive the same positions from seed
    auto positions = derive_positions(seed, total_inject, orig_len);

    // Reconstruct the payload
    std::vector<uint8_t> payload(payload_data, payload_data + payload_len);

    // Remove injected bytes in REVERSE order (last insertion removed first).
    // This is critical: insertions shift indices forward, so removing in
    // reverse order ensures each position is still valid.
    for (size_t i = total_inject; i > 0; --i) {
        size_t pos = positions[i - 1];
        if (pos < payload.size()) {
            payload.erase(payload.begin() + static_cast<ptrdiff_t>(pos));
        }
    }

    // Verify we got back to original length
    if (payload.size() != orig_len) {
        return {}; // corruption or version mismatch
    }

    return payload;
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
