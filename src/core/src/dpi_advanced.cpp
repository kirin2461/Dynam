#include "../include/ncp_dpi_advanced.hpp"
#include "../include/ncp_ech.hpp"  // Use new ECH implementation
#include <sodium.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <set>

namespace ncp {
namespace DPI {

// TCPManipulator implementation
struct TCPManipulator::Impl {
    // Removed: std::mt19937 rng{std::random_device{}()};
    // Now using libsodium CSPRNG via randombytes_uniform()
};

TCPManipulator::TCPManipulator() : impl_(std::make_unique<Impl>()) {}
TCPManipulator::~TCPManipulator() = default;

std::vector<std::vector<uint8_t>> TCPManipulator::split_segments(
    const uint8_t* data,
    size_t len,
    const std::vector<size_t>& split_points
) {
    std::vector<std::vector<uint8_t>> segments;
    if (!data || len == 0) return segments;
    
    std::vector<size_t> valid_points;
    for (auto pt : split_points) {
        if (pt > 0 && pt < len) {
            valid_points.push_back(pt);
        }
    }
    std::sort(valid_points.begin(), valid_points.end());
    valid_points.erase(
        std::unique(valid_points.begin(), valid_points.end()),
        valid_points.end()
    );
    
    size_t prev = 0;
    for (size_t pt : valid_points) {
        segments.emplace_back(data + prev, data + pt);
        prev = pt;
    }
    if (prev < len) {
        segments.emplace_back(data + prev, data + len);
    }
    
    return segments;
}

std::vector<std::vector<uint8_t>> TCPManipulator::create_overlap(
    const uint8_t* data,
    size_t len,
    size_t overlap_size
) {
    std::vector<std::vector<uint8_t>> segments;
    if (!data || len == 0 || overlap_size == 0) {
        if (data && len > 0) {
            segments.emplace_back(data, data + len);
        }
        return segments;
    }
    
    size_t segment_size = std::max<size_t>(overlap_size * 2, 16);
    size_t offset = 0;
    
    while (offset < len) {
        size_t end = std::min(offset + segment_size, len);
        segments.emplace_back(data + offset, data + end);
        
        if (end < len) {
            size_t overlap_start = end - std::min(overlap_size, end - offset);
            segments.emplace_back(data + overlap_start, data + end);
        }
        offset = end;
    }
    
    return segments;
}

std::vector<uint8_t> TCPManipulator::add_oob_marker(
    const uint8_t* data,
    size_t len,
    size_t urgent_position
) {
    std::vector<uint8_t> result(data, data + len);
    if (urgent_position < len) {
        result.insert(result.begin() + urgent_position, 0x00);
    }
    return result;
}

void TCPManipulator::shuffle_segments(
    std::vector<std::vector<uint8_t>>& segments,
    std::mt19937& /* unused - kept for API compatibility */
) {
    if (segments.size() <= 1) return;
    
    for (size_t i = segments.size() - 1; i > 0; --i) {
        uint32_t j = randombytes_uniform(static_cast<uint32_t>(i + 1));
        std::swap(segments[i], segments[j]);
    }
}

// ... [REST OF FILE UNCHANGED UNTIL ECH SECTION] ...

// TrafficObfuscator implementation (unchanged)
struct TrafficObfuscator::Impl {
    ObfuscationMode mode;
    std::vector<uint8_t> key;
    size_t xor_offset = 0;
    
    Impl(ObfuscationMode m, const std::vector<uint8_t>& k)
        : mode(m), key(k) {
        if (key.empty()) {
            key.resize(32);
            randombytes_buf(key.data(), key.size());
        }
    }
};

TrafficObfuscator::TrafficObfuscator(ObfuscationMode mode, const std::vector<uint8_t>& key)
    : impl_(std::make_unique<Impl>(mode, key)) {}

TrafficObfuscator::~TrafficObfuscator() = default;

std::vector<uint8_t> TrafficObfuscator::obfuscate(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    std::vector<uint8_t> result;
    
    switch (impl_->mode) {
        case ObfuscationMode::XOR_SIMPLE:
            result.resize(len);
            for (size_t i = 0; i < len; ++i) {
                result[i] = data[i] ^ impl_->key[i % impl_->key.size()];
            }
            break;
            
        case ObfuscationMode::XOR_ROLLING:
            result.resize(len);
            for (size_t i = 0; i < len; ++i) {
                size_t key_idx = (impl_->xor_offset + i) % impl_->key.size();
                result[i] = data[i] ^ impl_->key[key_idx];
            }
            impl_->xor_offset = (impl_->xor_offset + len) % impl_->key.size();
            break;
            
        case ObfuscationMode::CHACHA20:
            if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES) {
                uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
                randombytes_buf(nonce, sizeof(nonce));
                
                result.resize(sizeof(nonce) + len);
                std::copy(nonce, nonce + sizeof(nonce), result.begin());
                
                crypto_stream_chacha20_xor(result.data() + sizeof(nonce), data, len,
                                          nonce, impl_->key.data());
            } else {
                result.assign(data, data + len);
            }
            break;
            
        case ObfuscationMode::NONE:
        default:
            result.assign(data, data + len);
            break;
    }
    
    return result;
}

std::vector<uint8_t> TrafficObfuscator::deobfuscate(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    switch (impl_->mode) {
        case ObfuscationMode::CHACHA20:
            if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES &&
                len > crypto_stream_chacha20_NONCEBYTES) {
                
                const uint8_t* nonce = data;
                const uint8_t* ciphertext = data + crypto_stream_chacha20_NONCEBYTES;
                size_t ciphertext_len = len - crypto_stream_chacha20_NONCEBYTES;
                
                std::vector<uint8_t> result(ciphertext_len);
                crypto_stream_chacha20_xor(result.data(), ciphertext, ciphertext_len,
                                          nonce, impl_->key.data());
                return result;
            }
            return std::vector<uint8_t>(data, data + len);
            
        default:
            return obfuscate(data, len);
    }
}

ObfuscationMode TrafficObfuscator::get_mode() const {
    return impl_->mode;
}

void TrafficObfuscator::rotate_key() {
    randombytes_buf(impl_->key.data(), impl_->key.size());
    impl_->xor_offset = 0;
}

// ... [TLSManipulator and other code unchanged] ...

// ==================== ECH (Encrypted Client Hello) - NOW WITH REAL HPKE ====================

/**
 * @brief Apply ECH encryption to ClientHello using proper HPKE
 * 
 * This replaces the old insecure stub with real HPKE-based encryption.
 * Requires OpenSSL 3.2+ with HPKE support.
 */
std::vector<uint8_t> DPIEvasion::apply_ech(
    const std::vector<uint8_t>& client_hello,
    const std::vector<uint8_t>& ech_config_data
) {
    // Parse ECHConfig
    ECH::ECHConfig config;
    if (!ECH::parse_ech_config(ech_config_data, config)) {
        // Failed to parse config - return unmodified
        return client_hello;
    }

    // Use new HPKE-based ECH implementation
    return ECH::apply_ech(client_hello, config);
}

// ... [REST OF FILE UNCHANGED] ...

// Domain Fronting (unchanged)
static int find_sni_hostname_offset_internal(const uint8_t* data, size_t len) {
    // ... [implementation unchanged] ...
    return -1;
}

std::vector<uint8_t> DPIEvasion::apply_domain_fronting(
    const std::vector<uint8_t>& data,
    const std::string& front_domain,
    const std::string& real_domain
) {
    // ... [implementation unchanged] ...
    return data;
}

// ... [Preset configurations unchanged] ...

} // namespace DPI
} // namespace ncp
