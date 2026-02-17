#include "../include/ncp_dpi_advanced.hpp"
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

// Fixed: Remove conditional swap (rng() % 2) for proper Fisher-Yates shuffle
// Fixed: Remove mt19937& parameter - now using CSPRNG directly
void TCPManipulator::shuffle_segments(
    std::vector<std::vector<uint8_t>>& segments,
    std::mt19937& /* unused - kept for API compatibility */
) {
    if (segments.size() <= 1) return;
    
    // Proper Fisher-Yates shuffle with CSPRNG
    for (size_t i = segments.size() - 1; i > 0; --i) {
        // Use CSPRNG instead of mt19937
        uint32_t j = randombytes_uniform(static_cast<uint32_t>(i + 1));
        // Unconditional swap for uniform distribution
        std::swap(segments[i], segments[j]);
    }
}

// TLSManipulator implementation
struct TLSManipulator::Impl {
    // Removed: std::mt19937 rng{std::random_device{}()};
    
    static constexpr uint16_t GREASE_VALUES[] = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
        0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
        0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    };
};

TLSManipulator::TLSManipulator() : impl_(std::make_unique<Impl>()) {}
TLSManipulator::~TLSManipulator() = default;

std::vector<size_t> TLSManipulator::find_sni_split_points(
    const uint8_t* data,
    size_t len
) {
    std::vector<size_t> points;
    
    if (!data || len < 43) return points;
    if (data[0] != 0x16 || data[1] != 0x03) return points;
    
    size_t pos = 5;
    if (pos + 4 > len || data[pos] != 0x01) return points;
    
    pos += 4;
    pos += 2 + 32;
    
    if (pos + 1 > len) return points;
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;
    
    if (pos + 2 > len) return points;
    uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_len;
    
    if (pos + 1 > len) return points;
    pos += 1 + data[pos];
    
    if (pos + 2 > len) return points;
    uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    size_t ext_end = std::min(pos + ext_len, len);
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        
        if (ext_type == 0x0000) {
            if (pos + 5 <= ext_end) {
                points.push_back(pos);
                size_t hostname_offset = pos + 5;
                if (hostname_offset + 1 < ext_end) {
                    points.push_back(hostname_offset + 1);
                    points.push_back(hostname_offset + 3);
                }
            }
            break;
        }
        pos += ext_data_len;
    }
    
    return points;
}

std::vector<std::vector<uint8_t>> TLSManipulator::split_tls_record(
    const uint8_t* data,
    size_t len,
    size_t max_fragment_size
) {
    std::vector<std::vector<uint8_t>> records;
    if (!data || len < 5) return records;
    
    uint8_t content_type = data[0];
    uint8_t version_major = data[1];
    uint8_t version_minor = data[2];
    size_t payload_len = (data[3] << 8) | data[4];
    
    if (5 + payload_len > len) payload_len = len - 5;
    
    const uint8_t* payload = data + 5;
    size_t offset = 0;
    
    while (offset < payload_len) {
        size_t chunk_size = std::min(max_fragment_size, payload_len - offset);
        
        std::vector<uint8_t> record;
        record.push_back(content_type);
        record.push_back(version_major);
        record.push_back(version_minor);
        record.push_back((chunk_size >> 8) & 0xFF);
        record.push_back(chunk_size & 0xFF);
        record.insert(record.end(), payload + offset, payload + offset + chunk_size);
        
        records.push_back(std::move(record));
        offset += chunk_size;
    }
    
    return records;
}

std::vector<uint8_t> TLSManipulator::add_tls_padding(
    const uint8_t* data,
    size_t len,
    size_t padding_size
) {
    std::vector<uint8_t> result(data, data + len);
    for (size_t i = 0; i < padding_size; ++i) {
        result.push_back(0x00);
    }
    return result;
}

std::vector<uint8_t> TLSManipulator::inject_grease(
    const uint8_t* data,
    size_t len
) {
    if (!data || len < 43) return std::vector<uint8_t>(data, data + len);
    if (data[0] != 0x16 || data[1] != 0x03) return std::vector<uint8_t>(data, data + len);
    
    std::vector<uint8_t> result(data, data + len);
    
    // Find extensions section in ClientHello
    size_t pos = 5;
    if (pos + 4 > len || data[pos] != 0x01) return result;
    
    pos += 4;  // Skip handshake header
    pos += 2 + 32;  // Skip version and random
    
    if (pos + 1 > len) return result;
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;
    
    if (pos + 2 > len) return result;
    uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_len;
    
    if (pos + 1 > len) return result;
    pos += 1 + data[pos];
    
    if (pos + 2 > len) return result;
    size_t ext_len_pos = pos;
    
    // Select random GREASE value using CSPRNG
    uint16_t grease = impl_->GREASE_VALUES[randombytes_uniform(16)];
    
    // Create GREASE extension (empty data)
    std::vector<uint8_t> grease_ext;
    grease_ext.push_back((grease >> 8) & 0xFF);
    grease_ext.push_back(grease & 0xFF);
    grease_ext.push_back(0x00);  // Length high byte
    grease_ext.push_back(0x00);  // Length low byte
    
    // Insert GREASE extension at extensions start
    size_t insert_pos = ext_len_pos + 2;
    result.insert(result.begin() + insert_pos, grease_ext.begin(), grease_ext.end());
    
    // Update extensions length
    uint16_t old_ext_len = (result[ext_len_pos] << 8) | result[ext_len_pos + 1];
    // Check for overflow before modifying lengths
    if (old_ext_len > UINT16_MAX - grease_ext.size()) {
        return result; // Would overflow, return unmodified
    }
        uint16_t new_ext_len = old_ext_len + grease_ext.size();
    result[ext_len_pos] = (new_ext_len >> 8) & 0xFF;
    result[ext_len_pos + 1] = new_ext_len & 0xFF;
    
    // Update handshake length (at position 6-8)
    if (result.size() > 8) {
        uint32_t hs_len = ((result[6] << 16) | (result[7] << 8) | result[8]) + grease_ext.size();
        result[6] = (hs_len >> 16) & 0xFF;
        result[7] = (hs_len >> 8) & 0xFF;
        result[8] = hs_len & 0xFF;
    }
    
    // Update TLS record length (at position 3-4)
    uint16_t rec_len = ((result[3] << 8) | result[4]) + grease_ext.size();
    result[3] = (rec_len >> 8) & 0xFF;
    result[4] = rec_len & 0xFF;
    
    return result;
}

// TODO (Issue #1): Replace this function with realistic TLS ClientHello implementation
// Required changes:
// 1. Add 15 cipher suites (TLS 1.3: 0x1301-0x1303, TLS 1.2: 0xC02C, 0xC02B, 0xC030, etc.)
// 2. Add 32-byte random session ID (currently empty)
// 3. Add proper extensions: supported_versions, supported_groups, signature_algorithms
// 4. Add GREASE values for anti-fingerprinting
// See dpi_advanced_fixed.cpp for reference implementation
std::vector<uint8_t> TLSManipulator::create_fake_client_hello(
    const std::string& fake_sni
) {
    std::vector<uint8_t> hello;
    
    hello.push_back(0x16);
    hello.push_back(0x03);
    hello.push_back(0x01);
    
    size_t len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    hello.push_back(0x01);
    size_t hs_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    hello.push_back(0x03);
    hello.push_back(0x03);
    
    // Fixed: Use CSPRNG for random bytes instead of mt19937
    uint8_t random_bytes[32];
    randombytes_buf(random_bytes, sizeof(random_bytes));
    hello.insert(hello.end(), random_bytes, random_bytes + 32);
    
    hello.push_back(0x00);
    
    hello.push_back(0x00);
    hello.push_back(0x02);
    hello.push_back(0x00);
    hello.push_back(0x3C);
    
    hello.push_back(0x01);
    hello.push_back(0x00);
    
    size_t ext_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    hello.push_back(0x00);
    hello.push_back(0x00);
    size_t sni_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    size_t list_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    hello.push_back(0x00);
    hello.push_back((fake_sni.size() >> 8) & 0xFF);
    hello.push_back(fake_sni.size() & 0xFF);
    hello.insert(hello.end(), fake_sni.begin(), fake_sni.end());
    
    size_t total_ext_len = hello.size() - ext_len_pos - 2;
    hello[ext_len_pos] = (total_ext_len >> 8) & 0xFF;
    hello[ext_len_pos + 1] = total_ext_len & 0xFF;
    
    size_t sni_ext_len = hello.size() - sni_len_pos - 2;
    hello[sni_len_pos] = (sni_ext_len >> 8) & 0xFF;
    hello[sni_len_pos + 1] = sni_ext_len & 0xFF;
    
    size_t list_len = fake_sni.size() + 3;
    hello[list_len_pos] = (list_len >> 8) & 0xFF;
    hello[list_len_pos + 1] = list_len & 0xFF;
    
    size_t hs_len = hello.size() - hs_len_pos - 3;
    hello[hs_len_pos] = (hs_len >> 16) & 0xFF;
    hello[hs_len_pos + 1] = (hs_len >> 8) & 0xFF;
    hello[hs_len_pos + 2] = hs_len & 0xFF;
    
    size_t record_len = hello.size() - 5;
    hello[len_pos] = (record_len >> 8) & 0xFF;
    hello[len_pos + 1] = record_len & 0xFF;
    
    return hello;
}

// TrafficObfuscator implementation
struct TrafficObfuscator::Impl {
    ObfuscationMode mode;
    std::vector<uint8_t> key;
    // Removed: std::mt19937 rng{std::random_device{}()};
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
                // Fixed: Generate unique nonce for each call instead of deriving from key
                uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
                randombytes_buf(nonce, sizeof(nonce));
                
                // Prepend nonce to result (nonce + ciphertext)
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
                
                // Extract nonce from beginning
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
            // XOR modes are symmetric
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

// AdvancedDPIBypass implementation
struct AdvancedDPIBypass::Impl {
    AdvancedDPIConfig config;
    AdvancedDPIStats stats;
    std::atomic<bool> running{false};
    mutable std::mutex mutex;
    
    std::unique_ptr<TCPManipulator> tcp_manip;
    std::unique_ptr<TLSManipulator> tls_manip;
    std::unique_ptr<TrafficObfuscator> obfuscator;
    
    std::function<void(const std::string&)> log_callback;
    // Removed: std::mt19937 rng{std::random_device{}()};
    std::set<EvasionTechnique> active_techniques;
    
    void log(const std::string& msg) {
        if (log_callback) log_callback(msg);
    }
    
    bool is_technique_active(EvasionTechnique t) const {
        return active_techniques.count(t) > 0;
    }
};

AdvancedDPIBypass::AdvancedDPIBypass() : impl_(std::make_unique<Impl>()) {}
AdvancedDPIBypass::~AdvancedDPIBypass() { stop(); }

bool AdvancedDPIBypass::initialize(const AdvancedDPIConfig& config) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    impl_->config = config;
    impl_->tcp_manip = std::make_unique<TCPManipulator>();
    impl_->tls_manip = std::make_unique<TLSManipulator>();
    
    if (config.obfuscation != ObfuscationMode::NONE) {
        impl_->obfuscator = std::make_unique<TrafficObfuscator>(
            config.obfuscation, config.obfuscation_key);
    }
    
    impl_->active_techniques.clear();
    for (const auto& tech : config.techniques) {
        impl_->active_techniques.insert(tech);
    }
    
    impl_->log("Advanced DPI bypass initialized with " + 
               std::to_string(impl_->active_techniques.size()) + " techniques");
    
    return true;
}

bool AdvancedDPIBypass::start() {
    impl_->running = true;
    impl_->log("Advanced DPI bypass started");
    return true;
}

void AdvancedDPIBypass::stop() {
    impl_->running = false;
    impl_->log("Advanced DPI bypass stopped");
}

bool AdvancedDPIBypass::is_running() const {
    return impl_->running;
}

AdvancedDPIStats AdvancedDPIBypass::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->stats;
}

std::vector<std::vector<uint8_t>> AdvancedDPIBypass::process_outgoing(
    const uint8_t* data,
    size_t len
) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::vector<std::vector<uint8_t>> result;
    
    if (!data || len == 0) return result;
    
    bool is_client_hello = (len > 5 && data[0] == 0x16 && 
                           data[1] == 0x03 && data[5] == 0x01);
    
    std::vector<uint8_t> processed(data, data + len);
    
    // Apply GREASE injection for TLS ClientHello
    if (is_client_hello && impl_->is_technique_active(EvasionTechnique::GREASE_INJECTION)) {
        processed = impl_->tls_manip->inject_grease(processed.data(), processed.size());
        impl_->stats.grease_injected++;
    }
    
    // Apply TLS record splitting
    if (is_client_hello && impl_->is_technique_active(EvasionTechnique::TLS_RECORD_SPLIT)) {
        auto records = impl_->tls_manip->split_tls_record(
            processed.data(), processed.size(), 64);
        if (!records.empty()) {
            for (auto& rec : records) {
                result.push_back(std::move(rec));
            }
            impl_->stats.tls_records_split++;
            return result;
        }
    }
    
    // Apply TCP segmentation
    if (impl_->is_technique_active(EvasionTechnique::TCP_SEGMENTATION)) {
        std::vector<size_t> split_points;
        
        if (is_client_hello) {
            split_points = impl_->tls_manip->find_sni_split_points(
                processed.data(), processed.size());
        }
        
        if (processed.size() > 10) {
            split_points.push_back(1);
            split_points.push_back(processed.size() / 2);
        }
        
        if (!split_points.empty()) {
            auto segments = impl_->tcp_manip->split_segments(
                processed.data(), processed.size(), split_points);
            for (auto& seg : segments) {
                result.push_back(std::move(seg));
            }
            impl_->stats.tcp_segments_split++;
        }
    }
    
    if (result.empty()) {
        result.push_back(std::move(processed));
    }
    
    // Apply obfuscation
    if (impl_->obfuscator) {
        for (auto& segment : result) {
            auto obfuscated = impl_->obfuscator->obfuscate(
                segment.data(), segment.size());
            segment = std::move(obfuscated);
            impl_->stats.bytes_obfuscated += segment.size();
        }
    }
    
    // Apply TCP disorder - Fixed: pass dummy rng (not used anymore)
    if (impl_->is_technique_active(EvasionTechnique::TCP_DISORDER) && 
        result.size() > 1) {
        std::mt19937 dummy_rng; // Kept for API compatibility, not used
        impl_->tcp_manip->shuffle_segments(result, dummy_rng);
    }
    
    return result;
}

std::vector<uint8_t> AdvancedDPIBypass::process_incoming(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    std::vector<uint8_t> result(data, data + len);
    
    if (impl_->obfuscator) {
        result = impl_->obfuscator->deobfuscate(result.data(), result.size());
        impl_->stats.bytes_deobfuscated += result.size();
    }
    
    return result;
}

void AdvancedDPIBypass::set_log_callback(
    std::function<void(const std::string&)> callback
) {
    impl_->log_callback = callback;
}

void AdvancedDPIBypass::set_technique_enabled(
    EvasionTechnique technique,
    bool enabled
) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (enabled) {
        impl_->active_techniques.insert(technique);
    } else {
        impl_->active_techniques.erase(technique);
    }
}

std::vector<EvasionTechnique> AdvancedDPIBypass::get_active_techniques() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return std::vector<EvasionTechnique>(
        impl_->active_techniques.begin(),
        impl_->active_techniques.end());
}

void AdvancedDPIBypass::apply_preset(AdvancedDPIBypass::BypassPreset preset) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->active_techniques.clear();
    
    switch (preset) {
        case BypassPreset::MINIMAL:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            break;
            
        case BypassPreset::MODERATE:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            impl_->active_techniques.insert(EvasionTechnique::TLS_RECORD_SPLIT);
            impl_->active_techniques.insert(EvasionTechnique::SNI_SPLIT);
            impl_->active_techniques.insert(EvasionTechnique::GREASE_INJECTION);
            break;
            
        case BypassPreset::AGGRESSIVE:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            impl_->active_techniques.insert(EvasionTechnique::TLS_RECORD_SPLIT);
            impl_->active_techniques.insert(EvasionTechnique::SNI_SPLIT);
            impl_->active_techniques.insert(EvasionTechnique::GREASE_INJECTION);
            impl_->active_techniques.insert(EvasionTechnique::FAKE_SNI);
            impl_->active_techniques.insert(EvasionTechnique::TCP_DISORDER);
            break;
            
        case BypassPreset::STEALTH:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            impl_->active_techniques.insert(EvasionTechnique::TLS_RECORD_SPLIT);
            impl_->active_techniques.insert(EvasionTechnique::SNI_SPLIT);
            impl_->active_techniques.insert(EvasionTechnique::GREASE_INJECTION);
            impl_->active_techniques.insert(EvasionTechnique::TCP_DISORDER);
            impl_->active_techniques.insert(EvasionTechnique::TCP_OOB_DATA);
            break;
    }
    
    impl_->log("Applied preset with " + 
               std::to_string(impl_->active_techniques.size()) + " techniques");
}

// ==================== ECH (Encrypted Client Hello) ====================

// Apply ECH encryption to ClientHello
std::vector<uint8_t> DPIEvasion::apply_ech(
    const std::vector<uint8_t>& client_hello,
    const std::vector<uint8_t>& ech_config
) {
    std::vector<uint8_t> result = client_hello;

        // WARNING: This ECH implementation is a STUB and provides NO REAL SECURITY!
    // ECH requires HPKE encryption (RFC 9180) which is NOT implemented here.
    // Using this function gives FALSE sense of security. Either:
    // 1. Implement proper HPKE-based ECH encryption
    // 2. Or remove this function entirely
    // TODO: Issue #XX - Implement real ECH or remove stub
    #ifndef NCP_ALLOW_INSECURE_ECH_STUB
    #error "ECH stub is insecure! Define NCP_ALLOW_INSECURE_ECH_STUB to compile anyway"
    #endif

    
#ifdef HAVE_OPENSSL
    // ECH implementation using OpenSSL (TLS 1.3)
    // This is a simplified version - full ECH requires ECHConfig parsing
    // and HPKE encryption (RFC 9180)
    
    // ECH uses HPKE for encryption
    // For now, we add the ECH extension with encrypted payload
    
    if (ech_config.empty()) {
        return result; // No ECH config available
    }
    
    // Find extensions section in ClientHello
    // ClientHello structure: type(1) + length(3) + version(2) + random(32) + ...
    if (result.size() < 43) return result;
    
    // Add ECH extension (type 0xfe0d)
    std::vector<uint8_t> ech_extension;
    ech_extension.push_back(0xfe); // ECH extension type (high byte)
    ech_extension.push_back(0x0d); // ECH extension type (low byte)
    
    // Extension length (placeholder)
    uint16_t ext_len = ech_config.size() + 4;
    ech_extension.push_back(ext_len >> 8);
    ech_extension.push_back(ext_len & 0xFF);
    
    // ECH payload (simplified - should be HPKE encrypted)
    ech_extension.insert(ech_extension.end(), ech_config.begin(), ech_config.end());
    
    // Insert ECH extension into ClientHello
    result.insert(result.end(), ech_extension.begin(), ech_extension.end());
#endif
    
    return result;
}

// ==================== Domain Fronting ====================

// Helper function to find SNI hostname offset (borrowed from ncp_dpi.cpp logic)
static int find_sni_hostname_offset_internal(const uint8_t* data, size_t len) {
    if (!data || len < 5 + 4) return -1;
    
    if (data[0] != 0x16 || data[1] != 0x03) return -1;
    
    size_t pos = 5;
    if (pos + 4 > len) return -1;
    
    uint8_t handshake_type = data[pos];
    if (handshake_type != 0x01) return -1;
    
    uint32_t hs_len = (static_cast<uint32_t>(data[pos + 1]) << 16) |
                      (static_cast<uint32_t>(data[pos + 2]) << 8) |
                      static_cast<uint32_t>(data[pos + 3]);
    (void)hs_len;
    pos += 4;
    
    if (pos + 2 + 32 + 1 > len) return -1;
    pos += 2;  // client_version
    pos += 32; // random
    
    uint8_t session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > len) return -1;
    pos += session_id_len;
    
    if (pos + 2 > len) return -1;
    uint16_t cipher_suites_len = (static_cast<uint16_t>(data[pos]) << 8) |
                                 static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    if (pos + cipher_suites_len > len) return -1;
    pos += cipher_suites_len;
    
    if (pos + 1 > len) return -1;
    uint8_t compression_methods_len = data[pos];
    pos += 1;
    if (pos + compression_methods_len > len) return -1;
    pos += compression_methods_len;
    
    if (pos + 2 > len) return -1;
    uint16_t extensions_len = (static_cast<uint16_t>(data[pos]) << 8) |
                              static_cast<uint16_t>(data[pos + 1]);
    pos += 2;
    
    size_t exts_end = pos + extensions_len;
    if (exts_end > len) exts_end = len;
    
    while (pos + 4 <= exts_end) {
        uint16_t ext_type = (static_cast<uint16_t>(data[pos]) << 8) |
                            static_cast<uint16_t>(data[pos + 1]);
        uint16_t ext_data_len = (static_cast<uint16_t>(data[pos + 2]) << 8) |
                                static_cast<uint16_t>(data[pos + 3]);
        pos += 4;
        
        if (pos + ext_data_len > exts_end) break;
        
        if (ext_type == 0x0000) { // server_name extension
            size_t sni_pos = pos;
            if (sni_pos + 2 > exts_end) return -1;
            
            uint16_t list_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;
            if (sni_pos + list_len > exts_end || list_len < 3) return -1;
            
            uint8_t name_type = data[sni_pos];
            (void)name_type;
            sni_pos += 1;
            if (sni_pos + 2 > exts_end) return -1;
            
            uint16_t host_len = (static_cast<uint16_t>(data[sni_pos]) << 8) |
                                static_cast<uint16_t>(data[sni_pos + 1]);
            sni_pos += 2;
            
            if (sni_pos + host_len > exts_end) return -1;
            
            return static_cast<int>(sni_pos);
        }
        
        pos += ext_data_len;
    }
    
    return -1;
}

// Fixed: Apply domain fronting using robust SNI parser
std::vector<uint8_t> DPIEvasion::apply_domain_fronting(
    const std::vector<uint8_t>& data,
    const std::string& front_domain,
    const std::string& real_domain
) {
    std::vector<uint8_t> result = data;
    
    if (result.empty() || front_domain.empty()) {
        return result;
    }
    
    // Use proper SNI parser instead of naive byte scan
    int sni_offset = find_sni_hostname_offset_internal(result.data(), result.size());
    
    if (sni_offset < 0) {
        // SNI not found - return unmodified
        return result;
    }
    
    size_t hostname_pos = static_cast<size_t>(sni_offset);
    
    // Get current hostname length
    if (hostname_pos < 2) return result;
    size_t hostname_len_pos = hostname_pos - 2;
    uint16_t old_hostname_len = (static_cast<uint16_t>(result[hostname_len_pos]) << 8) |
                                static_cast<uint16_t>(result[hostname_len_pos + 1]);
    
    // Validate bounds
    if (hostname_pos + old_hostname_len > result.size()) {
        return result;
    }
    
    // Replace hostname with front domain
    std::vector<uint8_t> new_hostname(front_domain.begin(), front_domain.end());
    uint16_t new_hostname_len = static_cast<uint16_t>(new_hostname.size());
    
    // Erase old hostname
    result.erase(result.begin() + hostname_pos, 
                 result.begin() + hostname_pos + old_hostname_len);
    
    // Insert new hostname
    result.insert(result.begin() + hostname_pos,
                  new_hostname.begin(), new_hostname.end());
    
    // Update hostname length field
    result[hostname_len_pos] = (new_hostname_len >> 8) & 0xFF;
    result[hostname_len_pos + 1] = new_hostname_len & 0xFF;
    
    // Update SNI extension length (hostname_len + 3 for type + length)
    if (hostname_len_pos >= 5) {
        size_t sni_ext_len_pos = hostname_len_pos - 3;
        uint16_t new_list_len = new_hostname_len + 3;
        result[sni_ext_len_pos] = (new_list_len >> 8) & 0xFF;
        result[sni_ext_len_pos + 1] = new_list_len & 0xFF;
        
        // Update extension data length
        size_t ext_len_pos = sni_ext_len_pos - 2;
        uint16_t new_ext_len = new_list_len + 2;
        result[ext_len_pos] = (new_ext_len >> 8) & 0xFF;
        result[ext_len_pos + 1] = new_ext_len & 0xFF;
    }
    
    // Update TLS record and handshake lengths
    int len_delta = static_cast<int>(new_hostname_len) - static_cast<int>(old_hostname_len);
    
    // Update TLS record length (position 3-4)
    if (result.size() > 4) {
        uint16_t rec_len = (static_cast<uint16_t>(result[3]) << 8) | result[4];
        rec_len += len_delta;
        result[3] = (rec_len >> 8) & 0xFF;
        result[4] = rec_len & 0xFF;
    }
    
    // Update handshake length (position 6-8)
    if (result.size() > 8) {
        uint32_t hs_len = (static_cast<uint32_t>(result[6]) << 16) |
                          (static_cast<uint32_t>(result[7]) << 8) |
                          static_cast<uint32_t>(result[8]);
        hs_len += len_delta;
        result[6] = (hs_len >> 16) & 0xFF;
        result[7] = (hs_len >> 8) & 0xFF;
        result[8] = hs_len & 0xFF;
    }
    
    return result;
}


// ==================== Preset Configurations ====================

namespace Presets {

AdvancedDPIConfig create_tspu_preset() {
    AdvancedDPIConfig config;
    config.techniques = {
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::FAKE_SNI,
        EvasionTechnique::TLS_RECORD_SPLIT
    };
    config.obfuscation = ObfuscationMode::NONE;
    return config;
}

AdvancedDPIConfig create_gfw_preset() {
    AdvancedDPIConfig config;
    config.techniques = {
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::GREASE_INJECTION,
        EvasionTechnique::TLS_RECORD_SPLIT,
        EvasionTechnique::TCP_DISORDER
    };
    config.obfuscation = ObfuscationMode::XOR_ROLLING;
    config.obfuscation_key.resize(32);
    randombytes_buf(config.obfuscation_key.data(), config.obfuscation_key.size());
    return config;
}

AdvancedDPIConfig create_iran_preset() {
    AdvancedDPIConfig config;
    config.techniques = {
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::FAKE_SNI,
        EvasionTechnique::TLS_RECORD_SPLIT,
        EvasionTechnique::GREASE_INJECTION,
        EvasionTechnique::TCP_OOB_DATA
    };
    config.obfuscation = ObfuscationMode::XOR_SIMPLE;
    config.obfuscation_key.resize(32);
    randombytes_buf(config.obfuscation_key.data(), config.obfuscation_key.size());
    return config;
}

AdvancedDPIConfig create_aggressive_preset() {
    AdvancedDPIConfig config;
    config.techniques = {
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::TCP_OVERLAP,
        EvasionTechnique::TCP_DISORDER,
        EvasionTechnique::TCP_OOB_DATA,
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::FAKE_SNI,
        EvasionTechnique::TLS_RECORD_SPLIT,
        EvasionTechnique::TLS_PADDING,
        EvasionTechnique::GREASE_INJECTION
    };
    config.obfuscation = ObfuscationMode::CHACHA20;
    config.obfuscation_key.resize(32);
    randombytes_buf(config.obfuscation_key.data(), config.obfuscation_key.size());
    return config;
}

AdvancedDPIConfig create_stealth_preset() {
    AdvancedDPIConfig config;
    config.techniques = {
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TLS_RECORD_SPLIT,
        EvasionTechnique::GREASE_INJECTION,
        EvasionTechnique::TCP_DISORDER
    };
    config.obfuscation = ObfuscationMode::CHACHA20;
    config.obfuscation_key.resize(32);
    randombytes_buf(config.obfuscation_key.data(), config.obfuscation_key.size());
    return config;
}

AdvancedDPIConfig create_compatible_preset() {
    AdvancedDPIConfig config;
    config.techniques = {
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::SNI_SPLIT
    };
    config.obfuscation = ObfuscationMode::NONE;
    return config;
}

} // namespace Presets

} // namespace DPI

} // namespace ncp
