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
#include <random>
#include <set>

namespace ncp {
namespace DPI {

// TCPManipulator implementation
struct TCPManipulator::Impl {
    std::mt19937 rng{std::random_device{}()};
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
    std::mt19937& rng
) {
    if (segments.size() <= 1) return;
    for (size_t i = segments.size() - 1; i > 0; --i) {
        std::uniform_int_distribution<size_t> dist(0, i);  // Proper uniform distribution
            size_t j = dist(rng);
        if (j != i && (rng() % 2 == 0)) {
            std::swap(segments[i], segments[j]);
        }
    }
}

// TLSManipulator implementation
struct TLSManipulator::Impl {
    std::mt19937 rng{std::random_device{}()};
    
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
    
    // Select random GREASE value
    uint16_t grease = impl_->GREASE_VALUES[impl_->rng() % 16];
    
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
    
    for (int i = 0; i < 32; ++i) {
        hello.push_back(impl_->rng() & 0xFF);
    }
    
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
    std::mt19937 rng{std::random_device{}()};
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
    
    std::vector<uint8_t> result(len);
    
    switch (impl_->mode) {
        case ObfuscationMode::XOR_SIMPLE:
            for (size_t i = 0; i < len; ++i) {
                result[i] = data[i] ^ impl_->key[i % impl_->key.size()];
            }
            break;
            
        case ObfuscationMode::XOR_ROLLING:
            for (size_t i = 0; i < len; ++i) {
                size_t key_idx = (impl_->xor_offset + i) % impl_->key.size();
                result[i] = data[i] ^ impl_->key[key_idx];
            }
            impl_->xor_offset = (impl_->xor_offset + len) % impl_->key.size();
            break;
            
        case ObfuscationMode::CHACHA20:
            if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES) {
                uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
                for (size_t i = 0; i < sizeof(nonce); ++i) {
                    nonce[i] = impl_->key[(i + 16) % impl_->key.size()];
                }
                crypto_stream_chacha20_xor(result.data(), data, len,
                                          nonce, impl_->key.data());
            } else {
                std::copy(data, data + len, result.begin());
            }
            break;
            
        case ObfuscationMode::NONE:
        default:
            std::copy(data, data + len, result.begin());
            break;
    }
    
    return result;
}

std::vector<uint8_t> TrafficObfuscator::deobfuscate(
    const uint8_t* data,
    size_t len
) {
    return obfuscate(data, len);
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
    std::mt19937 rng{std::random_device{}()};
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
    
    // Apply TCP disorder
    if (impl_->is_technique_active(EvasionTechnique::TCP_DISORDER) && 
        result.size() > 1) {
        impl_->tcp_manip->shuffle_segments(result, impl_->rng);
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

// Apply domain fronting by manipulating SNI and Host headers
std::vector<uint8_t> DPIEvasion::apply_domain_fronting(
    const std::vector<uint8_t>& data,
    const std::string& front_domain,
    const std::string& real_domain
) {
    std::vector<uint8_t> result = data;
    
    // Replace SNI in TLS ClientHello
    // SNI is in TLS extensions (type 0x0000)
    for (size_t i = 0; i < result.size() - 5; i++) {
        // Look for SNI extension pattern
        if (result[i] == 0x00 && result[i+1] == 0x00) {
            // Found potential SNI extension
            uint16_t ext_len = (result[i+2] << 8) | result[i+3];
            
            if (i + 4 + ext_len <= result.size()) {
                // Replace SNI hostname with front domain
                // SNI structure: type(2) + length(2) + list_length(2) + type(1) + hostname_length(2) + hostname
                size_t hostname_offset = i + 9;
                
                if (hostname_offset < result.size()) {
                    // Replace hostname with front domain
                    std::vector<uint8_t> new_sni(front_domain.begin(), front_domain.end());
                    
                    // Update lengths
                    uint16_t new_hostname_len = new_sni.size();
                    uint16_t new_list_len = new_hostname_len + 3;
                    uint16_t new_ext_len = new_list_len + 2;
                    
                    result[i+2] = new_ext_len >> 8;
                    result[i+3] = new_ext_len & 0xFF;
                    result[i+4] = new_list_len >> 8;
                    result[i+5] = new_list_len & 0xFF;
                    result[i+7] = new_hostname_len >> 8;
                    result[i+8] = new_hostname_len & 0xFF;
                    
                    // Replace hostname
                    result.erase(result.begin() + hostname_offset, result.begin() + hostname_offset + ext_len - 5);
                    result.insert(result.begin() + hostname_offset, new_sni.begin(), new_sni.end());
                    
                    break;
                }
            }
        }
    }
    
    return result;
}

} // namespace DPI
} // namespace ncp
