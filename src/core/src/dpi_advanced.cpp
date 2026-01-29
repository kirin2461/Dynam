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

namespace NCP {
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
    
    // Create overlapping segments for DPI confusion
    size_t segment_size = std::max<size_t>(overlap_size * 2, 16);
    size_t offset = 0;
    
    while (offset < len) {
        size_t end = std::min(offset + segment_size, len);
        segments.emplace_back(data + offset, data + end);
        
        if (end < len) {
            // Add overlap - send some bytes again
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
    // TCP OOB data uses urgent pointer
    // This is a simplified marker - actual OOB requires socket-level control
    std::vector<uint8_t> result(data, data + len);
    if (urgent_position < len) {
        // Mark position for urgent data handling
        result.insert(result.begin() + urgent_position, 0x00);  // Placeholder
    }
    return result;
}

void TCPManipulator::shuffle_segments(
    std::vector<std::vector<uint8_t>>& segments,
    std::mt19937& rng
) {
    if (segments.size() <= 1) return;
    // Partial shuffle - don't fully randomize to maintain some order
    for (size_t i = segments.size() - 1; i > 0; --i) {
        size_t j = rng() % (i + 1);
        if (j != i && (rng() % 2 == 0)) {  // 50% chance to swap
            std::swap(segments[i], segments[j]);
        }
    }
}

// TLSManipulator implementation
struct TLSManipulator::Impl {
    std::mt19937 rng{std::random_device{}()};
    
    // GREASE values for TLS extension randomization
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
    
    // TLS record header check
    if (!data || len < 43) return points;
    if (data[0] != 0x16 || data[1] != 0x03) return points;  // Not TLS handshake
    
    // Parse to find SNI extension
    size_t pos = 5;  // Skip record header
    if (pos + 4 > len || data[pos] != 0x01) return points;  // Not ClientHello
    
    pos += 4;  // Skip handshake header
    pos += 2 + 32;  // Skip version and random
    
    if (pos + 1 > len) return points;
    uint8_t session_id_len = data[pos++];
    pos += session_id_len;
    
    if (pos + 2 > len) return points;
    uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_len;
    
    if (pos + 1 > len) return points;
    pos += 1 + data[pos];  // compression methods
    
    if (pos + 2 > len) return points;
    uint16_t ext_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    size_t ext_end = std::min(pos + ext_len, len);
    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_data_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        
        if (ext_type == 0x0000) {  // SNI extension
            if (pos + 5 <= ext_end) {
                // Split before SNI hostname
                points.push_back(pos);
                // Split in middle of hostname
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
    
    // Parse TLS record header
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
    // TLS 1.3 supports record padding
    // Add padding as zeros followed by content type
    for (size_t i = 0; i < padding_size; ++i) {
        result.push_back(0x00);
    }
    return result;
}

std::vector<uint8_t> TLSManipulator::inject_grease(
    const uint8_t* data,
    size_t len
) {
    // GREASE (Generate Random Extensions And Sustain Extensibility)
    // Add random GREASE values to make fingerprinting harder
    std::vector<uint8_t> result(data, data + len);
    
    uint16_t grease = impl_->GREASE_VALUES[impl_->rng() % 16];
    // This would need to be injected into the extensions list
    // For now, return as-is (full implementation requires TLS parsing)
    
    return result;
}

std::vector<uint8_t> TLSManipulator::create_fake_client_hello(
    const std::string& fake_sni
) {
    std::vector<uint8_t> hello;
    
    // TLS record header
    hello.push_back(0x16);  // Handshake
    hello.push_back(0x03);  // TLS 1.0 for compatibility
    hello.push_back(0x01);
    
    // Placeholder for length (will be filled later)
    size_t len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // Handshake header
    hello.push_back(0x01);  // ClientHello
    size_t hs_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // Client version (TLS 1.2)
    hello.push_back(0x03);
    hello.push_back(0x03);
    
    // Random (32 bytes)
    for (int i = 0; i < 32; ++i) {
        hello.push_back(impl_->rng() & 0xFF);
    }
    
    // Session ID (0 length)
    hello.push_back(0x00);
    
    // Cipher suites
    hello.push_back(0x00);
    hello.push_back(0x02);
    hello.push_back(0x00);
    hello.push_back(0x3C);  // TLS_RSA_WITH_AES_128_CBC_SHA256
    
    // Compression methods
    hello.push_back(0x01);
    hello.push_back(0x00);
    
    // Extensions with fake SNI
    size_t ext_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // SNI extension
    hello.push_back(0x00);
    hello.push_back(0x00);
    size_t sni_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // SNI list
    size_t list_len_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // Host name entry
    hello.push_back(0x00);  // host_name type
    hello.push_back((fake_sni.size() >> 8) & 0xFF);
    hello.push_back(fake_sni.size() & 0xFF);
    hello.insert(hello.end(), fake_sni.begin(), fake_sni.end());
    
    // Fill in lengths
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
    size_t xor_offset = 0;  // For rolling XOR
    
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
                // Generate pseudo-random nonce from key
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
    // XOR is its own inverse, ChaCha20 too
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
    
    // Initialize active techniques
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
    
    // Detect if this is TLS ClientHello
    bool is_client_hello = (len > 5 && data[0] == 0x16 && 
                            data[1] == 0x03 && data[5] == 0x01);
    
    std::vector<uint8_t> processed(data, data + len);
    
    // Apply TLS-level techniques if ClientHello
    if (is_client_hello) {
        if (impl_->is_technique_active(EvasionTechnique::TLS_RECORD_SPLIT)) {
            auto records = impl_->tls_manip->split_tls_record(
                processed.data(), processed.size(), 64);
            if (!records.empty()) {
                for (auto& rec : records) {
                    result.push_back(std::move(rec));
                }
                impl_->stats.tls_records_split++;
                return result;  // Already split
            }
        }
    }
    
    // Apply TCP segmentation
    if (impl_->is_technique_active(EvasionTechnique::TCP_SEGMENTATION)) {
        std::vector<size_t> split_points;
        
        if (is_client_hello) {
            split_points = impl_->tls_manip->find_sni_split_points(
                processed.data(), processed.size());
        }
        
        // Add additional split points
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
    
    // If no segmentation applied, return as single chunk
    if (result.empty()) {
        result.push_back(std::move(processed));
    }
    
    // Apply obfuscation if enabled
    if (impl_->obfuscator) {
        for (auto& segment : result) {
            auto obfuscated = impl_->obfuscator->obfuscate(
                segment.data(), segment.size());
            segment = std::move(obfuscated);
            impl_->stats.bytes_obfuscated += segment.size();
        }
    }
    
    // Apply padding if enabled
    if (impl_->config.padding.enabled) {
        std::uniform_int_distribution<size_t> dist(
            impl_->config.padding.min_padding,
            impl_->config.padding.max_padding);
        
        for (auto& segment : result) {
            size_t pad_size = dist(impl_->rng);
            for (size_t i = 0; i < pad_size; ++i) {
                segment.push_back(impl_->config.padding.random_padding ?
                    (impl_->rng() & 0xFF) : impl_->config.padding.padding_byte);
            }
            impl_->stats.packets_padded++;
            impl_->stats.bytes_padding += pad_size;
        }
    }
    
    // Apply disorder if enabled
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
    
    // Deobfuscate if needed
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

void AdvancedDPIBypass::apply_preset(BypassPreset preset) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->active_techniques.clear();
    
    switch (preset) {
        case BypassPreset::MINIMAL:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            break;
            
        case BypassPreset::MODERATE:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            impl_->active_techniques.insert(EvasionTechnique::TLS_RECORD_SPLITTING);
            impl_->active_techniques.insert(EvasionTechnique::SNI_SPLITTING);
            break;
            
        case BypassPreset::AGGRESSIVE:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            impl_->active_techniques.insert(EvasionTechnique::TLS_RECORD_SPLITTING);
            impl_->active_techniques.insert(EvasionTechnique::SNI_SPLITTING);
            impl_->active_techniques.insert(EvasionTechnique::FAKE_SNI);
            impl_->active_techniques.insert(EvasionTechnique::TLS_PADDING);
            impl_->active_techniques.insert(EvasionTechnique::TIMING_MANIPULATION);
            break;
            
        case BypassPreset::STEALTH:
            impl_->active_techniques.insert(EvasionTechnique::TCP_SEGMENTATION);
            impl_->active_techniques.insert(EvasionTechnique::TLS_RECORD_SPLITTING);
            impl_->active_techniques.insert(EvasionTechnique::SNI_SPLITTING);
            impl_->active_techniques.insert(EvasionTechnique::TLS_PADDING);
            impl_->active_techniques.insert(EvasionTechnique::TIMING_MANIPULATION);
            impl_->active_techniques.insert(EvasionTechnique::TRAFFIC_SHAPING);
            impl_->active_techniques.insert(EvasionTechnique::DECOY_TRAFFIC);
            break;
    }
    
    log("Applied preset with " + std::to_string(impl_->active_techniques.size()) + " techniques");
}
}

std::vector<std::vector<uint8_t>> AdvancedDPIBypass::process_outgoing(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::vector<std::vector<uint8_t>> result;
    
    std::vector<uint8_t> current(data, data + len);
    
    // Apply TCP manipulations
    if (has_technique(EvasionTechnique::TCP_SEGMENTATION)) {
        auto segments = impl_->tcp_manipulator->segment(current.data(), current.size());
        if (!segments.empty()) {
            for (auto& seg : segments) {
                result.push_back(std::move(seg));
            }
            impl_->stats.packets_segmented++;
        }
    }
    
    if (result.empty()) {
        result.push_back(current);
    }
    
    // Apply TLS manipulations to each segment
    if (has_technique(EvasionTechnique::TLS_RECORD_SPLITTING) ||
        has_technique(EvasionTechnique::SNI_SPLITTING) ||
        has_technique(EvasionTechnique::TLS_PADDING)) {
        
        std::vector<std::vector<uint8_t>> tls_processed;
        for (auto& segment : result) {
            auto processed = impl_->tls_manipulator->process_clienthello(
                segment.data(), segment.size());
            if (!processed.empty()) {
                tls_processed.push_back(std::move(processed));
                impl_->stats.tls_records_modified++;
            } else {
                tls_processed.push_back(std::move(segment));
            }
        }
        result = std::move(tls_processed);
    }
    
    // Apply obfuscation
    if (impl_->obfuscator) {
        for (auto& segment : result) {
            segment = impl_->obfuscator->obfuscate(segment.data(), segment.size());
            impl_->stats.bytes_obfuscated += segment.size();
        }
    }
    
    impl_->stats.total_packets_processed++;
    return result;
}

std::vector<uint8_t> AdvancedDPIBypass::process_incoming(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    std::vector<uint8_t> result(data, data + len);
    
    // Deobfuscate if needed
    if (impl_->obfuscator) {
        result = impl_->obfuscator->deobfuscate(result.data(), result.size());
        impl_->stats.bytes_deobfuscated += result.size();
    }
    
    return result;
}

BypassStats AdvancedDPIBypass::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->stats;
}

void AdvancedDPIBypass::reset_stats() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->stats = BypassStats{};
}

bool AdvancedDPIBypass::has_technique(EvasionTechnique technique) const {
    return impl_->active_techniques.count(technique) > 0;
}

void AdvancedDPIBypass::log(const std::string& message) {
    if (impl_->log_callback) {
        impl_->log_callback(message);
    }
}

} // namespace ncp
