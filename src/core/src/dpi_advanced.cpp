#include "../include/ncp_dpi_advanced.hpp"
#include "../include/ncp_dpi.hpp"
#include "../include/ncp_ech.hpp"
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
#include <chrono>
#include <random>

namespace ncp {
namespace DPI {

// ==================== Helper Functions ====================

namespace {

// Secure random number generator using libsodium
inline uint32_t secure_random(uint32_t max) {
    return randombytes_uniform(max);
}

// Generate random bytes
inline std::vector<uint8_t> random_bytes(size_t count) {
    std::vector<uint8_t> result(count);
    randombytes_buf(result.data(), count);
    return result;
}

// GREASE values for TLS (RFC 8701)
static const std::vector<uint16_t> GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
};

inline uint16_t get_random_grease() {
    return GREASE_VALUES[secure_random(static_cast<uint32_t>(GREASE_VALUES.size()))];
}

} // anonymous namespace

// ==================== TCPManipulator Implementation ====================

struct TCPManipulator::Impl {
    // No RNG needed - using libsodium CSPRNG
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
    
    // Validate and sort split points
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
    
    // Create segments
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
        
        // Create overlapping segment
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
        // Insert OOB marker
        result.insert(result.begin() + urgent_position, 0x00);
    }
    return result;
}

void TCPManipulator::shuffle_segments(
    std::vector<std::vector<uint8_t>>& segments,
    std::mt19937& /* unused - kept for API compatibility */
) {
    if (segments.size() <= 1) return;
    
    // Fisher-Yates shuffle using libsodium
    for (size_t i = segments.size() - 1; i > 0; --i) {
        uint32_t j = secure_random(static_cast<uint32_t>(i + 1));
        std::swap(segments[i], segments[j]);
    }
}

// ==================== TLSManipulator Implementation ====================

struct TLSManipulator::Impl {
    // Helper to parse TLS ClientHello structure
    static int find_sni_offset(const uint8_t* data, size_t len);
};

TLSManipulator::TLSManipulator() : impl_(std::make_unique<Impl>()) {}
TLSManipulator::~TLSManipulator() = default;

int TLSManipulator::Impl::find_sni_offset(const uint8_t* data, size_t len) {
    if (!data || len < 5 + 4) return -1;
    
    // TLS record header (5 bytes) + handshake header
    if (data[0] != 0x16 || data[1] != 0x03) return -1;
    
    size_t pos = 5; // Skip TLS record header
    if (pos + 4 > len) return -1;
    
    // Handshake type must be ClientHello (0x01)
    if (data[pos] != 0x01) return -1;
    
    pos += 4; // Skip handshake header
    
    // Skip client_version (2) + random (32)
    if (pos + 2 + 32 + 1 > len) return -1;
    pos += 2 + 32;
    
    // Skip session_id
    uint8_t session_id_len = data[pos++];
    if (pos + session_id_len > len) return -1;
    pos += session_id_len;
    
    // Skip cipher_suites
    if (pos + 2 > len) return -1;
    uint16_t cipher_suites_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (pos + cipher_suites_len > len) return -1;
    pos += cipher_suites_len;
    
    // Skip compression_methods
    if (pos + 1 > len) return -1;
    uint8_t compression_len = data[pos++];
    if (pos + compression_len > len) return -1;
    pos += compression_len;
    
    // Parse extensions
    if (pos + 2 > len) return -1;
    uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    
    size_t exts_end = std::min(pos + extensions_len, len);
    
    // Find SNI extension (type 0x0000)
    while (pos + 4 <= exts_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        
        if (pos + ext_len > exts_end) break;
        
        if (ext_type == 0x0000) { // server_name extension
            if (pos + 2 > exts_end) return -1;
            uint16_t list_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            
            if (pos + list_len > exts_end || list_len < 3) return -1;
            
            // Skip name_type (1 byte)
            pos += 1;
            if (pos + 2 > exts_end) return -1;
            
            uint16_t hostname_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            
            if (pos + hostname_len > exts_end) return -1;
            
            // Return offset to hostname
            return static_cast<int>(pos);
        }
        
        pos += ext_len;
    }
    
    return -1;
}

std::vector<size_t> TLSManipulator::find_sni_split_points(
    const uint8_t* data,
    size_t len
) {
    std::vector<size_t> split_points;
    
    int sni_offset = Impl::find_sni_offset(data, len);
    if (sni_offset > 0) {
        size_t sni_pos = static_cast<size_t>(sni_offset);
        
        // Split before SNI
        split_points.push_back(sni_pos);
        
        // Additional split inside SNI hostname for aggressive bypass
        if (sni_pos + 4 < len) {
            split_points.push_back(sni_pos + 2);
        }
    } else {
        // Fallback: split at TLS record boundary
        if (len > 40) {
            split_points.push_back(40);
        }
    }
    
    return split_points;
}

std::vector<std::vector<uint8_t>> TLSManipulator::split_tls_record(
    const uint8_t* data,
    size_t len,
    size_t max_fragment_size
) {
    std::vector<std::vector<uint8_t>> fragments;
    if (!data || len == 0) return fragments;
    
    size_t offset = 0;
    while (offset < len) {
        size_t chunk_size = std::min(max_fragment_size, len - offset);
        fragments.emplace_back(data + offset, data + offset + chunk_size);
        offset += chunk_size;
    }
    
    return fragments;
}

std::vector<uint8_t> TLSManipulator::add_tls_padding(
    const uint8_t* data,
    size_t len,
    size_t padding_size
) {
    if (!data || len == 0) return {};
    
    std::vector<uint8_t> result(data, data + len);
    
    // Add random padding bytes
    auto padding = random_bytes(padding_size);
    result.insert(result.end(), padding.begin(), padding.end());
    
    return result;
}

std::vector<uint8_t> TLSManipulator::inject_grease(
    const uint8_t* data,
    size_t len
) {
    if (!data || len < 10) {
        return std::vector<uint8_t>(data, data + len);
    }
    
    std::vector<uint8_t> result(data, data + len);
    
    // Inject GREASE values at random positions in extensions
    // (Simplified: just modify a few bytes to add randomness)
    size_t inject_pos = 5 + secure_random(std::min(static_cast<uint32_t>(20), static_cast<uint32_t>(len - 5)));
    if (inject_pos + 2 < result.size()) {
        uint16_t grease = get_random_grease();
        result[inject_pos] = (grease >> 8) & 0xFF;
        result[inject_pos + 1] = grease & 0xFF;
    }
    
    return result;
}

std::vector<uint8_t> TLSManipulator::create_fake_client_hello(
    const std::string& fake_sni
) {
    // Minimal TLS 1.2 ClientHello with fake SNI
    std::vector<uint8_t> hello;
    
    // TLS record header
    hello.push_back(0x16); // Handshake
    hello.push_back(0x03); // Version major
    hello.push_back(0x01); // Version minor (TLS 1.0 for compatibility)
    
    // Length placeholder (will be filled later)
    size_t length_pos = hello.size();
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // Handshake header
    hello.push_back(0x01); // ClientHello
    hello.push_back(0x00); // Length (3 bytes, filled later)
    hello.push_back(0x00);
    hello.push_back(0x00);
    
    // ClientHello content
    hello.push_back(0x03); // Version major
    hello.push_back(0x03); // Version minor (TLS 1.2)
    
    // Random (32 bytes)
    auto random_data = random_bytes(32);
    hello.insert(hello.end(), random_data.begin(), random_data.end());
    
    // Session ID (empty)
    hello.push_back(0x00);
    
    // Cipher suites (minimal)
    hello.push_back(0x00);
    hello.push_back(0x02); // 2 bytes
    hello.push_back(0x00);
    hello.push_back(0x2f); // TLS_RSA_WITH_AES_128_CBC_SHA
    
    // Compression methods
    hello.push_back(0x01); // 1 byte
    hello.push_back(0x00); // null compression
    
    // Extensions
    size_t ext_length_pos = hello.size();
    hello.push_back(0x00); // Extensions length (2 bytes, filled later)
    hello.push_back(0x00);
    
    // SNI extension
    hello.push_back(0x00); // Extension type: server_name
    hello.push_back(0x00);
    
    size_t sni_ext_len = 5 + fake_sni.length();
    hello.push_back(static_cast<uint8_t>((sni_ext_len >> 8) & 0xFF));
    hello.push_back(static_cast<uint8_t>(sni_ext_len & 0xFF));
    
    // SNI list length
    hello.push_back(static_cast<uint8_t>(((sni_ext_len - 2) >> 8) & 0xFF));
    hello.push_back(static_cast<uint8_t>((sni_ext_len - 2) & 0xFF));
    
    // SNI entry
    hello.push_back(0x00); // hostname type
    hello.push_back(static_cast<uint8_t>((fake_sni.length() >> 8) & 0xFF));
    hello.push_back(static_cast<uint8_t>(fake_sni.length() & 0xFF));
    hello.insert(hello.end(), fake_sni.begin(), fake_sni.end());
    
    // Fill in lengths
    uint16_t total_len = static_cast<uint16_t>(hello.size() - 5);
    hello[length_pos] = static_cast<uint8_t>((total_len >> 8) & 0xFF);
    hello[length_pos + 1] = static_cast<uint8_t>(total_len & 0xFF);
    
    uint32_t handshake_len = static_cast<uint32_t>(hello.size() - 9);
    hello[6] = static_cast<uint8_t>((handshake_len >> 16) & 0xFF);
    hello[7] = static_cast<uint8_t>((handshake_len >> 8) & 0xFF);
    hello[8] = static_cast<uint8_t>(handshake_len & 0xFF);
    
    uint16_t ext_len = static_cast<uint16_t>(hello.size() - ext_length_pos - 2);
    hello[ext_length_pos] = static_cast<uint8_t>((ext_len >> 8) & 0xFF);
    hello[ext_length_pos + 1] = static_cast<uint8_t>(ext_len & 0xFF);
    
    return hello;
}

// ==================== TrafficObfuscator Implementation ====================

struct TrafficObfuscator::Impl {
    ObfuscationMode mode;
    std::vector<uint8_t> key;
    size_t xor_offset = 0;
    
    Impl(ObfuscationMode m, const std::vector<uint8_t>& k)
        : mode(m), key(k) {
        if (key.empty()) {
            key.resize(crypto_stream_chacha20_KEYBYTES);
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
        case ObfuscationMode::XOR_SIMPLE: {
            result.resize(len);
            for (size_t i = 0; i < len; ++i) {
                result[i] = data[i] ^ impl_->key[i % impl_->key.size()];
            }
            break;
        }
            
        case ObfuscationMode::XOR_ROLLING: {
            result.resize(len);
            for (size_t i = 0; i < len; ++i) {
                size_t key_idx = (impl_->xor_offset + i) % impl_->key.size();
                result[i] = data[i] ^ impl_->key[key_idx];
            }
            impl_->xor_offset = (impl_->xor_offset + len) % impl_->key.size();
            break;
        }
            
        case ObfuscationMode::CHACHA20: {
            if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES) {
                uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
                randombytes_buf(nonce, sizeof(nonce));
                
                result.resize(sizeof(nonce) + len);
                std::copy(nonce, nonce + sizeof(nonce), result.begin());
                
                crypto_stream_chacha20_xor(
                    result.data() + sizeof(nonce),
                    data,
                    len,
                    nonce,
                    impl_->key.data()
                );
            } else {
                result.assign(data, data + len);
            }
            break;
        }
            
        case ObfuscationMode::HTTP_CAMOUFLAGE: {
            // Wrap data in fake HTTP response
            std::string header = "HTTP/1.1 200 OK\r\n"
                               "Content-Type: text/html\r\n"
                               "Content-Length: " + std::to_string(len) + "\r\n"
                               "\r\n";
            result.reserve(header.size() + len);
            result.insert(result.end(), header.begin(), header.end());
            result.insert(result.end(), data, data + len);
            break;
        }
            
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
        case ObfuscationMode::CHACHA20: {
            if (impl_->key.size() >= crypto_stream_chacha20_KEYBYTES &&
                len > crypto_stream_chacha20_NONCEBYTES) {
                
                const uint8_t* nonce = data;
                const uint8_t* ciphertext = data + crypto_stream_chacha20_NONCEBYTES;
                size_t ciphertext_len = len - crypto_stream_chacha20_NONCEBYTES;
                
                std::vector<uint8_t> result(ciphertext_len);
                crypto_stream_chacha20_xor(
                    result.data(),
                    ciphertext,
                    ciphertext_len,
                    nonce,
                    impl_->key.data()
                );
                return result;
            }
            return std::vector<uint8_t>(data, data + len);
        }
        
        case ObfuscationMode::HTTP_CAMOUFLAGE: {
            // Strip HTTP header
            const char* header_end = "\r\n\r\n";
            auto it = std::search(
                data, data + len,
                header_end, header_end + 4
            );
            if (it != data + len) {
                size_t offset = (it - data) + 4;
                return std::vector<uint8_t>(data + offset, data + len);
            }
            return std::vector<uint8_t>(data, data + len);
        }
            
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

// ==================== AdvancedDPIBypass Implementation ====================

struct AdvancedDPIBypass::Impl {
    std::atomic<bool> running{false};
    AdvancedDPIConfig config;
    AdvancedDPIStats stats;
    
    std::unique_ptr<DPIBypass> base_bypass;
    std::unique_ptr<TCPManipulator> tcp_manip;
    std::unique_ptr<TLSManipulator> tls_manip;
    std::unique_ptr<TrafficObfuscator> obfuscator;
    
    std::function<void(const std::string&)> log_callback;
    mutable std::mutex stats_mutex;
    
    // Adaptive fragmentation state
    std::atomic<int> detection_counter{0};
    std::atomic<int> current_strategy{0};
    
    void log(const std::string& msg) {
        if (log_callback) {
            log_callback(msg);
        }
    }
};

AdvancedDPIBypass::AdvancedDPIBypass() : impl_(std::make_unique<Impl>()) {}
AdvancedDPIBypass::~AdvancedDPIBypass() { stop(); }

bool AdvancedDPIBypass::initialize(const AdvancedDPIConfig& config) {
    impl_->config = config;
    
    // Initialize base DPI bypass
    impl_->base_bypass = std::make_unique<DPIBypass>();
    if (!impl_->base_bypass->initialize(config.base_config)) {
        impl_->log("Failed to initialize base DPI bypass");
        return false;
    }
    
    // Initialize manipulators
    impl_->tcp_manip = std::make_unique<TCPManipulator>();
    impl_->tls_manip = std::make_unique<TLSManipulator>();
    
    // Initialize obfuscator if enabled
    if (config.obfuscation != ObfuscationMode::NONE) {
        impl_->obfuscator = std::make_unique<TrafficObfuscator>(
            config.obfuscation,
            config.obfuscation_key
        );
    }
    
    impl_->log("Advanced DPI bypass initialized with " +
              std::to_string(config.techniques.size()) + " techniques");
    
    return true;
}

bool AdvancedDPIBypass::start() {
    if (!impl_->base_bypass) {
        impl_->log("Base bypass not initialized");
        return false;
    }
    
    impl_->running = true;
    
    if (!impl_->base_bypass->start()) {
        impl_->log("Failed to start base DPI bypass");
        impl_->running = false;
        return false;
    }
    
    impl_->log("Advanced DPI bypass started");
    return true;
}

void AdvancedDPIBypass::stop() {
    impl_->running = false;
    
    if (impl_->base_bypass) {
        impl_->base_bypass->stop();
    }
    
    impl_->log("Advanced DPI bypass stopped");
}

bool AdvancedDPIBypass::is_running() const {
    return impl_->running;
}

AdvancedDPIStats AdvancedDPIBypass::get_stats() const {
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    
    AdvancedDPIStats stats = impl_->stats;
    if (impl_->base_bypass) {
        stats.base_stats = impl_->base_bypass->get_stats();
    }
    
    return stats;
}

std::vector<std::vector<uint8_t>> AdvancedDPIBypass::process_outgoing(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    std::vector<std::vector<uint8_t>> result;
    std::vector<uint8_t> working_data(data, data + len);
    
    const auto& cfg = impl_->config;
    const auto& techniques = cfg.techniques;
    
    // Check if this is TLS ClientHello
    bool is_client_hello = (len > 5 && data[0] == 0x16 && 
                            data[1] == 0x03 && data[5] == 0x01);
    
    // Apply pattern obfuscation
    if (cfg.base_config.enable_pattern_obfuscation && is_client_hello) {
        // Inject GREASE for TLS fingerprint randomization
        working_data = impl_->tls_manip->inject_grease(
            working_data.data(),
            working_data.size()
        );
        
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.grease_injected++;
    }
    
    // Apply decoy SNI
    if (cfg.base_config.enable_decoy_sni && is_client_hello &&
        !cfg.base_config.decoy_sni_domains.empty()) {
        
        // Send fake ClientHello with decoy SNI first
        for (const auto& decoy_domain : cfg.base_config.decoy_sni_domains) {
            auto fake_hello = impl_->tls_manip->create_fake_client_hello(decoy_domain);
            result.push_back(std::move(fake_hello));
            
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.fake_packets_injected++;
        }
    }
    
    // Apply multi-layer split - Fix C2664: convert vector<int> to vector<size_t>
    if (cfg.base_config.enable_multi_layer_split && is_client_hello &&
        !cfg.base_config.split_positions.empty()) {
        
        // Convert vector<int> to vector<size_t>
        std::vector<size_t> split_positions_size_t;
        split_positions_size_t.reserve(cfg.base_config.split_positions.size());
        for (int pos : cfg.base_config.split_positions) {
            if (pos >= 0) {
                split_positions_size_t.push_back(static_cast<size_t>(pos));
            }
        }
        
        auto segments = impl_->tcp_manip->split_segments(
            working_data.data(),
            working_data.size(),
            split_positions_size_t
        );
        
        result.insert(result.end(), segments.begin(), segments.end());
        
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.tcp_segments_split += segments.size();
    } else if (is_client_hello) {
        // Standard SNI-based split
        auto split_points = impl_->tls_manip->find_sni_split_points(
            working_data.data(),
            working_data.size()
        );
        
        if (!split_points.empty()) {
            // Apply randomization if enabled
            if (cfg.base_config.randomize_split_position) {
                int jitter = static_cast<int>(secure_random(static_cast<uint32_t>(
                    cfg.base_config.split_position_max - cfg.base_config.split_position_min + 1
                )));
                jitter += cfg.base_config.split_position_min;
                
                for (auto& pt : split_points) {
                    pt = std::min(pt + static_cast<size_t>(jitter), working_data.size() - 1);
                }
            }
            
            auto segments = impl_->tcp_manip->split_segments(
                working_data.data(),
                working_data.size(),
                split_points
            );
            
            result.insert(result.end(), segments.begin(), segments.end());
            
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.tls_records_split++;
        } else {
            result.push_back(working_data);
        }
    } else {
        result.push_back(working_data);
    }
    
    // Apply padding if enabled
    if (cfg.padding.enabled && cfg.padding.max_padding > 0) {
        for (auto& segment : result) {
            size_t padding_size = cfg.padding.random_padding
                ? secure_random(static_cast<uint32_t>(
                    cfg.padding.max_padding - cfg.padding.min_padding + 1
                  )) + cfg.padding.min_padding
                : cfg.padding.max_padding;
            
            segment = impl_->tls_manip->add_tls_padding(
                segment.data(),
                segment.size(),
                padding_size
            );
            
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.packets_padded++;
            impl_->stats.bytes_padding += padding_size;
        }
    }
    
    // Apply obfuscation
    if (impl_->obfuscator) {
        for (auto& segment : result) {
            segment = impl_->obfuscator->obfuscate(segment.data(), segment.size());
            
            std::lock_guard<std::mutex> lock(impl_->stats_mutex);
            impl_->stats.bytes_obfuscated += segment.size();
        }
    }
    
    // Apply timing jitter if enabled
    if (cfg.base_config.enable_timing_jitter && result.size() > 1) {
        // Add small delays between segments (caller should handle this)
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.timing_delays_applied += result.size() - 1;
    }
    
    return result;
}

std::vector<uint8_t> AdvancedDPIBypass::process_incoming(
    const uint8_t* data,
    size_t len
) {
    if (!data || len == 0) return {};
    
    // Reverse obfuscation if enabled
    if (impl_->obfuscator) {
        auto result = impl_->obfuscator->deobfuscate(data, len);
        
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        impl_->stats.bytes_deobfuscated += result.size();
        
        return result;
    }
    
    return std::vector<uint8_t>(data, data + len);
}

void AdvancedDPIBypass::set_log_callback(std::function<void(const std::string&)> callback) {
    impl_->log_callback = std::move(callback);
}

void AdvancedDPIBypass::set_technique_enabled(EvasionTechnique technique, bool enabled) {
    auto& techniques = impl_->config.techniques;
    auto it = std::find(techniques.begin(), techniques.end(), technique);
    
    if (enabled && it == techniques.end()) {
        techniques.push_back(technique);
    } else if (!enabled && it != techniques.end()) {
        techniques.erase(it);
    }
}

std::vector<EvasionTechnique> AdvancedDPIBypass::get_active_techniques() const {
    return impl_->config.techniques;
}

void AdvancedDPIBypass::apply_preset(BypassPreset preset) {
    auto& cfg = impl_->config.base_config;
    auto& techniques = impl_->config.techniques;
    techniques.clear();
    
    switch (preset) {
        case BypassPreset::MINIMAL:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;
            cfg.enable_noise = false;
            cfg.enable_fake_packet = false;
            techniques.push_back(EvasionTechnique::SNI_SPLIT);
            break;
            
        case BypassPreset::MODERATE:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;
            cfg.enable_noise = true;
            cfg.enable_fake_packet = true;
            cfg.enable_pattern_obfuscation = true;
            techniques.push_back(EvasionTechnique::SNI_SPLIT);
            techniques.push_back(EvasionTechnique::TLS_GREASE);
            techniques.push_back(EvasionTechnique::IP_TTL_TRICKS);
            break;
            
        case BypassPreset::AGGRESSIVE:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;
            cfg.enable_noise = true;
            cfg.enable_fake_packet = true;
            cfg.enable_pattern_obfuscation = true;
            cfg.randomize_split_position = true;
            cfg.randomize_fake_ttl = true;
            cfg.enable_timing_jitter = true;
            cfg.enable_decoy_sni = true;
            cfg.enable_multi_layer_split = true;
            techniques.push_back(EvasionTechnique::SNI_SPLIT);
            techniques.push_back(EvasionTechnique::TLS_GREASE);
            techniques.push_back(EvasionTechnique::IP_TTL_TRICKS);
            techniques.push_back(EvasionTechnique::TIMING_JITTER);
            techniques.push_back(EvasionTechnique::FAKE_SNI);
            techniques.push_back(EvasionTechnique::TCP_SEGMENTATION);
            break;
            
        case BypassPreset::STEALTH:
            cfg.enable_tcp_split = true;
            cfg.split_at_sni = true;
            cfg.enable_noise = false; // Less noise for stealth
            cfg.enable_fake_packet = false;
            cfg.enable_pattern_obfuscation = true;
            cfg.enable_timing_jitter = true;
            cfg.timing_jitter_min_us = 50;
            cfg.timing_jitter_max_us = 200;
            techniques.push_back(EvasionTechnique::SNI_SPLIT);
            techniques.push_back(EvasionTechnique::TIMING_JITTER);
            impl_->config.obfuscation = ObfuscationMode::HTTP_CAMOUFLAGE;
            break;
    }
    
    impl_->log("Applied preset: " + std::to_string(static_cast<int>(preset)));
}

// ==================== ECH Integration ====================

std::vector<uint8_t> DPIEvasion::apply_ech(
    const std::vector<uint8_t>& client_hello,
    const std::vector<uint8_t>& ech_config_data
) {
    ECH::ECHConfig config;
    if (!ECH::parse_ech_config(ech_config_data, config)) {
        return client_hello;
    }
    
    return ECH::apply_ech(client_hello, config);
}

std::vector<uint8_t> DPIEvasion::apply_domain_fronting(
    const std::vector<uint8_t>& data,
    const std::string& front_domain,
    const std::string& real_domain
) {
    // Simple domain fronting: replace SNI with front domain
    // (Simplified implementation)
    std::vector<uint8_t> result = data;
    
    // Find and replace SNI hostname
    // (In real implementation, would parse TLS properly)
    auto pos = std::search(
        result.begin(), result.end(),
        real_domain.begin(), real_domain.end()
    );
    
    if (pos != result.end() && front_domain.size() == real_domain.size()) {
        std::copy(front_domain.begin(), front_domain.end(), pos);
    }
    
    return result;
}

// ==================== Preset Configurations ====================

namespace Presets {

AdvancedDPIConfig create_tspu_preset() {
    AdvancedDPIConfig config;
    
    // Base config for Russian TSPU (ТСПУ РКНРОСРКН)
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.split_position = 1;
    config.base_config.fragment_size = 1;
    config.base_config.enable_fake_packet = true;
    config.base_config.fake_ttl = 2;
    config.base_config.enable_disorder = true;
    config.base_config.disorder_delay_ms = 10;
    config.base_config.enable_noise = true;
    config.base_config.noise_size = 128;
    
    // Advanced features
    config.base_config.randomize_split_position = true;
    config.base_config.split_position_min = 1;
    config.base_config.split_position_max = 5;
    config.base_config.enable_pattern_obfuscation = true;
    config.base_config.randomize_fake_ttl = true;
    config.base_config.enable_timing_jitter = true;
    config.base_config.timing_jitter_min_us = 100;
    config.base_config.timing_jitter_max_us = 500;
    config.base_config.enable_decoy_sni = true;
    config.base_config.decoy_sni_domains = {"google.com", "cloudflare.com"};
    
    // Techniques
    config.techniques = {
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::IP_TTL_TRICKS,
        EvasionTechnique::TIMING_JITTER,
        EvasionTechnique::TLS_GREASE,
        EvasionTechnique::FAKE_SNI
    };
    
    config.tspu_bypass = true;
    
    return config;
}

AdvancedDPIConfig create_gfw_preset() {
    AdvancedDPIConfig config;
    
    // Base config for China GFW
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.fragment_size = 2;
    config.base_config.enable_fake_packet = true;
    config.base_config.enable_disorder = true;
    
    // GFW-specific
    config.base_config.enable_pattern_obfuscation = true;
    config.base_config.enable_multi_layer_split = true;
    config.base_config.split_positions = {2, 40, 120};
    
    config.techniques = {
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::TCP_DISORDER,
        EvasionTechnique::TLS_GREASE
    };
    
    config.china_gfw_bypass = true;
    config.obfuscation = ObfuscationMode::XOR_ROLLING;
    
    return config;
}

AdvancedDPIConfig create_iran_preset() {
    AdvancedDPIConfig config;
    
    // Iran DPI characteristics
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.enable_fake_packet = true;
    config.base_config.enable_pattern_obfuscation = true;
    
    config.techniques = {
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TLS_GREASE,
        EvasionTechnique::HTTP_CAMOUFLAGE
    };
    
    config.obfuscation = ObfuscationMode::HTTP_CAMOUFLAGE;
    
    return config;
}

AdvancedDPIConfig create_aggressive_preset() {
    AdvancedDPIConfig config;
    
    // Maximum evasion
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.split_position = 1;
    config.base_config.fragment_size = 1;
    config.base_config.enable_fake_packet = true;
    config.base_config.fake_ttl = 1;
    config.base_config.enable_disorder = true;
    config.base_config.enable_noise = true;
    config.base_config.noise_size = 256;
    
    // All advanced features
    config.base_config.randomize_split_position = true;
    config.base_config.enable_pattern_obfuscation = true;
    config.base_config.randomize_fake_ttl = true;
    config.base_config.enable_tcp_options_randomization = true;
    config.base_config.enable_timing_jitter = true;
    config.base_config.enable_multi_layer_split = true;
    config.base_config.enable_decoy_sni = true;
    config.base_config.enable_adaptive_fragmentation = true;
    
    config.techniques = {
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TCP_SEGMENTATION,
        EvasionTechnique::TCP_DISORDER,
        EvasionTechnique::TCP_OVERLAP,
        EvasionTechnique::IP_TTL_TRICKS,
        EvasionTechnique::TLS_GREASE,
        EvasionTechnique::FAKE_SNI,
        EvasionTechnique::TIMING_JITTER
    };
    
    config.obfuscation = ObfuscationMode::CHACHA20;
    config.padding.enabled = true;
    config.padding.max_padding = 128;
    
    return config;
}

AdvancedDPIConfig create_stealth_preset() {
    AdvancedDPIConfig config;
    
    // Minimal footprint
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.fragment_size = 4;
    config.base_config.enable_pattern_obfuscation = true;
    config.base_config.enable_timing_jitter = true;
    config.base_config.timing_jitter_min_us = 50;
    config.base_config.timing_jitter_max_us = 150;
    
    config.techniques = {
        EvasionTechnique::SNI_SPLIT,
        EvasionTechnique::TIMING_JITTER
    };
    
    config.obfuscation = ObfuscationMode::HTTP_CAMOUFLAGE;
    
    return config;
}

AdvancedDPIConfig create_compatible_preset() {
    AdvancedDPIConfig config;
    
    // Maximum compatibility with minimal disruption
    config.base_config.mode = DPIMode::PROXY;
    config.base_config.enable_tcp_split = true;
    config.base_config.split_at_sni = true;
    config.base_config.split_position = 2;
    config.base_config.fragment_size = 8;
    
    config.techniques = {
        EvasionTechnique::SNI_SPLIT
    };
    
    return config;
}

} // namespace Presets

} // namespace DPI
} // namespace ncp
