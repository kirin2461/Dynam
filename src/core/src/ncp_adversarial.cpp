#include "ncp_adversarial.hpp"

#include <algorithm>
#include <cstring>
#include <numeric>
#include <cassert>

namespace ncp {
namespace DPI {

// ===== String conversion =====

const char* strategy_to_string(AdversarialStrategy s) noexcept {
    switch (s) {
        case AdversarialStrategy::RANDOM:     return "RANDOM";
        case AdversarialStrategy::HTTP_MIMIC: return "HTTP_MIMIC";
        case AdversarialStrategy::TLS_MIMIC:  return "TLS_MIMIC";
        case AdversarialStrategy::QUIC_MIMIC: return "QUIC_MIMIC";
        case AdversarialStrategy::DNS_MIMIC:  return "DNS_MIMIC";
        case AdversarialStrategy::ADAPTIVE:   return "ADAPTIVE";
        case AdversarialStrategy::CUSTOM:     return "CUSTOM";
        default: return "UNKNOWN";
    }
}

AdversarialStrategy strategy_from_string(const std::string& name) noexcept {
    if (name == "RANDOM")     return AdversarialStrategy::RANDOM;
    if (name == "HTTP_MIMIC") return AdversarialStrategy::HTTP_MIMIC;
    if (name == "TLS_MIMIC")  return AdversarialStrategy::TLS_MIMIC;
    if (name == "QUIC_MIMIC") return AdversarialStrategy::QUIC_MIMIC;
    if (name == "DNS_MIMIC")  return AdversarialStrategy::DNS_MIMIC;
    if (name == "ADAPTIVE")   return AdversarialStrategy::ADAPTIVE;
    if (name == "CUSTOM")     return AdversarialStrategy::CUSTOM;
    return AdversarialStrategy::RANDOM;
}

// ===== Config Presets =====

AdversarialConfig AdversarialConfig::aggressive() {
    AdversarialConfig c;
    c.strategy = AdversarialStrategy::ADAPTIVE;
    c.pre_padding_min = 24;
    c.pre_padding_max = 48;
    c.enable_post_padding = true;
    c.post_padding_min = 8;
    c.post_padding_max = 32;
    c.mutate_tcp_window = true;
    c.mutate_tcp_options = true;
    c.mutate_tcp_timestamps = true;
    c.enable_dummy_packets = true;
    c.dummy_packet_ratio = 0.08;
    c.max_overhead_percent = 10.0;
    c.max_padding_absolute = 96;
    return c;
}

AdversarialConfig AdversarialConfig::balanced() {
    AdversarialConfig c;
    c.strategy = AdversarialStrategy::TLS_MIMIC;
    c.pre_padding_min = 16;
    c.pre_padding_max = 32;
    c.enable_post_padding = false;
    c.mutate_tcp_window = true;
    c.mutate_tcp_options = true;
    c.mutate_tcp_timestamps = true;
    c.enable_dummy_packets = true;
    c.dummy_packet_ratio = 0.05;
    c.max_overhead_percent = 5.0;
    return c;
}

AdversarialConfig AdversarialConfig::minimal() {
    AdversarialConfig c;
    c.strategy = AdversarialStrategy::TLS_MIMIC;
    c.pre_padding_min = 8;
    c.pre_padding_max = 16;
    c.enable_post_padding = false;
    c.mutate_tcp_window = false;
    c.mutate_tcp_options = false;
    c.mutate_tcp_timestamps = false;
    c.enable_dummy_packets = false;
    c.enable_size_normalization = false;
    c.max_overhead_percent = 2.0;
    return c;
}

AdversarialConfig AdversarialConfig::stealth_max() {
    AdversarialConfig c;
    c.strategy = AdversarialStrategy::ADAPTIVE;
    c.pre_padding_min = 32;
    c.pre_padding_max = 64;
    c.enable_post_padding = true;
    c.post_padding_min = 16;
    c.post_padding_max = 48;
    c.mutate_tcp_window = true;
    c.mutate_tcp_urgent = true;
    c.mutate_tcp_options = true;
    c.mutate_tcp_timestamps = true;
    c.enable_size_normalization = true;
    c.enable_dummy_packets = true;
    c.dummy_packet_ratio = 0.12;
    c.adaptive_switch_threshold = 0.5;
    c.max_overhead_percent = 15.0;
    c.max_padding_absolute = 128;
    return c;
}

// ===== Constructor / Destructor =====

AdversarialPadding::AdversarialPadding()
    : AdversarialPadding(AdversarialConfig::balanced()) {}

AdversarialPadding::AdversarialPadding(const AdversarialConfig& config)
    : config_(config),
      active_strategy_(config.strategy == AdversarialStrategy::ADAPTIVE
                       ? AdversarialStrategy::TLS_MIMIC
                       : config.strategy),
      packets_since_evaluation_(0) {
    // Phase 0: Initialize libsodium CSPRNG (idempotent)
    ncp::csprng_init();
    
    strategy_scores_.fill(0.5); // neutral starting score
}

AdversarialPadding::~AdversarialPadding() = default;

AdversarialPadding::AdversarialPadding(AdversarialPadding&&) noexcept = default;
AdversarialPadding& AdversarialPadding::operator=(AdversarialPadding&&) noexcept = default;

// ===== Padding Generation =====

std::vector<uint8_t> AdversarialPadding::generate_random_padding(size_t len) {
    return ncp::csprng_bytes(len);
}

std::vector<uint8_t> AdversarialPadding::generate_http_mimic_padding(size_t len) {
    // Mimic the start of an HTTP/1.1 response or request.
    // Transformer sees first bytes and classifies as HTTP.
    static const std::vector<std::vector<uint8_t>> http_prefixes = {
        // "GET / HTTP/1.1\r\nHost: "
        {0x47,0x45,0x54,0x20,0x2F,0x20,0x48,0x54,0x54,0x50,0x2F,0x31,0x2E,0x31,0x0D,0x0A,
         0x48,0x6F,0x73,0x74,0x3A,0x20},
        // "HTTP/1.1 200 OK\r\nContent-"
        {0x48,0x54,0x54,0x50,0x2F,0x31,0x2E,0x31,0x20,0x32,0x30,0x30,0x20,0x4F,0x4B,0x0D,
         0x0A,0x43,0x6F,0x6E,0x74,0x65,0x6E,0x74,0x2D},
        // "POST /api/v1 HTTP/1.1\r\n"
        {0x50,0x4F,0x53,0x54,0x20,0x2F,0x61,0x70,0x69,0x2F,0x76,0x31,0x20,0x48,0x54,0x54,
         0x50,0x2F,0x31,0x2E,0x31,0x0D,0x0A},
    };
    
    const auto& prefix = http_prefixes[ncp::csprng_uniform(static_cast<uint32_t>(http_prefixes.size()))];
    
    std::vector<uint8_t> result(len);
    size_t copy_len = (std::min)(len, prefix.size());
    std::memcpy(result.data(), prefix.data(), copy_len);
    
    // Fill remainder with printable ASCII (HTTP-like)
    if (copy_len < len) {
        for (size_t i = copy_len; i < len; ++i) {
            result[i] = static_cast<uint8_t>(ncp::csprng_range(0x20, 0x7E));
        }
    }
    return result;
}

std::vector<uint8_t> AdversarialPadding::generate_tls_mimic_padding(size_t len) {
    // Mimic TLS Application Data record header.
    // 0x17 = Application Data, 0x03 0x03 = TLS 1.2, then length
    std::vector<uint8_t> result(len);
    
    if (len >= 5) {
        result[0] = 0x17;  // ContentType: Application Data
        result[1] = 0x03;  // Major version
        result[2] = 0x03;  // Minor version (TLS 1.2)
        // Record length (remaining bytes after header)
        uint16_t record_len = static_cast<uint16_t>(len > 5 ? len - 5 : 0);
        result[3] = static_cast<uint8_t>((record_len >> 8) & 0xFF);
        result[4] = static_cast<uint8_t>(record_len & 0xFF);
        
        // Fill rest with high-entropy data (looks like encrypted TLS)
        if (len > 5) {
            ncp::csprng_fill(result.data() + 5, len - 5);
        }
    } else {
        ncp::csprng_fill(result.data(), len);
    }
    return result;
}

std::vector<uint8_t> AdversarialPadding::generate_quic_mimic_padding(size_t len) {
    // Mimic QUIC Initial packet header
    std::vector<uint8_t> result(len);
    
    if (len >= 8) {
        // QUIC long header: form bit=1, fixed bit=1, type=Initial(00)
        result[0] = 0xC0; // 1100 0000
        // Version: QUIC v1 (0x00000001)
        result[1] = 0x00;
        result[2] = 0x00;
        result[3] = 0x00;
        result[4] = 0x01;
        // DCID length
        result[5] = 0x08; // 8 bytes DCID
        // Random DCID
        ncp::csprng_fill(result.data() + 6, (std::min)(len - 6, static_cast<size_t>(8)));
        
        // Fill rest
        if (len > 14) {
            ncp::csprng_fill(result.data() + 14, len - 14);
        }
    } else {
        ncp::csprng_fill(result.data(), len);
    }
    return result;
}

std::vector<uint8_t> AdversarialPadding::generate_dns_mimic_padding(size_t len) {
    // Mimic DNS query header
    std::vector<uint8_t> result(len);
    
    if (len >= 12) {
        // Transaction ID (random)
        ncp::csprng_fill(result.data(), 2);
        // Flags: standard query, recursion desired
        result[2] = 0x01;
        result[3] = 0x00;
        // QDCOUNT = 1
        result[4] = 0x00;
        result[5] = 0x01;
        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        std::memset(result.data() + 6, 0, 6);
        
        // Fill rest with label-like data (a-z)
        if (len > 12) {
            for (size_t i = 12; i < len; ++i) {
                result[i] = static_cast<uint8_t>(ncp::csprng_range(0x61, 0x7A));
            }
        }
    } else {
        ncp::csprng_fill(result.data(), len);
    }
    return result;
}

std::vector<uint8_t> AdversarialPadding::generate_padding(
    AdversarialStrategy strategy, size_t len) {
    switch (strategy) {
        case AdversarialStrategy::RANDOM:     return generate_random_padding(len);
        case AdversarialStrategy::HTTP_MIMIC: return generate_http_mimic_padding(len);
        case AdversarialStrategy::TLS_MIMIC:  return generate_tls_mimic_padding(len);
        case AdversarialStrategy::QUIC_MIMIC: return generate_quic_mimic_padding(len);
        case AdversarialStrategy::DNS_MIMIC:  return generate_dns_mimic_padding(len);
        case AdversarialStrategy::CUSTOM:
            if (!config_.custom_pattern.empty()) {
                std::vector<uint8_t> result(len);
                for (size_t i = 0; i < len; ++i)
                    result[i] = config_.custom_pattern[i % config_.custom_pattern.size()];
                return result;
            }
            return generate_random_padding(len);
        case AdversarialStrategy::ADAPTIVE:
            return generate_padding(active_strategy_, len);
        default:
            return generate_random_padding(len);
    }
}

// ===== Size Selection =====

size_t AdversarialPadding::select_pre_padding_size() {
    if (!config_.enable_pre_padding) return 0;
    size_t min_s = config_.pre_padding_min;
    size_t max_s = (std::min)(config_.pre_padding_max, config_.max_padding_absolute);
    if (min_s >= max_s) return min_s;
    return ncp::csprng_range_size(min_s, max_s);
}

size_t AdversarialPadding::select_post_padding_size() {
    if (!config_.enable_post_padding) return 0;
    size_t min_s = config_.post_padding_min;
    size_t max_s = (std::min)(config_.post_padding_max, config_.max_padding_absolute);
    if (min_s >= max_s) return min_s;
    return ncp::csprng_range_size(min_s, max_s);
}

size_t AdversarialPadding::find_nearest_target_size(size_t current_size) const {
    if (config_.target_sizes.empty()) return current_size;
    
    size_t best = config_.target_sizes[0];
    size_t best_diff = (current_size > best) ? current_size - best : best - current_size;
    
    for (size_t t : config_.target_sizes) {
        if (t < current_size) continue; // only pad up
        size_t diff = t - current_size;
        if (diff < best_diff) {
            best = t;
            best_diff = diff;
        }
    }
    return best;
}

// ===== Core: pad() =====
// FIX #69 + #70: Control header expanded to 4 bytes.
// Layout: [ctrl0][ctrl1][ctrl2][ctrl3]
//   ctrl0: [strategy:4 bits][pre_len_hi:4 bits]
//   ctrl1: [pre_len_lo:8 bits]          => pre_len = 12 bits (up to 4095) — same as before for back-compat range
//   ctrl2: [payload_len_hi:8 bits]
//   ctrl3: [payload_len_lo:8 bits]      => payload_len = 16 bits (up to 65535)
//
// FIX #70: For pre_len > 4095, we use an extended encoding:
//   If ctrl0 low nibble == 0x0F and ctrl1 == 0xFF (sentinel = 0x0FFF),
//   then actual pre_len is stored in ctrl2:ctrl3 and payload_len follows in next 2 bytes (6-byte header).
//   For simplicity and practical use (max_padding_absolute is typically <=128),
//   we keep the 4-byte format with 16-bit pre_len using both ctrl0:ctrl1 fully:
//
// REVISED simpler layout (BREAKING CHANGE from 2-byte header):
//   ctrl0: [strategy:4 bits][reserved:4 bits]
//   ctrl1: [pre_len_hi:8 bits]
//   ctrl2: [pre_len_lo:8 bits]          => pre_len = 16 bits (up to 65535)
//   ctrl3: reserved (0x00), available for future flags
//
// payload_len is encoded as: total_len - CONTROL_HEADER_SIZE - pre_len - post_len
// But since unpad() doesn't know post_len, we store original payload length explicitly.
//
// FINAL layout (4 bytes):
//   Byte 0: [strategy:4][pre_len bits 15..12]
//   Byte 1: [pre_len bits 11..4]
//   Byte 2: [pre_len bits 3..0][payload_len bits 19..16]
//   Byte 3: ... not enough room.
//
// Let's use the cleanest approach: 6-byte control header.
//   Byte 0: [strategy:4][flags:4]
//   Byte 1-2: pre_len (16-bit big-endian)
//   Byte 3-4: payload_len (16-bit big-endian) — original payload length
//   Byte 5: reserved (0x00)
// This is unambiguous and fully self-contained for unpad().
// But that's a lot of overhead for small packets. Let's do 4 bytes:
//
// FINAL FINAL (4 bytes):
//   Byte 0: [strategy:4 bits][pre_len_hi:4 bits]   (pre_len bits 11..8)
//   Byte 1: [pre_len_lo:8 bits]                     (pre_len bits 7..0) => 12-bit pre_len, max 4095
//   Byte 2: [payload_len_hi:8 bits]                  (payload_len bits 15..8)
//   Byte 3: [payload_len_lo:8 bits]                  (payload_len bits 7..0) => 16-bit payload_len
//
// This solves #69 (unpad knows exact payload length) and keeps pre_len at 12-bit which is
// sufficient given max_padding_absolute defaults. The #70 issue about >4096 pre_len is
// practically moot since no config preset exceeds 128 bytes, and we add a runtime clamp.

std::vector<uint8_t> AdversarialPadding::pad(
    const uint8_t* payload, size_t len) {
    
    if (!config_.enabled || len == 0) {
        return std::vector<uint8_t>(payload, payload + len);
    }
    
    stats_.packets_processed.fetch_add(1);
    stats_.bytes_original.fetch_add(len);
    
    // Check overhead limit
    uint64_t total_orig = stats_.bytes_original.load();
    uint64_t total_pad = stats_.bytes_padding_added.load();
    if (total_orig > 0) {
        double current_overhead = (static_cast<double>(total_pad) / total_orig) * 100.0;
        if (current_overhead > config_.max_overhead_percent) {
            // Over budget — pass through without padding
            return std::vector<uint8_t>(payload, payload + len);
        }
    }
    
    // Determine strategy
    AdversarialStrategy strat = config_.strategy;
    if (strat == AdversarialStrategy::ADAPTIVE) {
        strat = active_strategy_;
        packets_since_evaluation_++;
        if (packets_since_evaluation_ >= static_cast<size_t>(config_.adaptive_window_packets)) {
            evaluate_adaptive_strategy();
            packets_since_evaluation_ = 0;
        }
    }
    
    size_t pre_len = select_pre_padding_size();
    size_t post_len = select_post_padding_size();
    
    // FIX #70: Clamp pre_len to 12-bit max (4095) for control header encoding
    if (pre_len > MAX_PRE_PADDING) {
        pre_len = MAX_PRE_PADDING;
    }
    
    // FIX #69: Clamp payload_len to 16-bit max (65535) for control header encoding
    // Payloads >64KB are passed through unpadded (extremely rare at this layer)
    if (len > MAX_PAYLOAD_LEN) {
        return std::vector<uint8_t>(payload, payload + len);
    }
    
    // FIX #69 + #70: New 4-byte control header
    // Byte 0: [strategy:4][pre_len_hi:4]  (pre_len bits 11..8)
    // Byte 1: [pre_len_lo:8]              (pre_len bits 7..0)
    // Byte 2: [payload_len_hi:8]          (original payload length bits 15..8)
    // Byte 3: [payload_len_lo:8]          (original payload length bits 7..0)
    
    size_t total = CONTROL_HEADER_SIZE + pre_len + len + post_len;
    std::vector<uint8_t> result;
    result.reserve(total);
    
    // Control header byte 0: strategy (high nibble) + pre_len high 4 bits (low nibble)
    uint8_t strat_nibble = static_cast<uint8_t>(strat) & 0x0F;
    uint8_t pre_hi = static_cast<uint8_t>((pre_len >> 8) & 0x0F);
    result.push_back((strat_nibble << 4) | pre_hi);
    
    // Control header byte 1: pre_len low 8 bits
    result.push_back(static_cast<uint8_t>(pre_len & 0xFF));
    
    // FIX #69: Control header bytes 2-3: original payload length (16-bit big-endian)
    uint16_t payload_len16 = static_cast<uint16_t>(len);
    result.push_back(static_cast<uint8_t>((payload_len16 >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(payload_len16 & 0xFF));
    
    // Pre-padding
    if (pre_len > 0) {
        auto pre_pad = generate_padding(strat, pre_len);
        result.insert(result.end(), pre_pad.begin(), pre_pad.end());
    }
    
    // Original payload
    result.insert(result.end(), payload, payload + len);
    
    // Post-padding
    if (post_len > 0) {
        auto post_pad = generate_padding(strat, post_len);
        result.insert(result.end(), post_pad.begin(), post_pad.end());
    }
    
    stats_.packets_padded.fetch_add(1);
    stats_.bytes_padding_added.fetch_add(pre_len + post_len + CONTROL_HEADER_SIZE);
    
    return result;
}

std::vector<uint8_t> AdversarialPadding::pad(const std::vector<uint8_t>& payload) {
    return pad(payload.data(), payload.size());
}

// ===== Core: unpad() =====
// FIX #69: Now decodes payload_len from control header to precisely strip post-padding.

std::vector<uint8_t> AdversarialPadding::unpad(
    const uint8_t* padded_data, size_t len) {
    
    if (len < CONTROL_HEADER_SIZE) {
        return std::vector<uint8_t>(padded_data, padded_data + len);
    }
    
    // Decode control header (4 bytes)
    uint8_t ctrl0 = padded_data[0];
    uint8_t ctrl1 = padded_data[1];
    uint8_t ctrl2 = padded_data[2];
    uint8_t ctrl3 = padded_data[3];
    
    size_t pre_len = (static_cast<size_t>(ctrl0 & 0x0F) << 8) | ctrl1;
    
    // FIX #69: Decode original payload length from bytes 2-3
    size_t payload_len = (static_cast<size_t>(ctrl2) << 8) | ctrl3;
    
    size_t data_start = CONTROL_HEADER_SIZE + pre_len;
    size_t data_end = data_start + payload_len;
    
    if (data_start >= len || data_end > len) {
        // Malformed — return empty
        return {};
    }
    
    // Return exactly the original payload, no post-padding garbage
    return std::vector<uint8_t>(padded_data + data_start, padded_data + data_end);
}

std::vector<uint8_t> AdversarialPadding::unpad(const std::vector<uint8_t>& padded_data) {
    return unpad(padded_data.data(), padded_data.size());
}

// ===== TCP Header Mutation =====

bool AdversarialPadding::mutate_tcp_header(uint8_t* tcp_header, size_t header_len) {
    if (!tcp_header || header_len < 20) return false;
    
    bool mutated = false;
    
    if (config_.mutate_tcp_window) {
        randomize_window_size(tcp_header);
        mutated = true;
    }
    
    if (config_.mutate_tcp_options && header_len > 20) {
        randomize_tcp_options(tcp_header, header_len);
        mutated = true;
    }
    
    if (config_.mutate_tcp_timestamps && header_len > 20) {
        jitter_timestamps(tcp_header, header_len);
        mutated = true;
    }
    
    if (config_.mutate_tcp_urgent) {
        // Set URG flag and random urgent pointer
        tcp_header[13] |= 0x20; // URG flag
        uint16_t urg;
        ncp::csprng_fill(&urg, sizeof(urg));
        tcp_header[18] = static_cast<uint8_t>((urg >> 8) & 0xFF);
        tcp_header[19] = static_cast<uint8_t>(urg & 0xFF);
        mutated = true;
    }
    
    if (mutated) {
        stats_.tcp_mutations_applied.fetch_add(1);
    }
    return mutated;
}

void AdversarialPadding::randomize_window_size(uint8_t* tcp_header) {
    // TCP window size is at offset 14-15.
    // Common browser windows: 64240, 65535, 29200, 28960
    static const uint16_t common_windows[] = {
        64240, 65535, 29200, 28960, 32768, 16384, 42340, 64000
    };
    uint16_t win = common_windows[ncp::csprng_uniform(8)];
    // Add small jitter
    int w = static_cast<int>(win) + ncp::csprng_range(-128, 128);
    if (w < 1) w = 1;
    if (w > 65535) w = 65535;
    win = static_cast<uint16_t>(w);
    tcp_header[14] = static_cast<uint8_t>((win >> 8) & 0xFF);
    tcp_header[15] = static_cast<uint8_t>(win & 0xFF);
}

// FIX #71: Actually mutate TCP options instead of NOP→NOP no-op.
// Strategy: Walk the option list and apply meaningful mutations:
//   - NOP (0x01): Replace with random choice among NOP/EOL/NOP-pair to vary padding layout
//   - MSS (kind=2, len=4): Apply small jitter to MSS value (±32) for fingerprint diversity
//   - Window Scale (kind=3, len=3): Jitter scale factor ±1
//   - Collect contiguous NOP runs and occasionally shuffle their count
void AdversarialPadding::randomize_tcp_options(uint8_t* tcp_header, size_t header_len) {
    size_t opts_start = 20;
    if (header_len <= opts_start) return;
    
    size_t i = opts_start;
    while (i < header_len) {
        uint8_t kind = tcp_header[i];
        
        if (kind == 0x00) {
            // EOL — end of options
            break;
        }
        
        if (kind == 0x01) {
            // NOP — single byte. Mutate: 50% chance replace with random padding byte
            // that is still valid (NOP=0x01 or EOL=0x00 at end of options area).
            // To actually change the fingerprint, we can:
            //   - Leave as NOP (25%)
            //   - Replace with a different NOP position (shift NOPs around) — handled below
            //   - Insert a no-op by writing 0x01 but with different surrounding context
            // Most effective: randomly decide to keep or convert trailing NOPs to EOL+NOPs
            uint32_t r = ncp::csprng_uniform(4);
            if (r == 0 && i + 1 < header_len && tcp_header[i + 1] == 0x01) {
                // Swap this NOP with next byte if next is also NOP (no visible change,
                // but re-aligns option boundaries creating different parse trees for some DPI)
                // Actually: convert a pair of NOPs into a single NOP + random padding
                tcp_header[i] = 0x01;
                // Write a different innocuous value that won't break TCP parsing:
                // 0x01 is safest. But we can also use kind=30 (experimental) with len=2
                // which is a valid no-op option that some fingerprinters key on.
                if (ncp::csprng_uniform(2) == 0) {
                    // Replace pair with Experimental option kind=30 len=2 (RFC 4727)
                    tcp_header[i] = 30;     // kind = experimental
                    tcp_header[i + 1] = 2;  // length = 2 (just kind+len, no data)
                    i += 2;
                    continue;
                }
            } else if (r == 1) {
                // Convert NOP to kind=30 len=2 if there's room for 2 bytes
                // and next byte is also a NOP we can consume
                if (i + 1 < header_len && tcp_header[i + 1] == 0x01) {
                    tcp_header[i] = 30;
                    tcp_header[i + 1] = 2;
                    i += 2;
                    continue;
                }
            }
            // else: leave NOP as-is (still valid mutation: we changed other NOPs)
            i++;
            continue;
        }
        
        // Multi-byte option: kind at [i], length at [i+1]
        if (i + 1 >= header_len) break;
        uint8_t opt_len = tcp_header[i + 1];
        if (opt_len < 2 || i + opt_len > header_len) break;
        
        // MSS (kind=2, len=4): jitter value by ±32
        if (kind == 2 && opt_len == 4 && i + 4 <= header_len) {
            uint16_t mss = (static_cast<uint16_t>(tcp_header[i + 2]) << 8) | tcp_header[i + 3];
            int new_mss = static_cast<int>(mss) + ncp::csprng_range(-32, 32);
            if (new_mss < 536) new_mss = 536;   // RFC 791 minimum
            if (new_mss > 65535) new_mss = 65535;
            tcp_header[i + 2] = static_cast<uint8_t>((new_mss >> 8) & 0xFF);
            tcp_header[i + 3] = static_cast<uint8_t>(new_mss & 0xFF);
        }
        
        // Window Scale (kind=3, len=3): jitter shift count by ±1
        if (kind == 3 && opt_len == 3 && i + 3 <= header_len) {
            int ws = static_cast<int>(tcp_header[i + 2]) + ncp::csprng_range(-1, 1);
            if (ws < 0) ws = 0;
            if (ws > 14) ws = 14; // RFC 7323 max
            tcp_header[i + 2] = static_cast<uint8_t>(ws);
        }
        
        i += opt_len;
    }
}

void AdversarialPadding::jitter_timestamps(uint8_t* tcp_header, size_t header_len) {
    // Find TCP timestamp option (kind=8, length=10)
    size_t i = 20;
    while (i + 1 < header_len) {
        uint8_t kind = tcp_header[i];
        if (kind == 0) break;      // EOL
        if (kind == 1) { i++; continue; }  // NOP
        if (i + 1 >= header_len) break;
        uint8_t opt_len = tcp_header[i + 1];
        if (opt_len < 2 || i + opt_len > header_len) break;
        
        if (kind == 8 && opt_len == 10 && i + 10 <= header_len) {
            // TSval is at i+2..i+5, TSecr at i+6..i+9
            // Add small jitter to TSval
            uint32_t tsval = 0;
            tsval |= static_cast<uint32_t>(tcp_header[i+2]) << 24;
            tsval |= static_cast<uint32_t>(tcp_header[i+3]) << 16;
            tsval |= static_cast<uint32_t>(tcp_header[i+4]) << 8;
            tsval |= static_cast<uint32_t>(tcp_header[i+5]);
            
            int new_ts = static_cast<int>(tsval) + ncp::csprng_range(-50, 50);
            if (new_ts < 0) new_ts = 0;
            tsval = static_cast<uint32_t>(new_ts);
            
            tcp_header[i+2] = static_cast<uint8_t>((tsval >> 24) & 0xFF);
            tcp_header[i+3] = static_cast<uint8_t>((tsval >> 16) & 0xFF);
            tcp_header[i+4] = static_cast<uint8_t>((tsval >> 8) & 0xFF);
            tcp_header[i+5] = static_cast<uint8_t>(tsval & 0xFF);
            break;
        }
        i += opt_len;
    }
}

// ===== Packet Size Normalization =====

std::vector<uint8_t> AdversarialPadding::normalize_size(
    const std::vector<uint8_t>& data) {
    if (!config_.enable_size_normalization || data.empty()) return data;
    
    size_t target = find_nearest_target_size(data.size());
    if (target <= data.size()) return data;
    
    std::vector<uint8_t> result = data;
    size_t pad_needed = target - data.size();
    
    // Pad with strategy-appropriate bytes
    auto padding = generate_padding(active_strategy_, pad_needed);
    result.insert(result.end(), padding.begin(), padding.end());
    
    stats_.size_normalizations.fetch_add(1);
    stats_.bytes_padding_added.fetch_add(pad_needed);
    
    return result;
}

// ===== Dummy Packets =====

std::vector<uint8_t> AdversarialPadding::generate_dummy_packet() {
    size_t sz = ncp::csprng_range_size(config_.dummy_min_size, config_.dummy_max_size);
    
    std::vector<uint8_t> dummy;
    dummy.reserve(4 + sz); // 4 bytes magic + payload
    
    // Magic marker (recognized by receiver to discard)
    dummy.push_back(DUMMY_MAGIC_0);
    dummy.push_back(DUMMY_MAGIC_1);
    dummy.push_back(DUMMY_MAGIC_2);
    dummy.push_back(DUMMY_MAGIC_3);
    
    // Fill with strategy-appropriate content so DPI sees "normal" traffic
    auto content = generate_padding(active_strategy_, sz);
    dummy.insert(dummy.end(), content.begin(), content.end());
    
    stats_.dummy_packets_injected.fetch_add(1);
    return dummy;
}

bool AdversarialPadding::is_dummy_packet(const uint8_t* data, size_t len) const {
    if (len < 4) return false;
    return data[0] == DUMMY_MAGIC_0 &&
           data[1] == DUMMY_MAGIC_1 &&
           data[2] == DUMMY_MAGIC_2 &&
           data[3] == DUMMY_MAGIC_3;
}

// ===== Adaptive Strategy =====

void AdversarialPadding::report_feedback(const DetectionFeedback& feedback) {
    feedback_history_.push_back(feedback);
    
    // Update score for the strategy that was used
    int idx = static_cast<int>(feedback.strategy_used);
    if (idx >= 0 && idx < static_cast<int>(strategy_scores_.size())) {
        // Exponential moving average: score = 0.8 * old + 0.2 * new_detection
        double detection_val = feedback.detected ? feedback.confidence : 0.0;
        strategy_scores_[idx] = 0.8 * strategy_scores_[idx] + 0.2 * detection_val;
    }
    
    // If current strategy is doing poorly, switch immediately
    int active_idx = static_cast<int>(active_strategy_);
    if (active_idx >= 0 && active_idx < static_cast<int>(strategy_scores_.size())) {
        if (strategy_scores_[active_idx] > config_.adaptive_switch_threshold) {
            auto best = select_best_strategy();
            if (best != active_strategy_) {
                active_strategy_ = best;
                stats_.strategy_switches.fetch_add(1);
            }
        }
    }
}

void AdversarialPadding::evaluate_adaptive_strategy() {
    if (config_.strategy != AdversarialStrategy::ADAPTIVE) return;
    
    auto best = select_best_strategy();
    if (best != active_strategy_) {
        active_strategy_ = best;
        stats_.strategy_switches.fetch_add(1);
    }
}

AdversarialStrategy AdversarialPadding::select_best_strategy() const {
    // Find strategy with lowest detection score from the adaptive pool
    double best_score = 1.0;
    AdversarialStrategy best_strat = AdversarialStrategy::TLS_MIMIC; // fallback
    
    for (auto s : config_.adaptive_pool) {
        int idx = static_cast<int>(s);
        if (idx >= 0 && idx < static_cast<int>(strategy_scores_.size())) {
            if (strategy_scores_[idx] < best_score) {
                best_score = strategy_scores_[idx];
                best_strat = s;
            }
        }
    }
    return best_strat;
}

void AdversarialPadding::force_strategy(AdversarialStrategy strategy) {
    active_strategy_ = strategy;
    stats_.current_strategy = strategy;
}

AdversarialStrategy AdversarialPadding::current_strategy() const {
    return active_strategy_;
}

// ===== Config & Stats =====

void AdversarialPadding::set_config(const AdversarialConfig& config) {
    config_ = config;
    if (config_.strategy != AdversarialStrategy::ADAPTIVE) {
        active_strategy_ = config_.strategy;
    }
}

AdversarialConfig AdversarialPadding::get_config() const {
    return config_;
}

AdversarialStats AdversarialPadding::get_stats() const {
    AdversarialStats s(stats_);
    s.current_strategy = active_strategy_;
    return s;
}

void AdversarialPadding::reset_stats() {
    stats_.reset();
}

} // namespace DPI
} // namespace ncp
