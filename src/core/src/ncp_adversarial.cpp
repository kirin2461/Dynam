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
    
    // Encode: [control_byte_0][control_byte_1][pre_padding...][original_payload][post_padding...]
    // control_byte_0: [strategy:4][pre_len_hi:4]
    // control_byte_1: [pre_len_lo:8]
    
    size_t total = CONTROL_HEADER_SIZE + pre_len + len + post_len;
    std::vector<uint8_t> result;
    result.reserve(total);
    
    // Control header
    uint8_t strat_nibble = static_cast<uint8_t>(strat) & 0x0F;
    uint8_t pre_hi = static_cast<uint8_t>((pre_len >> 8) & 0x0F);
    result.push_back((strat_nibble << 4) | pre_hi);
    result.push_back(static_cast<uint8_t>(pre_len & 0xFF));
    
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

std::vector<uint8_t> AdversarialPadding::unpad(
    const uint8_t* padded_data, size_t len) {
    
    if (len < CONTROL_HEADER_SIZE) {
        return std::vector<uint8_t>(padded_data, padded_data + len);
    }
    
    // Decode control header
    uint8_t ctrl0 = padded_data[0];
    uint8_t ctrl1 = padded_data[1];
    
    size_t pre_len = (static_cast<size_t>(ctrl0 & 0x0F) << 8) | ctrl1;
    
    size_t data_start = CONTROL_HEADER_SIZE + pre_len;
    if (data_start >= len) {
        // Malformed — return empty
        return {};
    }
    
    // Post-padding is implicit: we encoded original length in the protocol layer above.
    // For standalone use, we strip control header + pre_padding, rest is payload + post_pad.
    // The protocol layer knows the original length.
    // For safety, return everything after pre-padding.
    return std::vector<uint8_t>(padded_data + data_start, padded_data + len);
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

void AdversarialPadding::randomize_tcp_options(uint8_t* tcp_header, size_t header_len) {
    // TCP options start at offset 20.
    // We look for NOP (0x01) and rewrite with random NOPs or padding.
    size_t opts_start = 20;
    if (header_len <= opts_start) return;
    
    for (size_t i = opts_start; i < header_len; ++i) {
        if (tcp_header[i] == 0x01) { // NOP
            // Sometimes replace NOP with NOP (keep), sometimes leave as is
            if (ncp::csprng_uniform(4) == 0) {
                tcp_header[i] = 0x01; // keep NOP
            }
            // else leave as is
        }
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
