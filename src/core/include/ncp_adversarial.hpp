#pragma once

/**
 * @file ncp_adversarial.hpp
 * @brief Adversarial Packet Padding — Phase 1 Anti-ML-TSPU
 *
 * Defeats transformer-based traffic classifiers (ET-BERT, FlowPic, etc.)
 * by injecting adversarial bytes into packet headers and payloads.
 *
 * Research basis: AdvTraffic (2025) demonstrated that 16-32 bytes of
 * pre-padding drops ET-BERT classification accuracy from 99% to 25%
 * with only 3.4% bandwidth overhead.
 *
 * Key insight: transformer models rely heavily on first 32 bytes of
 * payload for protocol classification. Corrupting this window with
 * adversarial content makes the classifier misclassify the flow.
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <atomic>
#include <string>
#include <functional>
#include <array>
#include <chrono>
#include <mutex>
#include "ncp_csprng.hpp"

namespace ncp {
namespace DPI {

// ===== Padding Strategy =====

enum class AdversarialStrategy {
    RANDOM,       // Pure random bytes — baseline, ~60% evasion
    HTTP_MIMIC,   // Looks like HTTP/1.1 start — tricks classifiers into HTTP bucket
    TLS_MIMIC,    // Looks like TLS record header — blends with HTTPS
    QUIC_MIMIC,   // Looks like QUIC Initial — blends with QUIC traffic
    DNS_MIMIC,    // Looks like DNS query — small packet cover
    ADAPTIVE,     // Rotates strategies based on feedback — highest evasion
    CUSTOM        // User-provided padding pattern
};

const char* strategy_to_string(AdversarialStrategy s) noexcept;
AdversarialStrategy strategy_from_string(const std::string& name) noexcept;

// ===== Configuration =====

struct AdversarialConfig {
    // Core padding
    bool enabled = true;
    AdversarialStrategy strategy = AdversarialStrategy::ADAPTIVE;
    
    // Pre-padding (before payload) — most effective against transformers
    bool enable_pre_padding = true;
    size_t pre_padding_min = 16;      // Minimum pre-padding bytes
    size_t pre_padding_max = 32;      // Maximum pre-padding bytes
    
    // Post-padding (after payload) — additional confusion
    bool enable_post_padding = false;
    size_t post_padding_min = 0;
    size_t post_padding_max = 16;
    
    // TCP header mutation
    bool mutate_tcp_window = true;      // Randomize TCP window size
    bool mutate_tcp_urgent = false;     // Set urgent pointer (risky)
    bool mutate_tcp_options = true;     // Randomize TCP options order
    bool mutate_tcp_timestamps = true;  // Jitter TCP timestamps
    
    // Packet size distribution shaping
    bool enable_size_normalization = true;   // Pad packets to common sizes
    std::vector<size_t> target_sizes = {64, 128, 256, 512, 1024, 1460};
    
    // Flow-level adversarial features
    bool enable_dummy_packets = true;   // Inject dummy packets in flow
    double dummy_packet_ratio = 0.05;   // 5% of packets are dummy
    size_t dummy_min_size = 40;
    size_t dummy_max_size = 200;
    
    // Adaptive strategy parameters
    int adaptive_window_packets = 100;         // Evaluate every N packets
    double adaptive_switch_threshold = 0.7;    // Switch if detection > 70%
    std::vector<AdversarialStrategy> adaptive_pool = {
        AdversarialStrategy::HTTP_MIMIC,
        AdversarialStrategy::TLS_MIMIC,
        AdversarialStrategy::QUIC_MIMIC,
        AdversarialStrategy::RANDOM
    };
    
    // Custom pattern (used when strategy == CUSTOM)
    std::vector<uint8_t> custom_pattern;
    
    // Performance limits
    double max_overhead_percent = 5.0;  // Max bandwidth overhead
    size_t max_padding_absolute = 64;   // Hard limit on padding bytes
    
    // Presets
    static AdversarialConfig aggressive();
    static AdversarialConfig balanced();
    static AdversarialConfig minimal();
    static AdversarialConfig stealth_max();
};

// ===== Statistics =====

struct AdversarialStats {
    std::atomic<uint64_t> packets_processed{0};
    std::atomic<uint64_t> packets_padded{0};
    std::atomic<uint64_t> bytes_original{0};
    std::atomic<uint64_t> bytes_padding_added{0};
    std::atomic<uint64_t> dummy_packets_injected{0};
    std::atomic<uint64_t> tcp_mutations_applied{0};
    std::atomic<uint64_t> strategy_switches{0};
    std::atomic<uint64_t> size_normalizations{0};
    
    AdversarialStrategy current_strategy{AdversarialStrategy::ADAPTIVE};
    
    double overhead_percent() const {
        uint64_t orig = bytes_original.load();
        if (orig == 0) return 0.0;
        return (static_cast<double>(bytes_padding_added.load()) / orig) * 100.0;
    }
    
    void reset() {
        packets_processed.store(0);
        packets_padded.store(0);
        bytes_original.store(0);
        bytes_padding_added.store(0);
        dummy_packets_injected.store(0);
        tcp_mutations_applied.store(0);
        strategy_switches.store(0);
        size_normalizations.store(0);
    }
    
    // Copy constructor for atomics
    AdversarialStats() = default;
    AdversarialStats(const AdversarialStats& o)
        : packets_processed(o.packets_processed.load()),
          packets_padded(o.packets_padded.load()),
          bytes_original(o.bytes_original.load()),
          bytes_padding_added(o.bytes_padding_added.load()),
          dummy_packets_injected(o.dummy_packets_injected.load()),
          tcp_mutations_applied(o.tcp_mutations_applied.load()),
          strategy_switches(o.strategy_switches.load()),
          size_normalizations(o.size_normalizations.load()),
          current_strategy(o.current_strategy) {}
};

// ===== Detection Feedback =====

/// Feedback from external detection test (for ADAPTIVE mode)
struct DetectionFeedback {
    bool detected = false;                // Was the traffic detected?
    double confidence = 0.0;              // Detection confidence 0.0-1.0
    std::string classifier_name;          // Which classifier detected it
    AdversarialStrategy strategy_used;    // Strategy that was tested
    std::chrono::steady_clock::time_point timestamp;
};

// ===== Main Class =====

class AdversarialPadding {
public:
    AdversarialPadding();
    explicit AdversarialPadding(const AdversarialConfig& config);
    ~AdversarialPadding();
    
    // Non-copyable, movable
    AdversarialPadding(const AdversarialPadding&) = delete;
    AdversarialPadding& operator=(const AdversarialPadding&) = delete;
    AdversarialPadding(AdversarialPadding&&) noexcept;
    AdversarialPadding& operator=(AdversarialPadding&&) noexcept;
    
    // ===== Core Operations =====
    
    /// Apply adversarial padding to outgoing packet payload.
    /// Returns padded payload. Original data can be extracted with unpad().
    ///
    /// Always writes V2 control header (4 bytes):
    ///   Byte 0: [strategy:4 bits][pre_len bits 11..8]
    ///   Byte 1: [pre_len bits 7..0]              => 12-bit pre_len (max 4095)
    ///   Byte 2: [payload_len bits 15..8]
    ///   Byte 3: [payload_len bits 7..0]           => 16-bit payload_len (max 65535)
    ///
    /// Wire format: [ctrl0..ctrl3][pre_padding][original_payload][post_padding]
    std::vector<uint8_t> pad(
        const uint8_t* payload, size_t len
    );
    
    std::vector<uint8_t> pad(const std::vector<uint8_t>& payload);
    
    /// Remove adversarial padding, restore original payload.
    ///
    /// Auto-detects header version:
    ///   - V2 (4-byte): uses payload_len to precisely strip post-padding.
    ///   - V1 (2-byte, legacy): returns payload + post-padding (caller strips).
    std::vector<uint8_t> unpad(
        const uint8_t* padded_data, size_t len
    );
    
    std::vector<uint8_t> unpad(const std::vector<uint8_t>& padded_data);
    
    // ===== TCP Header Mutation =====
    
    /// Mutate TCP header fields in-place to confuse OS fingerprinting
    /// and flow classification. Operates on raw TCP header bytes.
    /// @param tcp_header Pointer to start of TCP header
    /// @param header_len Length of TCP header (typically 20-60 bytes)
    /// @return true if mutation was applied
    bool mutate_tcp_header(uint8_t* tcp_header, size_t header_len);
    
    // ===== Packet Size Normalization =====
    
    /// Pad packet to nearest "normal" size from target_sizes list.
    /// Makes packet size distribution look like regular HTTPS.
    std::vector<uint8_t> normalize_size(
        const std::vector<uint8_t>& data
    );
    
    // ===== Dummy Packet Generation =====
    
    /// Generate a dummy packet that looks like real traffic.
    /// Should be injected into the flow at random intervals.
    /// Uses HMAC-derived per-session marker (not static magic bytes).
    std::vector<uint8_t> generate_dummy_packet();
    
    /// Check if a received packet is a dummy (to discard on receive side).
    /// Checks HMAC-derived marker first, falls back to legacy 0xDEADBEEF.
    bool is_dummy_packet(const uint8_t* data, size_t len) const;
    
    /// Get the 32-byte session dummy key for sharing with peer.
    /// Both sides must use the same key for is_dummy_packet() to work.
    std::vector<uint8_t> get_session_dummy_key() const;
    
    /// Set session dummy key received from peer (32 bytes).
    /// Call after key exchange to synchronize dummy detection.
    void set_session_dummy_key(const uint8_t* key, size_t len);
    void set_session_dummy_key(const std::vector<uint8_t>& key);
    
    // ===== Adaptive Feedback =====
    
    /// Report detection feedback for adaptive strategy selection.
    void report_feedback(const DetectionFeedback& feedback);
    
    /// Force switch to a specific strategy.
    void force_strategy(AdversarialStrategy strategy);
    
    /// Get current active strategy (may differ from config if adaptive).
    AdversarialStrategy current_strategy() const;
    
    // ===== Configuration =====
    
    void set_config(const AdversarialConfig& config);
    AdversarialConfig get_config() const;
    
    // ===== Statistics =====
    
    AdversarialStats get_stats() const;
    void reset_stats();

private:
    // Padding generators per strategy
    std::vector<uint8_t> generate_random_padding(size_t len);
    std::vector<uint8_t> generate_http_mimic_padding(size_t len);
    std::vector<uint8_t> generate_tls_mimic_padding(size_t len);
    std::vector<uint8_t> generate_quic_mimic_padding(size_t len);
    std::vector<uint8_t> generate_dns_mimic_padding(size_t len);
    std::vector<uint8_t> generate_padding(AdversarialStrategy strategy, size_t len);
    
    // Size selection
    size_t select_pre_padding_size();
    size_t select_post_padding_size();
    size_t find_nearest_target_size(size_t current_size) const;
    
    // TCP mutation helpers
    void randomize_window_size(uint8_t* tcp_header);
    void randomize_tcp_options(uint8_t* tcp_header, size_t header_len);
    void jitter_timestamps(uint8_t* tcp_header, size_t header_len);
    
    // Adaptive strategy selection
    void evaluate_adaptive_strategy();
    AdversarialStrategy select_best_strategy() const;
    
    // Dummy packet marker — HMAC-derived per session (replaces fixed 0xDEADBEEF)
    static constexpr size_t DUMMY_MARKER_SIZE = 4;
    static constexpr size_t SESSION_DUMMY_KEY_SIZE = 32;
    std::array<uint8_t, SESSION_DUMMY_KEY_SIZE> session_dummy_key_{};
    std::array<uint8_t, DUMMY_MARKER_SIZE> dummy_marker_{};  // Derived from key
    void derive_dummy_marker();  // HMAC(key, "NCP-DUMMY-MARKER-v1") → first 4 bytes
    
    // Legacy magic bytes for backward compatibility with older peers
    static constexpr uint8_t LEGACY_DUMMY_MAGIC_0 = 0xDE;
    static constexpr uint8_t LEGACY_DUMMY_MAGIC_1 = 0xAD;
    static constexpr uint8_t LEGACY_DUMMY_MAGIC_2 = 0xBE;
    static constexpr uint8_t LEGACY_DUMMY_MAGIC_3 = 0xEF;
    
    // Control header versioning
    //
    // V1 (legacy, 2 bytes):
    //   Byte 0: [strategy:4][pre_len_hi:4]
    //   Byte 1: [pre_len_lo:8]
    //   No payload_len — unpad() returns payload + post-padding.
    //
    // V2 (current, 4 bytes):
    //   Byte 0: [strategy:4][pre_len_hi:4]
    //   Byte 1: [pre_len_lo:8]
    //   Byte 2: [payload_len_hi:8]
    //   Byte 3: [payload_len_lo:8]
    //   unpad() uses payload_len to precisely strip post-padding.
    //
    // unpad() auto-detects: tries V2 first, falls back to V1.
    // pad() always writes V2.
    static constexpr size_t CONTROL_HEADER_SIZE_V1 = 2;   // Legacy
    static constexpr size_t CONTROL_HEADER_SIZE_V2 = 4;   // Current
    static constexpr size_t CONTROL_HEADER_SIZE = CONTROL_HEADER_SIZE_V2;  // pad() uses this
    static constexpr size_t MAX_PRE_PADDING = 4095;   // 12-bit limit
    static constexpr size_t MAX_PAYLOAD_LEN = 65535;   // 16-bit limit
    
    // Thread safety: protects config_, active_strategy_, feedback_history_,
    // strategy_scores_, packets_since_evaluation_, session_dummy_key_, dummy_marker_
    mutable std::mutex mutex_;
    
    AdversarialConfig config_;
    AdversarialStats stats_;  // Uses atomics internally — no mutex needed for reads
    
    // Adaptive state
    AdversarialStrategy active_strategy_;
    std::vector<DetectionFeedback> feedback_history_;
    size_t packets_since_evaluation_ = 0;
    
    // Per-strategy score (lower = better, means less detection)
    std::array<double, 7> strategy_scores_;  // indexed by AdversarialStrategy
};

} // namespace DPI
} // namespace ncp
