#ifndef NCP_GENEVA_ENGINE_HPP
#define NCP_GENEVA_ENGINE_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace ncp {
namespace DPI {

/// Geneva action types for packet manipulation
enum class GenevaAction {
    DUPLICATE,         // Duplicate a packet
    FRAGMENT,          // Fragment into smaller chunks
    TAMPER_TTL,        // Modify IP TTL field
    TAMPER_SEQ,        // Modify TCP sequence number
    TAMPER_FLAGS,      // Modify TCP flags
    TAMPER_CHECKSUM,   // Corrupt IP checksum
    DROP,              // Drop a packet
    DISORDER           // Reorder packets
};

/// Single step in a Geneva strategy
struct GenevaStep {
    GenevaAction action;
    size_t target_index = 0;    // Which packet to target
    size_t param = 0;           // Action-specific parameter
    std::string description;    // Human-readable description
};

/// Complete Geneva strategy (sequence of steps)
struct GenevaStrategy {
    std::string description;
    std::vector<GenevaStep> steps;

    // Preset strategies
    static GenevaStrategy tspu_2026();     // Russian TSPU bypass
    static GenevaStrategy gfw_2025();      // China GFW bypass
    static GenevaStrategy iran_dpi();      // Iran DPI bypass
    static GenevaStrategy universal();     // Universal (high overhead)
};

/// Statistics for Geneva engine
struct GenevaStats {
    uint64_t packets_processed = 0;
    uint64_t packets_duplicated = 0;
    uint64_t packets_fragmented = 0;
    uint64_t packets_tampered = 0;
    uint64_t packets_dropped = 0;
    int64_t total_overhead_bytes = 0;
};

/**
 * @brief Geneva-inspired packet manipulation engine
 *
 * Implements strategies from the Geneva research project (censorship.ai)
 * for evading stateful DPI systems through packet-level manipulation.
 */
class GenevaEngine {
public:
    GenevaEngine();
    ~GenevaEngine();

    /// Apply a strategy to a payload, producing multiple output packets
    std::vector<std::vector<uint8_t>> apply_strategy(
        const std::vector<uint8_t>& payload,
        const GenevaStrategy& strategy
    );

    /// Get statistics
    const GenevaStats& get_stats() const { return stats_; }

    /// Reset statistics
    void reset_stats() { stats_ = {}; }

private:
    // Action implementations
    std::vector<std::vector<uint8_t>> action_duplicate(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx);
    std::vector<std::vector<uint8_t>> action_fragment(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx, size_t fragment_size);
    std::vector<std::vector<uint8_t>> action_tamper_ttl(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx);
    std::vector<std::vector<uint8_t>> action_tamper_seq(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx);
    std::vector<std::vector<uint8_t>> action_tamper_flags(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx);
    std::vector<std::vector<uint8_t>> action_tamper_checksum(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx);
    std::vector<std::vector<uint8_t>> action_drop(
        const std::vector<std::vector<uint8_t>>& packets, size_t target_idx);
    std::vector<std::vector<uint8_t>> action_disorder(
        std::vector<std::vector<uint8_t>> packets);

    std::vector<std::vector<uint8_t>> fragment_packet(
        const std::vector<uint8_t>& packet, size_t fragment_size);

    // CSPRNG helpers (replaces insecure mt19937)
    static uint8_t csprng_byte();
    static uint32_t csprng_uniform(uint32_t upper_bound);

    GenevaStats stats_;
};

} // namespace DPI
} // namespace ncp

#endif // NCP_GENEVA_ENGINE_HPP
