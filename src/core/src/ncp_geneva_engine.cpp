#include "ncp_geneva_engine.hpp"
#include <cstring>
#include <sodium.h>

namespace ncp {
namespace DPI {

// ==================== CSPRNG Helpers ====================
uint8_t GenevaEngine::csprng_byte() {
    uint8_t val;
    randombytes_buf(&val, sizeof(val));
    return val;
}

uint32_t GenevaEngine::csprng_uniform(uint32_t upper_bound) {
    if (upper_bound <= 1) return 0;
    return randombytes_uniform(upper_bound);
}

// ---- Preset strategies -------------------------------------------------

GenevaStrategy GenevaStrategy::tspu_2026() {
    GenevaStrategy s;
    s.description = "Russian TSPU bypass (2026)";
    s.steps = {
        {GenevaAction::DUPLICATE, 0, 0, "Duplicate first packet"},
        {GenevaAction::TAMPER_TTL, 0, 1, "Set TTL=1 on duplicate (expires at TSPU)"},
        {GenevaAction::FRAGMENT, 1, 40, "Fragment original into 40-byte chunks"},
        {GenevaAction::TAMPER_SEQ, 0, 0, "Corrupt sequence on duplicate"}
    };
    return s;
}

GenevaStrategy GenevaStrategy::gfw_2025() {
    GenevaStrategy s;
    s.description = "China GFW bypass (2025)";
    s.steps = {
        {GenevaAction::DUPLICATE, 0, 0, "Duplicate SYN packet"},
        {GenevaAction::TAMPER_CHECKSUM, 0, 0, "Corrupt checksum on duplicate"},
        {GenevaAction::FRAGMENT, 1, 8, "Fragment payload into 8-byte segments"},
        {GenevaAction::DISORDER, 0, 0, "Reorder fragments"}
    };
    return s;
}

GenevaStrategy GenevaStrategy::iran_dpi() {
    GenevaStrategy s;
    s.description = "Iran DPI bypass";
    s.steps = {
        {GenevaAction::FRAGMENT, 0, 2, "Split into 2-byte fragments"},
        {GenevaAction::TAMPER_FLAGS, 0, 0, "Tamper TCP flags on first fragment"},
        {GenevaAction::DUPLICATE, 1, 0, "Duplicate second fragment"},
        {GenevaAction::TAMPER_TTL, 2, 2, "Set TTL=2 on duplicate"}
    };
    return s;
}

GenevaStrategy GenevaStrategy::universal() {
    GenevaStrategy s;
    s.description = "Universal strategy (high overhead)";
    s.steps = {
        {GenevaAction::DUPLICATE, 0, 0, "Duplicate packet"},
        {GenevaAction::TAMPER_TTL, 0, 1, "Set low TTL on duplicate"},
        {GenevaAction::TAMPER_CHECKSUM, 0, 0, "Corrupt checksum on duplicate"},
        {GenevaAction::FRAGMENT, 1, 16, "Fragment original into 16-byte pieces"},
        {GenevaAction::DISORDER, 0, 0, "Randomize fragment order"},
        {GenevaAction::TAMPER_SEQ, 0, 0, "Corrupt SEQ on decoy"}
    };
    return s;
}

// ---- GenevaEngine construction -----------------------------------------

GenevaEngine::GenevaEngine() {}

GenevaEngine::~GenevaEngine() = default;

// ---- Public API --------------------------------------------------------

std::vector<std::vector<uint8_t>> GenevaEngine::apply_strategy(
    const std::vector<uint8_t>& payload,
    const GenevaStrategy& strategy)
{
    if (payload.empty()) return {};

    // Start with original payload as single packet
    std::vector<std::vector<uint8_t>> packets = {payload};
    stats_.packets_processed++;

    for (const auto& step : strategy.steps) {
        switch (step.action) {
            case GenevaAction::DUPLICATE:
                packets = action_duplicate(packets, step.target_index);
                break;
            case GenevaAction::FRAGMENT:
                packets = action_fragment(packets, step.target_index,
                                          step.param > 0 ? step.param : 16);
                break;
            case GenevaAction::TAMPER_TTL:
                packets = action_tamper_ttl(packets, step.target_index);
                break;
            case GenevaAction::TAMPER_SEQ:
                packets = action_tamper_seq(packets, step.target_index);
                break;
            case GenevaAction::TAMPER_FLAGS:
                packets = action_tamper_flags(packets, step.target_index);
                break;
            case GenevaAction::TAMPER_CHECKSUM:
                packets = action_tamper_checksum(packets, step.target_index);
                break;
            case GenevaAction::DROP:
                packets = action_drop(packets, step.target_index);
                break;
            case GenevaAction::DISORDER:
                packets = action_disorder(std::move(packets));
                break;
        }
    }

    // Calculate overhead
    int64_t total_out = 0;
    for (const auto& p : packets) total_out += static_cast<int64_t>(p.size());
    stats_.total_overhead_bytes += total_out - static_cast<int64_t>(payload.size());

    return packets;
}

// ---- Action implementations --------------------------------------------

std::vector<std::vector<uint8_t>> GenevaEngine::action_duplicate(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size()) {
        result.insert(result.begin() + static_cast<long>(target_idx),
                      result[target_idx]);
        stats_.packets_duplicated++;
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_fragment(
    const std::vector<std::vector<uint8_t>>& packets,
    size_t target_idx, size_t fragment_size)
{
    auto result = packets;
    if (target_idx >= result.size() || fragment_size == 0) return result;

    auto fragments = fragment_packet(result[target_idx], fragment_size);
    if (fragments.size() <= 1) return result;

    result.erase(result.begin() + static_cast<long>(target_idx));
    result.insert(result.begin() + static_cast<long>(target_idx),
                  fragments.begin(), fragments.end());
    stats_.packets_fragmented++;
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_ttl(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size() && result[target_idx].size() > 8) {
        // IP TTL is at offset 8 in IPv4 header
        result[target_idx][8] = 1; // Set TTL to 1
        stats_.packets_tampered++;
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_seq(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size() && result[target_idx].size() > 24) {
        // TCP seq number at offset 24 in IP+TCP (assuming 20-byte IP header + offset 4 in TCP)
        // SECURITY FIX: Use unbiased randombytes_uniform(256) instead of std::uniform_int_distribution with mt19937
        for (int i = 24; i < 28 && i < static_cast<int>(result[target_idx].size()); ++i) {
            result[target_idx][i] = static_cast<uint8_t>(csprng_uniform(256));
        }
        stats_.packets_tampered++;
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_flags(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size() && result[target_idx].size() > 33) {
        // TCP flags at offset 33 (20-byte IP + offset 13 in TCP)
        result[target_idx][33] ^= 0x02; // Toggle SYN flag
        stats_.packets_tampered++;
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_checksum(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size() && result[target_idx].size() > 11) {
        // IP checksum at offset 10-11
        result[target_idx][10] ^= 0xFF;
        result[target_idx][11] ^= 0xFF;
        stats_.packets_tampered++;
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_drop(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size()) {
        result.erase(result.begin() + static_cast<long>(target_idx));
        stats_.packets_dropped++;
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_disorder(
    std::vector<std::vector<uint8_t>> packets)
{
    // SECURITY FIX: Replace std::shuffle with Fisher-Yates using unbiased randombytes_uniform
    if (packets.size() > 1) {
        for (size_t i = packets.size() - 1; i > 0; --i) {
            size_t j = csprng_uniform(static_cast<uint32_t>(i + 1));
            std::swap(packets[i], packets[j]);
        }
    }
    return packets;
}

std::vector<std::vector<uint8_t>> GenevaEngine::fragment_packet(
    const std::vector<uint8_t>& packet, size_t fragment_size)
{
    if (packet.empty() || fragment_size == 0) return {packet};

    std::vector<std::vector<uint8_t>> fragments;
    for (size_t offset = 0; offset < packet.size(); offset += fragment_size) {
        size_t len = std::min(fragment_size, packet.size() - offset);
        fragments.emplace_back(packet.begin() + static_cast<long>(offset),
                               packet.begin() + static_cast<long>(offset + len));
    }
    return fragments;
}

} // namespace DPI
} // namespace ncp
