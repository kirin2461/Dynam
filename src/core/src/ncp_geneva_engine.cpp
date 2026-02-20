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

// ==================== IP Header Helpers ====================

static constexpr size_t MIN_IPV4_HEADER = 20;

/// Verify buffer looks like a valid IPv4 packet:
/// version nibble == 4, IHL >= 5, and total_length roughly matches buffer size.
static bool is_ipv4_packet(const uint8_t* data, size_t len) {
    if (len < MIN_IPV4_HEADER) return false;
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 4) return false;
    uint8_t ihl = data[0] & 0x0F;
    if (ihl < 5) return false;
    uint16_t tot_len = (static_cast<uint16_t>(data[2]) << 8) |
                        static_cast<uint16_t>(data[3]);
    // tot_len should be close to buffer size (allow kernel padding up to 60 bytes)
    if (tot_len < MIN_IPV4_HEADER || tot_len > len + 60) return false;
    return true;
}

/// Return IP header length in bytes from IHL field.
static size_t ipv4_header_len(const uint8_t* data) {
    return static_cast<size_t>(data[0] & 0x0F) * 4;
}

/// Standard IP checksum over `len` bytes.
static uint16_t ip_checksum(const void* data, size_t len) {
    const uint16_t* buf = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t*>(buf);
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
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
    if (target_idx < result.size()) {
        auto& pkt = result[target_idx];
        // Guard: only tamper TTL if this is actually an IPv4 packet
        if (is_ipv4_packet(pkt.data(), pkt.size())) {
            pkt[8] = 1; // IPv4 TTL at offset 8
            // Recalculate IP header checksum after TTL change
            size_t hdr_len = ipv4_header_len(pkt.data());
            pkt[10] = 0; pkt[11] = 0; // zero checksum before recalc
            uint16_t cksum = ip_checksum(pkt.data(), hdr_len);
            pkt[10] = static_cast<uint8_t>(cksum & 0xFF);
            pkt[11] = static_cast<uint8_t>((cksum >> 8) & 0xFF);
            stats_.packets_tampered++;
        }
        // Non-IP data: skip silently to avoid corrupting TLS/application bytes
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_seq(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size()) {
        auto& pkt = result[target_idx];
        // Guard: only tamper TCP seq if this looks like an IP+TCP packet
        if (is_ipv4_packet(pkt.data(), pkt.size())) {
            size_t ip_hlen = ipv4_header_len(pkt.data());
            uint8_t protocol = pkt[9]; // IP protocol field
            // TCP = 6, and we need at least 8 bytes of TCP header for seq
            if (protocol == 6 && pkt.size() >= ip_hlen + 8) {
                size_t tcp_seq_off = ip_hlen + 4; // TCP seq at offset 4 within TCP header
                for (size_t i = tcp_seq_off; i < tcp_seq_off + 4 && i < pkt.size(); ++i) {
                    pkt[i] = static_cast<uint8_t>(csprng_uniform(256));
                }
                stats_.packets_tampered++;
            }
        }
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_flags(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size()) {
        auto& pkt = result[target_idx];
        // Guard: only tamper TCP flags if this looks like an IP+TCP packet
        if (is_ipv4_packet(pkt.data(), pkt.size())) {
            size_t ip_hlen = ipv4_header_len(pkt.data());
            uint8_t protocol = pkt[9];
            // TCP flags at offset 13 within TCP header
            size_t flags_off = ip_hlen + 13;
            if (protocol == 6 && pkt.size() > flags_off) {
                pkt[flags_off] ^= 0x02; // Toggle SYN flag
                stats_.packets_tampered++;
            }
        }
    }
    return result;
}

std::vector<std::vector<uint8_t>> GenevaEngine::action_tamper_checksum(
    const std::vector<std::vector<uint8_t>>& packets, size_t target_idx)
{
    auto result = packets;
    if (target_idx < result.size()) {
        auto& pkt = result[target_idx];
        // Guard: only tamper IP checksum if this is actually an IPv4 packet
        if (is_ipv4_packet(pkt.data(), pkt.size())) {
            // IP checksum at offset 10-11
            pkt[10] ^= 0xFF;
            pkt[11] ^= 0xFF;
            stats_.packets_tampered++;
        }
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

/// Fragment a packet. If it looks like a raw IPv4 packet, perform proper
/// IP-level fragmentation with Fragment Offset / MF flags and per-fragment
/// header + checksum. Otherwise fall back to simple payload-only split.
std::vector<std::vector<uint8_t>> GenevaEngine::fragment_packet(
    const std::vector<uint8_t>& packet, size_t fragment_size)
{
    if (packet.empty() || fragment_size == 0) return {packet};

    // ---- IP-level fragmentation when input is a raw IPv4 packet ----
    if (is_ipv4_packet(packet.data(), packet.size())) {
        size_t ip_hlen = ipv4_header_len(packet.data());
        if (ip_hlen >= packet.size()) {
            return {packet}; // header-only, nothing to fragment
        }

        const uint8_t* payload_ptr = packet.data() + ip_hlen;
        size_t payload_len = packet.size() - ip_hlen;

        // Fragment size must be a multiple of 8 for IP fragmentation
        size_t frag_payload = (fragment_size / 8) * 8;
        if (frag_payload == 0) frag_payload = 8; // minimum 8 bytes

        if (payload_len <= frag_payload) {
            return {packet}; // fits in one fragment
        }

        // Preserve original fragment offset and MF from the source packet
        uint16_t orig_frag_field = (static_cast<uint16_t>(packet[6]) << 8) |
                                    static_cast<uint16_t>(packet[7]);
        uint16_t orig_offset = orig_frag_field & 0x1FFF; // 13-bit offset
        bool orig_mf = (orig_frag_field & 0x2000) != 0;
        // Note: DF flag (0x4000) — if set, fragmentation is forbidden.
        // Geneva intentionally overrides DF for evasion purposes.

        std::vector<std::vector<uint8_t>> fragments;
        size_t offset = 0;

        while (offset < payload_len) {
            size_t chunk = std::min(frag_payload, payload_len - offset);
            bool last_fragment = (offset + chunk >= payload_len);

            // Build fragment: copy IP header + payload chunk
            std::vector<uint8_t> frag(ip_hlen + chunk);
            std::memcpy(frag.data(), packet.data(), ip_hlen); // copy header
            std::memcpy(frag.data() + ip_hlen, payload_ptr + offset, chunk);

            // Update total length
            uint16_t tot_len = static_cast<uint16_t>(ip_hlen + chunk);
            frag[2] = static_cast<uint8_t>(tot_len >> 8);
            frag[3] = static_cast<uint8_t>(tot_len & 0xFF);

            // Update Fragment Offset + MF flag
            uint16_t frag_off = orig_offset + static_cast<uint16_t>(offset / 8);
            bool mf = !last_fragment || orig_mf;
            uint16_t frag_field = frag_off & 0x1FFF;
            if (mf) frag_field |= 0x2000; // MF bit
            frag[6] = static_cast<uint8_t>(frag_field >> 8);
            frag[7] = static_cast<uint8_t>(frag_field & 0xFF);

            // Recalculate IP header checksum
            frag[10] = 0; frag[11] = 0;
            uint16_t cksum = ip_checksum(frag.data(), ip_hlen);
            frag[10] = static_cast<uint8_t>(cksum & 0xFF);
            frag[11] = static_cast<uint8_t>((cksum >> 8) & 0xFF);

            fragments.push_back(std::move(frag));
            offset += chunk;
        }

        return fragments;
    }

    // ---- Fallback: payload-only split for non-IP data (TLS, app bytes) ----
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
