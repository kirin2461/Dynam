#pragma once

/**
 * @file ncp_desync_confuse.hpp
 * @brief M3: TCP state confusion builders for the desync engine.
 *
 * Produces raw IPv4/TCP segment descriptors that break the DPI's TCP
 * state machine while keeping the session valid for the real endpoints.
 *
 * Techniques (zapret/bol-van analogues):
 *   1. Overlap     — two segments with the SAME seq, decoy first. A DPI
 *                    with "first-segment-wins" reassembly poisons its own
 *                    stream; the real endpoint keeps the last copy (or the
 *                    decoy dies earlier due to TTL/badsum on the path).
 *                    Used against midbox DPI: the server sees both, but the
 *                    desync target is the DPI's reassembler (cf. lab
 *                    permissive first/last overlap policies).
 *   2. TTL fake    — fake segment (e.g. fake SNI ClientHello fragment) with
 *                    ttl=1..3: crosses the ISP's on-path DPI but dies before
 *                    the server. The sender must set IP_TTL per-socket.
 *   3. OOB fake    — seq placed far outside the receiver window
 *                    (real_seq + 16M): the server drops it, but a DPI that
 *                    tracks TCP state loosely still feeds it to its stream.
 *   4. Badseq fake — seq = real_seq - 1 overlap trick (zapret "badseq"
 *                    analogue) with a correct checksum.
 *
 * All builders recompute IPv4 + TCP checksums correctly EXCEPT when
 * Segment::bad_checksum is true (zapret "badsum" analogue) — then the TCP
 * checksum field is poisoned with 0xDEAD.
 *
 * NOTE: ncp_dpi_zapret.hpp was reviewed first — it defines only desync
 *       policy enums/structs (ZDesyncPhase*, ZFoolingFlags, ...), no raw
 *       segment descriptor, so `Segment` is defined here and serialized
 *       into a full IPv4+TCP wire packet that the existing raw-socket
 *       backend (NetworkRawSocket::send_raw_packet) can transmit directly.
 */

#include <cstddef>
#include <cstdint>
#include <vector>

namespace ncp {
namespace desync {

/// Raw IPv4/TCP segment descriptor consumed by the raw-socket sender.
struct Segment {
    uint32_t seq = 0;                 ///< TCP sequence number (host order)
    std::vector<uint8_t> payload;     ///< TCP payload bytes
    uint8_t  ttl = 64;                ///< IPv4 TTL the sender must apply
    uint16_t ip_id = 0;               ///< IPv4 identification field
    bool     bad_checksum = false;    ///< poison TCP checksum with 0xDEAD
    uint32_t ack = 0;                 ///< TCP acknowledgement number
    uint8_t  tcp_flags = 0x18;        ///< TCP flags (default PSH|ACK)
};

/// Real connection tuple the confusion segments are injected into.
struct ConnTuple {
    uint32_t src_ip = 0;    ///< IPv4 source, host byte order
    uint32_t dst_ip = 0;    ///< IPv4 destination, host byte order
    uint16_t src_port = 0;  ///< TCP source port, host byte order
    uint16_t dst_port = 0;  ///< TCP destination port, host byte order
};

/// Offset used by build_oob_fake(): 16M past the real sequence number —
/// far beyond any sane receiver window (RFC 793 max window is 1 GiB with
/// window scaling, but DPI-affecting fakes target typical <=64 KiB windows).
constexpr uint32_t kOobSeqOffset = 16u * 1024u * 1024u;

/// Poison value written into the TCP checksum when bad_checksum is set
/// (zapret "badsum" analogue).
constexpr uint16_t kPoisonedTcpChecksum = 0xDEAD;

// ---------------------------------------------------------------------------
// Builders. All take the real connection tuple; the returned Segment(s)
// still need serialize_segment() to become wire bytes.
// ---------------------------------------------------------------------------

/// Technique 1: overlap. Two segments with the SAME seq, decoy first.
std::vector<Segment> build_overlap(const ConnTuple& tuple,
                                   uint32_t next_seq,
                                   const std::vector<uint8_t>& decoy_payload,
                                   const std::vector<uint8_t>& real_payload);

/// Technique 2: TTL-limited fake. ttl should be 1..3 so the segment crosses
/// the on-path DPI but expires before reaching the server.
Segment build_ttl_fake(const ConnTuple& tuple,
                       uint32_t next_seq,
                       const std::vector<uint8_t>& payload,
                       uint8_t ttl);

/// Technique 3: out-of-window fake. seq = real_seq + kOobSeqOffset so the
/// server discards it while a loosely-tracking DPI accepts it.
Segment build_oob_fake(const ConnTuple& tuple,
                       uint32_t real_seq,
                       const std::vector<uint8_t>& payload,
                       uint32_t window);

/// Technique 4: badseq fake. seq = real_seq - 1 (zapret badseq analogue)
/// with a correct checksum.
Segment build_badseq_fake(const ConnTuple& tuple,
                          uint32_t real_seq,
                          const std::vector<uint8_t>& payload);

// ---------------------------------------------------------------------------
// Serialization / checksums
// ---------------------------------------------------------------------------

/// Serialize a Segment into a full IPv4+TCP wire packet (20-byte IP header,
/// 20-byte TCP header, payload). All checksums are correct unless
/// seg.bad_checksum is set, in which case the TCP checksum is 0xDEAD.
std::vector<uint8_t> serialize_segment(const ConnTuple& tuple,
                                       const Segment& seg);

/// Standard one's-complement IPv4 header checksum.
uint16_t ipv4_checksum(const uint8_t* hdr, size_t len);

/// TCP checksum over the pseudo-header built from (src_ip, dst_ip) plus the
/// TCP segment (header + payload). IPs in host byte order.
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const uint8_t* tcp_segment, size_t tcp_len);

} // namespace desync
} // namespace ncp
