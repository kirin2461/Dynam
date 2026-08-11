#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP IP fragmentation helper — splits an IPv4 packet (TCP or UDP payload)
// into two IP fragments at a given payload offset.
//
// Platform-neutral pure function (unit-tested on Linux), used by the
// WinDivert backend to implement zapret-style ipfrag2 for TLS ClientHello
// and QUIC Initial packets.
//
// Notes:
//  - IPv4 only (IPv6 fragmentation uses extension headers — not supported).
//  - The transport checksum (TCP/UDP) is computed over the ORIGINAL packet
//    before fragmentation, so the first fragment carries a valid checksum.
//  - DF flag is cleared on the fragments.
// ═══════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ncp {

// Split IPv4 packet `packet` (len bytes) into two fragments, splitting the
// transport payload at `payload_offset` (bytes into TCP/UDP data).
// frag_offset must be > 0 and < payload length, and the first fragment's
// payload (transport header + payload_offset) must be a multiple of 8
// (IP fragment offset granularity) — the function adjusts the split point
// DOWN to the nearest multiple of 8 if needed.
//
// Returns false if fragmentation is impossible (bad packet, too small,
// IPv6, offset out of range).
bool build_ip_fragments(const uint8_t* packet, size_t len,
                        size_t payload_offset,
                        std::vector<uint8_t>& frag1,
                        std::vector<uint8_t>& frag2);

} // namespace ncp
