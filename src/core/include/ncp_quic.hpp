#pragma once

// ═══════════════════════════════════════════════════════════════════════════
// NCP QUIC helpers — fake QUIC Initial generation for DPI desync.
//
// A fake Initial looks plausible to DPI (long header, Initial type, random
// connection IDs, ≥1200 bytes) but is ignored by real servers because the
// DCID does not correspond to any connection and the payload is not a
// valid CRYPTO frame stream.
// ═══════════════════════════════════════════════════════════════════════════

#include <cstdint>
#include <cstddef>
#include <vector>

namespace ncp {

// True if a UDP payload looks like a QUIC long-header Initial packet.
inline bool is_quic_initial(const uint8_t* data, size_t len) {
    // long header: bit7 set, fixed bit6 set, type bits (5..4) == 0 (Initial)
    return data && len >= 7 &&
           (data[0] & 0x80) && (data[0] & 0x40) &&
           ((data[0] & 0x30) == 0x00);
}

// Build a fake QUIC Initial into out. Returns bytes written (0 if too small).
// dcid_len/scid_len are clamped to 8..20. Total size = target_len (≥ 64).
size_t build_fake_quic_initial(uint8_t* out, size_t out_cap,
                               size_t target_len = 1200,
                               uint8_t dcid_len = 8, uint8_t scid_len = 8);

// Vector convenience wrapper.
std::vector<uint8_t> build_fake_quic_initial(size_t target_len = 1200);

} // namespace ncp
