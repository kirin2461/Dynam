#include "ncp_quic.hpp"

#include <sodium.h>

namespace ncp {

size_t build_fake_quic_initial(uint8_t* out, size_t out_cap,
                               size_t target_len,
                               uint8_t dcid_len, uint8_t scid_len) {
    if (!out) return 0;
    if (target_len < 64) target_len = 64;
    if (target_len > out_cap) return 0;
    if (dcid_len < 8) dcid_len = 8;
    if (dcid_len > 20) dcid_len = 20;
    if (scid_len < 8) scid_len = 8;
    if (scid_len > 20) scid_len = 20;

    // header form=long(1), fixed=1, type=Initial(00), reserved=0, pn len=4 (11)
    out[0] = 0xC3;
    // version: random non-zero (use a plausible one: v1 0x00000001 or random)
    out[1] = 0x00; out[2] = 0x00; out[3] = 0x00;
    out[4] = (randombytes_uniform(2) == 0) ? 0x01
                                           : static_cast<uint8_t>(0x29 + randombytes_uniform(0x50));
    size_t pos = 5;
    out[pos++] = dcid_len;
    randombytes_buf(out + pos, dcid_len);
    pos += dcid_len;
    out[pos++] = scid_len;
    randombytes_buf(out + pos, scid_len);
    pos += scid_len;

    // token length (varint, 0) — single byte 0x00
    if (pos < target_len) out[pos++] = 0x00;
    // packet length varint (2-byte form: 0b01xxxxxx) — claim remaining size
    if (pos + 2 <= target_len) {
        const uint16_t plen = static_cast<uint16_t>(target_len - pos - 2);
        out[pos++] = static_cast<uint8_t>(0x40 | ((plen >> 8) & 0x3F));
        out[pos++] = static_cast<uint8_t>(plen & 0xFF);
    }
    // packet number (4 bytes) + random payload
    if (pos < target_len)
        randombytes_buf(out + pos, target_len - pos);
    return target_len;
}

std::vector<uint8_t> build_fake_quic_initial(size_t target_len) {
    std::vector<uint8_t> buf(target_len);
    const size_t n = build_fake_quic_initial(buf.data(), buf.size(), target_len);
    buf.resize(n);
    return buf;
}

} // namespace ncp
