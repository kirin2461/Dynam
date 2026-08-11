#include "ncp_ipfrag.hpp"

#include <cstring>

namespace ncp {

namespace {

uint16_t ip_checksum(const uint8_t* hdr, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<uint16_t>((hdr[i] << 8) | hdr[i + 1]);
    if (len & 1) sum += static_cast<uint16_t>(hdr[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t read16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
void write16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

} // namespace

bool build_ip_fragments(const uint8_t* packet, size_t len,
                        size_t payload_offset,
                        std::vector<uint8_t>& frag1,
                        std::vector<uint8_t>& frag2) {
    if (!packet || len < 20) return false;

    const uint8_t ihl = static_cast<uint8_t>((packet[0] & 0x0F) * 4);
    if ((packet[0] >> 4) != 4 || ihl < 20 || ihl > len) return false;  // IPv4 only

    const uint16_t total_len = read16(packet + 2);
    if (total_len > len || total_len < ihl) return false;

    const uint8_t proto = packet[9];
    size_t transport_hdr = 0;
    if (proto == 6) {           // TCP
        if (total_len < ihl + 20) return false;
        transport_hdr = static_cast<size_t>((packet[ihl + 12] >> 4) * 4);
        if (transport_hdr < 20) return false;
    } else if (proto == 17) {   // UDP
        transport_hdr = 8;
    } else {
        return false;
    }

    const size_t payload_start = ihl + transport_hdr;
    if (payload_start >= total_len) return false;  // no payload
    const size_t payload_len = total_len - payload_start;
    if (payload_offset == 0 || payload_offset >= payload_len) return false;

    // fragment payload boundary must be 8-byte aligned (measured from IP payload
    // start, i.e. including transport header)
    size_t first_ip_payload = transport_hdr + payload_offset;
    first_ip_payload &= ~static_cast<size_t>(7);  // round down to multiple of 8
    if (first_ip_payload < transport_hdr) return false;  // can't split before headers
    if (first_ip_payload == 0) return false;
    const size_t second_ip_payload_off = first_ip_payload;  // offset in IP payload
    const size_t second_len = total_len - ihl - second_ip_payload_off;
    if (second_len == 0) return false;

    // ── fragment 1: IP header + first_ip_payload bytes, MF=1, offset=0 ──
    frag1.assign(packet, packet + ihl + first_ip_payload);
    write16(frag1.data() + 2, static_cast<uint16_t>(ihl + first_ip_payload));
    uint16_t flags_off = read16(frag1.data() + 6);
    flags_off = static_cast<uint16_t>((flags_off & ~0x4000) | 0x2000);  // DF=0, MF=1
    write16(frag1.data() + 6, flags_off);
    write16(frag1.data() + 4, read16(packet + 4));  // same ID
    frag1[10] = 0; frag1[11] = 0;
    write16(frag1.data() + 10, ip_checksum(frag1.data(), ihl));

    // ── fragment 2: IP header + rest, MF=0, offset=first_ip_payload/8 ──
    frag2.resize(ihl + second_len);
    memcpy(frag2.data(), packet, ihl);
    memcpy(frag2.data() + ihl, packet + ihl + second_ip_payload_off, second_len);
    write16(frag2.data() + 2, static_cast<uint16_t>(ihl + second_len));
    uint16_t fo2 = static_cast<uint16_t>((read16(packet + 6) & ~0x4000 & ~0x2000) |
                                         ((second_ip_payload_off / 8) & 0x1FFF));
    write16(frag2.data() + 6, fo2);
    frag2[10] = 0; frag2[11] = 0;
    write16(frag2.data() + 10, ip_checksum(frag2.data(), ihl));

    return true;
}

} // namespace ncp
