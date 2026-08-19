#include "ncp_desync_confuse.hpp"

#include <cstring>

namespace ncp {
namespace desync {

namespace {

constexpr size_t kIPv4HeaderLen = 20;
constexpr size_t kTcpHeaderLen  = 20;

void write16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}

void write32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[3] = static_cast<uint8_t>(v & 0xFF);
}

} // namespace

uint16_t ipv4_checksum(const uint8_t* hdr, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<uint16_t>((hdr[i] << 8) | hdr[i + 1]);
    if (len & 1) sum += static_cast<uint16_t>(hdr[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const uint8_t* tcp_segment, size_t tcp_len) {
    // Pseudo-header: src(4) dst(4) zero(1) proto(1)=6 tcp_len(2)
    uint32_t sum = 0;
    uint32_t s = src_ip, d = dst_ip;
    sum += (s >> 16) & 0xFFFF; sum += s & 0xFFFF;
    sum += (d >> 16) & 0xFFFF; sum += d & 0xFFFF;
    sum += static_cast<uint16_t>(6);  // IPPROTO_TCP
    sum += static_cast<uint16_t>(tcp_len);

    for (size_t i = 0; i + 1 < tcp_len; i += 2)
        sum += static_cast<uint16_t>((tcp_segment[i] << 8) | tcp_segment[i + 1]);
    if (tcp_len & 1) sum += static_cast<uint16_t>(tcp_segment[tcp_len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

std::vector<Segment> build_overlap(const ConnTuple& tuple,
                                   uint32_t next_seq,
                                   const std::vector<uint8_t>& decoy_payload,
                                   const std::vector<uint8_t>& real_payload) {
    (void)tuple;
    Segment decoy;
    decoy.seq = next_seq;
    decoy.payload = decoy_payload;
    Segment real;
    real.seq = next_seq;
    real.payload = real_payload;
    // Decoy first: a "first-segment-wins" DPI reassembler poisons its stream.
    return {decoy, real};
}

Segment build_ttl_fake(const ConnTuple& tuple,
                       uint32_t next_seq,
                       const std::vector<uint8_t>& payload,
                       uint8_t ttl) {
    (void)tuple;
    Segment seg;
    seg.seq = next_seq;
    seg.payload = payload;
    seg.ttl = ttl;  // typically 1..3: crosses the DPI, dies before the server
    return seg;
}

Segment build_oob_fake(const ConnTuple& tuple,
                       uint32_t real_seq,
                       const std::vector<uint8_t>& payload,
                       uint32_t window) {
    (void)tuple;
    (void)window;  // kOobSeqOffset (16M) exceeds any standard receiver window
    Segment seg;
    seg.seq = real_seq + kOobSeqOffset;
    seg.payload = payload;
    return seg;
}

Segment build_badseq_fake(const ConnTuple& tuple,
                          uint32_t real_seq,
                          const std::vector<uint8_t>& payload) {
    (void)tuple;
    Segment seg;
    seg.seq = real_seq - 1;  // zapret badseq analogue: 1-byte back-overlap
    seg.payload = payload;
    return seg;
}

std::vector<uint8_t> serialize_segment(const ConnTuple& tuple,
                                       const Segment& seg) {
    const size_t total = kIPv4HeaderLen + kTcpHeaderLen + seg.payload.size();
    std::vector<uint8_t> pkt(total, 0);

    uint8_t* ip = pkt.data();
    uint8_t* tcp = pkt.data() + kIPv4HeaderLen;

    // ---- IPv4 header ----
    ip[0] = 0x45;  // version 4, IHL 5 (20 bytes, no options)
    ip[1] = 0;     // TOS/DSCP
    write16(ip + 2, static_cast<uint16_t>(total));
    write16(ip + 4, seg.ip_id);
    write16(ip + 6, 0x4000);  // flags: DF, frag offset 0
    ip[8] = seg.ttl;
    ip[9] = 6;  // IPPROTO_TCP
    write16(ip + 10, 0);  // checksum placeholder
    write32(ip + 12, tuple.src_ip);
    write32(ip + 16, tuple.dst_ip);
    write16(ip + 10, ipv4_checksum(ip, kIPv4HeaderLen));

    // ---- TCP header ----
    write16(tcp + 0, tuple.src_port);
    write16(tcp + 2, tuple.dst_port);
    write32(tcp + 4, seg.seq);
    write32(tcp + 8, seg.ack);
    tcp[12] = 0x50;  // data offset 5 (20 bytes, no options)
    tcp[13] = seg.tcp_flags;
    write16(tcp + 14, 65535);  // window
    write16(tcp + 16, 0);      // checksum placeholder
    write16(tcp + 18, 0);      // urgent pointer

    if (!seg.payload.empty())
        std::memcpy(tcp + kTcpHeaderLen, seg.payload.data(), seg.payload.size());

    const uint16_t csum = seg.bad_checksum
        ? kPoisonedTcpChecksum
        : tcp_checksum(tuple.src_ip, tuple.dst_ip, tcp,
                       kTcpHeaderLen + seg.payload.size());
    write16(tcp + 16, csum);

    return pkt;
}

} // namespace desync
} // namespace ncp
