// M3: tests for ncp_desync_confuse — TCP state confusion builders.
#include "ncp_desync_confuse.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

using ncp::desync::ConnTuple;
using ncp::desync::Segment;

namespace {

ConnTuple make_tuple() {
    ConnTuple t;
    t.src_ip = 0x0A000001;  // 10.0.0.1
    t.dst_ip = 0x0A000002;  // 10.0.0.2
    t.src_port = 51234;
    t.dst_port = 443;
    return t;
}

uint16_t read16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
uint32_t read32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

// Independent one's-complement checksum used ONLY by the tests (does not
// share code with the module under test).
uint16_t test_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
    if (len & 1) sum += static_cast<uint16_t>(data[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

// Verify a serialized IPv4 header checksum by summing the header INCLUDING
// the checksum field: a valid header folds to 0x0000.
bool ip_checksum_valid(const uint8_t* pkt) {
    return test_checksum(pkt, 20) == 0;
}

// Verify the TCP checksum independently via pseudo-header + TCP bytes.
bool tcp_checksum_valid(const ConnTuple& t, const uint8_t* pkt, size_t total) {
    uint32_t sum = 0;
    sum += (t.src_ip >> 16) & 0xFFFF; sum += t.src_ip & 0xFFFF;
    sum += (t.dst_ip >> 16) & 0xFFFF; sum += t.dst_ip & 0xFFFF;
    sum += 6;  // IPPROTO_TCP
    const size_t tcp_len = total - 20;
    sum += static_cast<uint16_t>(tcp_len);
    const uint8_t* tcp = pkt + 20;
    for (size_t i = 0; i + 1 < tcp_len; i += 2)
        sum += static_cast<uint16_t>((tcp[i] << 8) | tcp[i + 1]);
    if (tcp_len & 1) sum += static_cast<uint16_t>(tcp[tcp_len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    // Including the checksum field a valid segment folds to 0xFFFF -> ~0.
    return static_cast<uint16_t>(~sum) == 0;
}

std::vector<uint8_t> bytes(std::initializer_list<int> v) {
    std::vector<uint8_t> out;
    for (int x : v) out.push_back(static_cast<uint8_t>(x));
    return out;
}

} // namespace

// --- Technique 1: overlap — identical seq, decoy first, correct lengths ---
TEST(DesyncConfuse, OverlapPairSameSeqAndLengths) {
    auto t = make_tuple();
    auto decoy = bytes({0x16, 0x03, 0x01, 0x00, 0xAA});  // fake TLS-ish
    auto real  = bytes({'G', 'E', 'T', ' ', '/', ' '});   // real start

    auto segs = ncp::desync::build_overlap(t, 1000, decoy, real);
    ASSERT_EQ(segs.size(), 2u);
    EXPECT_EQ(segs[0].seq, 1000u);
    EXPECT_EQ(segs[1].seq, 1000u);            // SAME seq for both
    EXPECT_EQ(segs[0].payload.size(), decoy.size());
    EXPECT_EQ(segs[1].payload.size(), real.size());
    EXPECT_EQ(segs[0].payload, decoy);        // decoy first
    EXPECT_EQ(segs[1].payload, real);

    // Both serialize to correctly-sized, correctly-checksummed packets.
    for (const auto& s : segs) {
        auto pkt = ncp::desync::serialize_segment(t, s);
        ASSERT_EQ(pkt.size(), 40u + s.payload.size());
        EXPECT_TRUE(ip_checksum_valid(pkt.data()));
        EXPECT_TRUE(tcp_checksum_valid(t, pkt.data(), pkt.size()));
        EXPECT_EQ(read32(pkt.data() + 20 + 4), 1000u);  // TCP seq on wire
    }
}

// --- Technique 2: ttl_fake carries the requested TTL ---
TEST(DesyncConfuse, TtlFakeCarriesRequestedTtl) {
    auto t = make_tuple();
    auto payload = bytes({0x16, 0x03, 0x01, 0x01, 0x00, 0x01});  // fake CH frag
    for (uint8_t ttl : {1, 2, 3}) {
        auto seg = ncp::desync::build_ttl_fake(t, 5000, payload, ttl);
        EXPECT_EQ(seg.ttl, ttl);
        EXPECT_EQ(seg.seq, 5000u);
        auto pkt = ncp::desync::serialize_segment(t, seg);
        EXPECT_EQ(pkt[8], ttl);  // TTL field on the wire
        EXPECT_TRUE(ip_checksum_valid(pkt.data()));
        EXPECT_TRUE(tcp_checksum_valid(t, pkt.data(), pkt.size()));
    }
}

// --- Technique 3: oob seq is outside the receiver window ---
TEST(DesyncConfuse, OobFakeSeqOutsideWindow) {
    auto t = make_tuple();
    const uint32_t real_seq = 0x00010000;
    const uint32_t window = 65535;
    auto seg = ncp::desync::build_oob_fake(t, real_seq, bytes({1, 2, 3}), window);
    // Receiver accepts [real_seq, real_seq + window); the fake must be beyond.
    EXPECT_GE(seg.seq - real_seq, window);
    EXPECT_EQ(seg.seq, real_seq + ncp::desync::kOobSeqOffset);
    auto pkt = ncp::desync::serialize_segment(t, seg);
    EXPECT_TRUE(ip_checksum_valid(pkt.data()));
    EXPECT_TRUE(tcp_checksum_valid(t, pkt.data(), pkt.size()));
}

// --- Technique 4: badseq fake = real_seq - 1, correct checksum ---
TEST(DesyncConfuse, BadseqFakeSeqMinusOneValidChecksum) {
    auto t = make_tuple();
    const uint32_t real_seq = 424242;
    auto seg = ncp::desync::build_badseq_fake(t, real_seq, bytes({9, 9, 9, 9}));
    EXPECT_EQ(seg.seq, real_seq - 1);
    EXPECT_FALSE(seg.bad_checksum);  // zapret badseq uses a CORRECT checksum
    auto pkt = ncp::desync::serialize_segment(t, seg);
    EXPECT_TRUE(ip_checksum_valid(pkt.data()));
    EXPECT_TRUE(tcp_checksum_valid(t, pkt.data(), pkt.size()));
}

// --- bad_checksum poisons exactly the TCP checksum field ---
TEST(DesyncConfuse, BadChecksumPoisonsOnlyTcpChecksum) {
    auto t = make_tuple();
    Segment good = ncp::desync::build_ttl_fake(t, 777, bytes({1, 2, 3, 4, 5}), 2);
    Segment bad = good;
    bad.bad_checksum = true;

    auto pkt_good = ncp::desync::serialize_segment(t, good);
    auto pkt_bad  = ncp::desync::serialize_segment(t, bad);
    ASSERT_EQ(pkt_good.size(), pkt_bad.size());

    // TCP checksum field is at offset 20 (IP) + 16 = 36.
    EXPECT_EQ(read16(pkt_bad.data() + 36), 0xDEAD);
    EXPECT_NE(read16(pkt_good.data() + 36), 0xDEAD);

    // Everything else is byte-identical (IP checksum untouched and valid).
    for (size_t i = 0; i < pkt_good.size(); ++i) {
        if (i == 36 || i == 37) continue;
        EXPECT_EQ(pkt_good[i], pkt_bad[i]) << "byte " << i;
    }
    EXPECT_TRUE(ip_checksum_valid(pkt_bad.data()));       // IP csum still valid
    EXPECT_FALSE(tcp_checksum_valid(t, pkt_bad.data(), pkt_bad.size()));
    EXPECT_TRUE(tcp_checksum_valid(t, pkt_good.data(), pkt_good.size()));
}

// --- Wire-format sanity: header fields land where endpoints expect them ---
TEST(DesyncConfuse, SerializeWireFields) {
    auto t = make_tuple();
    auto payload = bytes({'h', 'e', 'l', 'l', 'o'});
    Segment seg = ncp::desync::build_badseq_fake(t, 0xDEAD0000, payload);
    seg.ip_id = 0x1234;
    seg.ttl = 42;
    seg.tcp_flags = 0x18;  // PSH|ACK

    auto pkt = ncp::desync::serialize_segment(t, seg);
    ASSERT_EQ(pkt.size(), 45u);
    EXPECT_EQ(pkt[0] >> 4, 4);                 // IPv4
    EXPECT_EQ(pkt[0] & 0x0F, 5);               // IHL = 20 bytes
    EXPECT_EQ(read16(pkt.data() + 2), 45);     // total length
    EXPECT_EQ(read16(pkt.data() + 4), 0x1234); // IP ID
    EXPECT_EQ(pkt[8], 42);                     // TTL
    EXPECT_EQ(pkt[9], 6);                      // TCP
    EXPECT_EQ(read32(pkt.data() + 12), t.src_ip);
    EXPECT_EQ(read32(pkt.data() + 16), t.dst_ip);
    EXPECT_EQ(read16(pkt.data() + 20), t.src_port);
    EXPECT_EQ(read16(pkt.data() + 22), t.dst_port);
    EXPECT_EQ(read32(pkt.data() + 24), 0xDEAD0000u - 1u);
    EXPECT_EQ(pkt[20 + 13], 0x18);             // flags
    EXPECT_EQ(std::memcmp(pkt.data() + 40, "hello", 5), 0);
}

// --- Odd-length payload (checksum padding path) ---
TEST(DesyncConfuse, OddLengthPayloadChecksum) {
    auto t = make_tuple();
    Segment seg = ncp::desync::build_ttl_fake(t, 1, bytes({0xAB}), 3);
    auto pkt = ncp::desync::serialize_segment(t, seg);
    ASSERT_EQ(pkt.size(), 41u);
    EXPECT_TRUE(ip_checksum_valid(pkt.data()));
    EXPECT_TRUE(tcp_checksum_valid(t, pkt.data(), pkt.size()));
}
