#include "../src/core/include/ncp_l3_stealth.hpp"
#include <cassert>
#include <iostream>
#include <cstring>
#include <sodium.h>

#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#endif

using namespace ncp;

// ==================== Test Packet Builders ====================

static std::vector<uint8_t> build_ipv4_tcp_syn(
    const char* src_ip, const char* dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t ttl = 64, uint16_t ipid = 0x1234,
    uint16_t mss = 1460, bool include_timestamp = true)
{
    // IP header (20) + TCP header (20) + options
    // Options: MSS(4) + NOP(1) + NOP(1) + Timestamp(10) + NOP(1) + NOP(1) = 18 padded to 20
    size_t tcp_options_len = 4; // MSS only
    if (include_timestamp) tcp_options_len = 4 + 2 + 10; // MSS + 2xNOP + TS  = 16
    // Pad to multiple of 4
    while (tcp_options_len % 4 != 0) tcp_options_len++;
    size_t ip_hdr_len = 20;
    size_t tcp_hdr_len = 20 + tcp_options_len;
    size_t total = ip_hdr_len + tcp_hdr_len;

    std::vector<uint8_t> pkt(total, 0);

    // IP header
    pkt[0] = 0x45; // ver=4, ihl=5
    pkt[1] = 0;    // TOS
    uint16_t tot_len = htons(static_cast<uint16_t>(total));
    std::memcpy(&pkt[2], &tot_len, 2);
    uint16_t id_n = htons(ipid);
    std::memcpy(&pkt[4], &id_n, 2);
    uint16_t frag = htons(0x4000); // DF set
    std::memcpy(&pkt[6], &frag, 2);
    pkt[8] = ttl;
    pkt[9] = 6; // TCP
    // checksum at [10-11] = 0 for now
    uint32_t sa, da;
    inet_pton(AF_INET, src_ip, &sa);
    inet_pton(AF_INET, dst_ip, &da);
    std::memcpy(&pkt[12], &sa, 4);
    std::memcpy(&pkt[16], &da, 4);

    // TCP header starts at offset 20
    size_t t = 20;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    std::memcpy(&pkt[t], &sp, 2);
    std::memcpy(&pkt[t+2], &dp, 2);
    uint32_t seq = htonl(0x12345678);
    std::memcpy(&pkt[t+4], &seq, 4);
    // ack = 0
    uint8_t doff = static_cast<uint8_t>((tcp_hdr_len / 4) << 4);
    pkt[t+12] = doff;
    pkt[t+13] = 0x02; // SYN
    uint16_t win = htons(65535);
    std::memcpy(&pkt[t+14], &win, 2);
    // checksum at [t+16..t+17] = 0
    // urg = 0

    // TCP options at t+20
    size_t opt_off = t + 20;
    // MSS option
    pkt[opt_off] = 2;  // Kind = MSS
    pkt[opt_off+1] = 4; // Length
    uint16_t mss_n = htons(mss);
    std::memcpy(&pkt[opt_off+2], &mss_n, 2);
    opt_off += 4;

    if (include_timestamp) {
        pkt[opt_off] = 1; // NOP
        pkt[opt_off+1] = 1; // NOP
        opt_off += 2;
        pkt[opt_off] = 8;   // Kind = Timestamp
        pkt[opt_off+1] = 10; // Length
        uint32_t tsval = htonl(123456789);
        uint32_t tsecr = htonl(0);
        std::memcpy(&pkt[opt_off+2], &tsval, 4);
        std::memcpy(&pkt[opt_off+6], &tsecr, 4);
        opt_off += 10;
    }

    // Pad remaining with NOP or END
    while (opt_off < t + tcp_hdr_len) {
        pkt[opt_off++] = 0; // END
    }

    return pkt;
}

static std::vector<uint8_t> build_ipv6_tcp_syn(
    uint16_t src_port, uint16_t dst_port,
    uint8_t hop_limit = 64, uint32_t flow_label = 0xABCDE)
{
    size_t ipv6_hdr = 40;
    size_t tcp_hdr = 20 + 4; // TCP + MSS option
    size_t total = ipv6_hdr + tcp_hdr;
    std::vector<uint8_t> pkt(total, 0);

    // IPv6 header
    uint32_t vtf = (6 << 28) | (0 << 20) | (flow_label & 0xFFFFF);
    uint32_t vtf_n = htonl(vtf);
    std::memcpy(&pkt[0], &vtf_n, 4);
    uint16_t plen = htons(static_cast<uint16_t>(tcp_hdr));
    std::memcpy(&pkt[4], &plen, 2);
    pkt[6] = 6; // next_header = TCP
    pkt[7] = hop_limit;
    // src/dst addr are all zeros (fine for test)

    // TCP at offset 40
    size_t t = 40;
    uint16_t sp = htons(src_port);
    uint16_t dp = htons(dst_port);
    std::memcpy(&pkt[t], &sp, 2);
    std::memcpy(&pkt[t+2], &dp, 2);
    uint32_t seq = htonl(0xAABBCCDD);
    std::memcpy(&pkt[t+4], &seq, 4);
    uint8_t doff = static_cast<uint8_t>((tcp_hdr / 4) << 4);
    pkt[t+12] = doff;
    pkt[t+13] = 0x02; // SYN
    uint16_t win = htons(65535);
    std::memcpy(&pkt[t+14], &win, 2);

    // MSS option at t+20
    pkt[t+20] = 2;  // MSS
    pkt[t+21] = 4;
    uint16_t mss_n = htons(1460);
    std::memcpy(&pkt[t+22], &mss_n, 2);

    return pkt;
}

// ==================== Tests ====================

static void test_ipid_randomization() {
    std::cout << "[TEST] IPID randomization... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = true;
    cfg.ipid_strategy = L3Stealth::IPIDStrategy::CSPRNG;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = false;
    cfg.enable_df_normalization = false;
    assert(stealth.initialize(cfg));

    auto pkt = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0x1234, 1460, false);
    uint16_t original_id;
    std::memcpy(&original_id, &pkt[4], 2);

    stealth.process_ipv4_packet(pkt);

    uint16_t new_id;
    std::memcpy(&new_id, &pkt[4], 2);

    // ID should be different (extremely unlikely to be same with CSPRNG)
    // We'll test multiple times to be safe
    bool changed = false;
    for (int i = 0; i < 10; i++) {
        auto p = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0x1234, 1460, false);
        stealth.process_ipv4_packet(p);
        uint16_t id;
        std::memcpy(&id, &p[4], 2);
        if (id != original_id) { changed = true; break; }
    }
    assert(changed);

    auto stats = stealth.get_stats();
    assert(stats.ipid_rewritten.load() > 0);

    std::cout << "PASS" << std::endl;
}

static void test_ipid_per_destination() {
    std::cout << "[TEST] IPID per-destination... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = true;
    cfg.ipid_strategy = L3Stealth::IPIDStrategy::PER_DESTINATION;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = false;
    cfg.enable_df_normalization = false;
    assert(stealth.initialize(cfg));

    // Send two packets to same dest — IDs should be sequential
    auto p1 = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0, 1460, false);
    auto p2 = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12346, 443, 64, 0, 1460, false);
    stealth.process_ipv4_packet(p1);
    stealth.process_ipv4_packet(p2);

    uint16_t id1, id2;
    std::memcpy(&id1, &p1[4], 2);
    std::memcpy(&id2, &p2[4], 2);
    id1 = ntohs(id1);
    id2 = ntohs(id2);

    // id2 should be slightly greater than id1 (increment 1-8)
    assert(id2 > id1);
    assert((id2 - id1) <= 8);

    std::cout << "PASS" << std::endl;
}

static void test_ttl_normalization() {
    std::cout << "[TEST] TTL normalization... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = false;
    cfg.enable_ttl_normalization = true;
    cfg.ttl_profile = L3Stealth::OSProfile::WINDOWS_10;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = false;
    cfg.enable_df_normalization = false;
    assert(stealth.initialize(cfg));

    // Packet with TTL=64 (Linux default)
    auto pkt = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0, 1460, false);
    stealth.process_ipv4_packet(pkt);

    // Should be normalized to 128 (Windows 10)
    assert(pkt[8] == 128);

    auto stats = stealth.get_stats();
    assert(stats.ttl_normalized.load() > 0);

    std::cout << "PASS" << std::endl;
}

static void test_mss_clamping() {
    std::cout << "[TEST] MSS clamping... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = false;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = true;
    cfg.target_mss = 1400; // Simulate tunnel MSS
    cfg.clamp_only_syn = true;
    cfg.enable_tcp_timestamp_normalization = false;
    cfg.enable_df_normalization = false;
    assert(stealth.initialize(cfg));

    // SYN with MSS=1460 — should be clamped to 1400
    auto pkt = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0, 1460, false);
    stealth.process_ipv4_packet(pkt);

    // Read MSS from TCP options (IP hdr 20 + TCP hdr 20 + MSS at offset 0)
    size_t mss_value_off = 20 + 20 + 2; // kind(1) + len(1) + value(2)
    uint16_t new_mss;
    std::memcpy(&new_mss, &pkt[mss_value_off], 2);
    new_mss = ntohs(new_mss);
    assert(new_mss == 1400);

    // MSS=1300 should NOT be clamped (already below target)
    auto pkt2 = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0, 1300, false);
    stealth.process_ipv4_packet(pkt2);
    std::memcpy(&new_mss, &pkt2[mss_value_off], 2);
    new_mss = ntohs(new_mss);
    assert(new_mss == 1300);

    std::cout << "PASS" << std::endl;
}

static void test_tcp_timestamp_normalization() {
    std::cout << "[TEST] TCP timestamp normalization... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = false;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = true;
    cfg.randomize_timestamp_offset = true;
    cfg.enable_df_normalization = false;
    assert(stealth.initialize(cfg));

    auto pkt = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0, 1460, true);

    // Original TSval
    // TCP starts at 20, options at 20+20=40, MSS(4)+NOP(1)+NOP(1)=6, TS at offset 46
    uint32_t original_ts;
    std::memcpy(&original_ts, &pkt[48], 4); // 40+6+2 = 48 (kind+len+TSval)
    original_ts = ntohl(original_ts);
    assert(original_ts == 123456789);

    stealth.process_ipv4_packet(pkt);

    uint32_t new_ts;
    std::memcpy(&new_ts, &pkt[48], 4);
    new_ts = ntohl(new_ts);
    // Should be different (normalized to our clock + offset)
    assert(new_ts != 123456789);

    auto stats = stealth.get_stats();
    assert(stats.timestamps_normalized.load() > 0);

    std::cout << "PASS" << std::endl;
}

static void test_ipv6_flow_label() {
    std::cout << "[TEST] IPv6 flow label randomization... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_flow_label_randomization = true;
    cfg.per_flow_label = true;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = false;
    assert(stealth.initialize(cfg));

    auto pkt = build_ipv6_tcp_syn(12345, 443, 64, 0xABCDE);

    stealth.process_ipv6_packet(pkt);

    uint32_t vtf;
    std::memcpy(&vtf, &pkt[0], 4);
    vtf = ntohl(vtf);
    uint32_t new_label = vtf & 0xFFFFF;

    // Should be different from original 0xABCDE
    // (could be same with 1/1M probability, but practically never)
    bool changed = (new_label != 0xABCDE);
    if (!changed) {
        // Try again
        auto pkt2 = build_ipv6_tcp_syn(12345, 443, 64, 0xABCDE);
        stealth.process_ipv6_packet(pkt2);
        std::memcpy(&vtf, &pkt2[0], 4);
        vtf = ntohl(vtf);
        new_label = vtf & 0xFFFFF;
        changed = (new_label != 0xABCDE);
    }
    assert(changed);

    // Same 5-tuple should get same label (per_flow_label=true)
    auto pkt3 = build_ipv6_tcp_syn(12345, 443, 64, 0x11111);
    auto pkt4 = build_ipv6_tcp_syn(12345, 443, 64, 0x22222);
    stealth.process_ipv6_packet(pkt3);
    stealth.process_ipv6_packet(pkt4);

    uint32_t vtf3, vtf4;
    std::memcpy(&vtf3, &pkt3[0], 4);
    std::memcpy(&vtf4, &pkt4[0], 4);
    vtf3 = ntohl(vtf3) & 0xFFFFF;
    vtf4 = ntohl(vtf4) & 0xFFFFF;
    // Same ports → same flow hash → same label
    assert(vtf3 == vtf4);

    auto stats = stealth.get_stats();
    assert(stats.flow_labels_randomized.load() > 0);

    std::cout << "PASS" << std::endl;
}

static void test_fragmentation() {
    std::cout << "[TEST] IP fragmentation... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = false;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = false;
    cfg.enable_df_normalization = false;
    cfg.enable_fragment_normalization = true;
    cfg.enforce_mtu = 100; // Small MTU for testing
    cfg.clear_df_for_tunneled = true;
    assert(stealth.initialize(cfg));

    // Build a larger packet (200+ bytes)
    std::vector<uint8_t> big_pkt(250, 0);
    big_pkt[0] = 0x45; // IPv4, IHL=5
    uint16_t tot = htons(250);
    std::memcpy(&big_pkt[2], &tot, 2);
    uint16_t id_n = htons(0x5678);
    std::memcpy(&big_pkt[4], &id_n, 2);
    uint16_t frag = htons(0x4000); // DF set
    std::memcpy(&big_pkt[6], &frag, 2);
    big_pkt[8] = 64; // TTL
    big_pkt[9] = 17; // UDP

    auto fragments = stealth.fragment_ipv4(big_pkt, 100);

    // Should produce multiple fragments
    assert(fragments.size() > 1);

    // Verify first fragment has MF flag
    uint16_t f0_frag;
    std::memcpy(&f0_frag, &fragments[0][6], 2);
    f0_frag = ntohs(f0_frag);
    assert((f0_frag & 0x2000) != 0); // MF set
    assert((f0_frag & 0x4000) == 0); // DF cleared

    // Last fragment should NOT have MF
    auto& last = fragments.back();
    uint16_t fl_frag;
    std::memcpy(&fl_frag, &last[6], 2);
    fl_frag = ntohs(fl_frag);
    assert((fl_frag & 0x2000) == 0); // No MF

    std::cout << "PASS" << std::endl;
}

static void test_df_normalization() {
    std::cout << "[TEST] DF bit normalization... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = false;
    cfg.enable_ttl_normalization = false;
    cfg.enable_mss_clamping = false;
    cfg.enable_tcp_timestamp_normalization = false;
    cfg.enable_df_normalization = true;
    cfg.force_df = true;
    assert(stealth.initialize(cfg));

    // Packet WITHOUT DF set
    auto pkt = build_ipv4_tcp_syn("10.0.0.1", "10.0.0.2", 12345, 443, 64, 0, 1460, false);
    // Clear DF
    uint16_t frag;
    std::memcpy(&frag, &pkt[6], 2);
    frag = ntohs(frag) & ~0x4000;
    frag = htons(frag);
    std::memcpy(&pkt[6], &frag, 2);

    stealth.process_ipv4_packet(pkt);

    // DF should now be set
    std::memcpy(&frag, &pkt[6], 2);
    frag = ntohs(frag);
    assert((frag & 0x4000) != 0);

    std::cout << "PASS" << std::endl;
}

static void test_os_detection() {
    std::cout << "[TEST] OS profile detection... ";

    auto profile = L3Stealth::detect_os_profile();

#ifdef _WIN32
    assert(profile == L3Stealth::OSProfile::WINDOWS_10);
    assert(L3Stealth::default_ttl_for_profile(profile) == 128);
#elif defined(__APPLE__)
    assert(profile == L3Stealth::OSProfile::MACOS_14);
    assert(L3Stealth::default_ttl_for_profile(profile) == 64);
#else
    assert(profile == L3Stealth::OSProfile::LINUX_6X);
    assert(L3Stealth::default_ttl_for_profile(profile) == 64);
#endif

    std::cout << "PASS" << std::endl;
}

static void test_combined_processing() {
    std::cout << "[TEST] Combined all-features processing... ";

    L3Stealth stealth;
    L3Stealth::Config cfg;
    cfg.enable_ipid_randomization = true;
    cfg.ipid_strategy = L3Stealth::IPIDStrategy::CSPRNG;
    cfg.enable_ttl_normalization = true;
    cfg.ttl_profile = L3Stealth::OSProfile::WINDOWS_10;
    cfg.enable_mss_clamping = true;
    cfg.target_mss = 1400;
    cfg.enable_tcp_timestamp_normalization = true;
    cfg.enable_df_normalization = true;
    cfg.force_df = true;
    assert(stealth.initialize(cfg));

    auto pkt = build_ipv4_tcp_syn("192.168.1.1", "8.8.8.8", 54321, 443, 55, 0xBEEF, 1460, true);

    bool modified = stealth.process_ipv4_packet(pkt);
    assert(modified);

    // Check TTL = 128
    assert(pkt[8] == 128);

    // Check IPID changed
    uint16_t new_id;
    std::memcpy(&new_id, &pkt[4], 2);
    new_id = ntohs(new_id);
    // Very unlikely to be exactly 0xBEEF

    // Check DF set
    uint16_t frag;
    std::memcpy(&frag, &pkt[6], 2);
    frag = ntohs(frag);
    assert((frag & 0x4000) != 0);

    // Check MSS clamped to 1400
    size_t mss_off = 20 + 20 + 2;
    uint16_t mss;
    std::memcpy(&mss, &pkt[mss_off], 2);
    mss = ntohs(mss);
    assert(mss == 1400);

    auto stats = stealth.get_stats();
    assert(stats.packets_processed.load() == 1);
    assert(stats.ipid_rewritten.load() > 0);
    assert(stats.ttl_normalized.load() > 0);
    assert(stats.mss_clamped.load() > 0);
    assert(stats.timestamps_normalized.load() > 0);

    std::cout << "PASS" << std::endl;
}

// ==================== Main ====================

int main() {
    sodium_init();

    std::cout << "=== L3 Stealth Phase 1 Tests ===" << std::endl;

    test_ipid_randomization();
    test_ipid_per_destination();
    test_ttl_normalization();
    test_mss_clamping();
    test_tcp_timestamp_normalization();
    test_ipv6_flow_label();
    test_fragmentation();
    test_df_normalization();
    test_os_detection();
    test_combined_processing();

    std::cout << std::endl << "All 10 tests PASSED!" << std::endl;
    return 0;
}
