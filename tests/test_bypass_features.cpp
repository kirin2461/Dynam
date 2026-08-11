// Tests for the bypass feature set:
//   hostlist matcher, TLS/HTTP parsing, fake QUIC, IP fragmentation,
//   zapret import, proxy split resolution, DPI detector, blockcheck primitives.
#include <gtest/gtest.h>

#include "ncp_hostlist.hpp"
#include "ncp_tls_parse.hpp"
#include "ncp_quic.hpp"
#include "ncp_ipfrag.hpp"
#include "ncp_zapret_import.hpp"
#include "ncp_proxy.hpp"
#include "ncp_dpi_detector.hpp"
#include "ncp_blockcheck.hpp"

#include <fstream>
#include <cstring>

using namespace ncp;

// ═══════════════════════════════════════════════════════════════════════════
// HostlistMatcher
// ═══════════════════════════════════════════════════════════════════════════

TEST(HostlistMatcher, ExactAndSuffix) {
    HostlistMatcher m;
    m.add("example.com");
    EXPECT_TRUE(m.contains("example.com"));
    EXPECT_TRUE(m.contains("www.example.com"));
    EXPECT_TRUE(m.contains("a.b.example.com"));
    EXPECT_FALSE(m.contains("notexample.com"));
    EXPECT_FALSE(m.contains("example.com.evil.org"));
    EXPECT_FALSE(m.contains("other.org"));
}

TEST(HostlistMatcher, Normalize) {
    EXPECT_EQ(HostlistMatcher::normalize("  Example.COM. "), "example.com");
    EXPECT_EQ(HostlistMatcher::normalize("*.example.com"), "example.com");
    EXPECT_EQ(HostlistMatcher::normalize(".example.com"), "example.com");
    EXPECT_TRUE(HostlistMatcher::normalize("   ").empty());
}

TEST(HostlistMatcher, WildcardPattern) {
    EXPECT_TRUE(HostlistMatcher::matches_pattern("www.youtube.com", "*.youtube.com"));
    EXPECT_TRUE(HostlistMatcher::matches_pattern("youtube.com", "*.youtube.com"));
    EXPECT_FALSE(HostlistMatcher::matches_pattern("notyoutube.com", "*.youtube.com"));
}

TEST(HostlistMatcher, LoadSaveRoundtrip) {
    const std::string path = "/tmp/ncp_test_hostlist.txt";
    {
        std::ofstream f(path);
        f << "# comment\nyoutube.com\n\n*.discord.gg\n  x.com  \ninvalid host!\n";
    }
    HostlistMatcher m;
    int n = m.load(path);
    EXPECT_EQ(n, 3);
    EXPECT_TRUE(m.contains("rr1---sn-x.youtube.com"));
    EXPECT_TRUE(m.contains("cdn.discord.gg"));
    EXPECT_TRUE(m.contains("x.com"));

    const std::string out = "/tmp/ncp_test_hostlist_out.txt";
    EXPECT_TRUE(m.save(out));
    HostlistMatcher m2;
    EXPECT_EQ(m2.load(out), 3);
    EXPECT_TRUE(m2.contains("youtube.com"));
}

TEST(HostlistMatcher, NoBareTldMatch) {
    HostlistMatcher m;
    m.add("com");
    // bare TLD entry matches only itself, not every .com domain
    EXPECT_TRUE(m.contains("com"));
    EXPECT_FALSE(m.contains("example.com"));
}

TEST(AutoHostlist, RecordAndPersist) {
    const std::string path = "/tmp/ncp_test_autohl.txt";
    std::remove(path.c_str());
    AutoHostlist a(path);
    EXPECT_TRUE(a.record_blocked("YouTube.COM"));
    EXPECT_FALSE(a.record_blocked("youtube.com"));   // dedup
    EXPECT_TRUE(a.record_blocked("www.youtube.com") == false ||
                a.contains("www.youtube.com"));      // covered by suffix
    EXPECT_EQ(a.size(), 1u);

    AutoHostlist b(path);
    EXPECT_TRUE(b.load());
    EXPECT_TRUE(b.contains("youtube.com"));
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS parsing
// ═══════════════════════════════════════════════════════════════════════════

TEST(TlsParse, ClientHelloSniOffsets) {
    auto ch = BlockChecker::build_client_hello("www.example.com");
    ASSERT_GT(ch.size(), 50u);
    EXPECT_TRUE(is_tls_client_hello(ch.data(), ch.size()));

    auto info = parse_tls_client_hello(ch.data(), ch.size());
    EXPECT_TRUE(info.valid);
    EXPECT_EQ(info.sni, "www.example.com");
    ASSERT_GT(info.sni_value_offset, 0u);
    ASSERT_EQ(info.sni_value_len, 15u);
    // bytes at the offset must equal the hostname
    EXPECT_EQ(std::string(reinterpret_cast<char*>(ch.data() + info.sni_value_offset),
                          info.sni_value_len),
              "www.example.com");
    // extension type field must be 0x0000 (server_name)
    EXPECT_EQ(ch[info.sni_ext_offset], 0x00);
    EXPECT_EQ(ch[info.sni_ext_offset + 1], 0x00);
}

TEST(TlsParse, RejectsGarbage) {
    uint8_t junk[32] = {0};
    EXPECT_FALSE(is_tls_client_hello(junk, sizeof(junk)));
    auto info = parse_tls_client_hello(junk, sizeof(junk));
    EXPECT_FALSE(info.valid);
}

TEST(HttpParse, HostHeaderOffsets) {
    const char* req =
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com:8080\r\n"
        "User-Agent: test\r\n"
        "\r\n";
    auto info = parse_http_request(reinterpret_cast<const uint8_t*>(req), strlen(req));
    EXPECT_TRUE(info.valid);
    EXPECT_FALSE(info.is_connect);
    EXPECT_EQ(info.method, "GET");
    EXPECT_EQ(info.host, "www.example.com");
    EXPECT_EQ(std::string(req + info.host_value_offset, info.host_value_len),
              "www.example.com");
    EXPECT_GT(info.headers_end, 0u);
}

TEST(HttpParse, Connect) {
    const char* req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    auto info = parse_http_request(reinterpret_cast<const uint8_t*>(req), strlen(req));
    EXPECT_TRUE(info.valid);
    EXPECT_TRUE(info.is_connect);
    EXPECT_EQ(info.target, "example.com:443");
}

TEST(SldOffset, Basic) {
    EXPECT_EQ(sld_start_offset("www.example.com"), 4u);
    EXPECT_EQ(sld_start_offset("example.com"), 0u);
    EXPECT_EQ(sld_start_offset("a.b.co.uk"), 2u);
}

// ═══════════════════════════════════════════════════════════════════════════
// QUIC helpers
// ═══════════════════════════════════════════════════════════════════════════

TEST(QuicFake, BuildInitial) {
    auto fake = build_fake_quic_initial(1200);
    ASSERT_EQ(fake.size(), 1200u);
    EXPECT_TRUE(is_quic_initial(fake.data(), fake.size()));
    // long header + fixed bit
    EXPECT_EQ(fake[0] & 0xC0, 0xC0);
    // two builds differ (random DCID/payload)
    auto fake2 = build_fake_quic_initial(1200);
    EXPECT_NE(memcmp(fake.data(), fake2.data(), fake.size()), 0);
}

TEST(QuicFake, DetectsInitial) {
    uint8_t short_hdr[16] = {0x40};  // short header
    EXPECT_FALSE(is_quic_initial(short_hdr, sizeof(short_hdr)));
    uint8_t long_retry[16] = {static_cast<uint8_t>(0xF0)};  // long header, type=Retry
    EXPECT_FALSE(is_quic_initial(long_retry, sizeof(long_retry)));
}

// ═══════════════════════════════════════════════════════════════════════════
// IP fragmentation
// ═══════════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> make_udp_packet(size_t payload_len) {
    std::vector<uint8_t> p(20 + 8 + payload_len, 0);
    p[0] = 0x45;                          // IPv4, IHL=5
    const uint16_t total = static_cast<uint16_t>(p.size());
    p[2] = static_cast<uint8_t>(total >> 8);
    p[3] = static_cast<uint8_t>(total & 0xFF);
    p[6] = 0x40; p[7] = 0x00;             // DF set
    p[8] = 64;                            // TTL
    p[9] = 17;                            // UDP
    p[12] = 10; p[15] = 1;                // src 10.0.0.1
    p[16] = 8;  p[19] = 8;                // dst 8.8.8.8
    for (size_t i = 28; i < p.size(); ++i) p[i] = static_cast<uint8_t>(i & 0xFF);
    return p;
}

TEST(IpFrag, SplitUdp) {
    auto pkt = make_udp_packet(200);
    std::vector<uint8_t> f1, f2;
    ASSERT_TRUE(build_ip_fragments(pkt.data(), pkt.size(), 100, f1, f2));

    // sizes sum to original + one extra IP header
    EXPECT_EQ(f1.size() + f2.size(), pkt.size() + 20);
    // frag1: MF set, offset 0
    EXPECT_EQ(f1[6] & 0x20, 0x20);
    // frag1 total length consistent
    EXPECT_EQ((f1[2] << 8) | f1[3], static_cast<int>(f1.size()));
    // frag2: MF clear, offset = (f1 payload)/8
    EXPECT_EQ(f2[6] & 0x20, 0);
    const size_t f1_payload = f1.size() - 20;
    EXPECT_EQ(f1_payload % 8, 0u);
    const uint16_t off2 = ((f2[6] & 0x1F) << 8) | f2[7];
    EXPECT_EQ(off2 * 8, f1_payload);
    // DF cleared on both
    EXPECT_EQ(f1[6] & 0x40, 0);
    EXPECT_EQ(f2[6] & 0x40, 0);
    // reassembled payload equals original
    std::vector<uint8_t> reassembled;
    reassembled.insert(reassembled.end(), f1.begin() + 20, f1.end());
    reassembled.insert(reassembled.end(), f2.begin() + 20, f2.end());
    EXPECT_EQ(reassembled.size(), pkt.size() - 20);
    EXPECT_EQ(memcmp(reassembled.data(), pkt.data() + 20, reassembled.size()), 0);
}

TEST(IpFrag, RejectsBadInput) {
    std::vector<uint8_t> f1, f2;
    EXPECT_FALSE(build_ip_fragments(nullptr, 0, 10, f1, f2));
    auto pkt = make_udp_packet(200);
    EXPECT_FALSE(build_ip_fragments(pkt.data(), pkt.size(), 0, f1, f2));     // off=0
    EXPECT_FALSE(build_ip_fragments(pkt.data(), pkt.size(), 500, f1, f2));   // off>len
    pkt[0] = 0x60;  // IPv6
    EXPECT_FALSE(build_ip_fragments(pkt.data(), pkt.size(), 100, f1, f2));
}

// ═══════════════════════════════════════════════════════════════════════════
// zapret import
// ═══════════════════════════════════════════════════════════════════════════

TEST(ZapretImport, Tokenize) {
    auto t = DPI::zapret_tokenize("--dpi-desync=fake --hostlist=\"my list.txt\" --new");
    ASSERT_EQ(t.size(), 3u);
    EXPECT_EQ(t[0], "--dpi-desync=fake");
    EXPECT_EQ(t[1], "--hostlist=my list.txt");
    EXPECT_EQ(t[2], "--new");
}

TEST(ZapretImport, BasicChain) {
    auto r = DPI::parse_zapret_cmdline(
        "--filter-tcp=443 --dpi-desync=fake,multisplit "
        "--dpi-desync-split-pos=2,midsld --dpi-desync-ttl=4 "
        "--dpi-desync-fooling=badsum,badseq --hostlist=list.txt");
    EXPECT_TRUE(r.errors.empty()) << (r.errors.empty() ? "" : r.errors[0]);
    ASSERT_EQ(r.profile.chains.size(), 1u);
    const auto& c = r.profile.chains[0];
    EXPECT_EQ(c.proto, DPI::ZProto::TCP);
    EXPECT_EQ(c.phase1, DPI::ZDesyncPhase1::FAKE);
    EXPECT_EQ(c.phase2, DPI::ZDesyncPhase2::MULTISPLIT);
    ASSERT_EQ(c.split_positions.size(), 2u);
    EXPECT_EQ(c.split_positions[0].type, DPI::ZSplitPosType::NUMERIC);
    EXPECT_EQ(c.split_positions[0].offset, 2);
    EXPECT_EQ(c.split_positions[1].type, DPI::ZSplitPosType::MIDSLD);
    EXPECT_EQ(c.orig_ttl.ttl, 4);
    EXPECT_EQ(c.fooling & DPI::ZFOOL_BADSUM, DPI::ZFOOL_BADSUM);
    EXPECT_EQ(c.fooling & DPI::ZFOOL_BADSEQ, DPI::ZFOOL_BADSEQ);
    EXPECT_EQ(c.hostlist, "list.txt");
}

TEST(ZapretImport, MultiChain) {
    auto r = DPI::parse_zapret_cmdline(
        "--filter-tcp=80 --dpi-desync=multisplit --dpi-desync-split-pos=method "
        "--new "
        "--filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic --dpi-desync-repeats=6");
    EXPECT_TRUE(r.errors.empty());
    ASSERT_EQ(r.profile.chains.size(), 2u);
    EXPECT_EQ(r.profile.chains[0].proto, DPI::ZProto::TCP);
    EXPECT_EQ(r.profile.chains[0].split_positions[0].type, DPI::ZSplitPosType::METHOD);
    EXPECT_EQ(r.profile.chains[1].proto, DPI::ZProto::UDP);
    EXPECT_EQ(r.profile.chains[1].fake_type, DPI::ZFakeType::QUIC);
    EXPECT_EQ(r.profile.chains[1].desync_repeats, 6);
}

TEST(ZapretImport, LegacySplit2) {
    auto r = DPI::parse_zapret_cmdline("--filter-tcp=443 --dpi-desync=fake,split2");
    EXPECT_TRUE(r.errors.empty());
    ASSERT_EQ(r.profile.chains.size(), 1u);
    EXPECT_EQ(r.profile.chains[0].phase2, DPI::ZDesyncPhase2::MULTISPLIT);
    ASSERT_EQ(r.profile.chains[0].split_positions.size(), 1u);
    EXPECT_EQ(r.profile.chains[0].split_positions[0].offset, 2);
}

TEST(ZapretImport, Autottl) {
    auto r = DPI::parse_zapret_cmdline(
        "--filter-tcp=443 --dpi-desync=fake --dpi-desync-autottl=2-8");
    EXPECT_TRUE(r.errors.empty());
    EXPECT_TRUE(r.profile.chains[0].orig_ttl.auto_ttl);
    EXPECT_EQ(r.profile.chains[0].orig_ttl.auto_ttl_min, 2);
    EXPECT_EQ(r.profile.chains[0].orig_ttl.auto_ttl_max, 8);
}

TEST(ZapretImport, UnknownFlagsAreWarnings) {
    auto r = DPI::parse_zapret_cmdline(
        "--filter-tcp=443 --dpi-desync=fake --some-unknown-opt=5");
    EXPECT_TRUE(r.errors.empty());
    EXPECT_FALSE(r.warnings.empty());
}

TEST(ZapretImport, JsonRoundTrip) {
    auto r = DPI::parse_zapret_cmdline(
        "--filter-tcp=443 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,sniext");
    std::string j = DPI::zapret_profile_to_json(r);
    EXPECT_NE(j.find("\"chains\""), std::string::npos);
    EXPECT_NE(j.find("sniext"), std::string::npos);
    EXPECT_NE(j.find("\"ok\": true"), std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// Proxy split resolution / chain selection (pure logic, no sockets)
// ═══════════════════════════════════════════════════════════════════════════

TEST(ProxySplit, NumericPositions) {
    auto ch = BlockChecker::build_client_hello("example.com");
    std::vector<DPI::ZSplitPos> pos = {
        {DPI::ZSplitPosType::NUMERIC, 2},
        {DPI::ZSplitPosType::NUMERIC, 5},
    };
    auto cuts = DesyncProxy::resolve_split_positions(pos, ch.data(), ch.size());
    ASSERT_EQ(cuts.size(), 2u);
    EXPECT_EQ(cuts[0], 2u);
    EXPECT_EQ(cuts[1], 5u);
}

TEST(ProxySplit, HostMarkerAtSni) {
    auto ch = BlockChecker::build_client_hello("example.com");
    auto info = parse_tls_client_hello(ch.data(), ch.size());
    std::vector<DPI::ZSplitPos> pos = {{DPI::ZSplitPosType::HOST, 0}};
    auto cuts = DesyncProxy::resolve_split_positions(pos, ch.data(), ch.size());
    ASSERT_EQ(cuts.size(), 1u);
    EXPECT_EQ(cuts[0], info.sni_value_offset);
}

TEST(ProxySplit, MidsldMarker) {
    auto ch = BlockChecker::build_client_hello("www.example.com");
    auto info = parse_tls_client_hello(ch.data(), ch.size());
    std::vector<DPI::ZSplitPos> pos = {{DPI::ZSplitPosType::MIDSLD, 0}};
    auto cuts = DesyncProxy::resolve_split_positions(pos, ch.data(), ch.size());
    ASSERT_EQ(cuts.size(), 1u);
    // sld = "example" starting at offset 4 within the hostname; mid = 4+3
    EXPECT_EQ(cuts[0], info.sni_value_offset + 4 + 3);
}

TEST(ProxySplit, SniextMarker) {
    auto ch = BlockChecker::build_client_hello("example.com");
    auto info = parse_tls_client_hello(ch.data(), ch.size());
    std::vector<DPI::ZSplitPos> pos = {{DPI::ZSplitPosType::SNIEXT, 0}};
    auto cuts = DesyncProxy::resolve_split_positions(pos, ch.data(), ch.size());
    ASSERT_EQ(cuts.size(), 1u);
    EXPECT_EQ(cuts[0], info.sni_ext_offset);
}

TEST(ProxySplit, HttpHostMarkers) {
    const char* req = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    std::vector<DPI::ZSplitPos> pos = {
        {DPI::ZSplitPosType::METHOD, 0},
        {DPI::ZSplitPosType::HOST, 0},
        {DPI::ZSplitPosType::ENDHOST, 0},
    };
    auto cuts = DesyncProxy::resolve_split_positions(
        pos, reinterpret_cast<const uint8_t*>(req), strlen(req));
    ASSERT_EQ(cuts.size(), 3u);
    EXPECT_EQ(cuts[0], 3u);   // after "GET"
    EXPECT_EQ(req[cuts[1]], 'w');
    EXPECT_EQ(cuts[2] - cuts[1], strlen("www.example.com"));
}

TEST(ProxyChainSelect, PortAndHostlist) {
    std::vector<DPI::ZapretChain> chains(2);
    chains[0].proto = DPI::ZProto::TCP;
    chains[0].ports = {{443, 443}};
    // chains[0] has hostlist patterns (parallel vector)
    chains[1].proto = DPI::ZProto::UDP;
    chains[1].ports = {{443, 443}};

    std::vector<std::vector<std::string>> patterns = {{"youtube.com"}, {}};

    EXPECT_EQ(DesyncProxy::select_chain(chains, patterns, DPI::ZProto::TCP, 443,
                                        "www.youtube.com"),
              &chains[0]);
    // host not in list → no chain
    EXPECT_EQ(DesyncProxy::select_chain(chains, patterns, DPI::ZProto::TCP, 443,
                                        "google.com"),
              nullptr);
    // proto mismatch
    EXPECT_EQ(DesyncProxy::select_chain(chains, patterns, DPI::ZProto::UDP, 443,
                                        "www.youtube.com"),
              &chains[1]);
}

// ═══════════════════════════════════════════════════════════════════════════
// DPI detector
// ═══════════════════════════════════════════════════════════════════════════

TEST(DpiDetector, RstInjectionEvent) {
    DpiDetector d;
    d.on_reset_after_hello("youtube.com");
    auto ev = d.recent_events(10);
    ASSERT_EQ(ev.size(), 1u);
    EXPECT_EQ(ev[0].kind, DpiDetector::EventKind::RST_INJECTION);
    EXPECT_EQ(ev[0].host, "youtube.com");
    auto blocked = d.blocked_hosts();
    ASSERT_EQ(blocked.size(), 1u);
}

TEST(DpiDetector, TimeoutThreshold) {
    DpiDetector d(16, 2);
    d.on_timeout("rutracker.org");
    EXPECT_EQ(d.total_events(), 0u);       // below threshold
    d.on_timeout("rutracker.org");
    EXPECT_EQ(d.total_events(), 1u);       // threshold reached
    d.on_timeout("rutracker.org");
    EXPECT_EQ(d.total_events(), 1u);       // already blocked, no spam
}

TEST(DpiDetector, SuccessClearsBlock) {
    DpiDetector d(16, 1);
    d.on_timeout("example.com");
    ASSERT_EQ(d.blocked_hosts().size(), 1u);
    d.on_success("example.com");
    EXPECT_TRUE(d.blocked_hosts().empty());
    auto ev = d.recent_events(10);
    EXPECT_EQ(ev.back().kind, DpiDetector::EventKind::BLOCK_CLEARED);
}

TEST(DpiDetector, JsonFormat) {
    DpiDetector::Event e{DpiDetector::EventKind::RST_INJECTION, "x.com", "d", 123};
    std::string j = DpiDetector::event_to_json(e);
    EXPECT_NE(j.find("\"kind\":\"rst_injection\""), std::string::npos);
    EXPECT_NE(j.find("\"host\":\"x.com\""), std::string::npos);
    EXPECT_NE(j.find("\"ts\":123"), std::string::npos);
}

// ═══════════════════════════════════════════════════════════════════════════
// Blockcheck primitives
// ═══════════════════════════════════════════════════════════════════════════

TEST(Blockcheck, ClientHelloWellFormed) {
    auto ch = BlockChecker::build_client_hello("youtube.com");
    // record header
    EXPECT_EQ(ch[0], 0x16);
    EXPECT_EQ(ch[1], 0x03);
    const size_t rec_len = 5 + ((ch[3] << 8) | ch[4]);
    EXPECT_EQ(rec_len, ch.size());
    // contains SNI
    auto info = parse_tls_client_hello(ch.data(), ch.size());
    EXPECT_EQ(info.sni, "youtube.com");
}

TEST(Blockcheck, DefaultStrategiesSanity) {
    auto strats = BlockChecker::default_strategies();
    EXPECT_GE(strats.size(), 10u);
    bool has_direct = false;
    for (const auto& s : strats) {
        if (s.is_direct) has_direct = true;
        EXPECT_FALSE(s.name.empty());
    }
    EXPECT_TRUE(has_direct);
}

TEST(Blockcheck, ReportJson) {
    BlockcheckReport r;
    BlockcheckStrategyResult sr;
    sr.strategy = "split-2";
    sr.success_count = 3;
    sr.total = 5;
    sr.avg_latency_ms = 42.5;
    sr.score = 299957;
    r.results.push_back(sr);
    r.best_strategy = "split-2";
    std::string j = BlockChecker::report_to_json(r);
    EXPECT_NE(j.find("\"best_strategy\": \"split-2\""), std::string::npos);
    EXPECT_NE(j.find("\"success\": 3"), std::string::npos);
}
