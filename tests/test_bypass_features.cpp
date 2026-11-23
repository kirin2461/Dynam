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
#include "ncp_adversary_tester.hpp"
#include "ncp_blockcheck.hpp"

#include <fstream>
#include <memory>
#include <thread>
#include <chrono>

#include "ncp_test_temp.hpp"
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
    const std::string path = ncp_test::temp_path("ncp_test_hostlist.txt");
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

    const std::string out = ncp_test::temp_path("ncp_test_hostlist_out.txt");
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
    const std::string path = ncp_test::temp_path("ncp_test_autohl.txt");
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

// ═══════════════════════════════════════════════════════════════════════════
// ClientHello wire format — regression for the extension-length bug
// ═══════════════════════════════════════════════════════════════════════════
//
// build_client_hello() previously declared extension lengths that did not
// match the bytes it wrote (supported_groups and signature_algorithms omitted
// their 2-byte list-length prefix from the declared size; key_share was off by
// two at both levels). Real TLS servers reject such a hello with a fatal
// decode_error alert, which silently broke every blockcheck probe.
//
// Existing tests parsed the hello back with the matching parser, so both sides
// shared the same wrong numbers and agreed. These checks instead verify the
// wire format structurally: declared lengths must tile the extension block
// exactly, and the inner list lengths must match their extents. A malformed
// length breaks the tiling, so this fails without needing a live server.

TEST(ClientHello, ExtensionLengthsTileExactly) {
    auto ch = BlockChecker::build_client_hello("example.com");
    ASSERT_GT(ch.size(), 50u);

    // Record header: type, version(2), length(2); then handshake header.
    ASSERT_EQ(ch[0], 0x16) << "not a handshake record";
    ASSERT_EQ(ch[5], 0x01) << "not a ClientHello";
    const size_t hs_len = (static_cast<size_t>(ch[6]) << 16) |
                          (static_cast<size_t>(ch[7]) << 8) |
                          static_cast<size_t>(ch[8]);
    ASSERT_EQ(hs_len + 9, ch.size()) << "handshake length disagrees with buffer";

    size_t p = 9;
    p += 2;                       // client_version
    p += 32;                      // random
    const size_t sid_len = ch[p]; p += 1 + sid_len;
    ASSERT_LT(p + 2, ch.size());
    const size_t cs_len = (static_cast<size_t>(ch[p]) << 8) | ch[p + 1];
    p += 2 + cs_len;
    ASSERT_LT(p, ch.size());
    const size_t comp_len = ch[p]; p += 1 + comp_len;
    ASSERT_LT(p + 2, ch.size());
    const size_t ext_total = (static_cast<size_t>(ch[p]) << 8) | ch[p + 1];
    p += 2;

    ASSERT_EQ(p + ext_total, ch.size())
        << "extensions block length does not match the record";

    size_t seen = 0;
    while (seen < ext_total) {
        ASSERT_LE(p + 4, ch.size()) << "truncated extension header";
        const unsigned type = (static_cast<unsigned>(ch[p]) << 8) | ch[p + 1];
        const size_t elen = (static_cast<size_t>(ch[p + 2]) << 8) | ch[p + 3];
        p += 4;
        ASSERT_LE(p + elen, ch.size())
            << "extension " << type << " overruns the record";

        // supported_groups / signature_algorithms: data begins with a 2-byte
        // list length that must account for the whole body.
        if (type == 0x000A || type == 0x000D) {
            ASSERT_GE(elen, 2u);
            const size_t list = (static_cast<size_t>(ch[p]) << 8) | ch[p + 1];
            ASSERT_EQ(list + 2, elen)
                << "extension " << type << " list length mismatch";
        }
        // key_share: data begins with a 2-byte client_shares length.
        if (type == 0x0033) {
            ASSERT_GE(elen, 2u);
            const size_t shares = (static_cast<size_t>(ch[p]) << 8) | ch[p + 1];
            ASSERT_EQ(shares + 2, elen) << "key_share client_shares mismatch";
        }

        p += elen;
        seen += 4 + elen;
    }
    EXPECT_EQ(seen, ext_total) << "extension lengths do not tile the block";
}

TEST(ClientHello, ServerNameExtensionIsWellFormed) {
    const std::string host = "www.example.com";
    auto ch = BlockChecker::build_client_hello(host);

    // The SNI list entry must appear intact, which only holds if the record and
    // handshake length fields are consistent.
    std::string raw(reinterpret_cast<const char*>(ch.data()), ch.size());
    EXPECT_NE(raw.find(host), std::string::npos)
        << "SNI hostname not present in the built hello";

    // Parse it back and require the parser to recover exactly what was written.
    auto info = parse_tls_client_hello(ch.data(), ch.size());
    EXPECT_TRUE(info.valid);
    EXPECT_EQ(info.sni, host);
    EXPECT_EQ(info.sni_value_len, host.size());
}

// ==============================================================================
// SizeErrorLearner + AdversaryTester learning (Task 1)
// ==============================================================================

TEST(SizeErrorLearner, PriorBeforeMinSamples) {
    ncp::DPI::SizeErrorLearner learner;
    ncp::DPI::SizeErrorFeatures f;
    f.error_rate = 0.0;
    f.ks_distance = 0.0;
    double clean = learner.predict(f);
    EXPECT_GE(clean, 0.0);
    EXPECT_LE(clean, 1.0);
    EXPECT_DOUBLE_EQ(clean, 0.15);  // pristine window: the prior's floor

    f.error_rate = 1.0;
    f.ks_distance = 1.0;
    double bad = learner.predict(f);
    EXPECT_GT(bad, clean) << "errors + KS deviation must raise detection risk";
    EXPECT_DOUBLE_EQ(bad, 0.98);  // most suspicious window saturates the clamp
}

TEST(SizeErrorLearner, FromSnapshotComputesStats) {
    ncp::DPI::FlowSnapshot snap;
    snap.packet_sizes = {100, 100, 200, 1400};
    auto f = ncp::DPI::SizeErrorLearner::from_snapshot(snap, 0.25);
    EXPECT_DOUBLE_EQ(f.size_mean, 450.0);
    EXPECT_GT(f.size_cv, 0.0);
    EXPECT_DOUBLE_EQ(f.frac_small, 0.5);    // 100,100 <= 128
    EXPECT_DOUBLE_EQ(f.frac_large, 0.25);   // 1400 >= 1200
    EXPECT_DOUBLE_EQ(f.error_rate, 0.25);
}

TEST(SizeErrorLearner, ObserveCountsSamples) {
    ncp::DPI::SizeErrorLearner learner;
    ncp::DPI::SizeErrorFeatures f;
    learner.observe(f, true);
    learner.observe(f, false);
    EXPECT_EQ(learner.samples(), 2u);
    auto w = learner.weights();
    EXPECT_EQ(w.size(), 9u);
}

TEST(SizeErrorLearner, LearnsSeparablePattern) {
    ncp::DPI::SizeErrorLearner::Params p;
    p.min_samples = 0;      // go straight to the learned model
    p.learning_rate = 0.3;
    ncp::DPI::SizeErrorLearner learner(p);

    ncp::DPI::SizeErrorFeatures good;
    good.error_rate = 0.0;
    good.ks_distance = 0.0;
    ncp::DPI::SizeErrorFeatures bad;
    bad.error_rate = 1.0;
    bad.ks_distance = 1.0;

    for (int i = 0; i < 400; ++i) {
        learner.observe(good, false);
        learner.observe(bad, true);
    }
    EXPECT_GT(learner.predict(bad), learner.predict(good));
    EXPECT_GT(learner.predict(bad), 0.6);
    EXPECT_LT(learner.predict(good), 0.4);
}

TEST(SizeErrorLearner, ResetClearsModel) {
    ncp::DPI::SizeErrorLearner learner;
    ncp::DPI::SizeErrorFeatures f;
    learner.observe(f, true);
    learner.reset();
    EXPECT_EQ(learner.samples(), 0u);
    auto w = learner.weights();
    for (double v : w) EXPECT_DOUBLE_EQ(v, 0.0);
}

TEST(AdversaryTesterLearning, NoProbabilityWithoutLearner) {
    ncp::DPI::AdversaryTesterConfig cfg;
    cfg.window_packets = 8;   // above the packets we record, so no auto-evaluation
    ncp::DPI::AdversaryTester tester(cfg);
    EXPECT_DOUBLE_EQ(tester.last_detection_probability(), -1.0);

    for (int i = 0; i < 3; ++i) tester.record_packet(std::vector<uint8_t>(300, 7));
    auto report = tester.evaluate_flow();
    EXPECT_DOUBLE_EQ(report.learned_detection_probability, -1.0);
    EXPECT_DOUBLE_EQ(tester.last_detection_probability(), -1.0);
}

TEST(AdversaryTesterLearning, AttachedLearnerProducesEstimate) {
    ncp::DPI::AdversaryTesterConfig cfg;
    cfg.window_packets = 8;
    ncp::DPI::AdversaryTester tester(cfg);
    auto learner = std::make_shared<ncp::DPI::SizeErrorLearner>();
    tester.set_size_learner(learner);
    ASSERT_NE(tester.get_size_learner(), nullptr);

    for (int i = 0; i < 3; ++i) tester.record_packet(std::vector<uint8_t>(300, 7));
    tester.record_error();
    auto report = tester.evaluate_flow();

    ASSERT_EQ(report.snapshot.packet_count, 3u);
    EXPECT_GE(report.learned_detection_probability, 0.0);
    EXPECT_LE(report.learned_detection_probability, 1.0);
    EXPECT_EQ(learner->samples(), 1u);
    EXPECT_DOUBLE_EQ(tester.last_detection_probability(),
                     report.learned_detection_probability);
}

// ==============================================================================
// DpiDetector per-host reports (Task 3)
// ==============================================================================

TEST(DpiDetectorReports, HostReportsSortedAndCounted) {
    DpiDetector d(16, 1);
    d.on_reset_after_hello("zeta.example");
    d.on_timeout("alpha.example");
    d.on_timeout("alpha.example");

    auto reports = d.host_reports();
    ASSERT_EQ(reports.size(), 2u);
    EXPECT_EQ(reports[0].host, "alpha.example");   // sorted
    EXPECT_EQ(reports[1].host, "zeta.example");
    EXPECT_EQ(reports[0].events, 1u);              // only the blocking timeout emits an event
    EXPECT_EQ(reports[0].consecutive_timeouts, 2);
    EXPECT_TRUE(reports[0].blocked);               // timeout threshold 1
    EXPECT_TRUE(reports[1].blocked);               // rst marks blocked
}

TEST(DpiDetectorReports, ResetAllClearsState) {
    DpiDetector d(16, 1);
    d.on_reset_after_hello("x.example");
    ASSERT_EQ(d.total_events(), 1u);

    d.reset_all();
    EXPECT_EQ(d.total_events(), 0u);
    EXPECT_TRUE(d.host_reports().empty());
    EXPECT_TRUE(d.blocked_hosts().empty());
    EXPECT_TRUE(d.recent_events(10).empty());
}

TEST(DpiDetectorReports, BlockTtlExpires) {
    DpiDetector d(16, 1);
    d.set_block_ttl(std::chrono::milliseconds(1));
    d.on_reset_after_hello("t.example");
    EXPECT_FALSE(d.blocked_hosts().empty());

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    EXPECT_TRUE(d.blocked_hosts().empty()) << "block should expire after its TTL";
    auto reports = d.host_reports();
    ASSERT_EQ(reports.size(), 1u);
    EXPECT_FALSE(reports[0].blocked);
}

// ==============================================================================
// Wasserstein-1 size-shape metric (W1 upgrade)
// ==============================================================================

TEST(AdversaryTesterW1, UniformMaxSizeFlowScoresFarFromReference) {
    ncp::DPI::AdversaryTesterConfig cfg;
    cfg.window_packets = 64;               // above what we record: no auto-eval
    ncp::DPI::AdversaryTester tester(cfg);

    // Constant 1460-byte packets are the pathological "pad everything to MTU"
    // flow: a DPI's size model sees a point mass, not a browser.
    for (int i = 0; i < 20; ++i)
        tester.record_packet(std::vector<uint8_t>(1460, 0x41));

    auto report = tester.evaluate_flow();
    ASSERT_EQ(report.snapshot.packet_count, 20u);
    // Reference web_browsing mass sits at 64..1460; W1 of a point mass at 1460
    // is E|1460 - X| > 1000 bytes.
    EXPECT_GT(report.scores.w1_distance, 800.0);
}

TEST(AdversaryTesterW1, ReferenceShapedFlowScoresLow) {
    ncp::DPI::AdversaryTesterConfig cfg;
    cfg.window_packets = 64;
    ncp::DPI::AdversaryTester tester(cfg);

    // Proportions of the web_browsing size model: 52(.30) 150(.15) 350(.10)
    // 580(.08) 1200(.12) 1460(.25). Emit that mix directly.
    //
    // The residual is not zero: ReferenceProfile stores only a CDF at bucket
    // boundaries, so the reconstructed reference places each bucket's mass at
    // its upper boundary. A browser mode at 52 bytes is therefore priced as 64.
    // That discretisation bias is bounded by one bucket width and is why the
    // threshold below is ~3x looser than the uniform-MTU case.
    static const size_t sizes[]  = {52, 150, 350, 580, 1200, 1460};
    static const int    counts[] = { 6,   3,   2,   2,    2,    5};
    for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); ++k)
        for (int i = 0; i < counts[k]; ++i)
            tester.record_packet(std::vector<uint8_t>(sizes[k], 0x41));

    auto report = tester.evaluate_flow();
    // ~264 bytes by hand: mass displacement, not detection failure.
    EXPECT_LT(report.scores.w1_distance, 300.0);
}

// A bound alone cannot distinguish "correctly low" from "not computed at all":
// with W1 stubbed to 0 the previous test passes vacuously. This one compares
// the two flows in the same units, so a zero-vs-zero implementation fails.
TEST(AdversaryTesterW1, UniformPaddingScoresWorseThanReferenceMix) {
    auto w1_for = [](bool uniform_max) {
        ncp::DPI::AdversaryTesterConfig cfg;
        cfg.window_packets = 64;
        ncp::DPI::AdversaryTester tester(cfg);
        if (uniform_max) {
            for (int i = 0; i < 20; ++i)
                tester.record_packet(std::vector<uint8_t>(1460, 0x41));
        } else {
            static const size_t sizes[]  = {52, 150, 350, 580, 1200, 1460};
            static const int    counts[] = { 6,   3,   2,   2,    2,    5};
            for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); ++k)
                for (int i = 0; i < counts[k]; ++i)
                    tester.record_packet(std::vector<uint8_t>(sizes[k], 0x41));
        }
        return tester.evaluate_flow().scores.w1_distance;
    };

    const double uniform = w1_for(true);
    const double mixed   = w1_for(false);
    EXPECT_GT(uniform, 2.0 * mixed);
}
TEST(HeuristicScoresW1, DisplacedSizesLowerStealth) {
    ncp::DPI::HeuristicScores base{};
    base.entropy_score = 0.95;
    base.chi_squared_pvalue = 0.8;
    base.ks_distance = 0.0;
    base.w1_distance = 0.0;
    base.size_variance_ratio = 1.0;
    base.timing_cov = 0.0;
    base.burst_anomaly = 0.0;

    ncp::DPI::HeuristicScores shifted = base;
    shifted.w1_distance = 600.0;      // every size displaced by 600 bytes

    EXPECT_GT(base.aggregate_stealth(), shifted.aggregate_stealth());
    // W_W1 = 0.05 with a 75-byte half-mark: 600 bytes leaves ~0.0056 of the term.
    EXPECT_NEAR(base.aggregate_stealth() - shifted.aggregate_stealth(),
                0.05 * (1.0 - 1.0 / (1.0 + 600.0 / 75.0)), 1e-9);
    EXPECT_NEAR(shifted.aggregate_stealth(),
                0.25 * 0.95 + 0.25 * 0.8 + 0.10 * 1.0 + 0.05 * (1.0 / 9.0) +
                0.10 * 1.0 + 0.15 * 1.0 + 0.10 * 1.0, 1e-9);
}
