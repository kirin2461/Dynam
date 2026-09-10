/**
 * @file test_awg31_hardening.cpp
 * @brief Tests for the AWG 3.1-inspired hardening: header protection
 *        (HKDF prefixes), version ranges, content padding, timer ranges,
 *        CPS chains — and their porthop/fog/aemm integration.
 */

#include <gtest/gtest.h>

#include "ncp_header_protection.hpp"
#include "ncp_timer_range.hpp"
#include "ncp_porthop.hpp"
#include "ncp_fog.hpp"
#include "ncp_aemm.hpp"
#include "ncp_cps.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace ncp;

namespace {

HeaderProtection make_hp(const std::string& secret,
                         const std::string& ctx = "ncp-test") {
    return HeaderProtection(std::vector<uint8_t>(secret.begin(), secret.end()),
                            ctx);
}

} // namespace

// ==================== HKDF-SHA256 (RFC 5869 Test Case 1) ====================

TEST(HkdfSha256, Rfc5869TestCase1) {
    const uint8_t ikm[22] = {0x0b};
    std::vector<uint8_t> ikm_v(22, 0x0b);
    const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
                            0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t okm[42];
    ASSERT_TRUE(hkdf_sha256(ikm_v.data(), ikm_v.size(),
                            salt, sizeof(salt), info, sizeof(info),
                            okm, sizeof(okm)));
    static const uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65};
    EXPECT_EQ(0, std::memcmp(okm, expected, sizeof(okm)));
    (void)ikm;
}

TEST(HkdfSha256, BadArgs) {
    uint8_t out[32];
    EXPECT_FALSE(hkdf_sha256(nullptr, 0, nullptr, 0, nullptr, 0, out, 32));
    EXPECT_FALSE(hkdf_sha256(reinterpret_cast<const uint8_t*>("k"), 1,
                             nullptr, 0, nullptr, 0, out, 0));
}

// ==================== HeaderProtection ====================

TEST(HeaderProtection, DisabledByDefault) {
    HeaderProtection hp;
    EXPECT_FALSE(hp.enabled());
    uint8_t out[4] = {1, 2, 3, 4};
    hp.prefix(7, out, 4);  // no-op
    EXPECT_EQ(out[0], 1);
    EXPECT_FALSE(hp.matches(7, out, 4));
}

TEST(HeaderProtection, DeterministicPrefix) {
    auto hp = make_hp("secret");
    uint8_t a[4], b[4];
    hp.prefix(42, a, 4);
    hp.prefix(42, b, 4);
    EXPECT_EQ(0, std::memcmp(a, b, 4));
    EXPECT_TRUE(hp.matches(42, a, 4));
}

TEST(HeaderProtection, PrefixDependsOnTagSecretContext) {
    auto hp = make_hp("secret");
    uint8_t base[4], other_tag[4];
    hp.prefix(1, base, 4);
    hp.prefix(2, other_tag, 4);
    EXPECT_NE(0, std::memcmp(base, other_tag, 4));

    auto hp2 = make_hp("other-secret");
    uint8_t other_secret[4];
    hp2.prefix(1, other_secret, 4);
    EXPECT_NE(0, std::memcmp(base, other_secret, 4));

    auto hp3 = make_hp("secret", "ncp-other-ctx");
    uint8_t other_ctx[4];
    hp3.prefix(1, other_ctx, 4);
    EXPECT_NE(0, std::memcmp(base, other_ctx, 4));

    // Wrong tag must not verify.
    EXPECT_FALSE(hp.matches(2, base, 4));
}

TEST(HeaderProtection, VersionRange) {
    auto hp = make_hp("s");
    EXPECT_EQ(hp.random_version(), 1);  // legacy default [1,1]
    EXPECT_TRUE(hp.version_accepted(1));
    EXPECT_FALSE(hp.version_accepted(2));

    hp.set_version_range(100, 104);
    for (int i = 0; i < 200; ++i) {
        const uint8_t v = hp.random_version();
        ASSERT_GE(v, 100);
        ASSERT_LE(v, 104);
    }
    EXPECT_TRUE(hp.version_accepted(103));
    EXPECT_FALSE(hp.version_accepted(99));
    EXPECT_FALSE(hp.version_accepted(105));

    // parse
    auto r1 = HeaderProtection::parse_version_range("7");
    ASSERT_TRUE(r1);
    EXPECT_EQ(r1->first, 7);
    EXPECT_EQ(r1->second, 7);
    auto r2 = HeaderProtection::parse_version_range("10-20");
    ASSERT_TRUE(r2);
    EXPECT_EQ(r2->first, 10);
    EXPECT_EQ(r2->second, 20);
    EXPECT_FALSE(HeaderProtection::parse_version_range("20-10"));
    EXPECT_FALSE(HeaderProtection::parse_version_range("0-5"));
    EXPECT_FALSE(HeaderProtection::parse_version_range("abc"));
}

// ==================== Content padding ====================

TEST(ContentPadding, ParseAndSample) {
    auto c = ContentPaddingConfig::parse("2-10");
    ASSERT_TRUE(c);
    EXPECT_TRUE(c->enabled());
    for (int i = 0; i < 200; ++i) {
        const uint16_t v = c->sample();
        ASSERT_GE(v, 2);
        ASSERT_LE(v, 10);
    }
    EXPECT_FALSE(ContentPaddingConfig::parse("0")->enabled());
    EXPECT_FALSE(ContentPaddingConfig::parse("10-2"));
}

TEST(ContentPadding, Roundtrip) {
    ContentPaddingConfig cfg;
    cfg.min_pad = 5;
    cfg.max_pad = 100;
    std::vector<uint8_t> buf = {'d', 'a', 't', 'a'};
    const size_t original = buf.size();
    const uint16_t pad = content_pad_append(buf, cfg, 65535);
    EXPECT_GE(pad, 5);
    EXPECT_EQ(buf.size(), original + pad + 1);

    const auto stripped = content_pad_strip(buf.data(), buf.size());
    ASSERT_TRUE(stripped);
    EXPECT_EQ(*stripped, original);
    EXPECT_EQ(0, std::memcmp(buf.data(), "data", 4));
}

TEST(ContentPadding, StripRejectsGarbage) {
    EXPECT_FALSE(content_pad_strip(nullptr, 0));
    const uint8_t buf[2] = {0xAA, 0x7F};  // padlen 127 > buf size
    EXPECT_FALSE(content_pad_strip(buf, sizeof(buf)));
}

// ==================== TimerRange ====================

TEST(TimerRange, ParseFixedAndRange) {
    auto f = TimerRange::parse("250");
    ASSERT_TRUE(f);
    EXPECT_DOUBLE_EQ(f->min_ms, 250.0);
    EXPECT_DOUBLE_EQ(f->max_ms, 250.0);
    EXPECT_EQ(f->sample(), 250.0);

    auto r = TimerRange::parse("100-500");
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->is_range());
    for (int i = 0; i < 200; ++i) {
        const double v = r->sample();
        ASSERT_GE(v, 100.0);
        ASSERT_LE(v, 500.0);
    }
    EXPECT_FALSE(TimerRange::parse("500-100"));
    EXPECT_FALSE(TimerRange::parse(""));
}

// ==================== PortHop integration ====================

static HopSchedule make_schedule() {
    return HopSchedule(std::vector<uint8_t>{'s', 'e', 'c', 'r', 'e', 't'},
                       40000, 8, 60);
}

TEST(PortHopHP, ProtectedRoundtrip) {
    PortHopSession tx(0x1122, make_schedule());
    PortHopSession rx(0x1122, make_schedule());
    auto hp = make_hp("hp-secret", "ncp-ph");
    tx.set_header_protection(hp);
    rx.set_header_protection(hp);

    const std::string msg = "hello protected world";
    auto wire = tx.encode(reinterpret_cast<const uint8_t*>(msg.data()),
                          msg.size());
    // No static magic on the wire.
    EXPECT_FALSE(wire[0] == 'P' && wire[1] == 'H');

    auto frame = rx.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame);
    EXPECT_EQ(frame->session_id, 0x1122u);
    EXPECT_EQ(std::string(frame->payload.begin(), frame->payload.end()), msg);
}

TEST(PortHopHP, WrongSecretRejected) {
    PortHopSession tx(0x1122, make_schedule());
    PortHopSession rx(0x1122, make_schedule());
    tx.set_header_protection(make_hp("hp-secret", "ncp-ph"));
    rx.set_header_protection(make_hp("wrong-secret", "ncp-ph"));

    const std::string msg = "x";
    auto wire = tx.encode(reinterpret_cast<const uint8_t*>(msg.data()), 1);
    EXPECT_FALSE(rx.decode(wire.data(), wire.size()));
}

TEST(PortHopHP, TamperedEpochRejected) {
    PortHopSession tx(0x1122, make_schedule());
    PortHopSession rx(0x1122, make_schedule());
    auto hp = make_hp("hp-secret", "ncp-ph");
    tx.set_header_protection(hp);
    rx.set_header_protection(hp);

    auto wire = tx.encode(nullptr, 0);
    // Flip a bit in the epoch field (bytes 11..14).
    wire[11] ^= 0x01;
    EXPECT_FALSE(rx.decode(wire.data(), wire.size()));
}

TEST(PortHopHP, LegacyModeUnaffected) {
    PortHopSession tx(0x99, make_schedule());
    PortHopSession rx(0x99, make_schedule());
    const std::string msg = "legacy";
    auto wire = tx.encode(reinterpret_cast<const uint8_t*>(msg.data()),
                          msg.size());
    EXPECT_EQ(wire[0], 'P');
    EXPECT_EQ(wire[1], 'H');
    auto frame = rx.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame);
    EXPECT_EQ(std::string(frame->payload.begin(), frame->payload.end()), msg);
}

TEST(PortHopHP, VersionRangeWire) {
    PortHopSession tx(0x77, make_schedule());
    PortHopSession rx(0x77, make_schedule());
    auto hp = make_hp("s3", "ncp-ph");
    hp.set_version_range(50, 60);
    tx.set_header_protection(hp);
    rx.set_header_protection(hp);

    for (int i = 0; i < 10; ++i) {
        auto wire = tx.encode(nullptr, 0);
        ASSERT_GE(wire[2], 50);
        ASSERT_LE(wire[2], 60);
        EXPECT_TRUE(rx.decode(wire.data(), wire.size()));
    }
    // A receiver with a different range must reject.
    PortHopSession rx2(0x77, make_schedule());
    auto hp2 = make_hp("s3", "ncp-ph");  // default range [1,1]
    rx2.set_header_protection(hp2);
    auto wire = tx.encode(nullptr, 0);
    EXPECT_FALSE(rx2.decode(wire.data(), wire.size()));
}

TEST(PortHopHP, ContentPaddingRoundtrip) {
    PortHopSession tx(0x55, make_schedule());
    PortHopSession rx(0x55, make_schedule());
    ContentPaddingConfig cfg;
    cfg.min_pad = 10;
    cfg.max_pad = 50;
    tx.set_content_padding(cfg);
    rx.set_content_padding(cfg);
    auto hp = make_hp("s4", "ncp-ph");
    tx.set_header_protection(hp);
    rx.set_header_protection(hp);

    const std::string msg = "padded payload";
    auto wire = tx.encode(reinterpret_cast<const uint8_t*>(msg.data()),
                          msg.size());
    EXPECT_TRUE(wire[19] & PH_FLAG_CONTENT_PADDING);
    EXPECT_GT(wire.size(), PortHopSession::HEADER_SIZE + msg.size());

    auto frame = rx.decode(wire.data(), wire.size());
    ASSERT_TRUE(frame);
    EXPECT_EQ(std::string(frame->payload.begin(), frame->payload.end()), msg);
}

TEST(PortHopHP, ParseFieldsNoMagicCheck) {
    PortHopSession tx(0x42, make_schedule());
    tx.set_header_protection(make_hp("s5", "ncp-ph"));
    auto wire = tx.encode(nullptr, 0);
    // Static decode_raw must reject (no legacy magic)…
    EXPECT_FALSE(PortHopSession::decode_raw(wire.data(), wire.size()));
    // …while parse_fields succeeds.
    auto f = PortHopSession::parse_fields(wire.data(), wire.size());
    ASSERT_TRUE(f);
    EXPECT_EQ(f->session_id, 0x42u);
}

TEST(PortHopHP, IntervalRangeSampled) {
    HopSchedule sched = make_schedule();
    sched.set_interval_range(30, 120);
    for (int i = 0; i < 100; ++i) {
        const uint32_t v = sched.sample_interval_sec();
        ASSERT_GE(v, 30u);
        ASSERT_LE(v, 120u);
    }
    HopSchedule fixed = make_schedule();
    EXPECT_EQ(fixed.sample_interval_sec(), 60u);
}

// ==================== Fog integration ====================

static FogFrame make_fog_frame(uint64_t seq) {
    FogFrame f;
    f.ttl = 5;
    f.type = FogMsgType::DATA;
    f.seq = seq;
    f.payload = {'f', 'o', 'g'};
    return f;
}

TEST(FogHP, ProtectedRoundtrip) {
    auto hp = make_hp("mesh-secret", "ncp-fog");
    auto wire = make_fog_frame(123).pack(hp);
    // No static magic on the wire.
    EXPECT_FALSE(wire[0] == 'F' && wire[1] == 'O' && wire[2] == 'G');

    auto f = FogFrame::parse(wire.data(), wire.size(), hp);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->seq, 123u);
    EXPECT_EQ(f->ttl, 5);
    EXPECT_EQ(f->type, FogMsgType::DATA);
    EXPECT_EQ(f->payload, std::vector<uint8_t>({'f', 'o', 'g'}));
}

TEST(FogHP, WrongSecretAndTamperRejected) {
    auto hp = make_hp("mesh-secret", "ncp-fog");
    auto bad = make_hp("other", "ncp-fog");
    auto wire = make_fog_frame(7).pack(hp);
    EXPECT_FALSE(FogFrame::parse(wire.data(), wire.size(), bad));

    wire[40] ^= 0x80;  // flip a bit inside seq field
    EXPECT_FALSE(FogFrame::parse(wire.data(), wire.size(), hp));
}

TEST(FogHP, LegacyUnaffected) {
    auto wire = make_fog_frame(9).pack();
    EXPECT_EQ(wire[0], 'F');
    auto f = FogFrame::parse(wire.data(), wire.size());
    ASSERT_TRUE(f);
    EXPECT_EQ(f->seq, 9u);
}

TEST(FogHP, VersionRangeWire) {
    auto hp = make_hp("mesh", "ncp-fog");
    hp.set_version_range(200, 210);
    for (int i = 0; i < 10; ++i) {
        auto wire = make_fog_frame(i).pack(hp);
        ASSERT_GE(wire[3], 200);
        ASSERT_LE(wire[3], 210);
        EXPECT_TRUE(FogFrame::parse(wire.data(), wire.size(), hp));
    }
}

// ==================== AEMM integration ====================

TEST(AemmHP, ProtectedShardRoundtrip) {
    auto hp = make_hp("aemm-secret", "ncp-aemm");
    const std::string data = "shard payload";
    auto shard = aemm::pack_shard_hp(
        3, 5, 0, 42,
        reinterpret_cast<const uint8_t*>(data.data()), data.size(),
        static_cast<uint32_t>(data.size()), hp);
    EXPECT_FALSE(shard[0] == 'R' && shard[1] == 'S');

    auto s = aemm::unpack_shard_hp(shard.data(), shard.size(), hp);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->block_id, 42u);
    EXPECT_EQ(s->k, 3);
    EXPECT_EQ(s->n, 5);
    EXPECT_EQ(std::string(s->payload.begin(), s->payload.end()), data);
}

TEST(AemmHP, WrongSecretRejected) {
    auto hp = make_hp("aemm-secret", "ncp-aemm");
    auto bad = make_hp("nope", "ncp-aemm");
    const std::string data = "x";
    auto shard = aemm::pack_shard_hp(
        2, 3, 1, 7,
        reinterpret_cast<const uint8_t*>(data.data()), data.size(), 1, hp);
    EXPECT_FALSE(aemm::unpack_shard_hp(shard.data(), shard.size(), bad));
    // Legacy unpack must also reject (no "RS" magic).
    EXPECT_FALSE(aemm::unpack_shard(shard.data(), shard.size()));
}

// ==================== CPS ====================

TEST(Cps, ParseChain) {
    auto chain = cps::CpsChain::parse("dns:yandex.ru;wait:20-80;quic;tls:mail.ru;hex:deadbeef");
    ASSERT_TRUE(chain);
    ASSERT_EQ(chain->steps.size(), 5u);
    EXPECT_EQ(chain->steps[0].kind, cps::StepKind::DNS_QUERY);
    EXPECT_EQ(chain->steps[1].kind, cps::StepKind::WAIT);
    EXPECT_EQ(chain->steps[1].wait_min_ms, 20u);
    EXPECT_EQ(chain->steps[1].wait_max_ms, 80u);
    EXPECT_EQ(chain->steps[2].kind, cps::StepKind::QUIC_INITIAL);
    EXPECT_EQ(chain->steps[3].kind, cps::StepKind::TLS_CLIENT_HELLO);
    EXPECT_EQ(chain->steps[4].kind, cps::StepKind::RAW_BYTES);

    EXPECT_FALSE(cps::CpsChain::parse("bogus:x"));
    EXPECT_FALSE(cps::CpsChain::parse("dns:"));
    EXPECT_FALSE(cps::CpsChain::parse(""));
    // roundtrip
    EXPECT_EQ(chain->to_string(),
              "dns:yandex.ru;wait:20-80;quic;tls:mail.ru;hex:deadbeef");
}

TEST(Cps, BuildDnsQuery) {
    auto pkt = cps::build_dns_query("example.com");
    ASSERT_GT(pkt.size(), 12u);
    EXPECT_EQ(pkt[4], 0);  // QDCOUNT hi
    EXPECT_EQ(pkt[5], 1);  // QDCOUNT lo
    // QNAME starts with label length 7 ("example")
    EXPECT_EQ(pkt[12], 7);
    EXPECT_EQ(0, std::memcmp(&pkt[13], "example", 7));
}

TEST(Cps, BuildQuicInitial) {
    auto pkt = cps::build_quic_initial("");
    ASSERT_GE(pkt.size(), 1200u);
    EXPECT_EQ(pkt[0] & 0xC0, 0xC0);          // long header
    EXPECT_EQ(pkt[1], 0);                    // version 0x00000001 (bytes 1..4)
    EXPECT_EQ(pkt[2], 0);
    EXPECT_EQ(pkt[3], 0);
    EXPECT_EQ(pkt[4], 1);
}

TEST(Cps, BuildTlsClientHello) {
    auto pkt = cps::build_tls_client_hello("mail.ru");
    ASSERT_GT(pkt.size(), 60u);
    EXPECT_EQ(pkt[0], 0x16);  // handshake record
    EXPECT_EQ(pkt[1], 0x03);
    EXPECT_EQ(pkt[5], 0x01);  // ClientHello
}

TEST(Cps, HexDecode) {
    auto v = cps::hex_decode("deadBEEF");
    ASSERT_EQ(v.size(), 4u);
    EXPECT_EQ(v[0], 0xDE);
    EXPECT_EQ(v[3], 0xEF);
    EXPECT_TRUE(cps::hex_decode("zz").empty());
    EXPECT_TRUE(cps::hex_decode("abc").empty());  // odd length
}
