// Tests for ncp_stegodns — Zero-Knowledge Stego-DNS records (M4)
#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <regex>
#include <string>

#include <sodium.h>

#include "ncp_stegodns.hpp"

namespace {

constexpr const char* kPassphrase = "correct horse battery staple";
constexpr const char* kDomain = "cdn.example.com";
constexpr uint64_t kNow = 1700000000;

struct SignKeys {
    std::array<uint8_t, 32> pk{};
    std::array<uint8_t, 64> sk{};
};

SignKeys make_sign_keys() {
    SignKeys k;
    crypto_sign_keypair(k.pk.data(), k.sk.data());
    return k;
}

ncp::NodeParams make_params(uint32_t expires = 1800000000u) {
    ncp::NodeParams p;
    p.ipv4 = {203, 0, 113, 7};
    p.port = 443;
    for (size_t i = 0; i < p.spa_pubkey.size(); ++i) {
        p.spa_pubkey[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    p.expires_unix = expires;
    return p;
}

class StegoDnsTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { ASSERT_GE(sodium_init(), 0); }

    SignKeys keys = make_sign_keys();
    ncp::StegoDnsEncoder encoder{kPassphrase, keys.sk};
    ncp::StegoDnsDecoder decoder{kPassphrase, keys.pk};
};

TEST_F(StegoDnsTest, Roundtrip) {
    const ncp::NodeParams in = make_params();
    const std::string txt = encoder.encode_txt(in, kDomain);
    const auto out = decoder.decode_txt(txt, kNow);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, in);
}

TEST_F(StegoDnsTest, OutputMatchesSpfShape) {
    const std::string txt = encoder.encode_txt(make_params(), kDomain);
    const std::regex shape(
        R"(^v=spf1 ip4:[a-z2-7]+ include:[a-z2-7]+\._ncp\.[a-z0-9.-]+ ~all$)");
    EXPECT_TRUE(std::regex_match(txt, shape)) << txt;
}

TEST_F(StegoDnsTest, TamperAnyCharFails) {
    const std::string txt = encoder.encode_txt(make_params(), kDomain);
    // Flip one character at several positions inside both base32 slots.
    // (The domain suffix is not authenticated data by design; only the two
    // base32 slots carry the signed/encrypted blob.)
    const size_t infix = txt.find(" include:");
    const std::array<size_t, 6> positions = {
        11u, 11u + 70u, infix - 1u,
        infix + 9u, infix + 9u + 40u, txt.find("._ncp.") - 1u};
    for (size_t pos : positions) {
        std::string bad = txt;
        // Flip the MOST significant base32 bit of the character. The low
        // bits of a slot-final character can be zero padding that the
        // decoder ignores — flipping only those would decode identically
        // (flaky). The MSB always lies inside the authenticated payload.
        static const char kAlpha[] = "abcdefghijklmnopqrstuvwxyz234567";
        const char* hit = std::strchr(kAlpha, bad[pos]);
        ASSERT_NE(hit, nullptr) << "pos " << pos << " not inside a base32 slot";
        bad[pos] = kAlpha[(hit - kAlpha) ^ 0x10];
        EXPECT_FALSE(decoder.decode_txt(bad, kNow).has_value())
            << "tampered at pos " << pos;
    }
    // Structural tampering: break the SPF prefix.
    std::string bad = txt;
    bad[8] = '6';  // "v=spf1 ip6:..."
    EXPECT_FALSE(decoder.decode_txt(bad, kNow).has_value());
}

TEST_F(StegoDnsTest, TruncationAndGarbageFail) {
    const std::string txt = encoder.encode_txt(make_params(), kDomain);
    EXPECT_FALSE(decoder.decode_txt("", kNow).has_value());
    EXPECT_FALSE(decoder.decode_txt("v=spf1 ~all", kNow).has_value());
    EXPECT_FALSE(
        decoder.decode_txt(txt.substr(0, txt.size() - 20), kNow).has_value());
    EXPECT_FALSE(decoder.decode_txt("garbage", kNow).has_value());
}

TEST_F(StegoDnsTest, WrongPassphraseFails) {
    const std::string txt = encoder.encode_txt(make_params(), kDomain);
    ncp::StegoDnsDecoder wrong("hunter2", keys.pk);
    EXPECT_FALSE(wrong.decode_txt(txt, kNow).has_value());
}

TEST_F(StegoDnsTest, WrongVerifyPubkeyFails) {
    const std::string txt = encoder.encode_txt(make_params(), kDomain);
    const SignKeys other = make_sign_keys();
    ncp::StegoDnsDecoder wrong(kPassphrase, other.pk);
    EXPECT_FALSE(wrong.decode_txt(txt, kNow).has_value());
}

TEST_F(StegoDnsTest, ExpiredFails) {
    const std::string txt =
        encoder.encode_txt(make_params(/*expires=*/kNow - 1), kDomain);
    EXPECT_FALSE(decoder.decode_txt(txt, kNow).has_value());
    // But it must decode while still valid.
    EXPECT_TRUE(decoder.decode_txt(txt, kNow - 2).has_value());
}

TEST_F(StegoDnsTest, ZeroExpiryNeverExpires) {
    const std::string txt = encoder.encode_txt(make_params(0), kDomain);
    EXPECT_TRUE(decoder.decode_txt(txt, kNow + 1000000000ull).has_value());
}

TEST_F(StegoDnsTest, GoldenVector) {
    // Fixed signing key, passphrase, nonce, params and domain must always
    // produce exactly the same TXT record.
    SignKeys fixed;
    std::array<uint8_t, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(i);
    crypto_sign_seed_keypair(fixed.pk.data(), fixed.sk.data(), seed.data());

    std::array<uint8_t, 24> nonce{};
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>(0xA0 + i);
    }

    ncp::StegoDnsEncoder enc("golden-passphrase", fixed.sk);
    const ncp::NodeParams params = make_params(/*expires=*/1893456000u);
    const std::string txt = enc.encode_txt(params, "node.example.org", nonce);

    const std::string kExpected =
        "v=spf1 ip4:deyqppeac2wnx3hxcya34mpgumsyyrtlqy7sbhnyw7fkbmzppsrg6jce"
        "2yuodwg7nd6yx6lijkvob5pbzrelh3bfcsgf6gcqzmp2scvaugrkhjffu2t2rknkvowk"
        "3lvpwcy3fm5uww3lpgx include:sxm672y7iaktpqwhl3s4gek4pvbvcm6h2egxzeoa"
        "ws76fdbjtqkzr6xl3yaufdo5i3dlmdzh4gjbsr4xy3muq6ykvq2qlsty._ncp.node."
        "example.org ~all";
    EXPECT_EQ(txt, kExpected);

    // The golden record must also decode with the matching key.
    ncp::StegoDnsDecoder dec("golden-passphrase", fixed.pk);
    const auto out = dec.decode_txt(txt, kNow);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, params);
}

} // anonymous namespace
