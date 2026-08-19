/**
 * @file test_semfluid.cpp
 * @brief gtest suite for ncp_semfluid (M8) — Semantic HTTP fluid transport.
 */

#include <gtest/gtest.h>
#include "ncp_semfluid.hpp"

#include <cctype>
#include <cstring>
#include <random>
#include <string>
#include <vector>

using namespace ncp;

namespace {

std::vector<uint8_t> make_payload(size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<uint8_t> p(n);
    for (auto& b : p) b = static_cast<uint8_t>(rng() & 0xFF);
    return p;
}

bool is_base62(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0;
}

// Realism lint: headers required for a plausible browser/agent request,
// cookie values in the expected charset, Content-Length consistent.
void lint_request(const HttpRequest& req) {
    EXPECT_FALSE(req.method.empty());
    EXPECT_FALSE(req.path.empty());
    EXPECT_EQ(req.path.front(), '/');

    EXPECT_TRUE(req.header("Host").has_value());
    EXPECT_TRUE(req.header("User-Agent").has_value());
    EXPECT_TRUE(req.header("Accept").has_value());
    EXPECT_TRUE(req.header("Accept-Language").has_value());
    EXPECT_TRUE(req.header("Connection").has_value());

    // UA and Host charsets: printable, no control chars.
    // NOTE: bind optionals to named variables — range-for over
    // *optional temporary dangles in C++17 (fixed only in C++23).
    const auto ua = req.header("User-Agent");
    for (char c : *ua) {
        EXPECT_GE(c, 0x20);
        EXPECT_LE(c, 0x7E);
    }
    const auto host = req.header("Host");
    for (char c : *host) {
        EXPECT_TRUE(std::isalnum(static_cast<unsigned char>(c)) ||
                    c == '.' || c == '-' || c == ':');
    }

    // Cookie values: either 64-char base62 chunks or a decorative cookie
    // with a plausible short value.
    bool saw_cookie = false;
    for (const auto& h : req.headers) {
        if (h.first != "Cookie") continue;
        saw_cookie = true;
        size_t pos = 0;
        while (pos < h.second.size()) {
            size_t end = h.second.find(';', pos);
            std::string pair = h.second.substr(
                pos, end == std::string::npos ? std::string::npos : end - pos);
            pos = (end == std::string::npos) ? h.second.size() : end + 1;
            size_t b = pair.find_first_not_of(" \t");
            if (b == std::string::npos) continue;
            size_t eq = pair.find('=', b);
            ASSERT_NE(eq, std::string::npos);
            std::string value = pair.substr(eq + 1);
            // Trim trailing whitespace.
            size_t e = value.find_last_not_of(" \t");
            value = value.substr(0, e + 1);
            EXPECT_FALSE(value.empty());
            for (char c : value) {
                EXPECT_TRUE(is_base62(c) || c == '=')
                    << "bad cookie char: " << c;
            }
        }
    }
    EXPECT_TRUE(saw_cookie);

    // Content-Length consistency.
    auto cl = req.header("Content-Length");
    if (cl) {
        EXPECT_EQ(std::stoull(*cl), req.body.size());
        EXPECT_EQ(req.method, "POST");
    } else {
        EXPECT_TRUE(req.body.empty());
    }
}

} // namespace

// ===== Roundtrip: 1 B .. 64 KiB across all templates =====

TEST(SemFluid, RoundtripAllTemplatesAndSizes) {
    const size_t sizes[] = {1, 2, 42, 43, 44, 100, 1000, 8192, 65536};
    for (int tid = 0; tid < SemanticWrapper::kTemplateCount; ++tid) {
        for (size_t n : sizes) {
            std::vector<uint8_t> payload = make_payload(n, 0xC0FFEE + n);
            std::mt19937_64 rng(1234 + n);
            HttpRequest req = SemanticWrapper::wrap(payload, tid, rng);
            auto back = SemanticWrapper::unwrap(req);
            ASSERT_TRUE(back.has_value())
                << "template=" << tid << " size=" << n;
            EXPECT_EQ(*back, payload)
                << "template=" << tid << " size=" << n;
        }
    }
}

// ===== Roundtrip through the wire format (serialize + parse) =====

TEST(SemFluid, WireRoundtrip) {
    std::vector<uint8_t> payload = make_payload(4096, 7);
    std::mt19937_64 rng(99);
    HttpRequest req = SemanticWrapper::wrap(payload, std::nullopt, rng);
    std::string wire = req.serialize();

    auto parsed = SemanticWrapper::parse_request(wire);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->method, req.method);
    EXPECT_EQ(parsed->path, req.path);
    EXPECT_EQ(parsed->headers, req.headers);
    EXPECT_EQ(parsed->body, req.body);

    auto back = SemanticWrapper::unwrap(*parsed);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(*back, payload);
}

// ===== Realism lint across all templates =====

TEST(SemFluid, RealismLint) {
    for (int tid = 0; tid < SemanticWrapper::kTemplateCount; ++tid) {
        std::mt19937_64 rng(555 + tid);
        HttpRequest req = SemanticWrapper::wrap(make_payload(300, tid), tid, rng);
        lint_request(req);
        // And the parsed (re-serialized) form must lint clean as well.
        auto parsed = SemanticWrapper::parse_request(req.serialize());
        ASSERT_TRUE(parsed.has_value());
        lint_request(*parsed);
    }
}

// ===== Tamper -> nullopt =====

TEST(SemFluid, TamperDetected) {
    std::vector<uint8_t> payload = make_payload(500, 11);
    for (int tid = 0; tid < SemanticWrapper::kTemplateCount; ++tid) {
        std::mt19937_64 rng(42);
        HttpRequest req = SemanticWrapper::wrap(payload, tid, rng);
        std::string wire = req.serialize();

        // Flip one char inside the first chunk cookie value.
        size_t pos = wire.find("MSFPC=");
        ASSERT_NE(pos, std::string::npos) << "template=" << tid;
        pos += 6; // start of the 64-char value
        char& c = wire[pos + 10];
        c = (c == 'A') ? 'B' : 'A'; // stays base62 -> checksum must fail
        auto parsed = SemanticWrapper::parse_request(wire);
        ASSERT_TRUE(parsed.has_value());
        EXPECT_FALSE(SemanticWrapper::unwrap(*parsed).has_value())
            << "template=" << tid;

        // Replace a chunk char with a non-base62 symbol -> chunk skipped,
        // chunk count mismatch -> nullopt.
        std::string wire2 = req.serialize();
        char& c2 = wire2[pos + 20];
        c2 = '!';
        auto parsed2 = SemanticWrapper::parse_request(wire2);
        ASSERT_TRUE(parsed2.has_value());
        EXPECT_FALSE(SemanticWrapper::unwrap(*parsed2).has_value())
            << "template=" << tid;
    }
}

// ===== Determinism: same seed -> byte-identical request =====

TEST(SemFluid, DeterministicWithSeed) {
    std::vector<uint8_t> payload = make_payload(1000, 3);
    std::mt19937_64 rng1(0xDEADBEEF);
    std::mt19937_64 rng2(0xDEADBEEF);
    HttpRequest r1 = SemanticWrapper::wrap(payload, std::nullopt, rng1);
    HttpRequest r2 = SemanticWrapper::wrap(payload, std::nullopt, rng2);
    EXPECT_EQ(r1.serialize(), r2.serialize());

    // Header order is stable and identical.
    ASSERT_EQ(r1.headers.size(), r2.headers.size());
    for (size_t i = 0; i < r1.headers.size(); ++i) {
        EXPECT_EQ(r1.headers[i].first, r2.headers[i].first);
        EXPECT_EQ(r1.headers[i].second, r2.headers[i].second);
    }
}

// ===== Empty payload edge case =====

TEST(SemFluid, EmptyPayloadRoundtrip) {
    std::vector<uint8_t> empty;
    std::mt19937_64 rng(1);
    HttpRequest req = SemanticWrapper::wrap(empty, 1, rng);
    auto back = SemanticWrapper::unwrap(req);
    ASSERT_TRUE(back.has_value());
    EXPECT_TRUE(back->empty());
}

// ===== Parser rejects garbage =====

TEST(SemFluid, ParseRejectsGarbage) {
    EXPECT_FALSE(SemanticWrapper::parse_request("").has_value());
    EXPECT_FALSE(SemanticWrapper::parse_request("not http at all").has_value());
    EXPECT_FALSE(SemanticWrapper::parse_request("GET / HTTP/1.1\r\nBadHeaderLine\r\n\r\n").has_value());
    // Truncated body.
    EXPECT_FALSE(SemanticWrapper::parse_request(
        "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc").has_value());
}

// ===== Unwrap of a request without chunks fails cleanly =====

TEST(SemFluid, UnwrapWithoutChunksFails) {
    HttpRequest req;
    req.method = "GET";
    req.path = "/";
    req.headers.emplace_back("Host", "example.com");
    EXPECT_FALSE(SemanticWrapper::unwrap(req).has_value());
}
