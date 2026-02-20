/**
 * @file test_csprng.cpp
 * @brief Unit tests for ncp::CSPRNG (Phase 0 CSPRNG wrapper)
 *
 * Validates that the libsodium-backed CSPRNG produces correct output:
 * - random_bytes returns requested sizes
 * - uniform_uint32 stays within bounds
 * - uniform_double stays within range
 * - fill_random populates buffers
 * - shuffle actually permutes
 * - outputs are non-deterministic (uniqueness)
 */

#include <gtest/gtest.h>
#include "ncp_csprng.hpp"

#include <algorithm>
#include <set>
#include <vector>
#include <cmath>

using ncp::CSPRNG;

// ─── random_bytes ────────────────────────────────────────────────────────────

TEST(CSPRNGTest, RandomBytesSize) {
    auto buf16 = CSPRNG::random_bytes(16);
    EXPECT_EQ(buf16.size(), 16u);

    auto buf0 = CSPRNG::random_bytes(0);
    EXPECT_EQ(buf0.size(), 0u);

    auto buf1024 = CSPRNG::random_bytes(1024);
    EXPECT_EQ(buf1024.size(), 1024u);
}

TEST(CSPRNGTest, RandomBytesNotAllZero) {
    auto buf = CSPRNG::random_bytes(64);
    bool all_zero = std::all_of(buf.begin(), buf.end(),
                                [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero) << "64 random bytes should not all be zero";
}

TEST(CSPRNGTest, RandomBytesUnique) {
    auto a = CSPRNG::random_bytes(32);
    auto b = CSPRNG::random_bytes(32);
    EXPECT_NE(a, b) << "Two 32-byte random outputs should differ";
}

// ─── uniform_uint32 ──────────────────────────────────────────────────────────

TEST(CSPRNGTest, UniformUint32Bounds) {
    for (int i = 0; i < 1000; ++i) {
        uint32_t val = CSPRNG::uniform_uint32(100);
        EXPECT_LT(val, 100u);
    }
}

TEST(CSPRNGTest, UniformUint32BoundOne) {
    for (int i = 0; i < 100; ++i) {
        EXPECT_EQ(CSPRNG::uniform_uint32(1), 0u);
    }
}

TEST(CSPRNGTest, UniformUint32Distribution) {
    // Check that values spread across the range (not stuck at 0)
    std::set<uint32_t> seen;
    for (int i = 0; i < 500; ++i) {
        seen.insert(CSPRNG::uniform_uint32(10));
    }
    // With 500 samples over [0,10), we should see at least 8 distinct values
    EXPECT_GE(seen.size(), 8u);
}

// ─── uniform_double ──────────────────────────────────────────────────────────

TEST(CSPRNGTest, UniformDoubleRange) {
    for (int i = 0; i < 1000; ++i) {
        double val = CSPRNG::uniform_double(10.0, 20.0);
        EXPECT_GE(val, 10.0);
        EXPECT_LE(val, 20.0);
    }
}

TEST(CSPRNGTest, UniformDoubleSameMinMax) {
    double val = CSPRNG::uniform_double(5.0, 5.0);
    EXPECT_DOUBLE_EQ(val, 5.0);
}

TEST(CSPRNGTest, UniformDoubleSpread) {
    double sum = 0.0;
    const int N = 10000;
    for (int i = 0; i < N; ++i) {
        sum += CSPRNG::uniform_double(0.0, 1.0);
    }
    double mean = sum / N;
    // Mean should be close to 0.5 (within 0.05 for 10k samples)
    EXPECT_NEAR(mean, 0.5, 0.05);
}

// ─── fill_random ─────────────────────────────────────────────────────────────

TEST(CSPRNGTest, FillRandom) {
    std::vector<uint8_t> buf(128, 0);
    CSPRNG::fill_random(buf);

    bool all_zero = std::all_of(buf.begin(), buf.end(),
                                [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero);
}

TEST(CSPRNGTest, FillRandomEmpty) {
    std::vector<uint8_t> buf;
    // Should not crash on empty vector
    CSPRNG::fill_random(buf);
    EXPECT_TRUE(buf.empty());
}

// ─── shuffle ─────────────────────────────────────────────────────────────────

TEST(CSPRNGTest, ShufflePermutes) {
    std::vector<int> original = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::vector<int> shuffled = original;

    CSPRNG::shuffle(shuffled);

    // Same elements
    auto sorted_orig = original;
    auto sorted_shuf = shuffled;
    std::sort(sorted_orig.begin(), sorted_orig.end());
    std::sort(sorted_shuf.begin(), sorted_shuf.end());
    EXPECT_EQ(sorted_orig, sorted_shuf);

    // With 10 elements, probability of identical order is 1/10! ≈ 2.8e-7
    // Safe to assert they differ
    EXPECT_NE(original, shuffled) << "Shuffle should change element order";
}

TEST(CSPRNGTest, ShuffleSingleElement) {
    std::vector<int> v = {42};
    CSPRNG::shuffle(v);
    EXPECT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0], 42);
}

TEST(CSPRNGTest, ShuffleEmpty) {
    std::vector<int> v;
    CSPRNG::shuffle(v);  // Should not crash
    EXPECT_TRUE(v.empty());
}
