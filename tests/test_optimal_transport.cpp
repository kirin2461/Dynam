// ══════════════════════════════════════════════════════════════════════════════
// tests/test_optimal_transport.cpp
// 1-D Wasserstein-1 distance + exact quantile shaping.
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_optimal_transport.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <vector>

using namespace ncp::DPI;

// ── W1: definition-level checks ───────────────────────────────────────────────

TEST(OptimalTransport, W1_IdenticalSamplesAreZero) {
    std::vector<double> a = {52, 150, 150, 1460, 300};
    EXPECT_DOUBLE_EQ(w1_distance(a, a), 0.0);
}

TEST(OptimalTransport, W1_PointMassesSeparatedByGap) {
    // W1 of a point mass at 0 and one at 10 is exactly the gap.
    EXPECT_DOUBLE_EQ(w1_distance({0.0}, {10.0}), 10.0);
    EXPECT_DOUBLE_EQ(w1_distance({10.0}, {0.0}), 10.0);
}

TEST(OptimalTransport, W1_ShiftedDistributionEqualsShift) {
    // Translating every sample by d shifts W1 by exactly d.
    std::vector<double> a = {0, 100, 200, 300};
    std::vector<double> b;
    for (double v : a) b.push_back(v + 37.0);
    EXPECT_NEAR(w1_distance(a, b), 37.0, 1e-9);
}

TEST(OptimalTransport, W1_KnownValueAgainstDegenerateReference) {
    // F_a: 0.0 at x<0, 0.5 on [0,10), 1.0 at x>=10
    // F_b: 0.0 at x<5,  1.0 at x>=5
    // integral |Fa-Fb| = 0.5*5 (on [0,5)) + 0.5*5 (on [5,10)) = 5.0
    std::vector<double> a = {0, 0, 10, 10};
    std::vector<double> b = {5, 5, 5, 5};
    EXPECT_NEAR(w1_distance(a, b), 5.0, 1e-9);
}

TEST(OptimalTransport, W1_IsSymmetric) {
    std::vector<double> a = {52, 52, 52, 1460};
    std::vector<double> b = {52, 300, 300, 1460, 1460, 1460};
    EXPECT_NEAR(w1_distance(a, b), w1_distance(b, a), 1e-12);
}

TEST(OptimalTransport, W1_EmptyInputs) {
    EXPECT_DOUBLE_EQ(w1_distance({}, {}), 0.0);
    // One side empty has no meaningful finite transport cost.
    EXPECT_TRUE(std::isinf(w1_distance({}, {1, 2, 3})));
    EXPECT_TRUE(std::isinf(w1_distance({1, 2, 3}, {})));
}

TEST(OptimalTransport, W1_SizesOverloadMatchesDoubleVersion) {
    std::vector<size_t> a = {52, 150, 1460};
    std::vector<size_t> b = {52, 300, 1460};
    std::vector<double> da;
    std::vector<double> db;
    for (size_t v : a) da.push_back(static_cast<double>(v));
    for (size_t v : b) db.push_back(static_cast<double>(v));
    EXPECT_DOUBLE_EQ(w1_distance_sizes(a, b), w1_distance(da, db));
}

TEST(OptimalTransport, W1_OrderOfInputDoesNotMatter) {
    std::vector<double> a = {1460, 52, 300};
    std::vector<double> a_sorted = {52, 300, 1460};
    std::vector<double> b = {52, 52, 52};
    EXPECT_DOUBLE_EQ(w1_distance(a, b), w1_distance(a_sorted, b));
}

// ── KS: sanity, and the point of W1 vs KS ────────────────────────────────────

TEST(OptimalTransport, KS_IdenticalIsZero) {
    std::vector<double> a = {1, 2, 3, 4, 5};
    EXPECT_DOUBLE_EQ(ks_distance_samples(a, a), 0.0);
}

TEST(OptimalTransport, KS_IsBoundedByOne) {
    std::vector<double> a = {0, 0, 0, 0};
    std::vector<double> b = {1000, 1000, 1000, 1000};
    EXPECT_DOUBLE_EQ(ks_distance_samples(a, b), 1.0);
}

// The reason W1 is the metric worth shaping against: a distribution can be
// close to the reference in KS while its mean is off by tens of bytes.
TEST(OptimalTransport, W1_CatchesWhatKSAtFixedRateAllows) {
    // Reference samples evenly spaced 150 bytes apart; observed is the same
    // shape shifted by half a spacing. KS only reaches 1/n = 0.09, well inside
    // the "good mimicry" band, while every sample - and therefore the mean -
    // is displaced by 75 bytes.
    std::vector<double> ref, obs;
    for (int i = 0; i <= 10; ++i) {
        ref.push_back(static_cast<double>(i) * 150.0);
        obs.push_back(static_cast<double>(i) * 150.0 + 75.0);
    }
    const double ks = ks_distance_samples(obs, ref);
    const double w1 = w1_distance(obs, ref);
    EXPECT_LT(ks, 0.1);          // KS says "close enough"
    EXPECT_NEAR(w1, 75.0, 1e-6); // W1 prices the displacement exactly
}

// Kantorovich-Rubinstein in 1-D: for equal-size samples the optimal coupling is
// the monotone one, so W1 equals the mean absolute difference of sorted values.
TEST(OptimalTransport, W1_EqualsMeanSortedDisplacement) {
    std::vector<double> a = {52, 60, 300, 1460, 1500};
    std::vector<double> b = {52, 80, 250, 1200, 1300};
    std::vector<double> sa = a, sb = b;
    std::sort(sa.begin(), sa.end());
    std::sort(sb.begin(), sb.end());
    double expected = 0.0;
    for (size_t i = 0; i < sa.size(); ++i) expected += std::fabs(sa[i] - sb[i]);
    expected /= static_cast<double>(sa.size());
    EXPECT_NEAR(w1_distance(a, b), expected, 1e-9);
}

// ── QuantileShaper ───────────────────────────────────────────────────────────

static std::vector<size_t> web_ref() {
    return expand_size_histogram({{52, 0.30}, {150, 0.15}, {350, 0.10},
                                  {580, 0.08}, {1200, 0.12}, {1460, 0.25}},
                                 256);
}

TEST(QuantileShaper, RejectsEmptyReference) {
    EXPECT_THROW(QuantileShaper({}), std::invalid_argument);
}

TEST(QuantileShaper, BlockSizeMatchesReference) {
    auto ref = web_ref();
    QuantileShaper shaper(ref);
    EXPECT_EQ(shaper.block_size(), ref.size());
    EXPECT_EQ(shaper.reference(), ref);   // stored sorted
}

TEST(QuantileShaper, FullBlockReproducesReferenceMultisetExactly) {
    auto ref = web_ref();
    QuantileShaper shaper(ref);

    std::vector<size_t> block;
    block.reserve(shaper.block_size());
    for (size_t i = 0; i < shaper.block_size(); ++i) block.push_back(shaper.next());

    std::vector<size_t> sorted_block = block;
    std::sort(sorted_block.begin(), sorted_block.end());
    EXPECT_EQ(sorted_block, ref);                    // exact multiset
    EXPECT_DOUBLE_EQ(w1_distance_sizes(block, ref), 0.0);
}

TEST(QuantileShaper, SecondBlockIsAlsoExactAndNotTheSameOrder) {
    auto ref = web_ref();
    QuantileShaper shaper(ref);

    std::vector<size_t> first, second;
    for (size_t i = 0; i < shaper.block_size(); ++i) first.push_back(shaper.next());
    for (size_t i = 0; i < shaper.block_size(); ++i) second.push_back(shaper.next());

    auto s1 = first, s2 = second;
    std::sort(s1.begin(), s1.end());
    std::sort(s2.begin(), s2.end());
    EXPECT_EQ(s1, ref);
    EXPECT_EQ(s2, ref);
    // A different epoch gets a fresh permutation; identical order across
    // epochs would be a learnable, repeating pattern.
    EXPECT_NE(first, second);
}

TEST(QuantileShaper, ResetRestartsTheBlock) {
    auto ref = web_ref();
    QuantileShaper shaper(ref);
    for (size_t i = 0; i < 10; ++i) shaper.next();
    EXPECT_EQ(shaper.emitted(), 10u);
    shaper.reset();
    EXPECT_EQ(shaper.emitted(), 0u);
}

TEST(QuantileShaper, PartialBlockUsesEachSizeAtMostOncePerEpoch) {
    auto ref = web_ref();
    QuantileShaper shaper(ref);
    std::vector<size_t> seen;
    for (size_t i = 0; i < shaper.block_size() / 2; ++i) seen.push_back(shaper.next());
    // No duplicate beyond the multiplicity the reference itself contains.
    std::vector<size_t> sorted_seen = seen;
    std::sort(sorted_seen.begin(), sorted_seen.end());
    for (size_t v : sorted_seen) {
        const size_t in_seen = static_cast<size_t>(
            std::count(sorted_seen.begin(), sorted_seen.end(), v));
        const size_t in_ref = static_cast<size_t>(
            std::count(ref.begin(), ref.end(), v));
        EXPECT_LE(in_seen, in_ref);
    }
}

TEST(QuantileShaper, SingleElementReferenceIsConstant) {
    QuantileShaper shaper({1460});
    for (int i = 0; i < 15; ++i) EXPECT_EQ(shaper.next(), 1460u);
}

// ── Histogram expansion ──────────────────────────────────────────────────────

TEST(ExpandSizeHistogram, ProportionsAreRespected) {
    auto ref = expand_size_histogram({{52, 0.25}, {1460, 0.75}}, 100);
    ASSERT_FALSE(ref.empty());
    const size_t small = static_cast<size_t>(std::count(ref.begin(), ref.end(), 52));
    const size_t large = static_cast<size_t>(std::count(ref.begin(), ref.end(), 1460));
    EXPECT_NEAR(static_cast<double>(small) / ref.size(), 0.25, 0.02);
    EXPECT_NEAR(static_cast<double>(large) / ref.size(), 0.75, 0.02);
}

TEST(ExpandSizeHistogram, ZeroWeightBucketIsDroppedButOthersSurvive) {
    auto ref = expand_size_histogram({{52, 0.0}, {1460, 1.0}}, 16);
    EXPECT_EQ(std::count(ref.begin(), ref.end(), 52), 0);
    EXPECT_GT(std::count(ref.begin(), ref.end(), 1460), 0);
}

TEST(ExpandSizeHistogram, EmptyInputYieldsEmpty) {
    EXPECT_TRUE(expand_size_histogram({}, 64).empty());
}

TEST(ExpandSizeHistogram, OutputIsSorted) {
    auto ref = expand_size_histogram({{1460, 0.5}, {52, 0.5}}, 32);
    EXPECT_TRUE(std::is_sorted(ref.begin(), ref.end()));
}
