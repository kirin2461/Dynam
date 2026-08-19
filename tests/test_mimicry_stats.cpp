// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_stats.cpp
// Tests for M5 — ncp_mimicry_stats (statistical traffic profiles)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_mimicry_stats.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <vector>

using namespace ncp;

namespace {

constexpr uint64_t kSeed = 0xC0FFEE123456ULL;
constexpr size_t kSamples = 10000;

struct Moments {
    double mean;
    double stddev;
};

Moments compute_moments(const std::vector<double>& xs) {
    double mean = std::accumulate(xs.begin(), xs.end(), 0.0) / xs.size();
    double var = 0.0;
    for (double x : xs) {
        double d = x - mean;
        var += d * d;
    }
    var /= xs.size();
    return {mean, std::sqrt(var)};
}

std::vector<double> sample_sizes(const StatProfile& p, size_t n) {
    std::mt19937_64 rng(kSeed);
    std::vector<double> out(n);
    for (auto& x : out) x = p.sample_size(rng);
    return out;
}

std::vector<double> sample_intervals(const StatProfile& p, size_t n) {
    std::mt19937_64 rng(kSeed);
    std::vector<double> out(n);
    for (auto& x : out) x = p.sample_interval_ms(rng);
    return out;
}

// All built-ins, for parameterized checks.
std::vector<StatProfile> all_profiles() {
    return {StatProfile::webrtc_video(),
            StatProfile::zoom_call(),
            StatProfile::youtube_stream(),
            StatProfile::voip_opus()};
}

} // namespace

// ── Mean/stddev within 5% of theoretical for every built-in ──────────────────

TEST(MimicryStatsTest, SizeMomentsWithinFivePercent) {
    for (const auto& p : all_profiles()) {
        auto xs = sample_sizes(p, kSamples);
        auto m = compute_moments(xs);
        double tmean = p.sizes.theoretical_mean();
        double tstd = p.sizes.theoretical_stddev();
        EXPECT_NEAR(m.mean, tmean, 0.05 * std::fabs(tmean)) << p.name;
        EXPECT_NEAR(m.stddev, tstd, 0.05 * std::fabs(tstd)) << p.name;
    }
}

TEST(MimicryStatsTest, IntervalMomentsWithinFivePercent) {
    for (const auto& p : all_profiles()) {
        auto xs = sample_intervals(p, kSamples);
        auto m = compute_moments(xs);
        double tmean = p.intervals.theoretical_mean();
        double tstd = p.intervals.theoretical_stddev();
        EXPECT_NEAR(m.mean, tmean, 0.05 * std::fabs(tmean)) << p.name;
        if (p.intervals.kind != IntervalKind::FIXED)
            EXPECT_NEAR(m.stddev, tstd, 0.05 * std::fabs(tstd)) << p.name;
        else
            EXPECT_DOUBLE_EQ(m.stddev, 0.0) << p.name;
    }
}

TEST(MimicryStatsTest, VoipOpusFixedCadence) {
    auto p = StatProfile::voip_opus();
    std::mt19937_64 rng(kSeed);
    for (int i = 0; i < 1000; ++i)
        EXPECT_DOUBLE_EQ(p.sample_interval_ms(rng), 20.0);
}

// ── Discrete mix ratios within ±1.5 percentage points ────────────────────────

TEST(MimicryStatsTest, WebRtcMixRatios) {
    auto p = StatProfile::webrtc_video();
    auto xs = sample_sizes(p, kSamples);

    // Keyframe spike component N(8000,1500), 2%: samples above 5000 are
    // dominated by it (N(1200,180) and N(400,80) tails are negligible).
    size_t big = 0, small = 0;
    for (double x : xs) {
        if (x >= 5000.0) ++big;      // ~2% keyframes
        else if (x < 700.0) ++small; // ~8% small-audio/signalling component
    }
    double big_ratio = static_cast<double>(big) / xs.size();
    double small_ratio = static_cast<double>(small) / xs.size();

    EXPECT_NEAR(big_ratio, 0.02, 0.015);
    EXPECT_NEAR(small_ratio, 0.08, 0.015);
}

// ── Determinism ───────────────────────────────────────────────────────────────

TEST(MimicryStatsTest, DeterministicPlanSameSeed) {
    auto p = StatProfile::webrtc_video();
    MimicryShaper a(p, kSeed);
    MimicryShaper b(p, kSeed);
    auto pa = a.plan(100000);
    auto pb = b.plan(100000);
    ASSERT_EQ(pa.size(), pb.size());
    for (size_t i = 0; i < pa.size(); ++i) {
        EXPECT_EQ(pa[i].bytes, pb[i].bytes);
        EXPECT_DOUBLE_EQ(pa[i].delay_ms, pb[i].delay_ms);
    }
}

TEST(MimicryStatsTest, DifferentSeedDifferentPlan) {
    auto p = StatProfile::webrtc_video();
    MimicryShaper a(p, kSeed);
    MimicryShaper b(p, kSeed + 1);
    auto pa = a.plan(100000);
    auto pb = b.plan(100000);
    bool any_diff = pa.size() != pb.size();
    for (size_t i = 0; !any_diff && i < pa.size(); ++i)
        any_diff = pa[i].bytes != pb[i].bytes;
    EXPECT_TRUE(any_diff);
}

TEST(MimicryStatsTest, ResetRestoresDeterminism) {
    auto p = StatProfile::zoom_call();
    MimicryShaper s(p, kSeed);
    auto first = s.plan(5000);
    s.reset(kSeed);
    auto second = s.plan(5000);
    ASSERT_EQ(first.size(), second.size());
    for (size_t i = 0; i < first.size(); ++i)
        EXPECT_EQ(first[i].bytes, second[i].bytes);
}

// ── Chunk planning ────────────────────────────────────────────────────────────

TEST(MimicryStatsTest, OneMbPlanPlausiblePacketCount) {
    auto p = StatProfile::webrtc_video();
    MimicryShaper shaper(p, kSeed);
    auto chunks = shaper.plan(1024 * 1024);

    size_t total = 0;
    for (const auto& c : chunks) {
        total += c.bytes;
        EXPECT_GE(c.bytes, 1u);
        EXPECT_GE(c.delay_ms, 0.0);
    }
    EXPECT_EQ(total, 1024u * 1024u);

    // Mixture mean ≈ 1272 bytes → ~824 chunks; spec allows 800–1400.
    EXPECT_GE(chunks.size(), 800u);
    EXPECT_LE(chunks.size(), 1400u);
}

TEST(MimicryStatsTest, EmptyPayloadYieldsEmptyPlan) {
    MimicryShaper shaper(StatProfile::voip_opus(), kSeed);
    EXPECT_TRUE(shaper.plan(0).empty());
}

TEST(MimicryStatsTest, FinalChunkCappedAtRemaining) {
    MimicryShaper shaper(StatProfile::webrtc_video(), kSeed);
    auto chunks = shaper.plan(100);
    ASSERT_EQ(chunks.size(), 1u);
    EXPECT_EQ(chunks[0].bytes, 100u);
}

// ── KS-style bucket check: |empirical CDF − expected CDF| < 0.03 ─────────────

TEST(MimicryStatsTest, KsStyleBucketCheckWebRtc) {
    auto p = StatProfile::webrtc_video();
    auto xs = sample_sizes(p, kSamples);
    std::sort(xs.begin(), xs.end());

    // 10 buckets → 11 edges spanning the clamp range.
    const std::vector<double> edges = {64, 300, 500, 800, 1000, 1200,
                                       1500, 2000, 4000, 7000, 9000};
    for (double e : edges) {
        double empirical = static_cast<double>(
            std::upper_bound(xs.begin(), xs.end(), e) - xs.begin()) / xs.size();
        double expected = p.sizes.theoretical_cdf(e);
        ASSERT_FALSE(std::isnan(expected));
        // Treat clamp bounds as CDF anchors.
        if (e <= p.sizes.clamp_min) expected = 0.0;
        if (e >= p.sizes.clamp_max) expected = 1.0;
        EXPECT_NEAR(empirical, expected, 0.03) << "edge=" << e;
    }
}
