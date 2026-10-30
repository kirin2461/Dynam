// ══════════════════════════════════════════════════════════════════════════════
// tests/test_mimicry_stats.cpp
// Tests for M5 — ncp_mimicry_stats (statistical traffic profiles)
// ══════════════════════════════════════════════════════════════════════════════
#include <gtest/gtest.h>
#include "ncp_mimicry_stats.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <utility>
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

    // Mixture mean ≈ 1272 bytes → ~824 chunks on libstdc++; libc++
    // (macOS) yields ~796 for the same seed because the C++ standard
    // leaves std::normal_distribution's algorithm implementation-defined.
    // Bounds are a sanity check, so keep generous margin: 700–1400.
    EXPECT_GE(chunks.size(), 700u);
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

// ══════════════════════════════════════════════════════════════════════════
// Joint size↔IAT sampling + prepared data shape API (profile epochs)
// ══════════════════════════════════════════════════════════════════════════

namespace {

// Single-component joint model with Cholesky L = [[10,0],[8,6]]:
// cov = L·Lᵀ, encoded corr = l10/√(l10²+l11²) = 0.8.
StatProfile joint_profile_08() {
    StatProfile p = StatProfile::webrtc_video();  // marginals unused by joint
    p.name = "joint_corr_08";
    JointSizeIatComponent c;
    c.weight = 1.0;
    c.mu_size_bytes = 500.0;
    c.mu_iat_ms = 20.0;
    c.l00 = 10.0;
    c.l10 = 8.0;
    c.l11 = 6.0;
    p.size_iat_joint.components = {c};
    return p;
}

double pearson_corr(const std::vector<double>& xs,
                    const std::vector<double>& ys) {
    EXPECT_EQ(xs.size(), ys.size());
    const double n = static_cast<double>(xs.size());
    auto m = compute_moments(xs);
    auto m2 = compute_moments(ys);
    double cov = 0.0;
    for (size_t i = 0; i < xs.size(); ++i)
        cov += (xs[i] - m.mean) * (ys[i] - m2.mean);
    cov /= n;
    return cov / (m.stddev * m2.stddev);
}

std::pair<std::vector<double>, std::vector<double>>
sample_pairs(const StatProfile& p, size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<double> sizes(n), iats(n);
    for (size_t i = 0; i < n; ++i)
        p.sample_size_iat(rng, sizes[i], iats[i]);
    return {sizes, iats};
}

} // namespace

// ── Joint sampling: correlation, determinism, bounds ─────────────────────────

TEST(JointSizeIatTest, CorrelationSurvives) {
    auto p = joint_profile_08();
    ASSERT_TRUE(p.has_joint_size_iat());
    auto [sizes, iats] = sample_pairs(p, 8000, kSeed);
    double corr = pearson_corr(sizes, iats);
    // Empirical correlation must land near the 0.8 the Cholesky encodes —
    // exactly what two independent 1-D marginals cannot reproduce.
    EXPECT_GT(corr, 0.7);
    EXPECT_LT(corr, 0.9);
}

TEST(JointSizeIatTest, IndependentMarginalsHaveNoCorrelation) {
    // Contrast control: the legacy independent path must NOT correlate.
    auto p = joint_profile_08();
    p.size_iat_joint.components.clear();  // fall back to 1-D marginals
    ASSERT_FALSE(p.has_joint_size_iat());
    auto [sizes, iats] = sample_pairs(p, 8000, kSeed);
    double corr = pearson_corr(sizes, iats);
    EXPECT_NEAR(corr, 0.0, 0.05);
}

TEST(JointSizeIatTest, DeterministicReplaySameSeed) {
    auto p = joint_profile_08();
    auto a = sample_pairs(p, 1000, kSeed);
    auto b = sample_pairs(p, 1000, kSeed);
    ASSERT_EQ(a.first.size(), b.first.size());
    for (size_t i = 0; i < a.first.size(); ++i) {
        EXPECT_DOUBLE_EQ(a.first[i], b.first[i]);
        EXPECT_DOUBLE_EQ(a.second[i], b.second[i]);
    }
}

TEST(JointSizeIatTest, DifferentSeedsDiffer) {
    auto p = joint_profile_08();
    auto a = sample_pairs(p, 1000, kSeed);
    auto b = sample_pairs(p, 1000, kSeed + 1);
    bool any_diff = false;
    for (size_t i = 0; i < a.first.size() && !any_diff; ++i)
        any_diff = a.first[i] != b.first[i] || a.second[i] != b.second[i];
    EXPECT_TRUE(any_diff);
}

TEST(JointSizeIatTest, SamplesWithinBounds) {
    auto p = joint_profile_08();
    auto [sizes, iats] = sample_pairs(p, kSamples, kSeed);
    for (size_t i = 0; i < sizes.size(); ++i) {
        EXPECT_GE(sizes[i], 1.0);
        EXPECT_LE(sizes[i], JointSizeIatSampler::kMaxSizeBytes);
        EXPECT_GE(iats[i], 0.0);
        EXPECT_LE(iats[i], JointSizeIatSampler::kMaxIatMs);
        EXPECT_TRUE(std::isfinite(sizes[i]));
        EXPECT_TRUE(std::isfinite(iats[i]));
    }
}

TEST(JointSizeIatTest, JointRespectsProfileSizeClamps) {
    // The joint sampler enforces the u16 wire budget; on top of that the
    // profile's declared [clamp_min, clamp_max] envelope must hold for every
    // plan()/prepare sample.
    auto p = joint_profile_08();
    p.sizes.clamp_min = 200.0;
    p.sizes.clamp_max = 600.0;
    auto [sizes, iats] = sample_pairs(p, kSamples, kSeed);
    for (double s : sizes) {
        EXPECT_GE(s, 200.0);
        EXPECT_LE(s, 600.0);
    }
    // And through plan(): every non-final chunk obeys the same envelope.
    MimicryShaper shaper(p, kSeed);
    auto chunks = shaper.plan(256 * 1024);
    ASSERT_GT(chunks.size(), 100u);
    chunks.pop_back();  // final chunk is capped at the remaining bytes
    for (const auto& c : chunks) {
        EXPECT_GE(c.bytes, 200u);
        EXPECT_LE(c.bytes, 600u);
    }
}

TEST(JointSizeIatTest, MalformedModelFallsBackAndLeavesRngUntouched) {
    // Empty components: invalid → benign fallback (512, 20), no rng draw.
    JointSizeIatSampler empty;
    EXPECT_FALSE(empty.is_valid());
    std::mt19937_64 a(kSeed), b(kSeed);
    auto s = empty.sample(a);
    EXPECT_DOUBLE_EQ(s.first, JointSizeIatSampler::kFallbackSizeBytes);
    EXPECT_DOUBLE_EQ(s.second, JointSizeIatSampler::kFallbackIatMs);
    // rng untouched: both streams must still agree afterwards.
    std::uniform_real_distribution<double> u(0.0, 1.0);
    EXPECT_DOUBLE_EQ(u(a), u(b));

    // All-zero weights: invalid.
    JointSizeIatSampler zero_w;
    zero_w.components = {{0.0, 500.0, 20.0, 10.0, 8.0, 6.0}};
    EXPECT_FALSE(zero_w.is_valid());
    EXPECT_DOUBLE_EQ(zero_w.sample(a).first,
                     JointSizeIatSampler::kFallbackSizeBytes);

    // Negative/NaN weights: invalid.
    JointSizeIatSampler neg;
    neg.components = {{-1.0, 500.0, 20.0, 10.0, 8.0, 6.0}};
    EXPECT_FALSE(neg.is_valid());

    // Hostile component count: > kMaxComponents rejected.
    JointSizeIatSampler huge;
    huge.components.resize(JointSizeIatSampler::kMaxComponents + 1,
                           {1.0, 500.0, 20.0, 10.0, 8.0, 6.0});
    EXPECT_FALSE(huge.is_valid());

    // An invalid joint on the profile means sample_size_iat uses marginals.
    StatProfile p = StatProfile::voip_opus();
    EXPECT_FALSE(p.has_joint_size_iat());
}

TEST(JointSizeIatTest, HostileComponentParamsClamped) {
    std::mt19937_64 rng(kSeed);
    const double bad_vals[] = {1e300,
                               std::numeric_limits<double>::infinity(),
                               -std::numeric_limits<double>::infinity(),
                               std::numeric_limits<double>::quiet_NaN()};
    for (double bad : bad_vals) {
        JointSizeIatSampler hostile;
        hostile.components = {{1.0, 500.0, bad, 10.0, 0.0, 5.0}};
        ASSERT_TRUE(hostile.is_valid());  // structural check only, by design
        for (int i = 0; i < 64; ++i) {
            auto [sz, iat] = hostile.sample(rng);
            EXPECT_TRUE(std::isfinite(iat)) << "mu_iat=" << bad;
            EXPECT_GE(iat, 0.0);
            EXPECT_LE(iat, JointSizeIatSampler::kMaxIatMs);
            EXPECT_TRUE(std::isfinite(sz));
            EXPECT_GE(sz, 1.0);
            EXPECT_LE(sz, JointSizeIatSampler::kMaxSizeBytes);
        }
    }
    // Hostile Cholesky terms feed the IAT too.
    JointSizeIatSampler hostile_l;
    hostile_l.components = {{1.0, 500.0, 20.0, 10.0, 1e308, 1e308}};
    for (int i = 0; i < 64; ++i) {
        auto [sz, iat] = hostile_l.sample(rng);
        EXPECT_TRUE(std::isfinite(iat));
        EXPECT_LE(iat, JointSizeIatSampler::kMaxIatMs);
        EXPECT_TRUE(std::isfinite(sz));
    }
}

// ── Backward compatibility of the legacy paths ───────────────────────────────

TEST(JointSizeIatTest, LegacyFallbackMatchesIndependentSampling) {
    // Without a joint model, sample_size_iat must reproduce exactly the
    // legacy sample_size() + sample_interval_ms() sequence (same rng
    // consumption, same values).
    for (const auto& p : all_profiles()) {
        ASSERT_FALSE(p.has_joint_size_iat()) << p.name;
        std::mt19937_64 a(kSeed), b(kSeed);
        for (int i = 0; i < 1000; ++i) {
            double s = 0.0, t = 0.0;
            p.sample_size_iat(a, s, t);
            EXPECT_DOUBLE_EQ(s, p.sample_size(b)) << p.name;
            EXPECT_DOUBLE_EQ(t, p.sample_interval_ms(b)) << p.name;
        }
    }
}

TEST(JointSizeIatTest, ShaperPlanWithJointCorrelates) {
    auto p = joint_profile_08();
    MimicryShaper shaper(p, kSeed);
    auto chunks = shaper.plan(1024 * 1024);
    ASSERT_GT(chunks.size(), 100u);

    // Drop the final chunk: it is capped at the remaining bytes, which would
    // attenuate the correlation.
    chunks.pop_back();
    std::vector<double> xs, ys;
    for (const auto& c : chunks) {
        xs.push_back(static_cast<double>(c.bytes));
        ys.push_back(c.delay_ms);
    }
    double corr = pearson_corr(xs, ys);
    EXPECT_GT(corr, 0.6);
    EXPECT_LT(corr, 0.95);

    size_t total = 0;
    for (const auto& c : shaper.plan(0)) (void)c;  // empty stays empty
    (void)total;
}

TEST(JointSizeIatTest, ShaperPlanWithJointDeterministic) {
    auto p = joint_profile_08();
    MimicryShaper a(p, kSeed), b(p, kSeed);
    auto pa = a.plan(100000);
    auto pb = b.plan(100000);
    ASSERT_EQ(pa.size(), pb.size());
    for (size_t i = 0; i < pa.size(); ++i) {
        EXPECT_EQ(pa[i].bytes, pb[i].bytes);
        EXPECT_DOUBLE_EQ(pa[i].delay_ms, pb[i].delay_ms);
    }
    // And differs under a different seed.
    MimicryShaper c(p, kSeed + 1);
    auto pc = c.plan(100000);
    bool any_diff = pa.size() != pc.size();
    for (size_t i = 0; !any_diff && i < pa.size(); ++i)
        any_diff = pa[i].bytes != pc[i].bytes ||
                   pa[i].delay_ms != pc[i].delay_ms;
    EXPECT_TRUE(any_diff);
}

// ── Prepared data shape API: epochs, control no-consume, cancel ─────────────

TEST(PreparedShapeTest, ControlPeekDoesNotConsume) {
    MimicryShaper shaper(joint_profile_08(), kSeed);
    EXPECT_EQ(shaper.profile_epoch(), 0u);
    EXPECT_FALSE(shaper.has_prepared_shape());

    // Control path: prepare/peek repeatedly — idempotent, nothing consumed.
    auto a = shaper.prepare_data_shape(1280);
    EXPECT_TRUE(shaper.has_prepared_shape());
    auto b = shaper.prepare_data_shape(1280);
    EXPECT_EQ(a.bytes, b.bytes);
    EXPECT_DOUBLE_EQ(a.delay_ms, b.delay_ms);
    EXPECT_EQ(a.profile_epoch, 0u);
    EXPECT_EQ(b.profile_epoch, 0u);

    // Data path consumes exactly once.
    PreparedShape out;
    ASSERT_TRUE(shaper.take_data_shape(out));
    EXPECT_EQ(out.bytes, a.bytes);
    EXPECT_DOUBLE_EQ(out.delay_ms, a.delay_ms);
    EXPECT_EQ(out.profile_epoch, 0u);
    EXPECT_FALSE(shaper.has_prepared_shape());
    EXPECT_FALSE(shaper.take_data_shape(out));  // already consumed
}

TEST(PreparedShapeTest, MtuBudgetValidation) {
    // Joint model with huge sizes: prepared shape must fit the MTU budget.
    StatProfile p = joint_profile_08();
    p.size_iat_joint.components[0].mu_size_bytes = 8000.0;
    p.size_iat_joint.components[0].l00 = 1500.0;
    MimicryShaper shaper(p, kSeed);
    for (int i = 0; i < 64; ++i) {
        auto s = shaper.prepare_data_shape(1280);
        EXPECT_GE(s.bytes, 1u);
        EXPECT_LE(s.bytes, 1280u);
        PreparedShape out;
        ASSERT_TRUE(shaper.take_data_shape(out));
    }
    // Zero budget is invalid input; degrade to the 1-byte minimum, never 0.
    auto s0 = shaper.prepare_data_shape(0);
    EXPECT_EQ(s0.bytes, 1u);
    // Delay is capped at the prepared-IAT budget even for hostile marginals.
    StatProfile hot = StatProfile::webrtc_video();
    hot.intervals.kind = IntervalKind::FIXED;
    hot.intervals.fixed_ms = 1e12;
    MimicryShaper hot_shaper(hot, kSeed);
    auto hs = hot_shaper.prepare_data_shape(1500);
    EXPECT_LE(hs.delay_ms, MimicryShaper::kMaxPreparedIatMs);
    EXPECT_TRUE(std::isfinite(hs.delay_ms));
}

TEST(PreparedShapeTest, DeterministicReplayAcrossShapers) {
    MimicryShaper a(joint_profile_08(), kSeed);
    MimicryShaper b(joint_profile_08(), kSeed);
    for (int i = 0; i < 200; ++i) {
        auto sa = a.prepare_data_shape(1500);
        auto sb = b.prepare_data_shape(1500);
        EXPECT_EQ(sa.bytes, sb.bytes);
        EXPECT_DOUBLE_EQ(sa.delay_ms, sb.delay_ms);
        PreparedShape oa, ob;
        ASSERT_TRUE(a.take_data_shape(oa));
        ASSERT_TRUE(b.take_data_shape(ob));
        EXPECT_EQ(oa.bytes, ob.bytes);
    }
    // Different seed → different shape stream.
    MimicryShaper c(joint_profile_08(), kSeed + 1);
    MimicryShaper d(joint_profile_08(), kSeed + 7);
    bool any_diff = false;
    for (int i = 0; i < 32 && !any_diff; ++i) {
        any_diff = c.prepare_data_shape(1500).bytes !=
                   d.prepare_data_shape(1500).bytes;
        PreparedShape o;
        c.take_data_shape(o);
        d.take_data_shape(o);
    }
    EXPECT_TRUE(any_diff);
}

TEST(PreparedShapeTest, StaleEpochCannotBeConsumed) {
    MimicryShaper shaper(joint_profile_08(), kSeed);
    auto s0 = shaper.prepare_data_shape(1500);
    ASSERT_EQ(s0.profile_epoch, 0u);

    // Transition: epoch bumps, queued stale shape is dropped.
    shaper.set_profile(StatProfile::zoom_call());
    EXPECT_EQ(shaper.profile_epoch(), 1u);
    EXPECT_FALSE(shaper.has_prepared_shape());
    PreparedShape out;
    EXPECT_FALSE(shaper.take_data_shape(out));  // stale shape not consumable

    // New-epoch shapes work and carry the new epoch tag.
    auto s1 = shaper.prepare_data_shape(1500);
    EXPECT_EQ(s1.profile_epoch, 1u);
    ASSERT_TRUE(shaper.take_data_shape(out));
    EXPECT_EQ(out.profile_epoch, 1u);
}

TEST(PreparedShapeTest, RepeatedTransitionsBumpEpochEachTime) {
    MimicryShaper shaper(joint_profile_08(), kSeed);
    shaper.set_profile(StatProfile::zoom_call());
    shaper.set_profile(StatProfile::voip_opus());
    shaper.set_profile(StatProfile::youtube_stream());
    EXPECT_EQ(shaper.profile_epoch(), 3u);
    auto s = shaper.prepare_data_shape(1500);
    EXPECT_EQ(s.profile_epoch, 3u);
    // A transition mid-queue invalidates even a just-prepared shape.
    shaper.set_profile(joint_profile_08());
    EXPECT_EQ(shaper.profile_epoch(), 4u);
    PreparedShape out;
    EXPECT_FALSE(shaper.take_data_shape(out));
}

TEST(PreparedShapeTest, CancelAbortCannotLeakQueuedShape) {
    MimicryShaper shaper(joint_profile_08(), kSeed);

    // Queue a shape in epoch 0, transition, queue a NEW-epoch shape, then
    // abort: the cancelled shape must be gone for good.
    (void)shaper.prepare_data_shape(1500);
    shaper.set_profile(StatProfile::zoom_call());
    auto queued = shaper.prepare_data_shape(1500);
    ASSERT_EQ(queued.profile_epoch, 1u);
    shaper.cancel_prepared_shape();
    EXPECT_FALSE(shaper.has_prepared_shape());
    PreparedShape out;
    EXPECT_FALSE(shaper.take_data_shape(out));  // nothing leaks

    // Preparing again after the abort yields a fresh current-epoch shape.
    auto fresh = shaper.prepare_data_shape(1500);
    EXPECT_EQ(fresh.profile_epoch, 1u);
    ASSERT_TRUE(shaper.take_data_shape(out));
    EXPECT_EQ(out.bytes, fresh.bytes);
    EXPECT_FALSE(shaper.take_data_shape(out));

    // Cancel with nothing queued is a no-op.
    shaper.cancel_prepared_shape();
    EXPECT_FALSE(shaper.take_data_shape(out));
}

TEST(PreparedShapeTest, ResetClearsPreparedAndReplaysDeterministically) {
    MimicryShaper shaper(joint_profile_08(), kSeed);
    auto first = shaper.prepare_data_shape(1500);
    PreparedShape out;
    ASSERT_TRUE(shaper.take_data_shape(out));
    (void)shaper.prepare_data_shape(1500);  // queue something mid-stream

    shaper.reset(kSeed);
    EXPECT_FALSE(shaper.has_prepared_shape());
    EXPECT_EQ(shaper.profile_epoch(), 0u);  // reset is not a transition
    auto replayed = shaper.prepare_data_shape(1500);
    EXPECT_EQ(replayed.bytes, first.bytes);
    EXPECT_DOUBLE_EQ(replayed.delay_ms, first.delay_ms);
}

TEST(PreparedShapeTest, LegacyShaperApiStillWorks) {
    // Old API surface unchanged: plan/reset/profile on a legacy profile.
    MimicryShaper shaper(StatProfile::webrtc_video(), kSeed);
    EXPECT_EQ(shaper.profile().name, "webrtc_video");
    auto chunks = shaper.plan(4096);
    size_t total = 0;
    for (const auto& c : chunks) total += c.bytes;
    EXPECT_EQ(total, 4096u);
    shaper.reset(kSeed);
    auto again = shaper.plan(4096);
    ASSERT_EQ(chunks.size(), again.size());
    for (size_t i = 0; i < chunks.size(); ++i)
        EXPECT_EQ(chunks[i].bytes, again[i].bytes);
}
