/**
 * @file ncp_mimicry_stats.cpp
 * @brief M5 — Statistical traffic profiles for protocol mimicry
 *
 * Pure math module: only <random>/<cmath>, no networking, no project deps.
 */

#include "ncp_mimicry_stats.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace ncp {

namespace {

double clampd(double v, double lo, double hi) {
    return std::min(std::max(v, lo), hi);
}

/// Standard normal CDF via erf.
double normal_cdf(double x, double mean, double stddev) {
    if (stddev <= 0.0)
        return x < mean ? 0.0 : 1.0;
    return 0.5 * (1.0 + std::erf((x - mean) / (stddev * std::sqrt(2.0))));
}

} // namespace

// ==================== SizeDistribution ====================

double SizeDistribution::theoretical_mean() const {
    switch (kind) {
        case SizeDistKind::NORMAL:
            return mean;
        case SizeDistKind::LOGNORMAL:
            return std::exp(mean + stddev * stddev / 2.0);
        case SizeDistKind::DISCRETE_MIX: {
            double m = 0.0;
            for (const auto& c : components)
                m += c.weight * c.mean;
            return m;
        }
    }
    return 0.0;
}

double SizeDistribution::theoretical_stddev() const {
    switch (kind) {
        case SizeDistKind::NORMAL:
            return stddev;
        case SizeDistKind::LOGNORMAL: {
            double s2 = stddev * stddev;
            double m = std::exp(mean + s2 / 2.0);
            return m * std::sqrt(std::exp(s2) - 1.0);
        }
        case SizeDistKind::DISCRETE_MIX: {
            double mean = theoretical_mean();
            double second = 0.0;
            for (const auto& c : components)
                second += c.weight * (c.stddev * c.stddev + c.mean * c.mean);
            double var = second - mean * mean;
            return var > 0.0 ? std::sqrt(var) : 0.0;
        }
    }
    return 0.0;
}

double SizeDistribution::theoretical_cdf(double x) const {
    switch (kind) {
        case SizeDistKind::NORMAL:
            return normal_cdf(x, mean, stddev);
        case SizeDistKind::LOGNORMAL:
            if (x <= 0.0) return 0.0;
            return normal_cdf(std::log(x), mean, stddev);
        case SizeDistKind::DISCRETE_MIX: {
            if (components.empty())
                return std::numeric_limits<double>::quiet_NaN();
            double cdf = 0.0;
            for (const auto& c : components)
                cdf += c.weight * normal_cdf(x, c.mean, c.stddev);
            return cdf;
        }
    }
    return std::numeric_limits<double>::quiet_NaN();
}

// ==================== IntervalDistribution ====================

double IntervalDistribution::theoretical_mean() const {
    switch (kind) {
        case IntervalKind::EXPONENTIAL: return mean_ms;
        case IntervalKind::NORMAL:      return mean_ms;
        case IntervalKind::FIXED:       return fixed_ms;
    }
    return 0.0;
}

double IntervalDistribution::theoretical_stddev() const {
    switch (kind) {
        case IntervalKind::EXPONENTIAL: return mean_ms;  // stddev == mean
        case IntervalKind::NORMAL:      return stddev_ms;
        case IntervalKind::FIXED:       return 0.0;
    }
    return 0.0;
}

// ==================== JointSizeIatSampler ====================

bool JointSizeIatSampler::is_valid() const noexcept {
    if (components.empty() || components.size() > kMaxComponents)
        return false;
    bool any_positive = false;
    for (const auto& c : components) {
        if (!std::isfinite(c.weight) || c.weight < 0.0)
            return false;
        if (c.weight > 0.0)
            any_positive = true;
    }
    return any_positive;
}

std::pair<double, double> JointSizeIatSampler::sample(
    std::mt19937_64& rng) const {
    if (!is_valid())
        return {kFallbackSizeBytes, kFallbackIatMs};

    // Pick a component by weight. Weights are validated non-negative and
    // finite; a hostile sum (overflow to inf) still degrades to fallback.
    double wsum = 0.0;
    for (const auto& c : components)
        wsum += c.weight;
    if (!std::isfinite(wsum) || !(wsum > 0.0))
        return {kFallbackSizeBytes, kFallbackIatMs};

    std::uniform_real_distribution<double> pick(0.0, 1.0);
    double r = pick(rng) * wsum;
    const JointSizeIatComponent* chosen = &components.back();
    for (const auto& c : components) {
        r -= c.weight;
        if (r <= 0.0) {
            chosen = &c;
            break;
        }
    }

    // Two independent standard normals via Box-Muller (one rng pair per
    // sample, so replay is deterministic for a given seed).
    constexpr double kTau = 6.283185307179586476925286766559;
    const double u1 = std::max(pick(rng), 1e-12);
    const double u2 = pick(rng);
    const double radius = std::sqrt(-2.0 * std::log(u1));
    const double z0 = radius * std::cos(kTau * u2);
    const double z1 = radius * std::sin(kTau * u2);

    double size = chosen->mu_size_bytes + chosen->l00 * z0;
    double iat = chosen->mu_iat_ms + chosen->l10 * z0 + chosen->l11 * z1;

    // is_valid() checks structure only, so a crafted model can carry
    // finite-but-huge (or NaN/Inf) component params. Mirror the 1-D IAT
    // clamp (MAX_BASE_IAT_MS): unclamped, the value would reach a sleep
    // site and stall the sender (or panic a Duration conversion).
    if (!std::isfinite(iat))
        iat = kFallbackIatMs;
    else
        iat = clampd(iat, 0.0, kMaxIatMs);
    if (!std::isfinite(size))
        size = kFallbackSizeBytes;
    size = clampd(size, 1.0, kMaxSizeBytes);

    return {size, iat};
}

double JointSizeIatSampler::component_correlation(
    const JointSizeIatComponent& c) noexcept {
    const double denom = std::sqrt(c.l10 * c.l10 + c.l11 * c.l11);
    return denom > 0.0 ? c.l10 / denom : 0.0;
}

// ==================== StatProfile sampling ====================

double StatProfile::sample_size(std::mt19937_64& rng) const {
    double v = 0.0;
    switch (sizes.kind) {
        case SizeDistKind::NORMAL: {
            std::normal_distribution<double> d(sizes.mean, sizes.stddev);
            v = d(rng);
            break;
        }
        case SizeDistKind::LOGNORMAL: {
            std::lognormal_distribution<double> d(sizes.mean, sizes.stddev);
            v = d(rng);
            break;
        }
        case SizeDistKind::DISCRETE_MIX: {
            if (sizes.components.empty()) {
                v = sizes.clamp_min;
                break;
            }
            std::uniform_real_distribution<double> pick(0.0, 1.0);
            double u = pick(rng);
            double acc = 0.0;
            const auto* chosen = &sizes.components.back();
            for (const auto& c : sizes.components) {
                acc += c.weight;
                if (u <= acc) {
                    chosen = &c;
                    break;
                }
            }
            std::normal_distribution<double> d(chosen->mean, chosen->stddev);
            v = d(rng);
            break;
        }
    }
    v = clampd(v, sizes.clamp_min, sizes.clamp_max);
    return v < 1.0 ? 1.0 : v;
}

double StatProfile::sample_interval_ms(std::mt19937_64& rng) const {
    switch (intervals.kind) {
        case IntervalKind::EXPONENTIAL: {
            std::exponential_distribution<double> d(1.0 / intervals.mean_ms);
            return d(rng);
        }
        case IntervalKind::NORMAL: {
            std::normal_distribution<double> d(intervals.mean_ms,
                                               intervals.stddev_ms);
            return std::max(0.0, d(rng));
        }
        case IntervalKind::FIXED:
            return intervals.fixed_ms;
    }
    return 0.0;
}

bool StatProfile::has_joint_size_iat() const noexcept {
    return size_iat_joint.is_valid();
}

void StatProfile::sample_size_iat(std::mt19937_64& rng,
                                  double& size_bytes_out,
                                  double& iat_ms_out) const {
    if (size_iat_joint.is_valid()) {
        const auto pair = size_iat_joint.sample(rng);
        // The joint sampler enforces the u16 wire budget [1, 65535]; on top
        // of that apply the profile's declared size clamps so plan()/prepare
        // stay within this StatProfile's [clamp_min, clamp_max] envelope.
        double size = clampd(pair.first, sizes.clamp_min, sizes.clamp_max);
        size_bytes_out = size < 1.0 ? 1.0 : size;
        iat_ms_out = pair.second;
        return;
    }
    // Legacy path: independent marginals, size sampled before the interval —
    // identical rng consumption and values to the pre-joint implementation.
    size_bytes_out = sample_size(rng);
    iat_ms_out = sample_interval_ms(rng);
}

// ==================== Built-in profiles ====================

StatProfile StatProfile::webrtc_video() {
    StatProfile p;
    p.name = "webrtc_video";
    // Mix of N(1200,180) 90% + N(400,80) 8% + keyframe spike N(8000,1500) 2%.
    p.sizes.kind = SizeDistKind::DISCRETE_MIX;
    p.sizes.components = {
        {0.90, 1200.0, 180.0},
        {0.08,  400.0,  80.0},
        {0.02, 8000.0, 1500.0},
    };
    p.sizes.clamp_min = 64.0;
    p.sizes.clamp_max = 9000.0;
    // ~30 fps video: Exp(mean 33 ms).
    p.intervals.kind = IntervalKind::EXPONENTIAL;
    p.intervals.mean_ms = 33.0;
    return p;
}

StatProfile StatProfile::zoom_call() {
    StatProfile p;
    p.name = "zoom_call";
    // Video frames with occasional large IDR spikes.
    p.sizes.kind = SizeDistKind::DISCRETE_MIX;
    p.sizes.components = {
        {0.80,  900.0, 120.0},
        {0.15,  300.0,  60.0},
        {0.05, 6000.0, 900.0},
    };
    p.sizes.clamp_min = 64.0;
    p.sizes.clamp_max = 9000.0;
    p.intervals.kind = IntervalKind::EXPONENTIAL;
    p.intervals.mean_ms = 25.0;
    return p;
}

StatProfile StatProfile::youtube_stream() {
    StatProfile p;
    p.name = "youtube_stream";
    // Chunked media segments: log-normal body sizes.
    p.sizes.kind = SizeDistKind::LOGNORMAL;
    p.sizes.mean = 7.0;    // mu of log(X): mean ~ 1246 bytes
    p.sizes.stddev = 0.5;  // sigma of log(X)
    p.sizes.clamp_min = 64.0;
    p.sizes.clamp_max = 9000.0;
    p.intervals.kind = IntervalKind::NORMAL;
    p.intervals.mean_ms = 40.0;
    p.intervals.stddev_ms = 10.0;
    return p;
}

StatProfile StatProfile::voip_opus() {
    StatProfile p;
    p.name = "voip_opus";
    // Opus voice frames: N(160, 20) bytes, fixed 20 ms cadence.
    p.sizes.kind = SizeDistKind::NORMAL;
    p.sizes.mean = 160.0;
    p.sizes.stddev = 20.0;
    p.sizes.clamp_min = 64.0;
    p.sizes.clamp_max = 9000.0;
    p.intervals.kind = IntervalKind::FIXED;
    p.intervals.fixed_ms = 20.0;
    return p;
}

// ==================== MimicryShaper ====================

MimicryShaper::MimicryShaper(StatProfile profile, uint64_t seed)
    : profile_(std::move(profile)), rng_(seed) {}

std::vector<Chunk> MimicryShaper::plan(size_t payload_len) {
    std::vector<Chunk> chunks;
    size_t remaining = payload_len;
    while (remaining > 0) {
        // sample_size_iat() keeps the legacy (size-then-interval) rng
        // consumption for profiles without a joint model, so legacy plans
        // are bit-identical; with a joint model each chunk is a correlated
        // (size, iat) pair.
        double sample = 0.0, iat = 0.0;
        profile_.sample_size_iat(rng_, sample, iat);
        size_t chunk = static_cast<size_t>(std::llround(sample));
        if (chunk == 0) chunk = 1;
        if (chunk > remaining) chunk = remaining;

        Chunk c;
        c.bytes = chunk;
        c.delay_ms = iat;
        chunks.push_back(c);

        remaining -= chunk;
    }
    return chunks;
}

void MimicryShaper::reset(uint64_t seed) {
    rng_.seed(seed);
    // A queued shape derives from the old rng stream; drop it so replay
    // starts from a clean slate.
    prepared_valid_ = false;
}

void MimicryShaper::set_profile(StatProfile profile) {
    profile_ = std::move(profile);
    ++profile_epoch_;
    // Stale-epoch shapes must never be consumed after a transition, and a
    // shape queued under the previous epoch must not leak into the new one.
    prepared_valid_ = false;
}

PreparedShape MimicryShaper::prepare_data_shape(size_t mtu_bytes) {
    if (prepared_valid_)
        return prepared_;

    double size = 0.0, iat = 0.0;
    profile_.sample_size_iat(rng_, size, iat);

    // MTU/budget validation: the prepared packet must fit the caller's
    // per-packet budget. A zero budget is invalid input; degrade to a
    // 1-byte minimum instead of emitting an empty packet.
    const size_t mtu = mtu_bytes == 0 ? 1 : mtu_bytes;
    long long bytes = static_cast<long long>(std::llround(size));
    if (bytes < 1) bytes = 1;
    if (static_cast<unsigned long long>(bytes) >
        static_cast<unsigned long long>(mtu))
        bytes = static_cast<long long>(mtu);

    PreparedShape s;
    s.bytes = static_cast<size_t>(bytes);
    // Defensive pacing cap, mirroring the joint sampler / MAX_BASE_IAT_MS
    // clamp: a non-finite or huge delay must never reach a sleep site.
    if (!std::isfinite(iat))
        iat = JointSizeIatSampler::kFallbackIatMs;
    s.delay_ms = clampd(iat, 0.0, kMaxPreparedIatMs);
    s.profile_epoch = profile_epoch_;

    prepared_ = s;
    prepared_valid_ = true;
    return s;
}

bool MimicryShaper::take_data_shape(PreparedShape& out) {
    if (!prepared_valid_)
        return false;
    if (prepared_.profile_epoch != profile_epoch_) {
        // Stale epoch: drop without consuming (defense in depth —
        // set_profile() already clears the queue on every transition).
        prepared_valid_ = false;
        return false;
    }
    out = prepared_;
    prepared_valid_ = false;
    return true;
}

void MimicryShaper::cancel_prepared_shape() noexcept {
    prepared_valid_ = false;
}

} // namespace ncp
