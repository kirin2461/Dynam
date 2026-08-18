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
        double sample = profile_.sample_size(rng_);
        size_t chunk = static_cast<size_t>(std::llround(sample));
        if (chunk == 0) chunk = 1;
        if (chunk > remaining) chunk = remaining;

        Chunk c;
        c.bytes = chunk;
        c.delay_ms = profile_.sample_interval_ms(rng_);
        chunks.push_back(c);

        remaining -= chunk;
    }
    return chunks;
}

void MimicryShaper::reset(uint64_t seed) {
    rng_.seed(seed);
}

} // namespace ncp
