#pragma once

/**
 * @file ncp_mimicry_stats.hpp
 * @brief M5 — Statistical traffic profiles for protocol mimicry
 *
 * Makes encrypted flows statistically indistinguishable from a target
 * protocol by padding packet sizes and shaping inter-packet timing.
 *
 * This is a pure math module: no networking, no crypto — only <random>.
 * The caller seeds the RNG for determinism and is responsible for
 * actually padding payloads to the planned chunk sizes.
 *
 * Built-in profiles: webrtc_video(), zoom_call(), youtube_stream(),
 * voip_opus().
 */

#include <cstdint>
#include <cstddef>
#include <random>
#include <string>
#include <vector>

namespace ncp {

// ===== Distribution kinds =====

enum class SizeDistKind {
    NORMAL,        // N(mean, stddev), clamped to [clamp_min, clamp_max]
    LOGNORMAL,     // log(X) ~ N(mean, stddev), clamped
    DISCRETE_MIX   // weighted mix of NORMAL components, clamped
};

enum class IntervalKind {
    EXPONENTIAL,   // Exp with mean `mean_ms`
    NORMAL,        // N(mean_ms, stddev_ms), clamped to >= 0
    FIXED          // always `fixed_ms`
};

// ===== Distributions =====

struct SizeDistribution {
    SizeDistKind kind = SizeDistKind::NORMAL;

    // NORMAL / LOGNORMAL parameters
    double mean = 0.0;     // NORMAL: mean; LOGNORMAL: mu of log(X)
    double stddev = 1.0;   // NORMAL: stddev; LOGNORMAL: sigma of log(X)

    // DISCRETE_MIX components (weights must sum to 1)
    struct Component {
        double weight = 0.0;
        double mean = 0.0;
        double stddev = 1.0;
    };
    std::vector<Component> components;

    // Clamping bounds applied to every sample
    double clamp_min = 64.0;
    double clamp_max = 9000.0;

    /// Analytical mean (clamping ignored) — for validation/tests.
    double theoretical_mean() const;
    /// Analytical standard deviation (clamping ignored).
    double theoretical_stddev() const;
    /// Analytical CDF at x (clamping ignored; NaN for empty mix).
    double theoretical_cdf(double x) const;
};

struct IntervalDistribution {
    IntervalKind kind = IntervalKind::EXPONENTIAL;

    double mean_ms = 33.0;    // EXPONENTIAL: mean; NORMAL: mean
    double stddev_ms = 0.0;   // NORMAL: stddev
    double fixed_ms = 20.0;   // FIXED: constant value

    double theoretical_mean() const;
    double theoretical_stddev() const;
};

// ===== Statistical profile =====

struct StatProfile {
    std::string name;
    SizeDistribution sizes;
    IntervalDistribution intervals;

    /// Sample a packet/chunk size in bytes (clamped, >= 1).
    double sample_size(std::mt19937_64& rng) const;
    /// Sample an inter-packet interval in milliseconds (>= 0).
    double sample_interval_ms(std::mt19937_64& rng) const;

    // Built-in profiles
    static StatProfile webrtc_video();
    static StatProfile zoom_call();
    static StatProfile youtube_stream();
    static StatProfile voip_opus();
};

// ===== Shaper =====

struct Chunk {
    size_t bytes = 0;
    double delay_ms = 0.0;
};

class MimicryShaper {
public:
    MimicryShaper(StatProfile profile, uint64_t seed);

    /// Split payload_len into profile-distributed chunks with delays.
    /// The final chunk is capped at the remaining bytes; padding up to
    /// the planned size is the caller's responsibility.
    std::vector<Chunk> plan(size_t payload_len);

    /// Reset the RNG to a known seed (deterministic replay).
    void reset(uint64_t seed);

    const StatProfile& profile() const noexcept { return profile_; }

private:
    StatProfile profile_;
    std::mt19937_64 rng_;
};

} // namespace ncp
