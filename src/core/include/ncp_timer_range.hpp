#pragma once

/**
 * @file ncp_timer_range.hpp
 * @brief Timers-as-ranges (AWG 3.1 analogue) — header-only.
 *
 * AmneziaWG 3.1 turns protocol timers (RekeyAfterTime, KeepaliveTimeout,
 * etc.) into *ranges* sampled per use, so ML classifiers cannot lock onto
 * fixed timer constants. This header provides the same primitive for NCP:
 *
 *   TimerRange keepalive{15000, 45000};   // ms
 *   sleep(keepalive.sample());
 *
 * Sampling uses libsodium's CSPRNG (randombytes_uniform). Parsing accepts
 * "250" (fixed) or "100-500" (range), matching the CLI convention used by
 * --hop-interval and friends.
 */

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

#include <sodium.h>

namespace ncp {

struct TimerRange {
    double min_ms = 0.0;
    double max_ms = 0.0;

    /// Fixed timer (min == max).
    static TimerRange fixed(double ms) { return TimerRange{ms, ms}; }

    /// Parse "250" or "100-500" (milliseconds). nullopt on bad input.
    static std::optional<TimerRange> parse(const std::string& spec) {
        if (spec.empty())
            return std::nullopt;
        const size_t dash = spec.find('-');
        try {
            if (dash == std::string::npos) {
                const double v = std::stod(spec);
                if (v < 0) return std::nullopt;
                return TimerRange{v, v};
            }
            const double lo = std::stod(spec.substr(0, dash));
            const double hi = std::stod(spec.substr(dash + 1));
            if (lo < 0 || hi < lo) return std::nullopt;
            return TimerRange{lo, hi};
        } catch (...) {
            return std::nullopt;
        }
    }

    bool is_range() const noexcept { return max_ms > min_ms; }

    /// Uniform sample in [min_ms, max_ms] via CSPRNG.
    double sample() const {
        if (max_ms <= min_ms)
            return min_ms;
        // Sample on integer microseconds for uniform coverage.
        const uint64_t lo = static_cast<uint64_t>(min_ms * 1000.0);
        const uint64_t hi = static_cast<uint64_t>(max_ms * 1000.0);
        const uint64_t span = hi - lo + 1;
        const uint64_t v = lo + randombytes_uniform(static_cast<uint32_t>(
            span > UINT32_MAX ? UINT32_MAX : span));
        return static_cast<double>(v) / 1000.0;
    }

    std::chrono::milliseconds sample_ms() const {
        return std::chrono::milliseconds(static_cast<int64_t>(sample()));
    }

    std::chrono::seconds sample_sec() const {
        return std::chrono::seconds(static_cast<int64_t>(sample() / 1000.0));
    }
};

} // namespace ncp
