#pragma once
#ifndef NCP_ERGODIC_HPP
#define NCP_ERGODIC_HPP

/// @file ncp_ergodic.hpp
/// @brief Ergodic transformations for traffic mixing.
///
/// Implements measure-preserving transformations that guarantee uniform
/// distribution in the limit (Birkhoff ergodic theorem):
///
/// Arnold cat map:  [x'] = [2 1] [x]  mod 1   (det = 1, Anosov diffeomorphism)
///                  [y']   [1 1] [y]
///
/// Baker map:       Stretches and folds the unit square, equivalent to
///                  the shift on bi-infinite binary sequences.
///
/// Irrational rotation on the torus T²:
///   x → x + α (mod 1),  y → y + β (mod 1)
/// where α, β are irrational (golden ratio). Unique ergodicity ⟹
/// time averages = space averages (Birkhoff theorem).
///
/// The mixing time τ_mix is estimated from autocorrelation decay.
/// Stealth guarantee: if τ_mix << observation window, the DPI sees
/// only the invariant measure (uniform), not our data.

#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <string>

namespace ncp {
namespace Math {

struct ErgodicConfig {
    enum class MapType { ARNOLD, BAKER, IRRATIONAL_ROTATION };

    MapType map_type = MapType::ARNOLD;
    int iterations = 100;
    double alpha = 0.0;   ///< For irrational rotation: first angle
    double beta = 0.0;    ///< For irrational rotation: second angle
    bool use_golden_ratio = true;  ///< α = (√5-1)/2, β = (√5-1)/3
};

struct ErgodicResult {
    std::vector<double> data;
    double convergence = 0.0;   ///< Birkhoff convergence rate
    double mixing_time = 0.0;   ///< Estimated mixing time
    double stealth_guarantee = 0.0;  ///< 1 - max autocorrelation
    bool success = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// ERGODIC SHAPER
// ═══════════════════════════════════════════════════════════════════════════

class ErgodicShaper {
public:
    ErgodicShaper() { init_golden_ratio(); }
    explicit ErgodicShaper(const ErgodicConfig& config) : config_(config) {
        if (config_.use_golden_ratio) init_golden_ratio();
    }

    /// Apply Arnold cat map to (x, y) for n iterations.
    /// x, y should be in [0, 1).
    static std::pair<double, double> arnold_cat_map(
        double x, double y, int iterations = 1);

    /// Apply Baker map to (x, y) for n iterations.
    static std::pair<double, double> baker_map(
        double x, double y, int iterations = 1);

    /// Apply irrational rotation to (x, y).
    std::pair<double, double> irrational_rotation(
        double x, double y, int iterations = 1) const;

    /// Transform data through ergodic map.
    /// Data values are mapped to [0,1)² and iterated.
    ErgodicResult transform(const std::vector<double>& data);

    /// Compute Birkhoff convergence rate.
    /// Measures how quickly time averages converge to space averages.
    double birkhoff_convergence(const std::vector<double>& data) const;

    /// Estimate mixing time from autocorrelation decay.
    double mixing_time_estimate(const std::vector<double>& data) const;

    /// Compute stealth guarantee: 1 - max|autocorrelation|.
    double ergodic_guarantee(const std::vector<double>& data) const;

    /// Compute autocorrelation at lag k.
    static double autocorrelation(const std::vector<double>& data, int lag);

    const ErgodicConfig& config() const { return config_; }
    void set_config(const ErgodicConfig& c) { config_ = c; }

private:
    ErgodicConfig config_;

    void init_golden_ratio() {
        double sqrt5 = std::sqrt(5.0);
        config_.alpha = (sqrt5 - 1.0) / 2.0;   // ≈ 0.6180339887
        config_.beta = (sqrt5 - 1.0) / 3.0;    // ≈ 0.4120226591
    }

    /// Map data values to [0, 1) range.
    static std::vector<double> normalize_to_unit(const std::vector<double>& data);
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline std::pair<double, double> ErgodicShaper::arnold_cat_map(
    double x, double y, int iterations) {
    // [x'] = [2 1] [x]  mod 1
    // [y']   [1 1] [y]
    for (int i = 0; i < iterations; ++i) {
        double nx = std::fmod(2.0 * x + y, 1.0);
        double ny = std::fmod(x + y, 1.0);
        if (nx < 0) nx += 1.0;
        if (ny < 0) ny += 1.0;
        x = nx;
        y = ny;
    }
    return {x, y};
}

inline std::pair<double, double> ErgodicShaper::baker_map(
    double x, double y, int iterations) {
    // Baker map: stretch x by 2, fold
    // If x < 0.5: x' = 2x, y' = y/2
    // If x >= 0.5: x' = 2x-1, y' = (y+1)/2
    for (int i = 0; i < iterations; ++i) {
        double nx, ny;
        if (x < 0.5) {
            nx = 2.0 * x;
            ny = y / 2.0;
        } else {
            nx = 2.0 * x - 1.0;
            ny = (y + 1.0) / 2.0;
        }
        x = nx;
        y = ny;
    }
    return {x, y};
}

inline std::pair<double, double> ErgodicShaper::irrational_rotation(
    double x, double y, int iterations) const {
    for (int i = 0; i < iterations; ++i) {
        x = std::fmod(x + config_.alpha, 1.0);
        y = std::fmod(y + config_.beta, 1.0);
        if (x < 0) x += 1.0;
        if (y < 0) y += 1.0;
    }
    return {x, y};
}

inline std::vector<double> ErgodicShaper::normalize_to_unit(
    const std::vector<double>& data) {
    if (data.empty()) return {};

    double min_val = *std::min_element(data.begin(), data.end());
    double max_val = *std::max_element(data.begin(), data.end());
    double range = max_val - min_val;

    std::vector<double> result(data.size());
    if (range < 1e-15) {
        std::fill(result.begin(), result.end(), 0.5);
        return result;
    }

    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = (data[i] - min_val) / range;
        // Clamp to (0, 1) to avoid boundary issues
        result[i] = std::max(1e-10, std::min(1.0 - 1e-10, result[i]));
    }
    return result;
}

inline ErgodicResult ErgodicShaper::transform(const std::vector<double>& data) {
    ErgodicResult result;
    size_t n = data.size();

    if (n < 2) {
        result.error_msg = "Data too short";
        return result;
    }

    // Normalize to [0, 1)
    auto normalized = normalize_to_unit(data);

    // Apply ergodic map to pairs
    result.data.resize(n);
    int iters = config_.iterations;

    switch (config_.map_type) {
        case ErgodicConfig::MapType::ARNOLD: {
            for (size_t i = 0; i + 1 < n; i += 2) {
                auto [nx, ny] = arnold_cat_map(normalized[i], normalized[i+1], iters);
                result.data[i] = nx;
                result.data[i+1] = ny;
            }
            if (n % 2 != 0) {
                auto [nx, ny] = arnold_cat_map(normalized[n-1], 0.5, iters);
                result.data[n-1] = nx;
            }
            break;
        }
        case ErgodicConfig::MapType::BAKER: {
            for (size_t i = 0; i + 1 < n; i += 2) {
                auto [nx, ny] = baker_map(normalized[i], normalized[i+1], iters);
                result.data[i] = nx;
                result.data[i+1] = ny;
            }
            if (n % 2 != 0) {
                auto [nx, ny] = baker_map(normalized[n-1], 0.5, iters);
                result.data[n-1] = nx;
            }
            break;
        }
        case ErgodicConfig::MapType::IRRATIONAL_ROTATION: {
            for (size_t i = 0; i + 1 < n; i += 2) {
                auto [nx, ny] = irrational_rotation(normalized[i], normalized[i+1], iters);
                result.data[i] = nx;
                result.data[i+1] = ny;
            }
            if (n % 2 != 0) {
                auto [nx, ny] = irrational_rotation(normalized[n-1], 0.5, iters);
                result.data[n-1] = nx;
            }
            break;
        }
    }

    // Rescale back to original range
    double orig_min = *std::min_element(data.begin(), data.end());
    double orig_max = *std::max_element(data.begin(), data.end());
    double orig_range = orig_max - orig_min;

    for (double& v : result.data) {
        v = orig_min + v * orig_range;
    }

    // Compute metrics
    result.convergence = birkhoff_convergence(result.data);
    result.mixing_time = mixing_time_estimate(result.data);
    result.stealth_guarantee = ergodic_guarantee(result.data);
    result.success = true;

    return result;
}

inline double ErgodicShaper::autocorrelation(const std::vector<double>& data, int lag) {
    size_t n = data.size();
    if (n < 2 || lag >= static_cast<int>(n)) return 0.0;

    double mean = 0.0;
    for (double v : data) mean += v;
    mean /= n;

    double var = 0.0;
    double cov = 0.0;
    for (size_t i = 0; i < n; ++i) {
        var += (data[i] - mean) * (data[i] - mean);
    }
    var /= n;

    if (var < 1e-15) return 0.0;

    size_t abs_lag = static_cast<size_t>(std::abs(lag));
    for (size_t i = 0; i + abs_lag < n; ++i) {
        cov += (data[i] - mean) * (data[i + abs_lag] - mean);
    }
    cov /= (n - abs_lag);

    return cov / var;
}

inline double ErgodicShaper::birkhoff_convergence(const std::vector<double>& data) const {
    // Measure how quickly running averages converge to the final average
    size_t n = data.size();
    if (n < 10) return 0.0;

    double final_mean = 0.0;
    for (double v : data) final_mean += v;
    final_mean /= n;

    // Compute max deviation of running mean from final mean
    double max_deviation = 0.0;
    double running_sum = 0.0;

    for (size_t i = 0; i < n; ++i) {
        running_sum += data[i];
        double running_mean = running_sum / (i + 1);
        double deviation = std::abs(running_mean - final_mean);
        if (deviation > max_deviation) max_deviation = deviation;
    }

    // Convergence rate: 1 / (1 + max_deviation)
    // Higher = faster convergence = better mixing
    return 1.0 / (1.0 + max_deviation * std::sqrt(static_cast<double>(n)));
}

inline double ErgodicShaper::mixing_time_estimate(const std::vector<double>& data) const {
    // Estimate mixing time from autocorrelation decay
    // Find first lag where |autocorrelation| < 1/e
    size_t n = data.size();
    if (n < 10) return 0.0;

    double threshold = 1.0 / std::exp(1.0);  // ≈ 0.368

    for (int lag = 1; lag < std::min(static_cast<int>(n) / 4, 100); ++lag) {
        double ac = std::abs(autocorrelation(data, lag));
        if (ac < threshold) {
            return static_cast<double>(lag);
        }
    }

    return static_cast<double>(std::min(static_cast<int>(n) / 4, 100));
}

inline double ErgodicShaper::ergodic_guarantee(const std::vector<double>& data) const {
    // Stealth guarantee: 1 - max|autocorrelation(lag > 0)|
    size_t n = data.size();
    if (n < 10) return 0.0;

    double max_ac = 0.0;
    int max_lag = std::min(static_cast<int>(n) / 4, 50);

    for (int lag = 1; lag < max_lag; ++lag) {
        double ac = std::abs(autocorrelation(data, lag));
        if (ac > max_ac) max_ac = ac;
    }

    return 1.0 - max_ac;
}

} // namespace Math
} // namespace ncp

#endif // NCP_ERGODIC_HPP
