#pragma once
#ifndef NCP_FRACTAL_HPP
#define NCP_FRACTAL_HPP

/// @file ncp_fractal.hpp
/// @brief Fractal traffic generation via fractional Gaussian noise.
///
/// Davies-Harte method (circulant embedding) generates exactly self-similar
/// sequences with prescribed Hurst exponent H ∈ (0,1).
///
/// The autocovariance of fGn is:
///   γ(k) = 0.5 σ² ( |k-1|^{2H} - 2|k|^{2H} + |k+1|^{2H} )
///
/// Davies-Harte embeds the n×n covariance matrix into a 2n×2n circulant,
/// whose eigenvalues are the DFT of the first row. We take square roots of
/// non-negative eigenvalues, multiply by complex Gaussian noise, and inverse
/// DFT. The real part of the first n components is a sample from the
/// desired distribution.
///
/// R/S analysis estimates H from observed data via the rescaled range:
///   (R/S)_n ~ c · n^H
///
/// MF-DFA computes the multifractal spectrum h(q) by detrended fluctuation
/// analysis at multiple scales and moment orders.
///
/// Reference:
///   Davies R.B., Harte R.B. (1987). "Tests for Hurst effect in a time series."
///   Biometrika 74(1): 95-101.

#include <vector>
#include <complex>
#include <cmath>
#include <random>
#include <algorithm>
#include <numeric>
#include <cassert>
#include <string>
#include <functional>

namespace ncp {
namespace Math {

/// Configuration for fractal traffic generation.
struct FractalConfig {
    double hurst = 0.75;          ///< Target Hurst exponent ∈ (0, 1)
    size_t length = 1024;          ///< Length of generated sequence
    double sigma = 1.0;            ///< Standard deviation scaling
    bool normalize = true;         ///< Normalize output to zero mean, unit variance
    unsigned seed = 0;             ///< RNG seed (0 = random device)
};

/// Result of fractal analysis.
struct FractalResult {
    std::vector<double> data;      ///< Generated / transformed data
    double hurst_estimate = 0.0;   ///< Estimated Hurst exponent
    double hurst_error = 0.0;      ///< Error of Hurst estimate
    double multifractal_width = 0.0; ///< Width of multifractal spectrum
    bool success = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// FRACTAL TRAFFIC GENERATOR
// ═══════════════════════════════════════════════════════════════════════════

class FractalTrafficGenerator {
public:
    FractalTrafficGenerator() = default;
    explicit FractalTrafficGenerator(const FractalConfig& config)
        : config_(config) {}

    /// Generate fractional Gaussian noise using Davies-Harte method.
    /// Returns vector of length config.length.
    FractalResult generate_fgn();

    /// Generate fGn with specific parameters (overrides config).
    FractalResult generate_fgn(size_t length, double hurst);

    /// Match observed data to target Hurst exponent.
    /// Returns reshaped data with the target self-similarity structure.
    FractalResult match_distribution(double target_hurst, size_t length);

    /// Compute Hurst exponent via R/S analysis.
    double compute_hurst(const std::vector<double>& data);

    /// Compute multifractal spectrum via MF-DFA.
    /// Returns vector of h(q) for q in q_range.
    std::vector<double> multifractal_spectrum(
        const std::vector<double>& data,
        const std::vector<double>& q_range = default_q_range());

    /// Compute multifractal spectrum width (h_max - h_min).
    double compute_mf_width(const std::vector<double>& data);

    /// Apply fractal structure to traffic data.
    /// Modifies timing/sizes to match target Hurst.
    FractalResult transform(const std::vector<double>& data, double target_hurst);

    const FractalConfig& config() const { return config_; }
    void set_config(const FractalConfig& c) { config_ = c; }

    /// Default q-range for MF-DFA: -5 to 5 in steps of 0.5.
    static std::vector<double> default_q_range() {
        std::vector<double> q;
        for (double v = -5.0; v <= 5.0; v += 0.5) {
            if (std::abs(v) > 0.01) q.push_back(v);
        }
        return q;
    }

private:
    FractalConfig config_;

    /// Autocovariance function of fGn: γ(k) for lag k.
    double autocovariance(int k, double H, double sigma) const;

    /// Build circulant first row for Davies-Harte embedding.
    std::vector<double> build_circulant_row(size_t n, double H, double sigma) const;

    /// Simple Cooley-Tukey FFT (radix-2, in-place).
    /// n must be a power of 2.
    void fft(std::vector<std::complex<double>>& x, bool inverse) const;

    /// Next power of 2 >= n.
    static size_t next_pow2(size_t n);

    /// R/S analysis helper: compute R/S for a single block size.
    double rs_for_block_size(const std::vector<double>& data, size_t block_size) const;

    /// Linear regression: y = a + b*x. Returns (a, b, r_squared).
    static std::tuple<double, double, double> linear_regression(
        const std::vector<double>& x,
        const std::vector<double>& y);
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline double FractalTrafficGenerator::autocovariance(int k, double H, double sigma) const {
    double k_abs = std::abs(static_cast<double>(k));
    double k_plus = std::abs(static_cast<double>(k) + 1.0);
    double k_minus = std::abs(static_cast<double>(k) - 1.0);

    double two_H = 2.0 * H;
    double gamma = 0.5 * sigma * sigma *
        (std::pow(k_minus, two_H) - 2.0 * std::pow(k_abs, two_H) + std::pow(k_plus, two_H));

    return gamma;
}

inline size_t FractalTrafficGenerator::next_pow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

inline void FractalTrafficGenerator::fft(std::vector<std::complex<double>>& x, bool inverse) const {
    size_t n = x.size();
    if (n <= 1) return;

    // Bit-reversal permutation
    for (size_t i = 1, j = 0; i < n; ++i) {
        size_t bit = n >> 1;
        for (; j & bit; bit >>= 1) {
            j ^= bit;
        }
        j ^= bit;
        if (i < j) std::swap(x[i], x[j]);
    }

    // Cooley-Tukey
    for (size_t len = 2; len <= n; len <<= 1) {
        double angle = 2.0 * M_PI / len * (inverse ? -1.0 : 1.0);
        std::complex<double> wlen(std::cos(angle), std::sin(angle));
        for (size_t i = 0; i < n; i += len) {
            std::complex<double> w(1.0);
            for (size_t j = 0; j < len / 2; ++j) {
                auto u = x[i + j];
                auto v = x[i + j + len / 2] * w;
                x[i + j] = u + v;
                x[i + j + len / 2] = u - v;
                w *= wlen;
            }
        }
    }

    if (inverse) {
        for (auto& v : x) v /= static_cast<double>(n);
    }
}

inline std::vector<double> FractalTrafficGenerator::build_circulant_row(
    size_t n, double H, double sigma) const {
    // Circulant first row of length 2n:
    // c = [γ(0), γ(1), ..., γ(n-1), γ(n), γ(n-1), ..., γ(1)]
    std::vector<double> c(2 * n);
    for (size_t k = 0; k <= n; ++k) {
        c[k] = autocovariance(static_cast<int>(k), H, sigma);
    }
    for (size_t k = 1; k < n; ++k) {
        c[2 * n - k] = c[k];
    }
    return c;
}

inline FractalResult FractalTrafficGenerator::generate_fgn() {
    return generate_fgn(config_.length, config_.hurst);
}

inline FractalResult FractalTrafficGenerator::generate_fgn(size_t length, double hurst) {
    FractalResult result;

    if (hurst <= 0.0 || hurst >= 1.0) {
        result.error_msg = "Hurst exponent must be in (0, 1)";
        return result;
    }
    if (length < 4) {
        result.error_msg = "Length must be at least 4";
        return result;
    }

    // Pad to power of 2 for FFT
    size_t n = next_pow2(length);
    size_t m = 2 * n;

    // Build circulant row
    auto c = build_circulant_row(n, hurst, config_.sigma);

    // Eigenvalues = FFT of circulant first row
    std::vector<std::complex<double>> eigenvalues(m);
    for (size_t i = 0; i < m; ++i) {
        eigenvalues[i] = (i < c.size()) ? std::complex<double>(c[i], 0.0) : std::complex<double>(0.0, 0.0);
    }
    fft(eigenvalues, false);

    // Check non-negativity and take square roots
    std::vector<double> sqrt_eigenvalues(m);
    for (size_t i = 0; i < m; ++i) {
        double re = eigenvalues[i].real();
        if (re < 0.0) {
            // Small negative eigenvalues are numerical artifacts; clamp to zero
            if (re > -1e-10) {
                sqrt_eigenvalues[i] = 0.0;
            } else {
                result.error_msg = "Negative eigenvalue in circulant embedding";
                return result;
            }
        } else {
            sqrt_eigenvalues[i] = std::sqrt(re);
        }
    }

    // Generate complex Gaussian noise
    std::mt19937 rng;
    if (config_.seed != 0) {
        rng.seed(config_.seed);
    } else {
        std::random_device rd;
        rng.seed(rd());
    }
    std::normal_distribution<double> normal(0.0, 1.0);

    std::vector<std::complex<double>> z(m);
    for (size_t i = 0; i < m; ++i) {
        z[i] = std::complex<double>(normal(rng), normal(rng));
    }

    // Multiply: w = sqrt(eigenvalues) * z
    std::vector<std::complex<double>> w(m);
    for (size_t i = 0; i < m; ++i) {
        w[i] = sqrt_eigenvalues[i] * z[i];
    }

    // Inverse FFT to get fGn
    fft(w, true);

    // Extract real part, take first 'length' samples
    result.data.resize(length);
    for (size_t i = 0; i < length; ++i) {
        result.data[i] = w[i].real();
    }

    // Normalize if requested
    if (config_.normalize && length > 1) {
        double mean = 0.0;
        for (double v : result.data) mean += v;
        mean /= length;

        double var = 0.0;
        for (double& v : result.data) {
            v -= mean;
            var += v * v;
        }
        var /= length;
        double std_dev = std::sqrt(var);

        if (std_dev > 1e-15) {
            for (double& v : result.data) {
                v = v / std_dev * config_.sigma;
            }
        }
    }

    // Estimate Hurst of generated data
    result.hurst_estimate = compute_hurst(result.data);
    result.hurst_error = std::abs(result.hurst_estimate - hurst);
    result.success = true;

    return result;
}

inline double FractalTrafficGenerator::compute_hurst(const std::vector<double>& data) {
    if (data.size() < 20) return 0.5;

    // R/S analysis over multiple block sizes
    // Block sizes: powers of 2 from 8 to N/2
    std::vector<double> log_n, log_rs;

    for (size_t block_size = 8; block_size <= data.size() / 2; block_size *= 2) {
        double rs = rs_for_block_size(data, block_size);
        if (rs > 0.0) {
            log_n.push_back(std::log(static_cast<double>(block_size)));
            log_rs.push_back(std::log(rs));
        }
    }

    if (log_n.size() < 3) return 0.5;

    // H = slope of log(R/S) vs log(n)
    auto [a, b, r2] = linear_regression(log_n, log_rs);
    return b;
}

inline double FractalTrafficGenerator::rs_for_block_size(
    const std::vector<double>& data, size_t block_size) const {

    size_t n_blocks = data.size() / block_size;
    if (n_blocks == 0) return 0.0;

    double total_rs = 0.0;
    size_t count = 0;

    for (size_t b = 0; b < n_blocks; ++b) {
        size_t start = b * block_size;

        // Mean of block
        double mean = 0.0;
        for (size_t i = 0; i < block_size; ++i) {
            mean += data[start + i];
        }
        mean /= block_size;

        // Standard deviation
        double var = 0.0;
        for (size_t i = 0; i < block_size; ++i) {
            double d = data[start + i] - mean;
            var += d * d;
        }
        var /= block_size;
        double s = std::sqrt(var);

        if (s < 1e-15) continue;

        // Cumulative deviation from mean
        double cumdev = 0.0;
        double max_cumdev = -1e300, min_cumdev = 1e300;
        for (size_t i = 0; i < block_size; ++i) {
            cumdev += data[start + i] - mean;
            if (cumdev > max_cumdev) max_cumdev = cumdev;
            if (cumdev < min_cumdev) min_cumdev = cumdev;
        }

        // Range
        double R = max_cumdev - min_cumdev;
        total_rs += R / s;
        ++count;
    }

    return (count > 0) ? total_rs / count : 0.0;
}

inline std::tuple<double, double, double> FractalTrafficGenerator::linear_regression(
    const std::vector<double>& x,
    const std::vector<double>& y) {

    size_t n = x.size();
    if (n < 2 || n != y.size()) return {0.0, 0.0, 0.0};

    double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0, sum_y2 = 0.0;
    for (size_t i = 0; i < n; ++i) {
        sum_x += x[i];
        sum_y += y[i];
        sum_xy += x[i] * y[i];
        sum_x2 += x[i] * x[i];
        sum_y2 += y[i] * y[i];
    }

    double dn = static_cast<double>(n);
    double denom = dn * sum_x2 - sum_x * sum_x;
    if (std::abs(denom) < 1e-15) return {0.0, 0.0, 0.0};

    double b = (dn * sum_xy - sum_x * sum_y) / denom;
    double a = (sum_y - b * sum_x) / dn;

    // R-squared
    double mean_y = sum_y / dn;
    double ss_tot = sum_y2 - dn * mean_y * mean_y;
    double ss_res = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double pred = a + b * x[i];
        ss_res += (y[i] - pred) * (y[i] - pred);
    }

    double r2 = (ss_tot > 1e-15) ? 1.0 - ss_res / ss_tot : 0.0;

    return {a, b, r2};
}

inline std::vector<double> FractalTrafficGenerator::multifractal_spectrum(
    const std::vector<double>& data,
    const std::vector<double>& q_range) {

    // MF-DFA: for each q, compute h(q) via fluctuation function.
    //
    // Steps:
    // 1. Compute profile Y(k) = sum_{i=1}^{k} (x_i - <x>)
    // 2. For each scale s, divide profile into blocks of size s
    // 3. Detrend each block with polynomial fit (order 1 = linear)
    // 4. Compute fluctuation: F^2(q, s) = { 1/N_s * sum [variance]^{q/2} }^{1/q}
    // 5. h(q) = slope of log F(q, s) vs log s

    std::vector<double> h_values;
    size_t N = data.size();
    if (N < 100) {
        return std::vector<double>(q_range.size(), 0.5);
    }

    // Compute profile
    double mean = 0.0;
    for (double v : data) mean += v;
    mean /= N;

    std::vector<double> profile(N);
    double cumsum = 0.0;
    for (size_t i = 0; i < N; ++i) {
        cumsum += data[i] - mean;
        profile[i] = cumsum;
    }

    // Scales: powers of 2 from 10 to N/4
    std::vector<size_t> scales;
    for (size_t s = 10; s <= N / 4; s *= 2) {
        scales.push_back(s);
    }
    if (scales.size() < 3) {
        return std::vector<double>(q_range.size(), 0.5);
    }

    // For each q, compute h(q)
    for (double q : q_range) {
        std::vector<double> log_s, log_Fq;

        for (size_t s : scales) {
            size_t n_blocks = N / s;
            if (n_blocks < 2) continue;

            double F2_sum = 0.0;

            for (size_t b = 0; b < n_blocks; ++b) {
                size_t start = b * s;

                // Linear detrending of block
                double bx = 0.0, by = 0.0, bxx = 0.0, bxy = 0.0;
                for (size_t i = 0; i < s; ++i) {
                    double xi = static_cast<double>(i);
                    double yi = profile[start + i];
                    bx += xi;
                    by += yi;
                    bxx += xi * xi;
                    bxy += xi * yi;
                }
                double ds = static_cast<double>(s);
                double det = ds * bxx - bx * bx;
                double slope = 0.0, intercept = 0.0;
                if (std::abs(det) > 1e-15) {
                    slope = (ds * bxy - bx * by) / det;
                    intercept = (by - slope * bx) / ds;
                }

                // Variance of detrended block
                double variance = 0.0;
                for (size_t i = 0; i < s; ++i) {
                    double xi = static_cast<double>(i);
                    double trend = intercept + slope * xi;
                    double residual = profile[start + i] - trend;
                    variance += residual * residual;
                }
                variance /= s;

                // F^2(q, s) contribution
                if (q == 2.0) {
                    F2_sum += variance;
                } else if (variance > 1e-15) {
                    F2_sum += std::pow(variance, q / 2.0);
                }
            }

            F2_sum /= n_blocks;

            if (F2_sum > 1e-15) {
                double Fq;
                if (q == 2.0) {
                    Fq = std::sqrt(F2_sum);
                } else {
                    Fq = std::pow(F2_sum, 1.0 / q);
                }
                log_s.push_back(std::log(static_cast<double>(s)));
                log_Fq.push_back(std::log(Fq));
            }
        }

        if (log_s.size() >= 3) {
            auto [a, b, r2] = linear_regression(log_s, log_Fq);
            h_values.push_back(b);
        } else {
            h_values.push_back(0.5);
        }
    }

    return h_values;
}

inline double FractalTrafficGenerator::compute_mf_width(const std::vector<double>& data) {
    auto q_range = default_q_range();
    auto h = multifractal_spectrum(data, q_range);

    if (h.empty()) return 0.0;

    double h_min = *std::min_element(h.begin(), h.end());
    double h_max = *std::max_element(h.begin(), h.end());

    return h_max - h_min;
}

inline FractalResult FractalTrafficGenerator::match_distribution(
    double target_hurst, size_t length) {
    FractalConfig saved = config_;
    config_.hurst = target_hurst;
    config_.length = length;
    auto result = generate_fgn();
    config_ = saved;
    return result;
}

inline FractalResult FractalTrafficGenerator::transform(
    const std::vector<double>& data, double target_hurst) {

    FractalResult result;

    // Strategy: generate fGn with target Hurst, then use it to modulate
    // the input data. This preserves the data's amplitude while imposing
    // the target self-similarity structure on timing/patterns.

    size_t n = data.size();
    if (n < 4) {
        result.error_msg = "Data too short";
        return result;
    }

    // Generate fGn with target Hurst
    auto fgn = generate_fgn(n, target_hurst);
    if (!fgn.success) {
        return fgn;
    }

    // Modulate: output[i] = data[i] + alpha * fgn[i] * |data[i]|
    // where alpha controls how much fractal structure to inject
    double alpha = 0.3;
    result.data.resize(n);
    for (size_t i = 0; i < n; ++i) {
        result.data[i] = data[i] + alpha * fgn.data[i] * std::abs(data[i]);
    }

    result.hurst_estimate = compute_hurst(result.data);
    result.hurst_error = std::abs(result.hurst_estimate - target_hurst);
    result.multifractal_width = compute_mf_width(result.data);
    result.success = true;

    return result;
}

} // namespace Math
} // namespace ncp

#endif // NCP_FRACTAL_HPP
