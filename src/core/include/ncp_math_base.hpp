#pragma once
#ifndef NCP_MATH_BASE_HPP
#define NCP_MATH_BASE_HPP

/// @file ncp_math_base.hpp
/// @brief Base types for all mathematical transform modules.
///
/// Every math module (fractal, chaotic, ergodic, topological, tropical,
/// padic, cluster, mirror, anabelian) operates on vectors of doubles
/// and produces vectors of doubles. This header defines the common
/// interface and context types.

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cmath>
#include <stdexcept>

namespace ncp {
namespace Math {

/// Context passed to every transform: target identifier + parameters.
struct MathContext {
    std::string target;
    std::unordered_map<std::string, double> params;

    double get_param(const std::string& key, double default_val = 0.0) const {
        auto it = params.find(key);
        return (it != params.end()) ? it->second : default_val;
    }

    void set_param(const std::string& key, double value) {
        params[key] = value;
    }
};

/// Metrics computed by every transform.
struct TransformMetrics {
    double stealth_score = 0.0;
    double distortion = 0.0;     // L2 norm of (output - input)
    double correlation = 0.0;    // Pearson correlation
    double entropy_diff = 0.0;   // Shannon entropy difference

    /// Compute distortion: L2 norm between two vectors.
    static double compute_l2(const std::vector<double>& a,
                              const std::vector<double>& b);

    /// Compute Pearson correlation between two vectors.
    static double compute_correlation(const std::vector<double>& a,
                                       const std::vector<double>& b);

    /// Compute Shannon entropy of a vector (treated as histogram).
    static double compute_entropy(const std::vector<double>& data);
};

// ─── Inline implementations ─────────────────────────────────────────────

inline double TransformMetrics::compute_l2(const std::vector<double>& a,
                                             const std::vector<double>& b) {
    if (a.size() != b.size()) return -1.0;
    double sum = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        double d = a[i] - b[i];
        sum += d * d;
    }
    return std::sqrt(sum);
}

inline double TransformMetrics::compute_correlation(const std::vector<double>& a,
                                                      const std::vector<double>& b) {
    size_t n = a.size();
    if (n != b.size() || n < 2) return 0.0;

    double mean_a = 0.0, mean_b = 0.0;
    for (size_t i = 0; i < n; ++i) {
        mean_a += a[i];
        mean_b += b[i];
    }
    mean_a /= n;
    mean_b /= n;

    double cov = 0.0, var_a = 0.0, var_b = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double da = a[i] - mean_a;
        double db = b[i] - mean_b;
        cov += da * db;
        var_a += da * da;
        var_b += db * db;
    }

    double denom = std::sqrt(var_a * var_b);
    return (denom > 1e-15) ? cov / denom : 0.0;
}

inline double TransformMetrics::compute_entropy(const std::vector<double>& data) {
    if (data.empty()) return 0.0;

    // Build histogram with 64 bins
    const int num_bins = 64;
    std::vector<int> hist(num_bins, 0);

    double min_val = data[0], max_val = data[0];
    for (double v : data) {
        if (v < min_val) min_val = v;
        if (v > max_val) max_val = v;
    }

    double range = max_val - min_val;
    if (range < 1e-15) return 0.0;

    for (double v : data) {
        int bin = static_cast<int>((v - min_val) / range * (num_bins - 1));
        if (bin >= 0 && bin < num_bins) hist[bin]++;
    }

    double entropy = 0.0;
    double n = static_cast<double>(data.size());
    for (int count : hist) {
        if (count > 0) {
            double p = count / n;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

} // namespace Math
} // namespace ncp

#endif // NCP_MATH_BASE_HPP
