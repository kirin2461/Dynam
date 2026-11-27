#pragma once
#ifndef NCP_PADIC_HPP
#define NCP_PADIC_HPP

/// @file ncp_padic.hpp
/// @brief P-adic analysis for ultrametric clustering and multiscale analysis.
///
/// The p-adic numbers ℚₚ extend ℚ with a non-Archimedean absolute value:
///   |x|_p = p^{-v_p(x)}  where v_p(x) = max{k : p^k divides x}
///
/// Key property — ultrametric inequality:
///   |x + y|_p ≤ max(|x|_p, |y|_p)   (STRONGER than triangle inequality)
///
/// This gives ℚₚ a tree-like geometry where every triangle is isosceles
/// with the two long sides equal. Perfect for hierarchical clustering.
///
/// Applications:
/// - Ultrametric clustering of traffic features
/// - Multiscale analysis via p-adic wavelets (Mahler expansion)
/// - Adele ring: combine ℝ and ℚₚ analyses for complete picture
///
/// Reference:
///   Robert A.M. (2009). "A Course in p-adic Analysis." Springer GTM 198.

#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <string>
#include <map>
#include <complex>

namespace ncp {
namespace Math {

struct PadicConfig {
    int prime = 2;            ///< Prime p for p-adic analysis
    int num_terms = 20;       ///< Number of terms in p-adic expansion
    double clustering_threshold = 0.5;
    double epsilon = 1e-10;   ///< Numerical precision
};

struct PadicResult {
    std::vector<double> data;
    bool success = false;
    std::string error_msg;
};

struct ClusterInfo {
    std::vector<int> labels;         ///< Cluster assignment for each point
    int num_clusters = 0;
    std::vector<std::vector<int>> members;  ///< Members of each cluster
    double ultrametricity = 0.0;     ///< How well data fits ultrametric structure
};

struct AdeleResult {
    std::vector<double> real_component;     ///< ℝ component
    std::vector<std::vector<double>> padic_components;  ///< ℚₚ components
    double adele_norm = 0.0;               ///< Product formula
};

// ═══════════════════════════════════════════════════════════════════════════
// P-ADIC ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════

class PadicAnalysis {
public:
    PadicAnalysis() = default;
    explicit PadicAnalysis(const PadicConfig& config) : config_(config) {}

    // ─── P-adic expansion ────────────────────────────────────────────

    /// Compute p-adic expansion of integer x.
    /// Returns coefficients [a_0, a_1, ..., a_{n-1}] where x = Σ a_k * p^k
    /// and 0 ≤ a_k < p.
    std::vector<int> padic_expansion(long long x) const;

    /// Compute p-adic expansion of integer x with specific prime.
    static std::vector<int> padic_expansion(long long x, int p, int num_terms);

    /// P-adic valuation: v_p(x) = max k such that p^k | x.
    static int padic_valuation(long long x, int p);

    /// P-adic absolute value: |x|_p = p^{-v_p(x)}.
    static double padic_abs(long long x, int p);

    /// P-adic absolute value for doubles (approximate via rational approx).
    static double padic_abs_double(double x, int p);

    // ─── Ultrametric distance ────────────────────────────────────────

    /// Ultrametric distance between two integers: d_p(x, y) = |x - y|_p
    static double ultrametric_distance(long long x, long long y, int p);

    /// Approximate ultrametric distance for doubles.
    static double ultrametric_distance_double(double x, double y, int p);

    /// Compute full ultrametric distance matrix.
    std::vector<std::vector<double>> ultrametric_distance_matrix(
        const std::vector<double>& data) const;

    // ─── Mahler expansion ────────────────────────────────────────────

    /// Compute Mahler coefficients of a function f: ℤₚ → ℚₚ.
    /// f(x) = Σ c_k * C(x, k)  where C(x, k) = x(x-1)...(x-k+1)/k!
    /// Coefficients: c_k = Σ_{j=0}^{k} (-1)^{k-j} * C(k, j) * f(j)
    static std::vector<double> mahler_coefficients(
        const std::vector<double>& function_values, int num_terms);

    /// Evaluate Mahler expansion at point x.
    static double mahler_evaluate(
        const std::vector<double>& coefficients, int x, int prime);

    // ─── P-adic Fourier transform ────────────────────────────────────

    /// Compute p-adic Fourier transform (Volkenborn integral analogue).
    /// F(k) = Σ_{n=0}^{N-1} f(n) * χ_p(nk)
    /// where χ_p is the p-adic additive character.
    static std::vector<std::complex<double>> padic_fourier(
        const std::vector<double>& data, int p);

    /// Inverse p-adic Fourier transform.
    static std::vector<double> padic_inverse_fourier(
        const std::vector<std::complex<double>>& spectrum, int p);

    // ─── Adele ring ──────────────────────────────────────────────────

    /// Compute adele representation of data.
    /// Adele ring: 𝔸_ℚ = ℝ × ∏'_p ℚₚ (restricted product)
    AdeleResult adele_representation(const std::vector<double>& data) const;

    /// Compute product formula: Π_v |x|_v = 1 for all x ∈ ℚ*
    static double adele_product_formula(const std::vector<double>& data,
                                         int p);

    // ─── Ultrametric clustering ──────────────────────────────────────

    /// Hierarchical clustering using ultrametric distance.
    /// Returns cluster assignments at given threshold.
    ClusterInfo ultrametric_clustering(
        const std::vector<double>& data, double threshold) const;

    /// Compute ultrametricity score: how well distances fit ultrametric inequality.
    double compute_ultrametricity(const std::vector<double>& data) const;

    // ─── Transform ───────────────────────────────────────────────────

    /// Transform data using p-adic analysis.
    PadicResult transform(const std::vector<double>& data);

    const PadicConfig& config() const { return config_; }
    void set_config(const PadicConfig& c) { config_ = c; }

private:
    PadicConfig config_;

    /// Binomial coefficient C(n, k).
    static long long binomial(int n, int k);

    /// Quantize double to integer for p-adic analysis.
    static long long quantize(double x, double scale = 1000.0);
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline std::vector<int> PadicAnalysis::padic_expansion(long long x, int p, int num_terms) {
    std::vector<int> digits(num_terms, 0);

    if (x == 0) return digits;

    // Handle negative numbers: for p-adic, -x has a specific expansion
    bool negative = (x < 0);
    unsigned long long ux;
    if (negative) {
        // In p-adic: -1 = (p-1) + (p-1)*p + (p-1)*p^2 + ...
        ux = static_cast<unsigned long long>(-x);
    } else {
        ux = static_cast<unsigned long long>(x);
    }

    for (int i = 0; i < num_terms && ux > 0; ++i) {
        digits[i] = static_cast<int>(ux % p);
        ux /= p;
    }

    if (negative) {
        // Convert to p-adic negative: complement and add 1
        // -x = (p-1-d_0) + (p-1-d_1)*p + ... + 1
        int carry = 1;
        for (int i = 0; i < num_terms; ++i) {
            int complement = (p - 1 - digits[i]) + carry;
            digits[i] = complement % p;
            carry = complement / p;
        }
    }

    return digits;
}

inline std::vector<int> PadicAnalysis::padic_expansion(long long x) const {
    return padic_expansion(x, config_.prime, config_.num_terms);
}

inline int PadicAnalysis::padic_valuation(long long x, int p) {
    if (x == 0) return 1000;  // Convention: v_p(0) = +∞
    int v = 0;
    long long abs_x = (x < 0) ? -x : x;
    while (abs_x % p == 0 && abs_x > 0) {
        ++v;
        abs_x /= p;
    }
    return v;
}

inline double PadicAnalysis::padic_abs(long long x, int p) {
    if (x == 0) return 0.0;
    int v = padic_valuation(x, p);
    return std::pow(static_cast<double>(p), -v);
}

inline double PadicAnalysis::padic_abs_double(double x, int p) {
    long long qx = static_cast<long long>(std::round(x * 1000.0));
    return padic_abs(qx, p);
}

inline double PadicAnalysis::ultrametric_distance(long long x, long long y, int p) {
    return padic_abs(x - y, p);
}

inline double PadicAnalysis::ultrametric_distance_double(double x, double y, int p) {
    long long qx = static_cast<long long>(std::round(x * 1000.0));
    long long qy = static_cast<long long>(std::round(y * 1000.0));
    return padic_abs(qx - qy, p);
}

inline std::vector<std::vector<double>> PadicAnalysis::ultrametric_distance_matrix(
    const std::vector<double>& data) const {

    size_t n = data.size();
    std::vector<std::vector<double>> dist(n, std::vector<double>(n, 0.0));
    int p = config_.prime;

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            double d = ultrametric_distance_double(data[i], data[j], p);
            dist[i][j] = d;
            dist[j][i] = d;
        }
    }
    return dist;
}

inline std::vector<double> PadicAnalysis::mahler_coefficients(
    const std::vector<double>& function_values, int num_terms) {

    // c_k = Σ_{j=0}^{k} (-1)^{k-j} * C(k, j) * f(j)
    size_t n = function_values.size();
    std::vector<double> coeffs(num_terms, 0.0);

    for (int k = 0; k < num_terms; ++k) {
        double sum = 0.0;
        for (int j = 0; j <= std::min(k, static_cast<int>(n) - 1); ++j) {
            long long sign = ((k - j) % 2 == 0) ? 1 : -1;
            long long binom = binomial(k, j);
            sum += sign * binom * function_values[j];
        }
        coeffs[k] = sum;
    }

    return coeffs;
}

inline double PadicAnalysis::mahler_evaluate(
    const std::vector<double>& coefficients, int x, int prime) {

    // f(x) = Σ c_k * C(x, k)
    double result = 0.0;

    for (size_t k = 0; k < coefficients.size(); ++k) {
        // C(x, k) = x(x-1)...(x-k+1) / k!
        double binom = 1.0;
        for (size_t j = 0; j < k; ++j) {
            binom *= static_cast<double>(x - static_cast<int>(j));
            binom /= static_cast<double>(j + 1);
        }
        result += coefficients[k] * binom;
    }

    return result;
}

inline std::vector<std::complex<double>> PadicAnalysis::padic_fourier(
    const std::vector<double>& data, int p) {

    // P-adic Fourier transform using additive character.
    // χ_p(n) = exp(2πi * {n}_p)
    // where {n}_p is the fractional part in p-adic sense.
    //
    // For integers, {n}_p = Σ_{k<0} a_k p^k (the "fractional" part).
    // Since we work with non-negative integers, {n}_p ≈ n/p^m for large m.

    size_t N = data.size();
    std::vector<std::complex<double>> spectrum(N);

    double log_p = std::log(static_cast<double>(p));

    for (size_t k = 0; k < N; ++k) {
        std::complex<double> sum(0.0, 0.0);
        for (size_t n = 0; n < N; ++n) {
            // Additive character: exp(2πi * n * k / p^m)
            // Use m such that p^m ≈ N for good resolution
            int m = static_cast<int>(std::ceil(std::log(static_cast<double>(N)) / log_p));
            double pm = std::pow(static_cast<double>(p), m);
            double phase = 2.0 * M_PI * static_cast<double>(n * k) / pm;
            sum += data[n] * std::complex<double>(std::cos(phase), std::sin(phase));
        }
        spectrum[k] = sum / std::sqrt(static_cast<double>(N));
    }

    return spectrum;
}

inline std::vector<double> PadicAnalysis::padic_inverse_fourier(
    const std::vector<std::complex<double>>& spectrum, int p) {

    size_t N = spectrum.size();
    std::vector<double> result(N);

    double log_p = std::log(static_cast<double>(p));
    int m = static_cast<int>(std::ceil(std::log(static_cast<double>(N)) / log_p));
    double pm = std::pow(static_cast<double>(p), m);

    for (size_t n = 0; n < N; ++n) {
        std::complex<double> sum(0.0, 0.0);
        for (size_t k = 0; k < N; ++k) {
            double phase = -2.0 * M_PI * static_cast<double>(n * k) / pm;
            sum += spectrum[k] * std::complex<double>(std::cos(phase), std::sin(phase));
        }
        result[n] = sum.real() / std::sqrt(static_cast<double>(N));
    }

    return result;
}

inline AdeleResult PadicAnalysis::adele_representation(
    const std::vector<double>& data) const {

    AdeleResult result;
    result.real_component = data;

    // p-adic component: quantize and compute p-adic absolute values
    std::vector<double> padic_comp(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        padic_comp[i] = padic_abs_double(data[i], config_.prime);
    }
    result.padic_components.push_back(padic_comp);

    // Product formula: |x|_∞ * |x|_p * Π_{q≠p} |x|_q = 1
    // For our purposes, approximate: |x|_∞ * |x|_p ≈ const
    result.adele_norm = 1.0;
    for (size_t i = 0; i < data.size(); ++i) {
        result.adele_norm *= (std::abs(data[i]) + 1e-15) * (padic_comp[i] + 1e-15);
    }
    result.adele_norm = std::pow(result.adele_norm, 1.0 / data.size());

    return result;
}

inline double PadicAnalysis::adele_product_formula(const std::vector<double>& data, int p) {
    double product = 1.0;
    for (double x : data) {
        if (std::abs(x) > 1e-15) {
            product *= std::abs(x) * padic_abs_double(x, p);
        }
    }
    return (data.size() > 0) ? std::pow(product, 1.0 / data.size()) : 1.0;
}

inline ClusterInfo PadicAnalysis::ultrametric_clustering(
    const std::vector<double>& data, double threshold) const {

    ClusterInfo info;
    size_t n = data.size();
    if (n == 0) return info;

    auto dist_matrix = ultrametric_distance_matrix(data);

    // Single-linkage hierarchical clustering using ultrametric distance
    // Start with each point as its own cluster, merge closest pairs
    // until threshold is exceeded.

    info.labels.resize(n, 0);
    std::iota(info.labels.begin(), info.labels.end(), 0);

    // Simple agglomerative clustering
    std::vector<int> cluster_map(n);
    std::iota(cluster_map.begin(), cluster_map.end(), 0);
    int num_clusters = static_cast<int>(n);

    // Merge until no pairs below threshold
    bool merged = true;
    while (merged) {
        merged = false;
        double min_dist = std::numeric_limits<double>::max();
        int merge_i = -1, merge_j = -1;

        for (size_t i = 0; i < n; ++i) {
            for (size_t j = i + 1; j < n; ++j) {
                int ci = cluster_map[i], cj = cluster_map[j];
                if (ci != cj && dist_matrix[i][j] < min_dist) {
                    min_dist = dist_matrix[i][j];
                    merge_i = ci;
                    merge_j = cj;
                }
            }
        }

        if (merge_i >= 0 && merge_j >= 0 && min_dist <= threshold) {
            // Merge clusters merge_i and merge_j
            for (size_t i = 0; i < n; ++i) {
                if (cluster_map[i] == merge_j) {
                    cluster_map[i] = merge_i;
                }
            }
            --num_clusters;
            merged = true;
        }
    }

    // Renumber clusters
    std::map<int, int> cluster_id;
    int next_id = 0;
    info.labels.resize(n);
    for (size_t i = 0; i < n; ++i) {
        if (cluster_id.find(cluster_map[i]) == cluster_id.end()) {
            cluster_id[cluster_map[i]] = next_id++;
        }
        info.labels[i] = cluster_id[cluster_map[i]];
    }

    info.num_clusters = num_clusters;
    info.members.resize(num_clusters);
    for (size_t i = 0; i < n; ++i) {
        info.members[info.labels[i]].push_back(static_cast<int>(i));
    }

    return info;
}

inline double PadicAnalysis::compute_ultrametricity(const std::vector<double>& data) const {
    auto dist = ultrametric_distance_matrix(data);
    size_t n = data.size();
    if (n < 3) return 1.0;

    // Check ultrametric inequality: d(x,z) ≤ max(d(x,y), d(y,z))
    // Score = fraction of triples satisfying the inequality.
    int total_triples = 0;
    int satisfied = 0;

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            for (size_t k = j + 1; k < n; ++k) {
                ++total_triples;

                double d1 = dist[i][j], d2 = dist[j][k], d3 = dist[i][k];

                // Check all three permutations
                bool ok = (d3 <= std::max(d1, d2) + config_.epsilon * 100) &&
                          (d1 <= std::max(d2, d3) + config_.epsilon * 100) &&
                          (d2 <= std::max(d1, d3) + config_.epsilon * 100);
                if (ok) ++satisfied;
            }
        }
    }

    return (total_triples > 0) ? static_cast<double>(satisfied) / total_triples : 1.0;
}

inline PadicResult PadicAnalysis::transform(const std::vector<double>& data) {
    PadicResult result;
    if (data.empty()) {
        result.error_msg = "Empty data";
        return result;
    }

    // Transform: apply p-adic wavelet analysis (Mahler expansion)
    // and reconstruct with truncated coefficients
    int num_terms = std::min(config_.num_terms, static_cast<int>(data.size()));

    auto coeffs = mahler_coefficients(data, num_terms);

    // Reconstruct from truncated Mahler expansion
    result.data.resize(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result.data[i] = mahler_evaluate(coeffs, static_cast<int>(i), config_.prime);
    }

    result.success = true;
    return result;
}

inline long long PadicAnalysis::binomial(int n, int k) {
    if (k < 0 || k > n) return 0;
    if (k == 0 || k == n) return 1;
    if (k > n / 2) k = n - k;

    long long result = 1;
    for (int i = 0; i < k; ++i) {
        result = result * (n - i) / (i + 1);
    }
    return result;
}

inline long long PadicAnalysis::quantize(double x, double scale) {
    return static_cast<long long>(std::round(x * scale));
}

} // namespace Math
} // namespace ncp

#endif // NCP_PADIC_HPP
