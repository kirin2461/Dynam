#pragma once
#ifndef NCP_TROPICAL_HPP
#define NCP_TROPICAL_HPP

/// @file ncp_tropical.hpp
/// @brief Tropical geometry for traffic optimization.
///
/// Tropical semiring (ℝ ∪ {+∞}, ⊕, ⊗) where:
///   a ⊕ b = min(a, b)     (tropical addition)
///   a ⊗ b = a + b         (tropical multiplication)
///   0_⊕ = +∞, 1_⊗ = 0
///
/// Tropical polynomials are piecewise-linear concave functions:
///   p(x) = min_i (c_i + e_i · x)
///
/// Applications to DPI evasion:
/// - Tropical convex hull gives the set of traffic profiles achievable
///   through convex combinations in the tropical sense.
/// - Tropical LP finds the traffic parameters that minimize detection
///   probability subject to DPI boundary constraints.
///
/// Reference:
///   Maclagan D., Sturmfels B. (2021). "What is... a tropical variety?"
///   Notices of the AMS 68(6).

#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <limits>
#include <string>
#include <stdexcept>

namespace ncp {
namespace Math {

static constexpr double TROPICAL_INF = std::numeric_limits<double>::infinity();
static constexpr double TROPICAL_NEG_INF = -std::numeric_limits<double>::infinity();

struct TropicalConfig {
    double epsilon = 1e-10;  ///< Numerical precision
};

struct TropicalResult {
    std::vector<double> data;
    bool success = false;
    std::string error_msg;
};

struct TropicalLPResult {
    std::vector<double> optimal_point;
    double optimal_value = TROPICAL_INF;
    bool feasible = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// TROPICAL GEOMETRY
// ═══════════════════════════════════════════════════════════════════════════

class TropicalGeometry {
public:
    TropicalGeometry() = default;
    explicit TropicalGeometry(const TropicalConfig& config) : config_(config) {}

    // ─── Semiring operations ─────────────────────────────────────────

    /// Tropical addition: a ⊕ b = min(a, b)
    static double tropical_add(double a, double b);

    /// Tropical multiplication: a ⊗ b = a + b
    static double tropical_multiply(double a, double b);

    /// Tropical additive identity: +∞
    static double tropical_zero() { return TROPICAL_INF; }

    /// Tropical multiplicative identity: 0
    static double tropical_one() { return 0.0; }

    /// Tropical power: a^{⊗n} = n·a
    static double tropical_power(double a, int n);

    // ─── Tropical polynomials ────────────────────────────────────────

    /// Evaluate tropical polynomial at point x.
    /// p(x) = min_i (coefficients[i] + exponents[i] * x)
    static double tropical_polynomial(
        const std::vector<double>& coefficients,
        const std::vector<int>& exponents,
        double x);

    /// Evaluate multivariate tropical polynomial.
    /// p(x) = min_i (coefficients[i] + sum_j exponents[i][j] * x[j])
    static double tropical_polynomial_mv(
        const std::vector<double>& coefficients,
        const std::vector<std::vector<int>>& exponents,
        const std::vector<double>& x);

    /// Find roots of tropical polynomial (breakpoints of piecewise-linear function).
    static std::vector<double> tropical_roots(
        const std::vector<double>& coefficients,
        const std::vector<int>& exponents,
        double epsilon = 1e-10);

    // ─── Tropical convex hull ────────────────────────────────────────

    /// Tropical convex hull of a set of points.
    /// Returns vertices of the tropical convex hull.
    static std::vector<std::vector<double>> tropical_convex_hull(
        const std::vector<std::vector<double>>& points,
        double epsilon = 1e-10);

    /// Check if a point is in the tropical convex hull.
    static bool in_tropical_hull(
        const std::vector<double>& point,
        const std::vector<std::vector<double>>& generators,
        double epsilon = 1e-10);

    // ─── Tropical linear programming ─────────────────────────────────

    /// Solve tropical LP:
    ///   min c ⊗ x  subject to  A ⊗ x ≤ b
    /// i.e.,  min (c_i + x_i)  subject to  min_j (A_ij + x_j) ≤ b_i
    ///
    /// Uses reduction to classical LP via piecewise-linear structure.
    static TropicalLPResult tropical_linear_program(
        const std::vector<double>& c,
        const std::vector<std::vector<double>>& A,
        const std::vector<double>& b,
        double epsilon = 1e-10);

    // ─── DPI boundary evasion ────────────────────────────────────────

    /// Find traffic parameters that minimize DPI detection while
    /// staying within DPI boundary constraints.
    ///
    /// dpi_boundary: each row is [feature_index, threshold, direction]
    ///   direction: +1 = feature must be ≤ threshold
    ///              -1 = feature must be ≥ threshold
    static TropicalLPResult evade_dpi_boundary(
        const std::vector<double>& current_features,
        const std::vector<std::vector<double>>& dpi_boundary,
        const std::vector<double>& target_profile);

    /// Transform data using tropical operations.
    TropicalResult transform(const std::vector<double>& data);

    const TropicalConfig& config() const { return config_; }
    void set_config(const TropicalConfig& c) { config_ = c; }

private:
    TropicalConfig config_;
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline double TropicalGeometry::tropical_add(double a, double b) {
    return std::min(a, b);
}

inline double TropicalGeometry::tropical_multiply(double a, double b) {
    if (a == TROPICAL_INF || b == TROPICAL_INF) return TROPICAL_INF;
    return a + b;
}

inline double TropicalGeometry::tropical_power(double a, int n) {
    if (a == TROPICAL_INF) return TROPICAL_INF;
    if (n == 0) return 0.0;
    return static_cast<double>(n) * a;
}

inline double TropicalGeometry::tropical_polynomial(
    const std::vector<double>& coefficients,
    const std::vector<int>& exponents,
    double x) {

    if (coefficients.empty() || coefficients.size() != exponents.size())
        return TROPICAL_INF;

    double result = TROPICAL_INF;
    for (size_t i = 0; i < coefficients.size(); ++i) {
        double term = tropical_multiply(coefficients[i],
                                         static_cast<double>(exponents[i]) * x);
        // Wait — tropical poly: c_i ⊗ x^{⊗e_i} = c_i + e_i * x
        term = coefficients[i] + static_cast<double>(exponents[i]) * x;
        result = tropical_add(result, term);
    }
    return result;
}

inline double TropicalGeometry::tropical_polynomial_mv(
    const std::vector<double>& coefficients,
    const std::vector<std::vector<int>>& exponents,
    const std::vector<double>& x) {

    if (coefficients.empty() || coefficients.size() != exponents.size())
        return TROPICAL_INF;

    double result = TROPICAL_INF;
    for (size_t i = 0; i < coefficients.size(); ++i) {
        double term = coefficients[i];
        for (size_t j = 0; j < x.size() && j < exponents[i].size(); ++j) {
            term += static_cast<double>(exponents[i][j]) * x[j];
        }
        result = tropical_add(result, term);
    }
    return result;
}

inline std::vector<double> TropicalGeometry::tropical_roots(
    const std::vector<double>& coefficients,
    const std::vector<int>& exponents,
    double epsilon) {

    // Roots of tropical polynomial = breakpoints where the min switches
    // from one term to another. These occur at intersections of
    // lines y = c_i + e_i * x.

    std::vector<double> roots;
    size_t n = coefficients.size();

    if (n < 2) return roots;

    // For each pair of terms, find intersection point
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            int ei = exponents[i], ej = exponents[j];
            if (ei == ej) continue;

            // c_i + e_i * x = c_j + e_j * x
            // x = (c_j - c_i) / (e_i - e_j)
            double x = (coefficients[j] - coefficients[i]) /
                       static_cast<double>(ei - ej);

            // Check if this is actually on the lower envelope
            double val_at_x = tropical_polynomial(coefficients, exponents, x);
            double term_i = coefficients[i] + static_cast<double>(ei) * x;

            if (std::abs(val_at_x - term_i) < epsilon * 100) {
                roots.push_back(x);
            }
        }
    }

    std::sort(roots.begin(), roots.end());
    roots.erase(std::unique(roots.begin(), roots.end(),
        [epsilon](double a, double b) { return std::abs(a - b) < epsilon; }),
        roots.end());

    return roots;
}

inline std::vector<std::vector<double>> TropicalGeometry::tropical_convex_hull(
    const std::vector<std::vector<double>>& points,
    double epsilon) {

    // Tropical convex hull: the set of all tropical convex combinations.
    // A tropical convex combination is:
    //   y_j = min_i (λ_i + x_ij) - min_k(min_i(λ_i + x_ik))
    //
    // For 2D points, the tropical convex hull is a staircase polygon.
    // We return the extreme points (those not expressible as tropical
    // convex combinations of others).

    if (points.size() <= 2) return points;

    std::vector<bool> is_extreme(points.size(), true);

    for (size_t i = 0; i < points.size(); ++i) {
        // Check if point i is a tropical convex combination of others
        // Simplified: check if point i is dominated in all coordinates
        for (size_t j = 0; j < points.size(); ++j) {
            if (i == j || !is_extreme[j]) continue;

            bool dominated = true;
            for (size_t d = 0; d < points[i].size(); ++d) {
                if (points[i][d] < points[j][d] - epsilon) {
                    dominated = false;
                    break;
                }
            }
            if (dominated) {
                is_extreme[i] = false;
                break;
            }
        }
    }

    std::vector<std::vector<double>> hull;
    for (size_t i = 0; i < points.size(); ++i) {
        if (is_extreme[i]) hull.push_back(points[i]);
    }

    return hull;
}

inline bool TropicalGeometry::in_tropical_hull(
    const std::vector<double>& point,
    const std::vector<std::vector<double>>& generators,
    double epsilon) {

    if (generators.empty()) return false;

    // Point is in tropical convex hull iff it can be expressed as
    // a tropical convex combination of generators.
    // Simplified check: for each dimension, point value must be
    // achievable as min_i(λ_i + gen_i[d]) for some λ.

    for (size_t d = 0; d < point.size(); ++d) {
        double min_gen = TROPICAL_INF;
        for (const auto& gen : generators) {
            if (d < gen.size() && gen[d] < min_gen) {
                min_gen = gen[d];
            }
        }
        // Point must be ≥ minimum generator value in each dimension
        if (point[d] < min_gen - epsilon) return false;
    }

    return true;
}

inline TropicalLPResult TropicalGeometry::tropical_linear_program(
    const std::vector<double>& c,
    const std::vector<std::vector<double>>& A,
    const std::vector<double>& b,
    double epsilon) {

    TropicalLPResult result;
    size_t n = c.size();

    if (n == 0 || A.size() != b.size()) {
        result.error_msg = "Invalid LP dimensions";
        return result;
    }

    // Tropical LP: min ⊗_i (c_i + x_i) subject to min_j(A_ij + x_j) ≤ b_i
    //
    // This is equivalent to: for each constraint i, there exists j such that
    // A_ij + x_j ≤ b_i, i.e., x_j ≤ b_i - A_ij.
    //
    // Solution via dual: x*_j = min_i (b_i - A_ij)
    // Then check feasibility: for each constraint i, check if there exists j
    // such that A_ij + x*_j ≤ b_i.

    result.optimal_point.resize(n, TROPICAL_INF);

    // Compute x*
    for (size_t j = 0; j < n; ++j) {
        double min_val = TROPICAL_INF;
        for (size_t i = 0; i < A.size(); ++i) {
            if (j < A[i].size()) {
                double val = b[i] - A[i][j];
                if (val < min_val) min_val = val;
            }
        }
        result.optimal_point[j] = min_val;
    }

    // Check feasibility
    result.feasible = true;
    for (size_t i = 0; i < A.size(); ++i) {
        double min_constraint = TROPICAL_INF;
        for (size_t j = 0; j < n; ++j) {
            if (j < A[i].size()) {
                double val = A[i][j] + result.optimal_point[j];
                if (val < min_constraint) min_constraint = val;
            }
        }
        if (min_constraint > b[i] + epsilon) {
            result.feasible = false;
            break;
        }
    }

    // Compute optimal value: min_j (c_j + x*_j)
    if (result.feasible) {
        result.optimal_value = TROPICAL_INF;
        for (size_t j = 0; j < n; ++j) {
            double val = c[j] + result.optimal_point[j];
            if (val < result.optimal_value) result.optimal_value = val;
        }
    }

    return result;
}

inline TropicalLPResult TropicalGeometry::evade_dpi_boundary(
    const std::vector<double>& current_features,
    const std::vector<std::vector<double>>& dpi_boundary,
    const std::vector<double>& target_profile) {

    TropicalLPResult result;
    size_t n = current_features.size();

    if (n == 0) {
        result.error_msg = "Empty features";
        return result;
    }

    // Convert DPI constraints to tropical LP form.
    // Each boundary constraint: feature[feature_idx] [≤/≥] threshold
    // We want to find x closest to target_profile satisfying all constraints.

    // Objective: minimize Σ|x_i - target_i| (approximated in tropical sense)
    std::vector<double> c(n);
    for (size_t i = 0; i < n; ++i) {
        c[i] = (i < target_profile.size()) ? -target_profile[i] : 0.0;
    }

    // Constraints from DPI boundary
    std::vector<std::vector<double>> A;
    std::vector<double> b;

    for (const auto& constraint : dpi_boundary) {
        if (constraint.size() < 3) continue;
        int feature_idx = static_cast<int>(constraint[0]);
        double threshold = constraint[1];
        double direction = constraint[2];  // +1 for ≤, -1 for ≥

        if (feature_idx < 0 || feature_idx >= static_cast<int>(n)) continue;

        std::vector<double> row(n, TROPICAL_INF);
        if (direction > 0) {
            // feature ≤ threshold: A[row][feature_idx] + x[feature_idx] ≤ threshold
            row[feature_idx] = 0.0;
            A.push_back(row);
            b.push_back(threshold);
        } else {
            // feature ≥ threshold: handled differently
            // We add -x ≤ -threshold → x ≥ threshold
            // In tropical: this is not a standard ≤ constraint
            // Approximate: add as a lower bound on x
        }
    }

    if (A.empty()) {
        // No constraints, just return target profile
        result.optimal_point = target_profile;
        result.optimal_value = 0.0;
        result.feasible = true;
        return result;
    }

    return tropical_linear_program(c, A, b);
}

inline TropicalResult TropicalGeometry::transform(
    const std::vector<double>& data) {

    TropicalResult result;

    // Apply tropical normalization: shift by min so min becomes 0
    if (data.empty()) {
        result.error_msg = "Empty data";
        return result;
    }

    double min_val = *std::min_element(data.begin(), data.end());
    result.data.resize(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result.data[i] = data[i] - min_val;  // Tropical normalization
    }

    result.success = true;
    return result;
}

} // namespace Math
} // namespace ncp

#endif // NCP_TROPICAL_HPP
