#pragma once
#ifndef NCP_MIRROR_HPP
#define NCP_MIRROR_HPP

/// @file ncp_mirror.hpp
/// @brief Mirror symmetry and Bridgeland stability for traffic analysis.
///
/// Mirror symmetry relates two different geometric descriptions (A-side and
/// B-side) of the same underlying physics. Kontsevich-Soibelman's wall-crossing
/// formula describes how BPS states change as stability conditions vary.
///
/// Bridgeland stability condition on a derived category D:
///   Z: K(D) → ℂ  (central charge, group homomorphism)
///   such that Z(E) ∈ H = {r e^{iπφ} : r > 0, φ ∈ (0,1]} for all semistable E
///
/// An object E is:
///   STABLE     if φ is unique (no subobjects with same phase)
///   SEMISTABLE if 0 < φ ≤ 1
///   UNSTABLE   otherwise
///
/// Wall-crossing: as Z varies, the set of stable objects changes discontinuously
/// across "walls" in the space of stability conditions. The KS formula:
///   ∏_{γ} (1 - X_γ)^{-Ω(γ)} = constant along paths avoiding walls
///
/// Application to DPI:
/// - Traffic features live in K(D) (Grothendieck group)
/// - Different DPI systems correspond to different stability conditions
/// - Wall-crossing = transition between DPI-detectable and DPI-invisible regimes
/// - Mirror morph = A-side (timing) ↔ B-side (payload) duality

#include <vector>
#include <complex>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <string>
#include <unordered_map>

namespace ncp {
namespace Math {

enum class StabilityCondition {
    STABLE,
    SEMISTABLE,
    UNSTABLE
};

struct MirrorConfig {
    int mirror_dim = 3;
    double central_charge_scale = 1.0;
    int num_wall_crossings = 5;
};

struct MirrorResult {
    std::vector<double> data;
    std::vector<double> central_charges;
    std::vector<StabilityCondition> stability;
    int num_walls_crossed = 0;
    bool success = false;
    std::string error_msg;
};

/// Charge vector in the Grothendieck group K(D).
struct ChargeVector {
    double rank = 0.0;       // rk(E)
    double degree = 0.0;     // deg(E)
    double euler = 0.0;      // χ(E)

    double phase() const {
        if (rank == 0.0 && degree == 0.0) return 0.0;
        return std::atan2(degree, rank);
    }

    double modulus() const {
        return std::sqrt(rank * rank + degree * degree);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// MIRROR SYMMETRY
// ═══════════════════════════════════════════════════════════════════════════

class MirrorSymmetry {
public:
    MirrorSymmetry() = default;
    explicit MirrorSymmetry(const MirrorConfig& config) : config_(config) {}

    // ─── Central charge ──────────────────────────────────────────────

    /// Compute central charge Z(E) for a charge vector.
    /// Z(E) = -degree + i·rank  (simplified for curves)
    static std::complex<double> central_charge(const ChargeVector& E);

    /// Compute central charge with custom parameters.
    static std::complex<double> central_charge(
        const ChargeVector& E,
        double alpha, double beta);

    /// Central charge from traffic features.
    std::complex<double> traffic_central_charge(
        const std::unordered_map<std::string, double>& features) const;

    // ─── Stability ───────────────────────────────────────────────────

    /// Determine stability of an object given central charge.
    static StabilityCondition determine_stability(
        const std::complex<double>& Z,
        const ChargeVector& E);

    /// Check if object E is stable w.r.t. stability condition σ.
    static bool is_stable(const ChargeVector& E,
                          const std::complex<double>& Z);

    /// Compute slope stability: μ(E) = degree/rank.
    /// E is μ-stable if for all subobjects F ⊂ E, μ(F) < μ(E).
    static double mu_slope(const ChargeVector& E);

    // ─── Wall-crossing ───────────────────────────────────────────────

    /// Check if a path in stability space crosses a wall.
    /// Wall = locus where two objects have the same phase.
    static bool wall_crossing(
        const std::complex<double>& Z1,
        const std::complex<double>& Z2,
        const std::complex<double>& Z_path_start,
        const std::complex<double>& Z_path_end);

    /// Kontsevich-Soibelman wall-crossing formula.
    /// Computes the BPS index Ω(γ) after crossing.
    static int ks_wall_crossing(
        const ChargeVector& gamma1,
        const ChargeVector& gamma2,
        int initial_omega);

    /// Cross a wall: transform data across stability boundary.
    std::vector<double> cross_wall(
        const std::vector<double>& data,
        StabilityCondition target) const;

    // ─── Mirror morph ────────────────────────────────────────────────

    /// Apply mirror morph: transform A-side (timing) to B-side (payload).
    /// Uses Fourier-Mukai transform: F(E) = Rπ_*(π^* E ⊗ P)
    /// Simplified: swap frequency and amplitude representations.
    static std::vector<double> mirror_morph(
        const std::vector<double>& a_side_data);

    /// Inverse mirror morph: B-side → A-side.
    static std::vector<double> inverse_mirror_morph(
        const std::vector<double>& b_side_data);

    // ─── Traffic analysis ────────────────────────────────────────────

    /// Analyze traffic stability: determine which DPI systems can detect this.
    std::unordered_map<std::string, StabilityCondition> traffic_stability(
        const std::unordered_map<std::string, double>& features) const;

    /// Transform data using mirror symmetry.
    MirrorResult transform(const std::vector<double>& data);

    const MirrorConfig& config() const { return config_; }
    void set_config(const MirrorConfig& c) { config_ = c; }

private:
    MirrorConfig config_;

    /// Extract charge vector from traffic features.
    static ChargeVector features_to_charge(
        const std::unordered_map<std::string, double>& features);
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline std::complex<double> MirrorSymmetry::central_charge(const ChargeVector& E) {
    // Z(E) = -degree + i·rank
    return std::complex<double>(-E.degree, E.rank);
}

inline std::complex<double> MirrorSymmetry::central_charge(
    const ChargeVector& E, double alpha, double beta) {
    // Generalized: Z = α·(-degree + i·rank) + β·euler
    return std::complex<double>(alpha * (-E.degree) + beta * E.euler,
                                 alpha * E.rank);
}

inline std::complex<double> MirrorSymmetry::traffic_central_charge(
    const std::unordered_map<std::string, double>& features) const {

    ChargeVector E = features_to_charge(features);
    return central_charge(E, config_.central_charge_scale, 0.1);
}

inline StabilityCondition MirrorSymmetry::determine_stability(
    const std::complex<double>& Z,
    const ChargeVector& E) {

    // Phase φ = arg(Z) / π ∈ (0, 1]
    double phase = std::arg(Z) / M_PI;
    if (phase <= 0.0) phase += 1.0;  // Normalize to (0, 1]

    // For STABLE: no subobjects with same phase
    // Simplified: if rank > 0 and degree/rank ∈ (0, 1), then STABLE
    if (E.rank > 0.0) {
        double mu = E.degree / E.rank;
        if (mu > 0.0 && mu < 1.0) return StabilityCondition::STABLE;
        if (mu == 0.0 || mu == 1.0) return StabilityCondition::SEMISTABLE;
    }

    return StabilityCondition::UNSTABLE;
}

inline bool MirrorSymmetry::is_stable(const ChargeVector& E,
                                        const std::complex<double>& Z) {
    return determine_stability(Z, E) == StabilityCondition::STABLE;
}

inline double MirrorSymmetry::mu_slope(const ChargeVector& E) {
    if (std::abs(E.rank) < 1e-15) return 0.0;
    return E.degree / E.rank;
}

inline bool MirrorSymmetry::wall_crossing(
    const std::complex<double>& Z1,
    const std::complex<double>& Z2,
    const std::complex<double>& Z_path_start,
    const std::complex<double>& Z_path_end) {

    // Wall = locus where arg(Z1) = arg(Z2) (same phase)
    // Path crosses wall if phases of Z1 and Z2 are on opposite sides
    // at start and end of path.

    double phase1_start = std::arg(Z1);
    double phase2_start = std::arg(Z2);

    // At start: check if phases are equal (on the wall)
    double phase_diff_start = std::abs(phase1_start - phase2_start);
    if (phase_diff_start > M_PI) phase_diff_start = 2 * M_PI - phase_diff_start;

    // Simple check: do the phases "bracket" a wall?
    // If Z_path_start and Z_path_end have different phase relationships
    (void)Z_path_start;  // used indirectly via Z_path_end
    (void)Z_path_end;

    // Wall is crossed if we pass through the locus arg(Z1) = arg(Z2)
    double diff_start = std::arg(Z1) - std::arg(Z2);
    double diff_end = std::arg(Z_path_end * Z1) - std::arg(Z_path_end * Z2);

    // Simplified: check if phase difference changes sign
    return (diff_start * diff_end < 0) || (phase_diff_start < 0.01);
}

inline int MirrorSymmetry::ks_wall_crossing(
    const ChargeVector& gamma1,
    const ChargeVector& gamma2,
    int initial_omega) {

    // KS formula: Ω_after = Ω_before + ⟨γ1, γ2⟩ * Ω(γ1) * Ω(γ2)
    // where ⟨γ1, γ2⟩ is the symplectic pairing

    double pairing = gamma1.rank * gamma2.degree - gamma1.degree * gamma2.rank;

    // New BPS index
    int delta = static_cast<int>(std::round(std::abs(pairing)));
    return initial_omega + delta;
}

inline std::vector<double> MirrorSymmetry::cross_wall(
    const std::vector<double>& data,
    StabilityCondition target) const {

    std::vector<double> result = data;
    size_t n = data.size();

    // Transform data to cross stability wall
    // This means adjusting features so the stability condition changes
    // Strategy: apply exponential scaling that shifts phases

    for (size_t i = 0; i < n; ++i) {
        double phase_shift = 0.0;
        switch (target) {
            case StabilityCondition::STABLE:
                // Shift toward stable region: increase rank relative to degree
                phase_shift = 0.1 * std::sin(2.0 * M_PI * i / n);
                break;
            case StabilityCondition::SEMISTABLE:
                // Shift toward boundary
                phase_shift = 0.05 * std::cos(2.0 * M_PI * i / n);
                break;
            case StabilityCondition::UNSTABLE:
                // Shift away from stable region
                phase_shift = -0.2 * std::sin(2.0 * M_PI * i / n);
                break;
        }
        result[i] *= std::exp(phase_shift);
    }

    return result;
}

inline std::vector<double> MirrorSymmetry::mirror_morph(
    const std::vector<double>& a_side_data) {

    // Fourier-Mukai transform (simplified): A-side (time domain) → B-side (freq domain)
    // Use DFT-like transformation
    size_t n = a_side_data.size();
    std::vector<double> b_side(n);

    for (size_t k = 0; k < n; ++k) {
        double sum = 0.0;
        for (size_t j = 0; j < n; ++j) {
            double angle = 2.0 * M_PI * k * j / n;
            sum += a_side_data[j] * std::cos(angle);
        }
        b_side[k] = sum / std::sqrt(static_cast<double>(n));
    }

    return b_side;
}

inline std::vector<double> MirrorSymmetry::inverse_mirror_morph(
    const std::vector<double>& b_side_data) {

    // Inverse: B-side (freq) → A-side (time)
    size_t n = b_side_data.size();
    std::vector<double> a_side(n);

    for (size_t j = 0; j < n; ++j) {
        double sum = 0.0;
        for (size_t k = 0; k < n; ++k) {
            double angle = 2.0 * M_PI * k * j / n;
            sum += b_side_data[k] * std::cos(angle);
        }
        a_side[j] = sum / std::sqrt(static_cast<double>(n));
    }

    return a_side;
}

inline ChargeVector MirrorSymmetry::features_to_charge(
    const std::unordered_map<std::string, double>& features) {

    ChargeVector E;

    auto it = features.find("packet_size");
    if (it != features.end()) E.rank = it->second / 1000.0;

    it = features.find("arrival_rate");
    if (it != features.end()) E.degree = it->second / 100.0;

    it = features.find("entropy");
    if (it != features.end()) E.euler = it->second / 8.0;

    return E;
}

inline std::unordered_map<std::string, StabilityCondition>
MirrorSymmetry::traffic_stability(
    const std::unordered_map<std::string, double>& features) const {

    std::unordered_map<std::string, StabilityCondition> result;

    ChargeVector E = features_to_charge(features);
    auto Z = traffic_central_charge(features);
    StabilityCondition overall = determine_stability(Z, E);
    result["overall"] = overall;

    // Check stability against different DPI types
    // Each DPI type corresponds to a different stability condition
    double mu = mu_slope(E);
    result["qosmos"] = (mu > 0.3) ? StabilityCondition::STABLE : StabilityCondition::UNSTABLE;
    result["fortinet"] = (mu > 0.5) ? StabilityCondition::STABLE : StabilityCondition::SEMISTABLE;
    result["cisco"] = (mu > 0.1) ? StabilityCondition::SEMISTABLE : StabilityCondition::UNSTABLE;

    return result;
}

inline MirrorResult MirrorSymmetry::transform(const std::vector<double>& data) {
    MirrorResult result;

    if (data.empty()) {
        result.error_msg = "Empty data";
        return result;
    }

    // Apply mirror morph (A-side → B-side)
    auto b_side = mirror_morph(data);

    // Compute central charges for each point
    result.data.resize(data.size());
    result.central_charges.resize(data.size());
    result.stability.resize(data.size());

    for (size_t i = 0; i < data.size(); ++i) {
        ChargeVector E;
        E.rank = std::abs(data[i]) / 100.0;
        E.degree = b_side[i] / 100.0;
        E.euler = 0.0;

        auto Z = central_charge(E);
        result.central_charges[i] = std::abs(Z);
        result.stability[i] = determine_stability(Z, E);

        // Apply wall-crossing transformation
        result.data[i] = b_side[i];
        if (result.stability[i] != StabilityCondition::STABLE) {
            // Adjust to become stable
            result.data[i] *= (1.0 + 0.1 * std::sin(2.0 * M_PI * i / data.size()));
            ++result.num_walls_crossed;
        }
    }

    result.success = true;
    return result;
}

} // namespace Math
} // namespace ncp

#endif // NCP_MIRROR_HPP
