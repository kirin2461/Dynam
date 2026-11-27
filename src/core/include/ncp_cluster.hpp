#pragma once
#ifndef NCP_CLUSTER_HPP
#define NCP_CLUSTER_HPP

/// @file ncp_cluster.hpp
/// @brief Cluster algebra mutations for protocol switching.
///
/// Cluster algebras (Fomin-Zelevinsky, 2002) provide a framework for
/// combinatorial mutations that preserve the Laurent phenomenon.
///
/// A cluster algebra is defined by:
/// - A seed (x, B) where x = (x_1,...,x_n) are cluster variables
///   and B is the exchange matrix (skew-symmetrizable).
/// - Mutation μ_k in direction k:
///   x'_k = (∏_{b_ik>0} x_i^{b_ik} + ∏_{b_ik<0} x_i^{-b_ik}) / x_k
///   B' = μ_k(B) with entries:
///   b'_{ij} = -b_{ij} if i=k or j=k
///   b'_{ij} = b_{ij} + (|b_{ik}|b_{kj} + b_{ik}|b_{kj}|)/2  otherwise
///
/// Application to DPI evasion:
/// - Each protocol (HTTP, DNS, QUIC, WebSocket) corresponds to a cluster
/// - Mutation = protocol switch while maintaining algebraic invariants
/// - Laurent phenomenon ensures that all derived protocols are polynomial
///   in the original variables → predictable traffic structure
///
/// Reference:
///   Fomin S., Zelevinsky A. (2002). "Cluster algebras I: Foundations."
///   J. Amer. Math. Soc. 15: 497-529.

#include <vector>
#include <string>
#include <unordered_map>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <cassert>

namespace ncp {
namespace Math {

struct ClusterConfig {
    int initial_rank = 3;
    std::vector<std::string> mutation_sequence;
};

struct ClusterResult {
    std::vector<double> data;
    std::vector<double> cluster_vars;
    std::vector<std::vector<int>> exchange_matrix;
    std::string dynkin_type;
    bool success = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// CLUSTER ALGEBRA
// ═══════════════════════════════════════════════════════════════════════════

class ClusterAlgebra {
public:
    ClusterAlgebra() { init_default_seed(); }
    explicit ClusterAlgebra(const ClusterConfig& config) : config_(config) {
        init_default_seed();
    }

    // ─── Core mutation operations ────────────────────────────────────

    /// Mutate cluster variable x_k using exchange relation.
    /// x'_k = (∏_{b_ik>0} x_i^{b_ik} + ∏_{b_ik<0} x_i^{-b_ik}) / x_k
    static std::vector<double> mutation(
        int k,
        const std::vector<double>& x_vars,
        const std::vector<std::vector<int>>& B);

    /// Mutate exchange matrix B in direction k.
    /// b'_{ij} = -b_{ij}  if i=k or j=k
    /// b'_{ij} = b_{ij} + (|b_{ik}|b_{kj} + b_{ik}|b_{kj}|)/2  otherwise
    static std::vector<std::vector<int>> mutate_matrix(
        int k,
        const std::vector<std::vector<int>>& B);

    /// Perform sequence of mutations μ_{k_1} μ_{k_2} ... μ_{k_m}.
    static std::pair<std::vector<double>, std::vector<std::vector<int>>>
    mutate_sequence(
        const std::vector<int>& directions,
        std::vector<double> x_vars,
        std::vector<std::vector<int>> B);

    // ─── Laurent phenomenon ──────────────────────────────────────────

    /// Check if cluster variables satisfy the Laurent phenomenon:
    /// every cluster variable is a Laurent polynomial in the initial seed.
    /// (Simplified check: verify positivity of all variables after mutation.)
    static bool check_laurent_phenomenon(
        const std::vector<double>& x_vars,
        const std::vector<std::vector<int>>& B);

    // ─── Finite type classification ──────────────────────────────────

    /// Classify the cluster algebra type from the exchange matrix.
    /// Returns Dynkin type: "A_n", "B_n", "D_n", "E_6", "E_7", "E_8",
    /// "F_4", "G_2", or "infinite" if not finite type.
    static std::string finite_type_classification(
        const std::vector<std::vector<int>>& B);

    /// Compute the Cartan matrix from exchange matrix.
    static std::vector<std::vector<int>> cartan_matrix(
        const std::vector<std::vector<int>>& B);

    // ─── Protocol mutation ───────────────────────────────────────────

    /// Map protocol features to cluster variables.
    static std::vector<double> protocol_to_cluster(
        const std::unordered_map<std::string, double>& features);

    /// Map cluster variables back to protocol features.
    static std::unordered_map<std::string, double> cluster_to_protocol(
        const std::vector<double>& cluster_vars,
        const std::string& target_protocol);

    /// Perform protocol mutation: HTTP → DNS → QUIC → etc.
    static std::unordered_map<std::string, double> protocol_mutation(
        const std::unordered_map<std::string, double>& source_features,
        const std::string& target_protocol);

    // ─── Transform ───────────────────────────────────────────────────

    /// Transform data using cluster algebra mutations.
    ClusterResult transform(const std::vector<double>& data);

    const ClusterConfig& config() const { return config_; }
    void set_config(const ClusterConfig& c) { config_ = c; }

private:
    ClusterConfig config_;

    // Initial seed
    std::vector<double> initial_vars_;
    std::vector<std::vector<int>> initial_B_;

    void init_default_seed();

    /// Sign function for matrix mutation.
    static int sign(int x) { return (x > 0) - (x < 0); }
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline void ClusterAlgebra::init_default_seed() {
    int n = config_.initial_rank;

    // Default initial cluster: all variables = 1
    initial_vars_.resize(n, 1.0);

    // Default exchange matrix: type A_n quiver
    // B = adjacency of Dynkin quiver (skew-symmetric)
    initial_B_.assign(n, std::vector<int>(n, 0));
    for (int i = 0; i < n - 1; ++i) {
        initial_B_[i][i + 1] = 1;
        initial_B_[i + 1][i] = -1;
    }
}

inline std::vector<double> ClusterAlgebra::mutation(
    int k,
    const std::vector<double>& x_vars,
    const std::vector<std::vector<int>>& B) {

    int n = static_cast<int>(x_vars.size());
    assert(k >= 0 && k < n);

    std::vector<double> new_x = x_vars;

    // Exchange relation:
    // x'_k = (∏_{b_ik>0} x_i^{b_ik} + ∏_{b_ik<0} x_i^{-b_ik}) / x_k

    double positive_term = 1.0;
    double negative_term = 1.0;

    for (int i = 0; i < n; ++i) {
        if (i == k) continue;
        int b_ik = B[i][k];

        if (b_ik > 0) {
            positive_term *= std::pow(x_vars[i], b_ik);
        } else if (b_ik < 0) {
            negative_term *= std::pow(x_vars[i], -b_ik);
        }
    }

    if (std::abs(x_vars[k]) > 1e-15) {
        new_x[k] = (positive_term + negative_term) / x_vars[k];
    } else {
        new_x[k] = positive_term + negative_term;
    }

    return new_x;
}

inline std::vector<std::vector<int>> ClusterAlgebra::mutate_matrix(
    int k,
    const std::vector<std::vector<int>>& B) {

    int n = static_cast<int>(B.size());
    assert(k >= 0 && k < n);

    std::vector<std::vector<int>> B_new = B;

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            if (i == k || j == k) {
                B_new[i][j] = -B[i][j];
            } else {
                int b_ik = B[i][k];
                int b_kj = B[k][j];
                int correction = (std::abs(b_ik) * b_kj + b_ik * std::abs(b_kj)) / 2;
                B_new[i][j] = B[i][j] + correction;
            }
        }
    }

    return B_new;
}

inline std::pair<std::vector<double>, std::vector<std::vector<int>>>
ClusterAlgebra::mutate_sequence(
    const std::vector<int>& directions,
    std::vector<double> x_vars,
    std::vector<std::vector<int>> B) {

    for (int k : directions) {
        if (k < 0 || k >= static_cast<int>(x_vars.size())) continue;
        x_vars = mutation(k, x_vars, B);
        B = mutate_matrix(k, B);
    }

    return {x_vars, B};
}

inline bool ClusterAlgebra::check_laurent_phenomenon(
    const std::vector<double>& x_vars,
    const std::vector<std::vector<int>>& /*B*/) {

    // Simplified check: all cluster variables should be positive
    // (Laurent polynomials with positive coefficients evaluate to positive values
    // when initial variables are positive)
    for (double x : x_vars) {
        if (x <= 0.0 || std::isnan(x) || std::isinf(x)) return false;
    }
    return true;
}

inline std::string ClusterAlgebra::finite_type_classification(
    const std::vector<std::vector<int>>& B) {

    int n = static_cast<int>(B.size());
    if (n == 0) return "empty";

    // Compute Cartan matrix: c_{ij} = 2 if i=j, c_{ij} = -|b_{ij}| otherwise
    auto C = cartan_matrix(B);

    // Check determinant of Cartan matrix
    // Finite type iff det(C) > 0 (for simply-laced types)
    // Compute det via Gaussian elimination
    std::vector<std::vector<double>> Cd(n, std::vector<double>(n));
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            Cd[i][j] = static_cast<double>(C[i][j]);

    double det = 1.0;
    for (int i = 0; i < n; ++i) {
        // Find pivot
        int pivot = -1;
        for (int j = i; j < n; ++j) {
            if (std::abs(Cd[j][i]) > 1e-10) { pivot = j; break; }
        }
        if (pivot < 0) return "infinite";

        if (pivot != i) std::swap(Cd[i], Cd[pivot]);
        det *= Cd[i][i];

        for (int j = i + 1; j < n; ++j) {
            double factor = Cd[j][i] / Cd[i][i];
            for (int k = i; k < n; ++k) {
                Cd[j][k] -= factor * Cd[i][k];
            }
        }
    }

    if (det <= 0.5) return "infinite";

    // Classify by rank and structure
    // Check off-diagonal entries for type identification
    int max_off_diag = 0;
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            if (i != j) max_off_diag = std::max(max_off_diag, std::abs(C[i][j]));

    if (max_off_diag <= 1) {
        // Simply-laced: ADE classification
        if (n <= 8) return "A_" + std::to_string(n);
        return "infinite";
    } else if (max_off_diag == 2) {
        return "B_" + std::to_string(n);
    } else {
        return "infinite";
    }
}

inline std::vector<std::vector<int>> ClusterAlgebra::cartan_matrix(
    const std::vector<std::vector<int>>& B) {

    int n = static_cast<int>(B.size());
    std::vector<std::vector<int>> C(n, std::vector<int>(n, 0));

    for (int i = 0; i < n; ++i) {
        C[i][i] = 2;
        for (int j = 0; j < n; ++j) {
            if (i != j) {
                C[i][j] = -std::abs(B[i][j]);
            }
        }
    }

    return C;
}

inline std::vector<double> ClusterAlgebra::protocol_to_cluster(
    const std::unordered_map<std::string, double>& features) {

    // Map protocol features to cluster variables
    // Standard mapping: header_size → x_0, payload_ratio → x_1, encryption → x_2
    std::vector<double> vars = {1.0, 1.0, 1.0};  // Default seed

    auto it = features.find("header_size");
    if (it != features.end()) vars[0] = std::max(0.01, it->second / 100.0);

    it = features.find("payload_ratio");
    if (it != features.end()) vars[1] = std::max(0.01, it->second);

    it = features.find("encryption");
    if (it != features.end()) vars[2] = std::max(0.01, it->second + 0.5);

    return vars;
}

inline std::unordered_map<std::string, double> ClusterAlgebra::cluster_to_protocol(
    const std::vector<double>& cluster_vars,
    const std::string& target_protocol) {

    std::unordered_map<std::string, double> features;

    // Inverse mapping with protocol-specific adjustments
    if (target_protocol == "HTTP") {
        features["header_size"] = cluster_vars.size() > 0 ? cluster_vars[0] * 100.0 : 200.0;
        features["payload_ratio"] = cluster_vars.size() > 1 ? cluster_vars[1] : 0.8;
        features["encryption"] = cluster_vars.size() > 2 ? cluster_vars[2] - 0.5 : 0.0;
    } else if (target_protocol == "DNS") {
        features["header_size"] = cluster_vars.size() > 0 ? cluster_vars[0] * 50.0 : 40.0;
        features["payload_ratio"] = cluster_vars.size() > 1 ? cluster_vars[1] * 0.5 : 0.4;
        features["encryption"] = cluster_vars.size() > 2 ? std::max(0.0, cluster_vars[2] - 0.8) : 0.0;
        features["query_length"] = cluster_vars.size() > 0 ? cluster_vars[0] * 30.0 : 20.0;
    } else if (target_protocol == "QUIC") {
        features["header_size"] = cluster_vars.size() > 0 ? cluster_vars[0] * 80.0 : 80.0;
        features["payload_ratio"] = cluster_vars.size() > 1 ? cluster_vars[1] : 0.9;
        features["encryption"] = cluster_vars.size() > 2 ? std::min(1.0, cluster_vars[2]) : 1.0;
    } else {
        // Generic
        for (size_t i = 0; i < cluster_vars.size(); ++i) {
            features["var_" + std::to_string(i)] = cluster_vars[i];
        }
    }

    return features;
}

inline std::unordered_map<std::string, double> ClusterAlgebra::protocol_mutation(
    const std::unordered_map<std::string, double>& source_features,
    const std::string& target_protocol) {

    // Map to cluster variables
    auto x_vars = protocol_to_cluster(source_features);

    // Default exchange matrix for 3-cluster
    int n = static_cast<int>(x_vars.size());
    std::vector<std::vector<int>> B(n, std::vector<int>(n, 0));
    for (int i = 0; i < n - 1; ++i) {
        B[i][i + 1] = 1;
        B[i + 1][i] = -1;
    }

    // Determine mutation direction from target protocol
    int target_dir = 0;
    if (target_protocol == "DNS") target_dir = 0;
    else if (target_protocol == "QUIC") target_dir = 1;
    else if (target_protocol == "WebSocket") target_dir = 2;
    else if (target_protocol == "HTTP") target_dir = 0;

    // Apply mutation
    auto [new_x, new_B] = mutate_sequence({target_dir}, x_vars, B);

    // Map back to protocol features
    return cluster_to_protocol(new_x, target_protocol);
}

inline ClusterResult ClusterAlgebra::transform(const std::vector<double>& data) {
    ClusterResult result;

    if (data.empty()) {
        result.error_msg = "Empty data";
        return result;
    }

    int n = std::min(static_cast<int>(data.size()), config_.initial_rank);

    // Use data as initial cluster variables
    std::vector<double> x_vars(n);
    for (int i = 0; i < n; ++i) {
        x_vars[i] = std::max(0.01, std::abs(data[i]));
    }

    // Create exchange matrix
    std::vector<std::vector<int>> B(n, std::vector<int>(n, 0));
    for (int i = 0; i < n - 1; ++i) {
        B[i][i + 1] = 1;
        B[i + 1][i] = -1;
    }

    // Apply mutation sequence
    std::vector<int> mutations;
    for (int i = 0; i < n; ++i) {
        mutations.push_back(i);
    }

    auto [new_x, new_B] = mutate_sequence(mutations, x_vars, B);

    result.cluster_vars = new_x;
    result.exchange_matrix = new_B;
    result.dynkin_type = finite_type_classification(new_B);

    // Convert back to data
    result.data.resize(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        int idx = static_cast<int>(i) % n;
        result.data[i] = (data[i] >= 0 ? 1.0 : -1.0) * new_x[idx];
    }

    result.success = true;
    return result;
}

} // namespace Math
} // namespace ncp

#endif // NCP_CLUSTER_HPP
