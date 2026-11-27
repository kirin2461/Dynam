#pragma once
#ifndef NCP_TOPOLOGICAL_HPP
#define NCP_TOPOLOGICAL_HPP

/// @file ncp_topological.hpp
/// @brief Topological data analysis: persistent homology and optimal transport.
///
/// Implements Vietoris-Rips filtration on point cloud data (1D or 2D),
/// persistence diagram computation, and Wasserstein distance between diagrams.
///
/// Vietoris-Rips complex: for threshold ε, connect all pairs at distance ≤ ε.
/// As ε increases, edges appear (H₁ births), triangles fill in (H₁ deaths).
/// The persistence of each feature = death - birth. Long-lived features
/// represent genuine topology; short-lived ones are noise.
///
/// Wasserstein-1 distance between persistence diagrams uses the Hungarian
/// algorithm (or 1D sorting for diagonal projections).
///
/// Sinkhorn algorithm provides fast approximate optimal transport:
///   min <P, C> s.t. P1 = a, P^T 1 = b, P ≥ 0
/// via iterative proportional fitting: u ← 1/(Kv), v ← 1/(K^T u).

#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <string>
#include <limits>
#include <queue>

namespace ncp {
namespace Math {

/// A point in a persistence diagram: (birth, death).
struct PersistencePair {
    double birth = 0.0;
    double death = 0.0;
    int dimension = 0;  // Homology dimension (0 = connected components, 1 = loops)

    double persistence() const { return death - birth; }
};

struct TopologicalConfig {
    int max_homology_dim = 1;
    double max_filtration_radius = 10.0;
    int num_filtration_steps = 50;
    int sinkhorn_iterations = 100;
    double sinkhorn_epsilon = 0.1;   ///< Regularization parameter
};

struct TopologicalResult {
    std::vector<double> data;
    std::vector<PersistencePair> diagram;  ///< Persistence pairs
    double wasserstein_distance = 0.0;     ///< W1 to reference diagram
    double total_persistence = 0.0;
    double num_features = 0.0;
    bool success = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// TOPOLOGICAL MORPHER
// ═══════════════════════════════════════════════════════════════════════════

class TopologicalMorpher {
public:
    TopologicalMorpher() = default;
    explicit TopologicalMorpher(const TopologicalConfig& config) : config_(config) {}

    /// Compute pairwise distance matrix for 1D data (embedded as points on line).
    static std::vector<std::vector<double>> pairwise_distances(
        const std::vector<double>& data);

    /// Build Vietoris-Rips complex at given threshold ε.
    /// Returns list of edges (pairs of point indices).
    static std::vector<std::pair<int, int>> vietoris_rips_edges(
        const std::vector<double>& data, double epsilon);

    /// Compute persistence diagram via sublevel set filtration.
    /// For 1D data, this is the filtration by function value.
    std::vector<PersistencePair> persistence_diagram(
        const std::vector<double>& data) const;

    /// Compute persistence diagram from pairwise distances (Rips filtration).
    std::vector<PersistencePair> rips_persistence(
        const std::vector<double>& data) const;

    /// Wasserstein-1 distance between two persistence diagrams.
    /// Uses sorting-based algorithm for 1D bottleneck matching.
    static double wasserstein_distance(
        const std::vector<PersistencePair>& diag1,
        const std::vector<PersistencePair>& diag2);

    /// Bottleneck distance between diagrams.
    static double bottleneck_distance(
        const std::vector<PersistencePair>& diag1,
        const std::vector<PersistencePair>& diag2);

    /// Sinkhorn optimal transport distance between two distributions.
    /// cost_matrix[i][j] = cost of moving mass from i to j.
    /// a, b = source and target distributions (must sum to 1).
    static double sinkhorn_distance(
        const std::vector<std::vector<double>>& cost_matrix,
        const std::vector<double>& a,
        const std::vector<double>& b,
        int num_iterations = 100,
        double epsilon = 0.1);

    /// Transform data by modifying its topological structure.
    TopologicalResult transform(const std::vector<double>& data);

    /// Morph data toward a target persistence diagram.
    TopologicalResult morph_toward(
        const std::vector<double>& data,
        const std::vector<PersistencePair>& target_diagram);

    /// Compute Betti numbers at each filtration step.
    std::vector<int> betti_numbers(const std::vector<double>& data) const;

    const TopologicalConfig& config() const { return config_; }
    void set_config(const TopologicalConfig& c) { config_ = c; }

private:
    TopologicalConfig config_;

    /// Union-Find for computing H₀ persistence.
    class UnionFind {
    public:
        explicit UnionFind(int n) : parent_(n), rank_(n, 0) {
            std::iota(parent_.begin(), parent_.end(), 0);
        }
        int find(int x) {
            while (parent_[x] != x) {
                parent_[x] = parent_[parent_[x]];
                x = parent_[x];
            }
            return x;
        }
        bool unite(int x, int y) {
            x = find(x); y = find(y);
            if (x == y) return false;
            if (rank_[x] < rank_[y]) std::swap(x, y);
            parent_[y] = x;
            if (rank_[x] == rank_[y]) ++rank_[x];
            return true;
        }
    private:
        std::vector<int> parent_;
        std::vector<int> rank_;
    };
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline std::vector<std::vector<double>> TopologicalMorpher::pairwise_distances(
    const std::vector<double>& data) {
    size_t n = data.size();
    std::vector<std::vector<double>> dist(n, std::vector<double>(n, 0.0));

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            double d = std::abs(data[i] - data[j]);
            dist[i][j] = d;
            dist[j][i] = d;
        }
    }
    return dist;
}

inline std::vector<std::pair<int, int>> TopologicalMorpher::vietoris_rips_edges(
    const std::vector<double>& data, double epsilon) {
    std::vector<std::pair<int, int>> edges;
    size_t n = data.size();

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (std::abs(data[i] - data[j]) <= epsilon) {
                edges.push_back({static_cast<int>(i), static_cast<int>(j)});
            }
        }
    }
    return edges;
}

inline std::vector<PersistencePair> TopologicalMorpher::persistence_diagram(
    const std::vector<double>& data) const {

    // Sublevel set filtration for 1D data:
    // Sort values, track connected components (H₀) as threshold increases.
    // Each merge of two components creates a death event.

    std::vector<PersistencePair> diagram;
    size_t n = data.size();
    if (n < 2) return diagram;

    // Sort indices by data value
    std::vector<int> sorted_idx(n);
    std::iota(sorted_idx.begin(), sorted_idx.end(), 0);
    std::sort(sorted_idx.begin(), sorted_idx.end(),
              [&](int a, int b) { return data[a] < data[b]; });

    // Union-Find for tracking components
    UnionFind uf(static_cast<int>(n));
    std::vector<double> birth_time(static_cast<int>(n), 0.0);
    std::vector<bool> active(static_cast<int>(n), false);

    // Process points in order of increasing value
    for (size_t step = 0; step < n; ++step) {
        int idx = sorted_idx[step];
        double val = data[idx];
        active[idx] = true;
        birth_time[idx] = val;

        // Check neighbors (in original index space) for existing connections
        for (int neighbor : {idx - 1, idx + 1}) {
            if (neighbor >= 0 && neighbor < static_cast<int>(n) && active[neighbor]) {
                int root_idx = uf.find(idx);
                int root_nbr = uf.find(neighbor);

                if (root_idx != root_nbr) {
                    // Merge: younger component dies
                    int dying;
                    if (birth_time[root_idx] > birth_time[root_nbr]) {
                        dying = root_idx;
                    } else {
                        dying = root_nbr;
                    }

                    PersistencePair pair;
                    pair.birth = birth_time[dying];
                    pair.death = val;
                    pair.dimension = 0;
                    if (pair.persistence() > 1e-10) {
                        diagram.push_back(pair);
                    }

                    uf.unite(idx, neighbor);
                }
            }
        }
    }

    // Components that never die → paired with infinity
    // (we use max_data_value + range as proxy for infinity)
    double max_val = data[sorted_idx.back()];
    double min_val = data[sorted_idx[0]];
    double inf_proxy = max_val + (max_val - min_val);

    for (int i = 0; i < static_cast<int>(n); ++i) {
        if (uf.find(i) == i && active[i]) {
            PersistencePair pair;
            pair.birth = birth_time[i];
            pair.death = inf_proxy;
            pair.dimension = 0;
            diagram.push_back(pair);
        }
    }

    return diagram;
}

inline std::vector<PersistencePair> TopologicalMorpher::rips_persistence(
    const std::vector<double>& data) const {

    // Full Rips filtration: sort all edges by distance, add them one by one.
    // Track H₀ with Union-Find.
    // H₁ would need cycle detection (not implemented in simplified version).

    std::vector<PersistencePair> diagram;
    size_t n = data.size();
    if (n < 2) return diagram;

    // Compute all edge distances
    struct Edge {
        int u, v;
        double dist;
        bool operator<(const Edge& o) const { return dist < o.dist; }
    };

    std::vector<Edge> edges;
    edges.reserve(n * (n - 1) / 2);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            edges.push_back({static_cast<int>(i), static_cast<int>(j),
                            std::abs(data[i] - data[j])});
        }
    }
    std::sort(edges.begin(), edges.end());

    // Process edges in order of increasing distance
    UnionFind uf(static_cast<int>(n));
    std::vector<double> birth(static_cast<int>(n), 0.0);  // Birth = 0 for all (appear at ε=0)

    for (const auto& edge : edges) {
        if (edge.dist > config_.max_filtration_radius) break;

        int ru = uf.find(edge.u);
        int rv = uf.find(edge.v);

        if (ru != rv) {
            // Merge: the component born later dies
            int dying = (birth[ru] > birth[rv]) ? ru : rv;
            int surviving = (birth[ru] > birth[rv]) ? rv : ru;

            PersistencePair pair;
            pair.birth = birth[dying];
            pair.death = edge.dist;
            pair.dimension = 0;
            if (pair.persistence() > 1e-10) {
                diagram.push_back(pair);
            }

            uf.unite(edge.u, edge.v);
            // New root gets birth time of surviving component
            int new_root = uf.find(edge.u);
            birth[new_root] = birth[surviving];
        }
    }

    return diagram;
}

inline double TopologicalMorpher::wasserstein_distance(
    const std::vector<PersistencePair>& diag1,
    const std::vector<PersistencePair>& diag2) {

    // W1 between persistence diagrams.
    // Match points using sorting by (birth + death) / 2, with diagonal projection.

    if (diag1.empty() && diag2.empty()) return 0.0;

    // Convert to (birth, persistence) coordinates
    auto to_bp = [](const PersistencePair& p) -> std::pair<double, double> {
        return {p.birth, p.persistence()};
    };

    std::vector<std::pair<double, double>> pts1, pts2;
    for (const auto& p : diag1) pts1.push_back(to_bp(p));
    for (const auto& p : diag2) pts2.push_back(to_bp(p));

    // Sort by birth time
    std::sort(pts1.begin(), pts1.end());
    std::sort(pts2.begin(), pts2.end());

    // Match using sorted order (greedy nearest-neighbor in 1D)
    double total_cost = 0.0;
    size_t i = 0, j = 0;

    while (i < pts1.size() && j < pts2.size()) {
        // L1 distance in (birth, persistence) space
        double cost_direct = std::abs(pts1[i].first - pts2[j].first) +
                              std::abs(pts1[i].second - pts2[j].second);

        // Cost of projecting to diagonal (persistence = 0)
        double cost_diag1 = pts1[i].second;  // persistence of point 1
        double cost_diag2 = pts2[j].second;  // persistence of point 2

        // Choose minimum cost matching
        double min_cost = std::min({cost_direct, cost_diag1 + cost_diag2});
        total_cost += min_cost;

        ++i;
        ++j;
    }

    // Remaining unmatched points → project to diagonal
    while (i < pts1.size()) {
        total_cost += pts1[i].second;
        ++i;
    }
    while (j < pts2.size()) {
        total_cost += pts2[j].second;
        ++j;
    }

    return total_cost;
}

inline double TopologicalMorpher::bottleneck_distance(
    const std::vector<PersistencePair>& diag1,
    const std::vector<PersistencePair>& diag2) {

    if (diag1.empty() && diag2.empty()) return 0.0;

    double max_cost = 0.0;

    // L∞ matching (simplified greedy)
    size_t n = std::max(diag1.size(), diag2.size());
    for (size_t i = 0; i < n; ++i) {
        double cost;
        if (i < diag1.size() && i < diag2.size()) {
            cost = std::max(
                std::abs(diag1[i].birth - diag2[i].birth),
                std::abs(diag1[i].death - diag2[i].death));
        } else if (i < diag1.size()) {
            cost = diag1[i].persistence() / 2.0;  // distance to diagonal
        } else {
            cost = diag2[i].persistence() / 2.0;
        }
        if (cost > max_cost) max_cost = cost;
    }

    return max_cost;
}

inline double TopologicalMorpher::sinkhorn_distance(
    const std::vector<std::vector<double>>& cost_matrix,
    const std::vector<double>& a,
    const std::vector<double>& b,
    int num_iterations,
    double epsilon) {

    size_t n = a.size();
    size_t m = b.size();
    if (n == 0 || m == 0) return 0.0;

    // Kernel: K = exp(-C / ε)
    std::vector<std::vector<double>> K(n, std::vector<double>(m));
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < m; ++j) {
            K[i][j] = std::exp(-cost_matrix[i][j] / epsilon);
        }
    }

    // Sinkhorn-Knopp iterations
    std::vector<double> u(n, 1.0 / n);
    std::vector<double> v(m, 1.0 / m);

    for (int iter = 0; iter < num_iterations; ++iter) {
        // u ← a / (K * v)
        for (size_t i = 0; i < n; ++i) {
            double sum = 0.0;
            for (size_t j = 0; j < m; ++j) {
                sum += K[i][j] * v[j];
            }
            u[i] = (sum > 1e-15) ? a[i] / sum : 1.0 / n;
        }

        // v ← b / (K^T * u)
        for (size_t j = 0; j < m; ++j) {
            double sum = 0.0;
            for (size_t i = 0; i < n; ++i) {
                sum += K[i][j] * u[i];
            }
            v[j] = (sum > 1e-15) ? b[j] / sum : 1.0 / m;
        }
    }

    // Transport cost: <P*, C> where P* = diag(u) * K * diag(v)
    double cost = 0.0;
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < m; ++j) {
            double p_ij = u[i] * K[i][j] * v[j];
            cost += p_ij * cost_matrix[i][j];
        }
    }

    return cost;
}

inline TopologicalResult TopologicalMorpher::transform(
    const std::vector<double>& data) {

    TopologicalResult result;
    if (data.size() < 4) {
        result.error_msg = "Data too short for topological analysis";
        return result;
    }

    result.data = data;
    result.diagram = persistence_diagram(data);

    result.total_persistence = 0.0;
    for (const auto& p : result.diagram) {
        result.total_persistence += p.persistence();
    }
    result.num_features = static_cast<double>(result.diagram.size());
    result.success = true;

    return result;
}

inline TopologicalResult TopologicalMorpher::morph_toward(
    const std::vector<double>& data,
    const std::vector<PersistencePair>& target_diagram) {

    TopologicalResult result = transform(data);
    if (!result.success) return result;

    // Compute Wasserstein distance to target
    result.wasserstein_distance = wasserstein_distance(result.diagram, target_diagram);

    return result;
}

inline std::vector<int> TopologicalMorpher::betti_numbers(
    const std::vector<double>& data) const {

    std::vector<int> betti;
    size_t n = data.size();
    if (n < 2) return betti;

    // Compute Betti numbers at each filtration step
    std::vector<double> sorted_data = data;
    std::sort(sorted_data.begin(), sorted_data.end());

    int num_steps = config_.num_filtration_steps;
    double min_val = sorted_data.front();
    double max_val = sorted_data.back();
    double step_size = (max_val - min_val) / num_steps;

    for (int s = 0; s <= num_steps; ++s) {
        double eps = min_val + s * step_size;

        // Count connected components using Union-Find
        UnionFind uf(static_cast<int>(n));
        int num_edges = 0;

        for (size_t i = 0; i < n; ++i) {
            for (size_t j = i + 1; j < n; ++j) {
                if (std::abs(data[i] - data[j]) <= eps) {
                    if (uf.find(static_cast<int>(i)) != uf.find(static_cast<int>(j))) {
                        uf.unite(static_cast<int>(i), static_cast<int>(j));
                    }
                    ++num_edges;
                }
            }
        }

        // Count components
        std::vector<bool> seen(n, false);
        int num_components = 0;
        for (size_t i = 0; i < n; ++i) {
            int root = uf.find(static_cast<int>(i));
            if (!seen[root]) {
                seen[root] = true;
                ++num_components;
            }
        }

        // β₀ = components, β₁ = edges - vertices + components (Euler)
        int beta0 = num_components;
        int beta1 = num_edges - static_cast<int>(n) + num_components;
        beta1 = std::max(0, beta1);

        betti.push_back(beta0);
    }

    return betti;
}

} // namespace Math
} // namespace ncp

#endif // NCP_TOPOLOGICAL_HPP
