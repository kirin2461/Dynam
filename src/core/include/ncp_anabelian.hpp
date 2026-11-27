#pragma once
#ifndef NCP_ANABELIAN_HPP
#define NCP_ANABELIAN_HPP

/// @file ncp_anabelian.hpp
/// @brief Anabelian geometry for network topology reconstruction.
///
/// Grothendieck's anabelian conjecture (proven by Mochizuki for curves):
/// a hyperbolic curve over a number field is determined by its étale
/// fundamental group π₁^ét. That is, the topology of the space is
/// recoverable from the algebraic structure of its fundamental group.
///
/// Étale fundamental group π₁^ét(X, x̄):
/// - Classifies finite étale covers of X
/// - For a graph: π₁ is the free group on cycles
/// - Generators correspond to independent loops
/// - Relations encode the graph structure
///
/// Applications to network analysis:
/// - Traffic flows through a network define a topological space
/// - π₁^ét captures the routing structure
/// - Outer automorphisms Out(π₁) preserve the fundamental group structure
///   while changing the embedding → invisible topology morphs
/// - Dessin d'enfant: bipartite graph encoding of algebraic curves
///
/// Reference:
///   Mochizuki S. (1996). "The local pro-p anabelian geometry of curves."
///   Inventiones Mathematicae 124: 499-543.

#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <functional>
#include <set>

namespace ncp {
namespace Math {

struct AnabelianConfig {
    int base_prime = 2;
    int max_genus = 5;
    double embedding_threshold = 0.3;
};

/// Edge in the reconstructed topology.
struct TopoEdge {
    int from = 0;
    int to = 0;
    double weight = 1.0;
    int generator_index = -1;  // Which π₁ generator this edge belongs to
};

/// Node in the reconstructed topology.
struct TopoNode {
    int id = 0;
    std::string label;
    double centrality = 0.0;
};

/// Reconstructed network topology.
struct NetworkTopology {
    std::vector<TopoNode> nodes;
    std::vector<TopoEdge> edges;
    int genus = 0;                    // Genus = |E| - |V| + 1
    std::vector<int> betti_numbers;   // Betti numbers β₀, β₁, ...
    std::vector<std::vector<int>> generators;  // π₁ generators (cycle bases)
    int num_relations = 0;
};

/// Dessin d'enfant: bipartite graph encoding.
struct DessinDenfant {
    std::vector<std::pair<int, int>> edges;  // (black_vertex, white_vertex)
    int num_black = 0;
    int num_white = 0;
    int num_faces = 0;
    int genus = 0;
};

struct AnabelianResult {
    std::vector<double> data;
    NetworkTopology topology;
    int num_walls_crossed = 0;
    bool success = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// ANABELIAN RECONSTRUCTION
// ═══════════════════════════════════════════════════════════════════════════

class AnabelianReconstruction {
public:
    AnabelianReconstruction() = default;
    explicit AnabelianReconstruction(const AnabelianConfig& config) : config_(config) {}

    // ─── Fundamental group ───────────────────────────────────────────

    /// Compute π₁^ét from traffic samples.
    /// Each sample represents a path through the network.
    /// Cycles in the path ensemble generate π₁.
    NetworkTopology etale_fundamental_group(
        const std::vector<std::vector<double>>& traffic_samples) const;

    /// Compute π₁ generators from a graph (adjacency list).
    static std::vector<std::vector<int>> fundamental_group_generators(
        const std::vector<std::vector<int>>& adjacency);

    /// Compute genus from Euler characteristic: χ = V - E = 2 - 2g
    static int compute_genus(int num_vertices, int num_edges, int num_components = 1);

    // ─── Topology reconstruction ─────────────────────────────────────

    /// Reconstruct topology from traffic samples.
    /// Uses the traffic patterns to infer network graph structure.
    NetworkTopology reconstruct_from_traffic(
        const std::vector<std::vector<double>>& traffic_samples) const;

    /// Reconstruct topology from pairwise correlation matrix.
    /// High correlation ⟹ connected nodes.
    NetworkTopology reconstruct_from_correlations(
        const std::vector<std::vector<double>>& correlation_matrix,
        double threshold = 0.5) const;

    // ─── Outer automorphisms ─────────────────────────────────────────

    /// Apply outer automorphism to topology.
    /// Out(π₁) preserves group structure but changes embedding.
    /// This gives an "invisible" morph — same π₁, different geometry.
    static NetworkTopology apply_outer_automorphism(
        const NetworkTopology& topology,
        int automorphism_index = 0);

    /// Compute automorphism group size.
    static int automorphism_group_size(const NetworkTopology& topology);

    // ─── Dessin d'enfant ─────────────────────────────────────────────

    /// Construct dessin d'enfant from topology.
    /// Black vertices = network nodes, white vertices = edge midpoints.
    static DessinDenfant to_dessin(const NetworkTopology& topology);

    /// Reconstruct topology from dessin.
    static NetworkTopology from_dessin(const DessinDenfant& dessin);

    /// Compute Belyi function (simplified): maps topology to [0,1] interval.
    static std::vector<double> belyi_function(const NetworkTopology& topology);

    // ─── Topology-based stealth ──────────────────────────────────────

    /// Analyze topology-based stealth: how does the network topology
    /// affect traffic detectability?
    std::unordered_map<std::string, double> topology_stealth(
        const std::vector<double>& data) const;

    /// Transform data through topology-aware morph.
    AnabelianResult transform(const std::vector<double>& data);

    const AnabelianConfig& config() const { return config_; }
    void set_config(const AnabelianConfig& c) { config_ = c; }

private:
    AnabelianConfig config_;

    /// Build adjacency from traffic samples using correlation.
    std::vector<std::vector<int>> build_adjacency(
        const std::vector<std::vector<double>>& samples) const;

    /// Find cycle basis using BFS/DFS.
    static std::vector<std::vector<int>> find_cycle_basis(
        const std::vector<std::vector<int>>& adjacency, int num_vertices);

    /// Compute node centrality (betweenness).
    static std::vector<double> compute_centrality(
        const std::vector<std::vector<int>>& adjacency);
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline int AnabelianReconstruction::compute_genus(
    int V, int E, int C) {
    // Euler: χ = V - E = 2C - 2g
    // g = (2C - V + E) / 2
    int chi = V - E;
    int g = (2 * C - chi) / 2;
    return std::max(0, g);
}

inline std::vector<std::vector<int>> AnabelianReconstruction::fundamental_group_generators(
    const std::vector<std::vector<int>>& adjacency) {
    int n = static_cast<int>(adjacency.size());
    return find_cycle_basis(adjacency, n);
}

inline std::vector<std::vector<int>> AnabelianReconstruction::find_cycle_basis(
    const std::vector<std::vector<int>>& adjacency, int num_vertices) {

    // Find cycle basis using spanning tree approach:
    // 1. Build spanning tree via BFS
    // 2. Each non-tree edge creates exactly one fundamental cycle

    std::vector<bool> visited(num_vertices, false);
    std::vector<int> parent(num_vertices, -1);
    std::vector<int> depth(num_vertices, 0);
    std::set<std::pair<int, int>> tree_edges;

    // BFS to build spanning tree
    std::vector<int> queue;
    queue.push_back(0);
    visited[0] = true;

    size_t head = 0;
    while (head < queue.size()) {
        int u = queue[head++];
        for (int v : adjacency[u]) {
            if (!visited[v]) {
                visited[v] = true;
                parent[v] = u;
                depth[v] = depth[u] + 1;
                tree_edges.insert({std::min(u, v), std::max(u, v)});
                queue.push_back(v);
            }
        }
    }

    // Find fundamental cycles from non-tree edges
    std::vector<std::vector<int>> cycles;

    for (int u = 0; u < num_vertices; ++u) {
        for (int v : adjacency[u]) {
            if (u >= v) continue;
            auto edge = std::make_pair(std::min(u, v), std::max(u, v));
            if (tree_edges.count(edge) == 0) {
                // Non-tree edge: find path in tree from u to v
                // Cycle = path(u → LCA) + path(LCA → v) + edge(u, v)
                std::vector<int> cycle;

                // Find paths to root
                std::vector<int> path_u, path_v;
                int curr = u;
                while (curr != -1) { path_u.push_back(curr); curr = parent[curr]; }
                curr = v;
                while (curr != -1) { path_v.push_back(curr); curr = parent[curr]; }

                // Find LCA
                std::set<int> ancestors_u(path_u.begin(), path_u.end());
                int lca = -1;
                for (int node : path_v) {
                    if (ancestors_u.count(node)) { lca = node; break; }
                }

                if (lca >= 0) {
                    // Build cycle: u → ... → LCA → ... → v → u
                    std::vector<int> path_to_lca_u;
                    curr = u;
                    while (curr != lca) { path_to_lca_u.push_back(curr); curr = parent[curr]; }
                    path_to_lca_u.push_back(lca);

                    std::vector<int> path_to_lca_v;
                    curr = v;
                    while (curr != lca) { path_to_lca_v.push_back(curr); curr = parent[curr]; }

                    // Combine
                    cycle = path_to_lca_u;
                    std::reverse(path_to_lca_v.begin(), path_to_lca_v.end());
                    cycle.insert(cycle.end(), path_to_lca_v.begin(), path_to_lca_v.end());

                    if (cycle.size() >= 3) {
                        cycles.push_back(cycle);
                    }
                }
            }
        }
    }

    return cycles;
}

inline std::vector<double> AnabelianReconstruction::compute_centrality(
    const std::vector<std::vector<int>>& adjacency) {

    int n = static_cast<int>(adjacency.size());
    std::vector<double> centrality(n, 0.0);

    // Approximate betweenness centrality via BFS from each node
    for (int s = 0; s < n; ++s) {
        // BFS from s
        std::vector<int> dist(n, -1);
        std::vector<int> parent(n, -1);
        std::vector<int> count(n, 0);  // Number of shortest paths
        std::vector<int> queue;

        dist[s] = 0;
        count[s] = 1;
        queue.push_back(s);

        size_t head = 0;
        while (head < queue.size()) {
            int u = queue[head++];
            for (int v : adjacency[u]) {
                if (dist[v] == -1) {
                    dist[v] = dist[u] + 1;
                    count[v] = count[u];
                    parent[v] = u;
                    queue.push_back(v);
                } else if (dist[v] == dist[u] + 1) {
                    count[v] += count[u];
                }
            }
        }

        // Back-propagation for betweenness
        std::vector<double> delta(n, 0.0);
        for (int i = static_cast<int>(queue.size()) - 1; i >= 0; --i) {
            int w = queue[i];
            if (parent[w] != -1) {
                delta[parent[w]] += (1.0 + delta[w]) * count[parent[w]] / count[w];
            }
            if (w != s) {
                centrality[w] += delta[w];
            }
        }
    }

    // Normalize
    double max_c = *std::max_element(centrality.begin(), centrality.end());
    if (max_c > 1e-10) {
        for (double& c : centrality) c /= max_c;
    }

    return centrality;
}

inline std::vector<std::vector<int>> AnabelianReconstruction::build_adjacency(
    const std::vector<std::vector<double>>& samples) const {

    if (samples.empty()) return {};

    size_t max_len = 0;
    for (const auto& s : samples) max_len = std::max(max_len, s.size());

    if (max_len == 0) return {};

    // Compute correlation between each pair of positions
    size_t n = std::min(max_len, size_t(50));  // Limit size
    std::vector<std::vector<double>> corr(n, std::vector<double>(n, 0.0));

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i; j < n; ++j) {
            double sum_i = 0, sum_j = 0, sum_ij = 0;
            double sum_i2 = 0, sum_j2 = 0;
            int count = 0;

            for (const auto& sample : samples) {
                if (i < sample.size() && j < sample.size()) {
                    sum_i += sample[i];
                    sum_j += sample[j];
                    sum_ij += sample[i] * sample[j];
                    sum_i2 += sample[i] * sample[i];
                    sum_j2 += sample[j] * sample[j];
                    ++count;
                }
            }

            if (count > 1) {
                double mean_i = sum_i / count;
                double mean_j = sum_j / count;
                double cov = sum_ij / count - mean_i * mean_j;
                double std_i = std::sqrt(std::max(0.0, sum_i2 / count - mean_i * mean_i));
                double std_j = std::sqrt(std::max(0.0, sum_j2 / count - mean_j * mean_j));

                if (std_i > 1e-10 && std_j > 1e-10) {
                    corr[i][j] = cov / (std_i * std_j);
                    corr[j][i] = corr[i][j];
                }
            }
        }
    }

    // Build adjacency: connect if |correlation| > threshold
    std::vector<std::vector<int>> adj(n);
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            if (std::abs(corr[i][j]) > config_.embedding_threshold) {
                adj[i].push_back(static_cast<int>(j));
                adj[j].push_back(static_cast<int>(i));
            }
        }
    }

    return adj;
}

inline NetworkTopology AnabelianReconstruction::etale_fundamental_group(
    const std::vector<std::vector<double>>& traffic_samples) const {

    NetworkTopology topo;
    auto adj = build_adjacency(traffic_samples);
    int n = static_cast<int>(adj.size());

    if (n == 0) return topo;

    // Create nodes
    auto centrality = compute_centrality(adj);
    for (int i = 0; i < n; ++i) {
        TopoNode node;
        node.id = i;
        node.label = "node_" + std::to_string(i);
        node.centrality = centrality[i];
        topo.nodes.push_back(node);
    }

    // Create edges
    int edge_count = 0;
    for (int i = 0; i < n; ++i) {
        for (int j : adj[i]) {
            if (i < j) {
                TopoEdge edge;
                edge.from = i;
                edge.to = j;
                edge.weight = 1.0;
                topo.edges.push_back(edge);
                ++edge_count;
            }
        }
    }

    // Compute π₁ generators
    topo.generators = find_cycle_basis(adj, n);

    // Compute genus
    int num_components = 0;
    std::vector<bool> visited(n, false);
    for (int i = 0; i < n; ++i) {
        if (!visited[i]) {
            ++num_components;
            // BFS to mark component
            std::vector<int> queue = {i};
            visited[i] = true;
            size_t head = 0;
            while (head < queue.size()) {
                int u = queue[head++];
                for (int v : adj[u]) {
                    if (!visited[v]) {
                        visited[v] = true;
                        queue.push_back(v);
                    }
                }
            }
        }
    }

    topo.genus = compute_genus(n, edge_count, num_components);
    topo.betti_numbers = {num_components, static_cast<int>(topo.generators.size())};

    return topo;
}

inline NetworkTopology AnabelianReconstruction::reconstruct_from_traffic(
    const std::vector<std::vector<double>>& traffic_samples) const {
    return etale_fundamental_group(traffic_samples);
}

inline NetworkTopology AnabelianReconstruction::reconstruct_from_correlations(
    const std::vector<std::vector<double>>& correlation_matrix,
    double threshold) const {

    NetworkTopology topo;
    int n = static_cast<int>(correlation_matrix.size());
    if (n == 0) return topo;

    // Create nodes
    for (int i = 0; i < n; ++i) {
        TopoNode node;
        node.id = i;
        node.label = "node_" + std::to_string(i);
        topo.nodes.push_back(node);
    }

    // Create edges where |correlation| > threshold
    std::vector<std::vector<int>> adj(n);
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (std::abs(correlation_matrix[i][j]) > threshold) {
                TopoEdge edge;
                edge.from = i;
                edge.to = j;
                edge.weight = std::abs(correlation_matrix[i][j]);
                topo.edges.push_back(edge);
                adj[i].push_back(j);
                adj[j].push_back(i);
            }
        }
    }

    topo.generators = find_cycle_basis(adj, n);
    topo.genus = compute_genus(n, static_cast<int>(topo.edges.size()));
    topo.betti_numbers = {1, static_cast<int>(topo.generators.size())};

    return topo;
}

inline NetworkTopology AnabelianReconstruction::apply_outer_automorphism(
    const NetworkTopology& topology, int automorphism_index) {

    NetworkTopology result = topology;

    // Outer automorphism: permute generators while preserving group structure
    if (result.generators.empty()) return result;

    int num_gen = static_cast<int>(result.generators.size());
    if (num_gen < 2) return result;

    // Apply cyclic permutation of generators
    int shift = automorphism_index % num_gen;
    std::rotate(result.generators.begin(),
                result.generators.begin() + shift,
                result.generators.end());

    // Update edge generator indices
    for (auto& edge : result.edges) {
        if (edge.generator_index >= 0) {
            edge.generator_index = (edge.generator_index + shift) % num_gen;
        }
    }

    return result;
}

inline int AnabelianReconstruction::automorphism_group_size(
    const NetworkTopology& topology) {
    // Simplified: |Aut(Γ)| for a graph is hard to compute exactly
    // Use approximation based on symmetry

    int symmetry = 1;

    // Count nodes with same degree
    std::unordered_map<int, int> degree_count;
    for (const auto& node : topology.nodes) {
        int deg = 0;
        for (const auto& edge : topology.edges) {
            if (edge.from == node.id || edge.to == node.id) ++deg;
        }
        degree_count[deg]++;
    }

    for (const auto& [deg, count] : degree_count) {
        // Nodes with same degree can be permuted
        int factorial = 1;
        for (int i = 2; i <= count; ++i) factorial *= i;
        symmetry *= factorial;
    }

    return symmetry;
}

inline DessinDenfant AnabelianReconstruction::to_dessin(
    const NetworkTopology& topology) {

    DessinDenfant dessin;
    int n = static_cast<int>(topology.nodes.size());

    // Black vertices = original nodes
    dessin.num_black = n;

    // White vertices = edge midpoints
    dessin.num_white = static_cast<int>(topology.edges.size());

    // Edges in dessin: each original edge connects two black vertices
    // through a white vertex
    for (size_t i = 0; i < topology.edges.size(); ++i) {
        int white_id = n + static_cast<int>(i);
        dessin.edges.push_back({topology.edges[i].from, white_id});
        dessin.edges.push_back({topology.edges[i].to, white_id});
    }

    // Compute faces using Euler: V - E + F = 2 - 2g
    int V = dessin.num_black + dessin.num_white;
    int E = static_cast<int>(dessin.edges.size());
    int g = topology.genus;
    dessin.num_faces = 2 - 2 * g - V + E;
    dessin.genus = g;

    return dessin;
}

inline NetworkTopology AnabelianReconstruction::from_dessin(
    const DessinDenfant& dessin) {

    NetworkTopology topo;

    // Black vertices → nodes
    for (int i = 0; i < dessin.num_black; ++i) {
        TopoNode node;
        node.id = i;
        node.label = "node_" + std::to_string(i);
        topo.nodes.push_back(node);
    }

    // Reconstruct edges from bipartite structure
    // Each pair (black, white) that shares a white vertex gives an edge
    std::unordered_map<int, std::vector<int>> white_to_black;
    for (const auto& [b, w] : dessin.edges) {
        if (w >= dessin.num_black) {
            white_to_black[w].push_back(b);
        }
    }

    for (const auto& [white, blacks] : white_to_black) {
        if (blacks.size() == 2) {
            TopoEdge edge;
            edge.from = std::min(blacks[0], blacks[1]);
            edge.to = std::max(blacks[0], blacks[1]);
            edge.weight = 1.0;
            topo.edges.push_back(edge);
        }
    }

    topo.genus = dessin.genus;
    return topo;
}

inline std::vector<double> AnabelianReconstruction::belyi_function(
    const NetworkTopology& topology) {

    // Belyi function β: X → ℙ¹ ramified over {0, 1, ∞}
    // Simplified: map nodes to [0, 1] based on distance from "origin" node

    int n = static_cast<int>(topology.nodes.size());
    if (n == 0) return {};

    // Build adjacency
    std::vector<std::vector<int>> adj(n);
    for (const auto& edge : topology.edges) {
        adj[edge.from].push_back(edge.to);
        adj[edge.to].push_back(edge.from);
    }

    // BFS from node 0
    std::vector<int> dist(n, -1);
    std::vector<int> queue = {0};
    dist[0] = 0;
    size_t head = 0;
    int max_dist = 0;

    while (head < queue.size()) {
        int u = queue[head++];
        for (int v : adj[u]) {
            if (dist[v] == -1) {
                dist[v] = dist[u] + 1;
                max_dist = std::max(max_dist, dist[v]);
                queue.push_back(v);
            }
        }
    }

    // Map to [0, 1]
    std::vector<double> beta(n);
    for (int i = 0; i < n; ++i) {
        beta[i] = (max_dist > 0) ? static_cast<double>(dist[i]) / max_dist : 0.0;
    }

    return beta;
}

inline std::unordered_map<std::string, double> AnabelianReconstruction::topology_stealth(
    const std::vector<double>& data) const {

    std::unordered_map<std::string, double> result;

    if (data.empty()) return result;

    // Compute topological complexity metrics
    double entropy = 0.0;
    {
        std::vector<int> hist(32, 0);
        double min_v = *std::min_element(data.begin(), data.end());
        double max_v = *std::max_element(data.begin(), data.end());
        double range = max_v - min_v;
        if (range > 1e-15) {
            for (double v : data) {
                int bin = static_cast<int>((v - min_v) / range * 31);
                hist[std::min(31, std::max(0, bin))]++;
            }
            double n = static_cast<double>(data.size());
            for (int count : hist) {
                if (count > 0) {
                    double p = count / n;
                    entropy -= p * std::log2(p);
                }
            }
        }
    }

    // Topological complexity ≈ entropy * (1 + genus_factor)
    result["entropy"] = entropy;
    result["stealth_score"] = entropy / std::log2(32.0);  // Normalized
    result["topological_complexity"] = entropy * (1.0 + config_.max_genus * 0.1);
    result["data_length"] = static_cast<double>(data.size());

    return result;
}

inline AnabelianResult AnabelianReconstruction::transform(
    const std::vector<double>& data) {

    AnabelianResult result;

    if (data.empty()) {
        result.error_msg = "Empty data";
        return result;
    }

    // Create "traffic samples" from sliding window
    size_t window = std::min(size_t(20), data.size());
    size_t num_samples = std::max(size_t(1), (data.size() - window) / 5 + 1);

    std::vector<std::vector<double>> samples;
    for (size_t i = 0; i < num_samples; ++i) {
        size_t start = i * 5;
        if (start + window > data.size()) break;
        std::vector<double> sample(data.begin() + start,
                                    data.begin() + start + window);
        samples.push_back(sample);
    }

    // Reconstruct topology
    result.topology = reconstruct_from_traffic(samples);

    // Apply outer automorphism for invisible morph
    auto morphed_topo = apply_outer_automorphism(result.topology, 1);

    // Transform data using Belyi function
    auto beta = belyi_function(morphed_topo);

    // Apply transformation to data
    result.data = data;
    if (!beta.empty()) {
        for (size_t i = 0; i < data.size(); ++i) {
            int node_idx = static_cast<int>(i) % static_cast<int>(beta.size());
            result.data[i] *= (1.0 + 0.1 * (beta[node_idx] - 0.5));
        }
    }

    result.success = true;
    return result;
}

} // namespace Math
} // namespace ncp

#endif // NCP_ANABELIAN_HPP
