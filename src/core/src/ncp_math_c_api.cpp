/// @file ncp_math_c_api.cpp
/// @brief Implementation of C API for Python ctypes integration.

#include "ncp_math_c_api.hpp"
#include "ncp_math_all.hpp"
#include <cstring>
#include <cmath>
#include <vector>
#include <algorithm>

using namespace ncp::Math;

// ─── FRACTAL ────────────────────────────────────────────────────────────

extern "C" int ncp_fractal_generate(double* output, int length, double hurst, uint32_t seed) {
    if (!output || length <= 0) return NCP_ERROR_NULL_POINTER;
    if (hurst <= 0.0 || hurst >= 1.0) return NCP_ERROR_INVALID_INPUT;

    FractalConfig cfg;
    cfg.hurst = hurst;
    cfg.length = static_cast<size_t>(length);
    cfg.seed = seed;

    FractalTrafficGenerator gen(cfg);
    auto result = gen.generate_fgn();

    if (!result.success) return NCP_ERROR_COMPUTATION;

    std::copy(result.data.begin(), result.data.end(), output);
    return NCP_OK;
}

extern "C" double ncp_fractal_compute_hurst(const double* data, int length) {
    if (!data || length < 20) return 0.5;

    std::vector<double> v(data, data + length);
    FractalTrafficGenerator gen;
    return gen.compute_hurst(v);
}

extern "C" int ncp_fractal_transform(const double* input, double* output, int length, double target_hurst) {
    if (!input || !output || length < 4) return NCP_ERROR_NULL_POINTER;

    std::vector<double> in_vec(input, input + length);
    FractalTrafficGenerator gen;
    auto result = gen.transform(in_vec, target_hurst);

    if (!result.success) return NCP_ERROR_COMPUTATION;
    std::copy(result.data.begin(), result.data.end(), output);
    return NCP_OK;
}

// ─── CHAOTIC ────────────────────────────────────────────────────────────

extern "C" int ncp_chaotic_transform(const double* input, double* output, int length, double epsilon) {
    if (!input || !output || length < 4) return NCP_ERROR_NULL_POINTER;

    std::vector<double> in_vec(input, input + length);
    ChaoticConfig cfg;
    cfg.epsilon = epsilon;
    ChaoticEmbedder embedder(cfg);
    auto result = embedder.embed(in_vec, epsilon);

    if (!result.success) return NCP_ERROR_COMPUTATION;
    std::copy(result.data.begin(), result.data.end(), output);
    return NCP_OK;
}

extern "C" int ncp_chaotic_trajectory(double* output_x, double* output_y, double* output_z,
                                        int length, double sigma, double rho, double beta) {
    if (!output_x || !output_y || !output_z || length <= 0) return NCP_ERROR_NULL_POINTER;

    ChaoticConfig cfg;
    cfg.sigma = sigma;
    cfg.rho = rho;
    cfg.beta = beta;
    ChaoticEmbedder embedder(cfg);

    auto traj = embedder.generate_trajectory_3d(static_cast<size_t>(length));

    for (int i = 0; i < length && i < static_cast<int>(traj.size()); ++i) {
        output_x[i] = traj[i][0];
        output_y[i] = traj[i][1];
        output_z[i] = traj[i][2];
    }
    return NCP_OK;
}

extern "C" double ncp_chaotic_lyapunov(const double* data, int length) {
    if (!data || length < 20) return 0.0;

    std::vector<double> v(data, data + length);
    ChaoticEmbedder embedder;
    return embedder.largest_lyapunov(v);
}

// ─── ERGODIC ────────────────────────────────────────────────────────────

extern "C" int ncp_ergodic_arnold(const double* input, double* output, int length, int iterations) {
    if (!input || !output || length < 2) return NCP_ERROR_NULL_POINTER;

    // Apply Arnold cat map to pairs
    for (int i = 0; i + 1 < length; i += 2) {
        auto [x, y] = ErgodicShaper::arnold_cat_map(input[i], input[i+1], iterations);
        output[i] = x;
        output[i+1] = y;
    }
    if (length % 2 != 0) output[length-1] = input[length-1];

    return NCP_OK;
}

extern "C" int ncp_ergodic_baker(const double* input, double* output, int length, int iterations) {
    if (!input || !output || length < 2) return NCP_ERROR_NULL_POINTER;

    for (int i = 0; i + 1 < length; i += 2) {
        auto [x, y] = ErgodicShaper::baker_map(input[i], input[i+1], iterations);
        output[i] = x;
        output[i+1] = y;
    }
    if (length % 2 != 0) output[length-1] = input[length-1];

    return NCP_OK;
}

extern "C" double ncp_ergodic_convergence(const double* data, int length) {
    if (!data || length < 10) return 0.0;

    std::vector<double> v(data, data + length);
    ErgodicShaper shaper;
    return shaper.birkhoff_convergence(v);
}

extern "C" double ncp_ergodic_guarantee(const double* data, int length) {
    if (!data || length < 10) return 0.0;

    std::vector<double> v(data, data + length);
    ErgodicShaper shaper;
    return shaper.ergodic_guarantee(v);
}

// ─── TOPOLOGICAL ────────────────────────────────────────────────────────

extern "C" int ncp_topo_persistence(const double* data, int length,
                                      double* births, double* deaths, int max_pairs) {
    if (!data || !births || !deaths || length < 2) return 0;

    std::vector<double> v(data, data + length);
    TopologicalMorpher morpher;
    auto diagram = morpher.persistence_diagram(v);

    int n = std::min(static_cast<int>(diagram.size()), max_pairs);
    for (int i = 0; i < n; ++i) {
        births[i] = diagram[i].birth;
        deaths[i] = diagram[i].death;
    }
    return n;
}

extern "C" double ncp_topo_wasserstein(const double* births1, const double* deaths1, int n1,
                                         const double* births2, const double* deaths2, int n2) {
    if (!births1 || !deaths1 || !births2 || !deaths2) return 0.0;

    std::vector<PersistencePair> d1(n1), d2(n2);
    for (int i = 0; i < n1; ++i) { d1[i].birth = births1[i]; d1[i].death = deaths1[i]; }
    for (int i = 0; i < n2; ++i) { d2[i].birth = births2[i]; d2[i].death = deaths2[i]; }

    return TopologicalMorpher::wasserstein_distance(d1, d2);
}

// ─── TROPICAL ───────────────────────────────────────────────────────────

extern "C" double ncp_tropical_add(double a, double b) {
    return TropicalGeometry::tropical_add(a, b);
}

extern "C" double ncp_tropical_multiply(double a, double b) {
    return TropicalGeometry::tropical_multiply(a, b);
}

extern "C" double ncp_tropical_poly_eval(const double* coeffs, const int* exponents,
                                           int num_terms, double x) {
    if (!coeffs || !exponents || num_terms <= 0) return TROPICAL_INF;

    std::vector<double> c(coeffs, coeffs + num_terms);
    std::vector<int> e(exponents, exponents + num_terms);
    return TropicalGeometry::tropical_polynomial(c, e, x);
}

extern "C" int ncp_tropical_lp(const double* c, int n,
                                 const double* A, int m,
                                 const double* b,
                                 double* optimal_point, double* optimal_value) {
    if (!c || !A || !b || !optimal_point || !optimal_value) return NCP_ERROR_NULL_POINTER;

    std::vector<double> c_vec(c, c + n);
    std::vector<double> b_vec(b, b + m);
    std::vector<std::vector<double>> A_vec(m, std::vector<double>(n));
    for (int i = 0; i < m; ++i)
        for (int j = 0; j < n; ++j)
            A_vec[i][j] = A[i * n + j];

    auto result = TropicalGeometry::tropical_linear_program(c_vec, A_vec, b_vec);

    if (!result.feasible) return NCP_ERROR_COMPUTATION;

    std::copy(result.optimal_point.begin(), result.optimal_point.end(), optimal_point);
    *optimal_value = result.optimal_value;
    return NCP_OK;
}

// ─── P-ADIC ─────────────────────────────────────────────────────────────

extern "C" int ncp_padic_expansion(long long x, int p, int* digits, int max_terms) {
    if (!digits || max_terms <= 0 || p < 2) return NCP_ERROR_INVALID_INPUT;

    auto result = PadicAnalysis::padic_expansion(x, p, max_terms);
    std::copy(result.begin(), result.end(), digits);
    return static_cast<int>(result.size());
}

extern "C" int ncp_padic_valuation(long long x, int p) {
    return PadicAnalysis::padic_valuation(x, p);
}

extern "C" double ncp_padic_distance(long long x, long long y, int p) {
    return PadicAnalysis::ultrametric_distance(x, y, p);
}

extern "C" int ncp_padic_cluster(const double* data, int length, int* labels,
                                   double threshold, int p) {
    if (!data || !labels || length <= 0) return 0;

    std::vector<double> v(data, data + length);
    PadicConfig cfg;
    cfg.prime = p;
    cfg.clustering_threshold = threshold;
    PadicAnalysis analysis(cfg);

    auto result = analysis.ultrametric_clustering(v, threshold);
    std::copy(result.labels.begin(), result.labels.end(), labels);
    return result.num_clusters;
}

// ─── CLUSTER ────────────────────────────────────────────────────────────

extern "C" int ncp_cluster_mutate(int k, const double* x_vars, const int* B,
                                    int n, double* new_x, int* new_B) {
    if (!x_vars || !B || !new_x || !new_B || n <= 0 || k < 0 || k >= n)
        return NCP_ERROR_INVALID_INPUT;

    std::vector<double> x(x_vars, x_vars + n);
    std::vector<std::vector<int>> Bmat(n, std::vector<int>(n));
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            Bmat[i][j] = B[i * n + j];

    auto nx = ClusterAlgebra::mutation(k, x, Bmat);
    auto nB = ClusterAlgebra::mutate_matrix(k, Bmat);

    std::copy(nx.begin(), nx.end(), new_x);
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j)
            new_B[i * n + j] = nB[i][j];

    return NCP_OK;
}

extern "C" int ncp_cluster_laurent(const double* x_vars, int n) {
    if (!x_vars || n <= 0) return 0;

    std::vector<double> x(x_vars, x_vars + n);
    std::vector<std::vector<int>> B(n, std::vector<int>(n, 0));
    for (int i = 0; i < n - 1; ++i) {
        B[i][i+1] = 1;
        B[i+1][i] = -1;
    }

    return ClusterAlgebra::check_laurent_phenomenon(x, B) ? 1 : 0;
}

extern "C" int ncp_cluster_protocol_mutation(const double* source_features, int num_features,
                                               int target_protocol, double* result_features) {
    if (!source_features || !result_features || num_features <= 0)
        return NCP_ERROR_INVALID_INPUT;

    // Map features
    std::unordered_map<std::string, double> src;
    src["header_size"] = (num_features > 0) ? source_features[0] : 200.0;
    src["payload_ratio"] = (num_features > 1) ? source_features[1] : 0.8;
    src["encryption"] = (num_features > 2) ? source_features[2] : 0.0;

    std::string target;
    switch (target_protocol) {
        case 0: target = "HTTP"; break;
        case 1: target = "DNS"; break;
        case 2: target = "QUIC"; break;
        case 3: target = "WebSocket"; break;
        default: target = "HTTP"; break;
    }

    auto result = ClusterAlgebra::protocol_mutation(src, target);

    result_features[0] = result.count("header_size") ? result["header_size"] : 200.0;
    result_features[1] = result.count("payload_ratio") ? result["payload_ratio"] : 0.8;
    result_features[2] = result.count("encryption") ? result["encryption"] : 0.0;
    if (num_features > 3) result_features[3] = result.count("query_length") ? result["query_length"] : 0.0;

    return NCP_OK;
}

// ─── MIRROR ─────────────────────────────────────────────────────────────

extern "C" int ncp_mirror_morph(const double* input, double* output, int length) {
    if (!input || !output || length <= 0) return NCP_ERROR_NULL_POINTER;

    std::vector<double> in_vec(input, input + length);
    auto result = MirrorSymmetry::mirror_morph(in_vec);
    std::copy(result.begin(), result.end(), output);
    return NCP_OK;
}

extern "C" int ncp_mirror_inverse(const double* input, double* output, int length) {
    if (!input || !output || length <= 0) return NCP_ERROR_NULL_POINTER;

    std::vector<double> in_vec(input, input + length);
    auto result = MirrorSymmetry::inverse_mirror_morph(in_vec);
    std::copy(result.begin(), result.end(), output);
    return NCP_OK;
}

extern "C" int ncp_mirror_stability(double packet_size, double arrival_rate, double entropy) {
    std::unordered_map<std::string, double> features;
    features["packet_size"] = packet_size;
    features["arrival_rate"] = arrival_rate;
    features["entropy"] = entropy;

    ChargeVector E;
    E.rank = packet_size / 1000.0;
    E.degree = arrival_rate / 100.0;
    E.euler = entropy / 8.0;

    auto Z = MirrorSymmetry::central_charge(E);
    auto stab = MirrorSymmetry::determine_stability(Z, E);
    return static_cast<int>(stab);
}

// ─── ANABELIAN ──────────────────────────────────────────────────────────

extern "C" int ncp_anabelian_reconstruct(const double* samples, int num_samples,
                                           int sample_length, int* adj_matrix, int adj_size) {
    if (!samples || !adj_matrix || num_samples <= 0 || sample_length <= 0)
        return NCP_ERROR_INVALID_INPUT;

    // Build samples vector
    std::vector<std::vector<double>> sample_vecs;
    for (int s = 0; s < num_samples; ++s) {
        std::vector<double> sample(samples + s * sample_length,
                                    samples + (s + 1) * sample_length);
        sample_vecs.push_back(sample);
    }

    AnabelianConfig cfg;
    AnabelianReconstruction anabelian(cfg);
    auto topo = anabelian.reconstruct_from_traffic(sample_vecs);

    // Write adjacency matrix
    int n = std::min(static_cast<int>(topo.nodes.size()), adj_size);
    std::fill(adj_matrix, adj_matrix + adj_size * adj_size, 0);

    for (const auto& edge : topo.edges) {
        if (edge.from < adj_size && edge.to < adj_size) {
            adj_matrix[edge.from * adj_size + edge.to] = 1;
            adj_matrix[edge.to * adj_size + edge.from] = 1;
        }
    }

    return static_cast<int>(topo.edges.size());
}

extern "C" int ncp_anabelian_genus(int num_vertices, int num_edges, int num_components) {
    return AnabelianReconstruction::compute_genus(num_vertices, num_edges, num_components);
}

extern "C" int ncp_anabelian_belyi(const int* adj_matrix, int n, double* output) {
    if (!adj_matrix || !output || n <= 0) return NCP_ERROR_NULL_POINTER;

    // Build topology from adjacency
    NetworkTopology topo;
    for (int i = 0; i < n; ++i) {
        TopoNode node;
        node.id = i;
        topo.nodes.push_back(node);
    }
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            if (adj_matrix[i * n + j]) {
                TopoEdge edge;
                edge.from = i;
                edge.to = j;
                topo.edges.push_back(edge);
            }
        }
    }

    auto beta = AnabelianReconstruction::belyi_function(topo);
    std::copy(beta.begin(), beta.end(), output);
    return static_cast<int>(beta.size());
}

// ─── SELF-TEST ──────────────────────────────────────────────────────────

extern "C" int ncp_math_self_test(void) {
    return ncp::Math::self_test() ? 1 : 0;
}
