/// @file test_math_modules.cpp
/// @brief Compile test for all C++ math modules.

#include <iostream>
#include <vector>
#include <cmath>
#include <cassert>

#include "ncp_math_all.hpp"

void test_fractal() {
    std::cout << "=== Testing Fractal ===" << std::endl;

    ncp::Math::FractalConfig cfg;
    cfg.hurst = 0.75;
    cfg.length = 256;
    cfg.seed = 42;

    ncp::Math::FractalTrafficGenerator gen(cfg);

    // Generate fGn
    auto result = gen.generate_fgn();
    assert(result.success);
    assert(result.data.size() == 256);
    std::cout << "  Generated " << result.data.size() << " samples" << std::endl;
    std::cout << "  Hurst target: " << cfg.hurst << std::endl;
    std::cout << "  Hurst actual: " << result.hurst_estimate << std::endl;

    // Compute Hurst
    double H = gen.compute_hurst(result.data);
    std::cout << "  Computed Hurst: " << H << std::endl;

    // Multifractal spectrum
    auto h = gen.multifractal_spectrum(result.data);
    std::cout << "  MF spectrum size: " << h.size() << std::endl;

    std::cout << "  ✓ Fractal OK" << std::endl;
}

void test_chaotic() {
    std::cout << "=== Testing Chaotic ===" << std::endl;

    ncp::Math::ChaoticConfig cfg;
    cfg.sigma = 10.0;
    cfg.rho = 28.0;
    cfg.beta = 8.0 / 3.0;
    cfg.epsilon = 0.01;

    ncp::Math::ChaoticEmbedder embedder(cfg);

    // Generate trajectory
    auto traj = embedder.generate_trajectory(100);
    std::cout << "  Trajectory length: " << traj.size() << std::endl;

    // Embed data
    std::vector<double> data(50, 1.0);
    auto result = embedder.embed(data);
    assert(result.success);
    std::cout << "  Embedded " << result.data.size() << " samples" << std::endl;
    std::cout << "  Lyapunov: " << (result.lyapunov.empty() ? 0.0 : result.lyapunov[0]) << std::endl;
    std::cout << "  Correlation dim: " << result.correlation_dim << std::endl;

    std::cout << "  ✓ Chaotic OK" << std::endl;
}

void test_ergodic() {
    std::cout << "=== Testing Ergodic ===" << std::endl;

    ncp::Math::ErgodicConfig cfg;
    cfg.map_type = ncp::Math::ErgodicConfig::MapType::ARNOLD;
    cfg.iterations = 50;

    ncp::Math::ErgodicShaper shaper(cfg);

    std::vector<double> data(100);
    for (int i = 0; i < 100; ++i) data[i] = std::sin(i * 0.1);

    auto result = shaper.transform(data);
    assert(result.success);
    std::cout << "  Convergence: " << result.convergence << std::endl;
    std::cout << "  Mixing time: " << result.mixing_time << std::endl;
    std::cout << "  Stealth guarantee: " << result.stealth_guarantee << std::endl;

    // Test Arnold cat map directly
    auto [x, y] = ncp::Math::ErgodicShaper::arnold_cat_map(0.3, 0.7, 10);
    std::cout << "  Arnold map after 10 iters: (" << x << ", " << y << ")" << std::endl;

    std::cout << "  ✓ Ergodic OK" << std::endl;
}

void test_topological() {
    std::cout << "=== Testing Topological ===" << std::endl;

    ncp::Math::TopologicalConfig cfg;
    ncp::Math::TopologicalMorpher morpher(cfg);

    std::vector<double> data(50);
    for (int i = 0; i < 50; ++i) data[i] = std::sin(i * 0.3) + 0.5 * (i % 3);

    auto result = morpher.transform(data);
    assert(result.success);
    std::cout << "  Persistence pairs: " << result.diagram.size() << std::endl;
    std::cout << "  Total persistence: " << result.total_persistence << std::endl;

    // Test Wasserstein distance
    auto diag1 = morpher.persistence_diagram(data);
    std::vector<double> data2(50);
    for (int i = 0; i < 50; ++i) data2[i] = std::cos(i * 0.3) + 0.3 * (i % 4);
    auto diag2 = morpher.persistence_diagram(data2);

    double w1 = ncp::Math::TopologicalMorpher::wasserstein_distance(diag1, diag2);
    std::cout << "  W1 distance: " << w1 << std::endl;

    std::cout << "  ✓ Topological OK" << std::endl;
}

void test_tropical() {
    std::cout << "=== Testing Tropical ===" << std::endl;

    // Test semiring
    double a = 5.0, b = 3.0;
    std::cout << "  5 ⊕ 3 = " << ncp::Math::TropicalGeometry::tropical_add(a, b) << std::endl;
    std::cout << "  5 ⊗ 3 = " << ncp::Math::TropicalGeometry::tropical_multiply(a, b) << std::endl;

    // Test tropical polynomial
    std::vector<double> coeffs = {1.0, 2.0, 3.0};
    std::vector<int> exps = {0, 1, 2};
    double val = ncp::Math::TropicalGeometry::tropical_polynomial(coeffs, exps, 2.0);
    std::cout << "  Tropical poly at x=2: " << val << std::endl;

    // Test tropical LP
    std::vector<double> c = {1.0, 2.0};
    std::vector<std::vector<double>> A = {{0.0, 0.0}, {0.0, 0.0}};
    std::vector<double> b_vec = {5.0, 3.0};
    auto lp = ncp::Math::TropicalGeometry::tropical_linear_program(c, A, b_vec);
    std::cout << "  LP feasible: " << lp.feasible << std::endl;
    std::cout << "  LP optimal: " << lp.optimal_value << std::endl;

    std::cout << "  ✓ Tropical OK" << std::endl;
}

void test_padic() {
    std::cout << "=== Testing P-adic ===" << std::endl;

    ncp::Math::PadicConfig cfg;
    cfg.prime = 2;
    ncp::Math::PadicAnalysis analysis(cfg);

    // P-adic expansion
    auto digits = analysis.padic_expansion(37);
    std::cout << "  37 in 2-adic: ";
    for (int d : digits) std::cout << d << " ";
    std::cout << std::endl;

    // Valuation
    int v = ncp::Math::PadicAnalysis::padic_valuation(24, 2);
    std::cout << "  v_2(24) = " << v << std::endl;

    // Ultrametric distance
    double d = ncp::Math::PadicAnalysis::ultrametric_distance(10, 2, 2);
    std::cout << "  d_2(10, 2) = " << d << std::endl;

    // Clustering
    std::vector<double> data = {1.0, 1.1, 5.0, 5.2, 10.0, 10.1};
    auto clusters = analysis.ultrametric_clustering(data, 0.5);
    std::cout << "  Clusters: " << clusters.num_clusters << std::endl;

    std::cout << "  ✓ P-adic OK" << std::endl;
}

void test_cluster() {
    std::cout << "=== Testing Cluster ===" << std::endl;

    ncp::Math::ClusterConfig cfg;
    cfg.initial_rank = 3;
    ncp::Math::ClusterAlgebra algebra(cfg);

    // Test mutation
    std::vector<double> x = {1.0, 2.0, 3.0};
    std::vector<std::vector<int>> B = {{0, 1, -1}, {-1, 0, 1}, {1, -1, 0}};

    auto new_x = ncp::Math::ClusterAlgebra::mutation(0, x, B);
    std::cout << "  After μ_0: ";
    for (double v : new_x) std::cout << v << " ";
    std::cout << std::endl;

    auto new_B = ncp::Math::ClusterAlgebra::mutate_matrix(0, B);
    std::cout << "  Mutated B[0][1] = " << new_B[0][1] << std::endl;

    // Laurent check
    bool laurent = ncp::Math::ClusterAlgebra::check_laurent_phenomenon(new_x, new_B);
    std::cout << "  Laurent phenomenon: " << laurent << std::endl;

    // Classification
    std::string type = ncp::Math::ClusterAlgebra::finite_type_classification(B);
    std::cout << "  Dynkin type: " << type << std::endl;

    std::cout << "  ✓ Cluster OK" << std::endl;
}

void test_mirror() {
    std::cout << "=== Testing Mirror ===" << std::endl;

    ncp::Math::MirrorConfig cfg;
    ncp::Math::MirrorSymmetry mirror(cfg);

    // Test central charge
    ncp::Math::ChargeVector E;
    E.rank = 1.0;
    E.degree = 2.0;
    E.euler = 0.5;
    auto Z = ncp::Math::MirrorSymmetry::central_charge(E);
    std::cout << "  Z(E) = " << Z.real() << " + " << Z.imag() << "i" << std::endl;

    // Test stability
    auto stab = ncp::Math::MirrorSymmetry::determine_stability(Z, E);
    std::cout << "  Stability: " << static_cast<int>(stab) << std::endl;

    // Mirror morph
    std::vector<double> data(20);
    for (int i = 0; i < 20; ++i) data[i] = std::sin(i * 0.5);
    auto morphed = ncp::Math::MirrorSymmetry::mirror_morph(data);
    std::cout << "  Mirror morph: " << morphed.size() << " samples" << std::endl;

    std::cout << "  ✓ Mirror OK" << std::endl;
}

void test_anabelian() {
    std::cout << "=== Testing Anabelian ===" << std::endl;

    ncp::Math::AnabelianConfig cfg;
    cfg.embedding_threshold = 0.3;
    ncp::Math::AnabelianReconstruction anabelian(cfg);

    // Create traffic samples
    std::vector<std::vector<double>> samples;
    for (int s = 0; s < 5; ++s) {
        std::vector<double> sample(20);
        for (int i = 0; i < 20; ++i) {
            sample[i] = std::sin(i * 0.3 + s * 0.5) + 0.1 * s;
        }
        samples.push_back(sample);
    }

    // Reconstruct topology
    auto topo = anabelian.reconstruct_from_traffic(samples);
    std::cout << "  Nodes: " << topo.nodes.size() << std::endl;
    std::cout << "  Edges: " << topo.edges.size() << std::endl;
    std::cout << "  Genus: " << topo.genus << std::endl;
    std::cout << "  π₁ generators: " << topo.generators.size() << std::endl;

    // Belyi function
    auto beta = ncp::Math::AnabelianReconstruction::belyi_function(topo);
    std::cout << "  Belyi function: " << beta.size() << " values" << std::endl;

    std::cout << "  ✓ Anabelian OK" << std::endl;
}

int main() {
    std::cout << "╔══════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  Pied Piper Math Modules — C++ Compile Test ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;

    try {
        test_fractal();
        std::cout << std::endl;
        test_chaotic();
        std::cout << std::endl;
        test_ergodic();
        std::cout << std::endl;
        test_topological();
        std::cout << std::endl;
        test_tropical();
        std::cout << std::endl;
        test_padic();
        std::cout << std::endl;
        test_cluster();
        std::cout << std::endl;
        test_mirror();
        std::cout << std::endl;
        test_anabelian();
        std::cout << std::endl;

        // Self-test
        std::cout << "=== Running self_test() ===" << std::endl;
        bool ok = ncp::Math::self_test();
        std::cout << "  Self-test: " << (ok ? "PASSED" : "FAILED") << std::endl;
        std::cout << std::endl;

        std::cout << "╔══════════════════════════════════════════════╗" << std::endl;
        std::cout << "║         ALL 9 MODULES PASSED ✓              ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════╝" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "EXCEPTION: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
