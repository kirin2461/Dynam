#pragma once
#ifndef NCP_MATH_ALL_HPP
#define NCP_MATH_ALL_HPP

/// @file ncp_math_all.hpp
/// @brief Master include for all mathematical transform modules.
///
/// Pied Piper Edition — "Middle-Out Compression" for DPI evasion.
///
/// This header includes all 9 mathematical modules:
///
/// 1. ncp_fractal.hpp     — Fractal traffic (fGn, Hurst, MF-DFA)
/// 2. ncp_chaotic.hpp     — Chaotic embedding (Lorenz, Lyapunov)
/// 3. ncp_ergodic.hpp     — Ergodic mixing (Arnold, Baker, Birkhoff)
/// 4. ncp_topological.hpp — Topological morphing (persistence, Wasserstein)
/// 5. ncp_tropical.hpp    — Tropical geometry (min-plus, tropical LP)
/// 6. ncp_padic.hpp       — P-adic analysis (ultrametric, Mahler)
/// 7. ncp_cluster.hpp     — Cluster algebra (mutations, Laurent)
/// 8. ncp_mirror.hpp      — Mirror symmetry (wall-crossing, Bridgeland)
/// 9. ncp_anabelian.hpp   — Anabelian geometry (π₁^ét, dessins)
///
/// All modules are header-only for easy integration.

#include "ncp_math_base.hpp"
#include "ncp_fractal.hpp"
#include "ncp_chaotic.hpp"
#include "ncp_ergodic.hpp"
#include "ncp_topological.hpp"
#include "ncp_tropical.hpp"
#include "ncp_padic.hpp"
#include "ncp_cluster.hpp"
#include "ncp_mirror.hpp"
#include "ncp_anabelian.hpp"

namespace ncp {
namespace Math {

/// Quick test: run all modules on sample data and verify no crashes.
inline bool self_test() {
    std::vector<double> test_data(100);
    for (size_t i = 0; i < 100; ++i) {
        test_data[i] = std::sin(2.0 * M_PI * i / 100.0) + 0.1 * (i % 7);
    }

    // 1. Fractal
    {
        FractalConfig cfg;
        cfg.hurst = 0.75;
        cfg.length = 100;
        FractalTrafficGenerator gen(cfg);
        auto result = gen.generate_fgn();
        if (!result.success) return false;
    }

    // 2. Chaotic
    {
        ChaoticConfig cfg;
        ChaoticEmbedder embedder(cfg);
        auto result = embedder.transform(test_data);
        if (!result.success) return false;
    }

    // 3. Ergodic
    {
        ErgodicConfig cfg;
        ErgodicShaper shaper(cfg);
        auto result = shaper.transform(test_data);
        if (!result.success) return false;
    }

    // 4. Topological
    {
        TopologicalConfig cfg;
        TopologicalMorpher morpher(cfg);
        auto result = morpher.transform(test_data);
        if (!result.success) return false;
    }

    // 5. Tropical
    {
        TropicalGeometry geo;
        auto result = geo.transform(test_data);
        if (!result.success) return false;
    }

    // 6. P-adic
    {
        PadicConfig cfg;
        cfg.prime = 2;
        PadicAnalysis analysis(cfg);
        auto result = analysis.transform(test_data);
        if (!result.success) return false;
    }

    // 7. Cluster
    {
        ClusterConfig cfg;
        cfg.initial_rank = 3;
        ClusterAlgebra algebra(cfg);
        auto result = algebra.transform(test_data);
        if (!result.success) return false;
    }

    // 8. Mirror
    {
        MirrorConfig cfg;
        MirrorSymmetry mirror(cfg);
        auto result = mirror.transform(test_data);
        if (!result.success) return false;
    }

    // 9. Anabelian
    {
        AnabelianConfig cfg;
        AnabelianReconstruction anabelian(cfg);
        auto result = anabelian.transform(test_data);
        if (!result.success) return false;
    }

    return true;
}

} // namespace Math
} // namespace ncp

#endif // NCP_MATH_ALL_HPP
