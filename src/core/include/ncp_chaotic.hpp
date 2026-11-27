#pragma once
#ifndef NCP_CHAOTIC_HPP
#define NCP_CHAOTIC_HPP

/// @file ncp_chaotic.hpp
/// @brief Chaotic embedding for data hiding in chaotic attractors.
///
/// Uses the Lorenz system (σ=10, ρ=28, β=8/3) to generate a chaotic
/// trajectory. Data is embedded via Chaotic Signal Superposition (CSS):
///   output[i] = data[i] + ε · x[i]
/// where x[i] is the chaotic trajectory and ε controls modulation depth.
///
/// Lyapunov exponents are computed via the Wolf algorithm: two nearby
/// trajectories are tracked, and their exponential divergence rate
/// gives the largest Lyapunov exponent λ₁. Positive λ₁ ⟹ chaos.
///
/// Correlation dimension uses Grassberger-Procaccia:
///   C(r) = (2/N(N-1)) · #{pairs with distance < r} ~ r^D
/// where D is the correlation dimension.
///
/// Reference:
///   Lorenz E.N. (1963). "Deterministic nonperiodic flow."
///   J. Atmospheric Sciences 20(2): 130-141.

#include <vector>
#include <array>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <string>
#include <random>

namespace ncp {
namespace Math {

/// Lorenz system state
struct LorenzState {
    double x = 1.0, y = 1.0, z = 1.0;
};

/// Configuration for chaotic embedding
struct ChaoticConfig {
    double sigma = 10.0;           ///< Lorenz σ
    double rho = 28.0;             ///< Lorenz ρ
    double beta = 8.0 / 3.0;      ///< Lorenz β
    double dt = 0.01;              ///< Integration timestep
    double epsilon = 0.01;         ///< CSS modulation depth
    int embedding_dim = 3;         ///< Takens embedding dimension
    int time_delay = 1;            ///< Takens time delay
    size_t transient_steps = 1000; ///< Steps to discard before recording
};

/// Result of chaotic embedding
struct ChaoticResult {
    std::vector<double> data;       ///< Embedded data
    std::vector<double> trajectory; ///< Chaotic trajectory used
    std::vector<double> lyapunov;   ///< Lyapunov exponents
    double correlation_dim = 0.0;   ///< Correlation dimension
    bool success = false;
    std::string error_msg;
};

// ═══════════════════════════════════════════════════════════════════════════
// CHAOTIC EMBEDDER
// ═══════════════════════════════════════════════════════════════════════════

class ChaoticEmbedder {
public:
    ChaoticEmbedder() = default;
    explicit ChaoticEmbedder(const ChaoticConfig& config) : config_(config) {}

    /// Generate Lorenz trajectory of given length using RK4 integration.
    std::vector<double> generate_trajectory(size_t length);

    /// Generate 3D Lorenz trajectory (x, y, z interleaved).
    std::vector<std::array<double, 3>> generate_trajectory_3d(size_t length);

    /// Embed data using CSS modulation.
    ChaoticResult embed(const std::vector<double>& data);

    /// Embed data with custom modulation depth.
    ChaoticResult embed(const std::vector<double>& data, double epsilon);

    /// Apply chaotic transformation to data (for traffic morphing).
    ChaoticResult transform(const std::vector<double>& data);

    /// Compute Lyapunov exponents via Wolf algorithm.
    /// Returns vector of exponents (largest first).
    std::vector<double> lyapunov_exponents(const std::vector<double>& data,
                                            size_t embed_dim = 3,
                                            int time_delay = 1);

    /// Compute largest Lyapunov exponent only.
    double largest_lyapunov(const std::vector<double>& data);

    /// Compute correlation dimension via Grassberger-Procaccia.
    double correlation_dimension(const std::vector<double>& data,
                                  size_t embed_dim = 3,
                                  int time_delay = 1);

    /// Takens delay embedding: reconstruct phase space from scalar time series.
    std::vector<std::vector<double>> takens_embedding(
        const std::vector<double>& data,
        int embed_dim = 3,
        int time_delay = 1);

    const ChaoticConfig& config() const { return config_; }
    void set_config(const ChaoticConfig& c) { config_ = c; }

private:
    ChaoticConfig config_;

    /// Lorenz system derivatives: dx/dt, dy/dt, dz/dt
    std::array<double, 3> lorenz_deriv(double x, double y, double z) const;

    /// RK4 integration step
    LorenzState rk4_step(const LorenzState& state, double dt) const;
};

// ═══════════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════

inline std::array<double, 3> ChaoticEmbedder::lorenz_deriv(
    double x, double y, double z) const {
    return {
        config_.sigma * (y - x),
        x * (config_.rho - z) - y,
        x * y - config_.beta * z
    };
}

inline LorenzState ChaoticEmbedder::rk4_step(const LorenzState& s, double dt) const {
    auto k1 = lorenz_deriv(s.x, s.y, s.z);

    auto k2 = lorenz_deriv(
        s.x + 0.5 * dt * k1[0],
        s.y + 0.5 * dt * k1[1],
        s.z + 0.5 * dt * k1[2]);

    auto k3 = lorenz_deriv(
        s.x + 0.5 * dt * k2[0],
        s.y + 0.5 * dt * k2[1],
        s.z + 0.5 * dt * k2[2]);

    auto k4 = lorenz_deriv(
        s.x + dt * k3[0],
        s.y + dt * k3[1],
        s.z + dt * k3[2]);

    LorenzState next;
    next.x = s.x + (dt / 6.0) * (k1[0] + 2*k2[0] + 2*k3[0] + k4[0]);
    next.y = s.y + (dt / 6.0) * (k1[1] + 2*k2[1] + 2*k3[1] + k4[1]);
    next.z = s.z + (dt / 6.0) * (k1[2] + 2*k2[2] + 2*k3[2] + k4[2]);
    return next;
}

inline std::vector<std::array<double, 3>> ChaoticEmbedder::generate_trajectory_3d(
    size_t length) {

    std::vector<std::array<double, 3>> traj;
    traj.reserve(length);

    LorenzState state{0.1, 0.1, 0.1};  // Initial condition

    // Discard transient
    for (size_t i = 0; i < config_.transient_steps; ++i) {
        state = rk4_step(state, config_.dt);
    }

    // Record trajectory
    for (size_t i = 0; i < length; ++i) {
        state = rk4_step(state, config_.dt);
        traj.push_back({state.x, state.y, state.z});
    }

    return traj;
}

inline std::vector<double> ChaoticEmbedder::generate_trajectory(size_t length) {
    auto traj3d = generate_trajectory_3d(length);
    std::vector<double> traj(length);
    for (size_t i = 0; i < length; ++i) {
        traj[i] = traj3d[i][0];  // Use x-component
    }
    return traj;
}

inline ChaoticResult ChaoticEmbedder::embed(const std::vector<double>& data) {
    return embed(data, config_.epsilon);
}

inline ChaoticResult ChaoticEmbedder::embed(const std::vector<double>& data, double epsilon) {
    ChaoticResult result;
    size_t n = data.size();

    if (n < 4) {
        result.error_msg = "Data too short for chaotic embedding";
        return result;
    }

    // Generate chaotic trajectory
    auto trajectory = generate_trajectory(n);
    result.trajectory = trajectory;

    // CSS modulation: output = data + ε * trajectory
    result.data.resize(n);
    for (size_t i = 0; i < n; ++i) {
        result.data[i] = data[i] + epsilon * trajectory[i];
    }

    // Compute Lyapunov exponents
    result.lyapunov = lyapunov_exponents(trajectory, config_.embedding_dim, config_.time_delay);
    result.correlation_dim = correlation_dimension(trajectory, config_.embedding_dim, config_.time_delay);
    result.success = true;

    return result;
}

inline ChaoticResult ChaoticEmbedder::transform(const std::vector<double>& data) {
    return embed(data, config_.epsilon);
}

inline std::vector<std::vector<double>> ChaoticEmbedder::takens_embedding(
    const std::vector<double>& data, int embed_dim, int time_delay) {

    std::vector<std::vector<double>> embedded;
    size_t n = data.size();
    int min_len = (embed_dim - 1) * time_delay;

    if (static_cast<int>(n) <= min_len) return embedded;

    size_t num_points = n - min_len;
    embedded.reserve(num_points);

    for (size_t i = 0; i < num_points; ++i) {
        std::vector<double> point(embed_dim);
        for (int d = 0; d < embed_dim; ++d) {
            point[d] = data[i + d * time_delay];
        }
        embedded.push_back(std::move(point));
    }

    return embedded;
}

inline std::vector<double> ChaoticEmbedder::lyapunov_exponents(
    const std::vector<double>& data, size_t embed_dim, int time_delay) {

    // Wolf algorithm for largest Lyapunov exponent.
    // We reconstruct phase space, find nearest neighbors, and track
    // their divergence over time.

    auto points = takens_embedding(data, static_cast<int>(embed_dim), time_delay);
    size_t N = points.size();

    if (N < 20) return {0.0};

    // Compute largest Lyapunov exponent
    // Track average divergence rate
    double total_lambda = 0.0;
    int num_pairs = 0;

    // For each point, find nearest neighbor and track divergence
    size_t max_track = std::min(N / 4, size_t(100));

    for (size_t i = 0; i < N - max_track; i += std::max(size_t(1), N / 50)) {
        // Find nearest neighbor of point i (excluding i itself)
        size_t nn = 0;
        double min_dist = 1e300;

        for (size_t j = 0; j < N; ++j) {
            if (j == i) continue;
            double dist = 0.0;
            for (size_t d = 0; d < embed_dim; ++d) {
                double dd = points[i][d] - points[j][d];
                dist += dd * dd;
            }
            dist = std::sqrt(dist);
            if (dist < min_dist && dist > 1e-10) {
                min_dist = dist;
                nn = j;
            }
        }

        if (min_dist < 1e-10) continue;

        // Track divergence
        double initial_dist = min_dist;
        size_t track_len = std::min(max_track, N - std::max(i, nn));

        for (size_t t = 1; t < track_len; ++t) {
            if (i + t >= N || nn + t >= N) break;

            double dist = 0.0;
            for (size_t d = 0; d < embed_dim; ++d) {
                double dd = points[i + t][d] - points[nn + t][d];
                dist += dd * dd;
            }
            dist = std::sqrt(dist);

            if (dist > 1e-10 && initial_dist > 1e-10) {
                double lambda_t = std::log(dist / initial_dist) / static_cast<double>(t);
                total_lambda += lambda_t;
                ++num_pairs;
                break;  // Only use first reliable divergence
            }
        }
    }

    double lambda_max = (num_pairs > 0) ? total_lambda / num_pairs : 0.0;

    // For a 3D embedding, we return just the largest exponent
    // Full spectrum would need QR decomposition approach
    return {lambda_max};
}

inline double ChaoticEmbedder::largest_lyapunov(const std::vector<double>& data) {
    auto exponents = lyapunov_exponents(data, config_.embedding_dim, config_.time_delay);
    return exponents.empty() ? 0.0 : exponents[0];
}

inline double ChaoticEmbedder::correlation_dimension(
    const std::vector<double>& data, size_t embed_dim, int time_delay) {

    // Grassberger-Procaccia algorithm
    auto points = takens_embedding(data, static_cast<int>(embed_dim), time_delay);
    size_t N = points.size();

    if (N < 50) return 0.0;

    // Compute all pairwise distances (subsample for large N)
    std::vector<double> distances;
    size_t max_pairs = std::min(N * (N - 1) / 2, size_t(100000));

    // Compute distance range
    double max_dist = 0.0;
    size_t sample_step = std::max(size_t(1), N / 200);

    for (size_t i = 0; i < N; i += sample_step) {
        for (size_t j = i + 1; j < N; j += sample_step) {
            double dist = 0.0;
            for (size_t d = 0; d < embed_dim; ++d) {
                double dd = points[i][d] - points[j][d];
                dist += dd * dd;
            }
            dist = std::sqrt(dist);
            distances.push_back(dist);
            if (dist > max_dist) max_dist = dist;
            if (distances.size() >= max_pairs) goto done_distances;
        }
    }
    done_distances:

    if (distances.size() < 100) return 0.0;

    // Compute correlation integral C(r) for various r
    std::vector<double> log_r, log_C;
    size_t num_radii = 20;

    for (size_t k = 1; k <= num_radii; ++k) {
        double r = max_dist * k / num_radii;
        size_t count = 0;
        for (double d : distances) {
            if (d < r) ++count;
        }
        double C = static_cast<double>(count) / distances.size();
        if (C > 1e-10 && C < 0.99) {
            log_r.push_back(std::log(r));
            log_C.push_back(std::log(C));
        }
    }

    if (log_r.size() < 5) return 0.0;

    // D = slope of log C(r) vs log r
    double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
    size_t n = log_r.size();
    for (size_t i = 0; i < n; ++i) {
        sum_x += log_r[i];
        sum_y += log_C[i];
        sum_xy += log_r[i] * log_C[i];
        sum_x2 += log_r[i] * log_r[i];
    }
    double dn = static_cast<double>(n);
    double denom = dn * sum_x2 - sum_x * sum_x;
    if (std::abs(denom) < 1e-15) return 0.0;

    double D = (dn * sum_xy - sum_x * sum_y) / denom;
    return D;
}

} // namespace Math
} // namespace ncp

#endif // NCP_CHAOTIC_HPP
