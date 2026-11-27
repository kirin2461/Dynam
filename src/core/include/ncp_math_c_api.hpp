#ifndef NCP_MATH_C_API_HPP
#define NCP_MATH_C_API_HPP

/// @file ncp_math_c_api.hpp
/// @brief C API wrapper for all math modules (for Python ctypes integration).
///
/// Usage from Python:
///   lib = ctypes.CDLL("./libncp_math.so")
///   lib.ncp_fractal_generate(data_ptr, length, hurst, result_ptr)

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// ─── Result codes ───────────────────────────────────────────────────────

#define NCP_OK 0
#define NCP_ERROR_INVALID_INPUT -1
#define NCP_ERROR_COMPUTATION -2
#define NCP_ERROR_NULL_POINTER -3

// ─── FRACTAL ────────────────────────────────────────────────────────────

/// Generate fractional Gaussian noise.
/// @param output    Output buffer (length elements)
/// @param length    Number of samples to generate
/// @param hurst     Target Hurst exponent (0 < H < 1)
/// @param seed      RNG seed (0 = random)
/// @return NCP_OK on success
int ncp_fractal_generate(double* output, int length, double hurst, uint32_t seed);

/// Compute Hurst exponent of data.
/// @param data      Input data
/// @param length    Data length
/// @return Hurst exponent
double ncp_fractal_compute_hurst(const double* data, int length);

/// Apply fractal transformation to data.
/// @param input     Input data
/// @param output    Output data (same length)
/// @param length    Data length
/// @param target_hurst  Target Hurst exponent
/// @return NCP_OK on success
int ncp_fractal_transform(const double* input, double* output, int length, double target_hurst);

// ─── CHAOTIC ────────────────────────────────────────────────────────────

/// Apply chaotic embedding to data.
int ncp_chaotic_transform(const double* input, double* output, int length, double epsilon);

/// Generate Lorenz trajectory.
int ncp_chaotic_trajectory(double* output_x, double* output_y, double* output_z,
                            int length, double sigma, double rho, double beta);

/// Compute largest Lyapunov exponent.
double ncp_chaotic_lyapunov(const double* data, int length);

// ─── ERGODIC ────────────────────────────────────────────────────────────

/// Apply Arnold cat map to data (pairs of coordinates).
int ncp_ergodic_arnold(const double* input, double* output, int length, int iterations);

/// Apply Baker map to data.
int ncp_ergodic_baker(const double* input, double* output, int length, int iterations);

/// Compute Birkhoff convergence rate.
double ncp_ergodic_convergence(const double* data, int length);

/// Compute ergodic stealth guarantee.
double ncp_ergodic_guarantee(const double* data, int length);

// ─── TOPOLOGICAL ────────────────────────────────────────────────────────

/// Compute persistence diagram.
/// @param data      Input data
/// @param length    Data length
/// @param births    Output: birth times (caller allocates, max = length)
/// @param deaths    Output: death times (same size)
/// @param max_pairs Maximum number of pairs to write
/// @return Number of persistence pairs written
int ncp_topo_persistence(const double* data, int length,
                          double* births, double* deaths, int max_pairs);

/// Compute Wasserstein distance between two persistence diagrams.
double ncp_topo_wasserstein(const double* births1, const double* deaths1, int n1,
                             const double* births2, const double* deaths2, int n2);

// ─── TROPICAL ───────────────────────────────────────────────────────────

/// Tropical addition: min(a, b)
double ncp_tropical_add(double a, double b);

/// Tropical multiplication: a + b
double ncp_tropical_multiply(double a, double b);

/// Evaluate tropical polynomial.
double ncp_tropical_poly_eval(const double* coeffs, const int* exponents,
                               int num_terms, double x);

/// Solve tropical LP.
int ncp_tropical_lp(const double* c, int n,
                     const double* A, int m,
                     const double* b,
                     double* optimal_point, double* optimal_value);

// ─── P-ADIC ─────────────────────────────────────────────────────────────

/// Compute p-adic expansion of integer.
int ncp_padic_expansion(long long x, int p, int* digits, int max_terms);

/// Compute p-adic valuation.
int ncp_padic_valuation(long long x, int p);

/// Compute ultrametric distance.
double ncp_padic_distance(long long x, long long y, int p);

/// Ultrametric clustering.
/// @param data      Input data
/// @param length    Data length
/// @param labels    Output: cluster labels (caller allocates)
/// @param threshold Clustering threshold
/// @param p         Prime for p-adic metric
/// @return Number of clusters
int ncp_padic_cluster(const double* data, int length, int* labels,
                       double threshold, int p);

// ─── CLUSTER ────────────────────────────────────────────────────────────

/// Perform cluster mutation.
int ncp_cluster_mutate(int k, const double* x_vars, const int* B,
                        int n, double* new_x, int* new_B);

/// Check Laurent phenomenon.
int ncp_cluster_laurent(const double* x_vars, int n);

/// Protocol mutation (HTTP → DNS, etc.)
int ncp_cluster_protocol_mutation(const double* source_features, int num_features,
                                    int target_protocol, double* result_features);

// ─── MIRROR ─────────────────────────────────────────────────────────────

/// Apply mirror morph (A-side → B-side).
int ncp_mirror_morph(const double* input, double* output, int length);

/// Inverse mirror morph (B-side → A-side).
int ncp_mirror_inverse(const double* input, double* output, int length);

/// Analyze traffic stability.
/// @param features  Input features (packet_size, arrival_rate, entropy)
/// @return Stability: 0=STABLE, 1=SEMISTABLE, 2=UNSTABLE
int ncp_mirror_stability(double packet_size, double arrival_rate, double entropy);

// ─── ANABELIAN ──────────────────────────────────────────────────────────

/// Reconstruct topology from traffic samples.
/// @param samples   Flattened 2D array (num_samples × sample_length)
/// @param num_samples Number of samples
/// @param sample_length Length of each sample
/// @param adj_matrix Output adjacency matrix (caller allocates, size = sample_length²)
/// @param adj_size  Size of adjacency matrix
/// @return Number of edges in topology
int ncp_anabelian_reconstruct(const double* samples, int num_samples,
                                int sample_length, int* adj_matrix, int adj_size);

/// Compute genus of topology.
int ncp_anabelian_genus(int num_vertices, int num_edges, int num_components);

/// Compute Belyi function.
int ncp_anabelian_belyi(const int* adj_matrix, int n, double* output);

// ─── SELF-TEST ──────────────────────────────────────────────────────────

/// Run self-test for all modules. Returns 1 if all pass, 0 otherwise.
int ncp_math_self_test(void);

#ifdef __cplusplus
}
#endif

#endif // NCP_MATH_C_API_HPP
