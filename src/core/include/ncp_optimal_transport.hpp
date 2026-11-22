#ifndef NCP_OPTIMAL_TRANSPORT_HPP
#define NCP_OPTIMAL_TRANSPORT_HPP

// 1-D optimal transport (Wasserstein-1) and exact quantile shaping.
//
// Motivation
// ----------
// A DPI that models packet-size distributions can compare an observed flow to
// a reference with any statistic it likes. The Kolmogorov-Smirnov distance
// only bounds sup|F_obs - F_ref|, which says nothing about the mean: on a
// 1500-byte MTU a KS of 0.05 still permits a 75-byte error in mean packet
// size. The 1-D Wasserstein-1 distance
//
//     W1(P,Q) = inf over couplings E|X-Y| = integral |F_P(x) - F_Q(x)| dx
//
// is the exact worst-case over the whole class of 1-Lipschitz statistics
// (Kantorovich-Rubinstein duality): W1 <= e bounds the error of *every*
// 1-Lipschitz functional simultaneously - mean, median, trimmed means, any
// smoothed rate estimator. That is the property worth having, and in one
// dimension it has a closed form, so it costs O(n log n) to evaluate.
//
// QuantileShaper
// --------------
// The matching shaping rule is the monotone rearrangement T = F_ref^-1 . F_obs.
// For a discrete reference we do something stronger and simpler: each block of
// n packets replays the reference's own size multiset in permuted order. The
// empirical distribution of a complete block is then *identical* to the
// reference, so W1 and KS are exactly zero - not bounded, zero. Order within a
// block is randomised per epoch and does not affect any marginal statistic.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <utility>
#include <vector>

namespace ncp {
namespace DPI {

/// Exact 1-D Wasserstein-1 distance between two empirical samples.
/// Both empty -> 0.0. Exactly one empty -> +infinity (nothing to compare).
double w1_distance(const std::vector<double>& a, const std::vector<double>& b);

/// Convenience overload for packet sizes.
double w1_distance_sizes(const std::vector<size_t>& a,
                         const std::vector<size_t>& b);

/// Kolmogorov-Smirnov distance between two empirical samples:
/// sup |F_a(x) - F_b(x)|. Provided so callers can compare the two metrics on
/// the same inputs; the shaper targets the stronger W1 guarantee.
double ks_distance_samples(const std::vector<double>& a,
                           const std::vector<double>& b);

/// Streaming quantile shaper.
///
/// Constructed from a reference multiset of sizes (not a histogram - the
/// multiset *is* the shape). next() walks a per-epoch permutation of that
/// multiset, so every complete block of block_size() calls emits exactly the
/// reference multiset. Partial blocks are a prefix of a permutation, which
/// still samples the reference without replacement.
///
/// Thread-safe: next() may be called concurrently.
class QuantileShaper {
public:
    /// Throws std::invalid_argument if reference_sizes is empty.
    explicit QuantileShaper(std::vector<size_t> reference_sizes);

    /// Next target size. Wraps to a fresh permutation each block.
    size_t next();

    /// Restart at the beginning of a fresh block.
    void reset();

    /// Number of sizes in one complete block.
    size_t block_size() const;

    /// The reference multiset, sorted ascending.
    const std::vector<size_t>& reference() const;

    /// How many values have been emitted since construction / reset().
    size_t emitted() const;

private:
    void ensure_epoch_locked(uint64_t epoch);

    // Immutable after construction: sorted once, then only read. Not `const`
    // because the constructor has to sort it.
    std::vector<size_t> ref_;   // sorted ascending after construction
    std::vector<size_t> order_;       // permutation of 0..n-1 for `order_epoch_`
    uint64_t order_epoch_ = UINT64_MAX;
    mutable std::mutex mutex_;
    size_t emitted_ = 0;
};

/// Expand a weighted size histogram into a reference multiset of roughly
/// `resolution` entries, each bucket contributing at least one entry.
/// Buckets with non-positive weight are skipped. Unsorted input is fine.
std::vector<size_t> expand_size_histogram(
    const std::vector<std::pair<size_t, double>>& buckets,
    size_t resolution = 256);

} // namespace DPI
} // namespace ncp

#endif // NCP_OPTIMAL_TRANSPORT_HPP
