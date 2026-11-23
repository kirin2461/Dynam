#include "ncp_optimal_transport.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <numeric>
#include <sodium.h>
#include <stdexcept>

namespace ncp {
namespace DPI {

namespace {

// Both inputs are sorted ascending. Returns the number of elements <= x.
size_t count_leq(const std::vector<double>& sorted, double x) {
    return static_cast<size_t>(
        std::upper_bound(sorted.begin(), sorted.end(), x) - sorted.begin());
}

} // namespace

double w1_distance(const std::vector<double>& a, const std::vector<double>& b) {
    if (a.empty() && b.empty()) return 0.0;
    if (a.empty() || b.empty()) {
        return std::numeric_limits<double>::infinity();
    }

    std::vector<double> sa = a;
    std::vector<double> sb = b;
    std::sort(sa.begin(), sa.end());
    std::sort(sb.begin(), sb.end());

    // Integrate |F_a - F_b| over the merged breakpoints. Between consecutive
    // distinct sample values both CDFs are constant, so the integral is exact.
    std::vector<double> points;
    points.reserve(sa.size() + sb.size());
    points.insert(points.end(), sa.begin(), sa.end());
    points.insert(points.end(), sb.begin(), sb.end());
    std::sort(points.begin(), points.end());
    points.erase(std::unique(points.begin(), points.end()), points.end());

    const double na = static_cast<double>(sa.size());
    const double nb = static_cast<double>(sb.size());

    double total = 0.0;
    for (size_t i = 0; i + 1 < points.size(); ++i) {
        const double x0 = points[i];
        const double width = points[i + 1] - x0;
        if (width <= 0.0) continue;
        const double fa = static_cast<double>(count_leq(sa, x0)) / na;
        const double fb = static_cast<double>(count_leq(sb, x0)) / nb;
        total += std::fabs(fa - fb) * width;
    }
    return total;
}

double w1_distance_sizes(const std::vector<size_t>& a,
                         const std::vector<size_t>& b) {
    std::vector<double> da;
    std::vector<double> db;
    da.reserve(a.size());
    db.reserve(b.size());
    for (size_t v : a) da.push_back(static_cast<double>(v));
    for (size_t v : b) db.push_back(static_cast<double>(v));
    return w1_distance(da, db);
}

double ks_distance_samples(const std::vector<double>& a,
                           const std::vector<double>& b) {
    if (a.empty() || b.empty()) {
        return (a.empty() && b.empty()) ? 0.0 : 1.0;
    }

    std::vector<double> sa = a;
    std::vector<double> sb = b;
    std::sort(sa.begin(), sa.end());
    std::sort(sb.begin(), sb.end());

    const double na = static_cast<double>(sa.size());
    const double nb = static_cast<double>(sb.size());

    std::vector<double> points;
    points.reserve(sa.size() + sb.size());
    points.insert(points.end(), sa.begin(), sa.end());
    points.insert(points.end(), sb.begin(), sb.end());
    std::sort(points.begin(), points.end());
    points.erase(std::unique(points.begin(), points.end()), points.end());

    double max_d = 0.0;
    for (double x : points) {
        const double fa = static_cast<double>(count_leq(sa, x)) / na;
        const double fb = static_cast<double>(count_leq(sb, x)) / nb;
        max_d = std::max(max_d, std::fabs(fa - fb));
    }
    return max_d;
}

// ===== QuantileShaper =====================================================

QuantileShaper::QuantileShaper(std::vector<size_t> reference_sizes)
    : ref_(std::move(reference_sizes))
{
    if (ref_.empty()) {
        throw std::invalid_argument("QuantileShaper: empty reference");
    }
    std::sort(ref_.begin(), ref_.end());
    order_.resize(ref_.size());
    std::iota(order_.begin(), order_.end(), size_t{0});
}

void QuantileShaper::ensure_epoch_locked(uint64_t epoch) {
    if (epoch == order_epoch_) return;
    // Fisher-Yates over a fresh identity permutation. Order within a block is
    // irrelevant to every marginal statistic; randomising it only prevents a
    // fixed, learnable sawtooth (a monotone ramp of sizes is a *worse* shape
    // than no shaping at all).
    std::iota(order_.begin(), order_.end(), size_t{0});
    for (size_t i = order_.size(); i > 1; --i) {
        const size_t j = randombytes_uniform(static_cast<uint32_t>(i));
        std::swap(order_[i - 1], order_[j]);
    }
    order_epoch_ = epoch;
}

size_t QuantileShaper::next() {
    std::lock_guard<std::mutex> lock(mutex_);
    const size_t n = ref_.size();
    const uint64_t pos = static_cast<uint64_t>(emitted_++);
    const uint64_t epoch = pos / n;
    const size_t slot = static_cast<size_t>(pos % n);
    ensure_epoch_locked(epoch);
    return ref_[order_[slot]];
}

void QuantileShaper::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    emitted_ = 0;
    order_epoch_ = UINT64_MAX;
    std::iota(order_.begin(), order_.end(), size_t{0});
}

size_t QuantileShaper::block_size() const {
    return ref_.size();
}

const std::vector<size_t>& QuantileShaper::reference() const {
    return ref_;
}

size_t QuantileShaper::emitted() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return emitted_;
}

// ===== Histogram expansion =================================================

std::vector<size_t> expand_size_histogram(
    const std::vector<std::pair<size_t, double>>& buckets,
    size_t resolution)
{
    if (resolution == 0) resolution = 1;
    if (buckets.empty()) return {};

    double sum = 0.0;
    for (const auto& b : buckets) {
        if (b.second > 0.0) sum += b.second;
    }
    if (sum <= 0.0) {
        // Degenerate weights: fall back to one entry per bucket.
        std::vector<size_t> out;
        for (const auto& b : buckets) out.push_back(b.first);
        return out;
    }

    std::vector<size_t> out;
    out.reserve(resolution + buckets.size());
    for (const auto& b : buckets) {
        if (b.second <= 0.0) continue;
        const double share = b.second / sum;
        size_t count = static_cast<size_t>(share * static_cast<double>(resolution) + 0.5);
        if (count == 0) count = 1;   // every listed size stays represented
        for (size_t i = 0; i < count; ++i) out.push_back(b.first);
    }
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace DPI
} // namespace ncp
