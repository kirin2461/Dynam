#pragma once

/**
 * @file ncp_mimicry_stats.hpp
 * @brief M5 — Statistical traffic profiles for protocol mimicry
 *
 * Makes encrypted flows statistically indistinguishable from a target
 * protocol by padding packet sizes and shaping inter-packet timing.
 *
 * This is a pure math module: no networking, no crypto — only <random>.
 * The caller seeds the RNG for determinism and is responsible for
 * actually padding payloads to the planned chunk sizes.
 *
 * Built-in profiles: webrtc_video(), zoom_call(), youtube_stream(),
 * voip_opus().
 */

#include <cstdint>
#include <cstddef>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace ncp {

// ===== Distribution kinds =====

enum class SizeDistKind {
    NORMAL,        // N(mean, stddev), clamped to [clamp_min, clamp_max]
    LOGNORMAL,     // log(X) ~ N(mean, stddev), clamped
    DISCRETE_MIX   // weighted mix of NORMAL components, clamped
};

enum class IntervalKind {
    EXPONENTIAL,   // Exp with mean `mean_ms`
    NORMAL,        // N(mean_ms, stddev_ms), clamped to >= 0
    FIXED          // always `fixed_ms`
};

// ===== Distributions =====

struct SizeDistribution {
    SizeDistKind kind = SizeDistKind::NORMAL;

    // NORMAL / LOGNORMAL parameters
    double mean = 0.0;     // NORMAL: mean; LOGNORMAL: mu of log(X)
    double stddev = 1.0;   // NORMAL: stddev; LOGNORMAL: sigma of log(X)

    // DISCRETE_MIX components (weights must sum to 1)
    struct Component {
        double weight = 0.0;
        double mean = 0.0;
        double stddev = 1.0;
    };
    std::vector<Component> components;

    // Clamping bounds applied to every sample
    double clamp_min = 64.0;
    double clamp_max = 9000.0;

    /// Analytical mean (clamping ignored) — for validation/tests.
    double theoretical_mean() const;
    /// Analytical standard deviation (clamping ignored).
    double theoretical_stddev() const;
    /// Analytical CDF at x (clamping ignored; NaN for empty mix).
    double theoretical_cdf(double x) const;
};

struct IntervalDistribution {
    IntervalKind kind = IntervalKind::EXPONENTIAL;

    double mean_ms = 33.0;    // EXPONENTIAL: mean; NORMAL: mean
    double stddev_ms = 0.0;   // NORMAL: stddev
    double fixed_ms = 20.0;   // FIXED: constant value

    double theoretical_mean() const;
    double theoretical_stddev() const;
};

// ===== Joint size<->IAT sampler =====

/// One component of the joint (packet size, inter-arrival time) Gaussian
/// mixture. `L = [[l00, 0], [l10, l11]]` is the lower-triangular Cholesky
/// factor of the component's 2x2 covariance (cov = L * L^T); `l10` carries
/// the size<->IAT coupling that two independent 1-D marginals structurally
/// cannot express. Sampling a component draws z ~ N(0, I_2) and returns
/// mu + L * z.
struct JointSizeIatComponent {
    double weight = 0.0;          // mixture weight (>= 0; need not sum to 1)
    double mu_size_bytes = 0.0;   // size mean
    double mu_iat_ms = 0.0;       // IAT mean
    double l00 = 0.0;             // Cholesky: size spread
    double l10 = 0.0;             // Cholesky: size<->IAT coupling term
    double l11 = 0.0;             // Cholesky: residual IAT spread
};

/**
 * Sampler for the joint size<->IAT distribution: a 2-D Gaussian mixture.
 *
 * Mirrors the invariants of AIVPN's SizeIatGmm2d
 * (aivpn-common/src/mask.rs), implemented natively:
 *  - deterministic given the caller-supplied rng;
 *  - the (size, iat) pair is drawn TOGETHER from one component, so the
 *    encoded correlation survives on the wire;
 *  - malformed/hostile parameters never throw: an invalid model samples a
 *    benign fallback, and structurally valid but hostile component values
 *    are clamped (IAT to [0, kMaxIatMs], mirroring AIVPN's
 *    MAX_BASE_IAT_MS; size to [1, kMaxSizeBytes]).
 *
 * Named JointSizeIatSampler to stay collision-free with the catalog-side
 * descriptor metadata (ReferenceJointSizeIatModel), which stores only
 * lagged correlation summaries and is not a sampler.
 */
class JointSizeIatSampler {
public:
    static constexpr size_t kMaxComponents = 64;
    static constexpr double kMaxIatMs = 600000.0;     // 10 min cap
    static constexpr double kMaxSizeBytes = 65535.0;  // u16 wire budget
    static constexpr double kFallbackSizeBytes = 512.0;
    static constexpr double kFallbackIatMs = 20.0;

    std::vector<JointSizeIatComponent> components;

    /// Structural validity: 1..kMaxComponents entries, every weight finite
    /// and >= 0, at least one positive weight.
    bool is_valid() const noexcept;

    /// Sample a correlated (size_bytes, iat_ms) pair. Invalid models yield
    /// (kFallbackSizeBytes, kFallbackIatMs) without touching `rng` state
    /// beyond what validation needs (none — rng is left untouched).
    std::pair<double, double> sample(std::mt19937_64& rng) const;

    /// Analytical Pearson correlation a component encodes:
    /// l10 / sqrt(l10^2 + l11^2); 0 when the component has no IAT spread.
    static double component_correlation(
        const JointSizeIatComponent& c) noexcept;
};

// ===== Statistical profile =====

struct StatProfile {
    std::string name;
    SizeDistribution sizes;
    IntervalDistribution intervals;

    /// Optional joint size<->IAT model. When invalid (e.g. default-constructed
    /// with no components) sampling uses the independent 1-D marginals above,
    /// preserving the legacy behavior bit-for-bit.
    JointSizeIatSampler size_iat_joint;

    /// Sample a packet/chunk size in bytes (clamped, >= 1).
    double sample_size(std::mt19937_64& rng) const;
    /// Sample an inter-packet interval in milliseconds (>= 0).
    double sample_interval_ms(std::mt19937_64& rng) const;

    /// True when a structurally valid joint model is attached.
    bool has_joint_size_iat() const noexcept;

    /// Sample a (size_bytes, iat_ms) pair. With a valid joint model the pair
    /// is correlated; the joint sampler enforces the u16 wire budget and the
    /// size is additionally clamped to this profile's [sizes.clamp_min,
    /// sizes.clamp_max] envelope. Without a joint model this samples size
    /// then interval from the 1-D marginals in exactly the legacy order
    /// (identical rng consumption and values to calling sample_size() then
    /// sample_interval_ms()).
    void sample_size_iat(std::mt19937_64& rng,
                         double& size_bytes_out,
                         double& iat_ms_out) const;

    // Built-in profiles
    static StatProfile webrtc_video();
    static StatProfile zoom_call();
    static StatProfile youtube_stream();
    static StatProfile voip_opus();
};

// ===== Shaper =====

struct Chunk {
    size_t bytes = 0;
    double delay_ms = 0.0;
};

/// A queued, not-yet-consumed data packet shape: the (size, delay) pair was
/// sampled TOGETHER (joint model) or from the legacy marginals, tagged with
/// the profile epoch it was prepared under.
struct PreparedShape {
    size_t bytes = 0;             // target packet size, [1, mtu budget]
    double delay_ms = 0.0;        // paired delay, [0, kMaxPreparedIatMs]
    uint64_t profile_epoch = 0;   // epoch the shape was prepared in
};

/**
 * Splits payloads into profile-distributed chunks (plan) and prepares
 * single-packet data shapes ahead of send time (prepared data shape API).
 *
 * Backward compatibility: plan(), reset() and profile() behave exactly as
 * before for profiles without a joint model (identical rng consumption and
 * chunk sequences for a given seed).
 *
 * Prepared data shape API (size and IAT chosen as one pair before sending):
 *  - prepare_data_shape(mtu) samples and QUEUES the next data shape, then
 *    returns a copy. Repeated calls return the queued shape unchanged —
 *    a control packet may look at the timing without consuming anything.
 *  - take_data_shape(out) consumes the queued shape for the data packet.
 *    A shape queued under a stale profile epoch can never be consumed.
 *  - cancel_prepared_shape() aborts: the queued shape is dropped and can
 *    never leak into a later epoch or be consumed after the abort.
 *  - set_profile() performs a profile transition: it bumps profile_epoch()
 *    and drops any queued shape (stale-epoch shapes never leak into the new
 *    epoch; repeated transitions bump the epoch each time).
 */
class MimicryShaper {
public:
    MimicryShaper(StatProfile profile, uint64_t seed);

    /// Upper clamp applied to prepared-shape delays (mirrors the joint
    /// sampler's IAT cap and AIVPN's MAX_BASE_IAT_MS).
    static constexpr double kMaxPreparedIatMs = JointSizeIatSampler::kMaxIatMs;

    /// Split payload_len into profile-distributed chunks with delays.
    /// The final chunk is capped at the remaining bytes; padding up to
    /// the planned size is the caller's responsibility.
    /// With a joint model each chunk's (bytes, delay_ms) is a correlated
    /// pair; without one the legacy independent sampling order is kept.
    std::vector<Chunk> plan(size_t payload_len);

    /// Reset the RNG to a known seed (deterministic replay). Also drops any
    /// queued prepared shape, which derives from the old rng stream. Does
    /// NOT change the profile or its epoch.
    void reset(uint64_t seed);

    const StatProfile& profile() const noexcept { return profile_; }

    /// Current profile epoch; bumped by every set_profile() transition.
    uint64_t profile_epoch() const noexcept { return profile_epoch_; }

    /// Profile transition: installs `profile`, bumps the epoch and drops any
    /// queued prepared shape so stale-epoch shapes cannot be consumed later.
    void set_profile(StatProfile profile);

    /// Prepare (idempotently) the next data shape in the current epoch and
    /// return a copy. `mtu_bytes` is the hard per-packet budget: the shape's
    /// size is clamped to [1, max(mtu_bytes, 1)]. Control-path callers use
    /// this to learn the pacing delay WITHOUT consuming the queued shape.
    PreparedShape prepare_data_shape(size_t mtu_bytes);

    /// Consume the queued prepared shape for a data packet. Returns false
    /// when nothing is queued or the queued shape belongs to a stale epoch
    /// (the stale shape is dropped, never consumed).
    bool take_data_shape(PreparedShape& out);

    /// Abort/cancel: drop the queued shape without consuming it. A cancelled
    /// shape can never leak into a later epoch or be consumed afterwards.
    void cancel_prepared_shape() noexcept;

    /// True when a (current-epoch) shape is queued. Exposed for tests and
    /// abort paths; does not reveal the shape contents.
    bool has_prepared_shape() const noexcept { return prepared_valid_; }

private:
    StatProfile profile_;
    std::mt19937_64 rng_;
    uint64_t profile_epoch_ = 0;
    bool prepared_valid_ = false;
    PreparedShape prepared_{};
};

} // namespace ncp
