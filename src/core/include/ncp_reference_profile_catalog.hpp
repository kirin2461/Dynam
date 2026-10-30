#pragma once

/**
 * @file ncp_reference_profile_catalog.hpp
 * @brief Этап 1A — Versioned, signed reference profile catalog for traffic mimicry
 *
 * A ReferenceProfileCatalog stores immutable, content-addressed
 * ProfileDescriptor records describing the *statistical shape* of a target
 * protocol (sizes, inter-arrival times, bursts, FSM timing, padding/MTU
 * budgets). Descriptors NEVER carry payload bytes, IP addresses or private
 * PCAP data — only aggregate models and offline capture provenance metadata.
 *
 * Trust model:
 *   - Built-in profiles (adapted from the legacy StatProfile presets) enter
 *     through an explicit trusted path and need no signature.
 *   - External profiles default to SignaturePolicy::ENFORCE: a valid Ed25519
 *     signature over the content hash from a registered signing key is
 *     mandatory. WARN_ONLY and DEV_UNSIGNED must be requested explicitly and
 *     are recorded in the registration outcome.
 *
 * Integrity:
 *   - Canonical serialization is fully deterministic (fixed little-endian
 *     field order, IEEE-754 bit encoding of doubles, order-normalised
 *     capability/provenance sets).
 *   - content_hash = lowercase hex BLAKE2b-256 over the canonical bytes
 *     (signature fields excluded).
 *   - The artifact signature is an Ed25519 detached signature over the raw
 *     32 content-hash bytes.
 *
 * Per-session polymorphic derivation:
 *   - derive_session() produces a deterministic DerivedProfile from caller
 *     supplied secret session material via an HKDF-like extract/expand over
 *     HMAC-SHA256 (libsodium), followed by a counter-mode HMAC-DRBG stream.
 *     Raw key material is never exposed; derived parameters are clamped to
 *     DerivationBounds and to the base model clamps, and differ across
 *     sessions with overwhelming probability.
 *
 * The public API is designed for future consumers (MimicryAutoPilot,
 * TransitionManager): lookup by id/revision, latest-revision resolution,
 * family listing and wire-version compatibility checks.
 */

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ncp_mimicry_stats.hpp"  // SizeDistribution / IntervalDistribution / StatProfile

namespace ncp {

// ==================== Enums ====================

/// Broad protocol family the reference traffic belongs to.
///
/// I-SIB-1 (normative resolution, catalog schema 1): for the mimicry
/// session adapter this field IS the closed built-in mask-variant group of
/// the descriptor — schema 1 deliberately carries NO separate
/// per-descriptor variant-group field. The binding is hash-bound: `family`
/// is covered by ProfileDescriptor::content_hash, so the verified
/// descriptor identity (profile_id, revision, content_hash)
/// deterministically selects the reviewed built-in variant map
/// (family_variant_masks() in ncp_mimicry_session.cpp: QUIC ->
/// {QUIC_INITIAL, QUIC_SHORT_HEADER}, WEBRTC -> {STUN_MESSAGE}, otherwise
/// none) that both session endpoints use for TX variant selection and RX
/// sibling candidates. Rationale: a timing/statistics revision of a
/// descriptor must never silently change the wire parsers the receiver
/// loads, and introducing a new variant group requires reviewed code (a
/// family map change) rather than arbitrary catalog data.
/// Regression evidence: tests/test_mimicry_sibling_binding.cpp.
enum class ProtocolFamily : uint32_t {
    GENERIC_TCP = 0,
    GENERIC_UDP = 1,
    TLS         = 2,
    QUIC        = 3,
    HTTP2       = 4,
    WEBRTC      = 5,
    VOIP        = 6,
    VIDEO_STREAM= 7,
    MESSAGING   = 8,
    DNS         = 9,
    STUN        = 10,  ///< additive; existing numeric values are frozen
};

/// Where a descriptor came from. BUILTIN skips signature enforcement
/// (trusted compile-time path); EXTERNAL is policy-checked.
enum class TrustClass : uint32_t {
    BUILTIN  = 0,
    EXTERNAL = 1,
};

/// Signature handling for externally supplied descriptors.
enum class SignaturePolicy : uint32_t {
    ENFORCE      = 0,  ///< valid trusted signature required (default)
    WARN_ONLY    = 1,  ///< accept, but record a warning issue
    DEV_UNSIGNED = 2,  ///< accept unsigned/signed-anything (dev builds only)
};

/// Dominant traffic directionality of the profiled protocol.
enum class DirectionModel : uint32_t {
    CLIENT_DRIVEN = 0,
    SERVER_DRIVEN = 1,
    BIDIRECTIONAL = 2,
    SYMMETRIC     = 3,
};

// ==================== Sub-models ====================

/// Optional joint size↔IAT coupling descriptor (lagged correlation only —
/// no raw sample pairs are stored). Named ReferenceJointSizeIatModel to
/// stay collision-free with the sampler-side joint model in
/// ncp_mimicry_stats (this is descriptor metadata, not a sampler).
struct ReferenceJointSizeIatModel {
    double correlation = 0.0;  ///< Pearson correlation in [-1, 1]
    uint32_t lag_packets = 0;  ///< lag between size[i] and iat[i + lag]
};

/// Burstiness + directionality model.
struct BurstModel {
    bool enabled = false;
    double mean_burst_packets = 1.0;   ///< >= 1 when enabled
    double mean_burst_gap_ms = 0.0;    ///< >= 0
    DirectionModel direction = DirectionModel::BIDIRECTIONAL;
};

struct FsmState {
    std::string name;              ///< unique within the FSM
    double dwell_mean_ms = 0.0;    ///< >= 0
    double dwell_stddev_ms = 0.0;  ///< >= 0
};

struct FsmTransition {
    std::string from;      ///< must reference an existing state
    std::string to;        ///< must reference an existing state
    double probability = 0.0;  ///< (0, 1]
};

/// Optional Markov-style timing FSM (state dwell + transition matrix).
struct FsmModel {
    bool enabled = false;
    std::string initial_state;   ///< must exist in states when enabled
    std::vector<FsmState> states;
    std::vector<FsmTransition> transitions;
};

/// Header overhead + padding policy.
struct PaddingHeaderModel {
    uint32_t header_overhead_bytes = 0;  ///< per-packet transport/app header
    uint32_t padding_block_bytes = 0;    ///< 0 = no block padding
    uint32_t padding_max_bytes = 0;      ///< hard cap on total padding
    bool pad_to_block = false;
};

/// Path MTU / payload budget. max_payload_bytes must fit inside the MTU
/// once header overhead is accounted for.
struct MtuBudget {
    uint32_t path_mtu_bytes = 1500;
    uint32_t max_payload_bytes = 1400;
};

/// Offline capture provenance metadata. Opaque identifiers and manifest
/// hashes only — never payloads, IPs or raw PCAP content.
struct CaptureProvenance {
    std::string capture_id;     ///< opaque manifest identifier (unique)
    std::string capture_hash;   ///< 64 lowercase hex chars (BLAKE2b-256 of manifest)
    std::string environment;    ///< e.g. "lab", "residential", "datacenter"
    std::string session_group;  ///< sessions of one capture; groups must be
                                ///< disjoint between negative controls and
                                ///< primary captures
    uint64_t captured_epoch = 0;  ///< seconds since epoch
    uint32_t duration_s = 0;
    bool negative_control = false;
};

/// Statistical provenance: how much offline data backs this profile.
struct Provenance {
    uint64_t sample_count = 0;  ///< packets/records used to fit the models
    uint64_t window_count = 0;  ///< analysis windows
    std::vector<CaptureProvenance> captures;
};

/// Bounds for deterministic per-session polymorphic derivation. All jitter
/// values are relative (fractions of the base value), non-negative.
struct DerivationBounds {
    double size_mean_rel_jitter = 0.0;  ///< |Δmean|/mean   <= jitter
    double iat_mean_rel_jitter = 0.0;   ///< |Δiat|/iat     <= jitter
    double burst_rel_jitter = 0.0;      ///< |Δburst|/burst <= jitter
    double fsm_dwell_rel_jitter = 0.0;  ///< |Δdwell|/dwell <= jitter
    uint32_t padding_extra_max_bytes = 0;  ///< absolute extra padding cap
    /// Bounded signed shift of the per-session header/gap template, bytes.
    uint32_t header_gap_shift_max_bytes = 0;
};

/// Artifact signature over the content hash.
struct ArtifactSignature {
    bool present = false;
    std::string scheme;   ///< "ed25519"
    std::string key_id;   ///< signer key identifier
    std::vector<uint8_t> signature;  ///< 64 bytes, detached
};

// ==================== ProfileDescriptor ====================

/**
 * Immutable, versioned reference profile descriptor.
 *
 * Canonical form: canonical_serialize() is deterministic for a given value;
 * content_hash must equal compute_content_hash() of the descriptor with the
 * signature and content_hash fields excluded.
 */
struct ProfileDescriptor {
    static constexpr uint32_t kSchemaVersion = 1;

    uint32_t schema_version = kSchemaVersion;
    std::string profile_id;    ///< lowercase [a-z0-9_.-], unique with revision
    uint32_t revision = 1;
    ProtocolFamily family = ProtocolFamily::GENERIC_TCP;

    uint32_t min_wire_version = 0;  ///< min compatible wire protocol version
    uint32_t max_wire_version = 0;  ///< max compatible wire protocol version

    std::vector<std::string> required_capabilities;

    SizeDistribution sizes;      ///< packet/chunk size model
    IntervalDistribution iat;    ///< inter-arrival time model
    std::optional<ReferenceJointSizeIatModel> joint;  ///< optional size↔IAT coupling

    BurstModel burst;
    FsmModel fsm;
    PaddingHeaderModel padding_header;
    MtuBudget mtu;
    Provenance provenance;
    DerivationBounds derivation;

    ArtifactSignature signature;
    std::string content_hash;  ///< 64 lowercase hex chars, BLAKE2b-256

    /// True if wire_version falls into [min_wire_version, max_wire_version].
    bool is_wire_compatible(uint32_t wire_version) const noexcept {
        return wire_version >= min_wire_version && wire_version <= max_wire_version;
    }
};

// ==================== Validation ====================

enum class IssueSeverity : uint32_t { WARNING = 0, ERROR = 1 };

struct ValidationIssue {
    IssueSeverity severity = IssueSeverity::ERROR;
    std::string code;     ///< stable machine-readable code, e.g. "hash_mismatch"
    std::string message;  ///< human-readable detail
};

// ==================== Session derivation ====================

/**
 * Secret per-session material used to derive polymorphic parameters.
 * Construct via generate() or from_bytes(); the bytes are only ever fed
 * into HMAC inside the catalog and are never serialised or returned.
 */
class SessionSecret {
public:
    static constexpr size_t kSize = 32;

    static SessionSecret generate();  ///< CSPRNG (libsodium randombytes)
    static SessionSecret from_bytes(const std::array<uint8_t, kSize>& b);

    const std::array<uint8_t, kSize>& bytes() const noexcept { return bytes_; }

private:
    std::array<uint8_t, kSize> bytes_{};
};

/**
 * Deterministic per-session view of a descriptor. `stat` is a drop-in
 * StatProfile (name preserved) usable with the legacy MimicryShaper;
 * `rng_seed` seeds the shaper. All numeric fields stay within the
 * descriptor's DerivationBounds and model clamps.
 */
struct DerivedProfile {
    std::string profile_id;
    uint32_t revision = 0;
    uint64_t session_tag = 0;   ///< public, non-secret session distinguisher
    uint64_t rng_seed = 0;      ///< deterministic shaper seed
    StatProfile stat;           ///< jittered size/IAT models
    double burst_scale = 1.0;   ///< multiplicative burst-size factor >= 0
    /// Multiplicative FSM dwell-time factor in
    /// [1 - fsm_dwell_rel_jitter, 1 + fsm_dwell_rel_jitter]; consumers scale
    /// every FsmState dwell by it.
    double fsm_dwell_scale = 1.0;
    /// Bounded signed shift of the header/gap template, bytes
    /// (|shift| <= header_gap_shift_max_bytes).
    int32_t header_gap_shift_bytes = 0;
    uint32_t padding_extra_bytes = 0;  ///< <= derivation.padding_extra_max_bytes
};

// ==================== Catalog ====================

/// Capability registry strings (members of default_capabilities()).
/// kCapabilityStatefulMask: the descriptor requires session-bound stateful
/// outer-mask support (QUIC_SHORT_HEADER / STUN_MESSAGE family variants).
/// kCapabilityProfileTransitionV2: the descriptor is only a valid
/// *transition target* for sessions that negotiated profile_transition_v2;
/// the adapter refuses it under a v1 session (defense in depth on top of
/// the wire gate).
inline constexpr const char* kCapabilityStatefulMask = "stateful-mask";
inline constexpr const char* kCapabilityProfileTransitionV2 =
    "profile-transition-v2";

/// Profile ids of the two built-in stateful reference descriptors
/// (register_reference_builtins(); design §3.2/§3.3).
inline constexpr const char* kReferenceQuicProfileId = "ref.quic.v1";
inline constexpr const char* kReferenceWebrtcProfileId = "ref.webrtc.v1";

/// True when the descriptor gates itself on the profile_transition_v2
/// capability (and is therefore a v2-only transition target).
inline bool descriptor_requires_profile_transition_v2(
    const ProfileDescriptor& d) {
    for (const auto& c : d.required_capabilities)
        if (c == kCapabilityProfileTransitionV2) return true;
    return false;
}

class ReferenceProfileCatalog {
public:
    /// Hard resource bounds enforced during validation.
    struct Limits {
        size_t max_profiles = 256;
        size_t max_mix_components = 16;
        size_t max_fsm_states = 64;
        size_t max_fsm_transitions = 256;
        size_t max_captures = 32;
        size_t max_capabilities = 32;
        size_t max_string_len = 128;
        uint32_t max_profile_id_len = 64;
        double max_interval_ms = 600000.0;   ///< 10 min
        double max_size_bytes = 65535.0;
        uint64_t min_sample_count = 1;
    };

    struct Options {
        SignaturePolicy external_policy = SignaturePolicy::ENFORCE;
        Limits limits;
        /// Known capability registry. Empty => default_capabilities().
        std::vector<std::string> known_capabilities;
    };

    enum class RegisterStatus { OK, WARNED, REJECTED };

    struct RegisterOutcome {
        RegisterStatus status = RegisterStatus::REJECTED;
        std::string canonical_id;  ///< "profile_id@revision" when accepted
        std::vector<ValidationIssue> issues;
        bool ok() const noexcept { return status != RegisterStatus::REJECTED; }
    };

    ReferenceProfileCatalog();  ///< default options (ENFORCE policy)
    explicit ReferenceProfileCatalog(Options opts);
    ~ReferenceProfileCatalog();

    ReferenceProfileCatalog(const ReferenceProfileCatalog&) = delete;
    ReferenceProfileCatalog& operator=(const ReferenceProfileCatalog&) = delete;

    /// Default capability registry used when Options::known_capabilities
    /// is left empty.
    static std::vector<std::string> default_capabilities();

    // ---- trust store ----

    /// Register an Ed25519 public signing key (32 bytes) under key_id.
    bool add_trusted_key(std::string key_id,
                         const std::vector<uint8_t>& ed25519_pubkey);
    bool has_trusted_key(const std::string& key_id) const;

    // ---- canonical form / hashing / signing ----

    /// Deterministic canonical serialization (signature + content_hash
    /// fields excluded). Stable across runs, platforms and compilers.
    static std::vector<uint8_t> canonical_serialize(const ProfileDescriptor& d);

    /// Raw 32-byte BLAKE2b-256 of the canonical serialization.
    static std::array<uint8_t, 32> compute_content_hash_bytes(
        const ProfileDescriptor& d);

    /// Lowercase hex of compute_content_hash_bytes().
    static std::string compute_content_hash(const ProfileDescriptor& d);

    /// Refresh d.content_hash from the current descriptor contents.
    static void update_content_hash(ProfileDescriptor& d);

    /// Sign the descriptor's content hash with an Ed25519 secret key
    /// (64 bytes, libsodium format). Sets content_hash and signature fields.
    /// Returns false on crypto failure. Intended for tooling/tests.
    static bool sign_descriptor(ProfileDescriptor& d, std::string key_id,
                                const std::vector<uint8_t>& ed25519_secret_key);

    /// Ed25519 keypair for the profile-signing trust store. Intended for
    /// tooling and tests; production keys are provisioned externally.
    struct SigningKeyPair {
        std::vector<uint8_t> public_key;  ///< 32 bytes
        std::vector<uint8_t> secret_key;  ///< 64 bytes, libsodium format
    };
    static SigningKeyPair generate_signing_keypair();

    // ---- validation ----

    /// Structural + semantic validation (no signature/trust checks, no
    /// duplicate-id checks against the catalog). Pure function of the
    /// descriptor and the configured limits/capability registry.
    std::vector<ValidationIssue> validate_descriptor(
        const ProfileDescriptor& d) const;

    // ---- registration ----

    /// Validate and register an external (policy-checked) descriptor.
    RegisterOutcome register_profile(const ProfileDescriptor& d);

    /// Explicit trusted path for compile-time built-in descriptors.
    /// Skips signature enforcement; validation errors still reject.
    RegisterOutcome register_builtin(ProfileDescriptor d);

    /// Backward-compatible adapter: wrap a legacy StatProfile preset into
    /// a trusted built-in descriptor (profile_id == profile.name, size/IAT
    /// models copied verbatim so existing behavior is preserved) and
    /// register it through the trusted path.
    RegisterOutcome register_builtin_stat_profile(const StatProfile& p);

    /// Convenience: register all four legacy built-in StatProfiles.
    void register_legacy_builtins();

    /// Register the two stateful v2 reference descriptors (design §3.2/§3.3):
    /// ref.quic.v1 (family QUIC: QUIC_INITIAL bootstrap/handshake variant,
    /// QUIC_SHORT_HEADER established/data variant) and ref.webrtc.v1
    /// (family WEBRTC: STUN_MESSAGE variant; SRTP_LIKE deferred). Both are
    /// BUILTIN trust class and carry required_capabilities {stateful-mask,
    /// profile-transition-v2} — valid transition targets only for
    /// v2-negotiated sessions.
    void register_reference_builtins();

    // ---- lookup ----

    const ProfileDescriptor* find(const std::string& profile_id,
                                  uint32_t revision) const;
    /// Highest registered revision of profile_id, or nullptr.
    const ProfileDescriptor* find_latest(const std::string& profile_id) const;
    /// "profile_id@revision" of every registered profile, sorted.
    std::vector<std::string> list() const;
    /// Canonical ids of profiles in the given protocol family, sorted.
    std::vector<std::string> list_by_family(ProtocolFamily family) const;
    size_t size() const;

    // ---- backward-compatible adapters ----

    /// Rebuild a legacy StatProfile from a descriptor (name preserved).
    static StatProfile to_stat_profile(const ProfileDescriptor& d);

    /// Build a trusted built-in descriptor from a legacy StatProfile
    /// (does not register it). Revision 1, wire range [0, 0xFFFFFFFF].
    static ProfileDescriptor from_stat_profile(const StatProfile& p);

    // ---- per-session derivation ----

    /// Deterministic polymorphic derivation. Same (descriptor, secret)
    /// always yields the same DerivedProfile; different secrets yield
    /// different parameters, all clamped to DerivationBounds and the base
    /// model clamps. The secret material never leaves this call.
    static DerivedProfile derive_session(const ProfileDescriptor& d,
                                         const SessionSecret& secret);

private:
    struct Impl;
    Impl* impl_;  // raw owning pointer (deleted in ~) to keep ABI simple
};

} // namespace ncp
