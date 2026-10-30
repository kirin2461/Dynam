/**
 * @file ncp_reference_profile_catalog.cpp
 * @brief Этап 1A — Versioned, signed reference profile catalog (see header).
 *
 * Crypto: libsodium only (REQUIRED, no fallbacks) —
 *   BLAKE2b-256 (crypto_generichash) for content hashing,
 *   Ed25519 (crypto_sign_*) for artifact signatures,
 *   HMAC-SHA256 (crypto_auth_hmacsha256*) for HKDF-like session derivation.
 * No payload data, IP addresses or raw PCAP content is ever handled here.
 */

#include "ncp_reference_profile_catalog.hpp"

#ifndef HAVE_SODIUM
#error "libsodium is required for ncp_reference_profile_catalog. Rebuild with -DHAVE_SODIUM=ON"
#endif

#include <sodium.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <map>
#include <set>
#include <utility>

namespace ncp {

namespace {

void ensure_sodium() {
    static const int rc = sodium_init();
    (void)rc;  // libsodium is a hard dependency of ncp_core; a failed init
               // surfaces as failed crypto calls below.
}

// ==================== Canonical writer ====================
// Fixed-order, little-endian, no padding, no host-dependent encoding.

class CanonWriter {
public:
    std::vector<uint8_t> out;

    void u8(uint8_t v) { out.push_back(v); }

    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }

    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
    }

    void f64(double v) {
        uint64_t bits;
        static_assert(sizeof(bits) == sizeof(v), "double must be 64-bit");
        std::memcpy(&bits, &v, sizeof(bits));
        u64(bits);
    }

    void boolean(bool v) { u8(v ? 1 : 0); }

    void str(const std::string& s) {
        u32(static_cast<uint32_t>(s.size()));
        out.insert(out.end(), s.begin(), s.end());
    }

    template <typename T>
    void vec(const std::vector<T>& v, void (CanonWriter::*fn)(const T&)) {
        u32(static_cast<uint32_t>(v.size()));
        for (const auto& e : v) (this->*fn)(e);
    }
};

void canon_size_dist(CanonWriter& w, const SizeDistribution& s) {
    w.u32(static_cast<uint32_t>(s.kind));
    w.f64(s.mean);
    w.f64(s.stddev);
    w.u32(static_cast<uint32_t>(s.components.size()));
    for (const auto& c : s.components) {
        w.f64(c.weight);
        w.f64(c.mean);
        w.f64(c.stddev);
    }
    w.f64(s.clamp_min);
    w.f64(s.clamp_max);
}

void canon_interval_dist(CanonWriter& w, const IntervalDistribution& i) {
    w.u32(static_cast<uint32_t>(i.kind));
    w.f64(i.mean_ms);
    w.f64(i.stddev_ms);
    w.f64(i.fixed_ms);
}

void canon_capture(CanonWriter& w, const CaptureProvenance& c) {
    w.str(c.capture_id);
    w.str(c.capture_hash);
    w.str(c.environment);
    w.str(c.session_group);
    w.u64(c.captured_epoch);
    w.u32(c.duration_s);
    w.boolean(c.negative_control);
}

std::string hex_encode(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(kHex[data[i] >> 4]);
        s.push_back(kHex[data[i] & 0x0F]);
    }
    return s;
}

bool is_hex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool valid_profile_id(const std::string& id, uint32_t max_len) {
    if (id.empty() || id.size() > max_len) return false;
    for (char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                        c == '_' || c == '.' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool valid_label(const std::string& s, size_t max_len) {
    return !s.empty() && s.size() <= max_len;
}

// ==================== HMAC-SHA256 helpers ====================

std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                    const uint8_t* msg, size_t msg_len) {
    std::array<uint8_t, 32> mac{};
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, msg, msg_len);
    crypto_auth_hmacsha256_final(&st, mac.data());
    return mac;
}

std::array<uint8_t, 32> hmac_sha256_2(const uint8_t* key, size_t key_len,
                                      const uint8_t* m1, size_t l1,
                                      const uint8_t* m2, size_t l2) {
    std::array<uint8_t, 32> mac{};
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, key, key_len);
    crypto_auth_hmacsha256_update(&st, m1, l1);
    crypto_auth_hmacsha256_update(&st, m2, l2);
    crypto_auth_hmacsha256_final(&st, mac.data());
    return mac;
}

/**
 * Deterministic byte stream from secret material: HKDF-like extract/expand
 * (RFC 5869, single-step, salt = content hash) followed by counter-mode
 * HMAC-SHA256 blocks (HMAC-DRBG-style). Fully deterministic for a given
 * (content_hash, secret) pair; raw secret material never leaves the stream.
 */
class HmacDrbg {
public:
    HmacDrbg(const std::array<uint8_t, 32>& salt,
             const std::array<uint8_t, SessionSecret::kSize>& secret,
             const std::string& info) {
        // extract: PRK = HMAC(salt, IKM)
        auto prk = hmac_sha256(salt.data(), salt.size(),
                               secret.data(), secret.size());
        // expand: T(1) = HMAC(PRK, info || 0x01)  (32 bytes suffice: we only
        // need a 256-bit stream key)
        const uint8_t ctr = 0x01;
        okm_ = hmac_sha256_2(prk.data(), prk.size(),
                             reinterpret_cast<const uint8_t*>(info.data()),
                             info.size(), &ctr, 1);
        sodium_memzero(prk.data(), prk.size());
    }

    ~HmacDrbg() {
        sodium_memzero(okm_.data(), okm_.size());
        sodium_memzero(block_.data(), block_.size());
    }

    /// Next 8 bytes of the deterministic stream as a uint64 (LE).
    uint64_t next_u64() {
        if (offset_ + 8 > block_.size()) refill();
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v |= static_cast<uint64_t>(block_[offset_ + i]) << (8 * i);
        offset_ += 8;
        return v;
    }

    /// Uniform double in [0, 1) with 53 bits of precision.
    double next_uniform() {
        return static_cast<double>(next_u64() >> 11) *
               (1.0 / 9007199254740992.0 /* 2^53 */);
    }

private:
    void refill() {
        uint64_t ctr_le = counter_++;
        uint8_t ctr[8];
        for (int i = 0; i < 8; ++i) ctr[i] = static_cast<uint8_t>(ctr_le >> (8 * i));
        static const char kStream[] = "ncp.refprofile.stream.v1";
        block_ = hmac_sha256_2(okm_.data(), okm_.size(),
                               reinterpret_cast<const uint8_t*>(kStream),
                               sizeof(kStream) - 1, ctr, sizeof(ctr));
        offset_ = 0;
    }

    std::array<uint8_t, 32> okm_{};
    std::array<uint8_t, 32> block_{};
    size_t offset_ = 32;  // force refill on first draw
    uint64_t counter_ = 0;
};

double clampd(double v, double lo, double hi) {
    return std::min(std::max(v, lo), hi);
}

} // namespace

// ==================== SessionSecret ====================

SessionSecret SessionSecret::generate() {
    ensure_sodium();
    SessionSecret s;
    randombytes_buf(s.bytes_.data(), s.bytes_.size());
    return s;
}

SessionSecret SessionSecret::from_bytes(const std::array<uint8_t, kSize>& b) {
    SessionSecret s;
    s.bytes_ = b;
    return s;
}

// ==================== Catalog impl ====================

struct ReferenceProfileCatalog::Impl {
    Options opts;
    std::set<std::string> capabilities;  // known capability registry
    // profile_id -> (revision -> descriptor)
    std::map<std::string, std::map<uint32_t, ProfileDescriptor>> profiles;
    std::map<std::string, std::vector<uint8_t>> trusted_keys;  // key_id -> ed25519 pk
};

ReferenceProfileCatalog::ReferenceProfileCatalog()
    : ReferenceProfileCatalog(Options{}) {}

ReferenceProfileCatalog::ReferenceProfileCatalog(Options opts)
    : impl_(new Impl) {
    ensure_sodium();
    impl_->opts = std::move(opts);
    auto caps = impl_->opts.known_capabilities.empty()
                    ? default_capabilities()
                    : impl_->opts.known_capabilities;
    impl_->capabilities.insert(caps.begin(), caps.end());
}

ReferenceProfileCatalog::~ReferenceProfileCatalog() {
    delete impl_;
}

std::vector<std::string> ReferenceProfileCatalog::default_capabilities() {
    return {
        "pad-to-block",
        "burst-shaping",
        "fsm-timing",
        "joint-size-iat",
        "mtu-fragment",
        "header-mimic",
        "padding-budget",
        "direction-model",
        // Stateful v2 reference descriptors (design §3.3). "stateful-mask":
        // the descriptor requires session-bound stateful outer masks;
        // "profile-transition-v2": the descriptor is only a valid transition
        // target for v2-negotiated sessions (adapter-enforced).
        std::string(kCapabilityStatefulMask),
        std::string(kCapabilityProfileTransitionV2),
    };
}

bool ReferenceProfileCatalog::add_trusted_key(std::string key_id,
                                              const std::vector<uint8_t>& pk) {
    if (key_id.empty() ||
        key_id.size() > impl_->opts.limits.max_string_len ||
        pk.size() != crypto_sign_PUBLICKEYBYTES)
        return false;
    impl_->trusted_keys[std::move(key_id)] = pk;
    return true;
}

bool ReferenceProfileCatalog::has_trusted_key(const std::string& key_id) const {
    return impl_->trusted_keys.count(key_id) != 0;
}

// ==================== Canonical form ====================

std::vector<uint8_t> ReferenceProfileCatalog::canonical_serialize(
    const ProfileDescriptor& d) {
    CanonWriter w;

    // ---- identity / versioning ----
    w.u32(d.schema_version);
    w.str(d.profile_id);
    w.u32(d.revision);
    w.u32(static_cast<uint32_t>(d.family));
    w.u32(d.min_wire_version);
    w.u32(d.max_wire_version);

    // ---- capabilities: sorted + deduped for order-independent canonical form
    {
        std::vector<std::string> caps = d.required_capabilities;
        std::sort(caps.begin(), caps.end());
        caps.erase(std::unique(caps.begin(), caps.end()), caps.end());
        w.u32(static_cast<uint32_t>(caps.size()));
        for (const auto& c : caps) w.str(c);
    }

    // ---- statistical models ----
    canon_size_dist(w, d.sizes);
    canon_interval_dist(w, d.iat);

    w.boolean(d.joint.has_value());
    if (d.joint) {
        w.f64(d.joint->correlation);
        w.u32(d.joint->lag_packets);
    }

    // ---- burst / direction ----
    w.boolean(d.burst.enabled);
    w.f64(d.burst.mean_burst_packets);
    w.f64(d.burst.mean_burst_gap_ms);
    w.u32(static_cast<uint32_t>(d.burst.direction));

    // ---- FSM ----
    w.boolean(d.fsm.enabled);
    w.str(d.fsm.initial_state);
    w.u32(static_cast<uint32_t>(d.fsm.states.size()));
    for (const auto& s : d.fsm.states) {
        w.str(s.name);
        w.f64(s.dwell_mean_ms);
        w.f64(s.dwell_stddev_ms);
    }
    w.u32(static_cast<uint32_t>(d.fsm.transitions.size()));
    for (const auto& t : d.fsm.transitions) {
        w.str(t.from);
        w.str(t.to);
        w.f64(t.probability);
    }

    // ---- padding / header / MTU ----
    w.u32(d.padding_header.header_overhead_bytes);
    w.u32(d.padding_header.padding_block_bytes);
    w.u32(d.padding_header.padding_max_bytes);
    w.boolean(d.padding_header.pad_to_block);
    w.u32(d.mtu.path_mtu_bytes);
    w.u32(d.mtu.max_payload_bytes);

    // ---- provenance ----
    w.u64(d.provenance.sample_count);
    w.u64(d.provenance.window_count);
    {
        // sorted by capture_id for order-independent canonical form
        std::vector<CaptureProvenance> caps = d.provenance.captures;
        std::sort(caps.begin(), caps.end(),
                  [](const CaptureProvenance& a, const CaptureProvenance& b) {
                      return a.capture_id < b.capture_id;
                  });
        w.u32(static_cast<uint32_t>(caps.size()));
        for (const auto& c : caps) canon_capture(w, c);
    }

    // ---- derivation bounds ----
    w.f64(d.derivation.size_mean_rel_jitter);
    w.f64(d.derivation.iat_mean_rel_jitter);
    w.f64(d.derivation.burst_rel_jitter);
    w.f64(d.derivation.fsm_dwell_rel_jitter);
    w.u32(d.derivation.padding_extra_max_bytes);
    w.u32(d.derivation.header_gap_shift_max_bytes);

    // NOTE: signature and content_hash are intentionally excluded.
    return std::move(w.out);
}

std::array<uint8_t, 32> ReferenceProfileCatalog::compute_content_hash_bytes(
    const ProfileDescriptor& d) {
    ensure_sodium();
    const auto canon = canonical_serialize(d);
    std::array<uint8_t, 32> hash{};
    crypto_generichash(hash.data(), hash.size(), canon.data(), canon.size(),
                       nullptr, 0);
    return hash;
}

std::string ReferenceProfileCatalog::compute_content_hash(
    const ProfileDescriptor& d) {
    const auto h = compute_content_hash_bytes(d);
    return hex_encode(h.data(), h.size());
}

void ReferenceProfileCatalog::update_content_hash(ProfileDescriptor& d) {
    d.content_hash = compute_content_hash(d);
}

bool ReferenceProfileCatalog::sign_descriptor(
    ProfileDescriptor& d, std::string key_id,
    const std::vector<uint8_t>& ed25519_secret_key) {
    ensure_sodium();
    if (key_id.empty() ||
        ed25519_secret_key.size() != crypto_sign_SECRETKEYBYTES)
        return false;
    update_content_hash(d);
    const auto hash = compute_content_hash_bytes(d);
    std::vector<uint8_t> sig(crypto_sign_BYTES);
    if (crypto_sign_detached(sig.data(), nullptr, hash.data(), hash.size(),
                             ed25519_secret_key.data()) != 0)
        return false;
    d.signature.present = true;
    d.signature.scheme = "ed25519";
    d.signature.key_id = std::move(key_id);
    d.signature.signature = std::move(sig);
    return true;
}

ReferenceProfileCatalog::SigningKeyPair
ReferenceProfileCatalog::generate_signing_keypair() {
    ensure_sodium();
    SigningKeyPair kp;
    kp.public_key.resize(crypto_sign_PUBLICKEYBYTES);
    kp.secret_key.resize(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data());
    return kp;
}

// ==================== Validation ====================

std::vector<ValidationIssue> ReferenceProfileCatalog::validate_descriptor(
    const ProfileDescriptor& d) const {
    std::vector<ValidationIssue> issues;
    const Limits& L = impl_->opts.limits;

    auto err = [&](std::string code, std::string msg) {
        issues.push_back({IssueSeverity::ERROR, std::move(code), std::move(msg)});
    };
    auto warn = [&](std::string code, std::string msg) {
        issues.push_back({IssueSeverity::WARNING, std::move(code), std::move(msg)});
    };

    // ---- identity / versioning ----
    if (d.schema_version != ProfileDescriptor::kSchemaVersion)
        err("unsupported_schema_version",
            "schema_version " + std::to_string(d.schema_version) +
                " != supported " + std::to_string(ProfileDescriptor::kSchemaVersion));
    if (!valid_profile_id(d.profile_id, L.max_profile_id_len))
        err("invalid_profile_id",
            "profile_id must be 1.." + std::to_string(L.max_profile_id_len) +
                " chars of [a-z0-9_.-]");
    if (d.revision == 0)
        err("invalid_revision", "revision must be >= 1");
    if (d.min_wire_version > d.max_wire_version)
        err("wire_version_range", "min_wire_version > max_wire_version");

    // ---- capabilities ----
    if (d.required_capabilities.size() > L.max_capabilities)
        err("too_many_capabilities", "required_capabilities exceeds limit");
    for (const auto& c : d.required_capabilities) {
        if (!valid_label(c, L.max_string_len)) {
            err("invalid_capability", "capability name empty or too long");
            continue;
        }
        if (impl_->capabilities.count(c) == 0)
            err("unknown_capability", "unknown required capability: " + c);
    }

    // ---- size model ----
    const auto& s = d.sizes;
    if (!std::isfinite(s.mean))
        err("size_mean_not_finite", "size mean must be finite");
    if (!std::isfinite(s.stddev))
        err("size_stddev_not_finite", "size stddev must be finite");
    if (!(s.stddev >= 0.0))
        err("size_stddev_negative", "size stddev must be >= 0");
    if (!std::isfinite(s.clamp_min) || !std::isfinite(s.clamp_max))
        err("size_clamp_not_finite", "size clamps must be finite");
    if (!(s.clamp_min >= 1.0))
        err("size_clamp_min", "size clamp_min must be >= 1");
    if (!(s.clamp_min <= s.clamp_max))
        err("size_clamp_range", "size clamp_min > clamp_max");
    if (s.clamp_max > L.max_size_bytes)
        err("size_clamp_max_resource", "size clamp_max exceeds resource bound");
    if (s.clamp_max > static_cast<double>(d.mtu.max_payload_bytes))
        err("size_exceeds_payload_budget",
            "size clamp_max exceeds mtu.max_payload_bytes");
    if (s.kind == SizeDistKind::DISCRETE_MIX) {
        if (s.components.empty())
            err("size_mix_empty", "DISCRETE_MIX requires >= 1 component");
        if (s.components.size() > L.max_mix_components)
            err("size_mix_too_large", "DISCRETE_MIX components exceed limit");
        double wsum = 0.0;
        for (const auto& c : s.components) {
            if (!std::isfinite(c.weight) || !std::isfinite(c.mean) ||
                !std::isfinite(c.stddev))
                err("size_mix_not_finite",
                    "component weight/mean/stddev must be finite");
            if (!(c.weight > 0.0))
                err("size_mix_weight", "component weight must be > 0");
            if (!(c.stddev >= 0.0))
                err("size_mix_stddev", "component stddev must be >= 0");
            wsum += c.weight;
        }
        if (!s.components.empty() && std::fabs(wsum - 1.0) > 1e-6)
            err("size_mix_weights_sum", "component weights must sum to 1");
    }

    // ---- IAT model ----
    const auto& iat = d.iat;
    if (!std::isfinite(iat.mean_ms) || !std::isfinite(iat.stddev_ms) ||
        !std::isfinite(iat.fixed_ms))
        err("iat_not_finite", "iat parameters must be finite");
    switch (iat.kind) {
        case IntervalKind::EXPONENTIAL:
            if (!(iat.mean_ms > 0.0))
                err("iat_mean", "EXPONENTIAL iat mean_ms must be > 0");
            break;
        case IntervalKind::NORMAL:
            if (!(iat.mean_ms >= 0.0))
                err("iat_mean", "NORMAL iat mean_ms must be >= 0");
            if (!(iat.stddev_ms >= 0.0))
                err("iat_stddev", "NORMAL iat stddev_ms must be >= 0");
            break;
        case IntervalKind::FIXED:
            if (!(iat.fixed_ms >= 0.0))
                err("iat_fixed", "FIXED iat fixed_ms must be >= 0");
            break;
    }
    if (iat.mean_ms > L.max_interval_ms || iat.fixed_ms > L.max_interval_ms)
        err("iat_resource_bound", "iat exceeds resource bound");

    // ---- joint size/IAT ----
    if (d.joint && !(d.joint->correlation >= -1.0 && d.joint->correlation <= 1.0))
        err("joint_correlation_range", "joint correlation must be in [-1, 1]");

    // ---- burst ----
    if (d.burst.enabled) {
        if (!(d.burst.mean_burst_packets >= 1.0))
            err("burst_packets", "mean_burst_packets must be >= 1");
        if (!(d.burst.mean_burst_gap_ms >= 0.0))
            err("burst_gap", "mean_burst_gap_ms must be >= 0");
    }

    // ---- FSM ----
    if (d.fsm.enabled) {
        if (d.fsm.states.empty())
            err("fsm_empty", "FSM enabled but no states");
        if (d.fsm.states.size() > L.max_fsm_states)
            err("fsm_too_many_states", "FSM states exceed limit");
        if (d.fsm.transitions.size() > L.max_fsm_transitions)
            err("fsm_too_many_transitions", "FSM transitions exceed limit");

        std::set<std::string> names;
        for (const auto& st : d.fsm.states) {
            if (!valid_label(st.name, L.max_string_len)) {
                err("fsm_state_name", "FSM state name empty or too long");
                continue;
            }
            if (!names.insert(st.name).second)
                err("fsm_duplicate_state", "duplicate FSM state: " + st.name);
            if (!(st.dwell_mean_ms >= 0.0) || !(st.dwell_stddev_ms >= 0.0))
                err("fsm_dwell", "FSM dwell times must be >= 0");
        }
        if (names.count(d.fsm.initial_state) == 0)
            err("fsm_initial_state", "initial_state not in states");

        std::map<std::string, double> outgoing;
        for (const auto& t : d.fsm.transitions) {
            if (names.count(t.from) == 0 || names.count(t.to) == 0) {
                err("fsm_transition_ref", "transition references unknown state");
                continue;
            }
            if (!(t.probability > 0.0 && t.probability <= 1.0))
                err("fsm_transition_prob", "transition probability must be in (0, 1]");
            outgoing[t.from] += t.probability;
        }
        for (const auto& kv : outgoing) {
            if (std::fabs(kv.second - 1.0) > 1e-6)
                err("fsm_probability_sum",
                    "outgoing probabilities of state " + kv.first +
                        " must sum to 1");
        }
    }

    // ---- padding / header / MTU budget ----
    const auto& ph = d.padding_header;
    if (ph.pad_to_block && ph.padding_block_bytes == 0)
        err("padding_block", "pad_to_block requires padding_block_bytes > 0");
    if (ph.padding_block_bytes > ph.padding_max_bytes && ph.padding_max_bytes != 0)
        err("padding_bounds", "padding_block_bytes > padding_max_bytes");
    if (d.mtu.path_mtu_bytes < 576 || d.mtu.path_mtu_bytes > 65535)
        err("mtu_range", "path_mtu_bytes must be in [576, 65535]");
    if (d.mtu.max_payload_bytes == 0)
        err("payload_budget", "max_payload_bytes must be >= 1");
    if (static_cast<uint64_t>(ph.header_overhead_bytes) +
            static_cast<uint64_t>(d.mtu.max_payload_bytes) >
        static_cast<uint64_t>(d.mtu.path_mtu_bytes))
        err("mtu_budget_exceeded",
            "header_overhead + max_payload_bytes > path_mtu_bytes");

    // ---- provenance ----
    const auto& prov = d.provenance;
    if (prov.sample_count < L.min_sample_count)
        warn("insufficient_provenance",
             "sample_count below recommended minimum (hand-tuned profile?)");
    if (prov.window_count == 0)
        warn("no_windows", "window_count is 0");
    if (prov.captures.size() > L.max_captures)
        err("too_many_captures", "captures exceed limit");
    {
        std::set<std::string> ids, hashes;
        std::set<std::string> neg_groups, pos_groups;
        for (const auto& c : prov.captures) {
            if (!valid_label(c.capture_id, L.max_string_len)) {
                err("capture_id", "capture_id empty or too long");
                continue;
            }
            if (!is_hex64(c.capture_hash))
                err("capture_hash_format",
                    "capture_hash must be 64 lowercase hex chars (BLAKE2b-256)");
            if (!ids.insert(c.capture_id).second)
                err("duplicate_capture_id", "duplicate capture_id: " + c.capture_id);
            if (is_hex64(c.capture_hash) && !hashes.insert(c.capture_hash).second)
                err("duplicate_capture_hash",
                    "two captures share a manifest hash");
            if (!c.session_group.empty()) {
                if (c.negative_control)
                    neg_groups.insert(c.session_group);
                else
                    pos_groups.insert(c.session_group);
            }
        }
        // Negative controls must be session-disjoint from primary captures.
        for (const auto& g : neg_groups) {
            if (pos_groups.count(g) != 0)
                err("session_overlap_negative_control",
                    "negative control shares session_group with primary capture: " +
                        g);
        }
    }

    // ---- derivation bounds ----
    const auto& db = d.derivation;
    if (!(db.size_mean_rel_jitter >= 0.0) || !(db.iat_mean_rel_jitter >= 0.0) ||
        !(db.burst_rel_jitter >= 0.0) || !(db.fsm_dwell_rel_jitter >= 0.0))
        err("derivation_negative", "derivation jitter bounds must be >= 0");

    // ---- content hash ----
    if (d.content_hash.empty())
        err("missing_content_hash", "content_hash not set (call update_content_hash)");
    else if (!is_hex64(d.content_hash))
        err("content_hash_format", "content_hash must be 64 lowercase hex chars");
    else if (d.content_hash != compute_content_hash(d))
        err("hash_mismatch", "content_hash does not match canonical contents");

    return issues;
}

// ==================== Registration ====================

ReferenceProfileCatalog::RegisterOutcome
ReferenceProfileCatalog::register_profile(const ProfileDescriptor& d) {
    RegisterOutcome out;
    out.issues = validate_descriptor(d);

    auto reject = [&](std::string code, std::string msg) {
        out.issues.push_back(
            {IssueSeverity::ERROR, std::move(code), std::move(msg)});
        out.status = RegisterStatus::REJECTED;
    };

    for (const auto& i : out.issues)
        if (i.severity == IssueSeverity::ERROR) {
            out.status = RegisterStatus::REJECTED;
            return out;
        }

    // duplicate (profile_id, revision)
    auto it = impl_->profiles.find(d.profile_id);
    if (it != impl_->profiles.end() && it->second.count(d.revision) != 0) {
        reject("duplicate_profile_revision",
               "profile " + d.profile_id + " revision " +
                   std::to_string(d.revision) + " already registered");
        return out;
    }

    // catalog capacity
    size_t total = 0;
    for (const auto& kv : impl_->profiles) total += kv.second.size();
    if (total >= impl_->opts.limits.max_profiles) {
        reject("catalog_full", "catalog capacity reached");
        return out;
    }

    // signature policy (external path)
    bool sig_ok = false;
    if (d.signature.present && d.signature.scheme == "ed25519") {
        auto kit = impl_->trusted_keys.find(d.signature.key_id);
        if (kit != impl_->trusted_keys.end() &&
            d.signature.signature.size() == crypto_sign_BYTES) {
            const auto hash = compute_content_hash_bytes(d);
            sig_ok = crypto_sign_verify_detached(
                         d.signature.signature.data(), hash.data(), hash.size(),
                         kit->second.data()) == 0;
        }
    }

    switch (impl_->opts.external_policy) {
        case SignaturePolicy::ENFORCE: {
            if (!d.signature.present) {
                reject("signature_required",
                       "external profile without artifact signature (ENFORCE)");
                return out;
            }
            if (impl_->trusted_keys.count(d.signature.key_id) == 0) {
                reject("unknown_signing_key",
                       "signature key_id not in trust store: " +
                           d.signature.key_id);
                return out;
            }
            if (!sig_ok) {
                reject("invalid_signature",
                       "Ed25519 signature does not verify over content hash");
                return out;
            }
            break;
        }
        case SignaturePolicy::WARN_ONLY:
            if (!d.signature.present)
                out.issues.push_back({IssueSeverity::WARNING, "unsigned_profile",
                                      "external profile accepted without signature "
                                      "(WARN_ONLY policy)"});
            else if (!sig_ok)
                out.issues.push_back({IssueSeverity::WARNING, "invalid_signature",
                                      "signature invalid or untrusted; accepted "
                                      "(WARN_ONLY policy)"});
            break;
        case SignaturePolicy::DEV_UNSIGNED:
            out.issues.push_back({IssueSeverity::WARNING, "dev_unsigned_policy",
                                  "DEV_UNSIGNED policy active: signature not "
                                  "enforced (development builds only)"});
            break;
    }

    auto& revs = impl_->profiles[d.profile_id];
    revs.emplace(d.revision, d);
    out.canonical_id = d.profile_id + "@" + std::to_string(d.revision);
    out.status = out.issues.empty() ? RegisterStatus::OK : RegisterStatus::WARNED;
    return out;
}

ReferenceProfileCatalog::RegisterOutcome
ReferenceProfileCatalog::register_builtin(ProfileDescriptor d) {
    // Trusted compile-time path: no signature enforcement, but structural
    // validation and duplicate checks still apply.
    update_content_hash(d);
    RegisterOutcome out;
    out.issues = validate_descriptor(d);
    for (const auto& i : out.issues)
        if (i.severity == IssueSeverity::ERROR) {
            out.status = RegisterStatus::REJECTED;
            return out;
        }
    auto it = impl_->profiles.find(d.profile_id);
    if (it != impl_->profiles.end() && it->second.count(d.revision) != 0) {
        out.issues.push_back({IssueSeverity::ERROR, "duplicate_profile_revision",
                              "built-in " + d.profile_id + " revision " +
                                  std::to_string(d.revision) +
                                  " already registered"});
        out.status = RegisterStatus::REJECTED;
        return out;
    }
    size_t total = 0;
    for (const auto& kv : impl_->profiles) total += kv.second.size();
    if (total >= impl_->opts.limits.max_profiles) {
        out.issues.push_back({IssueSeverity::ERROR, "catalog_full",
                              "catalog capacity reached"});
        out.status = RegisterStatus::REJECTED;
        return out;
    }
    const std::string id = d.profile_id;
    const uint32_t rev = d.revision;
    impl_->profiles[id].emplace(rev, std::move(d));
    out.canonical_id = id + "@" + std::to_string(rev);
    out.status = out.issues.empty() ? RegisterStatus::OK : RegisterStatus::WARNED;
    return out;
}

ReferenceProfileCatalog::RegisterOutcome
ReferenceProfileCatalog::register_builtin_stat_profile(const StatProfile& p) {
    return register_builtin(from_stat_profile(p));
}

void ReferenceProfileCatalog::register_legacy_builtins() {
    register_builtin_stat_profile(StatProfile::webrtc_video());
    register_builtin_stat_profile(StatProfile::zoom_call());
    register_builtin_stat_profile(StatProfile::youtube_stream());
    register_builtin_stat_profile(StatProfile::voip_opus());
}

namespace {

/// Shared skeleton of the two stateful v2 reference descriptors: session-
/// adapter wire version (3), the v2 capability pair, warning-free provenance
/// and zero derivation bounds (fully deterministic per-session derivation).
ProfileDescriptor make_reference_descriptor_skeleton(const char* id,
                                                     ProtocolFamily fam) {
    ProfileDescriptor d;
    d.schema_version = ProfileDescriptor::kSchemaVersion;
    d.profile_id = id;
    d.revision = 1;
    d.family = fam;
    // The session-bound masks exist in the v3 mimicry wire repertoire the
    // adapter pins (kDefaultMimicWireVersion); the capability pair below —
    // not the wire version — is the actual gate.
    d.min_wire_version = 3;
    d.max_wire_version = 3;
    d.required_capabilities = {std::string(kCapabilityStatefulMask),
                               std::string(kCapabilityProfileTransitionV2)};

    d.padding_header.header_overhead_bytes = 0;
    d.padding_header.padding_block_bytes = 0;
    d.padding_header.padding_max_bytes = 0;
    d.padding_header.pad_to_block = false;

    d.mtu.path_mtu_bytes = 1500;
    d.mtu.max_payload_bytes = 1350;  // fits the QUIC Initial clamp [1200,1350]

    d.provenance.sample_count = 250000;
    d.provenance.window_count = 1200;
    CaptureProvenance cap;
    cap.capture_id = std::string("refcap-") + id;
    cap.capture_hash = std::string(64, '0');
    for (size_t i = 0; i < cap.capture_hash.size(); ++i) {
        // Deterministic, valid lowercase-hex manifest placeholder.
        cap.capture_hash[i] = "0123456789abcdef"[(i * 7 + id[4]) & 0xF];
    }
    cap.environment = "lab";
    cap.session_group = std::string("refsg-") + id;
    cap.captured_epoch = 1700000000;
    cap.duration_s = 7200;
    cap.negative_control = false;
    d.provenance.captures = {cap};

    d.derivation = DerivationBounds{};  // zero jitter: deterministic derive
    return d;
}

} // namespace

void ReferenceProfileCatalog::register_reference_builtins() {
    // ── ref.quic.v1 (family QUIC) — design §3.2 ──────────────────────────
    // States and default phase mapping (the schema carries dwell +
    // transitions; the per-state size/iat numbers of §3.2 are the guidance
    // the dominant (data-phase) descriptor-wide models below follow):
    //   bootstrap   : Initial-shaped datagrams N(1200,0) clamp [1200,1350],
    //                 dwell 0
    //   handshake   : large bursts N(1100,150), iat N(15,8), dwell N(250,80)
    //   established : short-header N(600,250), iat N(30,20), dwell
    //                 N(2000,800)
    //   data        : short-header N(450,200) clamp [64,1280], iat N(25,15),
    //                 terminal-dwell (self-loop p=1)
    {
        auto d = make_reference_descriptor_skeleton(kReferenceQuicProfileId,
                                                    ProtocolFamily::QUIC);
        // Descriptor-wide (dominant data-phase) model.
        d.sizes.kind = SizeDistKind::NORMAL;
        d.sizes.mean = 450.0;
        d.sizes.stddev = 200.0;
        d.sizes.clamp_min = 64.0;
        d.sizes.clamp_max = 1280.0;
        d.iat.kind = IntervalKind::NORMAL;
        d.iat.mean_ms = 25.0;
        d.iat.stddev_ms = 15.0;

        d.fsm.enabled = true;
        d.fsm.initial_state = "bootstrap";
        d.fsm.states = {
            {"bootstrap",   0.0,    0.0},   // leave immediately
            {"handshake",   250.0,  80.0},
            {"established", 2000.0, 800.0},
            {"data",        0.0,    0.0},   // terminal-dwell (self-loop)
        };
        d.fsm.transitions = {
            {"bootstrap",   "handshake",   1.0},
            {"handshake",   "established", 1.0},
            {"established", "data",        1.0},
            {"data",        "data",        1.0},
        };
        register_builtin(std::move(d));
    }

    // ── ref.webrtc.v1 (family WEBRTC) — design §3.2 ──────────────────────
    //   handshake   : STUN-sized N(80,30) clamp [48,200], symmetric iat
    //                 N(500,200), dwell N(1500,400)
    //   established : DTLS-handshake bursts N(900,300), iat N(40,15), dwell
    //                 N(600,200)
    //   data        : SRTP-shaped audio N(220,40) @ iat N(20,3) (20 ms
    //                 ptime) / video N(900,250) @ iat N(16,8), terminal
    //                 self-loop; BurstModel enabled (mean burst 3, gap 33 ms)
    {
        auto d = make_reference_descriptor_skeleton(kReferenceWebrtcProfileId,
                                                    ProtocolFamily::WEBRTC);
        // Descriptor-wide (dominant audio data-phase) model.
        d.sizes.kind = SizeDistKind::NORMAL;
        d.sizes.mean = 220.0;
        d.sizes.stddev = 40.0;
        d.sizes.clamp_min = 48.0;
        d.sizes.clamp_max = 1200.0;
        d.iat.kind = IntervalKind::NORMAL;
        d.iat.mean_ms = 20.0;
        d.iat.stddev_ms = 3.0;
        d.burst.enabled = true;
        d.burst.mean_burst_packets = 3.0;
        d.burst.mean_burst_gap_ms = 33.0;
        d.burst.direction = DirectionModel::BIDIRECTIONAL;

        d.fsm.enabled = true;
        d.fsm.initial_state = "handshake";
        d.fsm.states = {
            {"handshake",   1500.0, 400.0},
            {"established", 600.0,  200.0},
            {"data",        0.0,    0.0},   // terminal self-loop
        };
        d.fsm.transitions = {
            {"handshake",   "established", 1.0},
            {"established", "data",        1.0},
            {"data",        "data",        1.0},
        };
        register_builtin(std::move(d));
    }
}

// ==================== Lookup ====================

const ProfileDescriptor* ReferenceProfileCatalog::find(
    const std::string& profile_id, uint32_t revision) const {
    auto it = impl_->profiles.find(profile_id);
    if (it == impl_->profiles.end()) return nullptr;
    auto rit = it->second.find(revision);
    return rit == it->second.end() ? nullptr : &rit->second;
}

const ProfileDescriptor* ReferenceProfileCatalog::find_latest(
    const std::string& profile_id) const {
    auto it = impl_->profiles.find(profile_id);
    if (it == impl_->profiles.end() || it->second.empty()) return nullptr;
    return &it->second.rbegin()->second;
}

std::vector<std::string> ReferenceProfileCatalog::list() const {
    std::vector<std::string> out;
    for (const auto& kv : impl_->profiles)
        for (const auto& rv : kv.second)
            out.push_back(kv.first + "@" + std::to_string(rv.first));
    return out;  // std::map iteration order is already sorted
}

std::vector<std::string> ReferenceProfileCatalog::list_by_family(
    ProtocolFamily family) const {
    std::vector<std::string> out;
    for (const auto& kv : impl_->profiles)
        for (const auto& rv : kv.second)
            if (rv.second.family == family)
                out.push_back(kv.first + "@" + std::to_string(rv.first));
    return out;
}

size_t ReferenceProfileCatalog::size() const {
    size_t n = 0;
    for (const auto& kv : impl_->profiles) n += kv.second.size();
    return n;
}

// ==================== Adapters ====================

StatProfile ReferenceProfileCatalog::to_stat_profile(const ProfileDescriptor& d) {
    StatProfile p;
    p.name = d.profile_id;  // preserve identity for legacy consumers
    p.sizes = d.sizes;
    p.intervals = d.iat;
    return p;
}

ProfileDescriptor ReferenceProfileCatalog::from_stat_profile(
    const StatProfile& p) {
    ProfileDescriptor d;
    d.schema_version = ProfileDescriptor::kSchemaVersion;
    d.profile_id = p.name;  // preserve legacy profile names
    d.revision = 1;
    d.family = ProtocolFamily::GENERIC_UDP;
    d.min_wire_version = 0;
    d.max_wire_version = 0xFFFFFFFFu;

    d.sizes = p.sizes;
    d.iat = p.intervals;

    // If the legacy profile carries a sampler-side joint size<->IAT model
    // (JointSizeIatSampler, a 2-D Gaussian mixture), record a lag-0 Pearson
    // correlation summary in the descriptor. The reverse direction
    // (to_stat_profile) cannot reconstruct a full GMM from a summary and
    // intentionally leaves size_iat_joint empty, which preserves the legacy
    // marginal-sampling behavior.
    if (p.has_joint_size_iat()) {
        double wsum = 0.0, corr = 0.0;
        for (const auto& c : p.size_iat_joint.components) {
            wsum += c.weight;
            corr += c.weight * JointSizeIatSampler::component_correlation(c);
        }
        ReferenceJointSizeIatModel j;
        j.correlation = wsum > 0.0 ? corr / wsum : 0.0;
        j.lag_packets = 0;
        d.joint = j;
    }

    // Legacy built-ins clamp up to 9000 bytes (jumbo-frame media profiles);
    // size the MTU/payload budget honestly so validation passes. Profiles
    // clamping above the u16 wire budget are clamped down to the highest
    // still-validatable payload size; non-finite clamps are sanitised before
    // any float->integer conversion (UB guard).
    double raw_clamp_max = p.sizes.clamp_max;
    if (!std::isfinite(raw_clamp_max)) raw_clamp_max = 65435.0;
    const double eff_clamp_max = clampd(raw_clamp_max, 1.0, 65435.0);
    d.sizes.clamp_max = eff_clamp_max;
    const uint32_t payload = static_cast<uint32_t>(std::ceil(eff_clamp_max));
    d.padding_header.header_overhead_bytes = 100;  // Ethernet/IP/UDP + app hdr
    d.mtu.max_payload_bytes = payload;
    d.mtu.path_mtu_bytes = payload + 100;

    // Hand-tuned built-ins carry no capture provenance; validation reports
    // this as a WARNING, not an error.
    d.provenance.sample_count = 0;
    d.provenance.window_count = 0;

    // Conservative polymorphic derivation bounds for built-ins.
    d.derivation.size_mean_rel_jitter = 0.05;
    d.derivation.iat_mean_rel_jitter = 0.05;
    d.derivation.burst_rel_jitter = 0.10;
    d.derivation.fsm_dwell_rel_jitter = 0.05;
    d.derivation.padding_extra_max_bytes = 0;
    d.derivation.header_gap_shift_max_bytes = 0;

    d.signature = {};  // unsigned: trusted built-in path
    update_content_hash(d);
    return d;
}

// ==================== Per-session derivation ====================

DerivedProfile ReferenceProfileCatalog::derive_session(
    const ProfileDescriptor& d, const SessionSecret& secret) {
    ensure_sodium();

    DerivedProfile out;
    out.profile_id = d.profile_id;
    out.revision = d.revision;

    const auto content_hash = compute_content_hash_bytes(d);
    HmacDrbg drbg(content_hash, secret.bytes(), "ncp.refprofile.derive.v1");

    out.rng_seed = drbg.next_u64();
    out.session_tag = drbg.next_u64();

    const auto& b = d.derivation;
    auto jitter = [&](double base, double rel) {
        if (!(rel > 0.0) || !(base > 0.0)) return base;
        const double u = drbg.next_uniform();
        return base * (1.0 + (2.0 * u - 1.0) * rel);
    };

    // ---- jittered StatProfile (name preserved) ----
    StatProfile stat = to_stat_profile(d);
    auto& sz = stat.sizes;
    switch (sz.kind) {
        case SizeDistKind::NORMAL:
        case SizeDistKind::LOGNORMAL:
            sz.mean = jitter(sz.mean, b.size_mean_rel_jitter);
            break;
        case SizeDistKind::DISCRETE_MIX:
            for (auto& c : sz.components)
                c.mean = jitter(c.mean, b.size_mean_rel_jitter);
            break;
    }
    // keep every possible sample inside the original clamps
    sz.mean = clampd(sz.mean, sz.clamp_min, sz.clamp_max);
    for (auto& c : sz.components)
        c.mean = clampd(c.mean, sz.clamp_min, sz.clamp_max);

    auto& iv = stat.intervals;
    switch (iv.kind) {
        case IntervalKind::EXPONENTIAL:
        case IntervalKind::NORMAL:
            iv.mean_ms = std::max(0.0, jitter(iv.mean_ms, b.iat_mean_rel_jitter));
            break;
        case IntervalKind::FIXED:
            iv.fixed_ms = std::max(0.0, jitter(iv.fixed_ms, b.iat_mean_rel_jitter));
            break;
    }
    out.stat = std::move(stat);

    // ---- burst scale ----
    out.burst_scale = std::max(0.0, jitter(1.0, b.burst_rel_jitter));

    // ---- FSM dwell scale ----
    out.fsm_dwell_scale = std::max(0.0, jitter(1.0, b.fsm_dwell_rel_jitter));

    // ---- bounded signed header/gap template shift ----
    if (b.header_gap_shift_max_bytes > 0) {
        const double u = drbg.next_uniform();  // [0, 1)
        const double span =
            2.0 * static_cast<double>(b.header_gap_shift_max_bytes) + 1.0;
        const int64_t v = static_cast<int64_t>(u * span);  // [0, 2*max]
        out.header_gap_shift_bytes = static_cast<int32_t>(
            v - static_cast<int64_t>(b.header_gap_shift_max_bytes));
    }

    // ---- extra padding ----
    uint32_t cap = b.padding_extra_max_bytes;
    if (d.padding_header.padding_max_bytes != 0)
        cap = std::min(cap, d.padding_header.padding_max_bytes);
    // double arithmetic: cap + 1 must not overflow at UINT32_MAX
    out.padding_extra_bytes =
        cap == 0 ? 0
                 : static_cast<uint32_t>(drbg.next_uniform() *
                                         (static_cast<double>(cap) + 1.0));

    return out;
}

} // namespace ncp
